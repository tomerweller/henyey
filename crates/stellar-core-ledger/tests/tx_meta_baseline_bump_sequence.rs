use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use stellar_core_common::{normalize_transaction_meta, Hash256, NetworkId};
use stellar_core_crypto::{seed, xdr_compute_hash, SecretKey};
use stellar_core_ledger::execution::execute_transaction_set;
use stellar_core_ledger::{compute_header_hash, LedgerDelta, SnapshotBuilder, SnapshotHandle};
use stellar_core_tx::ClassicEventConfig;
use stellar_core_tx::soroban::SorobanConfig;
use stellar_xdr::curr::{
    AccountEntry, AccountEntryExt, AccountId, Asset, DecoratedSignature, LedgerEntry,
    LedgerEntryData, LedgerEntryExt, LedgerHeader, LedgerKey, LedgerKeyAccount, Memo, MuxedAccount,
    Operation, OperationBody, PaymentOp, Preconditions, SequenceNumber, Signature as XdrSignature,
    SignatureHint, StellarValue, String32, Thresholds, TimePoint, Transaction, TransactionEnvelope,
    TransactionExt, TransactionMeta, TransactionResultMetaV1, WriteXdr,
    TransactionV1Envelope, Uint256, VecM,
};

const GENESIS_BUCKET_LIST_HASH: [u8; 32] = hex_literal::hex!(
    "4e6a8404d33b17eee7031af0b3606b6af8e36fe5a3bff59e4e5e420bd0ad3bf4"
);

fn baseline_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/tx-meta-baseline-current/BumpSequenceTests.json")
}

fn load_baseline_hashes(test_name: &str) -> Vec<u64> {
    let path = baseline_file();
    let data = fs::read_to_string(&path).expect("read baseline file");
    let root: serde_json::Value = serde_json::from_str(&data).expect("parse baseline json");
    let hashes = root
        .get(test_name)
        .unwrap_or_else(|| panic!("missing baseline entry: {}", test_name))
        .as_array()
        .expect("hash array");

    hashes
        .iter()
        .map(|value| {
            let encoded = value.as_str().expect("hash string");
            let decoded = STANDARD.decode(encoded).expect("decode base64");
            assert_eq!(decoded.len(), 8);
            let mut tmp = 0u64;
            for byte in decoded {
                tmp = (tmp << 8) | (byte as u64);
            }
            tmp
        })
        .collect()
}

fn tx_meta_hash(meta: &TransactionMeta) -> u64 {
    let mut meta = meta.clone();
    normalize_transaction_meta(&mut meta).expect("normalize tx meta");
    xdr_compute_hash(&meta).expect("hash tx meta")
}

fn key_bytes(key: &LedgerKey) -> Vec<u8> {
    key.to_xdr(stellar_xdr::curr::Limits::none())
        .expect("key xdr")
}

fn entry_key_bytes(entry: &LedgerEntry) -> Vec<u8> {
    let key = stellar_core_ledger::entry_to_key(entry).expect("entry key");
    key_bytes(&key)
}

fn secret_from_name(name: &str) -> SecretKey {
    let mut seed = name.as_bytes().to_vec();
    while seed.len() < 32 {
        seed.push(b'.');
    }
    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(&seed[..32]);
    SecretKey::from_seed(&seed_bytes)
}

fn account_entry(
    account_id: AccountId,
    seq_num: i64,
    balance: i64,
    last_modified_ledger_seq: u32,
) -> (LedgerKey, LedgerEntry) {
    let key = LedgerKey::Account(LedgerKeyAccount {
        account_id: account_id.clone(),
    });
    let entry = LedgerEntry {
        last_modified_ledger_seq,
        data: LedgerEntryData::Account(AccountEntry {
            account_id,
            balance,
            seq_num: SequenceNumber(seq_num),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: VecM::default(),
            ext: AccountEntryExt::V0,
        }),
        ext: LedgerEntryExt::V0,
    };
    (key, entry)
}

fn genesis_header(ledger_version: u32, base_fee: u32, base_reserve: u32, total_coins: i64) -> LedgerHeader {
    let mut header = SnapshotBuilder::new(1)
        .build_with_default_header()
        .header()
        .clone();
    header.ledger_version = ledger_version;
    header.base_fee = base_fee;
    header.base_reserve = base_reserve;
    header.max_tx_set_size = 100;
    header.total_coins = total_coins;
    header.ledger_seq = 1;
    header.bucket_list_hash = stellar_xdr::curr::Hash(GENESIS_BUCKET_LIST_HASH);
    header.scp_value.close_time = TimePoint(0);
    header.scp_value = StellarValue {
        tx_set_hash: stellar_xdr::curr::Hash([0; 32]),
        close_time: TimePoint(0),
        upgrades: VecM::default(),
        ext: stellar_xdr::curr::StellarValueExt::Basic,
    };
    header
}

fn test_header(
    ledger_seq: u32,
    ledger_version: u32,
    base_fee: u32,
    base_reserve: u32,
    total_coins: i64,
    previous_hash: Hash256,
) -> LedgerHeader {
    let mut header = SnapshotBuilder::new(ledger_seq)
        .build_with_default_header()
        .header()
        .clone();
    header.ledger_version = ledger_version;
    header.base_fee = base_fee;
    header.base_reserve = base_reserve;
    header.max_tx_set_size = 100;
    header.ledger_seq = ledger_seq;
    header.total_coins = total_coins;
    header.previous_ledger_hash = previous_hash.into();
    header.bucket_list_hash = stellar_xdr::curr::Hash(GENESIS_BUCKET_LIST_HASH);
    header.scp_value.close_time = TimePoint(0);
    header
}

fn sign_envelope(
    envelope: &TransactionEnvelope,
    secret: &SecretKey,
    network_id: &NetworkId,
) -> DecoratedSignature {
    let frame = stellar_core_tx::TransactionFrame::with_network(envelope.clone(), *network_id);
    let hash = frame.hash(network_id).expect("tx hash");
    let signature = stellar_core_crypto::sign_hash(secret, &hash);
    let public_key = secret.public_key();
    let pk_bytes = public_key.as_bytes();
    let hint = SignatureHint([pk_bytes[28], pk_bytes[29], pk_bytes[30], pk_bytes[31]]);
    DecoratedSignature {
        hint,
        signature: XdrSignature(signature.0.to_vec().try_into().unwrap()),
    }
}

fn bump_sequence_envelope(
    source: &SecretKey,
    bump_to: i64,
    base_fee: u32,
    sequence: i64,
    network_id: &NetworkId,
) -> TransactionEnvelope {
    let operation = Operation {
        source_account: None,
        body: OperationBody::BumpSequence(stellar_xdr::curr::BumpSequenceOp {
            bump_to: SequenceNumber(bump_to),
        }),
    };
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*source.public_key().as_bytes())),
        fee: base_fee,
        seq_num: SequenceNumber(sequence),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![operation].try_into().unwrap(),
        ext: TransactionExt::V0,
    };
    let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });
    let decorated = sign_envelope(&envelope, source, network_id);
    if let TransactionEnvelope::Tx(ref mut env) = envelope {
        env.signatures = vec![decorated].try_into().unwrap();
    }
    envelope
}

fn payment_envelope(
    source: &SecretKey,
    destination: AccountId,
    amount: i64,
    base_fee: u32,
    sequence: i64,
    network_id: &NetworkId,
) -> TransactionEnvelope {
    let operation = Operation {
        source_account: None,
        body: OperationBody::Payment(PaymentOp {
            destination: destination.into(),
            asset: Asset::Native,
            amount,
        }),
    };
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*source.public_key().as_bytes())),
        fee: base_fee,
        seq_num: SequenceNumber(sequence),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![operation].try_into().unwrap(),
        ext: TransactionExt::V0,
    };
    let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });
    let decorated = sign_envelope(&envelope, source, network_id);
    if let TransactionEnvelope::Tx(ref mut env) = envelope {
        env.signatures = vec![decorated].try_into().unwrap();
    }
    envelope
}

fn apply_delta(entries: &mut HashMap<Vec<u8>, LedgerEntry>, delta: &LedgerDelta) {
    for change in delta.changes() {
        match change {
            stellar_core_ledger::EntryChange::Created(entry)
            | stellar_core_ledger::EntryChange::Updated { current: entry, .. } => {
                entries.insert(entry_key_bytes(entry), entry.clone());
            }
            stellar_core_ledger::EntryChange::Deleted { previous } => {
                entries.remove(&entry_key_bytes(previous));
            }
        }
    }
}

fn execute_and_apply(
    entries: &mut HashMap<Vec<u8>, LedgerEntry>,
    header: &LedgerHeader,
    network_id: NetworkId,
    base_fee: u32,
    base_reserve: u32,
    protocol_version: u32,
    envelope: TransactionEnvelope,
) -> (TransactionMeta, u64) {
    let snapshot = SnapshotBuilder::new(header.ledger_seq)
        .with_header(header.clone(), Hash256::ZERO)
        .add_entries(
            entries
                .values()
                .cloned()
                .map(|entry| (stellar_core_ledger::entry_to_key(&entry).expect("entry key"), entry)),
        )
        .expect("snapshot entries")
        .build()
        .expect("build snapshot");
    let snapshot = SnapshotHandle::new(snapshot);

    let mut delta = LedgerDelta::new(header.ledger_seq);
    let (_results, _tx_results, tx_result_metas, id_pool) = execute_transaction_set(
        &snapshot,
        &[(envelope, None)],
        header.ledger_seq,
        0,
        base_fee,
        base_reserve,
        protocol_version,
        network_id,
        &mut delta,
        SorobanConfig::default(),
        [0u8; 32],
        ClassicEventConfig::default(),
        None,
    )
    .expect("execute transaction set");

    apply_delta(entries, &delta);

    let meta: &TransactionResultMetaV1 = tx_result_metas.first().expect("tx meta");
    (meta.tx_apply_processing.clone(), id_pool)
}

fn starting_sequence_number(ledger_seq: u32) -> i64 {
    (ledger_seq as i64) << 32
}

fn base_headers(
    protocol_version: u32,
    base_fee: u32,
    base_reserve: u32,
    total_coins: i64,
) -> (LedgerHeader, LedgerHeader, LedgerHeader) {
    let genesis = genesis_header(protocol_version, base_fee, base_reserve, total_coins);
    let header2 = test_header(
        2,
        protocol_version,
        base_fee,
        base_reserve,
        total_coins,
        compute_header_hash(&genesis).expect("genesis hash"),
    );
    let header3 = test_header(
        3,
        protocol_version,
        base_fee,
        base_reserve,
        total_coins,
        compute_header_hash(&header2).expect("header2 hash"),
    );
    let header4 = test_header(
        4,
        protocol_version,
        base_fee,
        base_reserve,
        total_coins,
        compute_header_hash(&header3).expect("header3 hash"),
    );
    (header2, header3, header4)
}

fn base_entries(
    root_account_id: AccountId,
    total_coins: i64,
    base_fee: u32,
    base_reserve: u32,
    account_id: AccountId,
    account_balance: i64,
) -> HashMap<Vec<u8>, LedgerEntry> {
    let mut entries = HashMap::new();
    let create_balance = 2 * base_reserve as i64 + 1000;
    let root_balance = total_coins - (2 * create_balance + 2 * base_fee as i64);
    let (root_key, root_entry) = account_entry(root_account_id, 2, root_balance, 3);
    entries.insert(key_bytes(&root_key), root_entry);

    let account_seq = starting_sequence_number(2);
    let (account_key, account_entry) = account_entry(account_id, account_seq, account_balance, 2);
    entries.insert(key_bytes(&account_key), account_entry);

    entries
}

#[test]
fn bump_sequence_small_bump_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes("bump sequence|protocol version 25|test success|small bump");
    assert_eq!(expected.len(), 1);

    let network_id = NetworkId::from_passphrase("(V) (;,,;) (V)");
    let root_secret = SecretKey::from_seed(network_id.as_bytes());
    let root_account_id: AccountId = (&root_secret.public_key()).into();

    let account_secret = secret_from_name("A");
    let account_id: AccountId = (&account_secret.public_key()).into();

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;
    let total_coins = 1_000_000_000_000_000_000i64;
    let account_balance = 2 * base_reserve as i64 + 1000;

    let (_header2, _header3, header4) =
        base_headers(25, base_fee, base_reserve, total_coins);
    let mut entries =
        base_entries(root_account_id, total_coins, base_fee, base_reserve, account_id, account_balance);

    let account_seq = starting_sequence_number(2);
    let tx = bump_sequence_envelope(
        &account_secret,
        account_seq + 2,
        base_fee,
        account_seq + 1,
        &network_id,
    );
    let meta = execute_and_apply(
        &mut entries,
        &header4,
        network_id,
        base_fee,
        base_reserve,
        25,
        tx,
    )
    .0;

    assert_eq!(tx_meta_hash(&meta), expected[0]);
}

#[test]
fn bump_sequence_backward_jump_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected =
        load_baseline_hashes("bump sequence|protocol version 25|test success|backward jump (no-op)");
    assert_eq!(expected.len(), 1);

    let network_id = NetworkId::from_passphrase("(V) (;,,;) (V)");
    let root_secret = SecretKey::from_seed(network_id.as_bytes());
    let root_account_id: AccountId = (&root_secret.public_key()).into();

    let account_secret = secret_from_name("A");
    let account_id: AccountId = (&account_secret.public_key()).into();

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;
    let total_coins = 1_000_000_000_000_000_000i64;
    let account_balance = 2 * base_reserve as i64 + 1000;

    let (_header2, _header3, header4) =
        base_headers(25, base_fee, base_reserve, total_coins);
    let mut entries =
        base_entries(root_account_id, total_coins, base_fee, base_reserve, account_id, account_balance);

    let account_seq = starting_sequence_number(2);
    let tx = bump_sequence_envelope(
        &account_secret,
        1,
        base_fee,
        account_seq + 1,
        &network_id,
    );
    let meta = execute_and_apply(
        &mut entries,
        &header4,
        network_id,
        base_fee,
        base_reserve,
        25,
        tx,
    )
    .0;

    assert_eq!(tx_meta_hash(&meta), expected[0]);
}

#[test]
fn bump_sequence_large_bump_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected =
        load_baseline_hashes("bump sequence|protocol version 25|test success|large bump");
    assert_eq!(expected.len(), 1);

    let network_id = NetworkId::from_passphrase("(V) (;,,;) (V)");
    let root_secret = SecretKey::from_seed(network_id.as_bytes());
    let root_account_id: AccountId = (&root_secret.public_key()).into();

    let account_secret = secret_from_name("A");
    let account_id: AccountId = (&account_secret.public_key()).into();

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;
    let total_coins = 1_000_000_000_000_000_000i64;
    let account_balance = 2 * base_reserve as i64 + 1000;

    let (_header2, _header3, header4) =
        base_headers(25, base_fee, base_reserve, total_coins);
    let mut entries =
        base_entries(root_account_id, total_coins, base_fee, base_reserve, account_id, account_balance);

    let account_seq = starting_sequence_number(2);
    let tx = bump_sequence_envelope(
        &account_secret,
        i64::MAX,
        base_fee,
        account_seq + 1,
        &network_id,
    );
    let meta = execute_and_apply(
        &mut entries,
        &header4,
        network_id,
        base_fee,
        base_reserve,
        25,
        tx,
    )
    .0;

    assert_eq!(tx_meta_hash(&meta), expected[0]);
}

#[test]
fn bump_sequence_large_bump_no_more_tx_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes(
        "bump sequence|protocol version 25|test success|large bump|no more tx when INT64_MAX is reached",
    );
    assert_eq!(expected.len(), 1);

    let network_id = NetworkId::from_passphrase("(V) (;,,;) (V)");
    let root_secret = SecretKey::from_seed(network_id.as_bytes());
    let root_account_id: AccountId = (&root_secret.public_key()).into();

    let account_secret = secret_from_name("A");
    let account_id: AccountId = (&account_secret.public_key()).into();

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;
    let total_coins = 1_000_000_000_000_000_000i64;
    let account_balance = 2 * base_reserve as i64 + 1000;

    let (_header2, _header3, mut header4) =
        base_headers(25, base_fee, base_reserve, total_coins);
    let mut entries =
        base_entries(root_account_id.clone(), total_coins, base_fee, base_reserve, account_id, account_balance);

    let account_seq = starting_sequence_number(2);
    let bump_tx = bump_sequence_envelope(
        &account_secret,
        i64::MAX,
        base_fee,
        account_seq + 1,
        &network_id,
    );
    let _meta = execute_and_apply(
        &mut entries,
        &header4,
        network_id,
        base_fee,
        base_reserve,
        25,
        bump_tx,
    )
    .0;

    let header_hash = compute_header_hash(&header4).expect("header4 hash");
    header4 = test_header(
        5,
        25,
        base_fee,
        base_reserve,
        total_coins,
        header_hash,
    );
    let payment_tx = payment_envelope(
        &account_secret,
        root_account_id,
        1,
        base_fee,
        i64::MIN,
        &network_id,
    );
    let meta = execute_and_apply(
        &mut entries,
        &header4,
        network_id,
        base_fee,
        base_reserve,
        25,
        payment_tx,
    )
    .0;

    assert_eq!(tx_meta_hash(&meta), expected[0]);
}

#[test]
fn bump_sequence_bad_seq_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected =
        load_baseline_hashes("bump sequence|protocol version 25|test success|bad seq");
    assert_eq!(expected.len(), 2);

    let network_id = NetworkId::from_passphrase("(V) (;,,;) (V)");
    let root_secret = SecretKey::from_seed(network_id.as_bytes());
    let root_account_id: AccountId = (&root_secret.public_key()).into();

    let account_secret = secret_from_name("A");
    let account_id: AccountId = (&account_secret.public_key()).into();

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;
    let total_coins = 1_000_000_000_000_000_000i64;
    let account_balance = 2 * base_reserve as i64 + 1000;

    let (_header2, _header3, mut header4) =
        base_headers(25, base_fee, base_reserve, total_coins);
    let mut entries =
        base_entries(root_account_id, total_coins, base_fee, base_reserve, account_id, account_balance);

    let account_seq = starting_sequence_number(2);
    let tx1 = bump_sequence_envelope(
        &account_secret,
        -1,
        base_fee,
        account_seq + 1,
        &network_id,
    );
    let meta1 = execute_and_apply(
        &mut entries,
        &header4,
        network_id,
        base_fee,
        base_reserve,
        25,
        tx1,
    )
    .0;

    let header_hash = compute_header_hash(&header4).expect("header4 hash");
    header4 = test_header(
        5,
        25,
        base_fee,
        base_reserve,
        total_coins,
        header_hash,
    );
    let tx2 = bump_sequence_envelope(
        &account_secret,
        i64::MIN,
        base_fee,
        account_seq + 2,
        &network_id,
    );
    let meta2 = execute_and_apply(
        &mut entries,
        &header4,
        network_id,
        base_fee,
        base_reserve,
        25,
        tx2,
    )
    .0;

    let got = vec![tx_meta_hash(&meta1), tx_meta_hash(&meta2)];
    assert_eq!(got, expected);
}

#[test]
fn bump_sequence_starting_sequence_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes(
        "bump sequence|protocol version 25|seqnum equals starting sequence",
    );
    assert_eq!(expected.len(), 2);

    let network_id = NetworkId::from_passphrase("(V) (;,,;) (V)");
    let root_secret = SecretKey::from_seed(network_id.as_bytes());
    let root_account_id: AccountId = (&root_secret.public_key()).into();

    let account_secret = secret_from_name("A");
    let account_id: AccountId = (&account_secret.public_key()).into();

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;
    let total_coins = 1_000_000_000_000_000_000i64;
    let account_balance = 2 * base_reserve as i64 + 1000;

    let (_header2, header3, mut header4) =
        base_headers(25, base_fee, base_reserve, total_coins);
    let mut entries =
        base_entries(root_account_id.clone(), total_coins, base_fee, base_reserve, account_id, account_balance);

    let current_ledger = header3.ledger_seq;
    let new_seq = starting_sequence_number(current_ledger + 2) - 1;
    let account_seq = starting_sequence_number(2);
    let bump_tx = bump_sequence_envelope(
        &account_secret,
        new_seq,
        base_fee,
        account_seq + 1,
        &network_id,
    );
    let meta1 = execute_and_apply(
        &mut entries,
        &header4,
        network_id,
        base_fee,
        base_reserve,
        25,
        bump_tx,
    )
    .0;

    let header_hash = compute_header_hash(&header4).expect("header4 hash");
    header4 = test_header(
        5,
        25,
        base_fee,
        base_reserve,
        total_coins,
        header_hash,
    );
    let payment_tx = payment_envelope(
        &account_secret,
        root_account_id,
        1,
        base_fee,
        new_seq + 1,
        &network_id,
    );
    let meta2 = execute_and_apply(
        &mut entries,
        &header4,
        network_id,
        base_fee,
        base_reserve,
        25,
        payment_tx,
    )
    .0;

    let got = vec![tx_meta_hash(&meta1), tx_meta_hash(&meta2)];
    assert_eq!(got, expected);
}
