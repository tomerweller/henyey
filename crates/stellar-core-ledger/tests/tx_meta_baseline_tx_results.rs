use std::fs;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use stellar_core_common::{normalize_transaction_meta, Hash256, NetworkId};
use stellar_core_crypto::{seed, xdr_compute_hash, SecretKey};
use stellar_core_ledger::execution::execute_transaction_set;
use stellar_core_ledger::{compute_header_hash, entry_to_key, LedgerDelta, SnapshotBuilder, SnapshotHandle};
use stellar_core_tx::{ClassicEventConfig, soroban::SorobanConfig};
use stellar_xdr::curr::{
    AccountEntry, AccountEntryExt, AccountId, LedgerEntry, LedgerEntryData, LedgerEntryExt,
    LedgerHeader, LedgerKey, LedgerKeyAccount, MuxedAccount, Operation, OperationBody,
    Preconditions, SequenceNumber, Signature as XdrSignature, SignatureHint, String32,
    Thresholds, TimePoint, Transaction, TransactionEnvelope, TransactionExt, TransactionMeta,
    TransactionResultMetaV1, TransactionV1Envelope, Uint256, VecM, WriteXdr, Limits, Asset,
    PaymentOp, PublicKey,
};

const GENESIS_BUCKET_LIST_HASH: [u8; 32] = hex_literal::hex!(
    "4e6a8404d33b17eee7031af0b3606b6af8e36fe5a3bff59e4e5e420bd0ad3bf4"
);
const TEST_CLOSE_TIME: u64 = 1_451_606_400;

fn baseline_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/tx-meta-baseline-current/TxResultsTests.json")
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
    key.to_xdr(Limits::none())
        .unwrap_or_default()
}

fn muxed_from_account_id(account_id: &AccountId) -> MuxedAccount {
    match &account_id.0 {
        PublicKey::PublicKeyTypeEd25519(pk) => MuxedAccount::Ed25519(pk.clone()),
    }
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
    header.scp_value.close_time = TimePoint(TEST_CLOSE_TIME);
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
    header.scp_value.close_time = TimePoint(TEST_CLOSE_TIME);
    header
}

fn advance_header(header: &LedgerHeader, total_coins: i64) -> LedgerHeader {
    let header_hash = compute_header_hash(header).expect("header hash");
    test_header(
        header.ledger_seq + 1,
        header.ledger_version,
        header.base_fee,
        header.base_reserve,
        total_coins,
        header_hash,
    )
}

fn sign_envelope(
    envelope: &TransactionEnvelope,
    secret: &SecretKey,
    network_id: &NetworkId,
) -> stellar_xdr::curr::DecoratedSignature {
    let frame = stellar_core_tx::TransactionFrame::with_network(envelope.clone(), *network_id);
    let hash = frame.hash(network_id).expect("tx hash");
    let signature = stellar_core_crypto::sign_hash(secret, &hash);
    let public_key = secret.public_key();
    let pk_bytes = public_key.as_bytes();
    let hint = SignatureHint([pk_bytes[28], pk_bytes[29], pk_bytes[30], pk_bytes[31]]);
    stellar_xdr::curr::DecoratedSignature {
        hint,
        signature: XdrSignature(signature.0.to_vec().try_into().unwrap()),
    }
}

fn create_account_envelope(
    source: &SecretKey,
    destination: AccountId,
    starting_balance: i64,
    base_fee: u32,
    sequence: i64,
    network_id: &NetworkId,
) -> TransactionEnvelope {
    let operation = Operation {
        source_account: None,
        body: OperationBody::CreateAccount(stellar_xdr::curr::CreateAccountOp {
            destination,
            starting_balance,
        }),
    };

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*source.public_key().as_bytes())),
        fee: base_fee,
        seq_num: SequenceNumber(sequence),
        cond: Preconditions::None,
        memo: stellar_xdr::curr::Memo::None,
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

fn create_account_with_payment_after_envelope(
    root: &SecretKey,
    secondary: &SecretKey,
    destination: AccountId,
    payment_destination: AccountId,
    starting_balance: i64,
    payment_amount: i64,
    base_fee: u32,
    sequence: i64,
    network_id: &NetworkId,
) -> TransactionEnvelope {
    let create_op = Operation {
        source_account: None,
        body: OperationBody::CreateAccount(stellar_xdr::curr::CreateAccountOp {
            destination,
            starting_balance,
        }),
    };
    let payment_source = MuxedAccount::Ed25519(Uint256(*secondary.public_key().as_bytes()));
    let payment_op = Operation {
        source_account: Some(payment_source),
        body: OperationBody::Payment(PaymentOp {
            destination: muxed_from_account_id(&payment_destination),
            asset: Asset::Native,
            amount: payment_amount,
        }),
    };

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*root.public_key().as_bytes())),
        fee: base_fee * 2,
        seq_num: SequenceNumber(sequence),
        cond: Preconditions::None,
        memo: stellar_xdr::curr::Memo::None,
        operations: vec![create_op, payment_op].try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });
    let root_sig = sign_envelope(&envelope, root, network_id);
    let secondary_sig = sign_envelope(&envelope, secondary, network_id);
    if let TransactionEnvelope::Tx(ref mut env) = envelope {
        env.signatures = vec![root_sig, secondary_sig].try_into().unwrap();
    }
    envelope
}

fn apply_delta(entries: &mut std::collections::HashMap<Vec<u8>, LedgerEntry>, delta: &LedgerDelta) {
    for change in delta.changes() {
        match change {
            stellar_core_ledger::EntryChange::Created(entry)
            | stellar_core_ledger::EntryChange::Updated { current: entry, .. } => {
                let key = entry_to_key(entry).expect("entry key");
                entries.insert(key_bytes(&key), entry.clone());
            }
            stellar_core_ledger::EntryChange::Deleted { previous } => {
                let key = entry_to_key(previous).expect("entry key");
                entries.remove(&key_bytes(&key));
            }
        }
    }
}

fn execute_and_apply(
    entries: &mut std::collections::HashMap<Vec<u8>, LedgerEntry>,
    header: &LedgerHeader,
    network_id: NetworkId,
    base_fee: u32,
    base_reserve: u32,
    protocol_version: u32,
    envelope: TransactionEnvelope,
) -> TransactionMeta {
    let snapshot = SnapshotBuilder::new(header.ledger_seq)
        .with_header(header.clone(), Hash256::ZERO)
        .add_entries(
            entries
                .values()
                .cloned()
                .map(|entry| (entry_to_key(&entry).expect("entry key"), entry)),
        )
        .expect("snapshot entries")
        .build()
        .expect("build snapshot");
    let snapshot = SnapshotHandle::new(snapshot);

    let mut delta = LedgerDelta::new(header.ledger_seq);
    let (_results, _tx_results, tx_result_metas, _id_pool) = execute_transaction_set(
        &snapshot,
        &[(envelope, None)],
        header.ledger_seq,
        header.scp_value.close_time.0,
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
    meta.tx_apply_processing.clone()
}

fn account_seq(
    entries: &std::collections::HashMap<Vec<u8>, LedgerEntry>,
    account_id: &AccountId,
) -> i64 {
    let entry = entries
        .get(&key_bytes(&LedgerKey::Account(LedgerKeyAccount {
            account_id: account_id.clone(),
        })))
        .expect("account entry");
    match &entry.data {
        LedgerEntryData::Account(account) => account.seq_num.0,
        _ => panic!("entry is not account"),
    }
}

#[test]
fn txresults_create_account_normal_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes("txresults|protocol version 25|create account|normal");
    assert_eq!(expected.len(), 1);

    let network_id = NetworkId::from_passphrase("(V) (;,,;) (V)");
    let root_secret = SecretKey::from_seed(network_id.as_bytes());
    let root_account_id: AccountId = (&root_secret.public_key()).into();

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;
    let total_coins = 1_000_000_000_000_000_000i64;
    let start_amount = base_reserve as i64 * 100;
    let min_balance0 = 2i64 * base_reserve as i64;

    let genesis = genesis_header(25, base_fee, base_reserve, total_coins);
    let mut header = test_header(
        2,
        25,
        base_fee,
        base_reserve,
        total_coins,
        compute_header_hash(&genesis).expect("genesis hash"),
    );

    let (root_key, root_entry) = account_entry(
        root_account_id.clone(),
        0,
        total_coins,
        header.ledger_seq - 1,
    );
    let mut entries = std::collections::HashMap::new();
    entries.insert(key_bytes(&root_key), root_entry);

    for name in ["a", "b", "c", "d", "e"] {
        header = advance_header(&header, total_coins);
        let dest = secret_from_name(name);
        let dest_id: AccountId = (&dest.public_key()).into();
        let root_seq = account_seq(&entries, &root_account_id);
        let tx = create_account_envelope(
            &root_secret,
            dest_id,
            start_amount,
            base_fee,
            root_seq + 1,
            &network_id,
        );
        execute_and_apply(&mut entries, &header, network_id, base_fee, base_reserve, 25, tx);
    }

    header = advance_header(&header, total_coins);
    let g_secret = secret_from_name("g");
    let g_id: AccountId = (&g_secret.public_key()).into();
    let root_seq = account_seq(&entries, &root_account_id);
    let tx_g = create_account_envelope(
        &root_secret,
        g_id,
        min_balance0,
        base_fee,
        root_seq + 1,
        &network_id,
    );
    execute_and_apply(&mut entries, &header, network_id, base_fee, base_reserve, 25, tx_g);

    header = advance_header(&header, total_coins);
    let f_secret = secret_from_name("f");
    let f_id: AccountId = (&f_secret.public_key()).into();
    let root_seq = account_seq(&entries, &root_account_id);
    let tx_f = create_account_envelope(
        &root_secret,
        f_id,
        start_amount,
        base_fee,
        root_seq + 1,
        &network_id,
    );
    let meta = execute_and_apply(
        &mut entries,
        &header,
        network_id,
        base_fee,
        base_reserve,
        25,
        tx_f,
    );

    let got = tx_meta_hash(&meta);
    assert_eq!(got, expected[0]);
}

#[test]
fn txresults_create_account_with_payment_after_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes("txresults|protocol version 25|create account|with payment after");
    assert_eq!(expected.len(), 1);

    let network_id = NetworkId::from_passphrase("(V) (;,,;) (V)");
    let root_secret = SecretKey::from_seed(network_id.as_bytes());
    let root_account_id: AccountId = (&root_secret.public_key()).into();

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;
    let total_coins = 1_000_000_000_000_000_000i64;
    let start_amount = base_reserve as i64 * 100;
    let min_balance0 = 2i64 * base_reserve as i64;

    let genesis = genesis_header(25, base_fee, base_reserve, total_coins);
    let mut header = test_header(
        2,
        25,
        base_fee,
        base_reserve,
        total_coins,
        compute_header_hash(&genesis).expect("genesis hash"),
    );

    let (root_key, root_entry) = account_entry(
        root_account_id.clone(),
        0,
        total_coins,
        header.ledger_seq - 1,
    );
    let mut entries = std::collections::HashMap::new();
    entries.insert(key_bytes(&root_key), root_entry);

    for name in ["a", "b", "c", "d", "e"] {
        header = advance_header(&header, total_coins);
        let dest = secret_from_name(name);
        let dest_id: AccountId = (&dest.public_key()).into();
        let root_seq = account_seq(&entries, &root_account_id);
        let tx = create_account_envelope(
            &root_secret,
            dest_id,
            start_amount,
            base_fee,
            root_seq + 1,
            &network_id,
        );
        execute_and_apply(&mut entries, &header, network_id, base_fee, base_reserve, 25, tx);
    }

    header = advance_header(&header, total_coins);
    let g_secret = secret_from_name("g");
    let g_id: AccountId = (&g_secret.public_key()).into();
    let root_seq = account_seq(&entries, &root_account_id);
    let tx_g = create_account_envelope(
        &root_secret,
        g_id,
        min_balance0,
        base_fee,
        root_seq + 1,
        &network_id,
    );
    execute_and_apply(&mut entries, &header, network_id, base_fee, base_reserve, 25, tx_g);

    header = advance_header(&header, total_coins);
    let f_secret = secret_from_name("f");
    let f_id: AccountId = (&f_secret.public_key()).into();
    let a_secret = secret_from_name("a");
    let root_seq = account_seq(&entries, &root_account_id);
    let tx = create_account_with_payment_after_envelope(
        &root_secret,
        &a_secret,
        f_id,
        root_account_id,
        start_amount,
        start_amount / 2,
        base_fee,
        root_seq + 1,
        &network_id,
    );
    let meta = execute_and_apply(&mut entries, &header, network_id, base_fee, base_reserve, 25, tx);

    let got = tx_meta_hash(&meta);
    assert_eq!(got, expected[0]);
}
