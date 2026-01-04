use std::fs;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use stellar_core_common::{normalize_transaction_meta, Hash256, NetworkId};
use stellar_core_crypto::{seed, xdr_compute_hash, SecretKey};
use stellar_core_ledger::execution::execute_transaction_set;
use stellar_core_ledger::{compute_header_hash, LedgerDelta, SnapshotBuilder, SnapshotHandle};
use stellar_core_tx::{soroban::SorobanConfig, ClassicEventConfig};
use stellar_core_tx::state::update_account_seq_info;
use stellar_xdr::curr::{
    AccountEntry, AccountEntryExt, AccountId, LedgerEntry, LedgerEntryData, LedgerEntryExt,
    LedgerHeader, LedgerKey, LedgerKeyAccount, MuxedAccount, Operation, OperationBody, Preconditions,
    SignatureHint, Signature as XdrSignature, String32, Thresholds, TimePoint, Transaction,
    TransactionEnvelope, TransactionExt, TransactionMeta, TransactionResultMetaV1,
    TransactionV1Envelope, Uint256, VecM, WriteXdr, Asset, AssetCode4, AlphaNum4, Price, PublicKey,
};

const GENESIS_BUCKET_LIST_HASH: [u8; 32] = hex_literal::hex!(
    "4e6a8404d33b17eee7031af0b3606b6af8e36fe5a3bff59e4e5e420bd0ad3bf4"
);

fn baseline_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/tx-meta-baseline-current/CreateAccountTests.json")
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
        .unwrap_or_default()
}

fn entry_key_bytes(entry: &LedgerEntry) -> Vec<u8> {
    let key = stellar_core_ledger::entry_to_key(entry).expect("entry key");
    key_bytes(&key)
}

fn account_seq(entries: &std::collections::HashMap<Vec<u8>, LedgerEntry>, account_id: &AccountId) -> i64 {
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
            seq_num: stellar_xdr::curr::SequenceNumber(seq_num),
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

fn execute_create_account(
    snapshot: &SnapshotHandle,
    network_id: NetworkId,
    base_fee: u32,
    base_reserve: u32,
    ledger_seq: u32,
    source: &SecretKey,
    destination: AccountId,
    starting_balance: i64,
    sequence: i64,
) -> TransactionMeta {
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
        seq_num: stellar_xdr::curr::SequenceNumber(sequence),
        cond: Preconditions::None,
        memo: stellar_xdr::curr::Memo::None,
        operations: vec![operation].try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });
    let decorated = sign_envelope(&envelope, source, &network_id);
    if let TransactionEnvelope::Tx(ref mut env) = envelope {
        env.signatures = vec![decorated].try_into().unwrap();
    }

    let mut delta = LedgerDelta::new(ledger_seq);
    let (_results, _tx_results, tx_result_metas, _id_pool) = execute_transaction_set(
        snapshot,
        &[(envelope, None)],
        ledger_seq,
        0,
        base_fee,
        base_reserve,
        25,
        network_id,
        &mut delta,
        SorobanConfig::default(),
        [0u8; 32],
        ClassicEventConfig::default(),
        None,
    )
    .expect("execute transaction set");

    let meta: &TransactionResultMetaV1 = tx_result_metas.first().expect("tx meta");
    meta.tx_apply_processing.clone()
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
        seq_num: stellar_xdr::curr::SequenceNumber(sequence),
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
        body: OperationBody::Payment(stellar_xdr::curr::PaymentOp {
            destination: muxed_from_account_id(&destination),
            asset: Asset::Native,
            amount,
        }),
    };

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*source.public_key().as_bytes())),
        fee: base_fee,
        seq_num: stellar_xdr::curr::SequenceNumber(sequence),
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

fn manage_sell_offer_envelope(
    source: &SecretKey,
    selling: Asset,
    buying: Asset,
    amount: i64,
    price: Price,
    base_fee: u32,
    sequence: i64,
    network_id: &NetworkId,
) -> TransactionEnvelope {
    let operation = Operation {
        source_account: None,
        body: OperationBody::ManageSellOffer(stellar_xdr::curr::ManageSellOfferOp {
            selling,
            buying,
            amount,
            price,
            offer_id: 0,
        }),
    };

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*source.public_key().as_bytes())),
        fee: base_fee,
        seq_num: stellar_xdr::curr::SequenceNumber(sequence),
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

fn credit_asset(code: &[u8; 4], issuer: &AccountId) -> Asset {
    Asset::CreditAlphanum4(AlphaNum4 {
        asset_code: AssetCode4(*code),
        issuer: issuer.clone(),
    })
}

fn apply_delta(entries: &mut std::collections::HashMap<Vec<u8>, LedgerEntry>, delta: &LedgerDelta) {
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
    entries: &mut std::collections::HashMap<Vec<u8>, LedgerEntry>,
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

#[test]
fn create_account_low_reserve_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes(
        "create account|protocol version 25|Amount too small to create account",
    );
    assert_eq!(expected.len(), 1);

    let network_id = NetworkId::from_passphrase("(V) (;,,;) (V)");
    let root_secret = SecretKey::from_seed(network_id.as_bytes());
    let root_account_id: AccountId = (&root_secret.public_key()).into();

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;
    let total_coins = 1_000_000_000_000_000_000i64;
    let ledger_seq = 2u32;

    let genesis = genesis_header(25, base_fee, base_reserve, total_coins);
    let genesis_hash = compute_header_hash(&genesis).expect("genesis hash");

    let (root_key, root_entry) = account_entry(
        root_account_id.clone(),
        0,
        total_coins,
        ledger_seq - 1,
    );
    let header = test_header(
        ledger_seq,
        25,
        base_fee,
        base_reserve,
        total_coins,
        genesis_hash,
    );
    let snapshot = SnapshotBuilder::new(ledger_seq)
        .with_header(header, Hash256::ZERO)
        .add_entry(root_key, root_entry)
        .expect("add root")
        .build()
        .expect("build snapshot");
    let snapshot = SnapshotHandle::new(snapshot);

    let dest_secret = secret_from_name("B");
    let destination: AccountId = (&dest_secret.public_key()).into();
    let min_balance = 2i64 * base_reserve as i64;
    let starting_balance = min_balance - 1;

    let meta = execute_create_account(
        &snapshot,
        network_id,
        base_fee,
        base_reserve,
        ledger_seq,
        &root_secret,
        destination,
        starting_balance,
        1,
    );
    let got = tx_meta_hash(&meta);

    assert_eq!(got, expected[0]);
}

#[test]
fn create_account_success_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected =
        load_baseline_hashes("create account|protocol version 25|Success");
    assert_eq!(expected.len(), 1);

    let network_id = NetworkId::from_passphrase("(V) (;,,;) (V)");
    let root_secret = SecretKey::from_seed(network_id.as_bytes());
    let root_account_id: AccountId = (&root_secret.public_key()).into();

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;
    let total_coins = 1_000_000_000_000_000_000i64;
    let ledger_seq = 2u32;

    let genesis = genesis_header(25, base_fee, base_reserve, total_coins);
    let genesis_hash = compute_header_hash(&genesis).expect("genesis hash");

    let (root_key, root_entry) = account_entry(
        root_account_id.clone(),
        0,
        total_coins,
        ledger_seq - 1,
    );
    let header = test_header(
        ledger_seq,
        25,
        base_fee,
        base_reserve,
        total_coins,
        genesis_hash,
    );
    let snapshot = SnapshotBuilder::new(ledger_seq)
        .with_header(header, Hash256::ZERO)
        .add_entry(root_key, root_entry)
        .expect("add root")
        .build()
        .expect("build snapshot");
    let snapshot = SnapshotHandle::new(snapshot);

    let dest_secret = secret_from_name("B");
    let destination: AccountId = (&dest_secret.public_key()).into();
    let min_balance = 2i64 * base_reserve as i64;

    let meta = execute_create_account(
        &snapshot,
        network_id,
        base_fee,
        base_reserve,
        ledger_seq,
        &root_secret,
        destination,
        min_balance,
        1,
    );
    let got = tx_meta_hash(&meta);

    assert_eq!(got, expected[0]);
}

#[test]
fn create_account_already_exists_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected =
        load_baseline_hashes("create account|protocol version 25|Success|Account already exists");
    assert_eq!(expected.len(), 1);

    let network_id = NetworkId::from_passphrase("(V) (;,,;) (V)");
    let root_secret = SecretKey::from_seed(network_id.as_bytes());
    let root_account_id: AccountId = (&root_secret.public_key()).into();

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;
    let total_coins = 1_000_000_000_000_000_000i64;

    let ledger_seq = 3u32;
    let prev_ledger_seq = ledger_seq - 1;

    let genesis = genesis_header(25, base_fee, base_reserve, total_coins);
    let genesis_hash = compute_header_hash(&genesis).expect("genesis hash");
    let prev_header = test_header(
        prev_ledger_seq,
        25,
        base_fee,
        base_reserve,
        total_coins,
        genesis_hash,
    );
    let prev_hash = compute_header_hash(&prev_header).expect("prev hash");

    let min_balance = 2i64 * base_reserve as i64;
    let root_balance = total_coins - min_balance - base_fee as i64;

    let (root_key, mut root_entry) = account_entry(
        root_account_id.clone(),
        1,
        root_balance,
        prev_ledger_seq,
    );
    if let LedgerEntryData::Account(account) = &mut root_entry.data {
        update_account_seq_info(account, prev_ledger_seq, 0);
    }

    let dest_secret = secret_from_name("B");
    let destination: AccountId = (&dest_secret.public_key()).into();
    let (dest_key, dest_entry) = account_entry(
        destination.clone(),
        (prev_ledger_seq as i64) << 32,
        min_balance,
        prev_ledger_seq,
    );

    let header = test_header(
        ledger_seq,
        25,
        base_fee,
        base_reserve,
        total_coins,
        prev_hash,
    );
    let snapshot = SnapshotBuilder::new(ledger_seq)
        .with_header(header, Hash256::ZERO)
        .add_entry(root_key, root_entry)
        .expect("add root")
        .add_entry(dest_key, dest_entry)
        .expect("add dest")
        .build()
        .expect("build snapshot");
    let snapshot = SnapshotHandle::new(snapshot);

    let meta = execute_create_account(
        &snapshot,
        network_id,
        base_fee,
        base_reserve,
        ledger_seq,
        &root_secret,
        destination,
        min_balance,
        2,
    );
    let got = tx_meta_hash(&meta);

    assert_eq!(got, expected[0]);
}

#[test]
fn create_account_not_enough_funds_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected =
        load_baseline_hashes("create account|protocol version 25|Not enough funds (source)");
    assert_eq!(expected.len(), 2);

    let network_id = NetworkId::from_passphrase("(V) (;,,;) (V)");
    let root_secret = SecretKey::from_seed(network_id.as_bytes());
    let root_account_id: AccountId = (&root_secret.public_key()).into();

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;
    let total_coins = 1_000_000_000_000_000_000i64;

    let min_balance2 = (2 + 2) as i64 * base_reserve as i64;
    let gateway_payment = min_balance2 + 10 * base_fee as i64 + 1;

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

    let gateway_secret = secret_from_name("gate");
    let gateway_id: AccountId = (&gateway_secret.public_key()).into();

    let tx1 = create_account_envelope(
        &root_secret,
        gateway_id.clone(),
        gateway_payment,
        base_fee,
        1,
        &network_id,
    );
    let meta1 = execute_and_apply(
        &mut entries,
        &header,
        network_id,
        base_fee,
        base_reserve,
        25,
        tx1,
    )
    .0;

    let header_hash = compute_header_hash(&header).expect("header hash");
    header = test_header(
        3,
        25,
        base_fee,
        base_reserve,
        total_coins,
        header_hash,
    );

    let gateway_entry = entries
        .get(&key_bytes(&LedgerKey::Account(LedgerKeyAccount {
            account_id: gateway_id.clone(),
        })))
        .expect("gateway entry");
    let gateway_seq = match &gateway_entry.data {
        LedgerEntryData::Account(account) => account.seq_num.0,
        _ => panic!("gateway entry not account"),
    };

    let dest_secret = secret_from_name("B");
    let destination: AccountId = (&dest_secret.public_key()).into();
    let tx2 = create_account_envelope(
        &gateway_secret,
        destination,
        gateway_payment,
        base_fee,
        gateway_seq + 1,
        &network_id,
    );
    let meta2 = execute_and_apply(
        &mut entries,
        &header,
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
fn create_account_with_native_selling_liabilities_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected =
        load_baseline_hashes("create account|protocol version 25|with native selling liabilities");
    assert_eq!(expected.len(), 5);

    let network_id = NetworkId::from_passphrase("(V) (;,,;) (V)");
    let root_secret = SecretKey::from_seed(network_id.as_bytes());
    let root_account_id: AccountId = (&root_secret.public_key()).into();

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;
    let total_coins = 1_000_000_000_000_000_000i64;

    let min_balance0 = 2i64 * base_reserve as i64;
    let min_balance3 = 5i64 * base_reserve as i64;
    let acc1_balance = min_balance3 + 2 * base_fee as i64 + 500;

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

    let acc1_secret = secret_from_name("acc1");
    let acc1_id: AccountId = (&acc1_secret.public_key()).into();
    let tx1 = create_account_envelope(
        &root_secret,
        acc1_id.clone(),
        acc1_balance,
        base_fee,
        1,
        &network_id,
    );
    let meta1 = execute_and_apply(
        &mut entries,
        &header,
        network_id,
        base_fee,
        base_reserve,
        25,
        tx1,
    )
    .0;

    let header_hash = compute_header_hash(&header).expect("header hash");
    header = test_header(3, 25, base_fee, base_reserve, total_coins, header_hash);

    let cur1 = credit_asset(b"CUR1", &acc1_id);
    let tx2 = manage_sell_offer_envelope(
        &acc1_secret,
        Asset::Native,
        cur1.clone(),
        500,
        Price { n: 1, d: 1 },
        base_fee,
        account_seq(&entries, &acc1_id) + 1,
        &network_id,
    );
    let meta2 = execute_and_apply(
        &mut entries,
        &header,
        network_id,
        base_fee,
        base_reserve,
        25,
        tx2,
    )
    .0;

    let header_hash = compute_header_hash(&header).expect("header hash");
    header = test_header(4, 25, base_fee, base_reserve, total_coins, header_hash);

    let acc2_secret = secret_from_name("acc2");
    let acc2_id: AccountId = (&acc2_secret.public_key()).into();
    let tx3 = create_account_envelope(
        &acc1_secret,
        acc2_id.clone(),
        min_balance0 + 1,
        base_fee,
        account_seq(&entries, &acc1_id) + 1,
        &network_id,
    );
    let meta3 = execute_and_apply(
        &mut entries,
        &header,
        network_id,
        base_fee,
        base_reserve,
        25,
        tx3,
    )
    .0;

    let header_hash = compute_header_hash(&header).expect("header hash");
    header = test_header(5, 25, base_fee, base_reserve, total_coins, header_hash);

    let tx4 = payment_envelope(
        &root_secret,
        acc1_id.clone(),
        base_fee as i64,
        base_fee,
        account_seq(&entries, &root_account_id) + 1,
        &network_id,
    );
    let meta4 = execute_and_apply(
        &mut entries,
        &header,
        network_id,
        base_fee,
        base_reserve,
        25,
        tx4,
    )
    .0;

    let header_hash = compute_header_hash(&header).expect("header hash");
    header = test_header(6, 25, base_fee, base_reserve, total_coins, header_hash);

    let tx5 = create_account_envelope(
        &acc1_secret,
        acc2_id,
        min_balance0,
        base_fee,
        account_seq(&entries, &acc1_id) + 1,
        &network_id,
    );
    let meta5 = execute_and_apply(
        &mut entries,
        &header,
        network_id,
        base_fee,
        base_reserve,
        25,
        tx5,
    )
    .0;

    let got = vec![
        tx_meta_hash(&meta1),
        tx_meta_hash(&meta2),
        tx_meta_hash(&meta3),
        tx_meta_hash(&meta4),
        tx_meta_hash(&meta5),
    ];
    assert_eq!(got, expected);
}

#[test]
fn create_account_with_native_buying_liabilities_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected =
        load_baseline_hashes("create account|protocol version 25|with native buying liabilities");
    assert_eq!(expected.len(), 3);

    let network_id = NetworkId::from_passphrase("(V) (;,,;) (V)");
    let root_secret = SecretKey::from_seed(network_id.as_bytes());
    let root_account_id: AccountId = (&root_secret.public_key()).into();

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;
    let total_coins = 1_000_000_000_000_000_000i64;

    let min_balance0 = 2i64 * base_reserve as i64;
    let min_balance3 = 5i64 * base_reserve as i64;
    let acc1_balance = min_balance3 + 2 * base_fee as i64 + 500;

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

    let acc1_secret = secret_from_name("acc1");
    let acc1_id: AccountId = (&acc1_secret.public_key()).into();
    let tx1 = create_account_envelope(
        &root_secret,
        acc1_id.clone(),
        acc1_balance,
        base_fee,
        1,
        &network_id,
    );
    let meta1 = execute_and_apply(
        &mut entries,
        &header,
        network_id,
        base_fee,
        base_reserve,
        25,
        tx1,
    )
    .0;

    let header_hash = compute_header_hash(&header).expect("header hash");
    header = test_header(3, 25, base_fee, base_reserve, total_coins, header_hash);

    let cur1 = credit_asset(b"CUR1", &acc1_id);
    let tx2 = manage_sell_offer_envelope(
        &acc1_secret,
        cur1.clone(),
        Asset::Native,
        500,
        Price { n: 1, d: 1 },
        base_fee,
        account_seq(&entries, &acc1_id) + 1,
        &network_id,
    );
    let meta2 = execute_and_apply(
        &mut entries,
        &header,
        network_id,
        base_fee,
        base_reserve,
        25,
        tx2,
    )
    .0;

    let header_hash = compute_header_hash(&header).expect("header hash");
    header = test_header(4, 25, base_fee, base_reserve, total_coins, header_hash);

    let acc2_secret = secret_from_name("acc2");
    let acc2_id: AccountId = (&acc2_secret.public_key()).into();
    let tx3 = create_account_envelope(
        &acc1_secret,
        acc2_id,
        min_balance0 + 500,
        base_fee,
        account_seq(&entries, &acc1_id) + 1,
        &network_id,
    );
    let meta3 = execute_and_apply(
        &mut entries,
        &header,
        network_id,
        base_fee,
        base_reserve,
        25,
        tx3,
    )
    .0;

    let got = vec![tx_meta_hash(&meta1), tx_meta_hash(&meta2), tx_meta_hash(&meta3)];
    assert_eq!(got, expected);
}
