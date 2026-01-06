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
    AccountEntry, AccountEntryExt, AccountId, Asset, LedgerEntry, LedgerEntryData, LedgerEntryExt,
    LedgerHeader, LedgerKey, LedgerKeyAccount, MuxedAccount, Operation, OperationBody,
    PaymentOp, Preconditions, PublicKey, SequenceNumber, Signature as XdrSignature, SignatureHint,
    String32, Thresholds, TimePoint, Transaction, TransactionEnvelope, TransactionExt,
    TransactionMeta, TransactionResultMetaV1, TransactionV1Envelope, Uint256, VecM, WriteXdr, Limits,
};

const GENESIS_BUCKET_LIST_HASH: [u8; 32] = hex_literal::hex!(
    "4e6a8404d33b17eee7031af0b3606b6af8e36fe5a3bff59e4e5e420bd0ad3bf4"
);

fn baseline_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/tx-meta-baseline-current/PaymentTests.json")
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

fn entry_key_bytes(entry: &LedgerEntry) -> Vec<u8> {
    let key = entry_to_key(entry).expect("entry key");
    key_bytes(&key)
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

fn genesis_header(
    ledger_version: u32,
    base_fee: u32,
    base_reserve: u32,
    total_coins: i64,
) -> LedgerHeader {
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

fn payment_envelope(
    source: &SecretKey,
    destination: &AccountId,
    amount: i64,
    base_fee: u32,
    sequence: i64,
    network_id: &NetworkId,
) -> TransactionEnvelope {
    let operation = Operation {
        source_account: None,
        body: OperationBody::Payment(PaymentOp {
            destination: muxed_from_account_id(destination),
            asset: Asset::Native,
            amount,
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
                .map(|entry| (entry_to_key(&entry).expect("entry key"), entry)),
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

struct PaymentWorld {
    entries: std::collections::HashMap<Vec<u8>, LedgerEntry>,
    header: LedgerHeader,
    network_id: NetworkId,
    root_secret: SecretKey,
    root_account_id: AccountId,
    a1_id: AccountId,
}

struct PaymentFeeWorld {
    entries: std::collections::HashMap<Vec<u8>, LedgerEntry>,
    header: LedgerHeader,
    network_id: NetworkId,
    root_account_id: AccountId,
    pay_from_secret: SecretKey,
    pay_from_id: AccountId,
    create_meta: TransactionMeta,
}

fn setup_payment_world() -> PaymentWorld {
    let network_id = NetworkId::from_passphrase("(V) (;,,;) (V)");
    let root_secret = SecretKey::from_seed(network_id.as_bytes());
    let root_account_id: AccountId = (&root_secret.public_key()).into();

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;
    let total_coins = 1_000_000_000_000_000_000i64;

    let min_balance2 = (2 + 2) as i64 * base_reserve as i64 + 10 * base_fee as i64;
    let payment_amount = min_balance2;
    let more_payment = payment_amount / 2;
    let gateway_payment = min_balance2 + more_payment;

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

    let a1_secret = secret_from_name("A");
    let a1_id: AccountId = (&a1_secret.public_key()).into();
    let gate_secret = secret_from_name("gate");
    let gate_id: AccountId = (&gate_secret.public_key()).into();
    let gate2_secret = secret_from_name("gate2");
    let gate2_id: AccountId = (&gate2_secret.public_key()).into();

    let root_seq = account_seq(&entries, &root_account_id);
    let tx_a1 = create_account_envelope(
        &root_secret,
        a1_id.clone(),
        payment_amount,
        base_fee,
        root_seq + 1,
        &network_id,
    );
    execute_and_apply(&mut entries, &header, network_id, base_fee, base_reserve, 25, tx_a1);
    header = advance_header(&header, total_coins);

    let root_seq = account_seq(&entries, &root_account_id);
    let tx_gate = create_account_envelope(
        &root_secret,
        gate_id,
        gateway_payment,
        base_fee,
        root_seq + 1,
        &network_id,
    );
    execute_and_apply(&mut entries, &header, network_id, base_fee, base_reserve, 25, tx_gate);
    header = advance_header(&header, total_coins);

    let root_seq = account_seq(&entries, &root_account_id);
    let tx_gate2 = create_account_envelope(
        &root_secret,
        gate2_id,
        gateway_payment,
        base_fee,
        root_seq + 1,
        &network_id,
    );
    execute_and_apply(&mut entries, &header, network_id, base_fee, base_reserve, 25, tx_gate2);
    header = advance_header(&header, total_coins);

    PaymentWorld {
        entries,
        header,
        network_id,
        root_secret,
        root_account_id,
        a1_id,
    }
}

fn setup_payment_fee_world(
    base_fee: u32,
    base_reserve: u32,
    total_coins: i64,
    pay_from_balance: i64,
) -> PaymentFeeWorld {
    let network_id = NetworkId::from_passphrase("(V) (;,,;) (V)");
    let root_secret = SecretKey::from_seed(network_id.as_bytes());
    let root_account_id: AccountId = (&root_secret.public_key()).into();

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

    let pay_from_secret = secret_from_name("pay-from");
    let pay_from_id: AccountId = (&pay_from_secret.public_key()).into();
    let root_seq = account_seq(&entries, &root_account_id);
    let create_tx = create_account_envelope(
        &root_secret,
        pay_from_id.clone(),
        pay_from_balance,
        base_fee,
        root_seq + 1,
        &network_id,
    );
    let create_meta = execute_and_apply(
        &mut entries,
        &header,
        network_id,
        base_fee,
        base_reserve,
        25,
        create_tx,
    )
    .0;
    header = advance_header(&header, total_coins);

    PaymentFeeWorld {
        entries,
        header,
        network_id,
        root_account_id,
        pay_from_secret,
        pay_from_id,
        create_meta,
    }
}

fn run_payment_fee_case(base_fee: u32, base_reserve: u32, pay_from_balance: i64) -> Vec<u64> {
    let total_coins = 1_000_000_000_000_000_000i64;
    let amount = 1i64;

    let mut world = setup_payment_fee_world(base_fee, base_reserve, total_coins, pay_from_balance);
    let pay_from_seq = account_seq(&world.entries, &world.pay_from_id);
    let payment_tx = payment_envelope(
        &world.pay_from_secret,
        &world.root_account_id,
        amount,
        base_fee,
        pay_from_seq + 1,
        &world.network_id,
    );
    let meta_payment = execute_and_apply(
        &mut world.entries,
        &world.header,
        world.network_id,
        base_fee,
        base_reserve,
        25,
        payment_tx,
    )
    .0;
    vec![tx_meta_hash(&world.create_meta), tx_meta_hash(&meta_payment)]
}

#[test]
fn payment_send_xlm_to_existing_account_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected =
        load_baseline_hashes("payment|protocol version 25|send XLM to an existing account");
    assert_eq!(expected.len(), 1);

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;

    let payment_amount = ((2 + 2) as i64 * base_reserve as i64 + 10 * base_fee as i64) / 2;

    let mut world = setup_payment_world();
    let root_seq = account_seq(&world.entries, &world.root_account_id);
    let payment_tx = payment_envelope(
        &world.root_secret,
        &world.a1_id,
        payment_amount,
        base_fee,
        root_seq + 1,
        &world.network_id,
    );
    let meta = execute_and_apply(
        &mut world.entries,
        &world.header,
        world.network_id,
        base_fee,
        base_reserve,
        25,
        payment_tx,
    )
    .0;

    let got = tx_meta_hash(&meta);
    assert_eq!(got, expected[0]);
}

#[test]
fn payment_send_xlm_to_new_account_no_destination_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected =
        load_baseline_hashes("payment|protocol version 25|send XLM to a new account (no destination)");
    assert_eq!(expected.len(), 1);

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;
    let min_balance0 = 2i64 * base_reserve as i64;

    let mut world = setup_payment_world();

    let dest_secret = secret_from_name("B");
    let dest_id: AccountId = (&dest_secret.public_key()).into();

    let root_seq = account_seq(&world.entries, &world.root_account_id);
    let payment_tx = payment_envelope(
        &world.root_secret,
        &dest_id,
        min_balance0,
        base_fee,
        root_seq + 1,
        &world.network_id,
    );
    let meta = execute_and_apply(
        &mut world.entries,
        &world.header,
        world.network_id,
        base_fee,
        base_reserve,
        25,
        payment_tx,
    )
    .0;

    let got = tx_meta_hash(&meta);
    assert_eq!(got, expected[0]);
}

#[test]
fn payment_dest_amount_too_big_for_native_asset_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected =
        load_baseline_hashes("payment|protocol version 25|dest amount too big for native asset");
    assert_eq!(expected.len(), 1);

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;

    let mut world = setup_payment_world();
    let root_seq = account_seq(&world.entries, &world.root_account_id);
    let payment_tx = payment_envelope(
        &world.root_secret,
        &world.a1_id,
        i64::MAX,
        base_fee,
        root_seq + 1,
        &world.network_id,
    );
    let meta = execute_and_apply(
        &mut world.entries,
        &world.header,
        world.network_id,
        base_fee,
        base_reserve,
        25,
        payment_tx,
    )
    .0;

    let got = tx_meta_hash(&meta);
    assert_eq!(got, expected[0]);
}

#[test]
fn payment_fees_equal_base_reserve_min_balance_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes(
        "payment fees|protocol version 25|fee equal to base reserve|account has only base reserve + amount",
    );
    assert_eq!(expected.len(), 2);

    let base_reserve = 100_000_000u32;
    let base_fee = base_reserve;
    let min_balance0 = 2i64 * base_reserve as i64;
    let pay_from_balance = min_balance0 + 1;
    let got = run_payment_fee_case(base_fee, base_reserve, pay_from_balance);
    assert_eq!(got, expected);
}

#[test]
fn payment_fees_bigger_than_base_reserve_min_balance_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes(
        "payment fees|protocol version 25|fee bigger than base reserve|account has only base reserve + amount",
    );
    assert_eq!(expected.len(), 2);

    let base_reserve = 100_000_000u32;
    let base_fee = 200_000_000u32;
    let min_balance0 = 2i64 * base_reserve as i64;
    let pay_from_balance = min_balance0 + 1;
    let got = run_payment_fee_case(base_fee, base_reserve, pay_from_balance);
    assert_eq!(got, expected);
}

#[test]
fn payment_fees_equal_base_reserve_one_fee_minus_one_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes(
        "payment fees|protocol version 25|fee equal to base reserve|account has only base reserve + amount + one operation fee - one stroop",
    );
    assert_eq!(expected.len(), 2);

    let base_reserve = 100_000_000u32;
    let base_fee = base_reserve;
    let min_balance0 = 2i64 * base_reserve as i64;
    let pay_from_balance = min_balance0 + 1 + base_fee as i64 - 1;
    let got = run_payment_fee_case(base_fee, base_reserve, pay_from_balance);
    assert_eq!(got, expected);
}

#[test]
fn payment_fees_equal_base_reserve_one_fee_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes(
        "payment fees|protocol version 25|fee equal to base reserve|account has only base reserve + amount + one operation fee",
    );
    assert_eq!(expected.len(), 2);

    let base_reserve = 100_000_000u32;
    let base_fee = base_reserve;
    let min_balance0 = 2i64 * base_reserve as i64;
    let pay_from_balance = min_balance0 + 1 + base_fee as i64;
    let got = run_payment_fee_case(base_fee, base_reserve, pay_from_balance);
    assert_eq!(got, expected);
}

#[test]
fn payment_fees_bigger_base_reserve_one_fee_minus_one_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes(
        "payment fees|protocol version 25|fee bigger than base reserve|account has only base reserve + amount + one operation fee - one stroop",
    );
    assert_eq!(expected.len(), 2);

    let base_reserve = 100_000_000u32;
    let base_fee = 200_000_000u32;
    let min_balance0 = 2i64 * base_reserve as i64;
    let pay_from_balance = min_balance0 + 1 + base_fee as i64 - 1;
    let got = run_payment_fee_case(base_fee, base_reserve, pay_from_balance);
    assert_eq!(got, expected);
}

#[test]
fn payment_fees_bigger_base_reserve_one_fee_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes(
        "payment fees|protocol version 25|fee bigger than base reserve|account has only base reserve + amount + one operation fee",
    );
    assert_eq!(expected.len(), 2);

    let base_reserve = 100_000_000u32;
    let base_fee = 200_000_000u32;
    let min_balance0 = 2i64 * base_reserve as i64;
    let pay_from_balance = min_balance0 + 1 + base_fee as i64;
    let got = run_payment_fee_case(base_fee, base_reserve, pay_from_balance);
    assert_eq!(got, expected);
}

#[test]
fn payment_fees_equal_base_reserve_one_stroop_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes(
        "payment fees|protocol version 25|fee equal to base reserve|account has only base reserve + amount + one stroop",
    );
    assert_eq!(expected.len(), 2);

    let base_reserve = 100_000_000u32;
    let base_fee = base_reserve;
    let min_balance0 = 2i64 * base_reserve as i64;
    let pay_from_balance = min_balance0 + 1 + 1;
    let got = run_payment_fee_case(base_fee, base_reserve, pay_from_balance);
    assert_eq!(got, expected);
}

#[test]
fn payment_fees_equal_base_reserve_one_fee_plus_one_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes(
        "payment fees|protocol version 25|fee equal to base reserve|account has only base reserve + amount + one operation fee + one stroop",
    );
    assert_eq!(expected.len(), 2);

    let base_reserve = 100_000_000u32;
    let base_fee = base_reserve;
    let min_balance0 = 2i64 * base_reserve as i64;
    let pay_from_balance = min_balance0 + 1 + base_fee as i64 + 1;
    let got = run_payment_fee_case(base_fee, base_reserve, pay_from_balance);
    assert_eq!(got, expected);
}

#[test]
fn payment_fees_equal_base_reserve_two_fees_minus_two_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes(
        "payment fees|protocol version 25|fee equal to base reserve|account has only base reserve + amount + two operation fees - two stroops",
    );
    assert_eq!(expected.len(), 2);

    let base_reserve = 100_000_000u32;
    let base_fee = base_reserve;
    let min_balance0 = 2i64 * base_reserve as i64;
    let pay_from_balance = min_balance0 + 1 + 2 * base_fee as i64 - 2;
    let got = run_payment_fee_case(base_fee, base_reserve, pay_from_balance);
    assert_eq!(got, expected);
}

#[test]
fn payment_fees_equal_base_reserve_two_fees_minus_one_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes(
        "payment fees|protocol version 25|fee equal to base reserve|account has only base reserve + amount + two operation fees - one stroop",
    );
    assert_eq!(expected.len(), 2);

    let base_reserve = 100_000_000u32;
    let base_fee = base_reserve;
    let min_balance0 = 2i64 * base_reserve as i64;
    let pay_from_balance = min_balance0 + 1 + 2 * base_fee as i64 - 1;
    let got = run_payment_fee_case(base_fee, base_reserve, pay_from_balance);
    assert_eq!(got, expected);
}

#[test]
fn payment_fees_equal_base_reserve_two_fees_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes(
        "payment fees|protocol version 25|fee equal to base reserve|account has only base reserve + amount + two operation fees",
    );
    assert_eq!(expected.len(), 2);

    let base_reserve = 100_000_000u32;
    let base_fee = base_reserve;
    let min_balance0 = 2i64 * base_reserve as i64;
    let pay_from_balance = min_balance0 + 1 + 2 * base_fee as i64;
    let got = run_payment_fee_case(base_fee, base_reserve, pay_from_balance);
    assert_eq!(got, expected);
}

#[test]
fn payment_fees_bigger_base_reserve_one_stroop_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes(
        "payment fees|protocol version 25|fee bigger than base reserve|account has only base reserve + amount + one stroop",
    );
    assert_eq!(expected.len(), 2);

    let base_reserve = 100_000_000u32;
    let base_fee = 200_000_000u32;
    let min_balance0 = 2i64 * base_reserve as i64;
    let pay_from_balance = min_balance0 + 1 + 1;
    let got = run_payment_fee_case(base_fee, base_reserve, pay_from_balance);
    assert_eq!(got, expected);
}

#[test]
fn payment_fees_bigger_base_reserve_one_fee_plus_one_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes(
        "payment fees|protocol version 25|fee bigger than base reserve|account has only base reserve + amount + one operation fee + one stroop",
    );
    assert_eq!(expected.len(), 2);

    let base_reserve = 100_000_000u32;
    let base_fee = 200_000_000u32;
    let min_balance0 = 2i64 * base_reserve as i64;
    let pay_from_balance = min_balance0 + 1 + base_fee as i64 + 1;
    let got = run_payment_fee_case(base_fee, base_reserve, pay_from_balance);
    assert_eq!(got, expected);
}

#[test]
fn payment_fees_bigger_base_reserve_two_fees_minus_two_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes(
        "payment fees|protocol version 25|fee bigger than base reserve|account has only base reserve + amount + two operation fees - two stroops",
    );
    assert_eq!(expected.len(), 2);

    let base_reserve = 100_000_000u32;
    let base_fee = 200_000_000u32;
    let min_balance0 = 2i64 * base_reserve as i64;
    let pay_from_balance = min_balance0 + 1 + 2 * base_fee as i64 - 2;
    let got = run_payment_fee_case(base_fee, base_reserve, pay_from_balance);
    assert_eq!(got, expected);
}

#[test]
fn payment_fees_bigger_base_reserve_two_fees_minus_one_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes(
        "payment fees|protocol version 25|fee bigger than base reserve|account has only base reserve + amount + two operation fees - one stroop",
    );
    assert_eq!(expected.len(), 2);

    let base_reserve = 100_000_000u32;
    let base_fee = 200_000_000u32;
    let min_balance0 = 2i64 * base_reserve as i64;
    let pay_from_balance = min_balance0 + 1 + 2 * base_fee as i64 - 1;
    let got = run_payment_fee_case(base_fee, base_reserve, pay_from_balance);
    assert_eq!(got, expected);
}

#[test]
fn payment_fees_bigger_base_reserve_two_fees_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes(
        "payment fees|protocol version 25|fee bigger than base reserve|account has only base reserve + amount + two operation fees",
    );
    assert_eq!(expected.len(), 2);

    let base_reserve = 100_000_000u32;
    let base_fee = 200_000_000u32;
    let min_balance0 = 2i64 * base_reserve as i64;
    let pay_from_balance = min_balance0 + 1 + 2 * base_fee as i64;
    let got = run_payment_fee_case(base_fee, base_reserve, pay_from_balance);
    assert_eq!(got, expected);
}
