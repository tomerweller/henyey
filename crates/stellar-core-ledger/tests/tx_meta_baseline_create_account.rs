use std::fs;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use stellar_core_common::{normalize_transaction_meta, Hash256, NetworkId};
use stellar_core_crypto::{seed, xdr_compute_hash, SecretKey};
use stellar_core_ledger::execution::execute_transaction_set;
use stellar_core_ledger::{LedgerDelta, SnapshotBuilder, SnapshotHandle};
use stellar_core_tx::{soroban::SorobanConfig, ClassicEventConfig};
use stellar_xdr::curr::{
    AccountEntry, AccountEntryExt, AccountId, LedgerEntry, LedgerEntryData, LedgerEntryExt,
    LedgerHeader, LedgerKey, LedgerKeyAccount, MuxedAccount, Operation, OperationBody, Preconditions,
    SignatureHint, Signature as XdrSignature, String32, Thresholds, TimePoint, Transaction,
    TransactionEnvelope, TransactionExt, TransactionMeta, TransactionResultMetaV1,
    TransactionV1Envelope, Uint256, VecM,
};

fn baseline_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.upstream-v25/test-tx-meta-baseline-current/CreateAccountTests.json")
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

fn test_header(
    ledger_seq: u32,
    ledger_version: u32,
    base_fee: u32,
    base_reserve: u32,
    total_coins: i64,
) -> LedgerHeader {
    let mut header = SnapshotBuilder::new(ledger_seq)
        .build_with_default_header()
        .header()
        .clone();
    header.ledger_version = ledger_version;
    header.base_fee = base_fee;
    header.base_reserve = base_reserve;
    header.ledger_seq = ledger_seq;
    header.total_coins = total_coins;
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

#[test]
#[ignore = "baseline parity pending: ledger/header alignment"]
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

    let (root_key, root_entry) = account_entry(
        root_account_id.clone(),
        0,
        total_coins,
        ledger_seq - 1,
    );
    let header = test_header(ledger_seq, 25, base_fee, base_reserve, total_coins);
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
