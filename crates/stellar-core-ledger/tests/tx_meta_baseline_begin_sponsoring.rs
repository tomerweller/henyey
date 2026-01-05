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
    AccountEntry, AccountEntryExt, AccountId, AlphaNum4, AssetCode4, BeginSponsoringFutureReservesOp,
    BumpSequenceOp, ChangeTrustAsset, ChangeTrustOp, LedgerEntry, LedgerEntryData, LedgerEntryExt,
    LedgerHeader, LedgerKey, LedgerKeyAccount, MuxedAccount, Operation, OperationBody,
    Preconditions, SequenceNumber,
    Signature as XdrSignature, SignatureHint, String32,
    Thresholds, TimePoint, Transaction, TransactionEnvelope, TransactionExt, TransactionMeta,
    TransactionResultMetaV1, TransactionV1Envelope, Uint256, VecM, WriteXdr, Limits,
};

const GENESIS_BUCKET_LIST_HASH: [u8; 32] = hex_literal::hex!(
    "4e6a8404d33b17eee7031af0b3606b6af8e36fe5a3bff59e4e5e420bd0ad3bf4"
);

fn baseline_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/tx-meta-baseline-current/BeginSponsoringFutureReservesTests.json")
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

fn muxed_from_account_id(account_id: &AccountId) -> MuxedAccount {
    match &account_id.0 {
        stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(pk) => MuxedAccount::Ed25519(pk.clone()),
    }
}

fn begin_sponsoring_op(sponsored: AccountId) -> Operation {
    Operation {
        source_account: None,
        body: OperationBody::BeginSponsoringFutureReserves(BeginSponsoringFutureReservesOp {
            sponsored_id: sponsored,
        }),
    }
}

fn end_sponsoring_op() -> Operation {
    Operation {
        source_account: None,
        body: OperationBody::EndSponsoringFutureReserves,
    }
}

fn change_trust_op(asset: ChangeTrustAsset, limit: i64) -> Operation {
    Operation {
        source_account: None,
        body: OperationBody::ChangeTrust(ChangeTrustOp { line: asset, limit }),
    }
}

fn sign_multi(
    envelope: &mut TransactionEnvelope,
    secrets: &[&SecretKey],
    network_id: &NetworkId,
) {
    let mut signatures = Vec::new();
    for secret in secrets {
        signatures.push(sign_envelope(envelope, secret, network_id));
    }
    if let TransactionEnvelope::Tx(ref mut env) = envelope {
        env.signatures = signatures.try_into().unwrap();
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

fn execute_create_account(
    entries: &std::collections::HashMap<Vec<u8>, LedgerEntry>,
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
                .map(|entry| (stellar_core_ledger::entry_to_key(&entry).expect("entry key"), entry)),
        )
        .expect("snapshot entries")
        .build()
        .expect("build snapshot");
    let snapshot = SnapshotHandle::new(snapshot);

    let mut delta = stellar_core_ledger::LedgerDelta::new(header.ledger_seq);
    let (_results, _tx_results, tx_result_metas, _id_pool) = execute_transaction_set(
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

    let meta: &TransactionResultMetaV1 = tx_result_metas.first().expect("tx meta");
    meta.tx_apply_processing.clone()
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
    meta.tx_apply_processing.clone()
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
        body: OperationBody::BumpSequence(BumpSequenceOp {
            bump_to: SequenceNumber(bump_to),
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

fn sponsoring_change_trust_envelope(
    root_secret: &SecretKey,
    root_account: &AccountId,
    sponsored_secret: &SecretKey,
    sponsored_account: &AccountId,
    asset: ChangeTrustAsset,
    base_fee: u32,
    sequence: i64,
    network_id: &NetworkId,
) -> TransactionEnvelope {
    let mut op_begin = begin_sponsoring_op(sponsored_account.clone());
    op_begin.source_account = Some(muxed_from_account_id(root_account));

    let mut op_change = change_trust_op(asset, 1000);
    op_change.source_account = Some(muxed_from_account_id(sponsored_account));

    let mut op_end = end_sponsoring_op();
    op_end.source_account = Some(muxed_from_account_id(sponsored_account));

    let tx = Transaction {
        source_account: muxed_from_account_id(root_account),
        fee: base_fee * 3,
        seq_num: SequenceNumber(sequence),
        cond: Preconditions::None,
        memo: stellar_xdr::curr::Memo::None,
        operations: vec![op_begin, op_change, op_end].try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });
    sign_multi(&mut envelope, &[root_secret, sponsored_secret], network_id);
    envelope
}

#[test]
fn begin_sponsoring_success_baseline_matches() {
    seed(12345).expect("seed short hash");
    let expected =
        load_baseline_hashes("sponsor future reserves|protocol version 25|success");
    assert_eq!(expected.len(), 2);

    let network_id = NetworkId::from_passphrase("(V) (;,,;) (V)");
    let root_secret = SecretKey::from_seed(network_id.as_bytes());
    let root_account_id: AccountId = (&root_secret.public_key()).into();

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;
    let total_coins = 1_000_000_000_000_000_000i64;
    let min_balance0 = 2i64 * base_reserve as i64;

    let genesis = genesis_header(25, base_fee, base_reserve, total_coins);
    let header = test_header(
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

    let a1_secret = secret_from_name("a1");
    let a1_id: AccountId = (&a1_secret.public_key()).into();

    let tx = create_account_envelope(
        &root_secret,
        a1_id.clone(),
        min_balance0,
        base_fee,
        1,
        &network_id,
    );
    let meta = execute_create_account(
        &entries,
        &header,
        network_id,
        base_fee,
        base_reserve,
        25,
        tx,
    );

    let got = tx_meta_hash(&meta);
    assert_eq!(got, expected[0]);
}

#[test]
fn begin_sponsoring_precondition_v3_baseline_matches() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes(
        "sponsor future reserves|protocol version 25|sponsorships with precondition that uses v3 extension",
    );
    assert_eq!(expected.len(), 2);

    let network_id = NetworkId::from_passphrase("(V) (;,,;) (V)");
    let root_secret = SecretKey::from_seed(network_id.as_bytes());
    let root_account_id: AccountId = (&root_secret.public_key()).into();

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;
    let total_coins = 1_000_000_000_000_000_000i64;
    let min_balance0 = 2i64 * base_reserve as i64;

    let genesis = genesis_header(25, base_fee, base_reserve, total_coins);
    let header = test_header(
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

    let a1_secret = secret_from_name("a1");
    let a1_id: AccountId = (&a1_secret.public_key()).into();

    let tx = create_account_envelope(
        &root_secret,
        a1_id.clone(),
        min_balance0 + 301,
        base_fee,
        1,
        &network_id,
    );
    let meta_create = execute_and_apply(
        &mut entries,
        &header,
        network_id,
        base_fee,
        base_reserve,
        25,
        tx,
    );

    let header_after_create = test_header(
        3,
        25,
        base_fee,
        base_reserve,
        total_coins,
        compute_header_hash(&header).expect("header hash"),
    );

    let root_entry = entries
        .get(&key_bytes(&LedgerKey::Account(LedgerKeyAccount { account_id: root_account_id.clone() })))
        .expect("root entry");
    let root_seq = match &root_entry.data {
        LedgerEntryData::Account(account) => account.seq_num.0,
        _ => panic!("root entry not account"),
    };

    let cur1 = ChangeTrustAsset::CreditAlphanum4(AlphaNum4 {
        asset_code: AssetCode4(*b"CUR1"),
        issuer: root_account_id.clone(),
    });
    let sponsor_tx = sponsoring_change_trust_envelope(
        &root_secret,
        &root_account_id,
        &a1_secret,
        &a1_id,
        cur1,
        base_fee,
        root_seq + 1,
        &network_id,
    );
    let _meta_sponsor = execute_and_apply(
        &mut entries,
        &header_after_create,
        network_id,
        base_fee,
        base_reserve,
        25,
        sponsor_tx,
    );

    let header_after_sponsor = test_header(
        4,
        25,
        base_fee,
        base_reserve,
        total_coins,
        compute_header_hash(&header_after_create).expect("header hash"),
    );

    let a1_entry = entries
        .get(&key_bytes(&LedgerKey::Account(LedgerKeyAccount { account_id: a1_id.clone() })))
        .expect("a1 entry");
    let a1_seq = match &a1_entry.data {
        LedgerEntryData::Account(account) => account.seq_num.0,
        _ => panic!("a1 entry not account"),
    };

    let bump_tx = bump_sequence_envelope(
        &a1_secret,
        0,
        base_fee,
        a1_seq + 1,
        &network_id,
    );
    let meta_bump = execute_and_apply(
        &mut entries,
        &header_after_sponsor,
        network_id,
        base_fee,
        base_reserve,
        25,
        bump_tx,
    );

    let got = vec![tx_meta_hash(&meta_create), tx_meta_hash(&meta_bump)];
    assert_eq!(got, expected);
}
