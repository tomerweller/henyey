use std::fs;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use stellar_core_common::{normalize_transaction_meta, Hash256, NetworkId};
use stellar_core_crypto::{seed, xdr_compute_hash, SecretKey};
use stellar_core_ledger::execution::execute_transaction_set;
use stellar_core_ledger::{compute_header_hash, entry_to_key, LedgerDelta, SnapshotBuilder, SnapshotHandle, reserves};
use stellar_core_tx::{ClassicEventConfig, soroban::SorobanConfig};
use stellar_xdr::curr::{
    AccountEntry, AccountEntryExt, AccountId, DataValue, LedgerEntry, LedgerEntryData,
    LedgerEntryExt, LedgerHeader, LedgerKey, LedgerKeyAccount, ManageDataOp,
    MuxedAccount, Operation, OperationBody, Preconditions, SequenceNumber, Signature as XdrSignature,
    SignatureHint, String32, String64, Thresholds, TimePoint, Transaction, TransactionEnvelope,
    TransactionExt, TransactionMeta, TransactionResultMetaV1, TransactionV1Envelope, Uint256,
    VecM, WriteXdr, Limits, Asset, PaymentOp, Price, PublicKey, AccountEntryExtensionV1,
    AccountEntryExtensionV1Ext, AccountEntryExtensionV2, AccountEntryExtensionV2Ext,
    Liabilities, SponsorshipDescriptor,
};

const GENESIS_BUCKET_LIST_HASH: [u8; 32] = hex_literal::hex!(
    "4e6a8404d33b17eee7031af0b3606b6af8e36fe5a3bff59e4e5e420bd0ad3bf4"
);

fn baseline_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/tx-meta-baseline-current/ManageDataTests.json")
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
    key.to_xdr(Limits::none()).unwrap_or_default()
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
            destination: muxed_from_account_id(&destination),
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

fn credit_asset(code: &[u8; 4], issuer: &AccountId) -> Asset {
    Asset::CreditAlphanum4(stellar_xdr::curr::AlphaNum4 {
        asset_code: stellar_xdr::curr::AssetCode4(*code),
        issuer: issuer.clone(),
    })
}

fn update_account_subentries_and_sponsoring(
    entries: &mut std::collections::HashMap<Vec<u8>, LedgerEntry>,
    account_id: &AccountId,
    num_sub_entries: u32,
    num_sponsoring: u32,
    num_sponsored: u32,
    current_ledger_seq: u32,
) {
    let key = LedgerKey::Account(LedgerKeyAccount {
        account_id: account_id.clone(),
    });
    let entry = entries
        .get_mut(&key_bytes(&key))
        .expect("account entry");
    entry.last_modified_ledger_seq = current_ledger_seq;
    let LedgerEntryData::Account(account) = &mut entry.data else {
        panic!("entry is not account");
    };

    account.num_sub_entries = num_sub_entries;

    if num_sponsoring == 0 && num_sponsored == 0 {
        return;
    }

    let (liabilities, signer_sponsoring, ext_v2_ext) = match &account.ext {
        AccountEntryExt::V1(v1) => {
            let signer_sponsoring = match &v1.ext {
                AccountEntryExtensionV1Ext::V2(v2) => v2.signer_sponsoring_i_ds.clone(),
                AccountEntryExtensionV1Ext::V0 => {
                    vec![SponsorshipDescriptor(None); account.signers.len()]
                        .try_into()
                        .unwrap_or_default()
                }
            };
            let ext_v2_ext = match &v1.ext {
                AccountEntryExtensionV1Ext::V2(v2) => v2.ext.clone(),
                AccountEntryExtensionV1Ext::V0 => AccountEntryExtensionV2Ext::V0,
            };
            (v1.liabilities.clone(), signer_sponsoring, ext_v2_ext)
        }
        AccountEntryExt::V0 => (
            Liabilities { buying: 0, selling: 0 },
            vec![SponsorshipDescriptor(None); account.signers.len()]
                .try_into()
                .unwrap_or_default(),
            AccountEntryExtensionV2Ext::V0,
        ),
    };

    account.ext = AccountEntryExt::V1(AccountEntryExtensionV1 {
        liabilities,
        ext: AccountEntryExtensionV1Ext::V2(AccountEntryExtensionV2 {
            num_sponsored,
            num_sponsoring,
            signer_sponsoring_i_ds: signer_sponsoring,
            ext: ext_v2_ext,
        }),
    });
}

fn manage_data_envelope(
    source: &SecretKey,
    data_name: &str,
    data_value: Option<&[u8]>,
    base_fee: u32,
    sequence: i64,
    network_id: &NetworkId,
) -> TransactionEnvelope {
    let name = String64::try_from(data_name.as_bytes().to_vec()).expect("data name");
    let data_value = data_value
        .map(|value| DataValue::try_from(value.to_vec()).expect("data value"));
    let operation = Operation {
        source_account: None,
        body: OperationBody::ManageData(ManageDataOp {
            data_name: name,
            data_value,
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

fn execute_and_apply_with_result(
    entries: &mut std::collections::HashMap<Vec<u8>, LedgerEntry>,
    header: &LedgerHeader,
    network_id: NetworkId,
    base_fee: u32,
    base_reserve: u32,
    protocol_version: u32,
    envelope: TransactionEnvelope,
) -> (TransactionMeta, stellar_core_ledger::execution::TransactionExecutionResult) {
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

    let result = _results.first().expect("tx result").clone();
    let meta: &TransactionResultMetaV1 = tx_result_metas.first().expect("tx meta");
    (meta.tx_apply_processing.clone(), result)
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

fn account_available_balance(
    entries: &std::collections::HashMap<Vec<u8>, LedgerEntry>,
    account_id: &AccountId,
    base_reserve: u32,
) -> i64 {
    let entry = entries
        .get(&key_bytes(&LedgerKey::Account(LedgerKeyAccount {
            account_id: account_id.clone(),
        })))
        .expect("account entry");
    let LedgerEntryData::Account(account) = &entry.data else {
        panic!("entry is not account");
    };
    let selling_liabilities = match &account.ext {
        AccountEntryExt::V0 => 0,
        AccountEntryExt::V1(v1) => v1.liabilities.selling,
    };
    account.balance - reserves::minimum_balance(account, base_reserve) - selling_liabilities
}

fn data_entry_exists(
    entries: &std::collections::HashMap<Vec<u8>, LedgerEntry>,
    account_id: &AccountId,
    name: &str,
) -> bool {
    let data_name = String64::try_from(name.as_bytes().to_vec()).expect("data name");
    let key = LedgerKey::Data(stellar_xdr::curr::LedgerKeyData {
        account_id: account_id.clone(),
        data_name,
    });
    entries.contains_key(&key_bytes(&key))
}

fn run_manage_data_base_with_state(
) -> (
    Vec<u64>,
    std::collections::HashMap<Vec<u8>, LedgerEntry>,
    LedgerHeader,
    NetworkId,
    SecretKey,
    AccountId,
    u32,
    u32,
    i64,
) {
    let (mut entries, mut header, network_id, root_secret, root_account_id, base_fee, base_reserve, total_coins, _gateway_secret, gateway_id) =
        run_manage_data_setup_with_gateway();
    let mut hashes = Vec::new();
    header = advance_header(&header, total_coins);
    let root_seq = account_seq(&entries, &root_account_id);
    let (meta, result) = execute_and_apply_with_result(
        &mut entries,
        &header,
        network_id,
        base_fee,
        base_reserve,
        25,
        create_account_envelope(
            &root_secret,
            gateway_id.clone(),
            (2 + 3) as i64 * base_reserve as i64 - 100,
            base_fee,
            root_seq + 1,
            &network_id,
        ),
    );
    assert!(result.success);
    hashes.push(tx_meta_hash(&meta));

    let mut value = vec![0u8; 64];
    let mut value2 = vec![0u8; 64];
    for idx in 0..64 {
        value[idx] = idx as u8;
        value2[idx] = idx as u8 + 3;
    }

    let t1 = "test";
    let t2 = "test2";
    let t3 = "test3";
    let t4 = "test4";

    for (index, (name, data)) in [
        (t1, Some(value.as_slice())),
        (t2, Some(value.as_slice())),
        (t3, Some(value.as_slice())),
        (t1, Some(value2.as_slice())),
        (t1, None),
        (t3, Some(value.as_slice())),
        (t4, None),
    ]
    .into_iter()
    .enumerate()
    {
        header = advance_header(&header, total_coins);
        let gateway_seq = account_seq(&entries, &gateway_id);
        let tx = manage_data_envelope(
            &gateway_secret,
            name,
            data,
            base_fee,
            gateway_seq + 1,
            &network_id,
        );
        let (meta, result) =
            execute_and_apply_with_result(&mut entries, &header, network_id, base_fee, base_reserve, 25, tx);
        match index {
            2 | 6 => assert!(
                !result.success,
                "manage data op index {} expected failure",
                index
            ),
            _ => assert!(
                result.success,
                "manage data op index {} expected success: {:?}",
                index,
                result
            ),
        }
        if index == 2 {
            assert!(data_entry_exists(&entries, &gateway_id, t1));
            assert!(data_entry_exists(&entries, &gateway_id, t2));
        }
        hashes.push(tx_meta_hash(&meta));
    }

    (
        hashes,
        entries,
        header,
        network_id,
        root_secret,
        root_account_id,
        base_fee,
        base_reserve,
        total_coins,
    )
}

fn run_manage_data_setup_with_gateway(
) -> (
    std::collections::HashMap<Vec<u8>, LedgerEntry>,
    LedgerHeader,
    NetworkId,
    SecretKey,
    AccountId,
    u32,
    u32,
    i64,
    SecretKey,
    AccountId,
) {
    let network_id = NetworkId::from_passphrase("(V) (;,,;) (V)");
    let root_secret = SecretKey::from_seed(network_id.as_bytes());
    let root_account_id: AccountId = (&root_secret.public_key()).into();

    let base_fee = 100u32;
    let base_reserve = 100_000_000u32;
    let total_coins = 1_000_000_000_000_000_000i64;

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

    let gateway_secret = secret_from_name("gw");
    let gateway_id: AccountId = (&gateway_secret.public_key()).into();

    (
        entries,
        header,
        network_id,
        root_secret,
        root_account_id,
        base_fee,
        base_reserve,
        total_coins,
        gateway_secret,
        gateway_id,
    )
}

#[test]
fn manage_data_base_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes("manage data|protocol version 25");
    let (single_run, _entries, _header, _network_id, _root_secret, _root_account_id, _base_fee, _base_reserve, _total_coins) =
        run_manage_data_base_with_state();
    assert!(!single_run.is_empty());
    assert_eq!(expected.len() % single_run.len(), 0);

    let repeats = expected.len() / single_run.len();
    let mut got = Vec::with_capacity(expected.len());
    for _ in 0..repeats {
        let (run, _entries, _header, _network_id, _root_secret, _root_account_id, _base_fee, _base_reserve, _total_coins) =
            run_manage_data_base_with_state();
        got.extend(run);
    }

    assert_eq!(got, expected);
}

#[test]
fn manage_data_native_selling_liabilities_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected =
        load_baseline_hashes("manage data|protocol version 25|create data with native selling liabilities");
    assert_eq!(expected.len(), 5);
    let (_base_hashes, mut entries, mut header, network_id, root_secret, root_account_id, base_fee, base_reserve, total_coins) =
        run_manage_data_base_with_state();
    let min_balance2 = (2 + 2) as i64 * base_reserve as i64;
    let acc_balance = min_balance2 + (base_fee as i64 * 2) + 500 - 1;

    let acc_secret = secret_from_name("acc1");
    let acc_id: AccountId = (&acc_secret.public_key()).into();
    header = advance_header(&header, total_coins);
    let root_seq = account_seq(&entries, &root_account_id);
    let tx = create_account_envelope(
        &root_secret,
        acc_id.clone(),
        acc_balance,
        base_fee,
        root_seq + 1,
        &network_id,
    );
    let mut hashes = Vec::new();
    let (meta, result) =
        execute_and_apply_with_result(&mut entries, &header, network_id, base_fee, base_reserve, 25, tx);
    assert!(result.success);
    hashes.push(tx_meta_hash(&meta));

    header = advance_header(&header, total_coins);
    let acc_seq = account_seq(&entries, &acc_id);
    let cur1 = credit_asset(b"CUR1", &acc_id);
    let tx = manage_sell_offer_envelope(
        &acc_secret,
        Asset::Native,
        cur1,
        500,
        Price { n: 1, d: 1 },
        base_fee,
        acc_seq + 1,
        &network_id,
    );
    let (meta, result) =
        execute_and_apply_with_result(&mut entries, &header, network_id, base_fee, base_reserve, 25, tx);
    assert!(result.success);
    hashes.push(tx_meta_hash(&meta));

    header = advance_header(&header, total_coins);
    let acc_seq = account_seq(&entries, &acc_id);
    let mut value = vec![0u8; 64];
    for idx in 0..64 {
        value[idx] = idx as u8;
    }
    let tx = manage_data_envelope(
        &acc_secret,
        "test",
        Some(value.as_slice()),
        base_fee,
        acc_seq + 1,
        &network_id,
    );
    let (meta, result) =
        execute_and_apply_with_result(&mut entries, &header, network_id, base_fee, base_reserve, 25, tx);
    assert!(!result.success);
    hashes.push(tx_meta_hash(&meta));

    header = advance_header(&header, total_coins);
    let root_seq = account_seq(&entries, &root_account_id);
    let tx = payment_envelope(
        &root_secret,
        acc_id.clone(),
        base_fee as i64 + 1,
        base_fee,
        root_seq + 1,
        &network_id,
    );
    let (meta, result) =
        execute_and_apply_with_result(&mut entries, &header, network_id, base_fee, base_reserve, 25, tx);
    assert!(result.success);
    hashes.push(tx_meta_hash(&meta));

    header = advance_header(&header, total_coins);
    let acc_seq = account_seq(&entries, &acc_id);
    let tx = manage_data_envelope(
        &acc_secret,
        "test",
        Some(value.as_slice()),
        base_fee,
        acc_seq + 1,
        &network_id,
    );
    let (meta, result) =
        execute_and_apply_with_result(&mut entries, &header, network_id, base_fee, base_reserve, 25, tx);
    assert!(result.success);
    hashes.push(tx_meta_hash(&meta));

    assert_eq!(hashes, expected);
}

#[test]
fn manage_data_native_buying_liabilities_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected =
        load_baseline_hashes("manage data|protocol version 25|create data with native buying liabilities");
    assert_eq!(expected.len(), 3);

    let (_base_hashes, mut entries, mut header, network_id, root_secret, root_account_id, base_fee, base_reserve, total_coins) =
        run_manage_data_base_with_state();
    let min_balance2 = (2 + 2) as i64 * base_reserve as i64;
    let acc_balance = min_balance2 + (base_fee as i64 * 2) + 500 - 1;

    let acc_secret = secret_from_name("acc1");
    let acc_id: AccountId = (&acc_secret.public_key()).into();
    header = advance_header(&header, total_coins);
    let root_seq = account_seq(&entries, &root_account_id);
    let tx = create_account_envelope(
        &root_secret,
        acc_id.clone(),
        acc_balance,
        base_fee,
        root_seq + 1,
        &network_id,
    );
    let mut hashes = Vec::new();
    let (meta, result) =
        execute_and_apply_with_result(&mut entries, &header, network_id, base_fee, base_reserve, 25, tx);
    assert!(result.success);
    hashes.push(tx_meta_hash(&meta));

    header = advance_header(&header, total_coins);
    let acc_seq = account_seq(&entries, &acc_id);
    let cur1 = credit_asset(b"CUR1", &acc_id);
    let tx = manage_sell_offer_envelope(
        &acc_secret,
        cur1,
        Asset::Native,
        500,
        Price { n: 1, d: 1 },
        base_fee,
        acc_seq + 1,
        &network_id,
    );
    let (meta, result) =
        execute_and_apply_with_result(&mut entries, &header, network_id, base_fee, base_reserve, 25, tx);
    assert!(result.success);
    hashes.push(tx_meta_hash(&meta));

    header = advance_header(&header, total_coins);
    let acc_seq = account_seq(&entries, &acc_id);
    let mut value = vec![0u8; 64];
    for idx in 0..64 {
        value[idx] = idx as u8;
    }
    let tx = manage_data_envelope(
        &acc_secret,
        "test",
        Some(value.as_slice()),
        base_fee,
        acc_seq + 1,
        &network_id,
    );
    let (meta, result) =
        execute_and_apply_with_result(&mut entries, &header, network_id, base_fee, base_reserve, 25, tx);
    assert!(result.success);
    hashes.push(tx_meta_hash(&meta));

    assert_eq!(hashes, expected);
}

fn run_manage_data_too_many_subentries_case(
    num_sub_entries: u32,
    num_sponsoring: u32,
    num_sponsored: u32,
) -> Vec<TransactionMeta> {
    let (mut entries, mut header, network_id, root_secret, root_account_id, base_fee, base_reserve, total_coins, gateway_secret, gateway_id) =
        run_manage_data_setup_with_gateway();
    header = advance_header(&header, total_coins);
    let root_seq = account_seq(&entries, &root_account_id);
    let (_gateway_meta, result) = execute_and_apply_with_result(
        &mut entries,
        &header,
        network_id,
        base_fee,
        base_reserve,
        25,
        create_account_envelope(
            &root_secret,
            gateway_id.clone(),
            (2 + 3) as i64 * base_reserve as i64 - 100,
            base_fee,
            root_seq + 1,
            &network_id,
        ),
    );
    assert!(result.success);

    header = advance_header(&header, total_coins);
    let min_balance0 = (2 + 0) as i64 * base_reserve as i64;
    let acc_secret = secret_from_name("acc1");
    let acc_id: AccountId = (&acc_secret.public_key()).into();

    let root_seq = account_seq(&entries, &root_account_id);
    let tx = create_account_envelope(
        &root_secret,
        acc_id.clone(),
        min_balance0,
        base_fee,
        root_seq + 1,
        &network_id,
    );
    let (_create_meta, result) =
        execute_and_apply_with_result(&mut entries, &header, network_id, base_fee, base_reserve, 25, tx);
    assert!(result.success);

    header = advance_header(&header, total_coins);
    let root_seq = account_seq(&entries, &root_account_id);
    let root_available = account_available_balance(&entries, &root_account_id, base_reserve);
    let tx = payment_envelope(
        &root_secret,
        acc_id.clone(),
        root_available - 100,
        base_fee,
        root_seq + 1,
        &network_id,
    );
    let (_payment_meta, result) =
        execute_and_apply_with_result(&mut entries, &header, network_id, base_fee, base_reserve, 25, tx);
    assert!(result.success);

    update_account_subentries_and_sponsoring(
        &mut entries,
        &acc_id,
        num_sub_entries,
        num_sponsoring,
        num_sponsored,
        header.ledger_seq,
    );

    let mut value = vec![0u8; 64];
    for idx in 0..64 {
        value[idx] = idx as u8;
    }

    let acc_seq = account_seq(&entries, &acc_id);
    let tx1 = manage_data_envelope(
        &acc_secret,
        "test",
        Some(value.as_slice()),
        base_fee,
        acc_seq + 1,
        &network_id,
    );
    let tx2 = manage_data_envelope(
        &acc_secret,
        "test2",
        Some(value.as_slice()),
        base_fee,
        acc_seq + 2,
        &network_id,
    );
    let (meta1, result1) = execute_and_apply_with_result(
        &mut entries,
        &header,
        network_id,
        base_fee,
        base_reserve,
        25,
        tx1,
    );
    assert!(result1.success);

    let (meta2, result2) = execute_and_apply_with_result(
        &mut entries,
        &header,
        network_id,
        base_fee,
        base_reserve,
        25,
        tx2,
    );
    assert!(!result2.success);
    assert_eq!(result2.operation_results.len(), 1);
    assert!(matches!(
        result2.operation_results[0],
        stellar_xdr::curr::OperationResult::OpTooManySubentries
    ));

    vec![meta1, meta2]
}

#[test]
fn manage_data_too_many_subentries_tx_meta_matches_baseline() {
    seed(12345).expect("seed short hash");
    let expected = load_baseline_hashes("manage data|protocol version 25|too many subentries");
    assert_eq!(expected.len(), 4);

    let mut hashes = Vec::new();
    let case1 = run_manage_data_too_many_subentries_case(999, 0, 0);
    let case2 = run_manage_data_too_many_subentries_case(50, u32::MAX - 1 - 50, 0);
    hashes.extend(case1.iter().map(tx_meta_hash));
    hashes.extend(case2.iter().map(tx_meta_hash));

    assert_eq!(hashes, expected);
}
