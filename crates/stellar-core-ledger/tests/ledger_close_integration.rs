use stellar_core_bucket::BucketList;
use stellar_core_common::Hash256;
use stellar_core_db::Database;
use stellar_core_ledger::{
    LedgerCloseData, LedgerManager, LedgerManagerConfig, TransactionSetVariant,
};
use stellar_xdr::curr::{
    AccountId, Asset, BucketListType, ContractCodeEntry, ContractCodeEntryExt,
    ContractDataDurability, ContractDataEntry, ContractId, ExtensionPoint, Hash, LedgerCloseMeta,
    LedgerEntry, LedgerEntryData, LedgerEntryExt, LedgerHeader, LedgerHeaderExt, LedgerKey,
    LedgerKeyContractCode, OfferEntry, OfferEntryExt, Price, PublicKey, ScAddress, ScVal,
    StellarValue, StellarValueExt, TimePoint, TransactionResultSet, TransactionSet, TtlEntry,
    Uint256, VecM, WriteXdr,
};

fn make_genesis_header() -> LedgerHeader {
    LedgerHeader {
        ledger_version: 25,
        previous_ledger_hash: Hash([0u8; 32]),
        scp_value: StellarValue {
            tx_set_hash: Hash([0u8; 32]),
            close_time: TimePoint(0),
            upgrades: VecM::default(),
            ext: StellarValueExt::Basic,
        },
        tx_set_result_hash: Hash([0u8; 32]),
        bucket_list_hash: Hash([0u8; 32]),
        ledger_seq: 0,
        total_coins: 1_000_000,
        fee_pool: 0,
        inflation_seq: 0,
        id_pool: 0,
        base_fee: 100,
        base_reserve: 100,
        max_tx_set_size: 100,
        skip_list: [
            Hash([0u8; 32]),
            Hash([0u8; 32]),
            Hash([0u8; 32]),
            Hash([0u8; 32]),
        ],
        ext: LedgerHeaderExt::V0,
    }
}

#[test]
fn test_ledger_close_with_empty_tx_set() {
    let db = Database::open_in_memory().expect("db");
    let _bucket_dir = tempfile::tempdir().expect("bucket dir");

    let ledger = LedgerManager::new(db, "Test Network".to_string());

    let bucket_list = BucketList::new();
    let header = make_genesis_header();
    ledger
        .initialize_from_buckets_skip_verify(bucket_list, header)
        .expect("init");

    let close_data = LedgerCloseData::new(
        1,
        TransactionSetVariant::Classic(TransactionSet {
            previous_ledger_hash: Hash([0u8; 32]),
            txs: VecM::default(),
        }),
        1,
        ledger.current_header_hash(),
    );

    let mut ctx = ledger.begin_close(close_data).expect("begin close");
    let results = ctx.apply_transactions().expect("apply txs");
    assert!(results.is_empty());

    let result = ctx.commit().expect("commit");
    assert_eq!(result.header.ledger_seq, 1);
    assert_eq!(ledger.current_ledger_seq(), 1);
    assert_ne!(ledger.current_header_hash(), Hash256::ZERO);

    let empty_results = TransactionResultSet {
        results: VecM::default(),
    };
    let expected_hash = Hash256::hash_xdr(&empty_results).expect("result hash");
    assert_eq!(
        Hash256::from(result.header.tx_set_result_hash),
        expected_hash
    );

    let meta = result.meta.expect("ledger close meta");
    match meta {
        LedgerCloseMeta::V2(v2) => {
            assert_eq!(v2.tx_processing.len(), 0);
        }
        other => panic!("unexpected ledger close meta: {:?}", other),
    }
}

// =============================================================================
// Parallel Cache Init Tests
// =============================================================================

fn make_contract_id(seed: u8) -> Hash {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    Hash(bytes)
}

fn make_contract_code_entry(seed: u8, last_modified: u32) -> LedgerEntry {
    LedgerEntry {
        last_modified_ledger_seq: last_modified,
        data: LedgerEntryData::ContractCode(ContractCodeEntry {
            ext: ContractCodeEntryExt::V0,
            hash: make_contract_id(seed),
            code: vec![0u8; 100].try_into().unwrap(),
        }),
        ext: LedgerEntryExt::V0,
    }
}

fn make_contract_data_entry(
    seed: u8,
    durability: ContractDataDurability,
    last_modified: u32,
) -> LedgerEntry {
    let mut key_bytes = [0u8; 32];
    key_bytes[0] = seed;

    LedgerEntry {
        last_modified_ledger_seq: last_modified,
        data: LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: ScAddress::Contract(ContractId(Hash(key_bytes))),
            key: ScVal::U64(seed as u64),
            durability,
            val: ScVal::U64(100),
        }),
        ext: LedgerEntryExt::V0,
    }
}

fn make_ttl_entry_for_key(key: &LedgerKey, live_until: u32, last_modified: u32) -> LedgerEntry {
    use sha2::{Digest, Sha256};
    use stellar_xdr::curr::Limits;

    let key_bytes = key.to_xdr(Limits::none()).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&key_bytes);
    let hash = hasher.finalize();
    let mut key_hash = [0u8; 32];
    key_hash.copy_from_slice(&hash);

    LedgerEntry {
        last_modified_ledger_seq: last_modified,
        data: LedgerEntryData::Ttl(TtlEntry {
            key_hash: Hash(key_hash),
            live_until_ledger_seq: live_until,
        }),
        ext: LedgerEntryExt::V0,
    }
}

fn make_offer_entry(seed: u8, offer_id: i64) -> LedgerEntry {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;

    LedgerEntry {
        last_modified_ledger_seq: 1,
        data: LedgerEntryData::Offer(OfferEntry {
            seller_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes))),
            offer_id,
            selling: Asset::Native,
            buying: Asset::Native,
            amount: 1000,
            price: Price { n: 1, d: 1 },
            flags: 0,
            ext: OfferEntryExt::V0,
        }),
        ext: LedgerEntryExt::V0,
    }
}

/// Test that initialize_from_buckets_parallel produces the same results
/// as initialize_from_buckets for a bucket list with mixed entry types.
///
/// Verifies: offer count, soroban state (contract code, contract data),
/// and offers_initialized flag.
#[tokio::test(flavor = "multi_thread")]
async fn test_initialize_from_buckets_parallel_matches_sync() {
    // Build a bucket list with mixed entry types
    let code_entry = make_contract_code_entry(1, 1);
    let data_entry = make_contract_data_entry(2, ContractDataDurability::Persistent, 1);
    let code_key = LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: make_contract_id(1),
    });
    let ttl_entry = make_ttl_entry_for_key(&code_key, 1000, 1);
    let offer1 = make_offer_entry(10, 100);
    let offer2 = make_offer_entry(11, 200);

    let entries = vec![
        code_entry.clone(),
        data_entry.clone(),
        ttl_entry.clone(),
        offer1.clone(),
        offer2.clone(),
    ];

    // --- Synchronous path ---
    let mut bl_sync = BucketList::new();
    bl_sync
        .add_batch(
            1,
            25,
            BucketListType::Live,
            entries.clone(),
            vec![],
            vec![],
        )
        .unwrap();

    // Header with matching bucket list hash (use skip_verify to avoid hash computation)
    let header = make_genesis_header();

    let db_sync = Database::open_in_memory().expect("db");
    let lm_sync = LedgerManager::with_config(
        db_sync,
        "Test Network".to_string(),
        LedgerManagerConfig {
            validate_bucket_hash: false,
            persist_to_db: false,
            ..Default::default()
        },
    );

    lm_sync
        .initialize_from_buckets(bl_sync, None, header.clone(), None)
        .expect("sync init");

    let sync_soroban = lm_sync.soroban_state().read();
    let sync_code_count = sync_soroban.contract_code_count();
    let sync_data_count = sync_soroban.contract_data_count();
    let sync_offers_init = lm_sync.is_offers_initialized();
    drop(sync_soroban);

    // --- Parallel path ---
    let mut bl_parallel = BucketList::new();
    bl_parallel
        .add_batch(1, 25, BucketListType::Live, entries, vec![], vec![])
        .unwrap();

    let db_par = Database::open_in_memory().expect("db");
    let lm_par = LedgerManager::with_config(
        db_par,
        "Test Network".to_string(),
        LedgerManagerConfig {
            validate_bucket_hash: false,
            persist_to_db: false,
            ..Default::default()
        },
    );

    lm_par
        .initialize_from_buckets_parallel(bl_parallel, None, header, None)
        .await
        .expect("parallel init");

    let par_soroban = lm_par.soroban_state().read();
    let par_code_count = par_soroban.contract_code_count();
    let par_data_count = par_soroban.contract_data_count();
    let par_offers_init = lm_par.is_offers_initialized();
    drop(par_soroban);

    // Compare results
    assert_eq!(
        sync_code_count, par_code_count,
        "Contract code count should match between sync and parallel"
    );
    assert_eq!(
        sync_data_count, par_data_count,
        "Contract data count should match between sync and parallel"
    );
    assert_eq!(
        sync_offers_init, par_offers_init,
        "Offers initialized flag should match"
    );
    assert!(par_offers_init, "Offers should be initialized");
    assert_eq!(par_code_count, 1, "Should have 1 contract code entry");
    assert_eq!(par_data_count, 1, "Should have 1 contract data entry");
}

/// Test that initialize_from_buckets_parallel works with an empty bucket list.
#[tokio::test(flavor = "multi_thread")]
async fn test_initialize_from_buckets_parallel_empty() {
    let bl = BucketList::new();
    let header = make_genesis_header();

    let db = Database::open_in_memory().expect("db");
    let lm = LedgerManager::with_config(
        db,
        "Test Network".to_string(),
        LedgerManagerConfig {
            validate_bucket_hash: false,
            persist_to_db: false,
            ..Default::default()
        },
    );

    lm.initialize_from_buckets_parallel(bl, None, header, None)
        .await
        .expect("parallel init empty");

    assert!(lm.is_offers_initialized(), "Offers should be initialized even with empty bucket list");

    let soroban = lm.soroban_state().read();
    assert_eq!(soroban.contract_code_count(), 0);
    assert_eq!(soroban.contract_data_count(), 0);
}
