use stellar_core_bucket::BucketList;
use stellar_core_common::Hash256;
use stellar_core_ledger::{
    LedgerCloseData, LedgerManager, LedgerManagerConfig, TransactionSetVariant,
};
use stellar_xdr::curr::{
    Hash, LedgerCloseMeta, LedgerHeader, LedgerHeaderExt, StellarValue, StellarValueExt, TimePoint,
    TransactionResultSet, TransactionSet, VecM,
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
    let _bucket_dir = tempfile::tempdir().expect("bucket dir");

    let config = LedgerManagerConfig {
        validate_bucket_hash: false,
        ..Default::default()
    };
    let ledger = LedgerManager::new("Test Network".to_string(), config);

    let bucket_list = BucketList::new();
    let header = make_genesis_header();
    ledger
        .initialize_from_buckets(bucket_list, None, header, None)
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

    let result = ledger.close_ledger(close_data).expect("close ledger");
    assert!(result.tx_results.is_empty());
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
