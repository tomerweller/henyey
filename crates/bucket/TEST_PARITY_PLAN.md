# Bucket Crate Test Parity Plan

stellar-core: `stellar-core/src/bucket/test/` (5 files, ~42 top-level test cases, ~42 sub-sections)
Rust: `crates/henyey-bucket/` (286 tests across 21 modules + 3 integration test files)

## Architecture Mapping

| stellar-core Concept | Rust Equivalent |
|---|---|
| `BucketList` (11-level hierarchy) | `BucketList` (same 11-level structure) |
| `HotArchiveBucketList` | `HotArchiveBucketList` |
| `Bucket` (file-backed) | `Bucket` (in-memory) + `DiskBucket` (disk-backed) |
| `BucketManager` (singleton) | `BucketManager` (shared ownership) |
| `BucketIndex` / `BucketListDB` | `LiveBucketIndex` + `DiskIndex` + `InMemoryIndex` |
| `BucketOutputIterator` | `BucketOutputIterator` |
| `FutureBucket` (async merge) | `FutureBucket` + `LiveMergeFutures` |
| `EvictionIterator` | `EvictionIterator` |
| `SearchableBucketListSnapshot` | `SearchableBucketListSnapshot` |
| `BucketMergeMap` | `BucketMergeMap` |
| App restart / persistence | `BucketManager` disk operations (no full app restart) |

---

## Per-Test Parity Analysis

### 1. BucketTests.cpp

| # | stellar-core Test | Rust Equivalent | Status | Notes |
|---|----------|-----------------|--------|-------|
| 1.1 | `file backed buckets` - 10K entries, disk bucket creation, merge performance | `bucket.rs:test_bucket_save_and_load`, `test_disk_backed_bucket_roundtrip`, `test_disk_backed_with_metadata`, `test_xdr_serialization_roundtrip_produces_identical_bytes` | **COVERED** | Disk-backed storage well tested across 5+ tests |
| 1.2 | `merging bucket entries` / `dead [type] annihilates live [type]` - per entry type | `merge.rs:test_merge_dead_shadows_live`, `bucket_list.rs:test_live_dead_merge_semantics` | **COVERED** | Tests cover all entry types through generic merge logic |
| 1.3 | `merging bucket entries` / `random dead annihilates live` | `merge.rs:test_merge_shadow`, `test_merge_complex` | **COVERED** | Random merge scenarios tested |
| 1.4 | `merging bucket entries` / `random live overwrites live` | `merge.rs:test_merge_no_overlap`, `test_merge_complex` | **COVERED** | Live-overwrites-live in merge tests |
| 1.5 | `merging hot archive bucket entries` / `new annihilates old` | `hot_archive.rs:test_merge_newer_always_wins_*` (3 tests) | **COVERED** | Archived+Archived, Archived+Live, Live+Archived all tested |
| 1.6 | `merges proceed old-style despite newer shadows` - shadow version 12, mixed versions, refuse new version | `merge.rs:test_shadow_filtering_pre_protocol_12`, `test_shadow_filtering_disabled_post_protocol_12`, `test_shadow_empty_shadows_is_noop` | **COVERED** | Shadow+protocol version interaction tested with 3 dedicated tests |
| 1.7 | `merges refuse to exceed max protocol version` | `hot_archive.rs:test_hot_archive_merge_validates_constraint`, `merge.rs:test_build_output_metadata_validates_constraint` | **COVERED** | Protocol version cap enforced and tested |
| 1.8 | `bucket output iterator rejects wrong-version entries` - INITENTRY/METAENTRY rejected for old protocols | `merge.rs:test_pre_protocol_11_merge_produces_no_metadata`, `test_pre_protocol_11_merge_normalizes_init_to_live`, `test_in_memory_merge_pre_protocol_11_no_metadata` | **COVERED** | Version-dependent entry handling tested with 3 tests |
| 1.9 | `merging bucket entries with initentry` - dead+init annihilation, intervening live entries, multi-bucket | `merge.rs:test_cap0020_*` (5 tests), `bucket_list.rs:test_dead_plus_init_merge_semantics`, `test_init_dead_merge_semantics`, `test_init_live_merge_semantics` | **COVERED** | CAP-0020 comprehensively tested with 8+ dedicated tests |
| 1.10 | `merging bucket entries with initentry with shadows` - shadows don't revive dead, don't eliminate init | `merge.rs:test_shadow_preserves_init_entries_in_init_era`, `test_shadow_preserves_dead_entries_in_init_era`, `test_shadow_filters_live_but_not_lifecycle_entries`, `test_shadow_does_not_revive_dead_entries`, `test_shadow_does_not_eliminate_init_entries` | **COVERED** | Shadow+lifecycle interaction thoroughly tested with 5 dedicated tests |

### 2. BucketListTests.cpp

| # | stellar-core Test | Rust Equivalent | Status | Notes |
|---|----------|-----------------|--------|-------|
| 2.1 | `bucket list` - basic live BL and hot archive BL (130 batches) | `bucket_list.rs:test_bucket_list_add_batch`, `test_bucket_list_get`, integration `test_bucket_list_basic_operations` | **COVERED** | |
| 2.2 | `bucketUpdatePeriod arithmetic` - live BL and hot archive BL | `eviction.rs:test_bucket_update_period`, `test_bucket_update_period_arithmetic` | **COVERED** | |
| 2.3 | `bucket list shadowing pre/post proto 12` - frequently updated entries | `bucket_list.rs:test_bucket_list_lookup_shadowing`, `test_bucket_list_lookup_shadowing_correctness`, `test_bucket_list_shadowing_multiple_keys` | **COVERED** | Multiple shadowing tests verify latest value always returned |
| 2.4 | `hot archive bucket tombstones expire at bottom level` | integration `test_hot_archive_tombstones_expire_at_bottom_level` | **COVERED** | |
| 2.5 | `hot archive accepts multiple archives and restores for same key` | integration `test_hot_archive_multiple_archives_and_restores` | **COVERED** | |
| 2.6 | `live bucket tombstones expire at bottom level` | integration `test_tombstones_expire_at_bottom_level` | **COVERED** | |
| 2.7 | `bucket tombstones mutually-annihilate init entries` | integration `test_init_dead_annihilation` | **COVERED** | |
| 2.8 | `single entry bubbling up` | integration `test_single_entry_bubbling_up` | **COVERED** | |
| 2.9 | `BucketList sizeOf and oldestLedgerIn relations` - live + hot archive | `eviction.rs:test_level_size`, `test_level_half`, `test_bucket_update_period` | **COVERED** | Mathematical relations validated |
| 2.10 | `BucketList snap reaches steady state` - live + hot archive | integration `test_bucket_list_snap_steady_state` | **COVERED** | |
| 2.11 | `BucketList deepest curr accumulates` - live + hot archive | integration `test_bucket_list_deepest_curr_accumulates` | **COVERED** | |
| 2.12 | `BucketList sizes at ledger 1` - live + hot archive | `bucket_list.rs:test_bucket_list_sizes_at_ledger_1`, `test_hot_archive_bucket_list_sizes_at_ledger_1` | **COVERED** | Genesis structure verified for both bucket list types |
| 2.13 | `BucketList check bucket sizes` - 256 ledgers iterative | `bucket_list.rs:test_bucket_list_iterative_size_check`, `test_bucket_list_entry_bounds_after_spills` | **COVERED** | Iterative size and entry bounds validated over 256 ledgers |
| 2.14 | `network config snapshots Soroban state size` | N/A | **NOT APPLICABLE** | Higher-level feature; state size tracking is in ledger/execution crate |
| 2.15 | `eviction scan` - basic, shadowed, maxEntriesToArchive, scanSize, cross-bucket, iterator reset | `eviction.rs` (17 tests), integration tests (7 eviction tests) | **COVERED** | Comprehensive eviction coverage with 24+ tests |
| 2.16 | `Searchable BucketListDB snapshots` | integration `test_searchable_bucket_list_snapshots` | **COVERED** | |
| 2.17 | `BucketList number dump` | N/A | **NOT APPLICABLE** | Debug/informational test (`[!hide]` tag) |

### 3. BucketManagerTests.cpp

| # | stellar-core Test | Rust Equivalent | Status | Notes |
|---|----------|-----------------|--------|-------|
| 3.1 | `skip list` - skip list calculation | `henyey-ledger/header.rs:test_calculate_skip_values` | **COVERED** | In different crate (ledger) |
| 3.2 | `bucketmanager ownership` - reference counting, cleanup | `manager.rs:test_bucket_arc_reference_counting`, `test_bucket_gc_lifecycle`, `test_bucket_deduplication`, `test_retain_buckets` | **COVERED** | Arc refcounting, GC cleanup, deduplication all tested |
| 3.3 | `bucketmanager missing buckets fail` - app startup with missing files | `manager.rs:test_missing_bucket_detected`, `test_load_missing_bucket_fails`, `test_verify_buckets_exist` | **COVERED** | Missing file detection and load failure tested |
| 3.4 | `bucketmanager reattach to finished merge` - serialization/deserialization of merge state | `future_bucket.rs:test_reattach_to_finished_merge`, `test_snapshot_roundtrip_all_states`, `manager.rs:test_merge_result_persists_on_disk` | **COVERED** | Full roundtrip: serialize → deserialize → make_live → verify output |
| 3.5 | `bucketmanager reattach to running merge` - with artificial delay | `future_bucket.rs:test_reattach_to_running_merge` | **COVERED** | Serialize in-progress merge as HashInputs → deserialize → make_live restarts merge → resolve → verify identical result |
| 3.6 | `bucketmanager do not leak empty-merge futures` | `merge_map.rs:test_retain_outputs_gc`, integration `test_retain_outputs_gc` | **COVERED** | GC and cleanup well tested |
| 3.7 | `bucketmanager reattach HAS from publish queue to finished merge` | N/A | **NOT APPLICABLE** | Requires history publish queue (not yet implemented) |
| 3.8 | `bucket persistence over app restart with initentry` | N/A | **NOT APPLICABLE** | Complex multi-restart test with app restart infrastructure |
| 3.9 | `bucket persistence over app restart` | `future_bucket.rs:test_persistence_across_simulated_restart`, `test_persistence_with_incomplete_merge`, `manager.rs:test_merge_result_persists_on_disk` | **COVERED** | Persistence tested via snapshot roundtrip with merge continuation |

### 4. BucketIndexTests.cpp

| # | stellar-core Test | Rust Equivalent | Status | Notes |
|---|----------|-----------------|--------|-------|
| 4.1 | `key-value lookup` | `index.rs:test_in_memory_index`, `test_disk_index`, `bucket.rs:test_bucket_lookup` | **COVERED** | |
| 4.2 | `bl cache` - disable cache, populate, correctness | `cache.rs:test_cache_*` (8 tests) | **COVERED** | Comprehensive cache testing |
| 4.3 | `do not load outdated values` | `bucket_list.rs:test_bucket_list_lookup_shadowing`, `test_bucket_list_updates` | **COVERED** | Shadowing ensures latest value returned |
| 4.4 | `bucket entry counters` | `index.rs:test_entry_counters`, `metrics.rs:test_bucket_list_metrics` | **COVERED** | |
| 4.5 | `in-memory index construction` - with/without offers, offers at end/middle | `index.rs:test_index_with_no_offers`, `test_index_with_offers_at_end`, `test_index_with_offers_between_types` | **COVERED** | Offer positioning tested at end and between other entry types |
| 4.6 | `soroban cache population` | `index.rs:test_soroban_entry_counters`, `test_soroban_dead_entry_counters` | **COVERED** | Contract code/data durability counters validated |
| 4.7 | `load from historical snapshots` | `snapshot.rs:test_bucket_list_snapshot_*` (8 tests) | **COVERED** | |
| 4.8 | `loadPoolShareTrustLinesByAccountAndAsset` | `tests/test_pool_share_query.rs` (6 tests) | **COVERED** | Thorough pool share query testing |
| 4.9 | `loadAccountsByAccountID` | `index.rs:test_account_lookup_by_id`, `test_account_lookup_with_bloom_filter` | **COVERED** | Account lookup with bloom filter and offset verification |
| 4.10 | `ContractData key with same ScVal` | `index.rs:test_contract_data_same_scval_different_contracts`, `test_contract_data_same_scval_different_durability` | **COVERED** | Same ScVal with different contracts and durabilities distinguished |
| 4.11 | `serialize bucket indexes` | `index_persistence.rs:test_save_load_*` (12 tests) | **COVERED** | Comprehensive serialization/deserialization testing |
| 4.12 | `hot archive bucket lookups` | `hot_archive.rs:test_hot_archive_bucket_lookup`, `snapshot.rs:test_searchable_hot_archive_snapshot` | **COVERED** | |
| 4.13 | `getRangeForType bounds verification` - type ranges, single type, scan by type | `index.rs:test_range_entry`, integration `test_scan_for_entries_of_types_*` (6 tests) | **COVERED** | Entry-type scanning comprehensively tested |

### 5. BucketMergeMapTests.cpp

| # | stellar-core Test | Rust Equivalent | Status | Notes |
|---|----------|-----------------|--------|-------|
| 5.1 | `bucket merge map` - recording, lookup, caching | `merge_map.rs` (6 tests), `tests/test_merge_deduplication.rs` (7 tests) | **COVERED** | 13 tests including explicit stellar-core parity test |

---

## Summary

### Coverage Statistics

| Status | Count | % |
|--------|-------|---|
| **COVERED** | 38 | 90% |
| **NOT APPLICABLE** | 4 | 10% |
| **PARTIAL** | 0 | 0% |
| **MISSING** | 0 | 0% |
| **Total** | 42* | 100% |

\* Some stellar-core test cases with multiple sections are counted as one.

Excluding NOT APPLICABLE:

| Status | Count | % of applicable |
|--------|-------|-----------------|
| **COVERED** | 38 | 100% |
| **Total applicable** | 38 | 100% |

### Existing Rust-Only Tests (no stellar-core equivalent)

The Rust bucket crate has extensive testing beyond what stellar-core tests cover:

| Category | Test Count | Modules |
|----------|-----------|---------|
| Bloom filter | 7 | bloom_filter.rs |
| Bucket applicator (catchup) | 8 | applicator.rs |
| Disk bucket I/O | 7 | disk_bucket.rs |
| Live entries iterator | 7 | live_iterator.rs |
| Merge deduplication (advanced) | 13 | merge_map.rs, test_merge_deduplication.rs |
| Snapshot thread safety | 8 | snapshot.rs |
| Entry type scanning | 6 | bucket_list_integration.rs |
| Hot archive concurrent ops | 1 | bucket_list_integration.rs |
| Index persistence versioning | 12 | index_persistence.rs |
| Cache eviction policy | 8 | cache.rs |
