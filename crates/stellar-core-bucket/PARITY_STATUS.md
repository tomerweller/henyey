## C++ Parity Status

**Overall Parity: ~98%**

This section documents the implementation status relative to the C++ stellar-core bucket implementation (v25).

### Summary

| Category | Status | Notes |
|----------|--------|-------|
| Core Data Structures | Complete | BucketList, Bucket, BucketEntry |
| Merge Semantics (CAP-0020) | Complete | INIT/DEAD annihilation, all merge rules |
| Spill Mechanics | Complete | Matches C++ `levelShouldSpill` |
| FutureBucket (Async Merging) | Complete | Tokio-based async merges |
| Hot Archive Bucket List | Complete | Protocol 23+ Soroban state archival |
| Eviction Scanning | Complete | Incremental scanning with iterator |
| Disk-Backed Storage | Complete | Index with integrated bloom filter |
| BucketSnapshot/SnapshotManager | Complete | Thread-safe read snapshots with historical ledger support |
| Advanced Indexing | Complete | InMemoryIndex, DiskIndex, LiveBucketIndex with page ranges, asset-to-pool mapping |
| Specialized Queries | Complete | Inflation winners, type scanning, pool share trustline queries |
| RandomEvictionCache | Complete | LRU cache for account entries |
| BucketMergeMap | Complete | Merge deduplication and reattachment |
| BucketApplicator | Complete | Chunked entry application for catchup |
| Metrics/Counters | Complete | MergeCounters, EvictionCounters, BucketListMetrics |
| Streaming Iterators | Complete | BucketInputIterator, BucketOutputIterator |
| BucketManager State | Complete | loadCompleteLedgerState, mergeAllBuckets, ensureBucketsExist |
| In-Memory Level 0 | Complete | merge_in_memory, level_zero_entries optimization |

### Implemented

#### Core Data Structures
- **BucketList** (`BucketListBase` in C++) - Complete 11-level hierarchical bucket list structure with curr/snap buckets per level
- **BucketLevel** - Individual level with curr, snap, and next (staged merge) buckets
- **Bucket** - Immutable container for sorted ledger entries with content-addressable hash
- **BucketEntry** - All four entry types: Live, Dead, Init, Metadata (matching `BucketEntry` XDR union)

#### Bucket Operations
- **Bucket merging** - Full CAP-0020 INITENTRY/METAENTRY semantics:
  - INIT + DEAD annihilation
  - DEAD + INIT recreation (becomes LIVE)
  - INIT + LIVE preserves INIT status
  - Proper tombstone handling per level
- **merge_buckets** / **merge_buckets_with_options** - Two-way merge with shadowing
- **merge_multiple** - Multi-bucket merging
- **MergeIterator** - Streaming/lazy merge iteration

#### Spill Mechanics
- **level_size** / **level_half** - Spill boundary calculations matching C++ `levelSize`/`levelHalf`
- **level_should_spill** - Spill condition detection
- **keep_tombstone_entries** - Level-dependent tombstone retention
- **bucket_update_period** - Ledger frequency for level updates

#### Storage
- **BucketManager** - Bucket file lifecycle, caching, and garbage collection
- **DiskBucket** - Memory-efficient disk-backed storage with 8-byte key hash index
- In-memory buckets with `BTreeMap` key index for O(1) lookups
- Gzip compression for bucket files
- XDR record marking (RFC 5531) for bucket serialization

#### Eviction (Soroban State Archival)
- **EvictionIterator** - Incremental scan position tracking
- **EvictionResult** - Scan results with archived entries and evicted keys
- **StateArchivalSettings** - Configurable scan parameters
- **scan_for_eviction** / **scan_for_eviction_incremental** - Full and incremental eviction scanning
- **update_starting_eviction_iterator** - Iterator reset on bucket spills
- TTL lookup and expiration checking for Soroban entries

#### Entry Utilities
- **compare_entries** / **compare_keys** - Proper bucket entry ordering (matches C++ `LedgerCmp.h`)
- **ledger_entry_to_key** - Key extraction from ledger entries
- **is_soroban_entry** / **is_temporary_entry** / **is_persistent_entry** - Entry classification
- **get_ttl_key** / **is_ttl_expired** - TTL entry helpers

#### Async Merging
- **FutureBucket** (`future_bucket.rs`) - Async bucket merging support:
  - State machine for merge lifecycle (Clear, HashOutput, HashInputs, LiveOutput, LiveInputs)
  - Background merge execution via tokio async tasks
  - Serialization/deserialization via `FutureBucketSnapshot`
  - `MergeKey` for merge operation deduplication
  - `resolve()` async and `resolve_blocking()` sync resolution
  - `make_live()` for restarting deserialized merges
  - `to_snapshot()` / `from_snapshot()` for HistoryArchiveState persistence

#### Hot Archive Bucket List
- **HotArchiveBucket** (`hot_archive.rs`) - Bucket for archived persistent Soroban entries:
  - Stores `HotArchiveBucketEntry` (Metaentry, Archived, Live variants)
  - `fresh()` for creating from archived entries and restored keys
  - Key-based lookup and iteration
- **HotArchiveBucketList** (`hot_archive.rs`) - Dedicated 11-level bucket list for hot archive:
  - Same spill mechanics as live bucket list
  - `add_batch()` for archiving entries and marking restorations
  - `get()` / `contains()` for looking up archived entries
- **Hot archive merge semantics**:
  - Archived + Live in snap = Keep Archived
  - Live + Archived in snap = Annihilate (entry was restored)
  - Tombstones (Live markers) dropped at level 10

#### Bucket Snapshots (`snapshot.rs`)
- **BucketSnapshot** / **HotArchiveBucketSnapshot** - Read-only bucket snapshots using Arc for thread-safe sharing:
  - `get()` - Key lookup
  - `load_keys()` - Batched key lookups
  - `is_empty()` / `len()` / `hash()` - Bucket metadata
- **BucketListSnapshot** / **HotArchiveBucketListSnapshot** - Complete bucket list snapshots at a ledger:
  - Captures all 11 levels with associated ledger header
  - `get()` - Searches all levels from newest to oldest
  - `load_keys()` - Batched key lookups across all levels
  - `ledger_seq()` / `ledger_header()` - Ledger metadata
- **BucketSnapshotManager** - Thread-safe snapshot management with:
  - RwLock for concurrent read access
  - Historical snapshots for querying past ledger states (configurable count)
  - `update_current_snapshot()` - Main thread updates
  - `copy_searchable_live_snapshot()` / `copy_searchable_hot_archive_snapshot()` - Background thread access
  - `copy_live_and_hot_archive_snapshots()` - Atomic copy of both for consistent state
  - `maybe_update_live_snapshot()` - Refresh-if-newer semantics
- **SearchableBucketListSnapshot** / **SearchableHotArchiveBucketListSnapshot** - Searchable wrappers with:
  - `load()` - Single key lookup
  - `load_keys()` - Batched key lookups
  - `load_keys_from_ledger()` - Historical ledger queries
  - `available_ledger_range()` - Query range of available historical snapshots
  - `load_pool_share_trustlines_by_account_and_asset()` - Pool share trustline queries
  - `load_trustlines_for_account()` - Load all trustlines for an account
  - `scan_for_entries_of_type()` - Type-bounded entry scanning

#### Advanced Indexing (`index.rs`)
- **LiveBucketIndex** - Facade that automatically selects index type based on bucket size:
  - `InMemoryIndex` for small buckets (< 1024 entries by default)
  - `DiskIndex` for large buckets with page-based range index
  - `lookup()` returning offset ranges for key search
  - `get_range_for_type()` for type-bounded queries
- **InMemoryIndex** - Full in-memory index storing all entries:
  - `BTreeMap` key-to-offset mapping
  - Entry counters by type and durability
  - Asset-to-pool ID mapping
- **DiskIndex** - Page-based range index for large buckets:
  - Configurable page size (default 256 entries)
  - Range entries storing lower/upper bounds per page
  - Type ranges for type-bounded queries
  - Bloom filter integration
- **AssetPoolIdMap** - Maps assets to liquidity pool IDs:
  - `add_pool()` to register pool for both assets
  - `get_pool_ids()` to query pools containing an asset
- **BucketEntryCounters** - Entry statistics by type and durability:
  - Count and size tracking per `LedgerEntryTypeAndDurability`
  - Merge support for combining counters

#### Random Eviction Cache (`cache.rs`)
- **RandomEvictionCache** - LRU-style cache for frequently-accessed account entries:
  - Memory-limited with configurable max bytes and entries
  - Only caches Account entries (matching C++ behavior)
  - Thread-safe via `parking_lot::Mutex`
  - Random eviction policy (evicts random entry when full)
  - `get()` / `insert()` / `remove()` operations
  - `maybe_initialize()` based on bucket list account size
  - `CacheStats` for hit/miss tracking

#### Merge Deduplication (`merge_map.rs`)
- **BucketMergeMap** - Tracks merge input-output relationships:
  - `record_merge()` to register completed merges
  - `get_output()` / `has_output()` to find merge results
  - `get_outputs_for_input()` to find all outputs using an input
  - `forget_all_merges_producing()` to remove merges by output hash
  - `retain_outputs()` for garbage collection
- **LiveMergeFutures** - Tracks in-progress merges for reattachment:
  - `get()` / `get_or_insert()` for merge deduplication
  - `remove()` when merge completes
  - `cleanup_completed()` for batch cleanup
  - `MergeFuturesStats` for tracking merge/reattach counts

#### Bucket Applicator (`applicator.rs`)
- **BucketApplicator** - Chunked application of bucket entries for catchup:
  - Configurable chunk size (default 1024 entries)
  - Deduplication via seen-key tracking
  - Optional dead entry application
  - `advance()` to process next chunk
  - `has_more()` / `progress()` for iteration
  - `reset()` to restart from beginning
- **ApplicatorCounters** - Statistics for applied entries:
  - Counts by entry type (upserted/deleted)
  - `merge()` for combining counters
- **EntryToApply** - Enum for upsert vs delete operations

#### Metrics and Counters (`metrics.rs`)
- **MergeCounters** - Merge operation statistics:
  - Pre/post INITENTRY protocol merge counts
  - Running merge reattachment count
  - New meta/init/live/dead entry counts
  - Atomic operations for thread safety
- **EvictionCounters** - Eviction operation statistics:
  - Entries evicted count
  - Bytes scanned count
  - Incomplete bucket scan count
- **BucketListMetrics** - Aggregate bucket list metrics:
  - Entry counts by type and durability
  - Total size tracking
  - Snapshot support for point-in-time capture

#### Streaming Iterators (`iterator.rs`)
- **BucketInputIterator** - File-based streaming iteration:
  - Sequential reading with gzip decompression
  - Automatic metadata entry handling
  - Running hash computation
  - Position tracking (entries read, bytes read)
  - `open()` / `next()` / `peek()` / `collect_all()` operations
- **BucketOutputIterator** - Streaming bucket writing:
  - Gzip compressed output
  - Automatic metadata entry generation (protocol 11+)
  - Single-entry buffering for deduplication
  - Tombstone elision when `keep_tombstones=false`
  - Optional in-memory entry collection (for level 0 optimization)
- **MergeInput** trait - Abstraction for merge operations:
  - `MemoryMergeInput` - In-memory merge of two sorted vectors
  - `FileMergeInput` - File-based merge of two bucket iterators

#### BucketManager State Operations
- **load_complete_ledger_state** - Load full state from bucket list:
  - Iterates buckets from oldest to newest
  - Builds complete state map with dead entries shadowing live
  - Returns all live ledger entries
- **merge_all_buckets** - Merge entire bucket list into single bucket:
  - Creates consolidated "super bucket" from all entries
  - Useful for offline archives or testing
- **verify_buckets_exist** / **verify_bucket_hashes** - Bucket verification:
  - Check bucket files exist on disk
  - Verify bucket content hashes match expected values
- **ensure_buckets_exist** - Bucket fetching support:
  - Checks if buckets exist locally
  - Calls provided fetch function for missing buckets
  - Supports `assumeState` flow for HistoryArchiveState restoration

#### In-Memory Level 0 Optimization (`bucket.rs`, `merge.rs`, `bucket_list.rs`)
- **level_zero_entries** field in Bucket - Optional in-memory entry storage:
  - Enables fast in-memory merges at level 0
  - Avoids disk I/O for frequently-updated buckets
  - `has_in_memory_entries()` / `get_in_memory_entries()` / `set_in_memory_entries()` accessors
- **fresh_in_memory_only** - Create shell bucket for immediate merging:
  - No hash computation or index creation
  - Directly populates in-memory entries
- **merge_in_memory** - Fast level 0 merge using in-memory entries:
  - Uses entries directly from memory (no disk reads)
  - Preserves INIT entries (no normalization at level 0)
  - Keeps tombstones for shadowing deeper levels
  - Result bucket has in-memory entries for next merge
- **prepare_first_level** - BucketLevel method for level 0:
  - Uses in-memory merge when both buckets have entries in memory
  - Falls back to regular merge when entries not available

### Not Yet Implemented (Gaps)

#### Shadow Buckets (FutureBucket.h)
- **Shadow bucket support** - Buckets from lower levels that can inhibit entries during merge (protocol < 12)
- Not needed for protocol 23+ but present in C++ for backward compatibility

#### Medida Metrics Integration
- Full Medida metrics framework integration (counters, timers, meters):
  - `mBucketAddLiveBatch` / `mBucketAddArchiveBatch` timers
  - `mBucketSnapMerge` timer
  - `mCacheHitMeter` / `mCacheMissMeter`
  - Bloom filter metrics (`getBloomMissMeter`, `getBloomLookupMeter`)
- Note: Basic counters implemented in `metrics.rs` (MergeCounters, EvictionCounters, BucketListMetrics)

### Implementation Notes

#### Architectural Differences

1. **Synchronous vs Asynchronous Merging**: The Rust `BucketList::add_batch` performs merges synchronously, while the `FutureBucket` implementation provides async capability. C++ uses `FutureBucket` throughout with background thread pool execution.

2. **Single Bucket Type**: Rust uses a unified `Bucket` type with storage modes (InMemory/DiskBacked), while C++ has separate `LiveBucket` and `HotArchiveBucket` classes with distinct index types (`LiveBucketIndex` vs `HotArchiveBucketIndex`).

3. **Index Design**: Both implementations now support similar index structures:
   - `LiveBucketIndex` facade selecting `InMemoryIndex` or `DiskIndex` based on bucket size
   - Bloom filters for fast negative lookups
   - `RandomEvictionCache` for account entries
   - `AssetPoolIdMap` for liquidity pool queries
   - `BucketEntryCounters` for entry statistics

4. **Snapshot Architecture**: Both use similar snapshot systems with `BucketSnapshotManager` for concurrent read access with historical snapshots.

5. **Error Handling**: Rust uses `Result<T, BucketError>` consistently, while C++ uses exceptions.

6. **Shadow Buckets**: C++ supports shadow buckets for protocol < 12 compatibility; Rust omits this as protocol 23+ is required.

#### Protocol Compatibility

The Rust implementation correctly handles:
- Protocol 11+: INITENTRY and METAENTRY support
- Protocol 12+: Shadow bucket removal (implicitly, by not implementing them)
- Protocol 23+: Persistent eviction with `BucketMetadataExt::V1`, Hot Archive Bucket List

#### Performance Considerations

- Bloom filter integration reduces disk I/O for negative lookups (fast rejection of missing keys)
- Disk-backed buckets reduce memory usage during catchup but load entries on-demand
- `RandomEvictionCache` provides LRU caching for frequently-accessed account entries
- In-memory level 0 optimization reduces disk I/O for frequent merges

#### File Format Compatibility

- Bucket file format is fully compatible (gzip-compressed XDR with RFC 5531 record marking)
- Hash computation matches C++ (SHA-256 over uncompressed XDR including record marks)
- Bucket filenames follow same convention: `<hash>.bucket.gz`

### Future Work Priority

1. **Lower Priority**: Full Medida metrics integration (observability)
2. **Not Needed**: Shadow buckets (protocol < 12 feature, not required for protocol 23+)

### C++ to Rust File Mapping

| C++ File | Rust Equivalent | Status |
|----------|-----------------|--------|
| BucketListBase.h/cpp | bucket_list.rs | Complete |
| LiveBucketList.h/cpp | bucket_list.rs | Complete |
| HotArchiveBucketList.h/cpp | hot_archive.rs | Complete |
| BucketBase.h/cpp | bucket.rs | Complete |
| LiveBucket.h/cpp | bucket.rs, merge.rs | Complete |
| HotArchiveBucket.h/cpp | hot_archive.rs | Complete |
| FutureBucket.h/cpp | future_bucket.rs | Complete (no shadow buckets) |
| BucketManager.h/cpp | manager.rs | Complete (state operations) |
| BucketInputIterator.h/cpp | iterator.rs | Complete |
| BucketOutputIterator.h/cpp | iterator.rs | Complete |
| LiveBucketIndex.h/cpp | index.rs | Complete |
| HotArchiveBucketIndex.h/cpp | hot_archive.rs | Simplified |
| DiskIndex.h/cpp | index.rs (DiskIndex) | Complete |
| InMemoryIndex.h/cpp | index.rs (InMemoryIndex) | Complete |
| BucketSnapshot.h/cpp | snapshot.rs | Complete |
| BucketSnapshotManager.h/cpp | snapshot.rs | Complete |
| SearchableBucketList.h/cpp | snapshot.rs | Complete |
| BucketListSnapshotBase.h/cpp | snapshot.rs | Complete |
| BucketApplicator.h/cpp | applicator.rs | Complete |
| BucketMergeMap.h/cpp | merge_map.rs | Complete |
| BucketMergeAdapter.h | - | Not needed (Rust generics) |
| BucketIndexUtils.h/cpp | index.rs | Complete |
| LedgerCmp.h | entry.rs (compare_keys) | Complete |
| MergeKey.h/cpp | future_bucket.rs (MergeKey) | Complete |
| BucketUtils.h/cpp | entry.rs, eviction.rs | Complete |
| BinaryFuseFilter.h/cpp | bloom_filter.rs, disk_bucket.rs | Complete |
| RandomEvictionCache.h/cpp | cache.rs | Complete |
