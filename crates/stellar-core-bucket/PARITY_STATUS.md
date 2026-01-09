## C++ Parity Status

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
| Disk-Backed Storage | Partial | Simpler index than C++ |
| BucketSnapshot/SnapshotManager | Complete | Thread-safe read snapshots with historical ledger support |
| Advanced Indexing | Partial | Bloom filters implemented, no DiskIndex/InMemoryIndex |
| Specialized Queries | Partial | Inflation winners, type scanning implemented; pool share lookups pending |
| Metrics/Monitoring | Not Implemented | Medida integration |

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

### Not Yet Implemented (Gaps)

#### Specialized Queries (SearchableBucketList.h)
- **SearchableLiveBucketListSnapshot** specialized queries:
  - `loadPoolShareTrustLinesByAccountAndAsset()` - Pool share lookups - **Not Implemented** (requires asset-to-poolID index)
  - `loadInflationWinners()` - **Implemented** as `load_inflation_winners()` in `snapshot.rs`
  - `scanForEviction()` - Background eviction scanning - Partial (basic eviction in eviction.rs)
  - `scanForEntriesOfType()` - **Implemented** as `scan_for_entries_of_type()` in `snapshot.rs`
- **SearchableHotArchiveBucketListSnapshot** - Hot archive snapshot queries - Basic structure exists
- **InflationWinner** struct - **Implemented** in `snapshot.rs`

#### Advanced Indexing (LiveBucketIndex.h, DiskIndex.h, InMemoryIndex.h)
- **LiveBucketIndex** - Sophisticated index supporting:
  - **DiskIndex** - Disk-based page index for large buckets with configurable page sizes
  - **InMemoryIndex** - Full in-memory index for small buckets
  - Automatic selection based on bucket size threshold
  - `lookup()` returning offset ranges for key search
  - `scan()` for iterative key lookups
  - `getRangeForType()` for type-bounded queries
- **RandomEvictionCache** - LRU cache for account entries with:
  - Memory-limited cache sizing
  - `maybeInitializeCache()` based on bucket list account size
  - Thread-safe access via shared mutex
- **Bloom filter** - Implemented as `BucketBloomFilter` in `bloom_filter.rs`:
  - Uses `BinaryFuse16` (same algorithm as C++ via xorf crate)
  - False positive rate ~1/65536 (~0.0015%)
  - SipHash-2-4 key hashing for C++ compatibility
  - `may_contain()` / `may_contain_hash()` for fast negative lookups
  - Standalone module; not yet integrated with DiskBucket
- **Asset-to-PoolID mapping** - `getPoolIDsByAsset()` for liquidity pool queries - Not Implemented
- **HotArchiveBucketIndex** - Index for hot archive buckets - Not Implemented
- The Rust `DiskBucket` uses a simpler 8-byte key hash to file offset index (no range index, no page index)

#### Iterator Types (BucketInputIterator.h, BucketOutputIterator.h)
- **BucketInputIterator** - File-based iterator with:
  - Seeking and position tracking
  - Entry-by-entry streaming from disk
  - Hash verification during iteration
- **BucketOutputIterator** - Output iterator for writing bucket files:
  - Streaming writes with incremental hashing
  - Buffer management for efficiency
- The Rust implementation uses in-memory iteration via `BucketIter` or sequential disk reads

#### Shadow Buckets (FutureBucket.h)
- **Shadow bucket support** - Buckets from lower levels that can inhibit entries during merge (protocol < 12)
- The Rust `FutureBucket` does not include `mInputShadowBuckets` / `mInputShadowBucketHashes`
- Not needed for protocol 23+ but present in C++ for backward compatibility

#### In-Memory Level 0 Optimizations (LiveBucket.h)
- **mergeInMemory** - Faster level 0 merges keeping entries in RAM
- **mEntries** vector in `LiveBucket` - In-memory entry storage for level 0
- Rust performs all merges the same way regardless of level

#### BucketManager Features (BucketManager.h)
- **BucketMergeMap** (`mFinishedMerges`) - Weak reference map of completed merges for deduplication
- **FutureMapT** (`mLiveBucketFutures`, `mHotArchiveBucketFutures`) - Maps of in-progress merges with shared futures
- **getMergeFuture** / **putMergeFuture** - Merge future deduplication
- **assumeState** - Restore bucket list from HistoryArchiveState with merge restart
- **loadCompleteLedgerState** / **loadCompleteHotArchiveState** - Load full state from HAS
- **mergeBuckets** (on BucketManager) - Merge entire bucket list into single "super bucket"
- **visitLedgerEntries** - Filtered iteration over bucket list with callbacks and `minLedger` support
- **scheduleVerifyReferencedBucketsWork** - Background hash verification work
- **cleanupStaleFiles** / **forgetUnreferencedBuckets** - Garbage collection
- **maybeSetIndex** - Race-condition-safe index setting during startup

#### BucketApplicator (BucketApplicator.h)
- **BucketApplicator** - Apply bucket entries to database for catchup/replay
- Used in testing and debugging scenarios

#### Metrics and Monitoring
- Medida metrics integration (counters, timers, meters):
  - `mBucketLiveObjectInsertBatch` / `mBucketArchiveObjectInsertBatch`
  - `mBucketAddLiveBatch` / `mBucketAddArchiveBatch` timers
  - `mBucketSnapMerge` timer
  - `mSharedBucketsSize` counter
  - `mLiveBucketListSizeCounter` / `mArchiveBucketListSizeCounter`
  - `mCacheHitMeter` / `mCacheMissMeter`
  - `mLiveBucketIndexCacheEntries` / `mLiveBucketIndexCacheBytes`
  - `mBucketListEvictionCounters`
  - `mLiveMergeCounters` / `mHotArchiveMergeCounters`
- `BucketEntryCounters` - Entry count metrics by type and durability
- Bloom filter metrics (`getBloomMissMeter`, `getBloomLookupMeter`)
- `reportBucketEntryCountMetrics()` / `reportLiveBucketIndexCacheMetrics()`

### Implementation Notes

#### Architectural Differences

1. **Synchronous vs Asynchronous Merging**: The Rust `BucketList::add_batch` performs merges synchronously, while the `FutureBucket` implementation provides async capability. C++ uses `FutureBucket` throughout with background thread pool execution.

2. **Single Bucket Type**: Rust uses a unified `Bucket` type with storage modes (InMemory/DiskBacked), while C++ has separate `LiveBucket` and `HotArchiveBucket` classes with distinct index types (`LiveBucketIndex` vs `HotArchiveBucketIndex`).

3. **Index Design**: The Rust `DiskBucket` uses a simple hash-to-offset index (16 bytes per entry: 8-byte key hash + 8-byte offset/length), while C++ `LiveBucketIndex` supports:
   - Both in-memory and disk-based page indexes
   - Bloom filters for fast negative lookups
   - RandomEvictionCache for account entries
   - Asset-to-PoolID mappings

4. **Snapshot Architecture**: C++ has a sophisticated snapshot system (`BucketSnapshotManager`) for concurrent read access with historical snapshots, while Rust relies on `Arc` and cloning for thread safety.

5. **Error Handling**: Rust uses `Result<T, BucketError>` consistently, while C++ uses exceptions.

6. **Shadow Buckets**: C++ supports shadow buckets for protocol < 12 compatibility; Rust omits this as protocol 23+ is required.

#### Protocol Compatibility

The Rust implementation correctly handles:
- Protocol 11+: INITENTRY and METAENTRY support
- Protocol 12+: Shadow bucket removal (implicitly, by not implementing them)
- Protocol 23+: Persistent eviction with `BucketMetadataExt::V1`, Hot Archive Bucket List

#### Performance Considerations

- The simpler index design may require optimization for mainnet performance (no Bloom filter means more disk I/O)
- Disk-backed buckets reduce memory usage during catchup but load entries on-demand
- No cache layer for frequently-accessed entries (e.g., accounts) unlike C++'s RandomEvictionCache
- No in-memory level 0 optimization

#### File Format Compatibility

- Bucket file format is fully compatible (gzip-compressed XDR with RFC 5531 record marking)
- Hash computation matches C++ (SHA-256 over uncompressed XDR including record marks)
- Bucket filenames follow same convention: `<hash>.bucket.gz`

### Future Work Priority

1. **Medium Priority**: Advanced indexing (Bloom filters, caches) for query performance
2. **Medium Priority**: SearchableBucketListSnapshot specialized queries (pool shares, inflation winners)
3. **Lower Priority**: Metrics integration (observability)
4. **Lower Priority**: In-memory level 0 optimizations

### C++ to Rust File Mapping

| C++ File | Rust Equivalent | Status |
|----------|-----------------|--------|
| BucketListBase.h/cpp | bucket_list.rs | Complete |
| LiveBucketList.h/cpp | bucket_list.rs | Complete |
| HotArchiveBucketList.h/cpp | hot_archive.rs | Complete |
| BucketBase.h/cpp | bucket.rs | Complete |
| LiveBucket.h/cpp | bucket.rs, merge.rs | Partial (no in-memory optimization) |
| HotArchiveBucket.h/cpp | hot_archive.rs | Complete |
| FutureBucket.h/cpp | future_bucket.rs | Complete (no shadow buckets) |
| BucketManager.h/cpp | manager.rs | Partial |
| BucketInputIterator.h/cpp | bucket.rs (BucketIter) | Simplified |
| BucketOutputIterator.h/cpp | bucket.rs | Simplified (no streaming) |
| LiveBucketIndex.h/cpp | disk_bucket.rs | Simplified |
| HotArchiveBucketIndex.h/cpp | hot_archive.rs | Simplified |
| DiskIndex.h/cpp | disk_bucket.rs | Simplified |
| InMemoryIndex.h/cpp | bucket.rs (key_index) | Partial |
| BucketSnapshot.h/cpp | snapshot.rs | Complete |
| BucketSnapshotManager.h/cpp | snapshot.rs | Complete |
| SearchableBucketList.h/cpp | snapshot.rs | Partial (no specialized queries) |
| BucketListSnapshotBase.h/cpp | snapshot.rs | Complete |
| BucketApplicator.h/cpp | - | Not implemented |
| BucketMergeMap.h/cpp | - | Not implemented |
| BucketMergeAdapter.h | - | Not needed (Rust generics) |
| BucketIndexUtils.h/cpp | - | Not implemented |
| LedgerCmp.h | entry.rs (compare_keys) | Complete |
| MergeKey.h/cpp | future_bucket.rs (MergeKey) | Complete |
| BucketUtils.h/cpp | entry.rs, eviction.rs | Complete |
| BinaryFuseFilter.h/cpp | bloom_filter.rs | Complete (via xorf crate) |
