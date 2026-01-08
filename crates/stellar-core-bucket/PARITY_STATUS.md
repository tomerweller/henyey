## C++ Parity Status

This section documents the implementation status relative to the C++ stellar-core bucket implementation (v25).

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
- **compare_entries** / **compare_keys** - Proper bucket entry ordering
- **ledger_entry_to_key** - Key extraction from ledger entries
- **is_soroban_entry** / **is_temporary_entry** / **is_persistent_entry** - Entry classification
- **get_ttl_key** / **is_ttl_expired** - TTL entry helpers

### Not Yet Implemented (Gaps)

#### Async Merging
- **FutureBucket** - Async bucket merging with `std::shared_future`. The Rust implementation uses synchronous merging. FutureBucket provides:
  - Background merge threads that run in parallel with ledger closing
  - State machine for merge lifecycle (FB_CLEAR, FB_HASH_OUTPUT, FB_HASH_INPUTS, FB_LIVE_OUTPUT, FB_LIVE_INPUTS)
  - Serialization/deserialization of in-progress merges to HistoryArchiveState
  - Merge result caching via `BucketMergeMap`

#### Hot Archive Bucket List
- **HotArchiveBucket** - Separate bucket type for archived persistent Soroban entries
- **HotArchiveBucketList** - Dedicated bucket list for hot archive
- **HotArchiveBucketEntry** - XDR entry type with ARCHIVED/DELETED variants
- **HotArchiveBucketIndex** - Index for hot archive buckets
- The Rust implementation tracks archived entries in `EvictionResult` but doesn't maintain a separate hot archive bucket list

#### Bucket Snapshots
- **BucketSnapshot** / **BucketSnapshotBase** - Read-only bucket snapshots for concurrent access
- **BucketSnapshotManager** - Thread-safe snapshot management with historical snapshots
- **SearchableLiveBucketListSnapshot** - Searchable snapshot with specialized queries:
  - `loadPoolShareTrustLinesByAccountAndAsset`
  - `loadInflationWinners`
  - `loadKeys` with batched lookups
  - `scanForEntriesOfType`
- **SearchableHotArchiveBucketListSnapshot** - Hot archive snapshot queries

#### Advanced Indexing
- **LiveBucketIndex** - Sophisticated index with:
  - **DiskIndex** - Disk-based page index for large buckets with configurable page sizes
  - **InMemoryIndex** - Full in-memory index for small buckets
  - Bloom filter for fast negative lookups
  - **RandomEvictionCache** - LRU cache for account entries
  - Asset-to-PoolID mapping for liquidity pool queries
  - Range queries by `LedgerEntryType`
- **HotArchiveBucketIndex** - Index for hot archive buckets
- The Rust `DiskBucket` uses a simpler 8-byte key hash to file offset index

#### Specialized Merge Features
- **Shadow buckets** - Buckets from lower levels that can inhibit entries during merge (protocol < 12)
- **In-memory level 0 merges** - `LiveBucket::mergeInMemory` for faster level 0 operations
- **In-memory bucket entries** - `mEntries` vector in `LiveBucket` for level 0 optimizations
- **MergeCounters** - Detailed metrics for merge operations

#### Iterator Types
- **BucketInputIterator** - File-based iterator with seeking and position tracking
- **BucketOutputIterator** - Output iterator for writing bucket files with hashing
- The Rust implementation uses in-memory iteration via `BucketIter`

#### Additional Features
- **BucketApplicator** - Apply bucket entries to database (for tests/debugging)
- **BucketMergeMap** - Weak reference map of completed merges for deduplication
- **MergeKey** - Unique identifier for merge operations (input hashes)
- **LedgerCmp** - Comparators for ledger entries
- **visitLedgerEntries** - Filtered iteration over bucket list with callbacks
- **mergeBuckets** (on BucketManager) - Merge entire bucket list into single "super bucket"
- **loadCompleteLedgerState** / **loadCompleteHotArchiveState** - Load full state from HAS
- **scheduleVerifyReferencedBucketsWork** - Background hash verification
- **assumeState** - Restore bucket list from HistoryArchiveState

#### Metrics and Monitoring
- Medida metrics integration (counters, timers, meters)
- Bucket entry count metrics by type and durability
- Cache hit/miss metrics
- Bloom filter metrics
- Merge timing metrics

### Implementation Notes

#### Architectural Differences

1. **Synchronous vs Asynchronous Merging**: The Rust implementation performs bucket merges synchronously within `add_batch`, while C++ uses `FutureBucket` to run merges in background threads. This simplifies the Rust code but may impact performance for large merges.

2. **Single Bucket Type**: Rust uses a unified `Bucket` type with storage modes (InMemory/DiskBacked), while C++ has separate `LiveBucket` and `HotArchiveBucket` classes with distinct index types.

3. **Index Design**: The Rust `DiskBucket` uses a simple hash-to-offset index (16 bytes per entry), while C++ `LiveBucketIndex` supports both in-memory and disk-based page indexes with Bloom filters and caches.

4. **Snapshot Architecture**: C++ has a sophisticated snapshot system (`BucketSnapshotManager`) for concurrent read access, while Rust relies on `Arc` and cloning for thread safety.

5. **Error Handling**: Rust uses `Result<T, BucketError>` consistently, while C++ uses exceptions.

#### Protocol Compatibility

The Rust implementation correctly handles:
- Protocol 11+: INITENTRY and METAENTRY support
- Protocol 12+: Shadow bucket removal
- Protocol 23+: Persistent eviction with `BucketMetadataExt::V1`

#### Performance Considerations

- The synchronous merge design may require optimization for mainnet performance
- Disk-backed buckets reduce memory usage during catchup but load entries on-demand
- No Bloom filter means all lookups require index access
- No cache layer for frequently-accessed entries (e.g., accounts)

#### Future Work Priority

1. **High Priority**: FutureBucket for async merging (performance critical)
2. **High Priority**: HotArchiveBucketList for Soroban state archival completeness
3. **Medium Priority**: BucketSnapshotManager for concurrent access patterns
4. **Medium Priority**: Advanced indexing (Bloom filters, caches) for query performance
5. **Lower Priority**: Metrics integration (observability)
