# stellar-core-bucket

BucketList implementation for rs-stellar-core.

## Overview

The BucketList is Stellar's canonical on-disk data structure for storing ledger state. It organizes all ledger entries into a hierarchical structure of immutable "bucket" files, enabling efficient incremental updates, integrity verification, and state archival.

This crate provides a complete Rust implementation of the bucket list, compatible with C++ stellar-core's bucket format and semantics.

## Key Concepts

### BucketList Structure

The bucket list consists of 11 levels (0-10), where each level contains two buckets:

- **curr**: The current bucket being filled with merged entries
- **snap**: The snapshot bucket from the previous spill

```
Level 0:  [curr] [snap]   <- Updates every 2 ledgers (newest data)
Level 1:  [curr] [snap]   <- Updates every 8 ledgers
Level 2:  [curr] [snap]   <- Updates every 32 ledgers
...
Level 10: [curr] [snap]   <- Never spills (oldest data)
```

Lower levels update more frequently and contain recent data. Higher levels contain older, more stable data. This log-structured merge tree (LSM) design optimizes for append-heavy workloads.

### Bucket Entries

Bucket entries come in four types:

| Type | Description | XDR Discriminant |
|------|-------------|------------------|
| `Live` | An active ledger entry (current state) | 0 (LIVEENTRY) |
| `Init` | Entry created in this merge window (CAP-0020) | 1 (INITENTRY) |
| `Dead` | Tombstone marking deletion | 2 (DEADENTRY) |
| `Metadata` | Bucket metadata (protocol version) | 3 (METAENTRY) |

### Merge Semantics (CAP-0020)

When buckets are merged, entries interact according to these rules:

| Old Entry | New Entry | Result |
|-----------|-----------|--------|
| `Init` | `Dead` | Nothing (both annihilated) |
| `Dead` | `Init` | `Live` (recreation) |
| `Init` | `Live` | `Init` with new value |
| `Live` | `Dead` | `Dead` (if keeping tombstones) |
| `Live` | `Live` | Newer `Live` wins |

The `Init` type prevents tombstone accumulation when entries are created and deleted within the same merge window.

### Spill Schedule

Levels spill based on ledger sequence boundaries:

- `level_size(N)` = 4^(N+1): Size boundary for level N
- `level_half(N)` = level_size(N) / 2: Half-size boundary
- A level spills when the ledger is at a half or full size boundary

| Level | Size | Half | Spill Period |
|-------|------|------|--------------|
| 0 | 4 | 2 | 2 ledgers |
| 1 | 16 | 8 | 8 ledgers |
| 2 | 64 | 32 | 32 ledgers |
| 6 | 16384 | 8192 | 8192 ledgers |
| 10 | 4194304 | 2097152 | Never |

## Key Types

### Core Types

- **`Bucket`**: An immutable container of sorted ledger entries, identified by SHA-256 hash
- **`BucketList`**: The complete 11-level bucket list structure
- **`BucketLevel`**: A single level with `curr` and `snap` buckets
- **`BucketEntry`**: A single entry (Live, Dead, Init, or Metadata)

### Storage

- **`BucketManager`**: Manages bucket files on disk with caching
- **`DiskBucket`**: Memory-efficient disk-backed bucket for large buckets

### Eviction (Soroban State Archival)

- **`EvictionIterator`**: Tracks incremental scan position
- **`EvictionResult`**: Entries to archive and delete after a scan
- **`StateArchivalSettings`**: Configuration for eviction scans

## Usage

### Creating and Using a BucketList

```rust
use stellar_core_bucket::{BucketList, BucketEntry, BucketManager};
use stellar_xdr::curr::BucketListType;

// Create a bucket manager for disk storage
let manager = BucketManager::new("/path/to/buckets".into())?;

// Create a new bucket list
let mut bucket_list = BucketList::new();

// Add entries from a closed ledger
bucket_list.add_batch(
    ledger_seq,              // Current ledger sequence
    protocol_version,        // Protocol version
    BucketListType::Live,    // Live vs hot archive
    init_entries,            // Newly created entries
    live_entries,            // Updated entries
    dead_entries,            // Deleted entries
)?;

// Look up an entry
if let Some(entry) = bucket_list.get(&key)? {
    // Process the entry
}

// Get the bucket list hash for verification
let hash = bucket_list.hash();
```

### Working with Buckets

```rust
use stellar_core_bucket::{Bucket, BucketEntry};

// Create a bucket from entries
let entries = vec![
    BucketEntry::Live(account_entry),
    BucketEntry::Dead(deleted_key),
];
let bucket = Bucket::from_entries(entries)?;

// Get bucket hash (content-addressable)
let hash = bucket.hash();

// Look up an entry
if let Some(entry) = bucket.get(&key)? {
    match entry {
        BucketEntry::Live(le) => println!("Found live entry"),
        BucketEntry::Dead(_) => println!("Entry was deleted"),
        _ => {}
    }
}

// Iterate over all entries
for entry in bucket.iter() {
    process_entry(entry);
}
```

### Merging Buckets

```rust
use stellar_core_bucket::{merge_buckets, merge_buckets_with_options};

// Basic merge (normalizes Init -> Live)
let merged = merge_buckets(&old_bucket, &new_bucket, keep_dead, max_protocol)?;

// Merge with explicit normalization control
let merged = merge_buckets_with_options(
    &old_bucket,
    &new_bucket,
    keep_dead_entries,
    max_protocol_version,
    normalize_init_entries,  // false for same-level merges
)?;
```

### Eviction Scanning (Soroban)

```rust
use stellar_core_bucket::{EvictionIterator, StateArchivalSettings};

// Initialize iterator at default starting level (6)
let mut iter = EvictionIterator::default();

// Configure scan settings
let settings = StateArchivalSettings {
    eviction_scan_size: 100_000,        // 100 KB per ledger
    starting_eviction_scan_level: 6,
};

// Perform incremental scan
let result = bucket_list.scan_for_eviction_incremental(
    iter,
    current_ledger,
    &settings,
    &ttl_lookup_fn,
)?;

// Process results
for entry in result.archived_entries {
    // Add to hot archive bucket list
}
for key in result.evicted_keys {
    // Add as dead entry to live bucket list
}

// Save iterator for next ledger
iter = result.end_iterator;
```

## Disk-Backed Buckets

For mainnet catchup where buckets contain millions of entries, the crate provides memory-efficient disk-backed storage:

```rust
use stellar_core_bucket::Bucket;

// Create disk-backed bucket (index only in memory)
let bucket = Bucket::from_xdr_bytes_disk_backed(
    xdr_bytes,
    "/path/to/temp/file",
)?;

// Operations work the same, but entries are read from disk
if let Some(entry) = bucket.get(&key)? {
    // Entry was loaded from disk
}

// Check storage mode
if bucket.is_disk_backed() {
    println!("Using disk-backed storage");
}
```

## XDR Format

Bucket files use gzip-compressed XDR with RFC 5531 record marking:

```
[4-byte record mark][XDR entry 1]
[4-byte record mark][XDR entry 2]
...
```

The record mark has the high bit set (last fragment) and the remaining 31 bits contain the record length.

The bucket hash is computed over the **uncompressed** XDR bytes, including record marks, using SHA-256.

## Protocol Compatibility

| Feature | Minimum Protocol |
|---------|------------------|
| INITENTRY/METAENTRY | 11 |
| Persistent Eviction (Soroban) | 23 |
| Hot Archive Bucket List | 23 |

## Upstream Mapping

This crate corresponds to C++ stellar-core's bucket implementation:

| Rust | C++ |
|------|-----|
| `Bucket` | `Bucket`, `LiveBucket` |
| `BucketList` | `BucketList`, `LiveBucketList` |
| `BucketManager` | `BucketManager` |
| `BucketEntry` | `BucketEntry` (XDR union) |
| `DiskBucket` | `BucketIndex` + file access |

## Performance Notes

- **Merging**: O(n + m) where n and m are entry counts
- **Lookup**: O(levels * log(entries)) for in-memory, O(levels) disk seeks for disk-backed
- **Hash computation**: O(n) over all entries
- **Disk-backed index**: ~16 bytes per entry (8-byte key hash + 8-byte offset/length)

For production:
- Prefer disk-backed buckets during catchup to limit memory usage
- Cache hot buckets in `BucketManager` for repeated access
- Consider parallelizing merges at different levels when safe

## Testing

The crate includes extensive tests covering:

- Merge semantics (including CAP-0020 INITENTRY rules)
- Spill schedule correctness
- Hash computation compatibility
- Disk-backed bucket operations
- Eviction iterator behavior

Run tests with:

```bash
cargo test -p stellar-core-bucket
```

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