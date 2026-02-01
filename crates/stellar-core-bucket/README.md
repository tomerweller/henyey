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

## Architecture

```
                         BucketSnapshotManager
                         (concurrent read access)
                               |
                     +---------+---------+
                     |                   |
          BucketListSnapshot   HotArchiveBucketListSnapshot
                     |                   |
                     v                   v
               BucketList         HotArchiveBucketList
               (11 levels)           (11 levels)
                     |                   |
        +------------+------------+      |
        |            |            |      |
    BucketLevel  BucketLevel  ...     HotArchiveBucketLevel
    [curr][snap] [curr][snap]         [curr][snap]
        |                                 |
        v                                 v
      Bucket                       HotArchiveBucket
   (InMemory or DiskBacked)
        |
   +----+----+
   |         |
InMemory  DiskBucket
  (Vec)    (mmap + index)
              |
        +-----+-----+
        |           |
   LiveBucketIndex  BucketBloomFilter
   (InMemory or     (fast negative
    DiskIndex)       lookups)

Data Flow (per ledger close):
  1. New entries --> BucketList.add_batch()
  2. Level 0 merge (in-memory, fast)
  3. Spill cascades to deeper levels (async merges)
  4. Eviction scan --> expired entries to HotArchiveBucketList
  5. BucketSnapshotManager.update_current_snapshot()
```

## Key Types

### Core Types

- **`Bucket`**: An immutable container of sorted ledger entries, identified by SHA-256 hash. Supports two storage modes: in-memory (entries in `Vec`) or disk-backed (entries on disk with compact index).
- **`BucketList`**: The complete 11-level bucket list structure for live ledger state.
- **`BucketLevel`**: A single level with `curr`, `snap`, and optional `next` (pending merge result) buckets.
- **`BucketEntry`**: A single entry (Live, Dead, Init, or Metadata).

### Hot Archive (Soroban State Archival)

- **`HotArchiveBucketList`**: Separate 11-level bucket list for archived persistent Soroban entries.
- **`HotArchiveBucket`**: Bucket storing `HotArchiveBucketEntry` variants (Archived, Live tombstones, Metaentry).

### Storage and Indexing

- **`BucketManager`**: Manages bucket files on disk with caching, garbage collection, and state operations (load complete ledger state, merge all buckets, verify/ensure buckets exist).
- **`DiskBucket`**: Memory-efficient disk-backed bucket using memory-mapped I/O with a compact index.
- **`LiveBucketIndex`**: Facade that selects `InMemoryIndex` (for small buckets) or `DiskIndex` (page-based range index for large buckets) based on bucket size.
- **`BucketBloomFilter`**: Binary fuse filter for fast negative lookups, reducing disk I/O for missing keys.
- **Index persistence**: `save_disk_index` / `load_disk_index` serialize `DiskIndex` structures to `.index` files for fast startup without rebuilding from bucket files.

### Async Merging

- **`FutureBucket`**: Async bucket merging with state machine lifecycle. Level 0 uses synchronous in-memory merges; levels 1+ use background tokio tasks.
- **`PendingMerge`**: Enum wrapping either an `InMemory` result (level 0) or an `Async` handle (levels 1+).

### Snapshots (Thread-Safe Concurrent Access)

- **`BucketSnapshotManager`**: Manages current and historical snapshots with `RwLock` for concurrent reads.
- **`SearchableBucketListSnapshot`** / **`SearchableHotArchiveBucketListSnapshot`**: Query wrappers supporting single key lookup, batched key lookups, historical ledger queries, pool share trustline queries, and type-bounded entry scanning.
- **`BucketListSnapshot`**: Complete point-in-time snapshot of all 11 levels with associated ledger header.

### Streaming and Iteration

- **`BucketInputIterator`** / **`BucketOutputIterator`**: File-based streaming iteration with gzip decompression/compression, running hash computation, and automatic metadata handling.
- **`MergeIterator`**: Lazy streaming merge of two sorted bucket iterators.
- **`LiveEntriesIterator`**: Memory-efficient streaming iterator over all live entries in a bucket list, using `HashSet<LedgerKey>` deduplication (O(unique keys) memory instead of O(total entries)).

### Catchup Support

- **`BucketApplicator`**: Chunked application of bucket entries for catchup with deduplication, configurable chunk size, and progress tracking.

### Eviction (Soroban State Archival)

- **`EvictionIterator`**: Tracks incremental scan position (level, bucket, byte offset).
- **`EvictionResult`**: Entries to archive and delete after a scan.
- **`StateArchivalSettings`**: Configuration for eviction scans (scan size, starting level, max entries to archive).

### Metrics

- **`MergeCounters`**: Merge operation statistics (thread-safe via atomics).
- **`EvictionCounters`**: Eviction operation statistics.
- **`BucketListMetrics`**: Aggregate entry counts by type and durability.

### Caching

- **`RandomEvictionCache`**: LRU-style cache for frequently-accessed account entries with configurable memory limits.

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
    max_entries_to_archive: 1000,       // Max data entries per ledger
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

## XDR Format and File Layout

The canonical on-disk format is **uncompressed** XDR with RFC 5531 record marking, stored as `<hash>.bucket.xdr`. The legacy gzip-compressed format (`<hash>.bucket.gz`) is supported for backward compatibility and is transparently migrated on first load.

```
<bucket_dir>/
  <hash1>.bucket.xdr       (canonical, uncompressed)
  <hash2>.bucket.xdr
  bucket-<hash>.index       (optional persisted DiskIndex)
  ...
```

Each bucket file uses XDR Record Marking Standard (RFC 5531):

```
[4-byte record mark][XDR entry 1]
[4-byte record mark][XDR entry 2]
...
```

The record mark has the high bit set (last fragment) and the remaining 31 bits contain the record length.

The bucket hash is computed over the uncompressed XDR bytes, including record marks, using SHA-256. Using uncompressed files as the canonical format enables random-access seeks for disk-backed indexing and streaming iteration.

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
| `BucketLevel` | `BucketLevel` |
| `BucketManager` | `BucketManager` |
| `BucketEntry` | `BucketEntry` (XDR union) |
| `DiskBucket` | `BucketIndex` + file access |
| `LiveBucketIndex` | `LiveBucketIndex` |
| `DiskIndex` / `InMemoryIndex` | `DiskIndex` / `InMemoryIndex` |
| `HotArchiveBucketList` | `HotArchiveBucketList` |
| `HotArchiveBucket` | `HotArchiveBucket` |
| `FutureBucket` | `FutureBucket` |
| `BucketSnapshotManager` | `BucketSnapshotManager` |
| `SearchableBucketListSnapshot` | `SearchableBucketListSnapshot` |
| `BucketApplicator` | `BucketApplicator` |
| `BucketMergeMap` | `BucketMergeMap` |
| `LiveEntriesIterator` | `BucketApplicator` iteration pattern |
| `BucketBloomFilter` | `BinaryFuseFilter` |
| `RandomEvictionCache` | `RandomEvictionCache` |

## Performance Notes

- **Merging**: O(n + m) where n and m are entry counts
- **Lookup**: O(levels * log(entries)) for in-memory, O(levels) disk seeks for disk-backed
- **Bloom filter**: Reduces disk I/O for negative lookups (fast rejection of missing keys)
- **Hash computation**: O(n) over all entries
- **Disk-backed index**: ~16 bytes per entry (8-byte key hash + 8-byte offset/length)
- **Level 0 optimization**: In-memory merges avoid disk I/O for the most frequently updated level
- **Streaming iteration**: `LiveEntriesIterator` uses O(unique keys) memory instead of materializing all entries

For production:
- Prefer disk-backed buckets during catchup to limit memory usage
- `BucketManager` automatically selects disk-backed storage for files over 10 MB
- Enable index persistence (`with_persist_index`) for fast startup without rebuilding indexes
- Cache hot buckets in `BucketManager` for repeated access
- Levels 1+ use async merges (tokio tasks) to reduce ledger close time

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

See [PARITY_STATUS.md](PARITY_STATUS.md) for detailed C++ parity analysis.