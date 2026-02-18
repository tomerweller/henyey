# bucket

The BucketList implementation for storing cumulative ledger state. This crate manages Stellar's hierarchical append-only data structure where ledger entries are grouped into buckets across 11 levels, merged on geometric boundaries, indexed for fast lookups, and snapshotted for concurrent read access. It also handles Soroban state eviction via the hot archive bucket list.

## Key Files

- [manager.pc.md](manager.pc.md) -- Top-level manager for bucket file creation, caching, merging, and garbage collection
- [bucket_list.pc.md](bucket_list.pc.md) -- 11-level hierarchical bucket list with spill/merge algorithm
- [bucket.pc.md](bucket.pc.md) -- Immutable bucket container with in-memory and disk-backed storage
- [merge.pc.md](merge.pc.md) -- Core merge algorithm with CAP-0020 INITENTRY semantics
- [index.pc.md](index.pc.md) -- Hybrid indexing: InMemoryIndex for small buckets, DiskIndex for large
- [future_bucket.pc.md](future_bucket.pc.md) -- State machine for asynchronous bucket merge lifecycle
- [snapshot.pc.md](snapshot.pc.md) -- Thread-safe bucket list snapshots for concurrent read access

## Architecture

Ledger changes flow into the `BucketList`, which organizes entries across 11 hierarchical levels -- each containing a `curr` and `snap` bucket that merge on geometric boundaries via `FutureBucket`. Individual buckets are created as immutable containers (either in-memory or disk-backed via `DiskBucket`) identified by their SHA-256 content hash. The `merge` module implements CAP-0020 INITENTRY semantics where INIT+DEAD pairs annihilate and entries normalize across level boundaries. `BucketManager` orchestrates the entire subsystem including file caching, garbage collection, and merge deduplication (via `MergeMap`). Lookups use a hybrid `index` system with bloom filters for fast negatives, while `snapshot` provides thread-safe read access. The `eviction` module handles Soroban state archival scanning, and `hot_archive` manages the separate bucket list for evicted persistent entries.

## All Files

| File | Description |
|------|-------------|
| [applicator.pc.md](applicator.pc.md) | Applies bucket entries to the database during catchup |
| [bloom_filter.pc.md](bloom_filter.pc.md) | Binary fuse filter for fast negative lookups in bucket indexes |
| [bucket_list.pc.md](bucket_list.pc.md) | 11-level hierarchical bucket list with spill/merge algorithm |
| [bucket.pc.md](bucket.pc.md) | Immutable bucket container with in-memory and disk-backed storage |
| [cache.pc.md](cache.pc.md) | Random eviction cache for frequently-accessed account entries |
| [disk_bucket.pc.md](disk_bucket.pc.md) | Disk-backed bucket with mmap reads and lazy index building |
| [entry.pc.md](entry.pc.md) | BucketEntry types (Live/Dead/Init/Metadata) with merge semantics |
| [error.pc.md](error.pc.md) | Error types for bucket operations |
| [eviction.pc.md](eviction.pc.md) | Incremental eviction scanning for Soroban state archival |
| [future_bucket.pc.md](future_bucket.pc.md) | State machine for async bucket merge lifecycle and serialization |
| [hot_archive.pc.md](hot_archive.pc.md) | Hot archive bucket list for recently evicted Soroban entries |
| [index_persistence.pc.md](index_persistence.pc.md) | Serialization/deserialization of DiskIndex to .index files |
| [index.pc.md](index.pc.md) | Hybrid indexing with InMemoryIndex and DiskIndex by bucket size |
| [iterator.pc.md](iterator.pc.md) | Streaming XDR record reader/writer for bucket files |
| [lib.pc.md](lib.pc.md) | Crate root with module declarations and re-exports |
| [live_iterator.pc.md](live_iterator.pc.md) | Memory-efficient streaming iterator with key deduplication |
| [manager.pc.md](manager.pc.md) | Bucket file creation, caching, merging, and garbage collection |
| [merge_map.pc.md](merge_map.pc.md) | Merge deduplication tracking by input-to-output hash mappings |
| [merge.pc.md](merge.pc.md) | Core merge algorithm with CAP-0020 INITENTRY shadow semantics |
| [metrics.pc.md](metrics.pc.md) | Atomic counters for merge operations and entry statistics |
| [snapshot.pc.md](snapshot.pc.md) | Thread-safe bucket list snapshots with read-write lock access |
