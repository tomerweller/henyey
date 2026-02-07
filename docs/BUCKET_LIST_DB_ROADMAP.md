# Bucket List DB Revamp - Implementation Roadmap

**Target:** Enable mainnet support by reducing memory requirements from 50+ GB to < 16 GB

## Overview

This document outlines the complete implementation plan for the Bucket List DB revamp,
the critical path to mainnet support. It expands on the analysis in `MAINNET_GAPS.md`
and provides detailed implementation guidance for each phase.

## Current State

Significant foundational work is already in place:

| Component | Location | Status |
|-----------|----------|--------|
| `LiveEntriesIterator` | `stellar-core-bucket/src/live_iterator.rs` | Complete — streaming iteration with `HashSet<LedgerKey>` dedup |
| Offers SQL schema & queries | `stellar-core-db/src/queries/offers.rs` | Complete — schema, indexes, bulk ops, all query functions |
| Offer population during catchup | `stellar-core-ledger/src/manager.rs` (`initialize_all_caches`, `initialize_offers_sql`) | Complete — batch inserts via streaming iterator |
| Offer delta during ledger close | `stellar-core-ledger/src/manager.rs:1540-1576` | Complete — upserts/deletes from `EntryChange` |
| `LiveBucketIndex` (InMemory + Disk) | `stellar-core-bucket/src/index.rs` | Complete — threshold at 10,000 entries, page size 1,024 |
| `RandomEvictionCache` | `stellar-core-bucket/src/cache.rs` | Complete — 100 MB / 100k entry default, accounts only |
| `BucketList::get()` point lookup | `stellar-core-bucket/src/bucket_list.rs:789` | Complete — searches levels 0-10 newest-first |
| Index persistence (save/load) | `stellar-core-bucket/src/index_persistence.rs` | Complete — bincode format, version 2; bloom filter + asset_pool_map persisted |

## Phase Summary

| Phase | Focus | Status |
|-------|-------|--------|
| 1 | Streaming Iterator | **Complete** |
| 2 | SQL-Backed Offers | **Complete** |
| 3 | BucketListDB Point Lookups | **Complete** |
| 4 | Index Persistence | **Complete** |
| 5 | Uncompressed XDR On-Disk Format | **Complete** |
| 6 | Streaming Iteration & Merge | **Complete** |
| 7 | DiskBacked Buckets by Default | **Complete** |
| 8 | Connect Index System to DiskBucket | Not started |
| 9 | Arc\<Bucket\> Shared Ownership | Not started |
| 10 | HotArchive DiskBacked Support | Not started |

---

## Phase 1: Streaming Iterator (RFC-001)

**Status: Complete**

See `docs/RFC-001-STREAMING-LIVE-ENTRIES.md` for full design.

### What Was Delivered

- `LiveEntriesIterator` in `stellar-core-bucket/src/live_iterator.rs` (571 lines)
- Uses `HashSet<LedgerKey>` for deduplication (matches C++ `unordered_set<LedgerKey>`)
- Integrated into `initialize_all_caches()`, `initialize_offers_sql()`, and `initialize_soroban_state()`
- Statistics tracking: `entries_yielded`, `entries_skipped`, `seen_keys_count`

### Memory Profile

| Scale | Old `live_entries()` | New `live_entries_iter()` |
|-------|---------------------|--------------------------|
| Testnet (~70k entries) | ~405 MB | ~5 MB (keys only) |
| Mainnet (~60M entries) | ~52 GB | ~8.6 GB |

**Note:** The 8.6 GB deduplication `HashSet` is **transient** — it is allocated during
catchup/initialization and freed after the iteration completes. Steady-state operation
does not retain this set.

---

## Phase 2: SQL-Backed Offers

**Status: Complete**

### What Was Delivered

**Schema** (`stellar-core-db/src/queries/offers.rs`):

```sql
CREATE TABLE offers (
    sellerid         TEXT NOT NULL,
    offerid          INTEGER NOT NULL PRIMARY KEY,
    sellingasset     TEXT NOT NULL,
    buyingasset      TEXT NOT NULL,
    amount           INTEGER NOT NULL,
    pricen           INTEGER NOT NULL,
    priced           INTEGER NOT NULL,
    price            REAL NOT NULL,
    flags            INTEGER NOT NULL,
    lastmodified     INTEGER NOT NULL,
    extension        TEXT NOT NULL,
    ledgerext        TEXT NOT NULL
);

CREATE INDEX bestofferindex ON offers (sellingasset, buyingasset, price, offerid);
CREATE INDEX offerbyseller ON offers (sellerid);
```

**Query functions** — all implemented:
- `load_offer()`, `load_offer_by_id()` — point lookups
- `load_best_offers()`, `load_best_offers_worse_than()` — order book queries
- `load_offers_by_account_and_asset()` — account-scoped queries
- `load_all_offers()`, `bulk_load_offers()` — bulk reads
- `bulk_upsert_offers()`, `bulk_delete_offers()` — bulk writes (1,000-entry batches)
- `count_offers()`

**Integration points:**
- **Catchup**: `initialize_all_caches()` populates offers via streaming iterator
- **Ledger close**: `manager.rs:1540-1576` extracts offer `EntryChange`s from the delta and applies upserts/deletes in a SQLite transaction

### Memory Impact

- **Before**: All offers held in-memory as `Vec<LedgerEntry>`
- **After**: Offers stored in SQLite; ~0 MB heap usage for offer data

Mainnet has approximately **12-15 million offers**. At ~200 bytes per offer entry, this
represents **2.4-3 GB of memory savings** compared to an in-memory approach — substantially
more than the testnet ~500 MB figure.

### Offer Rollback (Resolved)

Per-transaction rollback semantics are achieved through `snapshot_delta()` + `rollback()`
in `state.rs`. Offers created in Tx_i are visible to Tx_{i+1} via shared in-memory state
(`executor.state`). The SQL offers table is batch-updated once at ledger close, matching
C++ behavior. The mechanism differs from C++ (delta snapshots vs nested `LedgerTxn`
hierarchy) but the observable semantics are identical.

---

## Phase 3: BucketListDB Point Lookups

**Status: Complete**

### What Was Delivered

1. **LiveBucketIndex** (`index.rs`, 939 lines)
   - `InMemoryIndex`: Full `LedgerKey -> offset` map for buckets with < 10,000 entries
   - `DiskIndex`: Page-based range index (1,024 entries/page) with bloom filter
   - `BucketEntryCounters` for per-type accounting

2. **RandomEvictionCache** (`cache.rs`, 599 lines)
   - Default: 100 MB / 100,000 entries
   - Only caches `Account` entries (hot path for TX validation)
   - Minimum bucket list size for cache activation: 1,000,000 entries

3. **BucketList::get()** (`bucket_list.rs:789`)
   - Searches levels 0-10 in order (newest first)
   - Checks `curr` then `snap` at each level
   - Returns first live match; dead entries return `None`

4. **LedgerManager cache-miss fallback** (`manager.rs`)
   - `create_snapshot()` provides a `lookup_fn` closure that falls back to bucket list
     point lookups when the entry cache misses
   - `load_entry()` populates the entry cache on demand from bucket list lookups

5. **Snapshot isolation** (`manager.rs`, `snapshot.rs`)
   - `create_snapshot()` captures a `BucketListSnapshot` at snapshot time instead of
     holding a reference to the live `Arc<RwLock<BucketList>>`
   - Point lookups during TX execution use the immutable snapshot — no lock acquisition
   - Eliminates contention with the write lock held during `commit()` (add_batch + hash)
   - `BucketListSnapshot::get_result()` and `BucketSnapshot::get_result()` propagate
     errors instead of silently swallowing them
   - Integration test (`test_snapshot_isolation_from_bucket_list_mutations`) verifies
     snapshot is not affected by subsequent bucket list mutations

### Configuration

```toml
[bucket_list_db]
# Bucket entry count threshold for InMemory vs Disk index
# Buckets with fewer than this many entries use full in-memory key->offset maps.
# Buckets with more entries use page-based range indexes with bloom filters.
index_entry_threshold = 10000

# Total memory budget for entry caching (MB)
memory_for_caching_mb = 100

# Entries per page for range index
page_size = 1024
```

**Note on units:** The C++ upstream uses a byte-size cutoff (`BUCKETLIST_DB_INDEX_CUTOFF`
defaults to 250 MB). The Rust implementation uses an entry-count threshold (10,000 entries).
These are functionally equivalent but the Rust approach is simpler to reason about since
entry sizes vary. If parity with the C++ byte-based cutoff is desired, this can be revisited.

### Memory Impact

| Component | Estimate |
|-----------|----------|
| Per-bucket caches | ~100 MB (configurable) |
| InMemory indexes (small buckets) | ~50-200 MB depending on level distribution |
| DiskIndex metadata (large buckets) | ~50-100 MB (page headers + bloom filters) |
| **Total** | **~200-400 MB** |

---

## Phase 4: Index Persistence

**Status: Complete**

### What Was Delivered

`index_persistence.rs` implements save/load using bincode serialization:

```
Header:
  - Version: u32 (BUCKET_INDEX_VERSION = 2)
  - page_size: u64

Body:
  - pages: Vec<(SerializableRangeEntry, u64)>
  - bloom_data: Option<BloomFilterData>   (bloom filter + seed, added in v2)
  - counters: SerializableCounters
  - type_ranges: HashMap<u32, (u64, u64)>
  - asset_pool_map: Vec<(xdr bytes, xdr bytes)>  (added in v2)
```

1. **Bloom filter persistence** — Serialized as `BloomFilterData` containing the
   `BinaryFuse16` fingerprints and seed. Eliminates rebuild on load.

2. **`asset_to_pool_id` map persistence** — Serialized as XDR byte pairs. Restored
   on load for complete index state.

3. **InMemoryIndex** — Small buckets rebuild quickly from the bucket file; no
   separate persistence path needed.

4. **BucketManager integration** — `persist_index()` flag controls automatic saving
   after catchup/merge. Loading falls back to rebuild if the index file is missing,
   corrupt, or has a version mismatch.

### C++ Reference

C++ saves indexes as `.index` files alongside bucket `.xdr` files:
```
buckets/
  <hash>.xdr.gz      # Bucket data
  <hash>.index       # Serialized index
```

### Memory Impact

- No direct memory impact
- Faster startup (avoids full bucket scans for index construction)

### Startup Time Target

- With persisted indexes (clean shutdown): target < 2 minutes
- Without indexes (crash recovery / first boot): full bucket scan required,
  proportional to total bucket data size

---

## Phase 5: Uncompressed XDR On-Disk Format

**Status: Complete**

**Why:** Foundation for all subsequent phases. The current `.bucket.gz` (gzip compressed)
format is not seekable — random-access reads are impossible without full decompression.
C++ stellar-core stores buckets as uncompressed `.xdr` files with RFC 5531 record marks,
enabling page-based seeks for the DiskIndex.

**Gap:** `BucketManager` stores files as `<hash>.bucket.gz`. `DiskBucket` stores
uncompressed `.xdr` separately. These are two disconnected paths.

### What Needs to Change

**Files:** `stellar-core-bucket/src/bucket.rs`, `src/manager.rs`

1. **Canonical format**: `BucketManager::bucket_path()` returns `<hash>.bucket.xdr`
   (uncompressed, with XDR record marks) instead of `<hash>.bucket.gz`

2. **Save**: `Bucket::save_to_xdr_file(path)` writes uncompressed XDR with record marks
   (the hash-compatible format already used by the hash computation)

3. **Load**: `BucketManager::load_bucket()` reads from `.bucket.xdr` (no decompression)

4. **Migration**: If `.bucket.gz` exists but `.bucket.xdr` doesn't, decompress on first access

5. **Download path**: Download `.gz` from archives → decompress → save `.xdr` to disk

**Compatibility:** The bucket hash is computed over uncompressed XDR with record marks.
This is already the internal format. Changing on-disk storage doesn't affect hash computation.

---

## Phase 6: Streaming Iteration & Merge

**Status: Complete**

**Why:** Two critical memory bottlenecks exist:

1. `DiskBucket::iter()` calls `reader.read_to_end(&mut bytes)`, loading the **entire file**
   (up to 6.4 GB for the largest mainnet bucket) into a `Vec<u8>`.

2. `merge_buckets_with_options()` calls `.iter().collect()` on both inputs, loading **all
   entries from both buckets** into `Vec<BucketEntry>`. For two large mainnet buckets, this
   is 10-20 GB.

C++ stellar-core uses `BucketInputIterator` / `BucketOutputIterator` that stream one entry
at a time from/to disk.

### What Needs to Change

**Files:** `stellar-core-bucket/src/disk_bucket.rs`, `src/merge.rs`, `src/iterator.rs`

#### 6a: Streaming DiskBucket Iteration

Replace `DiskBucketIter`:
- **Current**: `bytes: Vec<u8>` (entire file in memory), parses entries from byte buffer
- **New**: `reader: BufReader<File>` (8 KB buffer), reads one XDR record at a time

Since Phase 5 makes files uncompressed, sequential reads are straightforward:
read 4-byte record mark → extract length → read record bytes → parse `BucketEntry`.

**Memory:** O(1) per iterator (one entry + 8 KB buffer) instead of O(file_size)

#### 6b: Streaming Merge

Add `merge_buckets_streaming()`:
- Uses `BucketInputIterator` (already exists in `iterator.rs`) for both inputs
- Uses `BucketOutputIterator` (already exists) for output
- Standard two-pointer merge-sort, one entry at a time from each input
- Shadow checking via bloom filter lookups (no need to load shadow bucket entries)
- Output: new `.bucket.xdr` file → create DiskBacked `Bucket`

Update `merge_buckets_with_options()` dispatch:
- Both inputs have in-memory entries → existing in-memory merge (level 0)
- Otherwise → `merge_buckets_streaming()` (levels 1-10)

Update `AsyncMergeHandle::start_merge()` to pass output directory for streaming merges.

**Memory:** O(1) per merge (one entry from each input + output buffer) instead of O(entries)

### C++ Reference

```cpp
// BucketBase::merge() in .upstream-v25/src/bucket/BucketBase.cpp
// Creates BucketInputIterator for each input, BucketOutputIterator for output.
// Iterates one entry at a time. Memory: O(1) per input regardless of bucket size.
FileMergeInput<BucketT> fileMergeInput(oldBucket, newBucket);
mergeInternal(bm, maxProtocolVersion, keepDeadEntries, out, shadows, fileMergeInput);
```

---

## Phase 7: DiskBacked Buckets by Default

**Status: Complete**

**Why:** `BucketManager::load_bucket()` calls `Bucket::load_from_file()` which decompresses
`.gz` and loads **all entries** into `Vec<BucketEntry>`. This is the direct cause of the
OOM on mainnet (60+ GB peak RSS, killed by OOM killer on a 62 GB machine).

### What Needs to Change

**Files:** `stellar-core-bucket/src/manager.rs`, `src/bucket.rs`, `src/disk_bucket.rs`

1. **`BucketManager::load_bucket()` new flow:**
   - Check cache → return `Arc<Bucket>` if found
   - Check for `.bucket.xdr` on disk:
     - If file size < `INMEMORY_THRESHOLD` (e.g., 10 MB): load as InMemory
     - Otherwise: create DiskBacked Bucket from `.xdr` file
   - If only `.bucket.gz` exists: decompress to `.xdr`, then proceed as above

2. **`Bucket::from_xdr_file(path)` constructor:**
   - Builds `DiskBucket` from an existing uncompressed `.xdr` file
   - Streams through file to build index (one entry at a time, O(1) memory)
   - Computes hash during the streaming pass
   - Does NOT load entries into memory

3. **`DiskBucket::from_file()` streaming index build:**
   - Current: `reader.read_to_end(&mut bytes)` → `build_index(&bytes)` (entire file in memory)
   - New: read entries one at a time, record file offsets as we go
   - Builds `BTreeMap<u64, IndexEntry>` incrementally

4. **Eliminate clone in restore path:**
   - Current: `bucket_manager.load_bucket(hash).map(|b| (*b).clone())`
   - For DiskBacked, this clone is cheap (just Arc increments on internal DiskBucket)
   - Verify no deep copies occur

### Expected Memory Impact

| Scale | Before (InMemory) | After (DiskBacked) |
|-------|-------------------|-------------------|
| Testnet | ~1 GB | ~100 MB |
| Mainnet | **60+ GB (OOM)** | **~1 GB** (flat index only) |

The ~1 GB flat index is reduced to ~150 MB in Phase 8 (page-based index).

### Mainnet OOM Autopsy

Test run on 62 GB machine:
```
Peak RSS: 60.4 GB (63,335,868 KB)
Wall time: 6m 16s before OOM kill (signal 9)
Killed during: Bucket list restoration (downloading + loading last 2-3 of 42 buckets)
Largest bucket: 6.4 GB on disk (uncompressed XDR)
Total cached bucket data: 21 GB on disk across 137 files
```

The process never reached ledger execution — it was killed during initialization. The 42
mainnet buckets, when parsed into Rust structs with heap allocations (`Vec`, `String`, XDR
enum variants), expand from ~21 GB on disk to 60+ GB in memory.

---

## Phase 8: Connect Index System to DiskBucket

**Status: Not started**

**Why:** The `DiskBucket` flat index (`BTreeMap<u64, IndexEntry>`) stores one entry per
key (16 bytes each). For 60M mainnet keys, that's ~960 MB of index. The existing `index.rs`
`DiskIndex` uses pages (~1024 entries/page) reducing the index to ~60K entries (~10 MB)
plus a bloom filter (~138 MB). The `index.rs` code is complete but not connected to `DiskBucket`.

### What Needs to Change

**Files:** `stellar-core-bucket/src/disk_bucket.rs`, `src/index.rs`, `src/index_persistence.rs`

1. **Refactor DiskBucket to use `index.rs` indexes:**
   - Small buckets (< `INDEX_CUTOFF` entries): `InMemoryIndex` from `index.rs`
     - `BTreeMap<Vec<u8>, u64>` mapping key bytes → file offset
     - Bloom filter for fast negative lookups
   - Large buckets (≥ `INDEX_CUTOFF`): `DiskIndex` from `index.rs`
     - Page-based: `Vec<(RangeEntry, u64)>` with configurable page size (default 1024)
     - `BinaryFuseFilter` for fast negative lookups
     - Binary search to find candidate page → seek to page offset → scan within page

2. **Connect `RandomEvictionCache`** (`cache.rs`) **to DiskBucket:**
   - Per-bucket bounded cache of recently-accessed ACCOUNT entries
   - Size proportional to bucket's share of total ACCOUNT entry bytes
   - Total cache memory configurable (default 256 MB)
   - Matches C++ `RandomEvictionCache` behavior

3. **Lookup path for large DiskBacked bucket:**
   1. Check `RandomEvictionCache` → if hit, return immediately
   2. Check bloom filter → if definitely not present, return None
   3. Binary search `pages` vector → find candidate page with matching range
   4. Seek to page offset in `.xdr` file, scan entries within page
   5. If found and ACCOUNT type, add to `RandomEvictionCache`

4. **Index persistence integration:**
   - `BucketManager` saves DiskIndex as `<hash>.bucket.index` on creation
   - On load: check for `.index` file → deserialize; otherwise rebuild from `.xdr`
   - Uses existing `index_persistence.rs` serialization

### Memory After Phase 8

| Component | Memory |
|-----------|--------|
| DiskIndex pages (~60K entries across all buckets) | ~10 MB |
| Bloom filters (~2.3 bytes/key, ~60M keys) | ~138 MB |
| RandomEvictionCache (bounded) | ~256 MB (configurable) |
| **Total** | **~400 MB** |

### C++ Reference

```cpp
// DiskIndex<BucketT>::scan() in .upstream-v25/src/bucket/DiskIndex.cpp
// Uses lower_bound on RangeIndex to find page, then checks bloom filter,
// then returns file offset for page-level scan.
auto iter = lower_bound(begin, end, key, lowerBoundCmp);
if (mFilter && !mFilter->contain(keyHash)) return {ScanResult::NOT_FOUND};
```

---

## Phase 9: Arc\<Bucket\> Shared Ownership

**Status: Not started**

**Why:** `BucketList` currently owns `Bucket` directly. C++ uses `shared_ptr<Bucket>` so
the same bucket object is shared by `BucketList`, `BucketManager`, snapshots, and merges.
This eliminates copies and ensures deduplication.

### What Needs to Change

**Files:** `stellar-core-bucket/src/bucket_list.rs`, `src/snapshot.rs`

1. `BucketLevel` fields become `curr: Arc<Bucket>`, `snap: Arc<Bucket>`
2. `BucketSnapshot::new()` takes `Arc<Bucket>` directly (already supports this)
3. Creating `BucketListSnapshot` becomes zero-cost: just `Arc::clone` on each bucket
4. `BucketManager` cache shares `Arc<Bucket>` with `BucketList` — same object everywhere
5. Merge inputs take `Arc<Bucket>` — keeps bucket alive during background merge
6. `BucketManager::forgetUnreferencedBuckets()` — GC buckets where `Arc::strong_count() == 1`

---

## Phase 10: HotArchive DiskBacked Support

**Status: Not started**

**Why:** `HotArchiveBucket` is always InMemory (`BTreeMap<LedgerKey, HotArchiveBucketEntry>`).
On mainnet with persistent eviction (protocol 23+), the hot archive grows over time. C++
uses `HotArchiveBucketIndex` with `DiskIndex` (always disk-based, no cache).

### What Needs to Change

**Files:** `stellar-core-bucket/src/hot_archive.rs`

1. Add `DiskBacked` storage variant to `HotArchiveBucket`
2. Use `DiskIndex` (no `RandomEvictionCache`, matching C++)
3. `BucketManager::load_hot_archive_bucket()` creates DiskBacked for large files
4. Streaming merge and iteration for hot archive buckets (reuse Phase 6 patterns)

---

## Phase Dependencies (Complete Picture)

```
Phase 1 (Streaming Iterator)        ✅
    |
    v
Phase 2 (SQL Offers)                ✅ <------+
    |                                         |
    v                                         |
Phase 3 (Point Lookups)              ✅ ------+ (parallel)
    |
    v
Phase 4 (Index Persistence)          ✅
    |
    v
Phase 5 (Uncompressed XDR Format)    ✅
    |
    v
Phase 6 (Streaming Iteration/Merge)  ✅
    |
    v
Phase 7 (DiskBacked by Default)      ✅
    |
    v
Phase 8 (Connect Index to DiskBucket) ← Next
    |
    +------> Phase 9 (Arc<Bucket>)    ← Can parallelize with Phase 8
    |
    v
Phase 10 (HotArchive DiskBacked)     ← Reuses Phase 5-7 patterns
```

**Minimum viable for mainnet (fixes OOM):** Phases 5-7 ✅
**Full C++ parity:** All 10 phases

---

## Memory Budget Summary

### During Catchup (Peak)

| Component | Estimate |
|-----------|----------|
| Deduplication `HashSet<LedgerKey>` (transient, per-type) | ~240 MB |
| Bucket indexes | ~200-400 MB |
| Module cache (WASM compilation) | ~500 MB |
| SQLite (offers + overhead) | ~200 MB |
| Operating overhead (allocator, stack, etc.) | ~2 GB |
| **Peak total** | **~3-4 GB** |

*Note: The dedup HashSet was reduced from ~8.6 GB to ~240 MB by switching from
`live_entries_iter()` (all 60M keys) to per-type scanning (ContractData +
ContractCode, ~1.68M keys). See `docs/CATCHUP_MEMORY_ANALYSIS.md` for details.*

### Steady-State Operation

| Component | Estimate |
|-----------|----------|
| Bucket indexes (persistent) | ~200-400 MB |
| Entry cache (`RandomEvictionCache`) | ~100 MB (configurable) |
| Module cache | ~500 MB |
| SQLite (offers + overhead) | ~200 MB |
| Operating overhead | ~1.5 GB |
| **Steady-state total** | **~2.5-3 GB** |

The per-type deduplication HashSets are freed after catchup completes, so steady-state memory is
substantially lower than peak.

---

## Hot Archive Bucket List

The `HotArchiveBucketList` (`hot_archive.rs`, 1,869 lines) stores recently evicted persistent
Soroban entries. It currently uses **full in-memory materialization** (`Vec<HotArchiveBucketEntry>`
plus `BTreeMap` index).

On mainnet, the hot archive is expected to remain small relative to the live bucket list
because entries are only retained for a limited period after eviction. However, if the hot
archive grows significantly, it will need the same streaming/disk-backed treatment applied
to the live bucket list. This should be monitored during extended mainnet observer runs.

---

## Testing Strategy

### Unit Tests (Each Phase)
- Correctness: output matches old implementation
- Edge cases: empty buckets, single entry, all dead entries

### Integration Tests
- Full catchup with streaming iterator
- Ledger close with SQL offers (upserts + deletes verified)
- Point lookups with cache misses (verify disk fallback returns correct entries)

### Performance Tests
- Memory profiling during catchup (target: < 4 GB peak)
- Steady-state memory after 1,000+ ledger closes (target: < 4 GB)
- Iteration speed benchmark
- Point lookup latency (cache hit vs miss)
- SQL offer query latency during order book matching

### Mainnet Simulation
- Use mainnet bucket archives for realistic scale testing
- Verify peak memory stays within 16 GB budget
- Verify steady-state memory stays within 4 GB budget

---

## Dependencies (Phases 1-4)

```
Phase 1 (Streaming Iterator) ✅
    |
    v
Phase 2 (SQL Offers) ✅ <------+
    |                           |
    v                           |
Phase 3 (Point Lookups) ✅ ----+ (can parallelize)
    |
    v
Phase 4 (Index Persistence) ✅
```

See [Phase Dependencies (Complete Picture)](#phase-dependencies-complete-picture) for the full dependency graph including Phases 5-10.

---

## Risk Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **SQL offer query latency** | Medium | High — DEX matching is latency-sensitive | SQLite with the `bestofferindex` composite index should handle order book queries efficiently. Benchmark with mainnet-scale offer counts (~12M) early. If latency is unacceptable, consider an in-memory order book index backed by SQL as source of truth. |
| **Memory estimation off** | Medium | High — could exceed 16 GB target | Profile with real mainnet bucket archives. Per-type scanning reduced the transient dedup HashSet from ~8.6 GB to ~240 MB. If further reduction is needed, a bloom filter pre-screen could be added. |
| **Index format changes** | Low | Medium — breaks existing persisted indexes | Version field in the index header allows backward-compatible updates. Fallback to rebuild ensures no data loss. |
| **Regression in ledger close** | Low | Critical — consensus failure | Comprehensive comparison tests: run Rust and C++ side-by-side on the same ledger sequence and verify identical hashes for 1,000+ consecutive ledgers. |
| **Lock contention on BucketList** | Low (mitigated) | Medium — slower lookups under load | Addressed: `create_snapshot()` now captures a `BucketListSnapshot` so point lookups during TX execution use an immutable snapshot with no lock acquisition. |
| **Hot archive memory growth** | Low | Medium — unexpected memory pressure | Monitor hot archive size during extended mainnet observer runs. Flag for disk-backed treatment if it exceeds 1 GB. |

---

## Success Metrics

1. **Memory (peak)**: RSS < 4 GB during catchup with mainnet bucket archives
2. **Memory (steady-state)**: RSS < 4 GB during normal ledger close operation
3. **Correctness**: Ledger hashes match C++ for 1,000+ consecutive ledgers on testnet
4. **Performance**: Ledger close time within 10% of current
5. **Startup (warm)**: < 2 minutes from persisted state after clean shutdown
6. **Startup (cold)**: < 10 minutes with full index rebuild after crash recovery
7. **Offer queries**: Order book best-offer query < 5 ms at mainnet scale

---

## References

- [RFC-001: Streaming Live Entries](./RFC-001-STREAMING-LIVE-ENTRIES.md)
- [Mainnet Gaps Analysis](./MAINNET_GAPS.md)
- C++ LedgerTxnOfferSQL: `.upstream-v25/src/ledger/LedgerTxnOfferSQL.cpp`
- C++ LiveBucketIndex: `.upstream-v25/src/bucket/LiveBucketIndex.cpp`
- C++ BucketApplicator: `.upstream-v25/src/bucket/BucketApplicator.cpp`

---

*Last updated: February 2026*
