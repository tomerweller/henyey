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
| Index persistence (save/load) | `stellar-core-bucket/src/index_persistence.rs` | Partial — bincode format, version 1; bloom filter not yet persisted |

## Phase Summary

| Phase | Focus | Status |
|-------|-------|--------|
| 1 | Streaming Iterator | **Complete** |
| 2 | SQL-Backed Offers | **Complete** |
| 3 | BucketListDB Point Lookups | **Substantially Complete** — remaining: integration with LedgerManager for cache-miss fallback |
| 4 | Index Persistence | **Partial** — save/load works but bloom filter persistence missing |

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

### Open Items

- **Offer rollback on failed ledger close.** The current implementation applies offer SQL
  changes after the ledger close succeeds. If a ledger close fails mid-execution, the offers
  table remains consistent because changes are only committed at the end. However, this does
  not yet support the C++ `LedgerTxn` parent/child rollback semantics where offer mutations
  are speculatively applied and rolled back per-transaction. This gap is acceptable for now
  because the bucket list is the source of truth, not the offers table — on any mismatch,
  offers are rebuilt from the bucket list during the next catchup.

---

## Phase 3: BucketListDB Point Lookups

**Status: Substantially Complete**

### What Exists

The core building blocks are implemented:

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

### Remaining Work

1. **LedgerManager cache-miss fallback** — When `entry_cache` misses, fall back to
   `BucketList::get()` for on-demand disk lookups instead of requiring all entries to be
   pre-loaded. This is the final step to eliminate the full entry cache dependency.

2. **Snapshot isolation for point lookups** — `BucketList::get()` must be safe to call
   concurrently with bucket merges. The current implementation uses `RwLock` on the bucket
   list; point lookups take a read lock. During merges, `PendingMerge` transitions happen
   under a write lock. This is functionally correct but could become a contention point
   under high lookup rates. Consider whether a snapshot-based approach (reading from an
   immutable snapshot handle) would reduce lock contention.

### Memory Impact

| Component | Estimate |
|-----------|----------|
| Per-bucket caches | ~100 MB (configurable) |
| InMemory indexes (small buckets) | ~50-200 MB depending on level distribution |
| DiskIndex metadata (large buckets) | ~50-100 MB (page headers + bloom filters) |
| **Total** | **~200-400 MB** |

---

## Phase 4: Index Persistence

**Status: Partial**

### What Exists

`index_persistence.rs` (726 lines) implements save/load using bincode serialization:

```
Header:
  - Version: u32 (currently BUCKET_INDEX_VERSION = 1)

Body:
  - pages: Vec<(SerializableRangeEntry, u64)>
  - bloom_seed: [u8; 16]
  - counters: SerializableCounters
  - type_ranges: HashMap<u32, (u64, u64)>
```

### Remaining Work

1. **Bloom filter persistence** — Currently not serialized (noted in code:
   `index_persistence.rs:175-176`). The bloom filter is rebuilt on load, which
   partially defeats the purpose of persistence for large buckets. Adding bloom
   filter serialization would make startup significantly faster.

2. **`asset_to_pool_id` map persistence** — Not currently serialized. Needed for
   complete index restoration.

3. **InMemoryIndex persistence** — The current persistence is range-index focused.
   Small buckets using `InMemoryIndex` may need their own persistence path, or they
   can be rebuilt quickly since they are small by definition.

4. **Integration with BucketManager** — Automatically save indexes after catchup/merge
   and load on startup with fallback to rebuild if missing/corrupt.

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

## Memory Budget Summary

### During Catchup (Peak)

| Component | Estimate |
|-----------|----------|
| Deduplication `HashSet<LedgerKey>` (transient) | ~8.6 GB |
| Bucket indexes | ~200-400 MB |
| Module cache (WASM compilation) | ~500 MB |
| SQLite (offers + overhead) | ~200 MB |
| Operating overhead (allocator, stack, etc.) | ~2 GB |
| **Peak total** | **~12-13 GB** |

### Steady-State Operation

| Component | Estimate |
|-----------|----------|
| Bucket indexes (persistent) | ~200-400 MB |
| Entry cache (`RandomEvictionCache`) | ~100 MB (configurable) |
| Module cache | ~500 MB |
| SQLite (offers + overhead) | ~200 MB |
| Operating overhead | ~1.5 GB |
| **Steady-state total** | **~2.5-3 GB** |

The deduplication HashSet is freed after catchup completes, so steady-state memory is
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
- Memory profiling during catchup (target: < 13 GB peak)
- Steady-state memory after 1,000+ ledger closes (target: < 4 GB)
- Iteration speed benchmark
- Point lookup latency (cache hit vs miss)
- SQL offer query latency during order book matching

### Mainnet Simulation
- Use mainnet bucket archives for realistic scale testing
- Verify peak memory stays within 16 GB budget
- Verify steady-state memory stays within 4 GB budget

---

## Dependencies

```
Phase 1 (Streaming Iterator) ✅
    |
    v
Phase 2 (SQL Offers) ✅ <------+
    |                           |
    v                           |
Phase 3 (Point Lookups) -------+ (can parallelize)
    |     ~substantially complete
    v
Phase 4 (Index Persistence)
          ~partial
```

Phases 2 and 3 can be worked on in parallel after Phase 1 completes.

---

## Risk Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **SQL offer query latency** | Medium | High — DEX matching is latency-sensitive | SQLite with the `bestofferindex` composite index should handle order book queries efficiently. Benchmark with mainnet-scale offer counts (~12M) early. If latency is unacceptable, consider an in-memory order book index backed by SQL as source of truth. |
| **Memory estimation off** | Medium | High — could exceed 16 GB target | Profile with real mainnet bucket archives. The transient dedup HashSet (~8.6 GB) is the largest single allocation; if it's too large, a bloom filter pre-screen could be added as a second tier to reduce the set size. |
| **Index format changes** | Low | Medium — breaks existing persisted indexes | Version field in the index header allows backward-compatible updates. Fallback to rebuild ensures no data loss. |
| **Regression in ledger close** | Low | Critical — consensus failure | Comprehensive comparison tests: run Rust and C++ side-by-side on the same ledger sequence and verify identical hashes for 1,000+ consecutive ledgers. |
| **Lock contention on BucketList** | Medium | Medium — slower lookups under load | Point lookups take a read lock; merges take a write lock. If contention is observed, move to a snapshot-based read path that doesn't hold a lock during disk I/O. |
| **Hot archive memory growth** | Low | Medium — unexpected memory pressure | Monitor hot archive size during extended mainnet observer runs. Flag for disk-backed treatment if it exceeds 1 GB. |

---

## Success Metrics

1. **Memory (peak)**: RSS < 16 GB during catchup with mainnet bucket archives
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

*Last updated: January 2026*
