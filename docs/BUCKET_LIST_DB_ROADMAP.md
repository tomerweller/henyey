# Bucket List DB Revamp - Implementation Roadmap

**Target:** Enable mainnet support by reducing memory requirements from 50+ GB to < 16 GB

## Overview

This document outlines the complete implementation plan for the Bucket List DB revamp,
the critical path to mainnet support. It expands on the analysis in `MAINNET_GAPS.md`
and provides detailed implementation guidance for each phase.

## Phase Summary

| Phase | Focus | Duration | Status |
|-------|-------|----------|--------|
| 1 | Streaming Iterator | 1 week | RFC Approved (RFC-001) |
| 2 | SQL-Backed Offers | 2 weeks | Planned |
| 3 | BucketListDB Point Lookups | 2 weeks | Planned |
| 4 | Index Persistence | 1 week | Planned |
| **Total** | | **6 weeks** | |

---

## Phase 1: Streaming Iterator (RFC-001)

**Status:** RFC Approved - Ready for implementation

See `docs/RFC-001-STREAMING-LIVE-ENTRIES.md` for full details.

### Summary
- Replace `live_entries()` with `LiveEntriesIterator`
- Use `HashSet<LedgerKey>` for deduplication (matches C++)
- Memory: ~8.6 GB for 60M entries (vs 52 GB current)

### Key Deliverables
1. `LiveEntriesIterator` type in `stellar-core-bucket`
2. Migration of `initialize_all_caches()` 
3. Migration of `compute_soroban_state_size_from_bucket_list()`
4. Deprecation of `live_entries()`

---

## Phase 2: SQL-Backed Offers

**Status:** Planned

### Problem
Current Rust implementation keeps all offers in memory (`Vec<LedgerEntry>`).
C++ stores offers in SQLite with indexes for efficient order book queries.

### C++ Architecture (What We're Matching)

```sql
-- From LedgerTxnOfferSQL.cpp
CREATE TABLE offers (
    sellerid         VARCHAR(56) NOT NULL,
    offerid          BIGINT NOT NULL PRIMARY KEY,
    sellingasset     TEXT NOT NULL,
    buyingasset      TEXT NOT NULL,
    amount           BIGINT NOT NULL,
    pricen           INT NOT NULL,
    priced           INT NOT NULL,
    price            DOUBLE PRECISION NOT NULL,
    flags            INT NOT NULL,
    lastmodified     INT NOT NULL,
    extension        TEXT NOT NULL,
    ledgerext        TEXT NOT NULL
);

CREATE INDEX bestofferindex ON offers (sellingasset, buyingasset, price, offerid);
CREATE INDEX offerbyseller ON offers (sellerid);
```

### Implementation Tasks

1. **Create offers table schema** (1 day)
   - Add migration to create `offers` table
   - Match C++ column types and indexes

2. **Implement offer SQL operations** (3 days)
   - `load_offer(sellerid, offerid) -> Option<LedgerEntry>`
   - `load_best_offers(buying, selling, limit) -> Vec<LedgerEntry>`
   - `load_best_offers_worse_than(buying, selling, price, offerid, limit)`
   - `load_offers_by_account_and_asset(account, asset) -> Vec<LedgerEntry>`
   - `bulk_upsert_offers(entries)`
   - `bulk_delete_offers(keys)`

3. **Populate offers during catchup** (2 days)
   - During streaming iteration (Phase 1), insert offers into SQL
   - Use batch inserts for performance

4. **Update offers during ledger close** (2 days)
   - Extract offer changes from `LedgerDelta`
   - Apply upserts and deletes to SQL table

5. **Replace in-memory offer cache** (2 days)
   - Remove `offer_cache: Vec<LedgerEntry>` from `LedgerManager`
   - Update order book matching to use SQL queries
   - Update `create_snapshot_handle()` to query SQL

### Files to Modify

| File | Changes |
|------|---------|
| `crates/stellar-core-ledger/src/database/` | New module for offer SQL operations |
| `crates/stellar-core-ledger/src/manager.rs` | Remove `offer_cache`, use SQL |
| `crates/stellar-core-ledger/src/execution.rs` | Update order book matching |
| `crates/stellar-core-bucket/src/live_iterator.rs` | Add hook for offer collection |

### Memory Impact
- Current: ~500 MB for testnet offers (scales with offer count)
- After: ~0 MB (offers in SQLite file, not RAM)

---

## Phase 3: BucketListDB Point Lookups

**Status:** Planned

### Problem
Currently, entries are looked up via in-memory caches. For entries not in cache,
we need efficient disk-backed lookups.

### C++ Architecture (What We're Matching)

C++ uses two index types based on bucket size:

1. **InMemoryIndex** (small buckets < 20 MB)
   - Full `unordered_map<LedgerKey, file_offset>`
   - Fast lookups, higher memory

2. **DiskIndex / RangeIndex** (large buckets)
   - Page-based index with bloom filter
   - Lower memory, requires disk seeks

### Implementation Tasks

1. **Enhance DiskBucket index** (3 days)
   - Current: 8-byte hash -> offset (compact but collision-prone)
   - New: Support full `LedgerKey` -> offset for small buckets
   - Add configurable threshold (`BUCKETLIST_DB_INDEX_CUTOFF`)

2. **Implement per-bucket RandomEvictionCache** (3 days)
   - Cache ACCOUNT entries only (hot path for TX validation)
   - Proportional allocation based on bucket's share of accounts
   - Configurable memory budget

3. **Add BucketList.load(key) API** (2 days)
   ```rust
   impl BucketList {
       /// Load a single entry by key, checking cache then disk.
       pub fn load(&self, key: &LedgerKey) -> Result<Option<LedgerEntry>> {
           // 1. Check per-bucket caches (newest levels first)
           // 2. Query bucket indexes
           // 3. Read from disk if found
           // 4. Optionally cache result
       }
   }
   ```

4. **Integrate with LedgerManager** (2 days)
   - Use `BucketList.load()` for cache misses
   - Remove dependency on full entry cache where possible

### Configuration Options

```toml
[bucket_list_db]
# Bucket size threshold for InMemory vs Disk index (MB)
index_cutoff_mb = 20

# Total memory budget for entry caching (MB)
memory_for_caching_mb = 512

# Page size for range index (2^N bytes)
page_size_exponent = 14
```

### Memory Impact
- Per-bucket caches: ~512 MB (configurable)
- Indexes: ~500 MB

---

## Phase 4: Index Persistence

**Status:** Planned

### Problem
Currently, bucket indexes are rebuilt on every startup by scanning bucket files.
For mainnet with large buckets, this is slow.

### C++ Architecture
C++ saves indexes as `.index` files alongside bucket `.xdr` files:
```
buckets/
  <hash>.xdr.gz      # Bucket data
  <hash>.index       # Serialized index
```

### Implementation Tasks

1. **Define index file format** (1 day)
   ```
   Header:
     - Magic: "RSBI" (4 bytes)
     - Version: u32
     - Index type: u8 (InMemory=0, Range=1)
   
   Body (InMemoryIndex):
     - Entry count: u64
     - Entries: [(LedgerKey XDR, file_offset: u64), ...]
   
   Body (RangeIndex):
     - Bloom filter: BinaryFuse16 serialized
     - Page count: u64
     - Pages: [(start_key XDR, file_offset: u64), ...]
   
   Footer:
     - Checksum: u32 (CRC32)
   ```

2. **Implement save/load** (2 days)
   ```rust
   impl BucketIndex {
       pub fn save_to_file(&self, path: &Path) -> Result<()>;
       pub fn load_from_file(path: &Path, expected_hash: &Hash256) -> Result<Option<Self>>;
   }
   ```

3. **Integrate with BucketManager** (2 days)
   - Save index after building during catchup/merge
   - Load index on startup if available
   - Fall back to rebuild if missing/corrupt

### Memory Impact
- No direct memory impact
- Faster startup (avoids full bucket scans)

---

## Testing Strategy

### Unit Tests (Each Phase)
- Correctness: output matches old implementation
- Edge cases: empty buckets, single entry, all dead entries

### Integration Tests
- Full catchup with streaming iterator
- Ledger close with SQL offers
- Point lookups with cache misses

### Performance Tests
- Memory profiling during catchup (target: < 10 GB peak)
- Iteration speed benchmark
- Point lookup latency (cache hit vs miss)

### Mainnet Simulation
- Use mainnet bucket archives for realistic scale testing
- Verify memory stays within 16 GB budget

---

## Dependencies

```
Phase 1 (Streaming Iterator)
    |
    v
Phase 2 (SQL Offers) <-------+
    |                        |
    v                        |
Phase 3 (Point Lookups) -----+ (can parallelize)
    |
    v
Phase 4 (Index Persistence)
```

Phases 2 and 3 can be worked on in parallel after Phase 1 completes.

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| SQL performance for offers | Benchmark early; SQLite with proper indexes is fast |
| Memory estimation off | Profile with real mainnet data early in Phase 1 |
| Index format changes | Version field allows backward-compatible updates |
| Regression in ledger close | Comprehensive comparison tests vs old impl |

---

## Success Metrics

1. **Memory**: Peak RSS < 16 GB during catchup and steady-state operation
2. **Correctness**: All existing tests pass, ledger hashes match C++
3. **Performance**: Ledger close time within 10% of current
4. **Startup**: < 5 minutes from persisted state (with index persistence)

---

## References

- [RFC-001: Streaming Live Entries](./RFC-001-STREAMING-LIVE-ENTRIES.md)
- [Mainnet Gaps Analysis](./MAINNET_GAPS.md)
- C++ LedgerTxnOfferSQL: `.upstream-v25/src/ledger/LedgerTxnOfferSQL.cpp`
- C++ LiveBucketIndex: `.upstream-v25/src/bucket/LiveBucketIndex.cpp`
- C++ BucketApplicator: `.upstream-v25/src/bucket/BucketApplicator.cpp`

---

*Last updated: January 2026*
