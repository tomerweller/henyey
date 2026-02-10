# Catchup Memory Analysis

**Goal:** Reduce mainnet catchup peak RSS to < 16 GB

## Executive Summary

Mainnet catchup currently peaks at ~12-13 GB, dominated by a single allocation: the
`HashSet<LedgerKey>` dedup set in `LiveEntriesIterator` (~8.6 GB for 60M keys). stellar-core
stellar-core achieves ~1-2 GB during catchup by using per-type scanning and only
tracking the keys relevant to each operation.

Five architectural differences from stellar-core account for the excess memory. Fixing the
highest-priority issue (the dedup HashSet) saves ~8.4 GB and brings peak RSS to ~4 GB.

---

## stellar-core Memory Profile During Catchup

stellar-core (v25) uses a fundamentally different approach to state initialization:

| Component | stellar-core Approach | Memory |
|-----------|-------------|--------|
| Soroban state init | `InMemorySorobanState::initializeStateFromSnapshot()` — three per-type scans (`CONTRACT_DATA`, `TTL`, `CONTRACT_CODE`) with a `deletedKeys` set tracking only Soroban keys | ~240 MB |
| Offer SQL population | `ApplyBucketsWork` — `mSeenKeys` tracks only ~2M offer keys | ~200-300 MB |
| Bucket indexes | `DiskIndex` (page-based range + bloom filter) for large buckets; `InMemoryIndex` for small buckets (< 20 MB) | ~200-400 MB |
| Module cache (WASM) | Compiled module cache | ~500 MB |
| SQLite overhead | Offers + schema | ~200 MB |
| Operating overhead | Allocator, stack, OS | ~1-2 GB |
| **Total** | | **~1-2 GB** |

Key stellar-core config defaults:
- `BUCKETLIST_DB_INDEX_CUTOFF`: 20 MB (buckets below this get full InMemoryIndex)
- `BUCKETLIST_DB_INDEX_PAGE_SIZE_EXPONENT`: 14 (16 KB pages)
- `BUCKETLIST_DB_MEMORY_FOR_CACHING`: 0 (disabled by default)
- `WORKER_THREADS`: 11

---

## Rust Memory Profile During Catchup (Current)

### ISSUE 1: `compute_initial_soroban_state_size` dedup HashSet — 8.6 GB

**Status: FIXED** (see below)

**File:** `crates/henyey-history/src/catchup.rs:2354`

The function used `bucket_list.live_entries_iter()` which creates a `HashSet<LedgerKey>` for
ALL ~60M keys in the bucket list, consuming ~8.6 GB. However, it only needs `ContractData`
and `ContractCode` entries (~1.68M keys total).

**stellar-core equivalent:** `InMemorySorobanState::initializeStateFromSnapshot()` does three per-type
scans (`scanForEntriesOfType`) with a `deletedKeys` set tracking only Soroban-related keys.
Memory: ~240 MB.

**Fix:** Replace `live_entries_iter()` with `scan_for_entries_of_types()` targeting only
`ContractData` and `ContractCode`. This reduces the dedup set from ~60M keys to ~1.68M keys.

**Savings:** ~8.6 GB -> ~240 MB (**~8.4 GB saved**)

### ISSUE 2: DiskBucket index memory — ~200-400 MB

**File:** `crates/henyey-bucket/src/disk_bucket.rs`

The legacy flat `DiskBucketIndex` (`BTreeMap` per-key) was removed in favor of `LiveBucketIndex`
which supports both `InMemoryIndex` (full key→offset map for small buckets) and `DiskIndex`
(page-based range index + bloom filter for large buckets). The `LiveBucketIndex` is wired
into `DiskBucket` and index persistence is available (gated by `persist_index` flag).

Current memory usage depends on bucket size distribution:
- Small buckets (< 10K entries): `InMemoryIndex` with full key map
- Large buckets (≥ 10K entries): `DiskIndex` with pages (~60K total) + bloom filter

stellar-core uses page-based `DiskIndex` (~10 MB) + bloom filter (~138 MB) = ~148 MB.

**Remaining work:** Phase 8 — Wire persisted index loading into `DiskBucket` to avoid
full bucket scans on startup.

**Savings:** ~960 MB (old flat index) → ~200-400 MB (current) → ~148 MB (Phase 8)

### ISSUE 3: Bucket download buffers

**File:** `crates/henyey-history/src/catchup.rs:1067`

`archive.get_bucket(&hash).await` returns the full bucket as `Vec<u8>`, then writes to disk.
With 16 parallel downloads (`buffer_unordered(16)`), multiple large buckets could be in
memory simultaneously. The largest mainnet bucket is ~6.4 GB.

In practice, each download task saves to disk and drops the buffer quickly, so the actual
peak depends on download/write speed overlap. Worst case: 2-3 large buckets in flight.

**Fix:** Stream downloads directly to disk files (avoid full `Vec<u8>` buffering).

**Savings:** Variable (~1-6 GB in worst case)

### ~~ISSUE 4: Offer fallback closures use `live_entries_iter()`~~ (FIXED)

**File:** `crates/henyey-ledger/src/manager.rs`

Two fallback closures in `create_snapshot()` used `live_entries_iter()` when offers were not
initialized. Replaced with `scan_for_entries_of_type(Offer, ...)`.

**Savings:** ~8.6 GB -> ~200 MB (when fallback fires)

### ~~ISSUE 5: Dead code using `live_entries_iter()`~~ (FIXED)

Removed dead functions that used `live_entries_iter()`:
- `initialize_module_cache()` (manager.rs)
- `initialize_soroban_state()` (manager.rs)
- `compute_soroban_state_size_from_bucket_list()` (execution.rs)

---

## Memory Budget After Fixes

### During Catchup (Peak)

| Component | Current | After Issue 1 Fix | After All Fixes |
|-----------|---------|-------------------|-----------------|
| Dedup HashSet (soroban state) | ~8.6 GB | ~240 MB | ~240 MB |
| DiskBucket indexes (LiveBucketIndex) | ~200-400 MB | ~200-400 MB | ~148 MB (Phase 8) |
| Module cache (WASM) | ~500 MB | ~500 MB | ~500 MB |
| SQLite (offers + overhead) | ~200 MB | ~200 MB | ~200 MB |
| Operating overhead | ~2 GB | ~2 GB | ~2 GB |
| **Peak total** | **~12-13 GB** | **~4 GB** | **~3-4 GB** |

### Steady-State Operation

| Component | Estimate |
|-----------|----------|
| Bucket indexes | ~200-400 MB (Phase 8: ~148 MB) |
| RandomEvictionCache (integrated into BucketList::get) | ~100 MB (configurable) |
| Module cache | ~500 MB |
| SQLite | ~200 MB |
| Operating overhead | ~1.5 GB |
| **Steady-state total** | **~2.5-3 GB** |

---

## Priority Order

| Priority | Issue | Savings | Effort | Dependency |
|----------|-------|---------|--------|------------|
| 1 | Dedup HashSet in `compute_initial_soroban_state_size` | ~8.4 GB | Small — swap `live_entries_iter()` for `scan_for_entries_of_types()` | None |
| 2 | Phase 8: Wire persisted index loading into `DiskBucket` | ~50-250 MB | Medium — persistence exists, needs startup wiring | None |
| 3 | Streaming bucket downloads | Variable | Medium — requires streaming HTTP response to disk | None |
| 4 | ~~Offer fallback closures~~ | ~~~8.4 GB~~ | ~~Small~~ | FIXED |
| 5 | ~~Dead code cleanup~~ | N/A | ~~Trivial~~ | FIXED |

---

## Technical Notes

### How stellar-core Tracks Soroban State Size

stellar-core uses `InMemorySorobanState` with two running counters:
- `mContractCodeStateSize` (int64_t)
- `mContractDataStateSize` (int64_t)

**Initialization (catchup/startup):** Three per-type scans of the bucket list via
`scanForEntriesOfType` for `CONTRACT_DATA`, `TTL`, and `CONTRACT_CODE`. A `deletedKeys`
set (only Soroban keys) handles shadowing. Each entry's size is added to the running total.

**Maintenance (ledger close):** Purely incremental. Each `initEntries` / `liveEntries` /
`deadEntries` create/update/delete adjusts the counters by delta. No iteration needed.

**Our Rust implementation matches this pattern:** `soroban_state.rs` has the same
`contract_data_state_size` / `contract_code_state_size` fields, updated incrementally
during ledger close via `process_entry_create/update/delete`. The `initialize_all_caches()`
method in `manager.rs` uses per-type scanning (matching stellar-core). The only outlier was
`compute_initial_soroban_state_size()` in `catchup.rs`, which used the generic
`live_entries_iter()` instead of per-type scanning.

### Why `scan_for_entries_of_types` Is Safe for Soroban Size

The dedup set in `scan_for_entries_of_types` only needs to track keys of the requested types.
Since `LedgerKey` is a discriminated union, keys of different types never collide. A dead
`ContractData` entry at level 2 correctly shadows a live `ContractData` at level 5, and the
dedup set only holds ~1.68M ContractData + ContractCode keys instead of all 60M.

### Existing `initialize_all_caches` Already Does This Right

`LedgerManager::initialize_all_caches()` (manager.rs:774) uses five separate
`scan_for_entries_of_type()` calls for Offers, ContractCode, ContractData, TTL, and
ConfigSetting. Each scan builds a dedup set only for that entry type. Peak memory is
~240 MB (the ContractData scan with ~1.68M keys). This is the pattern that
`compute_initial_soroban_state_size` should follow.

---

*Last updated: February 2026*
