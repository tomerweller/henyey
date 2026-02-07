# Catchup Memory Analysis

**Goal:** Reduce mainnet catchup peak RSS to < 16 GB

## Executive Summary

Mainnet catchup currently peaks at ~12-13 GB, dominated by a single allocation: the
`HashSet<LedgerKey>` dedup set in `LiveEntriesIterator` (~8.6 GB for 60M keys). C++
stellar-core achieves ~1-2 GB during catchup by using per-type scanning and only
tracking the keys relevant to each operation.

Five architectural differences from C++ account for the excess memory. Fixing the
highest-priority issue (the dedup HashSet) saves ~8.4 GB and brings peak RSS to ~4 GB.

---

## C++ Memory Profile During Catchup

C++ stellar-core (v25) uses a fundamentally different approach to state initialization:

| Component | C++ Approach | Memory |
|-----------|-------------|--------|
| Soroban state init | `InMemorySorobanState::initializeStateFromSnapshot()` — three per-type scans (`CONTRACT_DATA`, `TTL`, `CONTRACT_CODE`) with a `deletedKeys` set tracking only Soroban keys | ~240 MB |
| Offer SQL population | `ApplyBucketsWork` — `mSeenKeys` tracks only ~2M offer keys | ~200-300 MB |
| Bucket indexes | `DiskIndex` (page-based range + bloom filter) for large buckets; `InMemoryIndex` for small buckets (< 20 MB) | ~200-400 MB |
| Module cache (WASM) | Compiled module cache | ~500 MB |
| SQLite overhead | Offers + schema | ~200 MB |
| Operating overhead | Allocator, stack, OS | ~1-2 GB |
| **Total** | | **~1-2 GB** |

Key C++ config defaults:
- `BUCKETLIST_DB_INDEX_CUTOFF`: 20 MB (buckets below this get full InMemoryIndex)
- `BUCKETLIST_DB_INDEX_PAGE_SIZE_EXPONENT`: 14 (16 KB pages)
- `BUCKETLIST_DB_MEMORY_FOR_CACHING`: 0 (disabled by default)
- `WORKER_THREADS`: 11

---

## Rust Memory Profile During Catchup (Current)

### ISSUE 1: `compute_initial_soroban_state_size` dedup HashSet — 8.6 GB

**Status: FIXED** (see below)

**File:** `crates/stellar-core-history/src/catchup.rs:2354`

The function used `bucket_list.live_entries_iter()` which creates a `HashSet<LedgerKey>` for
ALL ~60M keys in the bucket list, consuming ~8.6 GB. However, it only needs `ContractData`
and `ContractCode` entries (~1.68M keys total).

**C++ equivalent:** `InMemorySorobanState::initializeStateFromSnapshot()` does three per-type
scans (`scanForEntriesOfType`) with a `deletedKeys` set tracking only Soroban-related keys.
Memory: ~240 MB.

**Fix:** Replace `live_entries_iter()` with `scan_for_entries_of_types()` targeting only
`ContractData` and `ContractCode`. This reduces the dedup set from ~60M keys to ~1.68M keys.

**Savings:** ~8.6 GB -> ~240 MB (**~8.4 GB saved**)

### ISSUE 2: DiskBucket flat index — 960 MB

**File:** `crates/stellar-core-bucket/src/disk_bucket.rs`

The current `DiskBucket` uses a Legacy flat index (`BTreeMap<u64, IndexEntry>`) with 16 bytes
per key. For 60M mainnet keys across ~42 buckets: ~960 MB.

C++ uses page-based `DiskIndex` (~10 MB) + bloom filter (~138 MB) = ~148 MB.

The Rust `LiveBucketIndex` infrastructure already exists in `index.rs` with both `InMemoryIndex`
and `DiskIndex` modes, but it is NOT connected to `DiskBucket` yet (Phase 8 in the roadmap).

**Fix:** Phase 8 — Connect `LiveBucketIndex` to `DiskBucket`.

**Savings:** ~960 MB -> ~148 MB (**~812 MB saved**)

### ISSUE 3: Bucket download buffers

**File:** `crates/stellar-core-history/src/catchup.rs:1067`

`archive.get_bucket(&hash).await` returns the full bucket as `Vec<u8>`, then writes to disk.
With 16 parallel downloads (`buffer_unordered(16)`), multiple large buckets could be in
memory simultaneously. The largest mainnet bucket is ~6.4 GB.

In practice, each download task saves to disk and drops the buffer quickly, so the actual
peak depends on download/write speed overlap. Worst case: 2-3 large buckets in flight.

**Fix:** Stream downloads directly to disk files (avoid full `Vec<u8>` buffering).

**Savings:** Variable (~1-6 GB in worst case)

### ISSUE 4: Offer fallback closures use `live_entries_iter()`

**File:** `crates/stellar-core-ledger/src/manager.rs:1291, 1312`

Two fallback closures in `create_snapshot()` use `live_entries_iter()` when offers are not
initialized. These are rarely triggered (offers are normally initialized), but if they fire,
each creates an 8.6 GB dedup set just to find offers.

**Fix:** Replace with `scan_for_entries_of_type(Offer, ...)`.

**Savings:** ~8.6 GB -> ~200 MB (when fallback fires)

### ISSUE 5: Dead code using `live_entries_iter()`

**Files:**
- `manager.rs:571` — `initialize_module_cache()` (dead code, `#[allow(dead_code)]`)
- `manager.rs:624` — `initialize_soroban_state()` (dead code, `#[allow(dead_code)]`)
- `execution.rs:6187` — `compute_soroban_state_size_from_bucket_list()` (dead code, never called)

**Fix:** Remove dead code or convert to per-type scanning if resurrected.

---

## Memory Budget After Fixes

### During Catchup (Peak)

| Component | Current | After Issue 1 Fix | After All Fixes |
|-----------|---------|-------------------|-----------------|
| Dedup HashSet (soroban state) | ~8.6 GB | ~240 MB | ~240 MB |
| DiskBucket indexes (flat) | ~960 MB | ~960 MB | ~148 MB (Phase 8) |
| Module cache (WASM) | ~500 MB | ~500 MB | ~500 MB |
| SQLite (offers + overhead) | ~200 MB | ~200 MB | ~200 MB |
| Operating overhead | ~2 GB | ~2 GB | ~2 GB |
| **Peak total** | **~12-13 GB** | **~4 GB** | **~3-4 GB** |

### Steady-State Operation

| Component | Estimate |
|-----------|----------|
| Bucket indexes | ~200-400 MB (Phase 8: ~148 MB) |
| RandomEvictionCache | ~100 MB (configurable) |
| Module cache | ~500 MB |
| SQLite | ~200 MB |
| Operating overhead | ~1.5 GB |
| **Steady-state total** | **~2.5-3 GB** |

---

## Priority Order

| Priority | Issue | Savings | Effort | Dependency |
|----------|-------|---------|--------|------------|
| 1 | Dedup HashSet in `compute_initial_soroban_state_size` | ~8.4 GB | Small — swap `live_entries_iter()` for `scan_for_entries_of_types()` | None |
| 2 | Phase 8: Connect `LiveBucketIndex` to `DiskBucket` | ~812 MB | Medium — plumbing exists, needs wiring | None |
| 3 | Streaming bucket downloads | Variable | Medium — requires streaming HTTP response to disk | None |
| 4 | Offer fallback closures | ~8.4 GB (rare) | Small — same pattern as Issue 1 | None |
| 5 | Dead code cleanup | N/A | Trivial | None |

---

## Technical Notes

### How C++ Tracks Soroban State Size

C++ uses `InMemorySorobanState` with two running counters:
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
method in `manager.rs` uses per-type scanning (matching C++). The only outlier was
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
