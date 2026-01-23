# Known Issues

This document tracks known issues, limitations, and technical debt in rs-stellar-core.

## Performance Issues

### P1: In-Memory Soroban State Not Used for Contract Execution

**Status**: Open  
**Impact**: Suboptimal performance for Soroban contract execution  
**Added**: 2026-01-23

**Description**:
The `InMemorySorobanState` in `stellar-core-ledger` tracks all CONTRACT_DATA, CONTRACT_CODE, and TTL entries in memory with O(1) lookup. However, this cache is currently only used for:
- Computing the `LiveSorobanStateSizeWindow` state size (avoiding full bucket list scans)
- Tracking cumulative state size incrementally during ledger close

Contract execution still uses `LedgerStateManager` (in `stellar-core-tx`) which loads entries from the snapshot via bucket list B-tree lookups (O(log n) per entry).

**Current Behavior**:
1. Transaction footprint entries are loaded from `SnapshotHandle.get_entry()`
2. `SnapshotHandle` falls back to `bucket_list.get(key)` for cache misses
3. Each lookup traverses the bucket list B-tree

**Ideal Behavior**:
Soroban entry lookups should first check `InMemorySorobanState` for O(1) access before falling back to the bucket list.

**Complexity**:
Medium - requires plumbing the `InMemorySorobanState` through to the snapshot layer or providing an alternative lookup path for Soroban entries.

**Files Involved**:
- `crates/stellar-core-ledger/src/soroban_state.rs` - In-memory state implementation
- `crates/stellar-core-ledger/src/snapshot.rs` - Snapshot lookup logic
- `crates/stellar-core-ledger/src/manager.rs` - LedgerManager owns the soroban_state
- `crates/stellar-core-tx/src/soroban/host.rs` - Soroban host adapter

---

### P2: Invariant Checks Disabled Due to Bucket List Scans

**Status**: Open (workaround in place)  
**Impact**: Reduced validation, potential for undetected state inconsistencies  
**Added**: 2026-01-23

**Description**:
Ledger invariant checking is disabled (`validate_invariants: false`) because it requires full bucket list scans via `live_entries()` on every ledger close.

**Current Workaround**:
Invariants are disabled in `stellar-core-app/src/app.rs` to avoid memory growth from repeated bucket list scans.

**Ideal Solution**:
Refactor invariant checks to:
1. Only validate entries that changed (from the delta)
2. Use incremental state tracking instead of full scans
3. Or run invariant checks only periodically (e.g., every N ledgers)

**Files Involved**:
- `crates/stellar-core-app/src/app.rs` - Invariant config
- `crates/stellar-core-ledger/src/manager.rs` - Lines 1512-1519, 2174-2206
- `crates/stellar-core-invariant/` - Invariant implementations

---

## Memory Issues

### M1: Re-Catchup Causes Memory Growth

**Status**: Open  
**Impact**: Memory grows when validator falls behind and re-catches up  
**Added**: 2026-01-23

**Description**:
When the validator falls behind the network and triggers a re-catchup, the initialization caches (module cache, offer cache, soroban state) are repopulated from a fresh bucket list scan. The previous cache contents may not be fully released, causing gradual memory growth.

**Observed Behavior**:
- Initial memory: ~1.7 GB after first catchup
- After several re-catchups: ~4+ GB

**Potential Solutions**:
1. Explicitly clear caches before re-initialization
2. Use weak references or cache eviction
3. Investigate if Rust's allocator is not returning memory to OS

**Files Involved**:
- `crates/stellar-core-ledger/src/manager.rs` - `reinitialize_from_buckets()`

---

## Functional Limitations

### F1: Testnet Only

**Status**: By Design  
**Impact**: Cannot run on mainnet  
**Added**: 2026-01-23

**Description**:
This implementation is designed for testnet synchronization only. It should not be used on mainnet due to:
- Incomplete validation
- Disabled invariant checks
- Potential parity gaps with C++ stellar-core

---

## How to Add Issues

When adding a new issue:
1. Use the appropriate category (Performance, Memory, Functional)
2. Assign a unique ID (P1, M1, F1, etc.)
3. Include: Status, Impact, Added date, Description, and relevant file paths
4. Update status when issues are resolved
