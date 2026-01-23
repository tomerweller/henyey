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

### F2: Offline Verification Delta Mismatch for Failed Transactions with Asset Issuers

**Status**: Open (under investigation)  
**Impact**: Bucket list hash mismatch at specific ledgers during offline verification  
**Added**: 2026-01-23

**Description**:
When running offline `verify-execution`, certain ledgers show a bucket list hash mismatch due to missing LIVE entries in our delta compared to CDP metadata. The issue manifests when a transaction fails after partially executing operations that involve asset transfers.

**Observed at**: Ledger 203280 (testnet)

**Symptoms**:
- CDP expects 10 LIVE entries, we produce 9
- Missing entry is the **issuer account** of an asset involved in a failed payment operation
- The failed transaction's fee source IS correctly preserved in our delta
- All transaction execution results match CDP (success/failure status correct)

**Example**:
```
LIVE only in CDP: Account(94c035a17f8d6e30e27b5750f80ee88e6a1d8c9647058e4cff2a2401e9dbed15)
DELTA COMPARISON: LIVE: ours=9, cdp=10, only_ours=0, only_cdp=1
```

The missing account is the issuer of `USDPEND` token. TX 4 failed with `Payment(NoTrust)` after the first payment operation succeeded, but the issuer account modification isn't in our delta.

**Investigation Notes**:
- Switched from two-phase (fee then execution) to single-phase execution (`deduct_fee=true`) - issue persists
- The issue is NOT the fee source account rollback (that works correctly)
- May be related to how payment operations update issuer accounts or how partial success is handled before rollback

**Files Involved**:
- `crates/rs-stellar-core/src/main.rs` - `cmd_verify_execution()` around line 3200
- `crates/stellar-core-ledger/src/execution.rs` - Transaction execution and rollback
- `crates/stellar-core-tx/src/operations/execute/payment.rs` - Payment operation

---

### F3: Hot Archive Entry Restoration Fails (Protocol 25)

**Status**: Open (CRITICAL)  
**Impact**: Causes hash mismatches on any ledger with entry restoration  
**Added**: 2026-01-23

**Description**:
Protocol 25 introduced entry restoration from the hot archive. When a Soroban transaction attempts to restore archived entries, our implementation fails to find them in state, causing a bucket list hash mismatch.

**Observed at**: Ledger 637593 (testnet)

**Symptoms**:
```
P25: Transaction has archived entries to restore restored_count=3 restored_indices=[12, 13, 14]
P25: Archived entry being restored but NOT FOUND in state idx=12 key_type=Discriminant(6)
P25: Archived entry being restored but NOT FOUND in state idx=13 key_type=Discriminant(6)
P25: Archived entry being restored but NOT FOUND in state idx=14 key_type=Discriminant(6)
```

The transaction then fails with `HostError: Error(WasmVm, InvalidAction)` because the entries it needs to restore are not available.

**Root Cause**:
The hot archive bucket list is populated during catchup, but the restoration lookup is failing. Either:
1. The hot archive entries are not being indexed correctly
2. The restoration lookup is searching the wrong data structure
3. The hot archive bucket list hash is computed but the actual entries are not accessible

**Impact**:
- Any ledger with entry restoration will fail
- Validator cannot sync past these ledgers
- Re-catchup cannot recover (same failure repeats)

**Files Involved**:
- `crates/stellar-core-tx/src/soroban/host.rs` - Entry restoration logic
- `crates/stellar-core-bucket/src/hot_archive.rs` - Hot archive bucket list
- `crates/stellar-core-ledger/src/manager.rs` - Hot archive initialization

---

## Observed Hash Mismatches

This section logs ledger sequences where hash mismatches occurred during testnet validation. These are tracked to help identify patterns and root causes.

### Session: 2026-01-23 15:08 - 15:33 UTC

**Summary**: 4 hash mismatches out of 269 ledger closes (~1.5% failure rate). All recovered via automatic re-catchup.

| Ledger | Timestamp (UTC) | Our Hash (truncated) | Network Hash (truncated) | Recovery |
|--------|-----------------|----------------------|--------------------------|----------|
| 637247 | 15:21:27 | `73b081a8...` | `24ccf15c...` | Re-catchup to 637248 |
| 637308 | 15:26:32 | `d77061af...` | `2adeca8c...` | Re-catchup to 637312 |

**Observations**:
- Mismatches are NOT on sample ledgers (multiples of 64)
- Ledger 637246 (mod 64 = 62) and 637307 (mod 64 = 59) were the ledgers with wrong hashes
- Both occurred ~60-120 ledgers after a sample ledger
- Recovery via re-catchup was successful in both cases

**Suspected Cause**: Related to M1 (Re-catchup causes state drift). After re-catchup, in-memory Soroban state may not be properly re-synchronized with the new bucket list state.

### Session: 2026-01-23 15:48 - 15:51 UTC

**Summary**: Hash mismatch immediately after fresh start due to F3 (hot archive restoration failure).

| Ledger | Timestamp (UTC) | Our Hash (truncated) | Network Hash (truncated) | Cause |
|--------|-----------------|----------------------|--------------------------|-------|
| 637593 | 15:50:20 | `52917696...` | `b6ee1628...` | F3: Entry restoration failed |

**Root Cause**: Ledger 637593 contained a transaction requiring restoration of 3 archived CONTRACT_DATA entries. Our hot archive lookup returned NOT FOUND for all 3 entries.

---

## How to Add Issues

When adding a new issue:
1. Use the appropriate category (Performance, Memory, Functional)
2. Assign a unique ID (P1, M1, F1, etc.)
3. Include: Status, Impact, Added date, Description, and relevant file paths
4. Update status when issues are resolved
