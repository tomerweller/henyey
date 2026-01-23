# Known Issues

This document tracks known issues, limitations, and technical debt in rs-stellar-core.

## Performance Issues

### P1: In-Memory Soroban State Not Used for Contract Execution

**Status**: FIXED  
**Impact**: Was causing suboptimal performance for Soroban contract execution  
**Added**: 2026-01-23  
**Fixed**: 2026-01-23

**Description**:
The `InMemorySorobanState` in `stellar-core-ledger` tracks all CONTRACT_DATA, CONTRACT_CODE, and TTL entries in memory with O(1) lookup. Previously, this cache was only used for:
- Computing the `LiveSorobanStateSizeWindow` state size (avoiding full bucket list scans)
- Tracking cumulative state size incrementally during ledger close

Contract execution used `LedgerStateManager` which loaded entries from the snapshot via bucket list B-tree lookups (O(log n) per entry).

**Solution**:
Modified `LedgerManager::create_snapshot()` to create a lookup function that:
1. First checks `InMemorySorobanState` for Soroban entry types (CONTRACT_DATA, CONTRACT_CODE, TTL)
2. Falls back to bucket list for non-Soroban types or cache misses

This provides O(1) lookups for Soroban entries instead of O(log n) bucket list B-tree traversals.

**Files Changed**:
- `crates/stellar-core-ledger/src/manager.rs` - Modified `lookup_fn` in `create_snapshot()` to check `InMemorySorobanState` first

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

### F2: Offline Verification Delta Mismatch for Accessed-But-Unchanged Accounts

**Status**: FIXED  
**Impact**: Was causing bucket list hash mismatch at specific ledgers during offline verification  
**Added**: 2026-01-23  
**Fixed**: 2026-01-23

**Description**:
When running offline `verify-execution`, certain ledgers showed a bucket list hash mismatch due to missing LIVE entries in our delta compared to CDP metadata. The issue manifested in scenarios where accounts were accessed but unchanged.

**Root Causes (All Fixed)**:

1. **AccountMerge with 0 balance** (FIXED): When an AccountMerge transfers 0 balance, the destination account was accessed but unchanged, and we weren't recording it in the delta.

2. **CreateClaimableBalance with different op source** (FIXED): When `CreateClaimableBalance` has an operation source different from the transaction source (e.g., issuer account), C++ stellar-core calls `loadSourceAccount()` which records the access. We weren't calling `record_account_access()` for the source.

3. **AllowTrust/SetTrustLineFlags issuer account** (FIXED): Similar to above, the issuer account needs to be recorded when accessed.

**Observed at**: 
- Ledger 360249 (testnet) - AccountMerge with 0 balance
- Ledger 203280 (testnet) - CreateClaimableBalance with issuer as op source

**Fix Applied**:
1. The `flush_all_accounts_except()` method now checks `op_entry_snapshots` to determine if an entry was accessed during the operation.
2. Added `record_account_access()` method to `LedgerStateManager` that explicitly marks an account as accessed even if not modified.
3. Added `record_account_access()` calls in `execute_create_claimable_balance()`, `execute_allow_trust()`, and `execute_set_trust_line_flags()` to match C++ `loadSourceAccount()` behavior.

**Files Changed**:
- `crates/stellar-core-tx/src/state.rs` - Added `record_account_access()` method, updated `flush_all_accounts_except()`
- `crates/stellar-core-tx/src/operations/execute/claimable_balance.rs` - Call `record_account_access()` for source
- `crates/stellar-core-tx/src/operations/execute/trust_flags.rs` - Call `record_account_access()` for source

**Regression Test**: `test_create_claimable_balance_records_source_account_access` in `crates/stellar-core-tx/src/operations/execute/claimable_balance.rs`

**Verification**: Ledgers 64-203500+ now pass with 0 header mismatches

---

### F3: Hot Archive Entry Restoration Fails (Protocol 25)

**Status**: FIXED  
**Impact**: Was causing hash mismatches on any ledger with entry restoration  
**Added**: 2026-01-23  
**Fixed**: 2026-01-23

**Description**:
Protocol 25 introduced entry restoration from the hot archive. When a Soroban transaction attempts to restore archived entries, our implementation failed to find them in state, causing a bucket list hash mismatch.

**Observed at**: Ledger 637593 (testnet)

**Root Cause (Two Parts)**:
1. The `LedgerSnapshotAdapterP25::get_archived()` method only looked in `LedgerStateManager` (live state). Evicted entries are no longer in the live state - they're in the `HotArchiveBucketList`. The lookup returned "NOT FOUND" causing transaction failures.
2. Even after adding the hot archive lookup path, the hot archive was never actually passed to the transaction execution layer - `execute_transaction_set()` created a `TransactionExecutor` but never called `set_hot_archive()`.

**Solution**:
1. Added `HotArchiveLookup` trait in `stellar-core-tx` to enable lookup of evicted entries without depending on `stellar-core-bucket`. The `LedgerSnapshotAdapterP25::get_archived()` method now falls back to the hot archive when an entry is not found in live state.
2. Added `hot_archive` parameter to `execute_transaction_set()` and wired it through from `LedgerManager.apply_transactions()` to `TransactionExecutor.set_hot_archive()`.

**Files Changed**:
- `crates/stellar-core-tx/src/soroban/mod.rs` - Added `HotArchiveLookup` trait
- `crates/stellar-core-tx/src/soroban/host.rs` - Updated snapshot adapters with hot archive fallback
- `crates/stellar-core-ledger/src/execution.rs` - Added `HotArchiveLookupImpl` wrapper and hot_archive parameter
- `crates/stellar-core-ledger/src/manager.rs` - Pass hot archive to execute_transaction_set
- `crates/stellar-core-history/src/replay.rs` - Pass None for hot_archive during replay
- `crates/rs-stellar-core/src/main.rs` - Create compatible wrapper for offline verification

**Regression Test**: `test_execute_transaction_set_accepts_hot_archive_parameter` in `crates/stellar-core-ledger/tests/transaction_execution.rs`

---

### F4: Eviction-Related Bucket List Hash Mismatch

**Status**: Pending Re-validation (may be resolved by F3 fix)  
**Impact**: Was causing hash mismatches on ledgers with entry eviction  
**Added**: 2026-01-23

**Description**:
When entries are evicted from the live bucket list to the hot archive during ledger close, the computed bucket list hash diverges from the network's expected hash. This was originally thought to be a **different bug from F3** (restoration failure), but may have been caused by the same root issue (hot archive not being passed to execution).

**Observed at**: Ledgers 638670, 638737, 638938 (testnet)

**Symptoms**:
- Hash mismatch occurs on ledgers with `archived_count > 0` (eviction happening)
- `restored_count = 0` (no restoration attempted)
- The live bucket list hash is computed, but the combined hash differs from network
- Re-catchup does not resolve - the same ledger fails again

**Example from ledger 638938**:
```
Bucket list hash computation ledger_seq=638938 
  live_hash=2a358bc79b162929bf430c00781f3a0cde90379cb59caeca35223be367624002 
  pre_hot_hash=d01098b39647a140d57c03b600df49f2222b3c942765944fada47da18bcb92ff 
  post_hot_hash=8a8a28f5af4de00aa947c32a97d9e413a99ac7ee02a3e35e0e1e98cedd8a0f58 
  combined_hash=18d804eae377ae284491a299cf27583389c8cc41e0834562759eaa42aa6994e8 
  archived_count=1 restored_count=0

Hash mismatch:
  our_hash=01a052e0c9d825e139b39f64d2c0bdbebc4b20402d65e4eb425a27ef1c62056b
  network_prev_hash=49e7b351142d86d6fd882ff1e00ad288d4aa8a135ec8b2dc5b04574f3c9d483b
```

**Status Update (2026-01-23)**:
The F3 fix (wiring hot archive through to execution) resulted in **137+ consecutive ledger closes with 0 hash mismatches** during live testnet validation. This suggests F4 may have been a downstream effect of F3 (missing hot archive context affecting transaction execution, which then affected eviction/hash computation).

**Next Steps**:
- Continue monitoring live testnet validation for any recurrence
- If mismatches reappear, investigate eviction-specific issues:
  1. Hot archive entry format differences (Archived vs Live entry types)
  2. Hot archive bucket list merge timing
  3. Combined bucket list hash computation (live + hot archive)

**Files Involved**:
- `crates/stellar-core-ledger/src/manager.rs` - Eviction scan and hot archive update
- `crates/stellar-core-bucket/src/hot_archive.rs` - Hot archive bucket list operations
- `crates/stellar-core-bucket/src/bucket_list.rs` - Combined hash computation

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

**Root Cause (FIXED)**: The `restore_from_hashes()` method in bucket list sets `ledger_seq` to 0 after catchup. This caused `advance_to_ledger()` to erroneously apply hundreds of thousands of empty batches (from ledger 1 to N-1), corrupting the bucket list structure. The corruption manifested ~60 ledgers later when merge timing caused hash mismatches.

**Fix**: Set `bucket_list.set_ledger_seq(header.ledger_seq)` after restoring bucket lists in `initialize_from_buckets()`. See commit for details.

### Session: 2026-01-23 15:48 - 15:51 UTC

**Summary**: Hash mismatch immediately after fresh start due to F3 (hot archive restoration failure).

| Ledger | Timestamp (UTC) | Our Hash (truncated) | Network Hash (truncated) | Cause |
|--------|-----------------|----------------------|--------------------------|-------|
| 637593 | 15:50:20 | `52917696...` | `b6ee1628...` | F3: Entry restoration failed |

**Root Cause**: Ledger 637593 contained a transaction requiring restoration of 3 archived CONTRACT_DATA entries. Our hot archive lookup returned NOT FOUND for all 3 entries.

### Session: 2026-01-23 16:44 - 17:44 UTC

**Summary**: Multiple hash mismatches due to F4 (eviction-related bucket list hash mismatch).

| Ledger | Timestamp (UTC) | Our Hash (truncated) | Network Hash (truncated) | Cause |
|--------|-----------------|----------------------|--------------------------|-------|
| 638670 | 17:20:16 | `1031bae8...` | `95868c1c...` | F4: Eviction hash mismatch |
| 638737 | 17:25:47 | `4b477c50...` | `fbca4311...` | F4: Eviction hash mismatch |
| 638938 | 17:42:38 | `01a052e0...` | `49e7b351...` | F4: Eviction hash mismatch |

**Pattern**: All failing ledgers have `archived_count > 0` indicating entries were evicted to hot archive during that ledger close. No restoration was attempted (`restored_count = 0`).

### Session: 2026-01-23 18:57 - 19:10+ UTC (Post-F3 Fix)

**Summary**: After fixing the hot archive wiring issue (F3), **137+ consecutive ledger closes with 0 hash mismatches**. The validator is running stably in sync with testnet.

| Metric | Value |
|--------|-------|
| Start Ledger | ~639808 |
| Current Ledger | 639902+ |
| Ledgers Closed | 137+ |
| Hash Mismatches | 0 |
| Status | Running stably |

**Observations**:
- The F3 fix (wiring hot archive to transaction execution) appears to have resolved the eviction-related hash mismatches (F4)
- No restoration operations observed yet, but the validator continues to run without issues
- Continuing to monitor for any recurrence

---

## How to Add Issues

When adding a new issue:
1. Use the appropriate category (Performance, Memory, Functional)
2. Assign a unique ID (P1, M1, F1, etc.)
3. Include: Status, Impact, Added date, Description, and relevant file paths
4. Update status when issues are resolved
