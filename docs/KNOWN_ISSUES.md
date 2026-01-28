# Known Issues

This document tracks known issues, limitations, and technical debt in rs-stellar-core.

## Performance Issues

### P1: Merge Deduplication Not Integrated

**Status**: Known Gap  
**Impact**: Medium - Potential performance regression during catchup/restart  
**Added**: 2026-01-28

The `BucketMergeMap` and `LiveMergeFutures` data structures are implemented and tested (matching C++ behavior), but they are **not integrated** into the `BucketList` merge workflow.

**C++ Behavior:**
- `BucketManager::getMergeFuture()` checks for in-progress merges, then cached completed merges
- `recordMerge()` caches input→output mappings after merge completion
- This allows skipping re-runs when the same inputs are requested (e.g., catchup retries)

**Current Rust Behavior:**
- Guards against duplicate concurrent merges via `if self.next.is_some() { continue; }`
- Does NOT cache completed merge results for reuse
- Each `restart_merges()` re-runs merges even if same inputs were merged before

**Impact Assessment:**
- Minimal during normal operation (each ledger produces unique bucket contents)
- Potential regression during catchup/restart scenarios with repeated merge requests

**Files:**
- `crates/stellar-core-bucket/src/merge_map.rs` - Data structures (implemented)
- `crates/stellar-core-bucket/src/bucket_list.rs` - Would need integration
- `crates/stellar-core-bucket/PARITY_STATUS.md` - Detailed documentation

**To Fix:**
1. Add `BucketMergeMap` and `LiveMergeFutures` to `BucketManager`
2. Before `AsyncMergeHandle::start_merge()`, check for existing/completed merge
3. After merge completes, call `record_merge()`
4. Wire up GC to call `forget_all_merges_producing()` when buckets are dropped

---

## Limitations

### Testnet Only

**Status**: By Design

This implementation is designed for testnet synchronization only. It should not be used on mainnet due to:
- Potential parity gaps with C++ stellar-core
- Not yet production-hardened

---

## Resolved Issues Archive

The following issues have been fixed. They are kept here for historical reference.

<details>
<summary>P1: In-Memory Soroban State Not Used for Contract Execution (FIXED 2026-01-23)</summary>

Modified `LedgerManager::create_snapshot()` to check `InMemorySorobanState` first for Soroban entry types, providing O(1) lookups instead of O(log n) bucket list B-tree traversals.
</details>

<details>
<summary>M1: Re-Catchup Causes Memory Growth (Partially Fixed 2026-01-23)</summary>

Created `initialize_all_caches()` that does a single pass over `live_entries()` instead of three separate passes. Reduced initial memory by ~50%.
</details>

<details>
<summary>F2: Offline Verification Delta Mismatch for Accessed-But-Unchanged Accounts (FIXED 2026-01-23)</summary>

Fixed AccountMerge with 0 balance, CreateClaimableBalance with different op source, and AllowTrust/SetTrustLineFlags issuer account handling.
</details>

<details>
<summary>F3: Hot Archive Entry Restoration Fails - Protocol 25 (FIXED 2026-01-23)</summary>

Added `HotArchiveLookup` trait and wired hot archive through to transaction execution layer.
</details>

<details>
<summary>F4: Soroban Crypto Error - BN254 Point Encoding (FIXED 2026-01-24)</summary>

Updated to soroban-env-host v25.0.0 which includes the BN254 encoding fix.
</details>

<details>
<summary>F5: Hot Archive Restoration Emitting CREATED Instead of RESTORED (FIXED 2026-01-24)</summary>

Fixed `apply_soroban_storage_change` to check if entry was created in delta, not just if it exists in state.
</details>

<details>
<summary>F6: Rent Fee Double-Charged for Entries Already Restored (FIXED 2026-01-24)</summary>

Build `actual_restored_indices` list by checking if entries are truly archived at execution time.
</details>

<details>
<summary>F7: Extra RESTORED Changes for Entries Already Restored (FIXED 2026-01-24)</summary>

Propagated `actual_restored_indices` to `extract_hot_archive_restored_keys` function.
</details>

<details>
<summary>F8: Fee Refund Not Applied for Failed Soroban Transactions (FIXED 2026-01-24)</summary>

Added `reset()` method to `RefundableFeeTracker` that resets consumed fees on transaction failure.
</details>

<details>
<summary>F9: RestoreFootprint Hot Archive Keys Not Returned (FIXED 2026-01-24)</summary>

Modified hot archive key collection to not filter by `created_keys` for RestoreFootprint operations.
</details>

<details>
<summary>F10: Duplicate Entry Error When Restoring Hot Archive Entries (FIXED 2026-01-24)</summary>

Check if ContractCode/ContractData already exists in soroban_state before creating.
</details>

<details>
<summary>F11: Persistent Module Cache Not Updated for New Contracts (FIXED 2026-01-25)</summary>

Added module cache update after soroban_state update for newly deployed contracts.
</details>

<details>
<summary>F12: SetOptions Missing Inflation Destination Validation (FIXED 2026-01-25)</summary>

Added validation that inflation destination account exists (unless it's self).
</details>

<details>
<summary>F13: Bucket List Hash Divergence at Large Merge Points (FIXED 2026-01-26)</summary>

Fixed protocol version handling in bucket merges - in-memory uses max_protocol_version directly, disk-based uses max(old, new).
</details>

<details>
<summary>F14: LiquidityPoolDeposit/Withdraw Fails for Asset Issuers (FIXED 2026-01-26)</summary>

Added `is_issuer()` helper and updated liquidity pool operations to handle issuer special case (no trustline needed, unlimited capacity).
</details>

<details>
<summary>F15: Hot Archive Restored Then Deleted Should Not Go to DEAD (FIXED 2026-01-26)</summary>

Filter `dead_entries` to exclude keys in `hot_archive_restored_keys`.
</details>

<details>
<summary>F16: Duplicate Hot Archive Restored Keys (FIXED 2026-01-26)</summary>

Changed `collected_hot_archive_keys` and `our_hot_archive_restored_keys` from Vec to HashSet.
</details>

<details>
<summary>F17: Hot Archive Using Envelope Instead of Actual Restored Indices (FIXED 2026-01-26)</summary>

Propagated `actual_restored_indices` through `SorobanOperationMeta` to `extract_hot_archive_restored_keys` in execution.rs.
</details>

<details>
<summary>F18: Hot Archive Keys Not Collected During Catch-Up Mode (FIXED 2026-01-26)</summary>

Added `our_hot_archive_restored_keys.extend()` call in catch-up mode branch of verify-execution.
</details>

<details>
<summary>F19: CreateClaimableBalance Check Order - Underfunded Before LowReserve (FIXED 2026-01-26)</summary>

Fixed available balance check to not include sponsorship, and moved sponsor reserve check to after balance deduction, matching C++ stellar-core order.
</details>

<details>
<summary>F20: ChangeTrust Sponsor Account Not Loaded for Delete Operations (FIXED 2026-01-27)</summary>

When deleting a sponsored trustline (limit=0), the sponsor account wasn't being loaded into state, causing "source account not found" errors when trying to update the sponsor's `num_sponsoring` counter. Fixed by loading the trustline's sponsor account in `load_operation_accounts()` when deleting a trustline. Discovered at testnet ledger 677219.
</details>

---

## How to Add Issues

When adding a new issue:
1. Use the appropriate category (Performance, Memory, Functional)
2. Assign a unique ID (P1, M1, F1, etc.)
3. Include: Status, Impact, Added date, Description, and relevant file paths
4. Update status when issues are resolved
5. Move resolved issues to the archive section with a brief summary
