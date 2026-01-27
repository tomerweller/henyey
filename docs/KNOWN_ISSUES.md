# Known Issues

This document tracks known issues, limitations, and technical debt in rs-stellar-core.

## Open Issues

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

---

### F19: CreateClaimableBalance Check Order (Underfunded Before LowReserve)

**Status**: FIXED  
**Impact**: Was returning Underfunded when CDP expected LowReserve  
**Added**: 2026-01-26  
**Fixed**: 2026-01-26

**Description**:
The `CreateClaimableBalance` operation was incorrectly checking sponsor reserve (LowReserve) before available balance (Underfunded). In C++ stellar-core, the available balance check happens FIRST using the CURRENT minimum balance (without the new sponsorship), and the sponsor reserve check happens AFTER the balance is deducted.

**Observed at**: Ledger 647352 (testnet)

**Symptoms**:
- Our result: `CreateClaimableBalance(Underfunded)`
- CDP result: `CreateClaimableBalance(LowReserve)`
- The sponsor had enough balance for the claimable balance amount but not enough reserve for the new sponsorship

**Root Cause**:
In C++ stellar-core's `CreateClaimableBalanceOpFrame::doApply()`:
1. First calls `getAvailableBalance(sourceAccount)` which computes `balance - minBalance(CURRENT_state)`
   - **Key**: `minBalance` does NOT include the new sponsorship being created
2. If `available < amount`, returns `UNDERFUNDED`
3. Deducts the balance via `addBalance`
4. Calls `createEntryWithPossibleSponsorship` which checks sponsor reserve → `LOW_RESERVE`

Our code was incorrectly including `sponsorship_multiplier` in the available balance check when `sponsor == source`, causing us to return `Underfunded` when the balance check should pass but the reserve check should fail.

**Solution**:
1. Changed available balance check to NOT include sponsorship (matching C++ `getAvailableBalance`):
```rust
// BEFORE (incorrect):
let min_balance = if sponsor_is_source {
    state.minimum_balance_for_account_with_deltas(
        &account, context.protocol_version, 0, sponsorship_multiplier, 0,
    )?
} else {
    state.minimum_balance_for_account(&account, context.protocol_version, 0)?
};

// AFTER (correct - matches C++ getAvailableBalance):
let min_balance =
    state.minimum_balance_for_account(&account, context.protocol_version, 0)?;
```

2. Moved sponsor reserve check (LowReserve) to AFTER balance deduction, matching C++ order.

**Files Changed**:
- `crates/stellar-core-tx/src/operations/execute/claimable_balance.rs` - Reordered checks, fixed available balance calculation

**Regression Tests**:
- `test_create_claimable_balance_low_reserve_after_underfunded_check` - Verifies LOW_RESERVE when available passes but sponsor reserve fails
- `test_create_claimable_balance_underfunded` - Verifies UNDERFUNDED when available balance is too low

**Verification**: Ledgers 647350-647355 pass with 0 header mismatches.

---

## How to Add Issues

When adding a new issue:
1. Use the appropriate category (Performance, Memory, Functional)
2. Assign a unique ID (P1, M1, F1, etc.)
3. Include: Status, Impact, Added date, Description, and relevant file paths
4. Update status when issues are resolved
5. Move resolved issues to the archive section with a brief summary
