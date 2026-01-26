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

**Status**: Partially Fixed  
**Impact**: Memory usage reduced by ~50% during initialization  
**Added**: 2026-01-23  
**Partially Fixed**: 2026-01-23

**Description**:
When the validator falls behind the network and triggers a re-catchup, the initialization caches (module cache, offer cache, soroban state) are repopulated from a fresh bucket list scan. Previously this called `live_entries()` three times, creating three full copies of all entries in memory.

**Root Cause**:
The initialization process called `live_entries()` separately for:
1. `initialize_module_cache()` - to find CONTRACT_CODE entries
2. `initialize_offer_cache()` - to find Offer entries  
3. `initialize_soroban_state()` - to find CONTRACT_DATA, CONTRACT_CODE, and TTL entries

Each call created a full Vec of all live entries (~75K+ entries on testnet), consuming several GB of temporary memory.

**Solution Applied**:
1. Created `initialize_all_caches()` that does a single pass over `live_entries()` and processes all entry types in one iteration
2. Updated `reset_for_catchup()` to explicitly clear all caches (offer_cache, soroban_state) before re-initialization

**Results**:
- Initial memory after catchup: ~1.5 GB (down from ~3 GB)
- Peak memory during initialization reduced by ~66%

**Remaining Issue**:
Memory may still grow over time due to Rust's allocator not returning memory to the OS. This is a common behavior and may require using a different allocator (e.g., jemalloc with `background_thread` enabled) for better memory management.

**Files Changed**:
- `crates/stellar-core-ledger/src/manager.rs` - Added `initialize_all_caches()`, updated `reset_for_catchup()`

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
When running offline `verify-execution`, certain ledgers showed a bucket list hash mismatch due to missing or extra LIVE entries in our delta compared to CDP metadata. The issues involved subtle differences in when accounts should be recorded as modified.

**Root Causes (All Fixed)**:

1. **AccountMerge with 0 balance** (FIXED): When an AccountMerge transfers 0 balance, the destination account was accessed but unchanged, and we weren't recording it in the delta.

2. **CreateClaimableBalance with different op source** (FIXED): When `CreateClaimableBalance` has an operation source different from the transaction source (e.g., issuer account), C++ stellar-core calls `loadSourceAccount()` which records the access. We weren't calling `record_account_access()` for the source.

3. **AllowTrust/SetTrustLineFlags issuer account** (FIXED - removed recording): Initially we added `record_account_access()` for these operations, but this was WRONG. C++ stellar-core loads the source account in a **nested LedgerTxn** that gets rolled back, so the source account access is NOT recorded. Fixed by removing the `record_account_access()` calls.

**Observed at**: 
- Ledger 360249 (testnet) - AccountMerge with 0 balance
- Ledger 203280 (testnet) - CreateClaimableBalance with issuer as op source
- Ledger 500254 (testnet) - SetTrustLineFlags was incorrectly recording issuer

**Fix Applied**:
1. The `flush_all_accounts_except()` method now checks `op_entry_snapshots` to determine if an entry was accessed during the operation.
2. Added `record_account_access()` method to `LedgerStateManager` that explicitly marks an account as accessed even if not modified.
3. Added `record_account_access()` call in `execute_create_claimable_balance()` to match C++ `loadSourceAccount()` behavior.
4. **REMOVED** `record_account_access()` calls from `execute_allow_trust()` and `execute_set_trust_line_flags()` because C++ uses a rolled-back nested transaction for issuer loading.

**Files Changed**:
- `crates/stellar-core-tx/src/state.rs` - Added `record_account_access()` method, updated `flush_all_accounts_except()`
- `crates/stellar-core-tx/src/operations/execute/claimable_balance.rs` - Call `record_account_access()` for source
- `crates/stellar-core-tx/src/operations/execute/trust_flags.rs` - Uses `get_account()` (read-only), NOT `record_account_access()`

**Regression Tests**:
- `test_create_claimable_balance_records_source_account_access` in `crates/stellar-core-tx/src/operations/execute/claimable_balance.rs`
- `test_set_trust_line_flags_does_not_record_issuer_in_delta` in `crates/stellar-core-tx/src/operations/execute/trust_flags.rs`
- `test_allow_trust_does_not_record_issuer_in_delta` in `crates/stellar-core-tx/src/operations/execute/trust_flags.rs`

**Verification**: Ledgers 64-501000+ now pass with 0 header mismatches

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

### F4: Soroban Crypto Error - InvokeHostFunction Returns Trapped Instead of Success

**Status**: RESOLVED  
**Impact**: Was causing bucket list hash divergence starting at ledger 553997  
**Added**: 2026-01-23  
**Resolved**: 2026-01-24

**Description**:
A Soroban smart contract call that should succeed was failing with a crypto validation error in our implementation. The contract was calling `bn254_multi_pairing_check` which returned "bn254 G1: point not on curve".

**Observed at**: Ledger 553997, TX 3 (testnet)

**Error** (before fix):
```
HostError: Error(Crypto, InvalidInput)
"bn254 G1: point not on curve"
```

**Root Cause**:
We were using a pre-release version of soroban-env-host (git revision `0a0c2df`, Nov 5, 2025) which had incorrect BN254 G1/G2 point encoding/decoding:
- Field elements were using wrong byte order
- G2 extension field elements were serialized as (c0, c1) instead of (c1, c0)

This was fixed in upstream commit `cf58d535` ("Fix BN254 G1/G2 Point Encoding and Decoding #1614", Nov 25, 2025), which was included in soroban-env-host v25.0.0 (tag `d2ff024b`, Dec 4, 2025).

C++ stellar-core v25.1.0 uses the fixed v25.0.0 version, so testnet validators accept the BN254 operations that our pre-release version rejected.

**Resolution**:
Updated `Cargo.toml` to use soroban-env-host v25.0.0 (`d2ff024b72f7f3f75737402ac74ca5d0093a4690`) which includes the BN254 encoding fix. This required API compatibility changes due to XDR version differences:
- soroban-env-host v25.0.0 uses stellar-xdr 25.0.0 from crates.io
- Our workspace uses a git revision of stellar-xdr
- Added XDR serialization/deserialization conversion functions at the boundary

**Files Modified**:
- `Cargo.toml` - Updated soroban-env-host-p25 and soroban-env-common-p25 revisions
- `crates/stellar-core-tx/src/soroban/host.rs` - Added P25 XDR type aliases and conversion functions, updated `SnapshotSource` impl
- `crates/stellar-core-tx/src/soroban/protocol/p25.rs` - Added conversion functions, updated `SnapshotSource` impl
- `crates/stellar-core-tx/src/operations/execute/mod.rs` - Added `convert_ledger_entry_to_p25`
- `crates/stellar-core-ledger/src/soroban_state.rs` - Added `convert_ledger_entry_to_p25`

**Verification**: Ledgers 553996-553998 now pass verification successfully.

---

### F5: Hot Archive Restoration Emitting CREATED Instead of RESTORED

**Status**: FIXED  
**Impact**: Was causing transaction meta mismatch and bucket list hash divergence  
**Added**: 2026-01-23  
**Fixed**: 2026-01-24

**Description**:
When a Soroban transaction restores entries from the hot archive, the ContractCode/ContractData entries and their associated TTL entries should be emitted as `LEDGER_ENTRY_RESTORED` in transaction meta and recorded as `INIT` in the bucket list delta. Instead, they were being emitted as `LEDGER_ENTRY_CREATED` for the main entry and `LEDGER_ENTRY_CREATED` for TTL entries.

**Observed at**: Ledger 617809 (testnet) - TX 2 restores a ContractCode entry

**Root Cause**:
In `apply_soroban_storage_change`, the code checked `state.get_contract_code().is_some()` to decide whether to call `create` or `update`. But archived entries are pre-loaded into state from `InMemorySorobanState` (via `load_soroban_footprint`) before Soroban execution. The in-memory cache doesn't filter by TTL, so expired/archived entries appear as "existing" in state even though they're not in the live bucket list.

This caused `entry_exists = true` for the first hot archive restoration, making the code call `update` instead of `create`. The entry went to `LIVE` (updated) instead of `INIT` (created).

**Solution**:
Instead of checking if an entry exists in state, check if the entry was already **created in the delta** by a previous transaction in the same ledger. Added two helper functions:
- `key_already_created_in_delta()` - checks ContractData/ContractCode keys
- `ttl_already_created_in_delta()` - checks TTL keys

Modified `apply_soroban_storage_change` to:
1. For hot archive restores: check `key_already_created_in_delta()` instead of `state.get_*().is_some()`
2. First restoration → call `create_*` (records as INIT)
3. Subsequent access by another TX → call `update_*` (records as LIVE)

**Files Changed**:
- `crates/stellar-core-tx/src/operations/execute/invoke_host_function.rs` - Added helpers, fixed create/update logic

**Regression Test**: `test_hot_archive_restore_uses_create_not_update` updated to use `load_entry` (no delta tracking) instead of `create_contract_data` (adds to delta).

---

### F6: Rent Fee Double-Charged for Entries Already Restored by Earlier TX

**Status**: FIXED  
**Impact**: Was causing 24M stroops fee refund mismatch and bucket list hash divergence  
**Added**: 2026-01-24  
**Fixed**: 2026-01-24

**Description**:
When multiple transactions in the same ledger reference the same archived entry for restoration (via `archived_soroban_entries` in the transaction envelope), only the FIRST transaction should charge restoration rent. Subsequent transactions should treat the entry as already live.

**Observed at**: Ledger 617809 (testnet) - Two transactions both list the same ContractCode at index 4 for restoration

**Symptoms**:
- Fee refund mismatch: ours=3,621,585 vs cdp=27,636,621 (diff=-24,015,036)
- rent_fee_charged: ours=24,073,057 vs cdp=58,021
- The ContractCode was ~740KB, so charging full restoration rent twice produced a massive overcharge

**Root Cause**:
The `archived_soroban_entries` field in the transaction envelope lists indices that NEED restoration when the TX was created and simulated. But if an earlier TX in the same ledger already restored the entry, the later TX should NOT charge restoration rent for it.

Our code was blindly passing all `archived_soroban_entries` indices to the soroban-env-host's `invoke_host_function()`. The host then built a `restored_keys` set from these indices and computed rent as if EVERY entry at those indices was a new restoration.

C++ stellar-core has a `previouslyRestoredFromHotArchive()` check that skips entries already restored by earlier TXs in the same ledger.

**Solution**:
Build an `actual_restored_indices` list instead of using the envelope's `archived_soroban_entries` directly. For each index, check if the entry is ACTUALLY archived at this point:
- `live_until = None` → Entry is from hot archive (truly archived, needs restoration)
- `live_until < current_ledger` → Entry has expired TTL (live BL restore, needs restoration)
- `live_until >= current_ledger` → Entry was already restored by a previous TX (treat as live, NO restoration rent)

Pass only `actual_restored_indices` to `invoke_host_function()`.

**Files Changed**:
- `crates/stellar-core-tx/src/soroban/host.rs` - Both P24 and P25 code paths updated

**Verification**: Ledger 617809-617810 now pass with 0 header mismatches.

---

### F7: Extra RESTORED Changes for Entries Already Restored by Earlier TX

**Status**: FIXED  
**Impact**: Was causing extra RESTORED changes in TX meta and "contract code already exists" errors  
**Added**: 2026-01-24  
**Fixed**: 2026-01-24

**Description**:
When multiple transactions in the same ledger restore the same archived entry, ONLY the first transaction should emit RESTORED changes in its transaction meta. Subsequent transactions should treat the entry as already live and emit UPDATED changes instead. Our code was incorrectly emitting RESTORED for ALL transactions that listed the entry in their `archived_soroban_entries`.

**Observed at**: Ledger 252453 (testnet) - TX 21 was emitting 4 extra RESTORED changes

**Symptoms**:
- Extra RESTORED changes in transaction meta (count mismatch: ours=12, expected=8)
- Extra RESTORED ContractCode and TTL entries
- Error: "contract code already exists" when applying changes

**Root Cause**:
The `extract_hot_archive_restored_keys` function in `invoke_host_function.rs` used the raw `archived_soroban_entries` indices from the transaction envelope. But it should use the `actual_restored_indices` that are filtered during host invocation - entries already restored by earlier TXs are excluded from this filtered list.

The fix for F6 (rent fee double-charge) added `actual_restored_indices` to `SorobanExecutionResult`, but this information wasn't propagated to the `extract_hot_archive_restored_keys` call site.

**Solution**:
1. Added `actual_restored_indices` field to `SorobanExecutionResult` struct
2. Updated both P24 and P25 code paths to populate this field
3. Modified `extract_hot_archive_restored_keys` to take `actual_restored_indices` as a parameter instead of reading from `soroban_data.ext.archived_soroban_entries`
4. Updated the call site to pass `result.actual_restored_indices`

**Files Changed**:
- `crates/stellar-core-tx/src/soroban/host.rs` - Added field to struct and populated in both P24/P25 paths
- `crates/stellar-core-tx/src/operations/execute/invoke_host_function.rs` - Updated function signature and call site

**Verification**: Ledger 252453 and range 250000-253000 now pass with 0 header mismatches.

---

### F8: Fee Refund Not Applied for Failed Soroban Transactions

**Status**: FIXED  
**Impact**: Was causing fee refund mismatch and bucket list hash divergence  
**Added**: 2026-01-24  
**Fixed**: 2026-01-24

**Description**:
When a Soroban transaction fails (e.g., due to `InsufficientRefundableFee`), the full `max_refundable_fee` should be refunded to the user. Our implementation was returning a 0 refund because the `consumed_refundable_fee` had already been set to a value exceeding `max_refundable_fee` before the failure was detected.

**Observed at**: Ledger 224398 (testnet) - TX 7 failed with InsufficientRefundableFee

**Symptoms**:
- Fee refund mismatch: ours=0 vs cdp=47153 (diff=-47153)
- CDP soroban_meta: rent_fee_charged=0, refundable_fee_charged=0, non_refundable_fee_charged=125890
- Account balance diff: -47153 stroops

**Root Cause**:
In `RefundableFeeTracker::consume()`, when the second check fails (total consumed > max refundable), `consumed_refundable_fee` has already been set to the exceeded value. Then `refund_amount()` returns `max - consumed = negative → 0` instead of the full refund.

C++ stellar-core has a `resetConsumedFee()` method in `MutableTransactionResultBase` that is called by `setError()` when any error code is set. This resets all consumed fees to 0, so the refund becomes `max_refundable_fee - 0 = max_refundable_fee`.

**Solution**:
1. Added `reset()` method to `RefundableFeeTracker` that mirrors C++ `resetConsumedFee()`:
   - Resets `consumed_event_size_bytes` to 0
   - Resets `consumed_rent_fee` to 0
   - Resets `consumed_refundable_fee` to 0
2. Call `tracker.reset()` in the `!all_success` branch when a transaction fails, before computing the refund

**Files Changed**:
- `crates/stellar-core-ledger/src/execution.rs` - Added `reset()` method and call it on transaction failure

**Verification**: Ledger 224398 and range 224395-224400 now pass with 0 header mismatches.

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

### F9: RestoreFootprint Hot Archive Keys Not Returned for soroban_state Tracking

**Status**: FIXED  
**Impact**: Was causing "pending TTLs not empty after update" error and verification failure  
**Added**: 2026-01-24  
**Fixed**: 2026-01-24

**Description**:
When `RestoreFootprint` restored entries from the hot archive, the data/code keys were not being returned in `hot_archive_restored_keys`. This caused the in-memory `soroban_state` tracking (in `main.rs` verify-execution) to fail with "pending TTLs not empty after update: 1 remaining".

The issue was that TTL entries were created for hot archive restores, but the corresponding ContractData entries weren't being added to `our_init`, so soroban_state couldn't pair them.

**Observed at**: Ledger 327974 (testnet) - TX 3 RestoreFootprint from hot archive

**Symptoms**:
- Error: "pending TTLs not empty after update: 1 remaining"
- Pending TTL key_hash didn't match any contract data being created
- Verification would fail even though transaction metadata matched

**Root Cause**:
In `execution.rs`, when collecting `collected_hot_archive_keys`, the code filtered by `created_keys`:

```rust
collected_hot_archive_keys.extend(
    hot_archive_for_bucket_list
        .iter()
        .filter(|k| created_keys.contains(k))
        .cloned(),
);
```

For RestoreFootprint operations, data/code entries are **prefetched** from the hot archive into state (not created by the transaction's delta). Only TTL entries are created by the delta. So the filter removed all the data/code keys, leaving `hot_archive_restored_keys` empty.

This meant the restored data entries weren't added to `our_init` in main.rs, so soroban_state couldn't pair the TTL entries with their corresponding data entries.

**Solution**:
Modified the hot archive key collection to NOT filter by `created_keys` for RestoreFootprint operations:

```rust
if op_type == OperationType::RestoreFootprint {
    // For RestoreFootprint, include all hot archive entries
    collected_hot_archive_keys.extend(hot_archive_for_bucket_list.iter().cloned());
} else {
    // For InvokeHostFunction, filter by created_keys
    collected_hot_archive_keys.extend(
        hot_archive_for_bucket_list
            .iter()
            .filter(|k| created_keys.contains(k))
            .cloned(),
    );
}
```

**Files Changed**:
- `crates/stellar-core-ledger/src/execution.rs` - Conditional filtering for RestoreFootprint

**Regression Test**: `test_restore_footprint_hot_archive_ttl_pairing` in `crates/stellar-core-ledger/src/soroban_state.rs`

**Verification**: Ledger 327974 and range 327900-328100 (201 ledgers, 911 transactions) now pass with 0 header mismatches.

---

### F10: Duplicate Entry Error When Restoring Hot Archive Entries

**Status**: FIXED  
**Impact**: Was causing "contract code already exists" or "contract data already exists" errors  
**Added**: 2026-01-24  
**Fixed**: 2026-01-24

**Description**:
When `InvokeHostFunction` restores entries from the hot archive, ContractCode or ContractData may already exist in `soroban_state` (e.g., shared WASM code used by multiple contracts, or entries restored from checkpoint). The code was attempting to create these entries again, which failed with "already exists" error.

**Observed at**: Ledger 306338 (testnet)

**Symptoms**:
- Error: "contract code already exists" or "contract data already exists"
- Occurred when InvokeHostFunction restored a ContractCode with the same hash as an existing one
- The same WASM code can be used by multiple contracts (same hash)

**Root Cause**:
In `main.rs` verify-execution, when building `our_init` from the delta's `created` entries, we call `soroban_state.create_contract_code()` or `create_contract_data()`. These fail if the entry already exists. But for hot archive restores:
1. The same ContractCode might be used by multiple contracts (same WASM hash)
2. ContractData might have been initialized from a checkpoint
3. An earlier TX in the same ledger might have already restored the entry

**Solution**:
When building `our_init` from delta's `created` entries, check if each ContractCode/ContractData already exists in `soroban_state`:
- If exists: move to `moved_to_live` vector (will be updated, not created)
- If not exists: add to `our_init` (will be created)

Also skip entries already in `our_init` when processing `our_hot_archive_restored_keys` to avoid duplicates.

**Files Changed**:
- `crates/rs-stellar-core/src/main.rs` - Duplicate detection and handling

**Regression Tests**:
- `test_create_duplicate_contract_code_fails` - Verifies error on duplicate code
- `test_create_duplicate_contract_data_fails` - Verifies error on duplicate data  
- `test_process_entry_update_creates_if_not_exists` - Verifies update creates if missing

**Verification**: Ledgers 306337-306340 and range 300000-312750 (12,751 ledgers) pass with 0 header mismatches.

---

### F11: Persistent Module Cache Not Updated for Newly Deployed Contracts

**Status**: FIXED  
**Impact**: Was causing Soroban budget exceeded errors for contracts deployed after checkpoint  
**Added**: 2026-01-25  
**Fixed**: 2026-01-25

**Description**:
In the offline `verify-execution` command, the persistent module cache was populated once from the initial checkpoint's bucket list and never updated. Contracts deployed after the checkpoint were missing from the cache, causing `VmInstantiation` (expensive) instead of `VmCachedInstantiation` (cheap), leading to budget exceeded errors.

**Observed at**: Ledger 328879 (testnet) - TX 5 InvokeHostFunction failed with ResourceLimitExceeded

**Symptoms**:
- `ResourceLimitExceeded` (Budget ExceededLimit)
- CPU consumed: 4,928,529 vs limit: 4,910,269 (over by ~0.4%)
- Transaction succeeded in CDP but failed in our execution

**Root Cause**:
The module cache was built from contract code entries at the initial checkpoint (e.g., 328831) and never updated. Any contracts deployed between the checkpoint and a later ledger (e.g., 328879) would not be in the cache. Without a cached module, the soroban-env-host charges full `VmInstantiation` cost instead of `VmCachedInstantiation`, causing budget overflow.

C++ stellar-core's `LedgerManagerImpl::addAnyContractsToModuleCache()` is called during the commit phase of each ledger to add newly deployed contracts to the cache.

**Solution**:
After `soroban_state.update_state()` for each ledger in verify-execution, iterate over `all_init` and `all_live` entries and call `module_cache.add_contract()` for any `ContractCode` entries. This matches upstream behavior.

**Files Changed**:
- `crates/rs-stellar-core/src/main.rs` - Added module cache update after soroban_state update

**Verification**: Ledger 328879 and range 300000-365311 pass with 0 header mismatches.

---

### F12: SetOptions Missing Inflation Destination Validation

**Status**: FIXED  
**Impact**: Was causing SetOptions to succeed when it should return InvalidInflation  
**Added**: 2026-01-25  
**Fixed**: 2026-01-25

**Description**:
The `SetOptions` operation was not validating that the inflation destination account exists on the ledger (unless it's the source account itself). This allowed setting an inflation destination to a non-existent account, which C++ stellar-core rejects with `SET_OPTIONS_INVALID_INFLATION`.

**Observed at**: Ledger 329805 (testnet) - TX 4 SetOptions

**Symptoms**:
- Our result: `SetOptions(Success)`
- CDP result: `TxFailed([SetOptions(InvalidInflation)])`
- State divergence and cascading header mismatches

**Root Cause**:
In C++ stellar-core's `SetOptionsOpFrame::doApply()` (line 133-144 of `.upstream-v25/src/transactions/SetOptionsOpFrame.cpp`):
```cpp
if (mSetOptions.inflationDest)
{
    AccountID inflationID = *mSetOptions.inflationDest;
    if (!(inflationID == getSourceID()))
    {
        if (!stellar::loadAccountWithoutRecord(ltx, inflationID))
        {
            innerResult(res).code(SET_OPTIONS_INVALID_INFLATION);
            return false;
        }
    }
    account.inflationDest.activate() = inflationID;
}
```

Our Rust implementation was missing this validation - it unconditionally set the inflation destination without checking existence.

**Solution**:
Added validation before setting inflation destination:
```rust
if let Some(ref inflation_dest) = op.inflation_dest {
    if inflation_dest != source {
        if state.get_account(inflation_dest).is_none() {
            return Ok(make_result(SetOptionsResultCode::InvalidInflation));
        }
    }
}
```

**Files Changed**:
- `crates/stellar-core-tx/src/operations/execute/set_options.rs` - Added inflation destination validation and 3 regression tests

**Regression Tests**:
- `test_set_options_inflation_dest_nonexistent_account`
- `test_set_options_inflation_dest_self`
- `test_set_options_inflation_dest_existing_account`

**Verification**: Ledger 329805 and range 329804-329810 pass with 0 header mismatches.

---

### F13: Bucket List Hash Divergence at Large Merge Points

**Status**: FIXED  
**Impact**: Was causing bucket list hash divergence at major merge points after extended replay  
**Added**: 2026-01-25  
**Fixed**: 2026-01-26

**Description**:
When running verify-execution over extended ranges (e.g., 300000-400000), all transaction executions matched but the bucket list hash diverged at major merge points (where multiple levels spill simultaneously).

**Observed at**: Ledger 365312 (testnet) - levels 0-7 all spill

**Symptoms**:
- All transaction executions match (0 TX mismatches)
- All individual ledger header hashes match until the merge point
- At 365312 (level 0-7 merge), bucket list hash diverges
- Starting from a closer checkpoint (365248) passes verification

**Root Cause**:
Incorrect protocol version handling in bucket merges. C++ stellar-core has TWO different merge behaviors:

1. **In-memory merge (level 0)**: Uses `maxProtocolVersion` (current ledger's protocol version) directly for output metadata
2. **Disk-based merge (levels 1+)**: Uses `max(old_bucket_version, new_bucket_version)` via `calculateMergeProtocolVersion()`

Our Rust code was incorrectly using `max_protocol_version` as the output version for ALL merges, when it should only be used for in-memory (level 0) merges. This caused metadata protocol version mismatches that accumulated over many merges, eventually causing bucket hash divergence.

**Solution**:
1. `build_output_metadata()` now uses `max(old, new)` as output version, with `max_protocol_version` only as a constraint
2. `merge_in_memory()` creates metadata directly with `max_protocol_version`, matching C++ `LiveBucket::mergeInMemory()`
3. `merge_hot_archive_buckets()` uses `max(curr, snap)` as output version

**Files Changed**:
- `crates/stellar-core-bucket/src/merge.rs` - Fixed `build_output_metadata()` and `merge_in_memory()`
- `crates/stellar-core-bucket/src/hot_archive.rs` - Fixed `merge_hot_archive_buckets()`
- `crates/stellar-core-bucket/src/bucket_list.rs` - Updated `restart_merges_from_has()`

**Regression Tests** (11 new tests):
- `test_build_output_metadata_uses_max_of_inputs`
- `test_build_output_metadata_validates_constraint`
- `test_build_output_metadata_with_only_old_meta`
- `test_build_output_metadata_with_only_new_meta`
- `test_build_output_metadata_no_metadata_inputs`
- `test_merge_in_memory_uses_max_protocol_version_directly`
- `test_disk_merge_uses_max_of_inputs`
- `test_protocol_version_difference_in_memory_vs_disk`
- `test_hot_archive_merge_uses_max_of_inputs`
- `test_hot_archive_merge_validates_constraint`
- `test_hot_archive_merge_same_version_uses_that_version`

**Verification**: Ledgers 365183-365314 now pass with 0 header mismatches.

---

### F15: Hot Archive Restored Entries Then Deleted Should Not Go to Live Bucket List DEAD

**Status**: FIXED  
**Impact**: Was causing bucket list hash mismatches at ledgers with hot archive restore+delete  
**Added**: 2026-01-26  
**Fixed**: 2026-01-26

**Description**:
When entries are restored from hot archive during `InvokeHostFunction` execution and then deleted by the contract in the same transaction, they were incorrectly being added to the live bucket list's DEAD entries. This caused bucket list hash mismatches because:
1. The entries came from hot archive, not live bucket list
2. Deleting a restored-from-hot-archive entry should just remove it from hot archive, not add it to live DEAD

**Observed at**: Ledgers 603325 and 610541 (testnet)

**Symptoms**:
- Header mismatch with `DEAD only in OURS: ContractData(...HasRole...burner...)`
- `hot_archive_restored_keys: cdp_restored_count=3, our_restored_count=1`
- All 3 entries from `archived_soroban_entries` should be passed to hot archive bucket list

**Root Cause (Two Parts)**:

1. **Bucket list key filtering**: In `execution.rs`, for `InvokeHostFunction` we filtered `collected_hot_archive_keys` by `created_keys`. Entries that were auto-restored and then **modified** (going to `updated`, not `created`) by the contract were excluded. All entries in `archived_soroban_entries` should be passed to `HotArchiveBucketList::add_batch`.

2. **Dead entries not filtered**: In `manager.rs` and `main.rs`, entries restored from hot archive that were subsequently deleted were going into `dead_entries` for the live bucket list. They should NOT - they came from hot archive, not live bucket list.

**Solution**:

1. In `execution.rs`: Pass ALL hot archive keys (after live BL filtering) to `collected_hot_archive_keys`:
```rust
// Before (buggy):
collected_hot_archive_keys.extend(
    hot_archive_for_bucket_list
        .iter()
        .filter(|k| created_keys.contains(k))  // WRONG: filters out modified entries
        .cloned(),
);

// After (fixed):
collected_hot_archive_keys.extend(hot_archive_for_bucket_list.iter().cloned());
```

2. In `manager.rs`: Filter `dead_entries` to exclude keys in `hot_archive_restored_keys`:
```rust
if !self.hot_archive_restored_keys.is_empty() {
    let restored_set: std::collections::HashSet<_> =
        self.hot_archive_restored_keys.iter().collect();
    dead_entries.retain(|key| !restored_set.contains(key));
}
```

3. In `main.rs` (offline verify): Same filtering for `our_dead` by `our_hot_archive_restored_keys`

**Files Changed**:
- `crates/stellar-core-ledger/src/execution.rs` - Removed `created_keys` filtering
- `crates/stellar-core-ledger/src/manager.rs` - Added dead_entries filtering
- `crates/rs-stellar-core/src/main.rs` - Added our_dead filtering

**Verification**: Ledgers 603000-604000 (1001 ledgers) and 610000-611000 (1001 ledgers) now pass with 0 header mismatches.

---

### F14: LiquidityPoolDeposit/Withdraw Fails for Asset Issuers

**Status**: FIXED  
**Impact**: Was causing LiquidityPoolDeposit to return NoTrust when issuer deposits their own asset  
**Added**: 2026-01-26  
**Fixed**: 2026-01-26

**Description**:
When an asset issuer attempts to deposit into or withdraw from a liquidity pool containing their own asset, the operation was incorrectly returning `NoTrust` because the code required a trustline for the asset. In Stellar, issuers don't need trustlines for their own assets - they can create/destroy assets from nothing with unlimited capacity.

**Observed at**: Ledger 419086 (testnet) - TX 3 LiquidityPoolDeposit

**Symptoms**:
- Our result: `LiquidityPoolDeposit(NoTrust)` - TX failed
- CDP result: `LiquidityPoolDeposit(Success)` - TX succeeded
- Account balance diff: 5,000,000,000 stroops (5000 XLM)
- Missing from our delta: LiquidityPool entry + PoolShare trustline

**Root Cause**:
The `execute_liquidity_pool_deposit()` and related functions checked for trustlines without considering the issuer special case. In C++ stellar-core, the `TrustLineWrapper` class handles this via separate `IssuerImpl` and `NonIssuerImpl` implementations:

1. For non-issuers: Load and verify trustline exists and is authorized
2. For issuers: Use `IssuerImpl` which:
   - Returns `true` for `operator bool()` (always valid)
   - Returns `true` for `addBalance()` (no-op, assets created/destroyed from nothing)
   - Returns `i64::MAX` for available balance (unlimited capacity)

Our Rust code was unconditionally requiring trustlines.

**Solution**:
Added `is_issuer()` helper function and updated multiple code paths:

1. **Trustline checks**: Skip for issuers (`trustline_a`/`trustline_b` set to `None`)
2. **Available balance**: Return `i64::MAX` for issuers (unlimited capacity)
3. **Deduct balance**: No-op for issuers (they "create" assets from nothing)
4. **can_credit_asset()**: Return `Ok` for issuers (can always receive their own assets)
5. **credit_asset()**: No-op for issuers (received assets are "destroyed")
6. **Unrelated bug fix**: `make_deposit_result` → `make_withdraw_result` in withdraw's "pool not found" error

**Files Changed**:
- `crates/stellar-core-tx/src/operations/execute/liquidity_pool.rs` - Added `is_issuer()` helper and updated all affected functions

**Regression Tests**:
- `test_liquidity_pool_deposit_issuer_no_trustline` - Issuer can deposit their own asset without trustline
- `test_liquidity_pool_withdraw_issuer_no_trustline` - Issuer can withdraw and receive their own asset

**Verification**: Ledgers 419000-420000 (1001 ledgers, 3762 transactions) pass with 0 header mismatches.

---

### F16: Duplicate Hot Archive Restored Keys Causing Multiple Live Entries

**Status**: FIXED  
**Impact**: Was causing duplicate LIVE entries in bucket list for shared ContractCode  
**Added**: 2026-01-26  
**Fixed**: 2026-01-26

**Description**:
When multiple transactions in the same ledger restore the same entry from hot archive (e.g., shared ContractCode used by multiple contracts), the entry was being added to `collected_hot_archive_keys` and `our_live` multiple times. This caused duplicate LIVE entries to be sent to the bucket list.

**Observed at**: Ledger 635730 (testnet) - 15 transactions restoring the same ContractCode

**Symptoms**:
- LIVE entries contained the same ContractCode 15+ times
- `our_restored_count=15` when it should be 2 (deduplicated)
- Bucket list hash mismatch due to duplicate entries

**Root Cause (Three Parts)**:

1. **collected_hot_archive_keys as Vec**: In `execution.rs`, `collected_hot_archive_keys` was a `Vec<LedgerKey>`. When multiple transactions in the same ledger restored the same key, it was added multiple times.

2. **our_hot_archive_restored_keys as Vec**: In `main.rs`, `our_hot_archive_restored_keys` was a `Vec<LedgerKey>`. When aggregating across transactions, duplicates accumulated.

3. **our_live not deduplicated**: When building `our_live` from `live_by_key`, `hot_archive_live_entries`, and `moved_to_live`, entries from the latter two could duplicate entries already in `live_by_key`.

**Solution**:

1. In `execution.rs`: Changed `collected_hot_archive_keys` from `Vec` to `HashSet`:
```rust
let mut collected_hot_archive_keys: HashSet<LedgerKey> = HashSet::new();
```

2. In `main.rs`: Changed `our_hot_archive_restored_keys` from `Vec` to `HashSet`:
```rust
let mut our_hot_archive_restored_keys: std::collections::HashSet<LedgerKey> = std::collections::HashSet::new();
```

3. In `main.rs`: Deduplicate when adding to `our_live` using HashMap entry API:
```rust
for entry in hot_archive_live_entries {
    if let Some(key) = ledger_entry_to_key(&entry) {
        live_by_key.entry(key).or_insert(entry);
    }
}
for entry in moved_to_live {
    if let Some(key) = ledger_entry_to_key(&entry) {
        live_by_key.entry(key).or_insert(entry);
    }
}
```

**Files Changed**:
- `crates/stellar-core-ledger/src/execution.rs` - Changed `collected_hot_archive_keys` to HashSet
- `crates/rs-stellar-core/src/main.rs` - Changed `our_hot_archive_restored_keys` to HashSet, deduplicated `our_live` entries

**Verification**: Ledgers 603325 and 610541 (previously fixed) still pass. This fix prevents duplicate entries in future similar scenarios.

**Note**: This fix was combined with F17 to fully resolve ledger 635730.

---

### F17: Hot Archive Restoration Using Envelope Instead of Actual Restored Indices

**Status**: FIXED  
**Impact**: Was causing incorrect hot archive restored_count and bucket list hash mismatch  
**Added**: 2026-01-26  
**Fixed**: 2026-01-26

**Description**:
The `extract_hot_archive_restored_keys` function in `execution.rs` was using raw `archived_soroban_entries` from the transaction envelope to determine which entries should be removed from the hot archive. However, entries listed in `archived_soroban_entries` may have already been restored by a **previous transaction in the same ledger**. The envelope's indices are set at transaction submission time, not execution time.

**Observed at**: Ledger 635730 (testnet) - ContractCode and ContractData listed as hot archive restores but already live

**Symptoms**:
- `cdp_restored_count=0` but `our_restored_count=2`
- Entries had valid `live_until >= current_ledger` (already restored by ledger 635729)
- Bucket list hash mismatch due to incorrect hot archive deletion

**Root Cause**:
The `extract_hot_archive_restored_keys` function in `execution.rs` extracted hot archive keys from `archived_soroban_entries` in the transaction envelope. But the soroban-env-host already filters these indices during execution to build `actual_restored_indices`, which excludes entries that were already restored by a prior transaction.

The fix for F7 added `actual_restored_indices` to `SorobanExecutionResult` in `host.rs`, and F7 updated `extract_hot_archive_restored_keys` in `invoke_host_function.rs`. However, there was a SECOND copy of `extract_hot_archive_restored_keys` in `execution.rs` that was NOT updated to use this field.

**Solution**:

1. Added `actual_restored_indices` field to `SorobanOperationMeta` struct to propagate the filtered indices:
```rust
pub struct SorobanOperationMeta {
    // ... existing fields ...
    pub actual_restored_indices: Vec<u32>,
}
```

2. Updated `build_soroban_operation_meta` in `invoke_host_function.rs` to pass the field:
```rust
SorobanOperationMeta {
    // ... existing fields ...
    actual_restored_indices: result.actual_restored_indices.clone(),
}
```

3. Modified `extract_hot_archive_restored_keys` in `execution.rs` to take `actual_restored_indices` as a parameter instead of extracting from envelope:
```rust
fn extract_hot_archive_restored_keys(
    soroban_data: Option<&SorobanTransactionData>,
    op_type: OperationType,
    actual_restored_indices: &[u32],  // NEW parameter
) -> HashSet<LedgerKey>
```

4. Updated the call site to pass `actual_restored_indices` from `op_exec.soroban_meta`:
```rust
let actual_restored_indices = op_exec
    .soroban_meta
    .as_ref()
    .map(|m| m.actual_restored_indices.as_slice())
    .unwrap_or(&[]);
let mut hot_archive =
    extract_hot_archive_restored_keys(soroban_data, op_type, actual_restored_indices);
```

**Files Changed**:
- `crates/stellar-core-tx/src/operations/execute/mod.rs` - Added field to `SorobanOperationMeta`
- `crates/stellar-core-tx/src/operations/execute/invoke_host_function.rs` - Propagated field in all struct constructions
- `crates/stellar-core-ledger/src/execution.rs` - Updated function signature and call site

**Verification**: Ledgers 635729-635740 (12 ledgers) pass with 0 header mismatches. Combined with F16, ledger 635730 is now fully resolved.

---

### F18: Hot Archive Restored Keys Not Collected During Catch-Up Mode

**Status**: FIXED  
**Impact**: Was causing hot archive hash divergence when starting verification from a ledger after checkpoint  
**Added**: 2026-01-26  
**Fixed**: 2026-01-26

**Description**:
When running `verify-execution` with a `--from` ledger that is after the checkpoint ledger, the code processes "catch-up" ledgers (between checkpoint and start_ledger) to build up state. During this catch-up phase, hot archive restored keys were NOT being collected from transaction execution results, even though they still need to be passed to `HotArchiveBucketList::add_batch()` to remove restored entries from the hot archive.

**Observed at**: Ledger 635740 (testnet) - starting directly at 635740 produced different hot archive hash than starting from 635729

**Symptoms**:
- Starting from ledger 635729 to 635745: ALL ledgers pass (17 ledgers, 0 header mismatches)
- Starting from ledger 635740 to 635741: Ledger 635740 FAILS with header mismatch
- Different initial hot archive hash when starting from different ledgers within the same checkpoint range

**Root Cause**:
In `main.rs`, the `our_hot_archive_restored_keys` HashSet was only being populated inside the `if in_test_range` block (line 3357). For ledgers in catch-up mode (`!in_test_range`), the hot archive restored keys were not being collected from `result.hot_archive_restored_keys`, even though they were still passed to `hot_archive.add_batch()` to update the hot archive bucket list.

This meant that entries restored during catch-up ledgers remained in the hot archive, causing the hash to diverge when compared against expected values.

**Solution**:
Added collection of hot archive restored keys in the catch-up mode branch:

```rust
} else {
    // Not in test range (catch-up mode) - still need to collect hot archive
    // restored keys and apply refunds to ensure bucket list has correct state.
    if let Ok(result) = exec_result {
        // Collect hot archive restored keys during catch-up.
        our_hot_archive_restored_keys.extend(result.hot_archive_restored_keys.iter().cloned());
        
        if result.fee_refund > 0 {
            // ... refund handling ...
        }
    }
}
```

**Files Changed**:
- `crates/rs-stellar-core/src/main.rs` - Added `our_hot_archive_restored_keys.extend()` call in catch-up mode branch

**Regression Test**: This is a CLI-level integration issue affecting the offline `verify-execution` command's catch-up mode. The fix is verified by running:
- `./target/release/rs-stellar-core offline verify-execution --testnet --from 635740 --to 635741` - should pass with 0 header mismatches
- Starting from any ledger within a checkpoint range should produce identical results

**Verification**: Ledgers 635740-635741 now pass with 0 header mismatches when starting directly, matching the results when replaying from an earlier ledger (635729).

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
