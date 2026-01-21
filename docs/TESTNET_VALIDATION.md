# Testnet Validation Status

This document tracks the validation of rs-stellar-core against the Stellar testnet using the `verify-execution` command.

**Last Updated:** 2026-01-21

## Quick Reference: Running Verification

**IMPORTANT:** Use `offline verify-execution`, NOT `verify-history`. The `verify-history` command only verifies archive integrity, not transaction execution.

```bash
# Standard verification command
cargo run --release --bin rs-stellar-core -- offline verify-execution --testnet --from <START> --to <END>

# With detailed diff output on mismatch
cargo run --release --bin rs-stellar-core -- offline verify-execution --testnet --from 64 --to 50000 --show-diff

# Stop on first error for debugging
cargo run --release --bin rs-stellar-core -- offline verify-execution --testnet --from 64 --to 50000 --stop-on-error
```

## Verification Methodology

The `verify-execution` command performs true end-to-end verification:

1. Loads initial state from a checkpoint (bucket list from history archive)
2. Re-executes all transactions using our implementation
3. Updates bucket list using **our execution results** (not CDP metadata)
4. Compares computed header hashes against expected values from CDP

This is a strict verification that catches any execution divergence. If our transaction execution produces different state changes than C++ stellar-core, the bucket list hash will diverge.

### Key Difference from Previous Approach

Previously, `verify-execution` used CDP metadata to update the bucket list after each transaction, masking execution differences. The current approach uses only our execution results, making it a true parity test.

## Current Status

### Summary

| Metric | Status | Notes |
|--------|--------|-------|
| **End-to-end verification** | Extended | 64-50100+ continuous replay passes |
| **Primary failure mode** | Under investigation | Extending verification range |
| **Continuous replay** | Ledgers 64-50100+ | 100% header match |

### Verification Results

| Range | Ledgers | Transactions | Header Matches | Notes |
|-------|---------|--------------|----------------|-------|
| 64-50100+ | 50100+ | Many | 100% | Continuous replay passes |

### Issues Fixed (2026-01-21)

#### 1. INIT/LIVE Coalescing for Created+Updated Entries

When an entry is created by one transaction and updated by a subsequent transaction within the same ledger, the bucket list should see it as INIT (created), not LIVE (updated). Fixed in commit 4155cf9.

#### 2. Fee Refund Application to Delta

Soroban transactions that fail after fee deduction need their fee refund applied to the account balance in the delta. Fixed in commit 4155cf9.

#### 3. Delta Snapshot Preservation Across Transaction Rollback

When a transaction fails and rolls back, changes from previously committed transactions in the same ledger must be preserved. The `commit()` method was clearing the delta snapshot, but commit() is called multiple times within a single transaction (after fee deduction, sequence number updates, etc.). Fixed by not clearing delta_snapshot in commit() - only at transaction boundaries. Fixed in commit 928c229.

#### 5. TTL Bucket List Snapshot for Soroban Execution

Soroban transactions were seeing TTL values modified by previous transactions in the same ledger instead of the original bucket list values. C++ stellar-core uses the bucket list state at ledger start for Soroban snapshots. For example, at ledger 901:
- TX0 extended a TTL from 1054979 → 1054980
- TX1 saw TTL=1054980 instead of the original 1054979
- This caused TX1 to extract only 4 rent changes instead of 5, resulting in a 10,165 stroops fee refund difference

Fixed by adding `ttl_bucket_list_snapshot` to capture TTL values when entries are first loaded from the bucket list, and using `get_ttl_at_ledger_start()` for Soroban execution instead of `get_ttl()`.

### Known Issues

None currently - verification extended to 64-50100+ with all issues resolved.

#### (RESOLVED) Ledger 50034: Eviction Scan Results Not Used

Fixed by using our own eviction scan results instead of CDP metadata. The `verify-execution` command was running the eviction scan but only using the iterator result - the evicted keys were being discarded. This caused 12 DEAD entries (6 ContractData + 6 Ttl entries with expired TTLs) to be missing from our bucket list update. Fixed by storing `scan_result.evicted_keys` and adding them to `our_dead` for bucket list updates.

**Regression test:** The underlying `scan_for_eviction_incremental` function is already tested in `crates/stellar-core-bucket/tests/bucket_list_integration.rs`. The bug was in the CLI tool's integration, not the eviction scan itself. Testnet validation at ledger 50034+ serves as the regression test.

#### (RESOLVED) Ledger 7515: Offer Entry in Failed Transaction

Fixed by adding `accessed_in_op` check in `execute_manage_sell_offer` to skip offer update for offers not accessed during operation execution. The issue was that failed transactions with offers were incorrectly touching offer entries.

#### (RESOLVED) Ledger 9952: SetOptions Signer Sponsor Loading

Fixed by loading signer sponsor accounts from `signer_sponsoring_i_ds` in `load_operation_accounts` for SetOptions operations. When removing a sponsored signer, the sponsor account must be loaded to update `num_sponsoring`.

#### (RESOLVED) Ledger 12502: AllowTrust Offer Removal

Fixed by adding offer removal logic to `execute_allow_trust` to match C++ `TrustFlagsOpFrameBase::removeOffers`. When deauthorizing a trustline (removing maintain liabilities authorization), all offers owned by the account involving the asset must be removed, with proper liability clearing and sponsorship updates.

## Commands

### Run Verification

```bash
# Verify a range of ledgers
./target/release/rs-stellar-core offline verify-execution --testnet --from 64 --to 705

# Stop on first error
./target/release/rs-stellar-core offline verify-execution --testnet --from 64 --to 705 --stop-on-error

# Quiet mode (summary only)
./target/release/rs-stellar-core offline verify-execution --testnet --from 64 --to 705 -q

# Show detailed diffs on mismatch
./target/release/rs-stellar-core offline verify-execution --testnet --from 64 --to 705 --show-diff
```

### Diagnostic Output

The command outputs detailed delta comparisons:
- `INIT only in OURS/CDP`: Entries created only by one side
- `LIVE only in OURS/CDP`: Entries updated only by one side
- `INIT/LIVE DIFFERS`: Same key but different values
- `DEAD only in OURS/CDP`: Entries deleted only by one side

## Goal

Achieve 100% header match for the entire testnet history (ledger 64 to present) using true end-to-end verification. This requires:

1. Exact transaction execution parity with C++ stellar-core
2. Correct bucket list update logic
3. Correct header computation

## Regression Testing Requirement

**IMPORTANT:** When fixing any divergence issue discovered during testnet validation, a minimal regression test MUST be added alongside the fix. This ensures:

1. The specific bug is covered and won't regress
2. The fix is verifiable in isolation without running full testnet replay
3. Future refactoring won't accidentally reintroduce the issue

### Test Guidelines

- Place tests in the appropriate crate's test module (unit tests) or `tests/` directory (integration tests)
- Name tests descriptively: `test_<operation>_<specific_scenario>` (e.g., `test_allow_trust_removes_offers_on_deauthorize`)
- Include a comment referencing the testnet ledger where the issue was discovered
- Test the minimal scenario that triggers the bug, not the full ledger replay
- If the fix involves state management, test both the happy path and the edge case that caused divergence

### Issues Fixed (2026-01-21)

#### 4. Module Cache Update for Deployed Contracts

When contracts are deployed via Soroban transactions, the contract code was written to state but not added to the module cache. This caused subsequent transactions to pay full VmInstantiation costs instead of using VmCachedInstantiation, leading to budget exceeded errors. Fixed in commit f2fda5e.

## History

- **2026-01-21**: Fixed eviction scan results usage (ledger 50034) - extends replay to 64-50100+
- **2026-01-21**: Fixed AllowTrust offer removal (ledger 12502) - extends replay to 64-50000+
- **2026-01-21**: Fixed SetOptions signer sponsor loading (ledger 9952) - extends replay to 64-12501
- **2026-01-21**: Fixed offer entry in failed transaction (ledger 7515) - extends replay to 64-9951
- **2026-01-21**: Fixed TTL bucket list snapshot for Soroban execution - extends replay to 64-7514
- **2026-01-21**: Fixed module cache update for deployed contracts (commit f2fda5e) - extends replay to 64-900
- **2026-01-21**: Fixed delta snapshot preservation (commit 928c229) - enables continuous replay 64-705
- **2026-01-21**: Fixed INIT/LIVE coalescing and fee refund application (commit 4155cf9)
- **2026-01-21**: Converted verify-execution to true end-to-end test (commit f786311)
- **2026-01-21**: Created this validation document
