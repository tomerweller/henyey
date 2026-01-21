# Testnet Validation Status

This document tracks the validation of rs-stellar-core against the Stellar testnet using the `verify-execution` command.

**Last Updated:** 2026-01-21

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
| **End-to-end verification** | Partial | 837 ledgers verified (64-900) |
| **Primary failure mode** | Rent fee calculation | Ledger 901+ diverges |
| **Continuous replay** | Ledgers 64-900 | 100% header match |

### Verification Results

| Range | Ledgers | Transactions | Header Matches | Notes |
|-------|---------|--------------|----------------|-------|
| 64-900 | 837 | 588 | 837 (100%) | Continuous replay passes |

### Issues Fixed (2026-01-21)

#### 1. INIT/LIVE Coalescing for Created+Updated Entries

When an entry is created by one transaction and updated by a subsequent transaction within the same ledger, the bucket list should see it as INIT (created), not LIVE (updated). Fixed in commit 4155cf9.

#### 2. Fee Refund Application to Delta

Soroban transactions that fail after fee deduction need their fee refund applied to the account balance in the delta. Fixed in commit 4155cf9.

#### 3. Delta Snapshot Preservation Across Transaction Rollback

When a transaction fails and rolls back, changes from previously committed transactions in the same ledger must be preserved. The `commit()` method was clearing the delta snapshot, but commit() is called multiple times within a single transaction (after fee deduction, sequence number updates, etc.). Fixed by not clearing delta_snapshot in commit() - only at transaction boundaries. Fixed in commit 928c229.

### Known Issues

#### Ledger 901: Rent Fee Calculation Divergence

Starting at ledger 901, there's a rent fee calculation divergence. Our implementation computes a different fee refund than C++ stellar-core.

**Example at ledger 901:**
- Our refund: 53,783 stroops
- CDP refund: 43,618 stroops
- Difference: 10,165 stroops

This causes the account balance to differ, which propagates to bucket list hash mismatch.

**Status:** Under investigation

**Analysis needed:**
- Compare rent fee calculation for extended/restored entries
- Verify LedgerEntryRentChange construction matches C++ stellar-core
- Check if P24 vs P25 rent calculation differs

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

### Issues Fixed (2026-01-21)

#### 4. Module Cache Update for Deployed Contracts

When contracts are deployed via Soroban transactions, the contract code was written to state but not added to the module cache. This caused subsequent transactions to pay full VmInstantiation costs instead of using VmCachedInstantiation, leading to budget exceeded errors. Fixed in commit f2fda5e.

## History

- **2026-01-21**: Fixed module cache update for deployed contracts (commit f2fda5e) - extends replay to 64-900
- **2026-01-21**: Fixed delta snapshot preservation (commit 928c229) - enables continuous replay 64-705
- **2026-01-21**: Fixed INIT/LIVE coalescing and fee refund application (commit 4155cf9)
- **2026-01-21**: Converted verify-execution to true end-to-end test (commit f786311)
- **2026-01-21**: Created this validation document
