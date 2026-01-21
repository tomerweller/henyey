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
| **End-to-end verification** | ❌ Failing | Transaction execution differences |
| **Primary failure mode** | BadSequence | Sequence number mismatches |
| **Root cause** | Under investigation | State divergence from checkpoint |

### Observed Issues

#### 1. Transaction Execution Divergence

Starting from the very first ledger after any checkpoint, some transactions fail in our execution that CDP shows as successful:

```
# Ledger 499968 (first after checkpoint 499967):
TX 0: MISMATCH - our: failed vs CDP: TxSuccess([Payment(Success)])
  - Result diff: Operation count mismatch: ours=0, CDP=1
```

The transaction fails before executing operations (possibly precondition check), while CDP shows successful execution.

#### 2. Cascade Effect

When our execution fails a transaction that should succeed:
- State changes from that transaction are not applied (rollback)
- Subsequent transactions may fail due to missing state
- Account sequence numbers diverge
- Bucket list hash diverges

This explains the "Bad sequence" errors seen later - they're a symptom of earlier transactions failing when they should have succeeded.

#### 3. Root Cause Under Investigation

The exact reason our execution fails these transactions is still being investigated. Potential causes:
- Precondition checks being too strict
- Source account lookup issues
- State reading from bucket list vs executor cache

### Verification Results by Range

| Range | Ledgers | Header Matches | TX Matches | Notes |
|-------|---------|----------------|------------|-------|
| 64-100 | 37 | 37 (100%) | 0/0 | No transactions in range |
| 64-1000 | 937 | 98 (10%) | 640/900 (71%) | First divergence at ledger 162 |
| 499968-499970 | 3 | 0 (0%) | - | Divergence starts at first ledger after checkpoint |
| 500000-500100 | 101 | 0 (0%) | 200/457 (44%) | BadSequence errors (cascade from earlier failures) |

## Investigation Plan

### Hypothesis 1: Checkpoint State Mismatch

The bucket list state loaded from history archive may not exactly match the state that C++ stellar-core had when executing these transactions.

**Tests needed:**
- [ ] Compare specific account entries between our bucket list and Horizon API
- [ ] Verify sequence numbers at checkpoint boundaries

### Hypothesis 2: Fee Charging Differences

Our Phase 1 fee charging may produce different state changes than C++ stellar-core.

**Tests needed:**
- [ ] Compare fee_meta from our execution vs CDP
- [ ] Check if fee source balances match after fee deduction

### Hypothesis 3: Transaction Ordering

Transactions may need to be executed in a specific order with CDP sync between them.

**Tests needed:**
- [ ] Verify transaction order matches CDP
- [ ] Check if intra-ledger state consistency is the issue

## Commands

### Run Verification

```bash
# Verify a range of ledgers
./target/debug/rs-stellar-core offline verify-execution --from 64 --to 1000

# Stop on first error
./target/debug/rs-stellar-core offline verify-execution --from 64 --to 1000 --stop-on-error

# Quiet mode (summary only)
./target/debug/rs-stellar-core offline verify-execution --from 64 --to 1000 -q
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

## History

- **2026-01-21**: Converted verify-execution to true end-to-end test (commit f786311)
- **2026-01-21**: Created this validation document
