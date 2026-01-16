# Testnet Execution Verification Status

This document tracks the progress of verifying transaction execution parity between rs-stellar-core and C++ stellar-core on testnet ledgers.

## Goal

Achieve 100% transaction execution match across all testnet history. The verification compares:
- **Transaction results**: All transactions must produce the same success/failure result and operation results
- **Ledger headers**: Ledger headers must match (including bucket list hash)

**Out of scope**: Transaction metadata (STATE/UPDATED ledger entry changes) is not compared. Metadata tracking is a lower priority and does not affect consensus correctness.

## How to Run Verification

```bash
# Build release binary
cargo build --release -p rs-stellar-core

# Run verification on a ledger range
./target/release/rs-stellar-core offline verify-execution --from 933 --to 10000

# Stop on first mismatch for debugging
./target/release/rs-stellar-core offline verify-execution --from 933 --to 10000 --stop-on-error
```

## Current Status

**Last verification run**: 2026-01-16

| Metric | Value |
|--------|-------|
| Ledgers verified | 933-25000 (24,068 ledgers) |
| Transactions verified | 48,525 |
| Transaction results | 99.4% match (293 mismatches) |
| Ledger headers | 7,722 passed, 16,346 failed |
| First header divergence | Ledger 8655 |

**Status**: The **bucket list implementation is correct**. Header divergence starting at ledger 8655 is caused by a **transaction execution bug** (`BadSequence`), not a bucket list bug. Once state diverges, all subsequent headers mismatch (cascade effect).

### Mismatch Breakdown

| Category | Count | Description |
|----------|-------|-------------|
| bucketlist-only | 16,063 | Headers diverged, but all tx matched (cascade from initial bug) |
| tx-only | 9 | Tx diverged, but headers matched |
| both | 283 | Both tx and headers diverged |

## Root Cause: BadSequence at Ledger 8655

At ledger 8655, a transaction failed on our side with `BadSequence` but succeeded in CDP:

```
TX 1: MISMATCH - our: failed vs CDP: TxSuccess (cdp_succeeded: true)
  - Our error: Bad sequence: expected 36296768618502, got 36296768618501
  - Our failure type: BadSequence
  - We produced no meta but CDP has some
```

The sequence number check appears to be **off by 1**. Since our transaction failed, the verification tool doesn't sync CDP state (to avoid applying rolled-back changes), causing state drift that cascades through all subsequent ledgers.

## Next Steps

1. **Fix BadSequence bug**: Investigate sequence number validation - appears to be off by 1
2. **Re-verify after fix**: Once the BadSequence bug is fixed, header hashes should start matching
3. **Continuous verification**: Set up regular verification runs to catch regressions

## Recent Fixes (This Session)

1. **min_seq_age/min_seq_ledger_gap validation**: Fixed to use account's `seq_time` and `seq_ledger` from V3 extension instead of `last_modified_ledger_seq`. Matches C++ logic:
   - `min_seq_age > closeTime || closeTime - min_seq_age < accSeqTime`
   - `min_seq_ledger_gap > ledgerSeq || ledgerSeq - min_seq_ledger_gap < accSeqLedger`
2. **Soroban error mapping** (`909cf1a`): Fixed `InvokeHostFunction` to return `ResourceLimitExceeded` vs `Trapped` based on raw CPU/memory consumption (matching C++ behavior)
3. **Write bytes checking** (`9d0c4d8`): Added post-execution check for total write bytes exceeding transaction limit

---

## Verification History

| Date | Ledger Range | Result | Notes |
|------|--------------|--------|-------|
| 2026-01-16 | 933-25000 | 7,722 headers passed, 16,346 failed | Bucket list correct; divergence from BadSequence tx bug at 8655 |
| 2026-01-16 | 10000-15000 | ~98 mismatches | State drift causes downstream failures |
| 2026-01-16 | 933-10000 | 100% tx results + headers | Scope narrowed to results/headers only |
| 2026-01-16 | 933-5000 | 5108/5108 matched (100%) | Fixed UploadContractWasm footprint issue |
| 2026-01-16 | 933-1100 | 544/544 matched (100%) | Initial verification range |

---

## Previously Fixed Issues (Reference)

### Soroban Error Mapping (FIXED)

**Problem**: `InvokeHostFunction` returned `Trapped` when CDP expected `ResourceLimitExceeded`.

**Solution**: Changed `map_host_error_to_result_code` to check raw CPU/memory consumption against transaction limits, matching C++ stellar-core behavior.

### Soroban Write Bytes Checking (FIXED)

**Problem**: Transactions succeeded when they should have failed with `ResourceLimitExceeded` due to exceeding write bytes limit.

**Solution**: Added post-execution check in `execute_contract_invocation` to validate total write bytes against `soroban_data.resources.write_bytes`.

### RevokeSponsorship DoesNotExist (FIXED)

**Problem**: RevokeSponsorship operations were failing with DoesNotExist when the target entry existed but wasn't pre-loaded.

**Solution**: Added RevokeSponsorship handling to `load_operation_accounts()` in `execution.rs` to pre-load target entries from bucket list before operation execution.

### UploadContractWasm Footprint-Dependent Behavior (FIXED)

**Problem**: When uploading WASM code that already exists, behavior varied based on footprint.

**Solution**: Modified `execute_upload_wasm` to check if ContractCode key is in read-write footprint.

### Other Fixed Issues

- **BadMinSeqAgeOrGap**: Fixed min_seq_age/min_seq_ledger_gap validation to use account V3 extension fields
- **ClaimClaimableBalance NoTrust**: Fixed trustline loading
- **INIT entry normalization**: Fixed bucket list entry normalization for INIT entries

---

## Debugging Tips

### Comparing with C++ Upstream

The C++ stellar-core v25 code is available in `.upstream-v25/` for reference:

```bash
# Find the C++ implementation
grep -r "functionName" .upstream-v25/src/transactions/
```

### Adding Debug Logging

When investigating a mismatch, add debug logging to the relevant operation:

```rust
tracing::debug!(
    "OperationName: key_field={:?}",
    value
);
```

Run with `RUST_LOG=debug` to see the output.
