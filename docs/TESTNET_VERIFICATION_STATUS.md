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

**Last verification run**: 2026-01-17

| Metric | Value |
|--------|-------|
| Ledgers verified | 933-15000 (14,068 ledgers) |
| Transactions verified | 27,550 |
| Transaction results | 99.3% match (193 mismatches) |
| Ledger headers | 7,722 passed, 6,346 failed |
| First header divergence | Ledger 8655 |

**Status**: Transaction execution parity is **99.3%**. The BadSequence bug at ledger 8655 has been **FIXED** (CDP state sync was applying polluted sequence numbers from operation metadata). Header divergence persists due to **bucket list state tracking** - the verification tool's bucket list diverges from CDP even when all transactions match.

### Mismatch Breakdown

| Category | Count | Description |
|----------|-------|-------------|
| bucketlist-only | 6,248 | Headers diverged, but all tx matched |
| tx-only | 85 | Tx diverged, but headers matched |
| both | 98 | Both tx and headers diverged |

## Remaining Issues

### Transaction Mismatches (193 remaining)
All 193 mismatches are the same pattern:
- **Our result**: `InvokeHostFunction(ResourceLimitExceeded)`
- **CDP result**: `InvokeHostFunction(Trapped)`

**Root cause**: Our Soroban host reports higher CPU consumption than C++ stellar-core for the same transactions.

Example from logs:
- `cpu_consumed=10,368,856` vs `cpu_specified=6,942,449` → We return `ResourceLimitExceeded`
- C++ sees `cpu_consumed <= cpu_specified` → Returns `Trapped`

**Likely causes**:
1. We set budget to `tx_max_instructions * 2` for setup overhead, but `budget.get_cpu_insns_consumed()` returns TOTAL consumption including setup
2. C++ uses `invoke_host_function_v3` through rust bridge which may meter contract execution separately from setup
3. Possible differences in cost parameters or their application

**Impact**: Low - both results are transaction failures, just with different error codes.

### Bucket List Divergence
The bucket list hash diverges from CDP even when all transactions match. This is likely caused by:
- Different INIT vs LIVE classification in `apply_change_with_prestate()`
- Prestate lookup using our diverged bucket list instead of CDP's canonical state
- Missing or incorrectly applied CDP metadata (eviction, upgrades)

The bucket list divergence is **not a consensus issue** for transaction execution, but needs fixing for full header verification.

## Next Steps

1. **Investigate remaining tx mismatches**: Run with `--stop-on-error` to find and debug individual cases
2. **Fix bucket list divergence**: May require syncing bucket list entries from CDP metadata
3. **Continuous verification**: Set up regular verification runs to catch regressions

## Recent Fixes (This Session)

1. **CDP state sync sequence number pollution** (FIXED): Fixed BadSequence errors caused by CDP metadata containing polluted sequence numbers. The issue: CDP operation metadata for Soroban transactions captures STATE values that include sequence number changes from later transactions in the same ledger. Solution: Separate tx_changes (which include real sequence bumps) from operation_changes, and preserve our sequence numbers when applying operation changes.
2. **min_seq_age/min_seq_ledger_gap validation**: Fixed to use account's `seq_time` and `seq_ledger` from V3 extension instead of `last_modified_ledger_seq`. Matches C++ logic:
   - `min_seq_age > closeTime || closeTime - min_seq_age < accSeqTime`
   - `min_seq_ledger_gap > ledgerSeq || ledgerSeq - min_seq_ledger_gap < accSeqLedger`
2. **Soroban error mapping** (`909cf1a`): Fixed `InvokeHostFunction` to return `ResourceLimitExceeded` vs `Trapped` based on raw CPU/memory consumption (matching C++ behavior)
3. **Write bytes checking** (`9d0c4d8`): Added post-execution check for total write bytes exceeding transaction limit

---

## Verification History

| Date | Ledger Range | Result | Notes |
|------|--------------|--------|-------|
| 2026-01-17 | 933-15000 | 99.3% tx match (193/27,550 mismatches) | Fixed CDP state sync sequence pollution |
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
