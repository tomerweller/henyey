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
| Ledgers verified | 933-10000 |
| Transaction results | 100% match |
| Ledger headers | 100% match |

**Status: All transaction results and ledger headers match in verified range.**

## Next Steps

1. **Extend verification range**: Continue verifying higher ledger ranges (10000-20000, etc.)
2. **Full testnet verification**: Target complete testnet history verification
3. **Continuous verification**: Set up regular verification runs to catch regressions

---

## Verification History

| Date | Ledger Range | Result | Notes |
|------|--------------|--------|-------|
| 2026-01-16 | 933-10000 | 100% tx results + headers | Scope narrowed to results/headers only |
| 2026-01-16 | 933-5000 | 5108/5108 matched (100%) | Fixed UploadContractWasm footprint issue |
| 2026-01-16 | 933-1100 | 544/544 matched (100%) | Initial verification range |

---

## Previously Fixed Issues (Reference)

### RevokeSponsorship DoesNotExist (FIXED)

**Problem**: RevokeSponsorship operations were failing with DoesNotExist when the target entry existed but wasn't pre-loaded.

**Solution**: Added RevokeSponsorship handling to `load_operation_accounts()` in `execution.rs` to pre-load target entries from bucket list before operation execution.

### UploadContractWasm Footprint-Dependent Behavior (FIXED)

**Problem**: When uploading WASM code that already exists, behavior varied based on footprint.

**Solution**: Modified `execute_upload_wasm` to check if ContractCode key is in read-write footprint.

### Other Fixed Issues

- **BadMinSeqAgeOrGap**: Fixed minimum sequence age validation
- **ClaimClaimableBalance NoTrust**: Fixed trustline loading
- **Bucket List Hash Mismatch**: Fixed INIT entry normalization

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
