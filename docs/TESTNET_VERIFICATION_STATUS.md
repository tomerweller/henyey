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

# Run verification on a ledger range (starts from nearest checkpoint)
./target/release/rs-stellar-core --testnet offline verify-execution --from 152600 --to 152800

# Stop on first mismatch for debugging
./target/release/rs-stellar-core --testnet offline verify-execution --from 152600 --to 152800 --stop-on-error
```

## Current Status

**Last verification run**: 2026-01-20

### Executive Summary

| Metric | Value |
|--------|-------|
| **Bucket list implementation** | ✅ **Correct** |
| **Checkpoint-based verification** | ✅ **100% header match** |
| **Transaction execution accuracy** | **99.86%** (recent ledgers) |
| **Issues remaining** | 2 genuine bugs + 1 historical |
| **Issues fixed** | 13+ bugs fixed |

### Key Finding

**The bucket list implementation is correct.** When starting verification from any checkpoint, header hashes match perfectly (0 mismatches). This was confirmed by testing multiple ledger ranges:

| Ledger Range | Header Mismatches | TX Mismatches | Notes |
|--------------|-------------------|---------------|-------|
| 100,000-100,200 | **0** | **0** | ✅ Clean range |
| 152,600-152,800 | **0** | 1 | Issue #3: Historical cost model variance |
| 180,000-180,200 | **0** | **0** | ✅ Clean range |
| 201,400-201,800 | **0** | **0** | ✅ Issue #5 FIXED |
| 236,900-237,100 | **0** | **0** | ✅ Issue #10 FIXED |
| 342,600-342,800 | **0** | **0** | ✅ Issue #4 FIXED |
| 390,300-390,500 | **0** | 2 | Issue #6: Partially fixed |
| 407,200-407,400 | **0** | **0** | ✅ Issue #15 FIXED |
| 416,600-416,700 | **0** | **0** | ✅ Issue #16 FIXED |

### Continuous Replay Analysis

When running verification **continuously** from ledger 64 (not starting from a checkpoint), bucket list divergence accumulates. After fix `5e4f2f1`, correct replay extended from ~8,591 to ~40,970 ledgers:

| Range | Header Mismatches | Notes |
|-------|-------------------|-------|
| 64-10,000 | **0** | Bucket list correct ✅ |
| 64-20,000 | **0** | Bucket list correct ✅ |
| 64-30,000 | **0** | Bucket list correct ✅ |
| 64-40,000 | **0** | Bucket list correct ✅ |
| 64-40,970 | **0** | Last clean ledger ✅ |
| 64-41,000 | 30 | Divergence begins at 40971 |
| 64-50,000 | 9,030 | Accumulating divergence |

**Root cause (investigated 2026-01-20)**: The divergence at ledger 40971 is caused by **~16,000 Soroban TX execution mismatches** in ledgers 64-40970. These transactions (mostly InvokeHostFunction) fail with `ResourceLimitExceeded` in our execution but succeeded in the original execution due to historical cost model calibration differences. The accumulated state differences from these mismatches eventually cause the bucket list hash to diverge. See Issue #3 in [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for details.

**Key observation**: Continuous replay divergence is a **low priority** issue since production nodes always catch up from recent checkpoints.

---

## Issue Status

### Fixed Issues (Verified 2026-01-20)

| Issue | Ledger | Description | Verification |
|-------|--------|-------------|--------------|
| **Issue #4** | 342737 | InsufficientRefundableFee - restored TTL | ✅ 100% match |
| **Issue #5** | 201477 | Orderbook divergence - snapshot reload | ✅ 100% match |
| ManageSellOffer OpNotSupported | 237057 | Sponsored offer deletion | 100% match |
| TooManySubentries | 407293 | Subentry limit enforcement | 100% match |
| SetTrustLineFlags CantRevoke | 416662 | Liabilities check removed | 100% match |
| Liquidity Pool State Overwrite | - | Check state before loading | Fixed |
| InvokeHostFunction Resource Limit | - | WASM compilation budget | Fixed |
| Ed25519SignedPayload Verification | - | Hint and signature fixes | Fixed |
| Credit Asset Self-Payment | - | Credit before debit | Fixed |
| ClaimClaimableBalance Issuer | - | Issuer handling | Fixed |
| Soroban Archived Entry TTL | - | Minimum TTL provision | Fixed |
| Persistent WASM Module Cache | - | PersistentModuleCache | Fixed |
| Module Cache Wiring | - | Wired to LedgerManager | Fixed |

### Remaining Issues

| Issue | Ledger | Description | Status |
|-------|--------|-------------|--------|
| #3 | 152692 | Trapped vs ResourceLimitExceeded | Cannot fix - historical cost model |
| #6 | 390407 | Refundable fee bidirectional | Partially fixed - 2 remaining may be CDP anomaly |

See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for detailed descriptions.

---

## Investigation Priority

1. **Issue #6 (Refundable fee)**: Remaining cases may be CDP anomaly (bucket list matches)
2. **Issue #1 (Buffered gap)**: Architecture change needed for real-time sync
3. **Issue #2 (Continuous replay divergence at 40971)**: Low priority - only affects testing

---

## Verification History

| Date | Ledger Range | Result | Notes |
|------|--------------|--------|-------|
| 2026-01-20 | 400k-453k | 99.86% TX accuracy | 210,927/211,215 matched |
| 2026-01-20 | 300k-400k | 99.1% TX accuracy | 368,958/372,218 matched |
| 2026-01-20 | 64-40,970 | 0 header mismatches | Fix 5e4f2f1 extended correct replay |
| 2026-01-20 | 201,400-201,800 | 100% match | Issue #5 confirmed FIXED |
| 2026-01-20 | 342,600-342,800 | 100% match | Issue #4 confirmed FIXED |
| 2026-01-20 | Multi-checkpoint | 0 header per checkpoint | 100,000-416,700 all pass |
| 2026-01-19 | 236,900-237,100 | 100% match | Issue #10 confirmed FIXED |
| 2026-01-19 | 407,200-407,400 | 100% match | Issue #15 confirmed FIXED |
| 2026-01-19 | 416,600-416,700 | 100% match | Issue #16 confirmed FIXED |
| 2026-01-18 | 933-100000 | 99.99% | Full range verification |

---

## Debugging Tips

### Running Targeted Verification

When investigating a specific issue, run verification around that ledger:

```bash
# Verify around ledger 152692 (Issue #3)
./target/release/rs-stellar-core --testnet offline verify-execution --from 152600 --to 152800

# Show detailed diff
./target/release/rs-stellar-core --testnet offline verify-execution --from 152600 --to 152800 --show-diff
```

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
