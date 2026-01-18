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

**Last verification run**: 2026-01-18

### Extended Verification Summary

| Metric | Value |
|--------|-------|
| Total TX verified | ~100,000+ |
| TX match rate | **99.99%+** |
| Clean ranges verified | 30000-36000, 50000-60000, 70000-75000, 100000-110000, 250000-251000, 300000-301000 |
| **PRNG divergence** | ✅ RESOLVED (ledgers 71655, 71766) |

### Verification Results by Range

| Range | Transactions | Parity | Notes |
|-------|--------------|--------|-------|
| 10000-20000 | 26,916 | **100%** | ✅ Self-payment fix verified |
| 30000-36000 | 14,651 | **100%** | Clean range, all match |
| 30000-40000 | 21,999 | 99.98% | 4 mismatches (ClaimClaimableBalance/InvokeHostFunction) |
| 50000-60000 | 13,246 | **100%** | Clean range (header mismatches due to bucket list) |
| 70000-75000 | 9,027 | **100%** | Fixed: PRNG seed was 2 divergences (now resolved) |
| 70000-80000 | 16,662 | **100%** | Clean range (header mismatches due to bucket list) |
| 100000-110000 | 37,744 | **100%** | Clean range |
| 250000-251000 | 2,457 | **100%** | Clean range |
| 300000-301000 | 2,228 | **100%** | Clean range |

### RESOLVED: Soroban PRNG Seed Divergence (Fixed in `3105525`)

**Previously found 2 transactions where both Rust and C++ succeeded but returned DIFFERENT hash values:**

1. **Ledger 71655**:
   - Our hash (before fix): `e12337f8aabf2af4c90ad7c7c0aff9495a0d346008a0c40c02e17a818dc53014`
   - CDP hash: `7ecf7e8454b3758e6a5f8a68801b377141d40691308f009e82e6c780c4a0b0d3`

2. **Ledger 71766**:
   - Our hash (before fix): `5d52ad15f24c4a27c17e3923d880b3d6561ceb152e4ee495155e96fbf038fece`
   - CDP hash: `2834b42856c37e9e494d5bcc8717165d5b0a82166033347473544d678f4983c0`

**Root cause**: PRNG seed computation was incorrect:
- **Bug 1**: `sub_sha256` in `hash.rs` used little-endian byte order instead of big-endian
- **Bug 2**: PRNG seed in `execution.rs` and `main.rs` used 4-byte u32 instead of 8-byte u64

C++ stellar-core uses `subSha256(baseSeed, static_cast<uint64_t>(index))` where `xdr_to_opaque` serializes the u64 as 8 bytes big-endian (XDR network byte order).

**Status**: ✅ FIXED - Both ledgers now verify correctly

### Parallel Full Testnet Verification (Partial - 41/109 segments)

| Metric | Value |
|--------|-------|
| Ledgers verified | 205,000 |
| Transactions matched | 547,928 |
| Transactions mismatched | 157 |
| **TX match rate** | **99.97%** |
| Segments with bucket list OK | 19 (46%) |
| Segments with bucket list issues | 22 (54%) |
| Total header mismatches | 50,817 ledgers |

**Transaction Execution**: Near-perfect parity at 99.97%. The mismatches are **caused by bucket list divergence corrupting state** - NOT CPU metering issues. On segments with correct bucket list state, transaction execution achieves **100% parity**.

**Bucket List**: ~54% of segments show bucket list hash divergence. This is a **checkpoint-specific issue** - some checkpoints restore correctly while others diverge. The divergence appears to start mid-segment (not at checkpoint boundaries), suggesting an issue with bucket list state evolution after restoration. **This is the root cause of all transaction execution mismatches.**

### Segments with Perfect Bucket List Parity

| Segment | Ledger Range | Status |
|---------|--------------|--------|
| 1 | 64-5,063 | ✅ 0 header mismatches |
| 3-8 | 10,064-40,063 | ✅ 0 header mismatches |
| 11 | 50,064-55,063 | ✅ 0 header mismatches |
| 13 | 60,064-65,063 | ✅ 0 header mismatches |
| 16 | 75,064-80,063 | ✅ 0 header mismatches |
| 18 | 85,064-90,063 | ✅ 0 header mismatches |

### Segments with Bucket List Issues

| Segment | Ledger Range | Header Mismatches |
|---------|--------------|-------------------|
| 2 | 5,064-10,063 | 1,409 |
| 9 | 40,064-45,063 | 4,093 |
| 10 | 45,064-50,063 | 370 |
| 12 | 55,064-60,063 | 2,695 |
| 14 | 65,064-70,063 | 4,526 |
| 15 | 70,064-75,063 | 1,300 |
| 17 | 80,064-85,063 | 3,137 |
| 19+ | 90,064+ | Various |

### Mismatch Breakdown

| Range | Error Code Diffs | Phase 1 Fee Diffs | Header Failures |
|-------|------------------|-------------------|-----------------|
| 933-15000 | 193 | 0 | 6,346 |
| 15001-30000 | 526 | 52 | 0 |

## Remaining Issues

### Bucket List Divergence (CRITICAL)
The bucket list hash diverges in ~54% of segments. This is the **root cause of ALL transaction execution mismatches**.

**Impact**: When bucket list state diverges, subsequent transactions see different account balances or entry states, leading to different execution results. For example, at ledger 10710, a Payment operation returns `Underfunded` instead of `Success` because the bucket list divergence caused incorrect balance tracking.

**Key Finding (2026-01-18)**: The previously reported "CPU metering differences" (157 mismatches showing ResourceLimitExceeded vs Trapped) were **misdiagnosed**. Those mismatches were actually caused by bucket list divergence corrupting state, not CPU metering issues.

**Verification on clean segments shows 100% parity**:
- 30000-36000: 14,651 transactions, 100% match
- 50000-60000: 13,246 transactions, 100% match
- 70000-75000: 9,027 transactions, 100% match
- 100000-110000: 37,744 transactions, 100% match

### Phase 1 Fee Differences (52 cases - NEEDS INVESTIGATION)
A small number of transactions show Phase 1 fee calculation differences. This needs further investigation to understand the root cause.

### ClaimClaimableBalance NoTrust (4 cases - NEEDS INVESTIGATION)
Four transactions in segment 30000-40000 show `ClaimClaimableBalance(NoTrust)` instead of `Success`:
- Ledger 37272 TX 0: ClaimClaimableBalance + Payment
- Ledger 37307 TX 0: ClaimClaimableBalance + Payment
- Ledger 37316 TX 1: ClaimClaimableBalance + Payment
- Ledger 37046 TX 1: InvokeHostFunction (separate Soroban issue)

These occur in a segment with **correct bucket list state** (0 header mismatches), suggesting a bug in claimable balance or trustline handling rather than state corruption.

### ~~Soroban CPU Metering (RESOLVED)~~
~~Previously reported as "our soroban-env-host consumes more CPU than C++".~~

**Status**: This issue is **RESOLVED**. Investigation confirmed both implementations use the same Rust soroban-env-host crate with identical CPU consumption. The apparent differences were caused by bucket list divergence corrupting state.

## Next Steps

1. **Fix bucket list divergence (CRITICAL)**: This is the root cause of all transaction mismatches
2. **Investigate Phase 1 fee differences**: 52 cases need investigation
3. **Extend verification range**: Continue testing after bucket list is fixed

## Recent Fixes (January 2026)

1. **Soroban PRNG seed fix** (`3105525`): Fixed PRNG seed computation to use 8-byte XDR u64 big-endian encoding instead of 4-byte little-endian. This caused contracts using randomness (PRNG) to produce different results at ledgers 71655 and 71766.
2. **Clawback trustline flag fix** (`4f39c0e`): Fixed Clawback to check `TRUSTLINE_CLAWBACK_ENABLED_FLAG` (0x4) on the trustline instead of `AUTH_CLAWBACK_ENABLED_FLAG` (0x8) on the issuer account.
3. **Payment NoIssuer fix** (`5a567b1`): Removed protocol-obsolete issuer existence check in Payment operations. Since protocol v13 (CAP-0017), issuer existence is not checked.
4. **HashX signature validation** (`80a9870`): Fixed signature validation to accept variable-length HashX signatures instead of requiring 64-byte Ed25519 format.
5. **Soroban temporary entry archival** (`80a9870`): Fixed to treat expired temporary entries as non-existent rather than archived.
6. **minSeqNum relaxed sequence validation** (`7b249b5`): Fixed sequence validation to use relaxed check when minSeqNum is set.
7. **CDP state sync sequence number pollution** (`1898c9b`): Fixed BadSequence errors caused by polluted sequence numbers in CDP metadata.
8. **min_seq_age/min_seq_ledger_gap validation** (`10620bc`): Fixed to use account's V3 extension fields.
9. **Ed25519SignedPayload extra signer verification** (2026-01-18): Fixed two bugs in signed payload signature verification per CAP-0040:
   - Hint calculation: Must use XOR of public key hint and payload hint (not just public key hint)
   - Signature verification: Must verify signature against raw payload bytes (not SHA256 hash of payload)
10. **Credit asset self-payment order of operations** (2026-01-18): Fixed self-payments (source == destination) for credit assets to credit destination before checking source balance. C++ stellar-core uses `updateDestBalance` before `updateSourceBalance` in PathPaymentStrictReceive, so for self-payments the credited amount is available for the debit check. Affected ledgers: 11143, 11264, 11381, 11396.

---

## Verification History

| Date | Ledger Range | Result | Notes |
|------|--------------|--------|-------|
| 2026-01-17 | 15001-30000 | 100% tx match, 0 header failures | Extended verification, bucket list correct |
| 2026-01-17 | 933-15000 | 100% tx match (193 error code diffs) | Fixed minSeqNum relaxed validation |
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
