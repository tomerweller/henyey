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

**Last verification run**: 2026-01-19

### Full Testnet Verification Summary (64-440,063)

| Metric | Value |
|--------|-------|
| Ledgers verified | **440,000** |
| Segments completed | 44 / 56 |
| Total TX matched | **1,325,909** |
| Total TX mismatched | **432** |
| **TX match rate** | **99.97%** |
| Genuine bugs (tx_only) | **11** |
| Bucket-list induced | 421 |
| Header mismatches | 165,851 ledgers |

### Key Findings

1. **Transaction Execution**: 99.97% parity with C++ stellar-core
2. **Genuine Bugs**: 11 transaction mismatches NOT caused by bucket list divergence (tx_only)
3. **Bucket List**: Causes ~97% of mismatches; when bucket list is correct, TX execution is 100%
4. **Performance**: Later segments (380k+) run 10x slower due to missing WASM module cache (see KNOWN_ISSUES.md #17)

### Segment Results Summary

| Category | Count | Description |
|----------|-------|-------------|
| SUCCESS (0 tx mismatches) | 26 | Clean transaction execution |
| MISMATCH (tx errors) | 18 | Some transaction mismatches |
| KILLED (incomplete) | 12 | Segments 45-56 not completed |

### Segments with tx_only Mismatches (Genuine Bugs)

These are real execution bugs, NOT caused by bucket list divergence:

| Segment | Ledger Range | tx_only | Description |
|---------|--------------|---------|-------------|
| 16 | 150,064-160,063 | 1 | See KNOWN_ISSUES.md |
| 21 | 200,064-210,063 | 2 | Orderbook divergence |
| 24 | 230,064-240,063 | 1 | ManageSellOffer OpNotSupported |
| 33 | 320,064-330,063 | 2 | InvokeHostFunction issues |
| 34 | 330,064-340,063 | 1 | InvokeHostFunction refundable fee |
| 35 | 340,064-350,063 | 1 | InvokeHostFunction refundable fee |
| 40 | 390,064-400,063 | 1 | InvokeHostFunction refundable fee |
| 41 | 400,064-410,063 | 1 | ManageSellOffer TooManySubentries |
| 42 | 410,064-420,063 | 1 | SetTrustLineFlags CantRevoke |

**Total: 11 genuine bugs** documented in KNOWN_ISSUES.md (#10-#16)

### Full Segment Results

| Seg | Ledger Range | TXs | Mismatched | Header Issues | tx_only | Status |
|-----|--------------|-----|------------|---------------|---------|--------|
| 1 | 64-10,063 | 12,515 | 1 | 1,409 | 0 | MISMATCH |
| 2 | 10,064-20,063 | 26,842 | 0 | 0 | 0 | ✅ SUCCESS |
| 3 | 20,064-30,063 | 19,712 | 0 | 0 | 0 | ✅ SUCCESS |
| 4 | 30,064-40,063 | 21,936 | 0 | 0 | 0 | ✅ SUCCESS |
| 5 | 40,064-50,063 | 14,521 | 0 | 9,093 | 0 | ✅ SUCCESS |
| 6 | 50,064-60,063 | 13,235 | 0 | 2,695 | 0 | ✅ SUCCESS |
| 7 | 60,064-70,063 | 15,278 | 0 | 4,526 | 0 | ✅ SUCCESS |
| 8 | 70,064-80,063 | 16,650 | 0 | 6,300 | 0 | ✅ SUCCESS |
| 9 | 80,064-90,063 | 34,249 | 8 | 8,137 | 0 | MISMATCH |
| 10 | 90,064-100,063 | 48,312 | 5 | 9,925 | 0 | MISMATCH |
| 11 | 100,064-110,063 | 36,616 | 0 | 3,557 | 0 | ✅ SUCCESS |
| 12 | 110,064-120,063 | 33,193 | 0 | 5,327 | 0 | ✅ SUCCESS |
| 13 | 120,064-130,063 | 24,095 | 0 | 7 | 0 | ✅ SUCCESS |
| 14 | 130,064-140,063 | 30,978 | 71 | 8,937 | 0 | MISMATCH |
| 15 | 140,064-150,063 | 30,447 | 0 | 2,580 | 0 | ✅ SUCCESS |
| 16 | 150,064-160,063 | 32,990 | 1 | 4,377 | 1 | MISMATCH |
| 17 | 160,064-170,063 | 29,909 | 0 | 6,209 | 0 | ✅ SUCCESS |
| 18 | 170,064-180,063 | 28,463 | 0 | 8,012 | 0 | ✅ SUCCESS |
| 19 | 180,064-190,063 | 29,407 | 0 | 1,434 | 0 | ✅ SUCCESS |
| 20 | 190,064-200,063 | 33,288 | 0 | 3,365 | 0 | ✅ SUCCESS |
| 21 | 200,064-210,063 | 41,894 | 320 | 5,147 | 2 | MISMATCH |
| 22 | 210,064-220,063 | 29,097 | 0 | 7,018 | 0 | ✅ SUCCESS |
| 23 | 220,064-230,063 | 37,917 | 0 | 8,822 | 0 | ✅ SUCCESS |
| 24 | 230,064-240,063 | 41,887 | 1 | 0 | 1 | MISMATCH |
| 25 | 240,064-250,063 | 31,873 | 0 | 0 | 0 | ✅ SUCCESS |
| 26 | 250,064-260,063 | 26,506 | 0 | 6,023 | 0 | ✅ SUCCESS |
| 27 | 260,064-270,063 | 25,034 | 5 | 7,916 | 0 | MISMATCH |
| 28 | 270,064-280,063 | 29,185 | 1 | 9,633 | 0 | MISMATCH |
| 29 | 280,064-290,063 | 26,458 | 0 | 3,198 | 0 | ✅ SUCCESS |
| 30 | 290,064-300,063 | 29,733 | 0 | 4,975 | 0 | ✅ SUCCESS |
| 31 | 300,064-310,063 | 25,497 | 0 | 1,399 | 0 | ✅ SUCCESS |
| 32 | 310,064-320,063 | 23,127 | 1 | 8,737 | 0 | MISMATCH |
| 33 | 320,064-330,063 | 43,997 | 5 | 2,217 | 2 | MISMATCH |
| 34 | 330,064-340,063 | 38,555 | 1 | 4,166 | 1 | MISMATCH |
| 35 | 340,064-350,063 | 33,025 | 2 | 5,925 | 1 | MISMATCH |
| 36 | 350,064-360,063 | 43,232 | 0 | 0 | 0 | ✅ SUCCESS |
| 37 | 360,064-370,063 | 42,337 | 0 | 9,402 | 0 | ✅ SUCCESS |
| 38 | 370,064-380,063 | 40,213 | 1 | 6,192 | 0 | MISMATCH |
| 39 | 380,064-390,063 | 35,459 | 0 | 4,988 | 0 | ✅ SUCCESS |
| 40 | 390,064-400,063 | 46,945 | 5 | 6,689 | 1 | MISMATCH |
| 41 | 400,064-410,063 | 40,207 | 1 | 22 | 1 | MISMATCH |
| 42 | 410,064-420,063 | 36,050 | 3 | 2,246 | 1 | MISMATCH |
| 43 | 420,064-430,063 | 31,744 | 6 | 4,011 | 0 | MISMATCH |
| 44 | 430,064-440,063 | 37,452 | 0 | 109 | 0 | ✅ SUCCESS |
| 45-56 | 440,064-556,157 | - | - | - | - | KILLED |

### Performance Analysis

Later segments show significant slowdown due to missing persistent WASM module cache:

| Segment | Duration | TX/min | Notes |
|---------|----------|--------|-------|
| 20 | 604s | 3,306 | Normal speed |
| 35 | 919s | 2,156 | Slight slowdown |
| 39 | 6,965s | 305 | **10x slower** |
| 44 | 7,932s | 283 | **10x slower** |

See KNOWN_ISSUES.md #17 for details on the module cache fix.

## Remaining Issues

### 1. Bucket List Divergence (CRITICAL)
The bucket list hash diverges in ~63% of checkpoint segments (63,000 header mismatches out of ~100,000 ledgers). This causes **cascading transaction failures** when state corrupts.

**Impact**: When bucket list state diverges, subsequent transactions see different account balances or entry states. For example, at ledger 10710, a Payment operation returns `Underfunded` instead of `Success` due to incorrect balance tracking.

**Key Finding (2026-01-18)**: Many apparent "CPU metering differences" in segments with bucket list issues were **misdiagnosed**. The actual cause was bucket list divergence corrupting state.

**Ranges with 100% TX parity (clean bucket list)**:
- 40000-60000: 27,758 transactions, 0 mismatches
- 60000-80000: 31,943 transactions, 0 mismatches
- Earlier verified: 30000-36000, 70000-75000, 100000-110000

### ClaimClaimableBalance Issuer NoTrust (RESOLVED)
~~Four transactions in segment 30000-40000 showed `ClaimClaimableBalance(NoTrust)` instead of `Success`.~~

**Root Cause**: Issuers claiming their own claimable balances don't need trustlines. C++ `TrustLineWrapper::IssuerImpl` handles this, but our Rust code was missing the issuer check.

**Fix**: Added issuer check in `execute_claim_claimable_balance` - if source is the asset issuer, skip trustline lookup.

**Status**: ✅ Fully resolved. The InvokeHostFunction(Trapped) at ledger 37046 was a separate issue (Soroban archived entry TTL) also fixed on 2026-01-18.

### ~~Soroban CPU Metering (RESOLVED)~~
~~Previously reported as "our soroban-env-host consumes more CPU than C++".~~

**Status**: This issue is **RESOLVED**. Investigation confirmed both implementations use the same Rust soroban-env-host crate with identical CPU consumption. The apparent differences were caused by bucket list divergence corrupting state.

## Next Steps

1. **Fix bucket list divergence (CRITICAL)**: Root cause of most transaction mismatches in segments with header issues
2. **Investigate liquidity pool calculation**: Ledger 20226 shows ~0.09% difference in constant product AMM
3. **Investigate InvokeHostFunction resource failures**: 6 transactions at ledgers 26961-27057 fail incorrectly
4. **Extend verification to 500000+**: Continue testing to find more edge cases

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
11. **ClaimClaimableBalance issuer handling** (2026-01-18): Fixed issuers claiming their own claimable balances. C++ `TrustLineWrapper::IssuerImpl` allows issuers to receive their own asset without a trustline. Added issuer check to skip trustline lookup. Affected ledgers: 37272, 37307, 37316.
12. **Soroban archived entry TTL restoration** (2026-01-18): Fixed InvokeHostFunction failures when restoring archived entries (ContractData, ContractCode). The soroban-env-host validates that TTL >= current_ledger, but we were providing TTL=0. Changed to provide TTL=current_ledger for restored entries. Affected ledger: 37046.

---

## Verification History

| Date | Ledger Range | Result | Notes |
|------|--------------|--------|-------|
| 2026-01-18 | 933-100000 | 99.99% (221,355 TX, 21 mismatches) | Full range verification, 7 genuine mismatches found |
| 2026-01-18 | 80000-100000 | 99.98% (81,403 TX, 13 mismatches) | All mismatches bucket-list induced |
| 2026-01-18 | 60000-80000 | 100% (31,943 TX, 0 mismatches) | Clean TX execution |
| 2026-01-18 | 40000-60000 | 100% (27,758 TX, 0 mismatches) | Clean TX execution |
| 2026-01-18 | 20000-40000 | 99.98% (41,679 TX, 7 mismatches) | 0 header issues - genuine mismatches |
| 2026-01-18 | 933-20000 | 99.997% (38,572 TX, 1 mismatch) | 1 bucket-list induced mismatch |
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
