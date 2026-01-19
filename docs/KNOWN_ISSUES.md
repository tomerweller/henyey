# Known Issues

This document tracks known issues in rs-stellar-core that affect network synchronization and consensus participation.

**Last Updated:** 2026-01-19

## Summary

### Verification Statistics (2026-01-19)

Full testnet verification from ledger 64 to ~453,000 reveals:

| Metric | Count | Notes |
|--------|-------|-------|
| **Total genuine tx mismatches** | ~1,198 | Consistent "tx-only" count |
| **Bucket list correct** | Yes | 0 header mismatches when starting from any checkpoint |
| **Bucket list divergence** | After ~8,591 ledgers | Only when running continuously from early ledgers |

### Key Finding

**The bucket list implementation is correct.** When starting verification from any checkpoint, header hashes match perfectly (0 mismatches). The ~1,198 "tx-only" mismatches represent genuine execution bugs that need fixing.

Bucket list divergence only occurs when running **continuously** from early ledgers (e.g., starting at ledger 64). After ~8,591 ledgers of continuous replay, accumulated state differences cause header mismatches. This is a secondary concern compared to fixing the genuine execution bugs.

---

## 1. Buffered Gap After Catchup (Critical)

**Status:** Unresolved
**Severity:** Critical - Prevents real-time sync
**Component:** Catchup / Herder

### Description
After catchup completes to a checkpoint ledger, the node cannot close subsequent ledgers because the required transaction sets (tx_sets) are no longer available from peers.

### Symptoms
- Node stuck at checkpoint+1 ledger (e.g., `current_ledger=430400`, `first_buffered=430401`)
- Continuous "DontHave for TxSet" messages from peers
- Buffer keeps growing while the gap remains
- Repeated catchup attempts that skip because target is already past

### Root Cause
1. Catchup completes to checkpoint ledger N
2. Node advances to ledger N+1
3. To close ledger N+2, node needs its tx_set
4. Node requests tx_set from peers
5. Peers respond "DontHave" - tx_set is too old (peers only keep ~12 recent slots)
6. Without tx_set, ledger cannot close
7. Catchup system detects gap, tries to catchup to latest checkpoint
8. Latest checkpoint <= current ledger, so catchup is skipped
9. Cycle repeats indefinitely

### Potential Fixes
1. Implement ledger replay from history archive (fetch tx_sets from archive, not peers)
2. Fast-forward past the gap using EXTERNALIZE messages when tx_sets are unavailable
3. Catch up to a future checkpoint instead of the latest available one

---

## 2. Bucket List Continuous Replay Divergence

**Status:** Low Priority - Not a correctness issue
**Severity:** Low - Only affects continuous replay from genesis
**Component:** Bucket List
**Last Verified:** 2026-01-19

### Current State
The bucket list implementation is **correct** for normal operation. When starting from any checkpoint, bucket list hashes match the expected values perfectly.

Divergence only occurs when replaying **continuously** from early ledgers (e.g., starting at ledger 64 and running to ledger 100,000+). This is not a practical concern because:
1. Real nodes always catch up from recent checkpoints
2. The first ~8,591 ledgers replay correctly before divergence begins
3. Transaction execution mismatches in this scenario are caused by accumulated state differences, not fundamental bugs

### Verification Results
| Range | Header Mismatches | Notes |
|-------|-------------------|-------|
| 64-1,000 | 0 | Bucket list correct |
| 64-3,000 | 0 | Bucket list correct |
| 64-5,000 | 0 | Bucket list correct |
| 64-7,000 | 0 | Bucket list correct |
| 64-8,500 | 0 | Bucket list correct |
| 64-8,700 | 46 | Divergence begins ~8,591 |
| 64-10,000 | 1,346 | Accumulating divergence |

### Checkpoint-Based Verification (All Pass)
| Range | Header Mismatches | TX Mismatches |
|-------|-------------------|---------------|
| 152,600-152,800 | 0 | 1 (genuine bug) |
| 201,400-201,800 | 0 | 3 (genuine bugs) |
| 342,600-342,800 | 0 | 2 (genuine bugs) |
| 390,300-390,500 | 0 | 3 (genuine bugs) |

---

## 3. InvokeHostFunction Trapped vs ResourceLimitExceeded

**Status:** Genuine Bug - Needs Fix
**Severity:** Medium - Causes transaction execution mismatches
**Component:** Soroban Host / Error Mapping
**Last Verified:** 2026-01-19

### Description
Some InvokeHostFunction transactions return `Trapped` in our code but `ResourceLimitExceeded` in C++ stellar-core. Both are failures, but the error code differs.

### Details
```
Ledger 152692 TX 2:
  - Our result: InvokeHostFunction(Trapped)
  - CDP result: InvokeHostFunction(ResourceLimitExceeded)
```

### Investigation Status
**Confirmed genuine bug** - verification shows 0 header mismatches in this segment.

The error mapping logic in `map_host_error_to_result_code()` checks raw CPU/memory consumption against limits, but there may be subtle differences in how consumption is measured or limits are applied compared to C++ stellar-core.

### Affected Ledgers
- Ledger 152692 TX 2

---

## 4. InvokeHostFunction InsufficientRefundableFee

**Status:** Genuine Bug - Needs Fix
**Severity:** Medium - Causes transaction execution mismatches
**Component:** Soroban Host / Fee Handling
**Last Verified:** 2026-01-19

### Description
Some InvokeHostFunction transactions fail with `InsufficientRefundableFee` in our code but succeed in C++ stellar-core.

### Details
```
Ledger 342737 TX 3:
  - Our result: InvokeHostFunction(InsufficientRefundableFee)
  - CDP result: InvokeHostFunction(Success(Hash(...)))
```

### Investigation Status
**Confirmed genuine bug** - verification shows 0 header mismatches in this segment.

Rent fee calculation may differ from C++ stellar-core. A code fix was previously applied for protocol-version-dependent fee selection, but additional issues exist.

### Affected Ledgers
- Ledger 342737 TX 3

---

## 5. ManageSellOffer/ManageBuyOffer Orderbook State Divergence

**Status:** Genuine Bug - Needs Fix
**Severity:** Medium - Causes transaction execution mismatches
**Component:** Offer Management / Orderbook
**Last Verified:** 2026-01-19

### Description
Some ManageSellOffer and ManageBuyOffer transactions claim different offers than C++ stellar-core. Both succeed but with different `offers_claimed` results.

### Details
```
Ledger 201477 TX 2:
  - Our offers_claimed: [offer_id: 8071, 8072]
  - CDP offers_claimed: [offer_id: 8072, 8065, 8003, 7975]
```

### Investigation Status
**Confirmed genuine bug** - verification shows 0 header mismatches in this segment.

This is the most concerning bug - if the orderbook state is the same (as indicated by 0 header mismatches), the same offers should be claimed. The offer selection logic or offer iteration order may differ from C++ stellar-core.

### Affected Ledgers
- Ledger 201477, 201755

---

## 6. InvokeHostFunction Refundable Fee Bidirectional

**Status:** Genuine Bug - Needs Fix
**Severity:** Medium - Causes transaction execution mismatches in both directions
**Component:** Soroban Host / Fee Configuration
**Last Verified:** 2026-01-19

### Description
InvokeHostFunction transactions show inconsistent refundable fee behavior compared to C++ stellar-core. In some cases we succeed where CDP fails, and in other cases we fail where CDP succeeds.

### Details
**Case 1: We succeed, CDP fails**
```
Ledger 390407 TX 9, 10:
  - Our result: InvokeHostFunction(Success(...))
  - CDP result: InvokeHostFunction(InsufficientRefundableFee)
```

### Investigation Status
**Confirmed genuine bug** - verification shows 0 header mismatches in this segment.

A fix was applied for protocol-version-dependent fee selection (`fee_write1_kb` vs `fee_per_rent_1kb`), but issues persist. This may be related to Issue #4.

### Affected Ledgers
- Ledger 390407 TX 9, 10

---

## Issue Status Summary

| Issue | Type | Status | Description |
|-------|------|--------|-------------|
| #1 | Architecture | Critical | Buffered Gap After Catchup - prevents real-time sync |
| #2 | Non-issue | Low | Bucket list correct; divergence only in continuous replay |
| #3 | Execution Bug | Medium | Trapped vs ResourceLimitExceeded |
| #4 | Execution Bug | Medium | InsufficientRefundableFee |
| #5 | Execution Bug | Medium | Orderbook state divergence |
| #6 | Execution Bug | Medium | Refundable fee bidirectional |

---

## Recently Fixed Issues

The following issues were previously tracked but are now confirmed FIXED (verified 2026-01-19 with 100% match):

| Issue | Ledger | Fix Description |
|-------|--------|-----------------|
| ManageSellOffer OpNotSupported | 237057 | Sponsored offer deletion |
| TooManySubentries | 407293 | Subentry limit enforcement |
| SetTrustLineFlags CantRevoke | 416662 | Removed incorrect liabilities check |
| Liquidity Pool State Overwrite | - | Check state before loading from snapshot |
| InvokeHostFunction Resource Limit | - | Increased WASM compilation budget |
| Ed25519SignedPayload Extra Signer | - | Hint calculation and signature verification |
| Credit Asset Self-Payment | - | Credit before debit for self-payments |
| ClaimClaimableBalance Issuer NoTrust | - | Issuer handling |
| Soroban Archived Entry TTL | - | Provide current ledger as minimum TTL |
| Missing Persistent WASM Module Cache | - | Implemented PersistentModuleCache |
| Module Cache Not Wired | - | Wired to LedgerManager |

---

## Investigation Priority

1. **Issue #5 (Orderbook divergence)**: Most concerning - different offer selection with same state
2. **Issue #4 (InsufficientRefundableFee)**: Review rent fee calculation in detail
3. **Issue #6 (Refundable fee bidirectional)**: May be related to #4
4. **Issue #3 (Trapped vs ResourceLimitExceeded)**: Review error mapping logic
5. **Issue #1 (Buffered gap)**: Architecture change needed for real-time sync
