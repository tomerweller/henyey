# Known Issues

This document tracks known issues in rs-stellar-core that affect network synchronization and consensus participation.

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

## 2. Bucket List Hash Divergence (Partial)

**Status:** ~46% of checkpoint segments work correctly
**Severity:** Medium - Affects header verification but not transaction execution
**Component:** Bucket List
**Last Verified:** 2026-01-18

### Current State
Transaction execution achieves **99.97% parity** (547,928 matched, 157 mismatched out of 205,000 ledgers verified). The 157 mismatches are Soroban CPU metering differences where both implementations fail with different error codes.

Bucket list hash verification shows checkpoint-specific behavior:
- **46% of segments**: Perfect bucket list parity (0 header mismatches)
- **54% of segments**: Bucket list hash divergence

### Key Findings
- Divergence starts **mid-segment**, not at checkpoint boundaries
- This suggests an issue with bucket list state evolution after restoration
- The merge logic itself has been verified correct through unit testing
- HAS (History Archive State) restoration handles states 0 and 1 correctly

### Segments with Issues
Segments 2, 9, 10, 12, 14, 15, 17, and others show divergence. See `TESTNET_VERIFICATION_STATUS.md` for full details.

### Investigation Notes
- Merge argument order verified correct: OLD (level's curr) first, NEW (incoming) second
- Spill flow matches C++ stellar-core
- Hot archive bucket list handling may need further investigation for Protocol 23+

---

## 3. Soroban CPU Metering Difference (Low Priority)

**Status:** Known, not planned to fix
**Severity:** Low - Both implementations fail, just with different error codes
**Component:** Soroban Host

### Description
Our soroban-env-host consumes ~10-15% more CPU instructions than C++ stellar-core for identical operations. This causes some transactions to fail with `ResourceLimitExceeded` instead of `Trapped`.

### Impact
- 157 transactions (0.03%) show this difference
- Both implementations correctly reject the transaction
- Does not affect consensus correctness
