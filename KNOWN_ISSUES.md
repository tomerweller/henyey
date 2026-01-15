# Known Issues

This document tracks known issues in rs-stellar-core that affect network synchronization and consensus participation.

## 1. Buffered Gap After Catchup (Critical)

**Status:** Unresolved
**Severity:** Critical - Prevents real-time sync
**Component:** Catchup / Herder
**Last Verified:** 2026-01-11 - Observed on fresh testnet run

### Description
After catchup completes to a checkpoint ledger, the node cannot close subsequent ledgers because the required transaction sets (tx_sets) are no longer available from peers.

### Symptoms
- Node stuck at checkpoint+1 ledger (e.g., `current_ledger=430400`, `first_buffered=430401`)
- Continuous "DontHave for TxSet" messages from peers
- Buffer keeps growing while the gap remains
- Repeated catchup attempts that skip because target is already past

### Root Cause
1. Catchup completes to checkpoint ledger N (e.g., 430399)
2. Node advances to ledger N+1 (e.g., 430400)
3. To close ledger N+2 (e.g., 430401), node needs its tx_set
4. Node requests tx_set from peers
5. Peers respond "DontHave" - tx_set is too old (peers only keep ~12 recent slots)
6. Without tx_set, ledger cannot close
7. Catchup system detects gap, tries to catchup to latest checkpoint
8. Latest checkpoint <= current ledger, so catchup is skipped
9. Cycle repeats indefinitely

### Example Log Pattern
```
INFO  Evaluating buffered catchup current_ledger=430400 first_buffered=430401 last_buffered=430446
WARN  Buffered catchup stuck timeout; triggering catchup
INFO  Already at or past target; skipping catchup current_ledger=430400 target_ledger=430399
INFO  Peer reported DontHave for TxSet hash="fdd5aa743a41..."
```

### Potential Fixes
1. Implement ledger replay from history archive (fetch tx_sets from archive, not peers)
2. Fast-forward past the gap using EXTERNALIZE messages when tx_sets are unavailable
3. Catch up to a future checkpoint instead of the latest available one

---

## 2. Bucket List Hash Mismatch at P25 (Resolved)

**Status:** Resolved
**Severity:** N/A - Fixed
**Component:** Bucket List / Hot Archive
**Last Verified:** 2026-01-15

### Resolution Summary
The replay integration test (`test_catchup_replay_bucket_hash_verification`) now passes all ledger checkpoints including the previously failing L1 spill at ledger 380088.

### Fixes Applied
1. **Cross-Phase Deduplication:** Implemented `CoalescedLedgerChanges`.
2. **Transient Entry Annihilation:** Corrected `Init` -> `Dead` logic.
3. **Eviction Iterator Parity:** Implemented local `EvictionIterator` updates.
4. **Transaction Change Replay:** Corrected `tx_changes_before` handling.
5. **INIT Normalization:** Disabled `normalize_init` for level spills, aligning with observed C++ behavior.
6. **Merge Bucket Optimizations:** Removed fast-path optimizations in `merge_buckets` to ensure metadata updates and normalization logic are always applied consistently.
7. **Hot Archive Merge:** Fixed `merge_hot_archive_buckets` to prevent empty bucket optimization.