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

## 2. Bucket List Hash Mismatch at P25 (Partially Resolved)

**Status:** Skip_list logic fixed / Bucket list hash diverges when evictions occur
**Severity:** Medium - Affects verification tooling only
**Component:** Bucket List / Eviction / Hot Archive
**Last Verified:** 2026-01-14

### Status Update
- **Skip List Logic**: **RESOLVED**. Corrected misunderstanding about skip_list semantics - it stores bucket_list_hash values, not previous_ledger_hash, at intervals of 50/5000/50000/500000.
- **Short Range Verification**: **WORKS**. Starting from a checkpoint and verifying up to ~60 ledgers works correctly.
- **Eviction-Related Divergence**: **FAILS**. When evictions occur (around ledger N+62 from checkpoint), bucket_list_hash diverges.

### Investigation Summary & Fixes

#### Skip List Fix (2026-01-14)
**Critical discovery**: The skip_list does NOT store `previous_ledger_hash` values. It stores `bucket_list_hash` values at specific milestone ledgers:
- Skip intervals: SKIP_1=50, SKIP_2=5000, SKIP_3=50000, SKIP_4=500000
- skip_list[0] = bucket_list_hash at last ledger where seq % 50 == 0
- Updates cascade from [0] -> [1] -> [2] -> [3] at higher intervals
- Reference: C++ stellar-core BucketManager::calculateSkipValues()

#### Other Fixes
1.  **Cross-Phase Deduplication (Fixed):** Implemented a `CoalescedLedgerChanges` utility to unify all state changes (Fee, Tx, Post-Fee, Upgrades, Eviction) into a single, unique set per ledger.
2.  **Transient Entry Annihilation (Fixed):** Corrected logic for entries created and deleted in the same ledger (`Init` -> `Dead`).
3.  **Eviction Iterator Parity (Fixed):** Implemented missing local `EvictionIterator` updates.
4.  **Transaction Change Replay (Fixed):** Corrected `tx_changes_before` handling for failed transactions.
5.  **StellarValue Extension (Fixed):** The `scp_value.ext` field (Basic vs Signed) is now correctly propagated when computing header hashes.

### Current Issue: Eviction-Related Bucket List Divergence

When replaying ledgers, the bucket_list_hash diverges at the first ledger that triggers evictions:

```
From checkpoint 379903:
- Ledgers 379904-379964: All pass ✓ (0 evictions each)
- Ledger 379965: FAILS ✗ (3 evictions)
```

The eviction scan at ledger 379965 finds 3 entries to archive/evict. This is when the bucket list hash diverges from expected.

**Root Cause (suspected):** The eviction logic may be:
1. Evicting entries that shouldn't be evicted
2. Missing entries that should be evicted  
3. Incorrectly updating the hot archive bucket list
4. Processing evictions in the wrong order relative to other bucket list updates

### Verification Results
- Transactions: All match (results, fee calculations)
- Bucket list hash: Passes until evictions occur (~62 ledgers from checkpoint)
- Header hash: Fails due to bucket_list_hash differences

### Workarounds
1. Use `replay-bucket-list` for short-range bucket list verification
2. Focus on transaction result/meta matching rather than header hash verification
3. Verify single ledgers or ranges without evictions from fresh checkpoints

---
