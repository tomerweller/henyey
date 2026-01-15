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

**Status:** Eviction archive fix applied / Still failing at ~184 ledgers from checkpoint
**Severity:** Critical - Prevents live sync after ~184 ledgers from checkpoint
**Component:** Bucket List / Hot Archive
**Last Verified:** 2026-01-14

### Status Update
- **Skip List Logic**: **RESOLVED**. Corrected skip_list semantics - stores bucket_list_hash at intervals 50/5000/50000/500000.
- **Eviction Archive Logic**: **RESOLVED**. Fixed bug where evicted entries weren't being sent to hot archive (was filtering them as "dead").
- **Short/Medium Range Verification**: **WORKS**. Ledgers 379904-380087 (184 ledgers) all pass from checkpoint 379903.
- **Longer Range**: **FAILS**. Ledger 380088+ diverges for unknown reason.

**Impact:** In live catchup mode, this causes the node to compute incorrect ledger header hashes after ~184 ledgers from a checkpoint, preventing consensus with the network.

### Investigation Summary & Fixes

#### Skip List Fix (2026-01-14)
**Critical discovery**: The skip_list stores `bucket_list_hash` values at specific milestone ledgers:
- Skip intervals: SKIP_1=50, SKIP_2=5000, SKIP_3=50000, SKIP_4=500000
- skip_list[0] = bucket_list_hash at last ledger where seq % 50 == 0
- Updates cascade from [0] -> [1] -> [2] -> [3] at higher intervals
- Reference: C++ stellar-core BucketManager::calculateSkipValues()

#### Eviction Archive Fix (2026-01-14)
**Bug fixed**: When looking up entries for hot archive archival, the code was computing `dead_keys` AFTER eviction changes were applied to the aggregator. This caused evicted keys to be filtered out because they were already marked "dead".

**Solution**: Snapshot the aggregator's dead keys BEFORE applying eviction changes (`pre_eviction_dead`), and use this for the filter instead of post-eviction dead keys.

#### Other Fixes
1.  **Cross-Phase Deduplication (Fixed):** Implemented `CoalescedLedgerChanges` utility.
2.  **Transient Entry Annihilation (Fixed):** Corrected `Init` -> `Dead` handling.
3.  **Eviction Iterator Parity (Fixed):** Implemented local `EvictionIterator` updates.
4.  **Transaction Change Replay (Fixed):** Corrected `tx_changes_before` for failed transactions.
5.  **StellarValue Extension (Fixed):** `scp_value.ext` field correctly propagated.

### Current Issue: Bucket List Hash Divergence at ~184 Ledgers

After 184 ledgers from checkpoint 379903, the bucket list hash diverges at ledger 380088. This is NOT related to evictions (there are no evictions at 380088).

**Observations:**
- Checkpoint 379903, replay through 380087: All 184 ledgers PASS
- Ledger 380088: FAILS with bucket list hash mismatch
- Our combined hash: `4ba8bb98...`
- Expected hash: `0021ea62...`
- Our live hash: `75d6e2adf2dff827...`
- Our hot archive: `a31e4626b3f6b5db...`

**Suspected causes:**
1. Merge timing differences between live bucket list and hot archive bucket list
2. Bucket list spill/merge calculation divergence from C++ at specific ledger boundaries
3. Hot archive bucket list state not correctly restored from checkpoint

### Verification Results
- Transactions: All match (results, fee calculations)
- Bucket list hash: Passes up to ~184 ledgers from checkpoint
- Header hash: Fails after 184 ledgers due to bucket_list_hash differences

### Workarounds
1. Use short/medium range verification (< 184 ledgers from checkpoint)
2. Focus on transaction result/meta matching
3. Verify single ledgers or ranges from fresh checkpoints

---
