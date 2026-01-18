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

**Status:** Fixed up to ~180 ledgers from checkpoint / Failing at 380088
**Severity:** Critical - Prevents live sync after ~180 ledgers from checkpoint
**Component:** Bucket List / Hot Archive
**Last Verified:** 2026-01-15

### Status Update
- **Normalization Logic Fixed:** Disabling `INIT -> LIVE` normalization in `add_batch_internal` (L0 -> L1 spills) fixed mismatches at ledgers **380034** and **380080**.
- **Progress:** `replay-bucket-list` now passes for ledgers **380032..380087**.
- **Failure:** Ledger **380088** fails with a hash mismatch. This ledger corresponds to a Level 1 spill (L1 snaps to L2). The mismatch persists regardless of whether normalization is enabled or disabled, suggesting a more subtle issue with merge logic (possibly `shouldMergeWithEmptyCurr` interaction or specific entry type handling).

### Investigation Summary & Fixes
1.  **Cross-Phase Deduplication (Fixed):** Implemented `CoalescedLedgerChanges`.
2.  **Transient Entry Annihilation (Fixed):** Corrected `Init` -> `Dead` logic.
3.  **Eviction Iterator Parity (Fixed):** Implemented local `EvictionIterator` updates.
4.  **Transaction Change Replay (Fixed):** Corrected `tx_changes_before` handling.
5.  **INIT Normalization (Fixed):** Disabled `normalize_init` for level spills, aligning with observed C++ behavior (contrary to some documentation).

### Remaining Work
**Investigate L1 Spill at Ledger 380088.**
Ledger 380088 triggers a Level 1 spill where `L1` snaps and merges into `L2`. This is the first failure encountered after the initial checkpoint restore. Further investigation is needed to determine why the merge result at this specific boundary diverges from consensus.

---

## 3. Bucket List Hash Mismatch at Ledger 8655 (Testnet, P24)

**Status:** Unresolved
**Severity:** High - Blocks execution verification at ledger 8655
**Component:** Bucket List / CDP replay
**Last Verified:** 2026-01-18

### Description
While replaying testnet execution with `offline verify-execution`, ledger 8654 matches, but ledger 8655 diverges on `bucket_list_hash`. The mismatch is isolated to the live bucket list (hot archive hash is unchanged). The issue appears in the newly produced level 0 bucket for ledger 8655.

### Symptoms
- Ledger 8654: `bucket_list_hash` matches expected
- Ledger 8655: header mismatch
  - ours: `fce78763e5a6103d63e040fe83278c4c96636d249ed88dc1f2e01fe7368904d4`
  - expected: `07814e2a937fd444ea62c49d69804508614c79a4624190118bcc1ee0d3bdaa9d`

### Observations
- Protocol version for ledger 8655 is **24** (metaentry `ledger_version=24` is correct).
- L0 bucket we produce at ledger 8655 has **10 entries**: 1 META, 3 Account (LIVE), 2 ContractData nonce (INIT), 1 ContractData persistent (LIVE), 1 ConfigSetting (LIVE), 2 TTL (INIT).
- Entry ordering, XDR serialization, and record-mark hashing match local expectations.
- The generated L0 bucket hash does not exist in the Stellar history archive, implying C++ produces different content (likely INIT/LIVE classification or entry inclusion differences).
- Pre-state check confirms nonce ContractData entries do not exist in the bucket list prior to ledger 8655.

### Hypothesis
Mismatch is likely due to INIT vs LIVE classification of `Created` entries when replaying CDP changes. C++ uses `LedgerTxn` state (`entry.isInit()`), while rs-stellar-core classifies `Created` entries using pre-state bucket list lookups. A subtle difference in transaction-level state (e.g., restored vs created or shadowed/deleted entries) may cause divergent INIT/LIVE tagging at ledger 8655.

### Next Steps
1. A/B test: force all `Created` changes to LIVE for ledger 8655 and compare bucket hash.
2. Dump final coalesced key set (key + INIT/LIVE tag + lastModifiedLedgerSeq) for ledger 8655 for manual comparison.
3. Use `BucketList::find_all_occurrences` to confirm no lingering DELETED/INIT shadows for nonce/TTL keys in older levels before ledger 8655.
