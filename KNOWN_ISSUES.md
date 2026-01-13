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

**Status:** Partially Resolved
**Severity:** Critical - Prevents ledger closing
**Component:** Bucket List / Ledger State
**Last Verified:** 2026-01-13

### Description
The locally computed `bucketListHash` diverges from the network's expected hash, specifically at the transition to ledger 379904 (testnet) on Protocol 25. While the initial state at the checkpoint (379903) is verified to be in perfect sync, the creation of the new L0 bucket in the subsequent ledger produces a different hash than C++ stellar-core.

### Investigation Summary & Fixes
An extensive investigation has successfully identified and resolved several critical structural bugs that were contributing to hash divergence:

1.  **Cross-Phase Deduplication (Fixed):** Implemented a `CoalescedLedgerChanges` utility to unify all state changes (Fee, Tx, Post-Fee, Upgrades, Eviction) into a single, unique set per ledger. This mirrors C++ stellar-core's `LedgerDelta` behavior and prevents duplicate keys from being added to new buckets, which was a primary cause of hash mismatches.

2.  **Transient Entry Annihilation (Fixed):** Corrected the logic for handling entries that are created and then deleted within the same ledger (`Init` -> `Dead`). These "transient" entries are now properly annihilated instead of leaving incorrect tombstones.

3.  **Eviction Iterator Parity (Fixed):** Added the missing local `EvictionIterator` update to both the metadata replay and transaction execution paths. In Protocol 23+, nodes must deterministically scan buckets and update this `ConfigSetting` every ledger. Our implementation now correctly performs this scan, and the resulting iterator values have been verified to match between both paths.

### Remaining Issue
Despite these fixes, a mismatch persists. The divergence has been isolated to the content of the Level 0 `curr` bucket at ledger 379904.

- **CDP Replay vs. Execution**: Detailed XDR dumps show that our execution engine produces different `ContractData` entries for Soroban transactions compared to the authoritative CDP metadata (e.g., missing `write_timestamp` extensions).
- **CDP Replay Failure**: Crucially, even when replaying the "correct" entries directly from CDP metadata, the final hash still does not match the expected network hash.

This indicates the root cause is not just in transaction execution, but likely a subtle, protocol-level detail in how the L0 bucket is constructed or hashed in Protocol 25.

### Next Steps
- Further investigation into the XDR serialization of `BucketMetadata` for Protocol 25.
- A line-by-line comparison of the C++ `Bucket::fresh` and `BucketOutputIterator` logic against our Rust implementation to identify any discrepancies in entry sorting or serialization for new buckets.

---
