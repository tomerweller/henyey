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

**Status:** Bucket Logic Resolved / Execution Logic Fails
**Severity:** Critical - Prevents ledger closing
**Component:** Bucket List / Transaction Execution
**Last Verified:** 2026-01-14

### Status Update
- **Bucket List Logic**: **RESOLVED**. The `replay-bucket-list` command (which replays authoritative ledger changes from CDP) now produces the correct bucket list hash for ledger 379904. This confirms that the bucket list structure, hashing, deduplication, and metadata logic are now fully aligned with C++ stellar-core.
- **Transaction Execution**: **FAILING**. The `verify-execution` command (which re-executes transactions) produces a hash mismatch. Investigation reveals that the execution engine incorrectly generates an update for `LiveSorobanStateSizeWindow` (ConfigSettingId 12) at this ledger, whereas the authoritative CDP metadata does not. Note: Previous issues with missing `ContractData` timestamps appear to be resolved.

### Investigation Summary & Fixes
An extensive investigation has successfully identified and resolved several critical structural bugs that were contributing to hash divergence:

1.  **Cross-Phase Deduplication (Fixed):** Implemented a `CoalescedLedgerChanges` utility to unify all state changes (Fee, Tx, Post-Fee, Upgrades, Eviction) into a single, unique set per ledger. This mirrors C++ stellar-core's `LedgerDelta` behavior.
2.  **Transient Entry Annihilation (Fixed):** Corrected logic for entries created and deleted in the same ledger (`Init` -> `Dead`).
3.  **Eviction Iterator Parity (Fixed):** Implemented missing local `EvictionIterator` updates.
4.  **Transaction Change Replay (Fixed):** Corrected `tx_changes_before` handling for failed transactions.

### Remaining Work
Investigate why `maybe_snapshot_soroban_state_size_window` triggers an update at ledger 379904 when C++ stellar-core does not. This implies a logic error in the snapshot condition or the underlying state size calculation.

---
