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

## 2. Auth Sequence Errors with Peers

**Status:** Unresolved
**Severity:** Medium - Causes peer disconnections
**Component:** Overlay

### Description
Peers disconnect with "unexpected auth sequence" errors shortly after authentication.

### Symptoms
- Peer authenticates successfully
- Within seconds, peer sends ERROR with "unexpected auth sequence"
- Peer disconnects

### Example Log Pattern
```
INFO  Authenticated with peer GCIU45Y5BYUV5AWKFOWV5V7AN4CW5TADON7S6SGXJ43TZIBKRP45DQVW
INFO  Accepted peer: GCIU45Y5BYUV5AWKFOWV5V7AN4CW5TADON7S6SGXJ43TZIBKRP45DQVW
WARN  Peer GCIU45Y5... sent ERROR: code=Auth, msg=unexpected auth sequence
INFO  Peer GCIU45Y5... disconnected
```

### Potential Causes
- Sequence number mismatch in authenticated messages
- MAC verification failure
- Message ordering issue

---

## 3. Out-of-Sync Peer Disconnections

**Status:** Expected Behavior (consequence of Issue #1)
**Severity:** Low
**Component:** Overlay

### Description
Peers disconnect the node with "random disconnect due to out of sync" when the node falls too far behind the network.

### Symptoms
- Peer sends ERROR: `code=Load, msg=random disconnect due to out of sync`
- Happens when node is many ledgers behind

### Root Cause
This is expected C++ stellar-core behavior. Peers disconnect nodes that are significantly behind to avoid wasting resources. This is a consequence of Issue #1, not a separate bug.

---

## 4. heard_from_quorum=false Persistent Warning

**Status:** Unresolved
**Severity:** Medium - Indicates consensus issues
**Component:** Herder / SCP

### Description
The node continuously reports that it has not heard from its quorum, even while receiving SCP messages.

### Symptoms
- Heartbeat shows `heard_from_quorum=false`
- Warning: "Have not heard from quorum - may be experiencing network partition"
- Occurs despite processing valid SCP envelopes

### Example Log Pattern
```
INFO  Heartbeat tracking_slot=430445 ledger=430400 latest_ext=430444 peers=1 heard_from_quorum=false is_v_blocking=false
WARN  Have not heard from quorum - may be experiencing network partition
```

### Potential Causes
- Quorum intersection calculation not considering all received envelopes
- Timing issue - quorum check runs before envelopes are fully processed
- Related to the out-of-sync state from Issue #1

---

## Recently Fixed Issues

### Invalid SCP Envelope Warnings After Fast-Forward (Fixed)

**Fix:** Added `force_externalize` to SCP library and call it when fast-forwarding via EXTERNALIZE

When fast-forwarding via EXTERNALIZE messages from the network, the SCP library was not informed about the externalization. Subsequent envelopes for the same slot were marked Invalid because the ballot protocol didn't know the slot was already externalized.

**Root Cause:**
- When receiving EXTERNALIZE for a future slot, the herder recorded the externalization in `scp_driver`
- But the SCP library's slot/ballot state was never updated
- When more envelopes arrived for that slot, the ballot protocol rejected them because values didn't match the (unset) commit value

**Solution:**
- Added `BallotProtocol::force_externalize(value)` to set the ballot to Externalize phase
- Added `Slot::force_externalize(value)` calls the ballot's method
- Herder now calls `scp.force_externalize(slot, value)` when fast-forwarding

---

### SCP Envelope "Too Old" Rejection After Catchup (Fixed)

**Commit:** 632bcba
**Fix:** Added `MAX_SLOTS_TO_REMEMBER = 12` constant and window-based envelope acceptance

After catchup, SCP envelopes within a 12-slot window of the tracking slot are now accepted instead of being rejected as "too old". This matches C++ stellar-core behavior.
