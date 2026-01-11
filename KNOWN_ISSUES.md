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

## 2. Ledger Header Hash Mismatch (Critical)

**Status:** Unresolved
**Severity:** Critical - Prevents ledger closing
**Component:** Ledger Manager / Transaction Execution
**First Observed:** 2026-01-11

### Description
After catching up from history archives, the node's locally computed ledger header hash does not match the network's expected `prev_ledger_hash`. This prevents the node from closing new ledgers and participating in consensus.

### Symptoms
- Node catches up successfully to a checkpoint ledger
- When attempting to close the next ledger, hash mismatch error occurs
- Repeated ERROR logs: "Hash mismatch - our computed header hash differs from network's prev_ledger_hash"
- Node clears buffered ledgers and may trigger re-catchup
- Node state shows "Synced" but cannot advance ledgers

### Example Log Pattern
```
ERROR Hash mismatch - our computed header hash differs from network's prev_ledger_hash
      current_seq=432512 close_seq=432513
      our_hash=33cc2081dafcb857bf397fe67aa967bada5f14d3f1d60e2d3d33a6dce322cb47
      network_prev_hash=90f6e2ce99bf44f1cb9b966ab9ecf3be5660cc24c4d274312781ad64d9b2c155
      header_version=25
      header_bucket_list_hash=2854f44500d9400832aee9e63ede64401a7899c1d90490702063b47a0f686610
      header_tx_result_hash=74ae054c8f35c9ad2f7b960401ea316b3599b9a0e8dbaf2d07270cf464abf6de
      header_total_coins=1000000000000000000
      header_fee_pool=67689576225
      header_close_time=1768156899
      header_tx_set_hash=9a32a70d3195e3ce797952e0e912cf4583be56495550af3485343a81630a5a3b
      header_upgrades_count=0

ERROR Failed to apply buffered ledger ledger_seq=432513
      error=internal error: Failed to begin close: ledger hash mismatch

WARN  Hash mismatch detected - cleared all buffered ledgers, will trigger catchup
```

### Root Cause Analysis
The ledger header hash is computed from multiple components:
1. `ledgerVersion` - Protocol version
2. `previousLedgerHash` - Hash of prior ledger header
3. `scpValue` - SCP consensus value (close time, tx set hash, upgrades)
4. `txSetResultHash` - Merkle root of transaction results
5. `bucketListHash` - Hash of the bucket list state
6. `ledgerSeq` - Ledger sequence number
7. `totalCoins` - Total lumens in existence
8. `feePool` - Accumulated fees
9. `inflationSeq` - Inflation sequence (deprecated)
10. `idPool` - ID pool counter
11. `baseFee` / `baseReserve` - Network parameters
12. `maxTxSetSize` - Max transactions per ledger
13. `skipList` - Recent header hashes for verification

Potential sources of divergence:
- **Bucket list hash mismatch**: State from catchup may differ from network state due to:
  - Incorrect bucket application order
  - Missing or incorrect handling of DEADENTRY markers
  - Hot archive bucket state divergence
- **Transaction result hash mismatch**: Transaction execution produces different results:
  - Fee calculation differences
  - Operation result encoding differences
  - State changes not matching C++ stellar-core
- **Fee pool divergence**: Accumulated fees computed differently
- **Protocol upgrade handling**: Upgrade application timing/logic differs

### Investigation Steps
1. Compare bucket list hash at catchup checkpoint vs network expectation
2. Verify transaction execution parity with C++ stellar-core for specific ledger
3. Check fee calculation and accumulation logic
4. Verify ledger header XDR serialization matches upstream format

### Related Files
- `crates/stellar-core-ledger/src/manager.rs` - Ledger header computation
- `crates/stellar-core-ledger/src/header.rs` - Header hash calculation
- `crates/stellar-core-bucket/` - Bucket list management
- `crates/stellar-core-tx/` - Transaction execution

---

## 3. Auth Sequence Errors with Peers (Resolved)

**Status:** Resolved
**Severity:** Medium - Caused peer disconnections
**Component:** Overlay

### Description
Peers disconnected with "unexpected auth sequence" errors shortly after authentication.

### Resolution
Fixed in auth.rs codec improvements. The issue was related to MAC computation and sequence number handling in the overlay authentication protocol.

### Previous Symptoms
- Peer authenticates successfully
- Within seconds, peer sends ERROR with "unexpected auth sequence"
- Peer disconnects

### Verification
As of 2026-01-11, testnet connections show stable peer connectivity with 3 peers and no auth sequence errors. SCP envelopes are being processed as valid from all connected validators.

---

## 4. Out-of-Sync Peer Disconnections

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

## 5. heard_from_quorum=false Persistent Warning

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
