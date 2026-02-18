## Pseudocode: crates/app/src/app/consensus.rs

### try_trigger_consensus

"Matches stellar-core's triggerNextLedger() gate: only propose when
the node is tracking the network AND the ledger manager is synced
(LCL == tracking slot)."

```
GUARD herder.is_tracking() → return

current_ledger = read current_ledger
tracking_slot = herder.tracking_slot()

"stellar-core's isSynced() checks:
 lastClosedLedger + 1 == trackingConsensusLedgerIndex"
GUARD current_ledger + 1 >= tracking_slot
  → return (not synced, LCL behind tracking slot)

next_slot = current_ledger + 1

"Record local close time for drift tracking
 before triggering consensus."
local_time = system_time_unix_seconds()
drift_tracker.record_local_close_time(
  next_slot, local_time)

herder.trigger_next_ledger(next_slot)
```

**Calls**: [herder.trigger_next_ledger](../../herder/herder.pc.md#trigger_next_ledger)

### out_of_sync_recovery

"Performs out-of-sync recovery matching stellar-core's
outOfSyncRecovery(). Broadcasts recent SCP messages to peers
and requests SCP state."

"Tracks consecutive recovery attempts without ledger progress.
After RECOVERY_ESCALATION_SCP_REQUEST attempts (~30s) we actively
request SCP state. After RECOVERY_ESCALATION_CATCHUP attempts
(~60s) we trigger a full catchup."

```
latest_externalized = herder.latest_externalized_slot()
last_processed = read last_processed_slot
pending_tx_sets = herder.get_pending_tx_sets()
buffer_count = syncing_ledgers.len()
gap = latest_externalized - current_ledger

"Track consecutive recovery attempts without progress"
baseline = recovery_baseline_ledger
if current_ledger > baseline:
  "Progress! Reset the counter."
  recovery_baseline_ledger = current_ledger
  recovery_attempts_without_progress = 0
attempts = atomic_fetch_add(
  recovery_attempts_without_progress, 1)

"Clean up stale pending tx_set requests for slots
 we've already closed."
stale_cleared = herder.cleanup_old_pending_tx_sets(
  current_ledger + 1)
if stale_cleared > 0:
  clear tx_set_dont_have
  clear tx_set_last_request
  clear tx_set_exhausted_warned
  tx_set_all_peers_exhausted = false

"--- Escalation: force catchup after many attempts ---"
if attempts >= RECOVERY_ESCALATION_CATCHUP:
  clear syncing_ledgers buffer
  herder.clear_pending_tx_sets()
  clear all tx_set tracking state
  recovery_attempts_without_progress = 0

  if not catchup_in_progress (atomic swap):
    set_state(CatchingUp)
    herder.set_state(Syncing)
    catchup_message_handle =
      start_catchup_message_caching_from_self()
    catchup_result = catchup(CatchupTarget::Current)
    abort catchup_message_handle
    catchup_in_progress = false
    handle_catchup_result(catchup_result,
      force=true, "RecoveryEscalation")
  → return

"When essentially caught up (small or zero gap),
 do NOT request SCP state from peers."
if gap <= TX_SET_REQUEST_WINDOW:
  "Clear unfulfillable syncing_ledgers entries"
  syncing_ledgers.retain where
    seq > current_ledger AND tx_set exists
  herder.clear_pending_tx_sets()

  if attempts < RECOVERY_ESCALATION_SCP_REQUEST:
    "Wait for fresh EXTERNALIZE"
    → return

  "Escalation: request SCP state despite small gap"
  NOTE: falls through to SCP state request below

"Detect gaps in externalized slots"
next_slot = current_ledger + 1
if latest_externalized > next_slot:
  missing_slots = herder.find_missing_slots_in_range(
    next_slot, latest_externalized)

  if missing_slots not empty:
    if next_slot in missing_slots:
      "Next slot permanently missing — peers have evicted
       this slot's data from their caches."
      catchup_target = latest_externalized
        - TX_SET_REQUEST_WINDOW
      target_checkpoint = checkpoint_containing(
        catchup_target)    REF: henyey_history::checkpoint

      if target_checkpoint > latest_externalized:
        "Target checkpoint not yet published —
         request SCP state instead of archive catchup"
        NOTE: falls through to SCP state request
      else:
        "Trigger catchup to skip gap"
        syncing_ledgers.retain where
          seq > current_ledger AND tx_set exists
        maybe_start_externalized_catchup(
          latest_externalized)
        → return

"Broadcast recent SCP envelopes + request state"
from_slot = current_ledger - 5
(envelopes, _quorum_set) = herder.get_scp_state(
  from_slot)

GUARD overlay available → return
GUARD overlay.peer_count() > 0 → return

"Spawn background task (don't block main loop)"
spawn:
  for each envelope (concurrently):
    overlay.broadcast(ScpMessage(envelope))

  overlay.request_scp_state(current_ledger)
```

**Calls**: [catchup](catchup_impl.pc.md#catchup) | [handle_catchup_result](catchup_impl.pc.md#handle_catchup_result) | [maybe_start_externalized_catchup](catchup_impl.pc.md#maybe_start_externalized_catchup) | [start_catchup_message_caching_from_self](catchup_impl.pc.md#start_catchup_message_caching_from_self)

### send_scp_state

"Send SCP state to a peer in response to GetScpState."

```
(envelopes, quorum_set) = herder.get_scp_state(
  from_ledger)

GUARD overlay available → return

if quorum_set exists:
  overlay.send_to(peer_id, ScpQuorumset(qs))

for each envelope in envelopes:
  overlay.send_to(peer_id, ScpMessage(envelope))
  if send fails → break (channel full)
```

### send_quorum_set

"Respond to a GetScpQuorumset message."

```
GUARD overlay available → return

qs = herder.get_quorum_set_by_hash(requested_hash)
if qs found:
  overlay.send_to(peer_id, ScpQuorumset(qs))
else:
  overlay.send_to(peer_id, DontHave(
    type=ScpQuorumset, hash=requested_hash))
```

### handle_quorum_set

"Store a quorum set received from a peer."

```
hash = hash_quorum_set(quorum_set)   REF: henyey_scp::hash_quorum_set

node_ids = herder.get_pending_quorum_set_node_ids(hash)

db.store_scp_quorum_set(
  hash, current_ledger_seq, quorum_set)

if node_ids not empty:
  for each node_id in node_ids:
    herder.store_quorum_set(node_id, quorum_set)

herder.clear_quorum_set_request(hash)
```

### Helper: scp_quorum_set_hash

```
given statement pledges:
  Nominate   → nom.quorum_set_hash
  Prepare    → prep.quorum_set_hash
  Confirm    → conf.quorum_set_hash
  Externalize → ext.commit_quorum_set_hash
```

### Helper: tx_hash

```
→ Hash256.hash_xdr(tx_envelope)
```

### build_scp_history_entry

```
envelopes = herder.get_scp_envelopes(ledger_seq)
GUARD envelopes not empty → none

"Collect unique quorum set hashes from envelopes"
qset_hashes = set()
for each envelope in envelopes:
  hash = scp_quorum_set_hash(envelope.statement)
  if hash exists: qset_hashes.add(hash)

sort hashes by hex string

"Resolve all quorum sets by hash"
qsets = []
for each hash in sorted_hashes:
  qs = herder.get_quorum_set_by_hash(hash)
  GUARD qs found → none (missing quorum set)
  append qs

→ ScpHistoryEntry.V0 {
    quorum_sets: qsets,
    ledger_messages: { ledger_seq, envelopes }
  }
```

**Calls**: [scp_quorum_set_hash](#helper-scp_quorum_set_hash)

### check_scp_timeouts

```
GUARD is_validator → return
GUARD herder.state().can_receive_scp() → return

slot = herder.tracking_slot()
now = current_time()

timeouts = read scp_timeouts
if timeouts.slot != slot:
  "New slot — reset timeout state"
  timeouts.slot = slot
  timeouts.next_nomination = none
  timeouts.next_ballot = none

"Nomination timeout"
if next_nomination is set AND now >= next_nomination:
  herder.handle_nomination_timeout(slot)
  next_nomination = none
if next_nomination not set:
  timeout = herder.get_nomination_timeout(slot)
  if timeout exists:
    next_nomination = now + timeout

"Ballot timeout"
if next_ballot is set AND now >= next_ballot:
  herder.handle_ballot_timeout(slot)
  next_ballot = none
if next_ballot not set:
  timeout = herder.get_ballot_timeout(slot)
  if timeout exists:
    next_ballot = now + timeout
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~578   | ~200       |
| Functions     | 10     | 10         |
