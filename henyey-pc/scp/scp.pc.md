## Pseudocode: crates/scp/src/scp.rs

"Main SCP implementation coordinating consensus across multiple slots."
"SCP owns a map of slots, keyed by slot index (ledger sequence number)."
"Each Slot contains independent nomination and ballot protocol state."
"The SCPDriver provides application-specific callbacks."

```
CONST DEFAULT_MAX_SLOTS = 100
```

### SCP (struct)

```
struct SCP:
  local_node_id: NodeId
  is_validator: bool
  local_quorum_set: QuorumSet
  slots: Map<u64, Slot>         // concurrent read/write
  driver: Driver
  max_slots: int
```

### new

```
function new(node_id, is_validator, quorum_set, driver):
  → SCP {
      local_node_id = node_id,
      is_validator = is_validator,
      local_quorum_set = quorum_set,
      slots = empty map,
      driver = driver,
      max_slots = DEFAULT_MAX_SLOTS
    }
```

### receive_envelope

"Main entry point for processing SCP messages received from the network."

```
function receive_envelope(envelope):
  GUARD not driver.verify_envelope(envelope)  → Invalid

  slot_index = envelope.statement.slot_index
  slot = slots.get_or_create(slot_index,
           new_slot(slot_index, local_node_id,
                    local_quorum_set, is_validator))

  result = slot.process_envelope(envelope, driver)

  if slots.count > max_slots:
    cleanup_old_slots(slots)

  → result
```

**Calls:** [`Slot::process_envelope`](slot.pc.md#process_envelope), [`cleanup_old_slots`](#helper-cleanup_old_slots)

### nominate

"Start nomination process for a slot."

```
function nominate(slot_index, value, prev_value):
  GUARD not is_validator  → false

  slot = slots.get_or_create(slot_index,
           new_slot(slot_index, local_node_id,
                    local_quorum_set, is_validator))

  → slot.nominate(value, prev_value,
                   timeout=false, driver)
```

**Calls:** [`Slot::nominate`](slot.pc.md#nominate)

### nominate_timeout

"Called when nomination timer expires without reaching consensus."

```
function nominate_timeout(slot_index, value, prev_value):
  GUARD not is_validator  → false

  slot = slots.get(slot_index)
  GUARD slot is null  → false

  → slot.nominate(value, prev_value,
                   timeout=true, driver)
```

**Calls:** [`Slot::nominate`](slot.pc.md#nominate)

### stop_nomination

```
function stop_nomination(slot_index):
  slot = slots.get(slot_index)
  if slot is not null:
    slot.stop_nomination(driver)
```

**Calls:** [`Slot::stop_nomination`](slot.pc.md#stop_nomination)

### bump_ballot

"Called when ballot timer expires. Increases ballot counter to try to make progress."

```
function bump_ballot(slot_index):
  slot = slots.get(slot_index)
  GUARD slot is null  → false
  → slot.bump_ballot_on_timeout(driver)
```

**Calls:** [`Slot::bump_ballot_on_timeout`](slot.pc.md#bump_ballot_on_timeout)

### ballot_protocol_timer_expired

```
function ballot_protocol_timer_expired(slot_index):
  → delegate_to(bump_ballot, slot_index)
```

### get_externalized_value

```
function get_externalized_value(slot_index):
  slot = slots.get(slot_index)
  GUARD slot is null  → null
  → slot.get_externalized_value()
```

### is_slot_externalized

```
function is_slot_externalized(slot_index):
  slot = slots.get(slot_index)
  → slot is not null and slot.is_externalized()
```

### is_slot_fully_validated

```
function is_slot_fully_validated(slot_index):
  slot = slots.get(slot_index)
  → slot is not null and slot.is_fully_validated()
```

### force_externalize

"Used during catchup when applying historical ledgers."

```
function force_externalize(slot_index, value):
  slot = slots.get_or_create(slot_index,
           new_slot(slot_index, local_node_id,
                    local_quorum_set, is_validator))
  slot.force_externalize(value)
```

**Calls:** [`Slot::force_externalize`](slot.pc.md#force_externalize)

### purge_slots

"Remove old slots to free memory. Matches stellar-core SCP::purgeSlots."

```
function purge_slots(max_slot_index, slot_to_keep):
  for each (slot_index, _) in slots:
    if slot_index < max_slot_index
       and slot_index != slot_to_keep:
      remove slot_index from slots
```

### got_v_blocking

"Check if we've heard from a v-blocking set for a slot."

```
function got_v_blocking(slot_index):
  slot = slots.get(slot_index)
  GUARD slot is null  → false
  → slot.got_v_blocking()
```

### get_cumulative_statement_count

```
function get_cumulative_statement_count():
  → sum of slot.get_statement_count()
    for each slot in slots.values
```

### get_latest_messages_send

```
function get_latest_messages_send(slot_index):
  slot = slots.get(slot_index)
  GUARD slot is null  → empty list
  → slot.get_latest_messages_send()
```

### process_slots_ascending_from

```
function process_slots_ascending_from(from_slot, callback):
  indices = sorted(slot_index for slot_index in slots.keys
                   where slot_index >= from_slot)
  for each slot_index in indices:
    if not callback(slot_index):
      → false
  → true
```

### process_slots_descending_from

```
function process_slots_descending_from(from_slot, callback):
  indices = reverse_sorted(slot_index for slot_index in slots.keys
                           where slot_index <= from_slot)
  for each slot_index in indices:
    if not callback(slot_index):
      → false
  → true
```

### get_latest_message

"Get the latest message from a specific node across all slots."

```
function get_latest_message(node_id):
  latest = null
  latest_index = 0

  for each (slot_index, slot) in slots:
    env = slot.get_latest_envelope(node_id)
    if env is not null and slot_index > latest_index:
      latest = env
      latest_index = slot_index

  → latest
```

### get_externalizing_state

```
function get_externalizing_state(slot_index):
  slot = slots.get(slot_index)
  GUARD slot is null  → empty list
  → slot.get_externalizing_state()
```

### get_slot_state

```
function get_slot_state(slot_index):
  slot = slots.get(slot_index)
  GUARD slot is null  → null
  → SlotState {
      slot_index,
      is_externalized = slot.is_externalized(),
      is_nominating = slot.is_nominating(),
      heard_from_quorum = slot.heard_from_quorum(),
      ballot_phase = slot.ballot_phase(),
      nomination_round = slot.nomination().round(),
      ballot_round = slot.ballot_counter()
    }
```

### set_state_from_envelope

"Restore state from a saved envelope (for crash recovery)."

```
function set_state_from_envelope(envelope):
  slot_index = envelope.statement.slot_index
  slot = slots.get_or_create(slot_index,
           new_slot(slot_index, local_node_id,
                    local_quorum_set, is_validator))
  → slot.set_state_from_envelope(envelope)
```

**Calls:** [`Slot::set_state_from_envelope`](slot.pc.md#set_state_from_envelope)

### abandon_ballot

```
function abandon_ballot(slot_index, counter):
  slot = slots.get(slot_index)
  GUARD slot is null  → false
  → slot.abandon_ballot(driver, counter)
```

**Calls:** [`Slot::abandon_ballot`](slot.pc.md#abandon_ballot)

### bump_state

"Bump the ballot for a slot to a specific counter value."

```
function bump_state(slot_index, value, counter):
  slot = slots.get_or_create(slot_index,
           new_slot(slot_index, local_node_id,
                    local_quorum_set, is_validator))
  → slot.bump_state(driver, value, counter)
```

**Calls:** [`Slot::bump_state`](slot.pc.md#bump_state)

### force_bump_state

"Force-bump ballot state. Counter is auto-computed as current_counter + 1 (or 1)."

```
function force_bump_state(slot_index, value):
  slot = slots.get_or_create(slot_index,
           new_slot(slot_index, local_node_id,
                    local_quorum_set, is_validator))
  → slot.force_bump_state(driver, value)
```

**Calls:** [`Slot::force_bump_state`](slot.pc.md#force_bump_state)

### get_missing_nodes

"Returns nodes in our quorum set we haven't heard from for a slot."

```
function get_missing_nodes(slot_index):
  all_nodes = get_all_nodes(local_quorum_set)
      REF: quorum::get_all_nodes
  slot = slots.get(slot_index)
  if slot is null:
    → all_nodes

  heard_from = set of keys from
               slot.ballot().latest_envelopes
  → all_nodes - heard_from
```

### is_newer_statement

"Check if a statement is newer than what we have for that node."

```
function is_newer_statement(slot_index, statement):
  slot = slots.get(slot_index)
  if slot is null:
    → true    NOTE: no slot means any statement is "newer"

  if statement.pledges is Nominate:
    → slot.nomination().is_newer_statement(
        statement.node_id, statement)
  else:
    → slot.ballot().is_newer_statement(
        statement.node_id, statement)
```

### get_scp_state

"Return envelopes for slots from from_slot onward. Used to respond to GetScpState peer requests."

```
function get_scp_state(from_slot):
  envelopes = empty list
  indices = sorted(slot_index for slot_index in slots.keys
                   where slot_index >= from_slot)

  for each slot_index in indices:
    slot = slots.get(slot_index)
    slot.process_current_state(
      callback: append envelope to envelopes,
      include_self_when_not_validated = false)

  → envelopes
```

**Calls:** [`Slot::process_current_state`](slot.pc.md#process_current_state)

### get_entire_current_state

"Get ALL current envelopes for a slot, including self even when not fully validated."
"Matches stellar-core getEntireCurrentState() / getCurrentEnvelope() pattern."

```
function get_entire_current_state(slot_index):
  envelopes = empty list
  slot = slots.get(slot_index)
  if slot is not null:
    slot.process_current_state(
      callback: append envelope to envelopes,
      include_self_when_not_validated = true)
  → envelopes
```

### get_quorum_info_for_node

```
function get_quorum_info_for_node(slot_index, node_id):
  slot = slots.get(slot_index)
  GUARD slot is null  → null

  nom_state = slot.nomination().get_node_state(node_id)
  if nom_state != Missing:
    → NodeInfo { state = nom_state }

  ballot_state = slot.ballot().get_node_state(node_id)
  ballot_counter = extract counter from
    slot.ballot().latest_envelopes[node_id]
    (Prepare → ballot.counter,
     Confirm → ballot.counter,
     Externalize → commit.counter)

  → NodeInfo { state = ballot_state,
               ballot_counter }
```

### Helper: cleanup_old_slots

```
function cleanup_old_slots(slots):
  GUARD slots.count <= max_slots  → return

  indices = sorted(slots.keys)
  to_remove = indices.length - max_slots

  for each index in first to_remove of indices:
    remove index from slots
```

### SlotState (struct)

```
struct SlotState:
  slot_index: u64
  is_externalized: bool
  is_nominating: bool
  heard_from_quorum: bool
  ballot_phase: BallotPhase
  nomination_round: u32
  ballot_round: u32 or null
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~930   | ~260       |
| Functions     | 33     | 33         |
