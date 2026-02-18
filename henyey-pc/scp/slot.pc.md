## Pseudocode: crates/scp/src/slot.rs

"Per-slot consensus state for SCP."
"Each slot represents an independent consensus instance (typically a ledger sequence)."

"Slot Lifecycle:"
"[New] → [Nominating] → [Ballot: Prepare] → [Ballot: Confirm] → [Externalized]"

### Slot (struct)

```
struct Slot:
  slot_index: u64
  local_node_id: NodeId
  local_quorum_set: QuorumSet
  is_validator: bool
  nomination: NominationProtocol
  ballot: BallotProtocol
  envelopes: Map<NodeId, List<Envelope>>
  externalized_value: Value or null
  nomination_started: bool
  fully_validated: bool
  got_v_blocking: bool
```

### new

```
function new(slot_index, local_node_id,
             local_quorum_set, is_validator):
  nomination = new NominationProtocol()
  nomination.set_fully_validated(is_validator)
  ballot = new BallotProtocol()
  ballot.set_fully_validated(is_validator)

  → Slot {
      slot_index, local_node_id, local_quorum_set,
      is_validator, nomination, ballot,
      envelopes = empty map,
      externalized_value = null,
      nomination_started = false,
      fully_validated = is_validator,
      got_v_blocking = false
    }
```

### process_envelope

"Main entry point for processing incoming SCP envelopes for this slot."

```
function process_envelope(envelope, driver):
  node_id = envelope.statement.node_id

  "Check if first message from this node"
  "stellar-core checks getLatestMessage(nodeID) which checks ballot then nomination"
  prev = ballot.latest_envelopes has node_id
      or nomination.get_latest_nomination(node_id)
         is not null

  if envelope.statement.pledges is Nominate:
    result = process_nomination_envelope(envelope, driver)
  else:   NOTE: Prepare, Confirm, Externalize
    result = process_ballot_envelope(envelope, driver)

  if result is valid:
    append envelope to envelopes[node_id]

    "If first valid message from this node, check v-blocking"
    if not prev:
      maybe_set_got_v_blocking()

  check_nomination_to_ballot(driver)

  "Check if we've externalized"
  if ballot.is_externalized()
     and externalized_value is null:
    value = ballot.get_externalized_value()
    if value is not null:
      MUTATE externalized_value = value
      MUTATE fully_validated = true
      nomination.set_fully_validated(true)
      ballot.set_fully_validated(true)
      "Stop all timers when externalized"
      driver.stop_timer(slot_index, Nomination)
      driver.stop_timer(slot_index, Ballot)

  → result
```

**Calls:** [`process_nomination_envelope`](#helper-process_nomination_envelope), [`process_ballot_envelope`](#helper-process_ballot_envelope), [`maybe_set_got_v_blocking`](#helper-maybe_set_got_v_blocking), [`check_nomination_to_ballot`](#helper-check_nomination_to_ballot)

### nominate

```
function nominate(value, prev_value, timedout, driver):
  GUARD not is_validator        → false
  GUARD is_externalized()       → false

  MUTATE nomination_started = true

  ctx = SlotContext(local_node_id,
                    local_quorum_set, driver,
                    slot_index)
  result = nomination.nominate(
             ctx, value, prev_value, timedout)

  "stellar-core sets up nomination timer if nomination is active"
  "and no candidates confirmed yet"
  if nomination.is_started()
     and not nomination.is_stopped()
     and nomination.candidates() is empty:
    round = nomination.round()
    timeout = driver.compute_timeout(round, is_nomination=true)
    driver.setup_timer(slot_index, Nomination, timeout)

  → result
```

**Calls:** [`NominationProtocol::nominate`](nomination.pc.md#nominate)

### stop_nomination

```
function stop_nomination(driver):
  nomination.stop()
  driver.stop_timer(slot_index, Nomination)
```

### bump_ballot_on_timeout

```
function bump_ballot_on_timeout(driver):
  GUARD not is_validator  → false

  driver.timer_expired(slot_index, Ballot)

  composite = nomination.latest_composite()
  ctx = SlotContext(local_node_id,
                    local_quorum_set, driver,
                    slot_index)
  → ballot.bump_timeout(ctx, composite)
```

**Calls:** [`BallotProtocol::bump_timeout`](ballot/mod.pc.md#bump_timeout)

### process_current_state

```
function process_current_state(callback, force_self):
  → nomination.process_current_state(
      callback, local_node_id,
      fully_validated, force_self)
    and
    ballot.process_current_state(
      callback, local_node_id,
      fully_validated, force_self)
```

### force_externalize

"Used during catchup for historical ledgers or fast-forward via EXTERNALIZE messages."

```
function force_externalize(value):
  MUTATE externalized_value = value
  MUTATE fully_validated = true
  nomination.stop()
  nomination.set_fully_validated(true)
  ballot.force_externalize(value)
  ballot.set_fully_validated(true)
```

**Calls:** [`BallotProtocol::force_externalize`](ballot/mod.pc.md#force_externalize)

### set_state_from_envelope

"Restore slot state from a saved envelope (crash recovery)."
"Matches stellar-core Slot::setStateFromEnvelope."

```
function set_state_from_envelope(envelope):
  GUARD envelope.statement.node_id != local_node_id
     or envelope.statement.slot_index != slot_index
    → false

  "Check if first message from this node"
  prev = ballot.latest_envelopes has node_id
      or nomination.get_latest_nomination(node_id)
         is not null

  if envelope.statement.pledges is Nominate:
    result = nomination.set_state_from_envelope(envelope)
  else:   NOTE: Prepare, Confirm, Externalize
    result = ballot.set_state_from_envelope(envelope)
    if result and ballot.is_externalized():
      value = ballot.get_externalized_value()
      if value is not null:
        MUTATE externalized_value = value
        MUTATE fully_validated = true

  if result and not prev:
    maybe_set_got_v_blocking()

  → result
```

**Calls:** [`NominationProtocol::set_state_from_envelope`](nomination.pc.md#set_state_from_envelope), [`BallotProtocol::set_state_from_envelope`](ballot/mod.pc.md#set_state_from_envelope)

### abandon_ballot

```
function abandon_ballot(driver, counter):
  sync_composite_candidate()
  ctx = SlotContext(local_node_id,
                    local_quorum_set, driver,
                    slot_index)
  → ballot.abandon_ballot_public(counter, ctx)
```

**Calls:** [`BallotProtocol::abandon_ballot_public`](ballot/mod.pc.md#abandon_ballot_public)

### bump_state

```
function bump_state(driver, value, counter):
  ctx = SlotContext(local_node_id,
                    local_quorum_set, driver,
                    slot_index)
  → ballot.bump_state(ctx, value, counter)
```

**Calls:** [`BallotProtocol::bump_state`](ballot/mod.pc.md#bump_state)

### force_bump_state

"Counter is auto-computed as current_counter + 1 (or 1)."

```
function force_bump_state(driver, value):
  ctx = SlotContext(local_node_id,
                    local_quorum_set, driver,
                    slot_index)
  → ballot.bump(ctx, value, force=true)
```

**Calls:** [`BallotProtocol::bump`](ballot/mod.pc.md#bump)

### get_latest_messages_send

"Only returns messages if slot is fully validated (matching stellar-core gate)."

```
function get_latest_messages_send():
  GUARD not fully_validated  → empty list

  messages = empty list
  if nomination.get_last_envelope() is not null:
    append it to messages
  if ballot.get_last_envelope() is not null:
    append it to messages
  → messages
```

### get_latest_envelope

"Check ballot protocol first, then nomination. Matches stellar-core Slot::getLatestMessage."

```
function get_latest_envelope(node_id):
  → ballot.latest_envelopes[node_id]
    or nomination.get_latest_nomination(node_id)
```

### get_externalizing_state

```
function get_externalizing_state():
  → ballot.get_externalizing_state(
      local_node_id, fully_validated)
```

### get_statement_values (static)

"Extract all values referenced by a statement."

```
function get_statement_values(statement):
  values = empty list
  if statement.pledges is Nominate(nom):
    append all nom.votes to values
    append all nom.accepted to values
  else if statement.pledges is Prepare(prep):
    if prep.ballot.counter != 0:
      append prep.ballot.value
    if prep.prepared is not null:
      append prep.prepared.value
    if prep.prepared_prime is not null:
      append prep.prepared_prime.value
  else if statement.pledges is Confirm(conf):
    append conf.ballot.value
  else if statement.pledges is Externalize(ext):
    append ext.commit.value
  → values
```

### get_companion_quorum_set_hash_from_statement (static)

```
function get_companion_quorum_set_hash_from_statement(
    statement):
  if Nominate(nom):   → nom.quorum_set_hash
  if Prepare(prep):   → prep.quorum_set_hash
  if Confirm(conf):   → conf.quorum_set_hash
  if Externalize(ext): → ext.commit_quorum_set_hash
```

### get_node_state

"Ballot state takes precedence over nomination state."

```
function get_node_state(node_id):
  ballot_state = ballot.get_node_state(node_id)
  if ballot_state != Missing:
    → ballot_state
  → nomination.get_node_state(node_id)
```

### get_info

"Returns SlotInfo for JSON serialization/debugging."

```
function get_info():
  if externalized_value is not null:
    phase = "EXTERNALIZED"
  else if ballot.phase != Prepare
          or ballot has current ballot:
    phase = "BALLOT"
  else if nomination.is_started():
    phase = "NOMINATION"
  else:
    phase = "IDLE"

  → SlotInfo {
      slot_index, phase, fully_validated,
      nomination = nomination info if started,
      ballot = ballot info if active or externalized
    }
```

### get_quorum_info

```
function get_quorum_info():
  node_states = get_all_node_states()
  responding_nodes = set of nodes where
    state != Missing

  quorum_reached = is_quorum_slice(
    local_quorum_set, responding_nodes)
      REF: quorum::is_quorum_slice
  v_blocking = is_v_blocking(
    local_quorum_set, responding_nodes)
      REF: quorum::is_v_blocking

  → QuorumInfo {
      slot_index, local_node, quorum_set_hash,
      nodes with state and ballot_counter,
      quorum_reached, v_blocking
    }
```

### Helper: maybe_set_got_v_blocking

"Matches stellar-core Slot::maybeSetGotVBlocking()."

```
function maybe_set_got_v_blocking():
  if got_v_blocking:
    return

  all_nodes = get_all_nodes(local_quorum_set)
      REF: quorum::get_all_nodes
  heard_nodes = empty set

  for each node_id in all_nodes:
    "Check ballot protocol first, then nomination"
    if ballot.latest_envelopes has node_id
       or nomination.get_latest_nomination(node_id)
          is not null:
      add node_id to heard_nodes

  MUTATE got_v_blocking = is_v_blocking(
    local_quorum_set, heard_nodes)
      REF: quorum::is_v_blocking
```

### Helper: process_nomination_envelope

```
function process_nomination_envelope(envelope, driver):
  ctx = SlotContext(local_node_id,
                    local_quorum_set, driver,
                    slot_index)
  → nomination.process_envelope(envelope, ctx)
```

**Calls:** [`NominationProtocol::process_envelope`](nomination.pc.md#process_envelope)

### Helper: process_ballot_envelope

```
function process_ballot_envelope(envelope, driver):
  GUARD not ballot.is_statement_sane(
    envelope.statement, local_node_id,
    local_quorum_set, driver)
    → Invalid

  validation = ballot.validate_statement_values(
    envelope.statement, driver, slot_index)
  GUARD validation == Invalid  → Invalid

  if validation == MaybeValid:
    MUTATE fully_validated = false
    nomination.set_fully_validated(false)
    ballot.set_fully_validated(false)

  "Sync composite candidate so abandon_ballot can use it"
  sync_composite_candidate()

  ctx = SlotContext(local_node_id,
                    local_quorum_set, driver,
                    slot_index)
  result = ballot.process_envelope(envelope, ctx)

  "Check if ballot signaled nomination should stop"
  if ballot.take_needs_stop_nomination():
    nomination.stop()
    driver.stop_timer(slot_index, Nomination)

  → result
```

**Calls:** [`BallotProtocol::process_envelope`](ballot/mod.pc.md#process_envelope)

### Helper: check_nomination_to_ballot

"Transition from nomination to ballot protocol when composite value is ready."

```
function check_nomination_to_ballot(driver):
  "If we already have a ballot, don't transition"
  if ballot.current_ballot() is not null:
    return

  composite = nomination.latest_composite()
  if composite is not null:
    "stellar-core does NOT stop nomination here"
    "Nomination continues alongside ballot protocol"
    driver.stop_timer(slot_index, Nomination)
    driver.started_ballot_protocol(slot_index, composite)

    ctx = SlotContext(local_node_id,
                      local_quorum_set, driver,
                      slot_index)
    ballot.bump(ctx, composite, force=false)
```

**Calls:** [`BallotProtocol::bump`](ballot/mod.pc.md#bump)

### Helper: sync_composite_candidate

```
function sync_composite_candidate():
  ballot.set_composite_candidate(
    nomination.latest_composite())
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~944   | ~310       |
| Functions     | 35     | 35         |
