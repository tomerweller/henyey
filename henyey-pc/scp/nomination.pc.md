## Pseudocode: crates/scp/src/nomination.rs

"Nomination protocol — first phase of SCP consensus."
"Nodes propose and vote on candidate values. Goal: produce confirmed candidates for ballot protocol."

"Value Progression:"
"[Proposed] → vote → [Voted] → accept → [Accepted] → ratify → [Candidate]"

"Nomination statements are monotonic: a newer statement must contain"
"all values from previous statements plus at least one new value."

### NominationProtocol (struct)

```
struct NominationProtocol:
  round: u32
  votes: List<Value>
  accepted: List<Value>
  candidates: List<Value>
  started: bool
  stopped: bool
  latest_composite: Value or null
  previous_value: Value or null
  timer_exp_count: u32
  latest_nominations: Map<NodeId, Envelope>
  round_leaders: Set<NodeId>
  last_envelope: Envelope or null
  last_envelope_emit: Envelope or null
  fully_validated: bool
```

### nominate

```
function nominate(ctx, value, prev_value, timedout):
  GUARD stopped  → false

  "No need to continue if we already have candidates"
  GUARD candidates is not empty  → false

  if timedout:
    timer_exp_count += 1
    GUARD not started  → false

  MUTATE started = true
  MUTATE previous_value = prev_value
  MUTATE round += 1

  update_round_leaders(ctx, prev_value)

  updated = adopt_leader_values(ctx)
  updated = vote_as_leader(ctx, value) or updated

  if updated:
    emit_nomination(ctx)

  → updated
```

**Calls:** [`update_round_leaders`](#helper-update_round_leaders), [`adopt_leader_values`](#helper-adopt_leader_values), [`vote_as_leader`](#helper-vote_as_leader), [`emit_nomination`](#helper-emit_nomination)

### process_envelope

```
function process_envelope(envelope, ctx):
  node_id = envelope.statement.node_id

  GUARD pledges is not Nominate  → Invalid
  nomination = envelope.pledges.Nominate

  GUARD not is_newer_nomination_internal(
    node_id, nomination)                  → Invalid
  GUARD not is_sane_statement(nomination) → Invalid

  "Store the envelope"
  latest_nominations[node_id] = envelope

  state_changed = false

  if started:
    votes_to_check = nomination.votes

    (modified, new_candidates) = attempt_promote(
      votes_to_check, ctx.local_quorum_set,
      ctx.driver, ctx.slot_index)

    "N13: adopt leader votes only if no candidates yet"
    if candidates is empty
       and node_id in round_leaders:
      new_vote = get_new_value_from_nomination(
        nomination, ctx.driver, ctx.slot_index)
      if new_vote is not null:
        if insert_unique(votes, new_vote):
          modified = true
          ctx.driver.nominating_value(
            ctx.slot_index, new_vote)

    "stellar-core order: emit first, then composite"
    if modified:
      emit_nomination(ctx)
      state_changed = true

    if new_candidates:
      update_composite(ctx.driver, ctx.slot_index)
      state_changed = true

  → ValidNew if state_changed, else Valid
```

**Calls:** [`attempt_promote`](#helper-attempt_promote), [`emit_nomination`](#helper-emit_nomination), [`update_composite`](#helper-update_composite), [`get_new_value_from_nomination`](#helper-get_new_value_from_nomination)

### stop

"Matches stellar-core stopNomination() which sets mNominationStarted = false."

```
function stop():
  MUTATE stopped = true
  MUTATE started = false
```

### set_state_from_envelope

"Restore nomination state from a saved envelope (crash recovery)."
"stellar-core throws if mNominationStarted is true."
"Does NOT set mNominationStarted = true."

```
function set_state_from_envelope(envelope):
  GUARD started  → false
  GUARD pledges is not Nominate  → false

  nomination = envelope.pledges.Nominate
  MUTATE votes = nomination.votes
  MUTATE accepted = nomination.accepted

  latest_nominations[envelope.node_id] = envelope
  MUTATE last_envelope = envelope
  → true
```

### is_newer_statement

```
function is_newer_statement(node_id, statement):
  GUARD statement.pledges is not Nominate  → false
  → is_newer_nomination_internal(
      node_id, statement.pledges.Nominate)
```

### process_current_state

```
function process_current_state(callback,
    local_node_id, fully_validated, force_self):
  → process_envelopes_current_state(
      latest_nominations, callback,
      local_node_id, fully_validated, force_self)
```

### Helper: attempt_promote

"Core acceptance/ratification logic. Called from process_envelope and emit_nomination."
"Matches stellar-core where emitNomination() calls processEnvelope(self)."

```
function attempt_promote(votes_to_check,
    local_quorum_set, driver, slot_index):
  modified = false
  new_candidates = false

  "Phase 1: promote votes → accepted"
  for each value in votes_to_check:
    if value in accepted:
      continue
    if not should_accept_value(
        value, local_quorum_set, driver):
      continue

    validation = driver.validate_value(
      slot_index, value, nomination=true)

    if validation == FullyValidated:
      if insert_unique(accepted, value):
        insert_unique(votes, value)
        modified = true

    else if validation == MaybeValid:
      extracted = driver.extract_valid_value(
        slot_index, value)
      if extracted is not null:
        if insert_unique(votes, extracted):
          modified = true

  "Phase 2: promote accepted → candidates"
  for each value in accepted (copy):
    if value in candidates:
      continue
    if should_ratify_value(
        value, local_quorum_set, driver):
      if insert_unique(candidates, value):
        new_candidates = true
        "N12: stop nomination timer"
        driver.stop_timer(slot_index, Nomination)

  → (modified, new_candidates)
```

**Calls:** [`should_accept_value`](#helper-should_accept_value), [`should_ratify_value`](#helper-should_ratify_value)

### Helper: emit_nomination

"Matches stellar-core emitNomination() which creates self-envelope then"
"calls processEnvelope(self) to re-run acceptance/ratification."
"This can cascade: if acceptance modifies state, we emit again."

```
function emit_nomination(ctx):
  votes_sorted = sorted_values(votes)
  accepted_sorted = sorted_values(accepted)

  nomination = Nomination {
    quorum_set_hash = hash(ctx.local_quorum_set),
    votes = votes_sorted,
    accepted = accepted_sorted
  }
  statement = Statement {
    node_id = ctx.local_node_id,
    slot_index = ctx.slot_index,
    pledges = Nominate(nomination)
  }
  envelope = create and sign envelope

  "Step 1: record self-envelope"
  if not record_local_nomination(
      ctx.local_node_id, statement, envelope):
    return

  "Step 2: self-processing (may recurse)"
  if started:
    (modified, new_candidates) = attempt_promote(
      votes_sorted, ctx.local_quorum_set,
      ctx.driver, ctx.slot_index)

    if modified:
      "Cascade: recursive emit_nomination"
      emit_nomination(ctx)

    if new_candidates:
      update_composite(ctx.driver, ctx.slot_index)

  "Step 3: check if still newer than last_envelope"
  "stellar-core: if (!mLastEnvelope || isNewerStatement(...))"
  is_newer = (last_envelope is null) or
    is_newer_nomination(last_envelope.nom, nomination)

  if is_newer:
    MUTATE last_envelope = envelope
    if fully_validated
       and last_envelope_emit != envelope:
      MUTATE last_envelope_emit = envelope
      ctx.driver.emit_envelope(envelope)
```

### Helper: adopt_leader_values

```
function adopt_leader_values(ctx):
  updated = false
  for each leader in round_leaders:
    env = latest_nominations[leader]
    if env is null:
      continue
    nom = env.pledges.Nominate
    new_vote = get_new_value_from_nomination(
      nom, ctx.driver, ctx.slot_index)
    if new_vote is not null:
      if insert_unique(votes, new_vote):
        updated = true
        ctx.driver.nominating_value(
          ctx.slot_index, new_vote)
  → updated
```

### Helper: vote_as_leader

"Handles upgrade timeout logic: if too many timeouts and all votes have upgrades,"
"strips upgrades before voting (stellar-core lines 597-651)."

```
function vote_as_leader(ctx, value):
  GUARD ctx.local_node_id not in round_leaders
    → false

  over_limit = timer_exp_count >=
    ctx.driver.get_upgrade_nomination_timeout_limit()

  should_vote = false
  vote_value = value

  if votes is empty:
    should_vote = true

  if over_limit:
    all_have_upgrades = all votes have upgrades
      (via driver.has_upgrades)
    if all_have_upgrades:
      stripped = driver.strip_all_upgrades(vote_value)
      if stripped is not null and stripped != vote_value:
        vote_value = stripped
      should_vote = true

  if should_vote:
    validation = driver.validate_value(
      ctx.slot_index, vote_value, nomination=true)
    if validation != Invalid:
      if insert_unique(votes, vote_value):
        ctx.driver.nominating_value(
          ctx.slot_index, vote_value)
        → true

  → false
```

### Helper: should_accept_value

"Accept if v-blocking set accepts, or quorum has voted-or-accepted."

```
function should_accept_value(value,
    local_quorum_set, driver, slot_index):
  voters = nodes with value in nom.votes
  acceptors = nodes with value in nom.accepted
  supporters = voters union acceptors

  → is_blocking_set(local_quorum_set, acceptors)
    or is_quorum(local_quorum_set, supporters,
                 driver.get_quorum_set)
```

**Calls:** [`is_blocking_set`](quorum.pc.md#is_blocking_set), [`is_quorum`](quorum.pc.md#is_quorum)

### Helper: should_ratify_value

"Ratify (confirm) if quorum has accepted."

```
function should_ratify_value(value,
    local_quorum_set, driver):
  acceptors = nodes with value in nom.accepted
  → is_quorum(local_quorum_set, acceptors,
               driver.get_quorum_set)
```

**Calls:** [`is_quorum`](quorum.pc.md#is_quorum)

### Helper: get_new_value_from_nomination

"Pick the best value from a leader's nomination that we haven't voted for yet."
"Prefers accepted values; falls back to votes only if no valid accepted found."

```
function get_new_value_from_nomination(
    nomination, driver, slot_index):
  best = null
  found_valid = false

  function consider(value):
    candidate = null
    if driver.validate_value(slot_index, value,
         nomination=true) == FullyValidated:
      candidate = value
    else if validation == MaybeValid:
      candidate = driver.extract_valid_value(
        slot_index, value)

    if candidate is not null:
      "stellar-core sets foundValidValue = true"
      found_valid = true
      if candidate in votes:
        return    NOTE: skip already-voted values
      hash = hash_value(driver, slot_index, candidate)
      if best is null or hash >= best.hash:
        best = (hash, candidate)

  for each value in nomination.accepted:
    consider(value)

  "Only check votes if no valid accepted value found"
  if not found_valid:
    for each value in nomination.votes:
      consider(value)

  → best.value (or null)
```

### Helper: update_round_leaders

"Compute leaders for current round based on priority hash."
"stellar-core normalizes quorum set removing self, then finds highest-priority nodes."

```
function update_round_leaders(ctx, prev_value):
  normalized_qs = copy of ctx.local_quorum_set
  normalize_quorum_set_with_remove(
    normalized_qs, ctx.local_node_id)
      REF: quorum::normalize_quorum_set_with_remove

  max_leader_count = 1 + count_all_nodes(normalized_qs)

  while round_leaders.length < max_leader_count:
    new_leaders = empty set
    top_priority = get_node_priority(normalized_qs,
      driver, slot_index, prev_value,
      ctx.local_node_id, ctx.local_node_id)
    add ctx.local_node_id to new_leaders

    for each node in all_nodes(normalized_qs):
      priority = get_node_priority(normalized_qs,
        driver, slot_index, prev_value,
        ctx.local_node_id, node)
      if priority > top_priority:
        top_priority = priority
        clear new_leaders
      if priority == top_priority and priority > 0:
        add node to new_leaders

    if top_priority == 0:
      clear new_leaders

    old_size = round_leaders.length
    round_leaders = round_leaders union new_leaders
    if round_leaders.length != old_size:
      return    NOTE: found new leaders

    "No new leaders found, bump round and retry"
    round += 1
```

### Helper: get_node_priority

"Two-phase priority: first check weight threshold, then compute priority hash."

```
function get_node_priority(local_quorum_set,
    driver, slot_index, prev_value,
    local_node_id, node_id):
  is_local = (node_id == local_node_id)
  weight = base_get_node_weight(
    node_id, local_quorum_set, is_local)
      REF: driver::base_get_node_weight
  if weight == 0:
    → 0

  hash = driver.compute_hash_node(
    slot_index, prev_value,
    is_priority=false, round, node_id)
  if hash <= weight:
    → driver.compute_hash_node(
        slot_index, prev_value,
        is_priority=true, round, node_id)
  else:
    → 0
```

### Helper: update_composite

```
function update_composite(driver, slot_index):
  GUARD candidates is empty  → return

  composite = driver.combine_candidates(
    slot_index, candidates)
  if composite is not null
     and latest_composite != composite:
    driver.updated_candidate_value(
      slot_index, composite)
    MUTATE latest_composite = composite
```

### Helper: is_newer_nomination

"Monotonicity check: new nomination must be a strict superset."

```
function is_newer_nomination(old_nom, new_nom):
  old_votes = set(old_nom.votes)
  old_accepted = set(old_nom.accepted)
  new_votes = set(new_nom.votes)
  new_accepted = set(new_nom.accepted)

  votes_grew = old_votes ⊆ new_votes
               and |old_votes| < |new_votes|
  accepted_grew = old_accepted ⊆ new_accepted
                  and |old_accepted| < |new_accepted|

  → (old_votes ⊆ new_votes
     and old_accepted ⊆ new_accepted)
    and (votes_grew or accepted_grew)
```

### Helper: is_sane_statement

```
function is_sane_statement(nomination):
  GUARD votes is empty and accepted is empty
    → false
  → is_sorted_unique(votes)
    and is_sorted_unique(accepted)
```

## Summary

| Metric        | Source  | Pseudocode |
|---------------|---------|------------|
| Lines (logic) | ~1004   | ~320       |
| Functions     | 30      | 30         |
