## Pseudocode: crates/scp/src/ballot/state_machine.rs

CONST MAX_PROTOCOL_TRANSITIONS = "compile-time limit on recursive transitions"

### advance_slot

"Try to advance the slot state based on received messages."

```
function BallotProtocol.advance_slot(hint, ctx):
  current_message_level += 1
  ASSERT: current_message_level < MAX_PROTOCOL_TRANSITIONS
    "panic: maximum number of transitions reached"

  did_work = false

  did_work = attempt_accept_prepared(hint, ctx) OR did_work
  did_work = attempt_confirm_prepared(hint, ctx) OR did_work
  did_work = attempt_accept_commit(hint, ctx)    OR did_work
  did_work = attempt_confirm_commit(hint, ctx)   OR did_work

  if current_message_level == 1:
    loop:
      bumped = attempt_bump(ctx)
      did_work = bumped OR did_work
      if NOT bumped: break
    check_heard_from_quorum(ctx)

  current_message_level -= 1

  if did_work:
    send_latest_envelope(ctx.driver)
    → ValidNew
  else:
    → Valid
```

**Calls**: [attempt_accept_prepared](#attempt_accept_prepared) | [attempt_confirm_prepared](#attempt_confirm_prepared) | [attempt_accept_commit](#attempt_accept_commit) | [attempt_confirm_commit](#attempt_confirm_commit) | [attempt_bump](#attempt_bump) | [check_heard_from_quorum](statements.pc.md#check_heard_from_quorum) | [send_latest_envelope](envelope.pc.md#send_latest_envelope)

### attempt_accept_prepared

```
function attempt_accept_prepared(hint, ctx):
  GUARD phase NOT in {Prepare, Confirm} → false

  candidates = get_prepare_candidates(hint)

  for each ballot in candidates (descending):
    "In Confirm phase, constrain to compatible with prepared/commit"
    if phase == Confirm:
      if prepared present AND NOT (prepared ≤ ballot AND compatible):
        continue
      if commit present AND NOT compatible(commit, ballot):
        continue

    if prepared_prime present AND ballot ≤ prepared_prime:
      continue

    if prepared present AND ballot ≤ prepared AND compatible:
      continue

    accepted = federated_accept(
      voted: statement_votes_for_ballot(ballot, st),
      accepted: has_prepared_ballot(ballot, st),
      ...)

    if accepted AND set_accept_prepared(ballot, ctx):
      → true

  → false
```

**Calls**: [get_prepare_candidates](statements.pc.md#get_prepare_candidates) | [federated_accept](statements.pc.md#federated_accept) | [set_accept_prepared](#set_accept_prepared)

### set_accept_prepared

```
function set_accept_prepared(ballot, ctx):
  did_work = set_prepared(ballot, driver, slot_index)

  if commit is present:
    GUARD high_ballot is absent → did_work

    incompatible = (prepared present AND
                    high ≤ prepared AND NOT compatible)
                 OR (prepared_prime present AND
                     high ≤ prepared_prime AND NOT compatible)

    if incompatible:
      MUTATE commit = nothing
      did_work = true

  if did_work:
    emit_current_state(ctx)

  → did_work
```

**Calls**: [set_prepared](#set_prepared) | [emit_current_state](envelope.pc.md#emit_current_state)

### attempt_confirm_prepared

```
function attempt_confirm_prepared(hint, ctx):
  GUARD phase != Prepare    → false
  GUARD prepared is absent  → false

  candidates = get_prepare_candidates(hint)

  (new_h, new_h_index) = find_highest_confirmed_prepared(
                            candidates, ctx)
  GUARD not found → false

  new_c = find_lowest_commit_ballot(
            candidates, new_h, new_h_index, ctx)

  → set_confirm_prepared(new_c, new_h, ctx)
```

**Calls**: [find_highest_confirmed_prepared](#find_highest_confirmed_prepared) | [find_lowest_commit_ballot](#find_lowest_commit_ballot) | [set_confirm_prepared](#set_confirm_prepared)

### Helper: find_highest_confirmed_prepared

```
function find_highest_confirmed_prepared(candidates, ctx):
  for each (idx, ballot) in candidates (descending):
    if high_ballot present AND high_ballot >= ballot:
      break

    if federated_ratify(has_prepared_ballot(ballot, st), ...):
      → (ballot, idx)

  → nothing
```

**Calls**: [federated_ratify](statements.pc.md#federated_ratify) | [has_prepared_ballot](statements.pc.md#has_prepared_ballot)

### Helper: find_lowest_commit_ballot

```
function find_lowest_commit_ballot(candidates, new_h,
                                    new_h_index, ctx):
  new_c = (counter: 0, value: new_h.value)

  current = current_ballot OR (0, new_h.value)

  can_set_commit = commit is absent
    AND (prepared absent OR NOT incompatible(new_h, prepared))
    AND (prepared_prime absent OR NOT incompatible(new_h, pp))

  if can_set_commit:
    for each ballot in candidates[..=new_h_index] (descending):
      if ballot < current: break
      if NOT (ballot ≤ new_h AND compatible): continue

      if federated_ratify(has_prepared_ballot(ballot, st), ...):
        new_c = ballot
      else:
        break

  → new_c
```

### set_confirm_prepared

```
function set_confirm_prepared(new_c, new_h, ctx):
  did_work = false
  value_override = new_h.value

  if current_ballot absent OR compatible(current_ballot, new_h):
    if high_ballot absent OR new_h > high_ballot:
      high_ballot = new_h
      did_work = true

    if new_c.counter != 0 AND commit is absent:
      commit = new_c
      did_work = true

  did_work = update_current_if_needed(new_h) OR did_work

  if did_work:
    emit_current_state(ctx)

  → did_work
```

**Calls**: [update_current_if_needed](#update_current_if_needed) | [emit_current_state](envelope.pc.md#emit_current_state)

### attempt_accept_commit

```
function attempt_accept_commit(hint, ctx):
  GUARD phase NOT in {Prepare, Confirm} → false

  ballot = hint_ballot_for_commit(hint)
  GUARD ballot is absent → false

  if phase == Confirm:
    if high_ballot present AND NOT compatible(ballot, high):
      → false

  boundaries = get_commit_boundaries_from_statements(ballot)
  GUARD boundaries is empty → false

  candidate = (0, 0)
  find_extended_interval(candidate, boundaries, interval =>
    federated_accept(
      voted: statement_votes_commit(ballot, interval, st),
      accepted: commit_predicate(ballot, interval, st),
      ...))

  GUARD candidate.low == 0 → false

  if phase != Confirm
     OR candidate.high > high_ballot.counter:
    c = (candidate.low, ballot.value)
    h = (candidate.high, ballot.value)
    → set_accept_commit(c, h, ctx)

  → false
```

**Calls**: [federated_accept](statements.pc.md#federated_accept) | [set_accept_commit](#set_accept_commit)

### set_accept_commit

```
function set_accept_commit(c, h, ctx):
  did_work = false
  value_override = h.value

  if high_ballot != h OR commit != c:
    commit = c
    high_ballot = h
    did_work = true

  if phase == Prepare:
    MUTATE phase = Confirm
    if current_ballot present
       AND NOT (h ≤ current AND compatible):
      bump_to_ballot(h, false)
    prepared_prime = nothing
    did_work = true

  if did_work:
    update_current_if_needed(h)
    emit_current_state(ctx)

  → did_work
```

**Calls**: [bump_to_ballot](#bump_to_ballot) | [emit_current_state](envelope.pc.md#emit_current_state)

### attempt_confirm_commit

```
function attempt_confirm_commit(hint, ctx):
  GUARD phase != Confirm → false
  GUARD high_ballot is absent OR commit is absent → false

  ballot = hint_ballot_for_commit(hint)
  GUARD ballot is absent → false
  GUARD NOT compatible(ballot, commit) → false

  boundaries = get_commit_boundaries_from_statements(ballot)
  candidate = (0, 0)
  find_extended_interval(candidate, boundaries, interval =>
    federated_ratify(
      commit_predicate(ballot, interval, st), ...))

  GUARD candidate.low == 0 → false

  c = (candidate.low, ballot.value)
  h = (candidate.high, ballot.value)
  → set_confirm_commit(c, h, ctx)
```

**Calls**: [federated_ratify](statements.pc.md#federated_ratify) | [set_confirm_commit](#set_confirm_commit)

### set_confirm_commit

```
function set_confirm_commit(c, h, ctx):
  MUTATE commit = c
  MUTATE high_ballot = h
  update_current_if_needed(h)
  MUTATE phase = Externalize

  emit_current_state(ctx)

  "Signal that nomination should be stopped"
  "stellar-core calls mSlot.stopNomination() here"
  needs_stop_nomination = true

  "stellar-core uses c.value for valueExternalized"
  driver.value_externalized(slot_index, c.value)
  → true
```

**Calls**: [emit_current_state](envelope.pc.md#emit_current_state) | [SCPDriver.value_externalized](../driver.pc.md#SCPDriver)

### attempt_bump

```
function attempt_bump(ctx):
  GUARD phase NOT in {Prepare, Confirm} → false

  local_counter = current_ballot.counter OR 0

  GUARD NOT has_vblocking_subset_strictly_ahead_of(
    local_counter, ...) → false

  counters = sorted set of ballot counters
             where counter > local_counter

  for each counter in counters:
    if NOT has_vblocking_subset_strictly_ahead_of(counter, ...):
      → abandon_ballot(counter, ctx)

  → false
```

**Calls**: [has_vblocking_subset_strictly_ahead_of](statements.pc.md#has_vblocking_subset_strictly_ahead_of) | [abandon_ballot](#abandon_ballot)

### abandon_ballot

"Matches stellar-core abandonBallot(n)."
"Checks composite candidate first, falls back to current ballot value."

```
function abandon_ballot(counter, ctx):
  "Priority: composite candidate first, then current ballot value"
  value = composite_candidate (if non-empty)
          OR current_ballot.value

  GUARD value is absent → false

  if counter == 0:
    n = current_ballot.counter + 1 (or 1 if absent)
    → bump_state(ctx, value, n)
  else:
    → bump_state(ctx, value, counter)
```

**Calls**: [bump_state](mod.pc.md#bump_state)

### update_current_if_needed

```
function update_current_if_needed(ballot):
  if current_ballot absent OR current_ballot < ballot:
    → bump_to_ballot(ballot, true)
  → false
```

### update_current_value

"Matches stellar-core updateCurrentValue."
"Checks phase and commit compatibility before bumping."

```
function update_current_value(ballot):
  GUARD phase NOT in {Prepare, Confirm} → false

  if current_ballot is absent:
    bump_to_ballot(ballot, true)
    → true

  if commit present AND NOT compatible(commit, ballot):
    → false

  if current_ballot < ballot:
    bump_to_ballot(ballot, true)
    → true

  → false
```

### bump_to_ballot

"invariant: h.value = b.value"

```
function bump_to_ballot(ballot, check):
  if check:
    if current_ballot present AND ballot ≤ current_ballot:
      → false

  got_bumped = current_ballot absent
               OR current_ballot.counter != ballot.counter

  MUTATE current_ballot = ballot
  MUTATE value = ballot.value

  "invariant: h.value = b.value"
  if high_ballot present AND NOT compatible(ballot, high_ballot):
    MUTATE high_ballot = nothing
    "invariant: c set only when h is set"
    MUTATE commit = nothing

  if got_bumped:
    MUTATE heard_from_quorum = false

  → true
```

### Helper: get_commit_boundaries_from_statements

```
function get_commit_boundaries_from_statements(ballot):
  boundaries = sorted set

  for each envelope in latest_envelopes:
    if Prepare(prep):
      if compatible(ballot, prep.ballot) AND prep.n_c != 0:
        add prep.n_c, prep.n_h

    if Confirm(conf):
      if compatible(ballot, conf.ballot):
        add conf.n_commit, conf.n_h

    if Externalize(ext):
      if compatible(ballot, ext.commit):
        add ext.commit.counter, ext.n_h, MAX_U32

  → boundaries
```

### Helper: find_extended_interval

```
function find_extended_interval(candidate, boundaries, pred):
  for each boundary in boundaries (descending):
    current = if candidate.low == 0:
                (boundary, boundary)
              else if boundary > candidate.high:
                continue
              else:
                (boundary, candidate.high)

    if pred(current):
      candidate = current
    else if candidate.low != 0:
      break
```

### Helper: hint_ballot_for_commit

```
function hint_ballot_for_commit(hint):
  if Prepare(prep):
    if prep.n_c != 0: → (prep.n_h, prep.ballot.value)
    → nothing
  if Confirm(conf):     → (conf.n_h, conf.ballot.value)
  if Externalize(ext):  → (ext.n_h, ext.commit.value)
  → nothing
```

### Helper: set_prepared

"Set prepared ballot."

```
function set_prepared(ballot, driver, slot_index):
  did_work = false

  if prepared is present:
    if prepared < ballot:
      if NOT compatible(prepared, ballot):
        prepared_prime = prepared
      prepared = ballot
      did_work = true
    else if prepared > ballot:
      should_update_prime =
        prepared_prime absent
        OR (prepared_prime < ballot
            AND NOT compatible(prepared, ballot))
      if should_update_prime:
        prepared_prime = ballot
        did_work = true
    "if equal: no change"
  else:
    prepared = ballot
    did_work = true

  if did_work:
    driver.ballot_did_prepare(slot_index, ballot)

  → did_work
```

**Calls**: [SCPDriver.ballot_did_prepare](../driver.pc.md#SCPDriver)

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 755    | 280        |
| Functions    | 20     | 20         |
