## Pseudocode: crates/scp/src/ballot/statements.rs

### is_newer_statement

```
function BallotProtocol.is_newer_statement(node_id, statement):
  existing = latest_envelopes[node_id]
  if existing is absent:
    → true
  → is_newer_statement_pair(existing.statement, statement)
```

### Helper: is_newer_statement_pair

```
function is_newer_statement_pair(old, new):
  old_rank = pledge_rank(old.pledges)
  new_rank = pledge_rank(new.pledges)

  if old_rank != new_rank:
    → old_rank < new_rank

  if both Externalize:
    → false

  if both Confirm:
    compare ballots (old_c.ballot vs new_c.ballot):
      if Less    → true
      if Greater → false
      if Equal:
        if old_c.n_prepared == new_c.n_prepared:
          → old_c.n_h < new_c.n_h
        else:
          → old_c.n_prepared < new_c.n_prepared

  if both Prepare:
    compare ballots (old_p.ballot vs new_p.ballot):
      Less → true, Greater → false
    compare opt_ballot(old_p.prepared vs new_p.prepared):
      Less → true, Greater → false
    compare opt_ballot(old_p.prepared_prime vs new_p.prepared_prime):
      Less → true, Greater → false
      Equal → old_p.n_h < new_p.n_h

  → false
```

### Helper: pledge_rank

```
function pledge_rank(pledges):
  Prepare     → 0
  Confirm     → 1
  Externalize → 2
  other       → 3
```

### is_statement_sane

```
function BallotProtocol.is_statement_sane(statement,
    local_node_id, local_quorum_set, driver):

  quorum_set = statement_quorum_set(statement, ...)
  GUARD quorum_set is absent         → false
  GUARD is_quorum_set_sane(quorum_set) fails → false

  if Prepare(prep):
    is_self = statement.node_id == local_node_id
    GUARD NOT is_self AND prep.ballot.counter == 0 → false

    if prepared_prime AND prepared both present:
      GUARD prepared_prime NOT < prepared    → false
      GUARD prepared_prime compatible w/ prepared → false

    if prep.n_h != 0:
      GUARD prepared is absent               → false
      GUARD prep.n_h > prepared.counter      → false

    if prep.n_c != 0:
      GUARD prep.n_h == 0                    → false
      GUARD ballot.counter < n_h OR n_h < n_c → false

  if Confirm(conf):
    GUARD conf.ballot.counter == 0           → false
    GUARD conf.n_h > conf.ballot.counter     → false
    GUARD conf.n_commit > conf.n_h           → false

  if Externalize(ext):
    GUARD ext.commit.counter == 0            → false
    GUARD ext.n_h < ext.commit.counter       → false

  → true
```

**Calls**: [statement_quorum_set](#statement_quorum_set) | [is_quorum_set_sane](../quorum.pc.md#is_quorum_set_sane)

### validate_statement_values

```
function BallotProtocol.validate_statement_values(statement,
                                                   driver, slot_index):
  values = statement_values(statement)
  GUARD values is empty → Invalid

  level = FullyValidated
  for each value in values:
    next = driver.validate_value(slot_index, value, false)
    level = min_validation_level(level, next)
    if level == Invalid:
      break
  → level
```

**Calls**: [SCPDriver.validate_value](../driver.pc.md#SCPDriver)

### Helper: statement_quorum_set

```
function statement_quorum_set(statement, local_node_id,
                               local_quorum_set, driver):
  if Externalize:
    → simple_quorum_set(1, [statement.node_id])
  if Prepare(prep):
    hash = prep.quorum_set_hash
    → resolve_quorum_set(hash, statement.node_id, ...)
  if Confirm(conf):
    hash = conf.quorum_set_hash
    → resolve_quorum_set(hash, statement.node_id, ...)
  → nothing
```

**Calls**: [simple_quorum_set](../quorum.pc.md#simple_quorum_set) | [resolve_quorum_set](#resolve_quorum_set)

### Helper: resolve_quorum_set

"Resolve a quorum set from its hash, checking local, hash cache, then node lookup."

```
function resolve_quorum_set(provided_hash, node_id,
                             local_node_id, local_quorum_set,
                             driver):
  if node_id == local_node_id:
    expected = hash_quorum_set(local_quorum_set)
    if expected == provided_hash:
      → local_quorum_set

  if driver.get_quorum_set_by_hash(provided_hash) succeeds:
    → that quorum_set

  qset = driver.get_quorum_set(node_id)
  if qset is present:
    expected = hash_quorum_set(qset)
    if expected == provided_hash:
      → qset

  → nothing
```

### get_prepare_candidates

```
function BallotProtocol.get_prepare_candidates(hint):
  hint_ballots = collect_hint_ballots(hint)
  sort hint_ballots by ballot order

  candidates = []
  seen = set

  for each top_vote in hint_ballots (descending):
    for each envelope in latest_envelopes:
      if Prepare(prep):
        if prep.ballot ≤ top_vote AND compatible:
          add prep.ballot to candidates (dedup)
        if prep.prepared ≤ top_vote AND compatible:
          add prep.prepared to candidates (dedup)
        if prep.prepared_prime ≤ top_vote AND compatible:
          add prep.prepared_prime to candidates (dedup)

      if Confirm(conf):
        if top_vote compatible with conf.ballot:
          add top_vote to candidates (dedup)
          if conf.n_prepared < top_vote.counter:
            add (conf.n_prepared, top_vote.value) (dedup)

      if Externalize(ext):
        if top_vote compatible with ext.commit:
          add top_vote to candidates (dedup)

  sort candidates by ballot order
  → candidates
```

### commit_predicate

```
function BallotProtocol.commit_predicate(ballot, interval,
                                          statement):
  if Confirm(conf):
    if compatible(ballot, conf.ballot):
      → conf.n_commit ≤ interval.low
        AND interval.high ≤ conf.n_h
    → false

  if Externalize(ext):
    if compatible(ballot, ext.commit):
      → ext.commit.counter ≤ interval.low
    → false

  → false
```

### statement_ballot_counter

```
function statement_ballot_counter(statement):
  if Prepare(prep): → prep.ballot.counter
  if Confirm(conf): → conf.ballot.counter
  if Externalize:   → MAX_U32
  → 0
```

### has_vblocking_subset_strictly_ahead_of

```
function has_vblocking_subset_strictly_ahead_of(counter,
    local_node_id, local_quorum_set, driver):

  nodes = set of node_ids where
    statement_ballot_counter(envelope.statement) > counter

  → is_blocking_set(local_quorum_set, nodes)
    AND statement_quorum_set_map is not empty
```

**Calls**: [is_blocking_set](../quorum.pc.md#is_blocking_set)

### federated_accept

```
function BallotProtocol.federated_accept(voted_pred,
    accepted_pred, local_node_id, local_quorum_set, driver):

  accepted_nodes = set
  supporters = set

  for each (node_id, envelope) in latest_envelopes:
    if accepted_pred(statement):
      add to accepted_nodes AND supporters
    else if voted_pred(statement):
      add to supporters

  if is_blocking_set(local_quorum_set, accepted_nodes):
    → true

  qsets = statement_quorum_set_map(...)
  → is_quorum(local_quorum_set, supporters, qsets)
```

**Calls**: [is_blocking_set](../quorum.pc.md#is_blocking_set) | [is_quorum](../quorum.pc.md#is_quorum)

### federated_ratify

```
function BallotProtocol.federated_ratify(voted_pred,
    local_node_id, local_quorum_set, driver):

  supporters = set of node_ids where
    voted_pred(envelope.statement)

  qsets = statement_quorum_set_map(...)
  → is_quorum(local_quorum_set, supporters, qsets)
```

**Calls**: [is_quorum](../quorum.pc.md#is_quorum)

### statement_votes_for_ballot

```
function statement_votes_for_ballot(ballot, statement):
  if Prepare(prep): → ballot ≤ prep.ballot AND compatible
  if Confirm(conf): → compatible(ballot, conf.ballot)
  if Externalize(ext): → compatible(ballot, ext.commit)
  → false
```

### statement_votes_commit

```
function statement_votes_commit(ballot, interval, statement):
  if Prepare(prep):
    if compatible(ballot, prep.ballot) AND prep.n_c != 0:
      → prep.n_c ≤ interval.low AND interval.high ≤ prep.n_h
    → false

  if Confirm(conf):
    → compatible(ballot, conf.ballot)
      AND conf.n_commit ≤ interval.low

  if Externalize(ext):
    → compatible(ballot, ext.commit)
      AND ext.commit.counter ≤ interval.low

  → false
```

### has_prepared_ballot

```
function has_prepared_ballot(ballot, statement):
  if Prepare(prep):
    → (prep.prepared present AND ballot ≤ prep.prepared
       AND compatible)
    OR (prep.prepared_prime present AND ballot ≤ prep.prepared_prime
        AND compatible)

  if Confirm(conf):
    prepared = (conf.n_prepared, conf.ballot.value)
    → ballot ≤ prepared AND compatible

  if Externalize(ext):
    → compatible(ballot, ext.commit)

  → false
```

### check_heard_from_quorum

```
function BallotProtocol.check_heard_from_quorum(ctx):
  GUARD current_ballot is absent → return

  nodes = set
  quorum_sets = map

  for each (node_id, envelope) in latest_envelopes:
    include = false
    if Prepare(prep):
      include = current.counter ≤ prep.ballot.counter
    if Confirm or Externalize:
      include = true
    if NOT include: continue

    add node_id to nodes
    resolve and store quorum_set

  if is_quorum(local_quorum_set, nodes, quorum_sets):
    old = heard_from_quorum
    heard_from_quorum = true
    if NOT old:
      driver.ballot_did_hear_from_quorum(slot_index, current)
      if phase != Externalize:
        timeout = driver.compute_timeout(current.counter, false)
        driver.setup_timer(slot_index, Ballot, timeout)
    if phase == Externalize:
      driver.stop_timer(slot_index, Ballot)
  else:
    heard_from_quorum = false
    driver.stop_timer(slot_index, Ballot)
```

**Calls**: [is_quorum](../quorum.pc.md#is_quorum) | [SCPDriver.setup_timer](../driver.pc.md#SCPDriver) | [SCPDriver.stop_timer](../driver.pc.md#SCPDriver)

### get_working_ballot

"Extract the 'working ballot' from an SCP statement."

```
function get_working_ballot(statement):
  if Prepare(prep):     → prep.ballot
  if Confirm(conf):     → (conf.n_commit, conf.ballot.value)
  if Externalize(ext):  → (MAX_U32, ext.commit.value)
  if Nominate:          → nothing
```

### Helper: min_validation_level

```
function min_validation_level(left, right):
  if either is Invalid     → Invalid
  if either is MaybeValid  → MaybeValid
  → FullyValidated
```

### Helper: ballot_compare

```
function ballot_compare(a, b):
  → compare(a.counter, b.counter)
      then compare(a.value, b.value)
```

### Helper: cmp_opt_ballot

```
function cmp_opt_ballot(a, b):
  if both absent:  → Equal
  if a absent:     → Less
  if b absent:     → Greater
  → ballot_compare(a, b)
```

### Helper: ballot_compatible

```
function ballot_compatible(a, b):
  → a.value == b.value
```

### Helper: are_ballots_less_and_compatible

```
function are_ballots_less_and_compatible(a, b):
  → ballot_compare(a, b) != Greater AND compatible(a, b)
```

### Helper: are_ballots_less_and_incompatible

```
function are_ballots_less_and_incompatible(a, b):
  → ballot_compare(a, b) != Greater AND NOT compatible(a, b)
```

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 626    | 215        |
| Functions    | 22     | 22         |
