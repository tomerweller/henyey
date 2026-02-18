## Pseudocode: crates/scp/src/ballot/mod.rs

"The ballot protocol is the second phase of SCP consensus, following the
nomination phase. After nomination produces a composite value, nodes use
the ballot protocol to achieve Byzantine agreement on that exact value."

"A ballot <n, x> consists of:
- n: A counter (increases on timeout to try new ballots)
- x: The consensus value
Ballots with the same value but different counters are 'compatible'.
The protocol ensures only compatible ballots can be committed."

```
CONST MAX_PROTOCOL_TRANSITIONS = 50
  // Max state transitions per advance_slot call; exceeding indicates a bug
```

### State Machine: BallotPhase

```
STATE_MACHINE: BallotPhase
  STATES: [Prepare, Confirm, Externalize]
  TRANSITIONS:
    Prepare  → Confirm:     accept-commit achieved
    Confirm  → Externalize: confirm-commit achieved (terminal)
```

### State: BallotProtocol

"Following the SCP whitepaper notation:
- b: Current ballot we're working on
- p: Highest prepared ballot
- p': Second-highest prepared ballot (if incompatible with p)
- h: Highest ballot we can confirm prepared
- c: Commit ballot (lowest ballot we can commit)"

```
STATE: BallotProtocol
  current_ballot   : Ballot or null     // b in whitepaper
  prepared         : Ballot or null     // p — highest prepared
  prepared_prime   : Ballot or null     // p' — second-highest prepared, incompatible with p
  high_ballot      : Ballot or null     // h — highest confirmable
  commit           : Ballot or null     // c — commit ballot
  phase            : BallotPhase        // starts at Prepare
  latest_envelopes : Map<NodeId, Envelope>
  value            : Value or null
  value_override   : Value or null      // set when confirming prepared/commit
  composite_candidate : Value or null   // latest from nomination
  heard_from_quorum : bool              // default false
  current_message_level : int           // recursion depth for advance_slot
  last_envelope    : Envelope or null   // last envelope we constructed
  last_envelope_emit : Envelope or null // last envelope we emitted
  fully_validated  : bool               // default true
  needs_stop_nomination : bool          // signal to stop nomination
```

---

### new

```
function new() → BallotProtocol:
  → BallotProtocol with all fields at defaults
    phase = Prepare
    fully_validated = true
    all others null / empty / false / 0
```

---

### get_externalized_value

```
function get_externalized_value() → Value or null:
  if phase == Externalize:
    → value
  → null
```

---

### force_externalize

"Used when fast-forwarding via EXTERNALIZE messages from the network."

```
function force_externalize(value):
  ballot = Ballot(counter=UINT32_MAX, value=value)
  MUTATE commit      = ballot
  MUTATE high_ballot = ballot
  MUTATE current_ballot = ballot
  MUTATE value       = value
  MUTATE phase       = Externalize
```

---

### get_externalizing_state

"Matches stellar-core BallotProtocol::getExternalizingState():
- Only returns envelopes when in EXTERNALIZE phase
- For other nodes: only includes envelopes with ballots compatible with commit
- For self: only includes if fully_validated is true"

```
function get_externalizing_state(local_node_id, fully_validated)
    → list of Envelope:
  GUARD phase != Externalize     → empty list
  GUARD commit is null           → empty list

  result = []
  for each (node_id, envelope) in latest_envelopes:
    if node_id != local_node_id:
      working = get_working_ballot(envelope.statement)
      if working exists and ballot_compatible(working, commit):
        append envelope to result
    else if fully_validated:
      append envelope to result
  → result
```

**Calls**: [`get_working_ballot`](statements.pc.md#get_working_ballot), [`ballot_compatible`](statements.pc.md#ballot_compatible)

---

### check_invariants

```
function check_invariants() → ok or error:
  "In PREPARE phase, c != 0 ⇒ h != 0"
  if phase == Prepare and commit is set:
    GUARD high_ballot is null → error "commit set but high_ballot not"

  "prepared_prime must be < prepared and incompatible"
  if prepared and prepared_prime both set:
    GUARD ballot_compare(prepared_prime, prepared) != Less
        → error "prepared_prime must be less than prepared"
    GUARD ballot_compatible(prepared_prime, prepared)
        → error "prepared_prime must be incompatible with prepared"

  "c <= h with same value"
  if commit and high_ballot both set:
    GUARD commit.counter > high_ballot.counter
        → error "commit counter exceeds high counter"
    GUARD commit.value != high_ballot.value
        → error "commit and high have different values"

  "In EXTERNALIZE, must have commit and high"
  if phase == Externalize:
    GUARD commit is null or high_ballot is null
        → error "externalize requires commit and high"

  → ok
```

**Calls**: [`ballot_compare`](statements.pc.md#ballot_compare), [`ballot_compatible`](statements.pc.md#ballot_compatible)

---

### bump

"Start the ballot protocol with a value from nomination."

```
function bump(ctx, value, force) → bool:
  GUARD not force and current_ballot is set → false

  if current_ballot is set:
    counter = current_ballot.counter + 1
  else:
    counter = 1

  → bump_state(ctx, value, counter)
```

**Calls**: [bump_state](#bump_state)

---

### bump_timeout

"Matches stellar-core ballotProtocolTimerExpired → abandonBallot(0) flow."

```
function bump_timeout(ctx, composite_candidate) → bool:
  MUTATE self.composite_candidate = composite_candidate
  → abandon_ballot(0, ctx)
```

**Calls**: [`abandon_ballot`](state_machine.pc.md#abandon_ballot)

---

### process_envelope

"Process a ballot protocol envelope."

```
function process_envelope(envelope, ctx) → EnvelopeState:
  node_id = envelope.statement.node_id

  NOTE: Only accept Prepare, Confirm, or Externalize pledges
  GUARD pledge type not in {Prepare, Confirm, Externalize}
      → Invalid

  GUARD not is_newer_statement(node_id, envelope.statement)
      → Invalid

  if phase == Externalize:
    if statement_value_matches_commit(envelope.statement):
      store envelope in latest_envelopes[node_id]
      → Valid
    → Invalid

  store envelope in latest_envelopes[node_id]
  → advance_slot(envelope.statement, ctx)
```

**Calls**: [`is_newer_statement`](statements.pc.md#is_newer_statement), [statement_value_matches_commit](#statement_value_matches_commit), [`advance_slot`](state_machine.pc.md#advance_slot)

---

### statement_value_matches_commit

```
function statement_value_matches_commit(statement) → bool:
  GUARD commit is null → false

  if statement is Prepare:
    → commit.value == statement.ballot.value
  if statement is Confirm:
    → commit.value == statement.ballot.value
  if statement is Externalize:
    → commit.value == statement.commit.value
  → false
```

---

### collect_hint_ballots

"Extract candidate ballots from a hint statement for prepare/confirm scanning."

```
function collect_hint_ballots(hint) → list of Ballot:
  ballots = []

  if hint is Prepare:
    append hint.ballot
    if hint.prepared exists:
      append hint.prepared
    if hint.prepared_prime exists:
      append hint.prepared_prime

  if hint is Confirm:
    append Ballot(counter=hint.n_prepared, value=hint.ballot.value)
    append Ballot(counter=UINT32_MAX, value=hint.ballot.value)

  if hint is Externalize:
    append Ballot(counter=UINT32_MAX, value=hint.commit.value)

  → ballots
```

---

### set_state_from_envelope

"Restore state from a saved envelope (for crash recovery)."

```
function set_state_from_envelope(envelope) → bool:

  if envelope is Prepare(prep):
    MUTATE current_ballot = prep.ballot
    MUTATE prepared       = prep.prepared
    MUTATE prepared_prime = prep.prepared_prime
    if prep.n_c != 0:
      MUTATE commit = Ballot(counter=prep.n_c, value=prep.ballot.value)
    if prep.n_h != 0:
      MUTATE high_ballot = Ballot(counter=prep.n_h, value=prep.ballot.value)
    MUTATE value = prep.ballot.value
    MUTATE phase = Prepare
    store envelope in latest_envelopes and last_envelope
    → true

  if envelope is Confirm(conf):
    MUTATE current_ballot = conf.ballot
    MUTATE prepared = Ballot(counter=conf.n_prepared, value=conf.ballot.value)
    MUTATE prepared_prime = null
    MUTATE commit = Ballot(counter=conf.n_commit, value=conf.ballot.value)
    MUTATE high_ballot = Ballot(counter=conf.n_h, value=conf.ballot.value)
    MUTATE value = conf.ballot.value
    MUTATE phase = Confirm
    store envelope in latest_envelopes and last_envelope
    → true

  if envelope is Externalize(ext):
    MUTATE commit = ext.commit
    MUTATE high_ballot = Ballot(counter=ext.n_h, value=ext.commit.value)
    MUTATE current_ballot = Ballot(counter=UINT32_MAX, value=ext.commit.value)
    "stellar-core sets mPrepared = makeBallot(UINT32_MAX, v)"
    MUTATE prepared = Ballot(counter=UINT32_MAX, value=ext.commit.value)
    MUTATE value = ext.commit.value
    MUTATE phase = Externalize
    store envelope in latest_envelopes and last_envelope
    → true

  → false
```

---

### bump_state

"Bump the ballot to a specific counter value."

```
function bump_state(ctx, value, counter) → bool:
  GUARD phase not in {Prepare, Confirm} → false

  if value_override is set:
    "Use the value that we saw confirmed prepared
     or that we at least voted to commit to"
    effective_value = value_override
  else:
    effective_value = value

  ballot = Ballot(counter=counter, value=effective_value)
  updated = update_current_value(ballot)

  if updated:
    emit_current_state(ctx)
    check_heard_from_quorum(ctx)

  → updated
```

**Calls**: [`update_current_value`](state_machine.pc.md#update_current_value), [`emit_current_state`](envelope.pc.md#emit_current_state), [`check_heard_from_quorum`](state_machine.pc.md#check_heard_from_quorum)

---

### abandon_ballot_public

```
function abandon_ballot_public(counter, ctx) → bool:
  → abandon_ballot(counter, ctx)
```

**Calls**: [`abandon_ballot`](state_machine.pc.md#abandon_ballot)

---

### take_needs_stop_nomination

```
function take_needs_stop_nomination() → bool:
  val = needs_stop_nomination
  MUTATE needs_stop_nomination = false
  → val
```

---

### process_current_state

```
function process_current_state(callback, local_node_id,
    fully_validated, force_self) → bool:
  → delegate to process_envelopes_current_state(
      latest_envelopes, callback, local_node_id,
      fully_validated, force_self)
```

**Calls**: `REF: crate::process_envelopes_current_state`

---

### get_node_state

```
function get_node_state(node_id) → QuorumInfoNodeState:
  if latest_envelopes contains node_id:
    → QuorumInfoNodeState from envelope pledges
  → Missing
```

---

## Summary

| Metric        | Source (prod) | Pseudocode |
|---------------|---------------|------------|
| Lines (logic) | ~831          | ~200       |
| Functions     | 25            | 17         |

NOTE: 8 trivial getter/setter functions (`phase`, `current_ballot`, `current_ballot_counter`,
`prepared`, `commit`, `is_externalized`, `set_composite_candidate`, `set_fully_validated`,
`heard_from_quorum`, `high_ballot`, `prepared_prime`, `value`, `get_last_envelope`,
`get_latest_envelope`, `get_node_count`, `get_local_state`, `get_state_string`, `get_info`,
`latest_envelopes`) are omitted from pseudocode as they are direct field accessors or
debug formatting with no decision logic.

Core ballot protocol logic (advance_slot, abandon_ballot, update_current_value,
emit_current_state, check_heard_from_quorum, set_accept_prepare, set_confirm_prepare,
set_accept_commit, set_confirm_commit) lives in the submodule files:
- [`state_machine.pc.md`](state_machine.pc.md)
- [`envelope.pc.md`](envelope.pc.md)
- [`statements.pc.md`](statements.pc.md)
