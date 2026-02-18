## Pseudocode: crates/scp/src/ballot/envelope.rs

### send_latest_envelope

```
function BallotProtocol.send_latest_envelope(driver):
  GUARD current_message_level != 0     → return
  GUARD NOT fully_validated            → return
  GUARD last_envelope is absent        → return
  GUARD last_envelope == last_envelope_emit → return

  last_envelope_emit = last_envelope
  driver.emit_envelope(last_envelope)
```

**Calls**: [SCPDriver.emit_envelope](../driver.pc.md#emit_envelope)

### emit_prepare

"Build and record a prepare statement envelope."
"When current_ballot is absent (pristine state), a PREPARE with"
"ballot = {0, ''} is still created and recorded as a self-envelope."
"This matches stellar-core emitCurrentStateStatement which always"
"calls createStatement() and processEnvelope(self), even when"
"mCurrentBallot is null. The self-envelope is needed so the local"
"node counts itself in subsequent quorum calculations."
"However, the envelope is NOT emitted to the network when"
"current_ballot is absent (matching stellar-core canEmit)."

```
function BallotProtocol.emit_prepare(ctx):
  can_emit = current_ballot is present
  ballot = current_ballot OR default {counter: 0, value: ""}

  prep = Prepare {
    quorum_set_hash: hash(ctx.local_quorum_set),
    ballot: ballot,
    prepared: self.prepared,
    prepared_prime: self.prepared_prime,
    n_c: self.commit.counter OR 0,
    n_h: self.high_ballot.counter OR 0,
  }

  → record_envelope(Prepare(prep), can_emit,
      ctx.local_node_id, ctx.driver, ctx.slot_index)
```

**Calls**: [hash_quorum_set](../quorum.pc.md#hash_quorum_set) | [record_envelope](#record_envelope)

### record_envelope

"Sign, record, and optionally publish an envelope."
"Shared scaffolding for emit_prepare / emit_confirm / emit_externalize."

```
function BallotProtocol.record_envelope(pledges, set_last,
                                         local_node_id, driver,
                                         slot_index):
  statement = Statement {
    node_id: local_node_id,
    slot_index: slot_index,
    pledges: pledges,
  }

  envelope = Envelope { statement, signature: empty }
  driver.sign_envelope(envelope)

  if record_local_envelope(local_node_id, envelope):
    if set_last:
      last_envelope = envelope
    → statement
  → nothing
```

**Calls**: [SCPDriver.sign_envelope](../driver.pc.md#sign_envelope) | [record_local_envelope](#record_local_envelope)

### emit_confirm

"Build and record a confirm statement envelope."

```
function BallotProtocol.emit_confirm(ctx):
  GUARD current_ballot is absent → nothing

  conf = Confirm {
    ballot: current_ballot,
    n_prepared: self.prepared.counter OR 0,
    n_commit: self.commit.counter OR 0,
    n_h: self.high_ballot.counter OR 0,
    quorum_set_hash: hash(ctx.local_quorum_set),
  }

  → record_envelope(Confirm(conf), true,
      ctx.local_node_id, ctx.driver, ctx.slot_index)
```

**Calls**: [record_envelope](#record_envelope)

### emit_externalize

"Build and record an externalize statement envelope."

```
function BallotProtocol.emit_externalize(ctx):
  GUARD self.commit is absent → nothing

  ext = Externalize {
    commit: self.commit,
    n_h: self.high_ballot.counter OR 0,
    commit_quorum_set_hash: hash(ctx.local_quorum_set),
  }

  → record_envelope(Externalize(ext), true,
      ctx.local_node_id, ctx.driver, ctx.slot_index)
```

**Calls**: [record_envelope](#record_envelope)

### emit_current_state

"Emit current state and recursively self-process."
"Matches stellar-core emitCurrentStateStatement."
"After emitting, feeds self-envelope back into advance_slot"
"so cascading state transitions can happen within a single"
"top-level receiveEnvelope call."

```
function BallotProtocol.emit_current_state(ctx):
  if phase == Prepare:
    maybe_statement = emit_prepare(ctx)
  else if phase == Confirm:
    maybe_statement = emit_confirm(ctx)
  else if phase == Externalize:
    maybe_statement = emit_externalize(ctx)

  "Recursive self-processing: feed self-envelope back into
   advance_slot so cascading state transitions complete
   within a single receiveEnvelope."
  if maybe_statement is present:
    advance_slot(statement, ctx)

  "Emit latest envelope after self-processing completes.
   Dedup check in send_latest_envelope prevents double-emit."
  send_latest_envelope(ctx.driver)
```

**Calls**: [emit_prepare](#emit_prepare) | [emit_confirm](#emit_confirm) | [emit_externalize](#emit_externalize) | [advance_slot](mod.pc.md#advance_slot) | [send_latest_envelope](#send_latest_envelope)

### Helper: record_local_envelope

```
function BallotProtocol.record_local_envelope(local_node_id,
                                               envelope):
  GUARD NOT is_newer_statement(local_node_id,
                               envelope.statement) → false

  latest_envelopes[local_node_id] = envelope
  → true
```

**Calls**: [is_newer_statement](mod.pc.md#is_newer_statement)

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 205    | 95         |
| Functions    | 7      | 7          |
