## Pseudocode: crates/scp/src/lib.rs

"Stellar Consensus Protocol (SCP) implementation."
"SCP is a federated Byzantine agreement protocol that enables nodes"
"to reach consensus without closed membership or central authority."

### Type Aliases & Constants

```
TYPE SlotIndex = integer   "typically the ledger sequence number"
```

### Data Structure: SlotContext

"Shared context threaded through ballot and nomination protocol methods."
"Groups four parameters that nearly every internal SCP function needs."

```
STRUCT SlotContext:
  local_node_id: NodeId
  local_quorum_set: QuorumSet
  driver: SCPDriver
  slot_index: integer
```

### ENUM: EnvelopeState

```
ENUM EnvelopeState:
  Invalid    "bad signature, malformed, etc."
  Valid      "valid but not new (duplicate or older)"
  ValidNew   "valid and caused state change"
```

### EnvelopeState helpers

```
function EnvelopeState.is_valid():
  → self == Valid OR self == ValidNew

function EnvelopeState.is_new():
  → self == ValidNew
```

### ENUM: QuorumInfoNodeState

```
ENUM QuorumInfoNodeState:
  Missing       "no message received"
  Nominating    "sent a nomination message"
  Preparing     "in ballot PREPARE phase"
  Confirming    "in ballot CONFIRM phase"
  Externalized  "has externalized"
```

### QuorumInfoNodeState helpers

```
function QuorumInfoNodeState.from_pledges(pledges):
  if Nominate    → Nominating
  if Prepare     → Preparing
  if Confirm     → Confirming
  if Externalize → Externalized

function QuorumInfoNodeState.is_in_ballot():
  → self in {Preparing, Confirming, Externalized}

function QuorumInfoNodeState.is_externalized():
  → self == Externalized
```

### process_envelopes_current_state

"Iterate envelopes in sorted node order, skipping self if not fully validated."
"Shared implementation for NominationProtocol and BallotProtocol."

```
function process_envelopes_current_state(envelopes, callback,
                                          local_node_id,
                                          fully_validated,
                                          force_self):
  nodes = sorted keys of envelopes

  for each node_id in nodes:
    if NOT force_self
       AND node_id == local_node_id
       AND NOT fully_validated:
      continue

    envelope = envelopes[node_id]
    if callback(envelope) returns false:
      → false

  → true
```

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 100    | 55         |
| Functions    | 6      | 6          |
