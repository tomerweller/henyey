## Pseudocode: crates/scp/src/info.rs

"JSON-serializable SCP slot information for debugging and monitoring."
"Matches stellar-core getJsonInfo() functionality."

### Data Structures

```
STRUCT SlotInfo:
  slot_index: integer        "ledger sequence"
  phase: string
  fully_validated: boolean
  nomination: NominationInfo (optional)
  ballot: BallotInfo (optional)

STRUCT NominationInfo:
  running: boolean
  round: integer
  votes: list of string     "hex-encoded prefixes"
  accepted: list of string
  candidates: list of string
  node_count: integer

STRUCT BallotInfo:
  phase: string              "prepare/confirm/externalize"
  ballot_counter: integer
  ballot_value: string (optional)  "hex-encoded prefix"
  prepared: BallotValue (optional)
  prepared_prime: BallotValue (optional)
  commit: CommitBounds (optional)
  high: integer
  node_count: integer
  heard_from_quorum: boolean

STRUCT BallotValue:
  counter: integer
  value: string              "hex-encoded prefix"

STRUCT CommitBounds:
  low: integer
  high: integer

STRUCT QuorumInfo:
  slot_index: integer
  local_node: string         "short form node ID"
  quorum_set_hash: string
  nodes: map<string, NodeInfo>
  quorum_reached: boolean
  v_blocking: boolean

STRUCT NodeInfo:
  state: string
  ballot_counter: integer (optional)
```

NOTE: All structs are JSON-serializable. Optional fields are
omitted from JSON output when absent.

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 111    | 42         |
| Functions    | 0      | 0          |
