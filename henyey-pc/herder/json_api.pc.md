## Pseudocode: crates/herder/src/json_api.rs

"JSON API for Herder diagnostics and monitoring."
"Matches stellar-core getJsonInfo(), getJsonQuorumInfo(), and related methods."

### Data Structures

```
HerderJsonInfo:
  you:   string            // this node's public key
  scp:   ScpJsonInfo
  queue: PendingEnvelopesJsonInfo

ScpJsonInfo:
  slot:  u64 or null
  phase: string or null
  slots: List<SlotJsonInfo>

SlotJsonInfo:
  index:      u64
  phase:      string
  ballot:     BallotJsonInfo or null
  nomination: NominationJsonInfo or null
  validators: List<string>

BallotJsonInfo:
  counter:   u32
  value:     string       // abbreviated value hash
  committed: bool
  h:         u32 or null  // highest confirmed prepared

NominationJsonInfo:
  votes:    int
  accepted: int
  complete: bool

PendingEnvelopesJsonInfo:
  pending:  int
  ready:    int
  fetching: int
  slots:    List<PendingSlotJsonInfo>

PendingSlotJsonInfo:
  slot:  u64
  count: int

QuorumJsonInfo:
  node:             string
  qset:             QuorumSetJsonInfo
  transitive:       TransitiveQuorumJsonInfo or null
  maybe_dead_nodes: List<string>

QuorumSetJsonInfo:
  threshold:  u32
  validators: List<string>
  inner_sets: List<QuorumSetJsonInfo>   // recursive
  hash:       string or null
  agree:      List<SlotAgreementInfo>
  lag_ms:     LagJsonInfo or null
  cost:       ValidatorCostJsonInfo or null

SlotAgreementInfo:
  slot:   u64
  agrees: bool
  phase:  string or null

LagJsonInfo:
  nodes:   List<NodeLagInfo>
  summary: LagSummary or null

NodeLagInfo:
  node:   string
  lag_ms: u64

LagSummary:
  min_ms: u64
  max_ms: u64
  avg_ms: u64

ValidatorCostJsonInfo:
  validators: List<ValidatorCost>

ValidatorCost:
  node: string
  cost: u64

TransitiveQuorumJsonInfo:
  intersection:     bool
  node_count:       u64
  last_check_ledger: u64
  critical:         List<List<string>>
  last_good_ledger: u64 or null
  potential_split:  (List<string>, List<string>) or null
```

### format_node_id

```
function format_node_id(node_id, full_keys):
  strkey = encode_ed25519_public_key(node_id)
  if full_keys:
    → strkey
  else:
    → strkey[0..5]
```

### format_hash

```
function format_hash(hash, full):
  hex_str = hex_encode(hash)
  if full:
    → hex_str
  else:
    → hex_str[0..8]
```

### HerderJsonInfoBuilder

```
function HerderJsonInfoBuilder.build():
  → HerderJsonInfo {
      you:   self.you or "unknown",
      scp:   self.scp,
      queue: self.queue
    }
```

### QuorumJsonInfoBuilder

```
function QuorumJsonInfoBuilder.build():
  → QuorumJsonInfo {
      node:             self.node or "unknown",
      qset:             self.qset,
      transitive:       self.transitive,
      maybe_dead_nodes: self.maybe_dead_nodes
    }
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 378    | 95         |
| Functions     | 4      | 4          |

NOTE: This module is primarily data structure definitions (JSON-serializable
structs). The logic is minimal — format helpers and builders.
