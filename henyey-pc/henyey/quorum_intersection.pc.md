## Pseudocode: crates/henyey/src/quorum_intersection.rs

"Quorum intersection analysis for Stellar Consensus Protocol (SCP)."
"Verifies that all quorums in the network share at least one common node."

"The algorithm enumerates all possible subsets of nodes (2^n) to find quorums,
then checks all pairs for intersection. This is exponential in the number of
nodes and is only practical for small networks (roughly < 20 nodes)."

### check_quorum_intersection_from_json

"Main entry point. Loads network config from JSON, verifies each node
has a satisfiable quorum slice, then checks all quorums intersect."

```
qmap = load_quorum_map(path)
nodes = set of all keys in qmap

for each (node, qset) in qmap:
  GUARD not is_quorum_slice(qset, nodes)
    → error "quorum set for {node} has no slice in network"

→ network_enjoys_quorum_intersection(qmap)
```

**Calls**: [load_quorum_map](#helper-load_quorum_map) | [is_quorum_slice](henyey_scp#is_quorum_slice) | [network_enjoys_quorum_intersection](#network_enjoys_quorum_intersection)

---

### network_enjoys_quorum_intersection

"Enumerates all 2^n - 1 non-empty subsets, identifies quorums,
checks every pair intersects."

```
CONST MAX_QUORUM_INTERSECTION_NODES = 20
  // O(2^n * n^2) algorithm, cap to prevent runaway

nodes = list of all keys in qmap
GUARD empty → false
ASSERT: nodes.count <= MAX_QUORUM_INTERSECTION_NODES

"Enumerate all possible quorums by checking every subset"
quorums = []
for mask in 1..(2^total):
  subset = { nodes[i] : bit i is set in mask }
  if is_quorum_for_set(subset, qmap):
    quorums.append(subset)

"Check all pairs of quorums for intersection"
for i in 0..quorums.count:
  for j in (i+1)..quorums.count:
    if quorums[i] is disjoint from quorums[j]:
      → false

→ true
```

**Calls**: [is_quorum_for_set](#helper-is_quorum_for_set)

---

### Helper: is_quorum_for_set

"Checks if a set of nodes forms a valid quorum (every node's
slice requirements are satisfied by the set)."

```
GUARD empty set → false
first = any node from set
GUARD first not in qmap → false
local_qset = qmap[first]

→ is_quorum(local_qset, nodes, lookup = qmap.get)
```

**Calls**: [is_quorum](henyey_scp#is_quorum)

---

### Helper: load_quorum_map

"Reads JSON file, constructs NodeId → ScpQuorumSet mapping."

```
payload = read_file(path)
json = parse JSON as QuorumIntersectionJson

map = {}
for each entry in json.nodes:
  node_id = parse_node_id(entry.node)
  qset = parse_qset(entry.qset)
  map[node_id] = qset

→ map
```

**Calls**: [parse_qset](#helper-parse_qset) | [parse_node_id](henyey_scp#parse_node_id)

---

### Helper: parse_qset

"Converts JSON quorum set entry to ScpQuorumSet structure."

```
validators = []
for each node_str in entry.v:
  validators.append(parse_node_id(node_str))

→ ScpQuorumSet {
    threshold: entry.t,
    validators: validators,
    inner_sets: []
  }
```

---

### Helper: node_id_to_hex

```
→ hex_encode(node.public_key_bytes)
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~185   | ~55        |
| Functions     | 6      | 6          |
