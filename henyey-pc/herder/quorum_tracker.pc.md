## Pseudocode: crates/herder/src/quorum_tracker.rs

"Quorum tracking utilities for consensus participation monitoring."

"In SCP, quorum sets define which nodes a validator trusts. A node achieves
consensus when it hears from a quorum — a set of nodes that satisfies the
threshold requirements of its quorum set configuration."

### Data: SlotQuorumTracker

"Tracks which nodes have sent SCP messages for each slot and determines
whether the node has heard from quorum or has a v-blocking set."

```
SlotQuorumTracker:
  local_quorum_set      // local node's quorum set config (nullable)
  max_slots             // max slots to track before pruning
  slot_nodes            // map<SlotIndex, set<NodeId>>
```

### Data: NodeInfo

```
NodeInfo:
  quorum_set              // the node's quorum set (nullable)
  distance                // distance from local node (0 = local)
  closest_validators      // set<NodeId> — direct validators on shortest path
```

### Data: QuorumTracker

"Tracks the transitive quorum set — all nodes reachable through the quorum
graph starting from the local node. Primary security use: validating
EXTERNALIZE messages only from transitive quorum members."

```
QuorumTracker:
  local_node_id
  quorum                  // map<NodeId, NodeInfo>
```

---

### SlotQuorumTracker::new

```
function new(local_quorum_set, max_slots):
  → SlotQuorumTracker { local_quorum_set, max_slots, slot_nodes: empty }
```

### SlotQuorumTracker::set_local_quorum_set

```
function set_local_quorum_set(quorum_set):
  self.local_quorum_set = quorum_set
```

### SlotQuorumTracker::record_envelope

```
function record_envelope(slot, node_id):
  self.slot_nodes[slot].insert(node_id)
  prune()
```

### SlotQuorumTracker::clear_slot

```
function clear_slot(slot):
  self.slot_nodes.remove(slot)
```

### SlotQuorumTracker::clear_slots_below

```
function clear_slots_below(min_slot):
  remove all entries from slot_nodes where slot < min_slot
```

### SlotQuorumTracker::has_quorum

```
function has_quorum(slot, get_qs) → bool:
  GUARD local_quorum_set is null   → false
  GUARD slot not in slot_nodes     → false
  nodes = slot_nodes[slot]
  → is_quorum(local_quorum_set, nodes, get_qs)
```

**Calls:** [`is_quorum`](../scp/quorum.pc.md)

### SlotQuorumTracker::is_v_blocking

```
function is_v_blocking(slot) → bool:
  GUARD local_quorum_set is null   → false
  GUARD slot not in slot_nodes     → false
  nodes = slot_nodes[slot]
  → is_v_blocking(local_quorum_set, nodes)
```

**Calls:** [`is_v_blocking`](../scp/quorum.pc.md)

### SlotQuorumTracker::get_v_blocking_slots

"Used for out-of-sync recovery to find slots to purge."

```
function get_v_blocking_slots() → list<SlotIndex>:
  GUARD local_quorum_set is null   → empty list
  result = []
  for each (slot, nodes) in slot_nodes:
    if is_v_blocking(local_quorum_set, nodes):
      result.append(slot)
  sort result descending by slot
  → result
```

### Helper: prune

```
function prune():
  if max_slots == 0 or slot_nodes.size <= max_slots:
    return
  slots = sorted keys of slot_nodes (ascending)
  remove_count = slot_nodes.size - max_slots
  for each slot in first remove_count of slots:
    slot_nodes.remove(slot)
```

---

### QuorumTracker::new

```
function new(local_node_id):
  quorum = { local_node_id → NodeInfo { quorum_set: null, distance: 0,
                                         closest_validators: empty } }
  → QuorumTracker { local_node_id, quorum }
```

### QuorumTracker::is_node_definitely_in_quorum

```
function is_node_definitely_in_quorum(node_id) → bool:
  → node_id in self.quorum
```

### QuorumTracker::expand

"BFS-style expansion: when a node's quorum set is learned, add all its
members at distance + 1."

```
function expand(node_id, quorum_set) → bool:
  GUARD node_id not in quorum      → false

  node_info = quorum[node_id]
  if node_info.quorum_set is not null:
    "already expanded — return true iff same quorum set"
    → (node_info.quorum_set == quorum_set)

  node_info.quorum_set = quorum_set
  node_distance = node_info.distance
  closest_validators = node_info.closest_validators
  new_dist = node_distance + 1

  ok = true
  for each qnode in for_each_quorum_node(quorum_set):
    if not ok:
      break
    existed = qnode in self.quorum
    qnode_info = self.quorum.get_or_insert(qnode,
      NodeInfo { quorum_set: null, distance: new_dist,
                 closest_validators: empty })

    if existed:
      if qnode_info.distance < new_dist:
        continue
      if qnode_info.quorum_set is not null:
        "conflict: node already expanded at same or greater distance"
        ok = false
        continue
      if new_dist < qnode_info.distance:
        qnode_info.closest_validators.clear()
        qnode_info.distance = new_dist

    if new_dist == 1:
      "direct validator — closest to itself"
      qnode_info.closest_validators.insert(qnode)
    else:
      qnode_info.closest_validators.add_all(closest_validators)

  → ok
```

### QuorumTracker::rebuild

"Rebuild transitive quorum from scratch using BFS."

```
function rebuild(lookup) → error?:
  self.quorum.clear()
  self.quorum[local_node_id] = NodeInfo { quorum_set: null,
    distance: 0, closest_validators: empty }

  backlog = queue [local_node_id]

  while backlog is not empty:
    node = backlog.pop_front()
    GUARD node not in quorum   → error MissingNode
    info = quorum[node]
    if info.quorum_set is null:
      qset = lookup(node)
      if qset is not null:
        for each member in for_each_quorum_node(qset):
          backlog.push_back(member)
        if not expand(node, qset):
          → error ExpandFailed
  → ok
```

### QuorumTracker::quorum_map

```
function quorum_map() → map<NodeId, NodeInfo>:
  → self.quorum
```

### QuorumTracker::tracked_node_count

```
function tracked_node_count() → int:
  → self.quorum.size
```

### QuorumTracker::find_closest_validators

```
function find_closest_validators(node_id) → set<NodeId>?:
  GUARD node_id not in quorum   → null
  → quorum[node_id].closest_validators
```

---

### Helper: for_each_quorum_node

```
function for_each_quorum_node(quorum_set, callback):
  for each validator in quorum_set.validators:
    callback(validator)
  for each inner in quorum_set.inner_sets:
    for_each_quorum_node(inner, callback)
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~180   | ~120       |
| Functions     | 14     | 14         |
