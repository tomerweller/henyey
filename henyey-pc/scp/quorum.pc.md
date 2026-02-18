## Pseudocode: crates/scp/src/quorum.rs

"Quorum set operations for SCP."
"Quorum sets define which validators a node trusts and how consensus decisions are made."

```
CONST MAXIMUM_QUORUM_NESTING_LEVEL = 4
CONST MAXIMUM_QUORUM_NODES = 1000
```

### is_quorum_slice

"A quorum slice is satisfied if at least threshold of its members (validators + inner sets) agree."

```
function is_quorum_slice(quorum_set, nodes, get_quorum_set):
  threshold = quorum_set.threshold
  if threshold == 0:
    → true

  count = 0

  for each validator in quorum_set.validators:
    if validator in nodes:
      count += 1
      if count >= threshold:
        → true

  for each inner_set in quorum_set.inner_sets:
    if is_quorum_slice(inner_set, nodes, get_quorum_set):
      count += 1
      if count >= threshold:
        → true

  → count >= threshold
```

### is_quorum

"Uses iterative pruning to find a quorum within the given set of nodes."
"Repeatedly removes nodes whose quorum slices aren't satisfied by the remaining set until the set stabilizes."
"Matches stellar-core LocalNode::isQuorum() behavior."

```
function is_quorum(quorum_set, nodes, get_quorum_set):
  remaining = list(nodes)

  loop:
    count = remaining.length
    remaining_set = set(remaining)

    "Keep only nodes whose quorum slices are satisfied"
    remaining = [node for node in remaining
                 where get_quorum_set(node) is not null
                   and is_quorum_slice(
                         get_quorum_set(node),
                         remaining_set,
                         get_quorum_set)]

    if remaining.length == count:
      break

  "Check if local node's quorum slice is satisfied by surviving set"
  remaining_set = set(remaining)
  → is_quorum_slice(quorum_set, remaining_set,
                     get_quorum_set)
```

### is_blocking_set

"A blocking set intersects every quorum slice, preventing any quorum from being formed."

```
function is_blocking_set(quorum_set, nodes):
  → is_blocking_set_helper(quorum_set, nodes)
```

### Helper: is_blocking_set_helper

"Matches stellar-core LocalNode::isVBlockingInternal."

```
function is_blocking_set_helper(quorum_set, nodes):
  total = quorum_set.validators.length
        + quorum_set.inner_sets.length
  threshold = quorum_set.threshold

  "No v-blocking set for the empty set"
  if threshold == 0:
    → false

  "Need to block (total - threshold + 1) members"
  blocking_threshold = total - threshold + 1
  count = 0

  for each validator in quorum_set.validators:
    if validator in nodes:
      count += 1

  for each inner_set in quorum_set.inner_sets:
    if is_blocking_set_helper(inner_set, nodes):
      count += 1

  → count >= blocking_threshold
```

### is_v_blocking

```
function is_v_blocking(quorum_set, nodes):
  → is_blocking_set(quorum_set, nodes)
```

### is_quorum_set_sane

"Validates structural constraints, duplicate nodes, and optionally enforces safety threshold (> 50%)."

```
function is_quorum_set_sane(quorum_set, extra_checks):
  checker = {
    extra_checks = extra_checks,
    known_nodes = empty set,
    count = 0
  }

  check_sanity(checker, quorum_set, depth=0)

  GUARD checker.count < 1 or checker.count > MAXIMUM_QUORUM_NODES
    → error "Total nodes must be within 1 and 1000"

  → ok
```

### Helper: check_sanity

```
function check_sanity(checker, quorum_set, depth):
  GUARD depth > MAXIMUM_QUORUM_NESTING_LEVEL
    → error "Maximum nesting level exceeded"

  GUARD quorum_set.threshold < 1
    → error "Threshold must be > 0"

  total = quorum_set.validators.length
        + quorum_set.inner_sets.length
  GUARD quorum_set.threshold > total
    → error "Threshold exceeds total entries"

  v_blocking_size = total - quorum_set.threshold + 1
  if checker.extra_checks
     and quorum_set.threshold < v_blocking_size:
    → error "Threshold is below v-blocking size (< 51%)"

  checker.count += quorum_set.validators.length
  for each node in quorum_set.validators:
    GUARD node already in checker.known_nodes
      → error "Duplicate node"
    add node to checker.known_nodes

  for each inner in quorum_set.inner_sets:
    check_sanity(checker, inner, depth + 1)
```

### find_closest_v_blocking

"Returns a minimal set of nodes from nodes that would v-block the quorum set, excluding excluded if provided."

```
function find_closest_v_blocking(quorum_set,
                                  nodes, excluded):
  left_till_block = 1
    + quorum_set.validators.length
    + quorum_set.inner_sets.length
    - quorum_set.threshold

  if left_till_block <= 0:
    → empty list

  result = empty list

  for each validator in quorum_set.validators:
    if validator == excluded:
      continue
    if validator in nodes:
      append validator to result
    else:
      left_till_block -= 1
      if left_till_block == 0:
        → empty list

  inner_results = empty list
  for each (index, inner) in quorum_set.inner_sets:
    v = find_closest_v_blocking(inner, nodes, excluded)
    if v is empty:
      left_till_block -= 1
      if left_till_block == 0:
        → empty list
    else:
      append (v.length, index, v) to inner_results

  "Truncate result to at most left_till_block entries"
  if result.length > left_till_block:
    truncate result to left_till_block entries
  left_till_block -= result.length

  "Sort inner results by size (smallest first)"
  sort inner_results by v.length then index
  idx = 0
  while left_till_block != 0 and idx < inner_results.length:
    extend result with inner_results[idx].v
    left_till_block -= 1
    idx += 1

  → result
```

### hash_quorum_set

```
function hash_quorum_set(quorum_set):
  → hash_xdr(quorum_set) or ZERO
```

### normalize_quorum_set

"Normalize by sorting validators and inner sets for consistent hashing."

```
function normalize_quorum_set(quorum_set):
  normalize_quorum_set_with_remove(quorum_set, null)
```

### normalize_quorum_set_with_remove

"Normalize, optionally removing a node (used during EXTERNALIZE and leader computation)."
"Matches stellar-core normalizeQSet function signature."

```
function normalize_quorum_set_with_remove(
    quorum_set, id_to_remove):
  "Phase 1: simplify (merge singletons, remove node)"
  normalize_quorum_set_simplify(
    quorum_set, id_to_remove)

  "Phase 2: reorder"
  sort quorum_set.validators by node_id bytes
  for each inner_set in quorum_set.inner_sets:
    normalize_quorum_set_reorder(inner_set)
  sort quorum_set.inner_sets by quorum_set_cmp
```

### Helper: normalize_quorum_set_reorder

```
function normalize_quorum_set_reorder(quorum_set):
  sort quorum_set.validators by node_id bytes
  for each inner_set in quorum_set.inner_sets:
    normalize_quorum_set_reorder(inner_set)
  sort quorum_set.inner_sets by quorum_set_cmp
```

### Helper: normalize_quorum_set_simplify

```
function normalize_quorum_set_simplify(
    quorum_set, id_to_remove):
  inner_sets = copy of quorum_set.inner_sets
  merged_validators = copy of quorum_set.validators

  "Remove specified node from validators, adjust threshold"
  if id_to_remove is not null:
    original_len = merged_validators.length
    remove all entries == id_to_remove
      from merged_validators
    removed_count = original_len - merged_validators.length
    quorum_set.threshold -= removed_count

  idx = 0
  while idx < inner_sets.length:
    normalize_quorum_set_simplify(
      inner_sets[idx], id_to_remove)

    "Merge singleton inner sets into validators"
    if inner_sets[idx].threshold == 1
       and inner_sets[idx].validators.length == 1
       and inner_sets[idx].inner_sets is empty:
      append inner_sets[idx].validators[0]
        to merged_validators
      remove inner_sets[idx]
    else:
      idx += 1

  quorum_set.validators = merged_validators
  quorum_set.inner_sets = inner_sets

  "Collapse single-inner-set wrapper"
  if quorum_set.threshold == 1
     and quorum_set.validators is empty
     and quorum_set.inner_sets.length == 1:
    quorum_set = quorum_set.inner_sets[0]
```

### Helper: quorum_set_cmp

```
function quorum_set_cmp(a, b):
  "Compare validators element-wise by node_id bytes"
  "Then compare by validators length"
  "Then compare inner_sets element-wise recursively"
  "Then compare by inner_sets length"
  "Then compare by threshold"
```

### is_valid_quorum_set

```
function is_valid_quorum_set(quorum_set):
  total = quorum_set.validators.length
        + quorum_set.inner_sets.length
  GUARD quorum_set.threshold > total  → false

  for each inner_set in quorum_set.inner_sets:
    GUARD not is_valid_quorum_set(inner_set)  → false

  → true
```

### get_all_nodes

"Get all node IDs referenced in a quorum set (recursive)."

```
function get_all_nodes(quorum_set):
  nodes = empty set
  collect_nodes(quorum_set, nodes)
  → nodes
```

### Helper: collect_nodes

```
function collect_nodes(quorum_set, nodes):
  for each validator in quorum_set.validators:
    add validator to nodes
  for each inner_set in quorum_set.inner_sets:
    collect_nodes(inner_set, nodes)
```

### simple_quorum_set

```
function simple_quorum_set(threshold, validators):
  → QuorumSet {
      threshold = threshold,
      validators = validators,
      inner_sets = empty
    }
```

### singleton_quorum_set

```
function singleton_quorum_set(node_id):
  → simple_quorum_set(1, [node_id])
```

### SingletonQuorumSetCache

```
struct SingletonQuorumSetCache:
  cache: Map<NodeId, QuorumSet>
```

### SingletonQuorumSetCache::get_or_create

```
function get_or_create(node_id):
  if node_id in cache:
    → cache[node_id]

  qs = singleton_quorum_set(node_id)
  cache[node_id] = qs
  → qs
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~597   | ~210       |
| Functions     | 18     | 18         |
