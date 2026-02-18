## Pseudocode: crates/herder/src/dead_node_tracker.rs

"Dead node detection for monitoring network participation."
"Uses a two-interval approach: missing → dead after two consecutive intervals."
"Matches stellar-core's dead node detection in HerderImpl."

CONST CHECK_FOR_DEAD_NODES_MINUTES = 15  // check interval

### STATE_MACHINE: DeadNodeTracker

```
STATE_MACHINE: DeadNodeTracker
  STATES: [Active, Missing, Dead]
  TRANSITIONS:
    Active  → Missing: not seen during current interval
    Missing → Dead:    still not seen after next check_interval
    Dead    → Missing: new interval begins (all nodes start missing)
    Missing → Active:  SCP envelope received (record_node_activity)
```

### new / with_interval

```
function new():
  → with_interval(15 minutes)

function with_interval(check_interval):
  missing_nodes = empty set
  dead_nodes    = empty set
  last_check    = now
  → DeadNodeTracker
```

### reset_missing_nodes

```
function reset_missing_nodes(transitive_quorum):
  clear missing_nodes
  missing_nodes = copy of all transitive_quorum members
```

### record_node_activity

```
function record_node_activity(node_id):
  remove node_id from missing_nodes
```

### should_check

```
function should_check():
  → elapsed since last_check >= check_interval
```

### check_interval

"Nodes that were missing before and are still missing are now dead."

```
function check_interval(transitive_quorum):
  dead_nodes = take(missing_nodes)
    // missing_nodes is now empty;
    // dead_nodes holds formerly-missing nodes
  missing_nodes = copy of all transitive_quorum members
  last_check = now
```

### Accessors

```
function get_maybe_dead_nodes():  → dead_nodes set
function get_missing_nodes():     → missing_nodes set
function is_maybe_dead(node_id):  → dead_nodes contains node_id
function is_missing(node_id):     → missing_nodes contains node_id
function dead_count():            → size of dead_nodes
function missing_count():         → size of missing_nodes
```

### clear

```
function clear():
  clear missing_nodes
  clear dead_nodes
  last_check = now
```

### time_until_next_check

```
function time_until_next_check():
  remaining = check_interval - elapsed since last_check
  → max(remaining, 0)
```

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 100    | 38         |
| Functions    | 13     | 13         |
