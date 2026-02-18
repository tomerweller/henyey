## Pseudocode: crates/scp/src/driver.rs

"SCP driver trait defining callbacks for the SCP protocol."
"The SCPDriver trait is the primary integration point between SCP"
"consensus and the application layer (typically the Herder)."

### ENUM: SCPTimerType

```
ENUM SCPTimerType:
  Nomination   "triggers round advancement"
  Ballot       "triggers ballot bumping"
```

### ENUM: ValidationLevel

```
ENUM ValidationLevel:
  Invalid         "reject value"
  MaybeValid      "nomination-phase only; needs full validation"
  FullyValidated  "can be externalized"
```

### Trait: SCPDriver

```
TRAIT SCPDriver:
  "Validation"
  validate_value(slot_index, value, nomination) → ValidationLevel
  extract_valid_value(slot_index, value) → value or nothing
  combine_candidates(slot_index, candidates) → value or nothing

  "Network"
  emit_envelope(envelope)

  "Quorum set lookup"
  get_quorum_set(node_id) → quorum_set or nothing
  get_quorum_set_by_hash(hash) → quorum_set or nothing
    "default: nothing"

  "Notifications"
  nominating_value(slot_index, value)
  value_externalized(slot_index, value)
  ballot_did_prepare(slot_index, ballot)
  ballot_did_confirm(slot_index, ballot)
  ballot_did_hear_from_quorum(slot_index, ballot)
    "default: no-op"
  started_ballot_protocol(slot_index, value)
    "default: no-op"
  updated_candidate_value(slot_index, value)
    "default: no-op"

  "Hash computation for nomination ordering"
  compute_hash_node(slot_index, prev_value, is_priority,
                    round, node_id) → integer
  compute_value_hash(slot_index, prev_value,
                     round, value) → integer

  "Timing"
  compute_timeout(round, is_nomination) → duration

  "Cryptography"
  sign_envelope(envelope)
  verify_envelope(envelope) → boolean
  hash_quorum_set(quorum_set) → hash
    "default: SHA256(XDR(quorum_set))"

  "Node weight"
  get_node_weight(node_id, quorum_set, is_local_node) → integer
    "default: base_get_node_weight(...)"

  "Utilities"
  get_value_string(value) → string
    "default: hex prefix of value"
  get_hash_of(data) → hash
    "default: SHA256(data)"

  "Timer management"
  setup_timer(slot_index, timer_type, timeout)
    "default: no-op"
  stop_timer(slot_index, timer_type)
    "default: no-op"
  timer_expired(slot_index, timer_type)
    "default: no-op"

  "Upgrade handling"
  has_upgrades(value) → boolean
    "default: false"
  strip_all_upgrades(value) → value or nothing
    "default: nothing"
  get_upgrade_nomination_timeout_limit() → integer
    "default: MAX_INT (effectively never strip)"
```

### compute_weight

"Compute weight as ceil(m * threshold / total)."
"Matches upstream computeWeight in SCPDriver.cpp."
"Uses 128-bit to avoid overflow since m can be MAX_U64."

```
function compute_weight(m, total, threshold):
  GUARD threshold == 0 OR total == 0 → 0
  ASSERT: threshold <= total
  → ceil((m * threshold) / total)
```

### base_get_node_weight

"Base implementation matching upstream SCPDriver::getNodeWeight."

```
function base_get_node_weight(node_id, quorum_set, is_local_node):
  if is_local_node:
    → MAX_U64

  total = quorum_set.validators.size
         + quorum_set.inner_sets.size
  threshold = quorum_set.threshold

  GUARD threshold == 0 OR total == 0 → 0

  "Check top-level validators"
  for each validator in quorum_set.validators:
    if validator == node_id:
      → compute_weight(MAX_U64, total, threshold)

  "Recursively check inner sets"
  for each inner in quorum_set.inner_sets:
    leaf_w = base_get_node_weight(node_id, inner, false)
    if leaf_w > 0:
      → compute_weight(leaf_w, total, threshold)

  → 0
```

**Calls**: [compute_weight](#compute_weight)

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 167    | 95         |
| Functions    | 2      | 2          |
| Traits       | 1      | 1          |
