## Pseudocode: crates/scp/src/quorum_config.rs

"Quorum set configuration and validation utilities."

### Error Enum: QuorumConfigError

```
ENUM QuorumConfigError:
  InvalidPublicKey(key)
  InvalidThreshold { threshold, validator_count }
  InvalidStructure(message)
  NoQuorumIntersection
```

### config_to_quorum_set

"Convert a QuorumSetConfig to an XDR ScpQuorumSet."

```
function config_to_quorum_set(config):
  validators = []
  for each key_str in config.validators:
    node_id = parse_node_id(key_str)
    validators.append(node_id)

  inner_sets = []
  for each inner_config in config.inner_sets:
    inner_qs = config_to_quorum_set(inner_config)  "recursive"
    inner_sets.append(inner_qs)

  total = validators.size + inner_sets.size
  threshold = if total == 0: 0
              else: max(1, (threshold_percent * total) / 100)

  GUARD threshold > total → InvalidThreshold

  qs = QuorumSet { threshold, validators, inner_sets }

  GUARD NOT is_valid_quorum_set(qs) → InvalidStructure

  → qs
```

**Calls**: [parse_node_id](#parse_node_id) | [is_valid_quorum_set](quorum.pc.md#is_valid_quorum_set)

### parse_node_id

"Parse a node ID from a string (strkey G... or 64-char hex)."

```
function parse_node_id(key_str):
  key_str = trim(key_str)

  if key_str starts with 'G':
    → parse_strkey_node_id(key_str)

  if key_str.length == 64:
    → parse_hex_node_id(key_str)

  → error InvalidPublicKey
```

### Helper: parse_strkey_node_id

```
function parse_strkey_node_id(key_str):
  strkey = decode_strkey_ed25519(key_str)
  → NodeId(Ed25519(strkey.bytes))
```

### Helper: parse_hex_node_id

```
function parse_hex_node_id(key_str):
  bytes = hex_decode(key_str)
  GUARD bytes.length != 32 → InvalidPublicKey
  → NodeId(Ed25519(bytes))
```

### validate_quorum_config

"Validate that a quorum set configuration will produce valid consensus."

```
function validate_quorum_config(config):
  GUARD threshold_percent > 100 → InvalidThreshold

  qs = config_to_quorum_set(config)

  GUARD is_quorum_set_sane(qs) fails → InvalidStructure

  all_nodes = get_all_nodes(qs)
  if all_nodes is empty AND no validators AND no inner_sets:
    WARN "no validators - cannot reach consensus"

  if threshold_percent < 51:
    WARN "threshold below 51% - may compromise safety"

  if threshold_percent == 100 AND has validators:
    WARN "100% threshold - no fault tolerance"

  → success
```

**Calls**: [config_to_quorum_set](#config_to_quorum_set) | [is_quorum_set_sane](quorum.pc.md#is_quorum_set_sane) | [get_all_nodes](quorum.pc.md#get_all_nodes)

### Constants: Known Validators

```
CONST TESTNET_VALIDATORS = [
  "GDKXE2OZ...",  // core1
  "GCUCJTIY...",  // core2
  "GC2V2EFS...",  // core3
]

CONST MAINNET_SDF_VALIDATORS = [
  "GCGB2S2K...",  // sdf1
  "GCM6QMP3...",  // sdf2
  "GABMKJM6...",  // sdf3
]

CONST RECOMMENDED_THRESHOLD_PERCENT = 67
  // Byzantine fault tolerance for up to 1/3 faulty
CONST MINIMUM_SAFE_THRESHOLD_PERCENT = 51
```

### testnet_quorum_config

```
function testnet_quorum_config():
  → QuorumSetConfig {
    threshold_percent: 67,
    validators: TESTNET_VALIDATORS,
    inner_sets: []
  }
```

### node_id_to_strkey

```
function node_id_to_strkey(node_id):
  bytes = node_id.public_key.ed25519_bytes
  → encode_strkey_ed25519(bytes)
```

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 314    | 83         |
| Functions    | 8      | 8          |
