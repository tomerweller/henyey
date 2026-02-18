## Pseudocode: crates/scp/src/format.rs

"Display formatting helpers for SCP types (nodes, ballots, envelopes, values)."

### node_id_to_short_string

```
function node_id_to_short_string(node_id):
  "Returns the first 8 hex characters of the public key."
  bytes = node_id.public_key.ed25519_bytes
  → hex_encode(bytes[0..4])
```

### node_id_to_string

"Matches stellar-core toStrKey(NodeID, bool fullKeys)."

```
function node_id_to_string(node_id, full_keys):
  bytes = node_id.public_key.ed25519_bytes
  if full_keys:
    → hex_encode(bytes)
  else:
    → hex_encode(bytes[0..4])
```

### ballot_to_str

```
function ballot_to_str(ballot):
  → format "(counter, hex_prefix_of_value)"
    where hex_prefix = first 4 bytes of ballot.value
```

### value_to_str

```
function value_to_str(value):
  → hex_encode(value[0..min(8, length)])
```

### envelope_to_str

```
function envelope_to_str(envelope):
  node = node_id_to_short_string(envelope.statement.node_id)
  slot = envelope.statement.slot_index

  if Nominate(nom):
    votes = [value_to_str(v) for v in nom.votes]
    accepted = [value_to_str(v) for v in nom.accepted]
    → "NOMINATE<node, slot, votes, accepted>"

  if Prepare(prep):
    → "PREPARE<node, slot, b, p, p', c, h>"

  if Confirm(conf):
    → "CONFIRM<node, slot, b, p_n, c, h>"

  if Externalize(ext):
    → "EXTERNALIZE<node, slot, c, h>"
```

**Calls**: [node_id_to_short_string](#node_id_to_short_string) | [value_to_str](#value_to_str) | [ballot_to_str](#ballot_to_str)

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 97     | 38         |
| Functions    | 5      | 5          |
