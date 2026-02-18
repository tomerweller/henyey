## Pseudocode: crates/herder/src/herder_utils.rs

"Utility functions for Herder operations."
"Matches stellar-core HerderUtils.h."

### get_stellar_values

```
function get_stellar_values(statement):
  values = Slot.get_statement_values(statement)
  for each value in values:
    try parse value as StellarValue
    if parse succeeds:
      collect it
  → list of parsed StellarValues (invalid ones silently skipped)
```

**Calls**: [get_statement_values](../scp/slot.pc.md#get_statement_values)

### get_tx_set_hashes_from_envelope

```
function get_tx_set_hashes_from_envelope(envelope):
  stellar_values = get_stellar_values(envelope.statement)
  for each sv in stellar_values:
    extract sv.tx_set_hash
  → list of tx set hashes
```

**Calls**: [get_stellar_values](#get_stellar_values)

### to_short_string

```
function to_short_string(node_id):
  hex = hex_encode(node_id.public_key_bytes)
  → first 5 characters of hex
```

### to_short_strkey

```
function to_short_strkey(node_id):
  strkey = strkey_encode(node_id.public_key_bytes)
  → first 5 characters of strkey   // "GABCD..."
```

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 30     | 17         |
| Functions    | 4      | 4          |
