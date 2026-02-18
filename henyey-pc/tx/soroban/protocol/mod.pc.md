## Pseudocode: crates/tx/src/soroban/protocol/mod.rs

"Protocol-versioned Soroban host implementations."
"Dispatch is done at runtime based on the ledger's protocol version."

### execute_host_function

```
function execute_host_function(host_function, auth_entries,
    source, state, context, soroban_data, soroban_config):

  protocol_version = context.protocol_version

  @version(<25):
    → p24.invoke_host_function(host_function, auth_entries,
        source, state, context, soroban_data, soroban_config)

  @version(≥25):
    → p25.invoke_host_function(host_function, auth_entries,
        source, state, context, soroban_data, soroban_config)
```

**Calls:**
- [`p24.invoke_host_function`](../protocol/p24.pc.md) — protocol 24 host
- [`p25.invoke_host_function`](../protocol/p25.pc.md) — protocol 25+ host

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 24     | 12         |
| Functions     | 1      | 1          |
