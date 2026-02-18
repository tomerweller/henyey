## Pseudocode: crates/tx/src/soroban/mod.rs

"Soroban smart contract integration."

"Soroban execution follows this pipeline:
  Transaction with InvokeHostFunction
    → Footprint Validation (verify declared read/write keys)
    → Build Storage Map (load entries from bucket list)
    → Execute via e2e_invoke (soroban-env-host execution)
    → Collect Changes (storage changes, events, fees)
    → Apply to LedgerDelta"

"Protocol versioning is critical because:
  - Host function semantics may change between versions
  - Cost model parameters differ per protocol
  - PRNG behavior must match exactly for determinism"

### Interface: HotArchiveLookup

"Trait for looking up archived entries from the hot archive."
"Starting from Protocol 23, persistent Soroban entries that expire
are moved to the hot archive bucket list rather than being deleted.
When a transaction needs to restore an archived entry:
  1. Entry may still be in live bucket list with expired TTL
  2. Entry may have been fully evicted to hot archive
This trait handles case (2)."

```
interface HotArchiveLookup:
  function get(key) → entry or null
    "Returns entry if key exists as Archived entry.
     Returns null if not found or exists as Live marker."
```

### NoHotArchive

"A no-op implementation that always returns null."
"Used when hot archive is not available (pre-Protocol 23)
or when lookups are not needed."

```
class NoHotArchive implements HotArchiveLookup:
  function get(key):
    → null
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 18     | 10         |
| Functions     | 2      | 2          |
