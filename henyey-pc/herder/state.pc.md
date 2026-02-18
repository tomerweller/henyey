## Pseudocode: crates/herder/src/state.rs

"Herder state machine for consensus participation."
"Booting -> Syncing -> Tracking"

```
STATE_MACHINE: HerderState
  STATES: [Booting, Syncing, Tracking]
  TRANSITIONS:
    Booting  → Syncing:  initial sync begins
    Syncing  → Tracking: catchup completes
    Tracking → (terminal)
```

### can_receive_scp

```
→ state is Syncing or Tracking
```

### can_receive_transactions

```
→ state is Tracking
```

### is_tracking

```
→ state is Tracking
```

### is_booting

```
→ state is Booting
```

### is_syncing

```
→ state is Syncing
```

### next_state

```
if state is Booting:
  → Syncing
if state is Syncing:
  → Tracking
if state is Tracking:
  → null
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 41     | 22         |
| Functions     | 6      | 6          |
