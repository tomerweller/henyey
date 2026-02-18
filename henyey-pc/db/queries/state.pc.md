# Pseudocode: crates/db/src/queries/state.rs

"The storestate table is a simple key-value store used for persistent
node configuration and runtime state. It stores values like the network
passphrase, last closed ledger, and SCP state."

## Trait: StateQueries

### get_state

```
function get_state(key) -> string or none:
    → DB SELECT state FROM storestate
          WHERE statename = key
      (returns none if row absent)
```

### set_state

```
function set_state(key, value):
    DB INSERT OR REPLACE INTO storestate
        (statename, state) VALUES (key, value)
```

### delete_state

```
function delete_state(key):
    DB DELETE FROM storestate
        WHERE statename = key
```

### get_last_closed_ledger

```
function get_last_closed_ledger() -> integer or none:
    value = get_state(LAST_CLOSED_LEDGER)
    GUARD value is none → none
    parsed = parse value as integer
    GUARD parse fails → error "Invalid last closed ledger"
    → parsed
```

**Calls**: [get_state](#get_state)

### set_last_closed_ledger

```
function set_last_closed_ledger(seq):
    set_state(LAST_CLOSED_LEDGER, seq as string)
```

**Calls**: [set_state](#set_state)

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 37     | 20         |
| Functions    | 5      | 5          |
