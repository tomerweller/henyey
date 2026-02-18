# Pseudocode: crates/db/src/scp_persistence.rs

"SQLite-backed implementation of SCP state persistence for crash recovery."

## Struct: SqliteScpPersistence

```
struct SqliteScpPersistence:
    db    — Database handle
```

### new

```
function new(db) -> SqliteScpPersistence:
    → { db: db }
```

### save_scp_state

```
function save_scp_state(slot, state_json):
    db.with_connection(conn →
        conn.save_scp_slot_state(slot, state_json)
    )
```

**Calls**: [save_scp_slot_state](queries/scp.pc.md#save_scp_slot_state)

### load_scp_state

```
function load_scp_state(slot) -> string or none:
    → db.with_connection(conn →
        conn.load_scp_slot_state(slot)
    )
```

**Calls**: [load_scp_slot_state](queries/scp.pc.md#load_scp_slot_state)

### load_all_scp_states

```
function load_all_scp_states() -> list of (slot, json):
    → db.with_connection(conn →
        conn.load_all_scp_slot_states()
    )
```

**Calls**: [load_all_scp_slot_states](queries/scp.pc.md#load_all_scp_slot_states)

### delete_scp_state_below

```
function delete_scp_state_below(slot):
    db.with_connection(conn →
        conn.delete_scp_slot_states_below(slot)
    )
```

**Calls**: [delete_scp_slot_states_below](queries/scp.pc.md#delete_scp_slot_states_below)

### save_tx_set

```
function save_tx_set(hash, tx_set_bytes):
    db.with_connection(conn →
        conn.save_tx_set_data(hash, tx_set_bytes)
    )
```

**Calls**: [save_tx_set_data](queries/scp.pc.md#save_tx_set_data)

### load_tx_set

```
function load_tx_set(hash) -> bytes or none:
    → db.with_connection(conn →
        conn.load_tx_set_data(hash)
    )
```

**Calls**: [load_tx_set_data](queries/scp.pc.md#load_tx_set_data)

### load_all_tx_sets

```
function load_all_tx_sets() -> list of (hash, bytes):
    → db.with_connection(conn →
        conn.load_all_tx_set_data()
    )
```

**Calls**: [load_all_tx_set_data](queries/scp.pc.md#load_all_tx_set_data)

### has_tx_set

```
function has_tx_set(hash) -> boolean:
    → db.with_connection(conn →
        conn.has_tx_set_data(hash)
    )
```

**Calls**: [has_tx_set_data](queries/scp.pc.md#has_tx_set_data)

### delete_tx_sets_below

```
function delete_tx_sets_below(slot):
    db.with_connection(conn →
        conn.delete_old_tx_set_data(slot)
    )
```

**Calls**: [delete_old_tx_set_data](queries/scp.pc.md#delete_old_tx_set_data)

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 79     | 45         |
| Functions    | 10     | 10         |
