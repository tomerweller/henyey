# Pseudocode: crates/db/src/queries/ban.rs

"The ban table stores node IDs that should be excluded from consensus
and peer connections. Node IDs are stored as Stellar strkey format."

## Trait: BanQueries

### ban_node

```
function ban_node(node_id):
    DB INSERT OR IGNORE INTO ban (nodeid) VALUES (node_id)
```

### unban_node

```
function unban_node(node_id):
    DB DELETE FROM ban WHERE nodeid = node_id
```

### is_banned

```
function is_banned(node_id) -> boolean:
    count = DB SELECT COUNT(*) FROM ban
                WHERE nodeid = node_id
    → count > 0
```

### load_bans

```
function load_bans() -> list of strings:
    → DB SELECT nodeid FROM ban
```

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 30     | 12         |
| Functions    | 4      | 4          |
