# Pseudocode: crates/overlay/src/ban_manager.rs

## Overview

"Ban manager for persistent peer banning."

Maintains a persistent list of banned nodes in SQLite. Nodes are identified
by Ed25519 public key (NodeID). The ban list is checked during peer connection
acceptance.

```
DATABASE SCHEMA:
  CREATE TABLE ban (
    nodeid CHARACTER(56) NOT NULL PRIMARY KEY
  )
```

---

### STRUCT BanManager

```
STRUCT BanManager:
  cache: Set<PeerId>          "in-memory cache for fast lookups"
  db: optional DatabaseConnection
```

---

### new_in_memory

```
function new_in_memory() → BanManager:
  → BanManager { cache: empty set, db: none }
```

---

### new_with_db

```
function new_with_db(db_path) → BanManager:
  conn = open_database(db_path)
  manager = from_connection(conn)
  → manager
```

---

### from_connection

```
function from_connection(conn) → BanManager:
  execute "CREATE TABLE IF NOT EXISTS ban (...)" on conn
  cache = empty set

  rows = query "SELECT nodeid FROM ban" on conn
  for each row in rows:
    if row parses as valid PeerId:
      cache.add(parsed_peer_id)

  → BanManager { cache, db: conn }
```

---

### ban_node

```
function ban_node(self, node_id):
  GUARD cache contains node_id → return (no-op)

  node_id_str = node_id.to_strkey()

  if db is available:
    execute "INSERT OR IGNORE INTO ban (nodeid)
             VALUES (?)" with node_id_str

  MUTATE cache add node_id
```

---

### unban_node

```
function unban_node(self, node_id):
  node_id_str = node_id.to_strkey()

  if db is available:
    execute "DELETE FROM ban WHERE nodeid = ?"
            with node_id_str

  MUTATE cache remove node_id
```

---

### is_banned

```
function is_banned(self, node_id) → boolean:
  → cache contains node_id
```

---

### get_bans

```
function get_bans(self) → list of strings:
  → [id.to_strkey() for each id in cache]
```

---

### get_banned_ids

```
function get_banned_ids(self) → list of PeerId:
  → copy of all ids in cache
```

---

### ban_count

```
function ban_count(self) → integer:
  → cache.size()
```

---

### clear_all

```
function clear_all(self):
  if db is available:
    execute "DELETE FROM ban"

  MUTATE cache clear all entries
```

---

### drop_and_create

```
function drop_and_create(self):
  if db is available:
    execute "DROP TABLE IF EXISTS ban"
    execute "CREATE TABLE ban (
               nodeid CHARACTER(56) NOT NULL PRIMARY KEY
             )"

  MUTATE cache clear all entries
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 236    | 65         |
| Functions     | 10     | 10         |
