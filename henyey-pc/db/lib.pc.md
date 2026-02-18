# Pseudocode: crates/db/src/lib.rs

"Database abstraction layer for rs-stellar-core. Provides SQLite-based
persistence for ledger headers, transaction history, SCP state,
bucket list snapshots, peer records, and operational state."

## Database — Initialization

### open

```
function Database.open(path) -> Database:
    "Phase 1: Ensure parent directory exists"
    if path has parent directory:
        create_dir_all(parent)

    "Phase 2: Create connection pool"
    manager = SqliteConnectionManager(path)
        with init: PRAGMA busy_timeout = 30000
    pool = Pool.build(
        max_size: 10,
        connection_timeout: 30 seconds
    )

    db = Database { pool }
    db.initialize()
    → db
```

**Calls**: [initialize](#initialize)

### open_in_memory

```
function Database.open_in_memory() -> Database:
    manager = SqliteConnectionManager(memory)
    pool = Pool.build(max_size: 1)
    db = Database { pool }
    db.initialize()
    → db
```

**Calls**: [initialize](#initialize)

### initialize

```
function initialize():
    conn = connection()

    "Configure SQLite for performance"
    PRAGMA journal_mode = WAL
    PRAGMA synchronous = NORMAL
    PRAGMA cache_size = -64000   // 64MB cache
    PRAGMA foreign_keys = ON
    PRAGMA temp_store = MEMORY
    PRAGMA busy_timeout = 30000

    tables_exist = DB SELECT COUNT(*) > 0
        FROM sqlite_master
        WHERE type='table' AND name='storestate'

    if tables_exist:
        if needs_migration(conn):
            run_migrations(conn)
        verify_schema(conn)
    else:
        initialize_schema(conn)
```

**Calls**: [needs_migration](migrations.pc.md#needs_migration) | [run_migrations](migrations.pc.md#run_migrations) | [verify_schema](migrations.pc.md#verify_schema) | [initialize_schema](migrations.pc.md#initialize_schema)

### upgrade

```
function upgrade():
    conn = connection()
    run_migrations(conn)
```

**Calls**: [run_migrations](migrations.pc.md#run_migrations)

### schema_version

```
function schema_version() -> integer:
    conn = connection()
    → get_schema_version(conn)
```

**Calls**: [get_schema_version](migrations.pc.md#get_schema_version)

---

## Database — Ledger Operations

### get_latest_ledger_seq

```
function get_latest_ledger_seq() -> integer or none:
    → with_connection(conn →
        conn.get_latest_ledger_seq())
```

**Calls**: [get_latest_ledger_seq](queries/ledger.pc.md#get_latest_ledger_seq)

### get_ledger_header

```
function get_ledger_header(seq) -> LedgerHeader or none:
    → with_connection(conn →
        conn.load_ledger_header(seq))
```

**Calls**: [load_ledger_header](queries/ledger.pc.md#load_ledger_header)

### get_ledger_hash

```
function get_ledger_hash(seq) -> Hash256 or none:
    → with_connection(conn →
        conn.get_ledger_hash(seq))
```

**Calls**: [get_ledger_hash](queries/ledger.pc.md#get_ledger_hash)

---

## Database — Network Configuration

### get_network_passphrase

```
function get_network_passphrase() -> string or none:
    → with_connection(conn →
        conn.get_state(NETWORK_PASSPHRASE))
```

**Calls**: [get_state](queries/state.pc.md#get_state)

### set_network_passphrase

```
function set_network_passphrase(passphrase):
    with_connection(conn →
        conn.set_state(NETWORK_PASSPHRASE, passphrase))
```

**Calls**: [set_state](queries/state.pc.md#set_state)

---

## Database — Transaction History

### get_tx_history_entry

```
function get_tx_history_entry(seq)
    -> TransactionHistoryEntry or none:
    → with_connection(conn →
        conn.load_tx_history_entry(seq))
```

**Calls**: [load_tx_history_entry](queries/history.pc.md#load_tx_history_entry)

### get_tx_result_entry

```
function get_tx_result_entry(seq)
    -> TransactionHistoryResultEntry or none:
    → with_connection(conn →
        conn.load_tx_result_entry(seq))
```

**Calls**: [load_tx_result_entry](queries/history.pc.md#load_tx_result_entry)

---

## Database — SCP State

### store_scp_history

```
function store_scp_history(seq, envelopes):
    with_connection(conn →
        conn.store_scp_history(seq, envelopes))
```

**Calls**: [store_scp_history](queries/scp.pc.md#store_scp_history)

### load_scp_history

```
function load_scp_history(seq)
    -> list of ScpEnvelope:
    → with_connection(conn →
        conn.load_scp_history(seq))
```

**Calls**: [load_scp_history](queries/scp.pc.md#load_scp_history)

### store_scp_quorum_set

```
function store_scp_quorum_set(hash, last_ledger_seq,
                              quorum_set):
    with_connection(conn →
        conn.store_scp_quorum_set(
            hash, last_ledger_seq, quorum_set))
```

**Calls**: [store_scp_quorum_set](queries/scp.pc.md#store_scp_quorum_set)

### load_scp_quorum_set

```
function load_scp_quorum_set(hash)
    -> ScpQuorumSet or none:
    → with_connection(conn →
        conn.load_scp_quorum_set(hash))
```

**Calls**: [load_scp_quorum_set](queries/scp.pc.md#load_scp_quorum_set)

---

## Database — Maintenance

### delete_old_ledger_headers

```
function delete_old_ledger_headers(max_ledger, count)
    -> integer:
    → with_connection(conn →
        conn.delete_old_ledger_headers(max_ledger, count))
```

**Calls**: [delete_old_ledger_headers](queries/ledger.pc.md#delete_old_ledger_headers)

### delete_old_scp_entries

```
function delete_old_scp_entries(max_ledger, count)
    -> integer:
    → with_connection(conn →
        conn.delete_old_scp_entries(max_ledger, count))
```

**Calls**: [delete_old_scp_entries](queries/scp.pc.md#delete_old_scp_entries)

---

## Database — Bucket List

### store_bucket_list

```
function store_bucket_list(seq, levels):
    with_connection(conn →
        conn.store_bucket_list(seq, levels))
```

**Calls**: [store_bucket_list](queries/bucket_list.pc.md#store_bucket_list)

### load_bucket_list

```
function load_bucket_list(seq)
    -> list of (Hash256, Hash256) or none:
    → with_connection(conn →
        conn.load_bucket_list(seq))
```

**Calls**: [load_bucket_list](queries/bucket_list.pc.md#load_bucket_list)

---

## Database — Peer Management

### load_peers

```
function load_peers(limit)
    -> list of (host, port, PeerRecord):
    → with_connection(conn →
        conn.load_peers(limit))
```

**Calls**: [load_peers](queries/peers.pc.md#load_peers)

### store_peer

```
function store_peer(host, port, record):
    with_connection(conn →
        conn.store_peer(host, port, record))
```

**Calls**: [store_peer](queries/peers.pc.md#store_peer)

### load_peer

```
function load_peer(host, port) -> PeerRecord or none:
    → with_connection(conn →
        conn.load_peer(host, port))
```

**Calls**: [load_peer](queries/peers.pc.md#load_peer)

### remove_peers_with_failures

```
function remove_peers_with_failures(min_failures):
    with_connection(conn →
        conn.remove_peers_with_failures(min_failures))
```

**Calls**: [remove_peers_with_failures](queries/peers.pc.md#remove_peers_with_failures)

### load_random_peers

```
function load_random_peers(limit, max_failures,
                           now, peer_type):
    → with_connection(conn →
        conn.load_random_peers(
            limit, max_failures, now, peer_type))
```

**Calls**: [load_random_peers](queries/peers.pc.md#load_random_peers)

### load_random_peers_any_outbound

```
function load_random_peers_any_outbound(
    limit, max_failures, now, inbound_type):
    → with_connection(conn →
        conn.load_random_peers_any_outbound(
            limit, max_failures, now, inbound_type))
```

**Calls**: [load_random_peers_any_outbound](queries/peers.pc.md#load_random_peers_any_outbound)

### load_random_peers_any_outbound_max_failures

```
function load_random_peers_any_outbound_max_failures(
    limit, max_failures, inbound_type):
    → with_connection(conn →
        conn.load_random_peers_any_outbound_max_failures(
            limit, max_failures, inbound_type))
```

**Calls**: [load_random_peers_any_outbound_max_failures](queries/peers.pc.md#load_random_peers_any_outbound_max_failures)

### load_random_peers_by_type_max_failures

```
function load_random_peers_by_type_max_failures(
    limit, max_failures, peer_type):
    → with_connection(conn →
        conn.load_random_peers_by_type_max_failures(
            limit, max_failures, peer_type))
```

**Calls**: [load_random_peers_by_type_max_failures](queries/peers.pc.md#load_random_peers_by_type_max_failures)

---

## Database — Publish Queue

### enqueue_publish

```
function enqueue_publish(ledger_seq):
    with_connection(conn →
        conn.enqueue_publish(ledger_seq))
```

**Calls**: [enqueue_publish](queries/publish_queue.pc.md#enqueue_publish)

### remove_publish

```
function remove_publish(ledger_seq):
    with_connection(conn →
        conn.remove_publish(ledger_seq))
```

**Calls**: [remove_publish](queries/publish_queue.pc.md#remove_publish)

### load_publish_queue

```
function load_publish_queue(limit) -> list of integers:
    → with_connection(conn →
        conn.load_publish_queue(limit))
```

**Calls**: [load_publish_queue](queries/publish_queue.pc.md#load_publish_queue)

---

## Database — Ban List

### ban_node

```
function ban_node(node_id):
    with_connection(conn → conn.ban_node(node_id))
```

**Calls**: [ban_node](queries/ban.pc.md#ban_node)

### unban_node

```
function unban_node(node_id):
    with_connection(conn → conn.unban_node(node_id))
```

**Calls**: [unban_node](queries/ban.pc.md#unban_node)

### is_banned

```
function is_banned(node_id) -> boolean:
    → with_connection(conn → conn.is_banned(node_id))
```

**Calls**: [is_banned](queries/ban.pc.md#is_banned)

### load_bans

```
function load_bans() -> list of strings:
    → with_connection(conn → conn.load_bans())
```

**Calls**: [load_bans](queries/ban.pc.md#load_bans)

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 515    | 178        |
| Functions    | 28     | 28         |
