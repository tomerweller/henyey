# Pseudocode: crates/db/src/queries/peers.rs

"The peer table tracks known network peers with their connection state,
enabling persistent peer discovery and connection retry logic.

Peer types (application-defined):
  0: Inbound (peer connected to us)
  1: Preferred (configured preferred peers)
  2: Outbound (we connected to peer)"

## Struct: PeerRecord

```
struct PeerRecord:
    next_attempt   — unix timestamp for next connection attempt
    num_failures   — consecutive connection failure count
    peer_type      — peer category (inbound/preferred/outbound)
```

## Helper: peer_row

```
function peer_row(db_row) -> (host, port, PeerRecord):
    → (row.ip, row.port as u16,
       PeerRecord(row.nextattempt,
                  row.numfailures,
                  row.type))
```

## Trait: PeerQueries

### load_peer

```
function load_peer(host, port) -> PeerRecord or none:
    → DB SELECT nextattempt, numfailures, type
          FROM peers
          WHERE ip = host AND port = port
      (returns none if row absent)
```

### store_peer

```
function store_peer(host, port, record):
    DB INSERT OR REPLACE INTO peers
        (ip, port, nextattempt, numfailures, type)
        VALUES (host, port,
                record.next_attempt,
                record.num_failures,
                record.peer_type)
```

### load_peers

```
function load_peers(limit) -> list of (host, port, PeerRecord):
    sql = "SELECT ip, port, nextattempt, numfailures, type
           FROM peers"
    if limit is set:
        sql += " LIMIT limit"
    → execute sql, map each row with peer_row
```

**Calls**: [peer_row](#helper-peer_row)

### load_random_peers

```
function load_random_peers(limit, max_failures, now,
                           peer_type) -> list:
    sql = "SELECT ... FROM peers
           WHERE numfailures <= max_failures
             AND nextattempt <= now"
    if peer_type is set:
        sql += " AND type = peer_type"
    sql += " ORDER BY RANDOM() LIMIT limit"
    → execute sql, map each row with peer_row
```

**Calls**: [peer_row](#helper-peer_row)

### load_random_peers_any_outbound

```
function load_random_peers_any_outbound(
    limit, max_failures, now, inbound_type) -> list:
    → DB SELECT ... FROM peers
          WHERE numfailures <= max_failures
            AND nextattempt <= now
            AND type != inbound_type
          ORDER BY RANDOM() LIMIT limit
```

**Calls**: [peer_row](#helper-peer_row)

### load_random_peers_any_outbound_max_failures

"Ignores next attempt time — useful for aggressive
peer discovery when the peer table is sparse."

```
function load_random_peers_any_outbound_max_failures(
    limit, max_failures, inbound_type) -> list:
    → DB SELECT ... FROM peers
          WHERE numfailures <= max_failures
            AND type != inbound_type
          ORDER BY RANDOM() LIMIT limit
```

**Calls**: [peer_row](#helper-peer_row)

### load_random_peers_by_type_max_failures

```
function load_random_peers_by_type_max_failures(
    limit, max_failures, peer_type) -> list:
    → DB SELECT ... FROM peers
          WHERE numfailures <= max_failures
            AND type = peer_type
          ORDER BY RANDOM() LIMIT limit
```

**Calls**: [peer_row](#helper-peer_row)

### remove_peers_with_failures

"Garbage collection of persistently unreachable peers."

```
function remove_peers_with_failures(min_failures):
    DB DELETE FROM peers
        WHERE numfailures >= min_failures
```

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 139    | 62         |
| Functions    | 8      | 8          |
