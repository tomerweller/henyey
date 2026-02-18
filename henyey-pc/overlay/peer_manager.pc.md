## Pseudocode: crates/overlay/src/peer_manager.rs

### Constants

```
CONST MAX_FAILURES = 10
CONST SECONDS_PER_BACKOFF = 10
CONST MAX_BACKOFF_EXPONENT = 10
```

### Data Structures

```
StoredPeerType:
  Inbound = 0
  Outbound = 1
  Preferred = 2

PeerTypeFilter:
  InboundOnly | OutboundOnly | PreferredOnly | AnyOutbound

TypeUpdate:
  EnsureOutbound | SetPreferred | EnsureNotPreferred

BackOffUpdate:
  HardReset | Reset | Increase

PeerRecord:
  ip: string
  port: int
  next_attempt: unix_timestamp
  num_failures: int
  peer_type: StoredPeerType

PeerQuery:
  use_next_attempt: bool
  max_num_failures: int or null
  type_filter: PeerTypeFilter

PeerManager:
  cache: Map<(ip, port), PeerRecord>
  db: database connection or null
```

### Database Schema

```
"CREATE TABLE peers (
    ip VARCHAR(15) NOT NULL,
    port INT NOT NULL CHECK (port > 0 AND port <= 65535),
    nextattempt INTEGER NOT NULL,
    numfailures INT DEFAULT 0 CHECK (numfailures >= 0) NOT NULL,
    type INT NOT NULL,
    PRIMARY KEY (ip, port)
)"
```

### PeerRecord::new

```
function PeerRecord.new(ip, port):
  → PeerRecord {
      ip, port,
      next_attempt: now_unix(),
      num_failures: 0,
      peer_type: Inbound
    }
```

### PeerRecord::is_ready

```
function is_ready():
  → next_attempt <= now_unix()
```

### new_in_memory

```
function new_in_memory():
  → PeerManager { cache: empty map, db: null }
```

### new_with_db

```
function new_with_db(db_path):
  conn = open_database(db_path)
  init_db(conn)

  "Load existing peers into cache"
  cache = load_all_from_db(conn)

  → PeerManager { cache, db: conn }
```

### from_connection

```
function from_connection(conn):
  init_db(conn)
  cache = load_all_from_db(conn)
  → PeerManager { cache, db: conn }
```

### load_all_from_db

```
function load_all_from_db(conn):
  rows = query "SELECT ip, port, nextattempt,
                       numfailures, type FROM peers"
  cache = empty map
  for each row in rows:
    record = PeerRecord from row
    cache[(record.ip, record.port)] = record
  → cache
```

### ensure_exists

```
function ensure_exists(address):
  key = (address.host, address.port)

  "Check cache first"
  GUARD key in cache → return (already exists)

  record = PeerRecord.new(address.host, address.port)

  "Insert into database"
  if db is not null:
    execute "INSERT OR IGNORE INTO peers
             VALUES (ip, port, nextattempt,
                     numfailures, type)"

  "Update cache"
  cache[key] = record
```

### load

```
function load(address):
  key = (address.host, address.port)
  → cache[key] or null
```

### store

```
function store(record):
  key = (record.ip, record.port)

  "Update database"
  if db is not null:
    execute "INSERT OR REPLACE INTO peers
             VALUES (ip, port, nextattempt,
                     numfailures, type)"

  "Update cache"
  cache[key] = record
```

### update_type

```
function update_type(address, observed_type,
                     preferred_type_known):
  record = cache[(address.host, address.port)]
           or PeerRecord.new(address.host, address.port)

  type_update = get_type_update(record, observed_type,
                                preferred_type_known)
  apply_type_update(record, type_update)
  store(record)
```

### update_backoff

```
function update_backoff(address, backoff):
  record = cache[(address.host, address.port)]
           or PeerRecord.new(address.host, address.port)

  apply_backoff_update(record, backoff)
  store(record)
```

### update

```
function update(address, observed_type,
                preferred_type_known, backoff):
  record = cache[(address.host, address.port)]
           or PeerRecord.new(address.host, address.port)

  type_update = get_type_update(record, observed_type,
                                preferred_type_known)
  apply_type_update(record, type_update)
  apply_backoff_update(record, backoff)
  store(record)
```

### load_random_peers

```
function load_random_peers(query, size):
  now = now_unix()
  candidates = []

  for each record in cache.values():
    "Check next attempt time"
    if query.use_next_attempt and record.next_attempt > now:
      skip

    "Check failure count"
    if query.max_num_failures is set
       and record.num_failures > query.max_num_failures:
      skip

    "Check type filter"
    if query.type_filter is InboundOnly:
      GUARD record.peer_type != Inbound → skip
    if query.type_filter is OutboundOnly:
      GUARD record.peer_type != Outbound → skip
    if query.type_filter is PreferredOnly:
      GUARD record.peer_type != Preferred → skip
    if query.type_filter is AnyOutbound:
      GUARD record.peer_type == Inbound → skip

    append record to candidates

  "Shuffle and take up to size"
  shuffle(candidates)
  → first size elements as PeerAddress list
```

### remove_peers_with_many_failures

```
function remove_peers_with_many_failures(min_num_failures):
  "Remove from database"
  if db is not null:
    execute "DELETE FROM peers
             WHERE numfailures >= min_num_failures"

  "Remove from cache"
  retain entries where num_failures < min_num_failures
```

### get_peers_to_send

```
function get_peers_to_send(size, exclude):
  candidates = []

  for each record in cache.values():
    "Don't send peer back to itself"
    if record matches exclude: skip

    "Don't send private addresses"
    if record.address.is_private(): skip

    append record to candidates

  "Prefer outbound peers"
  sort candidates by:
    Preferred → 0
    Outbound  → 1
    Inbound   → 2

  → first size elements as PeerAddress list
```

### get_all_peers / peer_count / clear_all

```
function get_all_peers():
  → all cache values

function peer_count():
  → cache.length

function clear_all():
  if db is not null:
    execute "DELETE FROM peers"
  cache.clear()
```

### Helper: get_type_update

```
function get_type_update(record, observed_type,
                         preferred_type_known):
  is_preferred_in_db = (record.peer_type == Preferred)

  if observed_type is Preferred:
    → SetPreferred
  if observed_type is Outbound:
    if is_preferred_in_db and preferred_type_known:
      → EnsureNotPreferred
    else:
      → EnsureOutbound
  if observed_type is Inbound:
    → EnsureNotPreferred
```

### Helper: apply_type_update

```
function apply_type_update(record, update):
  if update is EnsureOutbound:
    if record.peer_type == Inbound:
      MUTATE record.peer_type = Outbound
  if update is SetPreferred:
    MUTATE record.peer_type = Preferred
  if update is EnsureNotPreferred:
    if record.peer_type == Preferred:
      MUTATE record.peer_type = Outbound
```

### Helper: compute_backoff

```
function compute_backoff(num_failures):
  backoff_count = min(num_failures, MAX_BACKOFF_EXPONENT)
  max_seconds = (2^backoff_count) * SECONDS_PER_BACKOFF
  random_seconds = random(1..max_seconds)
  → Duration(random_seconds)
```

### Helper: apply_backoff_update

```
function apply_backoff_update(record, update):
  now = now_unix()

  if update is HardReset:
    MUTATE record.num_failures = 0
    MUTATE record.next_attempt = now

  if update is Reset:
    MUTATE record.num_failures = 0
    backoff = compute_backoff(0)
    MUTATE record.next_attempt = now + backoff

  if update is Increase:
    MUTATE record.num_failures += 1
    backoff = compute_backoff(record.num_failures)
    MUTATE record.next_attempt = now + backoff
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 621    | 195        |
| Functions     | 20     | 20         |
