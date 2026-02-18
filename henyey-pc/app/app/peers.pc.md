## Pseudocode: crates/app/src/app/peers.rs

### peer_snapshots

```
→ delegate_to(overlay.peer_snapshots)
  if no overlay available → empty list
```

### connect_peer

```
GUARD overlay not available → error
→ overlay.connect(addr)
```

### disconnect_peer

```
GUARD overlay not available → false
→ overlay.disconnect(peer_id)
```

### ban_peer

```
GUARD peer_id_to_strkey fails → error "Invalid peer id"
db.ban_node(strkey)                  REF: henyey_db::ban_node
GUARD overlay not available → error
overlay.ban_peer(peer_id)
```

### unban_peer

```
GUARD peer_id_to_strkey fails → error "Invalid peer id"
db.unban_node(strkey)                REF: henyey_db::unban_node
GUARD overlay not available → error
→ overlay.unban_peer(peer_id)
```

### banned_peers

```
bans = db.load_bans()               REF: henyey_db::load_bans
peers = []
for each ban in bans:
  if strkey_to_peer_id(ban) succeeds:
    append to peers
→ peers
```

### maintain_peers

"This function must NOT hold the overlay lock during connection
attempts, because each connect can take 30-90 seconds."

```
CONST MIN_PEERS = 3
CONST PER_CONNECT_TIMEOUT = 15s
CONST OVERALL_TIMEOUT = 20s

db.remove_peers_with_failures(max_failures)

"Phase 1: Acquire lock briefly to check peer count
 and collect candidates."
GUARD overlay not available → return
peer_count = overlay.peer_count()
GUARD peer_count >= MIN_PEERS → return

candidates = refresh_known_peers(overlay)

"Phase 2: Connect to candidates concurrently WITHOUT
 holding the overlay lock."
GUARD overlay not available → return

for each candidate (concurrently):
  with timeout(PER_CONNECT_TIMEOUT):
    overlay.connect(candidate)

with timeout(OVERALL_TIMEOUT):
  await all connect futures

if any reconnected:
  sleep(200ms)  "Give peers time to complete handshake"
  request_scp_state_from_peers()
```

**Calls**: [refresh_known_peers](#refresh_known_peers) | [request_scp_state_from_peers](mod.pc.md#request_scp_state_from_peers)

### Helper: next_ping_hash

```
counter = atomic_increment(ping_counter)
→ hash(counter as big-endian bytes)
```

### send_peer_pings

```
CONST PING_TIMEOUT = 60s

"Phase 1: Collect snapshots (no long-lived lock needed)."
GUARD overlay not available → return
snapshots = overlay.peer_snapshots()
GUARD snapshots not empty → return

"Phase 2: Build the to_ping list (no overlay lock needed)."
now = current_time()
lock inflight and peer_inflight maps

"Expire timed-out pings"
for each (hash, info) in inflight:
  if elapsed > PING_TIMEOUT:
    if peer_inflight[info.peer_id] == hash:
      remove from peer_inflight
    remove from inflight

to_ping = []
for each snapshot in snapshots:
  if peer already has inflight ping → skip
  hash = next_ping_hash()
  peer_inflight[peer_id] = hash
  inflight[hash] = PingInfo(peer_id, now)
  append (peer_id, hash) to to_ping

unlock inflight and peer_inflight

"Phase 3: Send pings concurrently."
GUARD overlay not available → return
for each (peer, hash) in to_ping:
  msg = GetScpQuorumset(hash)
  if send fails:
    remove hash from inflight
    if peer_inflight[peer] == hash:
      remove from peer_inflight
```

**Calls**: [next_ping_hash](#helper-next_ping_hash)

### process_ping_response

```
hash = Hash256(raw_hash)
info = inflight.remove(hash)
GUARD info exists → return

if peer_inflight[info.peer_id] == hash:
  remove from peer_inflight

GUARD info.peer_id == peer_id → return

latency_ms = elapsed since info.sent_at
survey_data.record_peer_latency(peer_id, latency_ms)
```

### process_peer_list

```
GUARD overlay not available → return

"Convert XDR peer addresses to internal format"
addrs = []
for each xdr_addr in peer_list:
  if IPv6 → skip
  ip = format IPv4 bytes
  port = xdr_addr.port
  if port == 0 → skip
  append PeerAddress(ip, port)

addrs = filter_discovered_peers(addrs)
if addrs not empty:
  persist_peers(addrs)
  count = overlay.add_peers(addrs)

refresh_known_peers(overlay)
```

**Calls**: [filter_discovered_peers](#filter_discovered_peers) | [persist_peers](#persist_peers) | [refresh_known_peers](#refresh_known_peers)

### Helper: parse_peer_address

```
parts = value.split(':')
if 1 part  → PeerAddress(parts[0], default_port=11625)
if 2 parts → PeerAddress(parts[0], parse(parts[1]))
otherwise  → none
```

### Helper: peer_id_to_strkey

```
pk = PublicKey.from_bytes(peer_id)    REF: henyey_crypto::PublicKey
→ pk.to_strkey()
```

### Helper: strkey_to_peer_id

```
pk = PublicKey.from_strkey(value)     REF: henyey_crypto::PublicKey
→ PeerId.from_bytes(pk.bytes)
```

### load_persisted_peers

```
now = current_epoch_seconds()
peers = db.load_random_peers(        REF: henyey_db::load_random_peers
  limit=1000,
  max_failures,
  now,
  type=PEER_TYPE_OUTBOUND
)
→ convert (host, port) tuples to PeerAddress list
```

### store_config_peers

```
now = current_epoch_seconds()
for each addr in config.overlay.known_peers:
  peer = parse_peer_address(addr)
  if valid: db.store_peer(host, port,
    PeerRecord(now, failures=0, PEER_TYPE_OUTBOUND))

for each addr in config.overlay.preferred_peers:
  peer = parse_peer_address(addr)
  if valid: db.store_peer(host, port,
    PeerRecord(now, failures=0, PEER_TYPE_PREFERRED))
```

**Calls**: [parse_peer_address](#helper-parse_peer_address)

### Helper: load_advertised_outbound_peers

```
peers = db.load_random_peers_any_outbound_max_failures(
  limit=1000,
  PEER_MAX_FAILURES_TO_SEND,
  PEER_TYPE_INBOUND
)
→ convert to PeerAddress list
```

### Helper: load_advertised_inbound_peers

```
peers = db.load_random_peers_by_type_max_failures(
  limit=1000,
  PEER_MAX_FAILURES_TO_SEND,
  PEER_TYPE_INBOUND
)
→ convert to PeerAddress list
```

### persist_peers

```
now = current_epoch_seconds()
for each peer in peers:
  existing = db.load_peer(host, port)
  if existing → skip (already known)
  db.store_peer(host, port,
    PeerRecord(now, failures=0, PEER_TYPE_OUTBOUND))
```

### filter_discovered_peers

```
now = current_epoch_seconds()
filtered = []
for each peer in peers:
  if not is_public_peer(peer) → skip
  record = db.load_peer(peer.host, peer.port)
  if record exists:
    if record.num_failures >= max_failures → skip
    if record.next_attempt > now → skip
  append peer to filtered
→ filtered
```

**Calls**: [is_public_peer](#helper-is_public_peer)

### Helper: filter_advertised_peers

```
→ peers filtered by is_public_peer
```

### Helper: is_public_peer

```
if port == 0 → false
if host is not valid IP → true (treat as hostname)
if IPv4:
  reject private, loopback, link-local,
    multicast, unspecified
if IPv6 → false
```

### refresh_known_peers

```
"Build known peers list from config + DB"
peers = []
for each addr in config.known_peers:
  append parse_peer_address(addr)
for each addr in config.preferred_peers:
  upsert_peer_type(addr, PEER_TYPE_PREFERRED)
  append parse_peer_address(addr)
append load_persisted_peers()

peers = filter_discovered_peers(peers)
peers = dedupe_peers(peers)
overlay.set_known_peers(peers)

"Build advertised outbound list"
advertised_outbound = []
for each addr in config.known_peers:
  append parse_peer_address(addr)
for each addr in config.preferred_peers:
  append parse_peer_address(addr)
append load_advertised_outbound_peers()
advertised_outbound = filter_advertised_peers(...)
advertised_outbound = dedupe_peers(...)

"Build advertised inbound list"
advertised_inbound = load_advertised_inbound_peers()
advertised_inbound = filter_advertised_peers(...)
advertised_inbound = dedupe_peers(...)

overlay.set_advertised_peers(
  advertised_outbound, advertised_inbound)

→ peers
```

**Calls**: [parse_peer_address](#helper-parse_peer_address) | [upsert_peer_type](#helper-upsert_peer_type) | [load_persisted_peers](#load_persisted_peers) | [filter_discovered_peers](#filter_discovered_peers) | [dedupe_peers](#helper-dedupe_peers) | [load_advertised_outbound_peers](#helper-load_advertised_outbound_peers) | [load_advertised_inbound_peers](#helper-load_advertised_inbound_peers) | [filter_advertised_peers](#helper-filter_advertised_peers)

### Helper: upsert_peer_type

```
now = current_epoch_seconds()
existing = db.load_peer(host, port)
if existing:
  record = PeerRecord(existing.next_attempt,
    existing.num_failures, peer_type)
else:
  record = PeerRecord(now, 0, peer_type)
db.store_peer(host, port, record)
```

### Helper: dedupe_peers

```
seen = set()
deduped = []
for each peer in peers:
  socket_addr = peer.to_socket_addr()
  if socket_addr not in seen:
    seen.add(socket_addr)
    append peer to deduped
→ deduped
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~520   | ~220       |
| Functions     | 21     | 21         |
