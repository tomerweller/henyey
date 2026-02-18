# Pseudocode: crates/overlay/src/flood.rs

## Overview

"Flood gate for managing message propagation and duplicate detection."

The Stellar overlay propagates certain message types to all connected peers.
The FloodGate tracks which messages have been seen and from which peers to
prevent infinite loops and reduce bandwidth.

- **Duplicate Detection**: Messages identified by BLAKE2b-256 hash (matching stellar-core's `xdrBlake2`)
- **Peer Tracking**: Records which peers sent each message to avoid forwarding back
- **TTL-based Expiry**: Old entries cleaned up after configurable TTL
- **Rate Limiting**: Soft limit on messages per second

```
CONST DEFAULT_TTL_SECS = 300         // 5 minutes
CONST MAX_ENTRIES = 100_000          // prevents unbounded memory growth
CONST CLEANUP_INTERVAL_SECS = 60    // 1 minute
CONST DEFAULT_RATE_LIMIT_PER_SEC = 1000
```

---

### STRUCT SeenEntry

```
STRUCT SeenEntry:
  first_seen: timestamp
  ledger_seq: integer         "ledger sequence when first seen"
  peers: Set<PeerId>          "peers that sent us this message"
```

---

### STRUCT FloodGate

```
STRUCT FloodGate:
  seen: Map<Hash256, SeenEntry>
  ttl: duration
  last_cleanup: timestamp
  messages_seen: counter       "total messages processed"
  messages_dropped: counter    "duplicate messages dropped"
  rate_limit: integer          "max messages per second"
  rate_window_start: timestamp
  rate_window_count: counter
```

---

### new / with_ttl

```
function new() → FloodGate:
  → with_ttl(DEFAULT_TTL_SECS)

function with_ttl(ttl) → FloodGate:
  → FloodGate with empty seen map, given ttl,
    rate_limit = DEFAULT_RATE_LIMIT_PER_SEC
```

---

### should_flood

```
function should_flood(self, message_hash) → boolean:
  → seen does NOT contain message_hash
```

---

### record_seen

"Records that a message has been seen, optionally from a specific peer.
 Returns true if first time seeing this message (should flood),
 false if duplicate (should drop)."

```
function record_seen(self, message_hash, from_peer, ledger_seq) → boolean:
  increment messages_seen counter
  maybe_cleanup()

  if seen contains message_hash:
    entry = seen[message_hash]
    if from_peer is provided:
      MUTATE entry.peers add from_peer
    increment messages_dropped counter
    → false

  "New message"
  entry = SeenEntry { now, ledger_seq, empty peers }
  if from_peer is provided:
    entry.peers.add(from_peer)
  seen[message_hash] = entry
  → true
```

**Calls**: [maybe_cleanup](#maybe_cleanup)

---

### allow_message

"Checks if another message is allowed under the rate limit."

```
function allow_message(self) → boolean:
  now = current time
  if elapsed since rate_window_start >= 1 second:
    rate_window_start = now
    rate_window_count = 0

  increment rate_window_count
  → rate_window_count <= rate_limit
```

---

### get_forward_peers

"Returns list of peers to forward a message to, excluding peers
 that already sent us this message."

```
function get_forward_peers(self, message_hash, all_peers) → list of PeerId:
  exclude = seen[message_hash].peers (or empty set if not found)
  → [peer for peer in all_peers if peer not in exclude]
```

---

### has_seen

```
function has_seen(self, message_hash) → boolean:
  → seen contains message_hash
```

---

### cleanup

"Forces immediate cleanup of expired entries."

```
function cleanup(self):
  before_count = seen.size()
  remove all entries from seen where entry.is_expired(ttl)
  removed = before_count - seen.size()
  last_cleanup = now
```

---

### maybe_cleanup

```
function maybe_cleanup(self):
  should_cleanup = (elapsed since last_cleanup > CLEANUP_INTERVAL_SECS)
                   or (seen.size() > MAX_ENTRIES)
  if should_cleanup:
    cleanup()
```

**Calls**: [cleanup](#cleanup)

---

### stats

```
function stats(self) → FloodGateStats:
  → { seen_count, total_messages, dropped_messages }
```

---

### clear_below

"Removes flood records from ledgers before ledger_seq.
 Matches upstream stellar-core's clearBelow(maxLedger)."

```
function clear_below(self, ledger_seq):
  before_count = seen.size()
  remove all entries from seen where:
    entry.ledger_seq < ledger_seq OR entry.is_expired(ttl)
  last_cleanup = now
```

---

### clear

```
function clear(self):
  seen.clear()
  last_cleanup = now
```

---

### STRUCT FloodGateStats

```
STRUCT FloodGateStats:
  seen_count: integer
  total_messages: integer
  dropped_messages: integer
```

### duplicate_rate

```
function duplicate_rate(self) → float:
  if total_messages == 0:
    → 0.0
  → (dropped_messages / total_messages) * 100.0
```

---

### compute_message_hash

"Computes the BLAKE2b-256 hash of a message for flood tracking.
 This matches stellar-core's xdrBlake2() used in Floodgate::broadcast()."

```
function compute_message_hash(message) → Hash256:
  bytes = serialize message to XDR
  → BLAKE2b-256(bytes)
```

---

### STRUCT FloodRecord

```
STRUCT FloodRecord:
  hash: Hash256
  message: StellarMessage
  received: timestamp
  from_peer: optional PeerId
```

### FloodRecord::new

```
function FloodRecord::new(message, from_peer) → FloodRecord:
  hash = compute_message_hash(message)
  → FloodRecord { hash, message, received: now, from_peer }
```

**Calls**: [compute_message_hash](#compute_message_hash)

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 376    | 109        |
| Functions     | 14     | 14         |
