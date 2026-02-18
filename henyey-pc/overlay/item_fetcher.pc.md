# Pseudocode: crates/overlay/src/item_fetcher.rs

## Overview

"Item fetcher for TxSet and QuorumSet retrieval."

Implements the ItemFetcher and Tracker classes from stellar-core.
Manages asking peers for Transaction Sets and Quorum Sets during SCP consensus.

**Protocol:**
1. When an SCP envelope references an unknown TxSet or QuorumSet, we fetch it
2. The tracker asks peers one at a time with a timeout
3. If a peer responds with DONT_HAVE, we try the next peer
4. If we exhaust all peers, we restart with exponential backoff
5. When the item is received, all waiting envelopes are re-processed

---

### ENUM ItemType

```
ENUM ItemType:
  TxSet
  QuorumSet
```

---

### STRUCT ItemFetcherConfig

```
STRUCT ItemFetcherConfig:
  fetch_reply_timeout: duration   default 1500ms
  max_rebuild_fetch_list: integer default 10
```

---

### STRUCT Tracker

"State machine for fetching a single item from peers."

```
STRUCT Tracker:
  item_hash: Hash
  config: ItemFetcherConfig
  peers_asked: Map<PeerId, boolean>   "peer → had_before"
  last_asked_peer: optional PeerId
  waiting_envelopes: list of (envelope_hash, ScpEnvelope)
  fetch_start: timestamp
  last_ask_time: optional timestamp
  num_list_rebuild: integer
  last_seen_slot_index: integer
```

---

### Tracker::new

```
function new(item_hash, config) → Tracker:
  → Tracker {
      item_hash, config,
      peers_asked: empty,
      last_asked_peer: none,
      waiting_envelopes: empty,
      fetch_start: now,
      last_ask_time: none,
      num_list_rebuild: 0,
      last_seen_slot_index: 0,
    }
```

---

### listen

"Add an envelope to the waiting list."

```
function listen(self, env):
  MUTATE last_seen_slot_index =
    max(last_seen_slot_index, env.statement.slot_index)

  env_hash = compute_envelope_hash(env)

  "Don't track the same envelope twice"
  GUARD waiting_envelopes already contains env_hash → return

  waiting_envelopes.add((env_hash, env))
```

**Calls**: [compute_envelope_hash](#compute_envelope_hash)

---

### discard

```
function discard(self, env):
  env_hash = compute_envelope_hash(env)
  remove from waiting_envelopes where hash == env_hash
```

**Calls**: [compute_envelope_hash](#compute_envelope_hash)

---

### cancel

```
function cancel(self):
  MUTATE last_ask_time = none
  MUTATE last_seen_slot_index = 0
```

---

### clear

"Called after catchup to release memory."

```
function clear(self):
  waiting_envelopes.clear()
  MUTATE last_ask_time = none
  MUTATE last_seen_slot_index = 0
```

---

### clear_envelopes_below

"Returns true if at least one envelope remains."

```
function clear_envelopes_below(self, slot_index, slot_to_keep) → boolean:
  keep only envelopes where:
    env.slot_index >= slot_index OR env.slot_index == slot_to_keep

  if waiting_envelopes is empty:
    cancel()
    → false
  → true
```

**Calls**: [cancel](#cancel)

---

### doesnt_have

"Handle a DONT_HAVE response from a peer."

```
function doesnt_have(self, peer) → boolean:
  if last_asked_peer == peer:
    MUTATE last_asked_peer = none
    → true
  → false
```

---

### can_ask_peer

```
function can_ask_peer(self, peer, peer_has) → boolean:
  if peer not in peers_asked:
    → true
  had_before = peers_asked[peer]
  → peer_has AND NOT had_before
```

---

### try_next_peer

"Select the next peer to ask. Returns peer or wait instruction."

```
function try_next_peer(self, available_peers) → NextPeerResult:
  if last_asked_peer is set:
    MUTATE last_asked_peer = none

  "Find peers we haven't asked yet"
  candidates = [p for p in available_peers
                 if can_ask_peer(p, false)]

  if candidates is not empty:
    peer = candidates.first()
    MUTATE last_asked_peer = peer
    MUTATE peers_asked[peer] = false
    MUTATE last_ask_time = now

    → AskPeer { peer, timeout: config.fetch_reply_timeout }

  else:
    "We've asked all peers, rebuild the list"
    MUTATE num_list_rebuild += 1
    MUTATE peers_asked.clear()

    wait_time = fetch_reply_timeout
      * min(num_list_rebuild, max_rebuild_fetch_list)

    → Wait { duration: wait_time }
```

**Calls**: [can_ask_peer](#can_ask_peer)

---

### is_timed_out

```
function is_timed_out(self) → boolean:
  if last_ask_time exists:
    → elapsed >= config.fetch_reply_timeout
  → false
```

---

### ENUM NextPeerResult

```
ENUM NextPeerResult:
  AskPeer { peer: PeerId, timeout: duration }
  Wait { duration: duration }
```

---

### STRUCT ItemFetcher

```
STRUCT ItemFetcher:
  config: ItemFetcherConfig
  item_type: ItemType
  trackers: locked Map<Hash, Tracker>
  ask_peer: optional callback(PeerId, Hash, ItemType)
  available_peers: locked list of PeerId
```

---

### ItemFetcher::new

```
function new(item_type, config) → ItemFetcher:
  → ItemFetcher {
      config, item_type,
      trackers: empty map,
      ask_peer: none,
      available_peers: empty list,
    }
```

---

### set_ask_peer

```
function set_ask_peer(self, callback):
  MUTATE self.ask_peer = callback
```

---

### set_available_peers

```
function set_available_peers(self, peers):
  MUTATE available_peers = peers
```

---

### fetch

"Start fetching an item needed by an envelope.
 Immediately tries to fetch from a peer if callback is set."

```
function fetch(self, item_hash, envelope):
  available_peers = copy of self.available_peers

  if trackers contains item_hash:
    "Already tracking, just add the envelope"
    trackers[item_hash].listen(envelope)
  else:
    "Create new tracker"
    tracker = Tracker::new(item_hash, config)
    tracker.listen(envelope)

    "Immediately try to fetch from a peer"
    if ask_peer callback is set:
      result = tracker.try_next_peer(available_peers)
      if result is AskPeer { peer, .. }:
        ask_peer(peer, item_hash, item_type)

    trackers[item_hash] = tracker
```

**Calls**: [Tracker::new](#trackernew) | [listen](#listen) | [try_next_peer](#try_next_peer)

---

### stop_fetch

"Stop fetching for a specific envelope. If others still need it, continues."

```
function stop_fetch(self, item_hash, envelope):
  if trackers contains item_hash:
    trackers[item_hash].discard(envelope)
    if tracker.is_empty():
      tracker.cancel()
```

**Calls**: [discard](#discard) | [cancel](#cancel)

---

### get_last_seen_slot_index

```
function get_last_seen_slot_index(self, item_hash) → integer:
  → trackers[item_hash].last_seen_slot_index (or 0 if not found)
```

---

### fetching_for

```
function fetching_for(self, item_hash) → list of ScpEnvelope:
  → envelopes from trackers[item_hash].waiting_envelopes
    (or empty list if not found)
```

---

### stop_fetching_below

```
function stop_fetching_below(self, slot_index, slot_to_keep):
  remove trackers where:
    tracker.clear_envelopes_below(slot_index, slot_to_keep) returns false
```

**Calls**: [clear_envelopes_below](#clear_envelopes_below)

---

### doesnt_have

```
function doesnt_have(self, item_hash, peer):
  if trackers contains item_hash:
    trackers[item_hash].doesnt_have(peer)
```

---

### recv

"Called when an item is received. Returns waiting envelopes."

```
function recv(self, item_hash) → list of ScpEnvelope:
  if trackers contains item_hash:
    tracker = trackers[item_hash]

    "Drain all waiting envelopes"
    envelopes = take all from tracker.waiting_envelopes

    tracker.reset_last_seen_slot_index()
    tracker.cancel()

    → envelopes
  else:
    → empty list
```

---

### get_pending_requests

"Get items that need to be requested from peers."

```
function get_pending_requests(self, available_peers)
    → list of PendingRequest:

  requests = empty list

  for each (hash, tracker) in trackers:
    GUARD tracker.is_empty() → skip

    "Check if we need to ask a new peer"
    if tracker.last_asked_peer is none OR tracker.is_timed_out():
      result = tracker.try_next_peer(available_peers)
      if result is AskPeer { peer, timeout }:
        requests.add(PendingRequest { hash, peer, timeout })

  → requests
```

**Calls**: [is_timed_out](#is_timed_out) | [try_next_peer](#try_next_peer)

---

### process_pending

"Process pending requests and invoke callbacks. Called periodically."

```
function process_pending(self) → integer:
  available_peers = copy of self.available_peers
  requests = get_pending_requests(available_peers)

  GUARD requests is empty → return 0

  sent = 0
  if ask_peer callback is set:
    for each request in requests:
      ask_peer(request.peer, request.item_hash, item_type)
      sent += 1

  → sent
```

**Calls**: [get_pending_requests](#get_pending_requests)

---

### is_tracking

```
function is_tracking(self, item_hash) → boolean:
  → trackers contains item_hash
```

---

### num_trackers

```
function num_trackers(self) → integer:
  → trackers.size()
```

---

### get_stats

```
function get_stats(self) → ItemFetcherStats:
  total_waiting = 0
  oldest_duration = 0

  for each tracker in trackers:
    total_waiting += tracker.length
    oldest_duration = max(oldest_duration, tracker.get_duration())

  → ItemFetcherStats {
      item_type,
      num_trackers: trackers.size(),
      total_waiting_envelopes: total_waiting,
      oldest_fetch_duration: oldest_duration,
    }
```

---

### ItemFetcher::clear

"Clear all trackers and pending state. Called after catchup."

```
function clear(self):
  trackers.clear()
```

---

### Helper: compute_envelope_hash

"Compute hash of an SCP envelope for tracking.
 Uses BLAKE2b-256 of the StellarMessage wrapping the envelope,
 matching stellar-core's xdrBlake2."

```
function compute_envelope_hash(env) → Hash:
  msg = StellarMessage::ScpMessage(env)
  xdr_bytes = serialize msg to XDR
  → BLAKE2b-256(xdr_bytes)
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 668    | 193        |
| Functions     | 27     | 27         |
