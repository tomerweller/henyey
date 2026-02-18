## Pseudocode: crates/herder/src/fetching_envelopes.rs

"Handles SCP envelopes waiting for dependencies (TxSets and QuorumSets)
to be fetched from peers. When an envelope arrives referencing data we
don't have, we start fetching it and queue the envelope. Once all
dependencies are received, the envelope is ready for processing."

"This is the Rust equivalent of stellar-core's PendingEnvelopes fetching logic."

### Data Structures

```
ENUM RecvResult:
  Ready             // all dependencies available
  Fetching          // waiting for dependencies
  AlreadyProcessed  // duplicate or already handled
  Discarded         // invalid or rejected

STRUCT SlotEnvelopes:
  discarded: Set<Hash256>
  processed: Set<Hash256>
  fetching:  Map<Hash256, (ScpEnvelope, Timestamp)>
  ready:     List<ScpEnvelope>

STRUCT FetchingConfig:
  tx_set_fetcher_config: ItemFetcherConfig
  quorum_set_fetcher_config: ItemFetcherConfig
  max_slots: int           // default 12
  max_tx_set_cache: int    // default 100
  max_quorum_set_cache: int // default 100

STRUCT FetchingEnvelopes:
  config: FetchingConfig
  slots: ConcurrentMap<SlotIndex, SlotEnvelopes>
  tx_set_fetcher: ItemFetcher
  quorum_set_fetcher: ItemFetcher
  tx_set_cache: ConcurrentMap<Hash256, (SlotIndex, bytes)>
  quorum_set_cache: ConcurrentMap<Hash256, ScpQuorumSet>
  broadcast: nullable callback(ScpEnvelope)
  stats: FetchingStats
```

### recv_envelope

"Returns the result indicating whether the envelope is ready, fetching,
or was already processed/discarded."

```
function recv_envelope(envelope) -> RecvResult:
  slot = envelope.statement.slot_index
  env_hash = compute_envelope_hash(envelope)
  MUTATE stats envelopes_received += 1

  "Parity: reject envelopes with non-SIGNED StellarValues"
  GUARD not check_stellar_value_signed(envelope)
    → Discarded

  slot_state = slots.get_or_create(slot)

  GUARD slot_state.processed.contains(env_hash)
    or slot_state.discarded.contains(env_hash):
    MUTATE stats envelopes_duplicate += 1
    → AlreadyProcessed

  GUARD slot_state.fetching.contains(env_hash)
    → Fetching

  (need_tx_set, need_quorum_set) = check_dependencies(envelope)

  if not need_tx_set and not need_quorum_set:
    "Parity: broadcast to peers when dependencies are satisfied"
    broadcast_envelope(envelope)
    slot_state.ready.append(envelope)
    MUTATE stats envelopes_ready += 1
    → Ready

  if need_tx_set:
    tx_set_hash = extract_tx_set_hash(envelope)
    if tx_set_hash exists:
      tx_set_fetcher.fetch(tx_set_hash, envelope)

  if need_quorum_set:
    qs_hash = extract_quorum_set_hash(envelope)
    if qs_hash exists:
      quorum_set_fetcher.fetch(qs_hash, envelope)

  slot_state.fetching.insert(env_hash, (envelope, now()))
  MUTATE stats envelopes_fetching += 1
  → Fetching
```

**Calls:** [check_stellar_value_signed](#helper-check_stellar_value_signed), [check_dependencies](#helper-check_dependencies), [broadcast_envelope](#helper-broadcast_envelope), [extract_tx_set_hash](#helper-extract_tx_set_hash), [extract_quorum_set_hash](#helper-extract_quorum_set_hash)

### recv_tx_set

```
function recv_tx_set(hash, slot, data) -> bool:
  GUARD not tx_set_fetcher.is_tracking(hash)
    → false

  MUTATE stats tx_sets_received += 1

  evict_tx_set_cache_if_full(slot)
  tx_set_cache.insert(hash, (slot, data))

  waiting = tx_set_fetcher.recv(hash)

  for each env in waiting:
    check_and_move_to_ready(env)

  → true
```

**Calls:** [evict_tx_set_cache_if_full](#helper-evict_tx_set_cache_if_full), [check_and_move_to_ready](#helper-check_and_move_to_ready)

### recv_quorum_set

"Parity: reject insane quorum sets before caching."

```
function recv_quorum_set(hash, quorum_set) -> bool:
  GUARD not quorum_set_fetcher.is_tracking(hash)
    → false

  if not is_quorum_set_sane(quorum_set):
    "Stop tracking so fetching envelopes that depend on it
    eventually time out rather than wait forever"
    quorum_set_fetcher.recv(hash)
    → false

  MUTATE stats quorum_sets_received += 1

  evict_quorum_set_cache_if_full()
  quorum_set_cache.insert(hash, quorum_set)

  waiting = quorum_set_fetcher.recv(hash)

  for each env in waiting:
    check_and_move_to_ready(env)

  → true
```

**Calls:** `is_quorum_set_sane` REF: henyey_scp::is_quorum_set_sane, [evict_quorum_set_cache_if_full](#helper-evict_quorum_set_cache_if_full), [check_and_move_to_ready](#helper-check_and_move_to_ready)

### peer_doesnt_have

```
function peer_doesnt_have(item_type, hash, peer):
  if item_type == TxSet:
    tx_set_fetcher.doesnt_have(hash, peer)
  else if item_type == QuorumSet:
    quorum_set_fetcher.doesnt_have(hash, peer)
```

### pop

"Parity: stellar-core iterates from lowest slot to slotIndex and
returns the first available ready envelope. This ensures envelopes
are processed in slot order."

```
function pop(max_slot) -> nullable ScpEnvelope:
  ready_slots = slots
    .filter(slot <= max_slot and has ready envelopes)
    .sorted_ascending()

  for each slot in ready_slots:
    slot_state = slots.get(slot)
    if slot_state has ready envelopes:
      envelope = slot_state.ready.pop()
      env_hash = compute_envelope_hash(envelope)
      slot_state.processed.insert(env_hash)
      → envelope

  → null
```

### ready_slots

```
function ready_slots() -> List<SlotIndex>:
  → slots
      .filter(has ready envelopes)
      .keys()
      .sorted_ascending()
```

### erase_below

```
function erase_below(slot_index, slot_to_keep):
  "Remove old slots"
  for each slot in slots where slot < slot_index
      and slot != slot_to_keep:
    slots.remove(slot)

  "Evict old tx sets from cache (keeps memory bounded)"
  for each (hash, (s, _)) in tx_set_cache
      where s < slot_index and s != slot_to_keep:
    tx_set_cache.remove(hash)

  "Tell fetchers to stop fetching for old slots"
  tx_set_fetcher.stop_fetching_below(slot_index, slot_to_keep)
  quorum_set_fetcher.stop_fetching_below(slot_index, slot_to_keep)
```

### clear_all

"Called after catchup to release memory from stale data."

```
function clear_all():
  tx_set_cache.clear()
  quorum_set_cache.clear()
  slots.clear()
  tx_set_fetcher.clear()
  quorum_set_fetcher.clear()
```

### trim_stale

"Called after catchup to release memory from stale data while keeping
tx_sets that will be needed for the ledgers immediately after catchup."

"This is critical for avoiding sync gaps: during catchup, we receive
EXTERNALIZE envelopes and cache their tx_sets. After catchup completes,
we need those tx_sets to apply the buffered ledgers."

```
function trim_stale(keep_after_slot):
  slots.retain(slot > keep_after_slot)
  tx_set_cache.retain((_, (slot, _)) where slot > keep_after_slot)
  quorum_set_cache.clear()
  tx_set_fetcher.clear()
  quorum_set_fetcher.clear()
```

### cache_tx_set

```
function cache_tx_set(hash, slot, data):
  evict_tx_set_cache_if_full(slot)
  tx_set_cache.insert(hash, (slot, data))
```

### tx_set_available

"Used when we receive a tx set through other means (not the fetcher)
but want to notify waiting envelopes that the dependency is satisfied."

```
function tx_set_available(hash, slot):
  evict_tx_set_cache_if_full(slot)
  tx_set_cache.insert(hash, (slot, empty_bytes))
  recv_tx_set(hash, slot, empty_bytes)
  move_ready_envelopes_for_tx_set(hash)
```

**Calls:** [recv_tx_set](#recv_tx_set), [move_ready_envelopes_for_tx_set](#helper-move_ready_envelopes_for_tx_set)

### Helper: move_ready_envelopes_for_tx_set

```
function move_ready_envelopes_for_tx_set(tx_set_hash):
  for each slot_entry in slots:
    fetching_to_check = []
    for each (env_hash, (envelope, _)) in slot_entry.fetching:
      if extract_tx_set_hash(envelope) == tx_set_hash:
        fetching_to_check.append((env_hash, envelope))

    for each (_, envelope) in fetching_to_check:
      check_and_move_to_ready(envelope)
```

### cache_quorum_set

```
function cache_quorum_set(hash, quorum_set):
  evict_quorum_set_cache_if_full()
  quorum_set_cache.insert(hash, quorum_set)
```

### Helper: evict_tx_set_cache_if_full

```
function evict_tx_set_cache_if_full(current_slot):
  GUARD tx_set_cache.len() < config.max_tx_set_cache
    → return

  oldest_slot = current_slot
  oldest_hash = null

  for each (hash, (slot, _)) in tx_set_cache:
    if slot < oldest_slot:
      oldest_slot = slot
      oldest_hash = hash

  if oldest_hash exists:
    tx_set_cache.remove(oldest_hash)
```

### Helper: evict_quorum_set_cache_if_full

```
function evict_quorum_set_cache_if_full():
  GUARD quorum_set_cache.len() < config.max_quorum_set_cache
    → return

  hash = quorum_set_cache.any_key()
  quorum_set_cache.remove(hash)
```

### Helper: check_dependencies

"An envelope is ready only when all referenced data is cached."

```
function check_dependencies(envelope) -> (bool, bool):
  need_tx_set = false
  tx_hash = extract_tx_set_hash(envelope)
  if tx_hash exists and not tx_set_cache.contains(tx_hash):
    need_tx_set = true

  need_quorum_set = false
  qs_hash = extract_quorum_set_hash(envelope)
  if qs_hash exists and not quorum_set_cache.contains(qs_hash):
    need_quorum_set = true

  → (need_tx_set, need_quorum_set)
```

### Helper: check_and_move_to_ready

```
function check_and_move_to_ready(envelope):
  slot = envelope.statement.slot_index
  env_hash = compute_envelope_hash(envelope)
  (need_tx_set, need_quorum_set) = check_dependencies(envelope)

  if not need_tx_set and not need_quorum_set:
    "Parity: broadcast to peers when dependencies are satisfied"
    broadcast_envelope(envelope)
    slot_state = slots.get(slot)
    if slot_state.fetching.remove(env_hash) succeeded:
      slot_state.ready.append(envelope)
```

### Helper: broadcast_envelope

```
function broadcast_envelope(envelope):
  if broadcast callback is set:
    broadcast(envelope)
```

### Helper: check_stellar_value_signed

"Parity: stellar-core rejects envelopes containing non-signed
StellarValues in both nomination (votes/accepted) and ballot statements."

```
function check_stellar_value_signed(envelope) -> bool:
  values = extract value bytes from envelope:
    Nominate: all votes + accepted values
    Prepare:  ballot.value
    Confirm:  ballot.value
    Externalize: commit.value

  for each value_bytes in values:
    sv = decode StellarValue from value_bytes
    if decode fails → false
    if sv.ext == Basic → false

  → true
```

### Helper: extract_tx_set_hash

```
function extract_tx_set_hash(envelope) -> nullable Hash256:
  value = envelope.statement.pledges:
    Externalize → commit.value
    Confirm     → ballot.value
    Prepare     → ballot.value
    Nominate    → null

  if value exists:
    sv = decode StellarValue from value
    → sv.tx_set_hash

  → null
```

### Helper: extract_quorum_set_hash

```
function extract_quorum_set_hash(envelope) -> nullable Hash256:
  hash = envelope.statement.pledges:
    Nominate    → quorum_set_hash
    Prepare     → quorum_set_hash
    Confirm     → quorum_set_hash
    Externalize → commit_quorum_set_hash

  → Hash256(hash)
```

### Helper: compute_envelope_hash

```
function compute_envelope_hash(envelope) -> Hash256:
  → hash_xdr(envelope) or ZERO
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~776   | ~240       |
| Functions     | 30     | 26         |
