## Pseudocode: crates/herder/src/persistence.rs

"SCP state persistence for crash recovery. Persisted state includes SCP
envelopes, transaction sets, and quorum sets for recent slots."

"State is persisted to SQLite. On startup, restore_scp_state() loads
persisted tx sets, quorum sets, envelopes, and rebuilds quorum tracker."

### Data: PersistedSlotState

```
CONST CURRENT_VERSION = 1

PersistedSlotState:
  version         // format version
  envelopes       // list<bytes> — XDR-encoded SCP envelopes
  quorum_sets     // list<bytes> — XDR-encoded quorum sets
```

### Data: RestoredScpState

```
RestoredScpState:
  envelopes       // list<(slot, ScpEnvelope)>
  tx_sets         // list<(Hash, bytes)>
  quorum_sets     // list<(Hash, ScpQuorumSet)>
```

### Data: ScpPersistenceManager

```
ScpPersistenceManager:
  storage             // ScpStatePersistence backend
  last_slot_saved     // u64
```

### Trait: ScpStatePersistence

```
ScpStatePersistence:
  save_scp_state(slot, state)
  load_scp_state(slot) → PersistedSlotState?
  load_all_scp_states() → list<(slot, PersistedSlotState)>
  delete_scp_state_below(slot)
  save_tx_set(hash, tx_set_bytes)
  load_tx_set(hash) → bytes?
  load_all_tx_sets() → list<(Hash, bytes)>
  has_tx_set(hash) → bool
  delete_tx_sets_below(slot)
```

---

### PersistedSlotState::new

```
function new() → PersistedSlotState:
  → { version: CURRENT_VERSION, envelopes: [], quorum_sets: [] }
```

### PersistedSlotState::add_envelope

```
function add_envelope(envelope):
  bytes = xdr_serialize(envelope)
  self.envelopes.append(bytes)
```

### PersistedSlotState::add_quorum_set

```
function add_quorum_set(quorum_set):
  bytes = xdr_serialize(quorum_set)
  self.quorum_sets.append(bytes)
```

### PersistedSlotState::get_envelopes

```
function get_envelopes() → list<ScpEnvelope>:
  → [xdr_deserialize(bytes) for bytes in self.envelopes]
```

### PersistedSlotState::get_quorum_sets

```
function get_quorum_sets() → list<ScpQuorumSet>:
  → [xdr_deserialize(bytes) for bytes in self.quorum_sets]
```

### PersistedSlotState::to_json / from_json

```
function to_json() → string:
  → JSON.serialize(self)

function from_json(json) → PersistedSlotState:
  → JSON.deserialize(json)
```

### PersistedSlotState::to_base64 / from_base64

```
function to_base64() → string:
  → base64_encode(to_json())

function from_base64(encoded) → PersistedSlotState:
  json = utf8_decode(base64_decode(encoded))
  → from_json(json)
```

---

### InMemoryScpPersistence

"In-memory implementation for testing."

```
InMemoryScpPersistence:
  states      // map<u64, PersistedSlotState>
  tx_sets     // map<Hash, bytes>
```

NOTE: `delete_tx_sets_below` is a no-op — in-memory impl doesn't track
slot-to-txset associations.

---

### get_tx_set_hashes

"Extract transaction set hashes from an SCP envelope."

```
function get_tx_set_hashes(envelope) → list<Hash>:
  hashes = []

  case envelope.statement.pledges:
    Nominate(nom):
      for each value in nom.votes + nom.accepted:
        hash = extract_tx_set_hash_from_value(value)
        if hash is not null:
          hashes.append(hash)

    Prepare(prep):
      hash = extract_tx_set_hash_from_value(prep.ballot.value)
      if hash: hashes.append(hash)
      if prep.prepared exists:
        hash = extract_tx_set_hash_from_value(prep.prepared.value)
        if hash: hashes.append(hash)
      if prep.prepared_prime exists:
        hash = extract_tx_set_hash_from_value(prep.prepared_prime.value)
        if hash: hashes.append(hash)

    Confirm(conf):
      hash = extract_tx_set_hash_from_value(conf.ballot.value)
      if hash: hashes.append(hash)

    Externalize(ext):
      hash = extract_tx_set_hash_from_value(ext.commit.value)
      if hash: hashes.append(hash)

  "Deduplicate"
  sort and deduplicate hashes
  → hashes
```

### Helper: extract_tx_set_hash_from_value

```
function extract_tx_set_hash_from_value(value) → Hash?:
  "Value contains a StellarValue which has txSetHash"
  stellar_value = xdr_deserialize<StellarValue>(value)
  GUARD deserialize fails   → null
  → stellar_value.tx_set_hash
```

### get_quorum_set_hash

```
function get_quorum_set_hash(envelope) → Hash?:
  case envelope.statement.pledges:
    Nominate(nom):      → nom.quorum_set_hash
    Prepare(prep):      → prep.quorum_set_hash
    Confirm(conf):      → conf.quorum_set_hash
    Externalize(ext):   → ext.commit_quorum_set_hash
```

---

### ScpPersistenceManager::new

```
function new(storage) → ScpPersistenceManager:
  → { storage, last_slot_saved: 0 }
```

### ScpPersistenceManager::persist_scp_state

"Persist SCP state for a slot. Called after each envelope emission."

```
function persist_scp_state(slot, envelopes, tx_sets, quorum_sets):
  GUARD slot < last_slot_saved   → ok (skip older slots)

  last_slot_saved = slot

  state = PersistedSlotState::new()
  for each envelope in envelopes:
    state.add_envelope(envelope)
  for each (_, quorum_set) in quorum_sets:
    state.add_quorum_set(quorum_set)

  "Save transaction sets (skip if already exists)"
  for each (hash, tx_set) in tx_sets:
    if not storage.has_tx_set(hash):
      storage.save_tx_set(hash, tx_set)

  storage.save_scp_state(slot, state)
```

### ScpPersistenceManager::restore_scp_state

"Restore SCP state from persistence on startup."

```
function restore_scp_state() → RestoredScpState:
  restored = empty RestoredScpState

  "Load transaction sets"
  for each (hash, tx_set) in storage.load_all_tx_sets():
    restored.tx_sets.append((hash, tx_set))

  "Load SCP states"
  for each (slot, state) in storage.load_all_scp_states():
    "Process quorum sets"
    for each qs in state.get_quorum_sets():
      if qs decoded successfully:
        hash = hash_xdr(qs)
        restored.quorum_sets.append((hash, qs))

    "Process envelopes"
    for each env in state.get_envelopes():
      if env decoded successfully:
        env_slot = env.statement.slot_index
        restored.envelopes.append((env_slot, env))
        last_slot_saved = max(last_slot_saved, env_slot)

  → restored
```

### ScpPersistenceManager::cleanup

```
function cleanup(min_slot):
  storage.delete_scp_state_below(min_slot)
  storage.delete_tx_sets_below(min_slot)
```

---

### SqliteScpPersistence

"SQLite-backed implementation. Delegates to henyey_db::SqliteScpPersistence,
serializing PersistedSlotState as JSON."

```
SqliteScpPersistence:
  inner     // henyey_db::SqliteScpPersistence

function save_scp_state(slot, state):
  json = state.to_json()
  inner.save_scp_state(slot, json)

function load_scp_state(slot) → PersistedSlotState?:
  json = inner.load_scp_state(slot)
  if json is null: → null
  → PersistedSlotState::from_json(json)

function load_all_scp_states() → list<(slot, PersistedSlotState)>:
  result = []
  for each (slot, json) in inner.load_all_scp_states():
    state = PersistedSlotState::from_json(json)
    if state parsed ok:
      result.append((slot, state))
  → result
```

NOTE: Other SQLite methods (save_tx_set, load_tx_set, etc.) delegate
directly to the inner `henyey_db` implementation.

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~490   | ~175       |
| Functions     | 26     | 26         |
