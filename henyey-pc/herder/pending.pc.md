## Pseudocode: crates/herder/src/pending.rs

"Pending SCP envelope management."
"Buffers SCP envelopes for future slots; releases them when the slot becomes active."

### Data: PendingConfig

```
CONST MAX_PER_SLOT     = 100
CONST MAX_SLOTS        = 12
CONST MAX_AGE          = 300 seconds
CONST MAX_SLOT_DISTANCE = 12

PendingConfig:
  max_per_slot:      int
  max_slots:         int
  max_age:           Duration
  max_slot_distance: u64
```

### Data: PendingEnvelope

```
PendingEnvelope:
  envelope:    ScpEnvelope
  received_at: Timestamp
  hash:        Hash256
```

### Data: PendingEnvelopes

```
PendingEnvelopes:
  config:       PendingConfig
  slots:        Map<SlotIndex, List<PendingEnvelope>>
  seen_hashes:  Set<Hash256>
  current_slot: SlotIndex
  stats:        PendingStats
```

### Data: PendingStats

```
PendingStats:
  received:   u64
  added:      u64
  duplicates: u64
  too_old:    u64
  too_far:    u64
  released:   u64
  evicted:    u64
```

### Data: PendingResult

```
PendingResult: Added | Duplicate | SlotTooFar | SlotTooOld | BufferFull
```

### PendingEnvelope::new

```
function new(envelope):
  hash = hash_xdr(envelope)
  → PendingEnvelope {
      envelope, received_at: now(), hash
    }
```

### PendingEnvelope::is_expired

```
function is_expired(max_age):
  → elapsed(self.received_at) > max_age
```

### add

```
function add(slot, envelope):
  stats.received += 1
  current = self.current_slot

  GUARD slot < current        → SlotTooOld
  GUARD slot > current + config.max_slot_distance
                              → SlotTooFar

  pending = PendingEnvelope.new(envelope)

  GUARD seen_hashes contains pending.hash
                              → Duplicate

  if slots.count >= config.max_slots:
    evict_old_slots(current)
    GUARD slots.count >= config.max_slots
                              → BufferFull

  seen_hashes.add(pending.hash)

  entry = slots[slot] (create if absent)
  GUARD entry.length >= config.max_per_slot
                              → BufferFull

  entry.append(pending)
  stats.added += 1
  → Added
```

### release

```
function release(slot):
  envelopes = slots.remove(slot)
  if envelopes is null:
    → empty list

  stats.released += envelopes.length

  for each env in envelopes:
    seen_hashes.remove(env.hash)

  → filter envelopes where not is_expired(config.max_age)
    then extract .envelope from each
```

### release_up_to

```
function release_up_to(slot):
  result = ordered map

  slots_to_release = all keys in self.slots where key <= slot

  for each s in slots_to_release:
    envelopes = release(s)
    if envelopes is not empty:
      result[s] = envelopes

  → result
```

### Helper: evict_old_slots

```
function evict_old_slots(current):
  old_slots = all keys in self.slots where key < current

  for each slot in old_slots:
    envelopes = slots.remove(slot)
    stats.evicted += envelopes.length
    for each env in envelopes:
      seen_hashes.remove(env.hash)
```

### evict_expired

```
function evict_expired():
  for each entry in slots:
    expired_hashes = hashes of envelopes where is_expired(max_age)
    entry.retain(non-expired only)
    removed = initial_len - entry.length

    if removed > 0:
      stats.evicted += removed
      for each hash in expired_hashes:
        seen_hashes.remove(hash)

  slots.retain(entries that are non-empty)
```

### Accessors

```
function len():            → sum of lengths across all slots
function is_empty():       → len() == 0
function slot_count():     → slots.count
function stats():          → self.stats
function has_pending(slot): → slots[slot] exists and is non-empty
function pending_count(slot): → slots[slot].length or 0
function current_slot():   → self.current_slot
function set_current_slot(slot):
  MUTATE self.current_slot = slot
```

### clear

```
function clear():
  slots.clear()
  seen_hashes.clear()
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 346    | 88         |
| Functions     | 16     | 13         |
