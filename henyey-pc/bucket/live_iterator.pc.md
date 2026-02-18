## Pseudocode: crates/bucket/src/live_iterator.rs

"Streaming iterator for live bucket list entries."
"Memory-efficient alternative to materializing all entries — uses HashSet<LedgerKey>"
"for deduplication, matching stellar-core BucketApplicator pattern."
"For mainnet (~60M entries): old approach ~52 GB, new approach ~8.6 GB."

### Data: LiveEntriesIterator

```
STRUCT LiveEntriesIterator:
  levels          : ref to bucket list levels
  current_level   : int             // 0..10
  current_phase   : int             // 0 = curr, 1 = snap
  bucket_iter     : BucketIter or nil
  seen_keys       : set<LedgerKey>  // deduplication
  entries_yielded : int
  entries_skipped : int
```

### new

```
FUNCTION new(bucket_list) → LiveEntriesIterator:
  iter = LiveEntriesIterator {
    levels = bucket_list.levels(),
    current_level = 0,
    current_phase = 0,
    bucket_iter = nil,
    seen_keys = empty set,
    entries_yielded = 0,
    entries_skipped = 0,
  }
  iter.advance_to_next_bucket()
  → iter
```

**Calls**: [advance_to_next_bucket](#advance_to_next_bucket)

### advance_to_next_bucket

```
FUNCTION advance_to_next_bucket() → bool:
  loop:
    GUARD current_level >= len(levels) →
      bucket_iter = nil
      → false

    bucket = current_bucket()
    if bucket is not nil and not bucket.is_empty():
      bucket_iter = bucket.iter()
      → true

    "Advance to next position"
    if current_phase == 0:
      current_phase = 1          // curr → snap
    else:
      current_level += 1         // snap → next level curr
      current_phase = 0
```

### advance_position

```
FUNCTION advance_position():
  if current_phase == 0:
    current_phase = 1
  else:
    current_level += 1
    current_phase = 0
  bucket_iter = nil
```

### next (Iterator)

"Iteration order: level 0 curr, level 0 snap, level 1 curr, ..."
"First occurrence of each key shadows later occurrences."
"Dead entries shadow subsequent Live/Init entries with same key."

```
FUNCTION next() → LedgerEntry or nil:
  loop:
    if bucket_iter is nil:
      if not advance_to_next_bucket():
        → nil                            // no more buckets

    entry = bucket_iter.next()

    if entry is nil:
      advance_position()                 // bucket exhausted
      continue

    if entry is Live or Init:
      key = ledger_entry_to_key(entry)
      GUARD key is nil → continue        // skip invalid

      "stellar-core: mSeenKeys.emplace(key).second"
      if not seen_keys.insert(key):
        entries_skipped += 1
        continue                         // already seen

      entries_yielded += 1
      → entry.ledger_entry

    if entry is Dead:
      "Mark dead keys as seen (shadows older live entries)"
      seen_keys.insert(entry.key)
      continue

    if entry is Metadata:
      continue                           // skip metadata
```

**Calls**: [advance_to_next_bucket](#advance_to_next_bucket) | [advance_position](#advance_position) | [ledger_entry_to_key](entry.pc.md#ledger_entry_to_key)

### Data: LiveEntriesStats

```
STRUCT LiveEntriesStats:
  entries_yielded : int
  entries_skipped : int
  unique_keys     : int
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 273    | 75         |
| Functions     | 9      | 5          |
