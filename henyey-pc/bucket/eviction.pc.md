## Pseudocode: crates/bucket/src/eviction.rs

"Eviction scan implementation for Soroban state archival."
"Incremental scanning: each ledger scans a limited number of bytes."
"Position tracked with EvictionIterator; resets when bucket receives new data."

"References: stellar-core BucketListBase.cpp, BucketManager.cpp, CAP-0046"

### Constants

```
CONST DEFAULT_EVICTION_SCAN_SIZE = 100000  // 100 KB per ledger
CONST DEFAULT_STARTING_EVICTION_SCAN_LEVEL = 6
  // lower levels update too frequently
CONST DEFAULT_MAX_ENTRIES_TO_ARCHIVE = 1000
```

### EvictionIterator (struct)

"Scan order: level N curr → level N snap → level N+1 curr → ..."
"Wraps from top level back to starting level."

```
STRUCT EvictionIterator:
  bucket_file_offset: integer  // byte offset in bucket file
  bucket_list_level: integer   // 0 to NUM_LEVELS-1
  is_curr_bucket: boolean      // curr or snap
```

### new / default

```
function new(starting_level):
  → EvictionIterator(offset=0, level=starting_level,
                     is_curr=true)

function default():
  → new(DEFAULT_STARTING_EVICTION_SCAN_LEVEL)
```

### reset_offset

```
function reset_offset():
  bucket_file_offset = 0
```

### advance_to_next_bucket

"Move to next bucket in scan order. Returns true if wrapped."

```
function advance_to_next_bucket(starting_level):
  last_level = BUCKET_LIST_LEVELS - 1

  if is_curr_bucket:
    if level != last_level:
      "Move from curr to snap at same level"
      is_curr_bucket = false
      bucket_file_offset = 0
    else:
      "Last level has no snap scan; wrap"
      is_curr_bucket = true
      bucket_file_offset = 0
      bucket_list_level = starting_level
      → true (wrapped)
  else:
    "Move from snap to curr at next level"
    bucket_list_level += 1
    is_curr_bucket = true
    bucket_file_offset = 0
    if bucket_list_level > last_level:
      bucket_list_level = starting_level
      → true (wrapped)

  → false
```

### EvictionCandidate (struct)

"Collected during scan phase; resolved in resolution phase."

```
STRUCT EvictionCandidate:
  entry: LedgerEntry        // data entry being evicted
  data_key: LedgerKey       // data entry's key
  ttl_key: LedgerKey        // corresponding TTL key
  is_temporary: boolean     // temporary vs persistent
  position: EvictionIterator // resume point AFTER this entry
```

### EvictionResult (struct)

```
STRUCT EvictionResult:
  candidates: list of EvictionCandidate
  end_iterator: EvictionIterator  // end of scan region
  bytes_scanned: integer
  scan_complete: boolean
```

### resolve

"Matches stellar-core's resolveBackgroundEvictionScan."
"Two-phase: filter modified TTLs, then apply max_entries limit."

```
function resolve(max_entries_to_archive, modified_ttl_keys):
  scan_end_iterator = self.end_iterator

  "Phase 1: Filter out entries with modified TTLs"
  filtered = [c for c in candidates
              where c.ttl_key NOT in modified_ttl_keys]

  "Phase 2: Apply max_entries limit"
  archived_entries = empty list
  evicted_keys = empty list
  last_evicted_position = nothing
  remaining = max_entries_to_archive

  for each candidate in filtered:
    GUARD remaining == 0 → break

    if candidate.is_temporary:
      append candidate.data_key to evicted_keys
      append candidate.ttl_key to evicted_keys
    else:
      "Persistent: archive AND evict from live"
      append candidate.entry to archived_entries
      append candidate.data_key to evicted_keys
      append candidate.ttl_key to evicted_keys

    last_evicted_position = candidate.position
    remaining -= 1

  "Phase 3: Set iterator position"
  "stellar-core logic:"
  "  newEvictionIterator = endOfRegionIterator"
  "  Each eviction updates it to evicted entry's position"
  "  After loop: if remaining != 0 → use endOfRegionIterator"
  if max_entries_to_archive > 0 and remaining == 0:
    "Hit eviction limit — resume from last evicted position"
    end_iterator = last_evicted_position or scan_end_iterator
  else:
    "Didn't hit limit — advance to end of scan region"
    end_iterator = scan_end_iterator

  → ResolvedEviction(archived_entries, evicted_keys,
                     end_iterator)
```

### ResolvedEviction (struct)

```
STRUCT ResolvedEviction:
  archived_entries: list of LedgerEntry
    // persistent entries → hot archive bucket list
  evicted_keys: list of LedgerKey
    // data + TTL key pairs to delete from live
  end_iterator: EvictionIterator
```

### StateArchivalSettings (struct)

```
STRUCT StateArchivalSettings:
  eviction_scan_size: integer         // bytes per ledger
  starting_eviction_scan_level: integer
  max_entries_to_archive: integer     // per ledger
```

### level_size

"Idealized size of a bucket list level."
"Formula: 4^(level+1) = 1 << (2 * (level + 1))"

```
function level_size(level):
  → 1 << (2 * (level + 1))
```

### level_half

```
function level_half(level):
  → level_size(level) >> 1
```

### Helper: round_down

```
function round_down(value, modulo):
  "Round down to nearest multiple of power-of-2 modulo"
  → value AND NOT(modulo - 1)
```

### level_should_spill

"A level spills when ledger is at a levelHalf or levelSize boundary."
"Top level never spills."

```
function level_should_spill(ledger, level):
  GUARD level >= BUCKET_LIST_LEVELS - 1 → false
  half = level_half(level)
  size = level_size(level)
  → ledger == round_down(ledger, half)
    or ledger == round_down(ledger, size)
```

**Calls**: [level_half](#level_half) | [level_size](#level_size) | [round_down](#round_down)

### bucket_update_period

"How frequently a bucket receives new data (in ledgers)."

```
function bucket_update_period(level, is_curr):
  if not is_curr:
    "Snap updates when level below spills"
    → bucket_update_period(level + 1, true)
  if level == 0:
    → 1
  "Formula: 2^(2*level - 1)"
  → 1 << (2 * level - 1)
```

### update_starting_eviction_iterator

"Reset iterator when bucket has received new data (invalidating position)."
"Returns true if reset."

```
function update_starting_eviction_iterator(
    iter, first_scan_level, ledger_seq):
  was_reset = false

  "Reset if below minimum level"
  if iter.level < first_scan_level:
    iter.offset = 0
    iter.is_curr = true
    iter.level = first_scan_level
    was_reset = true

  "stellar-core checks spill from previous ledger"
  "because iterator is persisted before spills are applied"
  prev_ledger = ledger_seq - 1

  if iter.is_curr:
    if iter.level > 0:
      level_below = iter.level - 1
      if level_should_spill(prev_ledger, level_below):
        iter.offset = 0
        was_reset = true
    else:
      "Level 0 curr receives data every ledger"
      iter.offset = 0
      was_reset = true
  else:
    "Snap receives data when its own level spills"
    if level_should_spill(prev_ledger, iter.level):
      iter.offset = 0
      was_reset = true

  → was_reset
```

**Calls**: [level_should_spill](#level_should_spill)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 460    | 155        |
| Functions     | 12     | 12         |
