## Pseudocode: crates/history/src/archive_state.rs

"History Archive State (HAS) parsing and handling."
"The HAS is a JSON file describing the current state of a Stellar"
"history archive, including the current ledger and bucket list hashes."

### Constants and Data Structures

```
CONST MAX_HISTORY_ARCHIVE_BUCKET_SIZE = 100 GiB
  // matches stellar-core MAX_HISTORY_ARCHIVE_BUCKET_SIZE

CONST ZERO_HASH = "000...000" (64 hex zeros)

HistoryArchiveState:
  version: u32                    // currently 2
  server: string or null
  current_ledger: u32
  network_passphrase: string or null
  current_buckets: list of HASBucketLevel
  hot_archive_buckets: list of HASBucketLevel or null

HASBucketLevel:
  curr: string (hex hash)
  snap: string (hex hash)
  next: HASBucketNext

HASBucketNext:
  NOTE: Matches stellar-core FutureBucket::State
  NOTE: 0 = FB_CLEAR, 1 = FB_HASH_OUTPUT, 2 = FB_HASH_INPUTS
  state: u32
  output: string or null         // state == 1
  curr: string or null           // state == 2
  snap: string or null           // state == 2
  shadow: list of string or null // state == 2, pre-protocol 12

LiveBucketNextState:
  state: u32
  output: Hash256 or null
  input_curr: Hash256 or null
  input_snap: Hash256 or null
```

### Helper: parse_nonzero_hash

```
function parse_nonzero_hash(hex):
  if hex is empty or hex == ZERO_HASH:
    → null
  → Hash256.from_hex(hex)
```

### Helper: collect_bucket_hashes

```
function collect_bucket_hashes(levels, out):
  for each level in levels:
    if parse_nonzero_hash(level.curr) → h:
      append h to out
    if parse_nonzero_hash(level.snap) → h:
      append h to out
    if level.next.output is not null:
      if parse_nonzero_hash(output) → h:
        append h to out
    if level.next.state == 2:
      if level.next.curr is not null:
        if parse_nonzero_hash(curr) → h:
          append h to out
      if level.next.snap is not null:
        if parse_nonzero_hash(snap) → h:
          append h to out
```

### Helper: parse_bucket_hash_pairs

```
function parse_bucket_hash_pairs(levels):
  → for each level in levels:
      curr = parse_nonzero_hash(level.curr) or ZERO
      snap = parse_nonzero_hash(level.snap) or ZERO
      yield (curr, snap)
```

### Helper: parse_level_hashes

```
function parse_level_hashes(level):
  → (parse_nonzero_hash(level.curr),
     parse_nonzero_hash(level.snap))
```

### from_json

```
function from_json(json_string):
  → deserialize json_string as HistoryArchiveState
```

### to_json

```
function to_json():
  → serialize self as pretty JSON
```

### all_bucket_hashes

"Returns all non-zero bucket hashes from curr, snap, and"
"next fields of each bucket level."

```
function all_bucket_hashes():
  hashes = []
  collect_bucket_hashes(current_buckets, hashes)
  if hot_archive_buckets is not null:
    collect_bucket_hashes(hot_archive_buckets, hashes)
  → hashes
```

### unique_bucket_hashes

```
function unique_bucket_hashes():
  hashes = all_bucket_hashes()
  sort hashes
  deduplicate hashes
  → hashes
```

### bucket_hashes_at_level

```
function bucket_hashes_at_level(level):
  GUARD level >= length(current_buckets) → null
  → parse_level_hashes(current_buckets[level])
```

### hot_archive_bucket_hashes_at_level

```
function hot_archive_bucket_hashes_at_level(level):
  GUARD hot_archive_buckets is null → null
  GUARD level >= length(hot_archive_buckets) → null
  → parse_level_hashes(hot_archive_buckets[level])
```

### bucket_hash_pairs

"Format suitable for BucketList::restore_from_has."

```
function bucket_hash_pairs():
  → parse_bucket_hash_pairs(current_buckets)
```

### hot_archive_bucket_hash_pairs

```
function hot_archive_bucket_hash_pairs():
  GUARD hot_archive_buckets is null → null
  → parse_bucket_hash_pairs(hot_archive_buckets)
```

### live_next_states

"Extracts FutureBucket state from each level."

```
function live_next_states():
  → for each level in current_buckets:
      yield LiveBucketNextState {
        state: level.next.state,
        output: parse_hex(level.next.output),
        input_curr: parse_hex(level.next.curr),
        input_snap: parse_hex(level.next.snap)
      }
```

### hot_archive_next_states

```
function hot_archive_next_states():
  GUARD hot_archive_buckets is null → null
  → for each level in hot_archive_buckets:
      yield LiveBucketNextState { ... }
      NOTE: same mapping as live_next_states
```

### contains_valid_buckets

"Validate that all bucket hashes in this HAS exist in known set."
"Matches stellar-core's containsValidBuckets check."
"1. Level 0 next must be clear (state == 0)"
"2. All non-zero curr/snap hashes must exist in known_hashes"
"3. For state==2, input curr/snap must also exist"
"4. For state==1, output hash must exist"

```
function contains_valid_buckets(known_hashes):
  if current_buckets is not empty:
    GUARD current_buckets[0].next.state != 0
      → "level 0 next is not clear"

  for each (i, level) in current_buckets:
    if parse_nonzero_hash(level.curr) → h:
      GUARD h not in known_hashes
        → "unknown curr bucket hash at level i"

    if parse_nonzero_hash(level.snap) → h:
      GUARD h not in known_hashes
        → "unknown snap bucket hash at level i"

    if level.next.state == 1:
      if level.next.output is not null:
        if parse_nonzero_hash(output) → h:
          GUARD h not in known_hashes
            → "unknown output bucket hash at level i"

    else if level.next.state == 2:
      if level.next.curr is not null:
        if parse_nonzero_hash(curr) → h:
          GUARD h not in known_hashes
            → "unknown input curr bucket hash at level i"
      if level.next.snap is not null:
        if parse_nonzero_hash(snap) → h:
          GUARD h not in known_hashes
            → "unknown input snap bucket hash at level i"

    NOTE: state 0 (clear) — nothing to check
```

### futures_all_clear

```
function futures_all_clear():
  → all levels have next.state == 0
```

### futures_all_resolved

"State 0 (clear) and state 1 (output hash known) are resolved."
"Only state 2 (inputs known, merge in progress) is unresolved."

```
function futures_all_resolved():
  → all levels have next.state <= 1
```

### resolve_all_futures

"Convert state 1 (output) to state 0 (clear)."
"Used after restart to settle completed merges."

```
function resolve_all_futures():
  for each level in current_buckets:
    if level.next.state == 1:
      level.next = default (state 0)
```

### clear_all_futures

```
function clear_all_futures():
  for each level in current_buckets:
    level.next = default (state 0)
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~475   | ~160       |
| Functions     | 20     | 20         |
