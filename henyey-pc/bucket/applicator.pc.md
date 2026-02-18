## Pseudocode: crates/bucket/src/applicator.rs

"BucketApplicator — Apply bucket entries to database during catchup."
"Entries are processed from newest to oldest; first occurrence of a key"
"is the most recent value."

### Constants

```
CONST DEFAULT_CHUNK_SIZE = 10000
```

### ApplicatorCounters (struct)

```
STRUCT ApplicatorCounters:
  upserted_by_type: map[EntryType → count]
  deleted_by_type: map[EntryType → count]
  entries_processed: integer
  entries_skipped: integer
```

### ApplicatorCounters methods

```
function record_upsert(entry_type):
  MUTATE upserted_by_type[entry_type] += 1

function record_delete(entry_type):
  MUTATE deleted_by_type[entry_type] += 1

function record_processed():
  MUTATE entries_processed += 1

function record_skipped():
  MUTATE entries_skipped += 1

function total_upserted():
  → sum of all values in upserted_by_type

function total_deleted():
  → sum of all values in deleted_by_type

function total_applied():
  → total_upserted() + total_deleted()

function merge(other):
  for each (type, count) in other.upserted_by_type:
    MUTATE upserted_by_type[type] += count
  for each (type, count) in other.deleted_by_type:
    MUTATE deleted_by_type[type] += count
  MUTATE entries_processed += other.entries_processed
  MUTATE entries_skipped += other.entries_skipped

function reset():
  clear upserted_by_type, deleted_by_type
  entries_processed = 0
  entries_skipped = 0
```

### EntryToApply (enum)

```
ENUM EntryToApply:
  Upsert(key, ledger_entry)
  Delete(key)

function key():
  → key from either variant

function entry():
  if Upsert: → ledger_entry
  if Delete:  → nothing

function is_delete():
  → true if Delete variant
```

### BucketApplicator (struct)

```
STRUCT BucketApplicator:
  bucket: Bucket
  max_protocol_version: integer
  level: integer
  seen_keys: set of LedgerKey
  current_offset: integer
  chunk_size: integer
  apply_dead_entries: boolean
  cached_entries: optional list of BucketEntry
```

### new / with_chunk_size

```
function new(bucket, max_protocol_version, level):
  → BucketApplicator(
      bucket, max_protocol_version, level,
      seen_keys = empty set,
      current_offset = 0,
      chunk_size = DEFAULT_CHUNK_SIZE,
      apply_dead_entries = true,
      cached_entries = none)

function with_chunk_size(bucket, max_pv, level, chunk_size):
  same as new but with custom chunk_size
```

### has_more / progress / remaining

```
function has_more():
  → current_offset < bucket.len()

function progress():
  if bucket is empty: → 1.0
  → current_offset / bucket.len()

function remaining():
  → max(0, bucket.len() - current_offset)
```

### mark_seen / is_seen

```
function is_seen(key):
  → key in seen_keys

function mark_seen(key):
  add key to seen_keys

function mark_seen_many(keys):
  add all keys to seen_keys
```

### advance

"Processes up to chunk_size entries and returns them for application."
"Updates counters with statistics."

```
function advance(counters):
  batch = empty list

  "Load entries if needed (cache for disk-backed buckets)"
  if cached_entries is none and bucket is disk-backed:
    cached_entries = collect all entries from bucket

  entries = cached_entries or collect from bucket
  end = min(current_offset + chunk_size, len(entries))

  for each entry in entries[current_offset..end]:
    counters.record_processed()

    if entry is Live or Init:
      key = extract key from entry
      GUARD key already in seen_keys
        → skip, counters.record_skipped()
      add key to seen_keys
      entry_type = type of ledger entry data
      counters.record_upsert(entry_type)
      append Upsert(key, entry) to batch

    else if entry is Dead:
      GUARD apply_dead_entries is false → skip
      GUARD key already in seen_keys
        → skip, counters.record_skipped()
      add key to seen_keys
      entry_type = type of ledger key
      counters.record_delete(entry_type)
      append Delete(key) to batch

    else if entry is Metadata:
      "Skip metadata entries"

  current_offset = end
  → batch
```

**Calls**: [ledger_entry_to_key](entry.pc.md#ledger_entry_to_key) | [ledger_entry_data_type](entry.pc.md#ledger_entry_data_type) | [ledger_key_type](entry.pc.md#ledger_key_type)

### apply_all

```
function apply_all(counters):
  all_entries = empty list
  while has_more():
    batch = advance(counters)
    append batch to all_entries
  → all_entries
```

**Calls**: [advance](#advance)

### reset

```
function reset():
  clear seen_keys
  current_offset = 0
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 413    | 115        |
| Functions     | 22     | 22         |
