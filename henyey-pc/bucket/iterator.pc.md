## Pseudocode: crates/bucket/src/iterator.rs

"Streaming bucket iterators for memory-efficient bucket processing."

### Helper: read_xdr_record

"XDR records are prefixed with a 4-byte big-endian length field."

```
FUNCTION read_xdr_record(reader) → bytes or nil:
  len_buf = reader.read(4 bytes)
  GUARD EOF → nil

  len = big_endian_u32(len_buf)
  if len == 0:
    → empty bytes

  data = reader.read(len bytes)
  → data
```

### Helper: write_xdr_record

```
FUNCTION write_xdr_record(writer, data) → bytes_written:
  len = length(data) as u32
  writer.write(big_endian_bytes(len))
  writer.write(data)
  → 4 + length(data)
```

---

### Data: BucketInputIterator

"Streaming iterator over bucket entries from a file."
"Only holds one entry at a time — suitable for very large buckets."

```
STRUCT BucketInputIterator:
  reader             : buffered gzip reader
  path               : file path
  current            : BucketEntry or nil
  seen_metadata      : bool
  seen_other_entries : bool
  metadata           : BucketMetadata or nil
  hasher             : SHA-256
  entries_read       : int
  bytes_read         : int
```

### BucketInputIterator::open

```
FUNCTION open(path) → BucketInputIterator:
  file = open_file(path)
  reader = buffered(gzip_decode(file))

  iter = BucketInputIterator {
    reader, path,
    current = nil,
    seen_metadata = false,
    seen_other_entries = false,
    metadata = nil,
    hasher = SHA-256.new(),
    entries_read = 0,
    bytes_read = 0,
  }

  "Load first entry, handling metadata"
  iter.load_entry()
  → iter
```

**Calls**: [load_entry](#bucketinputiteratorload_entry)

### BucketInputIterator::load_entry

```
FUNCTION load_entry():
  loop:
    data = read_xdr_record(reader)

    if data is nil:
      current = nil
      return

    "Update hash"
    hasher.update(big_endian_bytes(length(data)))
    hasher.update(data)
    bytes_read += 4 + length(data)

    entry = BucketEntry.from_xdr(data)

    if entry is Metadata:
      GUARD seen_metadata →
        error "Multiple METAENTRY in bucket"
      GUARD seen_other_entries →
        error "METAENTRY must be first entry"
      seen_metadata = true
      metadata = entry.metadata
      continue                   // load next entry

    seen_other_entries = true
    entries_read += 1
    current = entry
    return
```

**Calls**: [read_xdr_record](#helper-read_xdr_record)

### BucketInputIterator::next_entry

```
FUNCTION next_entry() → BucketEntry or nil:
  current_entry = current
  current = nil
  if current_entry is not nil:
    load_entry()
  → current_entry
```

**Calls**: [load_entry](#bucketinputiteratorload_entry)

### BucketInputIterator::finish_hash

```
FUNCTION finish_hash() → Hash256:
  → Hash256(hasher.finalize())
```

### BucketInputIterator::collect_all

```
FUNCTION collect_all() → list<BucketEntry>:
  entries = []
  while entry = next_entry():
    entries.append(entry)
  → entries
```

---

### Data: BucketOutputIterator

"Streaming writer for bucket entries with automatic deduplication."
"Entries must be added in sorted order. Same-key entries are deduplicated"
"via single-entry buffering. Tombstones dropped when keep_tombstones=false."

```
CONST FIRST_PROTOCOL_SUPPORTING_METADATA = 11

STRUCT BucketOutputIterator:
  writer           : buffered gzip writer
  path             : file path
  buffer           : BucketEntry or nil
  keep_tombstones  : bool
  protocol_version : u32
  wrote_metadata   : bool
  hasher           : SHA-256
  entries_written  : int
  bytes_written    : int
  in_memory_entries: list<BucketEntry> or nil
```

### BucketOutputIterator::new_with_in_memory

"Used for level 0 optimization where entries are kept in memory"
"for faster subsequent merges."

```
FUNCTION new_with_in_memory(path, protocol_version, keep_tombstones):
  iter = new(path, protocol_version, keep_tombstones)
  iter.in_memory_entries = empty list
  → iter
```

### BucketOutputIterator::maybe_write_metadata

```
FUNCTION maybe_write_metadata():
  GUARD wrote_metadata → return
  wrote_metadata = true

  if protocol_version >= FIRST_PROTOCOL_SUPPORTING_METADATA:
    metadata = BucketMetadata {
      ledger_version = protocol_version
    }
    write_entry_raw(Metadata(metadata))
```

### BucketOutputIterator::write_entry_raw

```
FUNCTION write_entry_raw(entry):
  data = entry.to_xdr()
  hasher.update(big_endian_bytes(length(data)))
  hasher.update(data)
  bytes_written += write_xdr_record(writer, data)
```

**Calls**: [write_xdr_record](#helper-write_xdr_record)

### BucketOutputIterator::flush_buffer

```
FUNCTION flush_buffer():
  GUARD buffer is nil → return
  entry = buffer
  buffer = nil
  entries_written += 1
  write_entry_raw(entry)

  if in_memory_entries is not nil:
    in_memory_entries.append(entry)
```

**Calls**: [write_entry_raw](#bucketoutputiteratorwrite_entry_raw)

### BucketOutputIterator::put

```
FUNCTION put(entry):
  maybe_write_metadata()

  "Skip tombstones if not keeping them"
  GUARD entry is Dead and not keep_tombstones → return

  if buffer is not nil:
    cmp = compare_entries(buffer, entry)
    if cmp == LESS:
      flush_buffer()
      buffer = entry
    else if cmp == EQUAL:
      "Same key, replace buffered (newer wins)"
      buffer = entry
    else:  // GREATER
      error "Entries must be added in sorted order"
  else:
    buffer = entry
```

**Calls**: [maybe_write_metadata](#bucketoutputiteratormaybe_write_metadata) | [flush_buffer](#bucketoutputiteratorflush_buffer) | [compare_entries](entry.pc.md#compare_entries)

### BucketOutputIterator::finish

```
FUNCTION finish() → (path, hash, in_memory_entries or nil):
  maybe_write_metadata()
  flush_buffer()
  writer.flush()
  writer.finish_compression()
  hash = Hash256(hasher.finalize())
  → (path, hash, in_memory_entries)
```

**Calls**: [maybe_write_metadata](#bucketoutputiteratormaybe_write_metadata) | [flush_buffer](#bucketoutputiteratorflush_buffer)

---

### Interface: MergeInput

"Abstracts over in-memory and file-based merge inputs."

```
INTERFACE MergeInput:
  is_done()      → bool
  old_first()    → bool
  new_first()    → bool
  equal_keys()   → bool
  get_old_entry() → BucketEntry or nil
  get_new_entry() → BucketEntry or nil
  advance_old()
  advance_new()
```

### MemoryMergeInput

```
STRUCT MemoryMergeInput:
  old_entries : list<BucketEntry>
  new_entries : list<BucketEntry>
  old_index   : int
  new_index   : int

FUNCTION is_done() → bool:
  → old_index >= len(old_entries)
    and new_index >= len(new_entries)

FUNCTION old_first() → bool:
  GUARD old_index >= len(old_entries) → false
  GUARD new_index >= len(new_entries) → true
  → compare_entries(old[old_index], new[new_index]) == LESS

FUNCTION new_first() → bool:
  GUARD new_index >= len(new_entries) → false
  GUARD old_index >= len(old_entries) → true
  → compare_entries(new[new_index], old[old_index]) == LESS

FUNCTION equal_keys() → bool:
  GUARD old or new exhausted → false
  → compare_entries(old[old_index], new[new_index]) == EQUAL
```

**Calls**: [compare_entries](entry.pc.md#compare_entries)

### FileMergeInput

```
STRUCT FileMergeInput:
  old_iter : BucketInputIterator
  new_iter : BucketInputIterator

FUNCTION metadata() → BucketMetadata or nil:
  → new_iter.metadata() or old_iter.metadata()

FUNCTION old_first() → bool:
  old = old_iter.peek()
  new = new_iter.peek()
  if both present: → compare_entries(old, new) == LESS
  if only old:     → true
  else:            → false

FUNCTION new_first() → bool:
  "Mirror of old_first with reversed priority"

FUNCTION equal_keys() → bool:
  old = old_iter.peek()
  new = new_iter.peek()
  GUARD either is nil → false
  → compare_entries(old, new) == EQUAL
```

**Calls**: [compare_entries](entry.pc.md#compare_entries)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 703    | 185        |
| Functions     | 25     | 17         |
