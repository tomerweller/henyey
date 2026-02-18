## Pseudocode: crates/bucket/src/bucket.rs

"A bucket is an immutable container of sorted ledger entries, stored as"
"uncompressed XDR with record marks (RFC 5531). Buckets are identified by"
"their content hash (SHA-256 of the file contents)."

### BucketStorage (internal enum)

```
BucketStorage:
  InMemory:
    entries: shared<list<BucketEntry>>  // sorted
    key_index: shared<map<bytes, int>>  // serialized key → entry index
  DiskBacked:
    disk_bucket: shared<DiskBucket>
```

### LevelZeroState (internal enum)

"Level 0 in-memory state for bucket merging optimization."

```
LevelZeroState:
  None                                // no in-memory entries
  Separate(entries)                   // separate vector of entries
  SharedWithStorage { metadata_count } // shares storage, offset to skip metadata
```

### Bucket (struct)

```
Bucket:
  hash: Hash256
  storage: BucketStorage
  level_zero_state: LevelZeroState
```

---

### empty

"In stellar-core, empty buckets have mEntries initialized to an empty"
"vector. This means hasInMemoryEntries() returns true for empty buckets."

```
function empty():
  → Bucket {
    hash = ZERO_HASH,
    storage = InMemory { entries=[], key_index={} },
    level_zero_state = SharedWithStorage { metadata_count=0 }
  }
```

---

### from_entries

```
function from_entries(entries):
  sort entries by compare_entries
  → from_sorted_entries(entries)
```

**Calls** [`compare_entries`](entry.pc.md)

---

### from_sorted_entries

"Entries MUST already be sorted by key."
"Computes hash incrementally during a single serialization pass."

```
function from_sorted_entries(entries):
  key_index = {}
  hasher = SHA256.new()

  "Single pass: serialize each entry once, use for both index and hash"
  for (idx, entry) in entries:
    entry_bytes = serialize_xdr(entry.to_xdr_entry())

    "Write record mark + entry to hasher (XDR Record Marking format)"
    record_mark = len(entry_bytes) | 0x80000000
    hasher.update(big_endian(record_mark))
    hasher.update(entry_bytes)

    if entry.key() exists:
      key_bytes = serialize_xdr(entry.key())
      key_index[key_bytes] = idx

  hash = Hash256(hasher.finalize())
  → Bucket { hash, InMemory { entries, key_index },
      level_zero_state = None }
```

---

### from_parts

"Internal constructor used by optimized merge paths that have"
"already computed the hash incrementally."

```
function from_parts(hash, entries, key_index, metadata_count):
  → Bucket { hash, InMemory { entries, key_index },
      level_zero_state = SharedWithStorage { metadata_count } }
```

---

### fresh_in_memory_only

"Optimization matching stellar-core's freshInMemoryOnly."
"Creates bucket with entries for merging WITHOUT computing the hash."
"This bucket MUST only be used as input to an in-memory merge."

```
function fresh_in_memory_only(entries):
  metadata_count = count leading metadata entries
  → Bucket {
    hash = ZERO_HASH,
    storage = InMemory { entries, key_index={} },
    level_zero_state = SharedWithStorage { metadata_count }
  }
```

---

### from_xdr_bytes

```
function from_xdr_bytes(bytes):
  bucket = from_xdr_bytes_internal(bytes, build_index=true)

  "Debug: verify re-serializing produces the same hash"
  if storage is InMemory and entries non-empty:
    reserialized = serialize_entries(entries)
    reserialized_hash = SHA256(reserialized)
    if reserialized_hash != bucket.hash:
      warn("Bucket roundtrip hash mismatch detected")

  → bucket
```

---

### from_xdr_bytes_internal

```
function from_xdr_bytes_internal(bytes, build_index):
  entries = parse_entries(bytes)

  if build_index:
    key_index = {}
    for (idx, entry) in entries:
      if entry.key() exists:
        key_bytes = serialize_xdr(entry.key())
        key_index[key_bytes] = idx
  else:
    key_index = {}

  "Compute hash from raw bytes (including record marks)"
  hash = SHA256(bytes)

  → Bucket { hash, InMemory { entries, key_index },
      level_zero_state = None }
```

---

### from_xdr_bytes_disk_backed

```
function from_xdr_bytes_disk_backed(bytes, save_path):
  disk_bucket = DiskBucket.from_xdr_bytes(bytes, save_path)
  hash = disk_bucket.hash()
  → Bucket { hash, DiskBacked { disk_bucket },
      level_zero_state = None }
```

**Calls** [`DiskBucket.from_xdr_bytes`](disk_bucket.pc.md)

---

### from_xdr_file_disk_backed

"Builds index by streaming through the file one entry at a time."

```
function from_xdr_file_disk_backed(path):
  disk_bucket = DiskBucket.from_file_streaming(path)
  hash = disk_bucket.hash()
  → Bucket { hash, DiskBacked { disk_bucket },
      level_zero_state = None }
```

**Calls** [`DiskBucket.from_file_streaming`](disk_bucket.pc.md)

---

### from_xdr_file_disk_backed_prebuilt

"Used when loading a persisted index from disk."

```
function from_xdr_file_disk_backed_prebuilt(
    path, hash, entry_count, index):
  disk_bucket = DiskBucket.from_prebuilt(
    path, hash, entry_count, index)
  → Bucket { hash, DiskBacked { disk_bucket },
      level_zero_state = None }
```

**Calls** [`DiskBucket.from_prebuilt`](disk_bucket.pc.md)

---

### parse_entries

"Bucket files use XDR Record Marking Standard (RFC 5531)."

```
function parse_entries(bytes):
  if bytes is empty:
    → []

  "Check if file uses XDR record marking (high bit set)"
  uses_record_marks = (bytes.length >= 4 and
                       bytes[0] & 0x80 != 0)

  entries = []
  offset = 0

  if uses_record_marks:
    while offset + 4 <= bytes.length:
      record_mark = big_endian_u32(bytes[offset..offset+4])
      offset += 4
      record_len = record_mark & 0x7FFFFFFF

      GUARD offset + record_len > bytes.length
        → error("Record exceeds remaining data")

      record_data = bytes[offset .. offset + record_len]
      entry = parse XDR BucketEntry from record_data
      entries.append(BucketEntry.from_xdr_entry(entry))
      offset += record_len
  else:
    "Raw XDR format (legacy)"
    while not at end of bytes:
      entry = read_xdr(stream)
      if parse fails: break
      entries.append(BucketEntry.from_xdr_entry(entry))

  → entries
```

---

### serialize_entries

"Serialize entries to XDR bytes WITH record marks (RFC 5531)."

```
function serialize_entries(entries):
  bytes = []
  for each entry in entries:
    entry_bytes = serialize_xdr(entry.to_xdr_entry())
    record_mark = len(entry_bytes) | 0x80000000
    bytes.append(big_endian(record_mark))
    bytes.append(entry_bytes)
  → bytes
```

---

### save_to_xdr_file

```
function save_to_xdr_file(path):
  if storage is InMemory:
    uncompressed = serialize_entries(entries)
    write uncompressed to path
    sync file
  else if storage is DiskBacked:
    "File is already uncompressed XDR"
    if source_path != path:
      copy source_path to path
  → path
```

---

### load_from_xdr_file

```
function load_from_xdr_file(path):
  bytes = read_file(path)
  → from_xdr_bytes(bytes)
```

---

### Accessors

```
function hash():          → hash
function is_empty():
  if hash.is_zero(): → true
  if InMemory: → entries.is_empty()
  if DiskBacked: → disk_bucket.is_empty()

function len():
  if InMemory: → entries.length
  if DiskBacked: → disk_bucket.len()

function is_disk_backed(): → storage is DiskBacked

function live_index():
  if DiskBacked: → disk_bucket.live_index()
  else: → null

function backing_file_path():
  if DiskBacked: → disk_bucket.file_path()
  else: → null

function entry_counters():
  if DiskBacked: → disk_bucket.live_index().counters()
  else: → null

function maybe_initialize_cache(total_acct_bytes, config):
  if DiskBacked:
    disk_bucket.maybe_initialize_cache(total_acct_bytes, config)

function cache_stats():
  if DiskBacked: → disk_bucket.cache().stats()
  else: → null
```

---

### get

```
function get(key):
  if InMemory:
    key_bytes = serialize_xdr(key)
    idx = key_index.get(key_bytes)
    if idx exists: → entries[idx]
    else: → null
  if DiskBacked:
    → disk_bucket.get(key)
```

**Calls** [`DiskBucket.get`](disk_bucket.pc.md)

---

### get_by_key_bytes

"Avoids redundant key serialization when caller has already serialized."

```
function get_by_key_bytes(key, key_bytes):
  if InMemory:
    idx = key_index.get(key_bytes)
    if idx exists: → entries[idx]
    else: → null
  if DiskBacked:
    → disk_bucket.get_by_key_bytes(key, key_bytes)
```

---

### get_entry

```
function get_entry(key):
  entry = get(key)
  if entry is Live or Init: → entry.ledger_entry
  else: → null
```

---

### protocol_version

```
function protocol_version():
  for each entry in iter():
    if entry is Metadata:
      → entry.ledger_version
  → null
```

---

### to_xdr_bytes

```
function to_xdr_bytes():
  if InMemory: → serialize_entries(entries)
  if DiskBacked: → read_file(disk_bucket.file_path())
```

---

### Level 0 In-Memory Optimization

```
function has_in_memory_entries():
  → level_zero_state is not None

function get_in_memory_entries():
  if None: → null
  if Separate(entries): → entries
  if SharedWithStorage { metadata_count }:
    if InMemory: → entries[metadata_count..]
    if DiskBacked: → null

function set_in_memory_entries(entries):
  level_zero_state = Separate(entries)

function clear_in_memory_entries():
  level_zero_state = None
```

---

### from_sorted_entries_with_in_memory

"Per stellar-core (LiveBucket.h): Stores all BucketEntries"
"(except METAENTRY) in the same order for level 0 entries."
"Uses zero-copy shared storage."

```
function from_sorted_entries_with_in_memory(entries):
  key_index = {}
  hasher = SHA256.new()

  metadata_count = count leading metadata entries

  for (idx, entry) in entries:
    entry_bytes = serialize_xdr(entry.to_xdr_entry())
    record_mark = len(entry_bytes) | 0x80000000
    hasher.update(big_endian(record_mark))
    hasher.update(entry_bytes)

    if entry.key() exists:
      key_bytes = serialize_xdr(entry.key())
      key_index[key_bytes] = idx

  hash = Hash256(hasher.finalize())

  → Bucket { hash,
      InMemory { entries, key_index },
      SharedWithStorage { metadata_count } }
```

---

### iter

```
function iter():
  if InMemory: → InMemoryIter(entries)
  if DiskBacked: → disk_bucket.iter()
```

---

### iter_from_offset_with_sizes

"Optimized for eviction scan."

```
function iter_from_offset_with_sizes(start_offset):
  if InMemory:
    → InMemoryOffsetIter { entries, index=0,
        current_offset=0, start_offset }
  if DiskBacked:
    → disk_bucket.iter_from_offset_with_sizes(start_offset)
```

---

### BucketOffsetIter.next (InMemory variant)

```
function InMemoryOffsetIter.next():
  while index < entries.length:
    entry = entries[index]
    index += 1
    entry_size = len(serialize_xdr(entry)) + 4  // +4 for record mark
    entry_end = current_offset + entry_size

    if entry_end <= start_offset:
      current_offset = entry_end
      continue   // skip entries before start_offset

    current_offset = entry_end
    → (entry, entry_size)
  → null
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~1153  | ~250       |
| Functions     | 27     | 27         |
