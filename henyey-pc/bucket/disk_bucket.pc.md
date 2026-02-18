## Pseudocode: crates/bucket/src/disk_bucket.rs

"Disk-backed bucket implementation for memory-efficient storage."
"Instead of loading all entries into memory, the disk bucket:"
"1. Stores the raw XDR bucket file on disk (uncompressed)"
"2. Builds a LiveBucketIndex by streaming entries from the file"
"3. Reads entries on-demand from disk when accessed via mmap"

CONST BLOOM_FILTER_MIN_ENTRIES = 2
CONST DEFAULT_BLOOM_SEED = [0; 16]

### DiskBucket (struct)

```
DiskBucket:
  hash: Hash256
  file_path: path
  entry_count: int
  bloom_seed: HashSeed
  index: lazy<LiveBucketIndex>       // eagerly built, thread-safe
  mmap: lazy<MemoryMappedFile>       // lock-free reads
  cache: lazy<RandomEvictionCache>   // per-bucket, accounts only
```

---

### Helper: StreamingXdrEntryIterator

"Iterator that reads (BucketEntry, offset) pairs one at a time from an"
"uncompressed XDR bucket file. Each call to next() reads and parses a"
"single record, keeping only O(1) memory (one entry + reusable buffer)."
"Optionally computes SHA-256 hash incrementally as records are read."

```
function new(path, file_len, compute_hash=false):
  open file at path with buffered reader
  if compute_hash:
    hasher = SHA256.new()
  → StreamingXdrEntryIterator { reader, file_len,
      position=0, buf=[], hasher, record_count=0 }

function next():
  loop:
    if position + 4 > file_len:
      → null

    record_start = position
    mark_buf = read_exact(4 bytes)
    position += 4

    record_mark = big_endian_u32(mark_buf)
    record_len = record_mark & 0x7FFFFFFF

    if position + record_len > file_len:
      → null

    read record_len bytes into reusable buf
    position += record_len

    "Feed raw bytes to hasher before parsing"
    if hasher is set:
      hasher.update(mark_buf)
      hasher.update(buf[..record_len])
    record_count += 1

    "Parse entry — skip records that fail to parse"
    entry = try parse XDR BucketEntry from buf
    if entry is valid and entry.key() exists:
      → (entry, record_start)
    "else continue loop to skip unparseable records"

function finalize():
  if hasher:
    hash = Hash256(hasher.finalize())
  → (record_count, hash)
```

---

### Helper: create_mmap

"Uses MADV_RANDOM to optimize for point lookups (no readahead waste)."

```
function create_mmap(path):
  file = open(path, read_only)
  mmap = memory_map(file)
  madvise(mmap, RANDOM)
  → mmap
```

---

### ensure_index

```
function ensure_index():
  → index.get_or_init:
    "Safety net — index should have been built eagerly"
    file_len = file_metadata(file_path).size
    iter = StreamingXdrEntryIterator.new(file_path, file_len)
    live_index = LiveBucketIndex.from_entries_default(iter,
                   bloom_seed, file_len)
    → live_index
```

**Calls** [`LiveBucketIndex.from_entries_default`](index.pc.md)

---

### from_file_streaming_with_seed

"Create a disk bucket from an uncompressed XDR file using streaming I/O"
"with a custom bloom filter seed."

```
function from_file_streaming_with_seed(path, bloom_seed):
  file_len = file_metadata(path).size

  "Single pass: build index and compute hash simultaneously."
  iter = StreamingXdrEntryIterator.new(path, file_len,
           compute_hash=true)
  (live_index, iter) = LiveBucketIndex
    .from_entries_default_with_iter(iter, bloom_seed, file_len)
  (entry_count, hash) = iter.finalize()

  ASSERT: hash is set

  store index eagerly
  store mmap eagerly via create_mmap(path)

  → DiskBucket { hash, file_path=path, entry_count,
      bloom_seed, index, mmap, cache=empty }
```

**Calls** [`LiveBucketIndex.from_entries_default_with_iter`](index.pc.md)

---

### from_file_streaming

```
function from_file_streaming(path):
  → from_file_streaming_with_seed(path, DEFAULT_BLOOM_SEED)
```

---

### from_prebuilt

"Create a disk bucket from a pre-built index, skipping file scanning."
"Used when loading a persisted index from disk."

```
function from_prebuilt(path, hash, entry_count, prebuilt_index):
  store prebuilt_index eagerly
  store mmap eagerly via create_mmap(path)

  → DiskBucket { hash, file_path=path, entry_count,
      bloom_seed=DEFAULT_BLOOM_SEED, index, mmap,
      cache=empty }
```

---

### from_xdr_bytes_with_seed

"Create a disk bucket from raw XDR bytes with a custom bloom filter seed."

```
function from_xdr_bytes_with_seed(bytes, save_path, bloom_seed):
  write bytes to save_path
  sync file to disk
  → from_file_streaming_with_seed(save_path, bloom_seed)
```

---

### from_xdr_bytes

```
function from_xdr_bytes(bytes, save_path):
  → from_xdr_bytes_with_seed(bytes, save_path, DEFAULT_BLOOM_SEED)
```

---

### Accessors

```
function hash():       → hash
function is_empty():   → entry_count == 0 or hash.is_zero()
function len():        → entry_count
function file_path():  → file_path
function live_index(): → ensure_index()
function has_bloom_filter():
  → entry_count >= BLOOM_FILTER_MIN_ENTRIES
function bloom_filter_size_bytes():
  → ensure_index().bloom_filter_size_bytes()
function bloom_seed(): → bloom_seed
function cache():      → cache (if initialized)
function index_heap_bytes():
  → ensure_index().estimated_heap_bytes()
```

---

### maybe_initialize_cache

"Matches stellar-core's LiveBucketIndex::maybeInitializeCache:"
"- Only DiskIndex buckets get caches (InMemory already has everything)"
"- Cache size is proportional to this bucket's share of total account bytes"

```
function maybe_initialize_cache(
    total_bucket_list_account_size_bytes,
    config):
  if cache already initialized:
    return

  index = ensure_index()

  "Only DiskIndex buckets get caches"
  if index is not DiskIndex:
    return

  counters = index.counters()
  accounts_in_bucket = counters.count_for_type(ACCOUNT)
  max_cache_bytes = config.memory_for_caching_mb * 1024 * 1024

  if accounts_in_bucket == 0 or max_cache_bytes == 0:
    return

  account_bytes = counters.size_for_type(ACCOUNT)

  if total_bucket_list_account_size_bytes <= max_cache_bytes:
    "Can cache the entire bucket"
    cache_entries = accounts_in_bucket
  else:
    "Proportional allocation (stellar-core formula)"
    fraction = account_bytes / total_bucket_list_account_size_bytes
    bytes_for_bucket = max_cache_bytes * fraction
    avg_size = account_bytes / accounts_in_bucket
    cache_entries = floor(bytes_for_bucket / avg_size)

  if cache_entries == 0:
    return

  cache = RandomEvictionCache(max_bytes=MAX, max_entries=cache_entries)
  cache.activate()
  store cache
```

**Calls** [`RandomEvictionCache`](cache.pc.md)

---

### get

"Look up an entry by key. Bloom filter checked first to quickly reject"
"keys that are definitely not present (avoiding disk I/O)."

```
function get(key):
  "Check per-bucket cache first"
  if cache is initialized:
    cached = cache.get(key)
    if cached exists:
      → cached

  index = ensure_index()

  "Check bloom filter (built into the index)"
  if not index.may_contain(key):
    → null

  if index is InMemoryIndex:
    offset = index.get_offset(key)
    if offset is null:
      result = null
    else:
      entry = read_entry_at(offset)
      if entry.key() == key:
        result = entry
      else:
        result = null

  else if index is DiskIndex:
    "Page-based lookup: find candidate page, scan within it"
    page_offset = index.find_page_for_key(key)
    if page_offset is null:
      result = null
    else:
      result = scan_page_for_key(page_offset, key,
                 index.page_size())

  "Populate cache on miss"
  if result is not null and cache is initialized:
    cache.insert(key, result)

  → result
```

---

### get_by_key_bytes

"Look up using pre-serialized key bytes to avoid redundant serialization."

```
function get_by_key_bytes(key, key_bytes):
  "Check per-bucket cache first"
  if cache is initialized:
    cached = cache.get(key)
    if cached exists:
      → cached

  index = ensure_index()

  if not index.may_contain_bytes(key_bytes):
    → null

  if index is InMemoryIndex:
    offset = index.get_offset_by_key_bytes(key_bytes)
    if offset is null:
      result = null
    else:
      entry = read_entry_at(offset)
      if entry.key() == key:
        result = entry
      else:
        result = null

  else if index is DiskIndex:
    "Disk-based index uses key comparison for page search"
    page_offset = index.find_page_for_key(key)
    if page_offset is null:
      result = null
    else:
      result = scan_page_for_key(page_offset, key,
                 index.page_size())

  "Populate cache on miss"
  if result is not null and cache is initialized:
    cache.insert(key, result)

  → result
```

---

### read_entry_at

"No syscalls, no locks — direct memory access through the mmap."

```
function read_entry_at(offset):
  data = ensure_mmap()

  GUARD offset + 4 > data.length  → error(UnexpectedEof)

  mark_buf = data[offset .. offset+4]
  if mark_buf[0] high bit is set:
    record_mark = big_endian_u32(mark_buf)
    record_len = record_mark & 0x7FFFFFFF
    record_start = offset + 4
  else:
    "No record mark — try raw XDR from offset"
    → parse XDR BucketEntry from data[offset..]

  GUARD record_start + record_len > data.length
    → error(UnexpectedEof)

  "Parse from mmap slice — zero-copy until XDR deserialization"
  record_data = data[record_start .. record_start + record_len]
  → parse XDR BucketEntry from record_data
```

---

### scan_page_for_key

"Scan a page starting at page_offset for a key, reading up to page_size bytes."
"Terminates when position exceeds page boundary or entry key > target (sorted)."

```
function scan_page_for_key(page_offset, key, page_size):
  data = ensure_mmap()
  position = page_offset
  page_end = page_offset + page_size

  while position + 4 <= data.length and position < page_end:
    mark_buf = data[position .. position+4]
    position += 4
    record_mark = big_endian_u32(mark_buf)
    record_len = record_mark & 0x7FFFFFFF

    if position + record_len > data.length:
      break

    record_data = data[position .. position + record_len]
    position += record_len

    entry = try parse XDR BucketEntry from record_data
    if parse failed:
      continue

    if entry.key() == key:
      → entry
    if entry.key() > key:
      → null                   // entries are sorted

  → null
```

**Calls** [`compare_keys`](entry.pc.md)

---

### iter

"Streams entries from disk sequentially using buffered I/O."
"O(1) memory regardless of file size."

```
function iter():
  file = open(file_path)
  file_len = file.metadata().size
  reader = buffered_reader(file)

  "Check if file uses XDR record marks"
  if file_len >= 4:
    mark_buf = read first 4 bytes
    uses_record_marks = (mark_buf[0] high bit set)
    seek back to start
  else:
    uses_record_marks = false

  → DiskBucketIter { reader, file_len,
      position=0, uses_record_marks }
```

---

### DiskBucketIter.next

"Matches the stellar-core BucketInputIterator behavior."

```
function DiskBucketIter.next():
  if position >= file_len:
    → null

  if uses_record_marks:
    if position + 4 > file_len:
      → null
    mark_buf = read_exact(4 bytes)
    position += 4
    record_mark = big_endian_u32(mark_buf)
    record_len = record_mark & 0x7FFFFFFF
    if position + record_len > file_len:
      → null
    record_data = read_exact(record_len bytes)
    position += record_len
    → parse XDR BucketEntry from record_data
  else:
    "Raw XDR format — use streaming XDR reader"
    entry = read_xdr(reader)
    position = reader.stream_position()
    → entry
```

---

### iter_from_offset_with_sizes

"Optimized for eviction scan: seeks directly to start_offset,"
"returns on-disk record size with each entry."

```
function iter_from_offset_with_sizes(start_offset):
  file = open(file_path)
  file_len = file.metadata().size
  reader = buffered_reader(file)

  if start_offset > 0 and start_offset < file_len:
    seek reader to start_offset

  → DiskBucketOffsetIter { reader, file_len,
      position = min(start_offset, file_len) }
```

---

### DiskBucketOffsetIter.next

```
function DiskBucketOffsetIter.next():
  if position + 4 > file_len:
    → null

  mark_buf = read_exact(4 bytes)
  position += 4
  record_mark = big_endian_u32(mark_buf)
  record_len = record_mark & 0x7FFFFFFF
  total_record_size = record_len + 4

  if position + record_len > file_len:
    → null

  record_data = read_exact(record_len bytes)
  position += record_len

  entry = parse XDR BucketEntry from record_data
  → (entry, total_record_size)
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~950   | ~280       |
| Functions     | 20     | 20         |
