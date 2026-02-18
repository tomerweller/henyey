## Pseudocode: crates/bucket/src/manager.rs

"BucketManager - manages bucket files on disk."
"Responsible for creating, loading, caching, merging, and garbage collecting bucket files."

```
CONST DEFAULT_MAX_CACHE_SIZE = 100
CONST DISK_BACKED_THRESHOLD = 10 * 1024 * 1024  // 10 MB

"All bucket files use the single canonical .bucket.xdr extension:
uncompressed XDR with record marks (RFC 5531). The hash is the
hex-encoded SHA-256 of the file contents."
```

---

### canonical_bucket_filename

```
canonical_bucket_filename(hash):
  → "{hash_hex}.bucket.xdr"
```

---

### temp_merge_path

```
temp_merge_path(bucket_dir):
  id = atomic_increment(TEMP_FILE_COUNTER)
  → bucket_dir / "merge-tmp-{process_id}-{id}.xdr"
```

---

### BucketManager::new

```
new(bucket_dir):
  create_dir_all(bucket_dir)
  → BucketManager {
      bucket_dir,
      cache: empty map,
      max_cache_size: DEFAULT_MAX_CACHE_SIZE,
      persist_index: false,
      finished_merges: empty BucketMergeMap
    }
```

---

### BucketManager::with_cache_size

```
with_cache_size(bucket_dir, max_cache_size):
  create_dir_all(bucket_dir)
  → BucketManager { ..., max_cache_size }
```

---

### BucketManager::with_persist_index

```
with_persist_index(bucket_dir, persist_index):
  create_dir_all(bucket_dir)
  → BucketManager { ..., persist_index }
```

---

### BucketManager::bucket_path

```
bucket_path(hash):
  → bucket_dir / canonical_bucket_filename(hash)
```

---

### create_bucket

```
create_bucket(entries):
  GUARD entries is empty     → empty Bucket

  bucket = Bucket::from_entries(entries)    REF: bucket::Bucket::from_entries
  hash = bucket.hash()

  // Check if already cached
  if cache contains hash:
    → cached bucket

  // Save to disk as uncompressed XDR
  path = bucket_path(hash)
  bucket.save_to_xdr_file(path)    REF: bucket::Bucket::save_to_xdr_file

  add_to_cache(hash, bucket)
  → bucket
```

---

### create_bucket_from_ledger_entries

```
create_bucket_from_ledger_entries(live_entries, dead_entries):
  entries = []
  for each e in live_entries:
    entries.append(BucketEntry::Live(e))
  for each k in dead_entries:
    entries.append(BucketEntry::Dead(k))

  → create_bucket(entries)
```

---

### load_bucket

"First checks cache, then loads from disk. Files larger than
DISK_BACKED_THRESHOLD are loaded as DiskBacked (only index in memory);
smaller files are loaded entirely into memory."

```
load_bucket(hash):
  GUARD hash is zero         → empty Bucket

  // Check cache
  if cache contains hash:
    → cached bucket

  // Load from disk
  xdr_path = bucket_path(hash)
  GUARD xdr_path does not exist  → NotFound error

  file_size = metadata(xdr_path).size

  if file_size > DISK_BACKED_THRESHOLD:
    // Large file: DiskBacked
    if persist_index:
      disk_index = try_load_index_for_bucket(hash, DEFAULT_PAGE_SIZE)
      if disk_index exists:
        bucket = Bucket::from_xdr_file_disk_backed_prebuilt(
          xdr_path, hash, entry_count, disk_index)
        NOTE: "Skipped streaming build via persisted index"
      else:
        bucket = Bucket::from_xdr_file_disk_backed(xdr_path)
        if bucket has DiskIndex:
          save_index_for_bucket(hash, disk_index)
    else:
      bucket = Bucket::from_xdr_file_disk_backed(xdr_path)
  else:
    // Small file: load entirely into memory
    bucket = Bucket::load_from_xdr_file(xdr_path)    REF: bucket::Bucket::load_from_xdr_file

  // Verify hash
  GUARD bucket.hash() != hash  → HashMismatch error

  add_to_cache(hash, bucket)
  → bucket
```

---

### load_hot_archive_bucket

"Hot archive buckets contain HotArchiveBucketEntry instead of BucketEntry.
Not cached (different entry type)."

```
load_hot_archive_bucket(hash):
  GUARD hash is zero         → empty HotArchiveBucket

  xdr_path = bucket_path(hash)
  GUARD xdr_path does not exist  → NotFound error

  file_size = metadata(xdr_path).size
  if file_size > DISK_BACKED_THRESHOLD:
    bucket = HotArchiveBucket::from_xdr_file_disk_backed(xdr_path)
  else:
    bucket = HotArchiveBucket::load_from_xdr_file(xdr_path)

  GUARD bucket.hash() != hash  → HashMismatch error
  → bucket
```

**Calls** [HotArchiveBucket::from_xdr_file_disk_backed](hot_archive.pc.md#hotarchivebucketfrom_xdr_file_disk_backed), [HotArchiveBucket::load_from_xdr_file](hot_archive.pc.md#hotarchivebucketload_from_xdr_file)

---

### bucket_exists

```
bucket_exists(hash):
  GUARD hash is zero         → true
  if cache contains hash:    → true
  → bucket_path(hash) exists on disk
```

---

### merge

"Disk-backed streaming merge. Output written directly to disk.
Memory usage is O(index_size) not O(data_size)."

```
merge(old, new, max_protocol_version):
  GUARD both old and new are empty  → empty Bucket

  // Write merge output to temp file
  temp_path = temp_merge_path(bucket_dir)
  (hash, entry_count) = merge_buckets_to_file(
    old, new, temp_path,
    keep_dead_entries=true,
    max_protocol_version,
    normalize_init_entries=true)    REF: merge::merge_buckets_to_file

  if hash is zero or entry_count == 0:
    remove temp_path
    → empty Bucket

  // Check cache before doing disk work
  if cache contains hash:
    remove temp_path
    → cached bucket

  // Move temp → final canonical path
  final_path = bucket_path(hash)
  if final_path does not exist:
    rename temp_path → final_path
  else:
    remove temp_path

  // Load as DiskBacked (builds index)
  bucket = Bucket::from_xdr_file_disk_backed(final_path)

  // Persist index for next time
  if bucket has DiskIndex:
    save_index_for_bucket(hash, disk_index)

  add_to_cache(hash, bucket)
  → bucket
```

---

### save_index_for_bucket

```
save_index_for_bucket(hash, index):
  GUARD persist_index is false  → ok (no-op)
  bucket_path = bucket_path(hash)
  save_disk_index(index, bucket_path)    REF: index_persistence::save_disk_index
```

---

### try_load_index_for_bucket

```
try_load_index_for_bucket(hash, expected_page_size):
  GUARD persist_index is false  → None
  bucket_path = bucket_path(hash)
  → load_disk_index(bucket_path, expected_page_size)    REF: index_persistence::load_disk_index
```

---

### Helper: add_to_cache

```
add_to_cache(hash, bucket):
  if cache.size >= max_cache_size:
    "Remove a random entry (not ideal, but simple)"
    evict one entry from cache
  cache.insert(hash, bucket)
```

---

### clear_cache

```
clear_cache():
  cache.clear()
```

---

### list_buckets

```
list_buckets():
  hashes = []
  for each file in read_dir(bucket_dir):
    if filename ends with ".bucket.xdr":
      hash_str = strip suffix ".bucket.xdr"
      if parse hash_str as Hash256 succeeds:
        hashes.append(hash)
  → hashes
```

---

### delete_bucket

"Also removes the bucket from cache and deletes the associated
.index file when persist_index is true."

```
delete_bucket(hash):
  cache.remove(hash)

  xdr_path = bucket_path(hash)
  if xdr_path exists:
    if persist_index:
      delete_index(xdr_path)    REF: index_persistence::delete_index
    remove_file(xdr_path)
```

---

### retain_buckets

"Delete all bucket files not in the given set. Garbage collection."

```
retain_buckets(keep):
  keep_set = set(keep)
  all_buckets = list_buckets()
  deleted = 0

  for each hash in all_buckets:
    if hash not in keep_set:
      delete_bucket(hash)
      deleted += 1

  // Clean up merge map
  finished_merges.retain_outputs(keep_set)    REF: merge_map::BucketMergeMap::retain_outputs

  // Clean up orphaned index files
  if persist_index:
    cleanup_orphaned_indexes(bucket_dir)    REF: index_persistence::cleanup_orphaned_indexes

  → deleted
```

---

### import_bucket

"Saves raw bytes to disk, then loads via threshold-aware path."

```
import_bucket(xdr_bytes):
  hash = sha256(xdr_bytes)

  if cache contains hash:
    → cached bucket

  path = bucket_path(hash)
  if path does not exist:
    create parent dirs
    write xdr_bytes to path
    sync file

  // Load via threshold-aware path (DiskBacked for large, InMemory for small)
  → load_bucket(hash)
```

---

### export_bucket

```
export_bucket(hash):
  bucket = load_bucket(hash)
  → bucket.to_xdr_bytes()
```

---

### visit_ledger_entries

"Iterates through bucket entries, applying filter and accept functions.
Tracks seen keys to skip duplicates."

```
visit_ledger_entries(bucket_hashes, filter_entry, accept_entry, min_ledger):
  seen_keys = empty set

  for each hash in bucket_hashes:
    if hash is zero: continue

    bucket = load_bucket(hash)

    for each entry in bucket.iter():
      if entry is Live or Init:
        ledger_entry = entry.ledger_entry

        // Check min_ledger filter
        if min_ledger is set and entry.last_modified < min_ledger:
          continue

        // Check filter
        if not filter_entry(ledger_entry):
          continue

        // Check if already seen (dedup)
        key = ledger_entry_to_key(ledger_entry)    REF: entry::ledger_entry_to_key
        if key in seen_keys: continue
        seen_keys.add(key)

        // Accept the entry
        if not accept_entry(ledger_entry):
          → false  // stopped early

      else if entry is Dead:
        key = entry.key
        seen_keys.add(key)  // mark as seen (deleted)

      else if entry is Metadata:
        // skip

  → true  // iteration completed
```

---

### visit_ledger_entries_of_type

```
visit_ledger_entries_of_type(bucket_hashes, entry_type, accept_entry, min_ledger):
  → visit_ledger_entries(
      bucket_hashes,
      filter = |entry| entry.data_type == entry_type,
      accept_entry,
      min_ledger)
```

---

### load_complete_ledger_state

"Iterates all buckets oldest→newest, building a map.
Newer entries overwrite older. Dead entries remove keys."

```
load_complete_ledger_state(bucket_hashes):
  state = sorted map (key_bytes → LedgerEntry)

  "Process buckets from oldest to newest so newer entries win"
  for each hash in bucket_hashes:
    if hash is zero: continue

    bucket = load_bucket(hash)

    for each entry in bucket.iter():
      if entry is Live or Init:
        key_bytes = serialize(ledger_entry_to_key(entry))
        state.insert(key_bytes, ledger_entry)

      else if entry is Dead:
        key_bytes = serialize(entry.key)
        state.remove(key_bytes)  // dead shadows live

      else if entry is Metadata:
        // skip

  → state.values()
```

---

### merge_all_buckets

"Merges all buckets into a single 'super bucket' with all live entries."

```
merge_all_buckets(bucket_hashes, protocol_version):
  entries = load_complete_ledger_state(bucket_hashes)

  GUARD entries is empty  → empty Bucket

  bucket_entries = []
  // Add metadata
  bucket_entries.append(Metadata { ledger_version: protocol_version })
  // Add all as LIVE (not INIT since these are resolved entries)
  for each e in entries:
    bucket_entries.append(BucketEntry::Live(e))

  → create_bucket(bucket_entries)
```

---

### verify_buckets_exist

```
verify_buckets_exist(bucket_hashes):
  → [hash for hash in bucket_hashes
      if hash is not zero and not bucket_exists(hash)]
```

---

### verify_bucket_hashes

"Full hash verification by reading each bucket file. Expensive."

```
verify_bucket_hashes(bucket_hashes):
  mismatches = []

  for each expected_hash in bucket_hashes:
    if expected_hash is zero: continue

    xdr_path = bucket_path(expected_hash)
    if xdr_path does not exist: continue  // skip missing

    bucket = load_from_xdr_file(xdr_path)
    if load failed:
      mismatches.append((expected_hash, ZERO_HASH))
    else if bucket.hash() != expected_hash:
      mismatches.append((expected_hash, bucket.hash()))

  → mismatches
```

---

### ensure_buckets_exist

"Checks each bucket locally, fetching missing ones via callback.
Supports the assumeState flow for restoring from HistoryArchiveState."

```
ensure_buckets_exist(bucket_hashes, fetch_bucket):
  fetched = 0

  for each hash in bucket_hashes:
    if hash is zero: continue
    if bucket_exists(hash): continue

    xdr_bytes = fetch_bucket(hash)
    bucket = import_bucket(xdr_bytes)

    GUARD bucket.hash() != hash  → HashMismatch error
    fetched += 1

  → fetched
```

---

### cleanup_unreferenced_files

"Removes merge-tmp-*.xdr files not in the referenced set.
Only deletes files from PREVIOUS process runs to avoid race conditions
with in-flight async merges."

```
cleanup_unreferenced_files(referenced_paths):
  deleted = 0
  current_pid = process_id()

  for each file in read_dir(bucket_dir):
    if filename matches "merge-tmp-*.xdr":
      // Parse PID from filename: merge-tmp-{pid}-{counter}.xdr
      file_pid = parse pid from filename

      // Skip files from current process (may be in-flight)
      if file_pid == current_pid:
        continue

      // Delete unreferenced files from previous runs
      if file not in referenced_paths:
        remove_file(file)
        deleted += 1

  → deleted
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~580   | ~240       |
| Functions     | 24     | 24         |
