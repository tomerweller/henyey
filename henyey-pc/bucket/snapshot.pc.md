## Pseudocode: crates/bucket/src/snapshot.rs

"Thread-safe bucket list snapshots for concurrent access."
"BucketSnapshotManager uses a read-write lock to allow multiple concurrent"
"readers and exclusive write access when updating snapshots."

### BucketSnapshot (struct)

```
BucketSnapshot:
  bucket: shared<Bucket>
```

---

### BucketSnapshot.get

```
function get(key):
  → bucket.get(key)   // swallows errors
```

### BucketSnapshot.get_result

```
function get_result(key):
  → bucket.get(key)   // propagates errors
```

### BucketSnapshot.get_result_by_key_bytes

```
function get_result_by_key_bytes(key, key_bytes):
  → bucket.get_by_key_bytes(key, key_bytes)
```

### BucketSnapshot.load_keys

"For each key found, add to result and remove from keys."

```
function load_keys(keys, result):
  filter keys in place:
    entry = bucket.get(key)
    if entry is Live or Init:
      result.append(entry.ledger_entry)
      remove key
    if entry is Dead:
      remove key       // dead, don't add to result
    if entry is Metadata or not found:
      keep key         // continue searching
```

**Calls** [`Bucket.get`](bucket.pc.md)

---

### HotArchiveBucketSnapshot (struct)

```
HotArchiveBucketSnapshot:
  bucket: shared<HotArchiveBucket>
```

---

### BucketLevelSnapshot (struct)

```
BucketLevelSnapshot:
  curr: BucketSnapshot
  next: optional<BucketSnapshot>
  snap: BucketSnapshot

function from_level(level):
  curr = BucketSnapshot(share level.curr)
  next = level.next() if present
  snap = BucketSnapshot(share level.snap)
```

### HotArchiveBucketLevelSnapshot (struct)

```
HotArchiveBucketLevelSnapshot:
  curr: HotArchiveBucketSnapshot
  snap: HotArchiveBucketSnapshot
```

---

### BucketListSnapshot (struct)

"A complete snapshot of the live bucket list at a specific ledger."

```
BucketListSnapshot:
  levels: list<BucketLevelSnapshot>
  header: LedgerHeader
```

### BucketListSnapshot.new

```
function new(bucket_list, header):
  levels = for each level in bucket_list.levels():
    BucketLevelSnapshot.from_level(level)
  → BucketListSnapshot { levels, header }
```

---

### BucketListSnapshot.get

"Searches from level 0 (most recent) to level 10 (oldest)."
"Returns None immediately for OFFER keys (matching stellar-core's"
"LiveBucketIndex::typeNotSupported)."

```
function get(key):
  if type_not_supported(key_type(key)):
    → null

  key_bytes = serialize_xdr(key)

  for each level in levels:
    for each bucket in [level.curr, level.snap]:
      entry = bucket.get_result_by_key_bytes(key, key_bytes)
      if entry found:
        if entry is Live or Init: → entry.ledger_entry
        if entry is Dead: → null
        if entry is Metadata: continue

  → null
```

**Calls** [`LiveBucketIndex.type_not_supported`](index.pc.md)

---

### BucketListSnapshot.get_result

"Like get but propagates errors."

```
function get_result(key):
  if type_not_supported(key_type(key)):
    → null

  key_bytes = serialize_xdr(key)

  for each level in levels:
    for each bucket in [level.curr, level.snap]:
      entry = bucket.get_result_by_key_bytes(key, key_bytes)
      if entry found:
        if entry is Live or Init: → entry.ledger_entry
        if entry is Dead: → null
        if entry is Metadata: continue

  → null
```

---

### BucketListSnapshot.load_keys_result

"Batch-loads multiple entries in a single pass through the bucket list."
"Pre-serializes all keys once. Keys removed from search as found."

```
function load_keys_result(keys):
  result = []

  "Filter out unsupported types (OFFER)"
  keys = filter keys where not type_not_supported(key_type)

  if keys is empty: → result

  "Pre-serialize all keys once"
  remaining = [(key, serialize_xdr(key)) for key in keys]

  for each level in levels:
    if remaining is empty: break
    for each bucket in [level.curr, level.snap]:
      if remaining is empty: break
      filter remaining in place:
        entry = bucket.get_result_by_key_bytes(key, key_bytes)
        if entry is Live or Init:
          result.append(entry.ledger_entry)
          remove from remaining
        if entry is Dead:
          remove from remaining
        if entry is Metadata or not found:
          keep in remaining

  → result
```

---

### BucketListSnapshot.load_keys

```
function load_keys(keys):
  remaining_keys = copy of keys
  result = []

  for each level in levels:
    if remaining_keys is empty: break
    level.curr.load_keys(remaining_keys, result)
    if remaining_keys is empty: break
    level.snap.load_keys(remaining_keys, result)

  → result
```

---

### BucketListSnapshot.scan_for_eviction_incremental

"Snapshot-based equivalent of BucketList::scan_for_eviction_incremental."
"Performs the scan phase of eviction, collecting candidates within byte budget."

```
function scan_for_eviction_incremental(
    iter, current_ledger, settings):
  result = EvictionResult {
    candidates=[], end_iterator=iter,
    bytes_scanned=0, scan_complete=false }

  "Update iterator based on spills"
  update_starting_eviction_iterator(
    iter, settings.starting_eviction_scan_level,
    current_ledger)

  start_iter = iter
  bytes_remaining = settings.eviction_scan_size
  seen_keys = set<bytes>()

  loop:
    level = iter.bucket_list_level
    if level >= BUCKET_LIST_LEVELS:
      result.scan_complete = true
      break

    bucket = if iter.is_curr_bucket:
      levels[level].curr.raw_bucket()
    else:
      levels[level].snap.raw_bucket()

    (entries_scanned, bytes_used, finished_bucket) =
      scan_bucket_region(bucket, iter, bytes_remaining,
        current_ledger, result.candidates, seen_keys)

    result.bytes_scanned += bytes_used
    bytes_remaining = max(0, bytes_remaining - bytes_used)

    if bytes_remaining == 0:
      result.scan_complete = true
      break

    if finished_bucket:
      iter.advance_to_next_bucket(
        settings.starting_eviction_scan_level)

      "Check if we've looped back to start"
      if iter.bucket_list_level == start_iter.bucket_list_level
         and iter.is_curr_bucket == start_iter.is_curr_bucket:
        result.scan_complete = true
        break

  result.end_iterator = iter
  → result
```

**Calls** [`update_starting_eviction_iterator`](eviction.pc.md), [`EvictionIterator.advance_to_next_bucket`](eviction.pc.md)

---

### scan_bucket_region

"Scan a region of a bucket for evictable entries (scan phase only)."
"Returns (entries_scanned, bytes_used, finished_bucket)."

```
function scan_bucket_region(bucket, iter, max_bytes,
    current_ledger, candidates, seen_keys):
  entries_scanned = 0
  bytes_used = 0

  bucket_protocol = bucket.protocol_version() or 0
  if bucket_protocol < MIN_SOROBAN_PROTOCOL_VERSION:
    iter.bucket_file_offset = 0
    → (0, 0, true)

  start_offset = iter.bucket_file_offset

  for each (entry, entry_size) in
      bucket.iter_from_offset_with_sizes(start_offset):
    bytes_used += entry_size
    entries_scanned += 1

    if entry is Dead:
      seen_keys.insert(serialize_xdr(entry.key))
      if bytes_used >= max_bytes:
        iter.bucket_file_offset = start_offset + bytes_used
        → (entries_scanned, bytes_used, false)
      continue

    if entry is Metadata:
      if bytes_used >= max_bytes: ...same early return
      continue

    live_entry = entry.ledger_entry

    if not is_soroban_entry(live_entry):
      if bytes_used >= max_bytes: ...same early return
      continue

    key = ledger_entry_to_key(live_entry)
    if key is null:
      if bytes_used >= max_bytes: ...same early return
      continue

    key_bytes = serialize_xdr(key)

    "Skip if already seen (shadowed entry)"
    if key_bytes already in seen_keys:
      if bytes_used >= max_bytes: ...same early return
      continue

    seen_keys.insert(key_bytes)

    ttl_key = get_ttl_key(key)
    if ttl_key is null:
      if bytes_used >= max_bytes: ...same early return
      continue

    "Look up TTL entry from the snapshot"
    ttl_entry = self.get_result(ttl_key)
    if ttl_entry is null:
      if bytes_used >= max_bytes: ...same early return
      continue

    is_expired = is_ttl_expired(ttl_entry, current_ledger)
    if not is_expired:
      if bytes_used >= max_bytes: ...same early return
      continue

    "Entry is expired — collect as eviction candidate"
    is_temp = is_temporary_entry(live_entry)
    if not is_temp:
      "For persistent entries, archive NEWEST version"
      entry_for_candidate = self.get_result(key) or live_entry
    else:
      entry_for_candidate = live_entry

    candidates.append(EvictionCandidate {
      entry=entry_for_candidate, data_key=key,
      ttl_key, is_temporary=is_temp,
      position=EvictionIterator at
        (level, is_curr, start_offset + bytes_used) })

    if bytes_used >= max_bytes:
      iter.bucket_file_offset = start_offset + bytes_used
      → (entries_scanned, bytes_used, false)

  "Finished the bucket"
  iter.bucket_file_offset = start_offset + bytes_used
  → (entries_scanned, bytes_used, true)
```

**Calls** [`is_soroban_entry`](entry.pc.md), [`get_ttl_key`](entry.pc.md), [`is_ttl_expired`](entry.pc.md), [`is_temporary_entry`](entry.pc.md)

---

### HotArchiveBucketListSnapshot

```
HotArchiveBucketListSnapshot:
  levels: list<HotArchiveBucketLevelSnapshot>
  header: LedgerHeader

function new(bucket_list, header):
  levels = for each level in bucket_list.levels():
    HotArchiveBucketLevelSnapshot.from_level(level)
```

---

### SearchableBucketListSnapshot

"Higher-level interface with support for historical ledger lookups."

```
SearchableBucketListSnapshot:
  snapshot: BucketListSnapshot
  historical_snapshots: sorted_map<u32, BucketListSnapshot>
```

### SearchableBucketListSnapshot.load

```
function load(key):
  → snapshot.get(key)
```

### SearchableBucketListSnapshot.load_keys

```
function load_keys(keys):
  → snapshot.load_keys(keys)
```

### SearchableBucketListSnapshot.load_keys_from_ledger

```
function load_keys_from_ledger(keys, ledger_seq):
  if ledger_seq == snapshot.ledger_seq():
    → snapshot.load_keys(keys)
  snap = historical_snapshots.get(ledger_seq)
  if snap: → snap.load_keys(keys)
  → null
```

### SearchableBucketListSnapshot.available_ledger_range

```
function available_ledger_range():
  oldest = first key in historical_snapshots
           or snapshot.ledger_seq()
  → (oldest, snapshot.ledger_seq())
```

---

### scan_for_entries_of_type

"Scans all entries of a specific type from newest to oldest."

```
function scan_for_entries_of_type(entry_type, callback):
  seen_keys = set<LedgerKey>()

  for each level in snapshot.levels:
    for each bucket in [level.curr, level.snap]:
      for each bucket_entry in bucket.iter():
        key = bucket_entry.key()
        if key is null: continue

        "Skip if we've already seen a newer version"
        if key in seen_keys: continue

        matches_type = false
        if entry is Live or Init:
          matches_type = (entry_data_type == entry_type)
        if entry is Dead:
          matches_type = (key_type == entry_type)

        if matches_type:
          seen_keys.insert(key)
          if entry is not Dead:
            if not callback(bucket_entry):
              → false  // stopped early

  → true  // completed
```

---

### load_inflation_winners

"Legacy query: scans accounts with inflation destinations."

```
function load_inflation_winners(max_winners, min_balance):
  seen_accounts = set<AccountId>()
  vote_counts = map<AccountId, int64>()

  for each level in snapshot.levels:
    for each bucket in [level.curr, level.snap]:
      for each entry in bucket.iter():
        if entry is Live or Init:
          if entry is Account:
            if account_id in seen_accounts: continue
            seen_accounts.insert(account_id)
            if inflation_dest is set:
              vote_counts[inflation_dest] += balance
        if entry is Dead and key is Account:
          seen_accounts.insert(account_id)

  winners = filter vote_counts where votes >= min_balance
  sort winners by votes descending
  truncate to max_winners
  → winners
```

---

### load_pool_share_trustlines_by_account_and_asset

```
function load_pool_share_trustlines_by_account_and_asset(
    account_id, asset):
  pool_ids = collect_pool_ids_for_asset(asset)
  if pool_ids is empty: → []

  trustline_keys = for each pool_id in pool_ids:
    LedgerKey::Trustline(account_id, PoolShare(pool_id))

  → snapshot.load_keys(trustline_keys)
```

### Helper: collect_pool_ids_for_asset

```
function collect_pool_ids_for_asset(asset):
  pool_ids = []
  seen_pools = set<PoolId>()

  for each level in snapshot.levels:
    for each bucket in [level.curr, level.snap]:
      for each entry in bucket.iter():
        if entry is Live or Init and is LiquidityPool:
          if pool_id in seen_pools: continue
          if pool contains asset:
            seen_pools.insert(pool_id)
            pool_ids.append(pool_id)
        if entry is Dead and key is LiquidityPool:
          seen_pools.insert(pool_id)

  → pool_ids
```

---

### load_trustlines_for_account

```
function load_trustlines_for_account(account_id):
  trustlines = []
  seen_keys = set<LedgerKey>()

  for each level in snapshot.levels:
    for each bucket in [level.curr, level.snap]:
      for each entry in bucket.iter():
        if entry is Live or Init and is Trustline:
          if trustline.account_id == account_id:
            key = trustline key
            if key not in seen_keys:
              seen_keys.insert(key)
              trustlines.append(entry)
        if entry is Dead and key is Trustline:
          if key.account_id == account_id:
            seen_keys.insert(key)

  → trustlines
```

---

### SearchableHotArchiveBucketListSnapshot

```
SearchableHotArchiveBucketListSnapshot:
  snapshot: HotArchiveBucketListSnapshot
  historical_snapshots: sorted_map<u32, ...>
```

---

### BucketSnapshotManager

"Manages current and historical snapshots for thread-safe concurrent access."

```
BucketSnapshotManager:
  current_live: RwLock<BucketListSnapshot>
  current_hot_archive: RwLock<HotArchiveBucketListSnapshot>
  live_historical: RwLock<sorted_map<u32, BucketListSnapshot>>
  hot_archive_historical: RwLock<sorted_map<u32, ...>>
  num_historical_snapshots: u32
```

### BucketSnapshotManager.new

```
function new(live_snapshot, hot_archive_snapshot,
    num_historical_snapshots):
  current_live = live_snapshot
  current_hot_archive = hot_archive_snapshot
  live_historical = {}
  hot_archive_historical = {}
```

### copy_searchable_live_snapshot

"Acquires a read lock. Safe to call from any thread."

```
function copy_searchable_live_snapshot():
  snapshot = read_lock(current_live).copy()
  historical = read_lock(live_historical).copy()
  → SearchableBucketListSnapshot(snapshot, historical)
```

### copy_searchable_hot_archive_snapshot

```
function copy_searchable_hot_archive_snapshot():
  snapshot = read_lock(current_hot_archive).copy()
  historical = read_lock(hot_archive_historical).copy()
  → SearchableHotArchiveBucketListSnapshot(
      snapshot, historical)
```

### maybe_update_live_snapshot

```
function maybe_update_live_snapshot(snapshot):
  current = read_lock(current_live)
  needs_update = (current exists and
    (snapshot is null or
     current.ledger_seq > snapshot.ledger_seq))

  if needs_update:
    snapshot = copy_searchable_live_snapshot()
    → true
  → false
```

### update_current_snapshot

"Main thread only, after ledger close. Acquires write locks."

```
function update_current_snapshot(
    live_snapshot, hot_archive_snapshot):

  "Update live snapshot"
  write_lock(current_live, live_historical):
    if num_historical_snapshots > 0:
      prev = take current
      if prev exists:
        if historical.length >= num_historical_snapshots:
          remove oldest from historical
        historical.insert(prev.ledger_seq, prev)
    current = live_snapshot

  "Update hot archive snapshot"
  write_lock(current_hot_archive, hot_archive_historical):
    if num_historical_snapshots > 0:
      prev = take current
      if prev exists:
        if historical.length >= num_historical_snapshots:
          remove oldest from historical
        historical.insert(prev.ledger_seq, prev)
    current = hot_archive_snapshot
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~1321  | ~310       |
| Functions     | 32     | 32         |
