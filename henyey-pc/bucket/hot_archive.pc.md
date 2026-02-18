## Pseudocode: crates/bucket/src/hot_archive.rs

"Hot Archive Bucket List for recently evicted Soroban entries."
"When persistent entries (ContractData/ContractCode) expire, they move
from the live BucketList to the HotArchiveBucketList."

```
CONST FIRST_PROTOCOL_SUPPORTING_HOT_ARCHIVE = 23
CONST HOT_ARCHIVE_BUCKET_LIST_LEVELS = 11

"Merge semantics:
  Archived + Live    = Annihilate (entry was restored)
  Live + Archived    = Keep Archived (re-archived)
  Archived + Archived = Keep newer
  At level 10: Live entries are dropped (tombstones not needed)"
```

---

### HotArchiveStorage

```
STATE_MACHINE: HotArchiveStorage
  STATES: [InMemory, DiskBacked]
  InMemory:
    entries: sorted map (key_bytes → HotArchiveBucketEntry)
    ordered_entries: list  // preserves original order for hash
  DiskBacked:
    path: file path
    index: lazy sorted map (key_bytes → file_offset)
    entry_count: int
```

---

### Helper: build_index

"Streams through XDR file to build key→offset index."

```
build_index(path):
  file = open(path)
  file_len = file.metadata.size
  index = sorted map
  position = 0

  while position + 4 <= file_len:
    record_offset = position

    // Read XDR record mark (RFC 5531)
    mark_bytes = read 4 bytes
    record_mark = big_endian_u32(mark_bytes)
    record_len = record_mark & 0x7FFFFFFF

    if position + 4 + record_len > file_len:
      break

    data = read record_len bytes
    entry = parse HotArchiveBucketEntry from data
    key = hot_archive_entry_to_key(entry)
    index.insert(key, record_offset)

    position += 4 + record_len

  → index
```

---

### Helper: ensure_index

```
ensure_index():
  ASSERT: storage is DiskBacked
  → index.get_or_init(|| build_index(path))
```

---

### HotArchiveBucket::empty

```
empty():
  → HotArchiveBucket {
      storage: InMemory { entries: {}, ordered_entries: [] },
      hash: ZERO_HASH
    }
```

---

### HotArchiveBucket::from_entries

"Entries MUST be pre-sorted in stellar-core order (LedgerEntryIdCmp)."

```
from_entries(entries):
  entry_map = sorted map
  for each entry in entries:
    key = hot_archive_entry_to_key(entry)
    entry_map.insert(key, entry)

  bucket = HotArchiveBucket {
    storage: InMemory { entries: entry_map, ordered_entries: entries },
    hash: ZERO_HASH
  }
  bucket.hash = bucket.compute_hash()
  → bucket
```

---

### HotArchiveBucket::fresh

"Primary way to create a new hot archive bucket when entries are evicted."

```
fresh(protocol_version, archived_entries, restored_keys):
  "In stellar-core, BucketOutputIterator always writes a metaentry first,
   so fresh buckets always have at least a metaentry."

  entries = []

  // Add metadata (V1 with BucketListType::HotArchive)
  entries.append(Metaentry {
    ledger_version: protocol_version,
    ext: V1(HotArchive)
  })

  for each entry in archived_entries:
    entries.append(Archived(entry))

  for each key in restored_keys:
    entries.append(Live(key))

  // Sort using stellar-core comparison order (BucketEntryIdCmp)
  sort entries by compare_hot_archive_entries

  → from_entries(entries)
```

---

### HotArchiveBucket::get_protocol_version

"Returns ledger_version from metadata entry, or 0 if none."

```
get_protocol_version():
  if InMemory:
    if entries contains empty key → Metaentry:
      → meta.ledger_version
    → 0
  if DiskBacked:
    index = ensure_index()
    if index contains empty key:
      entry = read_entry_at_offset(path, offset)
      if entry is Metaentry:
        → meta.ledger_version
    → 0
```

---

### HotArchiveBucket::get

```
get(key):
  key_bytes = serialize(key)
  if InMemory:
    → entries.get(key_bytes)
  if DiskBacked:
    index = ensure_index()
    if index contains key_bytes:
      → read_entry_at_offset(path, index[key_bytes])
    → None
```

---

### HotArchiveBucket::iter

```
iter():
  if InMemory:
    → iterator over entries.values()
  if DiskBacked:
    file = open(path)
    → streaming XDR record iterator over file
```

---

### compute_hash

"Must match stellar-core bucket hashing: each entry has XDR record mark
(4-byte size with high bit set), hash covers entire serialized content."

```
compute_hash():
  if InMemory:
    GUARD ordered_entries is empty  → ZERO_HASH

    hasher = SHA-256
    "Iterate over ordered_entries which preserves original entry order.
     Critical: stellar-core uses semantic comparison (LedgerEntryIdCmp)
     which differs from XDR byte order."
    for each entry in ordered_entries:
      bytes = serialize(entry)
      sz = bytes.length
      record_mark = [sz >> 24 | 0x80, sz >> 16, sz >> 8, sz] // high bit set
      hasher.update(record_mark)
      hasher.update(bytes)
    → Hash256(hasher.finalize())

  if DiskBacked:
    → self.hash  // computed during construction
```

---

### Helper: read_entry_at_offset

```
read_entry_at_offset(path, offset):
  file = open(path)
  seek to offset

  mark_bytes = read 4 bytes
  record_mark = big_endian_u32(mark_bytes)
  record_len = record_mark & 0x7FFFFFFF

  data = read record_len bytes
  → parse HotArchiveBucketEntry from data
```

---

### from_xdr_bytes

"Parses XDR with Record Marking Standard (RFC 5531). Preserves original
file order for hash computation."

```
from_xdr_bytes(bytes):
  GUARD bytes is empty  → empty bucket

  entries = sorted map
  ordered_entries = []
  offset = 0

  uses_record_marks = (bytes[0] & 0x80) != 0

  if uses_record_marks:
    while offset + 4 <= bytes.length:
      record_mark = big_endian_u32(bytes[offset..offset+4])
      offset += 4
      record_len = record_mark & 0x7FFFFFFF

      GUARD offset + record_len > bytes.length  → error

      entry = parse HotArchiveBucketEntry from bytes[offset..offset+record_len]
      key = hot_archive_entry_to_key(entry)
      entries.insert(key, entry)
      ordered_entries.append(entry)
      offset += record_len
  else:
    // Legacy raw XDR stream
    while not at end of bytes:
      entry = read_xdr(HotArchiveBucketEntry)
      key = hot_archive_entry_to_key(entry)
      entries.insert(key, entry)
      ordered_entries.append(entry)

  hash = sha256(bytes)  // hash from raw bytes including record marks
  → HotArchiveBucket { InMemory { entries, ordered_entries }, hash }
```

---

### load_from_xdr_file

```
load_from_xdr_file(path):
  bytes = read_file(path)
  → from_xdr_bytes(bytes)
```

---

### to_xdr_bytes

```
to_xdr_bytes():
  if InMemory:
    bytes = []
    for each entry in ordered_entries:
      entry_bytes = serialize(entry)
      sz = entry_bytes.length
      record_mark = sz | 0x80000000
      bytes.append(big_endian_bytes(record_mark))
      bytes.append(entry_bytes)
    → bytes
  if DiskBacked:
    → read entire file
```

---

### save_to_xdr_file

```
save_to_xdr_file(path):
  if InMemory:
    bytes = to_xdr_bytes()
    write bytes to path
    sync file
  if DiskBacked:
    if source_path != path:
      copy source_path → path
  → path
```

---

### from_xdr_file_disk_backed

"Streams through file to build index without loading all entries.
Hash computed during the streaming pass. Index built eagerly."

```
from_xdr_file_disk_backed(path):
  file = open(path)
  file_len = file.metadata.size

  built_index = sorted map
  hasher = SHA-256
  entry_count = 0
  position = 0

  while position + 4 <= file_len:
    record_offset = position

    mark_bytes = read 4 bytes
    record_mark = big_endian_u32(mark_bytes)
    record_len = record_mark & 0x7FFFFFFF

    GUARD position + 4 + record_len > file_len  → error

    data = read record_len bytes

    // Hash: include record mark + data
    hasher.update(mark_bytes)
    hasher.update(data)

    entry = parse HotArchiveBucketEntry from data
    key = hot_archive_entry_to_key(entry)
    built_index.insert(key, record_offset)
    entry_count += 1

    position += 4 + record_len

  hash = if entry_count == 0: ZERO_HASH
         else: Hash256(hasher.finalize())

  → HotArchiveBucket {
      DiskBacked { path, index: built_index, entry_count },
      hash
    }
```

---

### HotArchiveIter (Iterator)

```
next():
  if InMemory:
    → next value from entries iterator

  if DiskBacked:
    GUARD position + 4 > file_len  → None

    mark_bytes = read 4 bytes
    record_mark = big_endian_u32(mark_bytes)
    record_len = record_mark & 0x7FFFFFFF

    GUARD position + 4 + record_len > file_len  → None

    data = read record_len bytes
    position += 4 + record_len
    → parse HotArchiveBucketEntry from data

  if Empty:
    → None
```

---

### HotArchiveBucketLevel

```
HotArchiveBucketLevel:
  curr: HotArchiveBucket
  snap: HotArchiveBucket
  next: optional HotArchiveBucket  // staged merge result
  _level: int
```

---

### HotArchiveBucketLevel::hash

```
hash():
  hasher = SHA-256
  hasher.update(curr.hash())
  hasher.update(snap.hash())
  → Hash256(hasher.finalize())
```

---

### HotArchiveBucketLevel::commit

```
commit():
  if next exists:
    curr = take(next)
```

---

### HotArchiveBucketLevel::snap

```
snap():
  self.snap = take(self.curr)  // curr becomes empty
  → self.snap
```

---

### HotArchiveBucketLevel::prepare

"Merges incoming bucket with curr (or empty curr). Stores result in next."

```
prepare(protocol_version, incoming, keep_tombstones, use_empty_curr):
  GUARD next already exists  → "merge already in progress" error

  curr_for_merge = if use_empty_curr: empty bucket
                   else: self.curr

  merged = merge_hot_archive_buckets(
    curr_for_merge, incoming,
    protocol_version, keep_tombstones)
  self.next = merged
```

**Calls** [merge_hot_archive_buckets](#merge_hot_archive_buckets)

---

### HotArchiveBucketList::new

```
new():
  levels = [HotArchiveBucketLevel::new(i) for i in 0..11]
  → HotArchiveBucketList { levels, ledger_seq: 0 }
```

---

### HotArchiveBucketList::hash

```
hash():
  hasher = SHA-256
  for each level in levels:
    hasher.update(level.hash())
  → Hash256(hasher.finalize())
```

---

### HotArchiveBucketList::referenced_file_paths

```
referenced_file_paths():
  paths = set
  for each level in levels:
    if level.curr has backing file: paths.add(path)
    if level.snap has backing file: paths.add(path)
    if level.next exists and has backing file: paths.add(path)
  → paths
```

---

### HotArchiveBucketList::all_bucket_hashes

```
all_bucket_hashes():
  hashes = []
  for each level:
    hashes.append(level.curr.hash())
    hashes.append(level.snap.hash())
  → hashes
```

---

### HotArchiveBucketList::add_batch

```
add_batch(ledger_seq, protocol_version, archived_entries, restored_keys):
  GUARD protocol_version < FIRST_PROTOCOL_SUPPORTING_HOT_ARCHIVE  → error

  "In stellar-core, BucketOutputIterator always writes metaentry first,
   so fresh() always creates a bucket with at least a metaentry."
  new_bucket = HotArchiveBucket::fresh(
    protocol_version, archived_entries, restored_keys)

  add_batch_internal(ledger_seq, protocol_version, new_bucket)
  self.ledger_seq = ledger_seq
```

---

### HotArchiveBucketList::advance_to_ledger

```
advance_to_ledger(target_ledger, protocol_version):
  current = self.ledger_seq
  GUARD target_ledger <= current  → ok (nothing to do)

  for seq in (current + 1)..target_ledger:
    add_batch(seq, protocol_version, [], [])  // empty batches
```

---

### add_batch_internal

"Process spills from highest level down, then add to level 0."

```
add_batch_internal(ledger_seq, protocol_version, new_bucket):
  GUARD ledger_seq == 0  → error

  // Process spills from highest level down
  for i in (HOT_ARCHIVE_BUCKET_LIST_LEVELS - 1) down to 1:
    if level_should_spill(ledger_seq, i - 1):
      spilling_snap = levels[i - 1].snap()
      levels[i].commit()

      keep_tombstones = keep_tombstone_entries(i)
      use_empty_curr = should_merge_with_empty_curr(ledger_seq, i)
      levels[i].prepare(
        protocol_version, spilling_snap,
        keep_tombstones, use_empty_curr)

  // Add new entries to level 0
  // Level 0 never uses empty curr
  keep_tombstones_0 = keep_tombstone_entries(0)
  levels[0].prepare(protocol_version, new_bucket, keep_tombstones_0, false)
  levels[0].commit()
```

---

### HotArchiveBucketList::get

```
get(key):
  for each level:
    for bucket in [level.curr, level.snap]:
      entry = bucket.get(key)
      if entry is Archived:  → entry.ledger_entry
      if entry is Live:      → None  // restored, not in archive
      if entry is Metaentry: continue
  → None
```

---

### Helper: round_down

```
round_down(value, modulus):
  if modulus == 0: → 0
  → value & !(modulus - 1)
```

---

### Helper: level_half

```
level_half(level):
  → 1 << (2 * level + 1)
```

---

### Helper: level_size

```
level_size(level):
  → 1 << (2 * (level + 1))
```

---

### level_should_spill

"Matches stellar-core's levelShouldSpill."

```
level_should_spill(ledger_seq, level):
  GUARD level == HOT_ARCHIVE_BUCKET_LIST_LEVELS - 1  → false

  half = level_half(level)
  size = level_size(level)
  → ledger_seq % half == 0 or ledger_seq % size == 0
```

---

### keep_tombstone_entries

```
keep_tombstone_entries(level):
  → level < HOT_ARCHIVE_BUCKET_LIST_LEVELS - 1
```

---

### should_merge_with_empty_curr

"Matches stellar-core's shouldMergeWithEmptyCurr."

```
should_merge_with_empty_curr(ledger_seq, level):
  GUARD level == 0  → false

  merge_start_ledger = round_down(ledger_seq, level_half(level - 1))
  next_change_ledger = merge_start_ledger + level_half(level - 1)

  // If the next spill would affect this level, use empty curr
  // because curr is about to be snapped
  → level_should_spill(next_change_ledger, level)
```

---

### restore_from_hashes

```
restore_from_hashes(hashes, load_bucket):
  GUARD hashes.length != HOT_ARCHIVE_BUCKET_LIST_LEVELS * 2  → error

  pairs = chunk hashes into (curr, snap) pairs
  next_states = [default HasNextState] * NUM_LEVELS

  → restore_from_has(pairs, next_states, load_bucket)
```

---

### restore_from_has

"Primary restoration method. Restores pending merge results when HAS
indicates a completed merge (state == HAS_NEXT_STATE_OUTPUT)."

```
restore_from_has(hashes, next_states, load_bucket):
  GUARD hashes.length != HOT_ARCHIVE_BUCKET_LIST_LEVELS  → error

  levels = []
  for i, (curr_hash, snap_hash) in enumerate(hashes):
    curr = if curr_hash is zero: empty
           else: load_bucket(curr_hash)
    snap = if snap_hash is zero: empty
           else: load_bucket(snap_hash)

    // Check for completed merge (state == HAS_NEXT_STATE_OUTPUT)
    next = None
    if next_states[i].state == HAS_NEXT_STATE_OUTPUT:
      output_hash = next_states[i].output
      if output_hash exists and not zero:
        next = load_bucket(output_hash)

    level = new HotArchiveBucketLevel(i)
    level.curr = curr
    level.snap = snap
    level.next = next
    levels.append(level)

  → HotArchiveBucketList { levels, ledger_seq: 0 }
```

---

### restart_merges_from_has

"Handles state 2 (HAS_NEXT_STATE_INPUTS) by restarting merges with
the exact input hashes stored in the HAS."

```
restart_merges_from_has(ledger, protocol_version, next_states,
                        load_bucket, restart_structure_based):
  for i in 1..HOT_ARCHIVE_BUCKET_LIST_LEVELS:
    // Skip if already has pending merge (from state 1 output)
    if levels[i].next exists: continue

    // Check if HAS has stored input hashes (state 2)
    if next_states[i].state == HAS_NEXT_STATE_INPUTS:
      curr_hash = next_states[i].input_curr
      snap_hash = next_states[i].input_snap

      if both hashes available:
        input_curr = if curr_hash is zero: empty
                     else: load_bucket(curr_hash)
        input_snap = if snap_hash is zero: empty
                     else: load_bucket(snap_hash)

        keep_tombstones = keep_tombstone_entries(i)
        merged = merge_hot_archive_buckets(
          input_curr, input_snap,
          protocol_version, keep_tombstones)
        levels[i].next = merged

  // Fall back to structure-based restart for levels with no HAS hashes
  if restart_structure_based:
    restart_merges(ledger, protocol_version)
  else:
    self.ledger_seq = ledger
```

---

### restart_merges

"Recreates pending merges by examining curr/snap buckets.
Matches stellar-core's BucketListBase::restartMerges() for hot archive."

```
restart_merges(ledger, protocol_version):
  for i in 1..HOT_ARCHIVE_BUCKET_LIST_LEVELS:
    if levels[i].next exists: continue

    prev_snap = levels[i - 1].snap
    if prev_snap is empty:
      break  // this and all higher levels are uninitialized

    merge_start_ledger = round_down(ledger, level_half(i - 1))

    // Determine merge parameters
    merge_protocol_version = if prev_snap.get_protocol_version() == 0:
                               protocol_version
                             else: prev_snap.get_protocol_version()
    keep_tombstones = keep_tombstone_entries(i)
    use_empty_curr = should_merge_with_empty_curr(merge_start_ledger, i)

    levels[i].prepare(
      merge_protocol_version, prev_snap,
      keep_tombstones, use_empty_curr)

  self.ledger_seq = ledger
```

---

### hot_archive_entry_to_key

```
hot_archive_entry_to_key(entry):
  if entry is Archived:
    key = ledger_entry_to_key(entry.ledger_entry)    REF: entry::ledger_entry_to_key
    → serialize(key)
  if entry is Live:
    → serialize(entry.key)
  if entry is Metaentry:
    → empty bytes  // special key
```

---

### compare_hot_archive_entries

"Matches stellar-core's BucketEntryIdCmp<HotArchiveBucket>."

```
compare_hot_archive_entries(a, b):
  // Metaentry always sorts first
  if a is Metaentry and b is Metaentry: → Equal
  if a is Metaentry: → Less
  if b is Metaentry: → Greater

  // Compare by LedgerKey
  key_a = extract LedgerKey from a
  key_b = extract LedgerKey from b
  → compare_ledger_keys(key_a, key_b)
```

---

### compare_ledger_keys

"Matches stellar-core's LedgerEntryIdCmp."

```
compare_ledger_keys(a, b):
  // Compare by type discriminant first
  if type(a) != type(b):
    → type_discriminant(a).cmp(type_discriminant(b))

  // Same type: compare by type-specific fields
  Account:       → account_id
  Trustline:     → (account_id, asset)
  Offer:         → (seller_id, offer_id)
  Data:          → (account_id, data_name)
  ClaimableBalance: → balance_id
  LiquidityPool: → liquidity_pool_id
  ContractData:  → (contract, key, durability)
  ContractCode:  → hash
  ConfigSetting: → config_setting_id
  Ttl:           → key_hash
```

---

### is_hot_archive_tombstone

```
is_hot_archive_tombstone(entry):
  → entry is Live  // Live marker = tombstone in hot archive
```

---

### merge_hot_archive_buckets

"Hot archive merge rules:
  Archived + Live     = Annihilate (restored)
  Live + Archived     = Keep Archived (re-archived)
  Archived + Archived = Keep newer (from snap)
  At bottom level: Live entries are dropped"

```
merge_hot_archive_buckets(curr, snap, protocol_version, keep_tombstones):
  NOTE: "We intentionally do NOT optimize for empty buckets.
  stellar-core always goes through the full merge process because
  output gets new metadata and hash includes metadata."

  GUARD snap empty and curr empty and protocol_version == 0
    → empty bucket

  merged_entries = map (key → entry)

  // Process curr entries first (older)
  for each entry in curr.iter():
    if entry is Metaentry: continue
    key = hot_archive_entry_to_key(entry)
    merged_entries.insert(key, entry)

  // Process snap entries (newer - always wins)
  "stellar-core mergeCasesWithEqualKeys always takes newer entry"
  for each entry in snap.iter():
    if entry is Metaentry: continue
    key = hot_archive_entry_to_key(entry)
    merged_entries.insert(key, entry)  // overwrites curr

  // Drop tombstones at bottom level
  if not keep_tombstones:
    merged_entries.remove_all(is_hot_archive_tombstone)

  // Build result with metadata
  NOTE: "Even if merged_entries is empty, create bucket with metaentry.
  In stellar-core, BucketOutputIterator always writes metaentry first.
  Critical for hash consistency."

  // Calculate output protocol version: max(curr, snap)
  output_version = max(curr.get_protocol_version(),
                       snap.get_protocol_version())

  GUARD protocol_version > 0 and output_version > protocol_version
    → "version exceeds max" error

  result_entries = []

  // Add metadata
  meta = BucketMetadata { ledger_version: output_version }
  @version(>= FIRST_PROTOCOL_SUPPORTING_HOT_ARCHIVE):
    meta.ext = V1(HotArchive)
  result_entries.append(Metaentry(meta))

  result_entries.extend(merged_entries.values())

  // Sort for hash consistency with stellar-core
  sort result_entries by compare_hot_archive_entries

  → HotArchiveBucket::from_entries(result_entries)
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~1000  | ~370       |
| Functions     | 37     | 37         |
