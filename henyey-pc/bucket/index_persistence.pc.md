## Pseudocode: crates/bucket/src/index_persistence.rs

"Index persistence for BucketListDB."
"Serialization/deserialization of DiskIndex to .index files."
"Enables fast startup without rebuilding indexes from bucket files."

```
CONST BUCKET_INDEX_VERSION = 4
  // v2: Added bloom filter and asset-to-pool-id persistence
  // v3: Page size changed from entry-count to byte-offset semantics
  // v4: Added entry_type_sizes to counters
```

### Data: File Format

```
FILE FORMAT: {hash}.bucket.index
  header:
    version   : u32
    page_size : u64
  data:
    pages          : list<(SerializableRangeEntry, u64)>
    bloom_seed     : 16 bytes
    bloom_filter   : BinaryFuse16 or nil
    counters       : SerializableCounters
    type_ranges    : map<u32, (u64, u64)>
    asset_pool_map : SerializableAssetPoolIdMap or nil
```

### Helper: entry_type_to_u32 / u32_to_entry_type

```
FUNCTION entry_type_to_u32(entry_type) → u32:
  Account=0, Trustline=1, Offer=2, Data=3,
  ClaimableBalance=4, LiquidityPool=5,
  ContractData=6, ContractCode=7,
  ConfigSetting=8, Ttl=9

FUNCTION u32_to_entry_type(value) → LedgerEntryType or nil:
  "Reverse of entry_type_to_u32"
```

### index_path_for_bucket

```
FUNCTION index_path_for_bucket(bucket_path) → path:
  → bucket_path with extension replaced by ".index"
```

### save_disk_index

"Uses atomic write via temp file + rename to prevent corruption."

```
FUNCTION save_disk_index(index, bucket_path):
  index_path = index_path_for_bucket(bucket_path)
  tmp_path = index_path + ".tmp"

  "Serialize index data"
  pages = []
  for (range, offset) in index.pages_iter():
    serializable_range = serialize_range_entry(range)
    pages.append((serializable_range, offset))

  type_ranges = {}
  for (entry_type, range) in index.type_ranges_iter():
    type_ranges[entry_type_to_u32(entry_type)] =
      (range.start_offset, range.end_offset)

  bloom_filter = index.bloom_filter() if present

  asset_pool_map = serialize_asset_pool_map(index)
  if asset_pool_map is empty:
    asset_pool_map = nil

  header = { version: BUCKET_INDEX_VERSION,
             page_size: index.page_size() }

  "Write to temp file"
  file = create(tmp_path)
  bincode_serialize(file, header)
  bincode_serialize(file, data)
  file.flush()

  "Atomic rename"
  rename(tmp_path → index_path)
  if rename fails:
    sleep(100ms)                   // race condition workaround
    rename(tmp_path → index_path)
```

### load_disk_index

"Returns nil if: file missing, version mismatch, page size mismatch, or deserialization error."

```
FUNCTION load_disk_index(bucket_path, expected_page_size)
    → DiskIndex or nil:
  index_path = index_path_for_bucket(bucket_path)

  GUARD not exists(index_path) → nil

  file = open(index_path)
  GUARD open fails (not found) → nil

  "Read and validate header"
  header = bincode_deserialize(file)
  GUARD deserialize fails → nil

  "Version check"
  if header.version != BUCKET_INDEX_VERSION:
    delete(index_path)
    → nil

  "PageSize check"
  if header.page_size != expected_page_size:
    delete(index_path)
    → nil

  "Load data"
  data = bincode_deserialize(file)
  GUARD deserialize fails →
    delete(index_path)
    → nil

  "Convert to DiskIndex"
  pages = deserialize_range_entries(data.pages)

  type_ranges = {}
  for (k, (start, end)) in data.type_ranges:
    entry_type = u32_to_entry_type(k)
    if entry_type is not nil:
      type_ranges[entry_type] = TypeRange(start, end)

  bloom_filter = restore_bloom(data.bloom_filter, data.bloom_seed)
  asset_pool_map = restore_asset_pool_map(data.asset_pool_map)

  → DiskIndex.from_persisted(
      header.page_size, pages, data.bloom_seed,
      data.counters, type_ranges,
      bloom_filter, asset_pool_map)
```

**Calls**: [index_path_for_bucket](#index_path_for_bucket) | [DiskIndex::from_persisted](index.pc.md#diskindexfrom_persisted)

### delete_index

```
FUNCTION delete_index(bucket_path):
  index_path = index_path_for_bucket(bucket_path)
  if exists(index_path):
    remove_file(index_path)
```

### cleanup_orphaned_indexes

"Remove index files without corresponding bucket files."

```
FUNCTION cleanup_orphaned_indexes(bucket_dir) → count:
  removed_count = 0

  for file in read_dir(bucket_dir):
    if file.extension == "index":
      bucket_path = file with extension ".xdr"
      if not exists(bucket_path):
        remove_file(file)
        removed_count += 1

  → removed_count
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 530    | 100        |
| Functions     | 12     | 7          |
