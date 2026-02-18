## Pseudocode: crates/bucket/src/index.rs

"Advanced bucket indexing for efficient lookups."
"Hybrid system: InMemoryIndex for small buckets, DiskIndex for large buckets."
"Matches stellar-core LiveBucketIndex pattern."

```
CONST DEFAULT_PAGE_SIZE = 16384      // 1 << 14, byte-offset page size
CONST DEFAULT_INDEX_CUTOFF = 20 MB   // file size threshold for index type
```

### Data: RangeEntry

```
STRUCT RangeEntry:
  lower_bound : LedgerKey   // inclusive
  upper_bound : LedgerKey   // inclusive
```

### RangeEntry::contains

```
FUNCTION contains(key) → bool:
  → compare_keys(key, lower_bound) >= EQUAL
    and compare_keys(key, upper_bound) <= EQUAL
```

**Calls**: [compare_keys](entry.pc.md#compare_keys)

---

### Data: BucketEntryCounters

```
STRUCT BucketEntryCounters:
  live_entries              : map<LedgerEntryType, u64>
  dead_entries              : map<LedgerEntryType, u64>
  init_entries              : map<LedgerEntryType, u64>
  entry_type_sizes          : map<LedgerEntryType, u64>   // XDR byte sizes
  persistent_soroban_entries : u64
  temporary_soroban_entries  : u64
```

### record_entry

```
FUNCTION record_entry(entry):
  xdr_size = entry.to_xdr().length

  if entry is Live(e):
    entry_type = type_of(e.data)
    live_entries[entry_type] += 1
    entry_type_sizes[entry_type] += xdr_size
    record_soroban_durability(e)

  else if entry is Init(e):
    entry_type = type_of(e.data)
    init_entries[entry_type] += 1
    entry_type_sizes[entry_type] += xdr_size
    record_soroban_durability(e)

  else if entry is Dead(k):
    entry_type = type_of(k)
    dead_entries[entry_type] += 1
    entry_type_sizes[entry_type] += xdr_size

  "Skip Metadata entries"
```

### Helper: record_soroban_durability

```
FUNCTION record_soroban_durability(ledger_entry):
  if entry.data is ContractData:
    if durability == Persistent:
      persistent_soroban_entries += 1
    else if durability == Temporary:
      temporary_soroban_entries += 1
  else if entry.data is ContractCode:
    "ContractCode is always persistent"
    persistent_soroban_entries += 1
```

### merge (counters)

```
FUNCTION merge(other):
  for each map in [live_entries, dead_entries,
                    init_entries, entry_type_sizes]:
    for (type, count) in other.map:
      self.map[type] += count
  persistent_soroban_entries += other.persistent_soroban_entries
  temporary_soroban_entries += other.temporary_soroban_entries
```

---

### Data: AssetPoolIdMap

"Maps assets to their associated liquidity pool IDs."

```
STRUCT AssetPoolIdMap:
  asset_to_pools : map<hash[32], set<PoolId>>
```

### add_pool

```
FUNCTION add_pool(pool_id, asset_a, asset_b):
  hash_a = SHA256(asset_a.to_xdr())
  hash_b = SHA256(asset_b.to_xdr())
  asset_to_pools[hash_a].add(pool_id)
  asset_to_pools[hash_b].add(pool_id)
```

### get_pools_for_asset

```
FUNCTION get_pools_for_asset(asset) → list<PoolId>:
  hash = SHA256(asset.to_xdr())
  → asset_to_pools[hash] as list, or []
```

---

### Data: TypeRange

```
STRUCT TypeRange:
  start_offset : u64   // byte offset in bucket file
  end_offset   : u64   // exclusive
```

---

### Data: InMemoryIndex

"O(1) lookup for small buckets (below DEFAULT_INDEX_CUTOFF file size)."

```
STRUCT InMemoryIndex:
  key_to_offset    : map<bytes, u64>     // XDR key → file offset
  bloom_filter     : BucketBloomFilter or nil
  bloom_seed       : 16 bytes
  asset_to_pool_id : AssetPoolIdMap
  counters         : BucketEntryCounters
  type_ranges      : map<LedgerEntryType, TypeRange>
```

### InMemoryIndex::from_entries

```
FUNCTION from_entries(entries_iter, bloom_seed) → InMemoryIndex:
  key_to_offset = {}
  bloom_key_hashes = []
  asset_to_pool_id = new AssetPoolIdMap
  counters = new BucketEntryCounters
  type_ranges = {}
  current_type = nil
  type_start_offset = 0

  for (entry, offset) in entries_iter:
    counters.record_entry(entry)

    key = entry.key()
    if key is nil: continue

    entry_type = type_of(key)

    "Track type ranges"
    if current_type != entry_type:
      if current_type is not nil:
        type_ranges[current_type] = (type_start_offset, offset)
      current_type = entry_type
      type_start_offset = offset

    key_bytes = key.to_xdr()
    key_to_offset[key_bytes] = offset
    bloom_key_hashes.append(bloom_hash(key, bloom_seed))

    "Extract pool mappings from liquidity pool entries"
    if entry is Live or Init:
      if entry.data is LiquidityPool(pool):
        asset_to_pool_id.add_pool(
          pool.id, pool.asset_a, pool.asset_b)

  "Close final type range"
  if current_type is not nil:
    type_ranges[current_type] = (type_start_offset, MAX_U64)

  "Build bloom filter"
  if len(bloom_key_hashes) >= 2:
    bloom_filter = BucketBloomFilter.from_hashes(
      bloom_key_hashes, bloom_seed)

  → InMemoryIndex { ... }
```

**Calls**: [record_entry](#record_entry) | [add_pool](#add_pool) | [BucketBloomFilter::from_hashes](bloom_filter.pc.md#from_hashes)

### InMemoryIndex::get_offset

```
FUNCTION get_offset(key) → u64 or nil:
  "Check bloom filter first"
  if bloom_filter is not nil:
    if not bloom_filter.may_contain(key, bloom_seed):
      → nil

  key_bytes = key.to_xdr()
  → key_to_offset.lookup(key_bytes)
```

---

### Data: DiskIndex

"Page-based range index for large buckets."
"Pages split at byte-offset boundaries matching stellar-core DiskIndex."

```
STRUCT DiskIndex:
  page_size        : u64
  pages            : list<(RangeEntry, u64)>   // (range, page_start_offset)
  bloom_filter     : BucketBloomFilter or nil
  bloom_seed       : 16 bytes
  asset_to_pool_id : AssetPoolIdMap
  counters         : BucketEntryCounters
  type_ranges      : map<LedgerEntryType, TypeRange>
```

### DiskIndex::from_entries

"Pages built by byte offset — new page starts when entry's file offset"
"crosses the next page_size-aligned boundary."

```
FUNCTION from_entries(entries_iter, bloom_seed, page_size) → DiskIndex:
  pages = []
  bloom_key_hashes = []
  asset_to_pool_id = new AssetPoolIdMap
  counters = new BucketEntryCounters
  type_ranges = {}
  current_type = nil
  type_start_offset = 0
  page_upper_bound = 0
  is_first_entry = true

  for (entry, offset) in entries_iter:
    counters.record_entry(entry)

    key = entry.key()
    if key is nil: continue

    entry_type = type_of(key)

    "Track type ranges (same as InMemoryIndex)"
    if current_type != entry_type:
      if current_type is not nil:
        type_ranges[current_type] = (type_start_offset, offset)
      current_type = entry_type
      type_start_offset = offset

    bloom_key_hashes.append(bloom_hash(key, bloom_seed))

    "Page handling: new page when offset crosses boundary"
    if is_first_entry or offset >= page_upper_bound:
      "Align to page boundary and advance"
      page_upper_bound = (offset & ~(page_size-1)) + page_size
      pages.append((RangeEntry(key, key), offset))
      is_first_entry = false
    else:
      "Extend current page upper bound"
      pages.last().range.upper_bound = key

    "Extract pool mappings (same as InMemoryIndex)"
    if entry is Live or Init:
      if entry.data is LiquidityPool(pool):
        asset_to_pool_id.add_pool(
          pool.id, pool.asset_a, pool.asset_b)

  "Close final type range"
  if current_type is not nil:
    type_ranges[current_type] = (type_start_offset, MAX_U64)

  "Build bloom filter"
  if len(bloom_key_hashes) >= 2:
    bloom_filter = BucketBloomFilter.from_hashes(
      bloom_key_hashes, bloom_seed)

  → DiskIndex { page_size, pages, bloom_filter, ... }
```

**Calls**: [record_entry](#record_entry) | [add_pool](#add_pool) | [BucketBloomFilter::from_hashes](bloom_filter.pc.md#from_hashes)

### DiskIndex::find_page_for_key

```
FUNCTION find_page_for_key(key) → u64 or nil:
  "Check bloom filter first"
  if bloom_filter is not nil:
    if not bloom_filter.may_contain(key, bloom_seed):
      → nil

  "Binary search for the page containing the key"
  idx = binary_search(pages, where
    page.range.upper_bound < key)

  if idx < len(pages) and pages[idx].range.contains(key):
    → pages[idx].offset
  → nil
```

**Calls**: [RangeEntry::contains](#rangeentrycontains)

### DiskIndex::from_persisted

```
FUNCTION from_persisted(page_size, pages, bloom_seed,
    counters, type_ranges, bloom_filter,
    asset_to_pool_id) → DiskIndex:
  → DiskIndex {
    page_size, pages, bloom_seed,
    bloom_filter, counters, type_ranges,
    asset_to_pool_id or default
  }
```

---

### Data: LiveBucketIndex (Facade)

"Hybrid index that auto-selects InMemory or Disk based on bucket size."

```
ENUM LiveBucketIndex:
  InMemory(InMemoryIndex)
  Disk(DiskIndex)
```

### LiveBucketIndex::from_entries

```
FUNCTION from_entries(entries, bloom_seed, file_size, config)
    → LiveBucketIndex:
  if file_size < config.index_cutoff_bytes():
    → InMemory(InMemoryIndex.from_entries(entries, bloom_seed))
  else:
    → Disk(DiskIndex.from_entries(
        entries, bloom_seed, config.page_size_bytes()))
```

**Calls**: [InMemoryIndex::from_entries](#inmemoryindexfrom_entries) | [DiskIndex::from_entries](#diskindexfrom_entries)

### LiveBucketIndex::type_not_supported

"Matches stellar-core LiveBucketIndex::typeNotSupported(OFFER)."

```
FUNCTION type_not_supported(entry_type) → bool:
  → entry_type == Offer
```

### get_pool_share_trustline_keys

```
FUNCTION get_pool_share_trustline_keys(account_id, asset)
    → list<LedgerKey>:
  pools = get_pools_for_asset(asset)

  → for each pool_id in pools:
      LedgerKey::Trustline {
        account_id,
        asset: PoolShare(pool_id)
      }
```

**Calls**: [get_pools_for_asset](#get_pools_for_asset)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 1013   | 230        |
| Functions     | 35     | 18         |
