## Pseudocode: crates/bucket/src/cache.rs

"Random eviction cache for frequently-accessed account entries."
"Uses 'least-recent-out-of-2-random-choices' eviction strategy,"
"matching stellar-core's approach. Only ACCOUNT entries are cached."

### CacheEntry (internal struct)

```
STRUCT CacheEntry:
  entry: shared BucketEntry
  size_bytes: integer
  access_count: integer
  vec_index: integer  // index into keys vec for O(1) swap-remove
```

### Helper: estimate_size

```
function estimate_size(entry):
  base_size = size_of(BucketEntry)
  data_size =
    if Live or Init:
      estimate_ledger_entry_size(ledger_entry)
    if Dead: 64
    if Metadata: 32
  → base_size + data_size

function estimate_ledger_entry_size(entry):
  Account:          ~200 + num_signers * 72
  Trustline:        150
  Offer:            200
  Data:             100 + data_value.len
  ClaimableBalance: 200 + num_claimants * 100
  LiquidityPool:    300
  ContractData:     500  // conservative
  ContractCode:     100 + code.len
  ConfigSetting:    500
  Ttl:              50
```

### CacheInner (internal struct)

```
STRUCT CacheInner:
  entries: map[LedgerKey → CacheEntry]
  keys: list of LedgerKey  // for O(1) random access
  access_counter: integer
  rng_state: integer       // xorshift64 state
  hits: integer
  misses: integer
```

### Helper: rand_index

```
function rand_index(len):
  "xorshift64 PRNG"
  x = rng_state
  x = x XOR (x << 13)
  x = x XOR (x >> 7)
  x = x XOR (x << 17)
  rng_state = x
  → x mod len
```

### RandomEvictionCache (struct)

```
STRUCT RandomEvictionCache:
  inner: mutex-protected CacheInner
  max_bytes: integer
  max_entries: integer
  current_bytes: atomic integer
  active: atomic integer
```

### with_limits

```
function with_limits(max_bytes, max_entries):
  → RandomEvictionCache(
      inner = CacheInner(
        entries = empty map,
        keys = empty list,
        access_counter = 0,
        rng_state = 0x5EED_CAFE_BABE_D00D,
        hits = 0, misses = 0),
      max_bytes, max_entries,
      current_bytes = 0,
      active = 0)  // not active initially
```

### is_active / activate / deactivate

```
function is_active():  → active != 0
function activate():   active = 1
function deactivate():
  active = 0
  clear()
```

### is_cached_type

"Only ACCOUNT entries are cached, matching stellar-core."

```
function is_cached_type(key):
  → key is Account type
```

### get

```
function get(key):
  GUARD not active or not cached type → nothing
  lock inner
  access_counter += 1
  if key found in entries:
    update entry.access_count = access_counter
    hits += 1
    → entry (shared reference)
  else:
    misses += 1
    → nothing
```

### insert

```
function insert(key, entry):
  GUARD not active or not cached type → return
  lock inner
  access_counter += 1

  "Update existing entry (no eviction needed)"
  if key exists in entries:
    old_size = existing.size_bytes
    replace existing with new CacheEntry
    adjust current_bytes by size difference
    → return

  "New entry — evict if at capacity"
  new_entry = create CacheEntry(entry, access_counter)

  if keys.len >= max_entries
     or current_bytes + entry_size > max_bytes:
    evict_one(inner)

  vec_index = keys.len
  append key to keys
  insert (key → cache_entry) in entries
  current_bytes += entry_size
```

**Calls**: [evict_one](#evict_one)

### remove

```
function remove(key):
  GUARD not active → return
  lock inner
  if key found in entries:
    remove from entries
    current_bytes -= entry.size_bytes
    swap_remove_key(inner, entry.vec_index)
```

**Calls**: [swap_remove_key](#swap_remove_key)

### clear

```
function clear():
  lock inner
  clear entries map
  clear keys list
  hits = 0
  misses = 0
  current_bytes = 0
```

### evict_one

"Least-recent-out-of-2-random-choices, matching stellar-core."
"Picks two random entries, evicts whichever was accessed less recently."
"O(1) and approximates LRU quality."

```
function evict_one(inner):
  GUARD keys is empty → return
  idx1 = rand_index(keys.len)
  idx2 = rand_index(keys.len)
  access1 = entries[keys[idx1]].access_count
  access2 = entries[keys[idx2]].access_count
  victim_idx = idx1 if access1 <= access2 else idx2

  victim_key = keys[victim_idx]
  entry = remove victim_key from entries
  current_bytes -= entry.size_bytes
  swap_remove_key(inner, victim_idx)
```

**Calls**: [rand_index](#rand_index) | [swap_remove_key](#swap_remove_key)

### swap_remove_key

```
function swap_remove_key(inner, idx):
  last_idx = keys.len - 1
  if idx != last_idx:
    swap keys[idx] and keys[last_idx]
    "Update swapped entry's vec_index in hashmap"
    entries[keys[idx]].vec_index = idx
  remove last element from keys
```

### stats

```
function stats():
  lock inner
  → CacheStats(
      entry_count = entries.len,
      size_bytes = current_bytes,
      max_bytes, max_entries,
      hits, misses,
      hit_rate = hits / (hits + misses) or 0.0,
      active = is_active())
```

### CacheStats (struct)

```
STRUCT CacheStats:
  entry_count, size_bytes,
  max_bytes, max_entries,
  hits, misses, hit_rate, active
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 429    | 130        |
| Functions     | 16     | 16         |
