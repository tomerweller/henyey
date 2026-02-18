## Pseudocode: crates/bucket/src/merge_map.rs

"Merge deduplication for bucket merging."
"Merges are identified by their MergeKey (curr_hash, snap_hash, keep_tombstones)."
"When a merge is requested, check if already in progress; if so, reattach."

### Data: BucketMergeMap

```
STRUCT BucketMergeMap:
  merge_key_to_output   : map<MergeKey, Hash256>
  input_to_output       : map<Hash256, set<Hash256>>
  output_to_merge_key   : map<Hash256, list<MergeKey>>
```

### record_merge

```
FUNCTION record_merge(merge_key, output_hash):
  merge_key_to_output[merge_key] = output_hash

  "Record input -> output mappings"
  input_to_output[merge_key.curr_hash].add(output_hash)
  input_to_output[merge_key.snap_hash].add(output_hash)

  "Record output -> merge key mapping"
  output_to_merge_key[output_hash].append(merge_key)
```

### get_output

```
FUNCTION get_output(merge_key) → Hash256 or nil:
  → merge_key_to_output.lookup(merge_key)
```

### has_output

```
FUNCTION has_output(merge_key) → bool:
  → merge_key_to_output.contains(merge_key)
```

### get_outputs_for_input

```
FUNCTION get_outputs_for_input(input_hash) → set<Hash256> or nil:
  → input_to_output.lookup(input_hash)
```

### remove_merge

```
FUNCTION remove_merge(merge_key):
  output_hash = merge_key_to_output.remove(merge_key)
  GUARD output_hash is nil → return

  "Remove from input mappings"
  for input_hash in [merge_key.curr_hash, merge_key.snap_hash]:
    outputs = input_to_output[input_hash]
    outputs.remove(output_hash)
    if outputs is empty:
      input_to_output.remove(input_hash)

  "Remove from output mapping"
  keys = output_to_merge_key[output_hash]
  keys.remove_where(k == merge_key)
  if keys is empty:
    output_to_merge_key.remove(output_hash)
```

**Calls**: [remove_merge](#remove_merge)

### retain_outputs

```
FUNCTION retain_outputs(keep_set):
  "Remove all merge records for outputs not in keep_set"
  keys_to_remove = []
  for (key, output) in merge_key_to_output:
    if output not in keep_set:
      keys_to_remove.append(key)

  for key in keys_to_remove:
    remove_merge(key)
```

**Calls**: [remove_merge](#remove_merge)

### forget_all_merges_producing

"Rust equivalent of stellar-core forgetAllMergesProducing"

```
FUNCTION forget_all_merges_producing(output_hash) → set<MergeKey>:
  keys_to_remove = output_to_merge_key[output_hash] or []
  removed = empty set

  for key in keys_to_remove:
    if merge_key_to_output[key] == output_hash:
      remove_merge(key)
      removed.add(key)

  → removed
```

**Calls**: [remove_merge](#remove_merge)

### clear

```
FUNCTION clear():
  merge_key_to_output.clear()
  input_to_output.clear()
  output_to_merge_key.clear()
```

---

### Data: LiveMergeFutures

"Tracks in-progress merge operations for reattachment."

```
STRUCT LiveMergeFutures:
  futures : map<MergeKey, shared<FutureBucket>>    // concurrent read/write
  stats   : MergeFuturesStats                      // concurrent read/write

STRUCT MergeFuturesStats:
  merges_started    : u64
  merges_reattached : u64
  merges_completed  : u64
```

### LiveMergeFutures::get

```
FUNCTION get(merge_key) → shared<FutureBucket> or nil:
  if futures.contains(merge_key):
    MUTATE stats merges_reattached += 1
    → futures[merge_key]
  → nil
```

### LiveMergeFutures::get_or_insert

```
FUNCTION get_or_insert(merge_key, future) → shared<FutureBucket>:
  "If already exists, reattach"
  if futures.contains(merge_key):
    MUTATE stats merges_reattached += 1
    → futures[merge_key]

  "Insert new"
  wrapped = shared(future)
  futures[merge_key] = wrapped
  MUTATE stats merges_started += 1
  → wrapped
```

### LiveMergeFutures::remove

```
FUNCTION remove(merge_key) → shared<FutureBucket> or nil:
  future = futures.remove(merge_key)
  if future is not nil:
    MUTATE stats merges_completed += 1
  → future
```

### LiveMergeFutures::cleanup_completed

```
FUNCTION cleanup_completed():
  keys_to_remove = []
  for (key, future) in futures:
    if future.merge_complete():
      keys_to_remove.append(key)

  for key in keys_to_remove:
    futures.remove(key)
    MUTATE stats merges_completed += 1
```

**Calls**: [FutureBucket::merge_complete](future_bucket.pc.md#merge_complete)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 192    | 110        |
| Functions     | 15     | 12         |
