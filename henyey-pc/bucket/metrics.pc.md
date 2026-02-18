## Pseudocode: crates/bucket/src/metrics.rs

"Metrics and counters for bucket operations."

### Data: MergeCounters

```
STRUCT MergeCounters:                          // all fields atomic
  pre_init_entry_protocol_merges  : u64
  post_init_entry_protocol_merges : u64
  running_merge_reattachments     : u64
  new_meta_entries                : u64
  new_init_entries                : u64
  new_live_entries                : u64
  new_dead_entries                : u64
  old_entries_shadowed            : u64
  entries_annihilated             : u64        // Init+Dead pairs
  merges_completed                : u64
  merge_time_us                   : u64
```

### record_new_entry

```
FUNCTION record_new_entry(entry_type):
  if entry_type == Meta:
    MUTATE self new_meta_entries += 1
  else if entry_type == Init:
    MUTATE self new_init_entries += 1
  else if entry_type == Live:
    MUTATE self new_live_entries += 1
  else if entry_type == Dead:
    MUTATE self new_dead_entries += 1
```

### record_merge_completed

```
FUNCTION record_merge_completed(duration_us):
  MUTATE self merges_completed += 1
  MUTATE self merge_time_us += duration_us
```

### MergeCountersSnapshot::total_new_entries

```
FUNCTION total_new_entries() → u64:
  → new_meta_entries + new_init_entries
    + new_live_entries + new_dead_entries
```

### MergeCountersSnapshot::avg_merge_time_us

```
FUNCTION avg_merge_time_us() → float:
  GUARD merges_completed == 0 → 0.0
  → merge_time_us / merges_completed
```

---

### Data: EvictionCounters

"Counters for eviction scanning operations (Soroban state archival)."

```
STRUCT EvictionCounters:                       // all fields atomic
  entries_evicted              : u64
  temp_entries_evicted         : u64
  persistent_entries_archived  : u64
  bytes_scanned                : u64
  incomplete_bucket_scans      : u64
  scan_cycles_completed        : u64
  scan_time_us                 : u64
```

### record_evicted

```
FUNCTION record_evicted(count, temp_count, persistent_count):
  MUTATE self entries_evicted += count
  MUTATE self temp_entries_evicted += temp_count
  MUTATE self persistent_entries_archived += persistent_count
```

### record_scan_cycle

```
FUNCTION record_scan_cycle(duration_us):
  MUTATE self scan_cycles_completed += 1
  MUTATE self scan_time_us += duration_us
```

### EvictionCountersSnapshot::eviction_rate

```
FUNCTION eviction_rate() → float:
  GUARD scan_cycles_completed == 0 → 0.0
  → entries_evicted / scan_cycles_completed
```

---

### Data: BucketListMetrics

```
STRUCT BucketListMetrics:                      // all fields atomic
  total_entries    : u64
  total_size_bytes : u64
  bucket_count     : u64
  entries_by_level : array[11] of u64
  size_by_level    : array[11] of u64
```

### update_level

```
FUNCTION update_level(level, entry_count, size_bytes):
  GUARD level >= 11 → return
  entries_by_level[level] = entry_count
  size_by_level[level] = size_bytes
```

### recalculate_totals

```
FUNCTION recalculate_totals():
  total_entries = 0
  total_size = 0
  bucket_count = 0

  for level in 0..11:
    entries = entries_by_level[level]
    size = size_by_level[level]
    total_entries += entries
    total_size += size
    if entries > 0:
      bucket_count += 2              // curr and snap buckets

  self.total_entries = total_entries
  self.total_size_bytes = total_size
  self.bucket_count = bucket_count
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 421    | 90         |
| Functions     | 18     | 10         |
