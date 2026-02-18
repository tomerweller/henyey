## Pseudocode: crates/herder/src/drift_tracker.rs

"Close time drift tracking for monitoring clock synchronization."
"Corresponds to mDriftCTSlidingWindow in HerderImpl.cpp."

CONST CLOSE_TIME_DRIFT_LEDGER_WINDOW_SIZE = 120  // ~10 min at 5s/ledger
CONST CLOSE_TIME_DRIFT_SECONDS_THRESHOLD  = 10   // seconds
CONST POSSIBLY_BAD_LOCAL_CLOCK = "Your local clock may be out of sync..."

### CloseTimeDriftTracker

```
STRUCT CloseTimeDriftTracker:
  window       "ordered map: ledger_seq → DriftEntry"
  window_size  "max entries in sliding window"
  threshold    "drift threshold in seconds for warnings"

STRUCT DriftEntry:
  local_close_time        "unix timestamp when ledger triggered"
  externalized_close_time "unix timestamp from network (or null)"
```

### new / with_config

```
function new():
  → with_config(120, 10)

function with_config(window_size, threshold):
  window = empty ordered map
  → CloseTimeDriftTracker
```

### record_local_close_time

"Called from trigger_next_ledger before close-time adjustments."

```
function record_local_close_time(ledger_seq, local_close_time):
  GUARD window already has ledger_seq → false

  insert (ledger_seq → {local_close_time, null})

  "Evict oldest entries if window is too large"
  while window.size > window_size:
    remove oldest entry (lowest ledger_seq)

  → true
```

### record_externalized_close_time

"Called from value_externalized when ledger is closed by network."

```
function record_externalized_close_time(ledger_seq,
                                         network_close_time):
  if window has entry for ledger_seq:
    MUTATE entry externalized_close_time = network_close_time

  if window.size >= window_size:
    → check_and_clear_drift()

  → null  // no warning
```

**Calls**: [check_and_clear_drift](#helper-check_and_clear_drift)

### Helper: check_and_clear_drift

"Compute 75th percentile of drift values; warn if exceeds threshold."

```
function check_and_clear_drift():
  drifts = []
  for each entry in window:
    if entry has externalized_close_time:
      "Positive drift = network ahead; negative = local ahead"
      drift = network_time - local_time
      append drift to drifts

  result = null
  if drifts is not empty:
    sort drifts ascending
    p75_index = ceil(count * 0.75) - 1
    p75_index = min(p75_index, count - 1)
    drift_p75 = drifts[p75_index]

    if abs(drift_p75) > threshold:
      result = warning message with drift_p75

  clear window
  → result
```

### get_drift_stats

"Returns statistics without clearing the window."

```
function get_drift_stats():
  drifts = [network - local for each completed entry]
  GUARD drifts is empty → null

  sort drifts
  min    = drifts[0]
  max    = drifts[last]
  median = drifts[count / 2]
  p75    = drifts[ceil(count * 0.75) - 1]

  → DriftStats { min, max, median, p75, sample_count }
```

### Accessors

```
function window_len():        → window.size
function completed_entries():  → count where
                                 externalized_close_time is set
```

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 140    | 55         |
| Functions    | 7      | 7          |
