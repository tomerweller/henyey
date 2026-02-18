## Pseudocode: crates/app/src/logging.rs

### Constants

```
CONST LOG_PARTITIONS = [
  ("Fs",        "stellar_core"),
  ("SCP",       "henyey_scp"),
  ("Bucket",    "henyey_bucket"),
  ("Database",  "henyey_db"),
  ("History",   "henyey_history"),
  ("Process",   "henyey_app"),
  ("Ledger",    "henyey_ledger"),
  ("Overlay",   "henyey_overlay"),
  ("Herder",    "henyey_herder"),
  ("Tx",        "henyey_tx"),
  ("LoadGen",   "henyey_app::loadgen"),
  ("Work",      "henyey_work"),
  ("Invariant", "henyey_invariant"),
  ("Perf",      "henyey_app::perf"),
]
```

### Data: LogConfig

```
LogConfig:
  level: Level            // TRACE | DEBUG | INFO | WARN | ERROR
  format: LogFormat       // Text | Json
  ansi_colors: boolean
  with_source_location: boolean
  with_thread_ids: boolean

DEFAULTS:
  level = INFO
  format = Text
  ansi_colors = true
  with_source_location = false
  with_thread_ids = false
```

### Data: LogLevelHandle

```
LogLevelHandle:
  handle: ReloadHandle    // for dynamically swapping the filter
  levels: map<string, string>   // partition name -> level
  global_level: string
```

### init_with_handle

```
function init_with_handle(config):
  env_filter = try_from_env() or build_filter(config.level)
    NOTE: always suppress noisy crates: hyper=warn, reqwest=warn, h2=warn

  initial_level = lowercase(config.level)

  if config.format == Text:
    fmt_layer = text_formatter(
      ansi=config.ansi_colors,
      target=true,
      thread_ids=config.with_thread_ids,
      file=config.with_source_location,
      line_number=config.with_source_location)
  else:  // Json
    fmt_layer = json_formatter(span_list=true, current_span=true)

  (filter, reload_handle) = create_reloadable_layer(env_filter)
  install_global_subscriber(filter, fmt_layer)

  -> LogLevelHandle(reload_handle, initial_level)
```

### LogLevelHandle::set_level

```
function set_level(level_str):
  level = normalize_level(level_str)
  filter = build_filter(level, no_override)
  reload(filter)
  global_level = level
  for each (partition, _) in LOG_PARTITIONS:
    levels[partition] = level
```

### LogLevelHandle::set_partition_level

```
function set_partition_level(partition, level_str):
  level = normalize_level(level_str)
  target = partition_to_target(partition)
  GUARD target is unknown           -> error("Unknown partition")

  levels[partition] = level
  filter = build_filter_with_partitions()
  reload(filter)
```

### Helper: build_filter_with_partitions

```
function build_filter_with_partitions():
  filter = new EnvFilter(global_level)
  add directives: hyper=warn, reqwest=warn, h2=warn

  for each (partition, level) in levels:
    if level != global_level:
      target = partition_to_target(partition)
      if target exists:
        add directive: "{target}={level}"

  -> filter
```

### Helper: normalize_level

```
function normalize_level(level_str):
  canonical = uppercase(level_str)
  if canonical in ["TRACE","DEBUG","INFO","WARN","WARNING","ERROR"]:
    -> lowercase(canonical)
    NOTE: "WARNING" normalizes to "warn"
  else:
    -> error("Invalid log level")
```

### Helper: partition_to_target

```
function partition_to_target(partition):
  for each (name, target) in LOG_PARTITIONS:
    if case_insensitive_equal(name, partition):
      -> target
  -> null
```

---

### Data: ProgressTracker

```
ProgressTracker:
  name: string
  total: optional<u64>
  processed: atomic<u64>
  start_time: Instant
  last_report: mutex<Instant>
  report_interval: Duration     // default 5 seconds
  completed: atomic<boolean>
```

### ProgressTracker::inc_by

```
function inc_by(n):
  processed = atomic_add(self.processed, n) + n
  maybe_report(processed)
```

### ProgressTracker::maybe_report

```
function maybe_report(processed):
  lock last_report
  if time_since(last_report) >= report_interval:
    last_report = now
    unlock

    elapsed = time_since(start_time)
    rate = processed / elapsed_seconds

    if total is known:
      percent = (processed / total) * 100
      eta = (total - processed) / rate
      log: name, processed, total, percent, rate, eta
    else:
      log: name, processed, rate
```

### ProgressTracker::complete

```
function complete():
  completed = true
  elapsed = time_since(start_time)
  processed = load(self.processed)
  log: name, processed, total (if known), elapsed
```

---

### STATE_MACHINE: CatchupPhase

```
STATE_MACHINE: CatchupPhase
  STATES: [Initializing, DownloadingState, DownloadingBuckets,
           ApplyingBuckets, DownloadingLedgers, ReplayingLedgers,
           Verifying, Complete]
  TRANSITIONS:
    Initializing     -> DownloadingState
    DownloadingState -> DownloadingBuckets
    DownloadingBuckets -> ApplyingBuckets
    ApplyingBuckets  -> DownloadingLedgers
    DownloadingLedgers -> ReplayingLedgers
    ReplayingLedgers -> Verifying
    Verifying        -> Complete
```

### Data: CatchupProgress

```
CatchupProgress:
  phase: mutex<CatchupPhase>
  ledgers_downloaded: atomic<u32>
  ledgers_applied: atomic<u32>
  buckets_downloaded: atomic<u32>
  total_buckets: atomic<u32>
  target_ledger: atomic<u32>
  start_time: Instant
```

### CatchupProgress::ledger_applied

```
function ledger_applied():
  applied = atomic_add(ledgers_applied, 1) + 1
  if applied % 100 == 0:
    log: applied, target_ledger
```

### CatchupProgress::bucket_downloaded

```
function bucket_downloaded():
  downloaded = atomic_add(buckets_downloaded, 1) + 1
  total = load(total_buckets)
  if total > 0 and (downloaded % 10 == 0 or downloaded == total):
    log: downloaded, total, percent
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~692   | ~140       |
| Functions     | 22     | 14         |
