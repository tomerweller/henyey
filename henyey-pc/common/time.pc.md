# Pseudocode: crates/common/src/time.rs

"Time utilities for Unix/Stellar timestamp conversions."

## Constants

```
CONST STELLAR_EPOCH = 946684800  // Jan 1, 2000 00:00:00 UTC as Unix timestamp
```

### current_timestamp

```
function current_timestamp() -> u64:
  -> seconds since Unix epoch (or 0 if clock before epoch)
```

### current_timestamp_ms

```
function current_timestamp_ms() -> u64:
  -> milliseconds since Unix epoch (or 0 if clock before epoch)
```

### timestamp_to_system_time

```
function timestamp_to_system_time(timestamp) -> SystemTime:
  -> UNIX_EPOCH + timestamp seconds
```

### unix_to_stellar_time

"Stellar timestamps are relative to Jan 1, 2000."

```
function unix_to_stellar_time(unix_ts) -> u64:
  -> saturating_subtract(unix_ts, STELLAR_EPOCH)
```

### stellar_to_unix_time

```
function stellar_to_unix_time(stellar_ts) -> u64:
  -> saturating_add(stellar_ts, STELLAR_EPOCH)
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 16     | 12         |
| Functions     | 5      | 5          |
