## Pseudocode: crates/app/src/maintainer.rs

"Database maintenance scheduler for rs-stellar-core."
"Periodically cleans up old data from the database to prevent unbounded growth."

### Constants

```
CONST DEFAULT_MAINTENANCE_PERIOD = 4 hours
CONST DEFAULT_MAINTENANCE_COUNT  = 50000   // max entries to delete per cycle
CONST CHECKPOINT_FREQUENCY       = 64      // ledgers per checkpoint
```

### MaintenanceConfig

```
fields:
  period   — how often to run maintenance
  count    — max entries to delete per cycle
  enabled  — whether maintenance is on
```

### new

```
constructor(database, shutdown_rx, get_ledger_bounds):
  → Maintainer with default config and provided deps
```

### with_config

```
constructor(database, config, shutdown_rx, get_ledger_bounds):
  → Maintainer with custom config
```

### start

"Runs until a shutdown signal is received."

```
GUARD not config.enabled              → return
GUARD period is zero OR count is 0    → return

"Check if we can keep up with ledger production"
ledgers_per_period = period_seconds / 5
if count <= ledgers_per_period:
  warn "maintenance may not keep up"

set interval timer with config.period (skip missed ticks)

loop:
  select:
    on interval tick:
      perform_maintenance()
    on shutdown signal:
      break
```

**Calls**: [perform_maintenance](#perform_maintenance)

### perform_maintenance

```
(lcl, min_queued) = get_ledger_bounds()

"Calculate the minimum ledger we need to keep"
"We need to keep enough history to support checkpoint publishing"
qmin = min(min_queued or lcl, lcl)
lmin = qmin - CHECKPOINT_FREQUENCY  // clamped at 0

delete_old_scp_entries(lmin, count)       REF: Database::delete_old_scp_entries
delete_old_ledger_headers(lmin, count)    REF: Database::delete_old_ledger_headers

if elapsed > 2 seconds:
  warn "maintenance took too long; consider increasing count"
```

### perform_maintenance_with_count

```
(lcl, min_queued) = get_ledger_bounds()
qmin = min(min_queued or lcl, lcl)
lmin = qmin - CHECKPOINT_FREQUENCY  // clamped at 0

delete_old_scp_entries(lmin, count)       REF: Database::delete_old_scp_entries
delete_old_ledger_headers(lmin, count)    REF: Database::delete_old_ledger_headers
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 185    | 42         |
| Functions     | 5      | 5          |
