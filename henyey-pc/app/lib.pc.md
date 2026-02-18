## Pseudocode: crates/app/src/lib.rs

"Application orchestration for rs-stellar-core."

This is the module root — it re-exports public types from sub-modules.
No production logic; purely module declarations and re-exports.

### Module Declarations

```
modules:
  app           — Core application struct, component init
  catchup_cmd   — History catchup command
  config        — Configuration loading/validation
  logging       — Logging setup, progress tracking
  maintainer    — Background DB maintenance scheduler
  meta_stream   — LedgerCloseMeta output stream
  run_cmd       — Node run command, HTTP status server
  survey        — Time-sliced overlay network surveys
```

### Re-exports

```
from app:        App, AppState, CatchupResult,
                 CatchupTarget, SurveyReport
from catchup_cmd: run_catchup, CatchupMode, CatchupOptions
from config:     AppConfig
from logging:    init_with_handle, LogConfig, LogFormat,
                 LogLevelHandle, LOG_PARTITIONS
from maintainer: Maintainer, MaintenanceConfig,
                 DEFAULT_MAINTENANCE_COUNT,
                 DEFAULT_MAINTENANCE_PERIOD
from run_cmd:    run_node, RunMode, RunOptions
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 18     | 22         |
| Functions     | 0      | 0          |
