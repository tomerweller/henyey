# stellar-core-app

Application orchestration layer for rs-stellar-core.

## Overview

This crate wires together overlay, herder, ledger, history, and configuration. It hosts the main application state machine, CLI-facing operations (run/catchup), logging setup, and HTTP status endpoints.

## Architecture

- `App` owns long-lived subsystem handles (overlay, herder, ledger, history, db).
- `run_cmd` drives the live event loop and exposes status via HTTP.
- `catchup_cmd` orchestrates history downloads and replay verification.
- `config` maps on-disk TOML into validated runtime settings.

## Key Concepts

- **App lifecycle**: create -> start subsystems -> run loop -> graceful shutdown.
- **Catchup target**: computed ledger sequence and mode (minimal/complete).
- **Consensus stuck policy**: timeout-based actions for stalled SCP.

## Upstream Mapping

- `src/main/`, `src/ledger/` orchestration logic
- Command handling and node lifecycle in stellar-core

## Layout

```
crates/stellar-core-app/
├── src/
│   ├── app.rs
│   ├── catchup_cmd.rs
│   ├── config.rs
│   ├── logging.rs
│   ├── run_cmd.rs
│   └── survey.rs
└── tests/
```

## Tests To Port

- Application lifecycle tests
- End-to-end validator readiness runs
