# app

Application orchestration for the Stellar node. This crate contains the central `App` coordinator, its event loop, consensus triggering, catchup logic, peer management, configuration loading, and supporting subsystems like logging, maintenance, metadata streaming, and overlay surveys.

## Key Files

- [app/mod.pc.md](app/mod.pc.md) -- Central App struct, initialization, state management, and herder callbacks
- [app/lifecycle.pc.md](app/lifecycle.pc.md) -- Main event loop: subsystem startup, consensus bootstrap, and shutdown
- [app/consensus.pc.md](app/consensus.pc.md) -- Consensus triggering gate matching stellar-core's triggerNextLedger
- [app/ledger_close.pc.md](app/ledger_close.pc.md) -- Ledger close persistence: serializes headers, tx sets, and metadata
- [app/catchup_impl.pc.md](app/catchup_impl.pc.md) -- Catchup execution with consensus-stuck recovery state machine
- [config.pc.md](config.pc.md) -- Node configuration defaults and TOML loading
- [run_cmd.pc.md](run_cmd.pc.md) -- Run command with Full/Validator/Watcher modes and HTTP status server

## Architecture

The `App` struct (defined in `app/mod.pc.md`) is the central coordinator that owns all subsystems. `lifecycle` drives the main event loop -- initializing overlay, running catchup if needed, bootstrapping consensus, and processing ledger close events. `consensus` gates when to trigger the next SCP round, while `catchup_impl` handles history catchup with a stuck-detection state machine. Peer management (`peers`), transaction flooding (`tx_flooding`), and survey collection (`survey_impl`) handle overlay interactions. Top-level commands (`run_cmd`, `catchup_cmd`) parse CLI options and invoke the App, while `config` loads TOML configuration, `logging` sets up partitioned log output, `maintainer` schedules periodic DB cleanup, and `meta_stream` emits LedgerCloseMeta to external consumers.

## All Files

| File | Description |
|------|-------------|
| [app/catchup_impl.pc.md](app/catchup_impl.pc.md) | Catchup execution with consensus-stuck recovery state machine |
| [app/consensus.pc.md](app/consensus.pc.md) | Consensus triggering gate matching stellar-core's triggerNextLedger |
| [app/ledger_close.pc.md](app/ledger_close.pc.md) | Persists ledger headers, tx sets, results, and metadata to DB |
| [app/lifecycle.pc.md](app/lifecycle.pc.md) | Main event loop: subsystem startup, consensus bootstrap, shutdown |
| [app/mod.pc.md](app/mod.pc.md) | Central App struct with initialization and herder callbacks |
| [app/peers.pc.md](app/peers.pc.md) | Peer connection, disconnection, banning, and snapshot delegation |
| [app/survey_impl.pc.md](app/survey_impl.pc.md) | Survey report generation from collected peer topology data |
| [app/tx_flooding.pc.md](app/tx_flooding.pc.md) | Transaction advertisement queuing and flooding to peers |
| [catchup_cmd.pc.md](catchup_cmd.pc.md) | CLI catchup command with target/mode parsing and options |
| [config.pc.md](config.pc.md) | Node configuration defaults, TOML loading, and validation |
| [lib.pc.md](lib.pc.md) | Crate root with module declarations and re-exports |
| [logging.pc.md](logging.pc.md) | Logging setup with per-subsystem partitions and progress tracking |
| [maintainer.pc.md](maintainer.pc.md) | Periodic database maintenance scheduler for old data cleanup |
| [meta_stream.pc.md](meta_stream.pc.md) | LedgerCloseMeta output stream with debug segment rotation |
| [run_cmd.pc.md](run_cmd.pc.md) | Run command for Full/Validator/Watcher modes with HTTP server |
| [survey.pc.md](survey.pc.md) | Time-sliced overlay network survey with phase state machine |
