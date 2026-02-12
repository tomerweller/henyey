# henyey

Main binary crate -- a pure Rust implementation of Stellar Core's CLI and node entry point.

## Overview

This crate is the primary executable for henyey, providing a command-line interface that wraps
the `henyey-app` library crate. It handles argument parsing (via `clap`), configuration loading,
logging initialization, and command dispatch. The actual node implementation, catchup logic,
consensus, and subsystem coordination are handled by the underlying library crates (`henyey-app`,
`henyey-ledger`, `henyey-overlay`, `henyey-herder`, etc.).

The crate corresponds to stellar-core's `main.cpp` entry point and its collection of CLI
subcommands.

## Architecture

```mermaid
graph TD
    CLI["CLI (clap)"] --> Config["Config Loading"]
    Config --> Dispatch["Command Dispatch"]
    Dispatch --> Run["run: start node"]
    Dispatch --> Catchup["catchup: sync from archives"]
    Dispatch --> Offline["offline: XDR tools, verify-execution, self-check"]
    Dispatch --> Admin["admin: new-db, new-keypair, info, sample-config"]
    Dispatch --> History["history: verify-history, publish-history"]
    Dispatch --> Quorum["check-quorum-intersection"]
    Dispatch --> HttpCmd["http-command"]
    Run --> App["henyey-app"]
    Catchup --> App
    Offline --> Ledger["henyey-ledger"]
    Offline --> Bucket["henyey-bucket"]
    Offline --> HistoryLib["henyey-history"]
    Quorum --> SCP["henyey-scp"]
```

## Key Types

| Type | Description |
|------|-------------|
| `Cli` | Top-level clap argument struct with global options (config, verbose, network) |
| `Commands` | Enum of all CLI subcommands (Run, Catchup, NewDb, Offline, etc.) |
| `OfflineCommands` | Enum of offline subcommands (ConvertKey, DecodeXdr, VerifyExecution, etc.) |
| `CliLogFormat` | Log format selection enum (Text, Json) |
| `VerifyExecutionOptions` | Options struct for the verify-execution command |
| `CommandArchiveTarget` | Configuration for publishing to remote archives via shell commands |

## Usage

### Running a node

```rust
// From the command line:
// henyey --testnet run
// henyey --testnet run --validator
// henyey --testnet run --watcher

// Internally, the CLI dispatches to henyey_app::run_node:
let options = RunOptions {
    mode: RunMode::Validator,
    force_catchup: false,
    ..Default::default()
};
run_node(config, options).await?;
```

### Catching up from history archives

```rust
// henyey --testnet catchup current --mode complete --parallelism 16

let options = CatchupOptions {
    target: "current".to_string(),
    mode: CatchupModeInternal::Complete,
    verify: true,
    parallelism: 16,
    keep_temp: false,
};
let result = run_catchup(config, options).await?;
```

### Offline verification against CDP

```rust
// henyey --testnet offline verify-execution --from 310000 --to 311000 --stop-on-error

// This restores bucket list state from a checkpoint, then re-executes
// transactions via close_ledger and compares results against CDP metadata.
// Differences indicate execution divergence from stellar-core.
```

## Module Layout

| Module | Description |
|--------|-------------|
| `main.rs` | CLI entry point, argument parsing, configuration loading, and all command handlers |
| `quorum_intersection.rs` | Quorum intersection analysis -- loads a JSON network config and checks that all quorums overlap |
| `bin/header_compare.rs` | Separate binary for comparing ledger headers between a local database and a history archive |

## Design Notes

- **Single-file command handlers**: All command implementations live in `main.rs` rather than
  being split across modules. This keeps the crate simple since it is a thin CLI wrapper, though
  `cmd_verify_execution` and `cmd_publish_history` are notably large functions (~950 and ~380
  lines respectively).

- **Temporary directory lifetime management**: The `cmd_verify_execution` function uses
  `Option<tempfile::TempDir>` holders to keep temporary directories alive for the duration of
  execution when caching is disabled. The TempDir is dropped (and cleaned up) when the function
  returns.

- **Quorum intersection algorithm**: The `quorum_intersection` module uses a brute-force O(2^n)
  algorithm that enumerates all node subsets. It is capped at 20 nodes to prevent runaway
  computation. stellar-core also has a SAT-solver-based v2 algorithm which is not yet implemented.

- **CDP integration**: The `verify-execution` and `debug-bucket-entry` offline commands use CDP
  (Crypto Data Platform) as ground truth for comparing transaction execution results. This is
  unique to the Rust implementation and is the primary tool for parity testing.

## stellar-core Mapping

| Rust | stellar-core |
|------|--------------|
| `main.rs` (CLI + dispatch) | `src/main/main.cpp`, `src/main/CommandLine.cpp` |
| `main.rs` (`cmd_run`) | `src/main/ApplicationUtils.cpp` (`runWithConfig`) |
| `main.rs` (`cmd_catchup`) | `src/main/ApplicationUtils.cpp` (`catchup`) |
| `main.rs` (`cmd_publish_history`) | `src/main/ApplicationUtils.cpp` (`publish`) |
| `main.rs` (`cmd_verify_history`) | `src/main/ApplicationUtils.cpp` (`verifyHistory`) |
| `main.rs` (`cmd_self_check`) | `src/main/ApplicationUtils.cpp` (`selfCheck`) |
| `main.rs` (`convert_key`) | `src/main/CommandLine.cpp` (`convertId`) |
| `main.rs` (`sign_transaction`) | `src/main/CommandLine.cpp` (`signTransaction`) |
| `main.rs` (`sec_to_pub`) | `src/main/CommandLine.cpp` (`secToPub`) |
| `main.rs` (`cmd_dump_ledger`) | `src/main/CommandLine.cpp` (`dumpLedger`) |
| `main.rs` (`cmd_http_command`) | `src/main/CommandLine.cpp` (`httpCommand`) |
| `quorum_intersection.rs` | `src/herder/QuorumIntersectionChecker*` (v1 brute-force only) |
| `bin/header_compare.rs` | No direct upstream equivalent (debugging tool) |

## Parity Status

See [PARITY_STATUS.md](PARITY_STATUS.md) for detailed stellar-core parity analysis.
