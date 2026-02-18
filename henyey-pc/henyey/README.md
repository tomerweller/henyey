# henyey

The main binary crate for rs-stellar-core. Provides the CLI entry point that parses arguments, loads configuration, and dispatches to subcommands covering node operation, history archive interaction, offline verification, and debugging utilities.

## Key Files

- [main.pc.md](main.pc.md) -- CLI entry point: argument parsing, config loading, and subcommand dispatch
- [quorum_intersection.pc.md](quorum_intersection.pc.md) -- Quorum intersection analysis verifying all quorums share at least one common node
- [bin/header_compare.pc.md](bin/header_compare.pc.md) -- Debugging utility comparing ledger headers between local DB and history archive

## Architecture

The `main` module defines the top-level CLI with subcommands for running a node, catching up, publishing history, verifying checkpoints, and various debugging tools. `quorum_intersection` implements an exponential brute-force algorithm for verifying quorum intersection on small networks. `bin/header_compare` is a standalone binary for diagnosing ledger hash mismatches by comparing local database headers against history archive data.

## All Files

| File | Description |
|------|-------------|
| [bin/header_compare.pc.md](bin/header_compare.pc.md) | Compares ledger headers between a local database and a history archive |
| [main.pc.md](main.pc.md) | CLI entry point with subcommands for node operation and debugging |
| [quorum_intersection.pc.md](quorum_intersection.pc.md) | Brute-force quorum intersection checker for small SCP networks |
