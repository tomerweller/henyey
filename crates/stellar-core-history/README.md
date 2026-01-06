# stellar-core-history

History archive access, catchup, replay, and publish support.

## Overview

This crate reads and writes history archives (HAS, buckets, ledger headers, transaction sets/results, and SCP history). It powers catchup and replay verification for validators.

## Architecture

- `archive` and `paths` map archive URLs and on-disk layout.
- `catchup` orchestrates checkpoint selection and replay sequencing.
- `replay` re-executes transactions and verifies hashes.
- `publish` writes new archive checkpoints when enabled.

## Key Concepts

- **Checkpoint**: 64-ledger boundary for archive snapshots.
- **HAS**: history archive state file with bucket list and ledger chain.
- **Record-marked XDR**: stream format used by history files.

## Upstream Mapping

- `src/history/*`
- `src/catchup/*`

## Layout

```
crates/stellar-core-history/
├── src/
│   ├── archive.rs
│   ├── catchup.rs
│   ├── checkpoint.rs
│   ├── publish.rs
│   ├── replay.rs
│   ├── verify.rs
│   └── error.rs
└── tests/
```

## Archive Structure

History archives are organized by checkpoint (64-ledger cadence), with buckets stored under `bucket/` and ledger/tx/SCP files stored under `ledger/`, `transactions/`, `results/`, and `scp/`.

## Tests To Port

From `src/history/test/`:
- HAS parsing and integrity checks.
- Replay verification of tx set/result hashes.
- Publish validation for archive layout.
