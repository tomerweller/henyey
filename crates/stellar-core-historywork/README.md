# stellar-core-historywork

History work items that drive catchup and publish workflows.

## Scope

- Download work: HAS, buckets, headers, transactions, results, and SCP history.
- Verification hooks for header chain, bucket, tx-set, and tx-result hashes.
- Publish scaffolding for HAS, buckets, headers, transactions, results, and SCP history.
- Progress tracking via shared state (`get_progress`).

## Architecture

- Work items are registered with `WorkScheduler` as a DAG of dependencies.
- Download tasks populate shared state for HAS, buckets, and checkpoint files.
- Verification tasks validate header chains and hash integrity before replay.
- Publish tasks reuse the same graph, writing to `ArchiveWriter` targets.

## Key Concepts

- **CheckpointData**: in-memory snapshot of downloaded artifacts.
- **ArchiveWriter**: abstraction for publishing checkpoints (local or remote).
- **Progress state**: shared map for reporting status across work items.
- **Work graph phases**: HAS -> buckets -> headers/tx/results/scp -> verify.

## Status

Partial parity with upstream `src/historywork/*`. Metrics export wiring and
full history replay integration remain.

## Usage

Use `HistoryWorkBuilder` to register download work with a
`WorkScheduler`. For publish flows, use `register_publish()` with an
`ArchiveWriter` implementation (e.g., `LocalArchiveWriter`).

To feed catchup with pre-downloaded data, build a `CheckpointData` from the
shared state and pass it to `catchup_to_ledger_with_checkpoint_data`:

```rust
let data = stellar_core_historywork::build_checkpoint_data(&state).await?;
catchup_manager
    .catchup_to_ledger_with_checkpoint_data(target, data)
    .await?;
```

See tests in `crates/stellar-core-historywork/tests/` for examples.
