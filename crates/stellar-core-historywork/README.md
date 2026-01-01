# stellar-core-historywork

History work items that drive catchup and publish workflows.

## Scope

- Download work: HAS, buckets, headers, transactions, results, and SCP history.
- Verification hooks for bucket and tx-result hashes.
- Publish scaffolding for HAS, buckets, headers, transactions, results, and SCP history.
- Progress tracking via shared state (`get_progress`).

## Status

Partial parity with upstream `src/historywork/*`. Metrics export wiring and
full history replay integration remain.

## Usage

Use `HistoryWorkBuilder` to register download work with a
`WorkScheduler`. For publish flows, use `register_publish()` with an
`ArchiveWriter` implementation (e.g., `LocalArchiveWriter`).

See tests in `crates/stellar-core-historywork/tests/` for examples.
