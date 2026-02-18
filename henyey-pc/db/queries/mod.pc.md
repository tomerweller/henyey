# Pseudocode: crates/db/src/queries/mod.rs

Module re-export hub for database query traits organized by domain.

## Submodules

- `ban` — node ban list management
- `bucket_list` — bucket list snapshot storage
- `history` — transaction history and results
- `ledger` — ledger header storage and retrieval
- `peers` — network peer management
- `publish_queue` — history archive publish queue
- `scp` — SCP consensus state persistence
- `state` — generic key-value state storage

## Re-exports

- BanQueries
- BucketListQueries
- HistoryQueries
- LedgerQueries
- PeerQueries, PeerRecord
- PublishQueueQueries
- ScpQueries, ScpStatePersistenceQueries
- StateQueries

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 18     | 18         |
| Functions    | 0      | 0          |
