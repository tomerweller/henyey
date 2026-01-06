# stellar-core-db

SQLite persistence layer for rs-stellar-core.

## Overview

This crate provides schema management and query helpers for ledger headers, transactions, SCP history, peers, and operational metadata. SQLite is the only supported backend.

## Architecture

- `schema` defines the SQLite layout and versioning.
- `migrate` handles schema upgrades at startup.
- `queries/*` is the typed access layer used by app, overlay, and ledger.

## Key Concepts

- **Schema versioning**: tracked in the DB and validated on startup.
- **History persistence**: headers, tx sets/results, and SCP envelopes stored for catchup.
- **Peer cache**: outbound/inbound peer records for overlay stability.

## Upstream Mapping

- `src/database/*`
- `src/persist/*`

## Layout

```
crates/stellar-core-db/
├── src/
│   ├── lib.rs
│   ├── migrate.rs
│   ├── schema.rs
│   ├── queries/
│   └── error.rs
└── tests/
```

## Schema Notes

- Ledger headers, tx sets/results, SCP envelopes, and bucket list snapshots are stored for catchup and publish.
- Peer discovery/backoff is persisted for overlay stability.

## Tests To Port

From `src/database/test/`:
- DB migration coverage
- Ledger/header persistence
- Peer list persistence and pruning

## Performance Notes

- Use prepared statements for hot paths.
- Batch writes during ledger close and history publish.
