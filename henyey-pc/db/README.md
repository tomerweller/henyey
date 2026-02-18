# db

SQLite-based persistence layer for rs-stellar-core. This crate provides connection pool management, schema creation and migration, and domain-specific query traits for ledger headers, transaction history, SCP consensus state, bucket list snapshots, peer records, publish queue, ban list, and key-value state storage.

## Key Files

- [lib.pc.md](lib.pc.md) -- Database initialization with connection pool and schema setup
- [schema.pc.md](schema.pc.md) -- Complete SQL schema definitions and well-known state keys
- [queries/ledger.pc.md](queries/ledger.pc.md) -- Ledger header storage, retrieval, and range queries
- [queries/scp.pc.md](queries/scp.pc.md) -- SCP envelope, quorum set, and slot state persistence
- [queries/history.pc.md](queries/history.pc.md) -- Transaction history, tx set, and tx result storage
- [scp_persistence.pc.md](scp_persistence.pc.md) -- SQLite-backed SCP state persistence for crash recovery
- [migrations.pc.md](migrations.pc.md) -- Sequential schema migrations with atomic transactions

## Architecture

The `Database` type (defined in `lib` and `pool`) wraps an r2d2 connection pool over SQLite, providing thread-safe concurrent access. On first open, `schema` creates the full table set, then `migrations` applies incremental schema changes up to the current version. All domain-specific data access is organized as query traits in the `queries` module: `ledger` for ledger headers, `history` for transactions/tx sets/results, `scp` for consensus envelopes and quorum sets, `bucket_list` for checkpoint bucket hashes, `peers` for network peer tracking, `publish_queue` for history archive publication, `ban` for excluded nodes, and `state` for generic key-value persistence. `scp_persistence` wraps the SCP query traits into a higher-level interface for crash recovery.

## All Files

| File | Description |
|------|-------------|
| [error.pc.md](error.pc.md) | Database error types: Sqlite, Pool, Io, Xdr, Integrity, Migration |
| [lib.pc.md](lib.pc.md) | Database initialization with connection pool and schema setup |
| [migrations.pc.md](migrations.pc.md) | Sequential schema migrations (v1-v5) with atomic transactions |
| [pool.pc.md](pool.pc.md) | Connection pool wrapper with transaction support |
| [queries/ban.pc.md](queries/ban.pc.md) | Node ban list management: add, remove, check, list |
| [queries/bucket_list.pc.md](queries/bucket_list.pc.md) | Bucket list snapshot storage and retrieval at checkpoint ledgers |
| [queries/history.pc.md](queries/history.pc.md) | Transaction history, tx set, and tx result storage and retrieval |
| [queries/ledger.pc.md](queries/ledger.pc.md) | Ledger header storage, retrieval, and range queries |
| [queries/mod.pc.md](queries/mod.pc.md) | Query module re-export hub organized by domain |
| [queries/peers.pc.md](queries/peers.pc.md) | Network peer tracking with connection state and retry logic |
| [queries/publish_queue.pc.md](queries/publish_queue.pc.md) | History archive publish queue: enqueue, dequeue, list pending |
| [queries/scp.pc.md](queries/scp.pc.md) | SCP envelope, quorum set, and slot state persistence |
| [queries/state.pc.md](queries/state.pc.md) | Generic key-value state storage for node config and runtime state |
| [schema.pc.md](schema.pc.md) | Complete SQL schema definitions for all tables and indexes |
| [scp_persistence.pc.md](scp_persistence.pc.md) | SQLite-backed SCP state persistence for crash recovery |
