# stellar-core-db

SQLite persistence layer for rs-stellar-core.

## Overview

This crate provides database abstraction for the Stellar blockchain node, handling persistent storage of:

- **Ledger headers**: Block metadata including sequence numbers, hashes, and timestamps
- **Transaction history**: Transaction bodies, results, and execution metadata
- **SCP state**: Stellar Consensus Protocol envelopes and quorum sets
- **Bucket list snapshots**: Merkle tree state at checkpoint ledgers
- **Peer records**: Network peer discovery and connection tracking
- **Operational state**: Node configuration and runtime state

## Architecture

The crate is organized into the following modules:

```
crates/stellar-core-db/
├── src/
│   ├── lib.rs              # Main entry point and Database methods
│   ├── error.rs            # Error types (DbError)
│   ├── pool.rs             # Connection pool (Database struct)
│   ├── schema.rs           # SQL schema definitions
│   ├── migrations.rs       # Schema versioning and migrations
│   ├── scp_persistence.rs  # SCP state persistence (SqliteScpPersistence)
│   └── queries/            # Typed query traits
│       ├── mod.rs
│       ├── ban.rs          # Node ban list
│       ├── bucket_list.rs  # Bucket list snapshots
│       ├── history.rs      # Transaction history
│       ├── ledger.rs       # Ledger headers
│       ├── peers.rs        # Peer management
│       ├── publish_queue.rs # History publishing queue
│       ├── scp.rs          # SCP consensus state
│       └── state.rs        # Key-value state storage
└── README.md
```

## Key Types

| Type | Description |
|------|-------------|
| `Database` | Connection pool with high-level query methods |
| `DbError` | Unified error type for all database operations |
| `PooledConnection` | A connection borrowed from the pool |
| `PeerRecord` | Network peer connection metadata |
| `SqliteScpPersistence` | SCP state persistence backed by SQLite |

### Query Traits

Query functionality is organized into domain-specific traits:

| Trait | Purpose |
|-------|---------|
| `LedgerQueries` | Ledger header storage and retrieval |
| `HistoryQueries` | Transaction history and results |
| `ScpQueries` | SCP envelopes and quorum sets |
| `ScpStatePersistenceQueries` | SCP slot state and tx set persistence for crash recovery |
| `StateQueries` | Key-value state storage |
| `PeerQueries` | Network peer tracking |
| `BucketListQueries` | Bucket list snapshots |
| `PublishQueueQueries` | History archive publish queue |
| `BanQueries` | Node ban list management |

## Usage

### Opening a Database

```rust
use stellar_core_db::Database;

// Open a persistent database (creates if it doesn't exist)
let db = Database::open("path/to/stellar.db")?;

// Or use an in-memory database for testing
let test_db = Database::open_in_memory()?;
```

### Querying Data

The `Database` type provides convenience methods for common operations:

```rust
// Get the latest ledger
if let Some(seq) = db.get_latest_ledger_seq()? {
    println!("Latest ledger: {}", seq);
}

// Get a specific ledger header
if let Some(header) = db.get_ledger_header(100)? {
    println!("Ledger {} closed at {}", header.ledger_seq, header.scp_value.close_time.0);
}

// Check network passphrase
if let Some(passphrase) = db.get_network_passphrase()? {
    println!("Network: {}", passphrase);
}
```

### Using Query Traits Directly

For advanced use cases, you can use the query traits directly on connections:

```rust
use stellar_core_db::{Database, queries::LedgerQueries};

let db = Database::open_in_memory()?;
db.with_connection(|conn| {
    // Use trait methods directly
    let header = conn.load_ledger_header(100)?;
    Ok(header)
})?;
```

### Transactions

For atomic operations, use the transaction wrapper:

```rust
db.transaction(|tx| {
    // Multiple operations in a single transaction
    tx.execute("INSERT INTO storestate (statename, state) VALUES ('key', 'value')", [])?;
    tx.execute("UPDATE storestate SET state = 'new' WHERE statename = 'key'", [])?;
    Ok(())
})?;
```

## Schema Management

The database uses a versioned schema with automatic migrations:

- Schema version is tracked in the `storestate` table
- Migrations run automatically when opening an existing database
- New databases are initialized with the current schema version

To manually check or upgrade the schema:

```rust
// Check current version
let version = db.schema_version()?;

// Explicitly run migrations (usually not needed)
db.upgrade()?;
```

## Database Tables

### Core State
- `storestate` - Key-value configuration and state
- `ledgerheaders` - Block headers with sequence, hash, timestamp

### History
- `txhistory` - Individual transactions
- `txsets` - Per-ledger transaction sets
- `txresults` - Per-ledger transaction results

### Consensus
- `scphistory` - SCP envelopes per ledger
- `scpquorums` - Quorum set definitions

### Operations
- `peers` - Known network peers
- `ban` - Banned node IDs
- `publishqueue` - Pending history publications
- `bucketlist` - Checkpoint bucket hashes

## Performance Notes

The database is configured for optimal performance:

- **WAL mode**: Enables concurrent reads during writes
- **64MB cache**: Reduces disk I/O for frequently accessed data
- **Connection pooling**: Up to 10 concurrent connections (file) or 1 (in-memory)

For write-heavy operations, consider batching within transactions to reduce fsync overhead.

## C++ Parity Status

See [PARITY_STATUS.md](PARITY_STATUS.md) for detailed C++ parity analysis.

## Testing

Tests use in-memory databases for isolation and speed:

```rust
#[test]
fn test_ledger_storage() {
    let db = Database::open_in_memory().unwrap();
    // Test operations...
}
```

## Upstream Mapping

This crate corresponds to the following C++ stellar-core components:

| Rust Module | C++ Component |
|-------------|---------------|
| `pool.rs` | `src/database/Database.cpp` (connection management) |
| `schema.rs` | Various `dropAll()` functions across the codebase |
| `migrations.rs` | `Database::upgradeToCurrentSchema()` |
| `queries/state.rs` | `src/main/PersistentState.cpp` |
| `queries/ledger.rs` | `src/ledger/LedgerHeaderUtils.cpp` |
| `queries/scp.rs` | `src/herder/HerderPersistenceImpl.cpp` |
| `queries/peers.rs` | `src/overlay/PeerManager.cpp` |
| `queries/ban.rs` | `src/overlay/BanManagerImpl.cpp` |
| `queries/history.rs` | `src/transactions/TransactionSQL.cpp` |
| `queries/publish_queue.rs` | `src/history/HistoryManagerImpl.cpp` |
| `queries/bucket_list.rs` | No direct C++ equivalent (new in Rust) |
| `scp_persistence.rs` | `src/herder/HerderPersistenceImpl.cpp` (SCP state persistence) |
