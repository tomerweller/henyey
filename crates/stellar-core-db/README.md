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
│   ├── lib.rs          # Main entry point and Database methods
│   ├── error.rs        # Error types (DbError)
│   ├── pool.rs         # Connection pool (Database struct)
│   ├── schema.rs       # SQL schema definitions
│   ├── migrations.rs   # Schema versioning and migrations
│   └── queries/        # Typed query traits
│       ├── mod.rs
│       ├── accounts.rs     # Account CRUD
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

### Query Traits

Query functionality is organized into domain-specific traits:

| Trait | Purpose |
|-------|---------|
| `LedgerQueries` | Ledger header storage and retrieval |
| `HistoryQueries` | Transaction history and results |
| `ScpQueries` | SCP envelopes and quorum sets |
| `StateQueries` | Key-value state storage |
| `AccountQueries` | Stellar account management |
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

### Ledger Entries
- `accounts` - Stellar accounts with balances and settings
- `trustlines` - Asset trust relationships
- `offers` - DEX offers
- `accountdata` - Account data entries
- `claimablebalance` - Claimable balances
- `liquiditypool` - AMM liquidity pools

### Soroban (Smart Contracts)
- `contractdata` - Contract storage
- `contractcode` - WASM bytecode
- `ttl` - Entry expiration tracking

### History
- `txhistory` - Individual transactions
- `txsets` - Per-ledger transaction sets
- `txresults` - Per-ledger transaction results
- `txfeehistory` - Fee-related ledger changes

### Consensus
- `scphistory` - SCP envelopes per ledger
- `scpquorums` - Quorum set definitions
- `upgradehistory` - Protocol upgrade records

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

This section documents the parity between this Rust crate and the upstream C++ stellar-core
database implementation in `.upstream-v25/src/database/` and related modules.

### Implemented

The following features from C++ stellar-core are implemented in this Rust crate:

**Core Database Infrastructure**
- [x] Database connection management (`Database` class -> `Database` struct)
- [x] Connection pooling (SOCI pool -> r2d2 pool)
- [x] Transaction support (SOCI transactions -> rusqlite transactions)
- [x] Schema versioning and migrations (`getDBSchemaVersion`, `upgradeToCurrentSchema`)
- [x] In-memory database for testing

**SQLite Configuration**
- [x] WAL journal mode
- [x] Cache size configuration
- [x] Busy timeout handling
- [x] Foreign keys enabled

**State Management (storestate table)**
- [x] Get/set/delete state values (`PersistentState` -> `StateQueries`)
- [x] Network passphrase storage
- [x] Last closed ledger tracking
- [x] Schema version tracking

**Ledger Headers (ledgerheaders table)**
- [x] Store ledger headers (`storeInDatabase` -> `store_ledger_header`)
- [x] Load by sequence number (`loadBySequence` -> `load_ledger_header`)
- [x] Get maximum ledger sequence (`loadMaxLedgerSeq` -> `get_latest_ledger_seq`)
- [x] Get ledger hash by sequence (`get_ledger_hash`)

**SCP State (scphistory, scpquorums tables)**
- [x] Store SCP envelopes per ledger (`HerderPersistence` -> `ScpQueries`)
- [x] Load SCP envelopes per ledger
- [x] Store quorum sets by hash
- [x] Load quorum sets by hash

**Peer Management (peers table)**
- [x] Store peer records (`PeerManager::store` -> `store_peer`)
- [x] Load peer records (`loadAllPeers` -> `load_peers`)
- [x] Random peer selection with filters (`load_random_peers*`)
- [x] Failure-based peer cleanup (`remove_peers_with_failures`)

**Ban Management (ban table)**
- [x] Ban node (`BanManager::banNode` -> `ban_node`)
- [x] Unban node (`BanManager::unbanNode` -> `unban_node`)
- [x] Check if banned (`BanManager::isBanned` -> `is_banned`)
- [x] List bans (`BanManager::getBans` -> `load_bans`)

**Transaction History (txhistory, txsets, txresults tables)**
- [x] Store individual transactions (`store_transaction`)
- [x] Load transactions by ID (`load_transaction`)
- [x] Store transaction history entries per ledger (`store_tx_history_entry`)
- [x] Load transaction history entries (`load_tx_history_entry`)
- [x] Store transaction result entries (`store_tx_result_entry`)
- [x] Load transaction result entries (`load_tx_result_entry`)

**Publish Queue (publishqueue table)**
- [x] Enqueue checkpoint for publishing (`enqueue_publish`)
- [x] Remove from queue after publishing (`remove_publish`)
- [x] Load pending checkpoints (`load_publish_queue`)

**Bucket List Snapshots (bucketlist table)**
- [x] Store bucket list levels at checkpoints (`store_bucket_list`)
- [x] Load bucket list levels (`load_bucket_list`)

**Account Management (accounts table)**
- [x] Load account by ID (`load_account`)
- [x] Store account (`store_account`)
- [x] Delete account (`delete_account`)

### Not Yet Implemented (Gaps)

The following C++ features are not yet implemented in this Rust crate:

**Database Backend Support**
- [ ] PostgreSQL support (C++ supports both SQLite and PostgreSQL via SOCI)
- [ ] `DatabaseTypeSpecificOperation` pattern for backend-specific code
- [ ] Database connection string parsing (`removePasswordFromConnectionString`)
- [ ] Read-only transaction mode (`setCurrentTransactionReadOnly`)
- [ ] Simple collation clause for PostgreSQL (`getSimpleCollationClause`)

**Performance Instrumentation**
- [ ] Query timers (`getInsertTimer`, `getSelectTimer`, `getDeleteTimer`, `getUpdateTimer`, `getUpsertTimer`)
- [ ] Query meter for counting operations
- [ ] Prepared statement caching with metrics (`mStatementsSize` counter)

**Prepared Statement Management**
- [ ] Per-session prepared statement cache (`getPreparedStatement`)
- [ ] Cache cleanup (`clearPreparedStatementCache`)
- [ ] `StatementContext` RAII wrapper for statement lifecycle

**Data Cleanup Operations**
- [ ] `deleteOldEntries` for ledger headers (prune old data)
- [ ] `deleteOldEntries` for SCP history
- [ ] `deleteOldEntries` for transaction history
- [ ] Bulk delete utilities (`DatabaseUtils::deleteOldEntriesHelper`)

**History Streaming**
- [ ] `copyToStream` for ledger headers (export to history archives)
- [ ] `copyToStream` for transactions
- [ ] `copyToStream` for SCP history

**Additional Ledger Entry Types (LedgerTxn SQL)**
- [ ] Trust lines (trustlines table) - schema exists but no query impl
- [ ] Offers (offers table) - schema exists but no query impl
- [ ] Account data entries (accountdata table) - schema exists but no query impl
- [ ] Claimable balances (claimablebalance table) - schema exists but no query impl
- [ ] Liquidity pools (liquiditypool table) - schema exists but no query impl

**Soroban/Smart Contract Storage**
- [ ] Contract data (contractdata table) - schema exists but no query impl
- [ ] Contract code (contractcode table) - schema exists but no query impl
- [ ] TTL entries (ttl table) - schema exists but no query impl

**Transaction Fee History**
- [ ] txfeehistory table operations - schema exists but no query impl

**Upgrade History**
- [ ] upgradehistory table operations - schema exists but no query impl

**Quorum Info**
- [ ] quoruminfo table (node -> qsethash mapping, used in C++ but not in Rust schema)

**Slot State**
- [ ] slotstate table (used for SCP state persistence in C++, not in Rust schema)

**Schema Migration Details**
- [ ] Migration from version 22 (drop txfeehistory)
- [ ] Migration from version 23 (drop SQL-based publish, upgrade history)
- [ ] Migration from version 24 (drop pubsub, migrate to slotstate)
- [ ] Migration from version 25 (remove dbbackend entry)

### Implementation Notes

**Architecture Differences**

1. **Database Library**: The C++ implementation uses SOCI (a C++ database access library), while Rust uses rusqlite with r2d2 for connection pooling. This is a fundamental difference that affects API design.

2. **Query Pattern**: C++ uses prepared statement caching with a shared cache per session name. Rust uses rusqlite's built-in statement handling without explicit caching.

3. **Multi-Database Support**: C++ supports both SQLite and PostgreSQL through SOCI's backend abstraction. The Rust implementation currently only supports SQLite.

4. **XDR Encoding**: C++ stores XDR data as base64-encoded text in many tables. Rust stores XDR data as raw binary blobs (BLOB type), which is more efficient.

5. **Schema Design**: The Rust schema is largely compatible with C++ but stores some fields differently:
   - C++ uses base64-encoded text for XDR data; Rust uses raw blobs
   - C++ uses CHARACTER(64) for hashes; Rust uses TEXT
   - Both use the same table names and primary keys

6. **Connection Pooling**: C++ creates a connection pool on-demand when `getPool()` is called. Rust creates the pool at database open time with a fixed size.

7. **Session Naming**: C++ uses named sessions for tracking prepared statement caches. Rust doesn't use this pattern.

**Intentional Omissions**

- **PostgreSQL**: The Rust implementation is SQLite-only by design, focusing on single-node deployments and testing scenarios.

- **Query Metrics**: The Rust crate doesn't include metrics infrastructure. Metrics would be added at a higher layer if needed.

- **Ledger Entry SQL**: The C++ `LedgerTxn*SQL` files implement complex ledger entry storage used during ledger application. The Rust implementation stores ledger entries in the bucket list (via stellar-core-ledger), not in SQL tables, following a different architecture.

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
| `queries/accounts.rs` | `src/ledger/LedgerTxnAccountSQL.cpp` (partial) |
