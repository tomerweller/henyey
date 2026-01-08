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
