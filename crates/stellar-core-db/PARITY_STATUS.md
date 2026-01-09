# C++ Parity Status

This document tracks the parity between this Rust crate (`stellar-core-db`) and the upstream
C++ stellar-core database implementation.

## Upstream References

The C++ implementation is spread across multiple files:
- **Core Database**: `.upstream-v25/src/database/Database.{h,cpp}` - connection management, prepared statements, metrics
- **Database Utilities**: `.upstream-v25/src/database/DatabaseUtils.{h,cpp}` - helper functions for bulk operations
- **Persistent State**: `.upstream-v25/src/main/PersistentState.{h,cpp}` - key-value state storage
- **Ledger Headers**: `.upstream-v25/src/ledger/LedgerHeaderUtils.{h,cpp}` - ledger header SQL operations
- **Peer Manager**: `.upstream-v25/src/overlay/PeerManager.{h,cpp}` - peer table operations
- **Ban Manager**: `.upstream-v25/src/overlay/BanManager.h`, `BanManagerImpl.cpp` - ban list operations
- **Herder Persistence**: `.upstream-v25/src/herder/HerderPersistence*.{h,cpp}` - SCP history storage
- **History Manager**: `.upstream-v25/src/history/HistoryManager*.{h,cpp}` - history publishing queue
- **Transaction SQL**: `.upstream-v25/src/transactions/TransactionSQL.{h,cpp}` - transaction history

## Parity Summary

| Category | Rust Status | Notes |
|----------|-------------|-------|
| Core Infrastructure | Implemented | Different library (rusqlite vs SOCI) |
| State Management | Implemented | Full parity |
| Ledger Headers | Implemented | Full parity |
| SCP History | Implemented | Full parity |
| Peer Management | Implemented | Full parity |
| Ban Management | Implemented | Full parity |
| Transaction History | Implemented | Full parity |
| Publish Queue | Implemented | Full parity |
| Bucket List Snapshots | Implemented | Full parity |
| Account Management | Implemented | Basic operations only |
| PostgreSQL Support | Not Implemented | Intentional - SQLite only |
| Query Metrics | Not Implemented | Intentional |
| Data Cleanup | Not Implemented | Gap |
| History Streaming | Not Implemented | Gap |
| Ledger Entry SQL | Not Implemented | Architectural difference |

## Implemented Features

### Core Database Infrastructure

| C++ Feature | Rust Equivalent | Status |
|-------------|-----------------|--------|
| `Database` class | `Database` struct | Done |
| `soci::session` | `rusqlite::Connection` | Done |
| `soci::connection_pool` | `r2d2::Pool` | Done |
| `soci::transaction` | `rusqlite::Transaction` | Done |
| `getDBSchemaVersion()` | `get_schema_version()` | Done |
| `upgradeToCurrentSchema()` | `run_migrations()` | Done |
| `initialize()` | `initialize_schema()` | Done |
| In-memory database | `Database::open_in_memory()` | Done |

### SQLite Configuration

| C++ Pragma | Rust Pragma | Status |
|------------|-------------|--------|
| `journal_mode = WAL` | `journal_mode = WAL` | Done |
| `wal_autocheckpoint=10000` | Not set | Different default |
| `busy_timeout = 10000` | Not set | Different default |
| `cache_size=-20000` | `cache_size = -64000` | Done (larger) |
| `mmap_size=104857600` | Not set | Not implemented |
| `synchronous = NORMAL` | `synchronous = NORMAL` | Done |
| `foreign_keys` | `foreign_keys = ON` | Done |
| N/A | `temp_store = MEMORY` | Rust addition |

### State Management (storestate table)

| C++ Method | Rust Method | Status |
|------------|-------------|--------|
| `PersistentState::getState()` | `StateQueries::get_state()` | Done |
| `PersistentState::setState()` | `StateQueries::set_state()` | Done |
| Network passphrase storage | `get/set_network_passphrase()` | Done |
| Last closed ledger | `get/set_last_closed_ledger()` | Done |
| Schema version tracking | `get/set_schema_version()` | Done |
| SCP slot state (slotstate table) | `ScpStatePersistenceQueries` | Done |
| TX set storage | `save/load_tx_set_data()` | Done |

### Ledger Headers (ledgerheaders table)

| C++ Method | Rust Method | Status |
|------------|-------------|--------|
| `storeInDatabase()` | `store_ledger_header()` | Done |
| `loadBySequence()` | `load_ledger_header()` | Done |
| `loadMaxLedgerSeq()` | `get_latest_ledger_seq()` | Done |
| Get hash by sequence | `get_ledger_hash()` | Done |

### SCP History (scphistory, scpquorums tables)

| C++ Method | Rust Method | Status |
|------------|-------------|--------|
| `HerderPersistence::saveSCPHistory()` | `store_scp_history()` | Done |
| `HerderPersistence::getSCPHistory()` | `load_scp_history()` | Done |
| Store quorum set by hash | `store_scp_quorum_set()` | Done |
| Load quorum set by hash | `load_scp_quorum_set()` | Done |

### Peer Management (peers table)

| C++ Method | Rust Method | Status |
|------------|-------------|--------|
| `PeerManager::store()` | `store_peer()` | Done |
| `PeerManager::load()` | `load_peer()` | Done |
| `PeerManager::loadAllPeers()` | `load_peers()` | Done |
| `PeerManager::loadRandomPeers()` | `load_random_peers()` | Done |
| Random peers by type | `load_random_peers_by_type_max_failures()` | Done |
| Random outbound peers | `load_random_peers_any_outbound()` | Done |
| `removePeersWithManyFailures()` | `remove_peers_with_failures()` | Done |

### Ban Management (ban table)

| C++ Method | Rust Method | Status |
|------------|-------------|--------|
| `BanManager::banNode()` | `ban_node()` | Done |
| `BanManager::unbanNode()` | `unban_node()` | Done |
| `BanManager::isBanned()` | `is_banned()` | Done |
| `BanManager::getBans()` | `load_bans()` | Done |

### Transaction History (txhistory, txsets, txresults tables)

| C++ Method | Rust Method | Status |
|------------|-------------|--------|
| Store individual transaction | `store_transaction()` | Done |
| Load transaction by ID | `load_transaction()` | Done |
| Store TX history entry | `store_tx_history_entry()` | Done |
| Load TX history entry | `load_tx_history_entry()` | Done |
| Store TX result entry | `store_tx_result_entry()` | Done |
| Load TX result entry | `load_tx_result_entry()` | Done |

### Publish Queue (publishqueue table)

| C++ Method | Rust Method | Status |
|------------|-------------|--------|
| Enqueue checkpoint | `enqueue_publish()` | Done |
| Remove from queue | `remove_publish()` | Done |
| Load pending queue | `load_publish_queue()` | Done |

### Bucket List Snapshots (bucketlist table)

| C++ Feature | Rust Method | Status |
|-------------|-------------|--------|
| Store bucket list levels | `store_bucket_list()` | Done |
| Load bucket list levels | `load_bucket_list()` | Done |

### Account Management (accounts table)

| C++ Feature | Rust Method | Status |
|-------------|-------------|--------|
| Load account by ID | `load_account()` | Done |
| Store account | `store_account()` | Done |
| Delete account | `delete_account()` | Done |

## Not Implemented (Gaps)

### Database Backend Support

| C++ Feature | Status | Notes |
|-------------|--------|-------|
| PostgreSQL backend | Not Implemented | Intentional - SQLite only by design |
| `DatabaseTypeSpecificOperation` pattern | N/A | Not needed for SQLite-only |
| Connection string parsing | N/A | Simplified configuration |
| Read-only transaction mode | Not Implemented | Could be added if needed |
| PostgreSQL collation clause | N/A | Not needed for SQLite |

### Performance Instrumentation

| C++ Feature | Status | Notes |
|-------------|--------|-------|
| `getInsertTimer()` | Not Implemented | Metrics at higher layer |
| `getSelectTimer()` | Not Implemented | Metrics at higher layer |
| `getDeleteTimer()` | Not Implemented | Metrics at higher layer |
| `getUpdateTimer()` | Not Implemented | Metrics at higher layer |
| `getUpsertTimer()` | Not Implemented | Metrics at higher layer |
| Query meter | Not Implemented | Metrics at higher layer |
| `mStatementsSize` counter | Not Implemented | Not tracking statement cache size |

### Prepared Statement Management

| C++ Feature | Status | Notes |
|-------------|--------|-------|
| `getPreparedStatement()` | Not Implemented | rusqlite handles internally |
| `clearPreparedStatementCache()` | Not Implemented | Not needed |
| `StatementContext` RAII wrapper | Not Implemented | Rust ownership handles this |
| Per-session statement caching | Not Implemented | Single pool, no sessions |

### Data Cleanup Operations

| C++ Feature | Status | Notes |
|-------------|--------|-------|
| `LedgerHeaderUtils::deleteOldEntries()` | **Gap** | Prune old ledger headers |
| `HerderPersistence::deleteOldEntries()` | **Gap** | Prune old SCP history |
| `DatabaseUtils::deleteOldEntriesHelper()` | **Gap** | Generic pruning helper |

### History Streaming

| C++ Feature | Status | Notes |
|-------------|--------|-------|
| `LedgerHeaderUtils::copyToStream()` | **Gap** | Export headers to history archives |
| Transaction `copyToStream()` | **Gap** | Export transactions to archives |
| SCP history streaming | **Gap** | Export SCP data to archives |

### Additional Ledger Entry Types

Schema exists but no query implementations:

| Table | C++ Location | Status |
|-------|--------------|--------|
| trustlines | `LedgerTxnTrustLineSQL.cpp` | Schema only |
| offers | `LedgerTxnOfferSQL.cpp` | Schema only |
| accountdata | `LedgerTxnDataSQL.cpp` | Schema only |
| claimablebalance | `LedgerTxnClaimableBalanceSQL.cpp` | Schema only |
| liquiditypool | `LedgerTxnLiquidityPoolSQL.cpp` | Schema only |
| contractdata | `LedgerTxnContractDataSQL.cpp` | Schema only |
| contractcode | `LedgerTxnContractCodeSQL.cpp` | Schema only |
| ttl | `LedgerTxnTTLSQL.cpp` | Schema only |

### Other Tables

| Table | C++ Feature | Status |
|-------|-------------|--------|
| txfeehistory | Transaction fee changes | Schema only |
| upgradehistory | Protocol upgrade history | Schema only |

## Architectural Differences

### Database Library

- **C++**: Uses SOCI with SQLite3 and optional PostgreSQL backends
- **Rust**: Uses rusqlite with r2d2 connection pooling

This is a fundamental difference that affects:
- Error handling (SOCI exceptions vs Rust Results)
- Statement preparation (explicit cache vs implicit)
- Type conversions (SOCI type traits vs rusqlite ToSql/FromSql)

### XDR Encoding

- **C++**: Stores XDR data as base64-encoded TEXT in most tables
- **Rust**: Stores XDR data as raw BLOB (binary), which is more efficient

This is intentional and does not affect parity of behavior, only storage format.

### Connection Pooling

- **C++**: Creates pool on-demand when `getPool()` is called, pool size based on hardware concurrency
- **Rust**: Creates pool at open time with fixed size (10 for file, 1 for in-memory)

### Session Management

- **C++**: Uses named sessions for prepared statement cache isolation
- **Rust**: No session names, simpler connection model

### Ledger Entry Storage

- **C++**: `LedgerTxn*SQL` files store all ledger entries in SQL tables during ledger close
- **Rust**: Ledger entries are stored in the bucket list only (via stellar-core-ledger crate)

This is a significant architectural difference. The Rust implementation uses the bucket list
as the primary state storage, matching the canonical Stellar state representation. SQL tables
for ledger entries exist in the schema for compatibility but are not actively used.

## Migration Compatibility

The Rust migration system uses a different versioning scheme than C++:

| C++ Version | Rust Version | Description |
|-------------|--------------|-------------|
| MIN_SCHEMA_VERSION = 21 | N/A | C++ minimum supported |
| SCHEMA_VERSION = 25 | CURRENT_VERSION = 5 | Current version |

The Rust crate starts fresh with its own version numbering since it:
1. Uses different storage formats (BLOB vs base64 TEXT)
2. Has different table structures in some cases
3. Does not need to support legacy C++ databases

## Recommendations for Future Work

### Priority 1: Data Cleanup Operations

Implement `deleteOldEntries` equivalents for:
- Ledger headers
- SCP history
- Transaction history

These are important for long-running nodes to manage database size.

### Priority 2: History Streaming

Implement `copyToStream` equivalents for history archive publishing.
Currently history publishing works but could be optimized.

### Priority 3: Additional SQLite Pragmas

Consider adding:
- `mmap_size` for memory-mapped I/O performance
- `wal_autocheckpoint` for WAL size management
- `busy_timeout` for concurrent access handling

### Not Recommended

- **PostgreSQL support**: The Rust implementation is designed for SQLite-only deployments
- **Query metrics in database layer**: Should be implemented at a higher level if needed
- **Prepared statement caching**: rusqlite handles this efficiently
