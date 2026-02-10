# Parity Status: henyey-db

**Overall Parity: ~85%**

## Overview

This crate provides SQLite-based database persistence for henyey, corresponding to stellar-core `src/database/` module and related SQL operations spread across the stellar-core codebase. The Rust implementation uses `rusqlite` with `r2d2` connection pooling, while stellar-core uses SOCI with support for both SQLite and PostgreSQL.

## stellar-core References

- **Core Database**: `.upstream-v25/src/database/Database.` - connection management, prepared statements, metrics
- **Database Utilities**: `.upstream-v25/src/database/DatabaseUtils.` - helper functions for bulk operations
- **Connection String**: `.upstream-v25/src/database/DatabaseConnectionString.` - connection string parsing
- **Persistent State**: `.upstream-v25/src/main/PersistentState.` - key-value state storage
- **Ledger Headers**: `.upstream-v25/src/ledger/LedgerHeaderUtils.` - ledger header SQL operations
- **Peer Manager**: `.upstream-v25/src/overlay/PeerManager.` - peer table operations
- **Ban Manager**: `.upstream-v25/src/overlay/BanManager.h`, `BanManagerImpl.cpp` - ban list operations
- **Herder Persistence**: `.upstream-v25/src/herder/HerderPersistence*.` - SCP history storage
- **History Manager**: `.upstream-v25/src/history/HistoryManager*.` - history publishing queue
- **Transaction SQL**: `.upstream-v25/src/transactions/TransactionSQL.` - transaction history

## Implemented Features

- [x] Database connection management
- [x] Connection pooling
- [x] Transaction support
- [x] Schema migrations
- [x] State management (storestate table)
- [x] Ledger header storage/retrieval
- [x] SCP history persistence
- [x] SCP quorum set storage
- [x] Peer management
- [x] Ban list management
- [x] Transaction history
- [x] Publish queue
- [x] Bucket list snapshots
- [x] Old entry cleanup/garbage collection
- [ ] PostgreSQL support (intentional - SQLite only)
- [ ] Misc database splitting (v25+ stellar-core feature)
- [ ] Query metrics/timers
- [ ] Prepared statement caching (handled by rusqlite)
- [ ] Connection string parsing/password removal
- [ ] History streaming to archives
- [ ] Read-only transaction mode

## Test Coverage Comparison

### stellar-core Tests (

| Test File | Test Name | Rust Equivalent | Status |
|-----------|-----------|-----------------|--------|
| `DatabaseTests.cpp` | `database smoketest` | (implicit in all tests) | ✅ Covered by unit tests |
| `DatabaseTests.cpp` | `database on-disk smoketest` | `Database::open()` tests | ✅ Covered |
| `DatabaseTests.cpp` | `sqlite MVCC test` | None | ❌ **Gap** |
| `DatabaseTests.cpp` | `postgres smoketest` | N/A | N/A (SQLite only) |
| `DatabaseTests.cpp` | `postgres MVCC test` | N/A | N/A (SQLite only) |
| `DatabaseTests.cpp` | `postgres performance` | N/A | N/A (SQLite only) |
| `DatabaseTests.cpp` | `schema test` | `test_verify_schema_current` | ✅ Covered |
| `DatabaseTests.cpp` | `getMiscDBName handles various file extensions` | None | ❌ **Gap** (no misc DB support) |
| `DatabaseTests.cpp` | `Database splitting migration works correctly` | None | ❌ **Gap** (no misc DB support) |
| `DatabaseConnectionStringTest.cpp` | `remove password from database connection string` (15 cases) | None | ❌ **Gap** (not implemented) |

### Rust Tests (33 total)

#### migrations.rs (5 tests)
| Test Name | stellar-core Equivalent | Notes |
|-----------|----------------|-------|
| `test_get_schema_version_default` | Part of `upgradeToCurrentSchema` | ✅ |
| `test_set_and_get_schema_version` | Part of `upgradeToCurrentSchema` | ✅ |
| `test_needs_migration` | Part of `upgradeToCurrentSchema` | ✅ |
| `test_verify_schema_current` | `schema test` | ✅ |
| `test_verify_schema_too_old` | Part of `validateVersion` | ✅ |

#### scp_persistence.rs (2 tests)
| Test Name | stellar-core Equivalent | Notes |
|-----------|----------------|-------|
| `test_sqlite_scp_persistence` | Covered in HerderPersistence tests | ✅ |
| `test_sqlite_tx_set_persistence` | Covered in HerderPersistence tests | ✅ |

#### queries/bucket_list.rs (2 tests)
| Test Name | stellar-core Equivalent | Notes |
|-----------|----------------|-------|
| `test_store_and_load_bucket_list` | None (Rust-specific) | ✅ Rust-only |
| `test_load_missing_bucket_list` | None (Rust-specific) | ✅ Rust-only |

#### queries/history.rs (6 tests)
| Test Name | stellar-core Equivalent | Notes |
|-----------|----------------|-------|
| `test_store_and_load_transaction` | TransactionSQL tests | ✅ |
| `test_store_transaction_without_meta` | TransactionSQL tests | ✅ |
| `test_load_nonexistent_transaction` | None explicit | ✅ Rust addition |
| `test_update_transaction` | None explicit | ✅ Rust addition |
| `test_store_and_load_tx_history_entry` | History archive tests | ✅ |
| `test_store_and_load_tx_result_entry` | History archive tests | ✅ |

#### queries/ledger.rs (4 tests)
| Test Name | stellar-core Equivalent | Notes |
|-----------|----------------|-------|
| `test_store_and_load_ledger_header` | LedgerHeaderUtils tests | ✅ |
| `test_get_latest_ledger_seq` | LedgerHeaderUtils tests | ✅ |
| `test_get_ledger_hash` | LedgerHeaderUtils tests | ✅ |
| `test_delete_old_ledger_headers` | `deleteOldEntries` tests | ✅ |

#### queries/peers.rs (6 tests)
| Test Name | stellar-core Equivalent | Notes |
|-----------|----------------|-------|
| `test_store_and_load_peer` | PeerManager tests | ✅ |
| `test_load_peers_limit` | PeerManager tests | ✅ |
| `test_load_random_peers_any_outbound_max_failures` | PeerManager tests | ✅ |
| `test_load_random_peers_by_type_max_failures` | PeerManager tests | ✅ |
| `test_remove_peers_with_failures` | PeerManager tests | ✅ |
| `test_load_random_peers` | PeerManager tests | ✅ |

#### queries/scp.rs (5 tests)
| Test Name | stellar-core Equivalent | Notes |
|-----------|----------------|-------|
| `test_scp_slot_state_roundtrip` | HerderPersistence tests | ✅ |
| `test_load_all_scp_slot_states` | HerderPersistence tests | ✅ |
| `test_delete_scp_slot_states_below` | HerderPersistence tests | ✅ |
| `test_tx_set_data_roundtrip` | HerderPersistence tests | ✅ |
| `test_delete_old_scp_entries` | `deleteOldEntries` tests | ✅ |

#### queries/state.rs (3 tests)
| Test Name | stellar-core Equivalent | Notes |
|-----------|----------------|-------|
| `test_get_set_state` | PersistentState tests | ✅ |
| `test_delete_state` | None explicit | ✅ Rust addition |
| `test_last_closed_ledger` | PersistentState tests | ✅ |

### Rust-only Tests (no stellar-core equivalent)
- `test_load_missing_bucket_list` - Bucket list table is Rust-specific
- `test_store_and_load_bucket_list` - Bucket list table is Rust-specific
- `test_load_nonexistent_transaction` - Edge case testing
- `test_update_transaction` - Upsert behavior testing
- `test_delete_state` - State deletion testing

## Known Gaps

### Critical Gaps

1. **MVCC Isolation Test**: stellar-core tests concurrent transaction isolation behavior (`checkMVCCIsolation`). The Rust crate lacks equivalent tests for verifying WAL mode and transaction isolation work correctly under concurrent access.

2. **Connection String Security**: stellar-core has comprehensive tests for removing passwords from connection strings (15 test cases in `DatabaseConnectionStringTest.cpp`). Not implemented in Rust since we use simpler path-based configuration.

### Intentional Omissions

1. **PostgreSQL Support**: Not implemented by design - henyey is SQLite-only.

2. **Misc Database Splitting**: stellar-core v26 introduced splitting overlay/SCP tables into a separate SQLite file for better concurrency. Not implemented in Rust.

3. **Query Metrics**: stellar-core tracks insert/select/delete/update timers per entity. Rust defers metrics to higher layers.

4. **Prepared Statement Caching**: rusqlite handles this internally; no explicit cache management needed.

### Feature Gaps

1. **History Streaming**: `copyToStream` methods for exporting data to history archives are not implemented.

2. **Read-only Transaction Mode**: `setCurrentTransactionReadOnly()` not implemented.

3. **Connection Pool Size**: stellar-core uses hardware concurrency for pool sizing; Rust uses fixed size (10).

## Architectural Differences

### Database Library
- **stellar-core**: SOCI with SQLite3 and optional PostgreSQL backends
- **Rust**: rusqlite with r2d2 connection pooling

### XDR Storage
- **stellar-core**: Stores XDR as base64-encoded TEXT
- **Rust**: Stores XDR as raw BLOB (more efficient)

### Schema Version
- **stellar-core**: MIN_SCHEMA_VERSION = 25, SCHEMA_VERSION = 26
- **Rust**: CURRENT_VERSION = 5 (independent versioning)

### SQLite Configuration

| Pragma | stellar-core Value | Rust Value | Notes |
|--------|-----------|------------|-------|
| `journal_mode` | WAL | WAL | Same |
| `synchronous` | (commented out) | NORMAL | Rust sets explicitly |
| `wal_autocheckpoint` | 10000 | (default) | Not set in Rust |
| `busy_timeout` | 10000 | 30000 | Rust uses longer timeout |
| `cache_size` | -20000 (20MB) | -64000 (64MB) | Rust uses larger cache |
| `mmap_size` | 104857600 (100MB) | (not set) | Not implemented |
| `foreign_keys` | (not set) | ON | Rust addition |
| `temp_store` | (not set) | MEMORY | Rust addition |

## Recommendations for Future Work

### Priority 1: Add MVCC Isolation Tests
Port the `checkMVCCIsolation` test to verify concurrent transaction behavior works correctly with the WAL journal mode.

### Priority 2: Integration Tests
Create integration tests in `crates/henyey-db/tests/` that exercise the full `Database` API including:
- Opening persistent databases
- Concurrent access patterns
- Transaction rollback scenarios
- Migration from older schema versions

### Priority 3: SQLite Pragmas
Consider adding:
- `mmap_size` for memory-mapped I/O performance
- `wal_autocheckpoint` for explicit WAL size management

### Not Recommended
- **PostgreSQL support**: Intentionally omitted
- **Misc database splitting**: Adds complexity for marginal benefit
- **Connection string parsing**: Not needed for file-based SQLite config

## Test Commands

```bash
# Run all database crate tests
cargo test -p henyey-db

# Run specific test module
cargo test -p henyey-db migrations::tests

# Run with output
cargo test -p henyey-db -- --nocapture
```
