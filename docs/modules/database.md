# Database Module Specification

**Crate**: `stellar-core-db`
**stellar-core mapping**: `src/database/`

## 1. Overview

The database module provides SQLite-based persistence for:
- Ledger state (accounts, trustlines, offers, etc.)
- Transaction history
- SCP state
- Application metadata

## 2. stellar-core Reference

In stellar-core, the database module (`src/database/`) contains:
- `Database.h/cpp` - Database connection management
- `DatabaseUtils.h/cpp` - Query utilities
- SQL schema definitions in various modules

stellar-core supports both PostgreSQL and SQLite. We support **SQLite only**.

## 3. Rust Implementation

### 3.1 Dependencies

**Important**: Pure Rust only - using `rusqlite` with bundled SQLite.

```toml
[dependencies]
# SQLite - rusqlite bundles SQLite as pure C, but we need it
# Alternative: Consider sqlite-vfs for pure Rust if available
rusqlite = { version = "0.31", features = ["bundled", "blob"] }

# Connection pooling
r2d2 = "0.8"
r2d2_sqlite = "0.24"

# Query building
sea-query = { version = "0.30", features = ["backend-sqlite"] }

# Utilities
thiserror = "1"
tracing = "0.1"
parking_lot = "0.12"
```

**Note**: `rusqlite` with `bundled` feature compiles SQLite from C source. If a pure Rust SQLite alternative becomes production-ready, we should migrate. For now, this is acceptable as SQLite is well-audited.

### 3.2 Module Structure

```
stellar-core-db/
├── src/
│   ├── lib.rs
│   ├── connection.rs    # Connection management
│   ├── pool.rs          # Connection pooling
│   ├── schema.rs        # Schema definitions
│   ├── migrations.rs    # Schema migrations
│   ├── queries/
│   │   ├── mod.rs
│   │   ├── accounts.rs
│   │   ├── trustlines.rs
│   │   ├── offers.rs
│   │   ├── data.rs
│   │   ├── claimable_balances.rs
│   │   ├── liquidity_pools.rs
│   │   ├── ledger.rs
│   │   ├── transactions.rs
│   │   ├── scp.rs
│   │   └── soroban.rs
│   └── error.rs
└── tests/
```

### 3.3 Core Types

#### Database Connection

```rust
use rusqlite::Connection;
use std::path::Path;

pub struct Database {
    pool: r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>,
}

impl Database {
    /// Open database at path (creates if not exists)
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DbError> {
        let manager = r2d2_sqlite::SqliteConnectionManager::file(path);
        let pool = r2d2::Pool::builder()
            .max_size(10)
            .build(manager)?;

        let db = Self { pool };
        db.initialize_schema()?;
        Ok(db)
    }

    /// Open in-memory database (for testing)
    pub fn open_in_memory() -> Result<Self, DbError> {
        let manager = r2d2_sqlite::SqliteConnectionManager::memory();
        let pool = r2d2::Pool::builder()
            .max_size(1) // Memory DB must be single connection
            .build(manager)?;

        let db = Self { pool };
        db.initialize_schema()?;
        Ok(db)
    }

    /// Get a connection from the pool
    pub fn connection(&self) -> Result<PooledConnection, DbError> {
        self.pool.get().map_err(DbError::from)
    }

    /// Execute in a transaction
    pub fn transaction<T, F>(&self, f: F) -> Result<T, DbError>
    where
        F: FnOnce(&rusqlite::Transaction) -> Result<T, DbError>,
    {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let result = f(&tx)?;
        tx.commit()?;
        Ok(result)
    }
}
```

### 3.4 Schema Definition

```rust
pub mod schema {
    pub const SCHEMA_VERSION: i32 = 1;

    pub const CREATE_TABLES: &str = r#"
        -- Schema version tracking
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY
        );

        -- Ledger headers
        CREATE TABLE IF NOT EXISTS ledgerheaders (
            ledgerhash TEXT PRIMARY KEY,
            prevhash TEXT NOT NULL,
            bucketlisthash TEXT NOT NULL,
            ledgerseq INTEGER UNIQUE NOT NULL,
            closetime INTEGER NOT NULL,
            data BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ledgerheaders_seq ON ledgerheaders(ledgerseq);

        -- Accounts
        CREATE TABLE IF NOT EXISTS accounts (
            accountid TEXT PRIMARY KEY,
            balance BIGINT NOT NULL,
            seqnum BIGINT NOT NULL,
            numsubentries INTEGER NOT NULL,
            inflationdest TEXT,
            homedomain TEXT,
            thresholds TEXT NOT NULL,
            flags INTEGER NOT NULL,
            signers TEXT,
            lastmodified INTEGER NOT NULL,
            extension BLOB
        );

        -- Trust lines
        CREATE TABLE IF NOT EXISTS trustlines (
            accountid TEXT NOT NULL,
            assettype INTEGER NOT NULL,
            issuer TEXT NOT NULL,
            assetcode TEXT NOT NULL,
            tlimit BIGINT NOT NULL,
            balance BIGINT NOT NULL,
            flags INTEGER NOT NULL,
            lastmodified INTEGER NOT NULL,
            extension BLOB,
            PRIMARY KEY (accountid, assettype, issuer, assetcode)
        );

        -- Offers
        CREATE TABLE IF NOT EXISTS offers (
            offerid BIGINT PRIMARY KEY,
            sellerid TEXT NOT NULL,
            sellingassettype INTEGER NOT NULL,
            sellingissuer TEXT,
            sellingassetcode TEXT,
            buyingassettype INTEGER NOT NULL,
            buyingissuer TEXT,
            buyingassetcode TEXT,
            amount BIGINT NOT NULL,
            pricen INTEGER NOT NULL,
            priced INTEGER NOT NULL,
            flags INTEGER NOT NULL,
            lastmodified INTEGER NOT NULL,
            extension BLOB
        );
        CREATE INDEX IF NOT EXISTS offers_seller ON offers(sellerid);

        -- Account data entries
        CREATE TABLE IF NOT EXISTS accountdata (
            accountid TEXT NOT NULL,
            dataname TEXT NOT NULL,
            datavalue TEXT NOT NULL,
            lastmodified INTEGER NOT NULL,
            extension BLOB,
            PRIMARY KEY (accountid, dataname)
        );

        -- Claimable balances
        CREATE TABLE IF NOT EXISTS claimablebalance (
            balanceid TEXT PRIMARY KEY,
            claimants TEXT NOT NULL,
            asset TEXT NOT NULL,
            amount BIGINT NOT NULL,
            lastmodified INTEGER NOT NULL,
            extension BLOB
        );

        -- Liquidity pools
        CREATE TABLE IF NOT EXISTS liquiditypool (
            poolid TEXT PRIMARY KEY,
            type INTEGER NOT NULL,
            assetA TEXT NOT NULL,
            assetB TEXT NOT NULL,
            fee INTEGER NOT NULL,
            reserveA BIGINT NOT NULL,
            reserveB BIGINT NOT NULL,
            totalshares BIGINT NOT NULL,
            poolshareholders INTEGER NOT NULL,
            lastmodified INTEGER NOT NULL,
            extension BLOB
        );

        -- Soroban contract data
        CREATE TABLE IF NOT EXISTS contractdata (
            contractid TEXT NOT NULL,
            key BLOB NOT NULL,
            keytype INTEGER NOT NULL,
            val BLOB NOT NULL,
            lastmodified INTEGER NOT NULL,
            PRIMARY KEY (contractid, key)
        );

        -- Soroban contract code
        CREATE TABLE IF NOT EXISTS contractcode (
            hash TEXT PRIMARY KEY,
            code BLOB NOT NULL,
            lastmodified INTEGER NOT NULL
        );

        -- Soroban TTL entries
        CREATE TABLE IF NOT EXISTS ttl (
            keyhash TEXT PRIMARY KEY,
            liveuntilledgerseq INTEGER NOT NULL
        );

        -- Transaction history
        CREATE TABLE IF NOT EXISTS txhistory (
            txid TEXT PRIMARY KEY,
            ledgerseq INTEGER NOT NULL,
            txindex INTEGER NOT NULL,
            txbody BLOB NOT NULL,
            txresult BLOB NOT NULL,
            txmeta BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS txhistory_ledger ON txhistory(ledgerseq);

        -- SCP state
        CREATE TABLE IF NOT EXISTS scphistory (
            nodeid TEXT NOT NULL,
            ledgerseq INTEGER NOT NULL,
            envelope BLOB NOT NULL,
            PRIMARY KEY (nodeid, ledgerseq)
        );

        -- SCP quorum information
        CREATE TABLE IF NOT EXISTS scpquorums (
            qsethash TEXT PRIMARY KEY,
            lastledgerseq INTEGER NOT NULL,
            qset BLOB NOT NULL
        );

        -- Persistent state
        CREATE TABLE IF NOT EXISTS storestate (
            statename TEXT PRIMARY KEY,
            state TEXT NOT NULL
        );

        -- Upgrade history
        CREATE TABLE IF NOT EXISTS upgradehistory (
            ledgerseq INTEGER NOT NULL,
            upgradeindex INTEGER NOT NULL,
            upgrade BLOB NOT NULL,
            changes BLOB NOT NULL,
            PRIMARY KEY (ledgerseq, upgradeindex)
        );
    "#;
}
```

### 3.5 Query Interfaces

#### Account Queries

```rust
use stellar_xdr::curr::{AccountEntry, AccountId};

pub trait AccountQueries {
    fn load_account(&self, account_id: &AccountId) -> Result<Option<AccountEntry>, DbError>;
    fn store_account(&self, entry: &AccountEntry, last_modified: u32) -> Result<(), DbError>;
    fn delete_account(&self, account_id: &AccountId) -> Result<(), DbError>;
    fn account_exists(&self, account_id: &AccountId) -> Result<bool, DbError>;
}

impl AccountQueries for rusqlite::Transaction<'_> {
    fn load_account(&self, account_id: &AccountId) -> Result<Option<AccountEntry>, DbError> {
        let account_str = account_id_to_string(account_id);

        let mut stmt = self.prepare_cached(
            "SELECT data FROM accounts WHERE accountid = ?"
        )?;

        let result = stmt.query_row([&account_str], |row| {
            let data: Vec<u8> = row.get(0)?;
            Ok(data)
        });

        match result {
            Ok(data) => {
                let entry = AccountEntry::from_xdr(&data, stellar_xdr::Limits::none())?;
                Ok(Some(entry))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn store_account(&self, entry: &AccountEntry, last_modified: u32) -> Result<(), DbError> {
        let account_str = account_id_to_string(&entry.account_id);
        let data = entry.to_xdr(stellar_xdr::Limits::none())?;

        self.execute(
            "INSERT OR REPLACE INTO accounts
             (accountid, balance, seqnum, numsubentries, flags, thresholds, lastmodified, data)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rusqlite::params![
                account_str,
                entry.balance,
                entry.seq_num.0,
                entry.num_sub_entries,
                entry.flags,
                hex::encode(&entry.thresholds.0),
                last_modified,
                data,
            ],
        )?;
        Ok(())
    }

    // ... other methods
}
```

#### Ledger Queries

```rust
use stellar_xdr::curr::LedgerHeader;

pub trait LedgerQueries {
    fn load_ledger_header(&self, seq: u32) -> Result<Option<LedgerHeader>, DbError>;
    fn load_latest_ledger(&self) -> Result<Option<LedgerHeader>, DbError>;
    fn store_ledger_header(&self, header: &LedgerHeader) -> Result<(), DbError>;
    fn get_ledger_hash(&self, seq: u32) -> Result<Option<Hash256>, DbError>;
}
```

### 3.6 Persistent State

```rust
/// Keys for persistent state storage
pub mod state_keys {
    pub const LAST_CLOSED_LEDGER: &str = "lastclosedledger";
    pub const HISTORY_ARCHIVE_STATE: &str = "historyarchivestate";
    pub const DATABASE_SCHEMA: &str = "databaseschema";
    pub const NETWORK_PASSPHRASE: &str = "networkpassphrase";
    pub const LEDGER_UPGRADE_VERSION: &str = "ledgerupgradeversion";
    pub const SCP_STATE: &str = "scpstate";
}

pub trait StateQueries {
    fn get_state(&self, key: &str) -> Result<Option<String>, DbError>;
    fn set_state(&self, key: &str, value: &str) -> Result<(), DbError>;
    fn delete_state(&self, key: &str) -> Result<(), DbError>;
}
```

### 3.7 Error Types

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("Connection pool error: {0}")]
    Pool(#[from] r2d2::Error),

    #[error("XDR error: {0}")]
    Xdr(#[from] stellar_xdr::Error),

    #[error("Schema migration failed: {0}")]
    Migration(String),

    #[error("Data not found: {0}")]
    NotFound(String),

    #[error("Data integrity error: {0}")]
    Integrity(String),
}
```

## 4. Schema Migration Strategy

```rust
pub struct Migrator {
    migrations: Vec<Migration>,
}

pub struct Migration {
    pub version: i32,
    pub description: &'static str,
    pub up: &'static str,
    pub down: &'static str,
}

impl Migrator {
    pub fn run(&self, conn: &Connection) -> Result<(), DbError> {
        let current = self.current_version(conn)?;

        for migration in &self.migrations {
            if migration.version > current {
                tracing::info!(
                    version = migration.version,
                    desc = migration.description,
                    "Running migration"
                );
                conn.execute_batch(migration.up)?;
                self.set_version(conn, migration.version)?;
            }
        }

        Ok(())
    }
}
```

## 5. Tests to Port from stellar-core

From database-related tests:
- Account CRUD operations
- Trustline operations
- Offer management
- Transaction history queries
- Schema migration tests
- Concurrent access tests

## 6. Performance Considerations

1. **Connection Pooling**: Use r2d2 for connection pooling
2. **Prepared Statements**: Cache prepared statements with `prepare_cached`
3. **Batch Operations**: Use transactions for bulk inserts
4. **Indexes**: Ensure proper indexes for common queries
5. **WAL Mode**: Enable WAL mode for better concurrent performance

```rust
impl Database {
    fn configure_connection(conn: &Connection) -> Result<(), DbError> {
        conn.execute_batch(r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -64000;  -- 64MB cache
            PRAGMA foreign_keys = ON;
            PRAGMA temp_store = MEMORY;
        "#)?;
        Ok(())
    }
}
```
