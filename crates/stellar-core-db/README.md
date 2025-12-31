# stellar-core-db

Database abstraction layer for rs-stellar-core.

## Overview

Provides SQLite-based persistence for:

- Ledger headers and state
- Transaction history
- SCP consensus state
- Account and trustline data
- Contract data (Soroban)

## Features

- SQLite with WAL mode for performance
- Connection pooling via r2d2
- Automatic schema migrations
- Query traits for type-safe database access

## Usage

### Opening a Database

```rust
use stellar_core_db::Database;

// Open or create a database file
let db = Database::open("stellar.db")?;

// Or open in-memory for testing
let db = Database::open_in_memory()?;
```

### Querying Ledger Data

```rust
use stellar_core_db::{Database, LedgerQueries};

let db = Database::open("stellar.db")?;

// Get latest ledger sequence
let seq = db.get_latest_ledger_seq()?;

// Load a specific ledger header
let header = db.get_ledger_header(1000)?;

// Get ledger hash
let hash = db.get_ledger_hash(1000)?;
```

### Querying Accounts

```rust
use stellar_core_db::{Database, AccountQueries};

let db = Database::open("stellar.db")?;
let conn = db.connection()?;

// Load account by ID
let account = conn.load_account(&account_id)?;

// Store account
conn.store_account(&account_entry, last_modified)?;

// Delete account
conn.delete_account(&account_id)?;
```

### Transactions

```rust
use stellar_core_db::Database;

let db = Database::open("stellar.db")?;

db.transaction(|tx| {
    // All operations in this closure are atomic
    tx.execute("INSERT INTO ...", [])?;
    tx.execute("UPDATE ...", [])?;
    Ok(())
})?;
```

## Schema

The database schema includes tables for:

| Table | Description |
|-------|-------------|
| `storestate` | Key-value store for node state |
| `ledgerheaders` | Ledger header data |
| `accounts` | Account entries |
| `trustlines` | Trust line entries |
| `offers` | DEX offers |
| `accountdata` | Account data entries |
| `claimablebalance` | Claimable balances |
| `liquiditypool` | Liquidity pools |
| `contractdata` | Soroban contract data |
| `contractcode` | Soroban contract code |
| `configsettings` | Protocol config settings |
| `ttl` | Contract state TTL |
| `scpstate` | SCP consensus state |
| `scpquorums` | Quorum set configurations |

## Migrations

Schema migrations are handled automatically:

```rust
use stellar_core_db::Database;

let db = Database::open("stellar.db")?;

// Check current version
let version = db.schema_version()?;

// Upgrade to latest (usually automatic)
db.upgrade()?;
```

## Query Traits

Type-safe query traits:

- `LedgerQueries` - Ledger header operations
- `AccountQueries` - Account operations
- `TrustlineQueries` - Trustline operations
- `OfferQueries` - DEX offer operations
- `ScpQueries` - SCP state operations

Each trait is implemented for `rusqlite::Connection`.

## Configuration

SQLite is configured for optimal performance:

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = -64000;  -- 64MB cache
PRAGMA foreign_keys = ON;
PRAGMA temp_store = MEMORY;
```

## Dependencies

- `rusqlite` - SQLite bindings
- `r2d2` - Connection pooling
- `r2d2_sqlite` - SQLite pool adapter

## License

Apache 2.0
