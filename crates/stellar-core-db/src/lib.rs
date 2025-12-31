//! Database abstraction layer for rs-stellar-core.
//!
//! Provides SQLite-based persistence for ledger state, transaction history,
//! and SCP state.

pub mod error;
pub mod migrations;
pub mod pool;
pub mod queries;
pub mod schema;

pub use error::DbError;
pub use migrations::{run_migrations, verify_schema, needs_migration, CURRENT_VERSION};
pub use pool::{Database, PooledConnection};
pub use queries::*;

use std::path::Path;
use tracing::info;

/// Result type for database operations.
pub type Result<T> = std::result::Result<T, DbError>;

impl Database {
    /// Open a database at the given path, creating if necessary.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let manager = r2d2_sqlite::SqliteConnectionManager::file(path);
        let pool = r2d2::Pool::builder()
            .max_size(10)
            .build(manager)?;

        let db = Self { pool };
        db.initialize()?;
        Ok(db)
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self> {
        let manager = r2d2_sqlite::SqliteConnectionManager::memory();
        let pool = r2d2::Pool::builder()
            .max_size(1)
            .build(manager)?;

        let db = Self { pool };
        db.initialize()?;
        Ok(db)
    }

    fn initialize(&self) -> Result<()> {
        let conn = self.connection()?;

        // Configure SQLite for performance
        conn.execute_batch(r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -64000;
            PRAGMA foreign_keys = ON;
            PRAGMA temp_store = MEMORY;
        "#)?;

        // Check if this is a fresh database
        let tables_exist: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='storestate'",
            [],
            |row| row.get(0),
        ).unwrap_or(false);

        if tables_exist {
            // Existing database - check version and run migrations if needed
            if migrations::needs_migration(&conn)? {
                info!("Database requires migration");
                migrations::run_migrations(&conn)?;
            }
            migrations::verify_schema(&conn)?;
        } else {
            // Fresh database - initialize with current schema
            migrations::initialize_schema(&conn)?;
        }

        Ok(())
    }

    /// Upgrade the database schema to the latest version.
    ///
    /// This should be called when running the "upgrade-db" command.
    pub fn upgrade(&self) -> Result<()> {
        let conn = self.connection()?;
        migrations::run_migrations(&conn)
    }

    /// Get the current schema version.
    pub fn schema_version(&self) -> Result<i32> {
        let conn = self.connection()?;
        migrations::get_schema_version(&conn)
    }

    /// Get the latest ledger sequence number.
    pub fn get_latest_ledger_seq(&self) -> Result<Option<u32>> {
        self.with_connection(|conn| {
            use queries::LedgerQueries;
            conn.get_latest_ledger_seq()
        })
    }

    /// Get a ledger header by sequence number.
    pub fn get_ledger_header(&self, seq: u32) -> Result<Option<stellar_xdr::curr::LedgerHeader>> {
        self.with_connection(|conn| {
            use queries::LedgerQueries;
            conn.load_ledger_header(seq)
        })
    }

    /// Get a ledger hash by sequence number.
    pub fn get_ledger_hash(&self, seq: u32) -> Result<Option<stellar_core_common::Hash256>> {
        self.with_connection(|conn| {
            use queries::LedgerQueries;
            conn.get_ledger_hash(seq)
        })
    }
}
