//! Connection pool management.

use crate::error::DbError;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;

/// Pooled database connection.
pub type PooledConnection = r2d2::PooledConnection<SqliteConnectionManager>;

/// Database connection pool.
pub struct Database {
    pub(crate) pool: Pool<SqliteConnectionManager>,
}

impl Database {
    /// Get a connection from the pool.
    pub fn connection(&self) -> Result<PooledConnection, DbError> {
        self.pool.get().map_err(DbError::from)
    }

    /// Execute a function within a transaction.
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

    /// Execute a function with a connection.
    pub fn with_connection<T, F>(&self, f: F) -> Result<T, DbError>
    where
        F: FnOnce(&Connection) -> Result<T, DbError>,
    {
        let conn = self.connection()?;
        f(&conn)
    }
}

impl Clone for Database {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
        }
    }
}
