//! Database error types.

use thiserror::Error;

/// Database errors.
#[derive(Error, Debug)]
pub enum DbError {
    /// SQLite error.
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// Connection pool error.
    #[error("Pool error: {0}")]
    Pool(#[from] r2d2::Error),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// XDR error.
    #[error("XDR error: {0}")]
    Xdr(#[from] stellar_xdr::curr::Error),

    /// Data not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// Data integrity error.
    #[error("Integrity error: {0}")]
    Integrity(String),

    /// Migration error.
    #[error("Migration error: {0}")]
    Migration(String),
}
