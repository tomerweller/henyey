//! Common error types for rs-stellar-core.

use thiserror::Error;

/// Common result type for rs-stellar-core operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Common error type for rs-stellar-core.
#[derive(Error, Debug)]
pub enum Error {
    /// XDR encoding/decoding error.
    #[error("XDR error: {0}")]
    Xdr(#[from] stellar_xdr::curr::Error),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Invalid data.
    #[error("Invalid data: {0}")]
    InvalidData(String),

    /// Not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// Operation failed.
    #[error("Operation failed: {0}")]
    OperationFailed(String),
}
