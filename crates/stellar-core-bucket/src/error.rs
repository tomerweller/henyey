//! Error types for bucket operations.

use thiserror::Error;

/// Errors that can occur during bucket operations.
#[derive(Debug, Error)]
pub enum BucketError {
    /// Bucket file not found.
    #[error("bucket not found: {0}")]
    NotFound(String),

    /// Bucket hash mismatch.
    #[error("bucket hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    /// Bucket serialization error.
    #[error("bucket serialization error: {0}")]
    Serialization(String),

    /// Bucket merge error.
    #[error("bucket merge error: {0}")]
    Merge(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Database error.
    #[error("database error: {0}")]
    Database(#[from] stellar_core_db::DbError),
}
