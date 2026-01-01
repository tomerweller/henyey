//! Error types for ledger operations.

use thiserror::Error;

/// Errors that can occur during ledger operations.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// Entry not found.
    #[error("entry not found")]
    EntryNotFound,

    /// Invalid ledger sequence.
    #[error("invalid ledger sequence: expected {expected}, got {actual}")]
    InvalidSequence { expected: u32, actual: u32 },

    /// Ledger hash mismatch.
    #[error("ledger hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    /// Invalid header chain.
    #[error("invalid header chain: {0}")]
    InvalidHeaderChain(String),

    /// Database error.
    #[error("database error: {0}")]
    Database(#[from] stellar_core_db::DbError),

    /// Bucket error.
    #[error("bucket error: {0}")]
    Bucket(#[from] stellar_core_bucket::BucketError),

    /// Invariant error.
    #[error("invariant error: {0}")]
    Invariant(#[from] stellar_core_invariant::InvariantError),

    /// XDR serialization error.
    #[error("XDR error: {0}")]
    Xdr(#[from] stellar_xdr::curr::Error),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Ledger not initialized.
    #[error("ledger not initialized")]
    NotInitialized,

    /// Ledger already initialized.
    #[error("ledger already initialized")]
    AlreadyInitialized,

    /// Invalid ledger close.
    #[error("invalid ledger close: {0}")]
    InvalidLedgerClose(String),

    /// Duplicate entry.
    #[error("duplicate entry: {0}")]
    DuplicateEntry(String),

    /// Missing entry.
    #[error("missing entry for update/delete: {0}")]
    MissingEntry(String),

    /// Snapshot error.
    #[error("snapshot error: {0}")]
    Snapshot(String),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}
