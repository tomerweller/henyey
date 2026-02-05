//! Error types for ledger operations.
//!
//! This module defines [`LedgerError`], the unified error type for all
//! ledger-related operations. Errors are categorized by their source
//! and severity to aid in debugging and error handling.

use thiserror::Error;

/// Errors that can occur during ledger operations.
///
/// This enum covers all error conditions that can arise during ledger
/// management, including initialization, ledger close, state access,
/// and validation failures.
///
/// # Error Categories
///
/// - **State errors**: `NotInitialized`, `AlreadyInitialized`, `EntryNotFound`
/// - **Validation errors**: `InvalidSequence`, `HashMismatch`, `InvalidHeaderChain`
/// - **Close errors**: `InvalidLedgerClose`, `DuplicateEntry`, `MissingEntry`
/// - **External errors**: `Database`, `Bucket`, `Xdr`
/// - **Internal errors**: `Serialization`, `Snapshot`, `Internal`
#[derive(Debug, Error)]
pub enum LedgerError {
    /// A requested ledger entry was not found.
    ///
    /// This can occur when loading entries that don't exist in the
    /// bucket list or snapshot cache.
    #[error("entry not found")]
    EntryNotFound,

    /// Ledger sequence number doesn't match expected value.
    ///
    /// This typically indicates an attempt to close a ledger out of order
    /// or a mismatch between expected and actual ledger sequences.
    #[error("invalid ledger sequence: expected {expected}, got {actual}")]
    InvalidSequence {
        /// The expected ledger sequence.
        expected: u32,
        /// The actual ledger sequence received.
        actual: u32,
    },

    /// Cryptographic hash mismatch.
    ///
    /// Indicates data corruption or an attempt to apply changes to
    /// the wrong ledger state. This is a critical error.
    #[error("ledger hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// The expected hash (hex-encoded).
        expected: String,
        /// The actual computed hash (hex-encoded).
        actual: String,
    },

    /// Invalid header chain linkage.
    ///
    /// The previous_ledger_hash or skip list entries don't match
    /// the expected values for chain continuity.
    #[error("invalid header chain: {0}")]
    InvalidHeaderChain(String),

    /// Error from bucket list operations.
    #[error("bucket error: {0}")]
    Bucket(#[from] stellar_core_bucket::BucketError),

    /// XDR encoding or decoding error.
    #[error("XDR error: {0}")]
    Xdr(#[from] stellar_xdr::curr::Error),

    /// Generic serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Operation attempted on uninitialized ledger manager.
    ///
    /// The ledger manager must be initialized via `initialize_from_buckets`
    /// before ledger close operations can begin.
    #[error("ledger not initialized")]
    NotInitialized,

    /// Attempted to initialize an already-initialized ledger manager.
    ///
    /// Use `reset_for_catchup` then `initialize_from_buckets` to reset state if needed.
    #[error("ledger already initialized")]
    AlreadyInitialized,

    /// Invalid ledger close operation.
    #[error("invalid ledger close: {0}")]
    InvalidLedgerClose(String),

    /// Attempted to create an entry that already exists.
    #[error("duplicate entry: {0}")]
    DuplicateEntry(String),

    /// Attempted to update or delete an entry that doesn't exist.
    #[error("missing entry for update/delete: {0}")]
    MissingEntry(String),

    /// Snapshot-related error.
    #[error("snapshot error: {0}")]
    Snapshot(String),

    /// Internal error (indicates a bug).
    ///
    /// These errors should not occur during normal operation and
    /// indicate a logic error in the implementation.
    #[error("internal error: {0}")]
    Internal(String),

    /// Invalid entry type or state.
    ///
    /// Indicates an entry has an unexpected type or is in an invalid state
    /// for the requested operation.
    #[error("invalid entry: {0}")]
    InvalidEntry(String),

    /// Invalid ledger sequence for state update.
    ///
    /// Ledger sequences must progress by exactly one for state updates.
    #[error("invalid ledger sequence: expected {expected}, got {actual}")]
    InvalidLedgerSequence {
        /// The expected ledger sequence.
        expected: u32,
        /// The actual ledger sequence received.
        actual: u32,
    },
}
