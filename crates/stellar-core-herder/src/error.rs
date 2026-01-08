//! Error types for Herder operations.
//!
//! This module defines the error types that can occur during Herder operations,
//! including transaction validation failures, SCP consensus errors, and internal
//! processing errors.

use thiserror::Error;

/// Errors that can occur during Herder operations.
///
/// The Herder can fail for various reasons including transaction validation issues,
/// capacity limits, SCP consensus problems, or internal state errors.
#[derive(Debug, Error)]
pub enum HerderError {
    /// Transaction validation failed.
    ///
    /// This occurs when a transaction fails basic structural validation,
    /// signature verification, or time bounds checking.
    #[error("transaction validation failed: {0}")]
    TransactionValidationFailed(String),

    /// Transaction queue is at capacity.
    ///
    /// The queue has reached its maximum size and cannot accept additional
    /// transactions without evicting lower-fee transactions.
    #[error("transaction queue full")]
    QueueFull,

    /// An error occurred in the SCP consensus layer.
    ///
    /// This wraps errors from the underlying SCP implementation, such as
    /// signature verification failures or invalid message handling.
    #[error("SCP error: {0}")]
    Scp(#[from] stellar_core_scp::ScpError),

    /// Operation requires validator mode but the node is not validating.
    ///
    /// Some operations (like triggering consensus) require the node to be
    /// configured as a validator with a secret key and quorum set.
    #[error("not in validating state")]
    NotValidating,

    /// An error occurred during ledger close processing.
    ///
    /// This can occur when applying a transaction set or computing the
    /// new ledger state after consensus.
    #[error("ledger close error: {0}")]
    LedgerClose(String),

    /// An internal error occurred.
    ///
    /// This is a catch-all for unexpected internal errors that don't fit
    /// other categories.
    #[error("internal error: {0}")]
    Internal(String),
}
