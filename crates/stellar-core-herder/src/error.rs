//! Error types for Herder operations.

use thiserror::Error;

/// Errors that can occur during Herder operations.
#[derive(Debug, Error)]
pub enum HerderError {
    /// Transaction validation failed.
    #[error("transaction validation failed: {0}")]
    TransactionValidationFailed(String),

    /// Transaction queue full.
    #[error("transaction queue full")]
    QueueFull,

    /// SCP error.
    #[error("SCP error: {0}")]
    Scp(#[from] stellar_core_scp::ScpError),

    /// Not in validating state.
    #[error("not in validating state")]
    NotValidating,

    /// Ledger close error.
    #[error("ledger close error: {0}")]
    LedgerClose(String),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}
