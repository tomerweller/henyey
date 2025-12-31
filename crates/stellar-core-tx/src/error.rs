//! Error types for transaction operations.

use thiserror::Error;

/// Errors that can occur during transaction operations.
#[derive(Debug, Error)]
pub enum TxError {
    /// Transaction validation failed.
    #[error("transaction validation failed: {0}")]
    ValidationFailed(String),

    /// Invalid signature.
    #[error("invalid signature")]
    InvalidSignature,

    /// Insufficient fee.
    #[error("insufficient fee: required {required}, got {provided}")]
    InsufficientFee { required: i64, provided: i64 },

    /// Bad sequence number.
    #[error("bad sequence number: expected {expected}, got {actual}")]
    BadSequence { expected: i64, actual: i64 },

    /// Source account not found.
    #[error("source account not found")]
    SourceAccountNotFound,

    /// Insufficient balance.
    #[error("insufficient balance")]
    InsufficientBalance,

    /// Operation failed.
    #[error("operation failed: {0}")]
    OperationFailed(String),

    /// Soroban execution error.
    #[error("Soroban error: {0}")]
    Soroban(String),

    /// Ledger error.
    #[error("ledger error: {0}")]
    LedgerError(String),

    /// Crypto error.
    #[error("crypto error: {0}")]
    Crypto(#[from] stellar_core_crypto::CryptoError),

    /// XDR error.
    #[error("XDR error: {0}")]
    Xdr(#[from] stellar_xdr::curr::Error),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}
