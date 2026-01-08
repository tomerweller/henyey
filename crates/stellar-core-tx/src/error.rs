//! Error types for transaction processing.
//!
//! This module defines the main error type [`TxError`] used throughout the crate
//! for handling failures in transaction validation, execution, and state operations.
//!
//! # Error Categories
//!
//! - **Validation errors**: Fee, sequence, signature, and structure issues
//! - **Execution errors**: Operation failures, Soroban errors
//! - **State errors**: Ledger access and crypto failures
//! - **Internal errors**: XDR serialization and unexpected conditions

use thiserror::Error;

/// Errors that can occur during transaction processing.
///
/// This enum covers all error conditions that can arise during transaction
/// validation, execution, and state management. It uses `thiserror` for
/// convenient error message formatting and trait implementations.
///
/// # Example
///
/// ```ignore
/// use stellar_core_tx::TxError;
///
/// fn process_tx() -> Result<(), TxError> {
///     // ... processing logic ...
///     Err(TxError::InsufficientFee {
///         required: 200,
///         provided: 100,
///     })
/// }
/// ```
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

    /// Account not found (with context).
    #[error("account not found: {0}")]
    AccountNotFound(String),

    /// Insufficient balance.
    #[error("insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: i64, available: i64 },

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
