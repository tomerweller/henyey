//! Error types for SCP operations.

use thiserror::Error;

/// Errors that can occur during SCP operations.
#[derive(Debug, Error)]
pub enum ScpError {
    /// Invalid SCP message.
    #[error("invalid SCP message: {0}")]
    InvalidMessage(String),

    /// Invalid quorum set.
    #[error("invalid quorum set: {0}")]
    InvalidQuorumSet(String),

    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// Value validation failed.
    #[error("value validation failed: {0}")]
    ValueValidationFailed(String),

    /// Slot not found.
    #[error("slot not found: {0}")]
    SlotNotFound(u64),

    /// Internal state error.
    #[error("internal state error: {0}")]
    InternalError(String),
}
