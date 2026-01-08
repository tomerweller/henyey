//! Error types for SCP operations.
//!
//! This module defines the error types that can occur during SCP consensus
//! operations, including message validation failures, quorum set issues,
//! and internal state errors.

use thiserror::Error;

/// Errors that can occur during SCP operations.
///
/// These errors represent various failure modes in the SCP consensus protocol,
/// from invalid messages to internal state inconsistencies.
#[derive(Debug, Error)]
pub enum ScpError {
    /// The SCP message is malformed or invalid.
    ///
    /// This can occur when:
    /// - The message structure doesn't match the expected format
    /// - Required fields are missing or have invalid values
    /// - The message type is unknown or unexpected
    #[error("invalid SCP message: {0}")]
    InvalidMessage(String),

    /// The quorum set configuration is invalid.
    ///
    /// This can occur when:
    /// - Threshold exceeds the number of validators
    /// - Nesting level exceeds the maximum allowed depth
    /// - Duplicate validators are present
    /// - The quorum set would not provide safety guarantees
    #[error("invalid quorum set: {0}")]
    InvalidQuorumSet(String),

    /// The envelope signature failed verification.
    ///
    /// Each SCP envelope must be signed by the sending node.
    /// This error indicates the signature is missing, malformed,
    /// or doesn't match the envelope content.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// The value being proposed or voted on is invalid.
    ///
    /// The driver determines whether values are valid based on
    /// application-specific rules (e.g., transaction validity).
    #[error("value validation failed: {0}")]
    ValueValidationFailed(String),

    /// The requested slot was not found in the slot map.
    ///
    /// This typically means the slot hasn't been created yet
    /// or has been purged from memory.
    #[error("slot not found: {0}")]
    SlotNotFound(u64),

    /// An internal state error occurred.
    ///
    /// This indicates a bug or unexpected condition in the SCP
    /// implementation that should not occur during normal operation.
    #[error("internal state error: {0}")]
    InternalError(String),
}
