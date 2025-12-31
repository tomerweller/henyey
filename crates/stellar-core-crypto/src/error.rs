//! Cryptographic error types.

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Invalid public key.
    #[error("invalid public key")]
    InvalidPublicKey,

    /// Invalid secret key.
    #[error("invalid secret key")]
    InvalidSecretKey,

    /// Invalid signature.
    #[error("invalid signature")]
    InvalidSignature,

    /// Invalid strkey encoding.
    #[error("invalid strkey encoding: {0}")]
    InvalidStrKey(String),

    /// Invalid hex encoding.
    #[error("invalid hex encoding")]
    InvalidHex,

    /// Invalid length.
    #[error("invalid length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },

    /// XDR encoding error.
    #[error("XDR error: {0}")]
    Xdr(#[from] stellar_xdr::curr::Error),
}
