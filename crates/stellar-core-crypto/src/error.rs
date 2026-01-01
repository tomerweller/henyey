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

    /// Encryption failed.
    #[error("encryption failed")]
    EncryptionFailed,

    /// Decryption failed.
    #[error("decryption failed")]
    DecryptionFailed,

    /// XDR encoding error.
    #[error("XDR error: {0}")]
    Xdr(#[from] stellar_xdr::curr::Error),

    /// Short hash seed conflict.
    #[error("short hash already seeded with {existing}, cannot reseed with {requested}")]
    ShortHashSeedConflict { existing: u32, requested: u32 },
}
