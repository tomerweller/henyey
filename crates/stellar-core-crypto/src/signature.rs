//! Signature utilities and helpers.
//!
//! This module provides convenience functions for signing and verification,
//! as well as the [`SignedMessage`] type for bundling a message with its
//! signature and signer hint.
//!
//! # Signature Hints
//!
//! Stellar uses "signature hints" to help identify which key created a
//! signature without storing the full public key. A hint is the last 4 bytes
//! of the public key. When verifying, the hint can quickly filter candidate
//! keys before performing the expensive signature verification.

use crate::error::CryptoError;
use crate::keys::{PublicKey, SecretKey, Signature};
use stellar_core_common::Hash256;

/// Signs arbitrary data with a secret key.
///
/// This is a convenience wrapper around [`SecretKey::sign`].
pub fn sign(secret_key: &SecretKey, data: &[u8]) -> Signature {
    secret_key.sign(data)
}

/// Verifies a signature over data.
///
/// This is a convenience wrapper around [`PublicKey::verify`].
///
/// # Errors
///
/// Returns [`CryptoError::InvalidSignature`] if verification fails.
pub fn verify(public_key: &PublicKey, data: &[u8], signature: &Signature) -> Result<(), CryptoError> {
    public_key.verify(data, signature)
}

/// A message bundled with its signature and a hint to identify the signer.
///
/// This type is useful when you need to transmit a signed message along with
/// enough information to verify it. The hint allows recipients to quickly
/// identify which key should be used for verification.
///
/// # Example
///
/// ```
/// use stellar_core_crypto::{SecretKey, SignedMessage};
///
/// let secret = SecretKey::generate();
/// let public = secret.public_key();
///
/// // Create a signed message
/// let signed = SignedMessage::new(&secret, b"hello".to_vec());
///
/// // Verify with the public key
/// assert!(signed.verify(&public).is_ok());
/// ```
#[derive(Debug, Clone)]
pub struct SignedMessage {
    /// The original message bytes.
    pub message: Vec<u8>,
    /// The Ed25519 signature over the message.
    pub signature: Signature,
    /// The signature hint (last 4 bytes of the signer's public key).
    pub hint: [u8; 4],
}

impl SignedMessage {
    /// Creates a new signed message.
    ///
    /// Signs the message with the provided secret key and extracts the hint
    /// from the corresponding public key.
    pub fn new(secret_key: &SecretKey, message: Vec<u8>) -> Self {
        let signature = secret_key.sign(&message);
        let public_key = secret_key.public_key();
        let hint = signature_hint(&public_key);

        Self {
            message,
            signature,
            hint,
        }
    }

    /// Verifies the signature against a public key.
    ///
    /// First checks that the hint matches the public key, then verifies
    /// the signature. This allows quick rejection of mismatched keys.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidSignature`] if:
    /// - The hint does not match the public key
    /// - The signature verification fails
    pub fn verify(&self, public_key: &PublicKey) -> Result<(), CryptoError> {
        // Check hint matches before doing expensive signature verification
        if self.hint != signature_hint(public_key) {
            return Err(CryptoError::InvalidSignature);
        }

        public_key.verify(&self.message, &self.signature)
    }
}

/// Computes the signature hint for a public key.
///
/// The hint is the last 4 bytes of the 32-byte public key. It is used in
/// Stellar to help identify signers without including the full public key.
pub fn signature_hint(public_key: &PublicKey) -> [u8; 4] {
    let key_bytes = public_key.as_bytes();
    [key_bytes[28], key_bytes[29], key_bytes[30], key_bytes[31]]
}

/// Signs a hash value.
///
/// This signs the raw 32 bytes of the hash. Use this when signing transaction
/// hashes or other pre-hashed data.
pub fn sign_hash(secret_key: &SecretKey, hash: &Hash256) -> Signature {
    secret_key.sign(hash.as_bytes())
}

/// Verifies a signature over a hash value.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidSignature`] if verification fails.
pub fn verify_hash(
    public_key: &PublicKey,
    hash: &Hash256,
    signature: &Signature,
) -> Result<(), CryptoError> {
    public_key.verify(hash.as_bytes(), signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let secret = SecretKey::generate();
        let public = secret.public_key();

        let message = b"test message";
        let sig = sign(&secret, message);

        assert!(verify(&public, message, &sig).is_ok());
        assert!(verify(&public, b"wrong", &sig).is_err());
    }

    #[test]
    fn test_signed_message() {
        let secret = SecretKey::generate();
        let public = secret.public_key();

        let signed = SignedMessage::new(&secret, b"hello".to_vec());
        assert!(signed.verify(&public).is_ok());

        // Wrong key should fail
        let other_secret = SecretKey::generate();
        let other_public = other_secret.public_key();
        assert!(signed.verify(&other_public).is_err());
    }

    #[test]
    fn test_signature_hint() {
        let secret = SecretKey::generate();
        let public = secret.public_key();

        let hint = signature_hint(&public);
        let key_bytes = public.as_bytes();

        assert_eq!(hint, [key_bytes[28], key_bytes[29], key_bytes[30], key_bytes[31]]);
    }

    #[test]
    fn test_sign_hash() {
        let secret = SecretKey::generate();
        let public = secret.public_key();

        let hash = Hash256::hash(b"test data");
        let sig = sign_hash(&secret, &hash);

        assert!(verify_hash(&public, &hash, &sig).is_ok());
    }
}
