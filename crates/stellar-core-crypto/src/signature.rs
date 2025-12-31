//! Signature utilities.

use crate::error::CryptoError;
use crate::keys::{PublicKey, SecretKey, Signature};
use stellar_core_common::Hash256;

/// Sign data with a secret key.
pub fn sign(secret_key: &SecretKey, data: &[u8]) -> Signature {
    secret_key.sign(data)
}

/// Verify a signature.
pub fn verify(public_key: &PublicKey, data: &[u8], signature: &Signature) -> Result<(), CryptoError> {
    public_key.verify(data, signature)
}

/// A signed message with its signature and public key hint.
#[derive(Debug, Clone)]
pub struct SignedMessage {
    /// The message that was signed.
    pub message: Vec<u8>,
    /// The signature.
    pub signature: Signature,
    /// Hint (last 4 bytes of public key).
    pub hint: [u8; 4],
}

impl SignedMessage {
    /// Create a new signed message.
    pub fn new(secret_key: &SecretKey, message: Vec<u8>) -> Self {
        let signature = secret_key.sign(&message);
        let public_key = secret_key.public_key();
        let key_bytes = public_key.as_bytes();
        let hint = [key_bytes[28], key_bytes[29], key_bytes[30], key_bytes[31]];

        Self {
            message,
            signature,
            hint,
        }
    }

    /// Verify the signature with a known public key.
    pub fn verify(&self, public_key: &PublicKey) -> Result<(), CryptoError> {
        // Check hint matches
        let key_bytes = public_key.as_bytes();
        let expected_hint = [key_bytes[28], key_bytes[29], key_bytes[30], key_bytes[31]];
        if self.hint != expected_hint {
            return Err(CryptoError::InvalidSignature);
        }

        public_key.verify(&self.message, &self.signature)
    }
}

/// Compute the signature hint (last 4 bytes of public key).
pub fn signature_hint(public_key: &PublicKey) -> [u8; 4] {
    let key_bytes = public_key.as_bytes();
    [key_bytes[28], key_bytes[29], key_bytes[30], key_bytes[31]]
}

/// Sign a hash.
pub fn sign_hash(secret_key: &SecretKey, hash: &Hash256) -> Signature {
    secret_key.sign(hash.as_bytes())
}

/// Verify a hash signature.
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
