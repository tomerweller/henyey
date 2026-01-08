//! Sealed box encryption for anonymous encrypted payloads.
//!
//! This module provides "sealed box" encryption, which allows encrypting a
//! message to a recipient's public key without revealing the sender's identity.
//! The primary use case in Stellar is encrypting survey response payloads.
//!
//! # How It Works
//!
//! Sealed boxes use X25519 key exchange combined with XSalsa20-Poly1305
//! authenticated encryption:
//!
//! 1. An ephemeral keypair is generated for each encryption
//! 2. X25519 key exchange derives a shared secret
//! 3. XSalsa20-Poly1305 encrypts and authenticates the message
//! 4. The ephemeral public key is prepended to the ciphertext
//!
//! This provides confidentiality and authenticity, but not sender authentication
//! (the sender is anonymous).
//!
//! # Ed25519 to Curve25519 Conversion
//!
//! Stellar uses Ed25519 keys, but sealed boxes require Curve25519 keys. This
//! module handles the conversion automatically when using Ed25519 keys, or
//! you can provide Curve25519 keys directly.
//!
//! # Example
//!
//! ```
//! use stellar_core_crypto::{SecretKey, seal_to_public_key, open_from_secret_key};
//!
//! let recipient_secret = SecretKey::generate();
//! let recipient_public = recipient_secret.public_key();
//!
//! // Encrypt a message
//! let plaintext = b"secret survey response";
//! let ciphertext = seal_to_public_key(&recipient_public, plaintext).unwrap();
//!
//! // Decrypt the message
//! let decrypted = open_from_secret_key(&recipient_secret, &ciphertext).unwrap();
//! assert_eq!(decrypted, plaintext);
//! ```

use crypto_box::{PublicKey as CurvePublicKey, SecretKey as CurveSecretKey};
use rand::rngs::OsRng;

use crate::{CryptoError, PublicKey, SecretKey};

/// Encrypts a payload to a recipient's Ed25519 public key.
///
/// The Ed25519 public key is converted to Curve25519 internally. The returned
/// ciphertext includes the ephemeral public key and authentication tag.
///
/// # Errors
///
/// Returns [`CryptoError::EncryptionFailed`] if encryption fails (rare, typically
/// only on RNG failure).
pub fn seal_to_public_key(recipient: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let curve_pk = CurvePublicKey::from(recipient.to_curve25519_bytes());
    let mut rng = OsRng;
    curve_pk
        .seal(&mut rng, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Encrypts a payload to a Curve25519 public key.
///
/// Use this when you already have a Curve25519 key rather than an Ed25519 key.
///
/// # Errors
///
/// Returns [`CryptoError::EncryptionFailed`] if encryption fails.
pub fn seal_to_curve25519_public_key(
    recipient: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let curve_pk = CurvePublicKey::from(*recipient);
    let mut rng = OsRng;
    curve_pk
        .seal(&mut rng, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Decrypts a sealed payload using the recipient's Ed25519 secret key.
///
/// The Ed25519 secret key is converted to Curve25519 internally.
///
/// # Errors
///
/// Returns [`CryptoError::DecryptionFailed`] if:
/// - The ciphertext was tampered with
/// - The wrong key was used
/// - The ciphertext is malformed
pub fn open_from_secret_key(recipient: &SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let curve_sk = CurveSecretKey::from(recipient.to_curve25519_bytes());
    curve_sk
        .unseal(ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Decrypts a sealed payload using a Curve25519 secret key.
///
/// Use this when you already have a Curve25519 key rather than an Ed25519 key.
///
/// # Errors
///
/// Returns [`CryptoError::DecryptionFailed`] if decryption fails.
pub fn open_from_curve25519_secret_key(
    recipient: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let curve_sk = CurveSecretKey::from(*recipient);
    curve_sk
        .unseal(ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}
