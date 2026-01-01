//! Sealed box encryption helpers for survey payloads.

use crypto_box::{PublicKey as CurvePublicKey, SecretKey as CurveSecretKey};
use rand::rngs::OsRng;

use crate::{CryptoError, PublicKey, SecretKey};

/// Encrypt a payload to the recipient's Ed25519 public key.
pub fn seal_to_public_key(recipient: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let curve_pk = CurvePublicKey::from(recipient.to_curve25519_bytes());
    let mut rng = OsRng;
    curve_pk
        .seal(&mut rng, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Encrypt a payload to a Curve25519 public key.
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

/// Decrypt a sealed payload using the recipient's Ed25519 secret key.
pub fn open_from_secret_key(recipient: &SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let curve_sk = CurveSecretKey::from(recipient.to_curve25519_bytes());
    curve_sk
        .unseal(ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Decrypt a sealed payload using a Curve25519 secret key.
pub fn open_from_curve25519_secret_key(
    recipient: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let curve_sk = CurveSecretKey::from(*recipient);
    curve_sk
        .unseal(ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}
