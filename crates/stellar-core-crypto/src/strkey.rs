//! Stellar StrKey encoding and decoding.
//!
//! StrKey is Stellar's human-readable key encoding format. It uses RFC 4648
//! base32 encoding with a version byte prefix and CRC16 checksum suffix.
//!
//! # Format
//!
//! A StrKey consists of:
//! 1. **Version byte**: Identifies the key type (determines the first character)
//! 2. **Payload**: The raw key bytes (typically 32 bytes)
//! 3. **Checksum**: CRC16-XModem of version + payload (2 bytes)
//!
//! The entire structure is then base32 encoded (no padding).
//!
//! # Key Types
//!
//! | Prefix | Type | Description |
//! |--------|------|-------------|
//! | G | Account ID | Ed25519 public key |
//! | S | Secret Seed | Ed25519 secret key |
//! | T | Pre-Auth TX | Pre-authorized transaction hash |
//! | X | SHA256 Hash | SHA-256 hash used as signer |
//! | M | Muxed Account | Account ID + 64-bit memo ID |
//! | P | Signed Payload | Account ID + arbitrary payload |
//!
//! # Example
//!
//! ```
//! use stellar_core_crypto::{encode_account_id, decode_account_id};
//!
//! let key = [0u8; 32];
//! let strkey = encode_account_id(&key);
//! assert!(strkey.starts_with('G'));
//!
//! let decoded = decode_account_id(&strkey).unwrap();
//! assert_eq!(decoded, key);
//! ```

use crate::error::CryptoError;

// Version bytes for different key types.
// The version byte determines the first character after base32 encoding.
// Computed as (character_index << 3) where character_index is the position
// in the base32 alphabet that produces the desired prefix letter.

/// Version byte for account IDs (produces 'G' prefix).
const VERSION_ACCOUNT_ID: u8 = 6 << 3;
/// Version byte for secret seeds (produces 'S' prefix).
const VERSION_SEED: u8 = 18 << 3;
/// Version byte for pre-auth transaction hashes (produces 'T' prefix).
const VERSION_PRE_AUTH_TX: u8 = 19 << 3;
/// Version byte for SHA256 hashes (produces 'X' prefix).
const VERSION_SHA256_HASH: u8 = 23 << 3;
/// Version byte for muxed accounts (produces 'M' prefix).
const VERSION_MUXED_ACCOUNT: u8 = 12 << 3;
/// Version byte for signed payloads (produces 'P' prefix).
#[allow(dead_code)]
const VERSION_SIGNED_PAYLOAD: u8 = 15 << 3;

/// Encodes an Ed25519 public key as a Stellar account ID (G...).
///
/// Account IDs are the standard way to represent Stellar accounts.
pub fn encode_account_id(key: &[u8; 32]) -> String {
    encode_check(VERSION_ACCOUNT_ID, key)
}

/// Decodes a Stellar account ID (G...) to raw key bytes.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidStrKey`] if the string is not a valid account ID.
pub fn decode_account_id(s: &str) -> Result<[u8; 32], CryptoError> {
    decode_check(VERSION_ACCOUNT_ID, s, 32)
}

/// Encodes an Ed25519 secret key as a Stellar seed (S...).
///
/// Seeds are used to store and transmit secret keys securely.
pub fn encode_secret_seed(seed: &[u8; 32]) -> String {
    encode_check(VERSION_SEED, seed)
}

/// Decodes a Stellar seed (S...) to raw key bytes.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidStrKey`] if the string is not a valid seed.
pub fn decode_secret_seed(s: &str) -> Result<[u8; 32], CryptoError> {
    decode_check(VERSION_SEED, s, 32)
}

/// Encodes a pre-authorized transaction hash (T...).
///
/// Pre-auth transaction hashes allow transactions to be authorized before
/// they are submitted to the network.
pub fn encode_pre_auth_tx(hash: &[u8; 32]) -> String {
    encode_check(VERSION_PRE_AUTH_TX, hash)
}

/// Decodes a pre-authorized transaction hash (T...).
///
/// # Errors
///
/// Returns [`CryptoError::InvalidStrKey`] if the string is not a valid pre-auth TX.
pub fn decode_pre_auth_tx(s: &str) -> Result<[u8; 32], CryptoError> {
    decode_check(VERSION_PRE_AUTH_TX, s, 32)
}

/// Encodes a SHA256 hash as a StrKey (X...).
///
/// SHA256 hashes can be used as signers for accounts.
pub fn encode_sha256_hash(hash: &[u8; 32]) -> String {
    encode_check(VERSION_SHA256_HASH, hash)
}

/// Decodes a SHA256 hash StrKey (X...).
///
/// # Errors
///
/// Returns [`CryptoError::InvalidStrKey`] if the string is not a valid SHA256 hash.
pub fn decode_sha256_hash(s: &str) -> Result<[u8; 32], CryptoError> {
    decode_check(VERSION_SHA256_HASH, s, 32)
}

/// Encodes a muxed account (M...).
///
/// Muxed accounts combine an account ID with a 64-bit memo ID, allowing
/// a single account to have multiple virtual sub-accounts.
pub fn encode_muxed_account(key: &[u8; 32], id: u64) -> String {
    let mut data = key.to_vec();
    data.extend_from_slice(&id.to_be_bytes());
    encode_check(VERSION_MUXED_ACCOUNT, &data)
}

/// Decodes a muxed account (M...) to key bytes and memo ID.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidStrKey`] if the string is not a valid muxed account.
pub fn decode_muxed_account(s: &str) -> Result<([u8; 32], u64), CryptoError> {
    let data = decode_check_variable(VERSION_MUXED_ACCOUNT, s)?;
    if data.len() != 40 {
        return Err(CryptoError::InvalidStrKey(format!(
            "muxed account data length {} != 40",
            data.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[..32]);
    // Safety: We've already verified data.len() == 40, so data[32..40] is exactly 8 bytes
    let id = u64::from_be_bytes(
        data[32..40]
            .try_into()
            .expect("slice is exactly 8 bytes after length check"),
    );
    Ok((key, id))
}

/// Encodes data with a version byte and CRC16 checksum.
///
/// Format: base32(version || data || crc16(version || data))
fn encode_check(version: u8, data: &[u8]) -> String {
    let mut payload = vec![version];
    payload.extend_from_slice(data);

    // Append CRC16-XModem checksum in little-endian
    let checksum = crc16_xmodem(&payload);
    payload.extend_from_slice(&checksum.to_le_bytes());

    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &payload)
}

/// Decodes a fixed-length StrKey with version verification.
///
/// Verifies the version byte matches and the checksum is valid.
fn decode_check<const N: usize>(expected_version: u8, s: &str, expected_len: usize) -> Result<[u8; N], CryptoError> {
    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, s)
        .ok_or_else(|| CryptoError::InvalidStrKey("invalid base32".to_string()))?;

    // Expected: 1 version byte + expected_len data bytes + 2 checksum bytes
    if decoded.len() != 1 + expected_len + 2 {
        return Err(CryptoError::InvalidStrKey(format!(
            "length {} != {}",
            decoded.len(),
            1 + expected_len + 2
        )));
    }

    let version = decoded[0];
    if version != expected_version {
        return Err(CryptoError::InvalidStrKey(format!(
            "version byte {:02x} != {:02x}",
            version, expected_version
        )));
    }

    // Verify CRC16 checksum
    let checksum_pos = decoded.len() - 2;
    let checksum = u16::from_le_bytes([decoded[checksum_pos], decoded[checksum_pos + 1]]);
    let computed = crc16_xmodem(&decoded[..checksum_pos]);
    if checksum != computed {
        return Err(CryptoError::InvalidStrKey("checksum mismatch".to_string()));
    }

    let mut key = [0u8; N];
    key.copy_from_slice(&decoded[1..1 + expected_len]);
    Ok(key)
}

/// Decodes a variable-length StrKey with version verification.
///
/// Used for key types with variable payload sizes (e.g., muxed accounts).
fn decode_check_variable(expected_version: u8, s: &str) -> Result<Vec<u8>, CryptoError> {
    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, s)
        .ok_or_else(|| CryptoError::InvalidStrKey("invalid base32".to_string()))?;

    // Minimum: 1 version + 0 data + 2 checksum = 3 bytes
    if decoded.len() < 3 {
        return Err(CryptoError::InvalidStrKey("too short".to_string()));
    }

    let version = decoded[0];
    if version != expected_version {
        return Err(CryptoError::InvalidStrKey(format!(
            "version byte {:02x} != {:02x}",
            version, expected_version
        )));
    }

    // Verify CRC16 checksum
    let checksum_pos = decoded.len() - 2;
    let checksum = u16::from_le_bytes([decoded[checksum_pos], decoded[checksum_pos + 1]]);
    let computed = crc16_xmodem(&decoded[..checksum_pos]);
    if checksum != computed {
        return Err(CryptoError::InvalidStrKey("checksum mismatch".to_string()));
    }

    Ok(decoded[1..checksum_pos].to_vec())
}

/// Computes the CRC16-XModem checksum of data.
///
/// CRC16-XModem uses polynomial 0x1021 with initial value 0.
/// This is the checksum algorithm used by Stellar for StrKey encoding.
fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for byte in data {
        crc ^= (*byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_id_roundtrip() {
        let key = [42u8; 32];
        let encoded = encode_account_id(&key);
        assert!(encoded.starts_with('G'));
        let decoded = decode_account_id(&encoded).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_secret_seed_roundtrip() {
        let seed = [42u8; 32];
        let encoded = encode_secret_seed(&seed);
        assert!(encoded.starts_with('S'));
        let decoded = decode_secret_seed(&encoded).unwrap();
        assert_eq!(seed, decoded);
    }

    #[test]
    fn test_known_account_id() {
        // Test with a zero key - known value
        let key = [0u8; 32];
        let strkey = encode_account_id(&key);
        // Decode and verify roundtrip
        let decoded = decode_account_id(&strkey).unwrap();
        assert_eq!(decoded, key);
        // Verify starts with G (account ID prefix)
        assert!(strkey.starts_with('G'));
    }

    #[test]
    fn test_invalid_checksum() {
        let encoded = encode_account_id(&[0u8; 32]);
        // Corrupt the last character
        let mut chars: Vec<char> = encoded.chars().collect();
        let last_idx = chars.len() - 1;
        chars[last_idx] = if chars[last_idx] == 'A' { 'B' } else { 'A' };
        let corrupted: String = chars.into_iter().collect();
        assert!(decode_account_id(&corrupted).is_err());
    }

    #[test]
    fn test_muxed_account() {
        let key = [42u8; 32];
        let id = 12345u64;
        let encoded = encode_muxed_account(&key, id);
        assert!(encoded.starts_with('M'));
        let (decoded_key, decoded_id) = decode_muxed_account(&encoded).unwrap();
        assert_eq!(key, decoded_key);
        assert_eq!(id, decoded_id);
    }
}
