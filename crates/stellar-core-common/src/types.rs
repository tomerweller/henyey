//! Common types for rs-stellar-core.
//!
//! This module provides fundamental types used throughout the codebase,
//! particularly the [`Hash256`] type for cryptographic hashes.

use sha2::{Digest, Sha256};
use std::fmt;

/// A 32-byte SHA-256 hash.
///
/// This is the canonical hash type used throughout Stellar for ledger hashes,
/// transaction hashes, network IDs, and other cryptographic identifiers.
///
/// # Examples
///
/// ```rust
/// use stellar_core_common::Hash256;
///
/// // Hash some data
/// let hash = Hash256::hash(b"hello world");
/// assert!(!hash.is_zero());
///
/// // Convert to/from hex
/// let hex_str = hash.to_hex();
/// let parsed = Hash256::from_hex(&hex_str).unwrap();
/// assert_eq!(hash, parsed);
///
/// // Create from raw bytes
/// let zeros = Hash256::from_bytes([0u8; 32]);
/// assert!(zeros.is_zero());
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    /// The zero hash (all bytes are 0x00).
    ///
    /// This is commonly used as a sentinel value or placeholder.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Compute the SHA-256 hash of arbitrary data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use stellar_core_common::Hash256;
    ///
    /// let hash = Hash256::hash(b"test data");
    /// assert_eq!(hash.as_bytes().len(), 32);
    /// ```
    pub fn hash(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    /// Compute the SHA-256 hash of XDR-encoded data.
    ///
    /// This is a convenience method that first serializes the value to XDR format
    /// and then computes its hash. This is the standard way to hash Stellar
    /// protocol objects.
    ///
    /// # Errors
    ///
    /// Returns an error if XDR serialization fails.
    pub fn hash_xdr<T: stellar_xdr::curr::WriteXdr>(
        value: &T,
    ) -> Result<Self, stellar_xdr::curr::Error> {
        let bytes = value.to_xdr(stellar_xdr::curr::Limits::none())?;
        Ok(Self::hash(&bytes))
    }

    /// Returns a reference to the underlying 32-byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Creates a `Hash256` from a 32-byte array.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Creates a `Hash256` from a hexadecimal string.
    ///
    /// The string must be exactly 64 hex characters (representing 32 bytes).
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not valid hex or not exactly 64 characters.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use stellar_core_common::Hash256;
    ///
    /// let hash = Hash256::from_hex(
    ///     "0000000000000000000000000000000000000000000000000000000000000000"
    /// ).unwrap();
    /// assert!(hash.is_zero());
    /// ```
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Converts the hash to a lowercase hexadecimal string.
    ///
    /// The resulting string is always 64 characters long.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Returns `true` if this is the zero hash.
    ///
    /// This is useful for checking sentinel values or uninitialized hashes.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({})", self.to_hex())
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl From<stellar_xdr::curr::Hash> for Hash256 {
    fn from(hash: stellar_xdr::curr::Hash) -> Self {
        Self(hash.0)
    }
}

impl From<Hash256> for stellar_xdr::curr::Hash {
    fn from(hash: Hash256) -> Self {
        stellar_xdr::curr::Hash(hash.0)
    }
}

impl From<[u8; 32]> for Hash256 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash256_hash() {
        let hash = Hash256::hash(b"hello");
        assert!(!hash.is_zero());

        // Same input should produce same hash
        let hash2 = Hash256::hash(b"hello");
        assert_eq!(hash, hash2);

        // Different input should produce different hash
        let hash3 = Hash256::hash(b"world");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_hash256_hex() {
        let hash = Hash256::hash(b"test");
        let hex = hash.to_hex();
        let parsed = Hash256::from_hex(&hex).unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn test_hash256_zero() {
        assert!(Hash256::ZERO.is_zero());
        assert!(!Hash256::hash(b"test").is_zero());
    }
}
