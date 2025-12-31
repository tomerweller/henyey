//! Common types for rs-stellar-core.

use sha2::{Digest, Sha256};
use std::fmt;

/// 32-byte SHA-256 hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    /// Zero hash.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Hash arbitrary data.
    pub fn hash(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    /// Hash XDR-encoded data.
    pub fn hash_xdr<T: stellar_xdr::curr::WriteXdr>(value: &T) -> Result<Self, stellar_xdr::curr::Error> {
        let bytes = value.to_xdr(stellar_xdr::curr::Limits::none())?;
        Ok(Self::hash(&bytes))
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create from a hex string.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Check if this is the zero hash.
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
