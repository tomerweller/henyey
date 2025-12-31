//! Hashing utilities.

use sha2::{Digest, Sha256};
use stellar_core_common::Hash256;

/// Compute SHA-256 hash of data.
pub fn sha256(data: &[u8]) -> Hash256 {
    Hash256::hash(data)
}

/// Compute SHA-256 hash of multiple data chunks.
pub fn sha256_multi(chunks: &[&[u8]]) -> Hash256 {
    let mut hasher = Sha256::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash256(bytes)
}

/// A streaming SHA-256 hasher.
pub struct Sha256Hasher {
    inner: Sha256,
}

impl Sha256Hasher {
    /// Create a new hasher.
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    /// Update the hasher with data.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return the hash.
    pub fn finalize(self) -> Hash256 {
        let result = self.inner.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Hash256(bytes)
    }
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        // Test vector from NIST
        let hash = sha256(b"abc");
        assert_eq!(
            hash.to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        assert_eq!(
            hash.to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_multi() {
        let hash1 = sha256(b"helloworld");
        let hash2 = sha256_multi(&[b"hello", b"world"]);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_streaming_hasher() {
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"hello");
        hasher.update(b"world");
        let hash = hasher.finalize();

        assert_eq!(hash, sha256(b"helloworld"));
    }
}
