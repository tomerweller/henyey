//! SHA-256 hashing utilities.
//!
//! This module provides SHA-256 hash computation in both single-shot and
//! streaming modes. All functions return [`Hash256`], a 32-byte hash value.
//!
//! # Single-shot Hashing
//!
//! For hashing data that is available all at once:
//!
//! ```
//! use stellar_core_crypto::sha256;
//!
//! let hash = sha256(b"hello world");
//! ```
//!
//! # Streaming Hashing
//!
//! For hashing data that arrives in chunks (e.g., reading from a file):
//!
//! ```
//! use stellar_core_crypto::Sha256Hasher;
//!
//! let mut hasher = Sha256Hasher::new();
//! hasher.update(b"hello ");
//! hasher.update(b"world");
//! let hash = hasher.finalize();
//! ```

use sha2::{Digest, Sha256};
use stellar_core_common::Hash256;

/// Computes the SHA-256 hash of the given data.
///
/// This is a convenience function for single-shot hashing. For streaming
/// hashing of large or chunked data, use [`Sha256Hasher`] instead.
///
/// # Example
///
/// ```
/// use stellar_core_crypto::sha256;
///
/// let hash = sha256(b"stellar");
/// assert_eq!(hash.as_bytes().len(), 32);
/// ```
pub fn sha256(data: &[u8]) -> Hash256 {
    Hash256::hash(data)
}

/// Computes the SHA-256 hash of multiple data chunks.
///
/// This is equivalent to concatenating all chunks and hashing the result,
/// but avoids the memory allocation of creating an intermediate buffer.
///
/// # Example
///
/// ```
/// use stellar_core_crypto::{sha256, sha256_multi};
///
/// let hash1 = sha256(b"helloworld");
/// let hash2 = sha256_multi(&[b"hello", b"world"]);
/// assert_eq!(hash1, hash2);
/// ```
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

/// A streaming SHA-256 hasher for incremental hash computation.
///
/// Use this when you need to hash data that is not available all at once,
/// such as when reading from a stream or processing data in chunks.
///
/// # Example
///
/// ```
/// use stellar_core_crypto::Sha256Hasher;
///
/// let mut hasher = Sha256Hasher::new();
/// hasher.update(b"chunk 1");
/// hasher.update(b"chunk 2");
/// let hash = hasher.finalize();
/// ```
pub struct Sha256Hasher {
    inner: Sha256,
}

impl Sha256Hasher {
    /// Creates a new SHA-256 hasher.
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    /// Feeds data into the hasher.
    ///
    /// This method can be called multiple times to incrementally add data.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Consumes the hasher and returns the computed hash.
    ///
    /// After calling this method, the hasher cannot be used again.
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
