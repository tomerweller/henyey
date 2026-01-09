//! Pure Rust cryptographic primitives for rs-stellar-core.
//!
//! This crate provides all cryptographic operations needed by Stellar Core,
//! implemented entirely in Rust with no C/C++ dependencies (no libsodium).
//!
//! # Features
//!
//! - **Ed25519 signatures**: Key generation, signing, and verification via [`SecretKey`] and [`PublicKey`]
//! - **SHA-256 hashing**: Single-shot ([`sha256`]) and streaming ([`Sha256Hasher`]) hash computation
//! - **BLAKE2 hashing**: Single-shot ([`blake2`]) and streaming ([`Blake2Hasher`]) hash computation
//! - **HMAC-SHA256**: Message authentication via [`hmac_sha256`] and [`hmac_sha256_verify`]
//! - **HKDF**: Key derivation via [`hkdf_extract`], [`hkdf_expand`], and [`hkdf`]
//! - **XDR hashing**: [`xdr_sha256`] and [`xdr_blake2`] for hashing XDR-encoded values
//! - **StrKey encoding**: Stellar's base32 key format for account IDs, secret seeds, and more
//! - **Short hashing**: SipHash-2-4 for deterministic ordering in bucket lists and ledger state
//! - **Sealed boxes**: Curve25519-based encryption for survey payloads
//! - **Curve25519 ECDH**: Key exchange for P2P overlay authentication via [`Curve25519Secret`] and [`Curve25519Public`]
//! - **Secure random**: Cryptographically secure random number generation
//!
//! # Design Goals
//!
//! This crate is designed to produce deterministic, bit-compatible results with
//! the C++ stellar-core implementation. Key material is handled via explicit types
//! that provide safety guarantees:
//!
//! - [`SecretKey`] is zeroized on drop
//! - [`PublicKey`] displays as a StrKey (G...) in debug output
//! - XDR hashing utilities ensure canonical byte ordering
//!
//! # Example
//!
//! ```
//! use stellar_core_crypto::{SecretKey, sha256};
//!
//! // Generate a new keypair
//! let secret = SecretKey::generate();
//! let public = secret.public_key();
//!
//! // Sign a message
//! let message = b"hello stellar";
//! let signature = secret.sign(message);
//!
//! // Verify the signature
//! assert!(public.verify(message, &signature).is_ok());
//!
//! // Hash some data
//! let hash = sha256(b"stellar");
//! ```

mod curve25519;
mod error;
mod hash;
pub mod hex;
mod keys;
mod random;
mod sealed_box;
mod short_hash;
mod signer_key;
mod signature;
mod strkey;

pub use curve25519::*;
pub use error::CryptoError;
pub use hash::*;
pub use keys::*;
pub use random::*;
pub use sealed_box::*;
pub use short_hash::*;
pub use signer_key::*;
pub use signature::*;
pub use strkey::*;

// Re-export Hash256 from common for convenience
pub use stellar_core_common::Hash256;
