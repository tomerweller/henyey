//! Pure Rust cryptographic primitives for rs-stellar-core.
//!
//! This crate provides all cryptographic operations needed by Stellar Core:
//! - Ed25519 signatures
//! - SHA-256 hashing
//! - Stellar key encoding (StrKey)
//! - Random number generation
//!
//! All implementations are pure Rust with no C/C++ dependencies.

mod error;
mod hash;
mod keys;
mod random;
mod sealed_box;
mod short_hash;
mod signature;
mod strkey;

pub use error::CryptoError;
pub use hash::*;
pub use keys::*;
pub use random::*;
pub use sealed_box::*;
pub use short_hash::*;
pub use signature::*;
pub use strkey::*;

// Re-export Hash256 from common for convenience
pub use stellar_core_common::Hash256;
