//! Protocol-versioned Soroban host implementations.
//!
//! This module provides protocol-versioned implementations of the Soroban host
//! to ensure deterministic replay across protocol upgrades. Each protocol version
//! has its own implementation that uses the exact same soroban-env-host version
//! as stellar-core.

pub mod p24;
pub mod p25;
mod types;

pub use types::*;
