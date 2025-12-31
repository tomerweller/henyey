//! Common types and utilities for rs-stellar-core.
//!
//! This crate provides shared types, traits, and utilities used across
//! all rs-stellar-core modules.

pub mod config;
pub mod error;
pub mod network;
pub mod time;
pub mod types;

pub use config::Config;
pub use error::{Error, Result};
pub use network::NetworkId;
pub use types::*;

/// Re-export stellar-xdr for convenience
pub use stellar_xdr;
