//! Common types and utilities for rs-stellar-core.
//!
//! This crate provides shared types, traits, and utilities used across
//! all rs-stellar-core modules.

pub mod config;
pub mod error;
pub mod meta;
pub mod network;
pub mod protocol;
pub mod resource;
pub mod time;
pub mod types;

pub use config::Config;
pub use error::{Error, Result};
pub use meta::*;
pub use network::NetworkId;
pub use protocol::*;
pub use resource::*;
pub use types::*;

/// Re-export stellar-xdr for convenience
pub use stellar_xdr;
