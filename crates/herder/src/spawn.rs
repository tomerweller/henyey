//! Spawn-blocking helpers with structured error logging.
//!
//! Re-exports [`henyey_common::spawn`] helpers for backward compatibility.
//! New callers should use `henyey_common::{spawn_blocking_logged, await_blocking_logged}`
//! directly.

pub use henyey_common::spawn::{await_blocking_logged, spawn_blocking_logged};
