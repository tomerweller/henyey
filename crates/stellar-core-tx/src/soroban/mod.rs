//! Soroban smart contract integration.
//!
//! This module provides the integration layer between the transaction processor
//! and Soroban smart contract execution. It handles:
//!
//! - Budget tracking for CPU and memory consumption
//! - Storage interface for contract state (persistent and temporary)
//! - Event recording (contract events, system events, diagnostics)
//! - Host function execution via `soroban-env-host`
//!
//! # Architecture
//!
//! Soroban execution follows this pipeline:
//!
//! ```text
//! Transaction with InvokeHostFunction
//!            |
//!            v
//! +---------------------+
//! | Footprint Validation |  <- Verify declared read/write keys
//! +---------------------+
//!            |
//!            v
//! +---------------------+
//! | Build Storage Map    |  <- Load entries from bucket list
//! +---------------------+
//!            |
//!            v
//! +---------------------+
//! | Execute via e2e_invoke |  <- soroban-env-host execution
//! +---------------------+
//!            |
//!            v
//! +---------------------+
//! | Collect Changes      |  <- Storage changes, events, fees
//! +---------------------+
//!            |
//!            v
//! Apply to LedgerDelta
//! ```
//!
//! # Protocol Versioning
//!
//! The `protocol` submodule provides protocol-versioned host implementations.
//! Each protocol version uses the exact same `soroban-env-host` version as
//! C++ stellar-core to ensure deterministic replay:
//!
//! | Protocol | soroban-env-host Version |
//! |----------|-------------------------|
//! | 24       | `soroban-env-host-p24`  |
//! | 25+      | `soroban-env-host-p25`  |
//!
//! This versioning is critical because:
//! - Host function semantics may change between versions
//! - Cost model parameters differ per protocol
//! - PRNG behavior must match exactly for determinism
//!
//! # Key Components
//!
//! - [`SorobanConfig`]: Network configuration for Soroban execution including
//!   cost parameters, TTL limits, and fee configuration.
//!
//! - [`SorobanBudget`]: Tracks resource consumption (CPU, memory, I/O) against
//!   declared limits to enforce execution bounds.
//!
//! - [`SorobanStorage`]: Provides the storage interface for contract state,
//!   tracking reads and writes during execution.
//!
//! - [`execute_host_function`]: Main entry point for executing Soroban
//!   operations, handling protocol version dispatch.
//!
//! # Entry TTL and Archival
//!
//! Soroban entries (ContractData, ContractCode) have time-to-live (TTL) values:
//!
//! - **Temporary entries**: Short-lived, cheaper storage. Automatically deleted
//!   when TTL expires.
//!
//! - **Persistent entries**: Long-lived storage. When TTL expires, entries move
//!   to the "hot archive" and can be restored via `RestoreFootprint`.
//!
//! The storage adapter checks TTL values and excludes expired entries from the
//! snapshot, matching C++ stellar-core behavior.

mod budget;
mod error;
mod events;
mod host;
pub mod protocol;
mod storage;

pub use budget::{
    FeeConfiguration, RentFeeConfiguration, ResourceLimits, SorobanBudget, SorobanConfig,
};
pub use events::{ContractEvent, ContractEvents, EventType};
pub use host::{
    compute_rent_fee_for_new_entry, execute_host_function, execute_host_function_with_cache,
    PersistentModuleCache, SorobanExecutionError, SorobanExecutionResult, StorageChange,
};
pub use storage::{SorobanStorage, StorageEntry, StorageKey};

use stellar_xdr::curr::{LedgerEntry, LedgerKey};

/// Trait for looking up archived entries from the hot archive.
///
/// This trait provides dependency inversion between `stellar-core-tx` (which executes
/// transactions) and `stellar-core-bucket`/`stellar-core-ledger` (which manage the
/// hot archive bucket list).
///
/// # Protocol 23+ Hot Archive
///
/// Starting from Protocol 23, persistent Soroban entries (ContractData, ContractCode)
/// that expire are moved to the "hot archive" bucket list rather than being deleted.
/// These entries can be restored via the `RestoreFootprint` operation or auto-restored
/// when marked in `SorobanTransactionDataExt::V1::archived_soroban_entries`.
///
/// When a transaction needs to restore an archived entry:
/// 1. The entry may still be in the live bucket list with an expired TTL ("live BL restore")
/// 2. The entry may have been fully evicted to the hot archive ("hot archive restore")
///
/// This trait handles case (2) by providing lookups into the hot archive bucket list.
pub trait HotArchiveLookup: Send + Sync {
    /// Look up an entry in the hot archive.
    ///
    /// Returns `Some(entry)` if the key exists in the hot archive as an `Archived` entry.
    /// Returns `None` if the key is not found or exists as a `Live` marker (restored).
    fn get(&self, key: &LedgerKey) -> Option<LedgerEntry>;
}

/// A no-op implementation of HotArchiveLookup that always returns None.
///
/// This is used when:
/// - Hot archive is not available (e.g., pre-Protocol 23)
/// - Running in a context where hot archive lookups are not needed
pub struct NoHotArchive;

impl HotArchiveLookup for NoHotArchive {
    fn get(&self, _key: &LedgerKey) -> Option<LedgerEntry> {
        None
    }
}
