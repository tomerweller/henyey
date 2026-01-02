//! SCP coordination and ledger close orchestration for rs-stellar-core.
//!
//! The Herder is the central coordinator that:
//!
//! - Drives the SCP consensus protocol
//! - Collects transactions from the overlay network
//! - Proposes transaction sets for consensus
//! - Triggers ledger close when consensus is reached
//! - Manages the transition between ledgers
//!
//! ## Architecture
//!
//! ```text
//! +------------------+
//! |     Herder       |
//! |------------------|
//! | - state          |  <-- HerderState (Booting/Syncing/Tracking)
//! | - tx_queue       |  <-- TransactionQueue
//! | - pending        |  <-- PendingEnvelopes
//! | - scp_driver     |  <-- ScpDriver
//! +------------------+
//!         |
//!         v
//! +------------------+     +------------------+
//! |   SCP Protocol   | <-> |  Overlay Network |
//! +------------------+     +------------------+
//!         |
//!         v
//! +------------------+
//! |  Ledger Manager  |
//! +------------------+
//! ```
//!
//! ## State Machine
//!
//! The Herder progresses through states:
//!
//! 1. **Booting**: Initial state, not connected to network
//! 2. **Syncing**: Catching up with the network via history archives
//! 3. **Tracking**: Synchronized and following consensus
//!
//! ## For Testnet Sync
//!
//! After catchup completes:
//! 1. Call `herder.bootstrap(ledger_seq)` to transition to Tracking
//! 2. SCP envelopes from overlay are processed via `receive_scp_envelope`
//! 3. Externalized values are tracked to keep the node synced
//!
//! ## Example
//!
//! ```ignore
//! use stellar_core_herder::{Herder, HerderConfig};
//!
//! // Create herder
//! let config = HerderConfig::default();
//! let herder = Herder::new(config);
//!
//! // Start syncing (when catchup begins)
//! herder.start_syncing();
//!
//! // After catchup completes
//! herder.bootstrap(ledger_seq);
//!
//! // Process incoming SCP envelopes
//! let state = herder.receive_scp_envelope(envelope);
//!
//! // Process incoming transactions
//! let result = herder.receive_transaction(tx);
//! ```

mod error;
mod herder;
mod pending;
mod quorum_tracker;
mod scp_driver;
mod state;
mod surge_pricing;
mod tx_queue;

// Re-export main types
pub use error::HerderError;
pub use herder::{EnvelopeState, Herder, HerderConfig, HerderStats, LedgerCloseInfo};
pub use pending::{PendingConfig, PendingEnvelopes, PendingResult, PendingStats};
pub use quorum_tracker::{QuorumTracker, SlotQuorumTracker};
pub use scp_driver::{
    CachedTxSet, ExternalizedSlot, HerderScpCallback, PendingTxSet, ScpDriver, ScpDriverConfig,
    ValueValidation,
};
pub use state::HerderState;
pub use tx_queue::{
    QueuedTransaction, TransactionQueue, TransactionSet, TxQueueConfig, TxQueueResult,
};

/// Result type for Herder operations.
pub type Result<T> = std::result::Result<T, HerderError>;

/// A pending transaction waiting to be included in a ledger.
#[derive(Debug)]
pub struct PendingTransaction {
    /// The transaction envelope.
    pub envelope: stellar_xdr::curr::TransactionEnvelope,
    /// When this transaction was received.
    pub received_at: std::time::Instant,
    /// Number of times this transaction was seen.
    pub broadcast_count: u32,
}

/// A value that has been externalized by SCP.
#[derive(Debug, Clone)]
pub struct ExternalizedValue {
    /// The ledger sequence.
    pub ledger_seq: u32,
    /// The transaction set hash.
    pub tx_set_hash: stellar_core_common::Hash256,
    /// The close time.
    pub close_time: u64,
}

/// Trait for Herder callbacks.
#[async_trait::async_trait]
pub trait HerderCallback: Send + Sync {
    /// Called when a ledger should be closed.
    async fn close_ledger(
        &self,
        ledger_seq: u32,
        tx_set: TransactionSet,
        close_time: u64,
        upgrades: Vec<stellar_xdr::curr::UpgradeType>,
    ) -> Result<stellar_core_common::Hash256>;

    /// Called to validate a proposed transaction set.
    async fn validate_tx_set(&self, tx_set_hash: &stellar_core_common::Hash256) -> bool;

    /// Called when an SCP message should be broadcast.
    async fn broadcast_scp_message(&self, envelope: stellar_xdr::curr::ScpEnvelope);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = HerderConfig::default();
        assert_eq!(config.max_pending_transactions, 1000);
        assert!(!config.is_validator);
        assert_eq!(config.ledger_close_time, 5);
    }

    #[test]
    fn test_herder_creation() {
        let config = HerderConfig::default();
        let herder = Herder::new(config);
        assert_eq!(herder.state(), HerderState::Booting);
    }

    #[test]
    fn test_state_transitions() {
        let config = HerderConfig::default();
        let herder = Herder::new(config);

        assert_eq!(herder.state(), HerderState::Booting);

        herder.start_syncing();
        assert_eq!(herder.state(), HerderState::Syncing);

        herder.bootstrap(100);
        assert_eq!(herder.state(), HerderState::Tracking);
        assert_eq!(herder.tracking_slot(), 100);
    }
}
