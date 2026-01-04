//! Stellar Consensus Protocol (SCP) implementation for rs-stellar-core.
//!
//! SCP is a federated Byzantine agreement protocol that enables nodes to
//! reach consensus without requiring a closed membership or central authority.
//!
//! ## Key Concepts
//!
//! - **Quorum Slices**: Each node defines its own set of trusted nodes
//! - **Quorum**: A set of nodes sufficient for agreement (intersection of slices)
//! - **Blocking Set**: A set that can prevent agreement
//! - **V-Blocking**: A set that intersects all quorum slices of a node
//!
//! ## Protocol Phases
//!
//! 1. **Nomination**: Nodes propose and vote on candidate values
//! 2. **Ballot Protocol**: Nodes vote to prepare and commit ballots
//!    - PREPARE: Vote to prepare a ballot
//!    - CONFIRM: Confirm that a ballot is prepared
//!    - EXTERNALIZE: Commit to a value
//!
//! ## Safety Guarantees
//!
//! SCP guarantees safety (agreement) for any two nodes that share a quorum,
//! and provides liveness when the network is well-behaved.
//!
//! ## Usage for Testnet Sync
//!
//! For testnet sync, SCP is needed only after catchup to track live consensus.
//! During catchup, we skip SCP and just apply historical ledgers using
//! `force_externalize()` to mark slots as externalized without going through
//! the consensus process.
//!
//! ```ignore
//! use stellar_core_scp::{SCP, SCPDriver, EnvelopeState};
//!
//! // During catchup - just mark slots as externalized
//! scp.force_externalize(ledger_seq, ledger_value);
//!
//! // During live sync - participate in consensus
//! scp.nominate(slot_index, value, &prev_value);
//! let state = scp.receive_envelope(envelope);
//! ```

mod ballot;
mod driver;
mod error;
mod nomination;
mod quorum;
pub mod quorum_config;
mod scp;
mod slot;

// Re-export main types
pub use ballot::{BallotPhase, BallotProtocol};
pub use driver::{SCPDriver, ValidationLevel};
pub use error::ScpError;
pub use nomination::NominationProtocol;
pub use quorum::{
    find_closest_v_blocking, get_all_nodes, hash_quorum_set, is_blocking_set, is_quorum,
    is_quorum_set_sane, is_quorum_slice, is_v_blocking, is_valid_quorum_set,
    normalize_quorum_set, simple_quorum_set,
};
pub use quorum_config::{
    config_to_quorum_set, node_id_to_strkey, parse_node_id, testnet_quorum_config,
    validate_quorum_config, QuorumConfigError,
};
pub use scp::{SlotState, SCP};
pub use slot::Slot;

/// Result type for SCP operations.
pub type Result<T> = std::result::Result<T, ScpError>;

/// A slot index (typically the ledger sequence number).
pub type SlotIndex = u64;

/// SCP ballot number.
pub type BallotCounter = u32;

/// The result of processing an SCP envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeState {
    /// Envelope is invalid (bad signature, malformed, etc.)
    Invalid,
    /// Envelope is valid but not new (duplicate or older state)
    Valid,
    /// Envelope is valid and caused state change
    ValidNew,
}

impl EnvelopeState {
    /// Check if the envelope was valid.
    pub fn is_valid(&self) -> bool {
        matches!(self, EnvelopeState::Valid | EnvelopeState::ValidNew)
    }

    /// Check if the envelope caused a state change.
    pub fn is_new(&self) -> bool {
        matches!(self, EnvelopeState::ValidNew)
    }
}

// Re-export XDR types commonly used with SCP
pub use stellar_xdr::curr::{
    NodeId, ScpBallot, ScpEnvelope, ScpNomination, ScpQuorumSet, ScpStatement,
    ScpStatementConfirm, ScpStatementExternalize, ScpStatementPledges,
    ScpStatementPrepare, Value,
};

// Re-export Hash256 for quorum set hashing
pub use stellar_core_common::Hash256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_state() {
        assert!(!EnvelopeState::Invalid.is_valid());
        assert!(EnvelopeState::Valid.is_valid());
        assert!(EnvelopeState::ValidNew.is_valid());

        assert!(!EnvelopeState::Invalid.is_new());
        assert!(!EnvelopeState::Valid.is_new());
        assert!(EnvelopeState::ValidNew.is_new());
    }
}
