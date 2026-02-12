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
//! use henyey_scp::{SCP, SCPDriver, EnvelopeState};
//!
//! // During catchup - just mark slots as externalized
//! scp.force_externalize(ledger_seq, ledger_value);
//!
//! // During live sync - participate in consensus
//! scp.nominate(slot_index, value, &prev_value);
//! let state = scp.receive_envelope(envelope);
//! ```

use std::sync::Arc;

mod ballot;
mod compare;
mod driver;
mod error;
mod format;
mod info;
mod nomination;
mod quorum;
pub mod quorum_config;
mod scp;
mod slot;

// Re-export main types
pub use ballot::{get_working_ballot, BallotPhase, BallotProtocol};
pub use compare::is_newer_nomination_or_ballot_st;
pub use driver::{SCPDriver, SCPTimerType, ValidationLevel};
pub use error::ScpError;
pub use format::{
    ballot_to_str, envelope_to_str, node_id_to_short_string, node_id_to_string, value_to_str,
};
pub use info::{
    BallotInfo, BallotValue, CommitBounds, NominationInfo, NodeInfo, QuorumInfo, SlotInfo,
};
pub use nomination::NominationProtocol;
pub use quorum::{
    find_closest_v_blocking, get_all_nodes, hash_quorum_set, is_blocking_set, is_quorum,
    is_quorum_set_sane, is_quorum_slice, is_v_blocking, is_valid_quorum_set, normalize_quorum_set,
    normalize_quorum_set_with_remove, simple_quorum_set, singleton_quorum_set,
    SingletonQuorumSetCache, MAXIMUM_QUORUM_NESTING_LEVEL, MAXIMUM_QUORUM_NODES,
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

/// Shared context threaded through ballot and nomination protocol methods.
///
/// Groups the four parameters that nearly every internal SCP function needs:
/// the local node identity, its quorum set, the application driver, and
/// the slot index. Passing a single `&SlotContext<D>` instead of four
/// separate arguments reduces parameter noise across ~40 call sites.
pub(crate) struct SlotContext<'a, D: SCPDriver> {
    pub local_node_id: &'a NodeId,
    pub local_quorum_set: &'a ScpQuorumSet,
    pub driver: &'a Arc<D>,
    pub slot_index: u64,
}

/// Iterate envelopes in sorted node order, skipping self if not fully validated.
///
/// Shared implementation for `NominationProtocol::process_current_state` and
/// `BallotProtocol::process_current_state`.
pub(crate) fn process_envelopes_current_state<F>(
    envelopes: &std::collections::HashMap<NodeId, ScpEnvelope>,
    mut f: F,
    local_node_id: &NodeId,
    fully_validated: bool,
    force_self: bool,
) -> bool
where
    F: FnMut(&ScpEnvelope) -> bool,
{
    let mut nodes: Vec<_> = envelopes.keys().collect();
    nodes.sort();

    for node_id in nodes {
        if !force_self && node_id == local_node_id && !fully_validated {
            continue;
        }

        if let Some(envelope) = envelopes.get(node_id) {
            if !f(envelope) {
                return false;
            }
        }
    }

    true
}

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

/// Node state for quorum information reporting.
///
/// This enum represents the state of a node as seen during consensus,
/// used for debugging and monitoring quorum status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumInfoNodeState {
    /// Node is missing (no message received)
    Missing,
    /// Node sent a nomination message
    Nominating,
    /// Node is in ballot PREPARE phase
    Preparing,
    /// Node is in ballot CONFIRM phase
    Confirming,
    /// Node has externalized
    Externalized,
}

impl QuorumInfoNodeState {
    /// Get state from an envelope's pledges.
    pub fn from_pledges(pledges: &ScpStatementPledges) -> Self {
        match pledges {
            ScpStatementPledges::Nominate(_) => QuorumInfoNodeState::Nominating,
            ScpStatementPledges::Prepare(_) => QuorumInfoNodeState::Preparing,
            ScpStatementPledges::Confirm(_) => QuorumInfoNodeState::Confirming,
            ScpStatementPledges::Externalize(_) => QuorumInfoNodeState::Externalized,
        }
    }

    /// Check if this state represents active participation in ballot protocol.
    pub fn is_in_ballot(&self) -> bool {
        matches!(
            self,
            QuorumInfoNodeState::Preparing
                | QuorumInfoNodeState::Confirming
                | QuorumInfoNodeState::Externalized
        )
    }

    /// Check if this state represents completed consensus.
    pub fn is_externalized(&self) -> bool {
        matches!(self, QuorumInfoNodeState::Externalized)
    }
}

/// A historical statement record for debugging and analysis.
///
/// This struct captures metadata about a statement when it was received,
/// useful for post-hoc analysis of consensus behavior.
#[derive(Debug, Clone)]
pub struct HistoricalStatement {
    /// The envelope containing the statement.
    pub envelope: ScpEnvelope,
    /// When the statement was received (monotonic counter or timestamp).
    pub received_at: u64,
    /// Whether this statement was valid.
    pub valid: bool,
}

/// JSON-serializable quorum set for persistence and debugging.
///
/// This provides a human-readable representation of a quorum set
/// that can be serialized to JSON, matching stellar-core `toJson()` functionality.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct QuorumSetJson {
    /// Threshold required for this quorum set.
    pub threshold: u32,
    /// Validator public keys (as strkey strings).
    pub validators: Vec<String>,
    /// Nested inner quorum sets.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inner_sets: Vec<QuorumSetJson>,
}

impl QuorumSetJson {
    /// Convert from XDR ScpQuorumSet to JSON-serializable format.
    pub fn from_xdr(qs: &ScpQuorumSet) -> Self {
        Self {
            threshold: qs.threshold,
            validators: qs
                .validators
                .iter()
                .map(quorum_config::node_id_to_strkey)
                .collect(),
            inner_sets: qs.inner_sets.iter().map(QuorumSetJson::from_xdr).collect(),
        }
    }

    /// Convert to XDR ScpQuorumSet from JSON format.
    ///
    /// Returns None if any validator key fails to parse.
    pub fn to_xdr(&self) -> Option<ScpQuorumSet> {
        let validators: std::result::Result<Vec<_>, _> = self
            .validators
            .iter()
            .map(|s| quorum_config::parse_node_id(s))
            .collect();
        let validators = validators.ok()?;

        let inner_sets: Option<Vec<_>> = self.inner_sets.iter().map(|i| i.to_xdr()).collect();
        let inner_sets = inner_sets?;

        Some(ScpQuorumSet {
            threshold: self.threshold,
            validators: validators.try_into().ok()?,
            inner_sets: inner_sets.try_into().ok()?,
        })
    }

    /// Create a simple quorum set with just validators.
    pub fn simple(threshold: u32, validators: Vec<String>) -> Self {
        Self {
            threshold,
            validators,
            inner_sets: vec![],
        }
    }
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
    NodeId, ScpBallot, ScpEnvelope, ScpNomination, ScpQuorumSet, ScpStatement, ScpStatementConfirm,
    ScpStatementExternalize, ScpStatementPledges, ScpStatementPrepare, Value,
};

// Re-export Hash256 for quorum set hashing
pub use henyey_common::Hash256;


#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{PublicKey, Uint256};

    fn make_node_id(seed: u8) -> NodeId {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        NodeId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes)))
    }

    fn make_value(data: &[u8]) -> Value {
        data.to_vec().try_into().unwrap()
    }

    fn make_quorum_set(nodes: Vec<NodeId>, threshold: u32) -> ScpQuorumSet {
        ScpQuorumSet {
            threshold,
            validators: nodes.try_into().unwrap(),
            inner_sets: vec![].try_into().unwrap(),
        }
    }

    #[test]
    fn test_envelope_state() {
        assert!(!EnvelopeState::Invalid.is_valid());
        assert!(EnvelopeState::Valid.is_valid());
        assert!(EnvelopeState::ValidNew.is_valid());

        assert!(!EnvelopeState::Invalid.is_new());
        assert!(!EnvelopeState::Valid.is_new());
        assert!(EnvelopeState::ValidNew.is_new());
    }

    #[test]
    fn test_quorum_info_node_state() {
        // Test from_pledges
        let value = make_value(&[1, 2, 3]);
        let node = make_node_id(1);
        let quorum_set = make_quorum_set(vec![node.clone()], 1);

        let nom = ScpNomination {
            quorum_set_hash: hash_quorum_set(&quorum_set).into(),
            votes: vec![value.clone()].try_into().unwrap(),
            accepted: vec![].try_into().unwrap(),
        };
        assert_eq!(
            QuorumInfoNodeState::from_pledges(&ScpStatementPledges::Nominate(nom)),
            QuorumInfoNodeState::Nominating
        );

        let ballot = ScpBallot {
            counter: 1,
            value: value.clone(),
        };
        let prep = ScpStatementPrepare {
            quorum_set_hash: hash_quorum_set(&quorum_set).into(),
            ballot: ballot.clone(),
            prepared: None,
            prepared_prime: None,
            n_c: 0,
            n_h: 0,
        };
        assert_eq!(
            QuorumInfoNodeState::from_pledges(&ScpStatementPledges::Prepare(prep)),
            QuorumInfoNodeState::Preparing
        );

        let conf = ScpStatementConfirm {
            ballot: ballot.clone(),
            n_prepared: 1,
            n_commit: 1,
            n_h: 1,
            quorum_set_hash: hash_quorum_set(&quorum_set).into(),
        };
        assert_eq!(
            QuorumInfoNodeState::from_pledges(&ScpStatementPledges::Confirm(conf)),
            QuorumInfoNodeState::Confirming
        );

        let ext = ScpStatementExternalize {
            commit: ballot.clone(),
            n_h: 1,
            commit_quorum_set_hash: hash_quorum_set(&quorum_set).into(),
        };
        assert_eq!(
            QuorumInfoNodeState::from_pledges(&ScpStatementPledges::Externalize(ext)),
            QuorumInfoNodeState::Externalized
        );

        // Test helper methods
        assert!(!QuorumInfoNodeState::Missing.is_in_ballot());
        assert!(!QuorumInfoNodeState::Nominating.is_in_ballot());
        assert!(QuorumInfoNodeState::Preparing.is_in_ballot());
        assert!(QuorumInfoNodeState::Confirming.is_in_ballot());
        assert!(QuorumInfoNodeState::Externalized.is_in_ballot());

        assert!(!QuorumInfoNodeState::Missing.is_externalized());
        assert!(!QuorumInfoNodeState::Preparing.is_externalized());
        assert!(QuorumInfoNodeState::Externalized.is_externalized());
    }

    #[test]
    fn test_historical_statement() {
        let node = make_node_id(1);
        let value = make_value(&[1, 2, 3]);
        let quorum_set = make_quorum_set(vec![node.clone()], 1);

        let nom = ScpNomination {
            quorum_set_hash: hash_quorum_set(&quorum_set).into(),
            votes: vec![value.clone()].try_into().unwrap(),
            accepted: vec![].try_into().unwrap(),
        };
        let statement = ScpStatement {
            node_id: node.clone(),
            slot_index: 1,
            pledges: ScpStatementPledges::Nominate(nom),
        };
        let envelope = ScpEnvelope {
            statement,
            signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
        };

        let hist = HistoricalStatement {
            envelope: envelope.clone(),
            received_at: 12345,
            valid: true,
        };

        assert_eq!(hist.received_at, 12345);
        assert!(hist.valid);
        assert_eq!(hist.envelope.statement.slot_index, 1);
    }

    #[test]
    fn test_quorum_set_json_simple() {
        let qs_json = QuorumSetJson::simple(
            2,
            vec![
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB".to_string(),
            ],
        );

        assert_eq!(qs_json.threshold, 2);
        assert_eq!(qs_json.validators.len(), 2);
        assert!(qs_json.inner_sets.is_empty());
    }

    #[test]
    fn test_quorum_set_json_serialization() {
        let qs_json = QuorumSetJson {
            threshold: 2,
            validators: vec!["GABC".to_string(), "GDEF".to_string()],
            inner_sets: vec![QuorumSetJson {
                threshold: 1,
                validators: vec!["GHIJ".to_string()],
                inner_sets: vec![],
            }],
        };

        let json = serde_json::to_string(&qs_json).unwrap();
        assert!(json.contains("\"threshold\":2"));
        assert!(json.contains("\"validators\":[\"GABC\",\"GDEF\"]"));
        assert!(json.contains("\"inner_sets\":[{"));

        let deserialized: QuorumSetJson = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.threshold, 2);
        assert_eq!(deserialized.validators.len(), 2);
        assert_eq!(deserialized.inner_sets.len(), 1);
        assert_eq!(deserialized.inner_sets[0].threshold, 1);
    }

    #[test]
    fn test_quorum_set_json_from_xdr_roundtrip() {
        let node1 = make_node_id(1);
        let node2 = make_node_id(2);
        let qs = make_quorum_set(vec![node1.clone(), node2.clone()], 2);

        // Convert to JSON format
        let qs_json = QuorumSetJson::from_xdr(&qs);
        assert_eq!(qs_json.threshold, 2);
        assert_eq!(qs_json.validators.len(), 2);

        // Serialize and deserialize
        let json = serde_json::to_string(&qs_json).unwrap();
        let deserialized: QuorumSetJson = serde_json::from_str(&json).unwrap();
        assert_eq!(qs_json, deserialized);

        // Convert back to XDR
        let qs_back = deserialized.to_xdr().unwrap();
        assert_eq!(qs_back.threshold, 2);
        assert_eq!(qs_back.validators.len(), 2);
    }

    #[test]
    fn test_quorum_set_json_with_inner_sets() {
        let node1 = make_node_id(1);
        let node2 = make_node_id(2);
        let node3 = make_node_id(3);

        let inner = ScpQuorumSet {
            threshold: 1,
            validators: vec![node3.clone()].try_into().unwrap(),
            inner_sets: vec![].try_into().unwrap(),
        };

        let qs = ScpQuorumSet {
            threshold: 2,
            validators: vec![node1.clone(), node2.clone()].try_into().unwrap(),
            inner_sets: vec![inner].try_into().unwrap(),
        };

        let qs_json = QuorumSetJson::from_xdr(&qs);
        assert_eq!(qs_json.threshold, 2);
        assert_eq!(qs_json.validators.len(), 2);
        assert_eq!(qs_json.inner_sets.len(), 1);
        assert_eq!(qs_json.inner_sets[0].threshold, 1);
        assert_eq!(qs_json.inner_sets[0].validators.len(), 1);

        // Roundtrip through JSON
        let json = serde_json::to_string_pretty(&qs_json).unwrap();
        let deserialized: QuorumSetJson = serde_json::from_str(&json).unwrap();
        let qs_back = deserialized.to_xdr().unwrap();

        assert_eq!(qs_back.threshold, 2);
        assert_eq!(qs_back.validators.len(), 2);
        assert_eq!(qs_back.inner_sets.len(), 1);
    }

    #[test]
    fn test_quorum_set_json_empty_inner_sets_skipped() {
        let qs_json = QuorumSetJson {
            threshold: 1,
            validators: vec!["GABC".to_string()],
            inner_sets: vec![],
        };

        let json = serde_json::to_string(&qs_json).unwrap();
        // inner_sets should be skipped when empty
        assert!(!json.contains("inner_sets"));

        // But deserialization should still work with missing field
        let deserialized: QuorumSetJson = serde_json::from_str(&json).unwrap();
        assert!(deserialized.inner_sets.is_empty());
    }
}
