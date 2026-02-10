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
pub use ballot::{get_working_ballot, BallotPhase, BallotProtocol};
pub use driver::{SCPDriver, SCPTimerType, ValidationLevel};
pub use error::ScpError;
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

/// JSON-serializable SCP slot information for debugging and monitoring.
///
/// This provides a structured view of slot state that can be serialized
/// to JSON, matching the C++ `getJsonInfo()` functionality.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SlotInfo {
    /// The slot index (ledger sequence).
    pub slot_index: u64,
    /// Current phase of the slot.
    pub phase: String,
    /// Whether the slot is fully validated.
    pub fully_validated: bool,
    /// Nomination state if in nomination phase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nomination: Option<NominationInfo>,
    /// Ballot state if in ballot phase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ballot: Option<BallotInfo>,
}

/// JSON-serializable nomination protocol information.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NominationInfo {
    /// Whether nomination is currently running.
    pub running: bool,
    /// Current nomination round.
    pub round: u32,
    /// Values we've voted for (hex-encoded prefixes).
    pub votes: Vec<String>,
    /// Values we've accepted (hex-encoded prefixes).
    pub accepted: Vec<String>,
    /// Confirmed candidate values.
    pub candidates: Vec<String>,
    /// Number of nodes heard from.
    pub node_count: usize,
}

/// JSON-serializable ballot protocol information.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BallotInfo {
    /// Current ballot phase (prepare/confirm/externalize).
    pub phase: String,
    /// Current ballot counter.
    pub ballot_counter: u32,
    /// Current ballot value (hex-encoded prefix).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ballot_value: Option<String>,
    /// Prepared ballot info if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prepared: Option<BallotValue>,
    /// Prepared prime ballot info if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prepared_prime: Option<BallotValue>,
    /// Commit boundaries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<CommitBounds>,
    /// High ballot counter.
    pub high: u32,
    /// Number of nodes heard from.
    pub node_count: usize,
    /// Whether we've heard from a quorum.
    pub heard_from_quorum: bool,
}

/// JSON-serializable ballot value.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BallotValue {
    /// Ballot counter.
    pub counter: u32,
    /// Ballot value (hex-encoded prefix).
    pub value: String,
}

/// JSON-serializable commit bounds.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommitBounds {
    /// Low commit counter.
    pub low: u32,
    /// High commit counter.
    pub high: u32,
}

/// JSON-serializable quorum information for a slot.
///
/// This provides a view of quorum state including which nodes
/// are participating and in what states.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuorumInfo {
    /// The slot index.
    pub slot_index: u64,
    /// Local node ID (short form).
    pub local_node: String,
    /// Quorum set hash.
    pub quorum_set_hash: String,
    /// Node states keyed by short node ID.
    pub nodes: std::collections::HashMap<String, NodeInfo>,
    /// Whether quorum is reached.
    pub quorum_reached: bool,
    /// Whether we have a v-blocking set.
    pub v_blocking: bool,
}

/// JSON-serializable node information within quorum.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeInfo {
    /// The node's current state.
    pub state: String,
    /// The node's latest ballot counter if in ballot phase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ballot_counter: Option<u32>,
}

/// JSON-serializable quorum set for persistence and debugging.
///
/// This provides a human-readable representation of a quorum set
/// that can be serialized to JSON, matching C++ `toJson()` functionality.
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
pub use stellar_core_common::Hash256;

/// Format a NodeId for display as a short string.
///
/// Returns the first 8 hex characters of the public key.
pub fn node_id_to_short_string(node_id: &NodeId) -> String {
    match &node_id.0 {
        stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::curr::Uint256(bytes)) => {
            hex::encode(&bytes[..4])
        }
    }
}

/// Format a NodeId for display with optional full key.
///
/// # Arguments
/// * `node_id` - The node ID to format
/// * `full_keys` - If true, returns the full 64-character hex encoding.
///   If false, returns the short 8-character format.
///
/// This matches the C++ `toStrKey(NodeID, bool fullKeys)` method.
pub fn node_id_to_string(node_id: &NodeId, full_keys: bool) -> String {
    match &node_id.0 {
        stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::curr::Uint256(bytes)) => {
            if full_keys {
                hex::encode(bytes)
            } else {
                hex::encode(&bytes[..4])
            }
        }
    }
}

/// Format a ballot for display.
pub fn ballot_to_str(ballot: &ScpBallot) -> String {
    format!(
        "({},{})",
        ballot.counter,
        hex::encode(&ballot.value.as_slice()[..4.min(ballot.value.len())])
    )
}

/// Format a Value for display.
pub fn value_to_str(value: &Value) -> String {
    hex::encode(&value.as_slice()[..8.min(value.len())])
}

/// Format an envelope for display.
pub fn envelope_to_str(envelope: &ScpEnvelope) -> String {
    let node = node_id_to_short_string(&envelope.statement.node_id);
    let slot = envelope.statement.slot_index;

    match &envelope.statement.pledges {
        ScpStatementPledges::Nominate(nom) => {
            let votes: Vec<_> = nom.votes.iter().map(value_to_str).collect();
            let accepted: Vec<_> = nom.accepted.iter().map(value_to_str).collect();
            format!(
                "NOMINATE<{}, slot={}, votes={:?}, accepted={:?}>",
                node, slot, votes, accepted
            )
        }
        ScpStatementPledges::Prepare(prep) => {
            format!(
                "PREPARE<{}, slot={}, b={}, p={:?}, p'={:?}, c={}, h={}>",
                node,
                slot,
                ballot_to_str(&prep.ballot),
                prep.prepared.as_ref().map(ballot_to_str),
                prep.prepared_prime.as_ref().map(ballot_to_str),
                prep.n_c,
                prep.n_h
            )
        }
        ScpStatementPledges::Confirm(conf) => {
            format!(
                "CONFIRM<{}, slot={}, b={}, p_n={}, c={}, h={}>",
                node,
                slot,
                ballot_to_str(&conf.ballot),
                conf.n_prepared,
                conf.n_commit,
                conf.n_h
            )
        }
        ScpStatementPledges::Externalize(ext) => {
            format!(
                "EXTERNALIZE<{}, slot={}, c={}, h={}>",
                node,
                slot,
                ballot_to_str(&ext.commit),
                ext.n_h
            )
        }
    }
}

/// Compare two nominations or ballot statements for ordering.
///
/// Returns true if `new_st` is newer than `old_st` for the same node.
/// This is used to determine if a statement should replace an existing one.
pub fn is_newer_nomination_or_ballot_st(old_st: &ScpStatement, new_st: &ScpStatement) -> bool {
    use ScpStatementPledges::*;

    // Different statement types have different ordering
    let type_rank = |pledges: &ScpStatementPledges| -> u8 {
        match pledges {
            Nominate(_) => 0,
            Prepare(_) => 1,
            Confirm(_) => 2,
            Externalize(_) => 3,
        }
    };

    let old_rank = type_rank(&old_st.pledges);
    let new_rank = type_rank(&new_st.pledges);

    if old_rank != new_rank {
        return new_rank > old_rank;
    }

    // Same type - compare within type
    match (&old_st.pledges, &new_st.pledges) {
        (Nominate(old), Nominate(new)) => {
            // Nomination is newer if it has more votes or accepted
            let old_votes: std::collections::HashSet<_> = old.votes.iter().collect();
            let old_accepted: std::collections::HashSet<_> = old.accepted.iter().collect();
            let new_votes: std::collections::HashSet<_> = new.votes.iter().collect();
            let new_accepted: std::collections::HashSet<_> = new.accepted.iter().collect();

            // New must be superset
            if !old_votes.is_subset(&new_votes) || !old_accepted.is_subset(&new_accepted) {
                return false;
            }

            // And must have at least one more element
            new_votes.len() > old_votes.len() || new_accepted.len() > old_accepted.len()
        }
        (Prepare(old), Prepare(new)) => {
            // Higher ballot counter is newer
            if new.ballot.counter > old.ballot.counter {
                return true;
            }
            if new.ballot.counter < old.ballot.counter {
                return false;
            }
            // Same counter - check prepared fields
            let cmp_opt_ballot =
                |a: &Option<ScpBallot>, b: &Option<ScpBallot>| -> std::cmp::Ordering {
                    match (a, b) {
                        (None, None) => std::cmp::Ordering::Equal,
                        (None, Some(_)) => std::cmp::Ordering::Less,
                        (Some(_), None) => std::cmp::Ordering::Greater,
                        (Some(a), Some(b)) => a
                            .counter
                            .cmp(&b.counter)
                            .then_with(|| a.value.cmp(&b.value)),
                    }
                };

            match cmp_opt_ballot(&old.prepared, &new.prepared) {
                std::cmp::Ordering::Less => true,
                std::cmp::Ordering::Greater => false,
                std::cmp::Ordering::Equal => {
                    match cmp_opt_ballot(&old.prepared_prime, &new.prepared_prime) {
                        std::cmp::Ordering::Less => true,
                        std::cmp::Ordering::Greater => false,
                        std::cmp::Ordering::Equal => new.n_h > old.n_h,
                    }
                }
            }
        }
        (Confirm(old), Confirm(new)) => {
            if new.ballot.counter > old.ballot.counter {
                return true;
            }
            if new.ballot.counter < old.ballot.counter {
                return false;
            }
            if new.n_prepared > old.n_prepared {
                return true;
            }
            if new.n_prepared < old.n_prepared {
                return false;
            }
            new.n_h > old.n_h
        }
        (Externalize(_), Externalize(_)) => {
            // Externalize statements are terminal - can't be newer
            false
        }
        _ => false,
    }
}

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
    fn test_node_id_to_short_string() {
        let node = make_node_id(0xab);
        let short = node_id_to_short_string(&node);
        assert_eq!(short.len(), 8);
        assert!(short.starts_with("ab"));
    }

    #[test]
    fn test_ballot_to_str() {
        let ballot = ScpBallot {
            counter: 5,
            value: make_value(&[0xde, 0xad, 0xbe, 0xef]),
        };
        let s = ballot_to_str(&ballot);
        assert!(s.contains("5"));
        assert!(s.contains("dead"));
    }

    #[test]
    fn test_value_to_str() {
        let value = make_value(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
        let s = value_to_str(&value);
        assert_eq!(s, "123456789abcdef0");
    }

    #[test]
    fn test_envelope_to_str() {
        let node = make_node_id(1);
        let value = make_value(&[1, 2, 3, 4]);
        let quorum_set = make_quorum_set(vec![node.clone()], 1);

        let nom = ScpNomination {
            quorum_set_hash: hash_quorum_set(&quorum_set).into(),
            votes: vec![value.clone()].try_into().unwrap(),
            accepted: vec![].try_into().unwrap(),
        };
        let statement = ScpStatement {
            node_id: node.clone(),
            slot_index: 42,
            pledges: ScpStatementPledges::Nominate(nom),
        };
        let envelope = ScpEnvelope {
            statement,
            signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
        };

        let s = envelope_to_str(&envelope);
        assert!(s.contains("NOMINATE"));
        assert!(s.contains("slot=42"));
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
    fn test_is_newer_nomination() {
        let node = make_node_id(1);
        let quorum_set = make_quorum_set(vec![node.clone()], 1);
        let value1 = make_value(&[1]);
        let value2 = make_value(&[2]);

        let nom1 = ScpNomination {
            quorum_set_hash: hash_quorum_set(&quorum_set).into(),
            votes: vec![value1.clone()].try_into().unwrap(),
            accepted: vec![].try_into().unwrap(),
        };
        let nom2 = ScpNomination {
            quorum_set_hash: hash_quorum_set(&quorum_set).into(),
            votes: vec![value1.clone(), value2.clone()].try_into().unwrap(),
            accepted: vec![].try_into().unwrap(),
        };

        let st1 = ScpStatement {
            node_id: node.clone(),
            slot_index: 1,
            pledges: ScpStatementPledges::Nominate(nom1),
        };
        let st2 = ScpStatement {
            node_id: node.clone(),
            slot_index: 1,
            pledges: ScpStatementPledges::Nominate(nom2),
        };

        // st2 has more votes, so it's newer
        assert!(is_newer_nomination_or_ballot_st(&st1, &st2));
        assert!(!is_newer_nomination_or_ballot_st(&st2, &st1));
    }

    // ==================== Tests for JSON info types ====================

    #[test]
    fn test_slot_info_serialization() {
        let info = SlotInfo {
            slot_index: 42,
            phase: "NOMINATION".to_string(),
            fully_validated: true,
            nomination: Some(NominationInfo {
                running: true,
                round: 1,
                votes: vec!["abcd1234".to_string()],
                accepted: vec![],
                candidates: vec![],
                node_count: 3,
            }),
            ballot: None,
        };

        // Test serialization
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"slot_index\":42"));
        assert!(json.contains("\"phase\":\"NOMINATION\""));
        assert!(json.contains("\"fully_validated\":true"));
        assert!(json.contains("\"running\":true"));
        assert!(json.contains("\"round\":1"));
        assert!(!json.contains("\"ballot\"")); // Should be skipped due to None

        // Test deserialization round-trip
        let deserialized: SlotInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.slot_index, 42);
        assert_eq!(deserialized.phase, "NOMINATION");
        assert!(deserialized.nomination.is_some());
        assert!(deserialized.ballot.is_none());
    }

    #[test]
    fn test_ballot_info_serialization() {
        let info = BallotInfo {
            phase: "Prepare".to_string(),
            ballot_counter: 5,
            ballot_value: Some("deadbeef".to_string()),
            prepared: Some(BallotValue {
                counter: 4,
                value: "cafebabe".to_string(),
            }),
            prepared_prime: None,
            commit: None,
            high: 5,
            node_count: 7,
            heard_from_quorum: true,
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"phase\":\"Prepare\""));
        assert!(json.contains("\"ballot_counter\":5"));
        assert!(json.contains("\"heard_from_quorum\":true"));
        assert!(json.contains("\"prepared\":{"));
        assert!(!json.contains("\"prepared_prime\"")); // Skipped

        let deserialized: BallotInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.ballot_counter, 5);
        assert!(deserialized.prepared.is_some());
        assert!(deserialized.prepared_prime.is_none());
    }

    #[test]
    fn test_quorum_info_serialization() {
        let mut nodes = std::collections::HashMap::new();
        nodes.insert(
            "node1234".to_string(),
            NodeInfo {
                state: "PREPARING".to_string(),
                ballot_counter: Some(3),
            },
        );
        nodes.insert(
            "node5678".to_string(),
            NodeInfo {
                state: "MISSING".to_string(),
                ballot_counter: None,
            },
        );

        let info = QuorumInfo {
            slot_index: 100,
            local_node: "localnode".to_string(),
            quorum_set_hash: "abcd1234".to_string(),
            nodes,
            quorum_reached: true,
            v_blocking: true,
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"slot_index\":100"));
        assert!(json.contains("\"quorum_reached\":true"));
        assert!(json.contains("\"v_blocking\":true"));

        let deserialized: QuorumInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.slot_index, 100);
        assert_eq!(deserialized.nodes.len(), 2);
        assert!(deserialized.quorum_reached);
    }

    #[test]
    fn test_commit_bounds_serialization() {
        let bounds = CommitBounds { low: 1, high: 5 };

        let json = serde_json::to_string(&bounds).unwrap();
        assert!(json.contains("\"low\":1"));
        assert!(json.contains("\"high\":5"));

        let deserialized: CommitBounds = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.low, 1);
        assert_eq!(deserialized.high, 5);
    }

    // ==================== Tests for QuorumSetJson ====================

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
