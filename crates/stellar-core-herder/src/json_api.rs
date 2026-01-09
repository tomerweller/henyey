//! JSON API for Herder diagnostics and monitoring.
//!
//! This module provides JSON-serializable structures for exposing Herder
//! state through admin endpoints. It matches the C++ `getJsonInfo()`,
//! `getJsonQuorumInfo()`, and related methods in `HerderImpl`.
//!
//! # C++ Parity
//!
//! This module corresponds to the JSON output methods in:
//! - `HerderImpl::getJsonInfo()`
//! - `HerderImpl::getJsonQuorumInfo()`
//! - `HerderImpl::getJsonTransitiveQuorumInfo()`
//! - `HerderImpl::getJsonTransitiveQuorumIntersectionInfo()`
//! - `PendingEnvelopes::getJsonInfo()`

use serde::{Deserialize, Serialize};
use stellar_xdr::curr::NodeId;

/// Complete Herder JSON info response.
///
/// This is the top-level structure returned by `getJsonInfo()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HerderJsonInfo {
    /// This node's public key.
    pub you: String,
    /// SCP state information.
    pub scp: ScpJsonInfo,
    /// Pending envelopes queue information.
    pub queue: PendingEnvelopesJsonInfo,
}

/// SCP state JSON information.
///
/// Contains slot-by-slot SCP state for debugging.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScpJsonInfo {
    /// Current slot index.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<u64>,
    /// Phase within the slot (nominate, prepare, confirm, externalize).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    /// Per-slot state information.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub slots: Vec<SlotJsonInfo>,
}

/// Per-slot SCP state information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotJsonInfo {
    /// Slot index.
    pub index: u64,
    /// Current phase.
    pub phase: String,
    /// Ballot information (if in ballot phase).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ballot: Option<BallotJsonInfo>,
    /// Nomination information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nomination: Option<NominationJsonInfo>,
    /// Nodes that have voted/accepted.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub validators: Vec<String>,
}

/// Ballot phase JSON information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BallotJsonInfo {
    /// Current ballot counter.
    pub counter: u32,
    /// Value hash (abbreviated).
    pub value: String,
    /// Whether we've committed.
    pub committed: bool,
    /// Highest confirmed prepared ballot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h: Option<u32>,
}

/// Nomination phase JSON information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NominationJsonInfo {
    /// Number of voted values.
    pub votes: usize,
    /// Number of accepted values.
    pub accepted: usize,
    /// Whether nomination is complete.
    pub complete: bool,
}

/// Pending envelopes queue JSON information.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PendingEnvelopesJsonInfo {
    /// Number of pending envelopes.
    pub pending: usize,
    /// Number of ready envelopes.
    pub ready: usize,
    /// Number of fetching envelopes.
    pub fetching: usize,
    /// Per-slot pending counts.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub slots: Vec<PendingSlotJsonInfo>,
}

/// Per-slot pending envelope information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingSlotJsonInfo {
    /// Slot index.
    pub slot: u64,
    /// Number of pending envelopes for this slot.
    pub count: usize,
}

/// Quorum information JSON response.
///
/// Returned by `getJsonQuorumInfo()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumJsonInfo {
    /// Node ID being queried.
    pub node: String,
    /// Quorum set information.
    pub qset: QuorumSetJsonInfo,
    /// Transitive quorum intersection info (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transitive: Option<TransitiveQuorumJsonInfo>,
    /// Nodes that may be dead.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub maybe_dead_nodes: Vec<String>,
}

/// Quorum set JSON information.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuorumSetJsonInfo {
    /// Threshold for this quorum set.
    pub threshold: u32,
    /// Direct validators in this quorum set.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub validators: Vec<String>,
    /// Inner quorum sets.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub inner_sets: Vec<QuorumSetJsonInfo>,
    /// Quorum set hash (abbreviated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// Agreement status per slot.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub agree: Vec<SlotAgreementInfo>,
    /// Lag information per node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lag_ms: Option<LagJsonInfo>,
    /// Cost information per validator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<ValidatorCostJsonInfo>,
}

/// Slot agreement status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotAgreementInfo {
    /// Slot index.
    pub slot: u64,
    /// Whether the node agrees on this slot.
    pub agrees: bool,
    /// Phase the node is in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
}

/// Lag information for quorum set nodes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LagJsonInfo {
    /// Per-node lag in milliseconds.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub nodes: Vec<NodeLagInfo>,
    /// Summary statistics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<LagSummary>,
}

/// Per-node lag information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeLagInfo {
    /// Node ID.
    pub node: String,
    /// Lag in milliseconds.
    pub lag_ms: u64,
}

/// Lag summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LagSummary {
    /// Minimum lag.
    pub min_ms: u64,
    /// Maximum lag.
    pub max_ms: u64,
    /// Average lag.
    pub avg_ms: u64,
}

/// Validator cost information.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidatorCostJsonInfo {
    /// Per-validator cost.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub validators: Vec<ValidatorCost>,
}

/// Per-validator cost entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorCost {
    /// Node ID.
    pub node: String,
    /// Total cost.
    pub cost: u64,
}

/// Transitive quorum intersection information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitiveQuorumJsonInfo {
    /// Whether the network enjoys quorum intersection.
    pub intersection: bool,
    /// Number of nodes in the transitive quorum.
    pub node_count: u64,
    /// Ledger when last checked.
    pub last_check_ledger: u64,
    /// Critical node groups (if intersection exists).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub critical: Vec<Vec<String>>,
    /// Last good ledger (if no intersection).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_good_ledger: Option<u64>,
    /// Potential split (if no intersection).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub potential_split: Option<(Vec<String>, Vec<String>)>,
}

/// Format a NodeID as a string.
///
/// # Arguments
///
/// * `node_id` - The node ID to format
/// * `full_keys` - If true, return full key; otherwise abbreviate
///
/// # Returns
///
/// A string representation of the node ID.
pub fn format_node_id(node_id: &NodeId, full_keys: bool) -> String {
    use stellar_strkey::ed25519::PublicKey as StrPublicKey;

    match &node_id.0 {
        stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(key) => {
            let strkey = StrPublicKey(key.0).to_string();
            if full_keys {
                strkey
            } else {
                // Return first 5 characters for abbreviated form
                strkey.chars().take(5).collect()
            }
        }
    }
}

/// Format a hash as a string.
///
/// # Arguments
///
/// * `hash` - The 32-byte hash
/// * `full` - If true, return full hex; otherwise abbreviate
///
/// # Returns
///
/// A hex string representation of the hash.
pub fn format_hash(hash: &[u8; 32], full: bool) -> String {
    let hex = hex::encode(hash);
    if full {
        hex
    } else {
        hex.chars().take(8).collect()
    }
}

/// Builder for constructing HerderJsonInfo.
#[derive(Debug, Default)]
pub struct HerderJsonInfoBuilder {
    you: Option<String>,
    scp: ScpJsonInfo,
    queue: PendingEnvelopesJsonInfo,
}

impl HerderJsonInfoBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the local node ID.
    pub fn you(mut self, node_id: &NodeId, full_keys: bool) -> Self {
        self.you = Some(format_node_id(node_id, full_keys));
        self
    }

    /// Set the local node ID from a string.
    pub fn you_str(mut self, you: String) -> Self {
        self.you = Some(you);
        self
    }

    /// Set the SCP info.
    pub fn scp(mut self, scp: ScpJsonInfo) -> Self {
        self.scp = scp;
        self
    }

    /// Set the pending envelopes info.
    pub fn queue(mut self, queue: PendingEnvelopesJsonInfo) -> Self {
        self.queue = queue;
        self
    }

    /// Build the HerderJsonInfo.
    pub fn build(self) -> HerderJsonInfo {
        HerderJsonInfo {
            you: self.you.unwrap_or_else(|| "unknown".to_string()),
            scp: self.scp,
            queue: self.queue,
        }
    }
}

/// Builder for constructing QuorumJsonInfo.
#[derive(Debug, Default)]
pub struct QuorumJsonInfoBuilder {
    node: Option<String>,
    qset: QuorumSetJsonInfo,
    transitive: Option<TransitiveQuorumJsonInfo>,
    maybe_dead_nodes: Vec<String>,
}

impl QuorumJsonInfoBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the node ID.
    pub fn node(mut self, node_id: &NodeId, full_keys: bool) -> Self {
        self.node = Some(format_node_id(node_id, full_keys));
        self
    }

    /// Set the quorum set info.
    pub fn qset(mut self, qset: QuorumSetJsonInfo) -> Self {
        self.qset = qset;
        self
    }

    /// Set the transitive quorum info.
    pub fn transitive(mut self, transitive: TransitiveQuorumJsonInfo) -> Self {
        self.transitive = Some(transitive);
        self
    }

    /// Add a maybe-dead node.
    pub fn add_maybe_dead_node(mut self, node_id: &NodeId, full_keys: bool) -> Self {
        self.maybe_dead_nodes.push(format_node_id(node_id, full_keys));
        self
    }

    /// Build the QuorumJsonInfo.
    pub fn build(self) -> QuorumJsonInfo {
        QuorumJsonInfo {
            node: self.node.unwrap_or_else(|| "unknown".to_string()),
            qset: self.qset,
            transitive: self.transitive,
            maybe_dead_nodes: self.maybe_dead_nodes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::Uint256;

    fn make_test_node_id(seed: u8) -> NodeId {
        let mut key = [0u8; 32];
        key[0] = seed;
        NodeId(stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(Uint256(key)))
    }

    #[test]
    fn test_format_node_id_full() {
        let node_id = make_test_node_id(0);
        let formatted = format_node_id(&node_id, true);
        assert!(formatted.starts_with('G'));
        assert_eq!(formatted.len(), 56); // Full strkey length
    }

    #[test]
    fn test_format_node_id_abbreviated() {
        let node_id = make_test_node_id(0);
        let formatted = format_node_id(&node_id, false);
        assert!(formatted.starts_with('G'));
        assert_eq!(formatted.len(), 5);
    }

    #[test]
    fn test_format_hash_full() {
        let hash = [0xABu8; 32];
        let formatted = format_hash(&hash, true);
        assert_eq!(formatted.len(), 64); // Full hex length
        assert!(formatted.starts_with("abab"));
    }

    #[test]
    fn test_format_hash_abbreviated() {
        let hash = [0xABu8; 32];
        let formatted = format_hash(&hash, false);
        assert_eq!(formatted.len(), 8);
        assert_eq!(formatted, "abababab");
    }

    #[test]
    fn test_herder_json_info_builder() {
        let node_id = make_test_node_id(1);
        let info = HerderJsonInfoBuilder::new()
            .you(&node_id, false)
            .scp(ScpJsonInfo::default())
            .queue(PendingEnvelopesJsonInfo::default())
            .build();

        assert_eq!(info.you.len(), 5);
        assert!(info.you.starts_with('G'));
    }

    #[test]
    fn test_quorum_json_info_builder() {
        let node_id = make_test_node_id(2);
        let info = QuorumJsonInfoBuilder::new()
            .node(&node_id, true)
            .qset(QuorumSetJsonInfo::default())
            .build();

        assert_eq!(info.node.len(), 56);
    }

    #[test]
    fn test_serialization() {
        let info = HerderJsonInfo {
            you: "GABCD".to_string(),
            scp: ScpJsonInfo {
                slot: Some(100),
                phase: Some("externalize".to_string()),
                slots: vec![],
            },
            queue: PendingEnvelopesJsonInfo {
                pending: 5,
                ready: 2,
                fetching: 1,
                slots: vec![],
            },
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("GABCD"));
        assert!(json.contains("externalize"));
        assert!(json.contains("\"pending\":5"));

        // Verify deserialization
        let parsed: HerderJsonInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.you, "GABCD");
        assert_eq!(parsed.scp.slot, Some(100));
    }

    #[test]
    fn test_transitive_quorum_serialization() {
        let info = TransitiveQuorumJsonInfo {
            intersection: true,
            node_count: 10,
            last_check_ledger: 12345,
            critical: vec![vec!["GABCD".to_string(), "GDEFG".to_string()]],
            last_good_ledger: None,
            potential_split: None,
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"intersection\":true"));
        assert!(json.contains("\"node_count\":10"));
        assert!(json.contains("GABCD"));
    }
}
