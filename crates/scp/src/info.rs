/// JSON-serializable SCP slot information for debugging and monitoring.
///
/// This provides a structured view of slot state that can be serialized
/// to JSON, matching the stellar-core `getJsonInfo()` functionality.
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
