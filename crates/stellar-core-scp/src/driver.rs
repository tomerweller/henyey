//! SCP driver trait defining callbacks for the SCP protocol.
//!
//! The SCPDriver trait is implemented by the Herder to connect SCP
//! to the rest of the system. SCP itself is completely isolated and
//! communicates only through this trait.

use std::time::Duration;

use stellar_core_common::Hash256;
use stellar_xdr::curr::{NodeId, ScpBallot, ScpEnvelope, ScpQuorumSet, Value};

/// Validation level for SCP values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationLevel {
    /// Invalid value - should be rejected.
    Invalid,
    /// Value may be valid but not fully validated yet.
    /// This is used during nomination when we don't have full context.
    MaybeValid,
    /// Fully validated value.
    FullyValidated,
}

/// Callback interface for SCP.
///
/// This trait is implemented by the Herder to connect SCP to the rest
/// of the system. SCP is designed to be completely isolated, and all
/// interactions happen through this trait.
pub trait SCPDriver: Send + Sync {
    /// Validate a value.
    ///
    /// # Arguments
    /// * `slot_index` - The slot for which this value is being considered
    /// * `value` - The value to validate
    /// * `nomination` - True if this is during nomination phase
    ///
    /// # Returns
    /// The validation level for this value.
    fn validate_value(
        &self,
        slot_index: u64,
        value: &Value,
        nomination: bool,
    ) -> ValidationLevel;

    /// Combine multiple nominated values into one.
    ///
    /// This is called when nomination has produced multiple candidate values
    /// and we need to combine them into a single composite value for the
    /// ballot protocol.
    ///
    /// # Arguments
    /// * `slot_index` - The slot index
    /// * `candidates` - The candidate values to combine
    ///
    /// # Returns
    /// The combined value, or None if combination is not possible.
    fn combine_candidates(
        &self,
        slot_index: u64,
        candidates: &[Value],
    ) -> Option<Value>;

    /// Extract a valid value from a potentially invalid composite.
    ///
    /// When we receive a value from the network that may be partially valid,
    /// this method extracts the valid portion.
    ///
    /// # Arguments
    /// * `slot_index` - The slot index
    /// * `value` - The value to extract from
    ///
    /// # Returns
    /// The extracted valid value, or None if no valid value can be extracted.
    fn extract_valid_value(
        &self,
        slot_index: u64,
        value: &Value,
    ) -> Option<Value>;

    /// Emit an envelope to peers.
    ///
    /// Called when SCP needs to broadcast a message to the network.
    fn emit_envelope(&self, envelope: &ScpEnvelope);

    /// Get the quorum set for a node.
    ///
    /// # Arguments
    /// * `node_id` - The node whose quorum set we need
    ///
    /// # Returns
    /// The quorum set, or None if unknown.
    fn get_quorum_set(&self, node_id: &NodeId) -> Option<ScpQuorumSet>;

    /// Called when we start nominating a value for a slot.
    fn nominating_value(&self, slot_index: u64, value: &Value);

    /// Called when consensus is reached on a value.
    ///
    /// This is the final callback indicating that the slot has been
    /// externalized with the given value.
    fn value_externalized(&self, slot_index: u64, value: &Value);

    /// Called when a ballot is prepared.
    fn ballot_did_prepare(&self, slot_index: u64, ballot: &ScpBallot);

    /// Called when a ballot is confirmed.
    fn ballot_did_confirm(&self, slot_index: u64, ballot: &ScpBallot);

    /// Compute hash for node priority in nomination.
    ///
    /// This is used to deterministically order nodes during nomination
    /// to ensure consistent behavior across the network.
    fn compute_hash_node(
        &self,
        slot_index: u64,
        prev_value: &Value,
        is_priority: bool,
        round: u32,
        node_id: &NodeId,
    ) -> u64;

    /// Compute value hash for nomination ordering.
    fn compute_value_hash(
        &self,
        slot_index: u64,
        prev_value: &Value,
        round: u32,
        value: &Value,
    ) -> u64;

    /// Compute timeout for a nomination round.
    ///
    /// Timeouts typically increase with round number to allow more
    /// time for consensus when the network is unstable.
    fn compute_timeout(&self, round: u32) -> Duration;

    /// Sign an envelope before sending.
    ///
    /// The implementation should compute the signature over the
    /// statement and set it on the envelope.
    fn sign_envelope(&self, envelope: &mut ScpEnvelope);

    /// Verify an envelope's signature.
    ///
    /// # Returns
    /// True if the signature is valid.
    fn verify_envelope(&self, envelope: &ScpEnvelope) -> bool;

    /// Get the hash of a quorum set.
    ///
    /// This is used to reference quorum sets by hash in SCP messages.
    fn hash_quorum_set(&self, quorum_set: &ScpQuorumSet) -> Hash256 {
        // Default implementation using XDR serialization
        Hash256::hash_xdr(quorum_set).unwrap_or(Hash256::ZERO)
    }
}
