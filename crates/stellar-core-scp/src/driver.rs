//! SCP driver trait defining callbacks for the SCP protocol.
//!
//! The [`SCPDriver`] trait is the primary integration point between the SCP
//! consensus protocol and the application layer (typically the Herder component).
//! SCP itself is completely isolated and stateless with respect to application
//! logic - all application-specific behavior is delegated through this trait.
//!
//! # Design Philosophy
//!
//! SCP is designed to be a pure consensus algorithm that:
//! - Does not know how to validate transaction sets
//! - Does not know how to persist data
//! - Does not know how to communicate with peers
//!
//! The driver provides all of this context, making SCP reusable and testable.
//!
//! # Implementation Requirements
//!
//! Implementors must ensure that:
//! - Value validation is deterministic across all nodes
//! - Hash computations match the network's expectations
//! - Timeouts increase appropriately to allow convergence
//!
//! # Example
//!
//! ```ignore
//! struct MyHerder {
//!     // ... application state
//! }
//!
//! impl SCPDriver for MyHerder {
//!     fn validate_value(&self, slot: u64, value: &Value, nomination: bool) -> ValidationLevel {
//!         // Validate transaction set...
//!         ValidationLevel::FullyValidated
//!     }
//!     // ... other methods
//! }
//! ```

use std::time::Duration;

use stellar_core_common::Hash256;
use stellar_xdr::curr::{NodeId, ScpBallot, ScpEnvelope, ScpQuorumSet, Value};

/// Validation level for SCP values.
///
/// During consensus, values must be validated to ensure nodes agree
/// on valid data. The validation level allows for deferred validation
/// during nomination (when full context may not be available) while
/// requiring full validation before externalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationLevel {
    /// The value is invalid and should be rejected.
    ///
    /// Invalid values are not voted for and not accepted from peers.
    Invalid,

    /// The value may be valid but has not been fully validated yet.
    ///
    /// This is used during the nomination phase when full validation
    /// may be expensive or require context not yet available. Values
    /// at this level can participate in nomination but will require
    /// full validation before being committed.
    MaybeValid,

    /// The value has been fully validated and is known to be valid.
    ///
    /// Only fully validated values can be externalized (committed).
    FullyValidated,
}

/// Callback interface for the SCP consensus protocol.
///
/// This trait is implemented by the application layer (typically the Herder)
/// to connect SCP to the rest of the system. SCP is designed to be completely
/// isolated from application logic, and all interactions happen through
/// this trait.
///
/// # Thread Safety
///
/// Implementors must be `Send + Sync` as SCP may invoke callbacks from
/// multiple contexts. Internal state should be protected appropriately.
///
/// # Callback Categories
///
/// The trait methods fall into several categories:
///
/// - **Validation**: [`validate_value`](Self::validate_value), [`extract_valid_value`](Self::extract_valid_value)
/// - **Value Composition**: [`combine_candidates`](Self::combine_candidates)
/// - **Quorum Set Lookup**: [`get_quorum_set`](Self::get_quorum_set), [`get_quorum_set_by_hash`](Self::get_quorum_set_by_hash)
/// - **Cryptography**: [`sign_envelope`](Self::sign_envelope), [`verify_envelope`](Self::verify_envelope), [`hash_quorum_set`](Self::hash_quorum_set)
/// - **Hash Computation**: [`compute_hash_node`](Self::compute_hash_node), [`compute_value_hash`](Self::compute_value_hash)
/// - **Network**: [`emit_envelope`](Self::emit_envelope)
/// - **Notifications**: [`nominating_value`](Self::nominating_value), [`value_externalized`](Self::value_externalized), etc.
/// - **Timing**: [`compute_timeout`](Self::compute_timeout)
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

    /// Get a quorum set by its hash.
    ///
    /// # Arguments
    /// * `hash` - The quorum set hash
    ///
    /// # Returns
    /// The quorum set, or None if unknown.
    fn get_quorum_set_by_hash(&self, _hash: &Hash256) -> Option<ScpQuorumSet> {
        None
    }

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

    /// Called when a ballot is accepted as prepared.
    fn accepted_ballot_prepared(&self, _slot_index: u64, _ballot: &ScpBallot) {}

    /// Called when a ballot is confirmed as prepared.
    fn confirmed_ballot_prepared(&self, _slot_index: u64, _ballot: &ScpBallot) {}

    /// Called when a ballot is accepted as commit.
    fn accepted_commit(&self, _slot_index: u64, _ballot: &ScpBallot) {}

    /// Called when we heard from a quorum for the current ballot.
    fn ballot_did_hear_from_quorum(&self, _slot_index: u64, _ballot: &ScpBallot) {}

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

    /// Compute timeout for a nomination or ballot round.
    ///
    /// Timeouts typically increase with round number to allow more
    /// time for consensus when the network is unstable.
    fn compute_timeout(&self, round: u32, is_nomination: bool) -> Duration;

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
