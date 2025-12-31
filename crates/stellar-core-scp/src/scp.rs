//! Main SCP driver implementation.
//!
//! This module provides the main `SCP` struct that coordinates
//! consensus across multiple slots.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use stellar_xdr::curr::{NodeId, ScpEnvelope, ScpQuorumSet, Value};

use crate::driver::SCPDriver;
use crate::slot::Slot;
use crate::EnvelopeState;

/// Main SCP driver that manages slots and coordinates consensus.
///
/// This is the primary interface for interacting with SCP.
/// It manages per-slot state and delegates to the driver for
/// application-specific behavior.
pub struct SCP<D: SCPDriver> {
    /// Local node identifier.
    local_node_id: NodeId,
    /// Whether this node is a validator.
    is_validator: bool,
    /// Local quorum set.
    local_quorum_set: ScpQuorumSet,
    /// Per-slot state.
    slots: RwLock<HashMap<u64, Slot>>,
    /// Driver callbacks.
    driver: Arc<D>,
    /// Maximum number of slots to keep in memory.
    max_slots: usize,
}

impl<D: SCPDriver> SCP<D> {
    /// Create a new SCP instance.
    ///
    /// # Arguments
    /// * `node_id` - The local node's identifier
    /// * `is_validator` - Whether this node participates in consensus
    /// * `quorum_set` - The local node's quorum set
    /// * `driver` - The driver for application-specific callbacks
    pub fn new(
        node_id: NodeId,
        is_validator: bool,
        quorum_set: ScpQuorumSet,
        driver: Arc<D>,
    ) -> Self {
        Self {
            local_node_id: node_id,
            is_validator,
            local_quorum_set: quorum_set,
            slots: RwLock::new(HashMap::new()),
            driver,
            max_slots: 100,
        }
    }

    /// Get the local node ID.
    pub fn local_node_id(&self) -> &NodeId {
        &self.local_node_id
    }

    /// Check if this node is a validator.
    pub fn is_validator(&self) -> bool {
        self.is_validator
    }

    /// Get the local quorum set.
    pub fn local_quorum_set(&self) -> &ScpQuorumSet {
        &self.local_quorum_set
    }

    /// Update the local quorum set.
    pub fn set_local_quorum_set(&mut self, quorum_set: ScpQuorumSet) {
        self.local_quorum_set = quorum_set;
    }

    /// Process an incoming SCP envelope.
    ///
    /// This is the main entry point for processing SCP messages
    /// received from the network.
    ///
    /// # Arguments
    /// * `envelope` - The SCP envelope to process
    ///
    /// # Returns
    /// The state of the envelope after processing.
    pub fn receive_envelope(&self, envelope: ScpEnvelope) -> EnvelopeState {
        // Verify signature
        if !self.driver.verify_envelope(&envelope) {
            tracing::warn!(
                node_id = ?envelope.statement.node_id,
                slot = envelope.statement.slot_index,
                "Invalid envelope signature"
            );
            return EnvelopeState::Invalid;
        }

        let slot_index = envelope.statement.slot_index;

        let mut slots = self.slots.write();

        // Get or create slot
        let slot = slots.entry(slot_index).or_insert_with(|| {
            Slot::new(
                slot_index,
                self.local_node_id.clone(),
                self.local_quorum_set.clone(),
                self.is_validator,
            )
        });

        // Process the envelope
        let result = slot.process_envelope(envelope, &self.driver);

        // Cleanup old slots if needed
        if slots.len() > self.max_slots {
            self.cleanup_old_slots(&mut slots);
        }

        result
    }

    /// Nominate a value for a slot.
    ///
    /// This starts the nomination process for a slot. Should be called
    /// when the application has a value it wants to propose for consensus.
    ///
    /// # Arguments
    /// * `slot_index` - The slot to nominate for
    /// * `value` - The value to nominate
    /// * `prev_value` - The previous slot's value (for priority calculation)
    ///
    /// # Returns
    /// True if nomination was started successfully.
    pub fn nominate(
        &self,
        slot_index: u64,
        value: Value,
        prev_value: &Value,
    ) -> bool {
        if !self.is_validator {
            return false;
        }

        let mut slots = self.slots.write();

        let slot = slots.entry(slot_index).or_insert_with(|| {
            Slot::new(
                slot_index,
                self.local_node_id.clone(),
                self.local_quorum_set.clone(),
                self.is_validator,
            )
        });

        slot.nominate(value, prev_value, false, &self.driver)
    }

    /// Nominate with timeout flag.
    ///
    /// Called when the nomination timer expires without reaching consensus.
    pub fn nominate_timeout(
        &self,
        slot_index: u64,
        value: Value,
        prev_value: &Value,
    ) -> bool {
        if !self.is_validator {
            return false;
        }

        let mut slots = self.slots.write();

        if let Some(slot) = slots.get_mut(&slot_index) {
            slot.nominate(value, prev_value, true, &self.driver)
        } else {
            false
        }
    }

    /// Stop nomination for a slot.
    ///
    /// Called when we want to stop proposing new values,
    /// typically when the ballot protocol has taken over.
    pub fn stop_nomination(&self, slot_index: u64) {
        if let Some(slot) = self.slots.write().get_mut(&slot_index) {
            slot.stop_nomination();
        }
    }

    /// Bump ballot on timeout.
    ///
    /// Called when the ballot timer expires. Increases the ballot
    /// counter to try to make progress.
    pub fn bump_ballot(&self, slot_index: u64) -> bool {
        if let Some(slot) = self.slots.write().get_mut(&slot_index) {
            slot.bump_ballot_on_timeout(&self.driver)
        } else {
            false
        }
    }

    /// Get the externalized value for a slot.
    ///
    /// # Returns
    /// The externalized value if consensus was reached, None otherwise.
    pub fn get_externalized_value(&self, slot_index: u64) -> Option<Value> {
        self.slots
            .read()
            .get(&slot_index)
            .and_then(|slot| slot.get_externalized_value().cloned())
    }

    /// Check if a slot is externalized.
    pub fn is_slot_externalized(&self, slot_index: u64) -> bool {
        self.slots
            .read()
            .get(&slot_index)
            .map(|slot| slot.is_externalized())
            .unwrap_or(false)
    }

    /// Check if a slot is fully validated.
    pub fn is_slot_fully_validated(&self, slot_index: u64) -> bool {
        self.slots
            .read()
            .get(&slot_index)
            .map(|slot| slot.is_fully_validated())
            .unwrap_or(false)
    }

    /// Force externalize a slot with a specific value.
    ///
    /// Used during catchup when applying historical ledgers.
    pub fn force_externalize(&self, slot_index: u64, value: Value) {
        let mut slots = self.slots.write();

        let slot = slots.entry(slot_index).or_insert_with(|| {
            Slot::new(
                slot_index,
                self.local_node_id.clone(),
                self.local_quorum_set.clone(),
                self.is_validator,
            )
        });

        slot.force_externalize(value);
    }

    /// Purge old slots to free memory.
    ///
    /// Removes slots older than `max_slot_to_keep`.
    pub fn purge_slots(&self, max_slot_to_keep: u64) {
        self.slots
            .write()
            .retain(|&slot_index, _| slot_index >= max_slot_to_keep);
    }

    /// Get the number of active slots.
    pub fn slot_count(&self) -> usize {
        self.slots.read().len()
    }

    /// Get all active slot indices.
    pub fn active_slots(&self) -> Vec<u64> {
        self.slots.read().keys().copied().collect()
    }

    /// Get the highest externalized slot.
    pub fn highest_externalized_slot(&self) -> Option<u64> {
        self.slots
            .read()
            .iter()
            .filter(|(_, slot)| slot.is_externalized())
            .map(|(&index, _)| index)
            .max()
    }

    /// Get the timeout duration for a nomination round.
    pub fn get_nomination_timeout(&self, round: u32) -> Duration {
        self.driver.compute_timeout(round)
    }

    /// Get the timeout duration for a ballot round.
    pub fn get_ballot_timeout(&self, round: u32) -> Duration {
        // Ballot timeouts are typically the same as nomination timeouts
        self.driver.compute_timeout(round)
    }

    /// Cleanup old slots, keeping only the most recent ones.
    fn cleanup_old_slots(&self, slots: &mut HashMap<u64, Slot>) {
        if slots.len() <= self.max_slots {
            return;
        }

        // Find the minimum slot to keep
        let mut indices: Vec<_> = slots.keys().copied().collect();
        indices.sort_unstable();

        let to_remove = indices.len() - self.max_slots;
        for index in indices.into_iter().take(to_remove) {
            slots.remove(&index);
        }
    }

    /// Get slot state for debugging.
    pub fn get_slot_state(&self, slot_index: u64) -> Option<SlotState> {
        self.slots.read().get(&slot_index).map(|slot| SlotState {
            slot_index,
            is_externalized: slot.is_externalized(),
            is_nominating: slot.is_nominating(),
            ballot_phase: slot.ballot_phase(),
            nomination_round: slot.nomination().round(),
        })
    }

    /// Get SCP envelopes for recent slots.
    ///
    /// Returns envelopes for slots starting from `from_slot` up to the current slot.
    /// This is used to respond to GetScpState requests from peers.
    pub fn get_scp_state(&self, from_slot: u64) -> Vec<ScpEnvelope> {
        let slots = self.slots.read();
        let mut envelopes = Vec::new();

        for (&slot_index, slot) in slots.iter() {
            if slot_index >= from_slot {
                // Get all envelopes from this slot
                for node_envelopes in slot.get_envelopes().values() {
                    envelopes.extend(node_envelopes.iter().cloned());
                }
            }
        }

        // Sort by slot index for deterministic ordering
        envelopes.sort_by_key(|e| e.statement.slot_index);

        envelopes
    }
}

/// Summary of slot state for debugging.
#[derive(Debug, Clone)]
pub struct SlotState {
    /// Slot index.
    pub slot_index: u64,
    /// Whether externalized.
    pub is_externalized: bool,
    /// Whether currently nominating.
    pub is_nominating: bool,
    /// Current ballot phase.
    pub ballot_phase: crate::ballot::BallotPhase,
    /// Current nomination round.
    pub nomination_round: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::ValidationLevel;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;
    use stellar_xdr::curr::{PublicKey, ScpBallot, Uint256};

    /// Mock driver for testing.
    struct MockDriver {
        emit_count: AtomicU32,
    }

    impl MockDriver {
        fn new() -> Self {
            Self {
                emit_count: AtomicU32::new(0),
            }
        }
    }

    impl SCPDriver for MockDriver {
        fn validate_value(
            &self,
            _slot_index: u64,
            _value: &Value,
            _nomination: bool,
        ) -> ValidationLevel {
            ValidationLevel::FullyValidated
        }

        fn combine_candidates(
            &self,
            _slot_index: u64,
            candidates: &[Value],
        ) -> Option<Value> {
            candidates.first().cloned()
        }

        fn extract_valid_value(
            &self,
            _slot_index: u64,
            value: &Value,
        ) -> Option<Value> {
            Some(value.clone())
        }

        fn emit_envelope(&self, _envelope: &ScpEnvelope) {
            self.emit_count.fetch_add(1, Ordering::SeqCst);
        }

        fn get_quorum_set(&self, _node_id: &NodeId) -> Option<ScpQuorumSet> {
            None
        }

        fn nominating_value(&self, _slot_index: u64, _value: &Value) {}

        fn value_externalized(&self, _slot_index: u64, _value: &Value) {}

        fn ballot_did_prepare(&self, _slot_index: u64, _ballot: &ScpBallot) {}

        fn ballot_did_confirm(&self, _slot_index: u64, _ballot: &ScpBallot) {}

        fn compute_hash_node(
            &self,
            _slot_index: u64,
            _prev_value: &Value,
            _is_priority: bool,
            _round: u32,
            _node_id: &NodeId,
        ) -> u64 {
            0
        }

        fn compute_value_hash(
            &self,
            _slot_index: u64,
            _prev_value: &Value,
            _round: u32,
            _value: &Value,
        ) -> u64 {
            0
        }

        fn compute_timeout(&self, round: u32) -> Duration {
            Duration::from_secs(1 + round as u64)
        }

        fn sign_envelope(&self, _envelope: &mut ScpEnvelope) {}

        fn verify_envelope(&self, _envelope: &ScpEnvelope) -> bool {
            true
        }
    }

    fn make_node_id(seed: u8) -> NodeId {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        NodeId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes)))
    }

    fn make_quorum_set() -> ScpQuorumSet {
        ScpQuorumSet {
            threshold: 1,
            validators: vec![].try_into().unwrap(),
            inner_sets: vec![].try_into().unwrap(),
        }
    }

    #[test]
    fn test_scp_new() {
        let driver = Arc::new(MockDriver::new());
        let scp = SCP::new(
            make_node_id(1),
            true,
            make_quorum_set(),
            driver,
        );

        assert!(scp.is_validator());
        assert_eq!(scp.slot_count(), 0);
    }

    #[test]
    fn test_force_externalize() {
        let driver = Arc::new(MockDriver::new());
        let scp = SCP::new(
            make_node_id(1),
            true,
            make_quorum_set(),
            driver,
        );

        let value: Value = vec![1, 2, 3].try_into().unwrap();
        scp.force_externalize(42, value.clone());

        assert!(scp.is_slot_externalized(42));
        assert_eq!(scp.get_externalized_value(42), Some(value));
    }

    #[test]
    fn test_purge_slots() {
        let driver = Arc::new(MockDriver::new());
        let scp = SCP::new(
            make_node_id(1),
            true,
            make_quorum_set(),
            driver,
        );

        // Create some slots
        for i in 1..=10 {
            let value: Value = vec![i as u8].try_into().unwrap();
            scp.force_externalize(i, value);
        }

        assert_eq!(scp.slot_count(), 10);

        // Purge old slots
        scp.purge_slots(6);

        assert_eq!(scp.slot_count(), 5);
        assert!(scp.get_externalized_value(5).is_none());
        assert!(scp.get_externalized_value(6).is_some());
    }
}
