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

    /// Get all envelopes for a specific slot.
    pub fn get_slot_envelopes(&self, slot_index: u64) -> Vec<ScpEnvelope> {
        let slots = self.slots.read();
        let Some(slot) = slots.get(&slot_index) else {
            return Vec::new();
        };

        slot.get_envelopes()
            .values()
            .flat_map(|envs| envs.iter().cloned())
            .collect()
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
        self.driver.compute_timeout(round, true)
    }

    /// Get the timeout duration for a ballot round.
    pub fn get_ballot_timeout(&self, round: u32) -> Duration {
        self.driver.compute_timeout(round, false)
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
            heard_from_quorum: slot.heard_from_quorum(),
            ballot_phase: slot.ballot_phase(),
            nomination_round: slot.nomination().round(),
            ballot_round: slot.ballot_counter(),
        })
    }

    /// Get SCP envelopes for recent slots.
    ///
    /// Returns envelopes for slots starting from `from_slot` up to the current slot.
    /// This is used to respond to GetScpState requests from peers.
    pub fn get_scp_state(&self, from_slot: u64) -> Vec<ScpEnvelope> {
        let slots = self.slots.read();
        let mut envelopes = Vec::new();

        let mut indices: Vec<_> = slots.keys().copied().filter(|s| *s >= from_slot).collect();
        indices.sort_unstable();

        for slot_index in indices {
            if let Some(slot) = slots.get(&slot_index) {
                slot.process_current_state(
                    |envelope| {
                        envelopes.push(envelope.clone());
                        true
                    },
                    false,
                );
            }
        }

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
    /// Whether we've heard from quorum for the current ballot.
    pub heard_from_quorum: bool,
    /// Current ballot phase.
    pub ballot_phase: crate::ballot::BallotPhase,
    /// Current nomination round.
    pub nomination_round: u32,
    /// Current ballot round (ballot counter), if any.
    pub ballot_round: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::ValidationLevel;
    use crate::quorum::hash_quorum_set;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;
    use stellar_xdr::curr::{
        PublicKey, ScpBallot, ScpNomination, ScpStatement, ScpStatementPrepare,
        ScpStatementPledges, Uint256,
    };

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
            1
        }

        fn compute_value_hash(
            &self,
            _slot_index: u64,
            _prev_value: &Value,
            _round: u32,
            _value: &Value,
        ) -> u64 {
            1
        }

        fn compute_timeout(&self, round: u32, _is_nomination: bool) -> Duration {
            Duration::from_secs(1 + round as u64)
        }

        fn sign_envelope(&self, _envelope: &mut ScpEnvelope) {}

        fn verify_envelope(&self, _envelope: &ScpEnvelope) -> bool {
            true
        }
    }

    /// Driver that treats all values as MaybeValid.
    struct MaybeValidDriver {
        emit_count: AtomicU32,
        quorum_set: ScpQuorumSet,
    }

    impl MaybeValidDriver {
        fn new(quorum_set: ScpQuorumSet) -> Self {
            Self {
                emit_count: AtomicU32::new(0),
                quorum_set,
            }
        }
    }

    impl SCPDriver for MaybeValidDriver {
        fn validate_value(
            &self,
            _slot_index: u64,
            _value: &Value,
            _nomination: bool,
        ) -> ValidationLevel {
            ValidationLevel::MaybeValid
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
            Some(self.quorum_set.clone())
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
            1
        }

        fn compute_value_hash(
            &self,
            _slot_index: u64,
            _prev_value: &Value,
            _round: u32,
            _value: &Value,
        ) -> u64 {
            1
        }

        fn compute_timeout(&self, round: u32, _is_nomination: bool) -> Duration {
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

    fn make_quorum_set_with(validators: Vec<NodeId>, threshold: u32) -> ScpQuorumSet {
        ScpQuorumSet {
            threshold,
            validators: validators.try_into().unwrap_or_default(),
            inner_sets: vec![].try_into().unwrap(),
        }
    }

    fn make_value(bytes: &[u8]) -> Value {
        bytes.to_vec().try_into().unwrap()
    }

    fn make_prepare_envelope(
        node_id: NodeId,
        slot_index: u64,
        quorum_set: &ScpQuorumSet,
        ballot: ScpBallot,
    ) -> ScpEnvelope {
        let prep = ScpStatementPrepare {
            quorum_set_hash: hash_quorum_set(quorum_set).into(),
            ballot,
            prepared: None,
            prepared_prime: None,
            n_c: 0,
            n_h: 0,
        };
        let statement = ScpStatement {
            node_id,
            slot_index,
            pledges: ScpStatementPledges::Prepare(prep),
        };
        ScpEnvelope {
            statement,
            signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
        }
    }

    fn make_nomination_envelope(
        node_id: NodeId,
        slot_index: u64,
        quorum_set: &ScpQuorumSet,
        value: Value,
    ) -> ScpEnvelope {
        let nomination = ScpNomination {
            quorum_set_hash: hash_quorum_set(quorum_set).into(),
            votes: vec![value].try_into().unwrap(),
            accepted: vec![].try_into().unwrap(),
        };
        let statement = ScpStatement {
            node_id,
            slot_index,
            pledges: ScpStatementPledges::Nominate(nomination),
        };
        ScpEnvelope {
            statement,
            signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
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
    fn test_get_scp_state_skips_self_when_not_fully_validated() {
        let node_a = make_node_id(1);
        let node_b = make_node_id(2);
        let quorum_set = make_quorum_set_with(vec![node_a.clone(), node_b.clone()], 1);
        let driver = Arc::new(MaybeValidDriver::new(quorum_set.clone()));
        let scp = SCP::new(node_a.clone(), true, quorum_set.clone(), driver.clone());

        let ballot = ScpBallot {
            counter: 1,
            value: make_value(&[7]),
        };
        let env_b = make_prepare_envelope(node_b, 1, &quorum_set, ballot);
        scp.receive_envelope(env_b);

        let value = make_value(&[1, 2, 3]);
        let prev = make_value(&[0]);
        scp.nominate(1, value, &prev);

        let envelopes = scp.get_scp_state(1);
        assert!(!envelopes.is_empty());
        assert!(envelopes.iter().all(|env| env.statement.node_id != node_a));
        assert_eq!(driver.emit_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_get_scp_state_includes_self_when_fully_validated() {
        let node_a = make_node_id(1);
        let quorum_set = make_quorum_set_with(vec![node_a.clone()], 1);
        let driver = Arc::new(MockDriver::new());
        let scp = SCP::new(node_a.clone(), true, quorum_set.clone(), driver);

        let value = make_value(&[4, 5, 6]);
        let prev = make_value(&[1]);
        scp.nominate(1, value, &prev);

        let envelopes = scp.get_scp_state(1);
        assert!(envelopes.iter().any(|env| env.statement.node_id == node_a));
    }

    #[test]
    fn test_get_scp_state_orders_by_node_id() {
        let node_a = make_node_id(1);
        let node_b = make_node_id(2);
        let quorum_set = make_quorum_set_with(vec![node_a.clone(), node_b.clone()], 1);
        let driver = Arc::new(MockDriver::new());
        let scp = SCP::new(node_a.clone(), true, quorum_set.clone(), driver);

        let value_a = make_value(&[1]);
        let value_b = make_value(&[2]);
        let env_b = make_nomination_envelope(node_b.clone(), 1, &quorum_set, value_b);
        let env_a = make_nomination_envelope(node_a.clone(), 1, &quorum_set, value_a);
        scp.receive_envelope(env_b);
        scp.receive_envelope(env_a);

        let envelopes = scp.get_scp_state(1);
        assert!(envelopes.len() >= 2);
        assert!(envelopes[0].statement.node_id <= envelopes[1].statement.node_id);
    }

    #[test]
    fn test_get_scp_state_orders_by_slot() {
        let node_a = make_node_id(1);
        let node_b = make_node_id(2);
        let quorum_set = make_quorum_set_with(vec![node_a.clone(), node_b.clone()], 1);
        let driver = Arc::new(MockDriver::new());
        let scp = SCP::new(node_a.clone(), true, quorum_set.clone(), driver);

        let env_slot2 = make_nomination_envelope(
            node_b.clone(),
            2,
            &quorum_set,
            make_value(&[2]),
        );
        let env_slot1 = make_nomination_envelope(
            node_a.clone(),
            1,
            &quorum_set,
            make_value(&[1]),
        );
        scp.receive_envelope(env_slot2);
        scp.receive_envelope(env_slot1);

        let envelopes = scp.get_scp_state(1);
        assert!(envelopes.len() >= 2);
        assert!(envelopes[0].statement.slot_index <= envelopes[1].statement.slot_index);
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
