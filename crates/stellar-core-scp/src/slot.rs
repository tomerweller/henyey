//! Per-slot consensus state for SCP.
//!
//! Each slot (typically corresponding to a ledger sequence number)
//! maintains its own nomination and ballot protocol state.

use std::collections::HashMap;
use std::sync::Arc;

use stellar_xdr::curr::{NodeId, ScpEnvelope, ScpQuorumSet, ScpStatementPledges, Value};

use crate::ballot::{BallotPhase, BallotProtocol};
use crate::driver::SCPDriver;
use crate::nomination::NominationProtocol;
use crate::EnvelopeState;

/// Per-slot consensus state.
///
/// Manages the nomination and ballot protocols for a single slot.
#[derive(Debug)]
pub struct Slot {
    /// The slot index (typically ledger sequence number).
    slot_index: u64,
    /// Local node ID.
    local_node_id: NodeId,
    /// Local quorum set.
    local_quorum_set: ScpQuorumSet,
    /// Whether we're a validator.
    is_validator: bool,
    /// Nomination protocol state.
    nomination: NominationProtocol,
    /// Ballot protocol state.
    ballot: BallotProtocol,
    /// All envelopes received for this slot.
    envelopes: HashMap<NodeId, Vec<ScpEnvelope>>,
    /// Externalized value (if consensus reached).
    externalized_value: Option<Value>,
    /// Whether nomination was triggered.
    nomination_started: bool,
    /// Whether we've fully externalized.
    fully_validated: bool,
}

impl Slot {
    /// Create a new slot.
    pub fn new(
        slot_index: u64,
        local_node_id: NodeId,
        local_quorum_set: ScpQuorumSet,
        is_validator: bool,
    ) -> Self {
        Self {
            slot_index,
            local_node_id,
            local_quorum_set,
            is_validator,
            nomination: NominationProtocol::new(),
            ballot: BallotProtocol::new(),
            envelopes: HashMap::new(),
            externalized_value: None,
            nomination_started: false,
            fully_validated: false,
        }
    }

    /// Get the slot index.
    pub fn slot_index(&self) -> u64 {
        self.slot_index
    }

    /// Get the nomination protocol state.
    pub fn nomination(&self) -> &NominationProtocol {
        &self.nomination
    }

    /// Get the ballot protocol state.
    pub fn ballot(&self) -> &BallotProtocol {
        &self.ballot
    }

    /// Get the externalized value if consensus was reached.
    pub fn get_externalized_value(&self) -> Option<&Value> {
        self.externalized_value.as_ref()
    }

    /// Check if this slot is externalized.
    pub fn is_externalized(&self) -> bool {
        self.externalized_value.is_some()
    }

    /// Check if this slot is fully validated.
    pub fn is_fully_validated(&self) -> bool {
        self.fully_validated
    }

    /// Process an incoming SCP envelope.
    ///
    /// # Returns
    /// The state of the envelope after processing.
    pub fn process_envelope<D: SCPDriver>(
        &mut self,
        envelope: ScpEnvelope,
        driver: &Arc<D>,
    ) -> EnvelopeState {
        let node_id = envelope.statement.node_id.clone();

        // Store envelope
        self.envelopes
            .entry(node_id.clone())
            .or_default()
            .push(envelope.clone());

        // Process based on statement type
        let result = match &envelope.statement.pledges {
            ScpStatementPledges::Nominate(_) => {
                self.process_nomination_envelope(&envelope, driver)
            }
            ScpStatementPledges::Prepare(_)
            | ScpStatementPledges::Confirm(_)
            | ScpStatementPledges::Externalize(_) => {
                self.process_ballot_envelope(&envelope, driver)
            }
        };

        // Check if we need to transition from nomination to ballot
        self.check_nomination_to_ballot(driver);

        // Check if we've externalized
        if self.ballot.is_externalized() && self.externalized_value.is_none() {
            if let Some(value) = self.ballot.get_externalized_value() {
                self.externalized_value = Some(value.clone());
                self.fully_validated = true;
            }
        }

        result
    }

    /// Nominate a value for this slot.
    ///
    /// # Returns
    /// True if nomination was successful.
    pub fn nominate<D: SCPDriver>(
        &mut self,
        value: Value,
        prev_value: &Value,
        timedout: bool,
        driver: &Arc<D>,
    ) -> bool {
        if !self.is_validator {
            return false;
        }

        if self.is_externalized() {
            return false;
        }

        self.nomination_started = true;

        self.nomination.nominate(
            &self.local_node_id,
            &self.local_quorum_set,
            driver,
            self.slot_index,
            value,
            prev_value,
            timedout,
        )
    }

    /// Stop nomination for this slot.
    pub fn stop_nomination(&mut self) {
        self.nomination.stop();
    }

    /// Bump the ballot on timeout.
    pub fn bump_ballot_on_timeout<D: SCPDriver>(&mut self, driver: &Arc<D>) -> bool {
        if !self.is_validator {
            return false;
        }

        self.ballot.bump_timeout(
            &self.local_node_id,
            &self.local_quorum_set,
            driver,
            self.slot_index,
        )
    }

    /// Get all envelopes received for this slot.
    pub fn get_envelopes(&self) -> &HashMap<NodeId, Vec<ScpEnvelope>> {
        &self.envelopes
    }

    /// Get the latest envelope from a specific node.
    pub fn get_latest_envelope(&self, node_id: &NodeId) -> Option<&ScpEnvelope> {
        self.envelopes.get(node_id).and_then(|v| v.last())
    }

    /// Process a nomination envelope.
    fn process_nomination_envelope<D: SCPDriver>(
        &mut self,
        envelope: &ScpEnvelope,
        driver: &Arc<D>,
    ) -> EnvelopeState {
        self.nomination.process_envelope(
            envelope,
            &self.local_node_id,
            &self.local_quorum_set,
            driver,
            self.slot_index,
        )
    }

    /// Process a ballot protocol envelope.
    fn process_ballot_envelope<D: SCPDriver>(
        &mut self,
        envelope: &ScpEnvelope,
        driver: &Arc<D>,
    ) -> EnvelopeState {
        self.ballot.process_envelope(
            envelope,
            &self.local_node_id,
            &self.local_quorum_set,
            driver,
            self.slot_index,
        )
    }

    /// Check if we should transition from nomination to ballot protocol.
    fn check_nomination_to_ballot<D: SCPDriver>(&mut self, driver: &Arc<D>) {
        // If we already have a ballot, don't need to transition
        if self.ballot.current_ballot().is_some() {
            return;
        }

        // Check if nomination has produced a composite value
        let composite = self.nomination.latest_composite().cloned();
        if let Some(composite) = composite {
            // Stop nomination and start ballot
            self.nomination.stop();

            // Start ballot protocol with the composite value
            self.ballot.bump(
                &self.local_node_id,
                &self.local_quorum_set,
                driver,
                self.slot_index,
                composite,
                false,
            );
        }
    }

    /// Force externalize with a specific value.
    ///
    /// This is used during catchup when we receive historical ledgers
    /// that have already been externalized by the network.
    pub fn force_externalize(&mut self, value: Value) {
        self.externalized_value = Some(value);
        self.fully_validated = true;
        self.nomination.stop();
    }

    /// Get the current ballot phase.
    pub fn ballot_phase(&self) -> BallotPhase {
        self.ballot.phase()
    }

    /// Check if we're in nomination phase.
    pub fn is_nominating(&self) -> bool {
        self.nomination_started && !self.nomination.is_stopped()
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

    fn make_quorum_set() -> ScpQuorumSet {
        ScpQuorumSet {
            threshold: 1,
            validators: vec![].try_into().unwrap(),
            inner_sets: vec![].try_into().unwrap(),
        }
    }

    #[test]
    fn test_slot_new() {
        let slot = Slot::new(42, make_node_id(1), make_quorum_set(), true);

        assert_eq!(slot.slot_index(), 42);
        assert!(!slot.is_externalized());
        assert!(slot.get_externalized_value().is_none());
    }

    #[test]
    fn test_force_externalize() {
        let mut slot = Slot::new(42, make_node_id(1), make_quorum_set(), true);

        let value: Value = vec![1, 2, 3].try_into().unwrap();
        slot.force_externalize(value.clone());

        assert!(slot.is_externalized());
        assert_eq!(slot.get_externalized_value(), Some(&value));
    }
}
