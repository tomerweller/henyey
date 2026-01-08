//! Per-slot consensus state for SCP.
//!
//! Each slot in SCP represents an independent consensus instance, typically
//! corresponding to a ledger sequence number in Stellar. This module provides
//! the [`Slot`] struct which manages the complete consensus state for a single
//! slot, including both the nomination and ballot protocol phases.
//!
//! # Slot Lifecycle
//!
//! 1. **Creation**: Slot is created when first needed (either via nomination
//!    or when receiving an envelope for that slot)
//! 2. **Nomination**: Nodes propose and vote on candidate values
//! 3. **Ballot Protocol**: Once candidates are confirmed, nodes vote on ballots
//!    to agree on a single value
//! 4. **Externalization**: When consensus is reached, the slot is externalized
//!    and its value becomes final
//!
//! # State Transitions
//!
//! ```text
//! [New] --> [Nominating] --> [Ballot: Prepare] --> [Ballot: Confirm] --> [Externalized]
//!                                    |                    |
//!                                    +--(timeout)---------+
//! ```
//!
//! # Force Externalization
//!
//! During catchup from historical data, slots can be force-externalized with
//! known values, bypassing the consensus process entirely.

use std::collections::HashMap;
use std::sync::Arc;

use stellar_xdr::curr::{NodeId, ScpEnvelope, ScpQuorumSet, ScpStatementPledges, Value};

use crate::ballot::{BallotPhase, BallotProtocol};
use crate::driver::SCPDriver;
use crate::nomination::NominationProtocol;
use crate::EnvelopeState;

/// Per-slot consensus state managing nomination and ballot protocols.
///
/// A `Slot` encapsulates all the state needed to reach consensus on a single
/// value for a given slot index. Each slot progresses independently through
/// the nomination phase (where candidates are proposed) and the ballot phase
/// (where a single value is agreed upon).
///
/// # Fields
///
/// The slot maintains:
/// - Nomination protocol state for collecting and voting on candidate values
/// - Ballot protocol state for the prepare/confirm/externalize phases
/// - Envelope history for all received SCP messages
/// - Validation state tracking
#[derive(Debug)]
pub struct Slot {
    /// The slot index (typically corresponds to ledger sequence number).
    slot_index: u64,

    /// The local node's identifier (public key).
    local_node_id: NodeId,

    /// The local node's quorum set configuration.
    local_quorum_set: ScpQuorumSet,

    /// Whether this node is a validator (actively participates in consensus).
    is_validator: bool,

    /// State machine for the nomination protocol phase.
    nomination: NominationProtocol,

    /// State machine for the ballot protocol phase.
    ballot: BallotProtocol,

    /// History of all envelopes received for this slot, grouped by sender.
    envelopes: HashMap<NodeId, Vec<ScpEnvelope>>,

    /// The externalized value if consensus has been reached, None otherwise.
    externalized_value: Option<Value>,

    /// Whether nomination has been explicitly started for this slot.
    nomination_started: bool,

    /// Whether all values in this slot have been fully validated.
    ///
    /// This affects whether local envelopes are emitted to the network.
    /// When false, the node defers broadcasting its own statements.
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
        let mut nomination = NominationProtocol::new();
        nomination.set_fully_validated(is_validator);
        let mut ballot = BallotProtocol::new();
        ballot.set_fully_validated(is_validator);

        Self {
            slot_index,
            local_node_id,
            local_quorum_set,
            is_validator,
            nomination,
            ballot,
            envelopes: HashMap::new(),
            externalized_value: None,
            nomination_started: false,
            fully_validated: is_validator,
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

    /// Check if we've heard from quorum for the current ballot.
    pub fn heard_from_quorum(&self) -> bool {
        self.ballot.heard_from_quorum()
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

        if result.is_valid() {
            self.envelopes
                .entry(node_id.clone())
                .or_default()
                .push(envelope.clone());
        }

        // Check if we need to transition from nomination to ballot
        self.check_nomination_to_ballot(driver);

        // Check if we've externalized
        if self.ballot.is_externalized() && self.externalized_value.is_none() {
            if let Some(value) = self.ballot.get_externalized_value() {
                self.externalized_value = Some(value.clone());
                self.fully_validated = true;
                self.nomination.set_fully_validated(true);
                self.ballot.set_fully_validated(true);
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

    /// Get the current ballot counter for this slot, if any.
    pub fn ballot_counter(&self) -> Option<u32> {
        self.ballot.current_ballot_counter()
    }

    /// Process the latest envelopes for this slot.
    pub fn process_current_state<F>(&self, mut f: F, force_self: bool) -> bool
    where
        F: FnMut(&ScpEnvelope) -> bool,
    {
        self.nomination.process_current_state(
            |env| f(env),
            &self.local_node_id,
            self.fully_validated,
            force_self,
        ) && self.ballot.process_current_state(
            |env| f(env),
            &self.local_node_id,
            self.fully_validated,
            force_self,
        )
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
        if !self.ballot.is_statement_sane(
            &envelope.statement,
            &self.local_node_id,
            &self.local_quorum_set,
            driver,
        ) {
            return EnvelopeState::Invalid;
        }

        let validation = self
            .ballot
            .validate_statement_values(&envelope.statement, driver, self.slot_index);

        if validation == crate::ValidationLevel::Invalid {
            return EnvelopeState::Invalid;
        }

        if validation == crate::ValidationLevel::MaybeValid {
            self.fully_validated = false;
            self.nomination.set_fully_validated(false);
            self.ballot.set_fully_validated(false);
        }

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
        self.nomination.set_fully_validated(true);
        self.ballot.set_fully_validated(true);
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
