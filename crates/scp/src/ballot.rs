//! Ballot protocol implementation for SCP.
//!
//! The ballot protocol is the second phase of SCP consensus, following the
//! nomination phase. After nomination produces a composite value, nodes use
//! the ballot protocol to achieve Byzantine agreement on that exact value.
//!
//! # Protocol Phases
//!
//! The ballot protocol progresses through three phases:
//!
//! 1. **PREPARE**: Nodes vote to prepare ballots. A ballot is "prepared" when
//!    nodes agree it's safe to commit (no conflicting ballot can be committed).
//!
//! 2. **CONFIRM**: Nodes confirm that a ballot is prepared. This phase ensures
//!    the network agrees that a particular ballot is prepared.
//!
//! 3. **EXTERNALIZE**: Once a ballot is confirmed prepared, nodes commit to
//!    its value. This is the final state where consensus is reached.
//!
//! # Ballot Structure
//!
//! A ballot `<n, x>` consists of:
//! - `n`: A counter (increases on timeout to try new ballots)
//! - `x`: The consensus value
//!
//! Ballots with the same value but different counters are "compatible".
//! The protocol ensures only compatible ballots can be committed.
//!
//! # Key State Variables
//!
//! Following the SCP whitepaper notation:
//! - `b`: Current ballot we're working on
//! - `p`: Highest prepared ballot
//! - `p'`: Second-highest prepared ballot (if incompatible with p)
//! - `h`: Highest ballot we can confirm prepared
//! - `c`: Commit ballot (lowest ballot we can commit)
//!
//! # Safety Guarantees
//!
//! The ballot protocol ensures that if any node externalizes a value,
//! all other nodes will externalize the same value (or not externalize at all).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Maximum number of state transitions allowed in a single advance_slot call.
/// Exceeding this limit indicates a bug in the protocol state machine.
const MAX_PROTOCOL_TRANSITIONS: u32 = 50;

use stellar_xdr::curr::{
    Limits, NodeId, ScpBallot, ScpEnvelope, ScpQuorumSet, ScpStatement, ScpStatementConfirm,
    ScpStatementExternalize, ScpStatementPledges, ScpStatementPrepare, Value, WriteXdr,
};

use crate::driver::{SCPDriver, ValidationLevel};
use crate::quorum::{
    hash_quorum_set, is_blocking_set, is_quorum, is_quorum_set_sane, simple_quorum_set,
};
use crate::EnvelopeState;
use crate::SlotContext;

/// Extract the "working ballot" from an SCP statement.
///
/// The working ballot is the ballot a node is actively working on:
/// - For PREPARE statements: returns the `ballot` field
/// - For CONFIRM statements: returns a ballot with `(n_commit, value)`
/// - For EXTERNALIZE statements: returns a ballot with `(UINT32_MAX, value)`
///
/// This is useful for comparing the progress of different nodes in the
/// ballot protocol.
///
/// # Arguments
/// * `statement` - The SCP statement to extract the working ballot from
///
/// # Returns
/// The working ballot if the statement is a ballot statement (PREPARE/CONFIRM/EXTERNALIZE),
/// or None if it's a nomination statement.
pub fn get_working_ballot(statement: &ScpStatement) -> Option<ScpBallot> {
    match &statement.pledges {
        ScpStatementPledges::Prepare(prep) => Some(prep.ballot.clone()),
        ScpStatementPledges::Confirm(conf) => Some(ScpBallot {
            counter: conf.n_commit,
            value: conf.ballot.value.clone(),
        }),
        ScpStatementPledges::Externalize(ext) => Some(ScpBallot {
            counter: u32::MAX,
            value: ext.commit.value.clone(),
        }),
        ScpStatementPledges::Nominate(_) => None,
    }
}

/// Phase of the ballot protocol.
///
/// The ballot protocol progresses through these phases in order.
/// Once in the Externalize phase, the slot has reached consensus
/// and the value is final.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BallotPhase {
    /// Preparing ballots - voting to confirm a ballot is safe to commit.
    ///
    /// In this phase, nodes exchange PREPARE messages to establish
    /// which ballots are prepared (safe to commit).
    Prepare,

    /// Confirming a prepared ballot - agreeing on which ballot to commit.
    ///
    /// In this phase, nodes exchange CONFIRM messages to agree on
    /// a commit range. Transition occurs when accept-commit is achieved.
    Confirm,

    /// Externalized - consensus has been reached.
    ///
    /// This is the terminal state. The committed value is final and
    /// will not change. Nodes broadcast EXTERNALIZE messages.
    Externalize,
}

/// State machine for the ballot protocol phase.
///
/// The `BallotProtocol` implements the second phase of SCP consensus,
/// tracking all state needed to progress from PREPARE through CONFIRM
/// to EXTERNALIZE.
///
/// # Whitepaper Correspondence
///
/// This implementation follows the SCP whitepaper. Key state variables:
/// - `current_ballot` corresponds to `b` (current ballot)
/// - `prepared` corresponds to `p` (highest prepared ballot)
/// - `prepared_prime` corresponds to `p'` (second-highest prepared, incompatible with p)
/// - `high_ballot` corresponds to `h` (highest confirmable ballot)
/// - `commit` corresponds to `c` (commit ballot)
#[derive(Debug)]
pub struct BallotProtocol {
    /// Current ballot we're working on (`b` in the whitepaper).
    ///
    /// The ballot counter increases on timeout; the value comes from nomination.
    current_ballot: Option<ScpBallot>,

    /// Highest prepared ballot (`p` in the whitepaper).
    ///
    /// A ballot is prepared when we've accepted it as prepared.
    prepared: Option<ScpBallot>,

    /// Second-highest prepared ballot (`p'` in the whitepaper).
    ///
    /// Only set if it's incompatible with `prepared`. Used to prevent
    /// committing conflicting values.
    prepared_prime: Option<ScpBallot>,

    /// Highest ballot we can confirm prepared (`h` in the whitepaper).
    ///
    /// When h is set and c <= h, we can move to confirm phase.
    high_ballot: Option<ScpBallot>,

    /// Commit ballot (`c` in the whitepaper).
    ///
    /// The lowest ballot counter at which we can commit the value.
    commit: Option<ScpBallot>,

    /// Current protocol phase.
    phase: BallotPhase,

    /// Latest ballot envelope from each node.
    latest_envelopes: HashMap<NodeId, ScpEnvelope>,

    /// The consensus value (from the current or commit ballot).
    value: Option<Value>,

    /// Override value set when confirming prepared/commit.
    ///
    /// Used to ensure we commit the correct value when switching ballots.
    value_override: Option<Value>,

    /// Latest composite candidate value from the nomination protocol.
    ///
    /// Set by the Slot before calling into ballot protocol methods, so that
    /// `abandon_ballot` can access it (matching stellar-core `mSlot.getLatestCompositeCandidate()`).
    composite_candidate: Option<Value>,

    /// Whether we've heard from a quorum for the current ballot.
    heard_from_quorum: bool,

    /// Recursion depth counter for `advance_slot` (prevents infinite loops).
    current_message_level: u32,

    /// Last envelope we constructed locally.
    last_envelope: Option<ScpEnvelope>,

    /// Last envelope we actually emitted to the network.
    last_envelope_emit: Option<ScpEnvelope>,

    /// Whether values are fully validated (affects envelope emission).
    fully_validated: bool,

    /// Signal that nomination should be stopped (set by set_confirm_commit).
    ///
    /// In stellar-core, `setConfirmCommit` calls `mSlot.stopNomination()` directly.
    /// In Rust, we set this flag and let the Slot handle it.
    needs_stop_nomination: bool,
}

impl BallotProtocol {
    /// Create a new ballot protocol state.
    pub fn new() -> Self {
        Self {
            current_ballot: None,
            prepared: None,
            prepared_prime: None,
            high_ballot: None,
            commit: None,
            phase: BallotPhase::Prepare,
            latest_envelopes: HashMap::new(),
            value: None,
            value_override: None,
            composite_candidate: None,
            heard_from_quorum: false,
            current_message_level: 0,
            last_envelope: None,
            last_envelope_emit: None,
            fully_validated: true,
            needs_stop_nomination: false,
        }
    }

    /// Get the current phase.
    pub fn phase(&self) -> BallotPhase {
        self.phase
    }

    /// Get the current ballot.
    pub fn current_ballot(&self) -> Option<&ScpBallot> {
        self.current_ballot.as_ref()
    }

    /// Get the current ballot counter, if any.
    pub fn current_ballot_counter(&self) -> Option<u32> {
        self.current_ballot.as_ref().map(|ballot| ballot.counter)
    }

    /// Get the prepared ballot.
    pub fn prepared(&self) -> Option<&ScpBallot> {
        self.prepared.as_ref()
    }

    /// Get the commit ballot.
    pub fn commit(&self) -> Option<&ScpBallot> {
        self.commit.as_ref()
    }

    /// Check if we're externalized.
    pub fn is_externalized(&self) -> bool {
        self.phase == BallotPhase::Externalize
    }

    /// Set the latest composite candidate from the nomination protocol.
    ///
    /// Called by the Slot before invoking ballot protocol methods, so that
    /// `abandon_ballot` can use the composite candidate value.
    pub fn set_composite_candidate(&mut self, value: Option<Value>) {
        self.composite_candidate = value;
    }

    /// Check and clear the needs_stop_nomination flag.
    ///
    /// Returns true if nomination should be stopped (set by set_confirm_commit).
    pub fn take_needs_stop_nomination(&mut self) -> bool {
        let val = self.needs_stop_nomination;
        self.needs_stop_nomination = false;
        val
    }

    /// Process the latest ballot envelopes with a callback.
    pub fn process_current_state<F>(
        &self,
        f: F,
        local_node_id: &NodeId,
        fully_validated: bool,
        force_self: bool,
    ) -> bool
    where
        F: FnMut(&ScpEnvelope) -> bool,
    {
        crate::process_envelopes_current_state(
            &self.latest_envelopes,
            f,
            local_node_id,
            fully_validated,
            force_self,
        )
    }

    /// Update fully-validated state for local emission gating.
    pub fn set_fully_validated(&mut self, fully_validated: bool) {
        self.fully_validated = fully_validated;
    }

    /// Check whether we've heard from quorum for the current ballot.
    pub fn heard_from_quorum(&self) -> bool {
        self.heard_from_quorum
    }

    /// Get the externalized value if we've reached consensus.
    pub fn get_externalized_value(&self) -> Option<&Value> {
        if self.phase == BallotPhase::Externalize {
            self.value.as_ref()
        } else {
            None
        }
    }

    /// Force the ballot protocol to the externalized state with the given value.
    ///
    /// This is used when fast-forwarding via EXTERNALIZE messages from the network.
    /// It ensures that subsequent envelopes for this slot are properly validated
    /// against the externalized value.
    pub fn force_externalize(&mut self, value: Value) {
        let ballot = ScpBallot {
            counter: u32::MAX, // Infinite ballot for externalize
            value: value.clone(),
        };
        self.commit = Some(ballot.clone());
        self.high_ballot = Some(ballot.clone());
        self.current_ballot = Some(ballot);
        self.value = Some(value);
        self.phase = BallotPhase::Externalize;
    }

    /// Get the last envelope constructed by this node.
    pub fn get_last_envelope(&self) -> Option<&ScpEnvelope> {
        self.last_envelope.as_ref()
    }

    /// Get the latest envelope from a specific node.
    pub fn get_latest_envelope(&self, node_id: &NodeId) -> Option<&ScpEnvelope> {
        self.latest_envelopes.get(node_id)
    }

    /// Get envelopes that contributed to externalization.
    ///
    /// Matches stellar-core `BallotProtocol::getExternalizingState()`:
    /// - Only returns envelopes when in EXTERNALIZE phase
    /// - For other nodes: only includes envelopes with ballots compatible with commit
    /// - For self: only includes if `fully_validated` is true
    pub fn get_externalizing_state(
        &self,
        local_node_id: &NodeId,
        fully_validated: bool,
    ) -> Vec<ScpEnvelope> {
        let mut res = Vec::new();
        if self.phase != BallotPhase::Externalize {
            return res;
        }

        let commit = match &self.commit {
            Some(c) => c,
            None => return res,
        };

        for (node_id, envelope) in &self.latest_envelopes {
            if node_id != local_node_id {
                // For other nodes: check ballot compatibility with commit
                if let Some(working) = get_working_ballot(&envelope.statement) {
                    if ballot_compatible(&working, commit) {
                        res.push(envelope.clone());
                    }
                }
            } else if fully_validated {
                // Only return self messages if fully validated
                res.push(envelope.clone());
            }
        }

        res
    }

    /// Get the high ballot (highest confirmable).
    pub fn high_ballot(&self) -> Option<&ScpBallot> {
        self.high_ballot.as_ref()
    }

    /// Get the prepared' ballot.
    pub fn prepared_prime(&self) -> Option<&ScpBallot> {
        self.prepared_prime.as_ref()
    }

    /// Get the current consensus value.
    pub fn value(&self) -> Option<&Value> {
        self.value.as_ref()
    }

    /// Check protocol invariants for debugging.
    ///
    /// Returns Ok(()) if invariants hold, Err with description otherwise.
    pub fn check_invariants(&self) -> Result<(), String> {
        // In PREPARE phase, c == 0 (no commit yet)
        if self.phase == BallotPhase::Prepare && self.commit.is_some() {
            // Actually in prepare phase, c is only set when we have h set
            // The invariant is: c != 0 => h != 0
            if self.high_ballot.is_none() {
                return Err("commit set but high_ballot not set in Prepare phase".to_string());
            }
        }

        // If we have prepared' it must be < prepared and incompatible
        if let (Some(prepared), Some(prepared_prime)) = (&self.prepared, &self.prepared_prime) {
            if ballot_compare(prepared_prime, prepared) != std::cmp::Ordering::Less {
                return Err("prepared_prime must be less than prepared".to_string());
            }
            if ballot_compatible(prepared_prime, prepared) {
                return Err("prepared_prime must be incompatible with prepared".to_string());
            }
        }

        // c <= h (commit counter <= high counter)
        if let (Some(commit), Some(high)) = (&self.commit, &self.high_ballot) {
            if commit.counter > high.counter {
                return Err("commit counter exceeds high counter".to_string());
            }
            // c and h must have same value
            if commit.value != high.value {
                return Err("commit and high have different values".to_string());
            }
        }

        // In EXTERNALIZE, we must have commit and high
        if self.phase == BallotPhase::Externalize
            && (self.commit.is_none() || self.high_ballot.is_none())
        {
            return Err("externalize phase requires commit and high".to_string());
        }

        Ok(())
    }

    /// Get a string representation of the local state for debugging.
    pub fn get_local_state(&self) -> String {
        let mut state = format!("phase={:?}", self.phase);

        if let Some(b) = &self.current_ballot {
            state.push_str(&format!(
                " b=({},{})",
                b.counter,
                hex::encode(&b.value.as_slice()[..4.min(b.value.len())])
            ));
        }

        if let Some(p) = &self.prepared {
            state.push_str(&format!(
                " p=({},{})",
                p.counter,
                hex::encode(&p.value.as_slice()[..4.min(p.value.len())])
            ));
        }

        if let Some(pp) = &self.prepared_prime {
            state.push_str(&format!(
                " p'=({},{})",
                pp.counter,
                hex::encode(&pp.value.as_slice()[..4.min(pp.value.len())])
            ));
        }

        if let Some(h) = &self.high_ballot {
            state.push_str(&format!(
                " h=({},{})",
                h.counter,
                hex::encode(&h.value.as_slice()[..4.min(h.value.len())])
            ));
        }

        if let Some(c) = &self.commit {
            state.push_str(&format!(
                " c=({},{})",
                c.counter,
                hex::encode(&c.value.as_slice()[..4.min(c.value.len())])
            ));
        }

        state.push_str(&format!(" heard_from_quorum={}", self.heard_from_quorum));

        state
    }

    /// Get the latest envelopes received from each node.
    ///
    /// Returns a map from node ID to the most recent envelope from that node.
    pub fn latest_envelopes(&self) -> &HashMap<NodeId, ScpEnvelope> {
        &self.latest_envelopes
    }

    /// Get the count of nodes we've heard from.
    pub fn get_node_count(&self) -> usize {
        self.latest_envelopes.len()
    }

    /// Get the state of a node in the ballot protocol.
    ///
    /// Returns the QuorumInfoNodeState for a given node based on their
    /// latest ballot envelope, or Missing if we haven't heard from them.
    pub fn get_node_state(&self, node_id: &NodeId) -> crate::QuorumInfoNodeState {
        if let Some(envelope) = self.latest_envelopes.get(node_id) {
            crate::QuorumInfoNodeState::from_pledges(&envelope.statement.pledges)
        } else {
            crate::QuorumInfoNodeState::Missing
        }
    }

    /// Get a summary string of the ballot state for debugging.
    pub fn get_state_string(&self) -> String {
        let mut state = format!("phase={:?}", self.phase);

        if let Some(b) = &self.current_ballot {
            state.push_str(&format!(" b={}", b.counter));
        }

        if let Some(p) = &self.prepared {
            state.push_str(&format!(" p={}", p.counter));
        }

        if let Some(h) = &self.high_ballot {
            state.push_str(&format!(" h={}", h.counter));
        }

        if let Some(c) = &self.commit {
            state.push_str(&format!(" c={}", c.counter));
        }

        state.push_str(&format!(
            " heard={} nodes={}",
            self.heard_from_quorum,
            self.latest_envelopes.len()
        ));

        state
    }

    /// Get JSON-serializable ballot information.
    ///
    /// Returns a BallotInfo struct that can be serialized to JSON
    /// for debugging and monitoring purposes.
    pub fn get_info(&self) -> crate::BallotInfo {
        let ballot_to_info = |b: &ScpBallot| crate::BallotValue {
            counter: b.counter,
            value: crate::value_to_str(&b.value),
        };

        crate::BallotInfo {
            phase: format!("{:?}", self.phase),
            ballot_counter: self.current_ballot.as_ref().map(|b| b.counter).unwrap_or(0),
            ballot_value: self
                .current_ballot
                .as_ref()
                .map(|b| crate::value_to_str(&b.value)),
            prepared: self.prepared.as_ref().map(ballot_to_info),
            prepared_prime: self.prepared_prime.as_ref().map(ballot_to_info),
            commit: self.commit.as_ref().map(|c| crate::CommitBounds {
                low: c.counter,
                high: self
                    .high_ballot
                    .as_ref()
                    .map(|h| h.counter)
                    .unwrap_or(c.counter),
            }),
            high: self.high_ballot.as_ref().map(|h| h.counter).unwrap_or(0),
            node_count: self.latest_envelopes.len(),
            heard_from_quorum: self.heard_from_quorum,
        }
    }

    /// Start the ballot protocol with a value from nomination.
    pub(crate) fn bump<'a, D: SCPDriver>(
        &mut self,
        ctx: &SlotContext<'a, D>,
        value: Value,
        force: bool,
    ) -> bool {
        if !force && self.current_ballot.is_some() {
            return false;
        }

        // Calculate new ballot counter
        let counter = self
            .current_ballot
            .as_ref()
            .map(|current| current.counter + 1)
            .unwrap_or(1);

        self.bump_state(
            ctx,
            value,
            counter,
        )
    }

    /// Bump ballot counter on timeout.
    ///
    /// This matches the stellar-core `ballotProtocolTimerExpired` → `abandonBallot(0)` flow.
    pub(crate) fn bump_timeout<'a, D: SCPDriver>(
        &mut self,
        ctx: &SlotContext<'a, D>,
        composite_candidate: Option<&Value>,
    ) -> bool {
        // Sync composite candidate from caller before abandoning
        self.composite_candidate = composite_candidate.cloned();
        self.abandon_ballot(0, ctx)
    }

    /// Process a ballot protocol envelope.
    pub(crate) fn process_envelope<'a, D: SCPDriver>(
        &mut self,
        envelope: &ScpEnvelope,
        ctx: &SlotContext<'a, D>,
    ) -> EnvelopeState {
        let node_id = &envelope.statement.node_id;

        match &envelope.statement.pledges {
            ScpStatementPledges::Prepare(_)
            | ScpStatementPledges::Confirm(_)
            | ScpStatementPledges::Externalize(_) => {}
            _ => return EnvelopeState::Invalid,
        }

        if !self.is_newer_statement(node_id, &envelope.statement) {
            return EnvelopeState::Invalid;
        }

        if self.phase == BallotPhase::Externalize {
            if self.statement_value_matches_commit(&envelope.statement) {
                self.latest_envelopes
                    .insert(node_id.clone(), envelope.clone());
                return EnvelopeState::Valid;
            }
            return EnvelopeState::Invalid;
        }

        // Store the envelope
        self.latest_envelopes
            .insert(node_id.clone(), envelope.clone());

        self.advance_slot(
            &envelope.statement,
            ctx,
        )
    }

    pub fn is_newer_statement(&self, node_id: &NodeId, statement: &ScpStatement) -> bool {
        match self.latest_envelopes.get(node_id) {
            None => true,
            Some(existing) => self.is_newer_statement_pair(&existing.statement, statement),
        }
    }

    fn is_newer_statement_pair(&self, old: &ScpStatement, new: &ScpStatement) -> bool {
        let old_rank = self.pledge_rank(&old.pledges);
        let new_rank = self.pledge_rank(&new.pledges);

        if old_rank != new_rank {
            return old_rank < new_rank;
        }

        match (&old.pledges, &new.pledges) {
            (ScpStatementPledges::Externalize(_), ScpStatementPledges::Externalize(_)) => false,
            (ScpStatementPledges::Confirm(old_c), ScpStatementPledges::Confirm(new_c)) => {
                match ballot_compare(&old_c.ballot, &new_c.ballot) {
                    std::cmp::Ordering::Less => true,
                    std::cmp::Ordering::Greater => false,
                    std::cmp::Ordering::Equal => {
                        if old_c.n_prepared == new_c.n_prepared {
                            old_c.n_h < new_c.n_h
                        } else {
                            old_c.n_prepared < new_c.n_prepared
                        }
                    }
                }
            }
            (ScpStatementPledges::Prepare(old_p), ScpStatementPledges::Prepare(new_p)) => {
                match ballot_compare(&old_p.ballot, &new_p.ballot) {
                    std::cmp::Ordering::Less => return true,
                    std::cmp::Ordering::Greater => return false,
                    std::cmp::Ordering::Equal => {}
                }
                match cmp_opt_ballot(&old_p.prepared, &new_p.prepared) {
                    std::cmp::Ordering::Less => return true,
                    std::cmp::Ordering::Greater => return false,
                    std::cmp::Ordering::Equal => {}
                }
                match cmp_opt_ballot(&old_p.prepared_prime, &new_p.prepared_prime) {
                    std::cmp::Ordering::Less => true,
                    std::cmp::Ordering::Greater => false,
                    std::cmp::Ordering::Equal => old_p.n_h < new_p.n_h,
                }
            }
            _ => false,
        }
    }

    fn pledge_rank(&self, pledges: &ScpStatementPledges) -> u8 {
        match pledges {
            ScpStatementPledges::Prepare(_) => 0,
            ScpStatementPledges::Confirm(_) => 1,
            ScpStatementPledges::Externalize(_) => 2,
            _ => 3,
        }
    }

    pub(crate) fn is_statement_sane<D: SCPDriver>(
        &self,
        statement: &ScpStatement,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
    ) -> bool {
        let quorum_set =
            match self.statement_quorum_set(statement, local_node_id, local_quorum_set, driver) {
                Some(qset) => qset,
                None => return false,
            };

        if is_quorum_set_sane(&quorum_set, false).is_err() {
            return false;
        }

        match &statement.pledges {
            ScpStatementPledges::Prepare(prep) => {
                let is_self = statement.node_id == *local_node_id;
                if !is_self && prep.ballot.counter == 0 {
                    return false;
                }

                if let (Some(prepared_prime), Some(prepared)) =
                    (&prep.prepared_prime, &prep.prepared)
                {
                    if ballot_compare(prepared_prime, prepared) != std::cmp::Ordering::Less
                        || ballot_compatible(prepared_prime, prepared)
                    {
                        return false;
                    }
                }

                if prep.n_h != 0 {
                    if let Some(prepared) = &prep.prepared {
                        if prep.n_h > prepared.counter {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }

                if prep.n_c != 0 {
                    if prep.n_h == 0 {
                        return false;
                    }
                    if prep.ballot.counter < prep.n_h || prep.n_h < prep.n_c {
                        return false;
                    }
                }
            }
            ScpStatementPledges::Confirm(conf) => {
                if conf.ballot.counter == 0 {
                    return false;
                }
                if conf.n_h > conf.ballot.counter {
                    return false;
                }
                if conf.n_commit > conf.n_h {
                    return false;
                }
            }
            ScpStatementPledges::Externalize(ext) => {
                if ext.commit.counter == 0 {
                    return false;
                }
                if ext.n_h < ext.commit.counter {
                    return false;
                }
            }
            _ => return false,
        }

        true
    }

    pub(crate) fn validate_statement_values<D: SCPDriver>(
        &self,
        statement: &ScpStatement,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> ValidationLevel {
        let values = self.statement_values(statement);
        if values.is_empty() {
            return ValidationLevel::Invalid;
        }

        let mut level = ValidationLevel::FullyValidated;
        for value in values {
            let next = driver.validate_value(slot_index, &value, false);
            level = min_validation_level(level, next);
            if level == ValidationLevel::Invalid {
                break;
            }
        }
        level
    }

    fn statement_quorum_set<D: SCPDriver>(
        &self,
        statement: &ScpStatement,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
    ) -> Option<ScpQuorumSet> {
        match &statement.pledges {
            ScpStatementPledges::Externalize(_) => {
                Some(simple_quorum_set(1, vec![statement.node_id.clone()]))
            }
            ScpStatementPledges::Prepare(prep) => {
                let provided = henyey_common::Hash256::from(prep.quorum_set_hash.clone());
                self.resolve_quorum_set(
                    &provided,
                    &statement.node_id,
                    local_node_id,
                    local_quorum_set,
                    driver,
                )
            }
            ScpStatementPledges::Confirm(conf) => {
                let provided = henyey_common::Hash256::from(conf.quorum_set_hash.clone());
                self.resolve_quorum_set(
                    &provided,
                    &statement.node_id,
                    local_node_id,
                    local_quorum_set,
                    driver,
                )
            }
            _ => None,
        }
    }

    /// Resolve a quorum set from its hash, checking local, hash cache, then node lookup.
    fn resolve_quorum_set<D: SCPDriver>(
        &self,
        provided: &henyey_common::Hash256,
        node_id: &NodeId,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
    ) -> Option<ScpQuorumSet> {
        if node_id == local_node_id {
            let expected = hash_quorum_set(local_quorum_set);
            if expected == *provided {
                return Some(local_quorum_set.clone());
            }
        }
        if let Some(qset) = driver.get_quorum_set_by_hash(provided) {
            return Some(qset);
        }
        driver.get_quorum_set(node_id).and_then(|qset| {
            let expected = hash_quorum_set(&qset);
            if expected == *provided {
                Some(qset)
            } else {
                None
            }
        })
    }

    fn statement_values(&self, statement: &ScpStatement) -> Vec<Value> {
        crate::slot::Slot::get_statement_values(statement)
    }

    fn statement_value_matches_commit(&self, statement: &ScpStatement) -> bool {
        let commit = match self.commit.as_ref() {
            Some(commit) => commit,
            None => return false,
        };

        match &statement.pledges {
            ScpStatementPledges::Prepare(prep) => commit.value == prep.ballot.value,
            ScpStatementPledges::Confirm(conf) => commit.value == conf.ballot.value,
            ScpStatementPledges::Externalize(ext) => commit.value == ext.commit.value,
            _ => false,
        }
    }

    /// Try to advance the slot state based on received messages.
    fn advance_slot<'a, D: SCPDriver>(
        &mut self,
        hint: &ScpStatement,
        ctx: &SlotContext<'a, D>,
    ) -> EnvelopeState {
        self.current_message_level = self.current_message_level.saturating_add(1);
        if self.current_message_level >= MAX_PROTOCOL_TRANSITIONS {
            // stellar-core throws std::runtime_error here. We panic to match the behavior:
            // this indicates a bug in the protocol state machine, not a recoverable error.
            panic!("maximum number of transitions reached in advanceSlot");
        }
        let mut did_work = false;

        did_work =
            self.attempt_accept_prepared(hint, ctx)
                || did_work;
        did_work = self.attempt_confirm_prepared(
            hint,
            ctx,
        ) || did_work;
        did_work =
            self.attempt_accept_commit(hint, ctx)
                || did_work;
        did_work =
            self.attempt_confirm_commit(hint, ctx)
                || did_work;

        if self.current_message_level == 1 {
            loop {
                let bumped = self.attempt_bump(ctx);
                did_work = bumped || did_work;
                if !bumped {
                    break;
                }
            }
            self.check_heard_from_quorum(ctx);
        }

        self.current_message_level = self.current_message_level.saturating_sub(1);
        if did_work {
            self.send_latest_envelope(ctx.driver);
            EnvelopeState::ValidNew
        } else {
            EnvelopeState::Valid
        }
    }

    fn attempt_accept_prepared<'a, D: SCPDriver>(
        &mut self,
        hint: &ScpStatement,
        ctx: &SlotContext<'a, D>,
    ) -> bool {
        if !matches!(self.phase, BallotPhase::Prepare | BallotPhase::Confirm) {
            return false;
        }

        let candidates = self.get_prepare_candidates(hint);

        for ballot in candidates.iter().rev() {
            if self.phase == BallotPhase::Confirm {
                if let Some(prepared) = &self.prepared {
                    if !are_ballots_less_and_compatible(prepared, ballot) {
                        continue;
                    }
                }
                if let Some(commit) = &self.commit {
                    if !ballot_compatible(commit, ballot) {
                        continue;
                    }
                }
            }

            if let Some(prepared_prime) = &self.prepared_prime {
                if ballot_compare(ballot, prepared_prime) != std::cmp::Ordering::Greater {
                    continue;
                }
            }

            if let Some(prepared) = &self.prepared {
                if are_ballots_less_and_compatible(ballot, prepared) {
                    continue;
                }
            }

            let accepted = self.federated_accept(
                |st| self.statement_votes_for_ballot(ballot, st),
                |st| self.has_prepared_ballot(ballot, st),
                ctx.local_node_id,
                ctx.local_quorum_set,
                ctx.driver,
            );

            if accepted
                && self.set_accept_prepared(
                    ballot.clone(),
                    ctx,
                )
            {
                return true;
            }
        }

        false
    }

    fn set_accept_prepared<'a, D: SCPDriver>(
        &mut self,
        ballot: ScpBallot,
        ctx: &SlotContext<'a, D>,
    ) -> bool {
        let mut did_work = self.set_prepared(ballot.clone(), ctx.driver, ctx.slot_index);

        if self.commit.is_some() {
            let Some(high) = self.high_ballot.as_ref() else {
                return did_work;
            };
            let incompatible = self
                .prepared
                .as_ref()
                .map(|p| are_ballots_less_and_incompatible(high, p))
                .unwrap_or(false)
                || self
                    .prepared_prime
                    .as_ref()
                    .map(|p| are_ballots_less_and_incompatible(high, p))
                    .unwrap_or(false);
            if incompatible {
                self.commit = None;
                did_work = true;
            }
        }

        if did_work {
            self.emit_current_state(ctx);
        }

        did_work
    }

    fn attempt_confirm_prepared<'a, D: SCPDriver>(
        &mut self,
        hint: &ScpStatement,
        ctx: &SlotContext<'a, D>,
    ) -> bool {
        if self.phase != BallotPhase::Prepare {
            return false;
        }
        if self.prepared.is_none() {
            return false;
        }

        let candidates = self.get_prepare_candidates(hint);
        let (new_h_ballot, new_h_index) = match self.find_highest_confirmed_prepared(
            &candidates,
            ctx,
        ) {
            Some(result) => result,
            None => return false,
        };

        let new_c = self.find_lowest_commit_ballot(
            &candidates,
            &new_h_ballot,
            new_h_index,
            ctx,
        );

        self.set_confirm_prepared(
            new_c,
            new_h_ballot,
            ctx,
        )
    }

    /// Find the highest ballot that a quorum has confirmed prepared.
    fn find_highest_confirmed_prepared<'a, D: SCPDriver>(
        &self,
        candidates: &[ScpBallot],
        ctx: &SlotContext<'a, D>,
    ) -> Option<(ScpBallot, usize)> {
        for (idx, ballot) in candidates.iter().enumerate().rev() {
            if let Some(high) = &self.high_ballot {
                if ballot_compare(high, ballot) != std::cmp::Ordering::Less {
                    break;
                }
            }

            if self.federated_ratify(
                |st| self.has_prepared_ballot(ballot, st),
                ctx.local_node_id,
                ctx.local_quorum_set,
                ctx.driver,
            ) {
                return Some((ballot.clone(), idx));
            }
        }
        None
    }

    /// Find the lowest commit ballot among candidates up to new_h.
    fn find_lowest_commit_ballot<'a, D: SCPDriver>(
        &self,
        candidates: &[ScpBallot],
        new_h_ballot: &ScpBallot,
        new_h_index: usize,
        ctx: &SlotContext<'a, D>,
    ) -> ScpBallot {
        let mut new_c = ScpBallot {
            counter: 0,
            value: new_h_ballot.value.clone(),
        };

        let current = self.current_ballot.clone().unwrap_or(ScpBallot {
            counter: 0,
            value: new_h_ballot.value.clone(),
        });

        let can_set_commit = self.commit.is_none()
            && self
                .prepared
                .as_ref()
                .map(|p| !are_ballots_less_and_incompatible(new_h_ballot, p))
                .unwrap_or(true)
            && self
                .prepared_prime
                .as_ref()
                .map(|p| !are_ballots_less_and_incompatible(new_h_ballot, p))
                .unwrap_or(true);

        if can_set_commit {
            for ballot in candidates[..=new_h_index].iter().rev() {
                if ballot_compare(ballot, &current) == std::cmp::Ordering::Less {
                    break;
                }
                if !are_ballots_less_and_compatible(ballot, new_h_ballot) {
                    continue;
                }
                if self.federated_ratify(
                    |st| self.has_prepared_ballot(ballot, st),
                    ctx.local_node_id,
                    ctx.local_quorum_set,
                    ctx.driver,
                ) {
                    new_c = ballot.clone();
                } else {
                    break;
                }
            }
        }

        new_c
    }

    fn set_confirm_prepared<'a, D: SCPDriver>(
        &mut self,
        new_c: ScpBallot,
        new_h: ScpBallot,
        ctx: &SlotContext<'a, D>,
    ) -> bool {
        let mut did_work = false;
        self.value_override = Some(new_h.value.clone());

        if self
            .current_ballot
            .as_ref()
            .map(|b| ballot_compatible(b, &new_h))
            .unwrap_or(true)
        {
            if self
                .high_ballot
                .as_ref()
                .map(|b| ballot_compare(&new_h, b) == std::cmp::Ordering::Greater)
                .unwrap_or(true)
            {
                self.high_ballot = Some(new_h.clone());
                did_work = true;
            }

            if new_c.counter != 0 && self.commit.is_none() {
                self.commit = Some(new_c);
                did_work = true;
            }

            if did_work {
                ctx.driver.confirmed_ballot_prepared(ctx.slot_index, &new_h);
            }
        }

        did_work = self.update_current_if_needed(&new_h) || did_work;
        if did_work {
            self.emit_current_state(ctx);
        }

        did_work
    }

    fn attempt_accept_commit<'a, D: SCPDriver>(
        &mut self,
        hint: &ScpStatement,
        ctx: &SlotContext<'a, D>,
    ) -> bool {
        if !matches!(self.phase, BallotPhase::Prepare | BallotPhase::Confirm) {
            return false;
        }

        let Some(ballot) = self.hint_ballot_for_commit(hint) else {
            return false;
        };
        if self.phase == BallotPhase::Confirm {
            if let Some(high) = &self.high_ballot {
                if !ballot_compatible(&ballot, high) {
                    return false;
                }
            }
        }

        let boundaries = self.get_commit_boundaries_from_statements(&ballot);
        if boundaries.is_empty() {
            return false;
        }

        let mut candidate = (0u32, 0u32);
        self.find_extended_interval(&mut candidate, &boundaries, |interval| {
            self.federated_accept(
                |st| self.statement_votes_commit(&ballot, interval, st),
                |st| self.commit_predicate(&ballot, interval, st),
                ctx.local_node_id,
                ctx.local_quorum_set,
                ctx.driver,
            )
        });

        if candidate.0 == 0 {
            return false;
        }

        if self.phase != BallotPhase::Confirm
            || candidate.1 > self.high_ballot.as_ref().map(|b| b.counter).unwrap_or(0)
        {
            let c = ScpBallot {
                counter: candidate.0,
                value: ballot.value.clone(),
            };
            let h = ScpBallot {
                counter: candidate.1,
                value: ballot.value.clone(),
            };
            return self.set_accept_commit(
                c,
                h,
                ctx,
            );
        }

        false
    }

    fn set_accept_commit<'a, D: SCPDriver>(
        &mut self,
        c: ScpBallot,
        h: ScpBallot,
        ctx: &SlotContext<'a, D>,
    ) -> bool {
        let mut did_work = false;
        self.value_override = Some(h.value.clone());

        if self
            .high_ballot
            .as_ref()
            .map(|b| ballot_compare(b, &h) != std::cmp::Ordering::Equal)
            .unwrap_or(true)
            || self
                .commit
                .as_ref()
                .map(|b| ballot_compare(b, &c) != std::cmp::Ordering::Equal)
                .unwrap_or(true)
        {
            self.commit = Some(c.clone());
            self.high_ballot = Some(h.clone());
            did_work = true;
        }

        if self.phase == BallotPhase::Prepare {
            self.phase = BallotPhase::Confirm;
            if let Some(current) = &self.current_ballot {
                if !are_ballots_less_and_compatible(&h, current) {
                    self.bump_to_ballot(&h, false);
                }
            }
            self.prepared_prime = None;
            did_work = true;
        }

        if did_work {
            self.update_current_if_needed(&h);
            ctx.driver.accepted_commit(ctx.slot_index, &h);
            self.emit_current_state(ctx);
        }

        did_work
    }

    fn attempt_confirm_commit<'a, D: SCPDriver>(
        &mut self,
        hint: &ScpStatement,
        ctx: &SlotContext<'a, D>,
    ) -> bool {
        if self.phase != BallotPhase::Confirm {
            return false;
        }
        if self.high_ballot.is_none() || self.commit.is_none() {
            return false;
        }

        let Some(ballot) = self.hint_ballot_for_commit(hint) else {
            return false;
        };
        if !ballot_compatible(&ballot, self.commit.as_ref().unwrap()) {
            return false;
        }

        let boundaries = self.get_commit_boundaries_from_statements(&ballot);
        let mut candidate = (0u32, 0u32);
        self.find_extended_interval(&mut candidate, &boundaries, |interval| {
            self.federated_ratify(
                |st| self.commit_predicate(&ballot, interval, st),
                ctx.local_node_id,
                ctx.local_quorum_set,
                ctx.driver,
            )
        });

        if candidate.0 == 0 {
            return false;
        }

        let c = ScpBallot {
            counter: candidate.0,
            value: ballot.value.clone(),
        };
        let h = ScpBallot {
            counter: candidate.1,
            value: ballot.value.clone(),
        };
        self.set_confirm_commit(c, h, ctx)
    }

    fn set_confirm_commit<'a, D: SCPDriver>(
        &mut self,
        c: ScpBallot,
        h: ScpBallot,
        ctx: &SlotContext<'a, D>,
    ) -> bool {
        self.commit = Some(c.clone());
        self.high_ballot = Some(h.clone());
        self.update_current_if_needed(&h);
        self.phase = BallotPhase::Externalize;

        self.emit_current_state(ctx);

        // Signal that nomination should be stopped (stellar-core calls mSlot.stopNomination() here)
        self.needs_stop_nomination = true;

        // stellar-core uses mCommit->getBallot().value (c.value) for valueExternalized
        ctx.driver.value_externalized(ctx.slot_index, &c.value);
        true
    }

    fn attempt_bump<'a, D: SCPDriver>(
        &mut self,
        ctx: &SlotContext<'a, D>,
    ) -> bool {
        if !matches!(self.phase, BallotPhase::Prepare | BallotPhase::Confirm) {
            return false;
        }

        let local_counter = self.current_ballot.as_ref().map(|b| b.counter).unwrap_or(0);
        if !self.has_vblocking_subset_strictly_ahead_of(
            local_counter,
            ctx.local_node_id,
            ctx.local_quorum_set,
            ctx.driver,
        ) {
            return false;
        }

        let mut counters = std::collections::BTreeSet::new();
        for envelope in self.latest_envelopes.values() {
            let counter = self.statement_ballot_counter(&envelope.statement);
            if counter > local_counter {
                counters.insert(counter);
            }
        }

        for counter in counters {
            if !self.has_vblocking_subset_strictly_ahead_of(
                counter,
                ctx.local_node_id,
                ctx.local_quorum_set,
                ctx.driver,
            ) {
                return self.abandon_ballot(counter, ctx);
            }
        }

        false
    }

    /// Abandon the current ballot.
    ///
    /// Matches stellar-core `abandonBallot(n)` which checks `mSlot.getLatestCompositeCandidate()`
    /// first, then falls back to `mCurrentBallot->value`, then calls `bumpState(value, n)`.
    /// This properly emits envelopes and checks heard-from-quorum (via `bump_state`).
    fn abandon_ballot<'a, D: SCPDriver>(
        &mut self,
        counter: u32,
        ctx: &SlotContext<'a, D>,
    ) -> bool {
        // stellar-core priority: composite candidate first, then current ballot value
        let value = self
            .composite_candidate
            .as_ref()
            .filter(|v| !v.0.is_empty())
            .cloned()
            .or_else(|| self.current_ballot.as_ref().map(|b| b.value.clone()));

        if let Some(value) = value {
            if counter == 0 {
                // bumpState(value, true) which computes counter = current+1
                let n = self
                    .current_ballot
                    .as_ref()
                    .map(|b| b.counter + 1)
                    .unwrap_or(1);
                self.bump_state(
                    ctx,
                    value,
                    n,
                )
            } else {
                self.bump_state(
                    ctx,
                    value,
                    counter,
                )
            }
        } else {
            false
        }
    }

    fn update_current_if_needed(&mut self, ballot: &ScpBallot) -> bool {
        if self
            .current_ballot
            .as_ref()
            .map(|b| ballot_compare(b, ballot) == std::cmp::Ordering::Less)
            .unwrap_or(true)
        {
            return self.bump_to_ballot(ballot, true);
        }
        false
    }

    /// Update current value enforcing invariants (matches stellar-core updateCurrentValue).
    ///
    /// This is more thorough than `update_current_if_needed`: it checks phase
    /// and commit compatibility before bumping.
    fn update_current_value(&mut self, ballot: &ScpBallot) -> bool {
        if self.phase != BallotPhase::Prepare && self.phase != BallotPhase::Confirm {
            return false;
        }

        if self.current_ballot.is_none() {
            self.bump_to_ballot(ballot, true);
            return true;
        }

        // If we have a commit and the new ballot is incompatible, reject
        if let Some(ref commit) = self.commit {
            if !ballot_compatible(&commit, ballot) {
                return false;
            }
        }

        let comp = ballot_compare(self.current_ballot.as_ref().unwrap(), ballot);

        match comp {
            std::cmp::Ordering::Less => {
                self.bump_to_ballot(ballot, true);
                true
            }
            _ => false,
        }
    }

    fn bump_to_ballot(&mut self, ballot: &ScpBallot, check: bool) -> bool {
        if check {
            if let Some(current) = &self.current_ballot {
                if ballot_compare(ballot, current) != std::cmp::Ordering::Greater {
                    return false;
                }
            }
        }

        let got_bumped = match &self.current_ballot {
            None => true,
            Some(current) => current.counter != ballot.counter,
        };

        self.current_ballot = Some(ballot.clone());
        self.value = Some(ballot.value.clone());

        // invariant: h.value = b.value
        if let Some(high) = &self.high_ballot {
            if !ballot_compatible(ballot, high) {
                self.high_ballot = None;
                // invariant: c set only when h is set
                self.commit = None;
            }
        }

        if got_bumped {
            self.heard_from_quorum = false;
        }

        true
    }

    fn collect_hint_ballots(hint: &ScpStatement) -> Vec<ScpBallot> {
        let mut hint_ballots: Vec<ScpBallot> = Vec::new();
        match &hint.pledges {
            ScpStatementPledges::Prepare(prep) => {
                hint_ballots.push(prep.ballot.clone());
                if let Some(prepared) = &prep.prepared {
                    hint_ballots.push(prepared.clone());
                }
                if let Some(prepared_prime) = &prep.prepared_prime {
                    hint_ballots.push(prepared_prime.clone());
                }
            }
            ScpStatementPledges::Confirm(conf) => {
                hint_ballots.push(ScpBallot {
                    counter: conf.n_prepared,
                    value: conf.ballot.value.clone(),
                });
                hint_ballots.push(ScpBallot {
                    counter: u32::MAX,
                    value: conf.ballot.value.clone(),
                });
            }
            ScpStatementPledges::Externalize(ext) => {
                hint_ballots.push(ScpBallot {
                    counter: u32::MAX,
                    value: ext.commit.value.clone(),
                });
            }
            _ => {}
        }
        hint_ballots
    }

    fn get_prepare_candidates(&self, hint: &ScpStatement) -> Vec<ScpBallot> {
        let mut hint_ballots = Self::collect_hint_ballots(hint);
        let mut candidates: Vec<ScpBallot> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        hint_ballots.sort_by(ballot_compare);

        for top_vote in hint_ballots.iter().rev() {
            for envelope in self.latest_envelopes.values() {
                match &envelope.statement.pledges {
                    ScpStatementPledges::Prepare(prep) => {
                        if are_ballots_less_and_compatible(&prep.ballot, top_vote) {
                            self.push_candidate(&mut candidates, &mut seen, prep.ballot.clone());
                        }
                        if let Some(prepared) = &prep.prepared {
                            if are_ballots_less_and_compatible(prepared, top_vote) {
                                self.push_candidate(&mut candidates, &mut seen, prepared.clone());
                            }
                        }
                        if let Some(prepared_prime) = &prep.prepared_prime {
                            if are_ballots_less_and_compatible(prepared_prime, top_vote) {
                                self.push_candidate(
                                    &mut candidates,
                                    &mut seen,
                                    prepared_prime.clone(),
                                );
                            }
                        }
                    }
                    ScpStatementPledges::Confirm(conf) => {
                        if ballot_compatible(top_vote, &conf.ballot) {
                            self.push_candidate(&mut candidates, &mut seen, top_vote.clone());
                            if conf.n_prepared < top_vote.counter {
                                self.push_candidate(
                                    &mut candidates,
                                    &mut seen,
                                    ScpBallot {
                                        counter: conf.n_prepared,
                                        value: top_vote.value.clone(),
                                    },
                                );
                            }
                        }
                    }
                    ScpStatementPledges::Externalize(ext) => {
                        if ballot_compatible(top_vote, &ext.commit) {
                            self.push_candidate(&mut candidates, &mut seen, top_vote.clone());
                        }
                    }
                    _ => {}
                }
            }
        }

        candidates.sort_by(ballot_compare);
        candidates
    }

    fn push_candidate(
        &self,
        candidates: &mut Vec<ScpBallot>,
        seen: &mut std::collections::HashSet<(u32, Vec<u8>)>,
        ballot: ScpBallot,
    ) {
        let key = (
            ballot.counter,
            ballot.value.to_xdr(Limits::none()).unwrap_or_default(),
        );
        if seen.insert(key) {
            candidates.push(ballot);
        }
    }

    fn commit_predicate(
        &self,
        ballot: &ScpBallot,
        interval: (u32, u32),
        statement: &ScpStatement,
    ) -> bool {
        match &statement.pledges {
            ScpStatementPledges::Confirm(conf) => {
                if ballot_compatible(ballot, &conf.ballot) {
                    conf.n_commit <= interval.0 && interval.1 <= conf.n_h
                } else {
                    false
                }
            }
            ScpStatementPledges::Externalize(ext) => {
                if ballot_compatible(ballot, &ext.commit) {
                    ext.commit.counter <= interval.0
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn get_commit_boundaries_from_statements(
        &self,
        ballot: &ScpBallot,
    ) -> std::collections::BTreeSet<u32> {
        let mut res = std::collections::BTreeSet::new();
        for envelope in self.latest_envelopes.values() {
            match &envelope.statement.pledges {
                ScpStatementPledges::Prepare(prep) => {
                    if ballot_compatible(ballot, &prep.ballot) && prep.n_c != 0 {
                        res.insert(prep.n_c);
                        res.insert(prep.n_h);
                    }
                }
                ScpStatementPledges::Confirm(conf) => {
                    if ballot_compatible(ballot, &conf.ballot) {
                        res.insert(conf.n_commit);
                        res.insert(conf.n_h);
                    }
                }
                ScpStatementPledges::Externalize(ext) => {
                    if ballot_compatible(ballot, &ext.commit) {
                        res.insert(ext.commit.counter);
                        res.insert(ext.n_h);
                        res.insert(u32::MAX);
                    }
                }
                _ => {}
            }
        }
        res
    }

    fn find_extended_interval<F>(
        &self,
        candidate: &mut (u32, u32),
        boundaries: &std::collections::BTreeSet<u32>,
        pred: F,
    ) where
        F: Fn((u32, u32)) -> bool,
    {
        for boundary in boundaries.iter().rev() {
            let current = if candidate.0 == 0 {
                (*boundary, *boundary)
            } else if *boundary > candidate.1 {
                continue;
            } else {
                (*boundary, candidate.1)
            };

            if pred(current) {
                *candidate = current;
            } else if candidate.0 != 0 {
                break;
            }
        }
    }

    fn hint_ballot_for_commit(&self, hint: &ScpStatement) -> Option<ScpBallot> {
        match &hint.pledges {
            ScpStatementPledges::Prepare(prep) => {
                if prep.n_c != 0 {
                    Some(ScpBallot {
                        counter: prep.n_h,
                        value: prep.ballot.value.clone(),
                    })
                } else {
                    None
                }
            }
            ScpStatementPledges::Confirm(conf) => Some(ScpBallot {
                counter: conf.n_h,
                value: conf.ballot.value.clone(),
            }),
            ScpStatementPledges::Externalize(ext) => Some(ScpBallot {
                counter: ext.n_h,
                value: ext.commit.value.clone(),
            }),
            _ => None,
        }
    }

    fn statement_ballot_counter(&self, statement: &ScpStatement) -> u32 {
        match &statement.pledges {
            ScpStatementPledges::Prepare(prep) => prep.ballot.counter,
            ScpStatementPledges::Confirm(conf) => conf.ballot.counter,
            ScpStatementPledges::Externalize(_) => u32::MAX,
            _ => 0,
        }
    }

    fn has_vblocking_subset_strictly_ahead_of<D: SCPDriver>(
        &self,
        counter: u32,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
    ) -> bool {
        let mut nodes = HashSet::new();
        for (node_id, envelope) in &self.latest_envelopes {
            if self.statement_ballot_counter(&envelope.statement) > counter {
                nodes.insert(node_id.clone());
            }
        }
        is_blocking_set(local_quorum_set, &nodes)
            && !self
                .statement_quorum_set_map(local_node_id, local_quorum_set, driver)
                .is_empty()
    }

    fn statement_quorum_set_map<D: SCPDriver>(
        &self,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
    ) -> HashMap<NodeId, ScpQuorumSet> {
        let mut map = HashMap::new();
        for (node_id, envelope) in &self.latest_envelopes {
            if let Some(qset) = self.statement_quorum_set(
                &envelope.statement,
                local_node_id,
                local_quorum_set,
                driver,
            ) {
                map.insert(node_id.clone(), qset);
            }
        }
        if !map.contains_key(local_node_id) {
            map.insert(local_node_id.clone(), local_quorum_set.clone());
        }
        map
    }

    fn federated_accept<D: SCPDriver, V, A>(
        &self,
        voted: V,
        accepted: A,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
    ) -> bool
    where
        V: Fn(&ScpStatement) -> bool,
        A: Fn(&ScpStatement) -> bool,
    {
        let mut accepted_nodes = HashSet::new();
        let mut supporters = HashSet::new();
        for (node_id, envelope) in &self.latest_envelopes {
            let statement = &envelope.statement;
            if accepted(statement) {
                accepted_nodes.insert(node_id.clone());
                supporters.insert(node_id.clone());
            } else if voted(statement) {
                supporters.insert(node_id.clone());
            }
        }

        if is_blocking_set(local_quorum_set, &accepted_nodes) {
            return true;
        }

        let qsets = self.statement_quorum_set_map(local_node_id, local_quorum_set, driver);
        let get_qs = |node_id: &NodeId| -> Option<ScpQuorumSet> { qsets.get(node_id).cloned() };
        is_quorum(local_quorum_set, &supporters, get_qs)
    }

    fn federated_ratify<D: SCPDriver, V>(
        &self,
        voted: V,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
    ) -> bool
    where
        V: Fn(&ScpStatement) -> bool,
    {
        let mut supporters = HashSet::new();
        for (node_id, envelope) in &self.latest_envelopes {
            if voted(&envelope.statement) {
                supporters.insert(node_id.clone());
            }
        }

        let qsets = self.statement_quorum_set_map(local_node_id, local_quorum_set, driver);
        let get_qs = |node_id: &NodeId| -> Option<ScpQuorumSet> { qsets.get(node_id).cloned() };
        is_quorum(local_quorum_set, &supporters, get_qs)
    }

    fn statement_votes_for_ballot(&self, ballot: &ScpBallot, statement: &ScpStatement) -> bool {
        match &statement.pledges {
            ScpStatementPledges::Prepare(prep) => {
                are_ballots_less_and_compatible(ballot, &prep.ballot)
            }
            ScpStatementPledges::Confirm(conf) => ballot_compatible(ballot, &conf.ballot),
            ScpStatementPledges::Externalize(ext) => ballot_compatible(ballot, &ext.commit),
            _ => false,
        }
    }

    fn statement_votes_commit(
        &self,
        ballot: &ScpBallot,
        interval: (u32, u32),
        statement: &ScpStatement,
    ) -> bool {
        match &statement.pledges {
            ScpStatementPledges::Prepare(prep) => {
                if ballot_compatible(ballot, &prep.ballot) && prep.n_c != 0 {
                    prep.n_c <= interval.0 && interval.1 <= prep.n_h
                } else {
                    false
                }
            }
            ScpStatementPledges::Confirm(conf) => {
                ballot_compatible(ballot, &conf.ballot) && conf.n_commit <= interval.0
            }
            ScpStatementPledges::Externalize(ext) => {
                ballot_compatible(ballot, &ext.commit) && ext.commit.counter <= interval.0
            }
            _ => false,
        }
    }

    fn has_prepared_ballot(&self, ballot: &ScpBallot, statement: &ScpStatement) -> bool {
        match &statement.pledges {
            ScpStatementPledges::Prepare(prep) => {
                prep.prepared
                    .as_ref()
                    .map(|p| are_ballots_less_and_compatible(ballot, p))
                    .unwrap_or(false)
                    || prep
                        .prepared_prime
                        .as_ref()
                        .map(|p| are_ballots_less_and_compatible(ballot, p))
                        .unwrap_or(false)
            }
            ScpStatementPledges::Confirm(conf) => {
                let prepared = ScpBallot {
                    counter: conf.n_prepared,
                    value: conf.ballot.value.clone(),
                };
                are_ballots_less_and_compatible(ballot, &prepared)
            }
            ScpStatementPledges::Externalize(ext) => ballot_compatible(ballot, &ext.commit),
            _ => false,
        }
    }

    /// Set prepared ballot.
    fn set_prepared<D: SCPDriver>(
        &mut self,
        ballot: ScpBallot,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> bool {
        let mut did_work = false;
        if let Some(ref current_prepared) = self.prepared {
            match ballot_compare(current_prepared, &ballot) {
                std::cmp::Ordering::Less => {
                    if !ballot_compatible(current_prepared, &ballot) {
                        self.prepared_prime = Some(current_prepared.clone());
                    }
                    self.prepared = Some(ballot.clone());
                    did_work = true;
                }
                std::cmp::Ordering::Greater => {
                    let should_update_prime = match &self.prepared_prime {
                        None => true,
                        Some(prepared_prime) => {
                            ballot_compare(prepared_prime, &ballot) == std::cmp::Ordering::Less
                                && !ballot_compatible(current_prepared, &ballot)
                        }
                    };
                    if should_update_prime {
                        self.prepared_prime = Some(ballot.clone());
                        did_work = true;
                    }
                }
                std::cmp::Ordering::Equal => {}
            }
        } else {
            self.prepared = Some(ballot.clone());
            did_work = true;
        }

        if did_work {
            driver.accepted_ballot_prepared(slot_index, &ballot);
            driver.ballot_did_prepare(slot_index, &ballot);
        }

        did_work
    }

    fn check_heard_from_quorum<'a, D: SCPDriver>(
        &mut self,
        ctx: &SlotContext<'a, D>,
    ) {
        let current = match self.current_ballot.as_ref() {
            Some(ballot) => ballot.clone(),
            None => return,
        };

        let mut nodes = HashSet::new();
        let mut quorum_sets = HashMap::new();

        for (node_id, envelope) in &self.latest_envelopes {
            let include = match &envelope.statement.pledges {
                ScpStatementPledges::Prepare(prep) => current.counter <= prep.ballot.counter,
                ScpStatementPledges::Confirm(_) | ScpStatementPledges::Externalize(_) => true,
                _ => false,
            };
            if !include {
                continue;
            }

            nodes.insert(node_id.clone());
            if let Some(qs) = self.statement_quorum_set(
                &envelope.statement,
                ctx.local_node_id,
                ctx.local_quorum_set,
                ctx.driver,
            ) {
                quorum_sets.insert(node_id.clone(), qs);
            }
        }

        let get_qs =
            |node_id: &NodeId| -> Option<ScpQuorumSet> { quorum_sets.get(node_id).cloned() };

        if is_quorum(ctx.local_quorum_set, &nodes, get_qs) {
            let old = self.heard_from_quorum;
            self.heard_from_quorum = true;
            if !old {
                ctx.driver.ballot_did_hear_from_quorum(ctx.slot_index, &current);
                // If we transition from not heard -> heard, start the ballot timer
                if self.phase != BallotPhase::Externalize {
                    let timeout = ctx.driver.compute_timeout(current.counter, false);
                    ctx.driver.setup_timer(ctx.slot_index, crate::driver::SCPTimerType::Ballot, timeout);
                }
            }
            if self.phase == BallotPhase::Externalize {
                ctx.driver.stop_timer(ctx.slot_index, crate::driver::SCPTimerType::Ballot);
            }
        } else {
            self.heard_from_quorum = false;
            ctx.driver.stop_timer(ctx.slot_index, crate::driver::SCPTimerType::Ballot);
        }
    }

    fn send_latest_envelope<D: SCPDriver>(&mut self, driver: &Arc<D>) {
        if self.current_message_level != 0 {
            return;
        }

        if !self.fully_validated {
            return;
        }

        let Some(envelope) = self.last_envelope.as_ref() else {
            return;
        };

        if self.last_envelope_emit.as_ref() == Some(envelope) {
            return;
        }

        self.last_envelope_emit = Some(envelope.clone());
        driver.emit_envelope(envelope);
    }

    /// Build and record a prepare statement envelope.
    /// Returns the statement if a new envelope was recorded (for self-processing).
    ///
    /// When `current_ballot` is `None` (pristine state, no `bumpState` call),
    /// a PREPARE with `ballot = {0, ""}` is still created and recorded as a
    /// self-envelope. This matches stellar-core `emitCurrentStateStatement` which always
    /// calls `createStatement()` and `processEnvelope(self)`, even when
    /// `mCurrentBallot` is null. The self-envelope is needed so that the local
    /// node counts itself in subsequent quorum calculations (e.g., prepared
    /// fields in the self-envelope contribute to `federated_accept`/`federated_ratify`).
    /// However, the envelope is NOT emitted to the network when `current_ballot`
    /// is `None` (matching stellar-core `canEmit = mCurrentBallot != nullptr`).
    fn emit_prepare<'a, D: SCPDriver>(
        &mut self,
        ctx: &SlotContext<'a, D>,
    ) -> Option<ScpStatement> {
        // Use the current ballot if set, otherwise use a default zero ballot
        // (matching stellar-core which creates a PREPARE with default ballot {0, ""} when
        // mCurrentBallot is null).
        let can_emit = self.current_ballot.is_some();
        let ballot = self.current_ballot.clone().unwrap_or_else(|| ScpBallot {
            counter: 0,
            value: Value(Vec::new().try_into().unwrap_or_default()),
        });

        let prep = ScpStatementPrepare {
            quorum_set_hash: hash_quorum_set(ctx.local_quorum_set).into(),
            ballot,
            prepared: self.prepared.clone(),
            prepared_prime: self.prepared_prime.clone(),
            n_c: self.commit.as_ref().map(|b| b.counter).unwrap_or(0),
            n_h: self.high_ballot.as_ref().map(|b| b.counter).unwrap_or(0),
        };

        // Only update last_envelope (for network emission) when we have a
        // real ballot. Matches stellar-core `canEmit = mCurrentBallot != nullptr`.
        self.record_envelope(
            ScpStatementPledges::Prepare(prep),
            can_emit,
            ctx.local_node_id,
            ctx.driver,
            ctx.slot_index,
        )
    }

    /// Sign, record, and optionally publish an envelope built from the given pledges.
    ///
    /// Shared scaffolding for emit_prepare / emit_confirm / emit_externalize.
    /// When `set_last` is true the envelope is stored for network emission.
    fn record_envelope<D: SCPDriver>(
        &mut self,
        pledges: ScpStatementPledges,
        set_last: bool,
        local_node_id: &NodeId,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> Option<ScpStatement> {
        let statement = ScpStatement {
            node_id: local_node_id.clone(),
            slot_index,
            pledges,
        };

        let mut envelope = ScpEnvelope {
            statement: statement.clone(),
            signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
        };

        driver.sign_envelope(&mut envelope);
        if self.record_local_envelope(local_node_id, envelope.clone()) {
            if set_last {
                self.last_envelope = Some(envelope);
            }
            return Some(statement);
        }
        None
    }

    /// Build and record a confirm statement envelope.
    /// Returns the statement if a new envelope was recorded (for self-processing).
    fn emit_confirm<'a, D: SCPDriver>(
        &mut self,
        ctx: &SlotContext<'a, D>,
    ) -> Option<ScpStatement> {
        if let Some(ref ballot) = self.current_ballot {
            let conf = ScpStatementConfirm {
                ballot: ballot.clone(),
                n_prepared: self.prepared.as_ref().map(|b| b.counter).unwrap_or(0),
                n_commit: self.commit.as_ref().map(|b| b.counter).unwrap_or(0),
                n_h: self.high_ballot.as_ref().map(|b| b.counter).unwrap_or(0),
                quorum_set_hash: hash_quorum_set(ctx.local_quorum_set).into(),
            };

            self.record_envelope(
                ScpStatementPledges::Confirm(conf),
                true,
                ctx.local_node_id,
                ctx.driver,
                ctx.slot_index,
            )
        } else {
            None
        }
    }

    /// Build and record an externalize statement envelope.
    /// Returns the statement if a new envelope was recorded (for self-processing).
    fn emit_externalize<'a, D: SCPDriver>(
        &mut self,
        ctx: &SlotContext<'a, D>,
    ) -> Option<ScpStatement> {
        if let Some(ref commit) = self.commit {
            let ext = ScpStatementExternalize {
                commit: commit.clone(),
                n_h: self.high_ballot.as_ref().map(|b| b.counter).unwrap_or(0),
                commit_quorum_set_hash: hash_quorum_set(ctx.local_quorum_set).into(),
            };

            self.record_envelope(
                ScpStatementPledges::Externalize(ext),
                true,
                ctx.local_node_id,
                ctx.driver,
                ctx.slot_index,
            )
        } else {
            None
        }
    }

    /// Emit current state and recursively self-process (matching stellar-core emitCurrentStateStatement).
    ///
    /// After emitting, feeds the self-envelope back into `advance_slot` so that
    /// cascading state transitions (e.g., accept-prepared → confirm-prepared →
    /// accept-commit) can happen within a single top-level `receiveEnvelope` call.
    /// The `current_message_level` guard in `send_latest_envelope` ensures only the
    /// final envelope is actually emitted to the network.
    fn emit_current_state<'a, D: SCPDriver>(
        &mut self,
        ctx: &SlotContext<'a, D>,
    ) {
        let maybe_statement = match self.phase {
            BallotPhase::Prepare => {
                self.emit_prepare(ctx)
            }
            BallotPhase::Confirm => {
                self.emit_confirm(ctx)
            }
            BallotPhase::Externalize => {
                self.emit_externalize(ctx)
            }
        };
        // Recursive self-processing: feed the self-envelope back into advance_slot
        // so cascading state transitions complete within a single receiveEnvelope.
        // This matches stellar-core emitCurrentStateStatement() calling processEnvelope(self).
        if let Some(statement) = maybe_statement {
            self.advance_slot(
                &statement,
                ctx,
            );
        }
        // Emit the latest envelope after self-processing completes.
        // If advance_slot caused cascading state changes, last_envelope
        // was updated to the final envelope and already emitted via
        // advance_slot's send_latest_envelope call. The dedup check in
        // send_latest_envelope (last_envelope_emit) prevents double-emit.
        // If no cascading happened, this ensures the original envelope
        // is emitted. Matches stellar-core sendLatestEnvelope() in
        // emitCurrentStateStatement after processEnvelope(self).
        self.send_latest_envelope(ctx.driver);
    }

    fn record_local_envelope(&mut self, local_node_id: &NodeId, envelope: ScpEnvelope) -> bool {
        if !self.is_newer_statement(local_node_id, &envelope.statement) {
            return false;
        }
        self.latest_envelopes
            .insert(local_node_id.clone(), envelope);
        true
    }

    /// Restore state from a saved envelope (for crash recovery).
    ///
    /// This method is used to restore the ballot protocol state from a previously
    /// saved envelope when restarting after a crash. It sets up the internal state
    /// to match what it would have been after processing that envelope.
    ///
    /// # Arguments
    /// * `envelope` - The envelope to restore state from
    ///
    /// # Returns
    /// True if state was successfully restored, false if the envelope is invalid
    /// for state restoration.
    pub fn set_state_from_envelope(&mut self, envelope: &ScpEnvelope) -> bool {
        match &envelope.statement.pledges {
            ScpStatementPledges::Prepare(prep) => {
                self.current_ballot = Some(prep.ballot.clone());
                self.prepared = prep.prepared.clone();
                self.prepared_prime = prep.prepared_prime.clone();
                if prep.n_c != 0 {
                    self.commit = Some(ScpBallot {
                        counter: prep.n_c,
                        value: prep.ballot.value.clone(),
                    });
                }
                if prep.n_h != 0 {
                    self.high_ballot = Some(ScpBallot {
                        counter: prep.n_h,
                        value: prep.ballot.value.clone(),
                    });
                }
                self.value = Some(prep.ballot.value.clone());
                self.phase = BallotPhase::Prepare;
                self.latest_envelopes
                    .insert(envelope.statement.node_id.clone(), envelope.clone());
                self.last_envelope = Some(envelope.clone());
                true
            }
            ScpStatementPledges::Confirm(conf) => {
                self.current_ballot = Some(conf.ballot.clone());
                self.prepared = Some(ScpBallot {
                    counter: conf.n_prepared,
                    value: conf.ballot.value.clone(),
                });
                self.prepared_prime = None;
                self.commit = Some(ScpBallot {
                    counter: conf.n_commit,
                    value: conf.ballot.value.clone(),
                });
                self.high_ballot = Some(ScpBallot {
                    counter: conf.n_h,
                    value: conf.ballot.value.clone(),
                });
                self.value = Some(conf.ballot.value.clone());
                self.phase = BallotPhase::Confirm;
                self.latest_envelopes
                    .insert(envelope.statement.node_id.clone(), envelope.clone());
                self.last_envelope = Some(envelope.clone());
                true
            }
            ScpStatementPledges::Externalize(ext) => {
                self.commit = Some(ext.commit.clone());
                self.high_ballot = Some(ScpBallot {
                    counter: ext.n_h,
                    value: ext.commit.value.clone(),
                });
                self.current_ballot = Some(ScpBallot {
                    counter: u32::MAX,
                    value: ext.commit.value.clone(),
                });
                // stellar-core sets mPrepared = makeBallot(UINT32_MAX, v)
                self.prepared = Some(ScpBallot {
                    counter: u32::MAX,
                    value: ext.commit.value.clone(),
                });
                self.value = Some(ext.commit.value.clone());
                self.phase = BallotPhase::Externalize;
                self.latest_envelopes
                    .insert(envelope.statement.node_id.clone(), envelope.clone());
                self.last_envelope = Some(envelope.clone());
                true
            }
            _ => false,
        }
    }

    /// Bump the ballot to a specific counter value.
    ///
    /// This is used when we need to bump to a specific ballot counter,
    /// for example when catching up to a higher ballot counter seen on the network.
    ///
    /// # Arguments
    /// * `local_node_id` - Our node ID
    /// * `local_quorum_set` - Our quorum set
    /// * `driver` - The SCP driver
    /// * `slot_index` - The slot index
    /// * `value` - The value for the ballot
    /// * `counter` - The specific counter to bump to
    ///
    /// # Returns
    /// True if the ballot was bumped, false if the operation failed.
    pub(crate) fn bump_state<'a, D: SCPDriver>(
        &mut self,
        ctx: &SlotContext<'a, D>,
        value: Value,
        counter: u32,
    ) -> bool {
        if self.phase != BallotPhase::Prepare && self.phase != BallotPhase::Confirm {
            return false;
        }

        let effective_value = if let Some(ref override_val) = self.value_override {
            // Use the value that we saw confirmed prepared
            // or that we at least voted to commit to
            override_val.clone()
        } else {
            value
        };

        let ballot = ScpBallot {
            counter,
            value: effective_value,
        };

        let updated = self.update_current_value(&ballot);

        if updated {
            self.emit_current_state(ctx);
            self.check_heard_from_quorum(ctx);
        }

        updated
    }

    /// Abandon the current ballot and move to a new one.
    ///
    /// This is a public wrapper around the internal abandon logic,
    /// used when we need to give up on the current ballot and try a new one.
    /// Properly emits envelopes and checks heard-from-quorum via `bump_state`.
    ///
    /// # Arguments
    /// * `counter` - The counter for the new ballot (0 to auto-increment)
    /// * `local_node_id` - The local node's identifier
    /// * `local_quorum_set` - The local node's quorum set
    /// * `driver` - The SCP driver
    /// * `slot_index` - The slot index
    ///
    /// # Returns
    /// True if the ballot was abandoned successfully.
    pub(crate) fn abandon_ballot_public<'a, D: SCPDriver>(
        &mut self,
        counter: u32,
        ctx: &SlotContext<'a, D>,
    ) -> bool {
        self.abandon_ballot(counter, ctx)
    }
}

fn min_validation_level(left: ValidationLevel, right: ValidationLevel) -> ValidationLevel {
    match (left, right) {
        (ValidationLevel::Invalid, _) | (_, ValidationLevel::Invalid) => ValidationLevel::Invalid,
        (ValidationLevel::MaybeValid, _) | (_, ValidationLevel::MaybeValid) => {
            ValidationLevel::MaybeValid
        }
        _ => ValidationLevel::FullyValidated,
    }
}

impl Default for BallotProtocol {
    fn default() -> Self {
        Self::new()
    }
}

/// Compare two ballots.
/// Returns Greater if a > b, Less if a < b, Equal if a == b.
fn ballot_compare(a: &ScpBallot, b: &ScpBallot) -> std::cmp::Ordering {
    match a.counter.cmp(&b.counter) {
        std::cmp::Ordering::Equal => a.value.cmp(&b.value),
        other => other,
    }
}

/// Compare two optional ballots (None < Some).
fn cmp_opt_ballot(a: &Option<ScpBallot>, b: &Option<ScpBallot>) -> std::cmp::Ordering {
    match (a, b) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        (Some(a), Some(b)) => ballot_compare(a, b),
    }
}

/// Check if two ballots are compatible (same value).
fn ballot_compatible(a: &ScpBallot, b: &ScpBallot) -> bool {
    a.value == b.value
}

fn are_ballots_less_and_compatible(a: &ScpBallot, b: &ScpBallot) -> bool {
    ballot_compare(a, b) != std::cmp::Ordering::Greater && ballot_compatible(a, b)
}

fn are_ballots_less_and_incompatible(a: &ScpBallot, b: &ScpBallot) -> bool {
    ballot_compare(a, b) != std::cmp::Ordering::Greater && !ballot_compatible(a, b)
}

#[cfg(test)]
impl BallotProtocol {
    /// Test helper: set current_message_level to simulate deep recursion.
    pub fn set_current_message_level_for_test(&mut self, level: u32) {
        self.current_message_level = level;
    }

    /// Test helper: expose advance_slot for testing.
    pub(crate) fn advance_slot_for_test<'a, D: SCPDriver>(
        &mut self,
        hint: &ScpStatement,
        ctx: &SlotContext<'a, D>,
    ) -> EnvelopeState {
        self.advance_slot(hint, ctx)
    }
}

#[cfg(test)]
mod tests;
