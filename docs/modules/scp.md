# SCP Module Specification

**Crate**: `stellar-core-scp`
**stellar-core mapping**: `src/scp/`

## 1. Overview

The SCP (Stellar Consensus Protocol) module implements Federated Byzantine Agreement (FBA). This is the heart of Stellar's consensus mechanism, enabling decentralized agreement without a central authority.

Key concepts:
- **Quorum Slices**: Each node defines who it trusts
- **Quorums**: Sets of nodes that can convince any member
- **Nomination**: Proposing candidate values
- **Ballot Protocol**: Agreeing on a single value

## 2. stellar-core Reference

In stellar-core, the SCP module (`src/scp/`) is intentionally isolated from the rest of the system:
- `SCP.h/cpp` - Main SCP driver
- `SCPDriver.h` - Abstract interface for SCP callbacks
- `Slot.h/cpp` - Per-slot consensus state
- `BallotProtocol.h/cpp` - Ballot protocol implementation
- `NominationProtocol.h/cpp` - Nomination protocol
- `QuorumSetUtils.h/cpp` - Quorum set operations
- `LocalNode.h/cpp` - Local node representation

### 2.1 SCP Message Types

```
SCPStatementType:
- SCP_ST_NOMINATE     - Nomination statement
- SCP_ST_PREPARE      - Ballot prepare
- SCP_ST_CONFIRM      - Ballot confirm
- SCP_ST_EXTERNALIZE  - Ballot externalize
```

## 3. Rust Implementation

### 3.1 Dependencies

```toml
[dependencies]
stellar-xdr = { version = "25.0.0", features = ["std", "curr"] }
stellar-core-crypto = { path = "../stellar-core-crypto" }

# Data structures
indexmap = "2"
im = "15"  # Immutable collections for efficient cloning

# Utilities
thiserror = "1"
tracing = "0.1"
parking_lot = "0.12"
```

### 3.2 Module Structure

```
stellar-core-scp/
├── src/
│   ├── lib.rs
│   ├── scp.rs              # Main SCP driver
│   ├── driver.rs           # SCPDriver trait
│   ├── slot.rs             # Per-slot state
│   ├── nomination.rs       # Nomination protocol
│   ├── ballot.rs           # Ballot protocol
│   ├── quorum.rs           # Quorum set operations
│   ├── local_node.rs       # Local node info
│   ├── envelope.rs         # Envelope handling
│   └── error.rs
└── tests/
    ├── nomination_tests.rs
    ├── ballot_tests.rs
    └── simulation_tests.rs
```

### 3.3 Core Types

#### SCPDriver Trait

```rust
use stellar_xdr::curr::{
    ScpEnvelope, ScpQuorumSet, ScpBallot, Value, NodeId, Hash,
};

/// Callback interface for SCP
/// Implemented by Herder to connect SCP to the rest of the system
#[async_trait::async_trait]
pub trait SCPDriver: Send + Sync {
    /// Validate a value (is this a valid candidate?)
    fn validate_value(
        &self,
        slot_index: u64,
        value: &Value,
        nomination: bool,
    ) -> ValidationLevel;

    /// Combine multiple values into one (for nomination)
    fn combine_candidates(
        &self,
        slot_index: u64,
        candidates: &[Value],
    ) -> Option<Value>;

    /// Extract valid value from a potentially invalid composite
    fn extract_valid_value(
        &self,
        slot_index: u64,
        value: &Value,
    ) -> Option<Value>;

    /// Emit an envelope to peers
    fn emit_envelope(&self, envelope: &ScpEnvelope);

    /// Get the quorum set for a node
    fn get_quorum_set(&self, node_id: &NodeId) -> Option<ScpQuorumSet>;

    /// Nominating value for slot
    fn nominating_value(&self, slot_index: u64, value: &Value);

    /// Value externalized (consensus reached)
    fn value_externalized(&self, slot_index: u64, value: &Value);

    /// Ballot prepared
    fn ballot_did_prepare(&self, slot_index: u64, ballot: &ScpBallot);

    /// Ballot confirmed
    fn ballot_did_confirm(&self, slot_index: u64, ballot: &ScpBallot);

    /// Slot fully externalized
    fn slot_externalized(&self, slot_index: u64, value: &Value);

    /// Compute hash for nomination (for consistency)
    fn compute_hash_node(
        &self,
        slot_index: u64,
        prev_value: &Value,
        is_priority: bool,
        round: u32,
        node_id: &NodeId,
    ) -> u64;

    /// Compute value hash for nomination
    fn compute_value_hash(
        &self,
        slot_index: u64,
        prev_value: &Value,
        round: u32,
        value: &Value,
    ) -> u64;

    /// Compute timeout for nomination round
    fn compute_timeout(&self, round: u32) -> std::time::Duration;

    /// Sign an envelope
    fn sign_envelope(&self, envelope: &mut ScpEnvelope);

    /// Verify envelope signature
    fn verify_envelope(&self, envelope: &ScpEnvelope) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationLevel {
    /// Invalid value
    Invalid,
    /// Value may be valid (not fully validated yet)
    MaybeValid,
    /// Fully validated
    FullyValidated,
}
```

#### SCP Main Driver

```rust
use std::collections::HashMap;
use parking_lot::RwLock;

/// Main SCP driver
pub struct SCP<D: SCPDriver> {
    /// Local node identifier
    local_node: LocalNode,
    /// Per-slot state
    slots: RwLock<HashMap<u64, Slot<D>>>,
    /// Driver callbacks
    driver: Arc<D>,
}

impl<D: SCPDriver> SCP<D> {
    pub fn new(
        node_id: NodeId,
        is_validator: bool,
        quorum_set: ScpQuorumSet,
        driver: Arc<D>,
    ) -> Self {
        Self {
            local_node: LocalNode::new(node_id, is_validator, quorum_set),
            slots: RwLock::new(HashMap::new()),
            driver,
        }
    }

    /// Process incoming SCP envelope
    pub fn receive_envelope(&self, envelope: ScpEnvelope) -> EnvelopeState {
        // Verify signature
        if !self.driver.verify_envelope(&envelope) {
            return EnvelopeState::Invalid;
        }

        let slot_index = envelope.statement.slot_index;
        let mut slots = self.slots.write();

        let slot = slots.entry(slot_index).or_insert_with(|| {
            Slot::new(slot_index, &self.local_node, Arc::clone(&self.driver))
        });

        slot.process_envelope(envelope)
    }

    /// Nominate a value for a slot
    pub fn nominate(
        &self,
        slot_index: u64,
        value: Value,
        prev_value: &Value,
    ) -> bool {
        let mut slots = self.slots.write();

        let slot = slots.entry(slot_index).or_insert_with(|| {
            Slot::new(slot_index, &self.local_node, Arc::clone(&self.driver))
        });

        slot.nominate(value, prev_value, false)
    }

    /// Stop nomination for a slot
    pub fn stop_nomination(&self, slot_index: u64) {
        if let Some(slot) = self.slots.write().get_mut(&slot_index) {
            slot.stop_nomination();
        }
    }

    /// Get externalized value for a slot (if consensus reached)
    pub fn get_externalized_value(&self, slot_index: u64) -> Option<Value> {
        self.slots.read().get(&slot_index)?.get_externalized_value()
    }

    /// Purge old slots to free memory
    pub fn purge_slots(&self, max_slot_to_keep: u64) {
        self.slots.write().retain(|&slot_index, _| slot_index >= max_slot_to_keep);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeState {
    /// Envelope is invalid
    Invalid,
    /// Envelope is valid but not new
    Valid,
    /// Envelope is valid and new (state changed)
    ValidNew,
}
```

#### Slot

```rust
/// Per-slot consensus state
pub struct Slot<D: SCPDriver> {
    slot_index: u64,
    local_node: LocalNode,
    driver: Arc<D>,

    /// Nomination protocol state
    nomination: NominationProtocol,
    /// Ballot protocol state
    ballot: BallotProtocol,

    /// All envelopes received for this slot
    envelopes: HashMap<NodeId, Vec<ScpEnvelope>>,
    /// Externalized value (if consensus reached)
    externalized_value: Option<Value>,
}

impl<D: SCPDriver> Slot<D> {
    pub fn new(slot_index: u64, local_node: &LocalNode, driver: Arc<D>) -> Self {
        Self {
            slot_index,
            local_node: local_node.clone(),
            driver: Arc::clone(&driver),
            nomination: NominationProtocol::new(),
            ballot: BallotProtocol::new(),
            envelopes: HashMap::new(),
            externalized_value: None,
        }
    }

    pub fn process_envelope(&mut self, envelope: ScpEnvelope) -> EnvelopeState {
        let node_id = envelope.statement.node_id.clone();

        // Store envelope
        self.envelopes
            .entry(node_id.clone())
            .or_default()
            .push(envelope.clone());

        match &envelope.statement.pledges {
            ScpStatementPledges::ScpStNominate(nom) => {
                self.nomination.process_envelope(&envelope, &self.driver)
            }
            ScpStatementPledges::ScpStPrepare(_)
            | ScpStatementPledges::ScpStConfirm(_)
            | ScpStatementPledges::ScpStExternalize(_) => {
                self.ballot.process_envelope(&envelope, &self.driver)
            }
        }
    }

    pub fn nominate(&mut self, value: Value, prev_value: &Value, timedout: bool) -> bool {
        self.nomination.nominate(&self.local_node, &self.driver, self.slot_index, value, prev_value, timedout)
    }

    pub fn stop_nomination(&mut self) {
        self.nomination.stop();
    }

    pub fn get_externalized_value(&self) -> Option<Value> {
        self.externalized_value.clone()
    }
}
```

### 3.4 Nomination Protocol

```rust
/// Nomination protocol state
pub struct NominationProtocol {
    /// Round number
    round: u32,
    /// Values we've voted for
    votes: Vec<Value>,
    /// Values we've accepted
    accepted: Vec<Value>,
    /// Nomination started
    started: bool,
    /// Nomination stopped (moving to ballot)
    stopped: bool,
    /// Latest composite value
    latest_composite: Option<Value>,
    /// Latest envelopes from each node
    latest_nominations: HashMap<NodeId, ScpEnvelope>,
}

impl NominationProtocol {
    pub fn new() -> Self {
        Self {
            round: 0,
            votes: Vec::new(),
            accepted: Vec::new(),
            started: false,
            stopped: false,
            latest_composite: None,
            latest_nominations: HashMap::new(),
        }
    }

    pub fn nominate<D: SCPDriver>(
        &mut self,
        local_node: &LocalNode,
        driver: &Arc<D>,
        slot_index: u64,
        value: Value,
        prev_value: &Value,
        timedout: bool,
    ) -> bool {
        if self.stopped {
            return false;
        }

        if timedout {
            self.round += 1;
        }

        // Add value to votes if not already present
        if !self.votes.contains(&value) {
            self.votes.push(value.clone());
        }

        // Emit nomination envelope
        self.emit_nomination(local_node, driver, slot_index);

        true
    }

    pub fn process_envelope<D: SCPDriver>(
        &mut self,
        envelope: &ScpEnvelope,
        driver: &Arc<D>,
    ) -> EnvelopeState {
        let node_id = &envelope.statement.node_id;

        if let ScpStatementPledges::ScpStNominate(nom) = &envelope.statement.pledges {
            // Check if this is newer than what we have
            if let Some(existing) = self.latest_nominations.get(node_id) {
                // Compare nomination statements
                // (newer has more voted/accepted values or higher round)
            }

            self.latest_nominations.insert(node_id.clone(), envelope.clone());

            // Check for newly accepted values based on quorum
            self.update_accepted(driver);

            // Update composite value
            self.update_composite(driver, envelope.statement.slot_index);

            EnvelopeState::ValidNew
        } else {
            EnvelopeState::Invalid
        }
    }

    fn update_accepted<D: SCPDriver>(&mut self, driver: &Arc<D>) {
        // A value is accepted if:
        // 1. We voted for it AND a quorum has voted for it, OR
        // 2. A blocking set has accepted it

        // Check each voted value
        for value in &self.votes.clone() {
            if !self.accepted.contains(value) {
                // Check if quorum has voted for this value
                // (requires quorum set intersection analysis)
                // This is simplified - real implementation needs full quorum checking
            }
        }
    }

    fn update_composite<D: SCPDriver>(&mut self, driver: &Arc<D>, slot_index: u64) {
        if !self.accepted.is_empty() {
            // Combine accepted values
            if let Some(composite) = driver.combine_candidates(slot_index, &self.accepted) {
                if self.latest_composite.as_ref() != Some(&composite) {
                    self.latest_composite = Some(composite.clone());
                    // Potentially bump to ballot protocol
                }
            }
        }
    }

    fn emit_nomination<D: SCPDriver>(
        &self,
        local_node: &LocalNode,
        driver: &Arc<D>,
        slot_index: u64,
    ) {
        // Create and emit nomination envelope
        let nom = ScpNomination {
            quorum_set_hash: hash_quorum_set(&local_node.quorum_set),
            votes: self.votes.clone().try_into().unwrap(),
            accepted: self.accepted.clone().try_into().unwrap(),
        };

        let statement = ScpStatement {
            node_id: local_node.node_id.clone(),
            slot_index,
            pledges: ScpStatementPledges::ScpStNominate(nom),
        };

        let mut envelope = ScpEnvelope {
            statement,
            signature: Default::default(),
        };

        driver.sign_envelope(&mut envelope);
        driver.emit_envelope(&envelope);
    }

    pub fn stop(&mut self) {
        self.stopped = true;
    }
}
```

### 3.5 Ballot Protocol

```rust
/// Ballot protocol state
pub struct BallotProtocol {
    /// Current ballot
    current_ballot: Option<ScpBallot>,
    /// Highest prepared ballot
    prepared: Option<ScpBallot>,
    /// Highest confirmed prepared ballot
    prepared_prime: Option<ScpBallot>,
    /// Lowest ballot we can accept commit
    high_ballot: Option<ScpBallot>,
    /// Lowest ballot we can accept commit
    low_ballot: Option<ScpBallot>,
    /// Committed ballot
    commit: Option<ScpBallot>,
    /// Phase
    phase: BallotPhase,
    /// Latest envelopes from each node
    latest_envelopes: HashMap<NodeId, ScpEnvelope>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BallotPhase {
    Prepare,
    Confirm,
    Externalize,
}

impl BallotProtocol {
    pub fn new() -> Self {
        Self {
            current_ballot: None,
            prepared: None,
            prepared_prime: None,
            high_ballot: None,
            low_ballot: None,
            commit: None,
            phase: BallotPhase::Prepare,
            latest_envelopes: HashMap::new(),
        }
    }

    /// Bump to a new ballot with the given value
    pub fn bump<D: SCPDriver>(
        &mut self,
        local_node: &LocalNode,
        driver: &Arc<D>,
        slot_index: u64,
        value: Value,
        force: bool,
    ) -> bool {
        let counter = self.current_ballot
            .as_ref()
            .map(|b| b.counter + 1)
            .unwrap_or(1);

        let ballot = ScpBallot { counter, value };

        self.current_ballot = Some(ballot.clone());

        // Emit prepare envelope
        self.emit_prepare(local_node, driver, slot_index);

        true
    }

    pub fn process_envelope<D: SCPDriver>(
        &mut self,
        envelope: &ScpEnvelope,
        driver: &Arc<D>,
    ) -> EnvelopeState {
        let node_id = &envelope.statement.node_id;

        match &envelope.statement.pledges {
            ScpStatementPledges::ScpStPrepare(prep) => {
                self.latest_envelopes.insert(node_id.clone(), envelope.clone());
                self.advance_slot(driver, envelope.statement.slot_index)
            }
            ScpStatementPledges::ScpStConfirm(conf) => {
                self.latest_envelopes.insert(node_id.clone(), envelope.clone());
                self.advance_slot(driver, envelope.statement.slot_index)
            }
            ScpStatementPledges::ScpStExternalize(ext) => {
                self.latest_envelopes.insert(node_id.clone(), envelope.clone());
                // Externalize received - may trigger local externalization
                self.advance_slot(driver, envelope.statement.slot_index)
            }
            _ => EnvelopeState::Invalid,
        }
    }

    fn advance_slot<D: SCPDriver>(
        &mut self,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> EnvelopeState {
        // Check for state transitions based on quorum/blocking set analysis

        match self.phase {
            BallotPhase::Prepare => {
                // Check if we can move to confirm
                // Requires: quorum has prepared the same ballot
            }
            BallotPhase::Confirm => {
                // Check if we can externalize
                // Requires: quorum has confirmed commit
            }
            BallotPhase::Externalize => {
                // Already done
            }
        }

        EnvelopeState::ValidNew
    }

    fn emit_prepare<D: SCPDriver>(
        &self,
        local_node: &LocalNode,
        driver: &Arc<D>,
        slot_index: u64,
    ) {
        // Create and emit prepare envelope
    }
}
```

### 3.6 Quorum Set Operations

```rust
use stellar_xdr::curr::{ScpQuorumSet, PublicKey};

/// Check if a set of nodes forms a quorum
pub fn is_quorum(
    quorum_set: &ScpQuorumSet,
    nodes: &HashSet<NodeId>,
    get_quorum_set: impl Fn(&NodeId) -> Option<ScpQuorumSet>,
) -> bool {
    is_quorum_slice(quorum_set, nodes, &get_quorum_set) &&
        nodes.iter().all(|n| {
            get_quorum_set(n)
                .map(|qs| is_quorum_slice(&qs, nodes, &get_quorum_set))
                .unwrap_or(false)
        })
}

/// Check if nodes satisfy a quorum slice
pub fn is_quorum_slice(
    quorum_set: &ScpQuorumSet,
    nodes: &HashSet<NodeId>,
    get_quorum_set: &impl Fn(&NodeId) -> Option<ScpQuorumSet>,
) -> bool {
    let threshold = quorum_set.threshold as usize;
    let mut count = 0;

    // Count validators
    for validator in &quorum_set.validators {
        if nodes.contains(&NodeId::from(validator)) {
            count += 1;
        }
    }

    // Count inner sets
    for inner_set in &quorum_set.inner_sets {
        if is_quorum_slice(inner_set, nodes, get_quorum_set) {
            count += 1;
        }
    }

    count >= threshold
}

/// Check if a set is a blocking set (can block consensus)
pub fn is_blocking_set(
    quorum_set: &ScpQuorumSet,
    nodes: &HashSet<NodeId>,
) -> bool {
    is_blocking_set_helper(quorum_set, nodes)
}

fn is_blocking_set_helper(
    quorum_set: &ScpQuorumSet,
    nodes: &HashSet<NodeId>,
) -> bool {
    let total = quorum_set.validators.len() + quorum_set.inner_sets.len();
    let threshold = quorum_set.threshold as usize;
    let blocking_threshold = total - threshold + 1;

    let mut count = 0;

    for validator in &quorum_set.validators {
        if nodes.contains(&NodeId::from(validator)) {
            count += 1;
        }
    }

    for inner_set in &quorum_set.inner_sets {
        if is_blocking_set_helper(inner_set, nodes) {
            count += 1;
        }
    }

    count >= blocking_threshold
}

/// Compute quorum set hash
pub fn hash_quorum_set(quorum_set: &ScpQuorumSet) -> Hash256 {
    let xdr = quorum_set.to_xdr(stellar_xdr::Limits::none()).unwrap();
    Hash256::hash(&xdr)
}
```

## 4. Tests to Port from stellar-core

From `src/scp/test/`:
- `SCPTests.cpp` - Core SCP tests
- `QuorumSetTests.cpp` - Quorum set operations
- Simulation tests with various network topologies

Key test scenarios:
1. Simple 3-node consensus
2. 4-node with 1 byzantine
3. Quorum intersection detection
4. Stuck scenarios and recovery
5. Timeout handling
6. Value priority ordering

## 5. Important Notes

### 5.1 SCP Isolation

The SCP module should be **completely isolated** from the rest of the system:
- No direct access to ledger state
- No direct network access
- All interaction through SCPDriver trait

### 5.2 Determinism

SCP must be deterministic:
- Same inputs → same outputs
- Hash computations must match stellar-core exactly
- Timeout handling must be consistent

### 5.3 Performance

- Minimize allocations during consensus
- Use efficient set operations for quorum checking
- Cache quorum set hashes
