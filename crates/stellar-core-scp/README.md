# stellar-core-scp

Stellar Consensus Protocol (SCP) implementation for rs-stellar-core.

## Overview

SCP is a federated Byzantine agreement protocol that enables nodes to reach consensus without requiring a closed membership or central authority.

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Quorum Slices** | Each node defines its own set of trusted nodes |
| **Quorum** | A set of nodes sufficient for agreement (intersection of slices) |
| **Blocking Set** | A set that can prevent agreement |
| **V-Blocking** | A set that intersects all quorum slices of a node |

## Protocol Phases

### 1. Nomination Phase

Nodes propose and vote on candidate values:

```rust
// Propose a value for nomination
scp.nominate(slot_index, value, &prev_value);
```

### 2. Ballot Protocol

Nodes vote to prepare and commit ballots:

| Phase | Description |
|-------|-------------|
| PREPARE | Vote to prepare a ballot |
| CONFIRM | Confirm that a ballot is prepared |
| EXTERNALIZE | Commit to a value |

## Safety Guarantees

SCP guarantees safety (agreement) for any two nodes that share a quorum, and provides liveness when the network is well-behaved.

## Usage

### Basic SCP Operations

```rust
use stellar_core_scp::{SCP, EnvelopeState};

let scp = SCP::new(node_id, quorum_set, driver);

// Nominate a value
scp.nominate(slot_index, value, &prev_value);

// Process an incoming envelope
let state = scp.receive_envelope(envelope);
match state {
    EnvelopeState::ValidNew => {
        // Envelope caused state change
    }
    EnvelopeState::Valid => {
        // Envelope valid but no change
    }
    EnvelopeState::Invalid => {
        // Invalid envelope
    }
}
```

### For Catchup/Sync Mode

During catchup, skip SCP and just apply historical ledgers:

```rust
// Mark a slot as externalized without consensus
scp.force_externalize(ledger_seq, ledger_value);
```

During live sync, participate in consensus:

```rust
// Nominate values and process envelopes
scp.nominate(slot_index, value, &prev_value);
let state = scp.receive_envelope(envelope);
```

### Quorum Utilities

```rust
use stellar_core_scp::{
    hash_quorum_set, is_quorum, is_quorum_slice, is_v_blocking, normalize_quorum_set,
};

// Check if a set forms a quorum
let is_q = is_quorum(&nodes, &quorum_set);

// Check if a set is a quorum slice
let is_slice = is_quorum_slice(&nodes, &quorum_set);

// Check if a set is v-blocking
let is_vb = is_v_blocking(&nodes, &quorum_set);

// Hash a quorum set for comparison
let hash = hash_quorum_set(&quorum_set);

// Normalize quorum set ordering
normalize_quorum_set(&mut quorum_set);
```

## Key Types

### SCP

Main SCP state machine:

```rust
let scp = SCP::new(node_id, true, quorum_set, driver);
let state = scp.get_slot_state(slot_index);
```

### SlotState

State of a consensus slot:

```rust
if let Some(state) = scp.get_slot_state(slot_index) {
    println!("nominating round: {}", state.nomination_round);
    println!("ballot round: {:?}", state.ballot_round);
    println!("phase: {:?}", state.ballot_phase);
}
```

### EnvelopeState

Result of processing an envelope:

```rust
let state = scp.receive_envelope(envelope);

assert!(state.is_valid());  // Valid or ValidNew
assert!(state.is_new());    // Caused state change
```

### SCPDriver

Trait for SCP callbacks (abridged; see `crates/stellar-core-scp/src/driver.rs`):

```rust
trait SCPDriver {
    fn validate_value(&self, slot: SlotIndex, value: &Value, nomination: bool) -> ValidationLevel;
    fn combine_candidates(&self, slot: SlotIndex, candidates: &[Value]) -> Option<Value>;
    fn extract_valid_value(&self, slot: SlotIndex, value: &Value) -> Option<Value>;
    fn emit_envelope(&self, envelope: &ScpEnvelope);
    fn get_quorum_set(&self, node_id: &NodeId) -> Option<ScpQuorumSet>;
    fn nominating_value(&self, slot: SlotIndex, value: &Value);
    fn value_externalized(&self, slot: SlotIndex, value: &Value);
    fn ballot_did_prepare(&self, slot: SlotIndex, ballot: &ScpBallot);
    fn ballot_did_confirm(&self, slot: SlotIndex, ballot: &ScpBallot);
    fn compute_hash_node(&self, slot: SlotIndex, prev: &Value, is_priority: bool, round: u32, node: &NodeId) -> u64;
    fn compute_value_hash(&self, slot: SlotIndex, prev: &Value, round: u32, value: &Value) -> u64;
    fn compute_timeout(&self, round: u32, is_nomination: bool) -> std::time::Duration;
    fn sign_envelope(&self, envelope: &mut ScpEnvelope);
    fn verify_envelope(&self, envelope: &ScpEnvelope) -> bool;
}
```

## Ballot Protocol Details

Ballots have a counter and value:

```rust
let ballot = ScpBallot {
    counter: 1,
    value: value.clone(),
};
```

The protocol progresses through:

1. **vote prepare(b)** - Vote to prepare ballot b
2. **accept prepare(b)** - Accept b is prepared
3. **confirm prepare(b)** - Confirm b is prepared
4. **vote commit(b)** - Vote to commit b
5. **accept commit(b)** - Accept b is committed

## Slot Index

Typically corresponds to the ledger sequence number:

```rust
type SlotIndex = u64;

let slot: SlotIndex = ledger_seq as u64;
```

## Dependencies

- `stellar-xdr` - SCP message types
- `sha2` - Quorum set hashing
- `stellar-core-common` - Hash256

## License

Apache 2.0
