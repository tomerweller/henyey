# stellar-core-scp

Rust implementation of the Stellar Consensus Protocol (SCP) for rs-stellar-core.

## Overview

SCP is a federated Byzantine agreement protocol that enables nodes to reach consensus without requiring a closed membership or central authority. This crate provides a complete implementation of SCP suitable for use in Stellar network nodes.

## Key Concepts

### Quorum Sets

Each node defines its own **quorum set** - a configuration specifying which validators it trusts. A quorum set includes:
- A **threshold**: minimum number of members that must agree
- **Validators**: direct trusted nodes
- **Inner sets**: nested quorum sets for hierarchical trust

### Quorum and Blocking Sets

- **Quorum**: A set of nodes where every member's quorum slice is satisfied. When a quorum agrees, the decision is irreversible.
- **Blocking Set (V-Blocking)**: A set that intersects every quorum slice, able to prevent any quorum from forming.

### Protocol Phases

SCP operates in two phases:

1. **Nomination**: Nodes propose and vote on candidate values
   - Values progress from voted -> accepted -> confirmed (candidate)
   - Confirmed candidates are combined into a composite value

2. **Ballot Protocol**: Nodes agree on a single value through:
   - **PREPARE**: Vote that a ballot is safe to commit
   - **CONFIRM**: Agree on which ballot to commit
   - **EXTERNALIZE**: Commit to the final value

## Architecture

```
+-------+     +------+     +--------------------+
|  SCP  | --> | Slot | --> | NominationProtocol |
+-------+     +------+     +--------------------+
                  |
                  +------> +----------------+
                           | BallotProtocol |
                           +----------------+
```

- `SCP`: Main coordinator managing multiple slots
- `Slot`: Per-slot state (nomination + ballot)
- `NominationProtocol`: First phase - value proposal and voting
- `BallotProtocol`: Second phase - commit and externalization

## Key Types

| Type | Description |
|------|-------------|
| `SCP<D>` | Main coordinator, parameterized by driver (`D: SCPDriver`) |
| `Slot` | Per-slot consensus state |
| `SCPDriver` | Trait for application callbacks |
| `NominationProtocol` | Nomination phase state machine |
| `BallotProtocol` | Ballot phase state machine |
| `EnvelopeState` | Result of processing an SCP message |
| `ValidationLevel` | Value validation result (Invalid/MaybeValid/FullyValidated) |
| `BallotPhase` | Current phase (Prepare/Confirm/Externalize) |
| `SCPTimerType` | Timer identifier (Nomination/Ballot) |
| `ScpError` | Error types for SCP operations |
| `SlotState` | Debugging snapshot of slot consensus state |
| `QuorumSetJson` | JSON-serializable quorum set for persistence and debugging |

## Usage

### Basic Setup

```rust
use stellar_core_scp::{SCP, SCPDriver, EnvelopeState};
use std::sync::Arc;

// Implement the driver trait for your application
struct MyDriver { /* ... */ }
impl SCPDriver for MyDriver { /* ... */ }

// Create SCP instance
let driver = Arc::new(MyDriver::new());
let scp = SCP::new(node_id, is_validator, quorum_set, driver);
```

### Participating in Consensus

```rust
// Nominate a value for a slot
scp.nominate(slot_index, value, &prev_value);

// Process incoming messages
let state = scp.receive_envelope(envelope);
match state {
    EnvelopeState::ValidNew => { /* State changed */ }
    EnvelopeState::Valid => { /* Valid but no change */ }
    EnvelopeState::Invalid => { /* Rejected */ }
}

// Check for externalized values
if let Some(value) = scp.get_externalized_value(slot_index) {
    // Consensus reached - apply the value
}
```

### Catchup Mode

During catchup from historical data, slots can be force-externalized:

```rust
// Skip consensus and directly mark slot as externalized
scp.force_externalize(ledger_seq, ledger_value);
```

## The SCPDriver Trait

The `SCPDriver` trait connects SCP to your application:

```rust
pub trait SCPDriver: Send + Sync {
    // Validate a proposed value
    fn validate_value(&self, slot_index: u64, value: &Value, nomination: bool) -> ValidationLevel;

    // Combine multiple candidates into one
    fn combine_candidates(&self, slot_index: u64, candidates: &[Value]) -> Option<Value>;

    // Extract a valid value from a potentially invalid composite
    fn extract_valid_value(&self, slot_index: u64, value: &Value) -> Option<Value>;

    // Broadcast an envelope to peers
    fn emit_envelope(&self, envelope: &ScpEnvelope);

    // Get a node's quorum set
    fn get_quorum_set(&self, node_id: &NodeId) -> Option<ScpQuorumSet>;

    // Notification callbacks
    fn nominating_value(&self, slot_index: u64, value: &Value);
    fn value_externalized(&self, slot_index: u64, value: &Value);
    fn ballot_did_prepare(&self, slot_index: u64, ballot: &ScpBallot);
    fn ballot_did_confirm(&self, slot_index: u64, ballot: &ScpBallot);

    // Deterministic hash computations (must match across all nodes)
    fn compute_hash_node(&self, slot_index: u64, prev_value: &Value,
        is_priority: bool, round: u32, node_id: &NodeId) -> u64;
    fn compute_value_hash(&self, slot_index: u64, prev_value: &Value,
        round: u32, value: &Value) -> u64;
    fn compute_timeout(&self, round: u32, is_nomination: bool) -> Duration;

    // Cryptographic operations
    fn sign_envelope(&self, envelope: &mut ScpEnvelope);
    fn verify_envelope(&self, envelope: &ScpEnvelope) -> bool;

    // ... and more (with default implementations):
    // get_quorum_set_by_hash, hash_quorum_set, get_node_weight,
    // get_value_string, get_hash_of, setup_timer, stop_timer,
    // accepted_ballot_prepared, confirmed_ballot_prepared,
    // accepted_commit, ballot_did_hear_from_quorum,
    // started_ballot_protocol, updated_candidate_value, timer_expired
}
```

## Quorum Configuration

Use the `quorum_config` module to set up quorum sets:

```rust
use stellar_core_scp::quorum_config::{testnet_quorum_config, config_to_quorum_set};

// Use predefined testnet config
let config = testnet_quorum_config();
let quorum_set = config_to_quorum_set(&config)?;

// Or create custom configuration (QuorumSetConfig is from stellar_core_common)
use stellar_core_common::config::QuorumSetConfig;
let config = QuorumSetConfig {
    threshold_percent: 67.into(),
    validators: vec![
        "GDKXE2OZMJIPOSLNA6N6F2BVCI3O777I2OOC4BV7VOYUEHYX7RTRYA7Y".to_string(),
        // ... more validators
    ],
    inner_sets: vec![],
};
```

## Safety Guarantees

SCP provides:
- **Agreement**: If two nodes externalize values, they externalize the same value
- **Validity**: Externalized values were proposed by some node
- **Liveness**: If the network is well-behaved, nodes eventually externalize

These guarantees hold as long as quorum sets have sufficient intersection.

## Determinism

For correct operation, the following must be deterministic:
- Value validation
- Hash computations
- Value ordering and comparison
- Timeout calculations (given the same inputs)

## Module Layout

```
src/
  lib.rs           - Crate root, re-exports
  scp.rs           - Main SCP coordinator
  slot.rs          - Per-slot state
  nomination.rs    - Nomination protocol
  ballot.rs        - Ballot protocol
  quorum.rs        - Quorum set operations
  quorum_config.rs - Configuration utilities
  driver.rs        - SCPDriver trait
  error.rs         - Error types
```

## Upstream Reference

This implementation corresponds to the C++ stellar-core SCP implementation in `src/scp/`.

---

## C++ Parity Status

See [PARITY_STATUS.md](PARITY_STATUS.md) for detailed C++ parity analysis.
