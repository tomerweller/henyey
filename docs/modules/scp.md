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

The crate relies on:
- `stellar-xdr` for SCP types.
- `stellar-core-common` for hashing helpers.
- `parking_lot` and standard collections for in-memory state.

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
│   └── error.rs
```

### 3.3 Core Types

#### SCPDriver Trait

```rust
use stellar_xdr::curr::{
    ScpEnvelope, ScpQuorumSet, ScpBallot, Value, NodeId, Hash,
};

/// Callback interface for SCP
/// Implemented by Herder to connect SCP to the rest of the system
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

    /// Compute timeout for nomination/ballot rounds
    fn compute_timeout(&self, round: u32, is_nomination: bool) -> std::time::Duration;

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
let scp = SCP::new(node_id, true, quorum_set, driver);

// Submit a nomination
scp.nominate(slot_index, value, &prev_value);

// Process incoming envelopes
let state = scp.receive_envelope(envelope);
```

#### Slot

Slots encapsulate per-ledger SCP state (nomination + ballot). Use
`SCP::get_slot_state` for summaries; internal slot state is managed by `SCP`.

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
