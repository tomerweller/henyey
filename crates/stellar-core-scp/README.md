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
| `SCP<D>` | Main coordinator, parameterized by driver |
| `Slot` | Per-slot consensus state |
| `SCPDriver` | Trait for application callbacks |
| `NominationProtocol` | Nomination phase state machine |
| `BallotProtocol` | Ballot phase state machine |
| `EnvelopeState` | Result of processing an SCP message |
| `ValidationLevel` | Value validation result |
| `BallotPhase` | Current phase (Prepare/Confirm/Externalize) |

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
    fn validate_value(&self, slot: u64, value: &Value, nomination: bool) -> ValidationLevel;

    // Combine multiple candidates into one
    fn combine_candidates(&self, slot: u64, candidates: &[Value]) -> Option<Value>;

    // Broadcast an envelope to peers
    fn emit_envelope(&self, envelope: &ScpEnvelope);

    // Get a node's quorum set
    fn get_quorum_set(&self, node_id: &NodeId) -> Option<ScpQuorumSet>;

    // Called when consensus is reached
    fn value_externalized(&self, slot: u64, value: &Value);

    // Cryptographic operations
    fn sign_envelope(&self, envelope: &mut ScpEnvelope);
    fn verify_envelope(&self, envelope: &ScpEnvelope) -> bool;

    // ... and more
}
```

## Quorum Configuration

Use the `quorum_config` module to set up quorum sets:

```rust
use stellar_core_scp::quorum_config::{testnet_quorum_config, config_to_quorum_set};

// Use predefined testnet config
let config = testnet_quorum_config();
let quorum_set = config_to_quorum_set(&config)?;

// Or create custom configuration
let config = QuorumSetConfig {
    threshold_percent: 67,
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

This section documents the parity between this Rust implementation and the upstream C++ stellar-core SCP implementation (v25).

### Implemented

#### Core Protocol Components

- **SCP Coordinator (`scp.rs` <- `SCP.h/cpp`)**
  - `receiveEnvelope()` - Process incoming SCP envelopes
  - `nominate()` - Submit values for nomination
  - `stopNomination()` - Stop nomination for a slot
  - `updateLocalQuorumSet()` / `getLocalQuorumSet()` - Quorum set management
  - `getLocalNodeID()` - Local node identifier
  - `purgeSlots()` - Memory cleanup for old slots
  - `isValidator()` - Validator status check
  - `isSlotFullyValidated()` - Slot validation status
  - `getKnownSlotsCount()` - Slot count monitoring
  - `processCurrentState()` - Iterate over current envelopes
  - Slot management with automatic cleanup

- **Slot (`slot.rs` <- `Slot.h/cpp`)**
  - `processEnvelope()` - Process envelopes for a specific slot
  - `nominate()` - Nominate values for this slot
  - `stopNomination()` - Stop nomination
  - `bumpState()` - Bump ballot on timeout (via `bump_ballot_on_timeout`)
  - `setFullyValidated()` / `isFullyValidated()` - Validation state
  - `getLatestMessagesSend()` - Get latest messages (via `get_envelopes`)
  - `processCurrentState()` - Envelope iteration
  - `getLatestMessage()` - Get latest envelope from a node
  - `getExternalizingState()` - Get externalized envelopes (partial)
  - Nomination-to-ballot transition logic
  - Force externalization for catchup

- **Nomination Protocol (`nomination.rs` <- `NominationProtocol.h/cpp`)**
  - `nominate()` - Nominate a value
  - `processEnvelope()` - Process nomination envelopes
  - `stopNomination()` - Stop nomination
  - `getLeaders()` - Get current round leaders
  - `getLatestCompositeCandidate()` - Get composite candidate value
  - `processCurrentState()` - Envelope iteration
  - `getLatestMessage()` - Get latest nomination from a node
  - Statement sanity checking (`isSane`)
  - Newer statement detection (`isNewerStatement`)
  - Round leader calculation with priority hashing
  - Value acceptance and ratification (federated voting)
  - Composite candidate generation

- **Ballot Protocol (`ballot.rs` <- `BallotProtocol.h/cpp`)**
  - `processEnvelope()` - Process ballot envelopes
  - `bumpState()` - Bump ballot state
  - `abandonBallot()` - Abandon current ballot
  - Phase transitions (PREPARE -> CONFIRM -> EXTERNALIZE)
  - `attemptAcceptPrepared()` / `setAcceptPrepared()` - Step 1/5 from SCP paper
  - `attemptConfirmPrepared()` / `setConfirmPrepared()` - Step 2/3/8 from SCP paper
  - `attemptAcceptCommit()` / `setAcceptCommit()` - Step 4/6/8 from SCP paper
  - `attemptConfirmCommit()` / `setConfirmCommit()` - Step 7/8 from SCP paper
  - `attemptBump()` - Step 9 from SCP paper
  - Ballot comparison and compatibility functions
  - Statement validation and sanity checks
  - Federated accept/ratify logic
  - Prepare candidate computation
  - Commit boundary computation
  - Extended interval finding
  - `heardFromQuorum` tracking
  - Envelope emission (PREPARE/CONFIRM/EXTERNALIZE)

- **Local Node / Quorum Operations (`quorum.rs` <- `LocalNode.h/cpp`, `QuorumSetUtils.h/cpp`)**
  - `isQuorumSlice()` - Check if nodes satisfy a quorum slice
  - `isQuorum()` - Check if nodes form a quorum
  - `isVBlocking()` / `isBlockingSet()` - Check for blocking sets
  - `findClosestVBlocking()` - Find closest v-blocking set
  - `forAllNodes()` - Iterate over quorum set nodes (via `get_all_nodes`)
  - `isQuorumSetSane()` - Validate quorum set structure
  - `normalizeQSet()` - Normalize quorum set
  - `hashQuorumSet()` - Compute quorum set hash
  - Singleton quorum set creation

- **SCPDriver Trait (`driver.rs` <- `SCPDriver.h/cpp`)**
  - `signEnvelope()` / `verifyEnvelope()` - Envelope cryptography
  - `emitEnvelope()` - Broadcast envelopes
  - `validateValue()` - Value validation with levels (Invalid/MaybeValid/FullyValidated)
  - `extractValidValue()` - Extract valid value from invalid composite
  - `combineCandidates()` - Combine candidate values
  - `getQSet()` / `getQuorumSet()` - Quorum set retrieval
  - `computeHashNode()` - Node priority hash
  - `computeValueHash()` - Value ordering hash
  - `computeTimeout()` - Timeout calculation
  - `valueExternalized()` - Externalization callback
  - `nominatingValue()` - Nomination callback
  - `acceptedBallotPrepared()` - Ballot prepared callback
  - `confirmedBallotPrepared()` - Ballot confirmed prepared callback
  - `acceptedCommit()` - Commit accepted callback
  - `ballotDidHearFromQuorum()` - Quorum heard callback

- **Quorum Configuration (`quorum_config.rs`)**
  - Quorum set configuration from config files
  - Strkey and hex public key parsing
  - Testnet/mainnet validator configurations
  - Configuration validation

- **Error Types (`error.rs`)**
  - `ScpError` for protocol errors

#### Key XDR Types (via stellar-xdr crate)
- `ScpEnvelope`, `ScpStatement`, `ScpBallot`
- `ScpNomination`
- `ScpStatementPrepare`, `ScpStatementConfirm`, `ScpStatementExternalize`
- `ScpQuorumSet`, `NodeId`, `Value`

### Not Yet Implemented (Gaps)

#### SCP Coordinator
- `gotVBlocking()` - Check if v-blocking set heard from (tracked in C++ but not exposed)
- `getCumulativeStatementCount()` - Statement count monitoring
- `getLatestMessagesSend()` - Get latest sent messages for a slot
- `setStateFromEnvelope()` - Rebuild state from envelope (crash recovery)
- `processSlotsAscendingFrom()` / `processSlotsDescendingFrom()` - Slot iteration helpers
- `getLatestMessage()` - Get latest message from any slot for a node
- `isNewerNominationOrBallotSt()` - Statement comparison (present but not exposed)
- `getExternalizingState()` - Get externalizing state for a slot
- Detailed slot info JSON methods (`getJsonInfo`, `getJsonQuorumInfo`)
- String formatting helpers (`getValueString`, `ballotToStr`, `envToStr`)
- `getMissingNodes()` - Get nodes missing from consensus
- `QuorumInfoNodeState` enum and related state calculation

#### Slot
- `abandonBallot()` - Direct ballot abandonment (available via ballot protocol)
- `getNominationLeaders()` - Get nomination round leaders
- `recordStatement()` - Historical statement recording
- `getStatementCount()` - Statement count
- Statement history tracking (`HistoricalStatement` struct)
- `getJsonInfo()` / `getJsonQuorumInfo()` - JSON status info
- `getState()` - Node state calculation for reporting
- `getCompanionQuorumSetHashFromStatement()` - Extract quorum set hash
- `getStatementValues()` - Extract values from statement
- `createEnvelope()` - Envelope creation helper

#### Nomination Protocol
- `setStateFromEnvelope()` - State recovery from envelope
- `getJsonInfo()` - JSON status info
- `getState()` - Node state for reporting
- Timer expiration count tracking (`mTimerExpCount` - partially implemented)

#### Ballot Protocol
- `ballotProtocolTimerExpired()` - Timer expiration handler (timeout handled differently)
- `bumpState(value, counter)` - Bump to specific counter
- `setStateFromEnvelope()` - State recovery from envelope
- `getJsonInfo()` / `getJsonQuorumInfo()` - JSON status info
- `getState()` - Node state for reporting
- `checkInvariants()` - Internal state validation
- `getLocalState()` - State string for logging
- Ballot timer start/stop methods
- `SCPBallotWrapper` - Value wrapper optimization

#### Local Node
- Full `LocalNode` class - Rust uses simpler quorum set storage in SCP struct
- `getSingletonQSet()` - Singleton quorum set caching
- `toJson()` / `fromJson()` - JSON serialization/deserialization for quorum sets
- `to_string()` - String representation

#### SCPDriver
- `wrapEnvelope()` - Envelope wrapper factory
- `wrapValue()` - Value wrapper factory
- `getValueString()` - Value debug string (has default in C++)
- `toStrKey()` / `toShortString()` - Node ID formatting
- `getHashOf()` - Generic hash computation
- `getNodeWeight()` - Node weight calculation (has default in C++)
- `setupTimer()` / `stopTimer()` - Timer management (handled externally)
- `updatedCandidateValue()` - Candidate update callback
- `startedBallotProtocol()` - Ballot protocol start callback

#### Utilities
- `ValueWrapper` / `SCPEnvelopeWrapper` - Reference-counted wrappers for memory optimization
- `WrappedValuePtrComparator` - Value comparison for sets
- Test utilities from `SCPUnitTests.cpp`, `SCPTests.cpp`, `QuorumSetTests.cpp`

### Implementation Notes

#### Architectural Differences

1. **Memory Management**
   - C++ uses `shared_ptr` wrappers (`ValueWrapper`, `SCPEnvelopeWrapper`) for efficient memory sharing
   - Rust uses owned values and cloning, relying on the compiler for optimization
   - The `ValueWrapperPtrSet` pattern from C++ is replaced with `Vec<Value>` in Rust

2. **Slot Reference**
   - C++ protocols hold references back to `Slot` and access `SCP` through it
   - Rust protocols are owned by `Slot` and receive driver/context via parameters

3. **LocalNode**
   - C++ has a separate `LocalNode` class managing node identity and quorum set
   - Rust embeds this directly in the `SCP` struct

4. **Timer Management**
   - C++ uses `setupTimer()`/`stopTimer()` callbacks in the driver
   - Rust exposes `get_nomination_timeout()`/`get_ballot_timeout()` and expects external timer management

5. **JSON Serialization**
   - C++ has extensive JSON output for debugging/monitoring
   - Rust relies on `Debug` trait and structured logging via `tracing`

6. **State Recovery**
   - C++ supports `setStateFromEnvelope()` for crash recovery
   - Rust currently lacks this feature; catchup uses `force_externalize()` instead

7. **Thread Safety**
   - C++ relies on external synchronization
   - Rust uses `RwLock` for slot map and `Arc` for driver sharing

#### Design Decisions

- **Testability**: Protocol state machines are more isolated in Rust, making unit testing easier
- **Type Safety**: Rust's type system provides compile-time guarantees the C++ implementation achieves through runtime checks
- **Async Compatibility**: Rust implementation is designed to work with async runtimes (tokio)
- **Error Handling**: Uses `Result`/`Option` types instead of exceptions

#### Test Coverage

The Rust implementation includes unit tests for:
- Quorum set operations and sanity checks
- Nomination protocol flow
- Ballot protocol state transitions
- Envelope state management
- Value validation levels

Missing test coverage compared to C++:
- Full integration tests (`SCPTests.cpp`)
- Fuzzing and stress tests
- Multi-node simulation tests
