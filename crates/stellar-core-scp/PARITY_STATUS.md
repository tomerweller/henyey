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
