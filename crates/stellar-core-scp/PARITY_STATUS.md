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
  - `setStateFromEnvelope()` - Rebuild state from envelope (crash recovery)
  - `abandonBallot()` - Abandon ballot for a slot
  - `bumpState()` - Bump ballot to specific counter
  - `gotVBlocking()` - Check if v-blocking set heard from
  - `getCumulativeStatementCount()` - Statement count monitoring
  - `getMissingNodes()` - Get nodes missing from consensus
  - `isNewerStatement()` - Statement comparison
  - `getInfo()` / `getQuorumInfo()` - JSON-serializable slot/quorum info
  - `getAllSlotInfo()` - Get info for all active slots
  - `empty()` - Check if SCP has any active slots
  - `getHighestKnownSlotIndex()` - Get highest known slot index (via `get_highest_known_slot`)
  - `getDriver()` - Access to the SCP driver (via `driver()`)
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
  - `setStateFromEnvelope()` - Rebuild state from envelope (crash recovery)
  - `abandonBallot()` - Direct ballot abandonment
  - `bump_state()` - Bump ballot to specific counter
  - `nomination_mut()` / `ballot_mut()` - Mutable protocol access
  - `getNominationLeaders()` - Get nomination round leaders
  - `recordStatement()` - Historical statement recording
  - `getStatementCount()` - Statement count
  - `get_node_state()` - Get node state for quorum reporting
  - `get_state_string()` - State summary string for debugging
  - `get_all_node_states()` - Get states of all quorum nodes
  - `get_info()` - JSON-serializable slot information
  - `get_quorum_info()` - JSON-serializable quorum information
  - `getCompanionQuorumSetHashFromStatement()` - Extract quorum set hash from statement (static)
  - `getStatementValues()` - Extract values from statement (static)
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
  - `getLastMessageSend()` - Get last envelope actually emitted to network
  - `setStateFromEnvelope()` - State recovery from envelope (crash recovery)
  - `candidates()` - Get confirmed candidates
  - `get_node_state()` - Get node state for quorum reporting
  - `get_state_string()` - State summary string for debugging
  - `get_info()` - JSON-serializable nomination information
  - Statement sanity checking (`isSane`)
  - Newer statement detection (`isNewerStatement`)
  - Round leader calculation with priority hashing
  - Value acceptance and ratification (federated voting)
  - Composite candidate generation

- **Ballot Protocol (`ballot.rs` <- `BallotProtocol.h/cpp`)**
  - `processEnvelope()` - Process ballot envelopes
  - `bumpState()` - Bump ballot state
  - `bump_state(value, counter)` - Bump to specific counter
  - `abandonBallot()` - Abandon current ballot
  - `setStateFromEnvelope()` - State recovery from envelope (crash recovery)
  - `checkInvariants()` - Internal state validation
  - `getLocalState()` - State string for logging
  - `latest_envelopes()` - Access latest envelopes from each node
  - `get_node_count()` - Count of nodes heard from
  - `get_node_state()` - Get node state for quorum reporting
  - `get_state_string()` - State summary string for debugging
  - `get_info()` - JSON-serializable ballot information
  - `getWorkingBallot()` - Extract working ballot from statement (via `get_working_ballot`)
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
  - `singleton_quorum_set()` - Create singleton quorum set
  - `SingletonQuorumSetCache` - Cached singleton quorum set creation (`getSingletonQSet()`)
  - `MAXIMUM_QUORUM_NESTING_LEVEL` - Maximum quorum set nesting depth constant
  - `MAXIMUM_QUORUM_NODES` - Maximum nodes in quorum set constant

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
  - `startedBallotProtocol()` - Ballot protocol start callback
  - `updatedCandidateValue()` - Candidate update callback
  - `getNodeWeight()` - Node weight calculation (default returns 1.0)
  - `getValueString()` - Value debug string
  - `getHashOf()` - Generic hash computation
  - `setupTimer()` - Request timer setup callback
  - `stopTimer()` - Request timer cancellation callback
  - `timerExpired()` - Timer expiration notification
  - `SCPTimerType` enum - Nomination vs Ballot timer types

- **Quorum Configuration (`quorum_config.rs`)**
  - Quorum set configuration from config files
  - Strkey and hex public key parsing
  - Testnet/mainnet validator configurations
  - Configuration validation

- **Error Types (`error.rs`)**
  - `ScpError` for protocol errors

- **State Reporting and Debugging (`lib.rs`)**
  - `QuorumInfoNodeState` enum - Node state for quorum info reporting
  - `HistoricalStatement` struct - Statement history tracking
  - `SlotInfo` struct - JSON-serializable slot information
  - `NominationInfo` struct - JSON-serializable nomination information
  - `BallotInfo` struct - JSON-serializable ballot information
  - `QuorumInfo` struct - JSON-serializable quorum information
  - `NodeInfo` struct - JSON-serializable node information
  - `BallotValue` / `CommitBounds` structs - JSON ballot details
  - `QuorumSetJson` struct - JSON-serializable quorum set (`toJson()`/`fromJson()`)
  - `QuorumSetJson::from_xdr()` / `to_xdr()` - XDR <-> JSON conversion
  - `node_id_to_short_string()` - Node ID formatting
  - `ballot_to_str()` - Ballot formatting
  - `value_to_str()` - Value formatting
  - `envelope_to_str()` - Envelope formatting
  - `is_newer_nomination_or_ballot_st()` - Statement comparison

#### Key XDR Types (via stellar-xdr crate)

- `ScpEnvelope`, `ScpStatement`, `ScpBallot`
- `ScpNomination`
- `ScpStatementPrepare`, `ScpStatementConfirm`, `ScpStatementExternalize`
- `ScpQuorumSet`, `NodeId`, `Value`

### Not Yet Implemented (Intentional Architectural Differences)

#### Ballot Protocol

- `SCPBallotWrapper` - Value wrapper optimization (not needed in Rust due to ownership model)

#### Local Node

- Full `LocalNode` class - Rust uses simpler quorum set storage in SCP struct

#### SCPDriver

- `wrapEnvelope()` / `wrapValue()` - Envelope/value wrapper factories (not needed in Rust)

#### Utilities

- `ValueWrapper` / `SCPEnvelopeWrapper` - Reference-counted wrappers (Rust uses owned values)
- `WrappedValuePtrComparator` - Value comparison for sets (Rust uses standard Ord trait)
- Full port of `SCPUnitTests.cpp`, `SCPTests.cpp`, `QuorumSetTests.cpp` (partial coverage exists)

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
   - Rust now also supports `setup_timer()`/`stop_timer()`/`timer_expired()` callbacks with `SCPTimerType` enum
   - Rust additionally exposes `get_nomination_timeout()`/`get_ballot_timeout()` for external timer management
   - Both approaches are supported: callback-based or polling-based timer management

5. **JSON Serialization**
   - C++ has extensive JSON output for debugging/monitoring
   - Rust relies on `Debug` trait and structured logging via `tracing`

6. **State Recovery**
   - C++ supports `setStateFromEnvelope()` for crash recovery
   - Rust now implements `set_state_from_envelope()` at SCP, Slot, Nomination, and Ballot levels
   - Catchup can also use `force_externalize()` for simpler scenarios

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
- State recovery from envelopes (`set_state_from_envelope`)
- Ballot bumping to specific counters (`bump_state`)
- Ballot abandonment (`abandon_ballot`)
- Invariant checking (`check_invariants`)
- Local state formatting (`get_local_state`)
- V-blocking set detection (`got_v_blocking`)
- Statement count monitoring (`get_cumulative_statement_count`)
- Missing nodes detection (`get_missing_nodes`)
- Statement comparison (`is_newer_statement`)
- Singleton quorum set creation and caching
- Thread-safe singleton quorum set cache
- JSON info serialization/deserialization for all info types
- Slot and quorum info generation
- QuorumSetJson serialization and XDR roundtrip
- Nested quorum set operations
- Full quorum verification with asymmetric trust
- Blocking set detection with nested sets
- Hash determinism verification
- Normalization preserves semantics
- Timer callback types and integration
- SCP empty check and highest known slot
- Driver access and slot tracking
- Working ballot extraction from statements

Integration tests for:
- Multi-node simulation (`tests/multi_node_simulation.rs`)
  - Basic 3-node consensus setup
  - All nodes nominating same value
  - Force externalization (catchup simulation)
  - Receiving externalize envelopes
  - Slot purging
  - Nomination/Prepare/Confirm/Externalize envelope processing
  - V-blocking set detection
  - Missing nodes detection
  - Slot state querying
  - JSON info serialization
  - Quorum info generation
  - State recovery from envelopes
  - Ballot abandonment
  - Ascending/descending slot iteration
  - Cumulative statement counting
  - Quorum slice verification
- Full protocol integration tests (`tests/multi_node_simulation.rs`)
  - Complete consensus flow via externalize messages (3-node network)
  - Ballot PREPARE phase progression
  - Ballot CONFIRM phase processing
  - Nodes heard-from tracking
  - Multiple slots reaching consensus independently
  - Out-of-order slot externalization
  - Ballot timeout bumping
  - Crash recovery from nomination statements
  - Crash recovery from prepare statements
  - Crash recovery from confirm statements
  - Watcher node behavior (no message emission)
  - Watcher node externalization tracking
  - get_externalizing_state envelope retrieval
  - get_latest_messages_send for syncing
  - get_scp_state for peer synchronization
- Quorum intersection tests (`tests/quorum_intersection_json.rs`)
  - JSON-based quorum set loading
  - Quorum intersection verification
  - Quorum slice consistency
- Stress tests (`tests/multi_node_simulation.rs`)
  - Many slots externalized rapidly (100 slots)
  - Many envelopes for same slot (10 nodes, 6-of-10 quorum)
  - Rapid slot creation and purging (slot churn)
  - Large quorum set (20 nodes, 14-of-20 quorum)
  - Interleaved/concurrent slot operations
- Byzantine failure simulation tests (`tests/multi_node_simulation.rs`)
  - Duplicate envelope handling
  - Conflicting values from same node (equivocation)
  - Unknown node messages (not in quorum set)
  - Minority nodes with different values
  - Stale ballot counter handling
  - Partial quorum doesn't externalize
  - Out-of-order message processing
  - Node restart recovery

Test coverage compared to C++:
- All major functionality covered
- Comprehensive multi-node simulation tests
- Stress tests for high-load scenarios
- Byzantine failure simulation tests
