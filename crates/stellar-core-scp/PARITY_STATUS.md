# C++ Parity Status

This document tracks the parity between the Rust `stellar-core-scp` crate and the upstream C++ stellar-core SCP implementation (v25.x).

## Summary

**Overall Parity: ~95%**

The Rust implementation provides full functional parity with the C++ SCP implementation for consensus operations. All core SCP protocol semantics are implemented correctly. The remaining gaps are primarily:

1. Architectural differences (Rust ownership model vs C++ shared pointers)
2. Some debugging/monitoring features with different approaches
3. Test coverage for edge cases from upstream test suites

## File Mapping

| C++ File | Rust File | Parity |
|----------|-----------|--------|
| `SCP.h/cpp` | `scp.rs` | Full |
| `Slot.h/cpp` | `slot.rs` | Full |
| `NominationProtocol.h/cpp` | `nomination.rs` | Full |
| `BallotProtocol.h/cpp` | `ballot.rs` | Full |
| `LocalNode.h/cpp` | `quorum.rs` (partial), `scp.rs` (embedded) | Full |
| `QuorumSetUtils.h/cpp` | `quorum.rs` | Full |
| `SCPDriver.h/cpp` | `driver.rs` | Full |
| `test/SCPTests.cpp` | `tests/multi_node_simulation.rs` | Partial |
| `test/SCPUnitTests.cpp` | Unit tests in source files | Partial |
| `test/QuorumSetTests.cpp` | `tests/quorum_intersection_json.rs` | Partial |

## Implemented Features

### SCP Coordinator (`scp.rs` <- `SCP.h/cpp`)

| C++ Method | Rust Method | Status |
|------------|-------------|--------|
| `receiveEnvelope()` | `receive_envelope()` | Implemented |
| `nominate()` | `nominate()` | Implemented |
| `stopNomination()` | `stop_nomination()` | Implemented |
| `updateLocalQuorumSet()` | `set_local_quorum_set()` | Implemented |
| `getLocalQuorumSet()` | `local_quorum_set()` | Implemented |
| `getLocalNodeID()` | `local_node_id()` | Implemented |
| `getLocalNode()` | N/A (embedded in SCP struct) | Architectural difference |
| `purgeSlots()` | `purge_slots()` | Implemented |
| `isValidator()` | `is_validator()` | Implemented |
| `isSlotFullyValidated()` | `is_slot_fully_validated()` | Implemented |
| `gotVBlocking()` | `got_v_blocking()` | Implemented |
| `getKnownSlotsCount()` | `slot_count()` | Implemented |
| `getCumulativeStatemtCount()` | `get_cumulative_statement_count()` | Implemented |
| `getLatestMessagesSend()` | `get_latest_messages_send()` | Implemented |
| `setStateFromEnvelope()` | `set_state_from_envelope()` | Implemented |
| `empty()` | `empty()` | Implemented |
| `processCurrentState()` | Via `get_scp_state()` | Implemented |
| `processSlotsAscendingFrom()` | `process_slots_ascending_from()` | Implemented |
| `processSlotsDescendingFrom()` | `process_slots_descending_from()` | Implemented |
| `getLatestMessage()` | `get_latest_message()` | Implemented |
| `isNewerNominationOrBallotSt()` | `is_newer_statement()` | Implemented |
| `getExternalizingState()` | `get_externalizing_state()` | Implemented |
| `getHighestKnownSlotIndex()` | `get_highest_known_slot()` | Implemented |
| `getDriver()` | `driver()` | Implemented |
| `getJsonInfo()` | `get_info()`, `get_all_slot_info()` | Implemented (serde) |
| `getJsonQuorumInfo()` | `get_quorum_info()`, `get_quorum_info_for_node()` | Implemented |
| `getMissingNodes()` | `get_missing_nodes()` | Implemented |
| `getValueString()` | Via `SCPDriver::get_value_string()` | Implemented |
| `ballotToStr()` | `ballot_to_str()` (in lib.rs) | Implemented |
| `envToStr()` | `envelope_to_str()` (in lib.rs) | Implemented |
| `getSlot()` | Internal slot management | Implemented |

### Slot (`slot.rs` <- `Slot.h/cpp`)

| C++ Method | Rust Method | Status |
|------------|-------------|--------|
| `processEnvelope()` | `process_envelope()` | Implemented |
| `nominate()` | `nominate()` | Implemented |
| `stopNomination()` | `stop_nomination()` | Implemented |
| `bumpState()` | `bump_state()`, `bump_ballot_on_timeout()` | Implemented |
| `abandonBallot()` | `abandon_ballot()` | Implemented |
| `setFullyValidated()` | `set_fully_validated()` | Implemented |
| `isFullyValidated()` | `is_fully_validated()` | Implemented |
| `getLatestMessagesSend()` | `get_latest_messages_send()` | Implemented |
| `processCurrentState()` | `process_current_state()` | Implemented |
| `getLatestMessage()` | `get_latest_envelope()` | Implemented |
| `getExternalizingState()` | `get_externalizing_state()` | Implemented |
| `setStateFromEnvelope()` | `set_state_from_envelope()` | Implemented |
| `getNominationLeaders()` | `get_nomination_leaders()` | Implemented |
| `recordStatement()` | `record_statement()` | Implemented |
| `getStatementCount()` | `get_statement_count()` | Implemented |
| `getJsonInfo()` | `get_info()` | Implemented |
| `getJsonQuorumInfo()` | `get_quorum_info()` | Implemented |
| `getState()` | `get_node_state()`, `get_all_node_states()` | Implemented |
| `gotVBlocking()` | Via SCP-level check | Implemented |
| `getLatestCompositeCandidate()` | `get_latest_composite_candidate()` | Implemented |
| `getCompanionQuorumSetHashFromStatement()` | `get_companion_quorum_set_hash()` (static) | Implemented |
| `getStatementValues()` | `get_statement_values()` (static) | Implemented |
| `getQuorumSetFromStatement()` | Via driver callback | Implemented |
| `createEnvelope()` | Internal envelope creation | Implemented |
| `federatedAccept()` | Internal federation logic | Implemented |
| `federatedRatify()` | Internal federation logic | Implemented |
| `getLocalNode()` | Via SCP reference | Implemented |
| `maybeSetGotVBlocking()` | Internal v-blocking tracking | Implemented |
| Force externalization (catchup) | `force_externalize()` | Implemented |
| Timer IDs (NOMINATION_TIMER, BALLOT_PROTOCOL_TIMER) | `SCPTimerType` enum | Implemented |

### Nomination Protocol (`nomination.rs` <- `NominationProtocol.h/cpp`)

| C++ Method | Rust Method | Status |
|------------|-------------|--------|
| `nominate()` | `nominate()` | Implemented |
| `processEnvelope()` | `process_envelope()` | Implemented |
| `stopNomination()` | `stop()` | Implemented |
| `getLeaders()` | `get_round_leaders()` | Implemented |
| `getLatestCompositeCandidate()` | `latest_composite()` | Implemented |
| `processCurrentState()` | `process_current_state()` | Implemented |
| `getLatestMessage()` | `get_latest_nomination()` | Implemented |
| `getLastMessageSend()` | `get_last_message_send()` | Implemented |
| `setStateFromEnvelope()` | `set_state_from_envelope()` | Implemented |
| `getJsonInfo()` | `get_info()` | Implemented |
| `getState()` | `get_node_state()` | Implemented |
| `isNewerStatement()` (static) | `is_newer_statement()` | Implemented |
| `isSane()` | `is_sane_statement()` | Implemented |
| `validateValue()` | Via driver callback | Implemented |
| `extractValidValue()` | Via driver callback | Implemented |
| `recordEnvelope()` | Internal envelope recording | Implemented |
| `emitNomination()` | `emit_nomination()` | Implemented |
| `updateRoundLeaders()` | `update_round_leaders()` | Implemented |
| `hashNode()` | `hash_node()` via driver | Implemented |
| `hashValue()` | `hash_value()` via driver | Implemented |
| `getNodePriority()` | `get_node_priority()` | Implemented |
| `getNewValueFromNomination()` | `get_new_value_from_nomination()` | Implemented |
| Round management | `round()`, round progression | Implemented |
| Timer expiration tracking | `timer_exp_count()` | Implemented |

### Ballot Protocol (`ballot.rs` <- `BallotProtocol.h/cpp`)

| C++ Method | Rust Method | Status |
|------------|-------------|--------|
| `processEnvelope()` | `process_envelope()` | Implemented |
| `ballotProtocolTimerExpired()` | `bump_on_timeout()` | Implemented |
| `abandonBallot()` | `abandon_ballot()` | Implemented |
| `bumpState()` (value, force) | `bump()` | Implemented |
| `bumpState()` (value, counter) | `bump_to_counter()` | Implemented |
| `getJsonInfo()` | `get_info()` | Implemented |
| `getState()` | `get_node_state()` | Implemented |
| `getJsonQuorumInfo()` | Via Slot | Implemented |
| `getCompanionQuorumSetHashFromStatement()` | `get_companion_quorum_set_hash()` | Implemented |
| `getWorkingBallot()` | `get_working_ballot()` (public function) | Implemented |
| `getLastMessageSend()` | `get_last_envelope()` | Implemented |
| `setStateFromEnvelope()` | `set_state_from_envelope()` | Implemented |
| `processCurrentState()` | `process_current_state()` | Implemented |
| `getLatestMessage()` | `get_latest_envelope()` | Implemented |
| `getExternalizingState()` | `get_externalizing_state()` | Implemented |
| `getStatementValues()` | Via internal logic | Implemented |
| `isNewerStatement()` (static) | `is_newer_statement()` | Implemented |
| `advanceSlot()` | `advance_slot()` | Implemented |
| `validateValues()` | Via driver callback | Implemented |
| `sendLatestEnvelope()` | `send_latest_envelope()` | Implemented |
| `attemptAcceptPrepared()` | `attempt_accept_prepared()` | Implemented |
| `setAcceptPrepared()` | `set_accept_prepared()` | Implemented |
| `attemptConfirmPrepared()` | `attempt_confirm_prepared()` | Implemented |
| `setConfirmPrepared()` | `set_confirm_prepared()` | Implemented |
| `attemptAcceptCommit()` | `attempt_accept_commit()` | Implemented |
| `setAcceptCommit()` | `set_accept_commit()` | Implemented |
| `attemptConfirmCommit()` | `attempt_confirm_commit()` | Implemented |
| `setConfirmCommit()` | `set_confirm_commit()` | Implemented |
| `attemptBump()` | `attempt_bump()` | Implemented |
| `getPrepareCandidates()` | `get_prepare_candidates()` | Implemented |
| `updateCurrentIfNeeded()` | `update_current_if_needed()` | Implemented |
| `findExtendedInterval()` | `find_extended_interval()` | Implemented |
| `getCommitBoundariesFromStatements()` | `get_commit_boundaries()` | Implemented |
| `hasPreparedBallot()` | `has_prepared_ballot()` | Implemented |
| `commitPredicate()` | `commit_predicate()` | Implemented |
| `setPrepared()` | `set_prepared()` | Implemented |
| `compareBallots()` | `ballot_compare()` | Implemented |
| `areBallotsCompatible()` | `ballot_compatible()` | Implemented |
| `areBallotsLessAndIncompatible()` | `ballot_less_and_incompatible()` | Implemented |
| `areBallotsLessAndCompatible()` | `ballot_less_and_compatible()` | Implemented |
| `isNewerStatement()` (instance) | `is_newer_statement()` | Implemented |
| `isStatementSane()` | `is_statement_sane()` | Implemented |
| `recordEnvelope()` | `record_envelope()` | Implemented |
| `bumpToBallot()` | `bump_to_ballot()` | Implemented |
| `updateCurrentValue()` | `update_current_value()` | Implemented |
| `emitCurrentStateStatement()` | `emit_current_state_statement()` | Implemented |
| `checkInvariants()` | `check_invariants()` | Implemented |
| `createStatement()` | `create_statement()` | Implemented |
| `getLocalState()` | `get_local_state()` | Implemented |
| `federatedAccept()` | Via Slot | Implemented |
| `federatedRatify()` | Via Slot | Implemented |
| `startBallotProtocolTimer()` | Via timer callbacks | Implemented |
| `stopBallotProtocolTimer()` | Via timer callbacks | Implemented |
| `checkHeardFromQuorum()` | `check_heard_from_quorum()` | Implemented |
| Phase transitions (PREPARE->CONFIRM->EXTERNALIZE) | `BallotPhase` enum | Implemented |
| heardFromQuorum tracking | `heard_from_quorum()` | Implemented |

### LocalNode / Quorum Operations (`quorum.rs` <- `LocalNode.h/cpp`, `QuorumSetUtils.h/cpp`)

| C++ Method | Rust Method | Status |
|------------|-------------|--------|
| `forAllNodes()` | `get_all_nodes()` | Implemented |
| `isQuorumSlice()` | `is_quorum_slice()` | Implemented |
| `isQuorum()` | `is_quorum()` | Implemented |
| `isVBlocking()` | `is_v_blocking()`, `is_blocking_set()` | Implemented |
| `findClosestVBlocking()` | `find_closest_v_blocking()` | Implemented |
| `getSingletonQSet()` | `singleton_quorum_set()` | Implemented |
| `buildSingletonQSet()` | `singleton_quorum_set()` | Implemented |
| `isQuorumSetSane()` | `is_quorum_set_sane()` | Implemented |
| `normalizeQSet()` | `normalize_quorum_set()` | Implemented |
| `hashQuorumSet()` | `hash_quorum_set()` | Implemented |
| `toJson()` | `QuorumSetJson::from_xdr()` | Implemented |
| `fromJson()` | `QuorumSetJson::to_xdr()` | Implemented |
| `to_string()` | Via Debug trait | Implemented |
| Node ID management | Embedded in SCP struct | Implemented |
| Quorum set updates | `set_local_quorum_set()` | Implemented |
| Singleton quorum set caching | `SingletonQuorumSetCache` | Implemented |
| `MAXIMUM_QUORUM_NESTING_LEVEL` | Constant | Implemented |
| `MAXIMUM_QUORUM_NODES` | Constant | Implemented |

### SCPDriver Trait (`driver.rs` <- `SCPDriver.h/cpp`)

| C++ Method | Rust Method | Status |
|------------|-------------|--------|
| `signEnvelope()` | `sign_envelope()` | Implemented |
| `wrapEnvelope()` | N/A (Rust ownership) | Not needed |
| `wrapValue()` | N/A (Rust ownership) | Not needed |
| `getQSet()` | `get_quorum_set_by_hash()` | Implemented |
| `emitEnvelope()` | `emit_envelope()` | Implemented |
| `validateValue()` | `validate_value()` | Implemented |
| `extractValidValue()` | `extract_valid_value()` | Implemented |
| `getValueString()` | `get_value_string()` | Implemented |
| `toStrKey()` | Via `node_id_to_strkey()` | Implemented |
| `toShortString()` | `node_id_to_short_string()` | Implemented |
| `getHashOf()` | `get_hash_of()` | Implemented |
| `computeHashNode()` | `compute_hash_node()` | Implemented |
| `computeValueHash()` | `compute_value_hash()` | Implemented |
| `combineCandidates()` | `combine_candidates()` | Implemented |
| `setupTimer()` | `setup_timer()` | Implemented |
| `stopTimer()` | `stop_timer()` | Implemented |
| `computeTimeout()` | `compute_timeout()` | Implemented |
| `getNodeWeight()` | `get_node_weight()` | Implemented |
| `valueExternalized()` | `value_externalized()` | Implemented |
| `nominatingValue()` | `nominating_value()` | Implemented |
| `updatedCandidateValue()` | `updated_candidate_value()` | Implemented |
| `startedBallotProtocol()` | `started_ballot_protocol()` | Implemented |
| `acceptedBallotPrepared()` | `accepted_ballot_prepared()` | Implemented |
| `confirmedBallotPrepared()` | `confirmed_ballot_prepared()` | Implemented |
| `acceptedCommit()` | `accepted_commit()` | Implemented |
| `ballotDidHearFromQuorum()` | `ballot_did_hear_from_quorum()` | Implemented |
| `ValidationLevel` enum | `ValidationLevel` enum | Implemented |
| Timer type constants | `SCPTimerType` enum | Implemented |

## Not Implemented (Intentional Architectural Differences)

### Memory Management Wrappers

The following C++ patterns are not implemented as they are unnecessary in Rust:

| C++ Pattern | Reason for Omission |
|-------------|---------------------|
| `ValueWrapper` | Rust's ownership model handles value lifetime automatically |
| `SCPEnvelopeWrapper` | Rust's ownership model handles envelope lifetime automatically |
| `ValueWrapperPtr` (shared_ptr) | Rust uses owned `Value` types with cloning |
| `SCPEnvelopeWrapperPtr` (shared_ptr) | Rust uses owned `ScpEnvelope` types with cloning |
| `WrappedValuePtrComparator` | Rust uses standard `Ord` trait implementations |
| `ValueWrapperPtrSet` | Rust uses `Vec<Value>` with standard sorting |
| `SCPBallotWrapper` | Rust uses owned `ScpBallot` directly |
| `wrapEnvelope()` factory | Not needed - envelopes are constructed directly |
| `wrapValue()` factory | Not needed - values are constructed directly |

### Class Structure Differences

| C++ Pattern | Rust Approach |
|-------------|---------------|
| `LocalNode` class | Embedded directly in `SCP` struct; quorum operations in `quorum.rs` |
| `Slot` holding reference to `SCP` | `Slot` receives driver via parameters; owned by `SCP` |
| `NominationProtocol` holding `Slot&` | Receives context via method parameters |
| `BallotProtocol` holding `Slot&` | Receives context via method parameters |

## Test Coverage Comparison

### Unit Tests

| C++ Test File | Rust Coverage | Notes |
|---------------|---------------|-------|
| `QuorumSetTests.cpp` | Partial | Core quorum logic tested in `quorum.rs` |
| `SCPUnitTests.cpp` | Partial | Protocol state machine tests in source files |

### Integration Tests

| C++ Test File | Rust Coverage | Notes |
|---------------|---------------|-------|
| `SCPTests.cpp` | Good | `multi_node_simulation.rs` covers similar scenarios |

### Rust Test Categories

The Rust implementation includes comprehensive tests:

**Unit Tests (in source files):**
- Quorum set operations and sanity checks
- Nomination protocol flow
- Ballot protocol state transitions
- Envelope state management
- Value validation levels
- State recovery from envelopes
- Ballot bumping and abandonment
- Invariant checking
- JSON info serialization/deserialization
- QuorumSetJson XDR roundtrip
- Timer callback types

**Integration Tests (`tests/multi_node_simulation.rs`):**
- Basic 3-node consensus
- Force externalization (catchup)
- Slot purging
- Envelope processing across phases
- V-blocking set detection
- Missing nodes detection
- State recovery from envelopes
- Ballot abandonment
- Slot iteration (ascending/descending)
- Statement counting
- Quorum slice verification
- Complete consensus flow
- Ballot phase progression
- Multiple slot handling
- Crash recovery scenarios
- Watcher node behavior
- Stress tests (100 slots, 10+ nodes)
- Byzantine failure simulations

**Quorum Tests (`tests/quorum_intersection_json.rs`):**
- JSON-based quorum set loading
- Quorum intersection verification

## Behavioral Parity Notes

### Determinism

The Rust implementation maintains strict determinism parity with C++:
- Hash computations use identical algorithms
- Value and ballot ordering follows C++ semantics
- Quorum evaluation produces identical results

### Edge Cases

All major edge cases from the C++ implementation are handled:
- Empty quorum sets (threshold 0)
- Singleton quorum sets
- Maximum nesting depth (4 levels)
- Maximum node count (1000 nodes)
- Equivocation detection
- Stale message handling

### Thread Safety

| Aspect | C++ Approach | Rust Approach |
|--------|--------------|---------------|
| Slot map | External synchronization | `RwLock<HashMap>` |
| Driver access | Reference | `Arc<D>` |
| State mutation | Mutable methods | Interior mutability |

## Known Differences

### JSON Output Format

The Rust implementation uses `serde` for JSON serialization, producing slightly different formatting than the C++ `jsoncpp` library. The semantic content is identical.

### Error Handling

| C++ Approach | Rust Approach |
|--------------|---------------|
| Assertions (`releaseAssert`) | `Result` types and `Option` |
| Exceptions (rare) | `Result` types |
| Return codes | Enum variants (`EnvelopeState`) |

### Logging

| C++ Approach | Rust Approach |
|--------------|---------------|
| `CLOG_*` macros | `tracing` crate |
| String formatting | Structured logging |

## Migration Notes

When porting code that uses the C++ SCP implementation:

1. Replace `shared_ptr<Value>` with owned `Value`
2. Replace `SCPEnvelopeWrapperPtr` with owned `ScpEnvelope`
3. Implement the `SCPDriver` trait instead of subclassing
4. Use `Arc<D>` for the driver instead of references
5. Handle `Result` return types for fallible operations

## Verification Status

- [x] All core consensus algorithms implemented
- [x] Quorum set operations verified against C++
- [x] Ballot protocol state machine complete
- [x] Nomination protocol complete
- [x] Driver callbacks implemented
- [x] Timer support added
- [x] State recovery (crash recovery) implemented
- [x] JSON info reporting implemented
- [x] Multi-node simulation tests passing
- [x] Stress tests passing
- [x] Byzantine failure handling tests passing
