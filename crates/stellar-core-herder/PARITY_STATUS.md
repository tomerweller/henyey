## C++ Parity Status

This section documents the parity between this Rust crate and the upstream C++ stellar-core herder implementation (v25).

### Implemented

#### Core Herder (`herder.rs` -> `Herder.h`, `HerderImpl.h/cpp`)
- [x] State machine (Booting, Syncing, Tracking)
- [x] `receive_scp_envelope()` - SCP envelope processing with signature verification
- [x] `receive_transaction()` - Transaction queue integration
- [x] `bootstrap()` - Transition to tracking state after catchup
- [x] `trigger_next_ledger()` - Validator consensus triggering
- [x] EXTERNALIZE fast-forward with security checks (quorum membership, slot distance)
- [x] Tracking slot management
- [x] `check_ledger_close()` - Ledger close readiness check
- [x] `ledger_closed()` - Post-close cleanup
- [x] Observer mode (non-validator) support
- [x] Validator mode with secret key signing
- [x] `get_scp_state()` - SCP state for peer requests
- [x] Quorum set storage and lookup
- [x] Pending tx set request tracking
- [x] `get_min_ledger_seq_to_ask_peers()` - Minimum ledger for peer requests
- [x] `heard_from_quorum()` / `is_v_blocking()` checks
- [x] `handle_nomination_timeout()` / `handle_ballot_timeout()` - Timeout handling

#### SCP State Persistence (`persistence.rs` -> `HerderPersistence.h/cpp`)
- [x] `PersistedSlotState` - Serializable SCP state for a slot
- [x] `ScpStatePersistence` trait - Storage backend abstraction
- [x] `InMemoryScpPersistence` - In-memory storage for testing
- [x] `ScpPersistenceManager` - Persistence coordinator
- [x] `persist_scp_state()` - Save SCP state with envelopes, tx sets, quorum sets
- [x] `restore_scp_state()` - Load persisted state for recovery
- [x] `cleanup()` - Remove old persisted state
- [x] `get_tx_set_hashes()` - Extract tx set hashes from envelopes
- [x] `get_quorum_set_hash()` - Extract quorum set hash from statements
- [x] JSON/base64 serialization for state encoding

#### SCP Driver (`scp_driver.rs` -> `HerderSCPDriver.h/cpp`)
- [x] `SCPDriver` trait implementation (`HerderScpCallback`)
- [x] `validate_value()` - StellarValue validation (close time, tx set hash, upgrades)
- [x] `combine_candidates()` - Value combination for consensus
- [x] `extract_valid_value()` - Value extraction
- [x] `emit_envelope()` - Envelope broadcasting
- [x] `sign_envelope()` / `verify_envelope()` - Cryptographic operations
- [x] `compute_timeout()` - Protocol 23+ timeout calculation with network config
- [x] `compute_hash_node()` / `compute_value_hash()` - Priority hash computation
- [x] Transaction set caching by hash
- [x] Pending tx set request management
- [x] Externalized slot tracking
- [x] Quorum set by node ID lookup
- [x] Quorum set by hash lookup
- [x] Value upgrade order validation

#### Transaction Queue (`tx_queue.rs` -> `TransactionQueue.h/cpp`, `TxSetFrame.h/cpp`)
- [x] `TransactionQueue` with fee-based ordering
- [x] `try_add()` - Transaction validation and addition
- [x] Signature validation
- [x] Time bounds validation
- [x] Ledger bounds validation
- [x] Extra signers validation (PreconditionsV2)
- [x] Sequence number extraction
- [x] Fee rate comparison (`fee_rate_cmp`)
- [x] Transaction eviction by lower fee
- [x] `TransactionSet` with hash computation
- [x] `GeneralizedTransactionSet` building (protocol 20+)
- [x] Two-phase transaction set (classic + Soroban)
- [x] Transaction set summary logging
- [x] `remove_applied()` - Post-ledger cleanup
- [x] `evict_expired()` - Age-based eviction
- [x] Eviction threshold tracking per lane
- [x] Starting sequence number map for tx set building

#### Surge Pricing (`surge_pricing.rs` -> `SurgePricingUtils.h/cpp`)
- [x] `SurgePricingLaneConfig` trait
- [x] `DexLimitingLaneConfig` - DEX lane separation
- [x] `SorobanGenericLaneConfig` - Soroban resource limits
- [x] `OpsOnlyLaneConfig` - Simple op-count limits
- [x] `SurgePricingPriorityQueue` - Fee-ordered selection
- [x] Multi-lane resource tracking
- [x] Lane limit enforcement
- [x] `pop_top_txs()` - Greedy selection with lane limits
- [x] `get_most_top_txs_within_limits()` - Max subset selection
- [x] `can_fit_with_eviction()` - Eviction planning
- [x] Tie-breaking with seeded hash

#### Pending Envelopes (`pending.rs` -> `PendingEnvelopes.h/cpp`)
- [x] `PendingEnvelopes` with slot-based buffering
- [x] Deduplication via envelope hash
- [x] Slot distance limits
- [x] Per-slot envelope limits
- [x] `release()` / `release_up_to()` - Slot activation
- [x] `evict_expired()` - Age-based cleanup
- [x] Statistics tracking

#### Quorum Tracker (`quorum_tracker.rs` -> `QuorumTracker.h/cpp`)
- [x] `SlotQuorumTracker` - Per-slot quorum monitoring
- [x] `has_quorum()` / `is_v_blocking()` checks
- [x] `QuorumTracker` - Transitive quorum tracking
- [x] `is_node_definitely_in_quorum()` - Security validation
- [x] `expand()` - Incremental quorum expansion
- [x] `rebuild()` - Full quorum reconstruction
- [x] Distance and closest validators tracking

### Not Yet Implemented (Gaps)

#### Core Herder
- [ ] **Persistence**: `persistUpgrades()` / `restoreUpgrades()` - Upgrade parameters persistence
- [ ] **Out-of-sync recovery**: `outOfSyncRecovery()`, `herderOutOfSync()`, `lostSync()` - Timeout-based recovery
- [ ] **Dead node detection**: `startCheckForDeadNodesInterval()`, missing node tracking
- [ ] **Drift tracking**: `mDriftCTSlidingWindow` - Close time drift monitoring
- [ ] **Metrics**: Full medida-style metrics (counters, timers, histograms)
- [ ] **Timer management**: `mTrackingTimer`, `mOutOfSyncTimer`, `mTriggerTimer` with VirtualClock
- [x] **JSON API**: `getJsonInfo()`, `getJsonQuorumInfo()`, `getJsonTransitiveQuorumInfo()` - see `json_api.rs`
- [ ] **Node ID resolution**: `resolveNodeID()` - Config-based node lookup
- [ ] **Upgrade scheduling**: `setUpgrades()`, `getUpgradesJson()` - Scheduled upgrade management
- [ ] **SCP state synchronization**: `forceSCPStateIntoSyncWithLastClosedLedger()`
- [x] **Flow control**: `getFlowControlExtraBuffer()`, `getMaxTxSize()`, `getMaxClassicTxSize()` - see `flow_control.rs`
- [ ] **Last checkpoint sending**: `SEND_LATEST_CHECKPOINT_DELAY` timing

#### SCP Driver (`HerderSCPDriver`)
- [ ] **Timer management**: `setupTimer()`, `stopTimer()` with VirtualTimer integration
- [ ] **SCP execution metrics**: `recordSCPExecutionMetrics()`, `recordSCPEvent()`, `recordSCPExternalizeEvent()`
- [ ] **Externalize lag tracking**: `getExternalizeLag()`, `mQSetLag` per-node timers
- [ ] **Missing node reporting**: `getMaybeDeadNodes()`, `mMissingNodes`, `mDeadNodes`
- [ ] **Node weight function**: `getNodeWeight()` - Application-specific leader election (protocol 22+)
- [ ] **TxSet validity caching**: `TxSetValidityKey`, `mTxSetValidCache` with `RandomEvictionCache`
- [ ] **Value wrapper**: `wrapStellarValue()`, `wrapValue()` with `ValueWrapperPtr`
- [ ] **Ballot phase callbacks**: `ballotDidHearFromQuorum()`, `nominatingValue()`, `updatedCandidateValue()`
- [ ] **Prepare timing**: `getPrepareStart()`, `mSCPExecutionTimes` tracking

#### Transaction Queue
- [ ] **Account state tracking**: `AccountState` with `mTotalFees`, `mAge`, per-account transaction lists
- [ ] **Transaction aging**: `shift()` - Age increment per ledger, auto-ban on max age
- [ ] **Ban mechanism**: `ban()`, `isBanned()` with `mBannedTransactions` deque
- [ ] **Rebroadcast**: `rebroadcast()`, `broadcast()` with flood timing
- [ ] **Flood control**: `broadcastSome()`, `getMaxResourcesToFloodThisPeriod()`
- [ ] **Arbitrage damping**: `mArbitrageFloodDamping`, `allowTxBroadcast()` for path payment loops
- [ ] **Separate queues**: `ClassicTransactionQueue`, `SorobanTransactionQueue` as distinct types
- [ ] **Queue rebuild**: `resetAndRebuild()` for config upgrades
- [ ] **Filtered operations**: `mFilteredTypes`, `isFiltered()` for operation type filtering
- [ ] **Footprint key filtering**: `mKeysToFilter`, `mTxsFilteredDueToFootprintKeys`
- [ ] **Pending depth configuration**: `mPendingDepth` for per-account limits
- [ ] **Pool ledger multiplier**: Queue sizing based on ledger multiplier

#### TxSetFrame
- [ ] **ApplicableTxSetFrame**: Validated tx set ready for application
- [ ] **Parallel execution stages**: `TxStageFrameList`, `ParallelSorobanOrder` for Soroban
- [ ] **TxSetXDRFrame**: Wire-format wrapper with `prepareForApply()`
- [ ] **Legacy format support**: `TransactionSet` (non-generalized) for old protocols
- [ ] **Tx set validation**: `checkValid()` with close time offset bounds
- [ ] **Per-phase iteration**: `getTransactionsForPhase()`, `PerPhaseTransactionList`
- [ ] **Encoded size calculation**: `encodedSize()` for flow control

#### Pending Envelopes
- [ ] **ItemFetcher integration**: `mTxSetFetcher`, `mQuorumSetFetcher` for network fetching
- [ ] **Fetching state tracking**: `mFetchingEnvelopes` with timestamps
- [ ] **Ready envelope queuing**: `mReadyEnvelopes` with wrappers
- [ ] **Cost tracking**: `mReceivedCost` per validator, `reportCostOutliersForSlot()`
- [ ] **Envelope processing callbacks**: `envelopeProcessed()`, `envelopeReady()`
- [ ] **Discarded envelope tracking**: `mDiscardedEnvelopes`, `discardSCPEnvelope()`
- [ ] **Quorum tracker integration**: `rebuildQuorumTrackerState()`, `forceRebuildQuorum()`

#### Upgrades (`Upgrades.h/cpp`)
- [ ] **Upgrades class**: Full upgrade scheduling and validation
- [ ] **UpgradeParameters**: Version, base fee, max tx size, base reserve, flags
- [ ] **ConfigUpgradeSetFrame**: Soroban config upgrade handling
- [ ] **Upgrade creation**: `createUpgradesFor()` based on scheduled time
- [ ] **Upgrade application**: `applyTo()` for ledger header updates
- [ ] **Upgrade validation**: `isValid()`, `isValidForApply()`, `isValidForNomination()`
- [ ] **Upgrade persistence**: Database storage and restoration

#### Quorum Intersection Checker (`QuorumIntersectionChecker.h/cpp`)
- [ ] **QuorumIntersectionChecker**: Network safety analysis
- [ ] **Intersection checking**: `networkEnjoysQuorumIntersection()`
- [ ] **Critical groups**: `getIntersectionCriticalGroups()`
- [ ] **Potential split detection**: `getPotentialSplit()`
- [ ] **Background analysis**: Async recalculation with interrupt support
- [ ] **QuorumMapIntersectionState**: Result caching and status tracking

#### Parallel TxSet Builder (`ParallelTxSetBuilder.h/cpp`)
- [ ] **Parallel execution planning**: Dependency analysis for Soroban transactions
- [ ] **Stage construction**: Grouping transactions into parallel stages
- [ ] **Cluster building**: Identifying dependent transaction clusters
- [ ] **Resource conflict detection**: Ledger key overlap analysis

#### HerderUtils (`HerderUtils.h/cpp`) - `herder_utils.rs`
- [x] **getStellarValues()**: Extract StellarValue from SCP statements
- [x] **getTxSetHashes()**: Extract tx set hashes from SCP envelopes
- [x] **toShortString()**: Short node ID rendering (hex and strkey formats)

#### LedgerCloseData - `ledger_close_data.rs`
- [x] **LedgerCloseData class**: Complete ledger close information wrapper
- [x] **Expected hash tracking**: `mExpectedLedgerHash` for validation
- [x] **XDR serialization**: `to_xdr()`, `from_xdr()`
- [x] **stellarValueToString()**: Human-readable StellarValue formatting

#### TxQueueLimiter (`TxQueueLimiter.h/cpp`) - `tx_queue_limiter.rs`
- [x] **TxQueueLimiter class**: Resource-aware queue limiting
- [x] **Multi-resource tracking**: Operations, bytes, Soroban resources
- [x] **Eviction candidate selection**: Finding lowest-fee eviction targets
- [x] **Evicted fee tracking**: Per-lane tracking of max evicted inclusion fee
- [x] **Flood priority queue**: Separate queue for flooding with highest-fee priority

#### FilteredEntries
- [ ] **Filtered entry tracking**: For footprint-based transaction filtering

### Implementation Notes

#### Architectural Differences

1. **Concurrency Model**
   - **C++**: Single-threaded with VirtualClock timers
   - **Rust**: Thread-safe with `RwLock`, `DashMap`; async-ready but timers not integrated

2. **Timer Management**
   - **C++**: VirtualTimer with Application's VirtualClock
   - **Rust**: Currently missing; timeout durations calculated but not scheduled

3. **Metrics**
   - **C++**: medida library with counters, meters, timers, histograms
   - **Rust**: Not implemented; would use `metrics` crate or similar

4. **Database Persistence**
   - **C++**: Direct SQL database access for SCP state
   - **Rust**: `ScpStatePersistence` trait with `InMemoryScpPersistence` for testing; SQLite backend via `stellar-core-db` pending

5. **Transaction Queue Architecture**
   - **C++**: Separate `ClassicTransactionQueue` and `SorobanTransactionQueue` classes
   - **Rust**: Unified `TransactionQueue` with lane-based separation

6. **Envelope Fetching**
   - **C++**: `ItemFetcher` for async network requests
   - **Rust**: Synchronous processing; overlay integration pending

7. **Error Handling**
   - **C++**: Exceptions and result codes
   - **Rust**: `Result<T, HerderError>` with thiserror

#### Key Design Decisions

1. **Security**: EXTERNALIZE validation matches C++ with quorum membership and slot distance checks
2. **Surge Pricing**: Lane configuration is trait-based for flexibility
3. **Quorum Tracking**: Both slot-level and transitive tracking implemented
4. **Value Validation**: Close time, tx set hash, and upgrade ordering all validated
5. **Transaction Set Building**: Supports both legacy and GeneralizedTransactionSet formats

#### Missing Integration Points

- Timer/scheduler integration with async runtime
- Database persistence layer
- Overlay network `ItemFetcher` equivalent
- Metrics collection and reporting
- JSON API for admin endpoints
- Upgrade scheduling with time-based triggers
