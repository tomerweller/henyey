## C++ Parity Status

This section documents the parity between this Rust crate and the upstream C++ stellar-core herder implementation (v25).

### Implemented

#### Core Herder (`herder.rs` -> `Herder.h`, `HerderImpl.h/cpp`)
- [x] State machine (Booting, Syncing, Tracking) - matches `HERDER_BOOTING_STATE`, `HERDER_SYNCING_STATE`, `HERDER_TRACKING_NETWORK_STATE`
- [x] `receive_scp_envelope()` - SCP envelope processing with signature verification
- [x] `receive_transaction()` - Transaction queue integration
- [x] `bootstrap()` - Transition to tracking state after catchup
- [x] `trigger_next_ledger()` - Validator consensus triggering
- [x] EXTERNALIZE fast-forward with security checks (quorum membership, slot distance)
- [x] Tracking slot management (`trackingConsensusLedgerIndex()`)
- [x] `check_ledger_close()` - Ledger close readiness check
- [x] `ledger_closed()` - Post-close cleanup
- [x] Observer mode (non-validator) support
- [x] Validator mode with secret key signing
- [x] `get_scp_state()` - SCP state for peer requests (`sendSCPStateToPeer()`)
- [x] Quorum set storage and lookup (`getQSet()`)
- [x] Pending tx set request tracking (`getTxSet()`)
- [x] `get_min_ledger_seq_to_ask_peers()` - Minimum ledger for peer requests
- [x] `heard_from_quorum()` / `is_v_blocking()` checks
- [x] `handle_nomination_timeout()` / `handle_ballot_timeout()` - Timeout handling
- [x] `getMaxClassicTxSize()` / `getMaxTxSize()` - Transaction size limits
- [x] `getFlowControlExtraBuffer()` - Flow control buffer sizing
- [x] `getMaxQueueSizeOps()` - Queue size for demand calculation

#### SCP State Persistence (`persistence.rs` -> `HerderPersistence.h/cpp`)
- [x] `PersistedSlotState` - Serializable SCP state for a slot
- [x] `ScpStatePersistence` trait - Storage backend abstraction
- [x] `InMemoryScpPersistence` - In-memory storage for testing
- [x] `SqliteScpPersistence` - SQLite storage for production (crash recovery)
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
- [x] `toShortString()` - Short node ID formatting

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
- [x] `ban()` / `is_banned()` - Transaction banning mechanism
- [x] `isFiltered()` / `mFilteredTypes` - Operation type filtering

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

#### Upgrades (`upgrades.rs` -> `Upgrades.h/cpp`)
- [x] `Upgrades` class - Upgrade scheduling and validation
- [x] `UpgradeParameters` - Version, base fee, max tx size, base reserve, flags, Soroban config
- [x] `create_upgrades_for()` - Create upgrade proposals based on scheduled time
- [x] `is_valid_for_apply()` - XDR validation and safety checks
- [x] `remove_upgrades()` - Remove applied/expired upgrades
- [x] `time_for_upgrade()` - Time-based upgrade triggering
- [x] `UpgradeValidity` enum - `VALID`, `XDR_INVALID`, `INVALID`
- [x] JSON serialization for upgrade parameters

#### HerderUtils (`herder_utils.rs` -> `HerderUtils.h/cpp`)
- [x] `getStellarValues()` - Extract StellarValue from SCP statements
- [x] `getTxSetHashes()` - Extract tx set hashes from SCP envelopes
- [x] `toShortString()` - Short node ID rendering (hex and strkey formats)

#### LedgerCloseData (`ledger_close_data.rs` -> `LedgerCloseData.h/cpp`)
- [x] `LedgerCloseData` class - Complete ledger close information wrapper
- [x] Expected hash tracking (`mExpectedLedgerHash`)
- [x] XDR serialization (`to_xdr()`, `from_xdr()`)
- [x] `stellarValueToString()` - Human-readable StellarValue formatting

#### TxQueueLimiter (`tx_queue_limiter.rs` -> `TxQueueLimiter.h/cpp`)
- [x] `TxQueueLimiter` class - Resource-aware queue limiting
- [x] Multi-resource tracking (operations, bytes, Soroban resources)
- [x] Eviction candidate selection (finding lowest-fee eviction targets)
- [x] Evicted fee tracking per lane
- [x] Flood priority queue for broadcasting

#### Timer & Sync Management
- [x] `TimerManager` (`timer_manager.rs`) - SCP timer scheduling with tokio
- [x] `SyncRecoveryManager` (`sync_recovery.rs`) - Consensus stuck detection and recovery
- [x] `CloseTimeDriftTracker` (`drift_tracker.rs`) - Network time drift monitoring

#### Flow Control (`flow_control.rs`)
- [x] `getFlowControlExtraBuffer()` - Extra buffer calculation
- [x] `getMaxTxSize()` - Maximum transaction size
- [x] `getMaxClassicTxSize()` - Maximum classic transaction size

#### Transaction Broadcast (`tx_broadcast.rs`)
- [x] `TxBroadcastManager` - Periodic flooding of transactions
- [x] `broadcastSome()` - Batch broadcasting with resource limits
- [x] Flood period configuration

#### JSON API (`json_api.rs`)
- [x] `getJsonInfo()` - Herder state information
- [x] `getJsonQuorumInfo()` - Quorum state information
- [x] `getJsonTransitiveQuorumInfo()` - Transitive quorum information

### Not Yet Implemented (Gaps)

#### Core Herder (`HerderImpl`)
- [ ] **Persistence**: `persistUpgrades()` / `restoreUpgrades()` - Upgrade parameters persistence to database
- [ ] **Dead node detection**: `startCheckForDeadNodesInterval()`, `CHECK_FOR_DEAD_NODES_MINUTES` - Missing node tracking
- [ ] **Metrics**: Full medida-style metrics (counters, timers, histograms)
- [ ] **Node ID resolution**: `resolveNodeID()` - Config-based node lookup from name
- [ ] **Upgrade scheduling API**: `setUpgrades()`, `getUpgradesJson()` - Admin endpoint for upgrade scheduling
- [ ] **SCP state synchronization**: `forceSCPStateIntoSyncWithLastClosedLedger()` - Force sync after catchup
- [ ] **Last checkpoint sending**: `SEND_LATEST_CHECKPOINT_DELAY` timing for peer sync
- [ ] **Quorum map reanalysis**: `checkAndMaybeReanalyzeQuorumMap()`, `checkAndMaybeReanalyzeQuorumMapV2()`
- [ ] **Keys to filter recomputation**: `recomputeKeysToFilter()` for Soroban footprint filtering

#### SCP Driver (`HerderSCPDriver`)
- [ ] **SCP execution metrics**: `recordSCPExecutionMetrics()`, `recordSCPEvent()`, `recordSCPExternalizeEvent()`
- [ ] **Externalize lag tracking**: `getExternalizeLag()`, `mQSetLag` per-node timers
- [ ] **Missing node reporting**: `getMaybeDeadNodes()`, `mMissingNodes`, `mDeadNodes`
- [ ] **Node weight function**: `getNodeWeight()` - Application-specific leader election (protocol 22+)
- [ ] **TxSet validity caching**: `TxSetValidityKey`, `mTxSetValidCache` with `RandomEvictionCache`
- [ ] **Value wrapper**: `wrapStellarValue()`, `wrapValue()` with `ValueWrapperPtr`
- [ ] **Ballot phase callbacks**: `ballotDidHearFromQuorum()`, `nominatingValue()`, `updatedCandidateValue()`
- [ ] **Prepare timing**: `getPrepareStart()`, `mSCPExecutionTimes` tracking

#### Transaction Queue (`TransactionQueue`)
- [ ] **Account state tracking**: Full `AccountState` with `mTotalFees`, `mAge`, per-account transaction lists
- [ ] **Transaction aging**: `shift()` - Age increment per ledger, auto-ban on max age
- [ ] **Arbitrage damping**: `mArbitrageFloodDamping`, `allowTxBroadcast()` for path payment loops
- [ ] **Separate queues**: `ClassicTransactionQueue`, `SorobanTransactionQueue` as distinct types (Rust uses unified queue)
- [ ] **Queue rebuild**: `resetAndRebuild()` for config upgrades
- [ ] **Footprint key filtering**: `mKeysToFilter`, `mTxsFilteredDueToFootprintKeys`
- [ ] **Pending depth configuration**: `mPendingDepth` for per-account limits
- [ ] **Pool ledger multiplier**: Queue sizing based on ledger multiplier

#### TxSetFrame (`TxSetFrame.h/cpp`)
- [ ] **ApplicableTxSetFrame**: Validated tx set ready for application with phase separation
- [ ] **TxSetPhaseFrame**: Phase-level abstraction with parallel stage support
- [ ] **Parallel execution stages**: `TxStageFrameList`, `ParallelSorobanOrder` for Soroban
- [ ] **TxSetXDRFrame**: Wire-format wrapper with `prepareForApply()`
- [ ] **Legacy format support**: `TransactionSet` (non-generalized) for old protocols
- [ ] **Tx set validation**: `checkValid()` with close time offset bounds
- [ ] **Per-phase iteration**: `getTransactionsForPhase()`, `PerPhaseTransactionList`
- [ ] **Encoded size calculation**: `encodedSize()` for flow control
- [ ] **Inclusion fee map**: Per-transaction base fee tracking

#### Pending Envelopes (`PendingEnvelopes`)
- [ ] **ItemFetcher integration**: `mTxSetFetcher`, `mQuorumSetFetcher` for async network fetching
- [ ] **Fetching state tracking**: `mFetchingEnvelopes` with timestamps
- [ ] **Ready envelope queuing**: `mReadyEnvelopes` with wrappers
- [ ] **Cost tracking**: `mReceivedCost` per validator, `reportCostOutliersForSlot()`
- [ ] **Envelope processing callbacks**: `envelopeProcessed()`, `envelopeReady()`
- [ ] **Discarded envelope tracking**: `mDiscardedEnvelopes`, `discardSCPEnvelope()`
- [ ] **Quorum tracker integration**: `rebuildQuorumTrackerState()`, `forceRebuildQuorum()`
- [ ] **Value size caching**: `mValueSizeCache` for txset/qset sizes

#### ConfigUpgradeSetFrame (`Upgrades.h/cpp`)
- [ ] **ConfigUpgradeSetFrame**: Soroban config upgrade handling
- [ ] **makeFromKey()**: Retrieve config from ledger state
- [ ] **getLedgerKey()**: Convert upgrade key to contract data key
- [ ] **upgradeNeeded()**: Check if upgrade differs from current config
- [ ] **applyTo()**: Apply config upgrade to ledger state
- [ ] **isConsistentWith()**: Validate against scheduled upgrade

#### Quorum Intersection Checker (`QuorumIntersectionChecker.h/cpp`)
- [ ] **QuorumIntersectionChecker**: Network safety analysis
- [ ] **networkEnjoysQuorumIntersection()**: Check for quorum intersection
- [ ] **getIntersectionCriticalGroups()**: Find critical node groups
- [ ] **getPotentialSplit()**: Detect potential network splits
- [ ] **Background analysis**: Async recalculation with interrupt support
- [ ] **QuorumMapIntersectionState**: Result caching and status tracking

#### Parallel TxSet Builder (`ParallelTxSetBuilder.h/cpp`)
- [ ] **buildSurgePricedParallelSorobanPhase()**: Parallel execution planning
- [ ] **Stage construction**: Grouping transactions into parallel stages
- [ ] **Cluster building**: Identifying dependent transaction clusters
- [ ] **Resource conflict detection**: Ledger key overlap analysis

#### FilteredEntries (`FilteredEntries.h`)
- [ ] **Filtered entry tracking**: For footprint-based transaction filtering

### Implementation Notes

#### Architectural Differences

1. **Concurrency Model**
   - **C++**: Single-threaded with VirtualClock timers, callback-driven
   - **Rust**: Thread-safe with `RwLock`, `DashMap`; async-ready with tokio integration

2. **Timer Management**
   - **C++**: VirtualTimer with Application's VirtualClock
   - **Rust**: `TimerManager` with tokio channels; `SyncRecoveryManager` for tracking timeouts

3. **Metrics**
   - **C++**: medida library with counters, meters, timers, histograms
   - **Rust**: Not implemented; would use `metrics` or `prometheus` crate

4. **Database Persistence**
   - **C++**: Direct SQL database access for SCP state and upgrades
   - **Rust**: `ScpStatePersistence` trait with `InMemoryScpPersistence` and `SqliteScpPersistence`

5. **Transaction Queue Architecture**
   - **C++**: Separate `ClassicTransactionQueue` and `SorobanTransactionQueue` classes with inheritance
   - **Rust**: Unified `TransactionQueue` with lane-based separation

6. **Envelope Fetching**
   - **C++**: `ItemFetcher` for async network requests with callbacks
   - **Rust**: Synchronous processing; overlay integration pending

7. **Error Handling**
   - **C++**: Exceptions and result codes
   - **Rust**: `Result<T, HerderError>` with thiserror

8. **Transaction Set Building**
   - **C++**: `TxSetXDRFrame` -> `ApplicableTxSetFrame` with `prepareForApply()`
   - **Rust**: Direct `TransactionSet` / `GeneralizedTransactionSet` building

#### Key Design Decisions

1. **Security**: EXTERNALIZE validation matches C++ with quorum membership and slot distance checks (`MAX_EXTERNALIZE_SLOT_DISTANCE = 1000`)
2. **Surge Pricing**: Lane configuration is trait-based for flexibility
3. **Quorum Tracking**: Both slot-level and transitive tracking implemented
4. **Value Validation**: Close time, tx set hash, and upgrade ordering all validated
5. **Transaction Set Building**: Supports both legacy and GeneralizedTransactionSet formats (protocol 20+)
6. **Constants Match**: `CONSENSUS_STUCK_TIMEOUT_SECONDS`, `LEDGER_VALIDITY_BRACKET`, `MAX_TIME_SLIP_SECONDS`

#### Missing Integration Points

- Overlay network `ItemFetcher` equivalent for async data fetching
- Metrics collection and reporting infrastructure
- Quorum intersection analysis for network health
- Parallel Soroban execution planning
- Config upgrade application to ledger state

#### App Integration Status

The following herder features are integrated with the main application:

- **Periodic cleanup**: 30s interval cleanup of expired pending envelopes, transactions, and old tx sets
- **Quorum loss detection**: `heard_from_quorum()` and `is_v_blocking()` checks in heartbeat
- **Close time drift tracking**: `CloseTimeDriftTracker` records local/network times and warns on drift
- **Transaction banning**: Failed transactions banned; ban queue shifts on ledger close
- **Pending envelope statistics**: `PendingStats` exposed via `HerderStats`
- **Transaction queue introspection**: `TxQueueStats` provides queue state visibility
- **Sync recovery manager**: Background task monitors for consensus stuck (35s timeout) and triggers recovery
- **Timer management**: SCP nomination/ballot timers with configurable timeouts
- **Transaction broadcast**: Periodic flooding with resource-aware batching

#### Parity Estimate

| Component | Parity |
|-----------|--------|
| Core Herder | ~85% |
| SCP Driver | ~80% |
| Transaction Queue | ~75% |
| Surge Pricing | ~95% |
| Pending Envelopes | ~70% |
| Quorum Tracker | ~90% |
| Upgrades | ~80% |
| TxSetFrame | ~60% |
| Persistence | ~85% |
| Quorum Intersection | 0% |
| Parallel TxSet Builder | 0% |
| **Overall** | **~75%** |
