# stellar-core-herder

SCP coordination and ledger-close orchestration for rs-stellar-core.

## Overview

The Herder is the central coordinator that bridges the overlay network and the ledger manager through SCP (Stellar Consensus Protocol). It orchestrates the entire flow from receiving transactions and SCP messages, through consensus, to triggering ledger close.

In the Stellar network architecture, the Herder sits between:
- **Overlay Network**: Receives transactions and SCP envelopes from peers
- **Ledger Manager**: Applies transaction sets and updates ledger state
- **SCP Consensus**: Byzantine fault-tolerant agreement on transaction sets

## Architecture

```text
                    +------------------+
                    |  Overlay Network |
                    +--------+---------+
                             |
            +----------------+----------------+
            | Transactions   | SCP Envelopes  |
            v                v                v
     +------+------+  +------+------+  +------+------+
     |    Herder   |  |    Herder   |  |    Herder   |
     | (Validator) |  | (Observer)  |  | (Catchup)   |
     +------+------+  +------+------+  +------+------+
            |                |                |
            +----------------+----------------+
                             |
    +------------------------+------------------------+
    |                        |                        |
    v                        v                        v
+---+---+              +-----+-----+           +------+------+
|  Tx   |              |  Pending  |           |    SCP      |
| Queue |              | Envelopes |           |   Driver    |
+---+---+              +-----+-----+           +------+------+
    |                        |                        |
    v                        |                        v
+---+-------------+          |              +---------+---+
| Surge Pricing   |          |              | Consensus   |
| Priority Queue  |          |              | Protocol    |
+-----------------+          |              +------+------+
                             |                     |
                             +----------+----------+
                                        |
                                        v
                              +---------+----------+
                              |   Ledger Manager   |
                              +--------------------+
```

## Core Concepts

### State Machine

The Herder progresses through three states:

```text
+----------+     start_syncing()     +----------+     bootstrap()     +----------+
|  Booting | ----------------------> |  Syncing | -----------------> | Tracking |
+----------+                         +----------+                     +----------+
     |                                    |                                |
     | Cannot receive                     | Can receive SCP                | Full consensus
     | any messages                       | (buffers for later)            | participation
     |                                    | Cannot receive txs             |
```

- **Booting**: Initial state after startup. No network participation.
- **Syncing**: Catching up via history archives. SCP envelopes are buffered.
- **Tracking**: Fully synchronized. Processing transactions and consensus.

### Operating Modes

#### Observer Mode (Non-Validator)

Observers track consensus without participating:
- Receive and validate SCP envelopes
- Track externalized values from EXTERNALIZE messages
- Fast-forward tracking slot based on network consensus
- No voting or value proposal

```rust
let config = HerderConfig::default();
let herder = Herder::new(config);
```

#### Validator Mode

Validators actively participate in consensus:
- Propose transaction sets (StellarValue) during nomination
- Vote on values through the SCP ballot protocol
- Sign SCP messages with node's secret key
- Require quorum set configuration

```rust
let config = HerderConfig {
    is_validator: true,
    node_public_key: secret.public_key(),
    local_quorum_set: Some(quorum_set),
    ..Default::default()
};
let herder = Herder::with_secret_key(config, secret);
```

### Transaction Queue

The `TransactionQueue` manages pending transactions with these guarantees:

1. **Fee-based ordering**: Higher fee-per-op transactions are prioritized
2. **Sequence continuity**: Only contiguous sequences per account are included
3. **Phase separation**: Classic and Soroban transactions go to different phases
4. **Lane limits**: DEX operations have independent capacity limits
5. **Surge pricing**: When demand exceeds capacity, minimum fees rise

```text
Transaction Queue Processing:

    Incoming Tx ──> Validate ──> Add to Queue ──> Build Tx Set
                         |              |               |
                         v              v               v
                    [Signatures]   [Fee Check]    [Surge Pricing]
                    [Time Bounds]  [Eviction]     [Lane Limits]
                    [Structure]    [Dedup]        [Sequence Order]
```

### Surge Pricing Lanes

Transactions are partitioned into lanes with independent resource limits:

| Lane | Purpose | Transactions |
|------|---------|--------------|
| Generic (0) | Umbrella limit | All transactions (aggregate) |
| DEX (1) | DEX operations | ManageSellOffer, ManageBuyOffer, etc. |
| Soroban | Smart contracts | InvokeHostFunction, etc. |

The generic lane's limits apply to all transactions. Specialized lanes have additional independent limits to prevent one type from crowding out others.

### GeneralizedTransactionSet (Protocol 20+)

Modern Stellar networks use `GeneralizedTransactionSet` with phases:

```text
GeneralizedTransactionSet
├── Phase 0: Classic
│   └── Components (grouped by base fee)
│       └── Transactions (sorted by hash)
└── Phase 1: Soroban (Parallel execution)
    └── Execution Stages
        └── Dependent Transaction Clusters
```

Classic transactions execute sequentially in a single phase. Soroban transactions can execute in parallel within stages, with dependencies captured in clusters.

## Security Considerations

### EXTERNALIZE Message Validation

EXTERNALIZE messages can fast-forward a node's tracking slot, which is necessary for catching up but also a potential attack vector. The Herder applies two security checks:

1. **Quorum Membership Check**: The sender must be in our transitive quorum set
2. **Slot Distance Limit**: The slot must be within 1000 ledgers of the current slot (~83 minutes at 5s/ledger)

```rust
// Security constant in herder.rs
const MAX_EXTERNALIZE_SLOT_DISTANCE: u64 = 1000;
```

These checks prevent malicious nodes from:
- Making us catch up to non-existent future slots
- Accepting fake consensus from untrusted nodes

### Transitive Quorum Tracking

The `QuorumTracker` builds a graph of all nodes reachable through quorum set relationships:

```text
Local Node (distance 0)
    |
    +-- Validator A (distance 1)
    |       |
    |       +-- Validator D (distance 2)
    |
    +-- Validator B (distance 1)
    |       |
    |       +-- Validator D (distance 2)  <- Reachable via both A and B
    |
    +-- Validator C (distance 1)
```

Only nodes in this transitive quorum can influence our consensus state.

## Key Components

### `Herder`

The main coordinator struct. Thread-safe via internal synchronization.

```rust
pub struct Herder {
    config: HerderConfig,
    state: RwLock<HerderState>,
    tx_queue: TransactionQueue,
    pending_envelopes: PendingEnvelopes,
    scp_driver: Arc<ScpDriver>,
    scp: Option<SCP<HerderScpCallback>>,
    // ... tracking state
}
```

Key methods:
- `receive_scp_envelope()`: Process incoming SCP messages
- `receive_transaction()`: Add transactions to queue
- `trigger_next_ledger()`: Start consensus for validators
- `check_ledger_close()`: Check if ledger is ready to close

### `TransactionQueue`

Pending transaction mempool with surge pricing support.

```rust
pub struct TransactionQueue {
    config: TxQueueConfig,
    by_hash: RwLock<HashMap<Hash256, QueuedTransaction>>,
    seen: RwLock<HashSet<Hash256>>,
    validation_context: RwLock<ValidationContext>,
    // ... eviction thresholds
}
```

Key methods:
- `try_add()`: Add transaction with validation
- `get_transaction_set()`: Build transaction set for consensus
- `build_generalized_tx_set()`: Build modern transaction set format
- `remove_applied()`: Clean up after ledger close

### `ScpDriver`

Bridge between SCP consensus and Herder application logic.

```rust
pub struct ScpDriver {
    config: ScpDriverConfig,
    secret_key: Option<SecretKey>,
    tx_set_cache: DashMap<Hash256, CachedTxSet>,
    pending_tx_sets: DashMap<Hash256, PendingTxSet>,
    externalized: RwLock<HashMap<SlotIndex, ExternalizedSlot>>,
    // ... quorum set storage
}
```

Key responsibilities:
- Validate SCP values (close time, tx set hash, upgrades)
- Sign and verify SCP envelopes
- Cache and retrieve transaction sets
- Track externalized slots

### `PendingEnvelopes`

Buffers SCP envelopes for future slots.

```rust
pub struct PendingEnvelopes {
    config: PendingConfig,
    slots: DashMap<SlotIndex, Vec<PendingEnvelope>>,
    seen_hashes: DashMap<Hash256, ()>,
    current_slot: RwLock<SlotIndex>,
}
```

Features:
- Deduplication via envelope hash
- Slot distance limits
- Automatic expiration
- Release on slot activation

### `QuorumTracker`

Tracks transitive quorum set membership.

```rust
pub struct QuorumTracker {
    local_node_id: NodeId,
    quorum: HashMap<NodeId, NodeInfo>,
}

pub struct NodeInfo {
    pub quorum_set: Option<ScpQuorumSet>,
    pub distance: usize,
    pub closest_validators: BTreeSet<NodeId>,
}
```

Key methods:
- `is_node_definitely_in_quorum()`: Security check for EXTERNALIZE
- `expand()`: Add a node's quorum set to the graph
- `rebuild()`: Reconstruct from scratch with a lookup function

## Configuration Reference

### `HerderConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_pending_transactions` | `usize` | 1000 | Transaction queue capacity |
| `is_validator` | `bool` | false | Enable validator mode |
| `ledger_close_time` | `u32` | 5 | Target ledger close time (seconds) |
| `node_public_key` | `PublicKey` | - | Node's public identity |
| `network_id` | `Hash256` | - | Network ID hash |
| `max_externalized_slots` | `usize` | 12 | Externalized slots to keep |
| `max_tx_set_size` | `usize` | 1000 | Max operations per tx set |
| `local_quorum_set` | `Option<ScpQuorumSet>` | None | Quorum configuration |
| `proposed_upgrades` | `Vec<LedgerUpgrade>` | [] | Protocol upgrades to propose |

### `TxQueueConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_size` | `usize` | 1000 | Maximum transactions in queue |
| `max_age_secs` | `u64` | 300 | Transaction expiration (5 min) |
| `min_fee_per_op` | `u32` | 100 | Minimum fee per operation |
| `validate_signatures` | `bool` | true | Verify signatures on add |
| `validate_time_bounds` | `bool` | true | Check time/ledger bounds |
| `max_dex_ops` | `Option<u32>` | None | DEX lane limit |
| `max_soroban_resources` | `Option<Resource>` | None | Soroban resource limit |

## Usage Examples

### Basic Observer Setup

```rust
use stellar_core_herder::{Herder, HerderConfig, HerderState};

// Create a non-validator herder
let config = HerderConfig::default();
let herder = Herder::new(config);

// Start syncing when catchup begins
herder.start_syncing();
assert_eq!(herder.state(), HerderState::Syncing);

// After catchup completes
herder.bootstrap(ledger_seq);
assert_eq!(herder.state(), HerderState::Tracking);

// Process incoming SCP envelopes
let state = herder.receive_scp_envelope(envelope);
match state {
    EnvelopeState::Valid => { /* New valid envelope */ }
    EnvelopeState::Pending => { /* Buffered for future slot */ }
    EnvelopeState::Duplicate => { /* Already seen */ }
    EnvelopeState::TooOld => { /* Slot already passed */ }
    EnvelopeState::InvalidSignature => { /* Bad signature */ }
    EnvelopeState::Invalid => { /* Validation failed */ }
}

// Check for ledger close
if let Some(close_info) = herder.check_ledger_close(slot) {
    // Apply the transaction set and close the ledger
    let tx_set = close_info.tx_set.expect("tx set available");
    // ... apply transactions
    herder.ledger_closed(slot, &applied_tx_hashes);
}
```

### Validator Setup

```rust
use stellar_core_herder::{Herder, HerderConfig};
use stellar_core_crypto::SecretKey;

let secret = SecretKey::from_seed(&seed);
let quorum_set = ScpQuorumSet {
    threshold: 2,
    validators: vec![node_a, node_b, local_node].try_into().unwrap(),
    inner_sets: vec![].try_into().unwrap(),
};

let config = HerderConfig {
    is_validator: true,
    node_public_key: secret.public_key(),
    local_quorum_set: Some(quorum_set),
    ledger_close_time: 5,
    ..Default::default()
};

let herder = Herder::with_secret_key(config, secret);

// Set up envelope broadcasting
herder.set_envelope_sender(|envelope| {
    // Broadcast to peers
    overlay.broadcast_scp(envelope);
});

// Trigger consensus periodically
herder.trigger_next_ledger(ledger_seq).await?;
```

### Transaction Queue Usage

```rust
use stellar_core_herder::{TransactionQueue, TxQueueConfig, TxQueueResult};

let config = TxQueueConfig {
    max_size: 5000,
    min_fee_per_op: 100,
    max_dex_ops: Some(500),  // Limit DEX operations
    ..Default::default()
};

let queue = TransactionQueue::new(config);

// Add transactions
match queue.try_add(tx_envelope) {
    TxQueueResult::Added => println!("Transaction queued"),
    TxQueueResult::Duplicate => println!("Already in queue"),
    TxQueueResult::QueueFull => println!("Queue at capacity"),
    TxQueueResult::FeeTooLow => println!("Increase fee"),
    TxQueueResult::Invalid => println!("Validation failed"),
}

// Build transaction set for consensus
let (tx_set, gen_tx_set) = queue.build_generalized_tx_set(
    previous_ledger_hash,
    max_ops,
);
```

## Consensus Timing

The Herder uses protocol 23+ SCP timing configuration for timeout calculations:

- **Nomination timeout**: Initial + (round - 1) * increment
- **Ballot timeout**: Initial + (round - 1) * increment
- **Maximum timeout**: Capped at 30 minutes

These values are read from the ledger's network configuration when available.

## Module Layout

```
src/
├── lib.rs              # Crate exports, main types, and documentation
├── herder.rs           # Main Herder implementation
├── scp_driver.rs       # SCP integration callbacks (SCPDriver trait impl)
├── tx_queue.rs         # Transaction queue and set building
├── surge_pricing.rs    # Lane configuration and priority queues
├── pending.rs          # Pending SCP envelope buffering
├── quorum_tracker.rs   # Quorum participation and security tracking
├── state.rs            # Herder state machine definition
└── error.rs            # Error types (HerderError)
```

## Upstream Mapping

This crate corresponds to the following C++ stellar-core components:

| Rust Module | C++ Source |
|-------------|------------|
| `herder.rs` | `src/herder/Herder.cpp`, `HerderImpl.cpp` |
| `scp_driver.rs` | `src/herder/HerderSCPDriver.cpp` |
| `tx_queue.rs` | `src/herder/TxSetFrame.cpp`, `TransactionQueue.cpp` |
| `pending.rs` | `src/herder/PendingEnvelopes.cpp` |
| `surge_pricing.rs` | `src/herder/SurgePricingUtils.cpp` |

## Dependencies

- `stellar-xdr`: XDR type definitions
- `stellar-core-common`: Common types (Hash256, NetworkId, Resource)
- `stellar-core-crypto`: Cryptographic operations
- `stellar-core-scp`: SCP consensus protocol implementation
- `stellar-core-tx`: Transaction validation and processing
- `stellar-core-ledger`: Ledger state management

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
- [ ] **Persistence**: `persistSCPState()` / `restoreSCPState()` - SCP state persistence to database
- [ ] **Persistence**: `persistUpgrades()` / `restoreUpgrades()` - Upgrade parameters persistence
- [ ] **Out-of-sync recovery**: `outOfSyncRecovery()`, `herderOutOfSync()`, `lostSync()` - Timeout-based recovery
- [ ] **Dead node detection**: `startCheckForDeadNodesInterval()`, missing node tracking
- [ ] **Drift tracking**: `mDriftCTSlidingWindow` - Close time drift monitoring
- [ ] **Metrics**: Full medida-style metrics (counters, timers, histograms)
- [ ] **Timer management**: `mTrackingTimer`, `mOutOfSyncTimer`, `mTriggerTimer` with VirtualClock
- [ ] **JSON API**: `getJsonInfo()`, `getJsonQuorumInfo()`, `getJsonTransitiveQuorumInfo()`
- [ ] **Node ID resolution**: `resolveNodeID()` - Config-based node lookup
- [ ] **Upgrade scheduling**: `setUpgrades()`, `getUpgradesJson()` - Scheduled upgrade management
- [ ] **SCP state synchronization**: `forceSCPStateIntoSyncWithLastClosedLedger()`
- [ ] **Flow control**: `getFlowControlExtraBuffer()`, `getMaxTxSize()`, `getMaxClassicTxSize()`
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

#### HerderUtils (`HerderUtils.h/cpp`)
- [ ] **getStellarValues()**: Extract StellarValue from SCP statements
- [ ] **Hash computation utilities**: Various hash helpers

#### LedgerCloseData
- [ ] **LedgerCloseData class**: Complete ledger close information wrapper
- [ ] **Expected hash tracking**: `mExpectedLedgerHash` for validation
- [ ] **XDR serialization**: `toXDR()`, `toLedgerCloseData()`

#### TxQueueLimiter (`TxQueueLimiter.h/cpp`)
- [ ] **TxQueueLimiter class**: Resource-aware queue limiting
- [ ] **Multi-resource tracking**: Operations, bytes, Soroban resources
- [ ] **Eviction candidate selection**: Finding lowest-fee eviction targets

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
   - **Rust**: Not implemented; would integrate with `stellar-core-db` when available

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
