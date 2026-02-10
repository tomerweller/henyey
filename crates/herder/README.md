# henyey-herder

SCP coordination and ledger-close orchestration for henyey.

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
     +---------------+------------+------------+----------------+
     |               |            |            |                |
     v               v            v            v                v
+----+----+    +-----+------+ +--+------+ +---+-------+ +------+------+
|   Tx    |    |  Fetching  | | Pending | |   SCP     | |  Upgrades   |
|  Queue  |    |  Envelopes | | Envlps  | |  Driver   | | (Scheduling)|
+----+----+    +-----+------+ +---------+ +---+-------+ +-------------+
     |               |                        |
     v               v                        v
+----+---------+ +---+----------+    +--------+--------+
| Surge Pricing| | ItemFetcher  |    | SCP Consensus   |
| Priority Que | | (TxSet/QSet) |    |   Protocol      |
+--------------+ +--------------+    +--------+--------+
                                              |
                                              v
                                   +----------+---------+
                                   |   Ledger Manager   |
                                   +--------------------+

Background Tasks (tokio):

  +----------------+    +------------------+    +-------------------+
  | TimerManager   |    | SyncRecovery     |    | TxBroadcast       |
  | (SCP timeouts) |    | (stuck detect)   |    | (flood to peers)  |
  +----------------+    +------------------+    +-------------------+

Monitoring:

  +-------------------+    +------------------+
  | CloseTimeDrift    |    | DeadNodeTracker  |
  | Tracker           |    | (offline detect) |
  +-------------------+    +------------------+
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
    fetching_envelopes: FetchingEnvelopes,
    scp_driver: Arc<ScpDriver>,
    scp: Option<SCP<HerderScpCallback>>,
    tracking_slot: RwLock<u64>,
    secret_key: Option<SecretKey>,
    ledger_manager: RwLock<Option<Arc<LedgerManager>>>,
    slot_quorum_tracker: RwLock<SlotQuorumTracker>,
    // ... additional tracking state
}
```

Key methods:
- `receive_scp_envelope()`: Process incoming SCP messages
- `receive_transaction()`: Add transactions to queue
- `trigger_next_ledger()`: Start consensus for validators
- `check_ledger_close()`: Check if ledger is ready to close
- `ledger_closed()`: Post-close cleanup (remove applied txs, shift bans)
- `bootstrap()`: Transition to tracking state after catchup
- `heard_from_quorum()` / `is_v_blocking()`: Quorum participation checks
- `get_scp_state()`: SCP state for peer synchronization

### `TransactionQueue`

Pending transaction mempool with surge pricing support.

```rust
pub struct TransactionQueue {
    config: TxQueueConfig,
    by_hash: RwLock<HashMap<Hash256, QueuedTransaction>>,
    seen: RwLock<HashSet<Hash256>>,
    validation_context: RwLock<ValidationContext>,
    banned_transactions: RwLock<VecDeque<HashSet<Hash256>>>,
    account_states: RwLock<HashMap<Vec<u8>, AccountState>>,
    // ... eviction thresholds per lane
}
```

Key methods:
- `try_add()`: Add transaction with validation (returns `TxQueueResult`)
- `build_generalized_tx_set()`: Build modern transaction set format
- `remove_applied()`: Clean up after ledger close
- `shift()`: Age transactions per ledger, auto-ban stale entries
- `ban()` / `is_banned()`: Transaction banning mechanism
- `evict_expired()`: Age-based eviction

### `ScpDriver`

Bridge between SCP consensus and Herder application logic.

```rust
pub struct ScpDriver {
    config: ScpDriverConfig,
    secret_key: Option<SecretKey>,
    tx_set_cache: DashMap<Hash256, CachedTxSet>,
    pending_tx_sets: DashMap<Hash256, PendingTxSet>,
    pending_quorum_sets: DashMap<Hash256, PendingQuorumSet>,
    externalized: RwLock<HashMap<SlotIndex, ExternalizedSlot>>,
    quorum_sets: DashMap<[u8; 32], ScpQuorumSet>,
    quorum_sets_by_hash: DashMap<[u8; 32], ScpQuorumSet>,
    ledger_manager: RwLock<Option<Arc<LedgerManager>>>,
    // ... envelope sender, network ID
}
```

Key responsibilities:
- Validate SCP values (close time, tx set hash, upgrades)
- Sign and verify SCP envelopes
- Cache and retrieve transaction sets by hash
- Track externalized slots
- Store and look up quorum sets (by node ID and by hash)
- Compute protocol 23+ timeouts from network configuration

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

### `FetchingEnvelopes`

Manages SCP envelopes waiting for their dependencies (TxSets and QuorumSets) to be fetched from peers. When an envelope references data we don't have locally, the fetcher queues it and uses `ItemFetcher` from the overlay layer to retrieve the missing data. Once all dependencies arrive, the envelope is marked ready for processing.

```text
Envelope Fetch Flow:

    SCP Envelope ──> Check Dependencies ──> All present? ──> Ready
                           |                                   ^
                           | Missing TxSet/QSet                |
                           v                                   |
                     Start Fetch ──> ItemFetcher ──> Received ─+
```

Features:
- TxSet and QuorumSet dependency tracking per envelope
- Integration with `ItemFetcher` for network requests
- Per-slot envelope organization with deduplication
- Discarded and processed envelope tracking

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
| `pending_config` | `PendingConfig` | (see defaults) | Pending envelope buffer config |
| `tx_queue_config` | `TxQueueConfig` | (see defaults) | Transaction queue config |
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
| `network_id` | `NetworkId` | testnet | Network ID for signature validation |
| `max_dex_ops` | `Option<u32>` | None | DEX lane op limit for tx set selection |
| `max_classic_bytes` | `Option<u32>` | 5 MB | Classic tx byte allowance for tx set |
| `max_dex_bytes` | `Option<u32>` | None | DEX lane byte limit for tx set |
| `max_soroban_resources` | `Option<Resource>` | None | Soroban resource limit for tx set |
| `max_soroban_bytes` | `Option<u32>` | 5 MB | Soroban tx byte allowance for tx set |
| `max_queue_dex_ops` | `Option<u32>` | None | DEX lane op limit for queue admission |
| `max_queue_soroban_resources` | `Option<Resource>` | None | Soroban resource limit for queue |
| `max_queue_ops` | `Option<u32>` | None | Total op limit for queue admission |
| `max_queue_classic_bytes` | `Option<u32>` | None | Classic byte limit for queue admission |
| `filtered_operation_types` | `HashSet<OperationType>` | empty | Op types to reject from mempool |

## Usage Examples

### Basic Observer Setup

```rust
use henyey_herder::{Herder, HerderConfig, HerderState};

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
    EnvelopeState::Fetching => { /* Waiting for TxSet/QuorumSet dependencies */ }
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
use henyey_herder::{Herder, HerderConfig};
use henyey_crypto::SecretKey;

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
use henyey_herder::{TransactionQueue, TxQueueConfig, TxQueueResult};

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
    TxQueueResult::Banned => println!("Transaction is banned"),
    TxQueueResult::Filtered => println!("Contains filtered op type"),
    TxQueueResult::TryAgainLater => println!("Account has pending tx"),
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
├── lib.rs                # Crate exports, main types, HerderCallback trait
├── herder.rs             # Main Herder implementation and HerderConfig
├── scp_driver.rs         # SCP integration callbacks (SCPDriver trait impl)
├── tx_queue.rs           # Transaction queue, set building, TxQueueConfig
├── tx_queue_limiter.rs   # Resource-aware queue limiting with eviction
├── surge_pricing.rs      # Lane configuration and priority queues
├── pending.rs            # Pending SCP envelope buffering (future slots)
├── fetching_envelopes.rs # Envelopes waiting for TxSet/QuorumSet from peers
├── quorum_tracker.rs     # Quorum participation and security tracking
├── persistence.rs        # SCP state persistence for crash recovery (SQLite)
├── upgrades.rs           # Ledger upgrade scheduling and validation
├── ledger_close_data.rs  # Complete ledger close data from consensus
├── herder_utils.rs       # Utility functions (value extraction, node IDs)
├── timer_manager.rs      # SCP nomination/ballot timeout scheduling (tokio)
├── sync_recovery.rs      # Out-of-sync detection and recovery
├── tx_broadcast.rs       # Periodic transaction flooding to peers
├── drift_tracker.rs      # Close time drift monitoring
├── dead_node_tracker.rs  # Missing/dead validator detection
├── flow_control.rs       # Flow control constants (tx size limits)
├── json_api.rs           # JSON structures for admin/diagnostic endpoints
├── state.rs              # Herder state machine definition
└── error.rs              # Error types (HerderError)
```

## Upstream Mapping

This crate corresponds to the following stellar-core components:

| Rust Module | stellar-core Source |
|-------------|------------|
| `herder.rs` | `src/herder/Herder.cpp`, `HerderImpl.cpp` |
| `scp_driver.rs` | `src/herder/HerderSCPDriver.cpp` |
| `tx_queue.rs` | `src/herder/TxSetFrame.cpp`, `TransactionQueue.cpp` |
| `tx_queue_limiter.rs` | `src/herder/TxQueueLimiter.cpp` |
| `pending.rs` | `src/herder/PendingEnvelopes.cpp` (buffering) |
| `fetching_envelopes.rs` | `src/herder/PendingEnvelopes.cpp` (fetching) |
| `surge_pricing.rs` | `src/herder/SurgePricingUtils.cpp` |
| `persistence.rs` | `src/herder/HerderPersistence.cpp` |
| `upgrades.rs` | `src/herder/Upgrades.cpp` |
| `ledger_close_data.rs` | `src/herder/LedgerCloseData.cpp` |
| `herder_utils.rs` | `src/herder/HerderUtils.cpp` |
| `quorum_tracker.rs` | `src/herder/QuorumTracker.cpp` |
| `flow_control.rs` | `src/herder/Herder.h` (constants), `src/overlay/Peer.h` |

## Dependencies

- `stellar-xdr`: XDR type definitions
- `henyey-common`: Common types (Hash256, NetworkId, Resource)
- `henyey-crypto`: Cryptographic operations
- `henyey-scp`: SCP consensus protocol implementation
- `henyey-tx`: Transaction validation and processing
- `henyey-ledger`: Ledger state management
- `henyey-db`: Database abstraction (SQLite persistence)
- `henyey-overlay`: Overlay network integration (ItemFetcher for TxSet/QuorumSet fetching)

## stellar-core Parity Status

See [PARITY_STATUS.md](PARITY_STATUS.md) for detailed stellar-core parity analysis.
