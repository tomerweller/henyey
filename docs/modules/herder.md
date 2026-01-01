# Herder Module Specification

**Crate**: `stellar-core-herder`
**stellar-core mapping**: `src/herder/`

## 1. Overview

The herder module is the coordination layer between SCP and the rest of stellar-core. It:
- Provides concrete implementations of SCP callbacks
- Manages consensus slots (ledger numbers)
- Coordinates transaction set creation
- Triggers ledger closing when consensus is reached
- Manages the transition from nomination to ballot protocol

## 2. stellar-core Reference

In stellar-core, the herder module (`src/herder/`) contains:
- `Herder.h/cpp` - Main interface
- `HerderImpl.h/cpp` - Implementation
- `HerderSCPDriver.h/cpp` - SCP driver implementation
- `PendingEnvelopes.h/cpp` - Envelope buffer
- `QuorumTracker.h/cpp` - Quorum set tracking
- `TransactionQueue.h/cpp` - Transaction queue
- `TxSetFrame.h/cpp` - Transaction set frame
- `TxSetUtils.h/cpp` - Transaction set utilities
- `Upgrades.h/cpp` - Protocol upgrade handling

### 2.1 Slot Lifecycle

1. **Nomination phase**: Collect candidate transaction sets
2. **Ballot phase**: Agree on single transaction set
3. **Externalization**: Apply agreed transaction set to ledger
4. **Close**: Move to next slot

## 3. Rust Implementation

### 3.1 Dependencies

```toml
[dependencies]
stellar-xdr = { version = "25.0.0", features = ["std", "curr"] }
stellar-core-scp = { path = "../stellar-core-scp" }
stellar-core-crypto = { path = "../stellar-core-crypto" }
stellar-core-ledger = { path = "../stellar-core-ledger" }
stellar-core-overlay = { path = "../stellar-core-overlay" }
stellar-core-tx = { path = "../stellar-core-tx" }

# Async
tokio = { version = "1", features = ["time", "sync"] }

# Utilities
thiserror = "1"
tracing = "0.1"
parking_lot = "0.12"
dashmap = "5"
```

### 3.2 Module Structure

```
stellar-core-herder/
├── src/
│   ├── lib.rs
│   ├── herder.rs             # Main herder
│   ├── scp_driver.rs         # SCPDriver implementation
│   ├── pending_envelopes.rs  # Envelope buffering
│   ├── transaction_queue.rs  # Tx queue management
│   ├── surge_pricing.rs      # Lane configs + priority queue helpers
│   ├── tx_set_frame.rs       # Transaction set frames
│   ├── quorum_tracker.rs     # Quorum set tracking
│   ├── upgrades.rs           # Protocol upgrades
│   └── error.rs
└── tests/
```

### 3.3 Core Types

#### Herder

```rust
use stellar_core_scp::{SCP, SCPDriver, EnvelopeState};
use stellar_core_ledger::LedgerManager;
use stellar_core_overlay::OverlayManager;

/// Herder state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HerderState {
    /// Waiting for network sync
    Booting,
    /// Syncing with network
    Syncing,
    /// Following consensus (tracking)
    Tracking,
}

/// Main herder coordinator
pub struct Herder {
    state: parking_lot::RwLock<HerderState>,

    /// SCP instance
    scp: Arc<SCP<HerderSCPDriver>>,

    /// SCP driver (callback implementation)
    scp_driver: Arc<HerderSCPDriver>,

    /// Ledger manager reference
    ledger_manager: Arc<LedgerManager>,

    /// Overlay manager reference
    overlay_manager: Arc<OverlayManager>,

    /// Pending envelopes (received before we're ready)
    pending_envelopes: PendingEnvelopes,

    /// Transaction queue
    transaction_queue: parking_lot::RwLock<TransactionQueue>,

    /// Current tracking slot
    tracking_scp_slot: parking_lot::RwLock<u64>,

    /// Quorum tracker
    quorum_tracker: QuorumTracker,

    /// Configuration
    config: HerderConfig,
}

pub struct HerderConfig {
    pub is_validator: bool,
    pub quorum_set: ScpQuorumSet,
    pub node_id: NodeId,
    pub network_passphrase: String,
}

impl Herder {
    pub fn new(
        config: HerderConfig,
        ledger_manager: Arc<LedgerManager>,
        overlay_manager: Arc<OverlayManager>,
        secret_key: SecretKey,
    ) -> Arc<Self> {
        let scp_driver = Arc::new(HerderSCPDriver::new(
            config.network_passphrase.clone(),
            secret_key,
        ));

        let scp = Arc::new(SCP::new(
            config.node_id.clone(),
            config.is_validator,
            config.quorum_set.clone(),
            Arc::clone(&scp_driver) as Arc<dyn SCPDriver>,
        ));

        Arc::new(Self {
            state: parking_lot::RwLock::new(HerderState::Booting),
            scp,
            scp_driver,
            ledger_manager,
            overlay_manager,
            pending_envelopes: PendingEnvelopes::new(),
            transaction_queue: parking_lot::RwLock::new(TransactionQueue::new()),
            tracking_scp_slot: parking_lot::RwLock::new(0),
            quorum_tracker: QuorumTracker::new(),
            config,
        })
    }

    /// Bootstrap the herder after catchup
    pub fn bootstrap(&self, ledger_seq: u32) {
        *self.tracking_scp_slot.write() = ledger_seq as u64 + 1;
        *self.state.write() = HerderState::Syncing;
        tracing::info!(slot = ledger_seq + 1, "Herder bootstrapped");
    }

    /// Receive an SCP envelope from the network
    pub fn receive_scp_envelope(&self, envelope: ScpEnvelope) -> EnvelopeState {
        let slot_index = envelope.statement.slot_index;
        let tracking = *self.tracking_scp_slot.read();

        // If we're not tracking yet, or envelope is for future slot, buffer it
        if *self.state.read() == HerderState::Booting || slot_index > tracking + 1 {
            self.pending_envelopes.add(envelope);
            return EnvelopeState::Valid;
        }

        // Process through SCP
        let result = self.scp.receive_envelope(envelope.clone());

        // Broadcast to peers if valid
        if result != EnvelopeState::Invalid {
            self.overlay_manager.flood_message(&StellarMessage::ScpMessage(envelope));
        }

        result
    }

    /// Trigger nomination for the current slot
    pub fn trigger_next_ledger(&self, ledger_seq: u32) {
        if !self.config.is_validator {
            return;
        }

        let slot = ledger_seq as u64 + 1;
        tracing::info!(slot = slot, "Triggering nomination");

        // Build transaction set from queue using the current ledger header max_tx_set_size
        let tx_set = self.build_transaction_set(ledger_seq);

        // Create SCP value from transaction set (includes configured upgrades)
        let value = self.create_scp_value(&tx_set, ledger_seq);

        // Get previous value for nomination
        let prev_value = self.get_previous_value(slot);

        // Nominate
        self.scp.nominate(slot, value, &prev_value);
    }

    fn build_transaction_set(&self, ledger_seq: u32) -> TransactionSet {
        let queue = self.transaction_queue.read();
        queue.get_transaction_set(ledger_seq)
    }

    fn create_scp_value(&self, tx_set: &TransactionSet, ledger_seq: u32) -> Value {
        // Create StellarValue from transaction set
        let close_time = current_time();

        let stellar_value = StellarValue {
            tx_set_hash: tx_set.hash(),
            close_time: TimePoint(close_time),
            upgrades: Vec::new().try_into().unwrap(),
            ext: StellarValueExt::StellarValueBasic,
        };

        stellar_value.to_xdr(stellar_xdr::Limits::none()).unwrap().into()
    }

    /// Called when SCP externalizes a value
    pub fn value_externalized(&self, slot: u64, value: &Value) {
        tracing::info!(slot = slot, "Value externalized");

        // Parse the value
        let stellar_value = StellarValue::from_xdr(value.as_slice(), stellar_xdr::Limits::none())
            .expect("Invalid externalized value");

        // Get the transaction set
        let tx_set = self.get_tx_set(&stellar_value.tx_set_hash)
            .expect("Missing transaction set for externalized value");

        // Apply to ledger
        self.ledger_manager.close_ledger(slot as u32, &tx_set, &stellar_value);

        // Update tracking
        *self.tracking_scp_slot.write() = slot + 1;
        *self.state.write() = HerderState::Tracking;

        // Process pending envelopes for next slot
        self.process_pending_envelopes(slot + 1);

        // Trigger next ledger nomination (after timeout)
        self.schedule_next_ledger(slot as u32);
    }

    fn process_pending_envelopes(&self, slot: u64) {
        let pending = self.pending_envelopes.pop(slot);
        for envelope in pending {
            self.scp.receive_envelope(envelope);
        }
    }

    /// Receive a transaction from the network
    pub fn receive_transaction(&self, tx: TransactionEnvelope) -> TransactionQueueResult {
        let mut queue = self.transaction_queue.write();
        queue.try_add(tx, &self.ledger_manager)
    }

    /// Get herder state
    pub fn state(&self) -> HerderState {
        *self.state.read()
    }

    /// Get the current tracking slot
    pub fn tracking_slot(&self) -> u64 {
        *self.tracking_scp_slot.read()
    }
}
```

#### HerderSCPDriver

```rust
/// Implements SCPDriver for Herder
pub struct HerderSCPDriver {
    network_passphrase: String,
    secret_key: SecretKey,

    /// Transaction sets by hash
    tx_sets: DashMap<Hash256, TransactionSet>,

    /// Quorum sets by hash
    quorum_sets: DashMap<Hash256, ScpQuorumSet>,

    /// Callback for envelope emission
    envelope_callback: parking_lot::RwLock<Option<Box<dyn Fn(ScpEnvelope) + Send + Sync>>>,

    /// Callback for externalization
    externalize_callback: parking_lot::RwLock<Option<Box<dyn Fn(u64, Value) + Send + Sync>>>,
}

impl HerderSCPDriver {
    pub fn new(network_passphrase: String, secret_key: SecretKey) -> Self {
        Self {
            network_passphrase,
            secret_key,
            tx_sets: DashMap::new(),
            quorum_sets: DashMap::new(),
            envelope_callback: parking_lot::RwLock::new(None),
            externalize_callback: parking_lot::RwLock::new(None),
        }
    }

    pub fn set_envelope_callback(&self, f: impl Fn(ScpEnvelope) + Send + Sync + 'static) {
        *self.envelope_callback.write() = Some(Box::new(f));
    }

    pub fn set_externalize_callback(&self, f: impl Fn(u64, Value) + Send + Sync + 'static) {
        *self.externalize_callback.write() = Some(Box::new(f));
    }

    pub fn cache_tx_set(&self, tx_set: TransactionSet) {
        let hash = tx_set.hash();
        self.tx_sets.insert(hash, tx_set);
    }

    pub fn get_tx_set(&self, hash: &Hash256) -> Option<TransactionSet> {
        self.tx_sets.get(hash).map(|r| r.clone())
    }
}

impl SCPDriver for HerderSCPDriver {
    fn validate_value(&self, slot_index: u64, value: &Value, nomination: bool) -> ValidationLevel {
        // Parse value as StellarValue
        let stellar_value = match StellarValue::from_xdr(value.as_slice(), stellar_xdr::Limits::none()) {
            Ok(v) => v,
            Err(_) => return ValidationLevel::Invalid,
        };

        // Check we have the transaction set
        if !self.tx_sets.contains_key(&stellar_value.tx_set_hash.into()) {
            // Request it from peers
            return ValidationLevel::MaybeValid;
        }

        // Validate close time
        // Validate upgrades
        // Validate transaction set contents

        ValidationLevel::FullyValidated
    }

    fn combine_candidates(&self, slot_index: u64, candidates: &[Value]) -> Option<Value> {
        if candidates.is_empty() {
            return None;
        }

        // Parse all candidates
        let values: Vec<StellarValue> = candidates
            .iter()
            .filter_map(|v| StellarValue::from_xdr(v.as_slice(), stellar_xdr::Limits::none()).ok())
            .collect();

        if values.is_empty() {
            return None;
        }

        // Combine transaction sets
        let combined_tx_set = self.combine_transaction_sets(&values);

        // Use median close time
        let mut times: Vec<_> = values.iter().map(|v| v.close_time.0).collect();
        times.sort();
        let median_time = times[times.len() / 2];

        // Combine upgrades
        let upgrades = self.combine_upgrades(&values);

        let combined = StellarValue {
            tx_set_hash: combined_tx_set.hash().into(),
            close_time: TimePoint(median_time),
            upgrades,
            ext: StellarValueExt::StellarValueBasic,
        };

        // Cache the combined transaction set
        self.cache_tx_set(combined_tx_set);

        Some(combined.to_xdr(stellar_xdr::Limits::none()).unwrap().into())
    }

    fn extract_valid_value(&self, slot_index: u64, value: &Value) -> Option<Value> {
        // For now, return as-is if valid
        if self.validate_value(slot_index, value, false) != ValidationLevel::Invalid {
            Some(value.clone())
        } else {
            None
        }
    }

    fn emit_envelope(&self, envelope: &ScpEnvelope) {
        if let Some(callback) = self.envelope_callback.read().as_ref() {
            callback(envelope.clone());
        }
    }

    fn get_quorum_set(&self, node_id: &NodeId) -> Option<ScpQuorumSet> {
        let hash = hash_node_id(node_id);
        self.quorum_sets.get(&hash).map(|r| r.clone())
    }

    fn nominating_value(&self, slot_index: u64, value: &Value) {
        tracing::debug!(slot = slot_index, "Nominating value");
    }

    fn value_externalized(&self, slot_index: u64, value: &Value) {
        tracing::info!(slot = slot_index, "Value externalized in driver");
        if let Some(callback) = self.externalize_callback.read().as_ref() {
            callback(slot_index, value.clone());
        }
    }

    fn ballot_did_prepare(&self, slot_index: u64, ballot: &ScpBallot) {
        tracing::debug!(slot = slot_index, counter = ballot.counter, "Ballot prepared");
    }

    fn ballot_did_confirm(&self, slot_index: u64, ballot: &ScpBallot) {
        tracing::debug!(slot = slot_index, counter = ballot.counter, "Ballot confirmed");
    }

    fn slot_externalized(&self, slot_index: u64, value: &Value) {
        // Called after full externalization
    }

    fn compute_hash_node(
        &self,
        slot_index: u64,
        prev_value: &Value,
        is_priority: bool,
        round: u32,
        node_id: &NodeId,
    ) -> u64 {
        // Deterministic hash for nomination priority
        let mut hasher = sha2::Sha256::new();
        hasher.update(&slot_index.to_le_bytes());
        hasher.update(prev_value.as_slice());
        hasher.update(&[is_priority as u8]);
        hasher.update(&round.to_le_bytes());
        hasher.update(&node_id.to_xdr(stellar_xdr::Limits::none()).unwrap());
        hasher.update(self.network_passphrase.as_bytes());

        let result = hasher.finalize();
        u64::from_le_bytes(result[..8].try_into().unwrap())
    }

    fn compute_value_hash(
        &self,
        slot_index: u64,
        prev_value: &Value,
        round: u32,
        value: &Value,
    ) -> u64 {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&slot_index.to_le_bytes());
        hasher.update(prev_value.as_slice());
        hasher.update(&round.to_le_bytes());
        hasher.update(value.as_slice());

        let result = hasher.finalize();
        u64::from_le_bytes(result[..8].try_into().unwrap())
    }

    fn compute_timeout(&self, round: u32) -> std::time::Duration {
        // Exponential backoff: 1s, 2s, 4s, 8s... capped at 5 minutes
        let secs = std::cmp::min(1 << round, 300);
        std::time::Duration::from_secs(secs as u64)
    }

    fn sign_envelope(&self, envelope: &mut ScpEnvelope) {
        let data = envelope.statement.to_xdr(stellar_xdr::Limits::none()).unwrap();
        let signature = self.secret_key.sign(&data);
        envelope.signature = signature.as_bytes().to_vec().try_into().unwrap();
    }

    fn verify_envelope(&self, envelope: &ScpEnvelope) -> bool {
        // Get the public key from the node ID
        let node_id = &envelope.statement.node_id;
        if let Some(public_key) = extract_public_key(node_id) {
            let data = envelope.statement.to_xdr(stellar_xdr::Limits::none()).unwrap();
            public_key.verify(&data, &envelope.signature.into()).is_ok()
        } else {
            false
        }
    }
}
```

### 3.4 Transaction Queue

The Rust transaction queue supports lane-aware limits for both tx set
selection and queue admission. The config now includes:

- `max_dex_ops`: optional DEX ops cap for tx set selection (classic lane).
- `max_classic_bytes`: optional classic byte allowance for tx set selection.
- DEX lane byte allowance always uses the classic byte allowance (MAX_CLASSIC_BYTE_ALLOWANCE).
- `max_soroban_resources`: optional Soroban resource cap for tx set selection.
- `max_soroban_bytes`: optional Soroban byte allowance for tx set selection (applied even if no other Soroban resource limits are set).
- `max_queue_dex_ops`: optional DEX ops cap at queue admission with fee-based eviction.
- `max_queue_soroban_resources`: optional Soroban resource cap at queue admission with fee-based eviction.
- `max_queue_ops`: optional total ops cap at queue admission with fee-based eviction.
- `max_queue_classic_bytes`: optional classic byte allowance for queue admission with fee-based eviction.

```rust
use stellar_xdr::curr::TransactionEnvelope;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionQueueResult {
    Added,
    Duplicate,
    TooOld,
    TooNew,
    InvalidSeqNum,
    InsufficientFee,
    Full,
    Invalid(String),
}

/// Queue of pending transactions
pub struct TransactionQueue {
    /// Transactions by source account
    by_account: HashMap<AccountId, Vec<TransactionEnvelope>>,
    /// All transactions by hash
    by_hash: HashMap<Hash256, TransactionEnvelope>,
    /// Maximum queue size
    max_size: usize,
    /// Fee statistics for surge pricing
    fee_stats: FeeStats,
}

impl TransactionQueue {
    pub fn new() -> Self {
        Self {
            by_account: HashMap::new(),
            by_hash: HashMap::new(),
            max_size: 10000,
            fee_stats: FeeStats::new(),
        }
    }

    pub fn try_add(
        &mut self,
        tx: TransactionEnvelope,
        ledger_manager: &LedgerManager,
    ) -> TransactionQueueResult {
        let hash = Hash256::hash_xdr(&tx).unwrap();

        // Check duplicate
        if self.by_hash.contains_key(&hash) {
            return TransactionQueueResult::Duplicate;
        }

        // Check queue size
        if self.by_hash.len() >= self.max_size {
            // Could evict low-fee transactions
            return TransactionQueueResult::Full;
        }

        // Validate sequence number
        let source = get_source_account(&tx);
        let account = ledger_manager.load_account(&source);

        // Check sequence number
        // Check fee
        // Check signatures (basic validation)

        // Add to queue
        self.by_hash.insert(hash, tx.clone());
        self.by_account.entry(source).or_default().push(tx);

        TransactionQueueResult::Added
    }

    pub fn get_transaction_set(&self, ledger_seq: u32) -> TransactionSet {
        // Sort transactions by fee (highest first)
        // Apply per-account limits
        // Build transaction set

        let mut txs: Vec<_> = self.by_hash.values().cloned().collect();
        txs.sort_by(|a, b| compare_tx_fee(b, a)); // Descending fee

        TransactionSet { txs }
    }

    pub fn remove_applied(&mut self, tx_hashes: &[Hash256]) {
        for hash in tx_hashes {
            if let Some(tx) = self.by_hash.remove(hash) {
                let source = get_source_account(&tx);
                if let Some(account_txs) = self.by_account.get_mut(&source) {
                    account_txs.retain(|t| Hash256::hash_xdr(t).unwrap() != *hash);
                }
            }
        }
    }
}
```

### 3.5 Pending Envelopes

```rust
/// Buffer for SCP envelopes received before we're ready to process them
pub struct PendingEnvelopes {
    envelopes: parking_lot::RwLock<HashMap<u64, Vec<ScpEnvelope>>>,
    max_per_slot: usize,
    max_slots: usize,
}

impl PendingEnvelopes {
    pub fn new() -> Self {
        Self {
            envelopes: parking_lot::RwLock::new(HashMap::new()),
            max_per_slot: 1000,
            max_slots: 10,
        }
    }

    pub fn add(&self, envelope: ScpEnvelope) {
        let slot = envelope.statement.slot_index;
        let mut envelopes = self.envelopes.write();

        // Clean up old slots
        if envelopes.len() >= self.max_slots {
            let min_slot = envelopes.keys().min().copied().unwrap_or(0);
            envelopes.remove(&min_slot);
        }

        let slot_envelopes = envelopes.entry(slot).or_default();
        if slot_envelopes.len() < self.max_per_slot {
            slot_envelopes.push(envelope);
        }
    }

    pub fn pop(&self, slot: u64) -> Vec<ScpEnvelope> {
        self.envelopes.write().remove(&slot).unwrap_or_default()
    }
}
```

## 4. Ledger Close Timing

```rust
/// Constants for ledger timing
pub mod timing {
    use std::time::Duration;

    /// Target ledger close time
    pub const EXPECTED_LEDGER_TIME: Duration = Duration::from_secs(5);

    /// Maximum close time in the future
    pub const MAX_TIME_DRIFT: Duration = Duration::from_secs(60);

    /// Timeout multiplier for slow rounds
    pub fn nomination_timeout(round: u32) -> Duration {
        Duration::from_secs(std::cmp::min(1 << round, 300))
    }
}
```

## 5. Tests to Port from stellar-core

From `src/herder/test/`:
- Transaction queue operations
- Envelope buffering
- Value validation
- Transaction set creation
- Consensus integration tests

## 6. Error Types

```rust
#[derive(Error, Debug)]
pub enum HerderError {
    #[error("Not tracking")]
    NotTracking,

    #[error("Invalid value: {0}")]
    InvalidValue(String),

    #[error("Missing transaction set: {0}")]
    MissingTxSet(Hash256),

    #[error("Invalid envelope: {0}")]
    InvalidEnvelope(String),

    #[error("Ledger error: {0}")]
    Ledger(#[from] LedgerError),

    #[error("SCP error: {0}")]
    Scp(String),
}
```
