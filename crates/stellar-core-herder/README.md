# stellar-core-herder

SCP coordination and ledger close orchestration for rs-stellar-core.

## Overview

The Herder is the central coordinator that:

- Drives the SCP consensus protocol
- Collects transactions from the overlay network
- Proposes transaction sets for consensus
- Triggers ledger close when consensus is reached
- Manages the transition between ledgers

## Architecture

```
+------------------+
|     Herder       |
|------------------|
| - state          |  <-- HerderState (Booting/Syncing/Tracking)
| - tx_queue       |  <-- TransactionQueue
| - pending        |  <-- PendingEnvelopes
| - scp_driver     |  <-- ScpDriver
+------------------+
        |
        v
+------------------+     +------------------+
|   SCP Protocol   | <-> |  Overlay Network |
+------------------+     +------------------+
        |
        v
+------------------+
|  Ledger Manager  |
+------------------+
```

## State Machine

The Herder progresses through states:

| State | Description |
|-------|-------------|
| `Booting` | Initial state, not connected to network |
| `Syncing` | Catching up with the network via history archives |
| `Tracking` | Synchronized and following consensus |

## Usage

### Creating a Herder

```rust
use stellar_core_herder::{Herder, HerderConfig};

let config = HerderConfig {
    max_pending_transactions: 1000,
    is_validator: false,
    ledger_close_time: 5,
    max_tx_set_size: 1000,
    ..Default::default()
};

let herder = Herder::new(config);
```

### State Transitions

```rust
// Initial state
assert_eq!(herder.state(), HerderState::Booting);

// Start syncing (when catchup begins)
herder.start_syncing();
assert_eq!(herder.state(), HerderState::Syncing);

// After catchup completes
herder.bootstrap(ledger_seq);
assert_eq!(herder.state(), HerderState::Tracking);
```

### Processing Messages

```rust
// Process incoming SCP envelopes
let state = herder.receive_scp_envelope(envelope);

// Process incoming transactions
let result = herder.receive_transaction(tx);
```

### For Validators

```rust
use stellar_core_herder::Herder;
use stellar_core_crypto::SecretKey;

// Create herder with signing capability
let keypair = SecretKey::generate();
let herder = Herder::with_secret_key(config, keypair);

// Trigger SCP nomination
herder.trigger_next_ledger();
```

## Key Types

### HerderConfig

Configuration for the Herder:

```rust
let config = HerderConfig {
    max_pending_transactions: 1000,
    is_validator: false,
    ledger_close_time: 5,  // seconds
    node_public_key: public_key,
    network_id: network_id,
    max_externalized_slots: 12,
    max_tx_set_size: 1000,
    pending_config: PendingConfig::default(),
    tx_queue_config: TxQueueConfig::default(),
    local_quorum_set: quorum_set,
};
```

### TransactionQueue

Manages pending transactions:

```rust
use stellar_core_herder::{TransactionQueue, TxQueueResult};

let queue = TransactionQueue::new(config);

// Add a transaction
let result = queue.add(tx);
match result {
    TxQueueResult::Added => { /* Success */ }
    TxQueueResult::Duplicate => { /* Already have it */ }
    TxQueueResult::Full => { /* Queue is full */ }
}

// Get transactions for a set
let txs = queue.get_transactions_for_set(max_count);
```

### PendingEnvelopes

Buffers SCP envelopes:

```rust
use stellar_core_herder::PendingEnvelopes;

let pending = PendingEnvelopes::new(config);

// Add an envelope for future processing
pending.add(envelope);

// Get envelopes for a slot
let envelopes = pending.get_slot_envelopes(slot_index);
```

### HerderCallback

Trait for Herder events:

```rust
#[async_trait]
trait HerderCallback {
    async fn close_ledger(
        &self,
        ledger_seq: u32,
        tx_set: Vec<TransactionEnvelope>,
        close_time: u64,
    ) -> Result<Hash256>;

    async fn validate_tx_set(&self, tx_set_hash: &Hash256) -> bool;

    async fn broadcast_scp_message(&self, envelope: ScpEnvelope);
}
```

## SCP Driver

The Herder includes an SCP driver that:

- Validates proposed values
- Combines candidate values
- Emits SCP envelopes
- Handles externalization

```rust
use stellar_core_herder::ScpDriver;

let driver = ScpDriver::new(config);

// Validate a value
let validation = driver.validate_value_impl(slot, &value);

// Get externalized slots
let slot = driver.get_externalized_slot(slot_index);
```

## Transaction Set

A set of transactions for a ledger:

```rust
use stellar_core_herder::TransactionSet;

let tx_set = TransactionSet::new(transactions);

// Get the hash
let hash = tx_set.hash();

// Get transaction count
let count = tx_set.len();
```

## Ledger Close Info

Information about a closed ledger:

```rust
let info = LedgerCloseInfo {
    ledger_seq: 1000,
    tx_set_hash: hash,
    close_time: 1234567890,
};
```

## For Testnet Sync

After catchup completes:

1. Call `herder.bootstrap(ledger_seq)` to transition to Tracking
2. SCP envelopes from overlay are processed via `receive_scp_envelope`
3. Externalized values are tracked to keep the node synced

## Dependencies

- `stellar-core-scp` - SCP implementation
- `stellar-xdr` - Message types
- `tokio` - Async runtime

## License

Apache 2.0
