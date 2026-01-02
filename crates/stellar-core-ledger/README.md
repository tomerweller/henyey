# stellar-core-ledger

Ledger management for rs-stellar-core.

## Overview

This crate handles ledger state management, including:

- Ledger header construction and validation
- Ledger state snapshots (via BucketList integration)
- Ledger close operations
- Fee and reserve calculations

## Ledger Close Process

1. Receive the externalized transaction set from Herder
2. Apply each transaction to the ledger state
3. Update the BucketList with state changes
4. Compute the new ledger header hash
5. Persist the ledger and prepare for the next round

## State Model

Ledger state consists of ledger entries:

| Entry Type | Description |
|------------|-------------|
| Accounts | User accounts |
| Trustlines | Asset trust lines |
| Offers | DEX offers |
| Data entries | Account data |
| Claimable balances | Pending claims |
| Liquidity pools | AMM pools |
| Contract data | Soroban state |
| Contract code | Soroban WASM |

## Usage

### Creating a Ledger Manager

```rust
use stellar_core_ledger::{LedgerManager, LedgerManagerConfig};

let config = LedgerManagerConfig {
    max_snapshots: 10,
    validate_bucket_hash: true,
    persist_to_db: true,
    base_reserve: 5_000_000,  // 0.5 XLM
    ..Default::default()
};

let manager = LedgerManager::new(db, bucket_manager, network_passphrase);
```

### Initializing from Catchup

```rust
// After catchup, initialize with the bucket list and header
manager.initialize_from_buckets(bucket_list, header)?;
```

### Closing a Ledger

```rust
use stellar_core_ledger::{LedgerCloseData, TransactionSetVariant};

// Create close data
let close_data = LedgerCloseData::new(
    ledger_seq,
    tx_set,
    close_time,
    previous_ledger_hash,
);

// Begin close
let mut ctx = manager.begin_close(close_data)?;

// Apply transactions and record changes
ctx.record_create(new_entry)?;
ctx.record_update(old_entry, new_entry)?;
ctx.record_delete(key)?;

// Commit the ledger
let result = ctx.commit()?;
println!("Closed ledger {} with hash {}", result.sequence, result.hash);
```
Classic transaction set hashes use the legacy contents hash
(previous ledger hash concatenated with each transaction’s XDR).

## Key Types

### LedgerManager

Main ledger state manager:

```rust
let manager = LedgerManager::new(db, bucket_manager, passphrase);

// Get current ledger info
let info = manager.current_ledger_info();

// Get an account
let account = manager.get_account(&account_id)?;

// Get a trustline
let tl = manager.get_trustline(&account_id, &asset)?;
```

### LedgerCloseContext

Context for closing a ledger:

```rust
let mut ctx = manager.begin_close(close_data)?;

// Record state changes
ctx.record_create(entry)?;
ctx.record_update(old, new)?;
ctx.record_delete(key)?;

// Access current state
let account = ctx.get_account(&id)?;

// Commit
let result = ctx.commit()?;
```

### LedgerDelta

Tracks changes during ledger close:

```rust
use stellar_core_ledger::LedgerDelta;

let mut delta = LedgerDelta::new(ledger_seq);

// Check for changes
assert!(!delta.has_changes());

// Get created/updated/deleted entries
let created = delta.created_entries();
let updated = delta.updated_entries();
let deleted = delta.deleted_keys();
```

### LedgerInfo

Simplified view of ledger header:

```rust
let info = LedgerInfo::from(&header);

println!("Sequence: {}", info.sequence);
println!("Close time: {}", info.close_time);
println!("Base fee: {}", info.base_fee);
println!("Base reserve: {}", info.base_reserve);
```

## Fee Calculations

```rust
use stellar_core_ledger::fees;

// Calculate transaction fee
let fee = fees::calculate_fee(&tx, base_fee);

// Calculate envelope fee
let fee = fees::calculate_envelope_fee(&envelope, base_fee);

// Check if account can afford fee
let can_afford = fees::can_afford_fee(&account, fee);

// Get available balance
let available = fees::available_balance(&account);
```

## Reserve Calculations

```rust
use stellar_core_ledger::reserves;

// Calculate minimum balance
let min_balance = reserves::minimum_balance(&account, base_reserve);

// Get available to send
let available = reserves::available_to_send(&account, base_reserve);

// Get available to receive
let available = reserves::available_to_receive(&account);

// Check if can add sub-entry
let can_add = reserves::can_add_sub_entry(&account, base_reserve);

// Get liabilities
let selling = reserves::selling_liabilities(&account);
let buying = reserves::buying_liabilities(&account);
```

## Header Utilities

```rust
use stellar_core_ledger::header;

// Compute header hash
let hash = header::compute_header_hash(&ledger_header)?;

// Create next header
let next = header::create_next_header(&prev_header, tx_set_hash, close_time)?;

// Verify header chain
header::verify_header_chain(&headers)?;

// Get protocol version
let version = header::protocol_version(&header);
```

## Snapshots

```rust
use stellar_core_ledger::{SnapshotManager, LedgerSnapshot};

let snapshot_manager = SnapshotManager::new(max_snapshots);

// Create a snapshot
let snapshot = snapshot_manager.create_snapshot(&bucket_list, &header)?;

// Get snapshot by sequence
let snapshot = snapshot_manager.get_snapshot(ledger_seq)?;

// List available snapshots
let snapshots = snapshot_manager.list_snapshots();
```

## Constants

```rust
use stellar_core_ledger::reserves::STROOPS_PER_XLM;

assert_eq!(STROOPS_PER_XLM, 10_000_000);
```

## Dependencies

- `stellar-core-bucket` - BucketList integration
- `stellar-core-db` - Persistence
- `stellar-xdr` - Ledger types
- `sha2` - Header hashing

## License

Apache 2.0
