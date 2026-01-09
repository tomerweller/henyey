# stellar-core-ledger

Ledger state management and ledger close pipeline for rs-stellar-core.

## Overview

This crate provides the core ledger state management for the Stellar network. It coordinates between transaction execution, bucket list updates, and ledger metadata generation to process ledger closes.

### Key Responsibilities

- **Ledger Close Pipeline**: Orchestrates the complete ledger close process from receiving externalized transaction sets to committing the new state
- **State Management**: Maintains ledger entries through the bucket list Merkle tree
- **Transaction Execution**: Bridges to `stellar-core-tx` for per-transaction processing
- **Invariant Validation**: Enforces ledger consistency rules after each close
- **Snapshot Management**: Provides consistent point-in-time views for concurrent access

## Architecture

```
                 +-----------------+
                 | LedgerManager   |
                 |  (coordinator)  |
                 +--------+--------+
                          |
          +---------------+---------------+
          |               |               |
   +------+------+ +------+------+ +------+------+
   | BucketList  | | SnapshotMgr | | InvariantMgr|
   | (Merkle tree)| | (point-in-  | | (validation)|
   |             | | time views) | |             |
   +-------------+ +-------------+ +-------------+
          |
   +------+------+
   | LedgerClose |
   | Context     |
   | (per-close) |
   +------+------+
          |
   +------+------+
   | Transaction |
   | Executor    |
   +-------------+
```

## Key Types

### Core Types

| Type | Description |
|------|-------------|
| `LedgerManager` | Central coordinator for all ledger operations |
| `LedgerCloseContext` | Context for processing a single ledger close |
| `LedgerCloseData` | Input data from SCP (tx set, close time, upgrades) |
| `LedgerCloseResult` | Output from a successful close (header, results, meta) |

### State Types

| Type | Description |
|------|-------------|
| `LedgerDelta` | Accumulator for state changes during close |
| `EntryChange` | Single entry change (create/update/delete) |
| `LedgerSnapshot` | Immutable point-in-time view of state |
| `SnapshotHandle` | Thread-safe wrapper with lazy loading support |

### Utility Types

| Type | Description |
|------|-------------|
| `LedgerInfo` | Simplified view of ledger header fields |
| `TransactionSetVariant` | Classic or generalized transaction set |
| `LedgerCloseStats` | Statistics from ledger processing |

## Usage

### Basic Ledger Close

```rust
use stellar_core_ledger::{LedgerManager, LedgerCloseData, TransactionSetVariant};

// Create and initialize the ledger manager
let manager = LedgerManager::new(db, network_passphrase);
manager.initialize_from_buckets(bucket_list, None, header)?;

// Begin a ledger close with externalized data
let close_data = LedgerCloseData::new(
    ledger_seq,
    tx_set,
    close_time,
    prev_ledger_hash,
);
let mut ctx = manager.begin_close(close_data)?;

// Apply all transactions
let results = ctx.apply_transactions()?;

// Commit the ledger
let result = ctx.commit()?;
println!("Closed ledger {} with hash {}",
    result.header.ledger_seq,
    result.header_hash.to_hex());
```

### Fee and Reserve Calculations

```rust
use stellar_core_ledger::{fees, reserves};

// Calculate transaction fee
let fee = fees::calculate_fee(&tx, base_fee);

// Check if account can pay fee
if fees::can_afford_fee(&account, fee) {
    // Process transaction
}

// Calculate minimum balance
let min_balance = reserves::minimum_balance(&account, base_reserve);

// Check available balance for sending
let available = reserves::available_to_send(&account, base_reserve);
```

### Working with Snapshots

```rust
use stellar_core_ledger::{SnapshotBuilder, SnapshotHandle};

// Build a snapshot with specific entries
let snapshot = SnapshotBuilder::new(ledger_seq)
    .with_header(header, header_hash)
    .add_entry(key, entry)?
    .build()?;

// Create a handle with lazy loading
let handle = SnapshotHandle::with_lookup(snapshot, bucket_list_lookup);

// Query entries (falls back to bucket list if not cached)
let entry = handle.get_entry(&key)?;
```

## Module Organization

| Module | Description |
|--------|-------------|
| `lib.rs` | Public API and convenience types |
| `manager.rs` | `LedgerManager` and `LedgerCloseContext` |
| `close.rs` | Close data structures and transaction set handling |
| `execution.rs` | Transaction execution integration |
| `delta.rs` | Change tracking and coalescing |
| `header.rs` | Header utilities (hash, skip list, chain verification) |
| `snapshot.rs` | Point-in-time state snapshots |
| `error.rs` | Error types for ledger operations |

## Protocol Support

This crate supports all Stellar protocol versions with special handling for:

- **Protocol 18**: Liquidity pools (AMM) with constant product invariant checking
- **Protocol 20**: Soroban smart contracts with resource metering and rent
- **Protocol 23**: Hot archive bucket list for state archival

## Design Notes

### Change Coalescing

When multiple operations affect the same entry within a ledger, changes are coalesced:

- Create + Update = Create (with final value)
- Create + Delete = No change
- Update + Update = Update (original previous, final current)
- Update + Delete = Delete

### Thread Safety

All public APIs are thread-safe:

- `LedgerManager` uses internal RwLocks for state protection
- `SnapshotHandle` wraps snapshots in Arc for efficient sharing
- `SnapshotManager` handles concurrent registration/lookup

### Determinism

All operations are deterministic to ensure consensus:

- Entry changes are tracked in insertion order
- Transaction ordering follows protocol rules
- Hash computations use canonical XDR encoding

## Upstream Mapping

This crate corresponds to the following C++ stellar-core components:

| Rust | C++ |
|------|-----|
| `LedgerManager` | `src/ledger/LedgerManager*` |
| `LedgerCloseContext` | `src/ledger/LedgerTxn*` |
| `LedgerDelta` | `src/ledger/LedgerDelta.*` |
| Header utilities | `src/ledger/LedgerHeaderUtils.*` |
| Close metadata | `src/ledger/LedgerCloseMeta*` |

## C++ Parity Status

See [PARITY_STATUS.md](PARITY_STATUS.md) for detailed C++ parity analysis.
