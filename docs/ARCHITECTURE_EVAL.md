# Architecture

This document describes the high-level architecture of rs-stellar-core.

## Overview

rs-stellar-core is organized as a Cargo workspace with 14 crates following a layered architecture. Dependencies flow strictly downward with no circular dependencies.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            ORCHESTRATION LAYER                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ rs-stellar-core (CLI)              stellar-core-app (App coordinator)   ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            COORDINATION LAYER                                │
│  ┌─────────────────────────┐    ┌──────────────────────────────────────────┐│
│  │ stellar-core-herder     │    │ stellar-core-historywork                 ││
│  │ (consensus coordinator) │    │ (history work scheduling)                ││
│  └─────────────────────────┘    └──────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DOMAIN LAYER                                    │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐ │
│  │ stellar-core- │  │ stellar-core- │  │ stellar-core- │  │ stellar-core- │ │
│  │ scp           │  │ tx            │  │ bucket        │  │ ledger        │ │
│  │ (consensus)   │  │ (execution)   │  │ (state store) │  │ (close logic) │ │
│  └───────────────┘  └───────────────┘  └───────────────┘  └───────────────┘ │
│  ┌───────────────┐                                                          │
│  │ stellar-core- │                                                          │
│  │ history       │                                                          │
│  │ (archives)    │                                                          │
│  └───────────────┘                                                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          INFRASTRUCTURE LAYER                                │
│  ┌─────────────────────────────────┐    ┌──────────────────────────────────┐│
│  │ stellar-core-db                 │    │ stellar-core-overlay             ││
│  │ (SQLite persistence)            │    │ (P2P networking)                 ││
│  └─────────────────────────────────┘    └──────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           FOUNDATION LAYER                                   │
│  ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────────────┐│
│  │ stellar-core-     │  │ stellar-core-     │  │ stellar-core-work         ││
│  │ common            │  │ crypto            │  │ (async scheduler)         ││
│  │ (shared types)    │  │ (cryptography)    │  │                           ││
│  └───────────────────┘  └───────────────────┘  └───────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

## Crate Dependency Graph

Internal dependencies (excluding external crates):

| Crate | Dependencies |
|-------|--------------|
| stellar-core-common | (none) |
| stellar-core-crypto | common |
| stellar-core-work | (none) |
| stellar-core-db | common |
| stellar-core-overlay | common, crypto |
| stellar-core-scp | common, crypto |
| stellar-core-tx | common, crypto, db |
| stellar-core-bucket | common, crypto, db |
| stellar-core-ledger | common, crypto, db, bucket, tx |
| stellar-core-history | common, crypto, db, bucket, ledger, tx |
| stellar-core-historywork | common, history, ledger, work |
| stellar-core-herder | common, crypto, db, scp, overlay, ledger, tx |
| stellar-core-app | (all of the above) |
| rs-stellar-core | app (CLI binary) |

## Layer Responsibilities

### Foundation Layer

**stellar-core-common** - Shared types and utilities with no I/O dependencies
- `Hash256`, `NetworkId`, `Config` types
- Protocol version utilities
- Resource accounting for surge pricing
- Metadata normalization
- Math utilities (bigDivide, saturating ops)

**stellar-core-crypto** - Pure Rust cryptographic primitives (no libsodium)
- Ed25519 signing and verification
- SHA-256 and BLAKE2 hashing
- HMAC-SHA256, HKDF key derivation
- StrKey encoding (G.../S.../C... addresses)
- SipHash for deterministic ordering
- Curve25519 ECDH for P2P authentication
- Sealed boxes for survey encryption

**stellar-core-work** - Async work scheduler
- `Work` trait for composable async tasks
- DAG-based dependency resolution
- Retry logic and cancellation propagation

### Infrastructure Layer

**stellar-core-db** - SQLite persistence
- Connection pooling via r2d2
- Schema migrations
- Trait-based query API: `LedgerQueries`, `ScpQueries`, `PeerQueries`
- Stores: ledger headers, transactions, SCP state, peer records

**stellar-core-overlay** - P2P networking
- X25519/HMAC-SHA256 authenticated connections
- FloodGate for duplicate message detection
- TCP with length-prefixed XDR encoding
- Peer ban management

### Domain Layer

**stellar-core-scp** - Stellar Consensus Protocol implementation
- Ballot tracking and nomination phases
- Quorum intersection validation
- Slot-based ledger advancement

**stellar-core-tx** - Transaction execution (largest crate, 44 files)
- Transaction frame validation
- All operation types (payments, offers, Soroban, etc.)
- Fee and fee-bump handling
- Soroban WASM contract execution
- `Savepoint` mechanism for per-operation state rollback (matches C++ nested `LedgerTxn`)
- `LedgerStateManager` with savepoint-based rollback for all entry types

**stellar-core-bucket** - BucketList state management
- 11-level bucket list with live/dead/init entries
- CAP-0020 merge semantics
- Bloom filters for negative lookups
- Hot archive for Soroban state eviction
- Disk-backed bucket storage

**stellar-core-ledger** - Ledger close pipeline
- `LedgerManager` orchestration
- `LedgerDelta` for accumulating state changes
- Transaction application and fee charging
- Per-operation savepoints in the execution loop (wraps each operation with `create_savepoint`/`rollback_to_savepoint` to match C++ nested `LedgerTxn` behavior)
- Bucket list merging and Merkle root computation
- Inline invariant validation during ledger close

**stellar-core-history** - History archive operations
- Catchup from history archives
- Replay verification
- Checkpoint publishing

### Coordination Layer

**stellar-core-herder** - Consensus coordination
- `TransactionQueue` with surge pricing
- `PendingEnvelopes` for future SCP slots
- SCP driver callback orchestration
- State machine: Booting → Syncing → Tracking ↔ Validating

**stellar-core-historywork** - History work scheduling
- Work-based pipeline for history operations
- Integrates WorkScheduler with CatchupManager

### Orchestration Layer

**stellar-core-app** - Application coordinator
- Central `App` owning all subsystems
- Lifecycle: Initialize → Catchup → Run → Shutdown
- Message routing from Overlay → Herder → Ledger
- Survey management for network topology

**rs-stellar-core** - CLI binary
- Command dispatch: run, catchup, new-db, verify-history, etc.
- Configuration loading and validation
- Logging initialization

## Data Flow

### Network to Ledger Close

```
NETWORK (Overlay)
    │
    │  Receives: SCP Envelopes + Transactions
    ▼
HERDER (Consensus Coordinator)
    ├─→ TransactionQueue (pending transactions)
    ├─→ PendingEnvelopes (future SCP slots)
    └─→ SCP Driver (consensus callbacks)
    │
    │  Consensus reached on LedgerCloseData
    ▼
LEDGER MANAGER
    ├─→ LedgerCloseContext (transactional context)
    ├─→ Transaction Execution (stellar-core-tx)
    │     └─→ Per-operation savepoints (rollback on failure)
    ├─→ LedgerDelta (accumulate state changes)
    └─→ BucketList Application
        ├─→ Merkle root computation
        └─→ Disk persistence
    │
    ▼
DATABASE PERSISTENCE
    └─→ Ledger headers, transactions, SCP messages
    │
    ▼
HISTORY ARCHIVE (Async)
    └─→ Checkpoint publication via HistoryWork
```

### Key Data Structures

1. `TransactionEnvelope` - Network input
2. `TransactionFrame` - Validation wrapper with cached hash
3. `LedgerCloseData` - SCP output (tx set hash, close time, etc.)
4. `LedgerDelta` - Accumulator for ledger state changes
5. `Savepoint` - State checkpoint for per-operation rollback (captures all entry types and delta lengths)
6. `LedgerCloseMeta` - Result metadata for history
7. `BucketList` - Persistent Merkle state
8. `LedgerHeader` - Consensus-confirmed state summary

## Design Principles

### Clean Layering
- Dependencies flow strictly downward
- No circular dependencies (verified via cargo tree)
- Each layer can be tested independently

### Pure Rust Cryptography
- No C dependencies (libsodium-free)
- All crypto is deterministic and bit-compatible with C++ stellar-core
- Keys are zeroized on drop via `zeroize` crate

### Trait-Based Composition
- `Work` trait for async task composition
- Query traits for database abstraction
- `HerderCallback` for SCP integration

### Async-First Design
- Tokio runtime throughout
- Non-blocking I/O for network and database
- Cancellation propagation via work scheduler

### Per-Operation Savepoints
- Each operation in a transaction is wrapped with a savepoint before execution
- Failed operations have all state mutations rolled back via `rollback_to_savepoint()`
- This matches C++ stellar-core's nested `LedgerTxn` commit/rollback behavior
- The `Savepoint` struct captures entry maps, delta vector lengths, and created entry sets
- Simpler than C++'s general-purpose nested transactions while providing the same isolation guarantees for the operation execution loop

### Determinism
- All observable behavior matches C++ stellar-core
- Byte-for-byte compatible hashes and signatures
- Identical sorting and tie-breaking rules

## File Size Analysis

Largest files (potential complexity hotspots):

| File | Lines | Notes |
|------|-------|-------|
| app.rs | ~6,600 | Could benefit from splitting |
| main.rs | ~4,400 | CLI binary, acceptable |
| execution.rs | ~4,300 | Ledger close, cohesive |
| tx_queue.rs | ~4,000 | Transaction queue, cohesive |
| ballot.rs | ~3,900 | SCP consensus, complex by nature |

## Potential Improvements

### High Priority

1. **Split app.rs into sub-modules**
   - `message_router.rs` - SCP/TX message handling
   - `ledger_closer.rs` - Ledger close coordination
   - `survey_manager.rs` - Network topology
   - `http_server.rs` - Status endpoints

2. **Error handling audit**
   - Review unwrap/expect usage in hot paths
   - Keep assertions in initialization and test code
   - Convert to proper error handling in ledger close pipeline

### Medium Priority

1. **Extend WorkScheduler usage**
   - Bucket list merging operations
   - Archive download operations
   - Peer connection establishment

2. **Document cross-crate interfaces**
   - Add interface documentation at crate boundaries
   - Document callback contracts

### Low Priority

1. **Consider merging stellar-core-historywork into stellar-core-history**
   - Single-file crate, closely related functionality

2. **Soroban version abstraction**
   - Currently works (p24/p25 at init), could be cleaner

## Testing Strategy

- **Unit tests**: Alongside code in each module
- **Integration tests**: In `crates/*/tests/` directories
- **Test naming**: Behavior-focused, e.g., `test_execute_transaction_min_seq_num_precondition`
- **Test utilities**: Shared fixtures and helpers in test modules

Run all tests:
```bash
cargo test --all
```

Run specific crate tests:
```bash
cargo test -p stellar-core-ledger
```
