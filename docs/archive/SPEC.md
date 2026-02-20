# henyey Specification

**Version:** 0.1.0
**Target Protocol:** v25.x (Protocol 24+ behavior)
**Network:** Testnet primary; mainnet readiness is a later milestone

## 1. Overview

henyey is a Rust implementation of Stellar Core intended for research and education. It targets deterministic, observable behavior compatible with stellar-core v25.x, with SQLite-only persistence and no production hardening.

This project is **not** production-grade.

### 1.1 Goals

1. Deterministic parity with stellar-core v25.x for observable behavior.
2. Modular 1:1 mapping between stellar-core subsystems and crates.
3. Protocol 24+ only to reduce legacy complexity.
4. Educational, auditable Rust implementation.

### 1.2 Non-Goals

- Legacy protocol support (1–23).
- PostgreSQL support (SQLite only).
- Full metrics parity with stellar-core.
- Production deployment or operational hardening.
- **Local state durability.** A crashed node recovers by catching up from a
  published history checkpoint, not from local database state. This means
  SQL tables do not need to survive restarts and the database is treated as
  an ephemeral cache rather than a durable store.

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                           henyey                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────┐  ┌─────────┐  ┌──────────┐  ┌──────────┐             │
│  │   CLI   │  │  Config │  │ Logging  │  │  Admin   │             │
│  └────┬────┘  └────┬────┘  └────┬─────┘  └────┬─────┘             │
│       │            │            │             │                   │
│  ┌────┴────────────┴────────────┴─────────────┴───────┐           │
│  │                      Application                   │           │
│  └──────────────────────────┬─────────────────────────┘           │
│                             │                                     │
│  ┌──────────────────────────┴───────────────────────────┐         │
│  │                         Herder                        │         │
│  └──────┬─────────────────┬─────────────────────┬───────┘         │
│         │                 │                     │                 │
│  ┌──────┴──────┐   ┌──────┴──────┐      ┌──────┴──────┐           │
│  │     SCP     │   │   Ledger    │      │  Overlay    │           │
│  └─────────────┘   └──────┬──────┘      └──────┬──────┘           │
│                           │                    │                  │
│  ┌────────────────────────┴────────────────────┴───────────────┐  │
│  │                    Transaction Processing                  │  │
│  └──────────────────────────┬──────────────────────────────────┘  │
│                             │                                     │
│  ┌──────────────────────────┴───────────────────────────────┐    │
│  │                      Storage Layer                       │    │
│  │  BucketList  |  Database (SQLite)  |  History Archives    │    │
│  └───────────────────────────────────────────────────────────┘    │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                      Foundation Layer                       │  │
│  │  Crypto  |  XDR (stellar-xdr)  |  Utils                      │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## 3. Workspace Layout

```
henyey/
├── Cargo.toml                 # Workspace root
├── README.md                  # Project overview
├── docs/                      # Specifications and architecture docs
│   ├── archive/SPEC.md        # This document (archived)
│   ├── spec-eval/             # Spec evaluation reports
│   └── stellar-specs/         # Protocol specifications
├── configs/                   # Example configs
└── crates/                    # Subsystem crates (14 crates)
```

Each crate contains a README with subsystem documentation and stellar-core mapping.

### 3.1 Module Mapping to stellar-core

| henyey crate | stellar-core directory | Description |
|-----------------------|------------------------|-------------|
| `henyey-app` | `src/main/` | Application orchestration and lifecycle |
| `henyey-scp` | `src/scp/` | Stellar Consensus Protocol |
| `henyey-herder` | `src/herder/` | SCP coordination, slot management |
| `henyey-overlay` | `src/overlay/` | P2P networking |
| `henyey-ledger` | `src/ledger/` | Ledger state, closing |
| `henyey-bucket` | `src/bucket/` | BucketList storage |
| `henyey-history` | `src/history/` | Archive publish/catchup |
| `henyey-tx` | `src/transactions/` | Transaction validation/execution |
| `henyey-crypto` | `src/crypto/` | Hashing, signatures, keys |
| `henyey-db` | `src/database/` | SQLite persistence |
| `henyey-common` | `src/util/` | Shared utilities |
| `henyey-work` | `src/work/` | Async work scheduler |
| `henyey-historywork` | `src/historywork/` | History work scheduling |
| `henyey` | `src/main/` | CLI binary |

## 4. Dependencies

### 4.1 Stellar Rust Crates

- `stellar-xdr` (v25)
- `soroban-env-host` (Protocol 24+ compatible)
- `soroban-env-common`

### 4.2 Third-Party Crates (selected)

- `tokio` (async runtime)
- `rusqlite` (SQLite)
- `ed25519-dalek`, `sha2`, `siphasher` (crypto)
- `tracing` (logging)
- `clap` (CLI)
- `reqwest` (history archive HTTP)
- `serde` / `serde_json` (serialization)

## 5. Protocol Support

- Protocol 24+ behavior only (targeting v25.x).
- Soroban operations supported via host integration.

## 5.1 Transaction Execution and State Management

Transaction execution uses a per-operation savepoint mechanism to match stellar-core's nested `LedgerTxn` behavior:

- **Savepoint creation**: Before each operation executes, a savepoint captures the current state (`LedgerStateManager::create_savepoint()` in `henyey-tx`).
- **Automatic rollback**: If an operation fails, `rollback_to_savepoint()` reverts all state mutations from that operation so subsequent operations see clean state.
- **Successful operations**: Keep their mutations in place without rollback.

This design replaces stellar-core's general-purpose nested `LedgerTxn` transactions with a simpler, targeted savepoint model. The savepoint captures all entry types (accounts, trustlines, offers, contract data, etc.) and their associated delta tracking, providing the same per-operation isolation guarantees as the stellar-core implementation.

The execution loop integration lives in `henyey-ledger` (`execution.rs`), while the `Savepoint` data structure and `LedgerStateManager` rollback methods are in `henyey-tx` (`state.rs`).

## 6. Testing Strategy

- Unit and integration tests live within each crate (`crates/*/src` and `crates/*/tests`).
- stellar-core test vectors should be ported where possible.
- Parity gaps are tracked in each crate's `PARITY_STATUS.md`.

## 7. Configuration

TOML configs under `configs/` mirror the runtime structure. Example:

```toml
[network]
passphrase = "Test SDF Network ; September 2015"
peer_port = 11625
http_port = 11626

[database]
path = "stellar.db"

[history]
archives = [
    "https://history.stellar.org/prd/core-testnet/core_testnet_001",
    "https://history.stellar.org/prd/core-testnet/core_testnet_002",
    "https://history.stellar.org/prd/core-testnet/core_testnet_003"
]
```

## 8. Known Limitations

- SQLite-only persistence.
- Metrics parity is intentionally out of scope.
- Not production-hardened; use for education and research only.

## 9. Out of Scope

The following components are explicitly out of scope for this implementation:

### 9.1 Simulation Framework

A deterministic multi-node simulation framework (`stellar-core-simulation`) is not included. The stellar-core provides simulation capabilities for testing overlay and consensus behavior in controlled environments. This Rust implementation focuses on production-like execution paths rather than simulation infrastructure.

### 9.2 Transaction Metadata Baseline Testing

Transaction metadata baseline tests that compare XDR hashes against reference values are not included. These tests verify byte-for-byte parity of transaction metadata output with stellar-core. While useful for strict parity verification, they are not essential for functional correctness and add significant maintenance overhead.

## 10. References

- stellar-core (: https://github.com/stellar/stellar-core
- CAPs: https://github.com/stellar/stellar-protocol/tree/master/core
- stellar-xdr: https://github.com/stellar/rs-stellar-xdr
- soroban-env-host: https://github.com/stellar/rs-soroban-env
