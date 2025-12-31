# rs-stellar-core Specification

**Version:** 0.1.0
**Target Protocol:** 23+
**Network:** Stellar Testnet (primary), Mainnet (future)

## 1. Overview

rs-stellar-core is a Rust implementation of the Stellar Core node software. It aims to be a fully functional validator node capable of:

- Catching up to the Stellar testnet via history archives
- Participating in Stellar Consensus Protocol (SCP)
- Processing and validating transactions
- Executing Soroban smart contracts
- Publishing to history archives

### 1.1 Goals

1. **Full Validator Capability**: Participate in consensus as a voting node
2. **Protocol 23+ Only**: No legacy protocol support, simplifying implementation
3. **Modular Architecture**: Each subsystem maps 1:1 to stellar-core for auditability
4. **Rust Ecosystem Integration**: Leverage existing Stellar Rust crates
5. **Research & Education**: Independent implementation for verification and learning

### 1.2 Non-Goals

- Full history catchup from genesis (Protocol 1-22)
- Custom Soroban host implementation (use `soroban-env-host`)
- PostgreSQL support (SQLite only initially)
- Production deployment (research/education focus)

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                           rs-stellar-core                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌──────────┐ │
│  │   CLI   │  │  Config │  │ Metrics │  │ Logging │  │  Admin   │ │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘  └────┬─────┘ │
│       │            │            │            │             │        │
│  ┌────┴────────────┴────────────┴────────────┴─────────────┴────┐  │
│  │                        Application                            │  │
│  └───────────────────────────┬───────────────────────────────────┘  │
│                              │                                      │
│  ┌───────────────────────────┴───────────────────────────────────┐  │
│  │                          Herder                                │  │
│  │          (Coordinates consensus and ledger closing)            │  │
│  └──────┬─────────────────┬─────────────────────┬────────────────┘  │
│         │                 │                     │                   │
│  ┌──────┴──────┐   ┌──────┴──────┐      ┌──────┴──────┐            │
│  │     SCP     │   │   Ledger    │      │  Overlay    │            │
│  │ (Consensus) │   │ (State Mgmt)│      │   (P2P)     │            │
│  └─────────────┘   └──────┬──────┘      └──────┬──────┘            │
│                           │                    │                    │
│  ┌────────────────────────┴────────────────────┴────────────────┐  │
│  │                    Transaction Processing                     │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │  │
│  │  │  Classic    │  │   Soroban   │  │   Transaction Pool  │   │  │
│  │  │    Ops      │  │    Host     │  │      (TxQueue)      │   │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘   │  │
│  └───────────────────────────┬───────────────────────────────────┘  │
│                              │                                      │
│  ┌───────────────────────────┴───────────────────────────────────┐  │
│  │                      Storage Layer                            │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │  │
│  │  │  BucketList │  │  Database   │  │      History        │   │  │
│  │  │  (Merkle)   │  │  (SQLite)   │  │    (Archives)       │   │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘   │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                      Foundation Layer                         │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │  │
│  │  │   Crypto    │  │     XDR     │  │       Utils         │   │  │
│  │  │ (ed25519,   │  │ (stellar-   │  │  (time, async,      │   │  │
│  │  │  sha256)    │  │    xdr)     │  │   serialization)    │   │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘   │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## 3. Module Structure

### 3.1 Workspace Organization

```
rs-stellar-core/
├── Cargo.toml                 # Workspace root
├── SPEC.md                    # This document
├── DOCUMENTATION_ISSUES.md    # stellar-core doc issues found
├── docs/
│   └── modules/               # Per-module specifications
│       ├── scp.md
│       ├── herder.md
│       ├── overlay.md
│       ├── ledger.md
│       ├── bucket.md
│       ├── history.md
│       ├── transactions.md
│       ├── crypto.md
│       └── database.md
├── crates/
│   ├── rs-stellar-core/       # Main binary crate
│   ├── stellar-core-scp/      # SCP implementation
│   ├── stellar-core-herder/   # Herder coordination
│   ├── stellar-core-overlay/  # P2P networking
│   ├── stellar-core-ledger/   # Ledger management
│   ├── stellar-core-bucket/   # BucketList storage
│   ├── stellar-core-history/  # History archives
│   ├── stellar-core-tx/       # Transaction processing
│   ├── stellar-core-crypto/   # Cryptographic primitives
│   ├── stellar-core-db/       # Database abstraction
│   └── stellar-core-common/   # Shared types and utilities
└── tests/
    ├── integration/           # Integration tests
    └── testnet/               # Testnet catchup tests
```

### 3.2 Module Mapping to stellar-core

| rs-stellar-core Crate | stellar-core Directory | Description |
|-----------------------|------------------------|-------------|
| `stellar-core-scp` | `src/scp/` | Stellar Consensus Protocol |
| `stellar-core-herder` | `src/herder/` | SCP coordination, slot management |
| `stellar-core-overlay` | `src/overlay/` | P2P network, peer management |
| `stellar-core-ledger` | `src/ledger/` | Ledger state, closing |
| `stellar-core-bucket` | `src/bucket/` | BucketList, merkle tree |
| `stellar-core-history` | `src/history/` | Archive publish/catchup |
| `stellar-core-tx` | `src/transactions/` | Transaction validation/execution |
| `stellar-core-crypto` | `src/crypto/` | Hashing, signatures, keys |
| `stellar-core-db` | `src/database/` | SQL persistence layer |
| `stellar-core-common` | `src/util/` | Shared utilities |

## 4. External Dependencies

### 4.1 Stellar Rust Crates (Official)

| Crate | Version | Purpose |
|-------|---------|---------|
| `stellar-xdr` | 25.0.0 | XDR type definitions |
| `soroban-env-host` | 23.x | Soroban smart contract execution |
| `soroban-env-common` | 23.x | Shared Soroban types |

### 4.2 Third-Party Crates

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `ed25519-dalek` | Ed25519 signatures |
| `sha2` | SHA-256 hashing |
| `rusqlite` | SQLite database |
| `serde` / `serde_json` | Serialization |
| `tracing` | Logging and diagnostics |
| `clap` | CLI argument parsing |
| `reqwest` | HTTP client (history archives) |
| `quinn` / `tokio-tungstenite` | P2P networking |
| `thiserror` / `anyhow` | Error handling |
| `bytes` | Byte buffer manipulation |
| `hex` | Hex encoding |
| `base64` | Base64 encoding |
| `flate2` | Gzip compression |

## 5. Protocol Support

### 5.1 Supported Protocols

- **Protocol 23** (Whisk) - Current testnet/mainnet
- **Future protocols** - Design for extensibility

### 5.2 Protocol 23 Features

1. **Parallel Soroban Execution** (CAP-0063)
2. **Live State in Memory** (CAP-0062)
3. **Automatic Restoration** (CAP-0066)
4. **Unified Events** (CAP-0067)
5. **Multiplexed Accounts in Soroban**

### 5.3 Classic Operations Supported

All Protocol 23 operations:
- CreateAccount, Payment, PathPayment*, ManageSellOffer, ManageBuyOffer
- CreatePassiveSellOffer, SetOptions, ChangeTrust, AllowTrust
- AccountMerge, Inflation (deprecated), ManageData
- BumpSequence, CreateClaimableBalance, ClaimClaimableBalance
- BeginSponsoringFutureReserves, EndSponsoringFutureReserves
- RevokeSponsorship, Clawback, ClawbackClaimableBalance
- SetTrustLineFlags, LiquidityPoolDeposit, LiquidityPoolWithdraw
- **InvokeHostFunction** (Soroban)
- **ExtendFootprintTTL** (Soroban)
- **RestoreFootprint** (Soroban)

## 6. Implementation Phases

### Phase 1: Foundation (Weeks 1-4)
- [ ] Project structure and workspace setup
- [ ] Crypto module (hashing, signatures, keys)
- [ ] XDR wrapper utilities
- [ ] Database abstraction with SQLite
- [ ] Common utilities (time, async helpers)
- [ ] Basic configuration and logging

### Phase 2: Storage (Weeks 5-8)
- [ ] BucketList implementation
- [ ] Bucket merging and lifecycle
- [ ] History archive client (read-only)
- [ ] History catchup mechanism
- [ ] Checkpoint parsing and validation

### Phase 3: Ledger & Transactions (Weeks 9-14)
- [ ] Ledger state management
- [ ] Classic operation processing
- [ ] Soroban host integration
- [ ] Transaction validation
- [ ] Transaction application
- [ ] Fee calculation

### Phase 4: Networking (Weeks 15-18)
- [ ] Overlay network basics
- [ ] Peer discovery and management
- [ ] Message flooding
- [ ] Authentication (HMAC)
- [ ] Flow control

### Phase 5: Consensus (Weeks 19-24)
- [ ] SCP core implementation
- [ ] Nomination protocol
- [ ] Ballot protocol
- [ ] Herder integration
- [ ] Slot management
- [ ] Value validation

### Phase 6: Integration (Weeks 25-28)
- [ ] Full node operation
- [ ] Testnet catchup verification
- [ ] Consensus participation
- [ ] Performance optimization
- [ ] Test suite completion

## 7. Testing Strategy

### 7.1 Unit Tests

Each module has comprehensive unit tests covering:
- Normal operation paths
- Error conditions
- Edge cases
- Serialization round-trips

### 7.2 Integration Tests

- Cross-module interaction tests
- End-to-end transaction processing
- Consensus simulation tests

### 7.3 Testnet Tests

- Real testnet catchup verification
- Ledger state comparison with stellar-core
- Transaction submission and tracking

### 7.4 Ported Tests from stellar-core

Tests from the following stellar-core directories should be converted:
- `src/scp/test/`
- `src/herder/test/`
- `src/ledger/test/`
- `src/bucket/test/`
- `src/history/test/`
- `src/transactions/test/`

## 8. Configuration

### 8.1 Configuration File Format

TOML format (similar to stellar-core's cfg but modernized):

```toml
[network]
passphrase = "Test SDF Network ; September 2015"
peer_port = 11625
http_port = 11626

[database]
path = "stellar.db"

[history.testnet]
get = "curl -sf https://history.stellar.org/prd/core-testnet/core_testnet_001/{0} -o {1}"

[quorum]
threshold_percent = 67
validators = [
    "GDKXE2OZMJIPOSLNA6N6F2BVCI3O777I2OOC4BV7VOYUEHYX7RTRYA7Y",
    "GCUCJTIYXSOXKBSNFGNFWW5MUQ54HKRPGJUTQFJ5RQXZXNOLNXYDHRAP",
    "GC2V2EFSXN6SQTWVYA5EPJPBWWIMSD2XQNKUEZ2ZJQNJ7MQAWQR4N5SB"
]

[logging]
level = "info"
```

### 8.2 Environment Variables

```
STELLAR_CORE_CONFIG=/path/to/config.toml
STELLAR_CORE_LOG_LEVEL=debug
STELLAR_CORE_DB_PATH=/path/to/stellar.db
```

## 9. Network Topology

### 9.1 Testnet Configuration

```
Network Passphrase: "Test SDF Network ; September 2015"
History Archives:
  - https://history.stellar.org/prd/core-testnet/core_testnet_001
  - https://history.stellar.org/prd/core-testnet/core_testnet_002
  - https://history.stellar.org/prd/core-testnet/core_testnet_003

SDF Testnet Validators:
  - core-testnet1.stellar.org
  - core-testnet2.stellar.org
  - core-testnet3.stellar.org
```

## 10. Success Criteria

### 10.1 Minimum Viable Product (MVP)

1. Successfully catch up to testnet from a recent checkpoint
2. Maintain synchronization with testnet for 24+ hours
3. Process and validate all transaction types
4. Execute Soroban smart contracts correctly
5. Pass 80%+ of ported stellar-core tests

### 10.2 Full Implementation

1. Participate in consensus as a validator
2. Publish to history archives
3. Handle network partitions and recovery
4. Match stellar-core behavior bit-for-bit on:
   - Ledger hashes
   - Transaction results
   - State hashes
5. Pass 95%+ of ported stellar-core tests

## 11. Known Limitations

1. **No Protocol Upgrades**: Cannot process ledgers from before Protocol 23
2. **Single Database**: SQLite only, no PostgreSQL
3. **Research Focus**: Not hardened for production use
4. **Limited Admin API**: Minimal HTTP endpoints initially

## 12. References

### stellar-core Documentation
- [Architecture](https://github.com/stellar/stellar-core/blob/master/docs/architecture.md)
- [History](https://github.com/stellar/stellar-core/blob/master/docs/history.md)
- [SCP](https://github.com/stellar/stellar-core/tree/master/src/scp)
- [Herder](https://github.com/stellar/stellar-core/tree/master/src/herder)

### Stellar Protocol
- [CAP Repository](https://github.com/stellar/stellar-protocol/tree/master/core)
- [Protocol 23 Announcement](https://stellar.org/blog/developers/announcing-protocol-23)
- [Stellar Developers](https://developers.stellar.org/)

### Rust Crates
- [stellar-xdr](https://github.com/stellar/rs-stellar-xdr)
- [soroban-env-host](https://github.com/stellar/rs-soroban-env)
