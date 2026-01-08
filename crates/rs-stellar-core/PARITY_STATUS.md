## C++ Parity Status

This section documents the feature parity between this Rust implementation and the C++ stellar-core (v25).

### Implemented

#### CLI Commands

| Command | Status | Notes |
|---------|--------|-------|
| `run` | Implemented | Supports watcher/validator/full modes, force-catchup |
| `catchup` | Implemented | Supports minimal/complete/recent modes, parallelism |
| `new-db` | Implemented | Database creation with force overwrite |
| `upgrade-db` | Implemented | Database schema upgrades |
| `new-keypair` / `gen-seed` | Implemented | Keypair generation |
| `info` / `offline-info` | Implemented | Node information display |
| `verify-history` | Implemented | History archive verification (HAS, headers, tx sets, results, SCP) |
| `publish-history` / `publish` | Implemented | History publishing (local and remote via commands) |
| `check-quorum-intersection` | Implemented | Quorum intersection checking from JSON |
| `sample-config` | Implemented | Configuration template generation |
| `convert-id` / `convert-key` | Implemented | Key format conversion (strkey/hex) |
| `decode-xdr` / `print-xdr` | Implemented | XDR decoding (LedgerHeader, TransactionEnvelope, TransactionResult) |
| `encode-xdr` / `encode-asset` | Implemented | XDR encoding (AccountId, MuxedAccount, Asset, Hash) |
| `bucket-info` / `diag-bucket-stats` | Partial | Basic bucket info (not full statistics) |

#### Offline Tools (Unique to Rust)

| Tool | Status | Notes |
|------|--------|-------|
| `replay-bucket-list` | Implemented | Validates bucket list against CDP metadata |
| `verify-execution` | Implemented | Compares transaction execution against CDP |
| `debug-bucket-entry` | Implemented | Inspects specific entries in bucket list |
| `header_compare` (binary) | Implemented | Compares ledger headers between DB and archive |

#### HTTP API Endpoints

| Endpoint | Status | Notes |
|----------|--------|-------|
| `/` | Implemented | API overview |
| `/info` | Implemented | Node information |
| `/status` | Implemented | Node status summary |
| `/metrics` | Implemented | Prometheus metrics |
| `/peers` | Implemented | Connected peers list |
| `/connect` | Implemented | Connect to peer |
| `/droppeer` | Implemented | Disconnect peer (with ban option) |
| `/bans` | Implemented | List banned peers |
| `/unban` | Implemented | Remove peer from ban list |
| `/ledger` | Implemented | Current ledger info |
| `/upgrades` | Implemented | Upgrade settings |
| `/self-check` | Implemented | Ledger self-check |
| `/quorum` | Implemented | Quorum set summary |
| `/survey` | Implemented | Survey report |
| `/scp` | Implemented | SCP slot summary |
| `/survey/start` | Implemented | Start survey collecting |
| `/survey/stop` | Implemented | Stop survey collecting |
| `/survey/topology` | Implemented | Survey topology request |
| `/survey/reporting/stop` | Implemented | Stop survey reporting |
| `/tx` | Implemented | Transaction submission |
| `/shutdown` | Implemented | Graceful shutdown |
| `/health` | Implemented | Health check |

#### Core Subsystems

| Subsystem | Rust Crate | Status | Notes |
|-----------|------------|--------|-------|
| Bucket List | `stellar-core-bucket` | Implemented | Live bucket list, merges, hashes |
| Cryptography | `stellar-core-crypto` | Implemented | Ed25519, SHA256, BLAKE2, key utils |
| Database | `stellar-core-db` | Implemented | SQLite with ledger/tx/SCP storage |
| Herder | `stellar-core-herder` | Implemented | SCP coordination, tx queue |
| History | `stellar-core-history` | Implemented | Archive access, checkpoint handling |
| Historywork | `stellar-core-historywork` | Implemented | Parallel downloads, work scheduling |
| Ledger | `stellar-core-ledger` | Implemented | Transaction execution, state management |
| Overlay | `stellar-core-overlay` | Implemented | Peer connections, message routing |
| SCP | `stellar-core-scp` | Implemented | Consensus protocol |
| Transactions | `stellar-core-tx` | Implemented | All classic operations, Soroban support |
| Invariants | `stellar-core-invariant` | Implemented | Ledger invariant checking |
| Work | `stellar-core-work` | Implemented | Async work scheduling |
| Simulation | `stellar-core-simulation` | Implemented | Network simulation |
| Application | `stellar-core-app` | Implemented | App orchestration, config |

### Not Yet Implemented (Gaps)

#### CLI Commands

| Command | C++ Description | Priority |
|---------|-----------------|----------|
| `replay-debug-meta` | Apply ledgers from local debug metadata files | Low |
| `verify-checkpoints` | Write verified checkpoint ledger hashes | Medium |
| `dump-xdr` (full) | Dump XDR file with all type support | Low |
| `dump-wasm` | Dump WASM blobs from ledger | Low |
| `force-scp` | Force SCP flag (deprecated in C++) | Low |
| `http-command` | Send command to local stellar-core | Medium |
| `merge-bucketlist` | Write diagnostic merged bucket list | Low |
| `dump-archival-stats` | Print state archival statistics | Low |
| `dump-ledger` | Dump current ledger state as JSON | Medium |
| `new-hist` | Initialize history archives | Low |
| `report-last-history-checkpoint` | Report last checkpoint info | Low |
| `sec-to-pub` | Print public key from secret | Low |
| `sign-transaction` | Add signature to transaction envelope | Medium |
| `get-settings-upgrade-txs` | Get settings upgrade transactions | Low |
| `print-publish-queue` | Print scheduled checkpoints | Low |

#### Test-Only Commands (BUILD_TESTS)

| Command | Description | Notes |
|---------|-------------|-------|
| `load-xdr` | Load XDR bucket file for testing | Test infrastructure |
| `rebuild-ledger-from-buckets` | Rebuild DB from bucket list | Test infrastructure |
| `fuzz` | Run fuzzer input | Testing |
| `gen-fuzz` | Generate fuzzer input | Testing |
| `test` | Execute test suite | Uses Rust test framework instead |
| `apply-load` | Run apply time load test | Benchmarking |
| `pregenerate-loadgen-txs` | Generate load test transactions | Benchmarking |

#### HTTP API Endpoints

| Endpoint | C++ Description | Priority |
|----------|-----------------|----------|
| `/clearmetrics` | Clear metrics | Low |
| `/ll` | Set log level | Medium |
| `/logrotate` | Rotate log files | Low |
| `/manualclose` | Manual ledger close | Medium |
| `/maintenance` | Run maintenance | Low |
| `/dumpproposedsettings` | Dump proposed settings | Low |
| `/sorobaninfo` | Soroban-specific info | Medium |
| `/generateload` | Generate synthetic load (test) | Low |
| `/testacc` | Test account operations (test) | Low |
| `/testtx` | Test transaction (test) | Low |
| `/toggleoverlayonlymode` | Toggle overlay-only mode (test) | Low |

#### Core Features

| Feature | C++ Location | Notes |
|---------|--------------|-------|
| Hot Archive Bucket List | `bucket/HotArchiveBucket*` | Protocol 23+ state archival (partial) |
| Catchup with trusted hash file | `--trusted-checkpoint-hashes` | Uses JSON hash file |
| Complete catchup validation | `--extra-verification` | Full archive verification |
| Metadata output stream | `--metadata-output-stream` | Stream ledger metadata |
| Database maintenance | `AUTOMATIC_MAINTENANCE_*` | Periodic DB cleanup |
| Tracy profiling | `USE_TRACY` | Performance profiling |
| Process management | `process/` | Child process spawning |

### Implementation Notes

#### Architectural Differences

1. **Async Runtime**: Rust uses `tokio` for async I/O, while C++ uses `asio` via a virtual clock. The Rust implementation is natively async throughout.

2. **Error Handling**: Rust uses `Result<T, E>` types and the `?` operator, providing compile-time error handling guarantees that C++ achieves through exceptions.

3. **Memory Safety**: Rust's ownership system eliminates the need for manual memory management patterns used in C++ (shared_ptr, unique_ptr).

4. **Configuration**: Both support TOML configuration files with environment variable overrides. The Rust version adds built-in testnet/mainnet defaults.

5. **Logging**: Rust uses `tracing` with structured logging, supporting both text and JSON output formats.

6. **Testing**: While C++ uses Catch2 for testing, Rust uses the built-in test framework with `cargo test`.

7. **CDP Integration**: The Rust implementation has extensive CDP (Crypto Data Platform) integration for offline verification, which is unique to this implementation.

#### Known Limitations

1. **Hot Archive**: Hot archive bucket list updates require entry lookup before deletion, which is partially implemented.

2. **Full XDR Support**: The `decode-xdr` command supports a subset of XDR types; C++ supports more types.

3. **Network Simulation**: The simulation crate exists but may have different capabilities than the C++ version.

4. **Fuzzing**: Rust would use `cargo-fuzz` or similar tools rather than the C++ fuzzing infrastructure.

#### Verification Status

- Transaction execution verified against CDP for testnet ledgers
- Bucket list hash computation verified against history archives
- Header hash computation verified against network
- SCP message handling verified through overlay tests
