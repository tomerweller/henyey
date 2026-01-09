## C++ Parity Status

This section documents the feature parity between this Rust implementation and the C++ stellar-core (v25).

### Implemented

#### CLI Commands

| Command | Status | Notes |
|---------|--------|-------|
| `run` | Implemented | Supports watcher/validator/full modes, force-catchup, --wait-for-consensus equivalent |
| `catchup` | Implemented | Supports minimal/complete/recent modes, parallelism, --no-verify |
| `new-db` | Implemented | Database creation with --force overwrite |
| `upgrade-db` | Implemented | Database schema upgrades |
| `new-keypair` / `gen-seed` | Implemented | Keypair generation |
| `info` / `offline-info` | Implemented | Node information display |
| `verify-history` | Implemented | History archive verification (HAS, headers, tx sets, results, SCP) |
| `publish` / `publish-history` | Implemented | History publishing (local paths and remote via put commands) |
| `check-quorum-intersection` | Implemented | Quorum intersection checking from JSON (v1 algorithm) |
| `sample-config` | Implemented | Configuration template generation |
| `convert-id` / `convert-key` | Implemented | Key format conversion (strkey/hex) |
| `decode-xdr` / `print-xdr` | Implemented | XDR decoding (LedgerHeader, TransactionEnvelope, TransactionResult) |
| `encode-xdr` / `encode-asset` | Implemented | XDR encoding (AccountId, MuxedAccount, Asset, Hash) |
| `diag-bucket-stats` / `bucket-info` | Partial | Basic bucket info (not full per-account aggregation) |

#### Offline Tools (Unique to Rust)

| Tool | Status | Notes |
|------|--------|-------|
| `replay-bucket-list` | Implemented | Validates bucket list against CDP metadata |
| `verify-execution` | Implemented | Compares transaction execution against CDP |
| `debug-bucket-entry` | Implemented | Inspects specific entries in bucket list |
| `header_compare` (binary) | Implemented | Compares ledger headers between DB and archive |

These CDP-based verification tools are unique to the Rust implementation and provide valuable parity testing capabilities against C++ stellar-core production data.

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
| `/self-check` | Implemented | Ledger self-check (online mode only) |
| `/quorum` | Implemented | Quorum set summary |
| `/scp` | Implemented | SCP slot summary |
| `/tx` | Implemented | Transaction submission |
| `/shutdown` | Implemented | Graceful shutdown |
| `/health` | Implemented | Health check |
| `/survey/start` | Implemented | Start survey collecting |
| `/survey/stop` | Implemented | Stop survey collecting |
| `/survey/topology` | Implemented | Survey topology request |
| `/survey/reporting/stop` | Implemented | Stop survey reporting |
| `/getsurveyresult` | Implemented | Get survey results |

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
| Application | `stellar-core-app` | Implemented | App orchestration, config |

### Not Yet Implemented (Gaps)

#### CLI Commands

| Command | C++ Description | Priority |
|---------|-----------------|----------|
| `replay-debug-meta` | Apply ledgers from local debug metadata files | Low |
| `verify-checkpoints` | Write verified checkpoint ledger hashes to file | Medium |
| `dump-xdr` | Dump XDR file (with streaming support) | Low |
| `dump-wasm` | Dump WASM blobs from ledger | Low |
| `force-scp` | Force SCP flag (deprecated in C++) | Low |
| `http-command` | Send command to local stellar-core HTTP port | Medium |
| `merge-bucketlist` | Write diagnostic merged bucket list | Low |
| `dump-archival-stats` | Print state archival statistics | Low |
| `dump-ledger` | Dump current ledger state as JSON with filtering | Medium |
| `new-hist` | Initialize history archives (create structure) | Low |
| `report-last-history-checkpoint` | Report last checkpoint info | Low |
| `sec-to-pub` | Print public key from secret key (stdin) | Low |
| `sign-transaction` | Add signature to transaction envelope | Medium |
| `get-settings-upgrade-txs` | Get settings upgrade transactions | Low |
| `print-publish-queue` | Print scheduled checkpoints | Low |
| `self-check` (offline mode) | Full DB vs bucket list consistency check | Medium |

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
| `/ll` | Set log level dynamically | Medium |
| `/logrotate` | Rotate log files | Low |
| `/manualclose` | Manual ledger close (testing) | Medium |
| `/maintenance` | Run maintenance | Low |
| `/dumpproposedsettings` | Dump proposed settings | Low |
| `/sorobaninfo` | Soroban-specific info and config | Medium |
| `/stopsurvey` | Stop survey (deprecated) | Low |
| `/generateload` | Generate synthetic load (test) | Low |
| `/testacc` | Test account operations (test) | Low |
| `/testtx` | Test transaction (test) | Low |
| `/toggleoverlayonlymode` | Toggle overlay-only mode (test) | Low |

#### Core Features

| Feature | C++ Location | Notes |
|---------|--------------|-------|
| Hot Archive Bucket List Updates | `bucket/HotArchiveBucket*` | Eviction-to-hot-archive requires entry lookup before deletion |
| Catchup with trusted hash file | `--trusted-checkpoint-hashes` | Uses JSON hash file for verified catchup |
| Complete catchup validation | `--extra-verification` | Full archive verification during catchup |
| Metadata output stream | `--metadata-output-stream` | Stream ledger metadata to file/fd |
| Database maintenance | `AUTOMATIC_MAINTENANCE_*` | Periodic DB cleanup for history data |
| Tracy profiling | `USE_TRACY` | Performance profiling integration |
| Process management | `process/` | Child process spawning for external commands |
| Check-quorum-intersection v2 | SAT-based algorithm | V1 (brute-force) implemented, V2 (SAT-solver) not yet |

### Implementation Notes

#### Architectural Differences

1. **Async Runtime**: Rust uses `tokio` for async I/O, while C++ uses `asio` via a virtual clock. The Rust implementation is natively async throughout.

2. **Error Handling**: Rust uses `Result<T, E>` types and the `?` operator, providing compile-time error handling guarantees that C++ achieves through exceptions.

3. **Memory Safety**: Rust's ownership system eliminates the need for manual memory management patterns used in C++ (shared_ptr, unique_ptr).

4. **Configuration**: Both support TOML configuration files with environment variable overrides. The Rust version adds built-in testnet/mainnet defaults via `--testnet` and `--mainnet` flags.

5. **Logging**: Rust uses `tracing` with structured logging, supporting both text and JSON output formats via `--log-format`.

6. **Testing**: While C++ uses Catch2 for testing, Rust uses the built-in test framework with `cargo test`.

7. **CDP Integration**: The Rust implementation has extensive CDP (Crypto Data Platform) integration for offline verification against C++ stellar-core production data, which is unique to this implementation.

#### Known Limitations

1. **Hot Archive Updates**: Hot archive bucket list updates require looking up the full entry data before deletion (for evicted entries). The eviction data in transaction meta only provides keys, not full entries. This is partially implemented.

2. **Full XDR Support**: The `decode-xdr` command supports a subset of XDR types (LedgerHeader, TransactionEnvelope, TransactionResult); C++ supports more types including TransactionMeta and bucket file streaming.

3. **Network Simulation**: Simulation framework is out of scope for this implementation.

4. **Fuzzing**: Rust would use `cargo-fuzz` or similar tools rather than the C++ fuzzing infrastructure.

5. **Self-Check Offline Mode**: The full database-vs-bucketlist consistency check (offline mode) is not implemented; only the online quick check is available.

#### Verification Status

- Transaction execution verified against CDP for testnet ledgers
- Bucket list hash computation verified against history archives
- Header hash computation verified against network
- SCP message handling verified through overlay tests
- Publish/verify cycle verified for local and command-based archives
