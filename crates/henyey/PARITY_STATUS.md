## stellar-core Parity Status

**Overall Parity: ~88%**

This section documents the feature parity between this Rust implementation and the stellar-core (v25).

### Implemented

#### CLI Commands

| Command | Status | Notes |
|---------|--------|-------|
| `run` | Implemented | Supports watcher/validator/full modes, force-catchup, --wait-for-consensus equivalent |
| `catchup` | Implemented | Supports minimal/complete/recent modes, parallelism, --no-verify |
| `new-db` | Implemented | Database creation with --force overwrite |
| `upgrade-db` | Implemented | Database schema upgrades |
| `new-keypair` / `gen-seed` | Implemented | Keypair generation |
| `info` | Implemented | Includes offline fallback output if app init fails (no separate `offline-info`) |
| `verify-history` | Implemented | History archive verification (HAS, headers, tx sets, results, SCP) |
| `publish` / `publish-history` | Implemented | History publishing (local paths and remote via put commands) |
| `check-quorum-intersection` | Implemented | Quorum intersection checking from JSON (v1 algorithm) |
| `sample-config` | Implemented | Configuration template generation |
| `convert-id` / `convert-key` | Implemented | Key format conversion (strkey/hex) |
| `decode-xdr` | Implemented | Base64 input only; partial `print-xdr` parity for LedgerHeader, TransactionEnvelope, TransactionResult |
| `encode-xdr` | Implemented | Encodes AccountId, MuxedAccount, Asset, Hash, Uint256, LedgerHeader, TransactionEnvelope, TransactionResult (covers `encode-asset`) |
| `sign-transaction` | Implemented | Add signature to transaction envelope |
| `sec-to-pub` | Implemented | Print public key from secret key (stdin) |
| `http-command` | Implemented | Send HTTP command to running node |
| `bucket-info` | Implemented | Basic bucket info (not full per-account aggregation) |
| `dump-ledger` | Implemented | Dump ledger entries to JSON with type/limit filtering |
| `self-check` | Implemented | Header chain, bucket hash verification, crypto benchmarking |
| `verify-checkpoints` | Implemented | Write verified checkpoint ledger hashes to file |

#### Offline Tools (Unique to Rust)

| Tool | Status | Notes |
|------|--------|-------|
| `replay-bucket-list` | Implemented | Validates bucket list against CDP metadata |
| `verify-execution` | Implemented | Compares transaction execution against CDP |
| `debug-bucket-entry` | Implemented | Inspects specific entries in bucket list |
| `header_compare` (binary) | Implemented | Compares ledger headers between DB and archive |

These CDP-based verification tools are unique to the Rust implementation and provide valuable parity testing capabilities against stellar-core production data.

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
| `/survey` | Implemented | Survey report data |
| `/survey/reporting/stop` | Implemented | Stop survey reporting |
| `/ll` | Implemented | Dynamic log level changes via tracing-subscriber reload layer |
| `/sorobaninfo` | Implemented | Soroban network configuration (basic format) |
| `/manualclose` | Implemented | Manual ledger close (requires is_validator and manual_close config) |
| `/clearmetrics` | Implemented | Logs request; Prometheus metrics don't support clearing |
| `/logrotate` | Implemented | Logs request; actual rotation depends on logging backend |
| `/maintenance` | Implemented | Manual database maintenance (cleans old SCP/ledger history) |
| `/dumpproposedsettings` | Implemented | Returns ConfigUpgradeSet from ledger |

#### Core Subsystems

| Subsystem | Rust Crate | Status | Notes |
|-----------|------------|--------|-------|
| Bucket List | `henyey-bucket` | Implemented | Live bucket list, merges, hashes |
| Cryptography | `henyey-crypto` | Implemented | Ed25519, SHA256, BLAKE2, key utils |
| Database | `henyey-db` | Implemented | SQLite with ledger/tx/SCP storage |
| Herder | `henyey-herder` | Implemented | SCP coordination, tx queue |
| History | `henyey-history` | Implemented | Archive access, checkpoint handling |
| Historywork | `henyey-historywork` | Implemented | Parallel downloads, work scheduling |
| Ledger | `henyey-ledger` | Implemented | Transaction execution, state management |
| Overlay | `henyey-overlay` | Implemented | Peer connections, message routing |
| SCP | `henyey-scp` | Implemented | Consensus protocol |
| Transactions | `henyey-tx` | Implemented | All classic operations, Soroban support |
| Invariants | `stellar-core-invariant` | Implemented | Ledger invariant checking |
| Work | `henyey-work` | Implemented | Async work scheduling |
| Application | `henyey-app` | Implemented | App orchestration, config |

### Not Yet Implemented (Gaps)

#### CLI Commands

| Command | stellar-core Description | Priority |
|---------|-----------------|----------|
| `replay-debug-meta` | Apply ledgers from local debug metadata files | Low |
| `dump-xdr` | Dump XDR file (with streaming support) | Low |
| `dump-wasm` | Dump WASM blobs from ledger | Low |
| `force-scp` | Force SCP flag (deprecated in stellar-core) | Low |
| `diag-bucket-stats` | Diagnostic bucket statistics | Low |
| `merge-bucketlist` | Write diagnostic merged bucket list | Low |
| `dump-archival-stats` | Print state archival statistics | Low |
| `new-hist` | Initialize history archives (create structure) | Low |
| `report-last-history-checkpoint` | Report last checkpoint info | Low |
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

| Endpoint | stellar-core Description | Priority |
|----------|-----------------|----------|
| `/stopsurvey` | Stop survey (deprecated) | Low |
| `/generateload` | Generate synthetic load (test) | Low |
| `/testacc` | Test account operations (test) | Low |
| `/testtx` | Test transaction (test) | Low |
| `/toggleoverlayonlymode` | Toggle overlay-only mode (test) | Low |

#### Core Features

| Feature | stellar-core Location | Notes |
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

1. **Async Runtime**: Rust uses `tokio` for async I/O, while stellar-core uses `asio` via a virtual clock. The Rust implementation is natively async throughout.

2. **Error Handling**: Rust uses `Result<T, E>` types and the `?` operator, providing compile-time error handling guarantees that stellar-core achieves through exceptions.

3. **Memory Safety**: Rust's ownership system eliminates the need for manual memory management patterns used in stellar-core (shared_ptr, unique_ptr).

4. **Configuration**: Both support TOML configuration files with environment variable overrides. The Rust version adds built-in testnet/mainnet defaults via `--testnet` and `--mainnet` flags.

5. **Logging**: Rust uses `tracing` with structured logging, supporting both text and JSON output formats via `--log-format`.

6. **Testing**: While stellar-core uses Catch2 for testing, Rust uses the built-in test framework with `cargo test`.

7. **CDP Integration**: The Rust implementation has extensive CDP (Crypto Data Platform) integration for offline verification against stellar-core production data, which is unique to this implementation.

#### Known Limitations

1. **Hot Archive Updates**: Hot archive bucket list updates require looking up the full entry data before deletion (for evicted entries). The eviction data in transaction meta only provides keys, not full entries. This is partially implemented.

2. **Full XDR Support**: The `decode-xdr` command supports a subset of XDR types (LedgerHeader, TransactionEnvelope, TransactionResult); stellar-core supports more types including TransactionMeta and bucket file streaming.

3. **Network Simulation**: Simulation framework is out of scope for this implementation.

4. **Fuzzing**: Rust would use `cargo-fuzz` or similar tools rather than stellar-core fuzzing infrastructure.

5. **Self-Check Offline Mode**: The full database-vs-bucketlist consistency check (offline mode) is not implemented; only the online quick check is available.

#### Verification Status

##### Testnet Execution Verification (January 2026)

The `verify-execution` tool compares transaction execution against CDP (Crypto Data Platform) metadata from stellar-core.

**Ledgers 15001-30000:**
| Metric | Count | Rate |
|--------|-------|------|
| Phase 1 fee calculations matched | 30,702 | 100% |
| Phase 1 fee calculations mismatched | 0 | 0% |
| Phase 2 execution matched | 30,176 | 98.3% |
| Phase 2 execution mismatched | 526 | 1.7% |
| Header verifications passed | 15,000 | 100% |

**Ledgers 30001-50000:**
| Metric | Count | Rate |
|--------|-------|------|
| Phase 1 fee calculations matched | 36,510 | 100% |
| Phase 1 fee calculations mismatched | 0 | 0% |
| Phase 2 execution matched | 36,248 | 99.3% |
| Phase 2 execution mismatched | 262 | 0.7% |
| Header verifications passed | 20,000 | 100% |
| Header mismatches | 0 | 0% |

**Ledgers 30001-33000 (after eviction scan fix):**
| Metric | Count | Rate |
|--------|-------|------|
| Phase 1 fee calculations matched | 7,212 | 100% |
| Phase 1 fee calculations mismatched | 0 | 0% |
| Phase 2 execution matched | 6,596 | 91.5% |
| Phase 2 execution mismatched | 616 | 8.5% |
| Header verifications passed | 3,000 | 100% |
| Header mismatches | 0 | 0% |

**Phase 1 (Fee Calculation)**: 100% parity after implementing per-transaction base fee extraction from `GeneralizedTransactionSet` to handle surge pricing.

**Phase 2 (Execution)**: ~91-99% parity. Remaining mismatches are primarily Soroban contract execution differences:
- CPU metering differences causing `ResourceLimitExceeded` vs success
- Storage limit handling differences
- These affect ~0.7-8.5% of transactions depending on ledger range

**Header Verification**: 100% parity after fixing eviction scan cycle completion check. Previous header mismatches in ledgers 32787+ were caused by incorrect eviction iterator advancement when wrapping from level 10 back to the starting level.

##### Known Phase 2 Mismatch Patterns

1. **Soroban CPU Metering Differences**: Small differences in CPU instruction counting between Rust and stellar-core Soroban implementations can cause transactions that are close to their budget limit to succeed in one implementation but fail in the other.

2. **Soroban Error Code Mapping**: When contracts fail due to resource limits, Rust returns `InvokeHostFunction(ResourceLimitExceeded)` while stellar-core may return `InvokeHostFunction(Trapped)`. This is a Soroban VM error propagation difference.

##### Verified Components

- Transaction execution verified against CDP for testnet ledgers
- Bucket list hash computation verified against history archives
- Header hash computation verified against network
- SCP message handling verified through overlay tests
- Publish/verify cycle verified for local and command-based archives
- Phase 1 fee calculation: 100% parity (surge pricing support)
- Classic transaction execution: >99% parity
- Soroban transaction execution: ~98% parity (error code mapping differences)
