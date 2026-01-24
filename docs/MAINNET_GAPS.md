# Mainnet Validator Readiness Assessment

This document evaluates the gaps between the current rs-stellar-core implementation and what's required for mainnet validator operation.

## Executive Summary

**Current Status: NOT READY for mainnet validator operation**

The project explicitly states it's "an educational experiment and **not** production-grade software." However, significant progress has been made with testnet validation working successfully.

| Mode | Network | Status |
|------|---------|--------|
| Observer | Testnet | Working |
| Validator | Testnet | Working |
| Observer | Mainnet | Should work, needs extended testing |
| Validator | Mainnet | Not recommended |

---

## Critical Gaps (Blocking Mainnet Validator)

| # | Gap | Impact | Effort | Priority |
|---|-----|--------|--------|----------|
| 1 | **Bucket list fully in memory** | Mainnet state (~60M entries) would require 50+ GB RAM | Very High | P0 |
| 2 | **No parallel transaction execution** | Validators will fall behind on high-throughput ledgers | High | P0 |
| 3 | **Insufficient metrics/monitoring** | Cannot monitor production operation | Medium | P1 |
| 4 | **No QuorumIntersection v2** | Cannot perform network safety analysis at scale | Medium | P1 |

---

## Detailed Assessment by Component

### 1. Transaction Execution (100% parity)

**Status: COMPLETE**

- All 24 classic operations implemented
- All 3 Soroban operations implemented (InvokeHostFunction, ExtendFootprintTtl, RestoreFootprint)
- 14,651 testnet transactions verified with matching results
- No `unimplemented!` or `todo!` markers in transaction code

**Verified Operations:**
- CreateAccount, Payment, PathPaymentStrictReceive, PathPaymentStrictSend
- ManageSellOffer, ManageBuyOffer, CreatePassiveSellOffer
- SetOptions, ChangeTrust, AllowTrust, AccountMerge
- ManageData, BumpSequence, Inflation
- CreateClaimableBalance, ClaimClaimableBalance
- BeginSponsoringFutureReserves, EndSponsoringFutureReserves, RevokeSponsorship
- Clawback, ClawbackClaimableBalance, SetTrustLineFlags
- LiquidityPoolDeposit, LiquidityPoolWithdraw

### 2. SCP Consensus (~90% parity)

**Status: Substantially Complete**

Implemented:
- Nomination protocol (complete)
- Ballot protocol (complete)
- Quorum set validation and normalization
- V-blocking detection
- Envelope state machine
- Timer management
- State persistence (crash recovery)
- Multi-node simulation tested

Gaps:
- **QuorumIntersection v2** - SAT-solver based analysis (only brute-force v1)
- **SCP execution metrics** - recordSCPExecutionMetrics(), recordSCPEvent()
- **Externalize lag tracking** - getExternalizeLag(), per-node timers
- **TxSet validity caching** - RandomEvictionCache for validation results

### 3. Ledger Operations (~90% parity)

**Status: Core Complete, Critical Memory Gap**

Implemented:
- Ledger close pipeline
- Genesis ledger creation
- Transaction execution (classic + Soroban)
- State transitions via LedgerDelta
- Bucket list state management
- Hot archive bucket list (P23+)
- Eviction scanning
- Invariant validation
- LedgerCloseMeta V2 generation
- **PersistentModuleCache** - Shared WASM module cache initialized from bucket list on catchup, new contracts added during execution

Gaps:
- **Bucket list fully in memory** - See [Bucket List Memory Architecture](#bucket-list-memory-architecture-critical) below
- **Parallel transaction execution** - Critical for validator performance
- **Nested transaction support** - LedgerTxn parent/child rollback

### 4. History/Catchup (~85% parity)

**Status: Functional**

Implemented:
- History archive HTTP client
- HistoryArchiveState parsing (v1/v2)
- Full catchup orchestration (7-step process)
- Bucket download/verification with parallel downloads
- Ledger replay (transaction re-execution)
- Header chain verification
- Basic publish to local paths and via shell commands

Gaps:
- **FutureBucket merge resolution** - In-progress bucket handling
- **Online catchup buffering** - Sophisticated mSyncingLedgers management
- **Archive failover** - Random archive selection on retry
- **Publish metrics** - Success/failure tracking

### 5. Overlay/Network (~88% parity)

**Status: Substantially Complete**

Implemented:
- Full Hello/Auth handshake
- Peer state machine (CONNECTING → GOT_AUTH)
- Flow control (SendMore/SendMoreExtended)
- Message flooding (Floodgate)
- Transaction advertisements/demands
- Full Survey Manager (time-sliced surveys)
- Peer management with SQLite persistence
- Ban manager
- Item fetcher for tx sets and quorum sets

Gaps:
- **LoopbackPeer** - For testing
- **VirtualClock integration** - For deterministic testing
- **Legacy survey protocol** - Non-time-sliced surveys

### 6. Database/Persistence (~85% parity)

**Status: Functional**

Implemented:
- SQLite-only (PostgreSQL intentionally not supported)
- Connection pooling (r2d2)
- Schema migrations
- Ledger header storage
- SCP state persistence (crash recovery)
- Peer/ban management
- Transaction history

Gaps:
- **MVCC isolation testing**
- **Query metrics/timers**
- **Read-only transaction mode**

Design Decision: PostgreSQL support intentionally omitted to reduce complexity.

### 7. Metrics/Monitoring (~20% parity) - CRITICAL GAP

**Status: Minimal**

Implemented:
- Basic Prometheus `/metrics` endpoint
- Overlay metrics (messages, bytes, errors)
- Bucket list metrics
- Work scheduler metrics

Gaps:
- **Full metrics suite** - Counters, timers, histograms (medida-style)
- **Ledger apply metrics** - TX count, op count, phase timings
- **SCP execution metrics** - Nomination/ballot timing
- **Soroban metrics** - CPU/memory usage, contract execution
- **Module cache metrics** - Compilation hit rate
- **Prefetch hit rate tracking**
- **Meta stream writing metrics**

This is a **critical gap** for production operation.

### 8. Configuration

**Status: Complete**

Implemented:
- Mainnet/Testnet presets
- Quorum set configuration with threshold_percent
- Validator list support
- History archive configuration
- Overlay peer configuration
- Protocol upgrade scheduling

---

## TODOs in Codebase

Only 3 TODO comments exist in production code:

1. `crates/stellar-core-bucket/src/snapshot.rs:741`
   - Historical snapshot query methods (minor feature)

2. `crates/stellar-core-history/src/catchup.rs:1740`
   - Module cache not passed during catchup replay (performance optimization)
   - Note: Module cache IS properly initialized after catchup completes

3. `crates/stellar-core-herder/src/fetching_envelopes.rs:436`
   - Quorum set fetching from peers

---

## Parity Status by Crate

| Crate | Parity | Critical Gaps |
|-------|--------|---------------|
| stellar-core-tx | **100%** | None |
| stellar-core-bucket | **~98%** | Shadow buckets (not needed) |
| stellar-core-crypto | **~95%** | Signature cache |
| stellar-core-scp | **~90%** | Test coverage |
| stellar-core-overlay | **~88%** | VirtualClock, LoopbackPeer |
| stellar-core-herder | **~82%** | Parallel TxSet, QuorumIntersection v2 |
| stellar-core-history | **~85%** | Online catchup, FutureBucket |
| stellar-core-ledger | **~90%** | Parallel apply |
| stellar-core-historywork | **~82%** | Metrics, archive failover |
| stellar-core-app | **~75%** | Metrics, ProcessManager |
| rs-stellar-core CLI | **~88%** | Some utility commands |

---

## Recommended Path to Mainnet

### Phase 1: Performance (Required)

1. **Implement parallel transaction execution**
   - Required for keeping up with mainnet throughput
   - Soroban parallel stages support

2. **Memory profiling and optimization**
   - Long-term stability testing
   - Leak detection

### Phase 2: Observability (Required)

3. **Full metrics suite**
   - Prometheus counters, gauges, histograms
   - Ledger close timing, TX execution stats
   - SCP participation metrics

4. **Structured logging improvements**
   - Reduce noise in steady-state operation
   - Add correlation IDs for tracing

5. **Health check endpoints**
   - Readiness/liveness probes
   - Sync status API

### Phase 3: Safety Analysis (Required)

6. **QuorumIntersection v2**
   - SAT-solver based analysis
   - Network split detection
   - Critical node identification

### Phase 4: Validation

7. **Extended mainnet observer testing**
   - Run as observer for weeks
   - Verify state consistency with C++ nodes

8. **Testnet validator stress testing**
   - High-throughput scenarios
   - Network partition simulation

9. **Third-party security review**
   - Consensus implementation audit
   - Cryptographic review

10. **Remove "not production-grade" disclaimer**
    - Update README and documentation
    - Production support commitment

---

## Bucket List Memory Architecture (CRITICAL)

### The Problem

The current implementation loads the **entire bucket list into memory** after catchup, making mainnet operation impossible without major architectural changes.

**Mainnet scale:**
- ~60 million ledger entries
- ~10-20+ GB of bucket data (uncompressed)
- Would require **50+ GB RAM** with current approach

**Testnet (for comparison):**
- ~5 GB RAM for ~70k Soroban entries + ~3k offers
- Manageable because testnet state is much smaller

### Current rs-stellar-core Behavior

After catchup completes, `initialize_all_caches()` calls `live_entries()` which:

1. **Iterates ALL buckets** across all 11 levels
2. **Materializes ALL entries** into a `Vec<LedgerEntry>`
3. **Builds multiple in-memory caches:**
   - `entry_cache` - HashMap of all ledger entries
   - `offer_cache` - All DEX offers
   - `soroban_state` - All Soroban entries (contracts, data, code, TTLs)
   - `module_cache` - Compiled WASM modules

**Code path:** `crates/stellar-core-ledger/src/manager.rs:614-620`

```rust
// Initialize all caches in a single pass over live_entries().
// This is a significant memory optimization - previously we called live_entries()
// three times... The single-pass approach reduces peak memory usage by ~66%.
self.initialize_all_caches(header.ledger_version, ledger_seq)?;
```

Even with the "optimization," this still loads everything into memory.

### Upstream C++ Behavior (BucketListDB)

The C++ stellar-core uses a fundamentally different approach:

1. **Buckets stored on disk** as `bucket-<hash>.xdr` files
2. **Two index types** per bucket:
   - `IndividualIndex` - Full key→offset map for small buckets (< 250 MB)
   - `RangeIndex` - Page-based index with bloom filter for large buckets
3. **On-demand disk reads** - Entries loaded only when accessed
4. **RandomEvictionCache** - LRU cache for frequently accessed entries
5. **No full materialization** - `live_entries()` equivalent doesn't exist for normal operation

**Key config options in C++:**
- `BUCKETLIST_DB_INDEX_CUTOFF` - Bucket size threshold (default 250 MB)
- `BUCKETLIST_DB_INDEX_PAGE_SIZE_EXPONENT` - Page size for RangeIndex
- `BUCKETLIST_DB_MEMORY_FOR_CACHING` - Memory budget for entry cache

### Required Changes for Mainnet

1. **Implement BucketListDB pattern:**
   - Keep buckets on disk after catchup
   - Build persistent indexes (IndividualIndex + RangeIndex)
   - Bloom filters for fast negative lookups

2. **Remove `live_entries()` dependency:**
   - Lazy initialization of caches
   - On-demand loading for offer cache, soroban state
   - Streaming iteration instead of materialization

3. **Add entry caching layer:**
   - RandomEvictionCache with configurable memory budget
   - Cache frequently accessed accounts/contracts
   - Evict based on access patterns

4. **Persist bucket indexes:**
   - Save indexes to disk (`.index` files)
   - Reload on startup without re-scanning buckets

**Estimated effort:** 4-6 weeks for a production-ready implementation

### Workarounds (Not Recommended)

- **More RAM**: Requires 64+ GB RAM machines for mainnet
- **Swap**: Would be extremely slow, not viable for consensus timing

---

## Architecture Differences from C++

### Concurrency Model
- **C++**: Single-threaded with VirtualClock timers, callback-driven
- **Rust**: Thread-safe with `RwLock`, `DashMap`; async with tokio

### Timer Management
- **C++**: VirtualTimer with Application's VirtualClock
- **Rust**: `TimerManager` with tokio channels; `SyncRecoveryManager` for tracking

### Memory Management
- **C++**: Manual with RAII, shared_ptr
- **Rust**: Ownership system, Arc for shared state

### Database
- **C++**: SQLite + PostgreSQL support
- **Rust**: SQLite only (by design)

---

## Testing Recommendations Before Mainnet

1. **Continuous testnet validation** - Run validator for extended periods
2. **Catchup stress testing** - Multiple full catchups from genesis
3. **Network partition testing** - Simulate peer disconnections
4. **Memory leak detection** - Valgrind/sanitizer runs
5. **Fuzzing** - Transaction and SCP message fuzzing
6. **Comparison testing** - Side-by-side with C++ stellar-core

---

## References

- [stellar-core v25 source](https://github.com/stellar/stellar-core)
- [Stellar Consensus Protocol paper](https://stellar.org/papers/stellar-consensus-protocol)
- [SEP-0054 CDP](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0054.md)
- Individual crate `PARITY_STATUS.md` files for detailed implementation status

---

*Last updated: January 2026*
*Based on commit: ed6002a (Added bucket list memory gap documentation)*
