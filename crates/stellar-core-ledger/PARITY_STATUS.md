## C++ Parity Status

This section documents the implementation status compared to the C++ upstream in `.upstream-v25/src/ledger/`.

### Implemented

#### Core Ledger Management (`LedgerManager.h`, `LedgerManagerImpl.h` -> `manager.rs`)
- [x] Ledger state management (`LedgerManager` struct)
- [x] Ledger close pipeline (`begin_close`, `apply_transactions`, `commit`)
- [x] Genesis ledger creation (`create_genesis_header`)
- [x] Last closed ledger tracking (header, hash)
- [x] Bucket list integration for state storage
- [x] Hot archive bucket list support (Protocol 23+)
- [x] Network passphrase and network ID handling
- [x] Invariant validation during ledger close
- [x] Snapshot management for concurrent reads
- [x] Entry cache for fast lookups
- [x] Initialize from buckets (catchup scenario)
- [x] Reinitialize from buckets (re-sync scenario)
- [x] Apply historical ledger (replay mode)
- [x] SCP timing configuration lookup

#### Ledger Header Utilities (`LedgerHeaderUtils.h/.cpp` -> `header.rs`)
- [x] Header hash computation (`compute_header_hash`)
- [x] Skip list computation (`compute_skip_list`)
- [x] Skip list target sequence calculation (`skip_list_target_seq`)
- [x] Header chain verification (`verify_header_chain`)
- [x] Skip list verification (`verify_skip_list`)
- [x] Next header creation (`create_next_header`)

#### Ledger Delta / Change Tracking (`LedgerTxn*.h` -> `delta.rs`)
- [x] Entry change tracking (create/update/delete)
- [x] Change coalescing (create+update=create, create+delete=no-op, etc.)
- [x] Fee pool delta tracking
- [x] Total coins delta tracking
- [x] Categorized entry extraction (init/live/dead for bucket list)
- [x] Deterministic ordering of changes
- [x] Delta merging

#### Ledger Close Data (`close.rs`)
- [x] Transaction set handling (classic and generalized)
- [x] Transaction set hash computation
- [x] Transaction ordering for apply (XOR-based sorting)
- [x] Close time handling
- [x] Protocol upgrades (version, base_fee, base_reserve, max_tx_set_size)
- [x] SCP history entries for metadata
- [x] Ledger close result generation
- [x] Ledger close statistics tracking

#### Ledger Snapshots (`LedgerStateSnapshot.h` -> `snapshot.rs`)
- [x] Point-in-time immutable snapshots (`LedgerSnapshot`)
- [x] Snapshot handles with lazy loading (`SnapshotHandle`)
- [x] Entry lookup with bucket list fallback
- [x] Header lookup for historical queries
- [x] Full entries enumeration
- [x] Snapshot lifecycle management (`SnapshotManager`)
- [x] Builder pattern for snapshot construction

#### Ledger Close Metadata (`LedgerCloseMetaFrame.h/.cpp` -> `manager.rs`)
- [x] LedgerCloseMeta V2 generation
- [x] LedgerHeaderHistoryEntry construction
- [x] Transaction result meta collection
- [x] SCP history inclusion

#### Transaction Execution (`execution.rs`)
- [x] Transaction execution during ledger close
- [x] Fee charging (upfront for all transactions)
- [x] Sequence number validation and consumption
- [x] State loading from snapshots
- [x] Operation execution via `stellar-core-tx`
- [x] Result and metadata collection
- [x] Soroban transaction support
- [x] Soroban config loading from ledger
- [x] Soroban resource fee computation
- [x] Soroban rent fee handling
- [x] Footprint-based entry loading
- [x] TTL entry handling
- [x] Archived entry clearing for restore operations
- [x] Classic event generation (fee events)
- [x] Operation-level invariant validation

#### Network Configuration (`NetworkConfig.h/.cpp` -> `execution.rs`)
- [x] Loading contract cost parameters (CPU/memory)
- [x] Loading compute limits (tx_max_instructions, memory_limit)
- [x] Loading ledger cost settings (fees for reads/writes)
- [x] Loading state archival TTL settings
- [x] Loading event size limits
- [x] Fee configuration construction
- [x] Rent fee configuration construction

#### Fee and Reserve Calculations (`lib.rs`)
- [x] Transaction fee calculation
- [x] Envelope fee calculation (V0, V1, fee bump)
- [x] Available balance for fees
- [x] Minimum balance calculation
- [x] Selling/buying liabilities handling
- [x] Available to send/receive
- [x] Sub-entry affordability check

### Not Yet Implemented (Gaps)

#### LedgerTxn System (`LedgerTxn.h`, `LedgerTxnImpl.h`, `LedgerTxnEntry.h`)
- [ ] **Nested transaction support** - C++ has `LedgerTxn` that can nest with parent/child relationships for rollback isolation. Rust uses `LedgerDelta` without nesting.
- [ ] **Entry activation tracking** - C++ tracks "active" entries to prevent concurrent access bugs via `LedgerTxnEntry::Impl`
- [ ] **Offer sorting utilities** (`isBetterOffer`, `OfferDescriptor`) - Used for order book operations
- [ ] **Asset pair hash utilities** (`AssetPairHash`, `AssetPair`)
- [ ] **Inflation winners query** (`InflationWinner` struct)
- [ ] **Restored entries tracking** (`RestoredEntries` struct) - Tracks entries restored from hot archive vs live bucket list

#### In-Memory Soroban State (`InMemorySorobanState.h/.cpp`)
- [ ] **In-memory contract data cache** - C++ maintains an in-memory map of live Soroban state for fast access
- [ ] **Contract code size tracking** - Tracks size in memory for each contract code entry
- [ ] **TTL data co-location** - TTL stored directly with contract data to avoid extra lookups
- [ ] **Memory-efficient contract data map** - Uses polymorphic entries to avoid key duplication

#### Shared Module Cache (`SharedModuleCacheCompiler.h/.cpp`)
- [ ] **Compiled module cache** - C++ pre-compiles WASM modules for faster Soroban execution
- [ ] **Background compilation** - Compiles contracts in background threads
- [ ] **Module cache rebuilding** - Rebuilds cache when arena builds up dead space

#### Network Configuration Management (`NetworkConfig.h/.cpp`)
- [ ] **Config upgrade creation functions** (`createLedgerEntriesForV20`, `createCostTypesForV21/V22/V23`)
- [ ] **Config upgrade validation** - Validates upgrade parameters against minimums
- [ ] **Live state size snapshots** (`maybeSnapshotSorobanStateSize`)
- [ ] **Eviction iterator management** (`updateEvictionIterator`)
- [ ] **Full SorobanNetworkConfig class** - C++ has a complete wrapper with all config getters

#### Parallel Transaction Apply (`LedgerManagerImpl.h`)
- [ ] **Apply thread separation** - C++ has dedicated apply thread for CPU-intensive work
- [ ] **Parallel Soroban execution** - Multiple threads execute non-conflicting Soroban transactions
- [ ] **Apply state phases** (SETTING_UP_STATE, READY_TO_APPLY, APPLYING, COMMITTING)
- [ ] **Thread-safe state transitions**
- [ ] **Soroban stage/cluster parallelism** (`applySorobanStageClustersInParallel`)

#### State Archival / Eviction
- [ ] **Eviction scan processing** - C++ scans bucket list for entries to evict
- [ ] **Hot archive integration during apply** - Moving evicted entries to hot archive
- [ ] **Eviction metrics** - Tracking eviction progress and sizes

#### SQL Backend Support (`LedgerTxn*.cpp`)
- [ ] **SQL transaction integration** - C++ uses SQL transactions for persistence
- [ ] **Entry prefetching** (`prefetchTransactionData`, `prefetchTxSourceIds`)
- [ ] **Batch commit optimization** (`LEDGER_ENTRY_BATCH_COMMIT_SIZE`)
- [ ] **Consistency modes** (`LedgerTxnConsistency::EXACT`, `EXTRA_DELETES`)

#### Metrics and Monitoring
- [ ] **Soroban metrics** (`SorobanMetrics.h/.cpp`) - Detailed metrics for Soroban execution
- [ ] **Ledger apply metrics** (transaction count, operation count, timings)
- [ ] **Prefetch hit rate tracking**
- [ ] **Meta stream writing metrics**

#### Checkpoint / History
- [ ] **Checkpoint range handling** (`CheckpointRange.h/.cpp`)
- [ ] **Ledger range utilities** (`LedgerRange.h/.cpp`)
- [ ] **Meta stream writing** (`XDROutputFileStream`)
- [ ] **Meta debug stream rotation** (`FlushAndRotateMetaDebugWork`)

#### Protocol 23 Hot Archive Bug Handling
- [ ] **P23HotArchiveBug.h/.cpp** - Special handling for a specific mainnet bug

### Implementation Notes

#### Architectural Differences

1. **State Management Model**
   - C++: Uses `LedgerTxn` with nested parent/child relationships for transactional isolation
   - Rust: Uses flat `LedgerDelta` with change coalescing. Simpler but less flexible for partial rollbacks.

2. **Threading Model**
   - C++: Multi-threaded with dedicated apply thread and parallel Soroban execution
   - Rust: Single-threaded execution. Thread safety is for concurrent reads, not parallel apply.

3. **Persistence Layer**
   - C++: Dual SQL + Bucket List with SQL being phased out
   - Rust: Bucket List only. No SQL persistence layer.

4. **Module Caching**
   - C++: Maintains compiled WASM module cache for Soroban performance
   - Rust: No module caching. Relies on Soroban host's own caching.

5. **State Lookup Strategy**
   - C++: In-memory Soroban state + bucket list with prefetching
   - Rust: Direct bucket list lookups with entry caching

#### Design Rationale

The Rust implementation prioritizes:
- **Simplicity**: Flat delta model vs nested transactions
- **Determinism**: All operations produce identical results
- **Correctness**: Focus on matching C++ ledger close semantics

Trade-offs made:
- Less flexible transaction isolation (no nested rollback)
- No parallel apply (simpler concurrency model)
- Potentially slower Soroban execution (no module cache)

## Tests To Port

From `src/ledger/test/`:
- [ ] Ledger close meta vectors
- [ ] LedgerTxn consistency checks
- [ ] Bucket hash consistency
- [ ] Skip list verification
- [ ] Entry change coalescing
- [ ] Soroban resource fee calculation
- [ ] Network config loading
