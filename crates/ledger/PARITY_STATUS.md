## stellar-core Parity Status

This section documents the implementation status compared to stellar-core upstream in `.upstream-v25/src/ledger/`.

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
- [x] Initialize from buckets (catchup scenario)
- [x] Reinitialize from buckets (re-sync scenario)
- [x] Apply historical ledger (replay mode)
- [x] SCP timing configuration lookup
- [x] LedgerCloseMeta V2 generation
- [x] LedgerHeaderHistoryEntry construction
- [x] Transaction result meta collection
- [x] SCP history inclusion in metadata

#### Ledger Header Utilities (`LedgerHeaderUtils.h/.cpp` -> `header.rs`)
- [x] Header hash computation (`compute_header_hash`)
- [x] Skip list computation (`compute_skip_list`)
- [x] Skip list target sequence calculation (`skip_list_target_seq`)
- [x] Header chain verification (`verify_header_chain`)
- [x] Skip list verification (`verify_skip_list`)
- [x] Next header creation (`create_next_header`)
- [x] Close time extraction
- [x] Protocol version extraction
- [x] Protocol version comparison utilities

#### Ledger Delta / Change Tracking (`LedgerTxn*.h` -> `delta.rs`)
- [x] Entry change tracking (create/update/delete)
- [x] Change coalescing (create+update=create, create+delete=no-op, etc.)
- [x] Fee pool delta tracking
- [x] Total coins delta tracking
- [x] Categorized entry extraction (init/live/dead for bucket list)
- [x] Deterministic ordering of changes
- [x] Delta merging
- [x] Entry-to-key conversion for all entry types

#### Ledger Close Data (`close.rs`)
- [x] Transaction set handling (classic and generalized)
- [x] Transaction set hash computation
- [x] Transaction ordering for apply (XOR-based sorting)
- [x] Close time handling
- [x] Protocol upgrades (version, base_fee, base_reserve, max_tx_set_size)
- [x] SCP history entries for metadata
- [x] Ledger close result generation
- [x] Ledger close statistics tracking
- [x] Parallel phase transaction ordering (V1 phases)
- [x] Per-component base fee handling

#### Ledger Snapshots (`LedgerStateSnapshot.h` -> `snapshot.rs`)
- [x] Point-in-time immutable snapshots (`LedgerSnapshot`)
- [x] Snapshot handles with lazy loading (`SnapshotHandle`)
- [x] Entry lookup with bucket list fallback
- [x] Header lookup for historical queries
- [x] Full entries enumeration
- [x] Snapshot lifecycle management
- [x] Builder pattern for snapshot construction
- [x] Account lookup utilities

#### Transaction Execution (`execution.rs`)
- [x] Transaction execution during ledger close
- [x] Fee charging (upfront for all transactions)
- [x] Sequence number validation and consumption
- [x] State loading from snapshots
- [x] Operation execution via `henyey-tx`
- [x] Result and metadata collection
- [x] Soroban transaction support
- [x] Soroban config loading from ledger
- [x] Soroban resource fee computation (via soroban-env-host)
- [x] Soroban rent fee handling
- [x] Footprint-based entry loading
- [x] TTL entry handling
- [x] Archived entry clearing for restore operations
- [x] Classic event generation (fee events)
- [x] Operation-level invariant validation
- [x] Refundable fee tracking and refund calculation
- [x] Transaction executor with state manager integration
- [x] Per-operation savepoints for automatic rollback on failure (matches stellar-core nested LedgerTxn)
- [x] HashX signature verification (variable length preimages)

#### Network Configuration (`NetworkConfig.h/.cpp` -> `execution.rs`)
- [x] Loading contract cost parameters (CPU/memory)
- [x] Loading compute limits (tx_max_instructions, memory_limit)
- [x] Loading ledger cost settings (fees for reads/writes)
- [x] Loading state archival TTL settings
- [x] Loading event size limits
- [x] Fee configuration construction
- [x] Rent fee configuration construction
- [x] Loading live Soroban state size window
- [x] Rent write fee computation

#### Fee and Reserve Calculations (`lib.rs`)
- [x] Transaction fee calculation
- [x] Envelope fee calculation (V0, V1, fee bump)
- [x] Available balance for fees
- [x] Minimum balance calculation
- [x] Selling/buying liabilities handling
- [x] Available to send/receive
- [x] Sub-entry affordability check
- [x] Sponsorship accounting in reserves

#### Order Book Utilities (`offer.rs`)
- [x] Offer sorting utilities (`isBetterOffer`, `OfferDescriptor`)
- [x] Asset pair hash utilities (`AssetPairHash`, `AssetPair`)
- [x] Offer cache for efficient orderbook operations (avoids bucket list scans)

#### In-Memory Soroban State (`soroban_state.rs` -> `InMemorySorobanState.h/.cpp`)
- [x] `InMemorySorobanState` - In-memory cache for contract data and code
- [x] `ContractDataMapEntry` - Contract data with co-located TTL
- [x] `ContractCodeMapEntry` - Contract code with TTL and size tracking
- [x] `TtlData` - TTL data structure for co-location
- [x] TTL co-location with entries (avoids redundant key storage)
- [x] Pending TTL handling for out-of-order initialization
- [x] Contract data state size tracking (XDR size)
- [x] Contract code state size tracking (in-memory module size)
- [x] Entry get/create/update/delete operations
- [x] TTL entry synthesis from co-located data
- [x] `update_state()` for ledger close batch updates
- [x] `SharedSorobanState` thread-safe wrapper with RwLock
- [x] Protocol-aware code size computation

### Not Yet Implemented (Gaps)

#### LedgerTxn Nested Transaction System (`LedgerTxn.h`, `LedgerTxnImpl.h`)
- [x] **Per-operation rollback isolation** - Rust uses savepoints (`create_savepoint` / `rollback_to_savepoint`) around each operation to match stellar-core nested `LedgerTxn` commit/rollback semantics. Failed operations have their state mutations fully reverted.
- [ ] **General-purpose nested transactions** - stellar-core supports arbitrary nesting depth with parent/child relationships. Rust supports single-level savepoints (sufficient for the operation execution loop).
- [ ] **Entry activation tracking** - stellar-core tracks "active" entries to prevent concurrent access bugs via `LedgerTxnEntry::Impl`
- [ ] **EntryPtrState tracking** (INIT/LIVE/DELETED states with merging logic)
- [ ] **LedgerTxnConsistency modes** (EXACT vs EXTRA_DELETES)
- [ ] **Transaction modes** (READ_ONLY_WITHOUT_SQL_TXN, READ_WRITE_WITH_SQL_TXN)

#### Order Book Utilities (`LedgerTxn.h`)
- [ ] **Inflation winners query** (`InflationWinner` struct)
- [x] **Best offer queries** for DEX matching (via `OfferIndex` in `henyey-tx`)
- [x] **Offer cache** - Pre-loaded offers from bucket list with incremental updates

#### Entry Restoration Tracking
- [ ] **Restored entries tracking** (`RestoredEntries` struct) - Tracks entries restored from hot archive vs live bucket list

#### Shared Module Cache (`SharedModuleCacheCompiler.h/.cpp`)
- [ ] **Compiled module cache** - stellar-core pre-compiles WASM modules for faster Soroban execution
- [ ] **Background compilation** - Compiles contracts in background threads
- [ ] **Module cache rebuilding** - Rebuilds cache when arena builds up dead space
- [ ] **Module cache eviction** - Evicts modules when contracts are evicted from live BL

#### Network Configuration Management (`NetworkConfig.h/.cpp`)
- [ ] **Config upgrade creation functions** (`createLedgerEntriesForV20`, `createCostTypesForV21/V22/V23/V25`)
- [ ] **Config upgrade validation** - Validates upgrade parameters against minimums/maximums
- [ ] **Live state size snapshots** (`maybeSnapshotSorobanStateSize`)
- [ ] **Eviction iterator management** (`updateEvictionIterator`)
- [ ] **Full SorobanNetworkConfig class** - stellar-core has a complete wrapper with all config getters
- [ ] **Protocol-specific upgrade handlers** (`createAndUpdateLedgerEntriesForV23`)

#### Parallel Transaction Apply (`LedgerManagerImpl.h`)
- [ ] **Apply thread separation** - stellar-core has dedicated apply thread for CPU-intensive work
- [ ] **Parallel Soroban execution** - Multiple threads execute non-conflicting Soroban transactions
- [ ] **Apply state phases** (SETTING_UP_STATE, READY_TO_APPLY, APPLYING, COMMITTING)
- [ ] **Thread-safe state transitions** with phase assertions
- [ ] **Soroban stage/cluster parallelism** (`applySorobanStageClustersInParallel`)
- [ ] **Global parallel apply ledger state** management
- [ ] **Thread parallel apply ledger state** per-thread state

#### State Archival / Eviction
- [ ] **Eviction scan processing** - stellar-core scans bucket list for entries to evict
- [ ] **Hot archive integration during apply** - Moving evicted entries to hot archive
- [ ] **Eviction metrics** - Tracking eviction progress and sizes
- [ ] **Eviction iterator state** persistence

#### SQL Backend Support (`LedgerTxn*.cpp`)
- [ ] **SQL transaction integration** - stellar-core uses SQL transactions for persistence
- [ ] **Entry prefetching** (`prefetchTransactionData`, `prefetchTxSourceIds`)
- [ ] **Batch commit optimization** (`LEDGER_ENTRY_BATCH_COMMIT_SIZE`)
- [ ] **SQL-based offer queries** (`LedgerTxnOfferSQL.cpp`)

#### Metrics and Monitoring
- [ ] **Soroban metrics** (`SorobanMetrics.h/.cpp`) - Detailed metrics for Soroban execution
- [ ] **Ledger apply metrics** (transaction count, operation count, timings per phase)
- [ ] **Prefetch hit rate tracking**
- [ ] **Meta stream writing metrics**
- [ ] **Module cache compilation metrics**

#### Checkpoint / History
- [ ] **Checkpoint range handling** (`CheckpointRange.h/.cpp`)
- [ ] **Ledger range utilities** (`LedgerRange.h/.cpp`)
- [ ] **Meta stream writing** (`XDROutputFileStream`)
- [ ] **Meta debug stream rotation** (`FlushAndRotateMetaDebugWork`)

#### Protocol 23 Hot Archive Bug Handling
- [ ] **P23HotArchiveBug.h/.cpp** - Special handling for a specific mainnet bug

#### Trust Line Wrapper (`TrustLineWrapper.h/.cpp`)
- [ ] **Trust line abstraction** for poolshare vs regular trust lines
- [ ] **Balance and limit getters/setters** with type checking

#### Internal Ledger Entry (`InternalLedgerEntry.h/.cpp`)
- [ ] **InternalLedgerEntry wrapper** - stellar-core wrapper adding sponsorship tracking
- [ ] **InternalLedgerKey** - Extended key type with additional metadata

### Implementation Notes

#### Architectural Differences

1. **State Management Model**
   - stellar-core: Uses `LedgerTxn` with nested parent/child relationships for transactional isolation. Each nested transaction can be independently committed or rolled back.
   - Rust: Uses `LedgerDelta` with change coalescing and per-operation savepoints. The savepoint mechanism provides the same per-operation rollback isolation as stellar-core nested `LedgerTxn`, ensuring failed operations do not leave partial state changes.

2. **Threading Model**
   - stellar-core: Multi-threaded with dedicated apply thread and parallel Soroban execution. Uses phase-based state machine (SETTING_UP_STATE -> READY_TO_APPLY -> APPLYING -> COMMITTING) to coordinate thread access.
   - Rust: Single-threaded execution. Thread safety is for concurrent reads, not parallel apply.

3. **Persistence Layer**
   - stellar-core: Dual SQL + Bucket List with SQL being phased out. Supports both read-only and read-write SQL transaction modes.
   - Rust: Bucket List only. No SQL persistence layer.

4. **Module Caching**
   - stellar-core: Maintains compiled WASM module cache for Soroban performance. Supports background compilation and cache rebuilding.
   - Rust: No module caching. Relies on Soroban host's own caching.

5. **State Lookup Strategy**
   - stellar-core: In-memory Soroban state + bucket list with prefetching for known transaction footprints.
   - Rust: Direct bucket list lookups with in-memory Soroban state.

6. **Entry Tracking**
   - stellar-core: Uses `LedgerEntryPtr` with INIT/LIVE/DELETED states and sophisticated merging logic.
   - Rust: Uses simpler `EntryChange` enum with Created/Updated/Deleted variants.

#### Design Rationale

The Rust implementation prioritizes:
- **Simplicity**: Delta model with targeted savepoints vs fully general nested transactions
- **Determinism**: All operations produce identical results
- **Correctness**: Focus on matching stellar-core ledger close semantics (per-operation rollback via savepoints)

Trade-offs made:
- No general-purpose nested transactions (savepoints cover the operation execution use case)
- No parallel apply (simpler concurrency model)
- Potentially slower Soroban execution (no module cache)
- No SQL backend (bucket list only)

### Parity Summary

| Category | stellar-core Features | Rust Implementation | Parity Level |
|----------|--------------|---------------------|--------------|
| Core Ledger Close | Full | Full | 100% |
| Header Utilities | Full | Full | 100% |
| Change Tracking | Full | Simplified | 90% |
| Snapshots | Full | Full | 100% |
| Transaction Execution | Full | Full | 100% |
| Network Config Loading | Full | Full | 100% |
| Fee/Reserve Calc | Full | Full | 100% |
| In-Memory Soroban State | Full | Full | 100% |
| Nested Transactions | Full | Per-operation savepoints | 50% |
| Parallel Apply | Full | None | 0% |
| Module Cache | Full | None | 0% |
| SQL Backend | Full | None | 0% |
| Eviction Processing | Full | None | 0% |
| Metrics | Full | Minimal | 20% |

**Overall Parity Estimate: ~85%**

The core ledger close functionality has full parity. Per-operation rollback isolation is implemented via savepoints, matching stellar-core nested `LedgerTxn` behavior for the operation execution loop. The remaining gaps are primarily in:
1. Advanced concurrency features (parallel apply, general-purpose nested transactions)
2. Performance optimizations (module cache, prefetching)
3. Legacy SQL backend support
4. Operational tooling (metrics, eviction)

## Tests To Port

From `src/ledger/test/`:
- [ ] Ledger close meta vectors
- [ ] LedgerTxn consistency checks
- [ ] Bucket hash consistency
- [ ] Skip list verification
- [ ] Entry change coalescing
- [ ] Soroban resource fee calculation
- [ ] Network config loading
- [x] Per-operation rollback semantics (via savepoints)
- [ ] General nested transaction rollback semantics (arbitrary nesting depth)
- [ ] Parallel apply correctness
