## C++ Parity Status

This section documents the parity between this Rust crate and the upstream C++ `src/simulation/` module.

### Implemented

#### OverlaySimulation (partial parity with C++ `Simulation` class)

| Feature | Rust | C++ | Notes |
|---------|------|-----|-------|
| Create multi-node simulation | `start()`, `start_with_seed()` | `Simulation()` constructor | Rust uses async, C++ uses VirtualClock |
| Deterministic key generation | `derive_seed()` | `SIMULATION_CREATE_NODE` macro | Both use SHA-256 based derivation |
| Star topology connections | `start_with_seed()` | `addPendingConnection()` | Rust only supports star; C++ supports arbitrary topologies |
| Node count accessor | `node_count()` | `getNodes().size()` | Equivalent functionality |
| Hub node accessor | `hub()` | `getNode(nodeID)` | Rust has convenience method for hub |
| Broadcast SCP messages | `broadcast_scp()` | N/A (done via Application) | Rust has test helper for placeholder SCP messages |
| Graceful shutdown | `shutdown()` | Destructor + `stopAllNodes()` | Both support clean termination |
| Port allocation | `allocate_port()` | Via `Config` | Rust uses ephemeral ports; C++ uses config-based |

#### VirtualClock (`virtual_clock.rs`)
- [x] `VirtualClock` - Clock abstraction with virtual/real time modes
- [x] `ClockMode::VirtualTime` / `ClockMode::RealTime` - Operating modes
- [x] `now()` / `now_nanos()` - Time queries (virtual or real)
- [x] `system_now()` - System time with virtual time support
- [x] `set_virtual_time()` - Set virtual time to specific point
- [x] `advance_by()` - Advance virtual time by duration
- [x] `sleep_for()` - Sleep (real) or advance (virtual) time
- [x] `schedule_at()` / `schedule_after()` - Time-based event scheduling
- [x] `EventHandle` - Cancel scheduled events
- [x] `crank()` / `crank_with_options()` - Event loop advancement
- [x] `crank_until()` - Crank until predicate is satisfied
- [x] `crank_for_at_least()` - Crank for minimum duration
- [x] `crank_for_at_most()` - Crank for maximum duration or until idle
- [x] `ClockStats` - Statistics tracking (events scheduled/triggered/cancelled, crank cycles)
- [x] `SharedVirtualClock` - Thread-safe Arc<VirtualClock> wrapper

#### TxGenerator (`tx_generator.rs`)
- [x] `TxGeneratorConfig` - Configuration (network passphrase, base_fee, max_fee_rate)
- [x] `TxGeneratorConfig::testnet()` / `::mainnet()` - Network presets
- [x] `TestAccount` - Account with sequence number tracking
- [x] `TestAccount::from_name()` - Deterministic name-based account creation
- [x] `TestAccount::next_sequence_number()` - Sequence increment for transactions
- [x] `TxGenerator` - Main transaction generator with account caching
- [x] `TxGenerator::find_account()` / `find_account_mut()` - Account lookup/creation
- [x] `TxGenerator::payment_transaction()` - Generate payment TXs (1 stroop)
- [x] `TxGenerator::create_account_transaction()` - Generate create account TXs
- [x] `TxGenerator::generate_fee()` - Fee generation with optional randomization
- [x] `derive_seed_from_name()` - Deterministic seed from account name (SHA-256)
- [x] `compute_network_id()` - Network ID hash computation
- [x] `compute_transaction_hash()` - Transaction hash for signing
- [x] `signature_hint()` - Last 4 bytes of public key for decorated signatures
- [x] Transaction signing and envelope creation

### Not Yet Implemented (Gaps)

#### Simulation Class (`Simulation.h/.cpp`)

| Feature | C++ API | Description | Priority |
|---------|---------|-------------|----------|
| **Connection Modes** | `Mode::OVER_TCP`, `Mode::OVER_LOOPBACK` | C++ supports both real TCP and in-process loopback connections | Medium |
| **Multi-Node Clock Sync** | `setCurrentVirtualTime()` across all nodes | Synchronize all node clocks to a specific time point | Medium |
| **Node Management** | `addNode()`, `removeNode()`, `getNode()` | Dynamic node add/remove during simulation | Medium |
| **Pending Connections** | `addPendingConnection()` | Queue connections before starting simulation | Low |
| **Loopback Connections** | `getLoopbackConnection()` | Access to loopback peer connections for testing | Low |
| **Start/Stop Control** | `startAllNodes()`, `stopAllNodes()` | Explicit lifecycle control for all nodes | Medium |
| **Crank Mechanisms** | `crankNode()`, `crankAllNodes()` | Manual event loop advancement for nodes | Medium |
| **Consensus Verification** | `haveAllExternalized()` | Check if all nodes externalized a ledger | High |
| **Metrics Summary** | `metricsSummary()` | Aggregate metrics across nodes | Low |
| **Connection Control** | `addConnection()`, `dropConnection()` | Dynamic connection manipulation | Medium |
| **Config Generation** | `newConfig()`, `ConfigGen` | Custom config generators per node | Medium |
| **Quorum Set Adjustment** | `QuorumSetAdjuster` | Modify quorum sets dynamically | Medium |
| **Overlay Tick Control** | `stopOverlayTick()` | Prevent automatic peer reconnection | Low |
| **Soroban Upgrade Support** | `isSetUpForSorobanUpgrade()`, `markReadyForSorobanUpgrade()` | Track Soroban upgrade readiness | Low |
| **Application Integration** | `ApplicationLoopbackOverlay` | Full application lifecycle management | High |

#### Topologies (`Topologies.h/.cpp`)

| Feature | C++ API | Description | Priority |
|---------|---------|-------------|----------|
| **Pair Topology** | `pair()` | Two-node connected simulation | Low |
| **Cycle4 Topology** | `cycle4()` | Four-node cyclic quorum network | Low |
| **Core (Mesh) Topology** | `core()` | N-node fully-connected mesh with shared quorum | Medium |
| **Cycle Topology** | `cycle()` | N-node one-way connected ring | Low |
| **Branched Cycle** | `branchedcycle()` | Ring with cross-connections | Low |
| **Separate (No Connection)** | `separate()` | N nodes with quorum but no connections | Low |
| **Hierarchical Quorum** | `hierarchicalQuorum()` | Multi-tier quorum (core + mid-tier nodes) | Medium |
| **Hierarchical Simplified** | `hierarchicalQuorumSimplified()` | 2-tier with variable core size | Medium |
| **Custom-A** | `customA()` | 7-node network for resilience testing | Low |
| **Asymmetric** | `asymmetric()` | Core topology with extra nodes on one validator | Low |

#### LoadGenerator (`LoadGenerator.h/.cpp`)

| Feature | C++ API | Description | Priority |
|---------|---------|-------------|----------|
| **Load Generation Modes** | `LoadGenMode` enum | PAY, SOROBAN_UPLOAD, SOROBAN_INVOKE, etc. | High |
| **Config-based Load** | `GeneratedLoadConfig` | Configure tx rates, spikes, accounts | High |
| **Generate Load** | `generateLoad()` | Step-based load generation | High |
| **Transaction Metrics** | `TxMetrics` | Track tx attempts, rejections, bytes | Medium |
| **Account Management** | `getNextAvailableAccount()` | Prevent source account collisions | Medium |
| **Soroban Load** | Various Soroban transaction creators | Upload, invoke, upgrade transactions | High |
| **Mixed Load** | `createMixedClassicSorobanTransaction()` | Blend classic and Soroban transactions | Medium |
| **Pre-generated TX Support** | `PAY_PREGENERATED` mode | Load transactions from XDR file | Low |
| **Success Rate Tracking** | `checkMinimumSorobanSuccess()` | Verify Soroban success thresholds | Medium |

#### TxGenerator - Remaining Gaps (`TxGenerator.h/.cpp`)

| Feature | C++ API | Description | Priority |
|---------|---------|-------------|----------|
| **Upload Wasm** | `createUploadWasmTransaction()` | Deploy Wasm blobs | High |
| **Create Contract** | `createContractTransaction()` | Deploy contract instances | High |
| **Invoke Contract** | `invokeSorobanLoadTransaction()` | Execute contract calls | High |
| **SAC Transactions** | `createSACTransaction()`, `invokeSACPayment()` | Stellar Asset Contract operations | Medium |
| **Batch Transfers** | `invokeBatchTransfer()` | Multi-destination transfers | Medium |
| **Random Wasm** | `sorobanRandomWasmTransaction()` | Generate random Wasm for testing | Low |
| **Config Upgrades** | `invokeSorobanCreateUpgradeTransaction()` | Network config upgrade TXs | Medium |

Note: Core payment transactions, create account transactions, account caching, and fee generation are now implemented in `tx_generator.rs`.

#### ApplyLoad (`ApplyLoad.h/.cpp`)

| Feature | C++ API | Description | Priority |
|---------|---------|-------------|----------|
| **Benchmark Mode** | `benchmark()` | Fill ledger with max transactions | High |
| **Max SAC TPS** | `findMaxSacTps()` | Binary search for max throughput | Medium |
| **Resource Utilization** | Various `get*Utilization()` methods | Track instruction, disk, tx size usage | Medium |
| **Contract Setup** | `setupLoadContract()`, `setupXLMContract()`, etc. | Initialize test contracts | High |
| **Close Ledger** | `closeLedger()` | Apply transactions and close | High |
| **Success Rate** | `successRate()` | Percentage of successful TXs | Medium |
| **Batch Transfer Setup** | `setupBatchTransferContracts()` | Initialize batch transfer testing | Low |
| **Hot Archive Entries** | `getKeyForArchivedEntry()` | Pre-populate archived state | Low |

#### CoreTests (`CoreTests.cpp`)

| Feature | Description | Priority |
|---------|-------------|----------|
| **Integration Tests** | Full consensus tests with multiple nodes | Medium |
| **Upgrade Tests** | Protocol upgrade scenario testing | Medium |
| **Resilience Tests** | Node failure and recovery scenarios | Medium |

### Implementation Notes

#### Architectural Differences

1. **Async vs VirtualClock**: The Rust implementation uses Tokio's async runtime alongside a `VirtualClock` abstraction that provides deterministic time control similar to C++. The Rust `VirtualClock` supports both virtual time (for fast deterministic tests) and real time modes, with crank-based event loop advancement (`crank()`, `crank_until()`, `crank_for_at_least()`, `crank_for_at_most()`).

2. **Application Integration**: The C++ `Simulation` class manages full `Application` instances with ledger, herder, overlay, and all other subsystems. The Rust `OverlaySimulation` currently only manages `OverlayManager` instances, meaning it cannot test consensus, ledger application, or transaction processing.

3. **Loopback vs TCP**: C++ supports both in-process loopback connections (faster, more deterministic) and real TCP connections. Rust currently uses real TCP on localhost.

4. **Topology Flexibility**: C++ has a rich `Topologies` module for creating various network structures. Rust currently hardcodes a star topology.

5. **Load Generation**: The C++ load generator is deeply integrated with the application stack for realistic transaction generation and application. This would require significant additional infrastructure in Rust.

#### Migration Path Recommendations

1. **Phase 1 - Virtual Time**: ✅ Implemented! The `VirtualClock` provides deterministic time control with crank-based event loop advancement.

2. **Phase 2 - Topologies**: Extract topology creation into a separate module supporting arbitrary connection patterns.

3. **Phase 3 - Application Integration**: Once `stellar-core-herder` and `stellar-core-ledger` are implemented, integrate them into simulation.

4. **Phase 4 - Load Generation**: ✅ Partially implemented! Core `TxGenerator` with payment and create account transactions. Remaining: Soroban contract transactions (upload, create, invoke).

#### Current Rust-Specific Advantages

- **Async-first design**: Better suited for real concurrent testing scenarios
- **Type safety**: Stronger compile-time guarantees
- **Simpler API**: `start_with_seed()` provides an easy entry point for basic tests
- **Test message helpers**: `broadcast_scp()` provides quick placeholder message generation
