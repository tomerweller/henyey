## C++ Parity Status

This section documents the feature parity between this Rust crate and the C++ upstream implementation in `stellar-core/src/overlay/`.

### Implemented

The following features from the C++ overlay are implemented in Rust:

#### Core Infrastructure
- **OverlayManager** (`manager.rs`) - Central coordinator for peer connections
  - Start/shutdown lifecycle management
  - Inbound/outbound connection limits with separate pools
  - Peer count tracking and statistics
  - Message broadcasting to all peers
  - Connection to specific peer addresses
  - Shutdown with graceful peer disconnection

- **Peer** (`peer.rs`) - Individual authenticated peer connection
  - Full Hello/Auth handshake implementation
  - Message send/receive with MAC authentication
  - Peer state machine (Connecting -> Handshaking -> Authenticated -> Disconnected)
  - Per-peer statistics (messages/bytes sent/received)
  - Flow control via SendMore/SendMoreExtended
  - Connection direction tracking (inbound vs outbound)

- **PeerAuth / AuthContext** (`auth.rs`) - X25519 + HMAC-SHA256 authentication
  - AuthCert creation and verification
  - Ephemeral X25519 key generation
  - Signature over network_id || envelope_type || expiration || pubkey
  - HKDF key derivation for send/receive MAC keys
  - Sequence numbers to prevent replay attacks
  - Message MAC computation and verification

- **TCPPeer / Connection** (`connection.rs`) - TCP transport layer
  - TCP connection establishment with timeout
  - Connection listener for inbound peers
  - TCP_NODELAY for low latency
  - Connection pool with atomic reservation

- **MessageCodec** (`codec.rs`) - XDR message framing
  - Length-prefixed message framing (4-byte header)
  - Bit 31 authentication flag handling
  - Streaming decode state machine
  - Message size limits (min 12 bytes, max 32MB)

- **Floodgate / FloodGate** (`flood.rs`) - Duplicate detection and flooding
  - SHA-256 message hash tracking
  - Peer tracking per message (who sent what)
  - TTL-based expiry with periodic cleanup
  - Rate limiting (messages per second)
  - Forward peer calculation (exclude senders)

#### Configuration & Types
- **OverlayConfig** - Testnet/Mainnet presets, configurable limits
- **LocalNode** - Node identity with protocol versions
- **PeerAddress** - Host:port representation
- **PeerId** - Ed25519 public key identifier
- **PeerInfo** - Static peer metadata
- **PeerStats** - Atomic message/byte counters

#### Message Handling
- Hello/Auth handshake messages
- Peers message for peer discovery
- SendMore/SendMoreExtended flow control
- Error message logging
- Flood message detection (Transaction, SCP, FloodAdvert, FloodDemand)

#### Peer Management
- Preferred peers with priority connection
- Automatic outbound connection maintenance
- Periodic peer list advertisement
- Known peer tracking and discovery
- Basic ban list (in-memory)

### Not Yet Implemented (Gaps)

The following C++ components are not yet implemented:

#### Major Features

| C++ Component | Files | Description | Priority |
|--------------|-------|-------------|----------|
| **FlowControl** | `FlowControl.h/cpp`, `FlowControlCapacity.h/cpp` | Full flow control with capacity tracking, outbound queuing, load shedding, message prioritization (SCP > TX > Demand > Advert) | High |
| **ItemFetcher** | `ItemFetcher.h/cpp`, `Tracker.h/cpp` | Anycast fetch for TxSet and QuorumSet with retry logic, timeout handling, and envelope tracking | High |
| **BanManager** | `BanManager.h/cpp`, `BanManagerImpl.h/cpp` | Persistent ban list in database, ban duration, unban functionality | Medium |
| **PeerManager** | `PeerManager.h/cpp` | Persistent peer storage in database, failure tracking, next-attempt scheduling, backoff | Medium |
| **SurveyManager** | `SurveyManager.h/cpp`, `SurveyDataManager.h/cpp`, `SurveyMessageLimiter.h/cpp` | Network topology surveys, time-sliced surveys, survey data collection and reporting | Medium |
| **TxAdverts** | `TxAdverts.h/cpp` | Transaction advertisement batching, outgoing advert queue, advert history cache | Medium |
| **TxDemandsManager** | `TxDemandsManager.h/cpp` | Transaction demand scheduling, retry with linear backoff, demand timeout handling | Medium |
| **OverlayMetrics** | `OverlayMetrics.h/cpp` | Comprehensive metrics collection via medida (timers, meters, counters, histograms) | Low |

#### Message Handlers

The following message types are received but not fully processed:

| Message Type | Status |
|--------------|--------|
| `GetTxSet` | Not handled (need TxSet storage) |
| `TxSet` / `GeneralizedTxSet` | Not handled (need ItemFetcher) |
| `GetScpQuorumSet` | Not handled (need QuorumSet storage) |
| `ScpQuorumset` | Not handled (need ItemFetcher) |
| `ScpMessage` | Forwarded to subscribers only (no SCP integration) |
| `GetScpState` | Not handled (need SCP state) |
| `Transaction` | Forwarded to subscribers only (no transaction queue) |
| `FloodAdvert` | Not handled (need TxAdverts) |
| `FloodDemand` | Not handled (need TxDemandsManager) |
| `TimeSlicedSurvey*` | Not handled (need SurveyManager) |
| `DontHave` | Not handled (need ItemFetcher) |

#### Detailed Feature Gaps

1. **Flow Control (Full Implementation)**
   - C++: Tracks local/remote capacity separately for messages and bytes
   - C++: Priority queuing (SCP > TX > Demand > Advert)
   - C++: Load shedding when queues are full
   - C++: Throttling detection and logging
   - Rust: Basic SendMoreExtended sending only

2. **Pull-Mode Transaction Flooding**
   - C++: TxAdverts batches outgoing transaction hashes
   - C++: FloodAdvert/FloodDemand message processing
   - C++: Demand retry with exponential backoff
   - C++: Pull latency metrics
   - Rust: Not implemented

3. **Persistent Peer Database**
   - C++: Peers stored in SQLite with failure counts
   - C++: Backoff scheduling for failed peers
   - C++: Random peer selection from database
   - Rust: In-memory only

4. **Quorum Set and Transaction Set Fetching**
   - C++: ItemFetcher tracks which envelopes need which data
   - C++: Tracker manages retry across multiple peers
   - C++: DontHave message triggers next peer attempt
   - Rust: Not implemented

5. **Background Thread Processing**
   - C++: Optional background overlay processing
   - C++: Thread-safe message handling
   - Rust: Tokio async only (different approach)

6. **Peer Door (Listener)**
   - C++: PeerDoor.h/cpp for inbound connection acceptance
   - Rust: Integrated into OverlayManager listener task

7. **Peer Bare Address**
   - C++: PeerBareAddress for IP + port with IPv4/IPv6 parsing
   - Rust: Simpler PeerAddress type

8. **Hmac Helper**
   - C++: Hmac.h/cpp wrapper around crypto
   - Rust: Direct use of hmac crate

### Implementation Notes

#### Architectural Differences

1. **Async Runtime**
   - C++: ASIO-based with callbacks and virtual clocks
   - Rust: Tokio-based with async/await

2. **Memory Management**
   - C++: shared_ptr/weak_ptr for peer lifecycle
   - Rust: Arc<Mutex<Peer>> with explicit ownership

3. **Concurrency Model**
   - C++: Main thread + optional background thread with mutexes
   - Rust: Tokio tasks with channels (mpsc, broadcast)

4. **Message Codec**
   - C++: Record Marking (RM) per RFC 5531
   - Rust: Equivalent 4-byte length prefix with auth bit

5. **Error Handling**
   - C++: Exceptions + error codes
   - Rust: Result<T, OverlayError> throughout

6. **Metrics**
   - C++: Medida library with timers/meters/counters
   - Rust: Basic atomic counters (full metrics TBD)

#### Key Algorithm Parity

- **HKDF Key Derivation**: Matches C++ implementation exactly
- **Auth Certificate Signing**: Signs SHA-256 hash of data (matches C++)
- **Message MAC**: HMAC-SHA256 over sequence + XDR message bytes
- **Flood Hash**: SHA-256 of XDR-encoded message

#### Testing Status

- Unit tests for auth, codec, flood gate
- No integration tests with real network yet
- No loopback peer for in-process testing

### Recommended Implementation Order

1. **High Priority** (needed for basic functionality):
   - Full FlowControl with capacity tracking
   - ItemFetcher and Tracker for TxSet/QuorumSet fetching
   - Message handlers for GetTxSet, DontHave

2. **Medium Priority** (needed for production):
   - PeerManager with database persistence
   - BanManager with persistent bans
   - TxAdverts and TxDemandsManager for pull-mode flooding

3. **Lower Priority** (nice to have):
   - SurveyManager for network topology
   - Full OverlayMetrics integration
   - Background thread processing option
