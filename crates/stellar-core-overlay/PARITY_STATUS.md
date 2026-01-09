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

- **FlowControl** (`flow_control.rs`) - Full flow control with capacity tracking
  - Message and byte capacity tracking (local and outbound)
  - Priority queuing (SCP > TX > Demand > Advert)
  - Load shedding when queues are full
  - Throttling detection and logging
  - SEND_MORE_EXTENDED message validation
  - Queue trimming for overloaded connections

- **ItemFetcher / Tracker** (`item_fetcher.rs`) - Anycast fetch for TxSet and QuorumSet
  - Tracker for each item being fetched
  - Retry logic with timeout handling
  - Envelope tracking (which envelopes need which data)
  - Peer rotation when DontHave received
  - Exponential backoff on list rebuild

- **MessageDispatcher** (`message_handlers.rs`) - Message handlers for fetch protocol
  - GetTxSet / TxSet / GeneralizedTxSet handling
  - GetScpQuorumSet / ScpQuorumset handling
  - DontHave message routing
  - TxSet and QuorumSet caching
  - Callback integration for item receipt

- **TxAdverts** (`tx_adverts.rs`) - Transaction advertisement batching for pull-mode flooding
  - Incoming advert queuing for demanding
  - Outgoing advert batching with periodic flush
  - History cache for duplicate detection
  - Retry queue for failed demands
  - Configurable batch size and flush period

- **TxDemandsManager** (`tx_demands.rs`) - Transaction demand scheduling with retry logic
  - Demand status tracking (Demand, RetryLater, Discard)
  - Linear backoff for retries (up to MAX_RETRY_COUNT attempts)
  - Demand history per transaction and peer
  - Pull latency tracking (end-to-end and per-peer)
  - Cleanup of abandoned demands
  - Respond to incoming FloodDemand messages

- **OverlayMetrics** (`metrics.rs`) - Comprehensive metrics collection
  - Message metrics (read, write, drop, broadcast)
  - Byte metrics (read, write)
  - Error and timeout counters
  - Connection latency timers
  - Per-message-type receive timers and send counters
  - Queue delay timers and drop counters per priority
  - Flood metrics (demanded, fulfilled, unfulfilled)
  - Pull latency timers
  - Thread-safe atomic counters

- **SurveyManager** (`survey.rs`) - Network topology survey orchestration
  - Survey lifecycle (Collecting -> Reporting -> Inactive phases)
  - Node and peer data collection during surveys
  - Surveyor allowlist for authorization
  - Message rate limiting (SurveyMessageLimiter)
  - Peer backlog management for survey requests
  - Bad response node tracking
  - Phase timeout handling
  - Finalized time-sliced node and peer data reporting

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

### Cross-Crate Integration Points

All major overlay components have been implemented. The following items require integration with other crates (SCP consensus, transaction queue) and are intentionally forwarded to subscribers:

#### Message Handlers

The following message types are received but not fully processed:

| Message Type | Status |
|--------------|--------|
| `GetTxSet` | **Implemented** - Returns cached TxSet or DontHave |
| `TxSet` / `GeneralizedTxSet` | **Implemented** - Cached and triggers callbacks |
| `GetScpQuorumSet` | **Implemented** - Returns cached QuorumSet or DontHave |
| `ScpQuorumset` | **Implemented** - Cached and triggers callbacks |
| `ScpMessage` | Forwarded to subscribers only (no SCP integration) |
| `GetScpState` | Not handled (need SCP state) |
| `Transaction` | Forwarded to subscribers only (no transaction queue) |
| `FloodAdvert` | **Implemented** - TxAdverts handles queuing, TxDemandsManager schedules demands |
| `FloodDemand` | **Implemented** - TxDemandsManager handles incoming demands |
| `TimeSlicedSurvey*` | **Implemented** - SurveyManager handles survey lifecycle and data collection |
| `DontHave` | **Implemented** - Routes to ItemFetcher for retry |

#### Feature Implementation Status

1. **Pull-Mode Transaction Flooding**
   - C++: TxAdverts batches outgoing transaction hashes
   - C++: FloodAdvert/FloodDemand message processing
   - C++: Demand retry with linear backoff
   - C++: Pull latency metrics
   - Rust: **Implemented** - TxAdverts (batching, queuing), TxDemandsManager (scheduling, retry, latency)

2. **Persistent Peer Database**
   - C++: Peers stored in SQLite with failure counts
   - C++: Backoff scheduling for failed peers
   - C++: Random peer selection from database
   - Rust: **Implemented** - PeerManager with SQLite persistence, failure tracking, backoff scheduling

3. **Background Thread Processing**
   - C++: Optional background overlay processing
   - C++: Thread-safe message handling
   - Rust: Tokio async only (different approach)

4. **Peer Door (Listener)**
   - C++: PeerDoor.h/cpp for inbound connection acceptance
   - Rust: Integrated into OverlayManager listener task

5. **Peer Bare Address**
   - C++: PeerBareAddress for IP + port with IPv4/IPv6 parsing
   - Rust: Simpler PeerAddress type

6. **Hmac Helper**
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
   - Rust: Full OverlayMetrics with atomic counters, timers, and comprehensive tracking (implemented)

#### Key Algorithm Parity

- **HKDF Key Derivation**: Matches C++ implementation exactly
- **Auth Certificate Signing**: Signs SHA-256 hash of data (matches C++)
- **Message MAC**: HMAC-SHA256 over sequence + XDR message bytes
- **Flood Hash**: SHA-256 of XDR-encoded message

#### Testing Status

- Unit tests for auth, codec, flood gate
- Unit tests for FlowControl (capacity tracking, throttling, queue management)
- Unit tests for ItemFetcher/Tracker (fetch lifecycle, retry logic, envelope tracking)
- Unit tests for MessageDispatcher (message handling, caching, callbacks)
- Unit tests for BanManager (in-memory and SQLite persistence)
- Unit tests for PeerManager (failure tracking, backoff, type updates, persistence)
- Unit tests for TxAdverts (queuing, batching, history cache, limits)
- Unit tests for TxDemandsManager (demand status, retries, pull latency, cleanup)
- Unit tests for OverlayMetrics (counters, timers, snapshots, thread safety)
- Unit tests for SurveyManager (lifecycle, data collection, rate limiting, peer backlog)
- No integration tests with real network yet
- No loopback peer for in-process testing

### Recommended Implementation Order

All major components have been implemented. Summary:

1. **High Priority** (completed):
   - ~~Full FlowControl with capacity tracking~~ **Done**
   - ~~ItemFetcher and Tracker for TxSet/QuorumSet fetching~~ **Done**
   - ~~Message handlers for GetTxSet, TxSet, GetScpQuorumSet, ScpQuorumset, DontHave~~ **Done**

2. **Medium Priority** (completed):
   - ~~PeerManager with database persistence~~ **Done**
   - ~~BanManager with persistent bans~~ **Done**
   - ~~TxAdverts for pull-mode flooding~~ **Done**
   - ~~TxDemandsManager for demand scheduling and retry logic~~ **Done**
   - ~~OverlayMetrics for comprehensive metrics~~ **Done**

3. **Lower Priority** (completed):
   - ~~SurveyManager for network topology~~ **Done**

4. **Future Enhancements** (nice to have):
   - Integration tests with real network
   - Loopback peer for in-process testing
   - Full Curve25519 encryption for survey responses
