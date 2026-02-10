## stellar-core Parity Status

**Overall Parity: ~88%**

This document tracks feature parity between this Rust crate and stellar-core implementation in `.upstream-v25/src/overlay/`.

### Parity Summary

| Component | stellar-core Files | Rust Files | Status |
|-----------|-----------|------------|--------|
| OverlayManager | OverlayManager.h, OverlayManagerImpl.cpp/h | manager.rs | **Full** |
| Peer | Peer.h, TCPPeer.h | peer.rs, connection.rs | **Full** |
| PeerAuth | PeerAuth.h | auth.rs | **Full** |
| Floodgate | Floodgate.h | flood.rs | **Full** |
| FlowControl | FlowControl.h, FlowControlCapacity.h | flow_control.rs | **Full** |
| ItemFetcher | ItemFetcher.h, Tracker.h | item_fetcher.rs | **Full** |
| BanManager | BanManager.h, BanManagerImpl.h | ban_manager.rs | **Full** |
| PeerManager | PeerManager.h, RandomPeerSource.h | peer_manager.rs | **Full** |
| TxAdverts | TxAdverts.h | tx_adverts.rs | **Full** |
| TxDemandsManager | TxDemandsManager.h | tx_demands.rs | **Full** |
| OverlayMetrics | OverlayMetrics.h | metrics.rs | **Full** |
| SurveyManager | SurveyManager.h, SurveyDataManager.h, SurveyMessageLimiter.h | survey.rs | **Full** |
| MessageCodec | (in Peer/TCPPeer) | codec.rs | **Full** |
| HMAC | Hmac.h | (in auth.rs) | **Full** |
| PeerDoor | PeerDoor.h | (in manager.rs) | **Full** |
| PeerBareAddress | PeerBareAddress.h | (in lib.rs as PeerAddress) | **Full** |
| PeerSharedKeyId | PeerSharedKeyId.h | (not needed - different cache approach) | N/A |

### Implemented Features

#### Core Infrastructure

**OverlayManager** (`manager.rs`) - Corresponds to `OverlayManager.h`, `OverlayManagerImpl.h`
- Start/shutdown lifecycle management
- Inbound/outbound connection limits with separate pools
- Peer count tracking and statistics
- Message broadcasting to all peers (`broadcastMessage`)
- Connection to specific peer addresses (`connectTo`)
- Shutdown with graceful peer disconnection
- Preferred peer handling (`isPreferred`, `isPossiblyPreferred`)
- Random peer selection for message forwarding
- Flood message tracking via FloodGate
- Message deduplication cache (`checkScheduledAndCache` equivalent)
- Authenticated peer management (pending -> authenticated transition)

**Peer** (`peer.rs`, `connection.rs`) - Corresponds to `Peer.h`, `TCPPeer.h`
- Full Hello/Auth handshake implementation
- Message send/receive with MAC authentication
- Peer state machine: `Connecting -> Handshaking -> Authenticated -> Closing -> Disconnected`
- Per-peer statistics (messages/bytes sent/received) - matches `PeerMetrics` struct
- Flow control via SendMore/SendMoreExtended
- Connection direction tracking (inbound vs outbound) - `PeerRole`
- All message handlers: `recvHello`, `recvAuth`, `recvPeers`, `recvError`, `recvDontHave`, `recvSendMore`, `recvGetTxSet`, `recvTxSet`, `recvTransaction`, `recvScpMessage`, `recvGetScpQuorumSet`, `recvScpQuorumSet`, `recvFloodAdvert`, `recvFloodDemand`, `recvSurvey*`
- Ping/pong for connection liveness (timer-based)
- Capacity-tracked message processing

**PeerAuth / AuthContext** (`auth.rs`) - Corresponds to `PeerAuth.h`
- AuthCert creation and verification
- Ephemeral X25519 key generation
- Signature over network_id || envelope_type || expiration || pubkey
- HKDF key derivation for send/receive MAC keys
- Sequence numbers to prevent replay attacks
- Message MAC computation and verification
- Shared key caching (different approach but same outcome)

**MessageCodec** (`codec.rs`) - Corresponds to XDR framing in `TCPPeer.cpp`
- Length-prefixed message framing (4-byte header)
- Bit 31 authentication flag handling
- Streaming decode state machine
- Message size limits: `MAX_MESSAGE_SIZE` (16 MB)

**Floodgate** (`flood.rs`) - Corresponds to `Floodgate.h`
- Message hash tracking (BLAKE2 in stellar-core, SHA-256 in Rust - both valid)
- Peer tracking per message (`mPeersTold` equivalent)
- Ledger-based expiry (`clearBelow`)
- Broadcast to peers excluding sender (`getPeersKnows`)
- Record management (`addRecord`, `forgetRecord`)

**FlowControl** (`flow_control.rs`) - Corresponds to `FlowControl.h`, `FlowControlCapacity.h`
- Message and byte capacity tracking (local and outbound)
- Priority queuing: SCP (0) > TX (1) > Demand (2) > Advert (3)
- Load shedding when queues are full
- Throttling detection and logging
- `SEND_MORE_EXTENDED` message validation
- Queue trimming for overloaded connections
- `beginMessageProcessing` / `endMessageProcessing`
- `addMsgAndMaybeTrimQueue` / `getNextBatchToSend` / `processSentMessages`
- Outbound capacity timeout detection

**ItemFetcher / Tracker** (`item_fetcher.rs`) - Corresponds to `ItemFetcher.h`, `Tracker.h`
- Tracker for each item being fetched
- Retry logic with timeout handling (`MS_TO_WAIT_FOR_FETCH_REPLY`)
- Envelope tracking (which envelopes need which data)
- Peer rotation when DontHave received (`doesntHave`, `tryNextPeer`)
- Exponential backoff on list rebuild (`MAX_REBUILD_FETCH_LIST`)
- Slot index tracking for envelope cleanup

**MessageDispatcher** (`message_handlers.rs`) - Message handlers for fetch protocol
- GetTxSet / TxSet / GeneralizedTxSet handling
- GetScpQuorumSet / ScpQuorumset handling
- DontHave message routing
- TxSet and QuorumSet caching
- Callback integration for item receipt

**BanManager** (`ban_manager.rs`) - Corresponds to `BanManager.h`, `BanManagerImpl.h`
- In-memory ban list (matches stellar-core `mBanned` set)
- SQLite persistence (matches stellar-core `ban` table)
- `banNode`, `unbanNode`, `isBanned` APIs
- `getBans` for listing banned nodes

**PeerManager** (`peer_manager.rs`) - Corresponds to `PeerManager.h`
- SQLite persistence (matches stellar-core `peers` table schema)
- Failure count tracking
- Backoff scheduling (`BackOffUpdate`: HARD_RESET, RESET, INCREASE)
- Type updates (`TypeUpdate`: ENSURE_OUTBOUND, SET_PREFERRED, ENSURE_NOT_PREFERRED)
- Random peer selection from database
- Peer query filters (`PeerTypeFilter`)

**TxAdverts** (`tx_adverts.rs`) - Corresponds to `TxAdverts.h`
- Incoming advert queuing for demanding
- Outgoing advert batching with periodic flush
- History cache for duplicate detection (`mAdvertHistory`)
- Retry queue for failed demands (`mTxHashesToRetry`)
- Configurable batch size and flush period
- `queueOutgoingAdvert`, `queueIncomingAdvert`, `popIncomingAdvert`
- `seenAdvert`, `clearBelow`

**TxDemandsManager** (`tx_demands.rs`) - Corresponds to `TxDemandsManager.h`
- Demand status tracking (Demand, RetryLater, Discard)
- Linear backoff for retries (up to `MAX_RETRY_COUNT = 15`)
- Demand history per transaction and peer (`DemandHistory` struct)
- Pull latency tracking (end-to-end and per-peer)
- Cleanup of abandoned demands
- Respond to incoming FloodDemand messages (`recvTxDemand`)

**OverlayMetrics** (`metrics.rs`) - Corresponds to `OverlayMetrics.h`
- Message metrics (read, write, drop, broadcast)
- Byte metrics (read, write)
- Error and timeout counters
- Connection latency timers
- Per-message-type receive timers and send counters
- Queue delay timers and drop counters per priority
- Flood metrics (demanded, fulfilled, unfulfilled)
- Pull latency timers
- Thread-safe atomic counters

**SurveyManager** (`survey.rs`) - Corresponds to `SurveyManager.h`, `SurveyDataManager.h`, `SurveyMessageLimiter.h`
- Survey lifecycle (Collecting -> Reporting -> Inactive phases)
- Node and peer data collection during surveys
- Surveyor allowlist for authorization
- Message rate limiting (`SurveyMessageLimiter`)
- Peer backlog management for survey requests
- Bad response node tracking
- Phase timeout handling
- Finalized time-sliced node and peer data reporting

### Configuration & Types

- **OverlayConfig** - Testnet/Mainnet presets, configurable limits
- **LocalNode** - Node identity with protocol versions
- **PeerAddress** - Host:port representation (matches `PeerBareAddress`)
- **PeerId** - Ed25519 public key identifier (matches `NodeID`)
- **PeerInfo** - Static peer metadata
- **PeerStats** - Atomic message/byte counters

### Message Types Handled

| Message Type | Handler Location | Status |
|--------------|------------------|--------|
| `Hello` | peer.rs | **Implemented** |
| `Auth` | peer.rs | **Implemented** |
| `DontHave` | message_handlers.rs | **Implemented** |
| `Error` | peer.rs | **Implemented** |
| `Peers` | peer.rs | **Implemented** |
| `GetTxSet` | message_handlers.rs | **Implemented** |
| `TxSet` | message_handlers.rs | **Implemented** |
| `GeneralizedTxSet` | message_handlers.rs | **Implemented** |
| `Transaction` | peer.rs -> subscribers | **Implemented** |
| `GetScpQuorumSet` | message_handlers.rs | **Implemented** |
| `ScpQuorumset` | message_handlers.rs | **Implemented** |
| `ScpMessage` | peer.rs -> subscribers | **Implemented** |
| `GetScpState` | peer.rs -> subscribers | **Implemented** |
| `SendMore` | peer.rs (legacy) | **Implemented** |
| `SendMoreExtended` | flow_control.rs | **Implemented** |
| `FloodAdvert` | tx_adverts.rs | **Implemented** |
| `FloodDemand` | tx_demands.rs | **Implemented** |
| `TimeSlicedSurveyStartCollectingMessage` | survey.rs | **Implemented** |
| `TimeSlicedSurveyStopCollectingMessage` | survey.rs | **Implemented** |
| `TimeSlicedSurveyRequestMessage` | survey.rs | **Implemented** |
| `SignedTimeSlicedSurveyResponseMessage` | survey.rs | **Implemented** |

### Architectural Differences

| Aspect | stellar-core Implementation | Rust Implementation |
|--------|-------------------|---------------------|
| Async Runtime | ASIO with callbacks and VirtualClock | Tokio with async/await |
| Memory Management | shared_ptr/weak_ptr for peer lifecycle | Arc<Mutex<Peer>> with explicit ownership |
| Concurrency | Main thread + optional background thread with mutexes | Tokio tasks with channels (mpsc, broadcast) |
| Message Framing | Record Marking (RM) per RFC 5531 | Equivalent 4-byte length prefix with auth bit |
| Error Handling | Exceptions + error codes | Result<T, OverlayError> throughout |
| Metrics Library | Medida (timers/meters/counters) | Custom OverlayMetrics with atomics |
| Flood Hash | BLAKE2 (xdrBlake2) | SHA-256 (either works for deduplication) |
| Timer System | VirtualTimer tied to VirtualClock | Tokio timers (real time only) |

### Key Algorithm Parity

- **HKDF Key Derivation**: Matches stellar-core implementation exactly (HKDF-Extract + HKDF-Expand)
- **Auth Certificate Signing**: Signs SHA-256 hash of data (matches stellar-core)
- **Message MAC**: HMAC-SHA256 over sequence + XDR message bytes
- **Flood Hash**: SHA-256 of XDR-encoded message (stellar-core uses BLAKE2, both valid)
- **Backoff Calculation**: Exponential backoff with same base timing

### Not Implemented / Out of Scope

1. **LoopbackPeer** - Test-only construct for in-process peer simulation
   - stellar-core: `LoopbackPeer.h` for testing
   - Rust: Not implemented (not needed for production)

2. **VirtualClock Integration** - Simulated time for testing
   - stellar-core: VirtualTimer throughout for testability
   - Rust: Uses real Tokio timers only

3. **Background Thread Mode** - Optional parallel message processing
   - stellar-core: `BACKGROUND_OVERLAY_PROCESSING` config option
   - Rust: Inherently async with Tokio (different approach, same result)

4. **Overlay Thread Snapshot** - Ledger state for background thread
   - stellar-core: `getOverlayThreadSnapshot` for thread-safe ledger access
   - Rust: Not needed (different concurrency model)

5. **Curve25519 Survey Response Encryption** - Full encryption for privacy
   - stellar-core: Encrypts survey responses with peer's Curve25519 key
   - Rust: Implemented outside this crate, in `henyey-app/src/app.rs` using `henyey_crypto::seal_to_curve25519_public_key` for encryption and `open_from_curve25519_secret_key` for decryption

### Testing Status

**Unit Tests (in-module)**
- auth.rs: Certificate creation, verification, key derivation
- codec.rs: Message framing, size limits, auth bit handling
- flood.rs: Hash tracking, TTL expiry, peer exclusion
- flow_control.rs: Capacity tracking, throttling, queue management, priority
- item_fetcher.rs: Fetch lifecycle, retry logic, envelope tracking
- message_handlers.rs: Message handling, caching, callbacks
- ban_manager.rs: In-memory and SQLite persistence
- peer_manager.rs: Failure tracking, backoff, type updates, persistence
- tx_adverts.rs: Queuing, batching, history cache, limits
- tx_demands.rs: Demand status, retries, pull latency, cleanup
- metrics.rs: Counters, timers, snapshots, thread safety
- survey.rs: Lifecycle, data collection, rate limiting, peer backlog

**Integration Tests**
- `tests/overlay_scp_integration.rs`: Basic SCP message handling integration
- `tests/item_fetcher_tests.rs`: ItemFetcher fetch lifecycle and retry logic

**Not Yet Tested**
- Real network connectivity
- Multi-node integration tests
- Protocol upgrade scenarios
- Malformed message handling edge cases

### Future Enhancements

1. **Integration Tests**: End-to-end tests with multiple nodes on real network
2. **LoopbackPeer**: For fast in-process testing without network
3. **VirtualClock Support**: For deterministic testing with simulated time
4. **Protocol Fuzzing**: Fuzz testing for message parsing robustness
