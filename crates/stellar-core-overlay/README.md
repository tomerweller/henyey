# stellar-core-overlay

P2P overlay networking layer for rs-stellar-core.

## Overview

This crate implements the Stellar overlay network protocol, enabling nodes to communicate with each other for consensus, transaction propagation, and state synchronization. It provides:

- **Peer discovery and connection management** - Automatic connection to known peers with support for preferred peers and connection limits
- **Authenticated peer connections** - X25519 key exchange with HMAC-SHA256 message authentication following the Stellar overlay protocol
- **Message routing and flooding** - Intelligent message propagation with duplicate detection and rate limiting
- **Flow control** - Bandwidth management using SendMore/SendMoreExtended messages

## Architecture

The crate is organized around these key components:

### Core Types

| Type | Description |
|------|-------------|
| `OverlayManager` | Central coordinator managing all peer connections and message routing |
| `Peer` | Represents a fully authenticated connection to a single peer |
| `FloodGate` | Tracks seen messages to prevent duplicate flooding |
| `AuthContext` | Manages the authentication handshake and message MAC verification |
| `Connection` | Low-level TCP connection with framed message I/O |

### Module Structure

```
stellar-core-overlay/
├── src/
│   ├── lib.rs         # Public API, configuration, and common types
│   ├── manager.rs     # OverlayManager - connection and message coordination
│   ├── peer.rs        # Peer - individual peer connection handling
│   ├── auth.rs        # Authentication handshake and MAC verification
│   ├── codec.rs       # Message framing (length-prefixed XDR)
│   ├── connection.rs  # TCP connection management
│   ├── flood.rs       # Duplicate detection and rate limiting
│   └── error.rs       # Error types
```

## Protocol Overview

### Connection Handshake

Each connection follows this authentication sequence:

1. **Hello Exchange**: Both peers send `Hello` messages containing:
   - Ed25519 public key (node identity)
   - Ephemeral X25519 public key for key exchange
   - Authentication certificate (signature over ephemeral key)
   - Random nonce for key derivation

2. **Key Derivation**: Both peers:
   - Verify the peer's auth certificate signature
   - Perform X25519 Diffie-Hellman to derive a shared secret
   - Use HKDF to derive separate MAC keys for each direction

3. **Auth Exchange**: Both peers send `Auth` messages with valid MACs to prove successful key derivation

4. **Authenticated Channel**: All subsequent messages include sequence numbers and HMAC-SHA256 MACs

### Message Types

The overlay handles various Stellar XDR message types:

| Category | Messages |
|----------|----------|
| Handshake | `Hello`, `Auth` |
| Discovery | `Peers` |
| Consensus | `ScpMessage`, `GetScpState`, `ScpQuorumset` |
| Transactions | `Transaction`, `FloodAdvert`, `FloodDemand` |
| Transaction Sets | `GetTxSet`, `TxSet`, `GeneralizedTxSet` |
| Flow Control | `SendMore`, `SendMoreExtended` |

### Flow Control

The overlay implements Stellar's flow control protocol:

- Peers advertise their receive capacity via `SendMoreExtended` messages
- Messages beyond the advertised capacity are buffered or dropped
- This prevents overwhelming nodes during traffic spikes

## Usage

### Basic Setup

```rust
use stellar_core_overlay::{OverlayConfig, OverlayManager, LocalNode, PeerAddress};
use stellar_core_crypto::SecretKey;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a node identity
    let secret_key = SecretKey::generate();
    let local_node = LocalNode::new_testnet(secret_key);

    // Configure the overlay
    let mut config = OverlayConfig::testnet();
    config.known_peers.push(PeerAddress::new("core-testnet1.stellar.org", 11625));

    // Create and start the manager
    let mut manager = OverlayManager::new(config, local_node)?;
    manager.start().await?;

    // Subscribe to incoming messages
    let mut rx = manager.subscribe();
    while let Ok(msg) = rx.recv().await {
        println!("Received {:?} from {}", msg.message, msg.from_peer);
    }

    Ok(())
}
```

### Configuration Options

```rust
use stellar_core_overlay::OverlayConfig;

let mut config = OverlayConfig::default();

// Connection limits
config.max_inbound_peers = 64;      // Max peers connecting to us
config.max_outbound_peers = 8;      // Max peers we connect to
config.target_outbound_peers = 4;   // Target number to maintain

// Timeouts
config.connect_timeout_secs = 5;    // TCP connection timeout
config.auth_timeout_secs = 10;      // Handshake timeout

// Network settings
config.listen_port = 11625;         // Standard Stellar port
config.listen_enabled = true;       // Accept incoming connections
config.network_passphrase = "Test SDF Network ; September 2015".to_string();

// Flood control
config.flood_ttl_secs = 300;        // How long to remember seen messages
```

### Sending Messages

```rust
use stellar_xdr::curr::StellarMessage;

// Broadcast to all peers
let tx_msg = StellarMessage::Transaction(/* ... */);
let sent_count = manager.broadcast(tx_msg).await?;

// Send to a specific peer
manager.send_to(&peer_id, message).await?;

// Request SCP state from all peers
manager.request_scp_state(ledger_seq).await?;
```

### Peer Management

```rust
// Get connected peer info
let peers = manager.peer_infos();
for info in peers {
    println!("Peer {} at {} (v{})",
        info.peer_id,
        info.address,
        info.version_string
    );
}

// Manual connection
let peer_id = manager.connect(&PeerAddress::new("validator.example.com", 11625)).await?;

// Disconnect a peer
manager.disconnect(&peer_id).await;

// Ban a misbehaving peer
manager.ban_peer(peer_id).await;
```

## Key Concepts

### Preferred Peers

Configure `preferred_peers` for validators or nodes that should always be connected. The overlay prioritizes these connections and will reconnect if disconnected.

### Peer Discovery

Peers share addresses via `Peers` messages. The overlay automatically:
- Learns new peers from connected nodes
- Advertises known peers to others
- Filters out private/local addresses

### Message Flooding

When a flood message (transaction, SCP message) is received:
1. Compute the message hash
2. Check if we've seen it before (via FloodGate)
3. If new, forward to all other peers
4. If duplicate, drop it

### Rate Limiting

The FloodGate enforces a soft rate limit on incoming messages (default 1000/sec). Messages beyond the limit are dropped to prevent resource exhaustion.

## Upstream Mapping

This crate corresponds to the following C++ stellar-core components:

- `src/overlay/OverlayManager.*` - Connection management
- `src/overlay/Peer.*` - Individual peer handling
- `src/overlay/FlowControl.*` - SendMore/SendMoreExtended
- `src/overlay/SurveyManager.*` - Network surveys (partial)

## Testing

```bash
# Run unit tests
cargo test -p stellar-core-overlay

# Run with debug logging
RUST_LOG=stellar_core_overlay=debug cargo test -p stellar-core-overlay
```

## Related Crates

- `stellar-core-common` - Shared types and utilities
- `stellar-core-crypto` - Ed25519 keys and signatures
- `stellar-xdr` - Stellar XDR type definitions

---

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
