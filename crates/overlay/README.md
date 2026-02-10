# henyey-overlay

P2P overlay networking layer for henyey.

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
| `FlowControl` | Bandwidth management via SendMore/SendMoreExtended capacity tracking |
| `AuthContext` | Manages the authentication handshake and message MAC verification |
| `Connection` | Low-level TCP connection with framed message I/O |
| `ItemFetcher` | Fetches missing items (tx sets, quorum sets) from peers with retry logic |
| `MessageDispatcher` | Routes fetch-protocol messages (GetTxSet, ScpQuorumset, DontHave) |
| `BanManager` | Tracks banned peers with SQLite persistence |
| `PeerManager` | SQLite-backed peer address storage with failure tracking and backoff |
| `TxAdverts` | Manages outgoing/incoming transaction flood adverts |
| `TxDemandsManager` | Tracks transaction demand lifecycle with retries and latency metrics |
| `SurveyManager` | Time-sliced network survey collection and reporting |
| `OverlayMetrics` | Thread-safe counters and timers for overlay statistics |

### Module Structure

```
henyey-overlay/
├── src/
│   ├── lib.rs              # Public API, configuration, and common types
│   ├── manager.rs          # OverlayManager - connection and message coordination
│   ├── peer.rs             # Peer - individual peer connection handling
│   ├── auth.rs             # Authentication handshake and MAC verification
│   ├── codec.rs            # Message framing (length-prefixed XDR)
│   ├── connection.rs       # TCP connection management
│   ├── flood.rs            # Duplicate detection and message flooding
│   ├── flow_control.rs     # SendMore/SendMoreExtended capacity tracking
│   ├── item_fetcher.rs     # Fetching missing items (tx sets, quorum sets)
│   ├── message_handlers.rs # Fetch-protocol message dispatch
│   ├── ban_manager.rs      # Peer banning with SQLite persistence
│   ├── peer_manager.rs     # Peer address storage, failure tracking, backoff
│   ├── tx_adverts.rs       # Transaction flood advert queuing and batching
│   ├── tx_demands.rs       # Transaction demand lifecycle and retries
│   ├── survey.rs           # Time-sliced network survey protocol
│   ├── metrics.rs          # Overlay metrics (counters, timers)
│   └── error.rs            # Error types
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
| Consensus | `ScpMessage`, `GetScpState`, `ScpQuorumset`, `GetScpQuorumset` |
| Transactions | `Transaction`, `FloodAdvert`, `FloodDemand` |
| Transaction Sets | `GetTxSet`, `TxSet`, `GeneralizedTxSet` |
| Flow Control | `SendMore`, `SendMoreExtended` |
| Errors | `ErrorMsg`, `DontHave` |
| Surveys | `TimeSlicedSurveyStartCollecting`, `TimeSlicedSurveyStopCollecting`, `TimeSlicedSurveyRequest`, `SignedTimeSlicedSurveyResponse` |

### Flow Control

The overlay implements Stellar's flow control protocol:

- Peers advertise their receive capacity via `SendMoreExtended` messages
- Messages beyond the advertised capacity are buffered or dropped
- This prevents overwhelming nodes during traffic spikes

## Usage

### Basic Setup

```rust
use henyey_overlay::{OverlayConfig, OverlayManager, LocalNode, PeerAddress};
use henyey_crypto::SecretKey;

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
use henyey_overlay::OverlayConfig;

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

This crate corresponds to the following stellar-core components:

- `src/overlay/OverlayManager.*` - Connection management
- `src/overlay/Peer.*`, `src/overlay/TCPPeer.*` - Individual peer handling
- `src/overlay/FlowControl.*`, `src/overlay/FlowControlCapacity.*` - SendMore/SendMoreExtended
- `src/overlay/Floodgate.*` - Message deduplication and flooding
- `src/overlay/ItemFetcher.*`, `src/overlay/Tracker.*` - Item fetching with retries
- `src/overlay/BanManager.*` - Peer banning
- `src/overlay/PeerManager.*`, `src/overlay/RandomPeerSource.*` - Peer address management
- `src/overlay/TxAdverts.*` - Transaction advert queuing
- `src/overlay/TxDemandsManager.*` - Transaction demand tracking
- `src/overlay/SurveyManager.*`, `src/overlay/SurveyDataManager.*` - Network surveys
- `src/overlay/OverlayMetrics.*` - Overlay statistics
- `src/overlay/PeerAuth.*`, `src/overlay/Hmac.*` - Authentication and MAC

## Testing

```bash
# Run unit tests
cargo test -p henyey-overlay

# Run with debug logging
RUST_LOG=henyey_overlay=debug cargo test -p henyey-overlay
```

## Related Crates

- `henyey-common` - Shared types and utilities (NetworkId, Hash256)
- `henyey-crypto` - Ed25519 keys, signatures, and Curve25519 operations
- `stellar-xdr` - Stellar XDR type definitions
- `stellar-strkey` - Stellar strkey encoding for public key display

---

## stellar-core Parity Status

See [PARITY_STATUS.md](PARITY_STATUS.md) for detailed stellar-core parity analysis.
