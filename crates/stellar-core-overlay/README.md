# stellar-core-overlay

P2P networking for rs-stellar-core.

## Overview

This crate implements the Stellar overlay network protocol, providing:

- Peer discovery and connection management
- Authenticated peer connections (using Curve25519 key exchange)
- Message routing and flooding
- Bandwidth management and flow control

## Protocol

The overlay uses TCP connections with XDR-encoded messages. Each connection begins with an authentication handshake that establishes a shared secret for message authentication.

## Message Types

| Message | Description |
|---------|-------------|
| `Hello` | Initial handshake with peer capabilities |
| `Auth` | Authentication challenge/response |
| `Peers` | Peer address exchange |
| `Transaction` | Transaction broadcasting |
| `SCP` | Consensus messages |
| `GetSCPState` | Request peer's SCP state |

## Usage

### Configuration

```rust
use stellar_core_overlay::OverlayConfig;

// Use testnet defaults
let config = OverlayConfig::testnet();

// Use mainnet defaults
let config = OverlayConfig::mainnet();

// Custom configuration
let config = OverlayConfig {
    max_inbound_peers: 64,
    max_outbound_peers: 8,
    target_outbound_peers: 8,
    listen_port: 11625,
    known_peers: vec![
        PeerAddress::new("core-testnet1.stellar.org", 11625),
    ],
    network_passphrase: "Test SDF Network ; September 2015".to_string(),
    auth_timeout_secs: 30,
    connect_timeout_secs: 10,
    flood_ttl_secs: 300,
    listen_enabled: true,
    version_string: "rs-stellar-core/0.1.0".to_string(),
};
```

### Local Node Setup

```rust
use stellar_core_overlay::LocalNode;
use stellar_core_crypto::SecretKey;

let secret_key = SecretKey::generate();

// Testnet node
let node = LocalNode::new_testnet(secret_key);

// Mainnet node
let node = LocalNode::new_mainnet(secret_key);

// Custom network
let node = LocalNode::new(secret_key, "My Network ; 2024");

// Get node's public identity
let peer_id = node.peer_id();
let public_key = node.public_key();
```

### Overlay Manager

```rust
use stellar_core_overlay::{OverlayManager, OverlayConfig};

let config = OverlayConfig::testnet();
let overlay = OverlayManager::new(config, local_node).await?;

// Start the overlay network
overlay.start().await?;

// Connect to a peer
overlay.connect_to(&peer_address).await?;

// Broadcast a transaction
overlay.broadcast_transaction(&tx_envelope).await?;

// Broadcast an SCP message
overlay.broadcast_scp(&scp_envelope).await?;

// Get connected peers
let peers = overlay.connected_peers().await;
```

### Handling Messages

```rust
use stellar_core_overlay::MessageHandler;

struct MyHandler;

#[async_trait]
impl MessageHandler for MyHandler {
    async fn handle_message(
        &self,
        peer_id: &PeerId,
        message: StellarMessage,
    ) -> Result<()> {
        match message {
            StellarMessage::Transaction(tx) => {
                // Handle incoming transaction
            }
            StellarMessage::ScpMessage(scp) => {
                // Handle SCP message
            }
            _ => {}
        }
        Ok(())
    }
}
```

## Key Types

### PeerAddress

Network address of a peer:

```rust
use stellar_core_overlay::PeerAddress;

let addr = PeerAddress::new("127.0.0.1", 11625);
println!("{}", addr); // "127.0.0.1:11625"
```

### PeerId

Unique identifier for a peer (their public key):

```rust
use stellar_core_overlay::PeerId;

let peer_id = PeerId::from_bytes(public_key_bytes);
println!("{}", peer_id); // "abc12345..."
```

### Peer

Represents a connected peer:

```rust
let peer_info = peer.info();
println!("Peer: {}", peer_info.peer_id);
println!("Address: {}", peer_info.address);
println!("State: {:?}", peer_info.state);
```

## Connection States

| State | Description |
|-------|-------------|
| `Connecting` | TCP connection in progress |
| `Connected` | TCP connected, starting handshake |
| `GotHello` | Received Hello, sending Auth |
| `Authenticated` | Fully authenticated |
| `Closing` | Connection being closed |

## Flood Gate

The flood gate prevents message amplification:

```rust
use stellar_core_overlay::FloodGate;

let flood_gate = FloodGate::new(ttl_secs);

// Check if message should be forwarded
if flood_gate.should_flood(&message_hash) {
    // Forward to peers
}
```

## Network Defaults

### Testnet

- Port: 11625
- Passphrase: "Test SDF Network ; September 2015"
- Known peers: core-testnet1/2/3.stellar.org

### Mainnet

- Port: 11625
- Passphrase: "Public Global Stellar Network ; September 2015"
- Known peers: core-live-a/b/c.stellar.org

## Authentication

Peer authentication uses:

1. Curve25519 key exchange for shared secret
2. HMAC-SHA256 for message authentication
3. Ed25519 signatures for identity verification

## Dependencies

- `tokio` - Async runtime
- `stellar-xdr` - Message encoding
- `ed25519-dalek` - Signatures
- `x25519-dalek` - Key exchange
- `hmac` + `sha2` - MAC computation

## License

Apache 2.0
