# stellar-core-simulation

A simulation harness for testing multi-node Stellar Core overlay networks in Rust.

## Overview

This crate provides utilities for spawning in-process overlay networks with deterministic key generation, enabling reproducible integration tests for peer-to-peer networking and SCP (Stellar Consensus Protocol) message propagation.

### Why Simulation?

Testing distributed consensus systems presents unique challenges:

- **Network dependencies**: Real network tests are slow, flaky, and require infrastructure
- **Non-determinism**: Random key generation makes failures hard to reproduce
- **Complexity**: Multi-node scenarios require coordinating many processes

The simulation harness addresses these challenges by:

1. Running all nodes in a single process with in-memory networking
2. Using deterministic seed-based key derivation for reproducible node identities
3. Providing a simple API for common test scenarios

## Architecture

### Star Topology

The simulation uses a star topology where node 0 acts as the central hub:

```text
       Node 1
         |
 Node 2--Node 0--Node 3
         |
       Node 4
```

This topology has important properties for testing:

- **Single-hop delivery**: Messages from the hub reach all peers directly
- **Predictable timing**: No multi-hop delays to account for
- **Simple assertions**: Easy to verify "message reaches all nodes"

### Component Relationships

```text
+---------------------+
|  OverlaySimulation  |  <-- High-level test interface
+---------------------+
         |
         | manages
         v
+---------------------+
|  OverlayManager[]   |  <-- One per simulated node
+---------------------+
         |
         | uses
         v
+---------------------+
|  LocalNode          |  <-- Identity derived from seed
+---------------------+
```

## Key Types

### `OverlaySimulation`

The main entry point for creating and managing simulated networks.

**Responsibilities:**
- Allocates ephemeral ports for each node
- Derives deterministic node identities from a seed
- Establishes the star topology connections
- Provides message broadcasting utilities
- Manages graceful shutdown

**Key Methods:**
- `start(count)` - Creates a simulation with random node identities
- `start_with_seed(count, seed)` - Creates a simulation with deterministic identities
- `broadcast_scp(slot)` - Sends a test SCP message from the hub
- `hub()` - Returns a reference to node 0
- `node_count()` - Returns the number of nodes
- `shutdown()` - Cleanly terminates all nodes

### Helper Functions

| Function | Purpose |
|----------|---------|
| `allocate_port()` | Gets an ephemeral port from the OS |
| `derive_seed(seed, index)` | Deterministically derives per-node seeds |
| `random_seed()` | Generates cryptographically secure random seeds |

## Usage

### Basic Example

```rust
use stellar_core_simulation::OverlaySimulation;
use anyhow::Result;

#[tokio::test]
async fn test_network_broadcast() -> Result<()> {
    // Start a 3-node simulation with a fixed seed for reproducibility.
    // The seed [7u8; 32] will always produce the same node identities.
    let sim = OverlaySimulation::start_with_seed(3, [7u8; 32]).await?;

    // Access the hub node directly.
    let hub = sim.hub().expect("simulation has nodes");
    let stats = hub.stats();
    assert!(stats.connected_peers >= 2);

    // Broadcast an SCP message from the hub.
    sim.broadcast_scp(1).await?;

    // Clean shutdown ensures no resource leaks.
    sim.shutdown().await?;
    Ok(())
}
```

### Subscribing to Messages

```rust
use stellar_core_simulation::OverlaySimulation;
use stellar_core_overlay::OverlayMessage;
use stellar_xdr::curr::StellarMessage;

#[tokio::test]
async fn test_message_reception() {
    let sim = OverlaySimulation::start_with_seed(2, [42u8; 32]).await.unwrap();

    // Subscribe to messages on node 1 (a non-hub node).
    let mut receiver = sim.managers[1].subscribe();

    // Broadcast from the hub (node 0).
    sim.broadcast_scp(1).await.unwrap();

    // Wait for the message to arrive.
    if let Ok(OverlayMessage { message, .. }) = receiver.recv().await {
        if matches!(message, StellarMessage::ScpMessage(_)) {
            println!("Node 1 received the SCP message!");
        }
    }

    sim.shutdown().await.unwrap();
}
```

### Handling Sandboxed Environments

Some CI environments restrict network operations. Handle this gracefully:

```rust
use stellar_core_simulation::OverlaySimulation;

#[tokio::test]
async fn test_with_sandbox_handling() -> anyhow::Result<()> {
    match OverlaySimulation::start_with_seed(3, [7u8; 32]).await {
        Ok(sim) => {
            // Run your test...
            sim.shutdown().await?;
        }
        Err(e) if e.to_string().contains("tcp bind not permitted") => {
            eprintln!("Skipping: network tests not supported in this environment");
        }
        Err(e) => return Err(e),
    }
    Ok(())
}
```

## Deterministic Key Derivation

Understanding how node identities are generated is important for debugging:

```text
Input:  base_seed (32 bytes) || node_index (4 bytes, big-endian)
Output: SHA-256(input) -> 32-byte per-node seed
```

This means:
- **Same seed + same index = same node identity** across test runs
- **Different indices = different identities** even with the same base seed
- **Useful for debugging**: If a test fails with seed X, you can reproduce it exactly

Example derivation for seed `[7u8; 32]`:
```text
Node 0: SHA256([7,7,7,...,7] || [0,0,0,0]) = <deterministic 32-byte seed>
Node 1: SHA256([7,7,7,...,7] || [0,0,0,1]) = <different deterministic seed>
Node 2: SHA256([7,7,7,...,7] || [0,0,0,2]) = <another different seed>
```

## Implementation Details

### Port Allocation

The simulation uses OS-assigned ephemeral ports to avoid conflicts:

1. Bind a TCP listener to `127.0.0.1:0`
2. Query the assigned port via `local_addr()`
3. Drop the listener (port may briefly be available to others)
4. Use the port for the overlay manager

This approach works well for testing but has a theoretical race condition. In practice, the OS typically doesn't reassign recently-freed ports immediately.

### Connection Timing

After starting nodes and initiating connections, the simulation waits 200ms for connections to establish. Tests that need stricter timing guarantees should add their own delays or use message-based synchronization.

### Placeholder SCP Messages

The `broadcast_scp()` method sends intentionally minimal/invalid SCP messages:

- Zero-filled node ID (not a real validator)
- Empty vote lists
- Invalid signature

These messages test network propagation, not consensus logic. Do not use them as templates for real SCP implementations.

## Testing Patterns

### Verifying Message Propagation

```rust
// Subscribe before broadcasting to avoid race conditions.
let mut receivers: Vec<_> = sim.managers.iter()
    .map(|m| m.subscribe())
    .collect();

sim.broadcast_scp(1).await?;

// Check each non-hub node received the message.
for (idx, rx) in receivers.iter_mut().enumerate().skip(1) {
    // ... wait for message with timeout ...
}
```

### Verifying Connectivity

```rust
// Allow time for connections to stabilize.
tokio::time::sleep(Duration::from_millis(300)).await;

// Hub should be connected to all other nodes.
let hub_peers = sim.managers[0].stats().connected_peers;
assert!(hub_peers >= sim.node_count() - 1);
```

## Limitations and Future Work

### Currently Implemented

- In-process overlay network simulation
- Deterministic node key generation
- Star topology with hub-based broadcasting
- Peer connection statistics
- Graceful shutdown

### Not Yet Implemented

- **Load generators**: Synthetic transaction generation for stress testing
- **Scenario validators**: Assertion helpers for complex consensus scenarios
- **Multi-hop topologies**: Mesh, ring, or custom network structures
- **Network partitions**: Simulating network splits and healing
- **Latency injection**: Artificial delays for timing-sensitive tests
- **Message filtering**: Selective message dropping for fault injection

## Related Crates

| Crate | Relationship |
|-------|--------------|
| `stellar-core-overlay` | The overlay network implementation being tested |
| `stellar-core-crypto` | Provides key generation and SHA-256 hashing |
| `stellar-core-scp` | The SCP implementation (not directly used here) |
| `stellar-xdr` | XDR type definitions for Stellar messages |

## C++ Parity Status

See [PARITY_STATUS.md](PARITY_STATUS.md) for detailed C++ parity analysis.
