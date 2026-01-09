//! Simulation harness for testing multi-node Stellar Core overlay networks.
//!
//! This crate provides utilities for spawning in-process overlay networks
//! with deterministic key generation, enabling reproducible integration tests
//! for peer-to-peer networking and SCP message propagation.
//!
//! # Overview
//!
//! The primary type is [`OverlaySimulation`], which manages a collection of
//! [`OverlayManager`] instances representing individual nodes in a simulated
//! network. Nodes are connected in a star topology with node 0 as the hub.
//!
//! # Virtual Clock
//!
//! For deterministic timing control, use the [`VirtualClock`] abstraction which
//! supports two modes:
//!
//! - **Virtual Time**: Time advances instantly under program control, enabling
//!   tests to run at maximum speed without wall-clock dependencies.
//! - **Real Time**: Time advances according to the actual wall clock.
//!
//! The virtual clock provides crank-based event loop advancement similar to
//! the C++ `VirtualClock` in stellar-core, enabling deterministic testing of
//! time-dependent behavior.
//!
//! # Deterministic Testing
//!
//! For reproducible test scenarios, use [`OverlaySimulation::start_with_seed`]
//! which derives node keys deterministically from a provided seed. This ensures
//! that node identities remain stable across test runs.
//!
//! # Network Topology
//!
//! The simulation uses a star topology where node 0 acts as the central hub:
//!
//! ```text
//!        Node 1
//!          |
//!  Node 2--Node 0--Node 3
//!          |
//!        Node 4
//! ```
//!
//! This design ensures single-hop message delivery from the hub to all peers,
//! simplifying test assertions about message propagation timing.
//!
//! # Example
//!
//! ```ignore
//! use stellar_core_simulation::{OverlaySimulation, VirtualClock};
//! use std::time::Duration;
//!
//! // Create a virtual clock for deterministic time control
//! let clock = VirtualClock::virtual_time();
//!
//! // Schedule an event
//! clock.schedule_after(Duration::from_secs(5), || {
//!     println!("Event fired!");
//! });
//!
//! // Advance time and process events
//! clock.crank_for_at_least(Duration::from_secs(5));
//!
//! #[tokio::test]
//! async fn test_message_broadcast() {
//!     // Start a 3-node simulation with a fixed seed for reproducibility
//!     let sim = OverlaySimulation::start_with_seed(3, [7u8; 32]).await.unwrap();
//!
//!     // Broadcast an SCP message from node 0
//!     sim.broadcast_scp(1).await.unwrap();
//!
//!     // Clean shutdown
//!     sim.shutdown().await.unwrap();
//! }
//! ```
//!
//! # Sandboxed Environments
//!
//! The simulation binds to localhost ports, which may fail in sandboxed
//! environments. Errors containing "tcp bind not permitted" should be handled
//! gracefully, typically by skipping the test.

use anyhow::{anyhow, Context, Result};
use stellar_core_crypto::SecretKey;
use stellar_core_overlay::{LocalNode, OverlayConfig, OverlayManager, PeerAddress};
use stellar_xdr::curr::{
    Hash, NodeId, PublicKey, ScpEnvelope, ScpNomination, ScpStatement, ScpStatementPledges,
    Signature, StellarMessage, Uint256,
};
use tokio::time::{sleep, Duration};

// =============================================================================
// Modules
// =============================================================================

pub mod virtual_clock;

// Re-export main types
pub use virtual_clock::{
    shared_clock, shared_virtual_clock, ClockMode, ClockStats, EventHandle, EventId,
    SharedVirtualClock, VirtualClock,
};

// =============================================================================
// Constants
// =============================================================================

/// Default connection establishment delay in milliseconds.
///
/// After starting all nodes and initiating connections, the simulation waits
/// this duration to allow TCP handshakes and authentication to complete.
const CONNECTION_SETTLE_MS: u64 = 200;

/// Connection timeout for peer connections in seconds.
const CONNECT_TIMEOUT_SECS: u64 = 5;

// =============================================================================
// OverlaySimulation
// =============================================================================

/// A simulated overlay network consisting of multiple connected nodes.
///
/// `OverlaySimulation` manages the lifecycle of multiple [`OverlayManager`]
/// instances and their interconnections. The simulation uses a star topology
/// where node 0 connects to all other nodes.
///
/// # Topology
///
/// ```text
///       Node 1
///         |
/// Node 2--Node 0--Node 3
///         |
///       Node 4
/// ```
///
/// Node 0 acts as the hub, establishing outbound connections to all other nodes.
/// This topology ensures that messages broadcast from node 0 reach all peers
/// directly.
///
/// # Port Allocation
///
/// Each node binds to a dynamically allocated port on localhost (127.0.0.1).
/// Port allocation uses the OS-provided ephemeral port mechanism to avoid
/// conflicts.
pub struct OverlaySimulation {
    /// The overlay managers for each node in the simulation.
    ///
    /// Index 0 is the hub node that connects to all others.
    pub managers: Vec<OverlayManager>,

    /// The peer addresses for each node, corresponding by index to `managers`.
    pub peer_addrs: Vec<PeerAddress>,
}

impl OverlaySimulation {
    /// Starts a new overlay simulation with a random seed.
    ///
    /// This is convenient for one-off tests but produces non-deterministic
    /// node identities. For reproducible tests, prefer [`Self::start_with_seed`].
    ///
    /// # Arguments
    ///
    /// * `node_count` - The number of nodes to create in the simulation.
    ///
    /// # Errors
    ///
    /// Returns an error if port allocation fails or if any overlay manager
    /// fails to start.
    pub async fn start(node_count: usize) -> Result<Self> {
        let seed = random_seed();
        Self::start_with_seed(node_count, seed).await
    }

    /// Starts a new overlay simulation with a deterministic seed.
    ///
    /// Node keys are derived from the seed using SHA-256, ensuring that the
    /// same seed always produces the same set of node identities. This is
    /// essential for reproducible test scenarios.
    ///
    /// # Arguments
    ///
    /// * `node_count` - The number of nodes to create in the simulation.
    /// * `seed` - A 32-byte seed used to derive node keys deterministically.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Port allocation fails (e.g., permission denied in sandboxed environments)
    /// - Any overlay manager fails to initialize or start
    ///
    /// # Network Setup
    ///
    /// After all nodes are started, node 0 initiates connections to all other
    /// nodes. A brief delay (200ms) allows connections to establish before
    /// returning.
    pub async fn start_with_seed(node_count: usize, seed: [u8; 32]) -> Result<Self> {
        let mut managers = Vec::new();
        let mut peer_addrs = Vec::new();

        for idx in 0..node_count {
            let port = allocate_port()?;
            let secret = SecretKey::from_seed(&derive_seed(&seed, idx as u32));
            let local = LocalNode::new_testnet(secret);

            let mut config = OverlayConfig::testnet();
            config.listen_port = port;
            config.listen_enabled = true;
            config.known_peers.clear();
            config.connect_timeout_secs = CONNECT_TIMEOUT_SECS;

            let mut manager = OverlayManager::new(config, local)
                .with_context(|| "create overlay manager")?;
            manager.start().await?;

            managers.push(manager);
            peer_addrs.push(PeerAddress::new("127.0.0.1", port));
        }

        // Connect node 0 (the hub) to all other nodes to form a star topology.
        if let Some(root) = managers.get(0) {
            for addr in peer_addrs.iter().skip(1) {
                let _ = root.connect(addr).await;
            }
        }

        // Allow time for connections to establish.
        sleep(Duration::from_millis(CONNECTION_SETTLE_MS)).await;

        Ok(Self { managers, peer_addrs })
    }

    /// Broadcasts a placeholder SCP nomination message from node 0.
    ///
    /// This method creates a minimal SCP envelope with the specified slot index
    /// and broadcasts it to all connected peers via node 0. The message uses
    /// placeholder values (zero node ID, empty votes) and is primarily useful
    /// for testing message propagation.
    ///
    /// # Arguments
    ///
    /// * `slot` - The slot index for the SCP message.
    ///
    /// # Errors
    ///
    /// Returns an error if the broadcast operation fails.
    ///
    /// # Note
    ///
    /// This is a test utility that sends an intentionally minimal/invalid SCP
    /// message. It should not be used as a template for real SCP message
    /// construction.
    pub async fn broadcast_scp(&self, slot: u64) -> Result<()> {
        let envelope = self.create_placeholder_scp_envelope(slot);
        let message = StellarMessage::ScpMessage(envelope);

        if let Some(hub) = self.managers.first() {
            hub.broadcast(message).await?;
        }

        Ok(())
    }

    /// Returns the number of nodes in this simulation.
    #[inline]
    pub fn node_count(&self) -> usize {
        self.managers.len()
    }

    /// Returns a reference to the hub node (node 0).
    ///
    /// Returns `None` if the simulation has no nodes.
    #[inline]
    pub fn hub(&self) -> Option<&OverlayManager> {
        self.managers.first()
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    /// Creates a minimal SCP envelope for testing message propagation.
    ///
    /// The envelope contains placeholder values (zero node ID, empty votes)
    /// and is not cryptographically valid. It is only useful for testing
    /// that messages flow through the network correctly.
    fn create_placeholder_scp_envelope(&self, slot: u64) -> ScpEnvelope {
        // Use zero-filled public key as a placeholder node ID.
        let placeholder_node_id = NodeId(PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32])));

        // Create a minimal nomination statement with no actual votes.
        let nomination = ScpNomination {
            quorum_set_hash: Hash([0u8; 32]),
            votes: vec![].try_into().expect("empty vec is valid"),
            accepted: vec![].try_into().expect("empty vec is valid"),
        };

        // Zero-filled signature (not cryptographically valid).
        let placeholder_signature = Signature(vec![0u8; 64].try_into().expect("64 bytes is valid"));

        ScpEnvelope {
            statement: ScpStatement {
                node_id: placeholder_node_id,
                slot_index: slot,
                pledges: ScpStatementPledges::Nominate(nomination),
            },
            signature: placeholder_signature,
        }
    }

    /// Shuts down all overlay managers in the simulation.
    ///
    /// This method consumes the simulation, ensuring it cannot be used after
    /// shutdown. Each manager is shut down in order, allowing pending
    /// operations to complete gracefully.
    ///
    /// # Errors
    ///
    /// Returns an error if any manager fails to shut down cleanly.
    pub async fn shutdown(mut self) -> Result<()> {
        for manager in &mut self.managers {
            manager.shutdown().await?;
        }
        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Allocates an ephemeral port by binding to port 0 and returning the
/// OS-assigned port number.
///
/// This approach ensures that tests don't conflict over port assignments,
/// as each node gets a unique port from the OS's ephemeral port range.
///
/// # Errors
///
/// Returns an error if binding fails. This commonly happens in sandboxed
/// environments where TCP binding is restricted.
fn allocate_port() -> Result<u16> {
    let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(anyhow!("tcp bind not permitted in this environment"));
        }
        Err(err) => return Err(err.into()),
    };
    let addr = listener.local_addr()?;
    Ok(addr.port())
}

/// Derives a unique seed for a node by hashing the base seed with the node index.
///
/// The derivation concatenates the 32-byte seed with the 4-byte big-endian
/// representation of the index and computes SHA-256. This produces a
/// deterministic but unique seed for each node index.
///
/// # Arguments
///
/// * `seed` - The base seed for the simulation.
/// * `index` - The node index (0-based).
///
/// # Returns
///
/// A 32-byte derived seed unique to the given index.
fn derive_seed(seed: &[u8; 32], index: u32) -> [u8; 32] {
    let mut input = [0u8; 36];
    input[..32].copy_from_slice(seed);
    input[32..].copy_from_slice(&index.to_be_bytes());
    let hash = stellar_core_crypto::sha256(&input);
    *hash.as_bytes()
}

/// Generates a cryptographically secure random 32-byte seed.
///
/// Uses the OS random number generator for high-quality entropy.
fn random_seed() -> [u8; 32] {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that seed derivation is deterministic and produces unique
    /// values for different indices.
    #[test]
    fn test_derive_seed_determinism() {
        let base_seed = [7u8; 32];

        // Same seed and index should produce identical results.
        let derived_a = derive_seed(&base_seed, 1);
        let derived_b = derive_seed(&base_seed, 1);
        assert_eq!(derived_a, derived_b, "seed derivation should be deterministic");

        // Different indices should produce different seeds.
        let derived_c = derive_seed(&base_seed, 2);
        assert_ne!(derived_a, derived_c, "different indices should produce different seeds");
    }

    /// Verifies that different base seeds produce different derived seeds.
    #[test]
    fn test_derive_seed_varies_with_base() {
        let seed_a = [1u8; 32];
        let seed_b = [2u8; 32];

        let derived_a = derive_seed(&seed_a, 0);
        let derived_b = derive_seed(&seed_b, 0);

        assert_ne!(derived_a, derived_b, "different base seeds should produce different results");
    }
}
