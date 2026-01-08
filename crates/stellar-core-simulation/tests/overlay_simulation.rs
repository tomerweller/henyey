//! Integration tests for overlay network simulation lifecycle and connectivity.
//!
//! These tests verify that the simulation correctly establishes peer connections
//! in a star topology and maintains expected connectivity patterns.

use anyhow::Result;
use std::time::Duration;
use stellar_core_simulation::OverlaySimulation;

/// Time to wait for connections to stabilize after simulation startup.
///
/// This accounts for TCP handshakes, authentication, and any additional
/// connection setup that may occur after the simulation's built-in delay.
const CONNECTION_STABILIZATION_DELAY: Duration = Duration::from_millis(300);

/// Attempts to start a simulation, returning `None` if TCP binding is restricted.
///
/// This helper function provides a consistent pattern for handling sandboxed
/// environments where network operations may be prohibited.
async fn start_or_skip(node_count: usize) -> Result<Option<OverlaySimulation>> {
    match OverlaySimulation::start_with_seed(node_count, [7u8; 32]).await {
        Ok(sim) => Ok(Some(sim)),
        Err(err) if err.to_string().contains("tcp bind not permitted") => {
            eprintln!("skipping test: tcp bind not permitted in this environment");
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

/// Tests basic simulation lifecycle: start, broadcast, and shutdown.
///
/// Verifies that:
/// - A 2-node simulation starts successfully
/// - The hub node establishes at least one peer connection
/// - SCP broadcasting completes without error
/// - Shutdown proceeds cleanly
#[tokio::test]
async fn test_overlay_simulation_broadcast() -> Result<()> {
    let Some(sim) = start_or_skip(2).await? else {
        return Ok(());
    };

    // Allow additional time for connection establishment.
    tokio::time::sleep(CONNECTION_STABILIZATION_DELAY).await;

    // Verify the hub has connected to the other node.
    let hub_stats = sim.managers[0].stats();
    assert!(
        hub_stats.connected_peers >= 1,
        "hub should have at least 1 connected peer, found {}",
        hub_stats.connected_peers
    );

    // Verify broadcast completes without error.
    sim.broadcast_scp(1).await?;
    sim.shutdown().await?;

    Ok(())
}

/// Tests that a multi-node simulation establishes expected peer counts.
///
/// In a star topology with 4 nodes:
/// - Node 0 (hub) should connect to all 3 other nodes
/// - Nodes 1-3 should each have at least 1 connection (to the hub)
#[tokio::test]
async fn test_overlay_simulation_peer_counts() -> Result<()> {
    let Some(sim) = start_or_skip(4).await? else {
        return Ok(());
    };

    tokio::time::sleep(CONNECTION_STABILIZATION_DELAY).await;

    // Verify hub connectivity: should be connected to all other nodes.
    let hub_stats = sim.managers[0].stats();
    assert!(
        hub_stats.connected_peers >= 3,
        "hub should have at least 3 connected peers, found {}",
        hub_stats.connected_peers
    );

    // Verify each non-hub node has at least one connection (to the hub).
    for idx in 1..sim.node_count() {
        let peer_stats = sim.managers[idx].stats();
        assert!(
            peer_stats.connected_peers >= 1,
            "peer {idx} should have at least 1 connection, found {}",
            peer_stats.connected_peers
        );
    }

    sim.shutdown().await?;
    Ok(())
}
