//! Integration tests verifying that SCP messages propagate through the simulated
//! overlay network from the hub node to all connected peers.

use anyhow::Result;
use stellar_core_overlay::OverlayMessage;
use stellar_core_simulation::OverlaySimulation;
use stellar_xdr::curr::StellarMessage;
use tokio::time::{timeout, Duration, Instant};

/// Maximum time to wait for a message to arrive at a peer node.
const MESSAGE_RECEIVE_TIMEOUT: Duration = Duration::from_secs(2);

/// Tests that an SCP message broadcast from the hub node (node 0) reaches
/// all other nodes in the star topology.
///
/// This test verifies the core message propagation functionality:
/// 1. All nodes receive message subscriptions correctly
/// 2. The hub's broadcast reaches every connected peer
/// 3. Messages maintain their type (SCP) through the network
#[tokio::test]
async fn test_overlay_broadcast_reaches_peers() -> Result<()> {
    // Attempt to start the simulation; skip gracefully if TCP binding is restricted.
    let sim = match OverlaySimulation::start_with_seed(3, [7u8; 32]).await {
        Ok(sim) => sim,
        Err(err) if err.to_string().contains("tcp bind not permitted") => {
            eprintln!("skipping test: tcp bind not permitted in this environment");
            return Ok(());
        }
        Err(err) => return Err(err),
    };

    // Subscribe to messages on all nodes before broadcasting.
    let mut receivers: Vec<_> = sim.managers.iter().map(|m| m.subscribe()).collect();

    // Broadcast an SCP message from the hub node.
    sim.broadcast_scp(1).await?;

    // Verify that each non-hub node receives the SCP message.
    for (idx, receiver) in receivers.iter_mut().enumerate() {
        // Skip node 0 (the hub) since it's the sender.
        if idx == 0 {
            continue;
        }

        let received_scp = wait_for_scp_message(receiver, MESSAGE_RECEIVE_TIMEOUT).await;
        assert!(received_scp, "peer {idx} did not receive SCP message within timeout");
    }

    sim.shutdown().await?;
    Ok(())
}

/// Waits for an SCP message on the given receiver, returning true if one arrives
/// before the deadline.
async fn wait_for_scp_message(
    receiver: &mut tokio::sync::broadcast::Receiver<OverlayMessage>,
    max_wait: Duration,
) -> bool {
    let deadline = Instant::now() + max_wait;

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());

        match timeout(remaining, receiver.recv()).await {
            Ok(Ok(OverlayMessage { message, .. })) => {
                if matches!(message, StellarMessage::ScpMessage(_)) {
                    return true;
                }
                // Continue waiting if we received a non-SCP message.
            }
            Ok(Err(_)) => break, // Channel closed.
            Err(_) => break,     // Timeout.
        }
    }

    false
}
