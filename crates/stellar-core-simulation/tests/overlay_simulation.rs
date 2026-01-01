use anyhow::Result;
use std::time::Duration;

use stellar_core_simulation::OverlaySimulation;

#[tokio::test]
async fn test_overlay_simulation_broadcast() -> Result<()> {
    let sim = OverlaySimulation::start(2).await?;

    tokio::time::sleep(Duration::from_millis(300)).await;
    let stats = sim.managers[0].stats();
    assert!(stats.connected_peers >= 1);

    sim.broadcast_scp(1).await?;
    sim.shutdown().await?;

    Ok(())
}

#[tokio::test]
async fn test_overlay_simulation_peer_counts() -> Result<()> {
    let sim = OverlaySimulation::start(4).await?;

    tokio::time::sleep(Duration::from_millis(300)).await;

    let root_stats = sim.managers[0].stats();
    assert!(root_stats.connected_peers >= 3);

    for idx in 1..sim.managers.len() {
        let stats = sim.managers[idx].stats();
        assert!(stats.connected_peers >= 1, "peer {idx} missing connection");
    }

    sim.shutdown().await?;
    Ok(())
}
