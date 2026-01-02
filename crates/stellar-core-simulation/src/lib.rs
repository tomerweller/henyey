//! Simulation harness for rs-stellar-core.

use anyhow::{anyhow, Context, Result};
use stellar_core_crypto::SecretKey;
use stellar_core_overlay::{LocalNode, OverlayConfig, OverlayManager, PeerAddress};
use stellar_xdr::curr::{
    Hash, ScpEnvelope, ScpNomination, ScpStatement, ScpStatementPledges, StellarMessage, Uint256,
};
use tokio::time::{sleep, Duration};

pub struct OverlaySimulation {
    pub managers: Vec<OverlayManager>,
    pub peer_addrs: Vec<PeerAddress>,
}

impl OverlaySimulation {
    pub async fn start(node_count: usize) -> Result<Self> {
        let seed = random_seed();
        Self::start_with_seed(node_count, seed).await
    }

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
            config.connect_timeout_secs = 5;

            let mut manager = OverlayManager::new(config, local)
                .with_context(|| "create overlay manager")?;
            manager.start().await?;

            managers.push(manager);
            peer_addrs.push(PeerAddress::new("127.0.0.1", port));
        }

        // Connect node 0 to all others.
        if let Some(root) = managers.get(0) {
            for addr in peer_addrs.iter().skip(1) {
                let _ = root.connect(addr).await;
            }
        }

        sleep(Duration::from_millis(200)).await;

        Ok(Self { managers, peer_addrs })
    }

    pub async fn broadcast_scp(&self, slot: u64) -> Result<()> {
        let envelope = ScpEnvelope {
            statement: ScpStatement {
                node_id: stellar_xdr::curr::NodeId(stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
                    Uint256([0u8; 32]),
                )),
                slot_index: slot,
                pledges: ScpStatementPledges::Nominate(ScpNomination {
                    quorum_set_hash: Hash([0u8; 32]),
                    votes: vec![].try_into().unwrap(),
                    accepted: vec![].try_into().unwrap(),
                }),
            },
            signature: stellar_xdr::curr::Signature(vec![0u8; 64].try_into().unwrap()),
        };

        let message = StellarMessage::ScpMessage(envelope);
        if let Some(root) = self.managers.get(0) {
            root.broadcast(message).await?;
        }
        Ok(())
    }

    pub async fn shutdown(mut self) -> Result<()> {
        for manager in &mut self.managers {
            manager.shutdown().await?;
        }
        Ok(())
    }
}

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

fn derive_seed(seed: &[u8; 32], index: u32) -> [u8; 32] {
    let mut input = [0u8; 36];
    input[..32].copy_from_slice(seed);
    input[32..].copy_from_slice(&index.to_be_bytes());
    let hash = stellar_core_crypto::sha256(&input);
    *hash.as_bytes()
}

fn random_seed() -> [u8; 32] {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_seed_is_stable() {
        let seed = [7u8; 32];
        let a = derive_seed(&seed, 1);
        let b = derive_seed(&seed, 1);
        let c = derive_seed(&seed, 2);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
