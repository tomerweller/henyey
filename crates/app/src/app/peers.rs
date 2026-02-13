use super::*;

impl App {
    pub async fn peer_snapshots(&self) -> Vec<PeerSnapshot> {
        let overlay = self.overlay.lock().await;
        overlay
            .as_ref()
            .map(|overlay| overlay.peer_snapshots())
            .unwrap_or_default()
    }

    pub async fn connect_peer(&self, addr: PeerAddress) -> anyhow::Result<PeerId> {
        let overlay = self.overlay.lock().await;
        let overlay = overlay
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Overlay manager not available"))?;
        overlay.connect(&addr).await.map_err(|e| anyhow::anyhow!(e))
    }

    pub async fn disconnect_peer(&self, peer_id: &PeerId) -> bool {
        let overlay = self.overlay.lock().await;
        let Some(overlay) = overlay.as_ref() else {
            return false;
        };
        overlay.disconnect(peer_id).await
    }

    pub async fn ban_peer(&self, peer_id: PeerId) -> anyhow::Result<()> {
        let Some(strkey) = Self::peer_id_to_strkey(&peer_id) else {
            anyhow::bail!("Invalid peer id");
        };
        self.db.ban_node(&strkey)?;
        let overlay = self.overlay.lock().await;
        let overlay = overlay
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Overlay manager not available"))?;
        overlay.ban_peer(peer_id).await;
        Ok(())
    }

    pub async fn unban_peer(&self, peer_id: &PeerId) -> anyhow::Result<bool> {
        let Some(strkey) = Self::peer_id_to_strkey(peer_id) else {
            anyhow::bail!("Invalid peer id");
        };
        self.db.unban_node(&strkey)?;
        let overlay = self.overlay.lock().await;
        let overlay = overlay
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Overlay manager not available"))?;
        Ok(overlay.unban_peer(peer_id))
    }

    pub async fn banned_peers(&self) -> anyhow::Result<Vec<PeerId>> {
        let bans = self.db.load_bans()?;
        let mut peers = Vec::new();
        for ban in bans {
            if let Some(peer_id) = Self::strkey_to_peer_id(&ban) {
                peers.push(peer_id);
            } else {
                tracing::warn!(node = %ban, "Ignoring invalid ban entry");
            }
        }
        Ok(peers)
    }

    /// Maintain peer connections - reconnect if peer count drops too low.
    pub(super) async fn maintain_peers(&self) {
        let _ = self
            .db
            .remove_peers_with_failures(self.config.overlay.peer_max_failures);
        let overlay_guard = self.overlay.lock().await;
        let overlay = match overlay_guard.as_ref() {
            Some(o) => o,
            None => return,
        };

        let peer_count = overlay.peer_count();
        let min_peers = 3; // Minimum peers we want

        if peer_count < min_peers {
            tracing::info!(
                peer_count,
                min_peers,
                "Peer count below threshold, reconnecting to known peers"
            );

            // Try to reconnect to known peers (dynamic list first, then config).
            let mut candidates = overlay.known_peers();
            for addr_str in &self.config.overlay.known_peers {
                // Parse "host:port" or just "host" (default port 11625)
                let parts: Vec<&str> = addr_str.split(':').collect();
                let peer_addr = match parts.len() {
                    1 => Some(PeerAddress::new(parts[0], 11625)),
                    2 => parts[1]
                        .parse()
                        .ok()
                        .map(|port| PeerAddress::new(parts[0], port)),
                    _ => None,
                };
                if let Some(addr) = peer_addr {
                    if !candidates.contains(&addr) {
                        candidates.push(addr);
                    }
                }
            }

            let mut reconnected = false;
            let candidates = self.refresh_known_peers(overlay);
            for addr in candidates {
                if overlay.peer_count() >= self.config.overlay.target_outbound_peers {
                    break;
                }

                if let Err(e) = overlay.connect(&addr).await {
                    tracing::debug!(addr = %addr, error = %e, "Failed to reconnect to peer");
                } else {
                    reconnected = true;
                }
            }

            // Drop the lock explicitly before requesting SCP state
            // (which needs to acquire the lock again)
            let _ = overlay;
            drop(overlay_guard);

            if reconnected {
                // Give peers time to complete handshake
                tokio::time::sleep(Duration::from_millis(200)).await;
                self.request_scp_state_from_peers().await;
            }
        }
    }

    fn next_ping_hash(&self) -> Hash256 {
        let counter = self.ping_counter.fetch_add(1, Ordering::Relaxed);
        Hash256::hash(&counter.to_be_bytes())
    }

    pub(super) async fn send_peer_pings(&self) {
        const PING_TIMEOUT: Duration = Duration::from_secs(60);

        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(o) => o,
            None => return,
        };

        let snapshots = overlay.peer_snapshots();
        if snapshots.is_empty() {
            return;
        }

        let now = Instant::now();
        let mut inflight = self.ping_inflight.write().await;
        let mut peer_inflight = self.peer_ping_inflight.write().await;
        inflight.retain(|hash, info| {
            if now.duration_since(info.sent_at) > PING_TIMEOUT {
                if let Some(existing) = peer_inflight.get(&info.peer_id) {
                    if existing == hash {
                        peer_inflight.remove(&info.peer_id);
                    }
                }
                return false;
            }
            true
        });

        let mut to_ping = Vec::new();
        for snapshot in snapshots {
            if peer_inflight.contains_key(&snapshot.info.peer_id) {
                continue;
            }
            let hash = self.next_ping_hash();
            peer_inflight.insert(snapshot.info.peer_id.clone(), hash);
            inflight.insert(
                hash,
                PingInfo {
                    peer_id: snapshot.info.peer_id.clone(),
                    sent_at: Instant::now(),
                },
            );
            to_ping.push((snapshot.info.peer_id, hash));
        }
        drop(inflight);
        drop(peer_inflight);

        for (peer, hash) in to_ping {
            let msg = StellarMessage::GetScpQuorumset(stellar_xdr::curr::Uint256(hash.0));
            if let Err(e) = overlay.send_to(&peer, msg).await {
                tracing::debug!(peer = %peer, error = %e, "Failed to send ping");
                let mut inflight = self.ping_inflight.write().await;
                inflight.remove(&hash);
                let mut peer_inflight = self.peer_ping_inflight.write().await;
                if let Some(existing) = peer_inflight.get(&peer) {
                    if *existing == hash {
                        peer_inflight.remove(&peer);
                    }
                }
            }
        }
    }

    pub(super) async fn process_ping_response(&self, peer_id: &henyey_overlay::PeerId, hash: [u8; 32]) {
        let hash = Hash256::from_bytes(hash);
        let info = {
            let mut inflight = self.ping_inflight.write().await;
            inflight.remove(&hash)
        };

        let Some(info) = info else {
            return;
        };

        {
            let mut peer_inflight = self.peer_ping_inflight.write().await;
            if let Some(existing) = peer_inflight.get(&info.peer_id) {
                if *existing == hash {
                    peer_inflight.remove(&info.peer_id);
                }
            }
        }

        if &info.peer_id != peer_id {
            return;
        }

        let latency_ms = info.sent_at.elapsed().as_millis() as u64;
        let mut survey_data = self.survey_data.write().await;
        survey_data.record_peer_latency(peer_id, latency_ms);
    }

    /// Process a peer list received from the network.
    pub(super) async fn process_peer_list(
        &self,
        peer_list: stellar_xdr::curr::VecM<stellar_xdr::curr::PeerAddress, 100>,
    ) {
        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(o) => o,
            None => return,
        };

        // Convert XDR peer addresses to our PeerAddress format
        let addrs: Vec<PeerAddress> = peer_list
            .iter()
            .filter_map(|xdr_addr| {
                // Extract IP address from the XDR type
                let ip = match &xdr_addr.ip {
                    stellar_xdr::curr::PeerAddressIp::IPv4(bytes) => {
                        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
                    }
                    stellar_xdr::curr::PeerAddressIp::IPv6(_) => {
                        return None;
                    }
                };

                let port = xdr_addr.port;

                // Skip obviously invalid addresses
                if port == 0 {
                    return None;
                }

                Some(PeerAddress::new(ip, port as u16))
            })
            .collect();

        let addrs = self.filter_discovered_peers(addrs);

        if !addrs.is_empty() {
            self.persist_peers(&addrs);
            let count = overlay.add_peers(addrs).await;
            if count > 0 {
                tracing::info!(added = count, "Added peers from discovery");
            }
        }

        let _ = self.refresh_known_peers(overlay);
    }

    pub(super) fn parse_peer_address(value: &str) -> Option<PeerAddress> {
        let parts: Vec<&str> = value.split(':').collect();
        match parts.len() {
            1 => Some(PeerAddress::new(parts[0], 11625)),
            2 => parts[1]
                .parse()
                .ok()
                .map(|port| PeerAddress::new(parts[0], port)),
            _ => None,
        }
    }

    fn peer_id_to_strkey(peer_id: &PeerId) -> Option<String> {
        henyey_crypto::PublicKey::from_bytes(peer_id.as_bytes())
            .ok()
            .map(|pk| pk.to_strkey())
    }

    pub(super) fn strkey_to_peer_id(value: &str) -> Option<PeerId> {
        henyey_crypto::PublicKey::from_strkey(value)
            .ok()
            .map(|pk| PeerId::from_bytes(*pk.as_bytes()))
    }

    pub(super) fn load_persisted_peers(&self) -> anyhow::Result<Vec<PeerAddress>> {
        let now = current_epoch_seconds();
        let peers = self.db.load_random_peers(
            1000,
            self.config.overlay.peer_max_failures,
            now,
            Some(PEER_TYPE_OUTBOUND),
        )?;
        let mut addrs = Vec::new();
        for (host, port, _) in peers {
            addrs.push(PeerAddress::new(host, port));
        }
        Ok(addrs)
    }

    pub(super) fn store_config_peers(&self) {
        let now = current_epoch_seconds();
        for addr in &self.config.overlay.known_peers {
            if let Some(peer) = Self::parse_peer_address(addr) {
                let record = henyey_db::queries::PeerRecord::new(now, 0, PEER_TYPE_OUTBOUND);
                let _ = self.db.store_peer(&peer.host, peer.port, record);
            }
        }
        for addr in &self.config.overlay.preferred_peers {
            if let Some(peer) = Self::parse_peer_address(addr) {
                let record = henyey_db::queries::PeerRecord::new(now, 0, PEER_TYPE_PREFERRED);
                let _ = self.db.store_peer(&peer.host, peer.port, record);
            }
        }
    }

    fn load_advertised_outbound_peers(&self) -> anyhow::Result<Vec<PeerAddress>> {
        let peers = self.db.load_random_peers_any_outbound_max_failures(
            1000,
            PEER_MAX_FAILURES_TO_SEND,
            PEER_TYPE_INBOUND,
        )?;
        let mut addrs = Vec::new();
        for (host, port, _) in peers {
            addrs.push(PeerAddress::new(host, port));
        }
        Ok(addrs)
    }

    fn load_advertised_inbound_peers(&self) -> anyhow::Result<Vec<PeerAddress>> {
        let peers = self.db.load_random_peers_by_type_max_failures(
            1000,
            PEER_MAX_FAILURES_TO_SEND,
            PEER_TYPE_INBOUND,
        )?;
        let mut addrs = Vec::new();
        for (host, port, _) in peers {
            addrs.push(PeerAddress::new(host, port));
        }
        Ok(addrs)
    }

    fn persist_peers(&self, peers: &[PeerAddress]) {
        let now = current_epoch_seconds();
        for peer in peers {
            let existing = self.db.load_peer(&peer.host, peer.port).ok().flatten();
            if existing.is_some() {
                continue;
            }
            let record = henyey_db::queries::PeerRecord::new(now, 0, PEER_TYPE_OUTBOUND);
            if let Err(err) = self.db.store_peer(&peer.host, peer.port, record) {
                tracing::debug!(peer = %peer, error = %err, "Failed to persist peer");
            }
        }
    }

    fn filter_discovered_peers(&self, peers: Vec<PeerAddress>) -> Vec<PeerAddress> {
        let now = current_epoch_seconds();
        let mut filtered = Vec::new();
        for peer in peers {
            if !Self::is_public_peer(&peer) {
                continue;
            }
            let record = self.db.load_peer(&peer.host, peer.port).ok().flatten();
            if let Some(record) = record {
                if record.num_failures >= self.config.overlay.peer_max_failures {
                    continue;
                }
                if record.next_attempt > now {
                    continue;
                }
            }
            filtered.push(peer);
        }
        filtered
    }

    fn filter_advertised_peers(&self, peers: Vec<PeerAddress>) -> Vec<PeerAddress> {
        peers.into_iter().filter(Self::is_public_peer).collect()
    }

    fn is_public_peer(peer: &PeerAddress) -> bool {
        if peer.port == 0 {
            return false;
        }
        let Ok(ip) = peer.host.parse::<std::net::IpAddr>() else {
            return true;
        };
        match ip {
            std::net::IpAddr::V4(v4) => {
                !(v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_multicast()
                    || v4.is_unspecified())
            }
            std::net::IpAddr::V6(_) => false,
        }
    }

    pub(super) fn refresh_known_peers(&self, overlay: &OverlayManager) -> Vec<PeerAddress> {
        let mut peers = Vec::new();
        for addr in &self.config.overlay.known_peers {
            if let Some(peer) = Self::parse_peer_address(addr) {
                peers.push(peer);
            }
        }
        for addr in &self.config.overlay.preferred_peers {
            if let Some(peer) = Self::parse_peer_address(addr) {
                self.upsert_peer_type(&peer, PEER_TYPE_PREFERRED);
                peers.push(peer);
            }
        }
        if let Ok(persisted) = self.load_persisted_peers() {
            peers.extend(persisted);
        }
        let peers = self.filter_discovered_peers(peers);
        let peers = self.dedupe_peers(peers);
        overlay.set_known_peers(peers.clone());

        let mut advertised_outbound = Vec::new();
        for addr in &self.config.overlay.known_peers {
            if let Some(peer) = Self::parse_peer_address(addr) {
                advertised_outbound.push(peer);
            }
        }
        for addr in &self.config.overlay.preferred_peers {
            if let Some(peer) = Self::parse_peer_address(addr) {
                advertised_outbound.push(peer);
            }
        }
        if let Ok(persisted) = self.load_advertised_outbound_peers() {
            advertised_outbound.extend(persisted);
        }
        let advertised_outbound = self.filter_advertised_peers(advertised_outbound);
        let advertised_outbound = self.dedupe_peers(advertised_outbound);

        let mut advertised_inbound = Vec::new();
        if let Ok(persisted) = self.load_advertised_inbound_peers() {
            advertised_inbound.extend(persisted);
        }
        let advertised_inbound = self.filter_advertised_peers(advertised_inbound);
        let advertised_inbound = self.dedupe_peers(advertised_inbound);
        overlay.set_advertised_peers(advertised_outbound, advertised_inbound);

        peers
    }

    fn upsert_peer_type(&self, peer: &PeerAddress, peer_type: i32) {
        let now = current_epoch_seconds();
        let existing = self.db.load_peer(&peer.host, peer.port).ok().flatten();
        let record = match existing {
            Some(existing) => henyey_db::queries::PeerRecord::new(
                existing.next_attempt,
                existing.num_failures,
                peer_type,
            ),
            None => henyey_db::queries::PeerRecord::new(now, 0, peer_type),
        };
        let _ = self.db.store_peer(&peer.host, peer.port, record);
    }

    fn dedupe_peers(&self, peers: Vec<PeerAddress>) -> Vec<PeerAddress> {
        let mut seen = HashSet::new();
        let mut deduped = Vec::new();
        for peer in peers {
            if seen.insert(peer.to_socket_addr()) {
                deduped.push(peer);
            }
        }
        deduped
    }
}
