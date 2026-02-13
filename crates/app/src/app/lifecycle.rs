use super::*;

impl App {
    /// Run the main event loop.
    ///
    /// This starts all subsystems and runs until shutdown is signaled.
    pub async fn run(&self) -> anyhow::Result<()> {
        tracing::info!("Starting main event loop");

        // Start overlay network if not already started.
        // (run_cmd may have already started it before catchup)
        {
            let overlay = self.overlay.lock().await;
            if overlay.is_none() {
                drop(overlay); // release lock before starting
                self.start_overlay().await?;
            }
        }

        // Get current ledger state (catchup was already done by run_cmd)
        let current_ledger = self.get_current_ledger().await?;

        if current_ledger == 0 {
            // This shouldn't happen if run_cmd did catchup, but handle it just in case
            tracing::info!("No ledger state, running catchup first");
            let result = self.catchup(CatchupTarget::Current).await?;
            *self.current_ledger.write().await = result.ledger_seq;
        } else {
            // Ledger manager was already initialized (e.g., catchup ran before run())
            *self.current_ledger.write().await = current_ledger;
        }

        // Bootstrap herder with current ledger
        let ledger_seq = *self.current_ledger.read().await;
        *self.last_processed_slot.write().await = ledger_seq as u64;
        self.herder.start_syncing();
        self.herder.bootstrap(ledger_seq);
        tracing::info!(ledger_seq, "Herder bootstrapped");

        // Wait a short time for initial peer connections, then request SCP state
        tokio::time::sleep(Duration::from_millis(500)).await;
        self.request_scp_state_from_peers().await;

        // Set state based on validator mode
        if self.is_validator {
            self.set_state(AppState::Validating).await;
        } else {
            self.set_state(AppState::Synced).await;
        }

        // Start sync recovery tracking to enable the consensus stuck timer
        self.start_sync_recovery_tracking();

        // Get message receiver from overlay
        let message_rx = {
            let overlay = self.overlay.lock().await;
            overlay.as_ref().map(|o| o.subscribe())
        };

        let mut message_rx = match message_rx {
            Some(rx) => rx,
            None => {
                tracing::warn!("Overlay not started, running without network");
                // Create a dummy receiver that never receives
                let (tx, rx) = tokio::sync::broadcast::channel::<OverlayMessage>(1);
                drop(tx);
                rx
            }
         };

        // Get dedicated SCP message receiver (never drops messages)
        let scp_message_rx = {
            let overlay = self.overlay.lock().await;
            match overlay.as_ref() {
                Some(o) => o.subscribe_scp().await,
                None => None,
            }
        };

        let mut scp_message_rx = match scp_message_rx {
            Some(rx) => rx,
            None => {
                // Create a dummy receiver that never receives
                let (_tx, rx) = tokio::sync::mpsc::unbounded_channel::<OverlayMessage>();
                rx
            }
        };

        // Get dedicated fetch response receiver (never drops messages)
        let fetch_response_rx = {
            let overlay = self.overlay.lock().await;
            match overlay.as_ref() {
                Some(o) => o.subscribe_fetch_responses().await,
                None => None,
            }
        };

        let mut fetch_response_rx = match fetch_response_rx {
            Some(rx) => rx,
            None => {
                // Create a dummy receiver that never receives
                let (_tx, rx) = tokio::sync::mpsc::unbounded_channel::<OverlayMessage>();
                rx
            }
        };

        // Main run loop
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let mut consensus_interval = tokio::time::interval(Duration::from_secs(5));
        let mut stats_interval = tokio::time::interval(Duration::from_secs(30));
        stats_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut tx_advert_interval = tokio::time::interval(self.flood_advert_period());
        let mut tx_demand_interval = tokio::time::interval(self.flood_demand_period());
        let mut survey_interval = tokio::time::interval(Duration::from_secs(1));
        let mut survey_phase_interval = tokio::time::interval(Duration::from_secs(5));
        let mut survey_request_interval = tokio::time::interval(Duration::from_secs(1));
        let mut scp_timeout_interval = tokio::time::interval(Duration::from_millis(500));
        let mut ping_interval = tokio::time::interval(Duration::from_secs(5));
        let mut peer_maintenance_interval = tokio::time::interval(Duration::from_secs(10));
        peer_maintenance_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut peer_refresh_interval = tokio::time::interval(Duration::from_secs(60));
        peer_refresh_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut herder_cleanup_interval = tokio::time::interval(Duration::from_secs(30));
        herder_cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Get mutable access to SCP envelope receiver
        let mut scp_rx = self.scp_envelope_rx.lock().await;

        // Process any externalized slots recorded during catchup BEFORE entering the main loop.
        // This ensures we buffer LedgerCloseInfo before new EXTERNALIZE messages trigger cleanup
        // which would remove older externalized slots (only max_externalized_slots are kept).
        self.process_externalized_slots().await;

        // After the pre-loop process_externalized_slots (which may have triggered a
        // rapid close phase), clear all pending tx_set requests and tracking state.
        // During catchup, SCP state responses bring EXTERNALIZE messages for slots
        // whose tx_sets may already be evicted from peers' caches. The pre-loop
        // process_externalized_slots creates syncing_ledgers entries for these slots
        // and kicks off tx_set requests.  If peers silently drop those requests
        // (because the tx_sets are evicted), the 10-second timeout fires, sets
        // tx_set_all_peers_exhausted, and triggers unnecessary catchup — which
        // then repeats the same cycle infinitely.
        //
        // Clearing the state here ensures the main loop starts clean.  Fresh
        // EXTERNALIZE messages arriving via the dedicated SCP channel will create
        // new entries with current tx_set hashes that peers actually have.
        {
            let current_ledger = *self.current_ledger.read().await;
            self.herder.clear_pending_tx_sets();
            // Also clear syncing_ledgers entries that have no tx_set — these are
            // unfulfillable entries created from stale EXTERNALIZE messages.
            let mut buffer = self.syncing_ledgers.write().await;
            let pre_count = buffer.len();
            buffer.retain(|seq, info| {
                // Keep entries that are above current_ledger AND have a tx_set.
                // Remove entries that are at or below current_ledger (already closed)
                // or that have no tx_set (unfulfillable from catchup-phase EXTERNALIZE).
                *seq > current_ledger && info.tx_set.is_some()
            });
            let removed = pre_count - buffer.len();
            if removed > 0 {
                tracing::info!(
                    removed,
                    remaining = buffer.len(),
                    current_ledger,
                    "Removed stale/unfulfillable syncing_ledgers entries before main loop"
                );
            }
            // Reset all tx_set tracking state
            self.tx_set_dont_have.write().await.clear();
            self.tx_set_last_request.write().await.clear();
            self.tx_set_exhausted_warned.write().await.clear();
            self.tx_set_all_peers_exhausted
                .store(false, Ordering::SeqCst);
        }

        tracing::info!("Entering main event loop");

        // Add a short heartbeat interval for debugging
        let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(10));
        heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // In-progress background ledger close. Polled in the select loop.
        let mut pending_close: Option<PendingLedgerClose> = None;

        loop {
            tokio::select! {
                // NOTE: Removed biased; to ensure timers get fair polling

                // Await pending ledger close completion
                join_result = async {
                    match pending_close.as_mut() {
                        Some(p) => (&mut p.handle).await,
                        None => std::future::pending().await,
                    }
                } => {
                    let pending = pending_close.take().unwrap();
                    let success = self.handle_close_complete(pending, join_result).await;
                    // Chain next close if successful.
                    if success {
                        // Before trying the next close, drain SCP + fetch response channels.
                        // During rapid buffered closes the select! loop may not poll these
                        // channels frequently enough, so EXTERNALIZEs and TxSet responses
                        // can sit unprocessed.  Draining here ensures we have the latest
                        // network state before deciding whether another close is ready.
                        while let Ok(scp_msg) = scp_message_rx.try_recv() {
                            self.handle_overlay_message(scp_msg).await;
                        }
                        while let Ok(fetch_msg) = fetch_response_rx.try_recv() {
                            self.handle_overlay_message(fetch_msg).await;
                        }
                        self.process_externalized_slots().await;

                        pending_close = self.try_start_ledger_close().await;

                        // If no more buffered ledgers to close, we just finished a rapid
                        // close cycle.  Do NOT proactively request SCP state here.
                        // Requesting SCP state brings in EXTERNALIZE messages for recent
                        // slots whose tx_sets are already evicted from peers' caches,
                        // causing a cascade of 10s timeouts → tx_set_all_peers_exhausted
                        // → unnecessary catchup.  Instead, just wait: the dedicated SCP
                        // channel guarantees the next natural EXTERNALIZE (with a fresh,
                        // fetchable tx_set) arrives within ~6 seconds.
                        if pending_close.is_none() {
                            let current_ledger = *self.current_ledger.read().await;

                            // Reset last_externalized_at so the heartbeat stall detector
                            // doesn't fire prematurely based on the timestamp of the
                            // EXTERNALIZE that was received 8-10s ago during rapid closes.
                            *self.last_externalized_at.write().await = Instant::now();

                            // Reset tx_set tracking so fresh requests can be made for
                            // buffered entries that still need tx_sets. Don't evict
                            // the entries themselves — they may be closeable once
                            // their tx_sets arrive from peers.
                            self.tx_set_all_peers_exhausted.store(false, Ordering::SeqCst);
                            self.tx_set_dont_have.write().await.clear();
                            self.tx_set_last_request.write().await.clear();
                            self.tx_set_exhausted_warned.write().await.clear();

                            // Also reset consensus stuck state since we just successfully
                            // closed ledgers — we're not stuck.
                            *self.consensus_stuck_state.write().await = None;

                            tracing::info!(
                                current_ledger,
                                "Rapid close cycle ended; waiting for next natural EXTERNALIZE"
                            );
                        }
                    }
                }

                // Process SCP messages from dedicated never-drop channel.
                // These are guaranteed to arrive even if the broadcast channel overflows.
                Some(scp_msg) = scp_message_rx.recv() => {
                    tracing::debug!(
                        latency_ms = scp_msg.received_at.elapsed().as_millis(),
                        "Received SCP message via dedicated channel"
                    );
                    self.handle_overlay_message(scp_msg).await;
                }

                // Process fetch response messages from dedicated never-drop channel.
                // GeneralizedTxSet, TxSet, DontHave, and ScpQuorumset are routed here
                // to ensure they are never lost when the broadcast channel overflows.
                Some(fetch_msg) = fetch_response_rx.recv() => {
                    tracing::debug!(
                        latency_ms = fetch_msg.received_at.elapsed().as_millis(),
                        "Received fetch response via dedicated channel"
                    );
                    self.handle_overlay_message(fetch_msg).await;
                }

                // Process non-critical overlay messages (TX floods, etc.).
                // SCP and fetch-response messages no longer arrive here — they are
                // routed exclusively to dedicated channels at the overlay layer.
                // The skip guards below are kept as defensive fallbacks.
                msg = message_rx.recv() => {
                    match msg {
                        Ok(overlay_msg) => {
                            // Skip SCP messages from broadcast channel — they are already
                            // handled via the dedicated SCP channel above.
                            if matches!(overlay_msg.message, StellarMessage::ScpMessage(_)) {
                                continue;
                            }
                            // Skip fetch response messages from broadcast channel — they are
                            // already handled via the dedicated fetch response channel above.
                            if matches!(
                                overlay_msg.message,
                                StellarMessage::GeneralizedTxSet(_)
                                    | StellarMessage::TxSet(_)
                                    | StellarMessage::DontHave(_)
                                    | StellarMessage::ScpQuorumset(_)
                            ) {
                                continue;
                            }
                            let delivery_latency = overlay_msg.received_at.elapsed();
                            let msg_type = match &overlay_msg.message {
                                StellarMessage::ScpMessage(_) => "SCP",
                                StellarMessage::Transaction(_) => "TX",
                                StellarMessage::TxSet(_) => "TxSet",
                                StellarMessage::GeneralizedTxSet(_) => {
                                    tracing::debug!(latency_ms = delivery_latency.as_millis(), "Overlay delivery latency for GeneralizedTxSet");
                                    "GeneralizedTxSet"
                                },
                                StellarMessage::ScpQuorumset(_) => {
                                    tracing::debug!(latency_ms = delivery_latency.as_millis(), "Overlay delivery latency for ScpQuorumset");
                                    "ScpQuorumset"
                                },
                                StellarMessage::GetTxSet(_) => "GetTxSet",
                                StellarMessage::Hello(_) => "Hello",
                                StellarMessage::Peers(_) => "Peers",
                                _ => "Other",
                            };
                            tracing::debug!(msg_type, latency_ms = delivery_latency.as_millis(), "Received overlay message");
                            self.handle_overlay_message(overlay_msg).await;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            // Only non-critical messages (TX floods) flow through the
                            // broadcast channel now, so lag is expected under load.
                            tracing::debug!(skipped = n, "Overlay broadcast receiver lagged (non-critical messages only)");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            tracing::info!("Overlay broadcast channel closed");
                            break;
                        }
                    }
                }

                // Broadcast outbound SCP envelopes
                envelope = scp_rx.recv() => {
                    if let Some(envelope) = envelope {
                        let slot = envelope.statement.slot_index;
                        let sample = {
                            let mut latency = self.scp_latency.write().await;
                            latency.record_self_sent(slot)
                        };
                        if let Some(ms) = sample {
                            let mut survey_data = self.survey_data.write().await;
                            survey_data.record_scp_first_to_self_latency(ms);
                        }
                        let msg = StellarMessage::ScpMessage(envelope);
                        let overlay = self.overlay.lock().await;
                        if let Some(ref overlay) = *overlay {
                            match overlay.broadcast(msg).await {
                                Ok(count) => {
                                    tracing::debug!(slot, peers = count, "Broadcast SCP envelope");
                                }
                                Err(e) => {
                                    tracing::warn!(slot, error = %e, "Failed to broadcast SCP envelope");
                                }
                            }
                        }
                    }
                }

                // Consensus timer - trigger ledger close for validators and process externalized
                _ = consensus_interval.tick() => {
                    // IMPORTANT: Drain pending overlay messages FIRST before any catchup evaluation.
                    // This ensures tx_sets that arrived via broadcast are processed before we
                    // decide whether to trigger catchup due to missing tx_sets.
                    let mut drained = 0;

                    // Drain dedicated SCP channel first (highest priority)
                    while let Ok(scp_msg) = scp_message_rx.try_recv() {
                        drained += 1;
                        self.handle_overlay_message(scp_msg).await;
                    }

                    // Drain dedicated fetch response channel (tx_sets, dont_have, etc.)
                    while let Ok(fetch_msg) = fetch_response_rx.try_recv() {
                        drained += 1;
                        self.handle_overlay_message(fetch_msg).await;
                    }

                    // Drain broadcast channel (remaining message types only)
                    loop {
                        match message_rx.try_recv() {
                            Ok(overlay_msg) => {
                                // Skip SCP messages — already handled via dedicated channel
                                if matches!(overlay_msg.message, StellarMessage::ScpMessage(_)) {
                                    continue;
                                }
                                // Skip fetch response messages — already handled via dedicated channel
                                if matches!(
                                    overlay_msg.message,
                                    StellarMessage::GeneralizedTxSet(_)
                                        | StellarMessage::TxSet(_)
                                        | StellarMessage::DontHave(_)
                                        | StellarMessage::ScpQuorumset(_)
                                ) {
                                    continue;
                                }
                                drained += 1;
                                self.handle_overlay_message(overlay_msg).await;
                            }
                            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(n)) => {
                                tracing::debug!(skipped = n, "Overlay broadcast receiver lagged during drain (non-critical messages only)");
                            }
                            Err(_) => break, // Empty or Closed
                        }
                    }
                    if drained > 0 {
                        tracing::debug!(drained, "Drained pending overlay messages before consensus tick");
                    }

                    // Check if SyncRecoveryManager requested recovery
                    if self.sync_recovery_pending.swap(false, Ordering::SeqCst) {
                        tracing::debug!("SyncRecoveryManager triggered out-of-sync recovery");
                        // SyncRecoveryManager triggered recovery - perform it now
                        if let Ok(current_ledger) = self.get_current_ledger().await {
                            self.out_of_sync_recovery(current_ledger).await;
                        }
                        // Also check for buffered catchup (this handles timeout-based catchup)
                        self.maybe_start_buffered_catchup().await;
                    }

                    // Check for externalized slots to process
                    self.process_externalized_slots().await;

                    // Start a background ledger close if one isn't already running.
                    if pending_close.is_none() {
                        pending_close = self.try_start_ledger_close().await;
                    }

                    // Request any pending tx sets we need
                    self.request_pending_tx_sets().await;

                    // For validators, try to trigger next round
                    if self.is_validator {
                        self.try_trigger_consensus().await;
                    }
                }

                // Stats logging
                _ = stats_interval.tick() => {
                    self.log_stats().await;
                }

                // Batched tx advert flush
                _ = tx_advert_interval.tick() => {
                    self.flush_tx_adverts().await;
                }

                // Demand missing transactions from peers
                _ = tx_demand_interval.tick() => {
                    self.run_tx_demands().await;
                }

                // Survey scheduler
                _ = survey_interval.tick() => {
                    if self.config.overlay.auto_survey {
                        self.advance_survey_scheduler().await;
                    }
                }

                // Survey reporting request top-off
                _ = survey_request_interval.tick() => {
                    self.top_off_survey_requests().await;
                }

                // Survey phase maintenance
                _ = survey_phase_interval.tick() => {
                    self.update_survey_phase().await;
                }

                // SCP nomination/ballot timeouts
                _ = scp_timeout_interval.tick() => {
                    self.check_scp_timeouts().await;
                }

                // Ping peers for latency measurements
                _ = ping_interval.tick() => {
                    self.send_peer_pings().await;
                }

                // Peer maintenance - reconnect if peer count drops too low
                _ = peer_maintenance_interval.tick() => {
                    self.maintain_peers().await;
                }

                // Refresh known peers from config + SQLite cache
                _ = peer_refresh_interval.tick() => {
                    if let Some(overlay) = self.overlay.lock().await.as_ref() {
                        let _ = self.refresh_known_peers(overlay);
                    }
                }

                // Herder cleanup - evict expired data
                _ = herder_cleanup_interval.tick() => {
                    self.herder.cleanup();
                }

                // Shutdown signal (lowest priority)
                _ = shutdown_rx.recv() => {
                    tracing::info!("Shutdown signal received");
                    break;
                }

                // Heartbeat for debugging
                _ = heartbeat_interval.tick() => {
                    let tracking_slot = self.herder.tracking_slot();
                    let ledger = *self.current_ledger.read().await;
                    let latest_ext = self.herder.latest_externalized_slot().unwrap_or(0);
                    let overlay = self.overlay.lock().await;
                    let peers = overlay.as_ref().map(|o| o.peer_count()).unwrap_or(0);
                    drop(overlay);

                    // Check quorum status - use latest_ext if available since we have
                    // actual SCP messages for that slot, otherwise fall back to tracking_slot
                    let quorum_check_slot = if latest_ext > 0 { latest_ext } else { tracking_slot };
                    let heard_from_quorum = self.herder.heard_from_quorum(quorum_check_slot);
                    let is_v_blocking = self.herder.is_v_blocking(quorum_check_slot);

                    tracing::info!(
                        tracking_slot,
                        ledger,
                        latest_ext,
                        peers,
                        heard_from_quorum,
                        is_v_blocking,
                        "Heartbeat"
                    );

                    // Warn if we haven't heard from quorum for a while
                    if self.is_validator && !heard_from_quorum && peers > 0 {
                        tracing::warn!(
                            tracking_slot,
                            is_v_blocking,
                            "Have not heard from quorum - may be experiencing network partition"
                        );
                    }

                    // If externalization stalls, ask peers for fresh SCP state.
                    if peers > 0 && self.herder.state().can_receive_scp() {
                        let now = Instant::now();
                        let last_ext = *self.last_externalized_at.read().await;
                        let last_request = *self.last_scp_state_request_at.read().await;
                        if now.duration_since(last_ext) > Duration::from_secs(20)
                            && now.duration_since(last_request) > Duration::from_secs(10)
                        {
                            // When essentially caught up (small gap), do NOT request
                            // SCP state.  Peers respond with EXTERNALIZE for recent
                            // slots whose tx_sets are already evicted from their
                            // caches, creating unfulfillable requests.  Instead, wait
                            // for the next natural EXTERNALIZE (~5-6s).
                            let current_ledger = *self.current_ledger.read().await;
                            let gap = latest_ext.saturating_sub(current_ledger as u64);
                            if gap <= TX_SET_REQUEST_WINDOW {
                                tracing::debug!(
                                    current_ledger,
                                    latest_ext,
                                    gap,
                                    "Heartbeat: essentially caught up, skipping SCP state request"
                                );
                            } else {
                                tracing::warn!(
                                    latest_ext,
                                    tracking_slot,
                                    heard_from_quorum,
                                    gap,
                                    "SCP externalization stalled; requesting SCP state"
                                );
                                *self.last_scp_state_request_at.write().await = now;
                                self.request_scp_state_from_peers().await;
                            }
                        }
                    }

                    // Out-of-sync recovery: purge old slots when we're too far behind.
                    // This mirrors stellar-core's outOfSyncRecovery() behavior.
                    // When we have v-blocking slots that are >100 ahead of older slots,
                    // purge the old slots to free memory and allow recovery.
                    if !self.herder.state().can_receive_scp() || !heard_from_quorum {
                        if let Some(purge_slot) = self.herder.out_of_sync_recovery(ledger as u64) {
                            tracing::info!(
                                purge_slot,
                                ledger,
                                tracking_slot,
                                "Out-of-sync recovery: purged old slots"
                            );
                        }
                    }
                }
            }
        }

        self.set_state(AppState::ShuttingDown).await;
        self.shutdown_internal().await?;

        Ok(())
    }

    /// Start the overlay network.
    pub async fn start_overlay(&self) -> anyhow::Result<()> {
        tracing::info!("Starting overlay network");

        self.store_config_peers();

        // Create local node info
        let local_node = if self.config.network.passphrase.contains("Test") {
            LocalNode::new_testnet(self.keypair.clone())
        } else {
            LocalNode::new_mainnet(self.keypair.clone())
        };

        // Start with testnet or mainnet defaults
        let mut overlay_config = if self.config.network.passphrase.contains("Test") {
            OverlayManagerConfig::testnet()
        } else {
            OverlayManagerConfig::mainnet()
        };

        // Override with app config settings
        overlay_config.max_inbound_peers = self.config.overlay.max_inbound_peers;
        overlay_config.max_outbound_peers = self.config.overlay.max_outbound_peers;
        overlay_config.target_outbound_peers = self.config.overlay.target_outbound_peers;
        overlay_config.listen_port = self.config.overlay.peer_port;
        overlay_config.listen_enabled = self.is_validator; // Validators listen for connections
        overlay_config.is_validator = self.is_validator; // Watchers filter non-essential messages
        overlay_config.network_passphrase = self.config.network.passphrase.clone();

        // Convert known peers from strings to PeerAddress
        if !self.config.overlay.known_peers.is_empty() {
            overlay_config.known_peers = self
                .config
                .overlay
                .known_peers
                .iter()
                .filter_map(|s| Self::parse_peer_address(s))
                .collect();
        }

        if let Ok(persisted) = self.load_persisted_peers() {
            for addr in persisted {
                if !overlay_config.known_peers.contains(&addr) {
                    overlay_config.known_peers.push(addr);
                }
            }
        }

        // Convert preferred peers
        if !self.config.overlay.preferred_peers.is_empty() {
            overlay_config.preferred_peers = self
                .config
                .overlay
                .preferred_peers
                .iter()
                .filter_map(|s| {
                    let parts: Vec<&str> = s.split(':').collect();
                    match parts.len() {
                        1 => Some(PeerAddress::new(parts[0], 11625)),
                        2 => parts[1]
                            .parse()
                            .ok()
                            .map(|port| PeerAddress::new(parts[0], port)),
                        _ => None,
                    }
                })
                .collect();
        }

        let (peer_event_tx, mut peer_event_rx) = mpsc::channel(1024);
        overlay_config.peer_event_tx = Some(peer_event_tx);

        let db = self.db.clone();
        tokio::spawn(async move {
            while let Some(event) = peer_event_rx.recv().await {
                update_peer_record(&db, event);
            }
        });

        tracing::info!(
            listen_port = overlay_config.listen_port,
            known_peers = overlay_config.known_peers.len(),
            listen_enabled = overlay_config.listen_enabled,
            "Creating overlay with config"
        );

        let mut overlay = OverlayManager::new(overlay_config, local_node)?;
        if let Ok(bans) = self.db.load_bans() {
            for ban in bans {
                if let Some(peer_id) = Self::strkey_to_peer_id(&ban) {
                    overlay.ban_peer(peer_id).await;
                } else {
                    tracing::warn!(node = %ban, "Ignoring invalid ban entry");
                }
            }
        }

        overlay.start().await?;

        let peer_count = overlay.peer_count();
        tracing::info!(peer_count, "Overlay network started");

        *self.overlay.lock().await = Some(overlay);
        Ok(())
    }

    /// Set the weak reference to self for spawning background tasks.
    /// Must be called after wrapping App in Arc.
    pub async fn set_self_arc(self: &Arc<Self>) {
        *self.self_arc.write().await = Arc::downgrade(self);
    }

    /// Handle a message from the overlay network.
    async fn handle_overlay_message(&self, msg: OverlayMessage) {
        match msg.message {
            StellarMessage::ScpMessage(envelope) => {
                let slot = envelope.statement.slot_index;
                let tracking = self.herder.tracking_slot();

                let sample = {
                    let mut latency = self.scp_latency.write().await;
                    latency.record_first_seen(slot);
                    latency.record_other_after_self(slot)
                };
                if let Some(ms) = sample {
                    let mut survey_data = self.survey_data.write().await;
                    survey_data.record_scp_self_to_other_latency(ms);
                }

                // Check if this is an EXTERNALIZE message so we can request the tx set
                let is_externalize = matches!(
                    &envelope.statement.pledges,
                    stellar_xdr::curr::ScpStatementPledges::Externalize(_)
                );
                let tx_set_hash = match &envelope.statement.pledges {
                    stellar_xdr::curr::ScpStatementPledges::Externalize(ext) => {
                        match StellarValue::from_xdr(
                            &ext.commit.value.0,
                            stellar_xdr::curr::Limits::none(),
                        ) {
                            Ok(stellar_value) => {
                                Some(Hash256::from_bytes(stellar_value.tx_set_hash.0))
                            }
                            Err(err) => {
                                tracing::warn!(slot, error = %err, "Failed to parse externalized StellarValue");
                                None
                            }
                        }
                    }
                    _ => None,
                };

                if let Some(hash) = Self::scp_quorum_set_hash(&envelope.statement) {
                    let hash256 = henyey_common::Hash256::from_bytes(hash.0);
                    let sender_node_id = envelope.statement.node_id.clone();
                    // Always call request_quorum_set to associate the quorum set with the node_id.
                    // If we already have the quorum set by hash, it will be associated with this
                    // node_id. If not, we'll create a pending request.
                    if self.herder.request_quorum_set(hash256, sender_node_id) {
                        // New pending request - need to fetch from network
                        let peer = msg.from_peer.clone();
                        let overlay = self.overlay.lock().await;
                        if let Some(ref overlay) = *overlay {
                            let request =
                                StellarMessage::GetScpQuorumset(stellar_xdr::curr::Uint256(hash.0));
                            if let Err(e) = overlay.send_to(&peer, request).await {
                                tracing::debug!(peer = %peer, error = %e, "Failed to request quorum set");
                            }
                        }
                    }
                }

                match self.herder.receive_scp_envelope(envelope) {
                    EnvelopeState::Valid => {
                        tracing::debug!(slot, tracking, "Processed SCP envelope (valid)");
                        // Signal heartbeat to sync recovery - consensus is making progress
                        self.sync_recovery_heartbeat();

                        // For EXTERNALIZE messages, immediately try to close ledger and request tx set
                        if is_externalize {
                            tracing::debug!(slot, tracking, "EXTERNALIZE Valid — processing slot");
                            if let Some(tx_set_hash) = tx_set_hash {
                                self.herder.scp_driver().request_tx_set(tx_set_hash, slot);
                                if self.herder.needs_tx_set(&tx_set_hash) {
                                    let peer = msg.from_peer.clone();
                                    let overlay = self.overlay.lock().await;
                                    if let Some(ref overlay) = *overlay {
                                        let request = StellarMessage::GetTxSet(
                                            stellar_xdr::curr::Uint256(tx_set_hash.0),
                                        );
                                        if let Err(e) = overlay.send_to(&peer, request).await {
                                            tracing::debug!(
                                                peer = %peer,
                                                error = %e,
                                                "Failed to request tx set from externalize peer"
                                            );
                                        }
                                    }
                                }
                            }
                            // First, process externalized slots to register pending tx set requests
                            self.process_externalized_slots().await;
                            // Then, immediately request any pending tx sets
                            self.request_pending_tx_sets().await;
                        }
                    }
                    EnvelopeState::Pending => {
                        tracing::debug!(slot, tracking, "SCP envelope buffered for future slot");
                    }
                    EnvelopeState::Duplicate => {
                        // Expected, ignore silently
                    }
                    EnvelopeState::TooOld => {
                        tracing::debug!(slot, tracking, "SCP envelope too old");
                    }
                    EnvelopeState::Invalid => {
                        tracing::debug!(slot, peer = %msg.from_peer, "Invalid SCP envelope");
                    }
                    EnvelopeState::InvalidSignature => {
                        tracing::warn!(slot, peer = %msg.from_peer, "SCP envelope with invalid signature");
                    }
                    EnvelopeState::Fetching => {
                        // Envelope is waiting for its tx set to be fetched.
                        // Request the tx set from the peer that sent this envelope.
                        tracing::debug!(
                            slot,
                            peer = %msg.from_peer,
                            "SCP EXTERNALIZE waiting for tx set (Fetching)"
                        );
                        if let Some(tx_set_hash) = tx_set_hash {
                            let peer = msg.from_peer.clone();
                            let overlay = self.overlay.lock().await;
                            if let Some(ref overlay) = *overlay {
                                let request = StellarMessage::GetTxSet(
                                    stellar_xdr::curr::Uint256(tx_set_hash.0),
                                );
                                if let Err(e) = overlay.send_to(&peer, request).await {
                                    tracing::debug!(
                                        peer = %peer,
                                        error = %e,
                                        "Failed to request tx set for fetching envelope"
                                    );
                                }
                            }
                        }
                        // Also request any other pending tx sets
                        self.request_pending_tx_sets().await;
                    }
                }
            }

            StellarMessage::Transaction(tx_env) => {
                let tx_hash = self.tx_hash(&tx_env);
                match self.herder.receive_transaction(tx_env.clone()) {
                    henyey_herder::TxQueueResult::Added => {
                        tracing::debug!(peer = %msg.from_peer, "Transaction added to queue");
                        if let Some(hash) = tx_hash {
                            self.record_tx_pull_latency(hash, &msg.from_peer).await;
                        }
                        self.enqueue_tx_advert(&tx_env).await;
                    }
                    henyey_herder::TxQueueResult::Duplicate => {
                        if let Some(hash) = tx_hash {
                            self.record_tx_pull_latency(hash, &msg.from_peer).await;
                        }
                        // Expected, ignore
                    }
                    henyey_herder::TxQueueResult::QueueFull => {
                        tracing::warn!("Transaction queue full, dropping transaction");
                    }
                    henyey_herder::TxQueueResult::FeeTooLow => {
                        tracing::debug!("Transaction fee too low, rejected");
                    }
                    henyey_herder::TxQueueResult::Invalid => {
                        tracing::debug!("Invalid transaction rejected");
                    }
                    henyey_herder::TxQueueResult::Banned => {
                        tracing::debug!("Transaction from banned source rejected");
                    }
                    henyey_herder::TxQueueResult::Filtered => {
                        tracing::debug!("Transaction filtered by operation type");
                    }
                    henyey_herder::TxQueueResult::TryAgainLater => {
                        tracing::debug!(
                            "Transaction rejected: account already has pending transaction"
                        );
                    }
                }
            }

            StellarMessage::FloodAdvert(advert) => {
                self.handle_flood_advert(&msg.from_peer, advert).await;
            }

            StellarMessage::FloodDemand(demand) => {
                self.handle_flood_demand(&msg.from_peer, demand).await;
            }

            StellarMessage::DontHave(dont_have) => {
                let is_tx_set = matches!(
                    dont_have.type_,
                    stellar_xdr::curr::MessageType::TxSet
                        | stellar_xdr::curr::MessageType::GeneralizedTxSet
                );
                let is_ping = matches!(
                    dont_have.type_,
                    stellar_xdr::curr::MessageType::ScpQuorumset
                );
                if is_tx_set {
                    tracing::debug!(
                        peer = %msg.from_peer,
                        hash = hex::encode(dont_have.req_hash.0),
                        "Peer reported DontHave for TxSet"
                    );
                    let hash = Hash256::from_bytes(dont_have.req_hash.0);
                    let mut map = self.tx_set_dont_have.write().await;
                    map.entry(hash).or_default().insert(msg.from_peer.clone());
                    
                    // Check if all connected peers have reported DontHave for this tx_set
                    let dont_have_count = map.get(&hash).map(|s| s.len()).unwrap_or(0);
                    let peer_count = self.get_peer_count().await;
                    let all_peers_dont_have = dont_have_count >= peer_count && peer_count > 0;
                    
                    if self.herder.needs_tx_set(&hash) {
                        if all_peers_dont_have {
                            // All peers don't have this tx_set - log but DON'T trigger catchup.
                            // Like stellar-core, we rely on slot eviction to eventually
                            // clean up old slots when we're >100 slots behind the highest
                            // v-blocking slot. Triggering catchup on DontHave creates loops
                            // because catchup targets checkpoints, leaving gaps that also
                            // get DontHave responses.
                            // Only log once per hash to avoid spam during recovery.
                            let already_warned = self.tx_set_exhausted_warned.read().await.contains(&hash);
                            if !already_warned {
                                self.tx_set_exhausted_warned.write().await.insert(hash);
                                tracing::info!(
                                    hash = %hash,
                                    dont_have_count,
                                    peer_count,
                                    "All peers reported DontHave for needed TxSet; relying on slot eviction"
                                );
                            }
                            drop(map);
                            // Reset request tracking to allow retry later
                            let mut last_request = self.tx_set_last_request.write().await;
                            last_request.remove(&hash);
                        } else {
                            let mut last_request = self.tx_set_last_request.write().await;
                            last_request.remove(&hash);
                            drop(last_request);
                            drop(map);
                            self.request_pending_tx_sets().await;
                        }
                    }
                }
                if is_ping {
                    self.process_ping_response(&msg.from_peer, dont_have.req_hash.0)
                        .await;
                }
            }

            StellarMessage::GetScpState(ledger_seq) => {
                tracing::debug!(ledger_seq, peer = %msg.from_peer, "Peer requested SCP state");
                self.send_scp_state(&msg.from_peer, ledger_seq).await;
            }

            StellarMessage::GetScpQuorumset(hash) => {
                tracing::debug!(hash = hex::encode(hash.0), peer = %msg.from_peer, "Peer requested quorum set");
                self.send_quorum_set(&msg.from_peer, hash).await;
            }

            StellarMessage::ScpQuorumset(quorum_set) => {
                tracing::debug!(peer = %msg.from_peer, "Received quorum set");
                let hash = henyey_scp::hash_quorum_set(&quorum_set);
                self.process_ping_response(&msg.from_peer, hash.0).await;
                self.handle_quorum_set(&msg.from_peer, quorum_set).await;
            }

            StellarMessage::TimeSlicedSurveyStartCollecting(start) => {
                self.handle_survey_start_collecting(&msg.from_peer, start)
                    .await;
            }

            StellarMessage::TimeSlicedSurveyStopCollecting(stop) => {
                self.handle_survey_stop_collecting(&msg.from_peer, stop)
                    .await;
            }

            StellarMessage::TimeSlicedSurveyRequest(request) => {
                self.handle_survey_request(&msg.from_peer, request).await;
            }

            StellarMessage::TimeSlicedSurveyResponse(response) => {
                self.handle_survey_response(&msg.from_peer, response).await;
            }

            StellarMessage::Peers(peer_list) => {
                tracing::debug!(count = peer_list.len(), peer = %msg.from_peer, "Received peer list");
                self.process_peer_list(peer_list).await;
            }

            StellarMessage::TxSet(tx_set) => {
                // Compute hash for logging
                let xdr_bytes = stellar_xdr::curr::WriteXdr::to_xdr(&tx_set, stellar_xdr::curr::Limits::none())
                    .unwrap_or_default();
                let computed_hash = henyey_common::Hash256::hash(&xdr_bytes);
                tracing::info!(
                    peer = %msg.from_peer,
                    computed_hash = %computed_hash,
                    prev_ledger = hex::encode(tx_set.previous_ledger_hash.0),
                    tx_count = tx_set.txs.len(),
                    "APP: Received TxSet from overlay"
                );
                self.handle_tx_set(tx_set).await;
            }

            StellarMessage::GeneralizedTxSet(gen_tx_set) => {
                // Compute hash for logging
                let xdr_bytes = stellar_xdr::curr::WriteXdr::to_xdr(&gen_tx_set, stellar_xdr::curr::Limits::none())
                    .unwrap_or_default();
                let computed_hash = henyey_common::Hash256::hash(&xdr_bytes);
                tracing::debug!(
                    peer = %msg.from_peer,
                    computed_hash = %computed_hash,
                    "APP: Received GeneralizedTxSet from overlay"
                );
                self.handle_generalized_tx_set(gen_tx_set).await;
            }

            StellarMessage::GetTxSet(hash) => {
                tracing::debug!(hash = hex::encode(hash.0), peer = %msg.from_peer, "Peer requested TxSet");
                self.send_tx_set(&msg.from_peer, &hash.0).await;
            }

            _ => {
                // Other message types (Hello, Auth, etc.) are handled by overlay
                tracing::trace!(msg_type = ?std::mem::discriminant(&msg.message), "Ignoring message type");
            }
        }
    }

    /// Log current stats.
    async fn log_stats(&self) {
        let stats = self.herder.stats();
        let ledger = *self.current_ledger.read().await;

        // Get overlay stats if available
        let (peer_count, flood_stats) = {
            let overlay = self.overlay.lock().await;
            match overlay.as_ref() {
                Some(o) => (o.peer_count(), Some(o.flood_stats())),
                None => (0, None),
            }
        };

        tracing::info!(
            state = ?stats.state,
            tracking_slot = stats.tracking_slot,
            pending_txs = stats.pending_transactions,
            ledger,
            peers = peer_count,
            is_validator = self.is_validator,
            "Node status"
        );

        if let Some(fs) = flood_stats {
            tracing::debug!(
                seen_messages = fs.seen_count,
                dropped_messages = fs.dropped_messages,
                "Flood gate stats"
            );
        }
    }

    /// Get the current ledger sequence from the database.
    pub(super) async fn get_current_ledger(&self) -> anyhow::Result<u32> {
        // Check if ledger manager is initialized
        if self.ledger_manager.is_initialized() {
            return Ok(self.ledger_manager.current_ledger_seq());
        }
        // No state yet
        Ok(0)
    }

    /// Get the number of connected peers.
    async fn get_peer_count(&self) -> usize {
        let overlay = self.overlay.lock().await;
        overlay.as_ref().map(|o| o.peer_count()).unwrap_or(0)
    }

    /// Signal the application to shut down.
    pub fn shutdown(&self) {
        tracing::info!("Shutdown requested");
        let _ = self.shutdown_tx.send(());
    }

    /// Subscribe to shutdown notifications.
    pub fn subscribe_shutdown(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Internal shutdown cleanup.
    async fn shutdown_internal(&self) -> anyhow::Result<()> {
        tracing::info!("Performing shutdown cleanup");

        self.set_state(AppState::ShuttingDown).await;
        self.stop_survey_reporting().await;

        let mut overlay = self.overlay.lock().await;
        if let Some(mut overlay) = overlay.take() {
            if let Err(err) = overlay.shutdown().await {
                tracing::warn!(error = %err, "Overlay shutdown reported error");
            }
        }

        Ok(())
    }
}
