## Pseudocode: crates/app/src/app/lifecycle.rs

### App::run

"Main event loop — starts all subsystems and runs until shutdown."

```
async function run():
  // --- Phase 1: Initialize subsystems ---
  if overlay not started:
    start_overlay()

  current_ledger = get_current_ledger()
  if current_ledger == 0:
    "No ledger state, running catchup first"
    result = catchup(Current)          REF: app/catchup_impl::catchup
    current_ledger = result.ledger_seq

  // --- Phase 2: Bootstrap consensus ---
  last_processed_slot = current_ledger
  herder.start_syncing()
  herder.bootstrap(current_ledger)     REF: henyey_herder::Herder::bootstrap

  sleep(500ms)
  request_scp_state_from_peers()
  restore_operational_state()
  start_sync_recovery_tracking()

  // --- Phase 3: Set up message channels ---
  message_rx       = overlay.subscribe()        // broadcast (non-critical)
  scp_message_rx   = overlay.subscribe_scp()    // dedicated, never-drop
  fetch_response_rx = overlay.subscribe_fetch_responses()  // dedicated

  // --- Phase 4: Pre-loop cleanup ---
  "Process externalized slots recorded during catchup
   BEFORE entering main loop"
  process_externalized_slots()

  "Clear pending tx_set requests and stale syncing_ledgers entries.
   During catchup, SCP state responses bring EXTERNALIZE messages for
   slots whose tx_sets may already be evicted from peers' caches."
  herder.clear_pending_tx_sets()
  remove syncing_ledgers entries where:
    seq <= current_ledger OR tx_set is null
  clear: tx_set_dont_have, tx_set_last_request,
         tx_set_exhausted_warned
  tx_set_all_peers_exhausted = false
```

```
  // --- Phase 5: Timers ---
  CONST MAX_DRAIN_PER_TICK = 200

  consensus_interval       = every 5s
  stats_interval           = every 30s
  tx_advert_interval       = every flood_advert_period
  tx_demand_interval       = every flood_demand_period
  survey_interval          = every 1s
  survey_phase_interval    = every 5s
  survey_request_interval  = every 1s
  scp_timeout_interval     = every 500ms
  ping_interval            = every 5s
  peer_maintenance_interval = every 10s
  peer_refresh_interval    = every 60s
  herder_cleanup_interval  = every 30s
  heartbeat_interval       = every 10s

  start_event_loop_watchdog()
  pending_close = null
```

```
  // --- Phase 6: Main select loop ---
  loop:
    select_iteration += 1
    tick_event_loop()

    select:
      // --- Branch: pending_close completed ---
      pending_close completes:
        success = handle_close_complete(pending_close, result)
        if success:
          if is_validator:
            try_trigger_consensus()

          "Drain SCP + fetch channels before deciding next close"
          drain up to MAX_DRAIN_PER_TICK from scp_message_rx
          drain up to MAX_DRAIN_PER_TICK from fetch_response_rx
          process_externalized_slots()
          pending_close = try_start_ledger_close()

          if pending_close is null:
            "Rapid close cycle ended"
            reset last_externalized_at = now
            reset tx_set tracking state
            reset consensus_stuck_state

      // --- Branch: SCP message (dedicated channel) ---
      scp_message_rx receives scp_msg:
        handle_overlay_message(scp_msg)

      // --- Branch: fetch response (dedicated channel) ---
      fetch_response_rx receives fetch_msg:
        handle_overlay_message(fetch_msg)

      // --- Branch: broadcast messages (non-critical) ---
      message_rx receives overlay_msg:
        NOTE: skip SCP messages (handled above)
        NOTE: skip fetch responses (handled above)
        handle_overlay_message(overlay_msg)

      // --- Branch: outbound SCP envelope ---
      scp_rx receives envelope:
        record scp_latency.self_sent(slot)
        if latency sample available:
          survey_data.record_scp_first_to_self_latency(ms)
        overlay.broadcast(ScpMessage(envelope))

      // --- Branch: consensus timer (5s) ---
      consensus_interval ticks:
        drain up to MAX_DRAIN_PER_TICK from scp_message_rx
        drain up to MAX_DRAIN_PER_TICK from fetch_response_rx

        if sync_recovery_pending:
          out_of_sync_recovery(current_ledger)
          maybe_start_buffered_catchup()

        process_externalized_slots()

        if pending_close is null:
          pending_close = try_start_ledger_close()

        request_pending_tx_sets()

        if is_validator:
          try_trigger_consensus()

      // --- Branch: stats (30s) ---
      stats_interval: log_stats()

      // --- Branch: tx advert flush ---
      tx_advert_interval: flush_tx_adverts()

      // --- Branch: tx demand ---
      tx_demand_interval: run_tx_demands()

      // --- Branch: survey scheduler (1s) ---
      survey_interval:
        if config.overlay.auto_survey:
          advance_survey_scheduler()

      // --- Branch: survey request top-off (1s) ---
      survey_request_interval: top_off_survey_requests()

      // --- Branch: survey phase (5s) ---
      survey_phase_interval: update_survey_phase()

      // --- Branch: SCP timeout (500ms) ---
      scp_timeout_interval: check_scp_timeouts()

      // --- Branch: ping (5s) ---
      ping_interval: send_peer_pings()

      // --- Branch: peer maintenance (10s) ---
      peer_maintenance_interval: maintain_peers()

      // --- Branch: peer refresh (60s) ---
      peer_refresh_interval: refresh_known_peers()

      // --- Branch: herder cleanup (30s) ---
      herder_cleanup_interval: herder.cleanup()

      // --- Branch: shutdown ---
      shutdown_rx: break

      // --- Branch: heartbeat (10s) ---
      heartbeat_interval:
        tracking_slot = herder.tracking_slot()
        latest_ext = herder.latest_externalized_slot()
        peers = overlay.peer_count()
        quorum_check_slot = latest_ext if > 0, else tracking_slot
        heard_from_quorum = herder.heard_from_quorum(quorum_check_slot)

        if is_validator and not heard_from_quorum and peers > 0:
          warn("may be experiencing network partition")

        "If externalization stalls, ask peers for fresh SCP state"
        if peers > 0 and herder can receive SCP:
          if time_since(last_externalized) > 20s
             and time_since(last_scp_state_request) > 10s:
            gap = latest_ext - current_ledger
            if gap <= TX_SET_REQUEST_WINDOW:
              NOTE: "essentially caught up, skipping SCP state request"
            else:
              request_scp_state_from_peers()

        "Out-of-sync recovery: purge old slots when too far behind"
        if not can_receive_scp or not heard_from_quorum:
          herder.out_of_sync_recovery(ledger)

  // --- Phase 7: Shutdown ---
  set_state(ShuttingDown)
  shutdown_internal()
```

### App::start_overlay

```
async function start_overlay():
  store_config_peers()

  local_node = if passphrase contains "Test":
    LocalNode.new_testnet(keypair)
  else:
    LocalNode.new_mainnet(keypair)
  local_node.listening_port = config.overlay.peer_port

  overlay_config = if passphrase contains "Test":
    OverlayManagerConfig.testnet()
  else:
    OverlayManagerConfig.mainnet()

  // Override with app config
  overlay_config.max_inbound_peers  = config values
  overlay_config.max_outbound_peers = config values
  overlay_config.target_outbound_peers = config values
  overlay_config.listen_port = config.overlay.peer_port
  overlay_config.listen_enabled = is_validator
  overlay_config.is_validator = is_validator
  overlay_config.network_passphrase = config passphrase

  // Parse known peers from config strings
  overlay_config.known_peers = parse each config.overlay.known_peers

  // Merge persisted peers from DB
  persisted = load_persisted_peers()
  for each addr in persisted:
    if addr not in known_peers:
      known_peers.push(addr)

  // Parse preferred peers
  overlay_config.preferred_peers = parse each config.overlay.preferred_peers

  // Set up peer event channel
  (peer_event_tx, peer_event_rx) = channel(1024)
  spawn task: forward peer_event_rx to update_peer_record(db, event)

  overlay = OverlayManager.new(overlay_config, local_node)
    REF: henyey_overlay::OverlayManager::new
  overlay.set_scp_callback(HerderScpCallback(herder))

  // Load ban list
  bans = db.load_bans()
  for each ban in bans:
    peer_id = strkey_to_peer_id(ban)
    overlay.ban_peer(peer_id)

  overlay.start()
  self.overlay = overlay
```

### App::handle_overlay_message

```
async function handle_overlay_message(msg):
  // --- SCP messages ---
  if ScpMessage(envelope):
    slot = envelope.statement.slot_index
    record scp_latency: first_seen(slot), other_after_self(slot)
    if latency sample: survey_data.record_scp_self_to_other_latency(ms)

    // Extract quorum set hash for fetching
    if envelope has quorum_set_hash:
      herder.request_quorum_set(hash, sender_node_id)
      if new pending request:
        overlay.try_send_to(peer, GetScpQuorumset(hash))

    // Extract tx_set_hash from EXTERNALIZE
    is_externalize = (pledges == Externalize)
    tx_set_hash = parse StellarValue from externalize commit value

    state = herder.receive_scp_envelope(envelope)
      REF: henyey_herder::Herder::receive_scp_envelope
    if state == Valid:
      sync_recovery_heartbeat()
      if is_externalize:
        herder.scp_driver().request_tx_set(tx_set_hash, slot)
        if herder.needs_tx_set(tx_set_hash):
          overlay.try_send_to(peer, GetTxSet(tx_set_hash))
        process_externalized_slots()
        request_pending_tx_sets()
    else if state == Fetching:
      "EXTERNALIZE waiting for tx set"
      if tx_set_hash:
        overlay.try_send_to(peer, GetTxSet(tx_set_hash))
      request_pending_tx_sets()

  // --- Transactions ---
  else if Transaction(tx_env):
    tx_hash = compute tx_hash(tx_env)
    result = herder.receive_transaction(tx_env)
    if result == Added:
      record_tx_pull_latency(tx_hash, peer)
      enqueue_tx_advert(tx_env)
    else if result == Duplicate:
      record_tx_pull_latency(tx_hash, peer)

  // --- Flood adverts/demands ---
  else if FloodAdvert(advert): handle_flood_advert(peer, advert)
  else if FloodDemand(demand): handle_flood_demand(peer, demand)

  // --- DontHave ---
  else if DontHave(dont_have):
    if is_tx_set type:
      hash = dont_have.req_hash
      tx_set_dont_have[hash].insert(peer)
      dont_have_count = tx_set_dont_have[hash].size
      peer_count = get_peer_count()

      if herder.needs_tx_set(hash):
        if dont_have_count >= peer_count and peer_count > 0:
          "All peers reported DontHave — relying on slot eviction"
          NOTE: "Like stellar-core, do NOT trigger catchup on DontHave"
          reset request tracking for this hash
        else:
          reset request tracking
          request_pending_tx_sets()

    if is_quorum_set type:
      process_ping_response(peer, hash)

  // --- SCP state request ---
  else if GetScpState(ledger_seq): send_scp_state(peer, ledger_seq)
  else if GetScpQuorumset(hash): send_quorum_set(peer, hash)
  else if ScpQuorumset(qs):
    process_ping_response(peer, hash)
    handle_quorum_set(peer, qs)

  // --- Survey messages ---
  else if TimeSlicedSurveyStartCollecting: handle_survey_start_collecting
  else if TimeSlicedSurveyStopCollecting:  handle_survey_stop_collecting
  else if TimeSlicedSurveyRequest:         handle_survey_request
  else if TimeSlicedSurveyResponse:        handle_survey_response

  // --- Peer list ---
  else if Peers(peer_list): process_peer_list(peer_list)

  // --- Tx sets ---
  else if TxSet(tx_set):              handle_tx_set(tx_set)
  else if GeneralizedTxSet(gen_set):  handle_generalized_tx_set(gen_set)
  else if GetTxSet(hash):             send_tx_set(peer, hash)
```

### App::shutdown_internal

```
async function shutdown_internal():
  set_state(ShuttingDown)
  stop_survey_reporting()

  if overlay exists:
    take ownership of overlay
    overlay.shutdown()
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~1158  | ~230       |
| Functions     | 8      | 5          |
