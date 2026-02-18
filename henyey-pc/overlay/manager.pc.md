## Pseudocode: crates/overlay/src/manager.rs

### Constants

```
CONST PEER_TIMEOUT             = 30s
CONST PEER_STRAGGLER_TIMEOUT   = 120s
CONST PING_INTERVAL_TICKS      = 5     // every 5s (1s tick × 5)
CONST MAX_PEERS_PER_MESSAGE    = 50
CONST POSSIBLY_PREFERRED_EXTRA = 2
```

### Data Structures

```
struct OverlayMessage:
  from_peer: PeerId
  message: StellarMessage
  received_at: timestamp

struct PeerSnapshot:
  info: PeerInfo
  stats: PeerStatsSnapshot

enum OutboundMessage:
  Send(StellarMessage)       // direct, non-flood
  Flood(StellarMessage)      // goes through FlowControl queue
  Shutdown                   // close connection

struct PeerHandle:
  outbound_tx: channel_sender<OutboundMessage>
  stats: shared<PeerStats>
  flow_control: shared<FlowControl>

struct SharedPeerState:
  peers: concurrent_map<PeerId, PeerHandle>
  flood_gate: shared<FloodGate>
  running: atomic<bool>
  message_tx: broadcast_sender<OverlayMessage>
  scp_message_tx: unbounded_sender<OverlayMessage>
  fetch_response_tx: bounded_sender<OverlayMessage>
  peer_handles: list<task_handle>
  advertised_outbound_peers: list<PeerAddress>
  advertised_inbound_peers: list<PeerAddress>
  added_authenticated_peers: atomic<u64>
  dropped_authenticated_peers: atomic<u64>
  banned_peers: set<PeerId>
  peer_info_cache: concurrent_map<PeerId, PeerInfo>
  last_closed_ledger: atomic<u32>
  scp_callback: ScpQueueCallback or null
  is_validator: bool
  peer_event_tx: channel_sender<PeerEvent> or null
  extra_subscribers: list<unbounded_sender<OverlayMessage>>

struct OverlayManager:
  config: OverlayConfig
  local_node: LocalNode
  peers: concurrent_map<PeerId, PeerHandle>
  flood_gate: shared<FloodGate>
  inbound_pool: ConnectionPool
  outbound_pool: ConnectionPool
  running: atomic<bool>
  message_tx: broadcast_sender<OverlayMessage>
  listener_handle: task_handle or null
  connector_handle: task_handle or null
  peer_handles: list<task_handle>
  known_peers: list<PeerAddress>
  advertised_outbound_peers: list<PeerAddress>
  advertised_inbound_peers: list<PeerAddress>
  peer_advertiser_handle: task_handle or null
  added_authenticated_peers: atomic<u64>
  dropped_authenticated_peers: atomic<u64>
  banned_peers: set<PeerId>
  shutdown_tx: broadcast_sender<()>
  peer_info_cache: concurrent_map<PeerId, PeerInfo>
  scp_message_tx: unbounded_sender<OverlayMessage>
  scp_message_rx: take-once receiver
  fetch_response_tx: bounded_sender<OverlayMessage>
  fetch_response_rx: take-once receiver
  extra_subscribers: list<unbounded_sender<OverlayMessage>>
  last_closed_ledger: atomic<u32>
  scp_callback: ScpQueueCallback or null
```

---

### Helper: is_fetch_message

```
function is_fetch_message(message):
  → message is one of:
      GetTxSet, TxSet, GeneralizedTxSet,
      GetScpState, ScpQuorumset, GetScpQuorumset,
      DontHave
```

---

### OverlayManager::new

```
function new(config, local_node):
  create broadcast channel (capacity 4096) for general messages
  create broadcast channel (capacity 1) for shutdown
  create unbounded channel for SCP messages
  create bounded channel (capacity 4096) for fetch responses

  inbound_pool:
    preferred_ips = parse IPs from config.preferred_peers
    if preferred_ips is not empty:
      ConnectionPool with preferred slots
        (max_inbound + POSSIBLY_PREFERRED_EXTRA)
    else:
      ConnectionPool(max_inbound_peers)

  outbound_pool = ConnectionPool(max_outbound_peers)
  flood_gate = FloodGate(ttl = config.flood_ttl_secs)
  known_peers = config.known_peers
  advertised_outbound = config.known_peers
  advertised_inbound = []
  last_closed_ledger = 0
```

### OverlayManager::register_peer

```
function register_peer(peer, peer_id, peer_info, shared):
  create outbound channel (capacity 256)
  stats = peer.stats()
  flow_control = new FlowControl(default config,
                                  shared.scp_callback)
  flow_control.set_peer_id(peer_id)

  MUTATE shared.peers[peer_id] = PeerHandle(
    outbound_tx, stats, flow_control)
  MUTATE shared.peer_info_cache[peer_id] = peer_info

  → (outbound_rx, flow_control)
```

### OverlayManager::start

```
function start():
  GUARD already running → error AlreadyStarted
  MUTATE running = true

  if config.listen_enabled:
    start_listener()

  start_connector()
  start_peer_advertiser()
```

### OverlayManager::start_listener

"Accepts incoming connections"

```
function start_listener():
  bind listener on config.listen_port
```

**Calls** [Listener::bind](#) for TCP accept

```
  spawn background task:
    loop until shutdown:
      select:
        connection = listener.accept():
          peer_ip = connection.remote_addr().ip()
          GUARD not inbound_pool.try_reserve_with_ip(peer_ip)
            → reject, continue

          spawn peer task:
            peer = Peer.accept(connection, local_node,
                               auth_timeout)
```

**Calls** [Peer::accept](#) for inbound handshake

```
            if peer acceptance fails:
              emit PeerEvent::Failed(addr, Inbound)
              pool.release()
              return

            peer_id = peer.id()
            GUARD peer_id in banned_peers
              → close peer, pool.release(), return
            GUARD peer_id already in peers map
              → close peer, pool.release(), return

            emit PeerEvent::Connected(addr, Inbound)
```

**Calls** [build_peers_message](#overlaymanagerbuild_peers_message) to send peer list

```
            "Send Peers message directly
             (we still own the peer)"
            peers_msg = build_peers_message(
              advertised_outbound,
              advertised_inbound,
              exclude = this peer's address)
            if peers_msg and peer.is_ready():
              peer.send(peers_msg)

            (outbound_rx, flow_control) =
              register_peer(peer, peer_id, peer_info, shared)
            MUTATE added_authenticated_peers += 1
```

**Calls** [run_peer_loop](#overlaymanagerrun_peer_loop) — blocks until peer disconnects

```
            run_peer_loop(peer_id, peer, outbound_rx,
                          flow_control, shared)

            "Cleanup after peer loop exits"
            MUTATE remove peer_id from peers
            MUTATE remove peer_id from peer_info_cache
            MUTATE dropped_authenticated_peers += 1
            pool.release()

        shutdown_rx.recv():
          break
```

### OverlayManager::start_connector

"Initiates outbound connections to maintain target peer count"

```
function start_connector():
  spawn background task:
    retry_after = {}         // addr → next retry time
    tick every 5 seconds

    loop until shutdown:
      GUARD not running → break

      outbound_count = count_outbound_peers()
      available = max_outbound - outbound_count
      GUARD available == 0 → continue

      remaining = available

      "Phase 1: preferred peers first"
      for each addr in preferred_peers:
        GUARD remaining == 0 → break
        GUARD retry_after[addr] > now → continue
        GUARD already connected to addr → continue

        if not pool.try_reserve():
```

**Calls** [maybe_evict_for_preferred](#overlaymanagermaybe_evict_for_preferred)

```
          "Preferred peer eviction: evict youngest
           non-preferred outbound peer to make room
           (matches stellar-core behavior)"
          evicted = maybe_evict_for_preferred(
            peers, peer_info_cache, preferred_addrs)
          if evicted:
            sleep 100ms  // let evicted peer clean up
          GUARD not pool.try_reserve() → break

        timeout = max(connect_timeout, auth_timeout)
```

**Calls** [connect_outbound_inner](#overlaymanagerconnect_outbound_inner)

```
        result = connect_outbound_inner(
          addr, local_node, timeout, pool, shared)
        if success:
          remove addr from retry_after
          remaining -= 1
        else:
          retry_after[addr] = now + 10s

      "Phase 2: fill remaining with known peers"
      outbound_count = count_outbound_peers()
      GUARD remaining == 0
        or outbound_count >= target_outbound
        → continue

      shuffle known_peers randomly

      for each addr in known_peers:
        GUARD remaining == 0 → break
        GUARD count_outbound_peers() >= target_outbound
          → break
        GUARD retry_after[addr] > now → continue
        GUARD already connected to addr → continue
        GUARD not pool.try_reserve() → break

        result = connect_outbound_inner(
          addr, local_node, timeout, pool, shared)
        if success:
          remove addr from retry_after
          remaining -= 1
        else:
          retry_after[addr] = now + 10s
```

### OverlayManager::run_peer_loop

"The peer is owned by this task (no mutex). Outbound messages arrive
via outbound_rx. The select multiplexes between network recv, outbound
channel, and periodic timers without blocking."

```
function run_peer_loop(peer_id, peer, outbound_rx,
                       flow_control, state):
```

**Calls** [Peer::send_more_extended](#) for initial flow control grant

```
  "Send initial SendMoreExtended to grant the peer
   our full reading capacity.
   Matches stellar-core's Peer::recvAuth() → sendSendMore()."
  initial_flood_msgs = peer_flood_reading_capacity
  initial_flood_bytes = peer_flood_reading_capacity
                        × flow_control_bytes_batch_size
  peer.send_more_extended(initial_flood_msgs,
                          initial_flood_bytes)

  last_read = now()
  last_write = now()
  total_messages = 0
  scp_messages = 0
  ticks_since_ping = 0
  periodic_interval = every 1 second

  loop:
    GUARD not running → break

    select:
      "Branch 1: outbound messages"
      msg = outbound_rx.recv():
        if msg is Send(m):
          peer.send(m)
          last_write = now()

        if msg is Flood(m):
          flow_control.add_msg_and_maybe_trim_queue(m)
```

**Calls** [send_flow_controlled_batch](#overlaymanagersend_flow_controlled_batch)

```
          sent = send_flow_controlled_batch(peer, flow_control)
          if sent: last_write = now()

        if msg is Shutdown:
          break

        if channel closed:
          break

      "Branch 2: receive from network"
      result = peer.recv():
        if connection closed or error:
          break

        message = result
        last_read = now()
        total_messages += 1

        "Flow control: begin tracking"
        flow_control.begin_message_processing(message)

        "Handle flow control messages"
        if message is SendMoreExtended:
          flow_control.maybe_release_capacity(message)
          send_flow_controlled_batch(peer, flow_control)
          if sent: last_write = now()

        "Route message"
        route_block:
          GUARD is_handshake_message → skip routing
          GUARD is SendMore/SendMoreExtended → skip routing

          "Watcher filter: drop non-essential flood
           messages for non-validator nodes"
          GUARD not is_validator
            and is_watcher_droppable(message) → skip

          "SCP messages are consensus-critical and
           must never be rate-limited"
          GUARD not ScpMessage
            and not flood_gate.allow_message()
            → skip (rate limited)

          if is_flood_message(message):
            hash = compute_message_hash(message)
            lcl = last_closed_ledger
            unique = flood_gate.record_seen(
              hash, peer_id, lcl)
            peer.record_flood_stats(unique, msg_size)
            GUARD not unique → skip (duplicate)

          else if is_fetch_message(message):
            peer.record_fetch_stats(true, msg_size)

          "Forward to subscribers"
          overlay_msg = OverlayMessage(
            peer_id, message, now())

          is_dedicated = message is one of:
            ScpMessage, GeneralizedTxSet, TxSet,
            DontHave, ScpQuorumset

          if message is ScpMessage:
            scp_messages += 1
            scp_message_tx.send(overlay_msg)

          if message is GeneralizedTxSet, TxSet,
             DontHave, or ScpQuorumset:
            fetch_response_tx.try_send(overlay_msg)

          "Send catchup-critical messages to
           extra subscribers"
          if message is ScpMessage, GeneralizedTxSet,
             TxSet, or ScpQuorumset:
            for each sub in extra_subscribers:
              sub.send(overlay_msg)

          if not is_dedicated:
            message_tx.broadcast(overlay_msg)

        "Flow control: end tracking, maybe send
         SendMoreExtended back"
        send_more_cap =
          flow_control.end_message_processing(message)
        if send_more_cap.should_send()
           and peer.is_connected():
          peer.send_more_extended(
            send_more_cap.num_flood_messages,
            send_more_cap.num_flood_bytes)
          last_write = now()

      "Branch 3: periodic timer (every 1s)"
      periodic_interval.tick():
        now = now()

        "Idle/straggler timeout check
         (matches stellar-core Peer::recurrentTimerExpired)"
        if (now - last_read) >= PEER_TIMEOUT
           and (now - last_write) >= PEER_TIMEOUT:
          break  // idle timeout

        if (now - last_write) >= PEER_STRAGGLER_TIMEOUT:
          break  // straggler timeout

        "Ping every 5 seconds"
        ticks_since_ping += 1
        if ticks_since_ping >= PING_INTERVAL_TICKS:
          ticks_since_ping = 0
          if peer.is_connected():
            ping_hash = sha256(now_nanos)
            peer.send(GetScpQuorumset(ping_hash))
            last_write = now()

  "Close peer (owned, no mutex needed)"
  peer.close()
```

### OverlayManager::send_flow_controlled_batch

"Send queued outbound messages that have flow control capacity"

```
function send_flow_controlled_batch(peer, flow_control):
  batch = flow_control.get_next_batch_to_send()
  GUARD batch is empty → false

  sent_by_priority = [] for each priority level

  for each queued in batch:
    if peer.send(queued.message) fails:
      flow_control.process_sent_messages(sent_by_priority)
      → error
    sent_by_priority[queued.priority].append(queued.message)

  flow_control.process_sent_messages(sent_by_priority)
  → true
```

### OverlayManager::connect

```
function connect(addr):
  GUARD not running → error NotStarted
  GUARD not outbound_pool.try_reserve()
    → error PeerLimitReached
  timeout = max(connect_timeout, auth_timeout)
  → connect_outbound_inner(addr, local_node, timeout,
                            outbound_pool, shared_state)
```

### OverlayManager::broadcast

```
function broadcast(message):
  GUARD not running → error NotStarted

  is_flood = is_flood_message(message)

  if is_flood:
    hash = compute_message_hash(message)
    lcl = last_closed_ledger
    flood_gate.record_seen(hash, null, lcl)
    "Only forward to peers that haven't already
     sent us this message"
    forward_peers = flood_gate.get_forward_peers(
      hash, all_peer_ids)

  sent = 0
  for each peer in peers:
    if is_flood and peer not in forward_peers:
      continue  // skip (already has message)

    outbound_msg = if is_flood: Flood(message)
                   else: Send(message)
    try_send outbound_msg to peer.outbound_tx
    if success: sent += 1
    NOTE: drops message if channel full (non-blocking)

  → sent
```

### OverlayManager::disconnect

```
function disconnect(peer_id):
  GUARD peer_id not in peers → false
  send Shutdown to peer's outbound channel
  → true
```

### OverlayManager::ban_peer

```
function ban_peer(peer_id):
  MUTATE banned_peers.insert(peer_id)
  if peer_id in peers:
    send Shutdown to peer's outbound channel
```

### OverlayManager::unban_peer

```
function unban_peer(peer_id):
  → banned_peers.remove(peer_id)
```

### OverlayManager::send_to

```
function send_to(peer_id, message):
  GUARD peer_id not in peers → error PeerNotFound
  send Send(message) to peer's outbound channel
```

### OverlayManager::try_send_to

"Non-blocking send: drops message if channel full"

```
function try_send_to(peer_id, message):
  GUARD peer_id not in peers → error PeerNotFound
  try_send Send(message) to peer's outbound channel
```

### OverlayManager::peer_count

```
function peer_count():
  → len(peer_info_cache)
```

### OverlayManager::connected_peers

```
function connected_peers():
  → list of keys from peer_info_cache
```

### Helper: count_outbound_peers

```
function count_outbound_peers(peer_info_cache):
  → count entries where direction == we_called_remote
```

### Helper: has_outbound_connection_to

```
function has_outbound_connection_to(peer_info_cache, addr):
  for each entry in peer_info_cache:
    GUARD direction != we_called_remote → skip
    "Check by original address first
     (handles hostnames correctly)"
    if entry.original_address matches addr → true
    "Fall back to IP comparison"
    if entry.address.port != addr.port → skip
    if entry.address.ip == parse(addr.host) → true
  → false
```

### OverlayManager::maybe_evict_for_preferred

"Evict the youngest non-preferred outbound peer to make room
for a preferred peer connection. Matches stellar-core's
OverlayManagerImpl::maybeAddInboundConnection eviction logic."

```
function maybe_evict_for_preferred(peers, peer_info_cache,
                                    preferred_addrs):
  youngest = null

  for each entry in peer_info_cache:
    GUARD direction != we_called_remote → skip

    is_preferred = any preferred_addr matches entry
      (by original_address or resolved IP)
    GUARD is_preferred → skip

    "Track the youngest (most recent connected_at)"
    if youngest is null
       or entry.connected_at > youngest.connected_at:
      youngest = (entry.peer_id, entry.connected_at)

  if youngest is not null:
    send Shutdown to youngest peer's outbound channel
    → true
  → false
```

### OverlayManager::connect_outbound_inner

```
function connect_outbound_inner(addr, local_node,
                                 timeout, pool, shared):
```

**Calls** [Peer::connect](#) for outbound handshake

```
  peer = Peer.connect(addr, local_node, timeout)
  if connection fails:
    pool.release()
    emit PeerEvent::Failed(addr, Outbound)
    → error

  peer_id = peer.id()
  GUARD peer_id in banned_peers
    → pool.release(), error PeerBanned
  GUARD peer_id already in peers
    → pool.release(), error AlreadyConnected

  (outbound_rx, flow_control) =
    register_peer(peer, peer_id, peer_info, shared)
  MUTATE added_authenticated_peers += 1
  emit PeerEvent::Connected(addr, Outbound)

  NOTE: "Do NOT send PEERS to outbound peers.
    In stellar-core, only the acceptor (REMOTE_CALLED_US)
    sends PEERS during recvAuth(). If we send PEERS to a
    peer we initiated a connection to, the remote will
    drop us silently (Peer.cpp:1225-1230)."
```

**Calls** [run_peer_loop](#overlaymanagerrun_peer_loop) in spawned task

```
  spawn task:
    run_peer_loop(peer_id, peer, outbound_rx,
                  flow_control, shared)
    "Cleanup"
    MUTATE remove peer_id from peers
    MUTATE remove peer_id from peer_info_cache
    MUTATE dropped_authenticated_peers += 1
    pool.release()

  → peer_id
```

### OverlayManager::start_peer_advertiser

```
function start_peer_advertiser():
  spawn background task:
    tick every 30 seconds

    loop until shutdown:
      GUARD not running → break

      message = build_peers_message(
        advertised_outbound, advertised_inbound,
        exclude = null)
      GUARD message is null → continue

      "Only send PEERS to inbound peers
       (peers that connected to us).
       stellar-core drops connections from initiators
       that send PEERS (Peer.cpp:1225-1230)."
      for each entry in peer_info_cache:
        if direction == Inbound:
          try_send Send(message) to peer's channel
```

### Helper: build_peers_message

```
function build_peers_message(outbound, inbound, exclude):
  CONST MAX_PEERS_PER_MESSAGE = 50
  shuffle outbound randomly
  shuffle inbound randomly
  peers = []
  unique = set()

  for each addr in outbound then inbound:
    GUARD len(peers) >= MAX_PEERS_PER_MESSAGE → break
    GUARD not is_public_peer(addr) → skip
    GUARD addr == exclude → skip
    GUARD addr.socket_addr already in unique → skip
    unique.insert(addr.socket_addr)
    peers.append(peer_address_to_xdr(addr))

  GUARD peers is empty → null
  → StellarMessage::Peers(peers)
```

### Helper: peer_address_to_xdr

```
function peer_address_to_xdr(addr):
  ip = parse addr.host as IP
  GUARD parse fails → null
  → XdrPeerAddress(ip, addr.port, num_failures=0)
```

### Helper: is_public_peer

```
function is_public_peer(addr):
  GUARD addr.port == 0 → false
  if addr.host is not parseable as IP:
    → true  // hostname, assume public
  if IPv4:
    → not (private or loopback or link_local
           or multicast or unspecified)
  if IPv6:
    → not (loopback or multicast or unspecified
           or unicast_link_local or unique_local)
```

---

### OverlayManager::peer_infos

```
function peer_infos():
  → list of values from peer_info_cache
```

### OverlayManager::peer_snapshots

```
function peer_snapshots():
  for each (peer_id, info) in peer_info_cache:
    stats = peers[peer_id].stats.snapshot() or default
    → PeerSnapshot(info, stats)
```

### OverlayManager::subscribe

```
function subscribe():
  → message_tx.subscribe()
```

### OverlayManager::subscribe_scp

"Can only be called once (takes ownership of the receiver)"

```
function subscribe_scp():
  → take scp_message_rx (returns null on second call)
```

### OverlayManager::subscribe_fetch_responses

"Can only be called once (takes ownership of the receiver)"

```
function subscribe_fetch_responses():
  → take fetch_response_rx (returns null on second call)
```

### OverlayManager::subscribe_catchup

```
function subscribe_catchup():
  (tx, rx) = new unbounded channel
  clean up closed subscribers from extra_subscribers
  extra_subscribers.push(tx)
  → rx
```

### OverlayManager::clear_ledgers_below

"Mirrors upstream OverlayManagerImpl::clearLedgersBelow()"

```
function clear_ledgers_below(ledger_seq, _lcl_seq):
  MUTATE last_closed_ledger = ledger_seq
  flood_gate.clear_below(ledger_seq)
```

**Calls** [FloodGate::clear_below](../flood.rs) for old flood record cleanup

### OverlayManager::handle_max_tx_size_increase

"Mirrors upstream Peer::handleMaxTxSizeIncrease()"

```
function handle_max_tx_size_increase(increase):
  GUARD increase == 0 → return

  send_more = SendMoreExtended(
    num_messages = 0, num_bytes = increase)

  for each peer in peers:
    peer.flow_control.handle_tx_size_increase(increase)
    try_send Send(send_more) to peer's channel
```

### OverlayManager::stats

```
function stats():
  → OverlayStats:
    connected_peers = peer_count()
    inbound_peers = inbound_pool.count()
    outbound_peers = outbound_pool.count()
    flood_stats = flood_gate.stats()
```

### OverlayManager::request_scp_state

```
function request_scp_state(ledger_seq):
  → broadcast(GetScpState(ledger_seq))
```

### OverlayManager::request_tx_set

```
function request_tx_set(hash):
  → broadcast(GetTxSet(hash))
```

### OverlayManager::send_get_tx_set

```
function send_get_tx_set(peer_id, hash):
  → send_to(peer_id, GetTxSet(hash))
```

### OverlayManager::send_get_quorum_set

```
function send_get_quorum_set(peer_id, hash):
  → send_to(peer_id, GetScpQuorumset(hash))
```

### OverlayManager::add_peer

```
function add_peer(addr):
  GUARD not running → error NotStarted
  GUARD not outbound_pool.try_reserve()
    → false (limit reached)
  GUARD already connected to addr
    → pool.release(), false

  spawn task:
    peer = Peer.connect(addr, local_node, timeout)
    if connection fails:
      emit PeerEvent::Failed, pool.release()
      return

    peer_id = peer.id()
    emit PeerEvent::Connected(addr, Outbound)
    register_peer(peer, peer_id, peer_info, shared)
    NOTE: "Do NOT send PEERS to outbound peers —
      see Peer.cpp:1225-1230."
    run_peer_loop(peer_id, peer, outbound_rx,
                  flow_control, shared)
    "Cleanup"
    remove peer_id from peers/cache
    pool.release()

  → true
```

### OverlayManager::add_peers

```
function add_peers(addrs):
  added = 0
  remaining = target_outbound - outbound_pool.count()

  for each addr in addrs:
    GUARD remaining == 0 or not pool.can_accept() → break
    add_known_peer(addr)
    if add_peer(addr) succeeds:
      added += 1
      remaining -= 1
    sleep 50ms between attempts

  → added
```

### Helper: add_known_peer

```
function add_known_peer(addr):
  GUARD addr already in known_peers → false
  MUTATE known_peers.push(addr)
  → true
```

### OverlayManager::shutdown

```
function shutdown():
  GUARD not running → return (no-op)
  MUTATE running = false

  send shutdown signal to all background tasks
  send Shutdown to every peer via outbound channels
  clear peers map

  "Wait for tasks to complete"
  wait for listener_handle
  wait for connector_handle
  wait for peer_advertiser_handle
  wait for all peer_handles
```

### OverlayManager::drop

```
function drop():
  MUTATE running = false
  send shutdown signal
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~1530  | ~480       |
| Functions     | 42     | 42         |
