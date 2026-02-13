# stellar-core Parity Status

**Crate**: `henyey-overlay`
**Upstream**: `.upstream-v25/src/overlay/`
**Overall Parity**: 82%
**Last Updated**: 2026-02-13

## Summary

| Area | Status | Notes |
|------|--------|-------|
| Authentication (PeerAuth, Hmac) | Full | HKDF key derivation, HMAC-SHA256 MAC |
| Peer Connection (Peer, TCPPeer) | Partial | Missing ping/pong, IO timeout, recurrent timer |
| OverlayManager | Partial | Missing tick, purgeDeadPeers, DNS resolution |
| Floodgate | Full | Message deduplication and forwarding |
| FlowControl | Full | Capacity tracking, throttling, priority queues |
| ItemFetcher / Tracker | Full | Fetch lifecycle, retry, envelope tracking |
| BanManager | Full | In-memory + SQLite persistence |
| PeerManager | Full | SQLite persistence, backoff, type tracking |
| TxAdverts | Full | Queuing, batching, history cache |
| TxDemandsManager | Full | Demand scheduling, pull latency |
| SurveyManager | Partial | Missing encryption, signature validation |
| OverlayMetrics | Full | Counters and timers for all message types |
| PeerBareAddress | Full | Mapped to PeerAddress in lib.rs |
| MessageCodec (framing) | Full | Length-prefix with auth bit |

## File Mapping

| stellar-core File | Rust Module | Notes |
|--------------------|-------------|-------|
| `BanManager.h` / `BanManagerImpl.h` / `BanManagerImpl.cpp` | `ban_manager.rs` | Full match |
| `Floodgate.h` / `Floodgate.cpp` | `flood.rs` | SHA-256 instead of BLAKE2 |
| `FlowControl.h` / `FlowControl.cpp` | `flow_control.rs` | Includes capacity classes |
| `FlowControlCapacity.h` / `FlowControlCapacity.cpp` | `flow_control.rs` | Merged into one module |
| `Hmac.h` / `Hmac.cpp` | `auth.rs` | Integrated into AuthContext |
| `ItemFetcher.h` / `ItemFetcher.cpp` | `item_fetcher.rs` | Full match |
| `OverlayManager.h` / `OverlayManagerImpl.h` / `OverlayManagerImpl.cpp` | `manager.rs` | Core logic present |
| `OverlayMetrics.h` / `OverlayMetrics.cpp` | `metrics.rs` | Custom atomics vs medida |
| `OverlayUtils.h` / `OverlayUtils.cpp` | (inline in error.rs) | logErrorOrThrow equivalent |
| `Peer.h` / `Peer.cpp` | `peer.rs`, `connection.rs` | Partial; many message handlers in manager |
| `PeerAuth.h` / `PeerAuth.cpp` | `auth.rs` | Full match |
| `PeerBareAddress.h` / `PeerBareAddress.cpp` | `lib.rs` (PeerAddress) | Full match |
| `PeerDoor.h` / `PeerDoor.cpp` | `connection.rs` (Listener) | Full match |
| `PeerManager.h` / `PeerManager.cpp` | `peer_manager.rs` | Full match |
| `RandomPeerSource.h` / `RandomPeerSource.cpp` | `peer_manager.rs` | Merged into PeerManager |
| `SurveyManager.h` / `SurveyManager.cpp` | `survey.rs` | Missing encryption/signatures |
| `SurveyDataManager.h` / `SurveyDataManager.cpp` | `survey.rs` | Merged into SurveyManager |
| `SurveyMessageLimiter.h` / `SurveyMessageLimiter.cpp` | `survey.rs` | Simplified implementation |
| `TCPPeer.h` / `TCPPeer.cpp` | `peer.rs`, `connection.rs`, `codec.rs` | Split across modules |
| `Tracker.h` / `Tracker.cpp` | `item_fetcher.rs` | Merged into ItemFetcher |
| `TxAdverts.h` / `TxAdverts.cpp` | `tx_adverts.rs` | Full match |
| `TxDemandsManager.h` / `TxDemandsManager.cpp` | `tx_demands.rs` | Full match |

## Component Mapping

### BanManager (`ban_manager.rs`)

Corresponds to: `BanManager.h`, `BanManagerImpl.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `BanManager::create()` | `BanManager::new_in_memory()` / `new_with_db()` | Full |
| `BanManager::dropAll()` | `BanManager::drop_and_create()` | Full |
| `banNode()` | `ban_node()` | Full |
| `unbanNode()` | `unban_node()` | Full |
| `isBanned()` | `is_banned()` | Full |
| `getBans()` | `get_bans()` | Full |

### Floodgate (`flood.rs`)

Corresponds to: `Floodgate.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `Floodgate()` | `FloodGate::new()` / `with_ttl()` | Full |
| `clearBelow()` | `cleanup()` | Full |
| `addRecord()` | `record_seen()` | Full |
| `broadcast()` | `get_forward_peers()` + external send | Full |
| `getPeersKnows()` | `get_forward_peers()` | Full |
| `forgetRecord()` | TTL-based cleanup | Full |
| `shutdown()` | `clear()` | Full |

### FlowControl (`flow_control.rs`)

Corresponds to: `FlowControl.h`, `FlowControlCapacity.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `FlowControl()` | `FlowControl::new()` | Full |
| `maybeReleaseCapacity()` | `maybe_release_capacity()` | Full |
| `handleTxSizeIncrease()` | `handle_tx_size_increase()` | Full |
| `addMsgAndMaybeTrimQueue()` | `add_msg_and_maybe_trim_queue()` | Full |
| `getNextBatchToSend()` | `get_next_batch_to_send()` | Full |
| `updateMsgMetrics()` | (inline in get_next_batch_to_send) | Full |
| `getNumMessages()` | (inline) | Full |
| `getMessagePriority()` | `MessagePriority::from_message()` | Full |
| `isSendMoreValid()` | `is_send_more_valid()` | Full |
| `beginMessageProcessing()` | `begin_message_processing()` | Full |
| `endMessageProcessing()` | `end_message_processing()` | Full |
| `canRead()` | `can_read()` | Full |
| `noOutboundCapacityTimeout()` | `no_outbound_capacity_timeout()` | Full |
| `getFlowControlJsonInfo()` | `get_stats()` | Full |
| `setPeerID()` | `set_peer_id()` | Full |
| `maybeThrottleRead()` | `maybe_throttle_read()` | Full |
| `stopThrottling()` | `stop_throttling()` | Full |
| `isThrottled()` | `is_throttled()` | Full |
| `processSentMessages()` | `process_sent_messages()` | Full |
| `FlowControlCapacity::getMsgResourceCount()` | (inline) | Full |
| `FlowControlCapacity::getCapacityLimits()` | (in config) | Full |
| `FlowControlCapacity::lockOutboundCapacity()` | (in get_next_batch_to_send) | Full |
| `FlowControlCapacity::lockLocalCapacity()` | (in begin_message_processing) | Full |
| `FlowControlCapacity::releaseLocalCapacity()` | (in end_message_processing) | Full |
| `FlowControlCapacity::hasOutboundCapacity()` | (inline) | Full |
| `FlowControlCapacity::msgBodySize()` | `msg_body_size()` | Full |

### ItemFetcher / Tracker (`item_fetcher.rs`)

Corresponds to: `ItemFetcher.h`, `Tracker.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `ItemFetcher()` | `ItemFetcher::new()` | Full |
| `fetch()` | `fetch()` | Full |
| `stopFetch()` | `stop_fetch()` | Full |
| `getLastSeenSlotIndex()` | `get_last_seen_slot_index()` | Full |
| `fetchingFor()` | `fetching_for()` | Full |
| `stopFetchingBelow()` | `stop_fetching_below()` | Full |
| `doesntHave()` | `doesnt_have()` | Full |
| `recv()` | `recv()` | Full |
| `Tracker()` | `Tracker::new()` | Full |
| `Tracker::empty()` | `is_empty()` | Full |
| `Tracker::waitingEnvelopes()` | `waiting_envelopes()` | Full |
| `Tracker::size()` | `len()` | Full |
| `Tracker::pop()` | `pop()` | Full |
| `Tracker::getDuration()` | `get_duration()` | Full |
| `Tracker::clearEnvelopesBelow()` | `clear_envelopes_below()` | Full |
| `Tracker::listen()` | `listen()` | Full |
| `Tracker::discard()` | `discard()` | Full |
| `Tracker::cancel()` | `cancel()` | Full |
| `Tracker::doesntHave()` | `doesnt_have()` | Full |
| `Tracker::tryNextPeer()` | `try_next_peer()` | Full |
| `Tracker::getLastSeenSlotIndex()` | `last_seen_slot_index()` | Full |
| `Tracker::resetLastSeenSlotIndex()` | `reset_last_seen_slot_index()` | Full |

### Peer (`peer.rs`, `connection.rs`)

Corresponds to: `Peer.h`, `TCPPeer.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `Peer()` constructor | `Peer::connect()` / `Peer::accept()` | Full |
| `initialize()` | (in connect/accept) | Full |
| `sendHello()` | (in handshake flow) | Full |
| `sendAuth()` | (in handshake flow) | Full |
| `recvHello()` | (in handshake flow via AuthContext) | Full |
| `recvAuth()` | (in handshake flow) | Full |
| `sendMessage()` | `send()` | Full |
| `recvMessage()` / `recvRawMessage()` | `recv()` | Full |
| `recvError()` | (in manager message dispatch) | Full |
| `recvPeers()` | (in manager message dispatch) | Full |
| `recvDontHave()` | (in MessageDispatcher) | Full |
| `recvSendMore()` | (in manager message dispatch) | Full |
| `recvGetTxSet()` | (in manager message dispatch) | Full |
| `recvTxSet()` / `recvGeneralizedTxSet()` | (in MessageDispatcher) | Full |
| `recvTransaction()` | (in manager via broadcast) | Full |
| `recvGetSCPQuorumSet()` | (in manager message dispatch) | Full |
| `recvSCPQuorumSet()` | (in MessageDispatcher) | Full |
| `recvSCPMessage()` | (in manager via broadcast) | Full |
| `recvGetSCPState()` | (in manager via broadcast) | Full |
| `recvFloodAdvert()` | (in manager via TxAdverts) | Full |
| `recvFloodDemand()` | (in manager via TxDemands) | Full |
| `recvSurveyRequestMessage()` | (in manager via SurveyManager) | Full |
| `recvSurveyResponseMessage()` | (in manager via SurveyManager) | Full |
| `recvSurveyStartCollectingMessage()` | (in manager) | Full |
| `recvSurveyStopCollectingMessage()` | (in manager) | Full |
| `sendGetTxSet()` | `PeerSender::send()` | Full |
| `sendGetQuorumSet()` | `PeerSender::send()` | Full |
| `sendGetScpState()` | `PeerSender::send()` | Full |
| `sendErrorAndDrop()` | (in manager error handling) | Full |
| `sendTxDemand()` | (via TxDemandsManager) | Full |
| `sendAdvert()` | (via TxAdverts) | Full |
| `sendSendMore()` | `send_more()` / `send_more_extended()` | Full |
| `sendDontHave()` | (in manager message dispatch) | Full |
| `sendPeers()` | (in manager advertiser) | Full |
| `sendSCPQuorumSet()` | (in manager message dispatch) | Full |
| `sendError()` | (in manager) | Full |
| `drop()` | `close()` | Full |
| `getRole()` | `direction()` | Full |
| `getLifeTime()` | (via PeerStats.connected_at) | Full |
| `getPing()` | N/A | None |
| `getRemoteVersion()` | `info().remote_version` | Full |
| `getRemoteOverlayVersion()` | `info().overlay_version` | Full |
| `getAddress()` | `remote_addr()` | Full |
| `getPeerID()` | `id()` | Full |
| `toString()` | `Display` impl | Full |
| `getJsonInfo()` | N/A | None |
| `handleMaxTxSizeIncrease()` | N/A | None |
| `pingPeer()` | N/A | None |
| `maybeProcessPingResponse()` | N/A | None |
| `startRecurrentTimer()` | N/A | None |
| `recurrentTimerExpired()` | N/A | None |
| `getIOTimeout()` | N/A | None |
| `beginMessageProcessing()` | `FlowControl::begin_message_processing()` | Full |
| `endMessageProcessing()` | `FlowControl::end_message_processing()` | Full |
| `process()` (query throttle) | N/A | None |
| `canRead()` | `FlowControl::can_read()` | Full |
| `retryAdvert()` | `TxAdverts::retry_incoming_advert()` | Full |
| `hasAdvert()` | `TxAdverts::has_adverts()` | Full |
| `popAdvert()` | `TxAdverts::pop_incoming_advert()` | Full |
| `clearBelow()` | `TxAdverts::clear_below()` | Full |
| `isConnected()` | `is_connected()` | Full |
| `isAuthenticated()` | `is_ready()` | Full |
| `PeerMetrics` struct | `PeerStats` struct | Full |
| `TimestampedMessage` | (implicit in codec/connection) | Full |
| `CapacityTrackedMessage` | N/A | None |
| `TCPPeer::initiate()` | `Peer::connect()` | Full |
| `TCPPeer::accept()` | `Peer::accept()` | Full |
| `TCPPeer::drop()` | `Peer::close()` | Full |
| `TCPPeer::sendMessage()` | `Connection::send()` | Full |
| `TCPPeer::recvMessage()` | `Connection::recv()` | Full |
| `TCPPeer::connected()` | (implicit in connect) | Full |
| `TCPPeer::scheduleRead()` | (implicit in tokio) | Full |
| `TCPPeer::messageSender()` | (implicit in async write) | Full |
| `TCPPeer::writeHandler()` | (implicit in tokio) | Full |
| `TCPPeer::readHeaderHandler()` | (in MessageCodec decoder) | Full |
| `TCPPeer::readBodyHandler()` | (in MessageCodec decoder) | Full |
| `TCPPeer::shutdown()` | `close()` | Full |

### PeerAuth / AuthContext (`auth.rs`)

Corresponds to: `PeerAuth.h`, `Hmac.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `PeerAuth()` | `AuthContext::new()` | Full |
| `getAuthCert()` | `AuthCert::new()` | Full |
| `verifyRemoteAuthCert()` | `AuthCert::verify()` | Full |
| `getSendingMacKey()` | `derive_mac_keys()` (send half) | Full |
| `getReceivingMacKey()` | `derive_mac_keys()` (recv half) | Full |
| `getSharedKey()` | (inline in derive_mac_keys) | Full |
| `Hmac::setSendMackey()` | (set in process_hello) | Full |
| `Hmac::setRecvMackey()` | (set in process_hello) | Full |
| `Hmac::checkAuthenticatedMessage()` | `unwrap_message()` | Full |
| `Hmac::setAuthenticatedMessageBody()` | `wrap_message()` | Full |

### PeerBareAddress (`lib.rs`)

Corresponds to: `PeerBareAddress.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `PeerBareAddress()` | `PeerAddress::new()` | Full |
| `resolve()` | (DNS resolution in connect flow) | Full |
| `isEmpty()` | N/A (Rust type always valid) | Full |
| `getIP()` | `.host` field | Full |
| `getPort()` | `.port` field | Full |
| `toString()` | `Display::fmt()` | Full |
| `isPrivate()` | `is_private()` | Full |
| `isLocalhost()` | (covered by is_private) | Full |
| `operator==` / `operator<` | `PartialEq` / `Eq` / `Hash` derives | Full |

### PeerDoor (`connection.rs`)

Corresponds to: `PeerDoor.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `PeerDoor()` | `Listener::bind()` | Full |
| `start()` | (bind returns listening socket) | Full |
| `close()` | (drop Listener) | Full |
| `acceptNextPeer()` | `Listener::accept()` | Full |
| `handleKnock()` | (in manager accept flow) | Full |

### PeerManager (`peer_manager.rs`)

Corresponds to: `PeerManager.h`, `RandomPeerSource.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `PeerManager()` | `PeerManager::new_in_memory()` / `new_with_db()` | Full |
| `dropAll()` | `clear_all()` | Full |
| `ensureExists()` | `ensure_exists()` | Full |
| `update()` (type) | `update_type()` | Full |
| `update()` (backoff) | `update_backoff()` | Full |
| `update()` (both) | `update()` | Full |
| `load()` | `load()` | Full |
| `store()` | `store()` | Full |
| `loadRandomPeers()` | `load_random_peers()` | Full |
| `removePeersWithManyFailures()` | `remove_peers_with_many_failures()` | Full |
| `getPeersToSend()` | `get_peers_to_send()` | Full |
| `loadAllPeers()` | `get_all_peers()` | Full |
| `storePeers()` | (via store) | Full |
| `RandomPeerSource::maxFailures()` | (inline in query construction) | Full |
| `RandomPeerSource::nextAttemptCutoff()` | (inline in query construction) | Full |
| `RandomPeerSource::getRandomPeers()` | `load_random_peers()` | Full |

### OverlayManager (`manager.rs`)

Corresponds to: `OverlayManager.h`, `OverlayManagerImpl.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `OverlayManagerImpl()` | `OverlayManager::new()` | Full |
| `start()` | `start()` | Full |
| `shutdown()` | `shutdown()` | Full |
| `isShuttingDown()` | `is_running()` (inverted) | Full |
| `clearLedgersBelow()` | N/A | None |
| `broadcastMessage()` | (via broadcast channel + flood gate) | Full |
| `recvFloodedMsgID()` | `FloodGate::record_seen()` | Full |
| `recvTransaction()` | (via broadcast channel) | Partial |
| `forgetFloodedMsg()` | (TTL-based cleanup) | Full |
| `recvTxDemand()` | `TxDemandsManager::recv_demand()` | Full |
| `getRandomAuthenticatedPeers()` | (shuffled peer list) | Full |
| `getRandomInboundAuthenticatedPeers()` | N/A | None |
| `getRandomOutboundAuthenticatedPeers()` | N/A | None |
| `getConnectedPeer()` | (via DashMap lookup) | Full |
| `maybeAddInboundConnection()` | (in listener accept flow) | Full |
| `addOutboundConnection()` | (in connector flow) | Full |
| `removePeer()` | (via peer drop) | Full |
| `acceptAuthenticatedPeer()` | (in handshake completion) | Full |
| `isPreferred()` | (via preferred_peers config) | Full |
| `isPossiblyPreferred()` | N/A | None |
| `haveSpaceForConnection()` | `ConnectionPool::can_accept()` | Full |
| `getInboundPendingPeers()` | N/A | None |
| `getOutboundPendingPeers()` | N/A | None |
| `getPendingPeers()` | N/A | None |
| `getLiveInboundPeersCounter()` | (via ConnectionPool.count) | Full |
| `getPendingPeersCount()` | N/A | None |
| `getInboundAuthenticatedPeers()` | N/A | None |
| `getOutboundAuthenticatedPeers()` | N/A | None |
| `getAuthenticatedPeers()` | `authenticated_peers()` | Full |
| `getAuthenticatedPeersCount()` | `peer_count()` | Full |
| `connectTo()` | (in connector flow) | Full |
| `getPeersKnows()` | `FloodGate::get_forward_peers()` | Full |
| `getOverlayMetrics()` | (via OverlayMetrics) | Full |
| `getPeerAuth()` | (via AuthContext per peer) | Full |
| `getPeerManager()` | N/A (not exposed directly) | Partial |
| `getSurveyManager()` | N/A (not exposed directly) | Partial |
| `recordMessageMetric()` | (via OverlayMetrics) | Full |
| `getFlowControlBytesTotal()` | N/A | None |
| `checkScheduledAndCache()` | (via FloodGate.has_seen) | Full |
| `getOverlayThreadSnapshot()` | N/A | None |
| `tick()` | N/A | None |
| `updateTimerAndMaybeDropRandomPeer()` | N/A | None |
| `storeConfigPeers()` | N/A | None |
| `purgeDeadPeers()` | N/A | None |
| `triggerPeerResolution()` | N/A | None |
| `resolvePeers()` | (DNS resolution inline) | Partial |
| `storePeerList()` | N/A | None |
| `connectToImpl()` | (in connector flow) | Full |
| `moveToAuthenticated()` | (in handshake completion) | Full |
| `nonPreferredAuthenticatedCount()` | N/A | None |
| `updateSizeCounters()` | N/A | None |
| `shufflePeerList()` | (via rand::shuffle) | Full |
| `canAcceptOutboundPeer()` | (via ConnectionPool) | Full |
| `isFloodMessage()` | `helpers::is_flood_message()` | Full |
| `createTxBatch()` | N/A | None |
| `getFlowControlBytesBatch()` | N/A | None |

### OverlayMetrics (`metrics.rs`)

Corresponds to: `OverlayMetrics.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `OverlayMetrics()` | `OverlayMetrics::new()` | Full |
| All meter/timer/counter fields | Matching Counter/Timer fields | Full |

### TxAdverts (`tx_adverts.rs`)

Corresponds to: `TxAdverts.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `TxAdverts()` | `TxAdverts::new()` | Full |
| `size()` | `size()` | Full |
| `popIncomingAdvert()` | `pop_incoming_advert()` | Full |
| `queueOutgoingAdvert()` | `queue_outgoing_advert()` | Full |
| `queueIncomingAdvert()` | `queue_incoming_advert()` | Full |
| `retryIncomingAdvert()` | `retry_incoming_advert()` | Full |
| `getMaxAdvertSize()` | (via config) | Full |
| `seenAdvert()` | `seen_advert()` | Full |
| `clearBelow()` | `clear_below()` | Full |
| `start()` | `set_send_callback()` | Full |
| `shutdown()` | `shutdown()` | Full |
| `getOpsFloodLedger()` | N/A | None |

### TxDemandsManager (`tx_demands.rs`)

Corresponds to: `TxDemandsManager.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `TxDemandsManager()` | `TxDemandsManager::new()` | Full |
| `recordTxPullLatency()` | `record_tx_received()` | Full |
| `recvTxDemand()` | `recv_demand()` | Full |
| `start()` | `start()` | Full |
| `shutdown()` | `shutdown()` | Full |
| `startDemandTimer()` | (timer-based via caller) | Full |
| `demand()` | `process_adverts()` | Full |
| `getMaxDemandSize()` | (via config) | Full |
| `demandStatus()` | `demand_status()` | Full |
| `retryDelayDemand()` | `retry_delay()` | Full |

### SurveyManager (`survey.rs`)

Corresponds to: `SurveyManager.h`, `SurveyDataManager.h`, `SurveyMessageLimiter.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `SurveyManager()` | `SurveyManager::new()` | Full |
| `startSurveyReporting()` | `start_collecting()` | Full |
| `stopSurveyReporting()` | `stop_collecting()` | Full |
| `addNodeToRunningSurveyBacklog()` | `add_peer_to_backlog()` | Full |
| `relayOrProcessResponse()` | N/A | None |
| `relayOrProcessRequest()` | N/A | None |
| `clearOldLedgers()` | `clear_old_ledgers()` | Full |
| `getJsonResults()` | `get_node_data()` / peer data getters | Partial |
| `broadcastStartSurveyCollecting()` | N/A | None |
| `relayStartSurveyCollecting()` | N/A | None |
| `broadcastStopSurveyCollecting()` | N/A | None |
| `relayStopSurveyCollecting()` | N/A | None |
| `modifyNodeData()` | `modify_node_data()` | Full |
| `modifyPeerData()` | `modify_peer_data()` | Full |
| `recordDroppedPeer()` | `record_dropped_peer()` | Full |
| `updateSurveyPhase()` | `update_phase()` | Full |
| `sendTopologyRequest()` | N/A | None |
| `processTimeSlicedTopologyResponse()` | N/A | None |
| `processTimeSlicedTopologyRequest()` | N/A | None |
| `populateSurveyResponseMessage()` | N/A | None |
| `populateSurveyRequestMessage()` | N/A | None |
| `dropPeerIfSigInvalid()` | N/A | None |
| `surveyorPermitted()` | `surveyor_permitted()` | Full |
| `SurveyDataManager::startSurveyCollecting()` | `start_collecting()` | Full |
| `SurveyDataManager::stopSurveyCollecting()` | `stop_collecting()` | Full |
| `SurveyDataManager::modifyNodeData()` | `modify_node_data()` | Full |
| `SurveyDataManager::modifyPeerData()` | `modify_peer_data()` | Full |
| `SurveyDataManager::recordDroppedPeer()` | `record_dropped_peer()` | Full |
| `SurveyDataManager::getNonce()` | `nonce()` | Full |
| `SurveyDataManager::nonceIsReporting()` | (via phase check) | Full |
| `SurveyDataManager::fillSurveyData()` | N/A | None |
| `SurveyDataManager::getFinalNodeData()` | `get_node_data()` | Full |
| `SurveyDataManager::getFinalInboundPeerData()` | `get_inbound_peer_data()` | Full |
| `SurveyDataManager::getFinalOutboundPeerData()` | `get_outbound_peer_data()` | Full |
| `SurveyDataManager::surveyIsActive()` | `is_active()` | Full |
| `SurveyDataManager::updateSurveyPhase()` | `update_phase()` | Full |
| `SurveyMessageLimiter::addAndValidateRequest()` | `add_request()` | Partial |
| `SurveyMessageLimiter::recordAndValidateResponse()` | `record_response()` | Partial |
| `SurveyMessageLimiter::clearOldLedgers()` | `clear_old_ledgers()` | Full |
| `SurveyMessageLimiter::validateStartSurveyCollecting()` | N/A | None |
| `SurveyMessageLimiter::validateStopSurveyCollecting()` | N/A | None |

### MessageCodec (`codec.rs`)

Corresponds to: XDR framing in `TCPPeer.cpp`

| stellar-core | Rust | Status |
|--------------|------|--------|
| RM framing (4-byte header) | `MessageCodec` (Decoder+Encoder) | Full |
| Auth bit handling (bit 31) | `is_authenticated` field | Full |
| `MAX_UNAUTH_MESSAGE_SIZE` | `MIN_MESSAGE_SIZE` / `MAX_MESSAGE_SIZE` | Full |

### PeerSharedKeyId (`N/A`)

Corresponds to: `PeerSharedKeyId.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `PeerSharedKeyId` struct | N/A (different cache approach) | N/A |

## Intentional Omissions

Features excluded by design. These are NOT counted against parity %.

| stellar-core Component | Reason |
|------------------------|--------|
| `LoopbackPeer` (test/LoopbackPeer.h) | Test-only construct for in-process simulation |
| `OverlayTestUtils` (test/OverlayTestUtils.h) | Test utilities, not production code |
| `PeerSharedKeyId` | Different caching approach in Rust; key cache not needed |
| `StellarXDR.h` | Convenience header; handled by stellar-xdr crate |
| `VirtualClock` / `VirtualTimer` integration | Tokio provides async timers natively |
| `BACKGROUND_OVERLAY_PROCESSING` mode | Tokio async model is inherently parallel |
| `getOverlayThreadSnapshot()` | Different concurrency model; no separate overlay thread |
| `BUILD_TESTS`-only methods | Test helpers; Rust uses different test patterns |
| `OverlayUtils::logErrorOrThrow()` | Handled by Rust's tracing + Result types |
| `recvTxBatch()` (BUILD_TESTS only) | Test-only message handler |

## Gaps

Features not yet implemented. These ARE counted against parity %.

| stellar-core Component | Priority | Notes |
|------------------------|----------|-------|
| `Peer::pingPeer()` / `maybeProcessPingResponse()` | Medium | Ping/pong for connection liveness |
| `Peer::getJsonInfo()` | Low | JSON info for admin API |
| `Peer::handleMaxTxSizeIncrease()` | Medium | Protocol upgrade handling |
| `Peer::process()` (query throttle) | Low | Rate limiting GetTxSet/GetQuorumSet |
| `Peer::startRecurrentTimer()` / `recurrentTimerExpired()` | Medium | Periodic peer maintenance |
| `Peer::getIOTimeout()` | Medium | Idle/straggler timeout detection |
| `CapacityTrackedMessage` (RAII tracker) | Medium | Automatic capacity release on drop |
| `OverlayManagerImpl::tick()` | Medium | Periodic maintenance (connect, purge) |
| `OverlayManagerImpl::updateTimerAndMaybeDropRandomPeer()` | Medium | Random peer rotation |
| `OverlayManagerImpl::storeConfigPeers()` | Low | Persist config peers to DB |
| `OverlayManagerImpl::purgeDeadPeers()` | Medium | Remove stale peers from DB |
| `OverlayManagerImpl::triggerPeerResolution()` / `resolvePeers()` | Low | Async DNS with retry |
| `OverlayManagerImpl::clearLedgersBelow()` | Medium | Ledger-based cleanup coordination |
| `OverlayManagerImpl::getRandomInboundAuthenticatedPeers()` | Low | Separate inbound peer list |
| `OverlayManagerImpl::getRandomOutboundAuthenticatedPeers()` | Low | Separate outbound peer list |
| `OverlayManagerImpl::getInboundPendingPeers()` | Low | Pending peer tracking |
| `OverlayManagerImpl::getOutboundPendingPeers()` | Low | Pending peer tracking |
| `OverlayManagerImpl::getPendingPeersCount()` | Low | Pending count |
| `OverlayManagerImpl::getInboundAuthenticatedPeers()` | Low | Separate inbound map |
| `OverlayManagerImpl::getOutboundAuthenticatedPeers()` | Low | Separate outbound map |
| `OverlayManagerImpl::getFlowControlBytesTotal()` | Low | Aggregate flow control bytes |
| `OverlayManagerImpl::createTxBatch()` | Low | Batch TX message creation |
| `OverlayManagerImpl::getFlowControlBytesBatch()` | Low | Config-based batch size |
| `OverlayManagerImpl::nonPreferredAuthenticatedCount()` | Low | Count for peer eviction |
| `OverlayManagerImpl::updateSizeCounters()` | Low | Metrics for pending/auth sizes |
| `SurveyManager::relayOrProcessResponse()` | Medium | Full survey request/response relay |
| `SurveyManager::relayOrProcessRequest()` | Medium | Full survey request/response relay |
| `SurveyManager::broadcastStartSurveyCollecting()` | Medium | Survey initiation broadcasting |
| `SurveyManager::broadcastStopSurveyCollecting()` | Medium | Survey stop broadcasting |
| `SurveyManager::relayStartSurveyCollecting()` | Medium | Survey relay |
| `SurveyManager::relayStopSurveyCollecting()` | Medium | Survey relay |
| `SurveyManager::sendTopologyRequest()` | Medium | Topology survey requests |
| `SurveyManager::processTimeSlicedTopologyResponse()` | Medium | Process survey responses |
| `SurveyManager::processTimeSlicedTopologyRequest()` | Medium | Process survey requests |
| `SurveyManager::populateSurveyResponseMessage()` | Medium | Response message construction |
| `SurveyManager::populateSurveyRequestMessage()` | Medium | Request message construction |
| `SurveyManager::dropPeerIfSigInvalid()` | Medium | Signature validation for surveys |
| `SurveyDataManager::fillSurveyData()` | Medium | Fill survey response data |
| `SurveyMessageLimiter::validateStartSurveyCollecting()` | Medium | Full validation |
| `SurveyMessageLimiter::validateStopSurveyCollecting()` | Medium | Full validation |
| `TxAdverts::getOpsFloodLedger()` | Low | Ops-based flood rate calculation |

## Architectural Differences

1. **Async Runtime**
   - **stellar-core**: ASIO with callbacks, VirtualClock for timers, single main thread with optional background thread
   - **Rust**: Tokio async/await with native timers, tasks run on Tokio runtime
   - **Rationale**: Tokio provides equivalent async I/O with a more modern ergonomic model; inherently supports concurrent message processing without explicit threading

2. **Message Routing**
   - **stellar-core**: Messages dispatched in Peer class via virtual method calls (recvHello, recvAuth, etc.)
   - **Rust**: Messages received by Peer, then routed through OverlayManager which dispatches to MessageDispatcher, broadcast channel, or component-specific handlers
   - **Rationale**: Decouples message handling from connection management; makes testing easier

3. **Peer Lifecycle Management**
   - **stellar-core**: PeersList with pending/authenticated separation, shared_ptr/weak_ptr ownership, explicit CLOSING state
   - **Rust**: DashMap of Arc-wrapped peers, ConnectionPool for slot management, PeerState enum
   - **Rationale**: DashMap provides concurrent access without global locks; Arc handles ownership naturally

4. **Metrics System**
   - **stellar-core**: Medida library (timers, meters, counters, histograms)
   - **Rust**: Custom atomics-based Counter and Timer types in metrics.rs
   - **Rationale**: Avoids external metrics library dependency; atomics provide thread-safe counting with lower overhead

5. **Flood Message Hashing**
   - **stellar-core**: BLAKE2 via `xdrBlake2()` for message deduplication
   - **Rust**: SHA-256 via `henyey_common::Hash256::hash()`
   - **Rationale**: Both are cryptographic hashes suitable for deduplication; SHA-256 is used elsewhere in the codebase

6. **Survey Encryption**
   - **stellar-core**: Survey response encryption handled inline in SurveyManager
   - **Rust**: Encryption/decryption handled at application layer (henyey-app) using henyey_crypto
   - **Rationale**: Separation of concerns; crypto operations belong at a higher level

## Test Coverage

| Area | stellar-core Tests | Rust Tests | Notes |
|------|-------------------|------------|-------|
| Overlay/Peer | 39 TEST_CASE / 87 SECTION | 2 #[test] (peer.rs) + 2 (connection.rs) | Significant gap; upstream has extensive handshake tests |
| Flood | 1 TEST_CASE / 17 SECTION | 5 #[test] | Reasonable coverage |
| FlowControl | (in OverlayTests) | 9 #[test] | Good coverage |
| ItemFetcher | 2 TEST_CASE / 16 SECTION | 12 #[test] + 8 integration | Good coverage |
| Tracker | 1 TEST_CASE / 8 SECTION | (in item_fetcher tests) | Covered |
| PeerManager | 8 TEST_CASE / 38 SECTION | 7 #[test] | Moderate gap |
| BanManager | (not separate) | 7 #[test] | Good coverage |
| TCPPeer | 3 TEST_CASE / 5 SECTION | (in codec + connection tests) | Partial coverage |
| SurveyManager | 5 TEST_CASE / 7 SECTION | 15 #[test] | Good coverage |
| SurveyMessageLimiter | 1 TEST_CASE / 10 SECTION | (in survey tests) | Partial |
| TxAdverts | 1 TEST_CASE / 5 SECTION | 9 #[test] | Good coverage |
| OverlayManager | 4 TEST_CASE | 1 #[test] | Significant gap |
| OverlayTopology | 2 TEST_CASE / 7 SECTION | 0 | Not covered |
| MessageDispatcher | N/A | 8 #[test] | Rust-specific |
| Metrics | N/A | 12 #[test] | Rust-specific |
| Auth | N/A | 3 #[test] | Basic coverage |
| Codec | N/A | 7 #[test] | Good coverage |
| TxDemands | N/A | 15 #[test] | Good coverage |

### Test Gaps

- **Peer handshake and connection lifecycle**: Upstream has 39 TEST_CASE with 87 SECTION in OverlayTests.cpp covering extensive edge cases for handshake, version negotiation, error handling, etc. Rust has minimal tests here.
- **PeerManager persistence**: Upstream has 8 TEST_CASE with 38 SECTION covering database operations, type updates, backoff scenarios. Rust has 7 tests.
- **Multi-node topology**: Upstream has OverlayTopologyTests with 2 TEST_CASE / 7 SECTION for multi-node overlay scenarios. Rust has none.
- **OverlayManager integration**: Upstream has 4 TEST_CASE for manager-level operations. Rust has 1 basic test.
- **Network error handling**: Upstream TCPPeer tests cover error conditions, message size limits, and connection failures. Rust coverage is partial.

## Parity Calculation

| Category | Count |
|----------|-------|
| Implemented (Full) | 247 |
| Gaps (None + Partial) | 55 |
| Intentional Omissions | 10 |
| **Parity** | **247 / (247 + 55) = 82%** |
