## Pseudocode: crates/app/src/survey.rs

### Constants

```
CONST COLLECTING_PHASE_MAX_DURATION = 30 minutes
CONST REPORTING_PHASE_MAX_DURATION  = 3 hours
CONST DEFAULT_HISTOGRAM_SAMPLES     = 1024
CONST TIME_SLICED_PEERS_MAX         = 25
```

### STATE_MACHINE: SurveyPhase

```
STATE_MACHINE: SurveyPhase
  STATES: [Inactive, Collecting, Reporting]
  TRANSITIONS:
    Inactive   -> Collecting : start_collecting message
    Collecting -> Reporting  : stop_collecting message OR max duration exceeded
    Reporting  -> Inactive   : reporting phase expires (3 hours)
```

---

### Data: SurveyMessageLimiter

```
SurveyMessageLimiter:
  num_ledgers_before_ignore: u32
  max_request_limit: u32
  record_map: sorted_map<ledger -> map<surveyor -> map<surveyed -> seen>>>
```

### SurveyMessageLimiter::add_and_validate_request

```
function add_and_validate_request(request, local_ledger,
                                  local_node_id, on_success_validation):
  GUARD request.command_type != TimeSlicedSurveyTopology -> false
  GUARD not survey_ledger_num_valid(request.ledger_num, local_ledger) -> false

  surveyor_is_self = (request.surveyor_peer_id == local_node_id)
  ledger_entry = record_map[request.ledger_num]  // auto-create

  if surveyor not in ledger_entry:
    GUARD not surveyor_is_self and
          ledger_entry.size >= max_request_limit  -> false
    GUARD not on_success_validation()             -> false
    ledger_entry[surveyor] = { request.surveyed_peer_id: false }
    -> true

  else:  // surveyor already tracked
    surveyed_map = ledger_entry[surveyor]
    GUARD not surveyor_is_self and
          surveyed_map.size >= max_request_limit   -> false

    if surveyed_peer not in surveyed_map:
      GUARD not on_success_validation()            -> false
      surveyed_map[request.surveyed_peer_id] = false
      -> true
    else:
      -> false  // duplicate
```

### SurveyMessageLimiter::record_and_validate_response

```
function record_and_validate_response(response, local_ledger,
                                      on_success_validation):
  GUARD not survey_ledger_num_valid(response.ledger_num, local_ledger) -> false
  GUARD response.ledger_num not in record_map                         -> false
  GUARD response.surveyor_peer_id not in ledger_entry                 -> false
  GUARD response.surveyed_peer_id not in surveyor_entry               -> false
  GUARD already seen                                                  -> false
  GUARD not on_success_validation()                                   -> false

  mark as seen = true
  -> true
```

### SurveyMessageLimiter::validate_start_collecting

```
function validate_start_collecting(start, local_ledger,
                                   survey_active, on_success_validation):
  GUARD not survey_ledger_num_valid(start.ledger_num, local_ledger) -> false
  GUARD survey_active                                               -> false
  -> on_success_validation()
```

### SurveyMessageLimiter::validate_stop_collecting

```
function validate_stop_collecting(stop, local_ledger,
                                  on_success_validation):
  GUARD not survey_ledger_num_valid(stop.ledger_num, local_ledger) -> false
  -> on_success_validation()
```

### SurveyMessageLimiter::clear_old_ledgers

```
function clear_old_ledgers(last_closed_ledger):
  threshold = last_closed_ledger - num_ledgers_before_ignore
  while record_map has entries:
    if oldest_ledger < threshold:
      remove oldest entry
    else:
      break
```

### Helper: survey_ledger_num_valid

```
function survey_ledger_num_valid(ledger_num, local_ledger):
  max_offset = max(num_ledgers_before_ignore, 1)
  upper = local_ledger + max_offset
  lower = local_ledger - num_ledgers_before_ignore
  -> ledger_num >= lower and ledger_num <= upper
```

---

### Helper: LatencyHistogram

```
LatencyHistogram:
  samples: bounded_deque<u64>    // max DEFAULT_HISTOGRAM_SAMPLES
  max_samples: integer

function update(value_ms):
  push_back(value_ms)
  if size > max_samples:
    pop_front()

function percentile(p):
  GUARD samples is empty -> 0
  sorted = sort(samples)
  idx = (len - 1) * p / 100
  -> sorted[idx]

function median():  -> percentile(50)
function p75():     -> percentile(75)
```

---

### Data: SurveyDataManager

```
SurveyDataManager:
  phase: SurveyPhase
  collect_start: optional<Instant>
  collect_end: optional<Instant>
  nonce: optional<u32>
  surveyor_id: optional<NodeId>
  collecting_node: optional<CollectingNodeData>
  collecting_inbound: map<PeerId, CollectingPeerData>
  collecting_outbound: map<PeerId, CollectingPeerData>
  final_node: optional<TimeSlicedNodeData>
  final_inbound: list<TimeSlicedPeerData>
  final_outbound: list<TimeSlicedPeerData>
  is_validator: boolean
  max_inbound: u32
  max_outbound: u32
```

### SurveyDataManager::start_collecting

```
function start_collecting(msg, inbound_peers, outbound_peers, node_stats):
  GUARD phase != Inactive -> false

  phase = Collecting
  collect_start = now()
  nonce = msg.nonce
  surveyor_id = msg.surveyor_id
  collecting_node = CollectingNodeData(
    initial_lost_sync_count = node_stats.lost_sync_count,
    initially_out_of_sync = node_stats.out_of_sync,
    initial_added_peers = node_stats.added_peers,
    initial_dropped_peers = node_stats.dropped_peers,
    scp_first_to_self_latency = new LatencyHistogram(1024),
    scp_self_to_other_latency = new LatencyHistogram(1024))

  collecting_inbound  = initialize_collecting_peers(inbound_peers)
  collecting_outbound = initialize_collecting_peers(outbound_peers)
  -> true
```

### SurveyDataManager::stop_collecting

```
function stop_collecting(msg, inbound_peers, outbound_peers,
                         added_total, dropped_total, lost_sync_total):
  GUARD phase != Collecting                         -> false
  GUARD nonce != msg.nonce or
        surveyor_id != msg.surveyor_id              -> false

  -> start_reporting_phase(inbound_peers, outbound_peers,
       added_total, dropped_total, lost_sync_total)
```

### SurveyDataManager::update_phase

```
function update_phase(inbound_peers, outbound_peers,
                      added_total, dropped_total, lost_sync_total):
  if phase == Collecting:
    if time_since(collect_start) > COLLECTING_PHASE_MAX_DURATION:
      start_reporting_phase(inbound_peers, outbound_peers,
        added_total, dropped_total, lost_sync_total)

  else if phase == Reporting:
    if time_since(collect_end) > REPORTING_PHASE_MAX_DURATION:
      reset()
```

### SurveyDataManager::record_peer_latency

```
function record_peer_latency(peer_id, latency_ms):
  GUARD phase != Collecting -> return

  if peer_id in collecting_inbound:
    collecting_inbound[peer_id].latency_ms.update(latency_ms)
    return
  if peer_id in collecting_outbound:
    collecting_outbound[peer_id].latency_ms.update(latency_ms)
```

### SurveyDataManager::fill_survey_data

```
function fill_survey_data(request):
  GUARD phase != Reporting                         -> null
  GUARD nonce != request.nonce                     -> null
  GUARD surveyor_id != request.surveyor_peer_id    -> null

  node_data = final_node
  GUARD node_data is null                          -> null

  inbound_peers  = slice_peer_data(final_inbound,  request.inbound_peers_index)
  outbound_peers = slice_peer_data(final_outbound, request.outbound_peers_index)

  -> TopologyResponseBodyV2(inbound_peers, outbound_peers, node_data)
```

### Helper: slice_peer_data

```
function slice_peer_data(peers, index):
  idx = index as integer
  GUARD idx >= peers.length -> empty list

  end = min(peers.length, idx + TIME_SLICED_PEERS_MAX)
  -> peers[idx..end]
```

### Helper: start_reporting_phase

```
function start_reporting_phase(inbound_peers, outbound_peers,
                               added_total, dropped_total, lost_sync_total):
  GUARD phase != Collecting -> false

  phase = Reporting
  collect_end = now()

  final_inbound  = finalize_peer_data(inbound_peers, collecting_inbound)
  final_outbound = finalize_peer_data(outbound_peers, collecting_outbound)
  final_node     = finalize_node_data(added_total, dropped_total, lost_sync_total)

  clear collecting_inbound, collecting_outbound, collecting_node
  -> true
```

### Helper: finalize_peer_data

```
function finalize_peer_data(current_peers, collecting_data):
  ordered = sort current_peers by peer_id bytes

  result = []
  for each snapshot in ordered:
    initial = collecting_data[snapshot.peer_id]
    GUARD initial not found -> skip

    NOTE: all counters are deltas = current - initial
    peer_stats = PeerStats(
      id              = snapshot.peer_id,
      messages_read   = snapshot.messages_received - initial.messages_read,
      messages_written= snapshot.messages_sent    - initial.messages_written,
      bytes_read      = snapshot.bytes_received   - initial.bytes_read,
      bytes_written   = snapshot.bytes_sent       - initial.bytes_written,
      seconds_connected = snapshot.connected_at.elapsed(),
      unique_flood_bytes_recv    = delta(...),
      duplicate_flood_bytes_recv = delta(...),
      unique_fetch_bytes_recv    = delta(...),
      duplicate_fetch_bytes_recv = delta(...),
      unique_flood_messages_recv = delta(...),
      duplicate_flood_messages_recv = delta(...),
      unique_fetch_messages_recv    = delta(...),
      duplicate_fetch_messages_recv = delta(...))

    latency_ms = initial.latency_ms.median()
    result.push(TimeSlicedPeerData(peer_stats, latency_ms))

  -> result
```

### Helper: finalize_node_data

```
function finalize_node_data(added_total, dropped_total, lost_sync_total):
  GUARD collecting_node is null -> null

  lost_sync = lost_sync_total - initial_lost_sync_count
  if initially_out_of_sync:
    lost_sync += 1

  -> TimeSlicedNodeData(
    added_authenticated_peers   = added_total - initial_added_peers,
    dropped_authenticated_peers = dropped_total - initial_dropped_peers,
    total_inbound_peer_count    = final_inbound.length,
    total_outbound_peer_count   = final_outbound.length,
    p75_scp_first_to_self_latency = scp_first_to_self_latency.p75(),
    p75_scp_self_to_other_latency = scp_self_to_other_latency.p75(),
    lost_sync_count             = lost_sync,
    is_validator                = self.is_validator,
    max_inbound_peer_count      = self.max_inbound,
    max_outbound_peer_count     = self.max_outbound)
```

### Helper: reset

```
function reset():
  phase = Inactive
  clear: collect_start, collect_end, nonce, surveyor_id,
         collecting_node, collecting_inbound, collecting_outbound,
         final_node, final_inbound, final_outbound
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~752   | ~215       |
| Functions     | 22     | 19         |
