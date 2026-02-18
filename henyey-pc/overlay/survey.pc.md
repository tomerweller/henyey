## Pseudocode: crates/overlay/src/survey.rs

### Constants

```
CONST MAX_COLLECTING_PHASE_DURATION = 30 min
CONST MAX_REPORTING_PHASE_DURATION  = 60 min
CONST NUM_LEDGERS_BEFORE_IGNORE     = 10
CONST MAX_REQUEST_LIMIT_PER_LEDGER  = 100
CONST SURVEY_THROTTLE_TIMEOUT_MULT  = 3
CONST SURVEY_THROTTLE_TIMEOUT_MS    = 200
```

### STATE_MACHINE: SurveyPhase

```
STATE_MACHINE: SurveyPhase
  STATES: [Collecting, Reporting, Inactive]
  TRANSITIONS:
    Inactive   → Collecting: start_collecting()
    Collecting → Reporting:  stop_collecting()
    Collecting → Inactive:   collecting phase timeout
    Reporting  → Inactive:   reporting phase timeout or reset()
    Any        → Inactive:   reset()
```

### Data Structures

```
struct CollectingNodeData:
  added_authenticated_peers: int
  dropped_authenticated_peers: int
  initial_lost_sync_count: int
  scp_first_to_self_latencies_ms: list<int>
  scp_self_to_other_latencies_ms: list<int>

struct CollectingPeerData:
  initial_messages_read: int
  initial_messages_written: int
  initial_bytes_read: int
  initial_bytes_written: int
  initial_unique_flood_bytes_recv: int
  initial_duplicate_flood_bytes_recv: int
  initial_unique_fetch_bytes_recv: int
  initial_duplicate_fetch_bytes_recv: int
  latencies_ms: list<int>

struct TimeSlicedPeerData:
  peer_id: PeerId
  messages_read: int       // delta from initial
  messages_written: int    // delta from initial
  bytes_read: int          // delta from initial
  bytes_written: int       // delta from initial
  avg_latency_ms: int

struct TimeSlicedNodeData:
  added_peers: int
  dropped_peers: int
  total_inbound_peers: int
  total_outbound_peers: int
  lost_sync_count: int
  avg_scp_first_to_self_latency_ms: int
  avg_scp_self_to_other_latency_ms: int

struct SurveyConfig:
  max_collecting_duration: duration
  max_reporting_duration: duration
  num_ledgers_before_ignore: int
  max_request_limit_per_ledger: int
  throttle_timeout: duration
  surveyor_allowlist: set<PeerId>   // empty = allow all

struct SurveyState:
  nonce: int
  phase: SurveyPhase
  collect_start_time: timestamp
  collect_end_time: timestamp or null
  node_data: CollectingNodeData
  inbound_peer_data: map<PeerId, CollectingPeerData>
  outbound_peer_data: map<PeerId, CollectingPeerData>
  final_node_data: TimeSlicedNodeData or null
  final_inbound_peer_data: list<TimeSlicedPeerData>
  final_outbound_peer_data: list<TimeSlicedPeerData>

struct SurveyManager:
  config: SurveyConfig
  state: SurveyState or null          // guarded by lock
  limiter: SurveyMessageLimiter       // guarded by lock
  peers_to_survey: deque<PeerId>      // guarded by lock
  surveyed_peers: set<PeerId>         // guarded by lock
  bad_response_nodes: set<PeerId>     // guarded by lock
```

---

### SurveyMessageLimiter::ledger_num_valid

```
function ledger_num_valid(ledger_num, current_ledger):
  GUARD ledger_num > current_ledger → false
  → (current_ledger - ledger_num) <= num_ledgers_before_ignore
```

### SurveyMessageLimiter::add_request

```
function add_request(ledger_num, surveyor, surveyed,
                     current_ledger):
  GUARD not ledger_num_valid(ledger_num, current_ledger)
    → false
  ledger_map = records[ledger_num]        // create if absent
  surveyor_map = ledger_map[surveyor]     // create if absent
  GUARD size(surveyor_map) >= max_request_limit_per_ledger
    → false
  GUARD surveyed in surveyor_map
    → false
  MUTATE surveyor_map[surveyed] = false   // response not yet seen
  → true
```

### SurveyMessageLimiter::record_response

```
function record_response(ledger_num, surveyor, surveyed,
                         current_ledger):
  GUARD not ledger_num_valid(ledger_num, current_ledger)
    → false
  response_seen = records[ledger_num][surveyor][surveyed]
  GUARD entry not found at any level → false
  GUARD response_seen == true → false     // already recorded
  MUTATE response_seen = true
  → true
```

### SurveyMessageLimiter::clear_old_ledgers

```
function clear_old_ledgers(last_closed_ledger):
  min_valid = last_closed_ledger - num_ledgers_before_ignore
  NOTE: saturating subtract to avoid underflow
  remove all entries from records where ledger < min_valid
```

---

### SurveyManager::phase

```
function phase():
  if state is null:
    → Inactive
  → state.phase
```

### SurveyManager::is_active

```
function is_active():
  → phase() != Inactive
```

### SurveyManager::nonce

```
function nonce():
  if state is null:
    → null
  → state.nonce
```

### SurveyManager::surveyor_permitted

```
function surveyor_permitted(surveyor):
  if surveyor_allowlist is empty:
    → true
  → surveyor in surveyor_allowlist
```

### SurveyManager::start_collecting

```
function start_collecting(nonce, initial_lost_sync_count,
                          inbound_peers, outbound_peers):
  GUARD state is not null → false
    "Cannot start survey: survey already active"

  inbound_peer_data = {}
  for each peer in inbound_peers:
    inbound_peer_data[peer] = new CollectingPeerData(0,0,0,0)

  outbound_peer_data = {}
  for each peer in outbound_peers:
    outbound_peer_data[peer] = new CollectingPeerData(0,0,0,0)

  MUTATE state = new SurveyState:
    nonce = nonce
    phase = Collecting
    collect_start_time = now()
    collect_end_time = null
    node_data = CollectingNodeData(initial_lost_sync_count)
    inbound_peer_data = inbound_peer_data
    outbound_peer_data = outbound_peer_data
    final_node_data = null
    final_inbound_peer_data = []
    final_outbound_peer_data = []
  → true
```

### SurveyManager::stop_collecting

```
function stop_collecting(nonce, current_lost_sync_count,
                         inbound_peers, outbound_peers):
  GUARD state is null
    or state.nonce != nonce
    or state.phase != Collecting
    → false

  MUTATE state.collect_end_time = now()
  MUTATE state.phase = Reporting
```

**Calls** [finalize_peer_data](#helper-finalize_peer_data) for inbound and outbound

```
  state.final_inbound_peer_data =
    finalize_peer_data(state.inbound_peer_data, inbound_peers)
  state.final_outbound_peer_data =
    finalize_peer_data(state.outbound_peer_data, outbound_peers)

  lost_sync_delta = current_lost_sync_count
                    - node_data.initial_lost_sync_count
```

**Calls** [avg_or_zero](#helper-avg_or_zero) for SCP latencies

```
  MUTATE state.final_node_data = new TimeSlicedNodeData:
    added_peers = node_data.added_authenticated_peers
    dropped_peers = node_data.dropped_authenticated_peers
    total_inbound_peers = len(final_inbound_peer_data)
    total_outbound_peers = len(final_outbound_peer_data)
    lost_sync_count = lost_sync_delta
    avg_scp_first_to_self_latency_ms =
      avg_or_zero(node_data.scp_first_to_self_latencies_ms)
    avg_scp_self_to_other_latency_ms =
      avg_or_zero(node_data.scp_self_to_other_latencies_ms)
  → true
```

### SurveyManager::reset

```
function reset():
  MUTATE state = null
  MUTATE peers_to_survey = empty deque
  MUTATE surveyed_peers = empty set
  MUTATE bad_response_nodes = empty set
```

### SurveyManager::update_phase

```
function update_phase():
  GUARD state is null → return

  now = now()
  if state.phase == Collecting:
    elapsed = now - state.collect_start_time
    if elapsed >= config.max_collecting_duration:
      "Survey collecting phase timed out"
      MUTATE state = null

  if state.phase == Reporting:
    if state.collect_end_time is not null:
      elapsed = now - state.collect_end_time
      if elapsed >= config.max_reporting_duration:
        "Survey reporting phase expired"
        MUTATE state = null
```

### SurveyManager::modify_node_data

```
function modify_node_data(callback):
  GUARD state is null → return
  GUARD state.phase != Collecting → return
  callback(state.node_data)
```

### SurveyManager::modify_peer_data

```
function modify_peer_data(peer_id, is_inbound, callback):
  GUARD state is null → return
  GUARD state.phase != Collecting → return
  peer_map = if is_inbound: state.inbound_peer_data
             else: state.outbound_peer_data
  GUARD peer_id not in peer_map → return
  callback(peer_map[peer_id])
```

### SurveyManager::record_dropped_peer

```
function record_dropped_peer(peer_id):
  GUARD state is null → return
  GUARD state.phase != Collecting → return
  MUTATE state.node_data.dropped_authenticated_peers += 1
  remove peer_id from state.inbound_peer_data
  remove peer_id from state.outbound_peer_data
```

### SurveyManager::record_added_peer

```
function record_added_peer(peer_id, is_inbound, initial_metrics):
  GUARD state is null → return
  GUARD state.phase != Collecting → return
  MUTATE state.node_data.added_authenticated_peers += 1
  peer_map = if is_inbound: state.inbound_peer_data
             else: state.outbound_peer_data
  MUTATE peer_map[peer_id] = initial_metrics
```

### SurveyManager::get_node_data

```
function get_node_data():
  GUARD state is null → null
  GUARD state.phase != Reporting → null
  → state.final_node_data
```

### SurveyManager::get_inbound_peer_data

```
function get_inbound_peer_data():
  GUARD state is null or state.phase != Reporting → []
  → state.final_inbound_peer_data
```

### SurveyManager::get_outbound_peer_data

```
function get_outbound_peer_data():
  GUARD state is null or state.phase != Reporting → []
  → state.final_outbound_peer_data
```

### SurveyManager::add_peer_to_backlog

```
function add_peer_to_backlog(peer_id):
  GUARD peer_id in surveyed_peers → false
  MUTATE peers_to_survey.push_back(peer_id)
  → true
```

### SurveyManager::pop_peer_to_survey

```
function pop_peer_to_survey():
  peer = peers_to_survey.pop_front()
  GUARD peer is null → null
  MUTATE surveyed_peers.insert(peer)
  → peer
```

### SurveyManager::has_peers_to_survey

```
function has_peers_to_survey():
  → peers_to_survey is not empty
```

### SurveyManager::record_bad_response

```
function record_bad_response(peer_id):
  MUTATE bad_response_nodes.insert(peer_id)
```

### SurveyManager::is_bad_response_node

```
function is_bad_response_node(peer_id):
  → peer_id in bad_response_nodes
```

### SurveyManager::add_request

```
function add_request(ledger_num, surveyor, surveyed,
                     current_ledger):
  → delegate to limiter.add_request(...)
```

### SurveyManager::record_response

```
function record_response(ledger_num, surveyor, surveyed,
                         current_ledger):
  → delegate to limiter.record_response(...)
```

### SurveyManager::clear_old_ledgers

```
function clear_old_ledgers(last_closed_ledger):
  → delegate to limiter.clear_old_ledgers(...)
```

### SurveyManager::stats

```
function stats():
  → SurveyManagerStats:
    phase = state.phase or Inactive
    nonce = state.nonce or null
    peers_to_survey = len(peers_to_survey)
    peers_surveyed = len(surveyed_peers)
    bad_response_nodes = len(bad_response_nodes)
    collecting_inbound_peers = len(state.inbound_peer_data)
    collecting_outbound_peers = len(state.outbound_peer_data)
```

---

### Helper: avg_or_zero

```
function avg_or_zero(values):
  if values is empty:
    → 0
  → sum(values) / len(values)
```

### Helper: finalize_peer_data

```
function finalize_peer_data(collecting, current_peers):
  result = []
  for each (peer_id, msg_read, msg_write,
            bytes_read, bytes_write) in current_peers:
    initial = collecting[peer_id]
    if initial not found:
      continue
    result.append(TimeSlicedPeerData:
      peer_id = peer_id
      messages_read = msg_read - initial.initial_messages_read
      messages_written = msg_write - initial.initial_messages_written
      bytes_read = bytes_read - initial.initial_bytes_read
      bytes_written = bytes_write - initial.initial_bytes_written
      avg_latency_ms = initial.avg_latency_ms()
    )
  → result
```

### Helper: CollectingPeerData::avg_latency_ms

```
function avg_latency_ms():
  if latencies_ms is empty:
    → 0
  → sum(latencies_ms) / len(latencies_ms)
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~450   | ~280       |
| Functions     | 28     | 28         |
