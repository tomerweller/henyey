## Pseudocode: crates/app/src/app/survey_impl.rs

### survey_report

```
survey_data = read survey_data
phase = survey_data.phase()
nonce = survey_data.nonce()
local_node = survey_data.final_node_data()
inbound_peers = survey_data.final_inbound_peers()
outbound_peers = survey_data.final_outbound_peers()

(survey_in_progress, backlog, bad_response_nodes) =
  read survey_reporting {
    running, peers as hex, bad_response_nodes as hex
  }
sort backlog
sort bad_response_nodes

peer_reports = read survey_results:
  for each (nonce, peers):
    for each (peer_id, response):
      SurveyPeerReport(peer_id.hex, response)
    sort reports by peer_id
  → BTreeMap(nonce → reports)

→ SurveyReport {
    phase, nonce, local_node,
    inbound_peers, outbound_peers,
    peer_reports, survey_in_progress,
    backlog, bad_response_nodes
  }
```

### start_survey_collecting

```
ledger_num = survey_local_ledger()
→ broadcast_survey_start(nonce, ledger_num)
```

**Calls**: [broadcast_survey_start](#broadcast_survey_start) | [survey_local_ledger](#helper-survey_local_ledger)

### stop_survey_collecting

```
ledger_num = survey_local_ledger()
nonce = survey_data.nonce()
GUARD nonce exists → false
broadcast_survey_stop(nonce, ledger_num)
→ true
```

**Calls**: [broadcast_survey_stop](#broadcast_survey_stop)

### stop_survey_reporting

```
reporting.running = false
if nonce exists:
  survey_secrets.remove(nonce)
```

### survey_topology_timesliced

```
start = start_survey_reporting()
GUARD start != NotReady → false

"Remove prior result for this peer if re-queried"
if nonce exists:
  survey_results[nonce].remove(peer_id)

self_peer = PeerId from own public key
GUARD peer not already queued AND not self → false

reporting.bad_response_nodes.remove(peer_id)
reporting.peers.insert(peer_id)
reporting.queue.push_back(peer_id)
reporting.inbound_indices[peer_id] = inbound_index
reporting.outbound_indices[peer_id] = outbound_index
→ true
```

**Calls**: [start_survey_reporting](#start_survey_reporting)

### start_survey_reporting

```
nonce = survey_data.nonce()
GUARD nonce exists → NotReady
GUARD survey_data.final_node_data() exists → NotReady
GUARD not already running → AlreadyRunning

reporting.running = true
clear peers, queue, indices, bad_response_nodes
reporting.next_topoff = now

clear survey_results
ensure_survey_secret(nonce)

"Store own topology response"
if local_topology_response() exists:
  self_peer = own PeerId
  survey_results[nonce][self_peer] = response
→ Started
```

**Calls**: [ensure_survey_secret](#helper-ensure_survey_secret) | [local_topology_response](#helper-local_topology_response)

### Helper: local_topology_response

```
CONST MAX_PEERS = 25
node_data = survey_data.final_node_data()
GUARD node_data exists → none

inbound_peers = survey_data.final_inbound_peers()
  .take(MAX_PEERS)
outbound_peers = survey_data.final_outbound_peers()
  .take(MAX_PEERS)

→ TopologyResponseBodyV2 {
    inbound_peers, outbound_peers, node_data }
```

### top_off_survey_requests

```
CONST MAX_REQUEST_LIMIT_PER_LEDGER = 10

GUARD reporting.running → return
GUARD now >= reporting.next_topoff → return

nonce = survey_data.nonce()
GUARD nonce exists → stop_survey_reporting; return
GUARD survey_data.nonce_is_reporting(nonce)
  → stop_survey_reporting; return

ledger_num = survey_local_ledger()

"Dequeue up to MAX_REQUEST_LIMIT_PER_LEDGER peers"
to_send = []
while requests_sent < MAX_REQUEST_LIMIT_PER_LEDGER:
  peer_id = reporting.queue.pop_front()
  GUARD peer_id exists → break
  if not in reporting.peers → skip
  reporting.peers.remove(peer_id)
  inbound_index = reporting.inbound_indices[peer_id]
  outbound_index = reporting.outbound_indices[peer_id]
  to_send.push((peer_id, inbound_index, outbound_index))
  requests_sent++

reporting.next_topoff = now + survey_throttle

for each (peer_id, inbound_idx, outbound_idx):
  send_survey_request(peer_id, nonce, ledger_num,
    inbound_idx, outbound_idx)
```

**Calls**: [send_survey_request](#send_survey_request) | [survey_local_ledger](#helper-survey_local_ledger)

### send_survey_request

```
local_node_id = self.local_node_id()
secret = ensure_survey_secret(nonce)
encryption_key = Curve25519Public from secret

request = SurveyRequestMessage {
  surveyor = local_node_id,
  surveyed = peer_id,
  ledger_num, encryption_key,
  command = TimeSlicedSurveyTopology
}
message = TimeSlicedSurveyRequestMessage {
  request, nonce,
  inbound_peers_index, outbound_peers_index
}

message_bytes = encode message to XDR
signature = sign_survey_message(message_bytes)
signed = SignedTimeSlicedSurveyRequestMessage {
  signature, request: message
}

"Validate with rate limiter"
local_ledger = survey_local_ledger()
ok = survey_limiter.add_and_validate_request(
  signed.request, local_ledger, local_node_id,
  verify_signature_fn)
GUARD ok → false

→ broadcast_survey_message(
    TimeSlicedSurveyRequest(signed))
```

**Calls**: [ensure_survey_secret](#helper-ensure_survey_secret) | [sign_survey_message](#helper-sign_survey_message) | [broadcast_survey_message](#helper-broadcast_survey_message)

### broadcast_survey_start

```
start = TimeSlicedSurveyStartCollectingMessage {
  surveyor_id: local_node_id, nonce, ledger_num
}
signature = sign_survey_message(encode(start))
signed = SignedTimeslicedSurveyStartCollecting {
  signature, start_collecting: start
}

sent = broadcast_survey_message(
  TimeSlicedSurveyStartCollecting(signed))
if sent:
  survey_results[nonce] = empty map
  start_local_survey_collecting(start)
→ sent
```

**Calls**: [sign_survey_message](#helper-sign_survey_message) | [broadcast_survey_message](#helper-broadcast_survey_message) | [start_local_survey_collecting](#start_local_survey_collecting)

### broadcast_survey_stop

```
stop = TimeSlicedSurveyStopCollectingMessage {
  surveyor_id: local_node_id, nonce, ledger_num
}
signature = sign_survey_message(encode(stop))
signed = SignedTimeSlicedSurveyStopCollecting {
  signature, stop_collecting: stop
}

broadcast_survey_message(
  TimeSlicedSurveyStopCollecting(signed))
stop_local_survey_collecting(stop)
```

**Calls**: [sign_survey_message](#helper-sign_survey_message) | [stop_local_survey_collecting](#stop_local_survey_collecting)

### Helper: broadcast_survey_message

```
GUARD overlay available → false
→ overlay.broadcast(message)
```

### Helper: ensure_survey_secret

```
if survey_secrets[nonce] exists:
  → cached secret
secret = generate random Curve25519 secret key
survey_secrets[nonce] = secret
→ secret
```

### handle_survey_start_collecting

```
message_bytes = encode message to XDR
GUARD surveyor_permitted(message.surveyor_id)
  → return

local_ledger = survey_local_ledger()
survey_active = survey_data.survey_is_active()

is_valid = survey_limiter.validate_start_collecting(
  message, local_ledger, survey_active,
  verify_signature_fn)
GUARD is_valid → return

GUARD overlay available → return
snapshots = overlay.peer_snapshots()
added = overlay.added_authenticated_peers()
dropped = overlay.dropped_authenticated_peers()

(inbound, outbound) = partition_peer_snapshots(
  snapshots)
lost_sync = lost_sync_count
out_of_sync = state is Initializing or CatchingUp

node_stats = NodeStatsSnapshot {
  lost_sync, out_of_sync, added, dropped
}
survey_data.start_collecting(
  message, inbound, outbound, node_stats)
```

**Calls**: [surveyor_permitted](#surveyor_permitted) | [partition_peer_snapshots](#helper-partition_peer_snapshots) | [survey_local_ledger](#helper-survey_local_ledger)

### handle_survey_stop_collecting

```
message_bytes = encode message to XDR
GUARD surveyor_permitted(message.surveyor_id)
  → return

local_ledger = survey_local_ledger()
is_valid = survey_limiter.validate_stop_collecting(
  message, local_ledger, verify_signature_fn)
GUARD is_valid → return

GUARD overlay available → return
snapshots = overlay.peer_snapshots()
added = overlay.added_authenticated_peers()
dropped = overlay.dropped_authenticated_peers()

(inbound, outbound) = partition_peer_snapshots(
  snapshots)
lost_sync = lost_sync_count

survey_data.stop_collecting(
  message, inbound, outbound,
  added, dropped, lost_sync)
```

**Calls**: [surveyor_permitted](#surveyor_permitted) | [partition_peer_snapshots](#helper-partition_peer_snapshots)

### handle_survey_request

```
request_bytes = encode request to XDR
GUARD surveyor_permitted(
  request.surveyor_peer_id) → return

local_node_id = self.local_node_id()
local_ledger = survey_local_ledger()
nonce_is_reporting = survey_data.nonce_is_reporting(
  request.nonce)

is_valid = survey_limiter.add_and_validate_request(
  request, local_ledger, local_node_id,
  fn: nonce_is_reporting AND verify_signature)
GUARD is_valid → return

"If not addressed to us, relay to network"
if request.surveyed_peer_id != local_node_id:
  broadcast_survey_message(
    TimeSlicedSurveyRequest(signed))
  → return

"Build response for our node"
response_body = survey_data.fill_survey_data(request)
GUARD response_body exists → return

"Encrypt response to surveyor's key"
response_body_xdr = encode response_body
encrypted_body = seal_to_curve25519_public_key(
  request.encryption_key, response_body_xdr)
  REF: henyey_crypto::seal_to_curve25519_public_key

response = SurveyResponseMessage {
  surveyor = request.surveyor_peer_id,
  surveyed = local_node_id,
  ledger_num, command_type, encrypted_body
}
response_msg = TimeSlicedSurveyResponseMessage {
  response, nonce
}

signature = sign_survey_message(
  encode(response_msg))
signed_response = SignedTimeSlicedSurveyResponse {
  signature, response: response_msg
}

overlay.send_to(peer_id,
  TimeSlicedSurveyResponse(signed_response))
```

**Calls**: [surveyor_permitted](#surveyor_permitted) | [sign_survey_message](#helper-sign_survey_message) | [broadcast_survey_message](#helper-broadcast_survey_message)

### handle_survey_response

```
response_bytes = encode response_message to XDR

local_ledger = survey_local_ledger()
nonce_is_reporting = survey_data.nonce_is_reporting(
  response_message.nonce)

is_valid = survey_limiter.record_and_validate_response(
  response, local_ledger,
  fn: nonce_is_reporting AND verify_signature)
GUARD is_valid → return

"If not addressed to us, relay to network"
if response.surveyor_peer_id != local_node_id:
  broadcast_survey_message(
    TimeSlicedSurveyResponse(signed))
  → return

"Decrypt response"
secret = survey_secrets[response.nonce]
GUARD secret exists → return

decrypted = open_from_curve25519_secret_key(
  secret, encrypted_body)
  REF: henyey_crypto::open_from_curve25519_secret_key
if decryption fails:
  reporting.bad_response_nodes.insert(peer_id)
  → return

response_body = decode SurveyResponseBody from decrypted
if decode fails:
  reporting.bad_response_nodes.insert(peer_id)
  → return

"Merge into results"
body = response_body as TopologyResponseBodyV2
entry = survey_results[nonce][peer_id]
merge_topology_response(entry, body)

"Request more pages if response was full"
CONST TIME_SLICED_PEERS_MAX  // max per response page
if inbound at max OR outbound at max:
  if reporting.running:
    survey_topology_timesliced(peer_id,
      entry.inbound_len, entry.outbound_len)
```

**Calls**: [survey_topology_timesliced](#survey_topology_timesliced) | [merge_topology_response](#helper-merge_topology_response) | [broadcast_survey_message](#helper-broadcast_survey_message)

### Helper: local_node_id

```
→ NodeId(PublicKeyTypeEd25519(own public key bytes))
```

### Helper: survey_local_ledger

```
tracking = herder.tracking_slot()
if tracking == 0:
  → current_ledger
→ tracking
```

### Helper: partition_peer_snapshots

```
inbound = []
outbound = []
for each snapshot:
  if Inbound → inbound.push(snapshot)
  if Outbound → outbound.push(snapshot)
→ (inbound, outbound)
```

### Helper: select_survey_peers

```
(inbound, outbound) = partition_peer_snapshots(
  snapshots)

"Sort by activity: most messages received first,
 then by connection time, then by peer_id"
sort inbound and outbound by activity

"Interleave outbound-first selection"
selected = []
while selected.len() < max_peers
    AND candidates remain:
  if outbound available:
    selected.push(outbound[next])
  if inbound available:
    selected.push(inbound[next])
→ selected
```

### Helper: sign_survey_message

```
sig = keypair.sign(message)
→ sig as XDR Signature
```

### Helper: merge_topology_response

```
existing.node_data = incoming.node_data
existing.inbound_peers.extend(incoming.inbound_peers)
existing.outbound_peers.extend(incoming.outbound_peers)
```

### Helper: verify_survey_signature

```
key_bytes = node_id_bytes(node_id)
GUARD key_bytes valid → false
public_key = PublicKey.from_bytes(key_bytes)
GUARD public_key valid → false
sig = Signature.from(signature)
GUARD sig valid → false
→ verify(public_key, message, sig)
```

### Helper: node_id_bytes

```
→ node_id as Ed25519 key bytes (32 bytes)
```

### surveyor_permitted

```
allowed_keys = config.overlay.surveyor_keys
if allowed_keys empty:
  quorum_nodes = herder.local_quorum_nodes()
  if quorum_nodes empty → false
  → surveyor_id in quorum_nodes

bytes = node_id_bytes(surveyor_id)
GUARD bytes valid → false

→ any key in allowed_keys where
    PublicKey.from_strkey(key).bytes == bytes
```

STATE_MACHINE: SurveyScheduler
  STATES: [Idle, StartSent, RequestSent]
  TRANSITIONS:
    Idle → StartSent: survey_start sent successfully
    StartSent → RequestSent: requests sent to peers
    StartSent → Idle: send failed
    RequestSent → Idle: stop sent + topology queued

### advance_survey_scheduler

```
CONST SURVEY_INTERVAL = 60s
CONST SURVEY_COLLECT_DELAY = 5s
CONST SURVEY_RESPONSE_WAIT = 5s
CONST SURVEY_MAX_PEERS = 4

now = current_time()
GUARD now >= scheduler.next_action → return

STATE_MACHINE SurveySchedulerPhase:

  Idle:
    GUARD not survey_data.active → wait
    GUARD not reporting.running → wait
    GUARD state is Synced or Validating → wait
    GUARD throttle interval elapsed → wait
    GUARD overlay available → wait

    peers = select_survey_peers(snapshots,
      SURVEY_MAX_PEERS)
    GUARD peers not empty → wait

    nonce = survey_nonce++ (wrapping)
    if send_survey_start(peers, nonce, ledger_num):
      → StartSent
      scheduler.next_action = now + SURVEY_COLLECT_DELAY
    else:
      → wait SURVEY_INTERVAL

  StartSent:
    if send_survey_requests(peers, nonce, ledger_num):
      → RequestSent
      scheduler.next_action = now + SURVEY_RESPONSE_WAIT
    else:
      survey_secrets.remove(nonce)
      → Idle (wait SURVEY_INTERVAL)

  RequestSent:
    send_survey_stop(peers, nonce, ledger_num)
    for each peer in peers:
      survey_topology_timesliced(peer, 0, 0)
    clear scheduler state
    → Idle (wait SURVEY_INTERVAL)
```

**Calls**: [select_survey_peers](#helper-select_survey_peers) | [send_survey_start](#send_survey_start) | [send_survey_requests](#send_survey_requests) | [send_survey_stop](#send_survey_stop) | [survey_topology_timesliced](#survey_topology_timesliced)

### update_survey_phase

```
GUARD overlay available → return
snapshots = overlay.peer_snapshots()
added = overlay.added_authenticated_peers()
dropped = overlay.dropped_authenticated_peers()

(inbound, outbound) = partition_peer_snapshots(
  snapshots)
lost_sync = lost_sync_count

survey_data.update_phase(
  inbound, outbound, added, dropped, lost_sync)

last_closed = current_ledger
survey_limiter.clear_old_ledgers(last_closed)
```

### send_survey_start (targeted)

"Send survey start to specific peers (vs broadcast)."

```
start = TimeSlicedSurveyStartCollectingMessage {
  surveyor_id: local_node_id, nonce, ledger_num
}
signature = sign_survey_message(encode(start))
signed = SignedTimeSlicedSurveyStartCollecting {
  signature, start_collecting: start
}

sent = send_survey_message(peers,
  TimeSlicedSurveyStartCollecting(signed))
if sent:
  survey_results[nonce] = empty map
  start_local_survey_collecting(start)
→ sent
```

**Calls**: [send_survey_message](#helper-send_survey_message) | [start_local_survey_collecting](#start_local_survey_collecting)

### send_survey_requests (targeted)

"Send survey requests to specific peers."

```
secret = ensure_survey_secret(nonce)
encryption_key = Curve25519Public from secret

for each peer:
  request = SurveyRequestMessage {
    surveyor = local_node_id,
    surveyed = peer,
    ledger_num, encryption_key,
    command = TimeSlicedSurveyTopology
  }
  message = TimeSlicedSurveyRequestMessage {
    request, nonce,
    inbound_peers_index=0, outbound_peers_index=0
  }
  signature = sign_survey_message(encode(message))
  signed = SignedTimeSlicedSurveyRequest {
    signature, request: message
  }
  send_survey_message([peer],
    TimeSlicedSurveyRequest(signed))

→ all sends ok
```

**Calls**: [ensure_survey_secret](#helper-ensure_survey_secret) | [sign_survey_message](#helper-sign_survey_message) | [send_survey_message](#helper-send_survey_message)

### send_survey_stop (targeted)

```
stop = TimeSlicedSurveyStopCollectingMessage {
  surveyor_id: local_node_id, nonce, ledger_num
}
signature = sign_survey_message(encode(stop))
signed = SignedTimeSlicedSurveyStopCollecting {
  signature, stop_collecting: stop
}

send_survey_message(peers,
  TimeSlicedSurveyStopCollecting(signed))
stop_local_survey_collecting(stop)
```

**Calls**: [send_survey_message](#helper-send_survey_message) | [stop_local_survey_collecting](#stop_local_survey_collecting)

### Helper: send_survey_message

```
GUARD overlay available → false
for each peer:
  overlay.send_to(peer, message)
→ all sends ok
```

### start_local_survey_collecting

```
GUARD overlay available → return
snapshots = overlay.peer_snapshots()
added = overlay.added_authenticated_peers()
dropped = overlay.dropped_authenticated_peers()

(inbound, outbound) = partition_peer_snapshots(
  snapshots)
lost_sync = lost_sync_count
out_of_sync = state is Initializing or CatchingUp

node_stats = NodeStatsSnapshot {
  lost_sync, out_of_sync, added, dropped
}
survey_data.start_collecting(
  message, inbound, outbound, node_stats)
```

### stop_local_survey_collecting

```
GUARD overlay available → return
snapshots = overlay.peer_snapshots()
added = overlay.added_authenticated_peers()
dropped = overlay.dropped_authenticated_peers()

(inbound, outbound) = partition_peer_snapshots(
  snapshots)
lost_sync = lost_sync_count

survey_data.stop_collecting(
  message, inbound, outbound,
  added, dropped, lost_sync)
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~1196  | ~380       |
| Functions     | 30     | 30         |
