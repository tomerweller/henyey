## Pseudocode: crates/overlay/src/tx_demands.rs

### Constants

```
CONST MAX_RETRY_COUNT = 15
CONST MAX_DELAY_DEMAND = 2 seconds
CONST TX_DEMAND_VECTOR_MAX_SIZE = 1000
CONST DEFAULT_DEMAND_PERIOD_MS = 500
CONST DEFAULT_BACKOFF_DELAY_MS = 50
```

### Data Structures

```
TxDemandsConfig:
  demand_period: Duration
  backoff_delay: Duration
  max_demand_size: int
  max_retry_count: int

STATE_MACHINE: DemandStatus
  STATES: [Demand, RetryLater, Discard]

TxKnownStatus:
  STATES: [Unknown, Known, Banned]

DemandHistory:
  first_demanded: Timestamp
  last_demanded: Timestamp
  peers: Map<PeerId, Timestamp>
  latency_recorded: bool

TxDemandsState:
  demand_history: Map<Hash, DemandHistory>
  pending_demands: Deque<Hash>
  running: bool

PeerDemandResult:
  to_demand: List<Hash>
  to_retry: List<Hash>

TxPullLatency:
  total_latency: Duration
  peer_latency: Duration or null
  peers_asked: int

CleanupResult:
  abandoned: int
  cleaned: int
```

### new

```
function new(config):
  → TxDemandsManager with config and empty state
```

### start

```
function start():
  MUTATE state.running = true
```

### shutdown

```
function shutdown():
  MUTATE state.running = false
```

### is_running

```
function is_running():
  → state.running
```

### retry_delay

"Uses linear backoff: delay = num_attempts * backoff_delay, capped at MAX_DELAY_DEMAND."

```
function retry_delay(num_attempts):
  delay = config.backoff_delay * num_attempts
  → min(delay, MAX_DELAY_DEMAND)
```

### demand_status

```
function demand_status(tx_hash, peer_id):
  "Check transaction status via callback"
  if tx_status_fn is set:
    status = tx_status_fn(tx_hash)
    GUARD status is Known or Banned → Discard

  history = demand_history[tx_hash]

  if history is null:
    "Never demanded this transaction"
    → Demand

  "Check if we've already demanded from this peer"
  GUARD peer_id in history.peers → Discard

  num_demanded = history.peers.length

  if num_demanded < config.max_retry_count:
    delay = retry_delay(num_demanded)
    if elapsed_since(history.last_demanded) >= delay:
      → Demand
    else:
      → RetryLater
  else:
    "Max retries exceeded"
    → Discard
```

### process_adverts

```
function process_adverts(hashes, peer_id, max_demand):
  to_demand = []
  to_retry = []

  for each hash in hashes:
    if to_demand.length >= max_demand:
      "Already have enough demands, retry the rest"
      append hash to to_retry
      continue

    status = demand_status(hash, peer_id)
    if status is Demand:
      append hash to to_demand
    else if status is RetryLater:
      append hash to to_retry
    else:  // Discard
      skip

  → PeerDemandResult { to_demand, to_retry }
```

### record_demands

"Call this after sending a FloodDemand message."

```
function record_demands(hashes, peer_id):
  now = current_time()

  for each hash in hashes:
    is_new = hash not in demand_history
    if is_new:
      "First time demanding this hash"
      pending_demands.push_back(hash)
      demand_history[hash] = DemandHistory(now)

    history = demand_history[hash]
    history.peers[peer_id] = now
    MUTATE history.last_demanded = now
```

### record_tx_received

"Returns the pull latency if this was the first time receiving it."

```
function record_tx_received(tx_hash, peer_id):
  history = demand_history[tx_hash]
  GUARD history is null → null

  "Record end-to-end pull time (only once)"
  GUARD history.latency_recorded → null

  total_latency = elapsed_since(history.first_demanded)
  num_peers_asked = history.peers.length
  MUTATE history.latency_recorded = true

  "Record peer-specific latency if we demanded from this peer"
  peer_latency = null
  if peer_id in history.peers:
    peer_latency = elapsed_since(history.peers[peer_id])

  → TxPullLatency {
      total_latency,
      peer_latency,
      peers_asked: num_peers_asked
    }
```

### cleanup_old_demands

"Returns the number of abandoned demands (never received)."

```
function cleanup_old_demands():
  "Maximum retention time: 2 * MAX_RETRY_COUNT * MAX_DELAY_DEMAND"
  max_retention = MAX_DELAY_DEMAND * config.max_retry_count * 2
  abandoned = 0
  cleaned = 0

  while pending_demands is not empty:
    hash = pending_demands.front()
    history = demand_history[hash]

    if history is null:
      "Hash in queue but not in map — clean up"
      pending_demands.pop_front()
      continue

    if elapsed_since(history.first_demanded) >= max_retention:
      if not history.latency_recorded:
        "We never received this transaction"
        abandoned += 1
      remove hash from demand_history
      pending_demands.pop_front()
      cleaned += 1
    else:
      "Oldest demand is not old enough yet"
      break

  → CleanupResult { abandoned, cleaned }
```

### recv_demand

"Handle an incoming FloodDemand message. Returns transactions to send back."

```
function recv_demand(demand):
  GUARD get_tx_fn is not set → empty list

  result = []
  for each hash in demand.tx_hashes:
    tx = get_tx_fn(hash)
    if tx is not null:
      append tx to result

  → result
```

### stats

```
function stats():
  → TxDemandsStats {
      pending_demands: pending_demands.length,
      demand_history_size: demand_history.length,
      running: state.running
    }
```

### pending_count

```
function pending_count():
  → pending_demands.length
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 497    | 145        |
| Functions     | 14     | 14         |
