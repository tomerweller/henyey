## Pseudocode: crates/overlay/src/metrics.rs

### Counter

```
Counter:
  value: atomic int (initially 0)

function Counter.inc():
  MUTATE value += 1

function Counter.add(n):
  MUTATE value += n

function Counter.set(n):
  MUTATE value = n

function Counter.get():
  → value

function Counter.reset():
  prev = value
  MUTATE value = 0
  → prev
```

### Timer

```
Timer:
  total_duration_us: atomic int (initially 0)
  count: atomic int (initially 0)
  min_us: atomic int (initially MAX_INT)
  max_us: atomic int (initially 0)

function Timer.record(duration):
  us = duration_to_microseconds(duration)
  MUTATE total_duration_us += us
  MUTATE count += 1

  "Update min (compare-and-swap loop)"
  loop:
    current_min = min_us
    if us >= current_min: break
    if compare_and_swap(min_us, current_min, us): break

  "Update max"
  loop:
    current_max = max_us
    if us <= current_max: break
    if compare_and_swap(max_us, current_max, us): break

function Timer.start():
  → TimerGuard { timer: self, start: now() }
  NOTE: "Guard records duration when dropped/destroyed"

function Timer.count():
  → count

function Timer.total_duration():
  → microseconds_to_duration(total_duration_us)

function Timer.avg_duration():
  if count == 0: → zero_duration
  → microseconds_to_duration(total_duration_us / count)

function Timer.min_duration():
  if min_us == MAX_INT: → zero_duration
  → microseconds_to_duration(min_us)

function Timer.max_duration():
  → microseconds_to_duration(max_us)

function Timer.snapshot():
  → TimerSnapshot { count, total, avg, min, max }

function Timer.reset():
  MUTATE total_duration_us = 0
  MUTATE count = 0
  MUTATE min_us = MAX_INT
  MUTATE max_us = 0
```

### TimerGuard

```
on TimerGuard destruction:
  timer.record(elapsed_since(start))
```

### OverlayMetrics

"Comprehensive metrics for monitoring overlay operations.
All fields use atomic operations for thread safety."

```
OverlayMetrics:
  // --- Message metrics ---
  messages_read: Counter
  messages_written: Counter
  messages_dropped: Counter
  messages_broadcast: Counter

  // --- Byte metrics ---
  bytes_read: Counter
  bytes_written: Counter

  // --- Error metrics ---
  errors_read: Counter
  errors_write: Counter

  // --- Timeout metrics ---
  timeouts_idle: Counter
  timeouts_straggler: Counter

  // --- Connection metrics ---
  connection_latency: Timer
  connection_read_throttle: Timer
  connection_flood_throttle: Timer
  pending_peers: Counter
  authenticated_peers: Counter

  // --- Receive timers (processing time per msg type) ---
  recv_error: Timer
  recv_hello: Timer
  recv_auth: Timer
  recv_dont_have: Timer
  recv_peers: Timer
  recv_get_txset: Timer
  recv_txset: Timer
  recv_transaction: Timer
  recv_get_scp_qset: Timer
  recv_scp_qset: Timer
  recv_scp_message: Timer
  recv_get_scp_state: Timer
  recv_send_more: Timer
  recv_flood_advert: Timer
  recv_flood_demand: Timer
  recv_survey_request: Timer
  recv_survey_response: Timer

  // --- Send counters (per msg type) ---
  send_error: Counter
  send_hello: Counter
  send_auth: Counter
  send_dont_have: Counter
  send_peers: Counter
  send_get_txset: Counter
  send_transaction: Counter
  send_txset: Counter
  send_get_scp_qset: Counter
  send_scp_qset: Counter
  send_scp_message: Counter
  send_get_scp_state: Counter
  send_send_more: Counter
  send_flood_advert: Counter
  send_flood_demand: Counter
  send_survey_request: Counter
  send_survey_response: Counter

  // --- Queue metrics ---
  queue_delay_scp: Timer
  queue_delay_tx: Timer
  queue_delay_advert: Timer
  queue_delay_demand: Timer
  queue_drop_scp: Counter
  queue_drop_tx: Counter
  queue_drop_advert: Counter
  queue_drop_demand: Counter

  // --- Flood metrics ---
  flood_demanded: Counter
  flood_fulfilled: Counter
  flood_unfulfilled_banned: Counter
  flood_unfulfilled_unknown: Counter
  flood_unique_bytes_recv: Counter
  flood_duplicate_bytes_recv: Counter

  // --- Fetch metrics ---
  fetch_unique_bytes_recv: Counter
  fetch_duplicate_bytes_recv: Counter
  item_fetcher_next_peer: Counter

  // --- Pull metrics ---
  tx_pull_latency: Timer
  peer_tx_pull_latency: Timer
  demand_timeouts: Counter
  pulled_relevant_txs: Counter
  pulled_irrelevant_txs: Counter
  abandoned_demands: Counter
```

### snapshot

```
function snapshot():
  → OverlayMetricsSnapshot with all counter
    .get() values and timer .snapshot() values
```

### reset

```
function reset():
  for each counter in all_counters:
    counter.reset()
  for each timer in all_timers:
    timer.reset()
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 638    | 145        |
| Functions     | 14     | 14         |
