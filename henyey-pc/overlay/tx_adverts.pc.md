## Pseudocode: crates/overlay/src/tx_adverts.rs

### Constants

```
CONST ADVERT_CACHE_SIZE = 50000
CONST TX_ADVERT_VECTOR_MAX_SIZE = 1000
CONST DEFAULT_ADVERT_PERIOD_MS = 100
```

### Data Structures

```
TxAdvertsConfig:
  advert_period: Duration           // flush period
  max_advert_size: int              // max hashes per advert message
  history_cache_size: int           // max history entries
  max_ops: int                      // limits incoming queue size

TxAdvertsState:
  incoming_tx_hashes: Deque<Hash>   // hashes to demand
  tx_hashes_to_retry: Deque<Hash>   // hashes to retry demanding
  advert_history: Map<Hash, {ledger_seq: int}>
  outgoing_tx_hashes: List<Hash>    // hashes to advertise
  batch_start_time: Timestamp or null

TxAdvertsStats:
  incoming_queue_size: int
  retry_queue_size: int
  outgoing_queue_size: int
  history_size: int
```

### new

```
function new(config):
  → TxAdverts with config and empty state
```

### set_send_callback

```
function set_send_callback(callback):
  MUTATE send_callback = callback
```

### size

```
function size():
  → incoming_tx_hashes.length + tx_hashes_to_retry.length
```

### has_adverts

```
function has_adverts():
  → size() > 0
```

### pop_incoming_advert

```
function pop_incoming_advert():
  "Retry queue has priority"
  if tx_hashes_to_retry is not empty:
    → tx_hashes_to_retry.pop_front()
  → incoming_tx_hashes.pop_front()
```

### queue_outgoing_advert

```
function queue_outgoing_advert(tx_hash):
  if outgoing_tx_hashes is empty:
    batch_start_time = now()

  append tx_hash to outgoing_tx_hashes

  if outgoing_tx_hashes.length >= config.max_advert_size:
    flush_advert()
```

### queue_incoming_advert

```
function queue_incoming_advert(tx_hashes, ledger_seq):
  "Remember all hashes in history"
  for each hash in tx_hashes:
    advert_history[hash] = {ledger_seq}

  "Trim history if too large (simple LRU-like eviction)"
  while advert_history.length > config.history_cache_size:
    remove oldest entry from advert_history

  "Add hashes to incoming queue, respecting limit"
  limit = config.max_ops
  if tx_hashes.length > limit:
    start_idx = tx_hashes.length - limit
  else:
    start_idx = 0

  for each hash in tx_hashes[start_idx..]:
    incoming_tx_hashes.push_back(hash)

  "Trim incoming queue if over limit"
  total_size = incoming_tx_hashes.length
             + tx_hashes_to_retry.length
  if total_size > limit:
    to_remove = total_size - limit
    for i in 0..to_remove:
      "Pop from incoming first, then retry"
      if not incoming_tx_hashes.pop_front():
        tx_hashes_to_retry.pop_front()
```

### retry_incoming_advert

```
function retry_incoming_advert(hashes):
  for each hash in hashes:
    tx_hashes_to_retry.push_back(hash)

  "Trim if over limit"
  total_size = incoming_tx_hashes.length
             + tx_hashes_to_retry.length
  if total_size > config.max_ops:
    to_remove = total_size - config.max_ops
    for i in 0..to_remove:
      if not incoming_tx_hashes.pop_front():
        tx_hashes_to_retry.pop_front()
```

### seen_advert

```
function seen_advert(hash):
  → advert_history contains hash
```

### clear_below

```
function clear_below(ledger_seq):
  remove entries from advert_history
    where entry.ledger_seq < ledger_seq
```

### flush_advert

```
function flush_advert():
  GUARD outgoing_tx_hashes is empty → return

  hashes = take outgoing_tx_hashes
  batch_start_time = null

  if send_callback is set:
    msg = FloodAdvert { tx_hashes: hashes }
    send_callback(msg)
```

### maybe_flush_on_timer

```
function maybe_flush_on_timer():
  if batch_start_time is set
     and elapsed(batch_start_time) >= config.advert_period:
    flush_advert()
    → true
  → false
```

### outgoing_size

```
function outgoing_size():
  → outgoing_tx_hashes.length
```

### stats

```
function stats():
  → TxAdvertsStats from current state
```

### shutdown

```
function shutdown():
  flush_advert()
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 312    | 115        |
| Functions     | 14     | 14         |
