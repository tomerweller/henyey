## Pseudocode: crates/herder/src/tx_broadcast.rs

"Transaction broadcast management."
"Broadcasts transactions in surge-pricing order with rate limiting."

```
CONST DEFAULT_FLOOD_PERIOD_MS = 100

STATE_MACHINE: BroadcastState
  STATES: [Idle, Waiting, Shutdown]
  TRANSITIONS:
    Idle    → Waiting:  broadcast or rebroadcast requested
    Waiting → Idle:     all transactions broadcast
    Waiting → Waiting:  more transactions remain (reschedule)
    *       → Shutdown: shutdown command received
```

### Data: BroadcastCommand

```
BroadcastCommand:
  Broadcast                      // start a broadcast cycle
  Rebroadcast                    // rebroadcast all transactions
  AddTransaction(tx_hash, envelope)
  RemoveTransaction(tx_hash)
  MarkBroadcast(tx_hash)
  SetFloodPeriod(period_ms)
  Shutdown
```

### Data: TxBroadcastManager

```
TxBroadcastManager:
  callback:       TxBroadcastCallback
  pending:        Map<Hash, PendingTx>
  broadcast_set:  Set<Hash>
  state:          BroadcastState
  flood_period:   Duration
  next_broadcast: Timestamp or null
```

### Interface: TxBroadcastCallback

```
TxBroadcastCallback:
  broadcast_transaction(envelope) → bool
  get_flood_capacity() → int
  get_transactions_by_priority()
    → List<(tx_hash, envelope, already_broadcast)>
```

### TxBroadcastHandle (async command sender)

```
function broadcast():           send Broadcast
function rebroadcast():         send Rebroadcast
function add_transaction(h,e):  send AddTransaction(h, e)
function remove_transaction(h): send RemoveTransaction(h)
function mark_broadcast(h):     send MarkBroadcast(h)
function set_flood_period(ms):  send SetFloodPeriod(ms)
function shutdown():            send Shutdown
function try_add_transaction(h,e):
  → non-blocking send AddTransaction(h, e)
```

### new

```
function new(callback):
  channel = create_channel(capacity=256)
  handle = TxBroadcastHandle(channel.sender)
  manager = TxBroadcastManager {
    callback, pending: {}, broadcast_set: {},
    state: Idle,
    flood_period: DEFAULT_FLOOD_PERIOD_MS,
    next_broadcast: null
  }
  → (handle, manager)
```

### run

"Main event loop: processes commands and fires broadcast timer."

```
function run():
  loop:
    select:
      on command received:
        if Broadcast:       start_broadcast_cycle()
        if Rebroadcast:     rebroadcast()
        if AddTransaction:  add_transaction(hash, env)
        if RemoveTransaction: remove_transaction(hash)
        if MarkBroadcast:   broadcast_set.add(hash)
        if SetFloodPeriod:  flood_period = period_ms
        if Shutdown or channel closed:
          state = Shutdown
          break

      on timer fires (next_broadcast):
        if state == Waiting:
          broadcast_some()
```

### start_broadcast_cycle

```
function start_broadcast_cycle():
  GUARD state == Shutdown → return

  state = Waiting
  next_broadcast = now() + flood_period
```

### rebroadcast

```
function rebroadcast():
  GUARD state == Shutdown → return

  broadcast_set.clear()

  for each pending_tx in pending.values():
    pending_tx.broadcast_count = 0
    pending_tx.last_broadcast = null

  start_broadcast_cycle()
```

### broadcast_some

```
function broadcast_some():
  GUARD state == Shutdown → return

  capacity = callback.get_flood_capacity()
  broadcast_count = 0

  transactions = callback.get_transactions_by_priority()

  for each (tx_hash, envelope, already_broadcast) in transactions:
    if broadcast_count >= capacity:
      break
    if already_broadcast or broadcast_set contains tx_hash:
      continue

    if callback.broadcast_transaction(envelope):
      broadcast_set.add(tx_hash)
      broadcast_count += 1

      if pending contains tx_hash:
        MUTATE pending[tx_hash].broadcast_count += 1
        MUTATE pending[tx_hash].last_broadcast = now()

  "Check if more un-broadcast transactions remain"
  more_to_broadcast = any tx where
    not already_broadcast and not in broadcast_set

  if more_to_broadcast and broadcast_count > 0:
    next_broadcast = now() + flood_period
  else:
    state = Idle
    next_broadcast = null
```

### add_transaction

```
function add_transaction(tx_hash, envelope):
  pending[tx_hash] = PendingTx {
    envelope, broadcast_count: 0,
    last_broadcast: null
  }
```

### remove_transaction

```
function remove_transaction(tx_hash):
  pending.remove(tx_hash)
  broadcast_set.remove(tx_hash)
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 383    | 108        |
| Functions     | 13     | 10         |
