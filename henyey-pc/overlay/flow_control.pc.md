# Pseudocode: crates/overlay/src/flow_control.rs

## Overview

"Flow control for Stellar overlay connections."

Implements flow control as specified in stellar-core's `FlowControl.h` and
`FlowControlCapacity.h`. Tracks two types of capacity: message count and
byte count. Messages are prioritized in outbound queues.

**Protocol:**
1. After authentication, peers exchange `SEND_MORE_EXTENDED` messages
2. Each `SEND_MORE_EXTENDED` grants capacity (messages and bytes)
3. When capacity exhausted, sender waits for more
4. Receiver sends `SEND_MORE_EXTENDED` after processing messages

---

### TRAIT ScpQueueCallback

"Abstracts herder dependency for intelligent SCP queue trimming."

```
TRAIT ScpQueueCallback:
  function min_slot_to_remember() → integer
  function most_recent_checkpoint_seq() → integer
```

---

### STRUCT FlowControlConfig

```
STRUCT FlowControlConfig:
  peer_flood_reading_capacity: integer     default 200
  peer_reading_capacity: integer           default 201
  flow_control_send_more_batch_size: integer  default 40
  outbound_tx_queue_byte_limit: integer    default 3 MB
  max_tx_set_size_ops: integer             default 10000
  flow_control_bytes_batch_size: integer   default 300 KB
```

---

### STRUCT SendMoreCapacity

```
STRUCT SendMoreCapacity:
  num_flood_messages: integer
  num_flood_bytes: integer
  num_total_messages: integer
```

### should_send

```
function should_send(self) → boolean:
  → num_flood_messages > 0 or num_flood_bytes > 0
```

---

### ENUM MessagePriority

"Lower values = higher priority."

```
ENUM MessagePriority:
  Scp = 0          "highest priority, critical for consensus"
  Transaction = 1
  FloodDemand = 2
  FloodAdvert = 3  "lowest priority"
  COUNT = 4
```

### from_message

```
function from_message(msg) → optional MessagePriority:
  if msg is ScpMessage → Scp
  if msg is Transaction → Transaction
  if msg is FloodDemand → FloodDemand
  if msg is FloodAdvert → FloodAdvert
  else → none
```

---

### is_flow_controlled_message

"These are message types that consume flow control capacity and are
 queued through the priority outbound queue. Survey messages are flooded
 at the network routing layer but do NOT consume flow control capacity."

```
function is_flow_controlled_message(msg) → boolean:
  → msg is Transaction, ScpMessage,
    FloodAdvert, or FloodDemand
```

---

### Helper: msg_body_size

"Get message body size in bytes without heap allocation."

```
function msg_body_size(msg) → integer:
  write msg as XDR to a counting-only writer
  → bytes counted
```

---

### STRUCT FlowControlMessageCapacity

```
STRUCT FlowControlMessageCapacity:
  capacity:
    flood_capacity: integer
    total_capacity: optional integer
  outbound_capacity: integer
```

### get_msg_resource_count (message)

```
function get_msg_resource_count(msg) → integer:
  → 1  "each message takes one unit"
```

### has_outbound_capacity (message)

```
function has_outbound_capacity(msg) → boolean:
  → outbound_capacity >= get_msg_resource_count(msg)
```

### lock_outbound_capacity (message)

```
function lock_outbound_capacity(msg):
  if is_flow_controlled_message(msg):
    count = get_msg_resource_count(msg)
    MUTATE outbound_capacity -= count
```

### lock_local_capacity (message)

```
function lock_local_capacity(msg) → boolean:
  resources = get_msg_resource_count(msg)

  if total_capacity is tracked:
    GUARD total_capacity < resources → false
    MUTATE total_capacity -= resources

  if is_flow_controlled_message(msg):
    GUARD flood_capacity < resources → false
    MUTATE flood_capacity -= resources

  → true
```

### release_local_capacity (message)

```
function release_local_capacity(msg) → integer:
  freed = get_msg_resource_count(msg)

  if total_capacity is tracked:
    MUTATE total_capacity += freed

  if is_flow_controlled_message(msg):
    MUTATE flood_capacity += freed
    → freed

  → 0
```

### release_outbound_capacity (message)

```
function release_outbound_capacity(num_messages):
  MUTATE outbound_capacity += num_messages
```

### can_read (message)

```
function can_read() → boolean:
  → total_capacity > 0 (or true if not tracked)
```

---

### STRUCT FlowControlByteCapacity

```
STRUCT FlowControlByteCapacity:
  capacity:
    flood_capacity: integer
  capacity_limits:
    flood_capacity: integer
  outbound_capacity: integer
```

### get_msg_resource_count (byte)

```
function get_msg_resource_count(msg) → integer:
  → msg_body_size(msg)
```

**Calls**: [msg_body_size](#helper-msg_body_size)

### lock_local_capacity (byte)

```
function lock_local_capacity(msg) → boolean:
  resources = get_msg_resource_count(msg)

  if is_flow_controlled_message(msg):
    GUARD flood_capacity < resources → false
    MUTATE flood_capacity -= resources

  → true
```

### release_local_capacity (byte)

```
function release_local_capacity(msg) → integer:
  freed = get_msg_resource_count(msg)

  if is_flow_controlled_message(msg):
    MUTATE flood_capacity += freed
    → freed

  → 0
```

### handle_tx_size_increase

```
function handle_tx_size_increase(increase):
  MUTATE capacity.flood_capacity += increase
  MUTATE capacity_limits.flood_capacity += increase
```

### can_read (byte)

```
function can_read() → boolean:
  → true  "byte capacity doesn't have total limit"
```

---

### STRUCT FlowControlState

```
STRUCT FlowControlState:
  message_capacity: FlowControlMessageCapacity
  byte_capacity: FlowControlByteCapacity
  outbound_queues: array[4] of Deque<QueuedOutboundMessage>
  advert_queue_tx_hash_count: integer
  demand_queue_tx_hash_count: integer
  tx_queue_byte_count: integer
  flood_data_processed: integer
  flood_data_processed_bytes: integer
  total_msgs_processed: integer
  no_outbound_capacity: optional timestamp
  last_throttle: optional timestamp
  peer_id: optional PeerId
```

---

### STRUCT FlowControl

```
STRUCT FlowControl:
  config: FlowControlConfig
  state: locked FlowControlState
  scp_callback: optional ScpQueueCallback
  dropped_scp: counter
  dropped_txs: counter
  dropped_adverts: counter
  dropped_demands: counter
```

---

### FlowControl::new

```
function new(config) → FlowControl:
  → with_scp_callback(config, none)
```

### FlowControl::with_scp_callback

```
function with_scp_callback(config, scp_callback) → FlowControl:
  initial_bytes_capacity =
    config.peer_flood_reading_capacity * config.flow_control_bytes_batch_size

  → FlowControl {
      state: {
        message_capacity: new from config,
        byte_capacity: new with initial_bytes_capacity,
        outbound_queues: 4 empty deques,
        all counters: 0,
        no_outbound_capacity: now,
      },
      config, scp_callback,
      all drop counters: 0,
    }
```

---

### has_outbound_capacity (static)

```
function has_outbound_capacity(state, msg) → boolean:
  → state.message_capacity.has_outbound_capacity(msg)
    AND state.byte_capacity.has_outbound_capacity(msg)
```

---

### maybe_release_capacity

"Release outbound capacity when receiving SEND_MORE_EXTENDED."

```
function maybe_release_capacity(self, msg):
  GUARD msg is not SendMoreExtended → return

  send_more = msg.send_more_data

  if no_outbound_capacity was set:
    MUTATE no_outbound_capacity = none

  MUTATE message_capacity.release_outbound(send_more.num_messages)
  MUTATE byte_capacity.release_outbound(send_more.num_bytes)
```

---

### handle_tx_size_increase

```
function handle_tx_size_increase(self, increase):
  if increase > 0:
    byte_capacity.handle_tx_size_increase(increase)
```

---

### add_msg_and_maybe_trim_queue

"Add message to outbound queue, potentially trimming obsolete messages."

```
function add_msg_and_maybe_trim_queue(self, msg):
  priority = MessagePriority::from_message(msg)
  GUARD priority is none → return

  queue_idx = priority as index

  "Track resource counts"
  if msg is Transaction:
    bytes = byte_capacity.get_msg_resource_count(msg)
    GUARD bytes > outbound_tx_queue_byte_limit → return  "reject oversized"
    MUTATE tx_queue_byte_count += bytes

  if msg is FloodDemand:
    MUTATE demand_queue_tx_hash_count += demand.tx_hashes.length

  if msg is FloodAdvert:
    MUTATE advert_queue_tx_hash_count += advert.tx_hashes.length

  "Add to queue"
  outbound_queues[queue_idx].push_back({
    message: msg, time_emplaced: now, being_sent: false
  })

  "Trim queue if over limits"
  limit = config.max_tx_set_size_ops
  dropped = 0

  if priority is Transaction:
    is_over_limit = queue.length > limit
      OR tx_queue_byte_count > outbound_tx_queue_byte_limit
    if is_over_limit:
      dropped = queue.length
      MUTATE tx_queue_byte_count = 0
      queue.clear()
      increment dropped_txs counter

  if priority is Scp:
    if queue.length > limit:
      dropped = trim_scp_queue(queue, limit, scp_callback)
      increment dropped_scp counter

  if priority is FloodAdvert:
    if advert_queue_tx_hash_count > limit:
      dropped = advert_queue_tx_hash_count
      MUTATE advert_queue_tx_hash_count = 0
      queue.clear()
      increment dropped_adverts counter

  if priority is FloodDemand:
    if demand_queue_tx_hash_count > limit:
      dropped = demand_queue_tx_hash_count
      MUTATE demand_queue_tx_hash_count = 0
      queue.clear()
      increment dropped_demands counter
```

**Calls**: [trim_scp_queue](#trim_scp_queue)

---

### trim_scp_queue

"Trim SCP outbound queue when it exceeds limit.
 Uses SCP callback for intelligent trimming:
 - Drops messages for slots below min_slot_to_remember (except checkpoint)
 - Replaces older nomination/ballot with newer ones from the back.
 Falls back to naive FIFO when no callback."

```
function trim_scp_queue(queue, limit, scp_callback) → integer:
  dropped = 0

  if scp_callback is available:
    min_slot = callback.min_slot_to_remember()
    checkpoint_seq = callback.most_recent_checkpoint_seq()
    value_replaced = false

    i = 0
    while i < queue.length:
      GUARD queue[i].being_sent → skip (i += 1)

      slot_index = extract slot from queue[i].message
      GUARD not ScpMessage → skip (i += 1)

      "Drop messages for old slots (except checkpoint)"
      if slot_index < min_slot AND slot_index != checkpoint_seq:
        queue.remove(i)
        dropped += 1
        continue

      "Replace older nomination/ballot with newer from back"
      if NOT value_replaced
         AND i+1 < queue.length
         AND back of queue is not being_sent:

        old_statement = queue[i].scp_statement
        new_statement = queue.back().scp_statement

        if is_newer_nomination_or_ballot(old, new):
            REF: henyey_scp::is_newer_nomination_or_ballot_st
          value_replaced = true
          replace queue[i] with queue.pop_back()
          dropped += 1
          i += 1
          continue

      i += 1

  else:
    "Fallback: naive FIFO trimming"
    while queue.length > limit / 2:
      if queue.front() is not being_sent:
        queue.pop_front()
        dropped += 1
      else:
        break

  → dropped
```

---

### get_next_batch_to_send

"Get next batch of messages to send. Returns messages we have capacity for."

```
function get_next_batch_to_send(self) → list of QueuedOutboundMessage:
  batch = empty list
  to_mark = empty list
  out_of_capacity = false

  "Iterate queues in priority order (SCP first, Advert last)"
  for queue_idx in 0..4:
    for msg_idx in 0..queue[queue_idx].length:
      queued_msg = queue[queue_idx][msg_idx]
      GUARD queued_msg.being_sent → skip

      if NOT has_outbound_capacity(state, queued_msg.message):
        out_of_capacity = true
        break all loops

      to_mark.add(queue_idx, msg_idx, queued_msg.message)
      batch.add(queued_msg)

  if out_of_capacity:
    MUTATE no_outbound_capacity = now

  "Mark messages as being sent and lock capacity"
  for each (queue_idx, msg_idx, msg) in to_mark:
    MUTATE queue[queue_idx][msg_idx].being_sent = true
    message_capacity.lock_outbound_capacity(msg)
    byte_capacity.lock_outbound_capacity(msg)

  → batch
```

---

### process_sent_messages

"Remove sent messages from front of queues and update byte counts."

```
function process_sent_messages(self, sent_messages):
  for each (queue_idx, sent_msgs) in sent_messages:
    for each msg in sent_msgs:
      GUARD queue[queue_idx] is empty → skip
      GUARD front of queue != msg → skip

      "Update resource counts"
      if msg is Transaction:
        bytes = byte_capacity.get_msg_resource_count(msg)
        MUTATE tx_queue_byte_count -= bytes

      if msg is FloodDemand:
        MUTATE demand_queue_tx_hash_count -= demand.tx_hashes.length

      if msg is FloodAdvert:
        MUTATE advert_queue_tx_hash_count -= advert.tx_hashes.length

      queue[queue_idx].pop_front()
```

---

### is_send_more_valid

```
function is_send_more_valid(self, msg):
  GUARD msg is not SendMoreExtended
    → error "unexpected message type"

  send_more = msg.send_more_data

  GUARD send_more.num_bytes == 0
    → error "must have non-zero bytes"

  "Check for overflow"
  msg_overflow = send_more.num_messages
    would overflow outbound message capacity
  byte_overflow = send_more.num_bytes
    would overflow outbound byte capacity

  GUARD msg_overflow or byte_overflow
    → error "Peer capacity overflow"
```

---

### begin_message_processing

"Locks local capacity. Returns false if no capacity."

```
function begin_message_processing(self, msg) → boolean:
  → message_capacity.lock_local_capacity(msg)
    AND byte_capacity.lock_local_capacity(msg)
```

---

### end_message_processing

"Releases local capacity. Returns how much to request from peer."

```
function end_message_processing(self, msg) → SendMoreCapacity:
  MUTATE flood_data_processed +=
    message_capacity.release_local_capacity(msg)
  MUTATE flood_data_processed_bytes +=
    byte_capacity.release_local_capacity(msg)
  MUTATE total_msgs_processed += 1

  should_send_more =
    flood_data_processed >= config.flow_control_send_more_batch_size
    OR flood_data_processed_bytes >= config.flow_control_bytes_batch_size

  result = SendMoreCapacity { all zeros }

  if total_msgs_processed >= config.peer_reading_capacity:
    result.num_total_messages = total_msgs_processed
    MUTATE total_msgs_processed = 0

  if should_send_more:
    result.num_flood_messages = flood_data_processed
    result.num_flood_bytes = flood_data_processed_bytes
    MUTATE flood_data_processed = 0
    MUTATE flood_data_processed_bytes = 0

  → result
```

---

### can_read

```
function can_read(self) → boolean:
  → message_capacity.can_read() AND byte_capacity.can_read()
```

---

### no_outbound_capacity_timeout

```
function no_outbound_capacity_timeout(self, timeout_secs) → boolean:
  if no_outbound_capacity timestamp exists:
    → elapsed >= timeout_secs
  → false
```

---

### maybe_throttle_read

```
function maybe_throttle_read(self) → boolean:
  if NOT message_capacity.can_read()
     OR NOT byte_capacity.can_read():
    MUTATE last_throttle = now
    → true
  → false
```

---

### stop_throttling

```
function stop_throttling(self) → optional duration:
  if last_throttle exists:
    duration = elapsed since last_throttle
    MUTATE last_throttle = none
    → duration
  → none
```

---

### is_throttled

```
function is_throttled(self) → boolean:
  → last_throttle is set
```

---

### get_stats

```
function get_stats(self) → FlowControlStats:
  → snapshot of all capacity values, queue sizes,
    byte counts, and throttle state
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 968    | 270        |
| Functions     | 30     | 30         |
