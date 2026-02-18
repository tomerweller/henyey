## Pseudocode: crates/herder/src/sync_recovery.rs

"Out-of-sync detection and recovery for the Herder."
"Detects when consensus is stuck and initiates recovery."

```
CONST CONSENSUS_STUCK_TIMEOUT     = 35 seconds
CONST OUT_OF_SYNC_RECOVERY_INTERVAL = 5 seconds
CONST LEDGER_VALIDITY_BRACKET     = 15

STATE_MACHINE: SyncState
  STATES: [NotTracking, Tracking, OutOfSync]
  TRANSITIONS:
    NotTracking → Tracking:    start_tracking command
    Tracking    → OutOfSync:   stuck timer expires (no heartbeat)
    Tracking    → NotTracking: stop_tracking command
    OutOfSync   → Tracking:    heartbeat received or callback.is_tracking()
    OutOfSync   → NotTracking: stop_tracking command
```

### Data: SyncRecoveryCommand

```
SyncRecoveryCommand:
  TrackingHeartbeat
  StopTracking
  StartTracking
  SetApplyingLedger(bool)
  Shutdown
```

### Interface: SyncRecoveryCallback

```
SyncRecoveryCallback:
  on_lost_sync()            // transition to Syncing
  on_out_of_sync_recovery() // purge + broadcast + request
  is_applying_ledger() → bool
  is_tracking() → bool
  get_v_blocking_slots() → List<SlotIndex>
  purge_slots_below(slot)
  broadcast_latest_messages(from_slot)
  request_scp_state_from_peers()
```

### Data: SyncRecoveryManager

```
SyncRecoveryManager:
  callback:          SyncRecoveryCallback
  state:             SyncState
  tracking_deadline: Timestamp or null
  recovery_deadline: Timestamp or null
  is_applying:       bool
```

### SyncRecoveryHandle (async command sender)

```
function tracking_heartbeat():      send TrackingHeartbeat
function try_tracking_heartbeat():  non-blocking send
function stop_tracking():           send StopTracking
function start_tracking():          send StartTracking
function try_start_tracking():      non-blocking send
function set_applying_ledger(b):    send SetApplyingLedger(b)
function try_set_applying_ledger(b): non-blocking send
function shutdown():                send Shutdown
```

### new

```
function new(callback):
  channel = create_channel(capacity=64)
  handle = SyncRecoveryHandle(channel.sender)
  manager = SyncRecoveryManager {
    callback, state: NotTracking,
    tracking_deadline: null,
    recovery_deadline: null,
    is_applying: false
  }
  → (handle, manager)
```

### run

"Main event loop: processes commands and fires timers."

```
function run():
  loop:
    next_deadline = self.next_deadline()

    select:
      on command received:
        if TrackingHeartbeat:     handle_heartbeat()
        if StopTracking:          handle_stop_tracking()
        if StartTracking:         handle_start_tracking()
        if SetApplyingLedger(b):  is_applying = b
        if Shutdown or channel closed:
          break

      on timer fires (next_deadline):
        handle_timer_expired()
```

### handle_heartbeat

```
function handle_heartbeat():
  if state == Tracking:
    tracking_deadline = now() + CONSENSUS_STUCK_TIMEOUT

  else if state == OutOfSync:
    "Got activity while out of sync — back to tracking"
    state = Tracking
    tracking_deadline = now() + CONSENSUS_STUCK_TIMEOUT
    recovery_deadline = null
```

### handle_stop_tracking

```
function handle_stop_tracking():
  state = NotTracking
  tracking_deadline = null
  recovery_deadline = null
```

### handle_start_tracking

```
function handle_start_tracking():
  state = Tracking
  tracking_deadline = now() + CONSENSUS_STUCK_TIMEOUT
  recovery_deadline = null
```

### handle_timer_expired

```
function handle_timer_expired():
  now = current_time()

  if state == Tracking:
    if tracking_deadline is set and now >= tracking_deadline:
      on_tracking_timeout()

  if state == OutOfSync:
    if recovery_deadline is set and now >= recovery_deadline:
      on_recovery_timeout()
```

### on_tracking_timeout

```
function on_tracking_timeout():
  "If ledger application is in progress, just reset the timer"
  if is_applying or callback.is_applying_ledger():
    tracking_deadline = now() + CONSENSUS_STUCK_TIMEOUT
    → return

  "Consensus stuck — transition to out-of-sync"
  state = OutOfSync
  tracking_deadline = null

  callback.on_lost_sync()
  start_recovery()
```

### start_recovery

```
function start_recovery():
  perform_recovery()
  recovery_deadline = now() + OUT_OF_SYNC_RECOVERY_INTERVAL
```

### on_recovery_timeout

```
function on_recovery_timeout():
  if callback.is_tracking():
    "Now tracking — stop recovery"
    state = Tracking
    tracking_deadline = now() + CONSENSUS_STUCK_TIMEOUT
    recovery_deadline = null
    → return

  perform_recovery()
  recovery_deadline = now() + OUT_OF_SYNC_RECOVERY_INTERVAL
```

### perform_recovery

```
function perform_recovery():
  callback.on_out_of_sync_recovery()
```

### Helper: next_deadline

```
function next_deadline():
  if state == Tracking:  → tracking_deadline
  if state == OutOfSync: → recovery_deadline
  → null
```

### Data: SyncRecoveryStatsTracker

```
SyncRecoveryStats:
  lost_sync_count:    u64
  recovery_attempts:  u64
  is_out_of_sync:     bool

function record_lost_sync():
  MUTATE stats.lost_sync_count += 1
  MUTATE stats.is_out_of_sync = true

function record_recovery_attempt():
  MUTATE stats.recovery_attempts += 1

function record_back_in_sync():
  MUTATE stats.is_out_of_sync = false
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 453    | 112        |
| Functions     | 16     | 14         |
