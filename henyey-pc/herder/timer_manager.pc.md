## Pseudocode: crates/herder/src/timer_manager.rs

"Timer management for SCP consensus timeouts."
"Schedules and fires nomination and ballot timeouts per slot."

### Data: TimerCommand

```
TimerCommand:
  ScheduleNominationTimeout(slot, duration)
  ScheduleBallotTimeout(slot, duration)
  CancelSlotTimers(slot)
  CancelNominationTimer(slot)
  CancelBallotTimer(slot)
  PurgeOldSlots(min_slot)
  Shutdown
```

### Data: TimerType

```
TimerType: Nomination | Ballot
```

### Interface: TimerCallback

```
TimerCallback:
  on_nomination_timeout(slot)
  on_ballot_timeout(slot)
```

### Data: TimerManager

```
TimerManager:
  callback:   TimerCallback
  timers:     Map<(SlotIndex, TimerType), ActiveTimer>
  generation: u64

ActiveTimer:
  timer_type: TimerType
  slot:       SlotIndex
  expires_at: Timestamp
  generation: u64
```

### TimerManagerHandle (async command sender)

```
function schedule_nomination_timeout(slot, duration):
  send ScheduleNominationTimeout(slot, duration)
function schedule_ballot_timeout(slot, duration):
  send ScheduleBallotTimeout(slot, duration)
function cancel_slot_timers(slot):
  send CancelSlotTimers(slot)
function cancel_nomination_timer(slot):
  send CancelNominationTimer(slot)
function cancel_ballot_timer(slot):
  send CancelBallotTimer(slot)
function purge_old_slots(min_slot):
  send PurgeOldSlots(min_slot)
function shutdown():
  send Shutdown

"Non-blocking variants:"
function try_schedule_nomination_timeout(slot, dur): ...
function try_schedule_ballot_timeout(slot, dur): ...
function try_cancel_slot_timers(slot): ...
```

### new

```
function new(callback):
  channel = create_channel(capacity=256)
  handle = TimerManagerHandle(channel.sender)
  manager = TimerManager {
    callback, timers: {}, generation: 0
  }
  → (handle, manager)
```

### run

"Main event loop: processes commands and fires expired timers."

```
function run():
  loop:
    next_timeout = self.next_timeout()

    select:
      on command received:
        if ScheduleNominationTimeout(slot, dur):
          schedule_timer(slot, Nomination, dur)
        if ScheduleBallotTimeout(slot, dur):
          schedule_timer(slot, Ballot, dur)
        if CancelSlotTimers(slot):
          cancel_slot_timers(slot)
        if CancelNominationTimer(slot):
          cancel_timer(slot, Nomination)
        if CancelBallotTimer(slot):
          cancel_timer(slot, Ballot)
        if PurgeOldSlots(min_slot):
          purge_old_slots(min_slot)
        if Shutdown or channel closed:
          break

      on timer fires (next_timeout):
        fire_expired_timers()
```

### schedule_timer

```
function schedule_timer(slot, timer_type, duration):
  generation += 1
  expires_at = now() + duration

  timer = ActiveTimer {
    timer_type, slot, expires_at, generation
  }

  "Insert or replace timer for (slot, timer_type)"
  timers[(slot, timer_type)] = timer
```

### cancel_slot_timers

```
function cancel_slot_timers(slot):
  timers.remove((slot, Nomination))
  timers.remove((slot, Ballot))
```

### cancel_timer

```
function cancel_timer(slot, timer_type):
  timers.remove((slot, timer_type))
```

### purge_old_slots

```
function purge_old_slots(min_slot):
  timers.retain(entries where slot >= min_slot)
```

### Helper: next_timeout

```
function next_timeout():
  → min(timer.expires_at for all timers) or null
```

### fire_expired_timers

```
function fire_expired_timers():
  now = current_time()

  expired = all timers where expires_at <= now

  for each (key, timer_type, slot) in expired:
    timers.remove(key)

    if timer_type == Nomination:
      callback.on_nomination_timeout(slot)
    if timer_type == Ballot:
      callback.on_ballot_timeout(slot)
```

### TimerManagerWithStats

"Wraps TimerManager with stats tracking."

```
Data: TimerStats:
  nomination_timers: int
  ballot_timers:     int
  total_timers:      int

function update_stats():
  nomination_count = count timers where type == Nomination
  ballot_count     = count timers where type == Ballot
  MUTATE stats.nomination_timers = nomination_count
  MUTATE stats.ballot_timers     = ballot_count
  MUTATE stats.total_timers      = timers.length

function run():
  "Same event loop as TimerManager, but calls
   update_stats() at the start of each iteration."
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 456    | 113        |
| Functions     | 13     | 12         |
