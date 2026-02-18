## Pseudocode: work/lib.rs

"Work scheduler and orchestration primitives. Dependency-aware async
work scheduler modeled after stellar-core's work scheduling system."

CONST COMPLETION_CHANNEL_CAPACITY = 128  // internal channel size

STATE_MACHINE: WorkState
  STATES: [Pending, Running, Success, Failed, Blocked, Cancelled]
  TRANSITIONS:
    Pending → Running: deps satisfied & concurrency slot available
    Running → Success: work returned Success
    Running → Failed: work returned Failed or exhausted retries
    Running → Cancelled: cancellation detected
    Running → Pending: work returned Retry (if retries remain)
    Pending → Blocked: a dependency failed/cancelled/blocked

### is_terminal
```
→ state in {Success, Failed, Blocked, Cancelled}
```

### is_success
```
→ state == Success
```

### is_failure
```
→ state in {Failed, Blocked, Cancelled}
```

### WorkContext.is_cancelled
```
→ cancel_token.is_cancelled()
```

### WorkWithCallback.run
```
outcome = inner_work.run(ctx)
callback(outcome, ctx)
→ outcome
```

**Calls**: [Work.run](#work-trait)

### WorkScheduler.new
```
→ scheduler with:
    config = provided config
    next_id = 1
    entries = empty map
    states = empty map
    dependents = empty map
```

### add_work
```
function add_work(work, deps, retries) → work_id:
    id = next_id
    next_id += 1

    "register reverse dependency edges"
    for each dep in deps:
        dependents[dep].append(id)

    entries[id] = new WorkEntry:
        name = work.name()
        deps = deps
        retries_left = retries
        attempts = 0
        cancel_token = new cancel token
        work = work

    states[id] = Pending
    → id
```

**Calls**: [Work.name](#work-trait)

### state
```
function state(id) → work_state or nothing:
    → states[id] if exists, else nothing
```

### cancel
```
function cancel(id) → bool:
    GUARD states[id] exists       → false
    GUARD state is not terminal   → false

    entry = entries[id]
    trigger entry.cancel_token
    fail_or_cancel(id, Cancelled, entry.attempts)
    → true
```

**Calls**: [fail_or_cancel](#fail_or_cancel)

### cancel_all
```
function cancel_all():
    for each id in entries.keys():
        cancel(id)
```

**Calls**: [cancel](#cancel)

### snapshot
```
function snapshot() → list of WorkSnapshot:
    snapshots = for each (id, entry) in entries:
        WorkSnapshot:
            id, name, state, deps, dependents,
            attempts, retries_left, last_error,
            last_duration, total_duration
    sort snapshots by id
    → snapshots
```

### metrics
```
function metrics() → WorkSchedulerMetrics:
    metrics.total = entries.len()
    for each (id, entry) in entries:
        increment metrics counter for states[id]
        metrics.attempts += entry.attempts
        metrics.retries_left += entry.retries_left
    → metrics
```

### run_until_done
```
function run_until_done():
    cancel_token = new (untriggered) cancel token
    run_until_done_with_cancel(cancel_token)
```

**Calls**: [run_until_done_with_cancel](#run_until_done_with_cancel)

### run_until_done_with_cancel
```
function run_until_done_with_cancel(cancel):
    create completion channel (capacity = 128)
    running = empty set
    queue = ready_queue()
    queued = set of queue contents
    cancel_requested = false

    loop:
        "--- Phase 1: check cancellation ---"
        if not cancel_requested and cancel.is_cancelled():
            cancel_requested = true
            cancel_all()

        "--- Phase 2: fill concurrency slots ---"
        while running.size < max_concurrency:
            id = queue.pop_front()
            GUARD id exists             → break
            GUARD id not in running     → skip
            GUARD can_run(id)           → skip

            entry = entries[id]
            if entry.cancel_token.is_cancelled():
                fail_or_cancel(id, Cancelled, entry.attempts)
                continue

            entry.attempts += 1
            work = take work from entry (replace with placeholder)
            entry.started_at = now()
            states[id] = Running
            emit_event(id, Running, attempt)
            running.add(id)

            spawn async:
                outcome = work.run(WorkContext{id, attempt, cancel_token})
                send WorkCompletion{id, outcome, work, attempt, cancelled}

        "--- Phase 3: check for termination ---"
        GUARD running not empty or queue not empty → break

        "--- Phase 4: wait for completion ---"
        if cancel_requested:
            completion = receive from channel
        else:
            select:
                cancel triggered:
                    cancel_requested = true
                    cancel_all()
                    continue
                completion received from channel

        GUARD completion received → break
        running.remove(completion.id)

        cancelled = completion.cancelled
            or states[completion.id] == Cancelled

        "--- Phase 5: handle outcome ---"
        if outcome is Cancelled:
            fail_or_cancel(id, Cancelled, attempt)
            finalize_entry(id, work)

        else if outcome is Success:
            if cancelled:
                fail_or_cancel(id, Cancelled, attempt)
            else:
                states[id] = Success
                emit_event(id, Success, attempt)
            finalize_entry(id, work)
            enqueue_dependents(id, queue, queued, running)

        else if outcome is Retry{delay}:
            if cancelled:
                fail_or_cancel(id, Cancelled, attempt)
                continue
            if entry.retries_left == 0:
                finalize_entry(id, work)
                fail_or_cancel(id, Failed, attempt)
                continue
            entry.retries_left -= 1
            finalize_entry(id, work)
            retry_delay = delay if delay > 0, else config.retry_delay
            emit_event(id, Pending, attempt)
            sleep(retry_delay)
            queue.push_back(id)

        else if outcome is Failed(err):
            if cancelled:
                fail_or_cancel(id, Cancelled, attempt)
                continue
            entry.last_error = err
            finalize_entry(id, work)
            fail_or_cancel(id, Failed, attempt)
```

**Calls**: [ready_queue](#ready_queue) | [can_run](#can_run) | [fail_or_cancel](#fail_or_cancel) | [finalize_entry](#finalize_entry) | [emit_event](#emit_event) | [enqueue_dependents](#enqueue_dependents) | [cancel_all](#cancel_all)

### Helper: ready_queue
```
function ready_queue() → deque of work_ids:
    → all ids where states[id] == Pending
```

### Helper: enqueue_dependents
```
function enqueue_dependents(completed_id, queue, queued, running):
    children = dependents[completed_id]
    GUARD children exist → return

    for each child in children:
        GUARD child not in running            → skip
        GUARD states[child] == Pending        → skip
        if can_run(child) and child not in queued:
            queue.push_back(child)
            queued.add(child)
```

**Calls**: [can_run](#can_run)

### Helper: can_run
```
function can_run(id) → bool:
    entry = entries[id]
    GUARD entry exists → false
    → all deps have states[dep] == Success
```

### Helper: block_dependents
```
function block_dependents(id):
    children = dependents[id]
    for each child in children:
        if states[child] == Pending:
            states[child] = Blocked
            emit_event(child, Blocked, 0)
```

**Calls**: [emit_event](#emit_event)

### Helper: fail_or_cancel
```
function fail_or_cancel(id, state, attempt):
    states[id] = state
    emit_event(id, state, attempt)
    block_dependents(id)
```

**Calls**: [emit_event](#emit_event) | [block_dependents](#block_dependents)

### Helper: finalize_entry
```
function finalize_entry(id, work):
    entry = entries[id]
    GUARD entry exists → return

    if work provided:
        entry.work = work      "restore real work (replace placeholder)"
    if entry.started_at set:
        elapsed = now() - entry.started_at
        entry.last_duration = elapsed
        entry.total_duration += elapsed
```

### Helper: emit_event
```
function emit_event(id, state, attempt):
    GUARD config.event_tx exists → return
    name = entries[id].name or "unknown"
    try_send WorkEvent{id, name, state, attempt}
    "dropped silently if channel full"
```

### WorkSequence.push
```
function push(scheduler, work, retries) → work_id:
    deps = [last id in sequence] if any, else []
    id = scheduler.add_work(work, deps, retries)
    ids.append(id)
    → id
```

**Calls**: [add_work](#add_work)

### WorkSequence.ids
```
→ ids list
```

## Summary
| Metric | Source | Pseudocode |
|--------|--------|------------|
| Lines (logic) | ~550 (excl. docs, enums, structs, tests) | ~210 |
| Functions | 21 | 21 |
