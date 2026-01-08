# stellar-core-work

A dependency-aware async work scheduler for rs-stellar-core, modeled after the work scheduling system in stellar-core (C++).

## Overview

This crate provides primitives for scheduling and executing async work items with:

- **Dependency ordering**: Work items declare dependencies, and the scheduler ensures prerequisites complete before dependents run.
- **Concurrency control**: Configurable limit on simultaneously executing work items.
- **Automatic retries**: Work items can request retries with configurable delays and retry budgets.
- **Cooperative cancellation**: Work items receive cancellation signals and can respond appropriately.
- **Event streaming**: Optional channel for monitoring work state transitions.

## Architecture

### Execution Model

The scheduler uses a **directed acyclic graph (DAG)** execution model where:

- Work items are nodes in the graph
- Dependencies form directed edges between nodes
- Execution proceeds in topological order
- Failed nodes block all downstream dependents

```text
    [Download A]     [Download B]
          \              /
           \            /
            v          v
         [Verify Checksums]
                 |
                 v
           [Apply Changes]
```

In this example, "Verify Checksums" waits for both downloads to complete, and "Apply Changes" waits for verification.

### State Machine

Each work item progresses through a well-defined state machine:

```text
                     +----------+
                     | Pending  |
                     +----+-----+
                          |
             deps satisfied & slot available
                          |
                          v
                     +----------+
                     | Running  |
                     +----+-----+
                          |
       +--------+---------+---------+---------+
       |        |         |         |         |
       v        v         v         v         v
  +--------+ +------+ +-------+ +--------+ +-------+
  | Success| | Retry| | Failed| |Cancelled| |Blocked|
  +--------+ +------+ +-------+ +--------+ +-------+
                |
         (if retries remain)
                |
                v
           +----------+
           | Pending  |
           +----------+
```

**Terminal states**: Success, Failed, Blocked, Cancelled - work items in these states will not be executed again.

### Concurrency

The scheduler maintains a ready queue of work items whose dependencies have all succeeded. It spawns up to `max_concurrency` Tokio tasks to execute work items in parallel. When a task completes, its slot becomes available for the next ready item.

```text
Concurrency Slots: [Task A] [Task B] [Task C] [Empty]
Ready Queue:       [Task D] -> [Task E] -> [Task F]
```

## Key Types

### `Work` Trait

The core abstraction for schedulable work. Implement this trait for any async task:

```rust
#[async_trait]
pub trait Work: Send {
    /// Returns the name of this work item for logging and identification.
    fn name(&self) -> &str;

    /// Executes the work and returns an outcome.
    async fn run(&mut self, ctx: WorkContext) -> WorkOutcome;
}
```

**Implementation notes:**
- Work items receive `&mut self`, allowing them to maintain state across retry attempts
- The `name()` method should return a stable identifier for logging
- Check `ctx.is_cancelled()` periodically in long-running operations

### `WorkOutcome`

The result of a single work execution attempt:

| Variant | Description | Effect on Dependents |
|---------|-------------|---------------------|
| `Success` | Work completed successfully | Become runnable |
| `Retry { delay }` | Retry after the specified delay | Wait (no change) |
| `Failed(String)` | Terminal failure with error message | Blocked |
| `Cancelled` | Work was cancelled | Blocked |

**Retry behavior:**
- If `delay` is zero, the scheduler uses its configured `retry_delay`
- Retries only occur if the work item has remaining retry budget
- When retries are exhausted, `Retry` transitions to `Failed`

### `WorkState`

Current lifecycle state of a work item:

| State | Description | Terminal? |
|-------|-------------|-----------|
| `Pending` | Waiting for dependencies or a slot | No |
| `Running` | Currently executing | No |
| `Success` | Completed successfully | Yes |
| `Failed` | Failed permanently | Yes |
| `Blocked` | Dependency failed/cancelled | Yes |
| `Cancelled` | Explicitly cancelled | Yes |

### `WorkContext`

Execution context provided to a work item during execution:

```rust
pub struct WorkContext {
    pub id: WorkId,        // Unique identifier
    pub attempt: u32,      // Current attempt number (1-indexed)
    // ... internal fields
}

impl WorkContext {
    /// Returns true if cancellation has been requested.
    pub fn is_cancelled(&self) -> bool;

    /// Returns a reference to the cancellation token.
    pub fn cancel_token(&self) -> &CancellationToken;
}
```

### `WorkScheduler`

The main scheduler that manages work execution:

```rust
let mut scheduler = WorkScheduler::new(WorkSchedulerConfig {
    max_concurrency: 4,
    retry_delay: Duration::from_secs(1),
    event_tx: None,
});

// Add work items with dependencies
let id1 = scheduler.add_work(Box::new(work1), vec![], 3);  // 3 retries
let id2 = scheduler.add_work(Box::new(work2), vec![id1], 0);  // depends on id1

// Run until all work completes or is blocked
scheduler.run_until_done().await;

// Check results
assert_eq!(scheduler.state(id1), Some(WorkState::Success));
```

### `WorkSequence`

A helper for building linear chains of dependent work:

```rust
let mut sequence = WorkSequence::new();
sequence.push(&mut scheduler, Box::new(step1), 0);
sequence.push(&mut scheduler, Box::new(step2), 0);
sequence.push(&mut scheduler, Box::new(step3), 0);
// Execution order: step1 -> step2 -> step3

// Access all IDs in the sequence
let all_ids = sequence.ids();
```

### `WorkWithCallback`

A wrapper that invokes a callback after work completes:

```rust
let callback = Arc::new(|outcome, ctx| {
    println!("Work {} finished: {:?}", ctx.id, outcome);
});
let wrapped = WorkWithCallback::new(my_work, callback);
scheduler.add_work(Box::new(wrapped), vec![], 0);
```

## Cancellation

The scheduler supports cooperative cancellation at multiple levels:

### Individual Work Cancellation

```rust
// Cancel a specific work item
let cancelled = scheduler.cancel(id);
```

### Batch Cancellation

```rust
// Cancel all registered work items
scheduler.cancel_all();
```

### External Cancellation Control

```rust
let cancel_token = CancellationToken::new();
let token_clone = cancel_token.clone();

// Trigger cancellation from another task
tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(30)).await;
    token_clone.cancel();
});

// Run with external cancellation control
scheduler.run_until_done_with_cancel(cancel_token).await;
```

### Implementing Cancellation in Work Items

Work items should periodically check for cancellation and respond appropriately:

```rust
async fn run(&mut self, ctx: WorkContext) -> WorkOutcome {
    for chunk in self.data.chunks(1000) {
        // Check for cancellation between chunks
        if ctx.is_cancelled() {
            return WorkOutcome::Cancelled;
        }
        self.process_chunk(chunk).await?;
    }
    WorkOutcome::Success
}
```

For integration with async operations that support cancellation tokens:

```rust
async fn run(&mut self, ctx: WorkContext) -> WorkOutcome {
    tokio::select! {
        _ = ctx.cancel_token().cancelled() => WorkOutcome::Cancelled,
        result = self.long_running_operation() => {
            match result {
                Ok(_) => WorkOutcome::Success,
                Err(e) => WorkOutcome::Failed(e.to_string()),
            }
        }
    }
}
```

## Monitoring

### Event Streaming

Use `WorkSchedulerConfig::event_tx` to receive `WorkEvent` notifications:

```rust
let (event_tx, mut event_rx) = mpsc::channel(256);

let mut scheduler = WorkScheduler::new(WorkSchedulerConfig {
    event_tx: Some(event_tx),
    ..Default::default()
});

// Process events in a separate task
tokio::spawn(async move {
    while let Some(event) = event_rx.recv().await {
        println!("[{}] {} -> {:?}", event.id, event.name, event.state);
    }
});
```

### Metrics

Query aggregate statistics:

```rust
let metrics = scheduler.metrics();
println!("Total: {}, Success: {}, Failed: {}, Running: {}",
    metrics.total, metrics.success, metrics.failed, metrics.running);
```

### Snapshots

Get detailed state of all work items:

```rust
for item in scheduler.snapshot() {
    println!(
        "{}: {} - {:?} (attempts: {}, deps: {:?})",
        item.id, item.name, item.state, item.attempts, item.deps
    );
}
```

## Usage Patterns

### Parallel Downloads with Verification

```rust
// Download files in parallel
let downloads: Vec<WorkId> = files
    .iter()
    .map(|file| scheduler.add_work(Box::new(DownloadWork::new(file)), vec![], 3))
    .collect();

// Verify after all downloads complete
let verify_id = scheduler.add_work(
    Box::new(VerifyWork::new(&files)),
    downloads,  // depends on all downloads
    0,
);

scheduler.run_until_done().await;
```

### Retry with Exponential Backoff

```rust
struct BackoffWork {
    base_delay: Duration,
}

#[async_trait]
impl Work for BackoffWork {
    async fn run(&mut self, ctx: WorkContext) -> WorkOutcome {
        match self.try_operation().await {
            Ok(_) => WorkOutcome::Success,
            Err(_) => {
                // Exponential backoff: 1s, 2s, 4s, 8s...
                let delay = self.base_delay * 2u32.pow(ctx.attempt - 1);
                WorkOutcome::Retry { delay }
            }
        }
    }
}
```

### Pipeline Processing

```rust
let mut pipeline = WorkSequence::new();

// Each stage depends on the previous
pipeline.push(&mut scheduler, Box::new(FetchStage::new()), 3);
pipeline.push(&mut scheduler, Box::new(ParseStage::new()), 0);
pipeline.push(&mut scheduler, Box::new(ValidateStage::new()), 0);
pipeline.push(&mut scheduler, Box::new(ApplyStage::new()), 0);

scheduler.run_until_done().await;
```

## Design Notes

### Ownership Model

Work items are moved into the scheduler and remain there until it is dropped. During execution, work items are temporarily replaced with a placeholder to satisfy Rust's ownership rules. This allows:

- Stateful work items to maintain state across retries
- The scheduler to return work items after completion
- Efficient memory usage without cloning

### Thread Safety

- The scheduler itself is **not** thread-safe and should be driven from a single async task
- Work items execute on Tokio's thread pool and must be `Send`
- Shared state between work items should use appropriate synchronization (e.g., `Arc<Mutex<T>>`, channels)

### Ready Queue

The scheduler uses a simple ready-queue approach:
1. Work items whose dependencies have all succeeded are eligible for execution
2. Eligible items are started up to the concurrency limit
3. When work completes, newly eligible items are added to the queue

This provides predictable execution order while allowing maximum parallelism within dependency constraints.

## C++ Parity Status

This section documents the parity between this Rust crate and the upstream C++ work system in `stellar-core/src/work/`.

### Implemented

#### Core Work Abstractions
- **Work trait** (`Work` in Rust vs `BasicWork::onRun()` in C++): Async work execution with outcome-based state transitions
- **WorkOutcome enum**: Success, Retry, Failed, Cancelled outcomes matching C++ `BasicWork::State`
- **WorkState enum**: Pending, Running, Success, Failed, Blocked, Cancelled states
- **WorkContext**: Execution context with work ID, attempt number, and cancellation token

#### Scheduler Features
- **WorkScheduler**: Core scheduler with dependency tracking and concurrent execution
  - Dependency-aware execution (DAG model)
  - Configurable concurrency limits (`max_concurrency`)
  - Ready queue management with slot-based scheduling
- **Retry mechanism**: Configurable retry count and delay, matching C++ `maxRetries` and `getRetryDelay()`
- **Cancellation**: Individual work cancellation (`cancel(id)`) and batch cancellation (`cancel_all()`)
- **External cancellation control**: `run_until_done_with_cancel()` for external CancellationToken integration

#### Helper Types
- **WorkSequence**: Linear chain builder for sequential work dependencies (matches C++ `WorkSequence` concept)
- **WorkWithCallback**: Callback wrapper invoked after work completion (different from C++ version - see notes)

#### Monitoring and Introspection
- **WorkEvent**: State change events with work ID, name, state, and attempt number
- **WorkSchedulerMetrics**: Aggregate counts (total, pending, running, success, failed, blocked, cancelled, attempts, retries_left)
- **WorkSnapshot**: Point-in-time snapshot of individual work items with full state details

### Not Yet Implemented (Gaps)

#### C++ Class Hierarchy
- **BasicWork base class features**:
  - `RETRY_NEVER`, `RETRY_ONCE`, `RETRY_A_FEW`, `RETRY_A_LOT` constants (Rust uses raw `u32` retries)
  - `getStatus()` method returning formatted status string with state and retry ETA
  - `onReset()`, `onSuccess()`, `onFailureRetry()`, `onFailureRaise()` lifecycle hooks
  - `wakeUp()` and `wakeSelfUpCallback()` for WAITING state transitions
  - `setupWaitingCallback()` for timer-based waiting with automatic wake-up
  - `InternalState` distinction (PENDING, RUNNING, WAITING, ABORTING, ABORTED, RETRYING, SUCCESS, FAILURE)
  - State transition validation via `ALLOWED_TRANSITIONS` set
  - `isAborting()` for checking abort-in-progress state

- **Work class** (hierarchical work with children):
  - `addWork<T>()` / `addWorkWithCallback<T>()` for creating child work items
  - Round-robin child scheduling via `yieldNextRunningChild()`
  - `doWork()` pure virtual for local work after children are handled
  - `doReset()` for custom reset logic
  - `allChildrenSuccessful()`, `allChildrenDone()`, `anyChildRaiseFailure()`, `anyChildRunning()`, `hasChildren()`
  - `checkChildrenStatus()` utility
  - `shutdownChildren()` propagation
  - `mAbortChildrenButNotSelf` flag for graceful child abort before parent failure
  - `WorkUtils` namespace helpers: `getWorkStatus()`, `allSuccessful()`, `anyFailed()`, `anyRunning()`

- **WorkScheduler class** (C++ version):
  - Integration with Application's IO service (`postOnMainThread`)
  - `executeWork<T>()` synchronous execution until completion
  - `scheduleWork<T>()` returning shared_ptr to scheduled work
  - `TRIGGER_PERIOD` (50ms) for periodic crank scheduling
  - Yield checking via `shouldYield()` to avoid blocking main thread

- **BatchWork class**:
  - Parallel batching with configurable bandwidth (`MAX_CONCURRENT_SUBPROCESSES`)
  - Iterator-based work generation: `hasNext()`, `yieldMoreWork()`, `resetIter()`
  - Automatic cleanup of completed children from batch
  - Failure propagation (any child failure causes batch failure)
  - `getNumWorksInBatch()` for current batch size

- **ConditionalWork class**:
  - Monotonic condition function (`ConditionFn`) gating work execution
  - Polling with configurable `sleepDelay` (default 100ms)
  - Condition function cleanup after satisfaction (set to nullptr)
  - Delegation to conditioned work after condition is met
  - Status reporting showing waiting or delegated state

- **WorkWithCallback class** (C++ version):
  - Single-shot callback execution as work item
  - Takes `std::function<bool(Application&)>` returning success/failure
  - Exception handling with error logging
  - Note: Rust version wraps another work and calls callback on completion (different pattern)

#### Application Integration
- **VirtualClock integration**: Timer-based scheduling, `sleep_for`, `expires_from_now`
- **VirtualTimer**: Async timers for retry delays and waiting callbacks
- **Application context**: Access to `mApp` for clock, config, process manager, etc.
- **Tracy profiling**: `ZoneScoped` markers in critical paths
- **Logging integration**: `CLOG_*` macros with Work category

#### Advanced Features
- **WAITING state**: Work can pause and resume via timer or external wake-up
- **ABORTING state**: Graceful shutdown allowing work to clean up
- **State transition assertions**: Runtime validation of legal state transitions
- **Exponential backoff**: Built-in `getRetryDelay()` using `exponentialBackoff()` function
- **Retry ETA**: `getRetryETA()` for remaining time until next retry

### Implementation Notes

#### Architectural Differences

1. **Async Model**:
   - C++ uses cooperative scheduling via `crankWork()` calls on the main thread
   - Rust uses Tokio async tasks with true concurrent execution
   - C++ maintains explicit WAITING/RUNNING states; Rust work runs to completion or yields via async

2. **Ownership Model**:
   - C++ uses `shared_ptr` with reference counting and weak references
   - Rust moves work items into scheduler, uses placeholder during execution
   - C++ parent-child relationships; Rust flat dependency graph

3. **State Machine Simplification**:
   - C++ has 8 internal states (PENDING, RUNNING, WAITING, ABORTING, ABORTED, RETRYING, SUCCESS, FAILURE)
   - Rust has 6 states (Pending, Running, Success, Failed, Blocked, Cancelled)
   - Rust combines ABORTING/ABORTED into Cancelled, eliminates WAITING (async handles this)

4. **WorkSequence Design**:
   - C++ `WorkSequence` is a `BasicWork` subclass that manages a vector of work items internally
   - Rust `WorkSequence` is a helper that adds work items with auto-chained dependencies to an external scheduler
   - Rust approach is more flexible but less encapsulated

5. **WorkWithCallback Design**:
   - C++ `WorkWithCallback` wraps a callback function as work (executes callback, returns success/failure)
   - Rust `WorkWithCallback` wraps another work item and invokes callback after completion
   - Different use cases: C++ for inline logic, Rust for post-completion hooks

6. **Hierarchical vs Flat**:
   - C++ `Work` class supports parent-child hierarchies with round-robin child execution
   - Rust uses flat dependency graph with explicit `deps` vectors
   - C++ approach better for dynamic child creation; Rust approach simpler to reason about

7. **Timer Integration**:
   - C++ integrates with `VirtualClock` and `VirtualTimer` for retry scheduling
   - Rust uses `tokio::time::sleep` within async context
   - C++ can advance virtual time in tests; Rust relies on Tokio's test utilities

#### Design Decisions

- **No WAITING state**: Rust async naturally handles waiting; no explicit state needed
- **No hierarchical work**: Flat DAG model is sufficient for catchup/history workflows
- **No Application context**: Work items receive only `WorkContext`, not full app access
- **Simplified retry**: No exponential backoff built-in; work items control their own backoff logic
- **Event-based monitoring**: Uses channels instead of status strings for observability
