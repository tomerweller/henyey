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

## Status

Core parity with upstream stellar-core work scheduling:
- Dependency management
- Retry with configurable delays
- Cancellation propagation
- Metrics and introspection

Remaining gaps: app-wide metrics export wiring for Prometheus/observability integrations.
