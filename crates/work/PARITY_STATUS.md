# stellar-core Parity Status

**Overall Parity: ~90%**

This document tracks parity between `henyey-work` and the stellar-core work system in `stellar-core/src/work/`.

## stellar-core Source Files

| stellar-core File | Description | Rust Equivalent |
|----------|-------------|-----------------|
| `BasicWork.h/.cpp` | Base work class with state machine, retries, abort handling | `Work` trait, `WorkOutcome`, `WorkState` |
| `Work.h/.cpp` | Hierarchical work with parent-child relationships | Not implemented (flat DAG model instead) |
| `WorkScheduler.h/.cpp` | Top-level scheduler with IO service integration | `WorkScheduler` struct |
| `WorkSequence.h/.cpp` | Sequential work execution helper | `WorkSequence` struct |
| `WorkWithCallback.h/.cpp` | Single-shot callback as work item | `WorkWithCallback` (different design) |
| `BatchWork.h/.cpp` | Parallel batch execution with bandwidth control | Not implemented |
| `ConditionalWork.h/.cpp` | Condition-gated work execution | Not implemented |

## Parity Summary

| Feature | stellar-core | Rust | Notes |
|---------|-----|------|-------|
| Work trait/class | Yes | Yes | Different design (trait vs class hierarchy) |
| State machine | 8 states | 6 states | Rust simplifies by eliminating WAITING, ABORTING |
| Retry mechanism | Yes | Yes | stellar-core has exponential backoff built-in |
| Cancellation | Yes | Yes | Both support cooperative cancellation |
| Dependency ordering | Hierarchical | DAG | Rust uses flat graph with explicit deps |
| Concurrency control | Yes | Yes | `max_concurrency` / `MAX_CONCURRENT_SUBPROCESSES` |
| Work sequences | Yes | Yes | Different implementation approach |
| Batch work | Yes | No | stellar-core has iterator-based batch generation |
| Conditional work | Yes | No | stellar-core has monotonic condition gating |
| Event monitoring | Via status strings | Via channels | Rust uses `WorkEvent` channel |
| Metrics/snapshots | Via getStatus() | Via metrics()/snapshot() | Different introspection approach |

## Implemented

### Core Work Abstractions

- **`Work` trait**: Equivalent to stellar-core `BasicWork::onRun()`. Async work execution with outcome-based state transitions.
  - `name()` method matches stellar-core `getName()`
  - `run()` method matches stellar-core `onRun()` pure virtual

- **`WorkOutcome` enum**: Maps to stellar-core `BasicWork::State` return values:
  | Rust | stellar-core |
  |------|-----|
  | `Success` | `WORK_SUCCESS` |
  | `Retry { delay }` | `WORK_FAILURE` (with retries left) |
  | `Failed(String)` | `WORK_FAILURE` (no retries left) |
  | `Cancelled` | `WORK_ABORTED` |

- **`WorkState` enum**: Simplified state machine compared to stellar-core `InternalState`:
  | Rust | stellar-core InternalState |
  |------|-------------------|
  | `Pending` | `PENDING` |
  | `Running` | `RUNNING` |
  | `Success` | `SUCCESS` |
  | `Failed` | `FAILURE` |
  | `Blocked` | (no direct equivalent - Rust-specific for dep failures) |
  | `Cancelled` | `ABORTED` |
  | (handled via async) | `WAITING` |
  | (handled via async) | `RETRYING` |
  | (merged into Cancelled) | `ABORTING` |

- **`WorkContext`**: Execution context provided to work items:
  - `id: WorkId` - unique work identifier
  - `attempt: u32` - current attempt number (1-indexed)
  - `is_cancelled()` - check cancellation status
  - `cancel_token()` - access underlying `CancellationToken`

### Scheduler Features

- **`WorkScheduler`**: Core scheduler matching stellar-core `WorkScheduler` functionality:
  - `add_work()` - register work with dependencies and retry count
  - `run_until_done()` - execute all work to completion
  - `run_until_done_with_cancel()` - execute with external cancellation token
  - `cancel()` / `cancel_all()` - cancellation APIs
  - `state()` - query work state
  - `metrics()` - aggregate statistics
  - `snapshot()` - detailed work item snapshots

- **`WorkSchedulerConfig`**:
  - `max_concurrency` - equivalent to stellar-core `MAX_CONCURRENT_SUBPROCESSES`
  - `retry_delay` - default delay between retries
  - `event_tx` - optional channel for monitoring

- **Dependency handling**:
  - Work items declare dependencies via `deps: Vec<WorkId>` parameter
  - Scheduler uses DAG model for topological execution order
  - Failed/cancelled work blocks all dependents (`WorkState::Blocked`)

### Helper Types

- **`WorkSequence`**: Linear chain builder (different from stellar-core design):
  - stellar-core `WorkSequence` is a `BasicWork` subclass managing internal work vector
  - Rust `WorkSequence` is a helper adding work with auto-chained deps to external scheduler
  - Both achieve sequential execution semantics

- **`WorkWithCallback`**: Post-completion callback wrapper (different from stellar-core design):
  - stellar-core version wraps a callback function as the work itself
  - Rust version wraps another work item and calls callback after completion
  - Rust design better for instrumentation/logging; stellar-core design for inline logic

### Monitoring and Introspection

- **`WorkEvent`**: State change notifications via channel:
  - `id`, `name`, `state`, `attempt` fields
  - Sent via `try_send` to avoid blocking scheduler

- **`WorkSchedulerMetrics`**: Aggregate counts:
  - `total`, `pending`, `running`, `success`, `failed`, `blocked`, `cancelled`
  - `attempts` (total execution attempts across all work)
  - `retries_left` (remaining retry budget)

- **`WorkSnapshot`**: Point-in-time work item state:
  - `id`, `name`, `state`, `deps`, `dependents`
  - `attempts`, `retries_left`, `last_error`
  - `last_duration`, `total_duration`

## Not Implemented (Gaps)

### stellar-core Class Hierarchy Features

**BasicWork features not in Rust**:
- `RETRY_NEVER` (0), `RETRY_ONCE` (1), `RETRY_A_FEW` (5), `RETRY_A_LOT` (32) constants
- `getStatus()` formatted status string with state and retry ETA
- `onReset()`, `onSuccess()`, `onFailureRetry()`, `onFailureRaise()` lifecycle hooks
- `wakeUp()` / `wakeSelfUpCallback()` for WAITING state transitions
- `setupWaitingCallback()` for timer-based waiting
- `ALLOWED_TRANSITIONS` state transition validation
- `isAborting()` state check
- `getRetryDelay()` with exponential backoff via `exponentialBackoff()`
- `getRetryETA()` for time until next retry

**Work class (hierarchical) not in Rust**:
- `addWork<T>()` / `addWorkWithCallback<T>()` for child work
- Round-robin child scheduling via `yieldNextRunningChild()`
- `doWork()` pure virtual for local work
- `doReset()` for custom reset logic
- `allChildrenSuccessful()`, `allChildrenDone()`, `anyChildRaiseFailure()`, `anyChildRunning()`, `hasChildren()`
- `checkChildrenStatus()`, `shutdownChildren()`
- `mAbortChildrenButNotSelf` flag
- `WorkUtils` namespace helpers

### Missing stellar-core Classes

**BatchWork** (parallel batch execution):
- Configurable bandwidth via `MAX_CONCURRENT_SUBPROCESSES`
- Iterator-based work generation: `hasNext()`, `yieldMoreWork()`, `resetIter()`
- Automatic cleanup of completed children
- Failure propagation (any child failure causes batch failure)

**ConditionalWork** (condition-gated execution):
- Monotonic condition function (`ConditionFn`) gating work
- Polling with configurable `sleepDelay` (default 100ms)
- Delegation to conditioned work after condition satisfied

### Application Integration (Not Applicable)

These stellar-core features rely on stellar-core's Application context and are handled differently in Rust:
- `VirtualClock` / `VirtualTimer` integration (Rust uses Tokio timers)
- `postOnMainThread` scheduling (Rust uses async tasks)
- `shouldYield()` cooperative yielding (Rust async yields naturally)
- `mApp` application context access (Rust work has no app access)
- Tracy profiling markers (can be added if needed)
- `CLOG_*` logging macros (Rust uses `tracing` crate)

## Architectural Differences

### 1. Async Model

| Aspect | stellar-core | Rust |
|--------|-----|------|
| Execution model | Cooperative via `crankWork()` on main thread | True async via Tokio tasks |
| Waiting | Explicit `WORK_WAITING` state | Implicit via `async`/`.await` |
| Concurrency | Round-robin child scheduling | Parallel task execution up to limit |
| Timer integration | `VirtualTimer` with `async_wait` | `tokio::time::sleep` |

### 2. Ownership Model

| Aspect | stellar-core | Rust |
|--------|-----|------|
| Work ownership | `shared_ptr` with reference counting | Moved into scheduler |
| During execution | Shared via weak pointers | Replaced with `EmptyWork` placeholder |
| Parent-child | Hierarchical references | Flat with dependency IDs |

### 3. State Machine Simplification

stellar-core has 8 internal states with explicit transition validation:
```
PENDING -> RUNNING -> WAITING -> SUCCESS/FAILURE/RETRYING -> ABORTING -> ABORTED
```

Rust has 6 states with simpler transitions:
```
Pending -> Running -> Success/Failed/Cancelled/Blocked
```

Key simplifications:
- WAITING eliminated (async naturally handles waiting)
- RETRYING merged into retry loop logic
- ABORTING merged into Cancelled
- Blocked added for dependency failure propagation

### 4. Design Decisions

| Decision | Rationale |
|----------|-----------|
| No WAITING state | Rust async naturally handles waiting via `.await` |
| No hierarchical work | Flat DAG model sufficient for catchup/history workflows |
| No Application context | Work receives minimal `WorkContext`, not full app |
| No exponential backoff | Work items control their own backoff in `run()` |
| Event channels vs strings | Channel-based monitoring more suitable for async |

## Test Coverage

The Rust implementation includes integration tests for:
- Dependency ordering (`test_dependency_ordering`)
- Retry behavior (`test_retry_then_success`)
- Work sequences (`test_work_sequence_ordering`)
- Callback wrappers (`test_work_callback`)
- Cancellation (`test_cancel_work`)
- Metrics and snapshots (`test_metrics_snapshot`)

Test file: `crates/henyey-work/tests/scheduler.rs`

## Future Considerations

If additional stellar-core parity is needed:

1. **BatchWork equivalent**: Could be implemented as a work generator pattern with the existing scheduler
2. **ConditionalWork equivalent**: Could use async condition variables or channels
3. **Lifecycle hooks**: Could add optional trait methods for `on_success`, `on_failure`, etc.
4. **Retry constants**: Could add `RetryPolicy` enum with predefined strategies
5. **Exponential backoff**: Could add configurable backoff strategy to `WorkSchedulerConfig`
