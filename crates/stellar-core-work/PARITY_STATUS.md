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
