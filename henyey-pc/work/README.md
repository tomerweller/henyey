# work

Dependency-aware async work scheduler modeled after stellar-core's work scheduling system. Provides primitives for orchestrating units of work with dependency tracking, retry logic, concurrency limits, and cancellation support.

## Key Files

- [lib.pc.md](lib.pc.md) — Work scheduler with state machine, dependency tracking, and retry logic

## Architecture

The work scheduler is built around a `WorkState` state machine (Pending, Running, Success, Failed, Blocked, Cancelled). Work items transition from Pending to Running when their dependencies are satisfied and a concurrency slot is available. Failed work can be retried up to a configurable limit, and dependency failures propagate as Blocked states to downstream work items. The scheduler coordinates execution through an internal completion channel.

## All Files

| File | Description |
|------|-------------|
| [lib.pc.md](lib.pc.md) | Work scheduler with state machine, dependency tracking, and retry logic |
