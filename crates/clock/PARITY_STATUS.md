# stellar-core Parity Status

**Crate**: `henyey-clock`
**Upstream**: `No direct stellar-core source equivalent`
**Overall Parity**: 100%
**Last Updated**: 2026-04-26

## Summary

| Area | Status | Notes |
|------|--------|-------|
| Clock trait | Full | Object-safe injectable timing facade |
| Monotonic time reads | Full | `Clock::now()` backed by `Instant` |
| Wall-clock reads | Full | Default `Clock::system_now()` |
| Async delay primitive | Full | Default `Clock::sleep()` uses tokio |
| Production clock | Full | `RealClock` implements the full scoped API |
| Manual virtual time | None | Intentionally outside this crate |
| Timer handles | None | Intentionally delegated to async futures |

`henyey-clock` is an internal deterministic/runtime clock abstraction. It has
no direct stellar-core source directory to mirror; parity is calculated against
the scoped crate API that henyey callers depend on.

## File Mapping

| Scoped Component | Rust Module | Notes |
|------------------|-------------|-------|
| Clock injection facade | `src/lib.rs` | `Clock` trait with `now`, `system_now`, and `sleep` |
| Production runtime clock | `src/lib.rs` | `RealClock` delegates to `Instant`, `SystemTime`, and tokio |

## Component Mapping

### clock facade (`src/lib.rs`)

Corresponds to: scoped henyey runtime clock API.

| Scoped capability | Rust | Status |
|-------------------|------|--------|
| Injectable clock trait | `Clock` | Full |
| Monotonic timestamp | `Clock::now()` | Full |
| Wall-clock timestamp | `Clock::system_now()` | Full |
| Async sleep | `Clock::sleep()` | Full |
| Production implementation | `RealClock` | Full |

## Intentional Omissions

Features excluded by design. These are NOT counted against parity %.

| stellar-core Component | Reason |
|------------------------|--------|
| `VirtualClock` event-loop ownership | Tokio owns scheduling and wakeups in henyey |
| Manual virtual-time stepping | Simulation crates advance deterministic state directly |
| Explicit timer handles and event nodes | Async sleeps are represented as futures |
| Calendar/time conversion helpers | Rust standard library call sites handle conversions |
| Background-work accounting | Task ownership and metrics live in higher-level crates |

## Gaps

No known gaps.

## Architectural Differences

1. **Scoped clock facade**
   - **stellar-core**: `VirtualClock` combines clock reads, event-loop ownership, timer queues, and simulation stepping.
   - **Rust**: `Clock` exposes only clock reads and async sleep.
   - **Rationale**: Executor behavior belongs to tokio and workflow crates, not a timing facade.

2. **Production implementation**
   - **stellar-core**: Runtime mode is selected through `VirtualClock::Mode`.
   - **Rust**: `RealClock` is the only crate-local implementation.
   - **Rationale**: Current callers need dependency injection and real-time behavior; deterministic stepping is owned by simulation code.

3. **Timer representation**
   - **stellar-core**: Timers are explicit objects with cancellation and queue inspection.
   - **Rust**: Delays are futures returned by `Clock::sleep()`.
   - **Rationale**: This matches async Rust and avoids duplicating tokio timer state.

## Test Coverage

| Area | stellar-core Tests | Rust Tests | Notes |
|------|-------------------|------------|-------|
| Scoped clock API | No direct equivalent | 4 `#[test]` / `#[tokio::test]` | Covers monotonic time, sleep, wall time, and pre-epoch panic expectations |
| Omitted event-loop surface | Not applicable | 0 `#[test]` | Excluded from crate scope |

### Test Gaps

No scoped test gaps are known. Event-loop and manual virtual-time behavior are
outside the crate's API and are therefore not counted as gaps.

## Parity Calculation

| Category | Count |
|----------|-------|
| Implemented (Full) | 5 |
| Gaps (None + Partial) | 0 |
| Intentional Omissions | 5 |
| **Parity** | **5 / (5 + 0) = 100%** |
