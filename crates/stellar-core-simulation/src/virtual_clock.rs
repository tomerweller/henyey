//! Virtual clock for deterministic time control in simulations.
//!
//! This module provides a `VirtualClock` abstraction that enables deterministic
//! testing by controlling the passage of time. It supports two modes:
//!
//! - **Virtual Time**: Time advances instantly under program control, enabling
//!   tests to run at maximum speed without waiting for wall-clock time.
//! - **Real Time**: Time advances according to the actual wall clock, useful
//!   for integration testing with real network operations.
//!
//! # Overview
//!
//! The `VirtualClock` is inspired by the upstream C++ `VirtualClock` class in
//! `stellar-core/src/util/Timer.h`. It provides:
//!
//! - Configurable time modes (virtual vs real)
//! - Event scheduling with time-based triggers
//! - Crank-based event loop advancement for deterministic testing
//! - Thread-safe time queries
//!
//! # Example
//!
//! ```ignore
//! use stellar_core_simulation::VirtualClock;
//! use std::time::Duration;
//!
//! // Create a virtual clock for deterministic testing
//! let mut clock = VirtualClock::virtual_time();
//!
//! // Schedule an event for 1 second in the future
//! clock.schedule_after(Duration::from_secs(1), || {
//!     println!("Event triggered!");
//! });
//!
//! // Advance time to trigger the event
//! clock.advance_by(Duration::from_secs(1));
//!
//! // Crank to process the event
//! let processed = clock.crank();
//! assert_eq!(processed, 1);
//! ```
//!
//! # Parity with C++
//!
//! This implementation provides the core functionality of the C++ VirtualClock:
//!
//! - `now()` / `system_now()` - Time queries
//! - `setCurrentVirtualTime()` → `set_virtual_time()` / `advance_by()`
//! - `sleep_for()` → `sleep_for()` (virtual advance or real sleep)
//! - `crank()` → `crank()` - Event loop advancement
//! - Event scheduling and cancellation
//!
//! The main architectural difference is that Rust uses Tokio for async runtime
//! instead of ASIO, so the integration with async I/O differs.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// =============================================================================
// Constants
// =============================================================================

/// Maximum events to process per crank cycle.
///
/// This prevents a single crank from running indefinitely when events
/// continuously schedule more events.
const CRANK_EVENT_SLICE: usize = 100;

/// Maximum duration for a single crank cycle in real time mode.
const CRANK_TIME_SLICE: Duration = Duration::from_millis(500);

/// Base time for virtual mode system clock (early 1970).
///
/// In virtual mode, system time is calculated as this base plus the
/// virtual time offset. This matches the C++ implementation.
const VIRTUAL_BASE_SYSTEM_TIME: u64 = 365 * 24 * 60 * 60; // ~1 year after epoch

// =============================================================================
// ClockMode
// =============================================================================

/// The operating mode of a VirtualClock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockMode {
    /// Virtual time mode - time advances instantly under program control.
    ///
    /// In this mode:
    /// - `now()` returns the virtual time point
    /// - `sleep_for()` advances virtual time instead of blocking
    /// - `crank()` can advance time to the next scheduled event
    ///
    /// This is the preferred mode for unit and integration tests as it
    /// eliminates timing-dependent test flakiness and runs tests at
    /// maximum speed.
    VirtualTime,

    /// Real time mode - time advances according to the wall clock.
    ///
    /// In this mode:
    /// - `now()` returns the actual monotonic time
    /// - `sleep_for()` actually blocks the thread
    /// - `crank()` processes events that have reached their scheduled time
    ///
    /// This mode is useful for integration testing with real network
    /// operations or when testing timing-sensitive behavior.
    RealTime,
}

// =============================================================================
// VirtualClockEvent
// =============================================================================

/// A unique identifier for scheduled events.
pub type EventId = u64;

/// An event scheduled on a VirtualClock.
///
/// Events are stored in a priority queue ordered by scheduled time (earliest
/// first) and sequence number (for tie-breaking).
struct VirtualClockEvent {
    /// When the event should trigger.
    when: Instant,
    /// Sequence number for deterministic ordering of same-time events.
    seq: u64,
    /// The callback to execute when triggered.
    callback: Box<dyn FnOnce() + Send + 'static>,
    /// Whether this event has been cancelled.
    cancelled: Arc<AtomicBool>,
}

impl VirtualClockEvent {
    fn new(when: Instant, seq: u64, callback: impl FnOnce() + Send + 'static) -> Self {
        Self {
            when,
            seq,
            callback: Box::new(callback),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(AtomicOrdering::Acquire)
    }
}

// Implement Ord for BinaryHeap (min-heap by negating comparison)
impl Ord for VirtualClockEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap (earliest time first)
        match other.when.cmp(&self.when) {
            Ordering::Equal => other.seq.cmp(&self.seq),
            ord => ord,
        }
    }
}

impl PartialOrd for VirtualClockEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for VirtualClockEvent {}

impl PartialEq for VirtualClockEvent {
    fn eq(&self, other: &Self) -> bool {
        self.when == other.when && self.seq == other.seq
    }
}

// =============================================================================
// EventHandle
// =============================================================================

/// A handle to a scheduled event that can be used to cancel it.
///
/// When dropped without being explicitly cancelled, the event will still fire.
/// Call `cancel()` to prevent the event from executing.
#[derive(Clone)]
pub struct EventHandle {
    cancelled: Arc<AtomicBool>,
    id: EventId,
}

impl EventHandle {
    /// Cancels this event, preventing it from executing.
    ///
    /// If the event has already executed, this is a no-op.
    pub fn cancel(&self) {
        self.cancelled.store(true, AtomicOrdering::Release);
    }

    /// Returns the unique ID of this event.
    pub fn id(&self) -> EventId {
        self.id
    }

    /// Returns true if this event has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(AtomicOrdering::Acquire)
    }
}

// =============================================================================
// VirtualClock
// =============================================================================

/// A clock that can operate in virtual or real time mode.
///
/// In virtual time mode, time only advances when explicitly requested via
/// `advance_by()`, `set_virtual_time()`, or `crank()`. This enables
/// deterministic testing without wall-clock dependencies.
///
/// In real time mode, the clock tracks actual wall-clock time.
///
/// # Thread Safety
///
/// The clock is thread-safe and can be shared across threads. Time queries
/// and event scheduling are protected by internal synchronization.
pub struct VirtualClock {
    /// Operating mode.
    mode: ClockMode,

    /// The virtual time point (only used in VirtualTime mode).
    /// Stored as nanoseconds since the start instant.
    virtual_nanos: AtomicU64,

    /// The starting instant (used to anchor virtual time).
    start_instant: Instant,

    /// Next event sequence number.
    next_seq: AtomicU64,

    /// Priority queue of scheduled events.
    events: Mutex<BinaryHeap<VirtualClockEvent>>,

    /// Statistics tracking.
    stats: RwLock<ClockStats>,
}

/// Statistics about clock operation.
#[derive(Debug, Clone, Default)]
pub struct ClockStats {
    /// Total events scheduled.
    pub events_scheduled: u64,
    /// Total events triggered.
    pub events_triggered: u64,
    /// Total events cancelled.
    pub events_cancelled: u64,
    /// Total crank cycles.
    pub crank_cycles: u64,
    /// Total time advanced (in virtual mode).
    pub time_advanced_nanos: u64,
}

impl VirtualClock {
    /// Creates a new virtual clock in virtual time mode.
    ///
    /// This is the recommended mode for testing as it provides deterministic
    /// timing behavior and runs tests at maximum speed.
    pub fn virtual_time() -> Self {
        Self::new(ClockMode::VirtualTime)
    }

    /// Creates a new virtual clock in real time mode.
    ///
    /// In this mode, time advances according to the actual wall clock.
    pub fn real_time() -> Self {
        Self::new(ClockMode::RealTime)
    }

    /// Creates a new virtual clock with the specified mode.
    pub fn new(mode: ClockMode) -> Self {
        Self {
            mode,
            virtual_nanos: AtomicU64::new(0),
            start_instant: Instant::now(),
            next_seq: AtomicU64::new(0),
            events: Mutex::new(BinaryHeap::new()),
            stats: RwLock::new(ClockStats::default()),
        }
    }

    /// Returns the current mode of this clock.
    pub fn mode(&self) -> ClockMode {
        self.mode
    }

    /// Returns the current time as an `Instant`.
    ///
    /// In virtual time mode, returns the virtual time point.
    /// In real time mode, returns the actual monotonic time.
    pub fn now(&self) -> Instant {
        match self.mode {
            ClockMode::VirtualTime => {
                let nanos = self.virtual_nanos.load(AtomicOrdering::Acquire);
                self.start_instant + Duration::from_nanos(nanos)
            }
            ClockMode::RealTime => Instant::now(),
        }
    }

    /// Returns the current time as nanoseconds since clock creation.
    pub fn now_nanos(&self) -> u64 {
        match self.mode {
            ClockMode::VirtualTime => self.virtual_nanos.load(AtomicOrdering::Acquire),
            ClockMode::RealTime => self.start_instant.elapsed().as_nanos() as u64,
        }
    }

    /// Returns the current system time.
    ///
    /// In virtual time mode, returns a time point based on `UNIX_EPOCH` plus
    /// the virtual time offset (starting from early 1970).
    ///
    /// In real time mode, returns the actual system time.
    pub fn system_now(&self) -> SystemTime {
        match self.mode {
            ClockMode::VirtualTime => {
                let nanos = self.virtual_nanos.load(AtomicOrdering::Acquire);
                let secs = VIRTUAL_BASE_SYSTEM_TIME + nanos / 1_000_000_000;
                let subsec_nanos = (nanos % 1_000_000_000) as u32;
                UNIX_EPOCH + Duration::new(secs, subsec_nanos)
            }
            ClockMode::RealTime => SystemTime::now(),
        }
    }

    /// Sets the virtual time to a specific point.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - The clock is in real time mode
    /// - The specified time is before the current virtual time
    pub fn set_virtual_time(&self, instant: Instant) {
        assert_eq!(
            self.mode,
            ClockMode::VirtualTime,
            "set_virtual_time only valid in VirtualTime mode"
        );

        let nanos = instant
            .saturating_duration_since(self.start_instant)
            .as_nanos() as u64;

        let current = self.virtual_nanos.load(AtomicOrdering::Acquire);
        assert!(
            nanos >= current,
            "cannot set virtual time backwards: current={}, requested={}",
            current,
            nanos
        );

        let advanced = nanos - current;
        self.virtual_nanos.store(nanos, AtomicOrdering::Release);

        if let Ok(mut stats) = self.stats.write() {
            stats.time_advanced_nanos += advanced;
        }
    }

    /// Advances the virtual time by the specified duration.
    ///
    /// # Panics
    ///
    /// Panics if the clock is in real time mode.
    pub fn advance_by(&self, duration: Duration) {
        assert_eq!(
            self.mode,
            ClockMode::VirtualTime,
            "advance_by only valid in VirtualTime mode"
        );

        let nanos = duration.as_nanos() as u64;
        self.virtual_nanos
            .fetch_add(nanos, AtomicOrdering::AcqRel);

        if let Ok(mut stats) = self.stats.write() {
            stats.time_advanced_nanos += nanos;
        }
    }

    /// Sleeps for the specified duration.
    ///
    /// In virtual time mode, this advances the virtual clock instantly.
    /// In real time mode, this actually blocks the calling thread.
    pub fn sleep_for(&self, duration: Duration) {
        match self.mode {
            ClockMode::VirtualTime => self.advance_by(duration),
            ClockMode::RealTime => std::thread::sleep(duration),
        }
    }

    /// Schedules an event to fire at the specified instant.
    ///
    /// Returns an `EventHandle` that can be used to cancel the event.
    pub fn schedule_at(
        &self,
        when: Instant,
        callback: impl FnOnce() + Send + 'static,
    ) -> EventHandle {
        let seq = self.next_seq.fetch_add(1, AtomicOrdering::Relaxed);
        let event = VirtualClockEvent::new(when, seq, callback);
        let cancelled = event.cancelled.clone();

        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }

        if let Ok(mut stats) = self.stats.write() {
            stats.events_scheduled += 1;
        }

        EventHandle { cancelled, id: seq }
    }

    /// Schedules an event to fire after the specified duration.
    ///
    /// Returns an `EventHandle` that can be used to cancel the event.
    pub fn schedule_after(
        &self,
        delay: Duration,
        callback: impl FnOnce() + Send + 'static,
    ) -> EventHandle {
        let when = self.now() + delay;
        self.schedule_at(when, callback)
    }

    /// Processes pending events, returning the number of events triggered.
    ///
    /// In virtual time mode with `advance_to_next=true`, if no events are ready,
    /// the clock advances to the time of the next scheduled event and then
    /// processes events at that time.
    ///
    /// # Arguments
    ///
    /// * `advance_to_next` - If true and no events are ready, advance virtual
    ///   time to the next scheduled event (only in VirtualTime mode).
    ///
    /// # Returns
    ///
    /// The number of events that were triggered during this crank cycle.
    pub fn crank_with_options(&self, advance_to_next: bool) -> usize {
        let crank_start = Instant::now();
        let mut total_triggered = 0;
        let mut advanced = false;

        loop {
            let now = self.now();
            let mut triggered = 0;

            // Collect events that are ready to fire
            let mut ready_events = Vec::new();

            if let Ok(mut events) = self.events.lock() {
                while let Some(event) = events.peek() {
                    if event.when <= now {
                        if let Some(e) = events.pop() {
                            ready_events.push(e);
                        }
                    } else {
                        break;
                    }

                    // Limit events per crank cycle
                    if ready_events.len() >= CRANK_EVENT_SLICE {
                        break;
                    }

                    // Limit real time per crank cycle
                    if self.mode == ClockMode::RealTime && crank_start.elapsed() > CRANK_TIME_SLICE
                    {
                        break;
                    }
                }
            }

            // Execute ready events
            for event in ready_events {
                if !event.is_cancelled() {
                    (event.callback)();
                    triggered += 1;
                } else if let Ok(mut stats) = self.stats.write() {
                    stats.events_cancelled += 1;
                }
            }

            total_triggered += triggered;

            // In virtual time mode, advance to next event if nothing was triggered
            // and we haven't already advanced this cycle
            if self.mode == ClockMode::VirtualTime
                && advance_to_next
                && triggered == 0
                && !advanced
            {
                let should_advance = if let Ok(events) = self.events.lock() {
                    events.peek().map(|e| e.when).filter(|&t| t > self.now())
                } else {
                    None
                };

                if let Some(next_time) = should_advance {
                    self.set_virtual_time(next_time);
                    advanced = true;
                    continue; // Process events at the new time
                }
            }

            break;
        }

        // Update stats
        if let Ok(mut stats) = self.stats.write() {
            stats.events_triggered += total_triggered as u64;
            stats.crank_cycles += 1;
        }

        total_triggered
    }

    /// Processes pending events without advancing to next event.
    ///
    /// This is equivalent to `crank_with_options(false)`.
    pub fn crank(&self) -> usize {
        self.crank_with_options(false)
    }

    /// Cranks until a predicate returns true or timeout is reached.
    ///
    /// # Arguments
    ///
    /// * `predicate` - A function that returns true when the condition is met.
    /// * `timeout` - Maximum duration to wait for the condition.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the predicate returned true before timeout.
    /// `Err(())` if the timeout was reached before the predicate returned true.
    pub fn crank_until<F>(&self, predicate: F, timeout: Duration) -> Result<(), ()>
    where
        F: Fn() -> bool,
    {
        let deadline = self.now() + timeout;
        let poll_interval = Duration::from_secs(1);

        while self.now() < deadline {
            if predicate() {
                return Ok(());
            }

            // Crank and potentially advance time
            self.crank_with_options(true);

            // If still before deadline and predicate not satisfied, advance time
            if self.mode == ClockMode::VirtualTime && self.now() < deadline {
                let advance = std::cmp::min(poll_interval, deadline - self.now());
                if advance > Duration::ZERO {
                    self.advance_by(advance);
                }
            }
        }

        // Final check
        if predicate() {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Cranks for at least the specified duration.
    ///
    /// In virtual time mode, this advances virtual time by the duration.
    /// In real time mode, this blocks for the duration while processing events.
    pub fn crank_for_at_least(&self, duration: Duration) {
        let deadline = self.now() + duration;

        while self.now() < deadline {
            let processed = self.crank_with_options(true);

            // In real time mode, if no events were processed, sleep briefly
            if self.mode == ClockMode::RealTime && processed == 0 {
                let remaining = deadline.saturating_duration_since(self.now());
                let sleep_time = std::cmp::min(remaining, Duration::from_millis(10));
                if sleep_time > Duration::ZERO {
                    std::thread::sleep(sleep_time);
                }
            }

            // In virtual time mode, advance time if needed
            if self.mode == ClockMode::VirtualTime && self.now() < deadline {
                let remaining = deadline.saturating_duration_since(self.now());
                self.advance_by(remaining);
            }
        }
    }

    /// Cranks for at most the specified duration or until no more events.
    ///
    /// # Arguments
    ///
    /// * `duration` - Maximum duration to crank.
    ///
    /// # Returns
    ///
    /// The total number of events triggered.
    pub fn crank_for_at_most(&self, duration: Duration) -> usize {
        let deadline = self.now() + duration;
        let mut total_triggered = 0;

        while self.now() < deadline {
            let processed = self.crank_with_options(true);
            total_triggered += processed;

            // If no events were processed and queue is empty, we're done
            if processed == 0 {
                let has_pending = self
                    .events
                    .lock()
                    .map(|e| !e.is_empty())
                    .unwrap_or(false);
                if !has_pending {
                    break;
                }
            }
        }

        total_triggered
    }

    /// Returns the number of pending events.
    pub fn pending_event_count(&self) -> usize {
        self.events.lock().map(|e| e.len()).unwrap_or(0)
    }

    /// Returns the time of the next scheduled event, if any.
    pub fn next_event_time(&self) -> Option<Instant> {
        self.events.lock().ok()?.peek().map(|e| e.when)
    }

    /// Returns a copy of the current statistics.
    pub fn stats(&self) -> ClockStats {
        self.stats.read().map(|s| s.clone()).unwrap_or_default()
    }

    /// Clears all pending events.
    pub fn clear_events(&self) {
        if let Ok(mut events) = self.events.lock() {
            let cancelled_count = events.len();
            events.clear();

            if let Ok(mut stats) = self.stats.write() {
                stats.events_cancelled += cancelled_count as u64;
            }
        }
    }
}

impl Default for VirtualClock {
    fn default() -> Self {
        Self::virtual_time()
    }
}

// =============================================================================
// SharedVirtualClock
// =============================================================================

/// A thread-safe reference to a VirtualClock.
///
/// This type is `Clone` and can be shared across threads.
pub type SharedVirtualClock = Arc<VirtualClock>;

/// Creates a new shared virtual clock in virtual time mode.
pub fn shared_virtual_clock() -> SharedVirtualClock {
    Arc::new(VirtualClock::virtual_time())
}

/// Creates a new shared virtual clock with the specified mode.
pub fn shared_clock(mode: ClockMode) -> SharedVirtualClock {
    Arc::new(VirtualClock::new(mode))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn test_virtual_clock_creation() {
        let clock = VirtualClock::virtual_time();
        assert_eq!(clock.mode(), ClockMode::VirtualTime);

        let clock = VirtualClock::real_time();
        assert_eq!(clock.mode(), ClockMode::RealTime);
    }

    #[test]
    fn test_virtual_time_advance() {
        let clock = VirtualClock::virtual_time();
        let initial = clock.now_nanos();

        clock.advance_by(Duration::from_secs(5));
        let after = clock.now_nanos();

        assert_eq!(after - initial, 5_000_000_000);
    }

    #[test]
    fn test_schedule_and_crank() {
        let clock = VirtualClock::virtual_time();
        let triggered = Arc::new(AtomicBool::new(false));
        let triggered_clone = triggered.clone();

        clock.schedule_after(Duration::from_secs(1), move || {
            triggered_clone.store(true, AtomicOrdering::Release);
        });

        // Not yet triggered
        assert!(!triggered.load(AtomicOrdering::Acquire));
        assert_eq!(clock.crank(), 0);

        // Advance time and crank
        clock.advance_by(Duration::from_secs(1));
        assert_eq!(clock.crank(), 1);
        assert!(triggered.load(AtomicOrdering::Acquire));
    }

    #[test]
    fn test_event_ordering() {
        let clock = VirtualClock::virtual_time();
        let order = Arc::new(Mutex::new(Vec::new()));

        for i in (1..=5).rev() {
            let order_clone = order.clone();
            clock.schedule_after(Duration::from_secs(i), move || {
                order_clone.lock().unwrap().push(i);
            });
        }

        // Advance and crank all events
        clock.advance_by(Duration::from_secs(6));
        while clock.crank() > 0 {}

        let result = order.lock().unwrap();
        assert_eq!(*result, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_event_cancellation() {
        let clock = VirtualClock::virtual_time();
        let triggered = Arc::new(AtomicBool::new(false));
        let triggered_clone = triggered.clone();

        let handle = clock.schedule_after(Duration::from_secs(1), move || {
            triggered_clone.store(true, AtomicOrdering::Release);
        });

        // Cancel before triggering
        handle.cancel();
        assert!(handle.is_cancelled());

        clock.advance_by(Duration::from_secs(1));
        clock.crank();

        // Should not have triggered
        assert!(!triggered.load(AtomicOrdering::Acquire));
    }

    #[test]
    fn test_crank_with_advance() {
        let clock = VirtualClock::virtual_time();
        let triggered = Arc::new(AtomicBool::new(false));
        let triggered_clone = triggered.clone();

        clock.schedule_after(Duration::from_secs(10), move || {
            triggered_clone.store(true, AtomicOrdering::Release);
        });

        // Crank with advance_to_next should jump to the event time
        clock.crank_with_options(true);
        assert!(triggered.load(AtomicOrdering::Acquire));
        assert!(clock.now_nanos() >= 10_000_000_000);
    }

    #[test]
    fn test_crank_until() {
        let clock = VirtualClock::virtual_time();
        let counter = Arc::new(AtomicUsize::new(0));

        // Schedule multiple events
        for i in 1..=5 {
            let counter_clone = counter.clone();
            clock.schedule_after(Duration::from_secs(i), move || {
                counter_clone.fetch_add(1, AtomicOrdering::Relaxed);
            });
        }

        // Crank until counter reaches 3
        let counter_check = counter.clone();
        let result = clock.crank_until(
            move || counter_check.load(AtomicOrdering::Relaxed) >= 3,
            Duration::from_secs(10),
        );

        assert!(result.is_ok());
        assert!(counter.load(AtomicOrdering::Relaxed) >= 3);
    }

    #[test]
    fn test_crank_until_timeout() {
        let clock = VirtualClock::virtual_time();

        // Condition that never becomes true
        let result = clock.crank_until(|| false, Duration::from_secs(1));

        assert!(result.is_err());
    }

    #[test]
    fn test_crank_for_at_least() {
        let clock = VirtualClock::virtual_time();
        let initial = clock.now_nanos();

        clock.crank_for_at_least(Duration::from_secs(5));

        // Should have advanced at least 5 seconds
        assert!(clock.now_nanos() >= initial + 5_000_000_000);
    }

    #[test]
    fn test_crank_for_at_most() {
        let clock = VirtualClock::virtual_time();
        let triggered_count = Arc::new(AtomicUsize::new(0));

        // Schedule events at 1s intervals
        for i in 1..=10 {
            let count = triggered_count.clone();
            clock.schedule_after(Duration::from_secs(i), move || {
                count.fetch_add(1, AtomicOrdering::Relaxed);
            });
        }

        // Crank for at most 5 seconds
        let total = clock.crank_for_at_most(Duration::from_secs(5));

        // Should have triggered approximately 5 events
        assert!(total >= 4 && total <= 6);
    }

    #[test]
    fn test_system_now_virtual() {
        let clock = VirtualClock::virtual_time();

        let sys_time = clock.system_now();
        let since_epoch = sys_time.duration_since(UNIX_EPOCH).unwrap();

        // Should be around VIRTUAL_BASE_SYSTEM_TIME (1 year after epoch)
        assert!(since_epoch.as_secs() >= VIRTUAL_BASE_SYSTEM_TIME);
        assert!(since_epoch.as_secs() < VIRTUAL_BASE_SYSTEM_TIME + 10);

        // Advance virtual time
        clock.advance_by(Duration::from_secs(100));

        let sys_time2 = clock.system_now();
        let since_epoch2 = sys_time2.duration_since(UNIX_EPOCH).unwrap();

        // Should have advanced by 100 seconds
        assert_eq!(since_epoch2.as_secs() - since_epoch.as_secs(), 100);
    }

    #[test]
    fn test_sleep_for_virtual() {
        let clock = VirtualClock::virtual_time();
        let initial = clock.now_nanos();

        // sleep_for in virtual mode should advance instantly
        clock.sleep_for(Duration::from_secs(1000));

        let after = clock.now_nanos();
        assert_eq!(after - initial, 1_000_000_000_000);
    }

    #[test]
    fn test_pending_event_count() {
        let clock = VirtualClock::virtual_time();

        assert_eq!(clock.pending_event_count(), 0);

        clock.schedule_after(Duration::from_secs(1), || {});
        clock.schedule_after(Duration::from_secs(2), || {});
        clock.schedule_after(Duration::from_secs(3), || {});

        assert_eq!(clock.pending_event_count(), 3);

        clock.advance_by(Duration::from_secs(2));
        clock.crank();

        // One event should remain
        assert_eq!(clock.pending_event_count(), 1);
    }

    #[test]
    fn test_clear_events() {
        let clock = VirtualClock::virtual_time();

        clock.schedule_after(Duration::from_secs(1), || {});
        clock.schedule_after(Duration::from_secs(2), || {});
        clock.schedule_after(Duration::from_secs(3), || {});

        assert_eq!(clock.pending_event_count(), 3);

        clock.clear_events();

        assert_eq!(clock.pending_event_count(), 0);
    }

    #[test]
    fn test_stats() {
        let clock = VirtualClock::virtual_time();

        clock.schedule_after(Duration::from_secs(1), || {});
        let handle = clock.schedule_after(Duration::from_secs(2), || {});
        handle.cancel();

        clock.advance_by(Duration::from_secs(3));
        clock.crank();
        clock.crank();

        let stats = clock.stats();
        assert_eq!(stats.events_scheduled, 2);
        assert_eq!(stats.events_triggered, 1);
        assert_eq!(stats.events_cancelled, 1);
        assert_eq!(stats.crank_cycles, 2);
    }

    #[test]
    fn test_shared_clock() {
        let clock = shared_virtual_clock();
        let clock2 = clock.clone();

        clock.advance_by(Duration::from_secs(5));

        // Both references should see the same time
        assert_eq!(clock.now_nanos(), clock2.now_nanos());
    }

    #[test]
    fn test_next_event_time() {
        let clock = VirtualClock::virtual_time();

        assert!(clock.next_event_time().is_none());

        let when = clock.now() + Duration::from_secs(5);
        clock.schedule_at(when, || {});

        let next = clock.next_event_time().unwrap();
        assert_eq!(next, when);
    }

    #[test]
    fn test_same_time_events_ordered_by_sequence() {
        let clock = VirtualClock::virtual_time();
        let order = Arc::new(Mutex::new(Vec::new()));

        let now = clock.now();

        // Schedule multiple events at the exact same time
        for i in 0..5 {
            let order_clone = order.clone();
            clock.schedule_at(now, move || {
                order_clone.lock().unwrap().push(i);
            });
        }

        // Crank all
        while clock.crank() > 0 {}

        let result = order.lock().unwrap();
        // Events should fire in the order they were scheduled
        assert_eq!(*result, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    #[should_panic(expected = "set_virtual_time only valid in VirtualTime mode")]
    fn test_set_virtual_time_panics_in_real_mode() {
        let clock = VirtualClock::real_time();
        clock.set_virtual_time(clock.now() + Duration::from_secs(1));
    }

    #[test]
    #[should_panic(expected = "advance_by only valid in VirtualTime mode")]
    fn test_advance_by_panics_in_real_mode() {
        let clock = VirtualClock::real_time();
        clock.advance_by(Duration::from_secs(1));
    }
}
