//! Lock-latency telemetry for #1759 / #1772 freeze investigation.
//!
//! The first-run diagnostics in `f569b9ac` wrapped event-loop compute
//! hotspots with [`warn_if_slow`](super::warn_if_slow) to catch
//! in-function stalls. Live freeze capture (session `ebcc08d3`,
//! 21:07 / 21:30) showed those wrappers fired **zero** times across
//! 150+ freeze events — the event loop is not stalled *inside* any
//! wrapped compute path. The concurrent `/proc/*/wchan` sample showed
//! 42/44 threads parked in `futex_wait_queue`, 1 tokio worker in
//! `ep_poll`: classic "single held lock starving the pool" shape.
//!
//! The event loop is blocked *acquiring* a lock, not executing code.
//! This module provides helpers to name the offending lock in the
//! next freeze capture without requiring `py-spy` or `gdb` on the
//! host (which are not installed on production validators).
//!
//! Three candidate lock sites match the observed ingress/egress
//! contention shape:
//!
//! 1. [`App::syncing_ledgers`](super::App) — `tokio::sync::RwLock`
//!    touched on every fetch-response ingress *and* every ledger close.
//! 2. `ScpDriver::externalized` / `latest_externalized` —
//!    `parking_lot::RwLock` read on every overlay message that
//!    references an externalized slot.
//! 3. `Herder::state` — `parking_lot::RwLock` held inside most
//!    `Herder::*` entry points invoked from the event loop.
//!
//! The helpers here wrap (1) directly via [`tracked_write`] /
//! [`tracked_read`]. For (2)+(3), the synchronous `time_call` /
//! `PhaseTimer` primitives live in [`henyey_common::tracking`] and
//! are re-exported below so call sites in this crate keep using the
//! familiar `tracked_lock::time_call` path.
//!
//! See `docs/spec-eval/` and issues #1759 / #1768 / #1772 for the full
//! investigation trail.

use std::ops::{Deref, DerefMut};
use std::time::Instant;

// Re-export the shared primitives so in-crate call sites continue to
// write `tracked_lock::time_call(...)` / `tracked_lock::LOCK_SLOW_THRESHOLD`
// without needing to reach into `henyey_common::tracking` directly.
pub(crate) use henyey_common::tracking::{time_call, PhaseTimer, LOCK_SLOW_THRESHOLD};

/// RAII guard wrapper that emits a single `WARN` log line on drop
/// if the lock was held for at least [`LOCK_SLOW_THRESHOLD`].
///
/// Derefs mutably to the inner lock guard, so call sites change
/// only by swapping the acquisition call:
///
/// ```ignore
/// let mut buffer = self.syncing_ledgers.write().await;            // before
/// let mut buffer = tracked_write("syncing_ledgers", &self.syncing_ledgers).await; // after
/// ```
///
/// Emitting in `Drop` is correct behavior even across panics: a
/// panicking held lock *is* a slow lock if it exceeded threshold.
pub(crate) struct TrackedGuard<G> {
    inner: G,
    label: &'static str,
    hold_start: Instant,
}

impl<G> Drop for TrackedGuard<G> {
    fn drop(&mut self) {
        let hold = self.hold_start.elapsed();
        if hold >= LOCK_SLOW_THRESHOLD {
            tracing::warn!(
                lock = self.label,
                kind = "hold",
                hold_ms = hold.as_millis() as u64,
                "Slow RwLock hold (>= {}ms) — possible #1759 contributor",
                LOCK_SLOW_THRESHOLD.as_millis()
            );
        }
    }
}

impl<G: Deref> Deref for TrackedGuard<G> {
    type Target = G::Target;
    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<G: DerefMut> DerefMut for TrackedGuard<G> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.deref_mut()
    }
}

/// Acquire a write lock on `lock`, timing both the acquire-wait and
/// the subsequent hold.
///
/// If the acquire-wait alone exceeded [`LOCK_SLOW_THRESHOLD`], emits
/// one `WARN` with `kind="wait"`. The returned [`TrackedGuard`] will
/// emit an additional `kind="hold"` WARN on drop if the held duration
/// also exceeded the threshold.
pub(crate) async fn tracked_write<'a, T>(
    label: &'static str,
    lock: &'a tokio::sync::RwLock<T>,
) -> TrackedGuard<tokio::sync::RwLockWriteGuard<'a, T>> {
    let acquire_start = Instant::now();
    let inner = lock.write().await;
    let wait = acquire_start.elapsed();
    if wait >= LOCK_SLOW_THRESHOLD {
        tracing::warn!(
            lock = label,
            kind = "wait",
            acquire_wait_ms = wait.as_millis() as u64,
            "Slow RwLock acquire-wait (>= {}ms) — possible #1759 contributor",
            LOCK_SLOW_THRESHOLD.as_millis()
        );
    }
    TrackedGuard {
        inner,
        label,
        hold_start: Instant::now(),
    }
}

/// Acquire a read lock on `lock`, timing both the acquire-wait and
/// the subsequent hold.
///
/// Mirror of [`tracked_write`]. Slow reader waits implicate a writer
/// holding too long; slow reader holds are themselves suspect because
/// even concurrent readers will block writers.
pub(crate) async fn tracked_read<'a, T>(
    label: &'static str,
    lock: &'a tokio::sync::RwLock<T>,
) -> TrackedGuard<tokio::sync::RwLockReadGuard<'a, T>> {
    let acquire_start = Instant::now();
    let inner = lock.read().await;
    let wait = acquire_start.elapsed();
    if wait >= LOCK_SLOW_THRESHOLD {
        tracing::warn!(
            lock = label,
            kind = "wait",
            acquire_wait_ms = wait.as_millis() as u64,
            "Slow RwLock acquire-wait (>= {}ms) — possible #1759 contributor",
            LOCK_SLOW_THRESHOLD.as_millis()
        );
    }
    TrackedGuard {
        inner,
        label,
        hold_start: Instant::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::RwLock as TokioRwLock;
    use tracing::{
        field::{Field, Visit},
        subscriber::{with_default, Subscriber},
        Event, Metadata,
    };

    /// Captured tracing event: `(level, lock_label, kind, ms)`.
    ///
    /// `time_call` has its own capturing-subscriber tests in
    /// `henyey_common::tracking::tests` now; this module only exercises
    /// the tokio-specific `tracked_read` / `tracked_write` wrappers.
    #[derive(Clone, Debug, Default)]
    struct CapturedEvent {
        level: String,
        lock: Option<String>,
        kind: Option<String>,
        hold_ms: Option<u64>,
        acquire_wait_ms: Option<u64>,
    }

    #[derive(Clone, Default)]
    struct CapturingSubscriber {
        events: Arc<Mutex<Vec<CapturedEvent>>>,
    }

    impl Visit for CapturedEvent {
        fn record_str(&mut self, field: &Field, value: &str) {
            match field.name() {
                "lock" => self.lock = Some(value.to_string()),
                "kind" => self.kind = Some(value.to_string()),
                _ => {}
            }
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            match field.name() {
                "hold_ms" => self.hold_ms = Some(value),
                "acquire_wait_ms" => self.acquire_wait_ms = Some(value),
                _ => {}
            }
        }

        fn record_i64(&mut self, field: &Field, value: i64) {
            self.record_u64(field, value as u64);
        }

        fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}
    }

    impl Subscriber for CapturingSubscriber {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut captured = CapturedEvent {
                level: event.metadata().level().to_string(),
                ..Default::default()
            };
            event.record(&mut captured);
            self.events.lock().unwrap().push(captured);
        }

        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// Helper: hold duration that comfortably exceeds threshold but
    /// keeps CI fast. `THRESHOLD + 100ms = 350ms`.
    const TEST_HOLD_DURATION: Duration = Duration::from_millis(350);

    /// Build a single-threaded tokio runtime for tests. Tests use
    /// plain `#[test]` + this helper so the capturing subscriber
    /// `with_default` scope encloses the runtime and its `Drop`
    /// handlers; `#[tokio::test]` would invert that ordering.
    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// `tracked_write` emits a `kind="hold"` WARN when the guard is
    /// held at least `LOCK_SLOW_THRESHOLD`.
    #[test]
    fn tracked_write_warns_on_long_hold() {
        let sub = CapturingSubscriber::default();
        let events = sub.events.clone();
        let lock: TokioRwLock<u32> = TokioRwLock::new(0);

        with_default(sub, || {
            let rt = test_runtime();
            rt.block_on(async {
                let mut guard = tracked_write("test", &lock).await;
                *guard = 1;
                std::thread::sleep(TEST_HOLD_DURATION);
                drop(guard);
            });
        });

        let evs = events.lock().unwrap();
        let hold_events: Vec<_> = evs
            .iter()
            .filter(|e| e.kind.as_deref() == Some("hold") && e.lock.as_deref() == Some("test"))
            .collect();
        assert_eq!(hold_events.len(), 1, "expected exactly one hold WARN");
        assert_eq!(hold_events[0].level, "WARN");
        let ms = hold_events[0].hold_ms.expect("hold_ms missing");
        assert!(
            ms >= LOCK_SLOW_THRESHOLD.as_millis() as u64,
            "hold_ms={} must be >= threshold {}",
            ms,
            LOCK_SLOW_THRESHOLD.as_millis()
        );
    }

    /// `tracked_write` emits zero events when the guard is released
    /// promptly — zero log noise on the fast path.
    #[test]
    fn tracked_write_silent_on_fast_hold() {
        let sub = CapturingSubscriber::default();
        let events = sub.events.clone();
        let lock: TokioRwLock<u32> = TokioRwLock::new(0);

        with_default(sub, || {
            let rt = test_runtime();
            rt.block_on(async {
                let mut guard = tracked_write("test", &lock).await;
                *guard = 1;
                drop(guard);
            });
        });

        let evs = events.lock().unwrap();
        let hold_events: Vec<_> = evs
            .iter()
            .filter(|e| e.kind.as_deref() == Some("hold"))
            .collect();
        assert_eq!(hold_events.len(), 0, "fast path should emit no WARN");
    }

    /// `tracked_write` emits a `kind="wait"` WARN when a writer waits
    /// at least `LOCK_SLOW_THRESHOLD` for a contended lock.
    ///
    /// Uses real time (not `tokio::time::pause()`) because the
    /// drop-guard reads `Instant::now()`. Bounded by a 1s
    /// `tokio::time::timeout` to keep CI fast even on overload.
    /// Multi-thread runtime so the holder and waiter tasks run in
    /// parallel — on a single-threaded runtime the waiter would
    /// monopolise the scheduler and the holder's sleep couldn't
    /// complete.
    #[test]
    fn tracked_write_warns_on_long_wait() {
        let sub = CapturingSubscriber::default();
        let events = sub.events.clone();

        with_default(sub, || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async {
                let lock: Arc<TokioRwLock<u32>> = Arc::new(TokioRwLock::new(0));
                let holder_lock = Arc::clone(&lock);

                // Signal once the holder task has actually taken the
                // write lock, so the waiter doesn't start measuring
                // `acquire_wait_ms` before contention exists.
                let (held_tx, held_rx) = tokio::sync::oneshot::channel::<()>();

                let holder = tokio::spawn(async move {
                    let _guard = holder_lock.write().await;
                    let _ = held_tx.send(());
                    // Hold for the test duration; dropping the guard
                    // on function exit releases it.
                    tokio::time::sleep(TEST_HOLD_DURATION).await;
                });

                held_rx.await.expect("holder must acquire lock first");

                // Waiter: bounded 1s timeout so CI never hangs.
                let waiter_fut = tracked_write("test", &lock);
                let guard = tokio::time::timeout(Duration::from_secs(1), waiter_fut)
                    .await
                    .expect("timeout waiting for lock");
                drop(guard);

                // Ensure holder Drop has run before assertions below.
                holder.await.unwrap();
            });
        });

        let evs = events.lock().unwrap();
        let wait_events: Vec<_> = evs
            .iter()
            .filter(|e| e.kind.as_deref() == Some("wait") && e.lock.as_deref() == Some("test"))
            .collect();
        assert_eq!(
            wait_events.len(),
            1,
            "expected exactly one wait WARN; saw: {:?}",
            *evs
        );
        let ms = wait_events[0]
            .acquire_wait_ms
            .expect("acquire_wait_ms missing");
        assert!(
            ms >= LOCK_SLOW_THRESHOLD.as_millis() as u64,
            "acquire_wait_ms={} must be >= threshold {}",
            ms,
            LOCK_SLOW_THRESHOLD.as_millis()
        );
    }
}
