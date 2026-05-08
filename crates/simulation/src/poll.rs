//! Shared polling helper with built-in task-exit detection.
//!
//! Encapsulates the common simulation pattern: deadline + sleep +
//! task-exit-check, replacing the duplicated polling loops across
//! `Simulation` methods and test helpers.

use std::future::Future;
use std::time::Duration;

use super::Simulation;

/// Outcome of a polling loop.
#[derive(Debug)]
pub enum PollOutcome<T> {
    /// The condition was met.
    Satisfied(T),
    /// The deadline expired without the condition being met.
    TimedOut,
    /// A node's task exited during polling.
    NodeExited {
        node_id: String,
        /// Debug-formatted task status from `app_task_status()`.
        status: Option<String>,
    },
}

/// Which nodes to check for unexpected task exit during polling.
#[derive(Debug, Clone)]
pub enum CrashScope<'a> {
    /// Check all nodes in `running_apps` (sorted for determinism).
    AllNodes,
    /// Check only the named node.
    SingleNode(&'a str),
}

impl Simulation {
    /// Return the first node (by sorted ID) whose task has exited, within
    /// the given crash scope. Returns `None` if all scoped nodes are still
    /// running.
    ///
    /// If `scope` is `SingleNode` and the node ID is absent from
    /// `running_apps`, returns `None` (treated as "not exited").
    pub async fn find_exited_node(
        &self,
        scope: &CrashScope<'_>,
    ) -> Option<(String, Option<String>)> {
        match scope {
            CrashScope::AllNodes => {
                let mut ids: Vec<&String> = self.running_apps.keys().collect();
                #[cfg(test)]
                ids.extend(self.test_nodes.keys());
                ids.sort();
                ids.dedup();
                for id in ids {
                    if self.app_task_finished(id) == Some(true) {
                        let status = self.app_task_status(id).await;
                        return Some((id.clone(), status.map(|s| format!("{s:?}"))));
                    }
                }
                None
            }
            CrashScope::SingleNode(node_id) => {
                if self.app_task_finished(node_id) == Some(true) {
                    let status = self.app_task_status(node_id).await;
                    return Some((node_id.to_string(), status.map(|s| format!("{s:?}"))));
                }
                None
            }
        }
    }
}

/// Generic polling helper with built-in task-exit detection.
///
/// Repeatedly evaluates `condition` until it returns `Ok(Some(T))`, a
/// scoped node task exits, or the deadline expires.
///
/// ### Semantics
///
/// - **Crash check ordering**: Always crash-first (check before condition
///   evaluation), then post-success re-check (stale-state guard after
///   condition returns `Ok(Some(T))`).
/// - **Zero-timeout**: The loop body runs at least once before the deadline
///   check. A `timeout == Duration::ZERO` call evaluates the condition
///   exactly once, then returns `TimedOut` if not satisfied.
/// - **Sleep**: `poll_interval` clamped to remaining time.
/// - **Condition errors**: `Err(e)` from condition is propagated immediately.
///   For retryable side-effect errors, the condition should capture the error
///   internally and return `Ok(None)`.
/// - **Determinism**: `AllNodes` crash scan iterates `running_apps.keys()`
///   sorted.
pub async fn poll_until<T, F, Fut>(
    sim: &Simulation,
    timeout: Duration,
    poll_interval: Duration,
    crash_scope: CrashScope<'_>,
    mut condition: F,
) -> Result<PollOutcome<T>, anyhow::Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Option<T>, anyhow::Error>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        // Pre-condition crash check
        if let Some((node_id, status)) = sim.find_exited_node(&crash_scope).await {
            return Ok(PollOutcome::NodeExited { node_id, status });
        }

        // Evaluate condition
        if let Some(val) = condition().await? {
            // Post-success crash check (stale-state guard)
            if let Some((node_id, status)) = sim.find_exited_node(&crash_scope).await {
                return Ok(PollOutcome::NodeExited { node_id, status });
            }
            return Ok(PollOutcome::Satisfied(val));
        }

        // Deadline check (after condition, so zero-timeout evaluates once)
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(PollOutcome::TimedOut);
        }

        // Sleep (clamped to remaining time)
        let remaining = deadline
            .checked_duration_since(now)
            .unwrap_or(Duration::ZERO);
        tokio::time::sleep(poll_interval.min(remaining)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use crate::SimulationMode;

    /// Create a `Simulation` with no real nodes — just the test harness.
    fn sim() -> Simulation {
        Simulation::new(SimulationMode::OverLoopback)
    }

    /// Spawn a task that completes immediately (simulates a finished/exited node).
    fn finished_handle() -> tokio::task::JoinHandle<anyhow::Result<()>> {
        tokio::spawn(async { Ok(()) })
    }

    /// Spawn a task that never completes (simulates a running node).
    fn pending_handle() -> tokio::task::JoinHandle<anyhow::Result<()>> {
        tokio::spawn(std::future::pending::<anyhow::Result<()>>())
    }

    // ------------------------------------------------------------------
    // 1. Immediate satisfaction
    // ------------------------------------------------------------------
    #[tokio::test(start_paused = true)]
    async fn test_immediate_satisfaction() {
        let sim = sim();
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);

        let result = poll_until(
            &sim,
            Duration::from_secs(5),
            Duration::from_millis(100),
            CrashScope::AllNodes,
            || {
                let c = Arc::clone(&c);
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Ok(Some(42))
                }
            },
        )
        .await
        .unwrap();

        assert!(matches!(result, PollOutcome::Satisfied(42)));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // ------------------------------------------------------------------
    // 2. Timeout
    // ------------------------------------------------------------------
    #[tokio::test(start_paused = true)]
    async fn test_timeout() {
        let sim = sim();
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);

        let result = poll_until(
            &sim,
            Duration::from_secs(1),
            Duration::from_millis(100),
            CrashScope::AllNodes,
            || {
                let c = Arc::clone(&c);
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Ok::<Option<()>, anyhow::Error>(None)
                }
            },
        )
        .await
        .unwrap();

        assert!(matches!(result, PollOutcome::TimedOut));
        // 1s timeout / 100ms interval = 10 sleeps, plus 1 final evaluation = 11 calls
        assert_eq!(counter.load(Ordering::SeqCst), 11);
    }

    // ------------------------------------------------------------------
    // 3. Zero timeout
    // ------------------------------------------------------------------
    #[tokio::test(start_paused = true)]
    async fn test_zero_timeout() {
        let sim = sim();
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);

        let result = poll_until(
            &sim,
            Duration::ZERO,
            Duration::from_millis(100),
            CrashScope::AllNodes,
            || {
                let c = Arc::clone(&c);
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Ok::<Option<()>, anyhow::Error>(None)
                }
            },
        )
        .await
        .unwrap();

        assert!(matches!(result, PollOutcome::TimedOut));
        // Zero timeout: condition evaluated exactly once, then deadline fires.
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // ------------------------------------------------------------------
    // 4. Fatal condition error
    // ------------------------------------------------------------------
    #[tokio::test(start_paused = true)]
    async fn test_fatal_condition_error() {
        let sim = sim();
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);

        let result = poll_until(
            &sim,
            Duration::from_secs(5),
            Duration::from_millis(100),
            CrashScope::AllNodes,
            || {
                let c = Arc::clone(&c);
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Err::<Option<()>, _>(anyhow::anyhow!("boom"))
                }
            },
        )
        .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "boom");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // ------------------------------------------------------------------
    // 5. AllNodes crash preempts condition
    // ------------------------------------------------------------------
    #[tokio::test(start_paused = true)]
    async fn test_all_nodes_crash_preempts_condition() {
        let mut sim = sim();
        sim.insert_test_node("n1", finished_handle(), None);
        // Yield to let the spawned task complete.
        tokio::task::yield_now().await;

        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);

        let result = poll_until(
            &sim,
            Duration::from_secs(5),
            Duration::from_millis(100),
            CrashScope::AllNodes,
            || {
                let c = Arc::clone(&c);
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Ok::<Option<()>, anyhow::Error>(None)
                }
            },
        )
        .await
        .unwrap();

        match result {
            PollOutcome::NodeExited {
                ref node_id,
                ref status,
            } => {
                assert_eq!(node_id, "n1");
                assert!(status.is_none());
            }
            _ => panic!("expected NodeExited, got {result:?}"),
        }
        // Pre-condition crash check fires before condition is ever called.
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    // ------------------------------------------------------------------
    // 6. SingleNode crash preempts condition
    // ------------------------------------------------------------------
    #[tokio::test(start_paused = true)]
    async fn test_single_node_crash_preempts_condition() {
        let mut sim = sim();
        sim.insert_test_node("target", finished_handle(), None);
        tokio::task::yield_now().await;

        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);

        let result = poll_until(
            &sim,
            Duration::from_secs(5),
            Duration::from_millis(100),
            CrashScope::SingleNode("target"),
            || {
                let c = Arc::clone(&c);
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Ok::<Option<()>, anyhow::Error>(None)
                }
            },
        )
        .await
        .unwrap();

        match result {
            PollOutcome::NodeExited { ref node_id, .. } => {
                assert_eq!(node_id, "target");
            }
            _ => panic!("expected NodeExited, got {result:?}"),
        }
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    // ------------------------------------------------------------------
    // 7. SingleNode ignores unrelated node exit
    // ------------------------------------------------------------------
    #[tokio::test(start_paused = true)]
    async fn test_single_node_ignores_unrelated() {
        let mut sim = sim();
        sim.insert_test_node("other", finished_handle(), None);
        sim.insert_test_node("target", pending_handle(), None);
        tokio::task::yield_now().await;

        let result = poll_until(
            &sim,
            Duration::from_secs(5),
            Duration::from_millis(100),
            CrashScope::SingleNode("target"),
            || async { Ok(Some(1)) },
        )
        .await
        .unwrap();

        assert!(matches!(result, PollOutcome::Satisfied(1)));
    }

    // ------------------------------------------------------------------
    // 8. Post-success crash detection
    // ------------------------------------------------------------------
    #[tokio::test(start_paused = true)]
    async fn test_post_success_crash() {
        let mut sim = sim();
        sim.insert_test_node("n1", pending_handle(), None);

        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);

        // We need to abort the node from inside the condition closure.
        // Since poll_until takes &Simulation, we can't call abort_node_task
        // from the closure. Instead, we stash the abort handle.
        let abort_handle = sim.test_nodes.get("n1").unwrap().handle.abort_handle();

        let result = poll_until(
            &sim,
            Duration::from_secs(5),
            Duration::from_millis(100),
            CrashScope::AllNodes,
            || {
                let c = Arc::clone(&c);
                let abort_handle = abort_handle.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    // Simulate: condition succeeds, but the node exits
                    // between evaluation and the post-success re-check.
                    abort_handle.abort();
                    tokio::task::yield_now().await;
                    Ok(Some(99))
                }
            },
        )
        .await
        .unwrap();

        match result {
            PollOutcome::NodeExited { ref node_id, .. } => {
                assert_eq!(node_id, "n1");
            }
            _ => panic!("expected NodeExited, got {result:?}"),
        }
        // Condition was called exactly once — then post-success crash check fired.
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // ------------------------------------------------------------------
    // 9. AllNodes returns sorted-first exited node
    // ------------------------------------------------------------------
    #[tokio::test(start_paused = true)]
    async fn test_all_nodes_returns_sorted_first() {
        let mut sim = sim();
        sim.insert_test_node("charlie", finished_handle(), None);
        sim.insert_test_node("alpha", finished_handle(), None);
        sim.insert_test_node("bravo", pending_handle(), None);
        tokio::task::yield_now().await;

        let result = poll_until(
            &sim,
            Duration::from_secs(5),
            Duration::from_millis(100),
            CrashScope::AllNodes,
            || async { Ok::<Option<()>, anyhow::Error>(None) },
        )
        .await
        .unwrap();

        match result {
            PollOutcome::NodeExited { ref node_id, .. } => {
                assert_eq!(
                    node_id, "alpha",
                    "should return lexicographically first exited node"
                );
            }
            _ => panic!("expected NodeExited, got {result:?}"),
        }
    }

    // ------------------------------------------------------------------
    // 10. Crash with error status (format verification)
    // ------------------------------------------------------------------
    #[tokio::test(start_paused = true)]
    async fn test_crash_with_error_status() {
        let mut sim = sim();
        sim.insert_test_node(
            "n1",
            finished_handle(),
            Some(Err("panic in ledger close".to_string())),
        );
        tokio::task::yield_now().await;

        let result = poll_until(
            &sim,
            Duration::from_secs(5),
            Duration::from_millis(100),
            CrashScope::AllNodes,
            || async { Ok::<Option<()>, anyhow::Error>(None) },
        )
        .await
        .unwrap();

        match result {
            PollOutcome::NodeExited { ref status, .. } => {
                let status_str = status
                    .as_ref()
                    .expect("status should be Some for error exit");
                // find_exited_node formats via `format!("{s:?}")` where s: Result<(), String>
                assert!(
                    status_str.contains("panic in ledger close"),
                    "status should contain error message, got: {status_str}"
                );
            }
            _ => panic!("expected NodeExited, got {result:?}"),
        }
    }

    // ------------------------------------------------------------------
    // 11. SingleNode missing from running_apps is not treated as crashed
    // ------------------------------------------------------------------
    #[tokio::test(start_paused = true)]
    async fn test_single_node_missing_not_treated_as_crashed() {
        let sim = sim();

        let result = poll_until(
            &sim,
            Duration::from_secs(5),
            Duration::from_millis(100),
            CrashScope::SingleNode("ghost"),
            || async { Ok(Some(7)) },
        )
        .await
        .unwrap();

        assert!(matches!(result, PollOutcome::Satisfied(7)));
    }

    // ------------------------------------------------------------------
    // 12. Sleep clamped to remaining deadline
    // ------------------------------------------------------------------
    #[tokio::test(start_paused = true)]
    async fn test_sleep_clamped_to_remaining() {
        let sim = sim();
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);

        let start = tokio::time::Instant::now();
        let result = poll_until(
            &sim,
            Duration::from_millis(250),
            Duration::from_secs(1),
            CrashScope::AllNodes,
            || {
                let c = Arc::clone(&c);
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Ok::<Option<()>, anyhow::Error>(None)
                }
            },
        )
        .await
        .unwrap();

        let elapsed = start.elapsed();
        assert!(matches!(result, PollOutcome::TimedOut));
        // With poll_interval=1s but timeout=250ms, sleep is clamped to 250ms.
        // If NOT clamped, elapsed would be 1s. With clamping, exactly 250ms.
        assert_eq!(elapsed, Duration::from_millis(250));
        // Condition called twice: once initially, once after the clamped sleep.
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }
}
