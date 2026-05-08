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
    pub async fn find_exited_node(
        &self,
        scope: &CrashScope<'_>,
    ) -> Option<(String, Option<String>)> {
        match scope {
            CrashScope::AllNodes => {
                let mut ids: Vec<&String> = self.running_apps.keys().collect();
                ids.sort();
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
