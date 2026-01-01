//! Work scheduler for rs-stellar-core.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

pub type WorkId = u64;

/// Result of a work execution.
#[derive(Debug, Clone)]
pub enum WorkOutcome {
    /// Work completed successfully.
    Success,
    /// Work was cancelled.
    Cancelled,
    /// Retry the work after the given delay.
    Retry { delay: Duration },
    /// Work failed permanently.
    Failed(String),
}

/// Current state of a work item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkState {
    Pending,
    Running,
    Success,
    Failed,
    Blocked,
    Cancelled,
}

/// Execution context provided to a work item.
#[derive(Debug, Clone)]
pub struct WorkContext {
    pub id: WorkId,
    pub attempt: u32,
    cancel_token: CancellationToken,
}

impl WorkContext {
    pub fn is_cancelled(&self) -> bool {
        self.cancel_token.is_cancelled()
    }

    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel_token
    }
}

/// Work event emitted by the scheduler.
#[derive(Debug, Clone)]
pub struct WorkEvent {
    pub id: WorkId,
    pub name: String,
    pub state: WorkState,
    pub attempt: u32,
}

#[async_trait]
pub trait Work: Send {
    fn name(&self) -> &str;
    async fn run(&mut self, ctx: WorkContext) -> WorkOutcome;
}

struct WorkEntry {
    name: String,
    deps: Vec<WorkId>,
    retries_left: u32,
    attempts: u32,
    last_error: Option<String>,
    started_at: Option<Instant>,
    last_duration: Option<Duration>,
    total_duration: Duration,
    cancel_token: CancellationToken,
    work: Box<dyn Work + Send>,
}

/// Wrapper that invokes a callback after work finishes.
pub struct WorkWithCallback {
    work: Box<dyn Work + Send>,
    callback: Arc<dyn Fn(WorkOutcome, WorkContext) + Send + Sync>,
}

impl WorkWithCallback {
    pub fn new(
        work: Box<dyn Work + Send>,
        callback: Arc<dyn Fn(WorkOutcome, WorkContext) + Send + Sync>,
    ) -> Self {
        Self { work, callback }
    }
}

#[async_trait]
impl Work for WorkWithCallback {
    fn name(&self) -> &str {
        self.work.name()
    }

    async fn run(&mut self, ctx: WorkContext) -> WorkOutcome {
        let outcome = self.work.run(ctx.clone()).await;
        (self.callback)(outcome.clone(), ctx);
        outcome
    }
}

#[derive(Debug, Clone)]
pub struct WorkSchedulerConfig {
    pub max_concurrency: usize,
    pub retry_delay: Duration,
    pub event_tx: Option<mpsc::Sender<WorkEvent>>,
}

impl Default for WorkSchedulerConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 4,
            retry_delay: Duration::from_secs(1),
            event_tx: None,
        }
    }
}

/// Scheduler for async work items with dependencies.
pub struct WorkScheduler {
    config: WorkSchedulerConfig,
    next_id: WorkId,
    entries: HashMap<WorkId, WorkEntry>,
    states: HashMap<WorkId, WorkState>,
    dependents: HashMap<WorkId, Vec<WorkId>>,
}

#[derive(Debug, Clone, Default)]
pub struct WorkSchedulerMetrics {
    pub total: usize,
    pub pending: usize,
    pub running: usize,
    pub success: usize,
    pub failed: usize,
    pub blocked: usize,
    pub cancelled: usize,
    pub attempts: u64,
    pub retries_left: u64,
}

#[derive(Debug, Clone)]
pub struct WorkSnapshot {
    pub id: WorkId,
    pub name: String,
    pub state: WorkState,
    pub deps: Vec<WorkId>,
    pub dependents: Vec<WorkId>,
    pub attempts: u32,
    pub retries_left: u32,
    pub last_error: Option<String>,
    pub last_duration: Option<Duration>,
    pub total_duration: Duration,
}

impl WorkScheduler {
    pub fn new(config: WorkSchedulerConfig) -> Self {
        Self {
            config,
            next_id: 1,
            entries: HashMap::new(),
            states: HashMap::new(),
            dependents: HashMap::new(),
        }
    }

    /// Add a work item to the scheduler.
    pub fn add_work(
        &mut self,
        work: Box<dyn Work + Send>,
        deps: Vec<WorkId>,
        retries: u32,
    ) -> WorkId {
        let id = self.next_id;
        self.next_id += 1;

        let name = work.name().to_string();
        let entry = WorkEntry {
            name: name.clone(),
            deps: deps.clone(),
            retries_left: retries,
            attempts: 0,
            last_error: None,
            started_at: None,
            last_duration: None,
            total_duration: Duration::from_secs(0),
            cancel_token: CancellationToken::new(),
            work,
        };

        self.entries.insert(id, entry);
        self.states.insert(id, WorkState::Pending);

        for dep in deps {
            self.dependents.entry(dep).or_default().push(id);
        }

        debug!(work_id = id, name = %name, "registered work item");
        id
    }

    pub fn state(&self, id: WorkId) -> Option<WorkState> {
        self.states.get(&id).copied()
    }

    pub fn cancel(&mut self, id: WorkId) -> bool {
        let Some(state) = self.states.get(&id).copied() else { return false };
        match state {
            WorkState::Success | WorkState::Failed | WorkState::Blocked | WorkState::Cancelled => {
                return false;
            }
            WorkState::Pending | WorkState::Running => {}
        }

        if let Some(entry) = self.entries.get_mut(&id) {
            entry.cancel_token.cancel();
            let attempts = entry.attempts;
            self.states.insert(id, WorkState::Cancelled);
            self.emit_event(id, WorkState::Cancelled, attempts);
            self.block_dependents(id);
            return true;
        }
        false
    }

    pub fn cancel_all(&mut self) {
        let ids: Vec<WorkId> = self.entries.keys().copied().collect();
        for id in ids {
            let _ = self.cancel(id);
        }
    }

    pub fn snapshot(&self) -> Vec<WorkSnapshot> {
        let mut snapshots: Vec<WorkSnapshot> = self
            .entries
            .iter()
            .map(|(id, entry)| WorkSnapshot {
                id: *id,
                name: entry.name.clone(),
                state: self.states.get(id).copied().unwrap_or(WorkState::Pending),
                deps: entry.deps.clone(),
                dependents: self.dependents.get(id).cloned().unwrap_or_default(),
                attempts: entry.attempts,
                retries_left: entry.retries_left,
                last_error: entry.last_error.clone(),
                last_duration: entry.last_duration,
                total_duration: entry.total_duration,
            })
            .collect();
        snapshots.sort_by_key(|snapshot| snapshot.id);
        snapshots
    }

    pub fn metrics(&self) -> WorkSchedulerMetrics {
        let mut metrics = WorkSchedulerMetrics::default();
        metrics.total = self.entries.len();
        for (id, entry) in &self.entries {
            match self.states.get(id).copied().unwrap_or(WorkState::Pending) {
                WorkState::Pending => metrics.pending += 1,
                WorkState::Running => metrics.running += 1,
                WorkState::Success => metrics.success += 1,
                WorkState::Failed => metrics.failed += 1,
                WorkState::Blocked => metrics.blocked += 1,
                WorkState::Cancelled => metrics.cancelled += 1,
            }
            metrics.attempts += entry.attempts as u64;
            metrics.retries_left += entry.retries_left as u64;
        }
        metrics
    }

    /// Run until all work items complete or are blocked.
    pub async fn run_until_done(&mut self) {
        let cancel = CancellationToken::new();
        self.run_until_done_with_cancel(cancel).await;
    }

    pub async fn run_until_done_with_cancel(&mut self, cancel: CancellationToken) {
        let (tx, mut rx) = mpsc::channel::<WorkCompletion>(128);
        let mut running: HashSet<WorkId> = HashSet::new();
        let mut queue = self.ready_queue();
        let mut queued: HashSet<WorkId> = queue.iter().copied().collect();

        let mut cancel_requested = false;

        loop {
            if !cancel_requested && cancel.is_cancelled() {
                cancel_requested = true;
                self.cancel_all();
            }

            while running.len() < self.config.max_concurrency {
                let Some(id) = queue.pop_front() else { break };
                queued.remove(&id);
                if running.contains(&id) {
                    continue;
                }

                if !self.can_run(id) {
                    continue;
                }

                let Some(entry) = self.entries.get_mut(&id) else { continue };
                if entry.cancel_token.is_cancelled() {
                    let attempts = entry.attempts;
                    self.states.insert(id, WorkState::Cancelled);
                    self.emit_event(id, WorkState::Cancelled, attempts);
                    self.block_dependents(id);
                    continue;
                }
                entry.attempts += 1;
                let attempt = entry.attempts;
                let mut work = std::mem::replace(&mut entry.work, Box::new(EmptyWork));
                let name = entry.name.clone();
                let completion_tx = tx.clone();
                let cancel_token = entry.cancel_token.clone();
                entry.started_at = Some(Instant::now());

                self.states.insert(id, WorkState::Running);
                self.emit_event(id, WorkState::Running, attempt);
                running.insert(id);

                tokio::spawn(async move {
                    let outcome = work
                        .run(WorkContext {
                            id,
                            attempt,
                            cancel_token: cancel_token.clone(),
                        })
                        .await;
                    let _ = completion_tx
                        .send(WorkCompletion {
                            id,
                            outcome,
                            work: Some(work),
                            attempt,
                            cancelled: cancel_token.is_cancelled(),
                        })
                        .await;
                    debug!(work_id = id, name = %name, "work completed");
                });
            }

            if running.is_empty() && queue.is_empty() {
                // No runnable work left.
                break;
            }

            let completion = if cancel_requested {
                rx.recv().await
            } else {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        cancel_requested = true;
                        self.cancel_all();
                        continue;
                    }
                    completion = rx.recv() => completion,
                }
            };
            let Some(completion) = completion else { break };
            running.remove(&completion.id);

            let cancelled = completion.cancelled
                || matches!(self.states.get(&completion.id), Some(WorkState::Cancelled));

            match completion.outcome {
                WorkOutcome::Cancelled => {
                    self.states.insert(completion.id, WorkState::Cancelled);
                    self.emit_event(completion.id, WorkState::Cancelled, completion.attempt);
                    self.block_dependents(completion.id);
                    if let Some(entry) = self.entries.get_mut(&completion.id) {
                        if let Some(work) = completion.work {
                            entry.work = work;
                        }
                        if let Some(started_at) = entry.started_at.take() {
                            let elapsed = started_at.elapsed();
                            entry.last_duration = Some(elapsed);
                            entry.total_duration += elapsed;
                        }
                    }
                }
                WorkOutcome::Success => {
                    if cancelled {
                        self.states.insert(completion.id, WorkState::Cancelled);
                        self.emit_event(completion.id, WorkState::Cancelled, completion.attempt);
                        self.block_dependents(completion.id);
                    } else {
                    self.states.insert(completion.id, WorkState::Success);
                    self.emit_event(completion.id, WorkState::Success, completion.attempt);
                    }
                    if let Some(entry) = self.entries.get_mut(&completion.id) {
                        if let Some(work) = completion.work {
                            entry.work = work;
                        }
                        if let Some(started_at) = entry.started_at.take() {
                            let elapsed = started_at.elapsed();
                            entry.last_duration = Some(elapsed);
                            entry.total_duration += elapsed;
                        }
                    }
                    self.enqueue_ready(&mut queue, &mut queued, &running);
                }
                WorkOutcome::Retry { delay } => {
                    if cancelled {
                        self.states.insert(completion.id, WorkState::Cancelled);
                        self.emit_event(completion.id, WorkState::Cancelled, completion.attempt);
                        self.block_dependents(completion.id);
                        continue;
                    }
                    let retry_delay = if delay == Duration::from_secs(0) {
                        self.config.retry_delay
                    } else {
                        delay
                    };

                    if let Some(entry) = self.entries.get_mut(&completion.id) {
                        if entry.retries_left == 0 {
                            self.states.insert(completion.id, WorkState::Failed);
                            self.emit_event(completion.id, WorkState::Failed, completion.attempt);
                            self.block_dependents(completion.id);
                            continue;
                        }
                        entry.retries_left -= 1;
                        if let Some(work) = completion.work {
                            entry.work = work;
                        }
                        if let Some(started_at) = entry.started_at.take() {
                            let elapsed = started_at.elapsed();
                            entry.last_duration = Some(elapsed);
                            entry.total_duration += elapsed;
                        }
                        self.emit_event(completion.id, WorkState::Pending, completion.attempt);
                        let (wake_tx, wake_rx) = oneshot::channel::<WorkId>();
                        tokio::spawn(async move {
                            tokio::time::sleep(retry_delay).await;
                            let _ = wake_tx.send(completion.id);
                        });
                        if let Ok(id) = wake_rx.await {
                            if queued.insert(id) {
                                queue.push_back(id);
                            }
                        }
                    }
                }
                WorkOutcome::Failed(err) => {
                    if cancelled {
                        self.states.insert(completion.id, WorkState::Cancelled);
                        self.emit_event(completion.id, WorkState::Cancelled, completion.attempt);
                        self.block_dependents(completion.id);
                        continue;
                    }
                    warn!(work_id = completion.id, error = %err, "work failed");
                    self.states.insert(completion.id, WorkState::Failed);
                    self.emit_event(completion.id, WorkState::Failed, completion.attempt);
                    self.block_dependents(completion.id);
                    if let Some(entry) = self.entries.get_mut(&completion.id) {
                        entry.last_error = Some(err);
                        if let Some(work) = completion.work {
                            entry.work = work;
                        }
                        if let Some(started_at) = entry.started_at.take() {
                            let elapsed = started_at.elapsed();
                            entry.last_duration = Some(elapsed);
                            entry.total_duration += elapsed;
                        }
                    }
                }
            }
        }

        info!("work scheduler finished");
    }

    fn ready_queue(&self) -> VecDeque<WorkId> {
        self.entries
            .keys()
            .filter(|id| matches!(self.states.get(id), Some(WorkState::Pending)))
            .copied()
            .collect()
    }

    fn enqueue_ready(
        &self,
        queue: &mut VecDeque<WorkId>,
        queued: &mut HashSet<WorkId>,
        running: &HashSet<WorkId>,
    ) {
        for id in self.ready_queue() {
            if running.contains(&id) {
                continue;
            }
            if queued.insert(id) {
                queue.push_back(id);
            }
        }
    }

    fn can_run(&self, id: WorkId) -> bool {
        let Some(entry) = self.entries.get(&id) else { return false };
        entry.deps.iter().all(|dep| matches!(self.states.get(dep), Some(WorkState::Success)))
    }

    fn block_dependents(&mut self, id: WorkId) {
        if let Some(children) = self.dependents.get(&id).cloned() {
            for child in children {
                if matches!(self.states.get(&child), Some(WorkState::Pending)) {
                    self.states.insert(child, WorkState::Blocked);
                    self.emit_event(child, WorkState::Blocked, 0);
                }
            }
        }
    }

    fn emit_event(&self, id: WorkId, state: WorkState, attempt: u32) {
        let Some(tx) = self.config.event_tx.as_ref() else { return };
        let name = self
            .entries
            .get(&id)
            .map(|entry| entry.name.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let _ = tx.try_send(WorkEvent {
            id,
            name,
            state,
            attempt,
        });
    }
}

struct WorkCompletion {
    id: WorkId,
    outcome: WorkOutcome,
    work: Option<Box<dyn Work + Send>>,
    attempt: u32,
    cancelled: bool,
}

struct EmptyWork;

#[async_trait]
impl Work for EmptyWork {
    fn name(&self) -> &str {
        "empty"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        WorkOutcome::Success
    }
}

/// Helper for creating sequential work dependencies.
#[derive(Default)]
pub struct WorkSequence {
    last: Option<WorkId>,
    ids: Vec<WorkId>,
}

impl WorkSequence {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(
        &mut self,
        scheduler: &mut WorkScheduler,
        work: Box<dyn Work + Send>,
        retries: u32,
    ) -> WorkId {
        let deps = self.last.into_iter().collect();
        let id = scheduler.add_work(work, deps, retries);
        self.last = Some(id);
        self.ids.push(id);
        id
    }

    pub fn ids(&self) -> &[WorkId] {
        &self.ids
    }
}
