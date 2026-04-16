use std::sync::Arc;
use std::time::Duration;

use henyey_app::App;
use tokio::sync::Semaphore;

use crate::fee_window::FeeWindows;

/// Shared state for all RPC handlers.
pub(crate) struct RpcContext {
    /// The application instance.
    pub app: Arc<App>,
    /// Sliding-window fee statistics for `getFeeStats`.
    pub fee_windows: Arc<FeeWindows>,
    /// Limits concurrent `simulateTransaction` requests to prevent CPU/thread exhaustion.
    pub simulation_semaphore: Arc<Semaphore>,
    /// Limits total concurrent request executions.
    pub request_semaphore: Arc<Semaphore>,
    /// Limits concurrent RPC database queries (aligned to DB pool capacity).
    pub db_semaphore: Arc<Semaphore>,
    /// Timeout for read-only request execution.
    pub request_timeout: Duration,
}
