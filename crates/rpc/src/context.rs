use std::sync::Arc;

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
}
