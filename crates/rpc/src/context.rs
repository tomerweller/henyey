use std::sync::Arc;

use henyey_app::App;

/// Shared state for all RPC handlers.
pub struct RpcContext {
    /// The application instance.
    pub app: Arc<App>,
}
