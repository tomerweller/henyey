//! Spawn-blocking helpers with structured error logging.
//!
//! Provides [`spawn_blocking_logged`] and [`await_blocking_logged`] — thin
//! wrappers around `tokio::task::spawn_blocking` that log any `JoinError`
//! (differentiating panic from cancellation) and return the error to the
//! caller for domain-specific handling.

use tokio::task::JoinHandle;
use tracing::error;

/// Await a `spawn_blocking` handle, logging any `JoinError` with context.
///
/// Returns `Ok(value)` on success, `Err(JoinError)` on panic or cancellation.
/// On error, logs the error with the provided `context` string, differentiating
/// panic from non-panic failures.
///
/// Callers that need domain-specific context (e.g., `ledger_seq`) should log
/// an additional line when handling the `Err` case.
pub async fn await_blocking_logged<T>(
    context: &str,
    handle: JoinHandle<T>,
) -> Result<T, tokio::task::JoinError> {
    match handle.await {
        Ok(val) => Ok(val),
        Err(e) if e.is_panic() => {
            error!(error = %e, "{context} panicked in spawn_blocking");
            Err(e)
        }
        Err(e) => {
            error!(error = %e, "spawn_blocking join error for {context}");
            Err(e)
        }
    }
}

/// Spawn a blocking closure and log any `JoinError`/panic.
///
/// Convenience wrapper: spawns on the blocking pool and immediately awaits.
/// Use [`await_blocking_logged`] when you need to do work between spawn and
/// await (e.g., setting a phase marker).
pub async fn spawn_blocking_logged<T, F>(context: &str, f: F) -> Result<T, tokio::task::JoinError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    await_blocking_logged(context, tokio::task::spawn_blocking(f)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_spawn_blocking_logged_success() {
        let result = spawn_blocking_logged("test-success", || 42).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_spawn_blocking_logged_panic() {
        let result = spawn_blocking_logged("test-panic", || -> () { panic!("boom") }).await;
        let err = result.unwrap_err();
        assert!(err.is_panic());
    }

    #[tokio::test]
    async fn test_await_blocking_logged_success() {
        let handle = tokio::task::spawn_blocking(|| "hello");
        let result = await_blocking_logged("test-await", handle).await;
        assert_eq!(result.unwrap(), "hello");
    }

    #[tokio::test]
    async fn test_await_blocking_logged_panic() {
        let handle = tokio::task::spawn_blocking(|| -> i32 { panic!("kaboom") });
        let result = await_blocking_logged("test-await-panic", handle).await;
        let err = result.unwrap_err();
        assert!(err.is_panic());
    }
}
