//! End-to-end regression test for watchdog shutdown (issue #2548).
//!
//! Verifies that a watchdog thread does NOT call `process::abort()` after
//! the App shuts down. The original bug (#2547) was an orphaned watchdog
//! thread firing SIGABRT after App shutdown — the `WatchdogGuard` RAII fix
//! ensures the thread exits promptly on drop.
//!
//! Because `process::abort()` kills the entire process (including the test
//! runner), this test uses a subprocess harness: the parent spawns a child
//! process that runs the App with a short `watchdog_abort_secs`, shuts down,
//! sleeps past the abort window, and exits. The parent asserts clean exit.

use std::sync::Arc;
use std::time::{Duration, Instant};

use henyey_app::config::ConfigBuilder;
use henyey_app::run_cmd::NodeRunner;
use henyey_app::{AppState, RunOptions};

/// Subprocess-based regression test for watchdog clean shutdown.
///
/// When run normally (no env var), acts as the parent: spawns a child and
/// asserts it exits cleanly. When `WATCHDOG_SHUTDOWN_CHILD=1` is set, acts
/// as the child: runs the App, shuts down, sleeps past the abort window.
#[tokio::test]
async fn test_watchdog_clean_shutdown_no_abort() {
    if std::env::var("WATCHDOG_SHUTDOWN_CHILD").is_ok() {
        child_main().await;
        return;
    }
    parent_main().await;
}

/// Parent: spawn child process and assert clean exit (no SIGABRT).
async fn parent_main() {
    let exe = std::env::current_exe().expect("failed to get current exe path");

    let child = tokio::process::Command::new(&exe)
        .env("WATCHDOG_SHUTDOWN_CHILD", "1")
        .arg("test_watchdog_clean_shutdown_no_abort")
        .arg("--exact")
        .arg("--test-threads=1")
        .arg("--nocapture")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn child process");

    // 60s timeout: ~5s startup + ~5s shutdown + 25s observation + margin.
    let output = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
        .await
        .expect("child process timed out after 60s — possible hang")
        .expect("failed to wait for child process");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // On Unix, check specifically for signal-based termination (SIGABRT = 6).
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = output.status.signal() {
            panic!(
                "Child process killed by signal {} (SIGABRT=6). \
                 This indicates the watchdog thread outlived App shutdown \
                 and called process::abort().\n\
                 stdout:\n{stdout}\nstderr:\n{stderr}",
                signal,
            );
        }
    }

    assert!(
        output.status.success(),
        "Child process exited with status {:?}. \
         Expected clean exit (code 0).\n\
         stdout:\n{stdout}\nstderr:\n{stderr}",
        output.status,
    );
}

/// Child: run App with short watchdog, shut down, sleep past abort window.
async fn child_main() {
    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let db_path = tmp.path().join("test.db");

    let mut config = ConfigBuilder::new().database_path(&db_path).build();
    config.diagnostics.watchdog_abort_secs = 2;
    // Prevent start_overlay() from injecting testnet/mainnet seed peers.
    config.is_compat_config = true;
    // Fully hermetic — no DNS resolution or TCP connections.
    config.overlay.known_peers = vec![];
    config.overlay.target_outbound_peers = 0;
    config.overlay.max_outbound_peers = 0;

    let runner = Arc::new(
        NodeRunner::new(config, RunOptions::watcher())
            .await
            .expect("failed to create NodeRunner"),
    );

    // Spawn the run loop (which starts the watchdog thread internally).
    let runner_for_task = runner.clone();
    let run_handle = tokio::spawn(async move { runner_for_task.run().await });

    // Wait for AppState::Synced — proves the event loop started and
    // last_event_loop_tick_ms is non-zero (watchdog is active).
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if run_handle.is_finished() {
            panic!("run task exited before reaching Synced state");
        }
        let state = runner.app().state().await;
        if state == AppState::Synced {
            break;
        }
        if Instant::now() > deadline {
            panic!(
                "timed out waiting for Synced state (last observed: {:?})",
                state
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Trigger clean shutdown — this drops WatchdogGuard in the event loop,
    // which signals the watchdog thread to exit.
    runner.shutdown();

    // Await run task completion to ensure WatchdogGuard::drop() has executed.
    let result = tokio::time::timeout(Duration::from_secs(5), run_handle)
        .await
        .expect("shutdown timed out after 5s")
        .expect("run task panicked");
    result.expect("run task returned an error");

    // Sleep past the abort window. Without the WatchdogGuard fix, an
    // orphaned watchdog thread would wake from its 10s condvar poll, find
    // last_event_loop_tick_ms stale by ≥10s (exceeding watchdog_abort_secs=2),
    // and call process::abort(). With the fix, the thread has already exited,
    // so this sleep completes without incident.
    std::thread::sleep(Duration::from_secs(25));

    // If we reach here, the watchdog did NOT abort — the fix is working.
}
