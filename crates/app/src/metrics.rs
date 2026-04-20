//! Prometheus metrics facade for the henyey node.
//!
//! This module is the single source of truth for all metric names, types,
//! descriptions, and scrape-time refresh logic. It wraps the [`metrics`] crate
//! facade to provide:
//!
//! - Centralized metric name constants
//! - One-time HELP/TYPE registration via [`describe_metrics`]
//! - Pre-registration of labeled counter series at zero via [`register_label_series`]
//! - Scrape-time gauge refresh via [`refresh_gauges`]
//! - A once-per-process test helper via [`ensure_test_recorder`]

use std::sync::OnceLock;

use metrics::{counter, describe_counter, describe_gauge, gauge};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

use crate::http::ServerState;

// ── Metric name constants ──────────────────────────────────────────────

// Stellar-compatible names (backward compatibility with existing dashboards).
pub const LEDGER_SEQUENCE: &str = "stellar_ledger_sequence";
pub const PEER_COUNT: &str = "stellar_peer_count";
pub const PENDING_TRANSACTIONS: &str = "stellar_pending_transactions";
pub const UPTIME_SECONDS: &str = "stellar_uptime_seconds";
pub const IS_VALIDATOR: &str = "stellar_is_validator";
pub const META_STREAM_BYTES_TOTAL: &str = "stellar_meta_stream_bytes_total";
pub const META_STREAM_WRITES_TOTAL: &str = "stellar_meta_stream_writes_total";

// Henyey-specific metrics.
pub const SCP_PREFILTER_REJECTS_TOTAL: &str = "henyey_scp_prefilter_rejects_total";
pub const SCP_POST_VERIFY_DROPS_TOTAL: &str = "henyey_scp_post_verify_drops_total";
pub const SCP_POST_VERIFY_TOTAL: &str = "henyey_scp_post_verify_total";
pub const SCP_VERIFY_INPUT_BACKLOG: &str = "henyey_scp_verify_input_backlog";
pub const SCP_VERIFY_OUTPUT_BACKLOG: &str = "henyey_scp_verify_output_backlog";
pub const SCP_VERIFIER_THREAD_STATE: &str = "henyey_scp_verifier_thread_state";
pub const SCP_VERIFY_LATENCY_US_SUM: &str = "henyey_scp_verify_latency_us_sum";
pub const SCP_VERIFY_LATENCY_US_COUNT: &str = "henyey_scp_verify_latency_us_count";
pub const OVERLAY_FETCH_CHANNEL_DEPTH: &str = "henyey_overlay_fetch_channel_depth";
pub const OVERLAY_FETCH_CHANNEL_DEPTH_MAX: &str = "henyey_overlay_fetch_channel_depth_max";
pub const POST_CATCHUP_HARD_RESET_TOTAL: &str = "henyey_post_catchup_hard_reset_total";

// SCP/herder counters (Phase 1 — expose already-tracked App-level counters).
pub const SCP_ENVELOPE_EMIT_TOTAL: &str = "stellar_scp_envelope_emit_total";
pub const SCP_ENVELOPE_RECEIVE_TOTAL: &str = "stellar_scp_envelope_receive_total";
pub const HERDER_LOST_SYNC_TOTAL: &str = "stellar_herder_lost_sync_total";
pub const HERDER_STATE: &str = "stellar_herder_state";
pub const HERDER_PENDING_ENVELOPES: &str = "stellar_herder_pending_envelopes";
pub const HERDER_CACHED_TX_SETS: &str = "stellar_herder_cached_tx_sets";
pub const HERDER_PENDING_RECEIVED_TOTAL: &str = "stellar_herder_pending_received_total";
pub const HERDER_PENDING_DUPLICATES_TOTAL: &str = "stellar_herder_pending_duplicates_total";
pub const HERDER_PENDING_TOO_OLD_TOTAL: &str = "stellar_herder_pending_too_old_total";
pub const HERDER_PENDING_EVICTED_TOTAL: &str = "stellar_herder_pending_evicted_total";

// Bucket merge counters (Phase 1 — live MergeCounters from BucketList).
pub const BUCKET_MERGE_COMPLETED_TOTAL: &str = "stellar_bucket_merge_completed_total";
pub const BUCKET_MERGE_TIME_US_TOTAL: &str = "stellar_bucket_merge_time_us_total";
pub const BUCKET_MERGE_NEW_LIVE_TOTAL: &str = "stellar_bucket_merge_new_live_total";
pub const BUCKET_MERGE_NEW_DEAD_TOTAL: &str = "stellar_bucket_merge_new_dead_total";
pub const BUCKET_MERGE_NEW_INIT_TOTAL: &str = "stellar_bucket_merge_new_init_total";
pub const BUCKET_MERGE_NEW_META_TOTAL: &str = "stellar_bucket_merge_new_meta_total";
pub const BUCKET_MERGE_SHADOWED_TOTAL: &str = "stellar_bucket_merge_shadowed_total";
pub const BUCKET_MERGE_ANNIHILATED_TOTAL: &str = "stellar_bucket_merge_annihilated_total";

// Overlay counters (Phase 1 — wired to OverlayMetrics in OverlayManager).
pub const OVERLAY_MESSAGE_READ_TOTAL: &str = "stellar_overlay_message_read_total";
pub const OVERLAY_MESSAGE_WRITE_TOTAL: &str = "stellar_overlay_message_write_total";
pub const OVERLAY_MESSAGE_BROADCAST_TOTAL: &str = "stellar_overlay_message_broadcast_total";
pub const OVERLAY_ERROR_READ_TOTAL: &str = "stellar_overlay_error_read_total";
pub const OVERLAY_ERROR_WRITE_TOTAL: &str = "stellar_overlay_error_write_total";
pub const OVERLAY_TIMEOUT_IDLE_TOTAL: &str = "stellar_overlay_timeout_idle_total";
pub const OVERLAY_TIMEOUT_STRAGGLER_TOTAL: &str = "stellar_overlay_timeout_straggler_total";

// Ledger close metrics (Phase 2 — per-ledger snapshot gauges).
pub const LEDGER_CLOSE_TIME_MS: &str = "stellar_ledger_close_time_ms";
pub const LEDGER_TX_COUNT: &str = "stellar_ledger_tx_count";
pub const LEDGER_OP_COUNT: &str = "stellar_ledger_op_count";
pub const LEDGER_TX_SUCCESS_COUNT: &str = "stellar_ledger_tx_success_count";
pub const LEDGER_TX_FAILED_COUNT: &str = "stellar_ledger_tx_failed_count";
pub const LEDGER_TOTAL_FEES: &str = "stellar_ledger_total_fees";
pub const LEDGER_ENTRIES_CREATED: &str = "stellar_ledger_entries_created";
pub const LEDGER_ENTRIES_UPDATED: &str = "stellar_ledger_entries_updated";
pub const LEDGER_ENTRIES_DELETED: &str = "stellar_ledger_entries_deleted";
pub const LEDGER_APPLY_US: &str = "stellar_ledger_apply_us";

// Herder tx queue metrics (Phase 2 — from TxQueueStats).
pub const HERDER_TX_QUEUE_ACCOUNTS: &str = "stellar_herder_tx_queue_accounts";
pub const HERDER_TX_QUEUE_BANNED: &str = "stellar_herder_tx_queue_banned";
pub const HERDER_TX_QUEUE_SEEN: &str = "stellar_herder_tx_queue_seen";

// Herder pending envelope metrics (Phase 2 — completing the set).
pub const HERDER_PENDING_ADDED_TOTAL: &str = "stellar_herder_pending_added_total";
pub const HERDER_PENDING_RELEASED_TOTAL: &str = "stellar_herder_pending_released_total";

// Clock drift metrics (Phase 2 — from CloseTimeDriftTracker).
pub const DRIFT_MIN_SECONDS: &str = "henyey_herder_drift_min_seconds";
pub const DRIFT_MAX_SECONDS: &str = "henyey_herder_drift_max_seconds";
pub const DRIFT_MEDIAN_SECONDS: &str = "henyey_herder_drift_median_seconds";
pub const DRIFT_P75_SECONDS: &str = "henyey_herder_drift_p75_seconds";
pub const DRIFT_SAMPLE_COUNT: &str = "henyey_herder_drift_sample_count";

// ── Registration ───────────────────────────────────────────────────────

/// Register HELP/TYPE annotations for all metrics.
///
/// Must be called **after** the global recorder is installed, otherwise
/// the descriptions are silently dropped.
pub fn describe_metrics() {
    // Stellar-compatible gauges.
    describe_gauge!(LEDGER_SEQUENCE, "Current ledger sequence number");
    describe_gauge!(PEER_COUNT, "Number of connected peers");
    describe_gauge!(PENDING_TRANSACTIONS, "Number of pending transactions");
    describe_counter!(UPTIME_SECONDS, "Node uptime in seconds");
    describe_gauge!(IS_VALIDATOR, "Whether this node is a validator");
    describe_counter!(
        META_STREAM_BYTES_TOTAL,
        "Total bytes written to metadata output stream"
    );
    describe_counter!(
        META_STREAM_WRITES_TOTAL,
        "Total frames written to metadata output stream"
    );

    // SCP verify pipeline.
    describe_counter!(
        SCP_PREFILTER_REJECTS_TOTAL,
        "SCP envelopes rejected by the event-loop pre-filter, by reason"
    );
    describe_counter!(
        SCP_POST_VERIFY_DROPS_TOTAL,
        "Envelopes dropped after verification (aggregate)"
    );
    describe_counter!(
        SCP_POST_VERIFY_TOTAL,
        "Envelopes processed by post-verify, by reason"
    );
    describe_gauge!(
        SCP_VERIFY_INPUT_BACKLOG,
        "Current depth of the SCP signature-verify input channel (event-loop sampled)"
    );
    describe_gauge!(
        SCP_VERIFY_OUTPUT_BACKLOG,
        "Current depth of the verified-envelope output channel (envelopes awaiting the event loop)"
    );
    describe_gauge!(
        SCP_VERIFIER_THREAD_STATE,
        "Worker thread state (0=Running, 1=Stopping, 2=Dead)"
    );
    // SCP verify latency — formerly exposed as a synthetic Prometheus
    // "summary" (`# TYPE henyey_scp_verify_latency_us summary` with _sum
    // and _count sub-metrics). The `metrics` crate has no native summary
    // type, so these are now separate gauges. Consumers computing average
    // latency as sum/count continue to work unchanged.
    describe_gauge!(
        SCP_VERIFY_LATENCY_US_SUM,
        "Enqueue-to-post-verify latency microseconds (cumulative sum)"
    );
    describe_gauge!(
        SCP_VERIFY_LATENCY_US_COUNT,
        "Enqueue-to-post-verify latency sample count"
    );

    // Overlay fetch channel.
    describe_gauge!(
        OVERLAY_FETCH_CHANNEL_DEPTH,
        "Current depth of the overlay fetch-response channel (event-loop sampled)"
    );
    describe_gauge!(
        OVERLAY_FETCH_CHANNEL_DEPTH_MAX,
        "Monotonic maximum depth of the overlay fetch-response channel since process start"
    );

    // Catchup.
    describe_counter!(
        POST_CATCHUP_HARD_RESET_TOTAL,
        "Total post-catchup hard resets performed"
    );

    // SCP/herder counters.
    describe_counter!(
        SCP_ENVELOPE_EMIT_TOTAL,
        "Total SCP envelopes emitted by the local node"
    );
    describe_counter!(
        SCP_ENVELOPE_RECEIVE_TOTAL,
        "Total SCP envelopes received from peers"
    );
    describe_counter!(
        HERDER_LOST_SYNC_TOTAL,
        "Total lost-sync events (transitions out of Tracking)"
    );
    describe_gauge!(
        HERDER_STATE,
        "Herder state (0=Booting, 1=Syncing, 2=Tracking)"
    );
    describe_gauge!(
        HERDER_PENDING_ENVELOPES,
        "SCP envelopes queued in pending pool"
    );
    describe_gauge!(
        HERDER_CACHED_TX_SETS,
        "Transaction sets cached for pending SCP slots"
    );
    describe_counter!(
        HERDER_PENDING_RECEIVED_TOTAL,
        "Total envelopes received by pending pool"
    );
    describe_counter!(
        HERDER_PENDING_DUPLICATES_TOTAL,
        "Envelopes rejected as duplicates by pending pool"
    );
    describe_counter!(
        HERDER_PENDING_TOO_OLD_TOTAL,
        "Envelopes rejected as too old by pending pool"
    );
    describe_counter!(
        HERDER_PENDING_EVICTED_TOTAL,
        "Envelopes evicted from pending pool"
    );

    // Bucket merge counters.
    describe_counter!(
        BUCKET_MERGE_COMPLETED_TOTAL,
        "Total bucket merges completed"
    );
    describe_counter!(
        BUCKET_MERGE_TIME_US_TOTAL,
        "Total bucket merge time in microseconds"
    );
    describe_counter!(
        BUCKET_MERGE_NEW_LIVE_TOTAL,
        "Total new LIVEENTRY entries written during merges"
    );
    describe_counter!(
        BUCKET_MERGE_NEW_DEAD_TOTAL,
        "Total new DEADENTRY entries written during merges"
    );
    describe_counter!(
        BUCKET_MERGE_NEW_INIT_TOTAL,
        "Total new INITENTRY entries written during merges"
    );
    describe_counter!(
        BUCKET_MERGE_NEW_META_TOTAL,
        "Total new METAENTRY entries written during merges"
    );
    describe_counter!(
        BUCKET_MERGE_SHADOWED_TOTAL,
        "Total entries shadowed during merges"
    );
    describe_counter!(
        BUCKET_MERGE_ANNIHILATED_TOTAL,
        "Total INIT+DEAD entry pairs annihilated during merges"
    );

    // Overlay counters.
    describe_counter!(
        OVERLAY_MESSAGE_READ_TOTAL,
        "Total overlay messages read from peers"
    );
    describe_counter!(
        OVERLAY_MESSAGE_WRITE_TOTAL,
        "Total overlay messages written to peers"
    );
    describe_counter!(
        OVERLAY_MESSAGE_BROADCAST_TOTAL,
        "Total overlay messages broadcast to all peers"
    );
    describe_counter!(OVERLAY_ERROR_READ_TOTAL, "Total overlay read errors");
    describe_counter!(OVERLAY_ERROR_WRITE_TOTAL, "Total overlay write errors");
    describe_counter!(
        OVERLAY_TIMEOUT_IDLE_TOTAL,
        "Total peers dropped due to idle timeout"
    );
    describe_counter!(
        OVERLAY_TIMEOUT_STRAGGLER_TOTAL,
        "Total peers dropped due to straggler timeout"
    );

    // Ledger close metrics.
    describe_gauge!(
        LEDGER_CLOSE_TIME_MS,
        "Wall-clock time of the most recent ledger close (milliseconds)"
    );
    describe_gauge!(LEDGER_TX_COUNT, "Transactions processed in the last close");
    describe_gauge!(LEDGER_OP_COUNT, "Operations executed in the last close");
    describe_gauge!(
        LEDGER_TX_SUCCESS_COUNT,
        "Successful transactions in the last close"
    );
    describe_gauge!(
        LEDGER_TX_FAILED_COUNT,
        "Failed transactions in the last close"
    );
    describe_gauge!(
        LEDGER_TOTAL_FEES,
        "Fees collected in the last close (stroops)"
    );
    describe_gauge!(
        LEDGER_ENTRIES_CREATED,
        "Ledger entries created in the last close"
    );
    describe_gauge!(
        LEDGER_ENTRIES_UPDATED,
        "Ledger entries updated in the last close"
    );
    describe_gauge!(
        LEDGER_ENTRIES_DELETED,
        "Ledger entries deleted in the last close"
    );
    describe_gauge!(LEDGER_APPLY_US, "Total ledger close time in microseconds");

    // Herder tx queue metrics.
    describe_gauge!(
        HERDER_TX_QUEUE_ACCOUNTS,
        "Accounts with pending transactions in the queue"
    );
    describe_gauge!(
        HERDER_TX_QUEUE_BANNED,
        "Currently banned transactions in the queue"
    );
    describe_gauge!(
        HERDER_TX_QUEUE_SEEN,
        "Deduplicated transaction hashes in the seen set"
    );

    // Herder pending envelope metrics.
    describe_counter!(
        HERDER_PENDING_ADDED_TOTAL,
        "Envelopes added to the pending pool"
    );
    describe_counter!(
        HERDER_PENDING_RELEASED_TOTAL,
        "Envelopes released from the pending pool"
    );

    // Clock drift metrics.
    describe_gauge!(
        DRIFT_MIN_SECONDS,
        "Minimum close time drift in the last completed window (seconds)"
    );
    describe_gauge!(
        DRIFT_MAX_SECONDS,
        "Maximum close time drift in the last completed window (seconds)"
    );
    describe_gauge!(
        DRIFT_MEDIAN_SECONDS,
        "Median close time drift in the last completed window (seconds)"
    );
    describe_gauge!(
        DRIFT_P75_SECONDS,
        "75th percentile close time drift in the last completed window (seconds)"
    );
    describe_gauge!(
        DRIFT_SAMPLE_COUNT,
        "Number of samples in the last completed drift window"
    );
}

/// Pre-register all metrics with initial values so that every metric appears
/// on the very first scrape with its HELP/TYPE annotations.
///
/// Must be called **after** [`describe_metrics`].
pub fn register_label_series() {
    use henyey_herder::scp_verify::{PostVerifyReason, PreFilterRejectReason};

    // Initialize all gauges to zero so they appear in output.
    gauge!(LEDGER_SEQUENCE).set(0.0);
    gauge!(PEER_COUNT).set(0.0);
    gauge!(PENDING_TRANSACTIONS).set(0.0);
    counter!(UPTIME_SECONDS).absolute(0);
    gauge!(IS_VALIDATOR).set(0.0);
    // Note: meta stream counters are intentionally NOT pre-registered —
    // they only appear when the meta stream is active (matching current behavior).

    // SCP verify pipeline gauges.
    gauge!(SCP_VERIFY_INPUT_BACKLOG).set(0.0);
    gauge!(SCP_VERIFY_OUTPUT_BACKLOG).set(0.0);
    gauge!(SCP_VERIFIER_THREAD_STATE).set(0.0);
    gauge!(SCP_VERIFY_LATENCY_US_SUM).set(0.0);
    gauge!(SCP_VERIFY_LATENCY_US_COUNT).set(0.0);

    // Overlay fetch channel gauges.
    gauge!(OVERLAY_FETCH_CHANNEL_DEPTH).set(0.0);
    gauge!(OVERLAY_FETCH_CHANNEL_DEPTH_MAX).set(0.0);

    // Counters.
    counter!(SCP_POST_VERIFY_DROPS_TOTAL).absolute(0);
    counter!(POST_CATCHUP_HARD_RESET_TOTAL).absolute(0);

    // SCP/herder counters.
    counter!(SCP_ENVELOPE_EMIT_TOTAL).absolute(0);
    counter!(SCP_ENVELOPE_RECEIVE_TOTAL).absolute(0);
    counter!(HERDER_LOST_SYNC_TOTAL).absolute(0);
    gauge!(HERDER_STATE).set(0.0);
    gauge!(HERDER_PENDING_ENVELOPES).set(0.0);
    gauge!(HERDER_CACHED_TX_SETS).set(0.0);
    counter!(HERDER_PENDING_RECEIVED_TOTAL).absolute(0);
    counter!(HERDER_PENDING_DUPLICATES_TOTAL).absolute(0);
    counter!(HERDER_PENDING_TOO_OLD_TOTAL).absolute(0);
    counter!(HERDER_PENDING_EVICTED_TOTAL).absolute(0);

    // Bucket merge counters.
    counter!(BUCKET_MERGE_COMPLETED_TOTAL).absolute(0);
    counter!(BUCKET_MERGE_TIME_US_TOTAL).absolute(0);
    counter!(BUCKET_MERGE_NEW_LIVE_TOTAL).absolute(0);
    counter!(BUCKET_MERGE_NEW_DEAD_TOTAL).absolute(0);
    counter!(BUCKET_MERGE_NEW_INIT_TOTAL).absolute(0);
    counter!(BUCKET_MERGE_NEW_META_TOTAL).absolute(0);
    counter!(BUCKET_MERGE_SHADOWED_TOTAL).absolute(0);
    counter!(BUCKET_MERGE_ANNIHILATED_TOTAL).absolute(0);

    // Overlay counters.
    counter!(OVERLAY_MESSAGE_READ_TOTAL).absolute(0);
    counter!(OVERLAY_MESSAGE_WRITE_TOTAL).absolute(0);
    counter!(OVERLAY_MESSAGE_BROADCAST_TOTAL).absolute(0);
    counter!(OVERLAY_ERROR_READ_TOTAL).absolute(0);
    counter!(OVERLAY_ERROR_WRITE_TOTAL).absolute(0);
    counter!(OVERLAY_TIMEOUT_IDLE_TOTAL).absolute(0);
    counter!(OVERLAY_TIMEOUT_STRAGGLER_TOTAL).absolute(0);

    // Ledger close gauges (Phase 2).
    gauge!(LEDGER_CLOSE_TIME_MS).set(0.0);
    gauge!(LEDGER_TX_COUNT).set(0.0);
    gauge!(LEDGER_OP_COUNT).set(0.0);
    gauge!(LEDGER_TX_SUCCESS_COUNT).set(0.0);
    gauge!(LEDGER_TX_FAILED_COUNT).set(0.0);
    gauge!(LEDGER_TOTAL_FEES).set(0.0);
    gauge!(LEDGER_ENTRIES_CREATED).set(0.0);
    gauge!(LEDGER_ENTRIES_UPDATED).set(0.0);
    gauge!(LEDGER_ENTRIES_DELETED).set(0.0);
    gauge!(LEDGER_APPLY_US).set(0.0);

    // Herder tx queue gauges (Phase 2).
    gauge!(HERDER_TX_QUEUE_ACCOUNTS).set(0.0);
    gauge!(HERDER_TX_QUEUE_BANNED).set(0.0);
    gauge!(HERDER_TX_QUEUE_SEEN).set(0.0);

    // Herder pending envelope counters (Phase 2).
    counter!(HERDER_PENDING_ADDED_TOTAL).absolute(0);
    counter!(HERDER_PENDING_RELEASED_TOTAL).absolute(0);

    // Clock drift gauges (Phase 2).
    gauge!(DRIFT_MIN_SECONDS).set(0.0);
    gauge!(DRIFT_MAX_SECONDS).set(0.0);
    gauge!(DRIFT_MEDIAN_SECONDS).set(0.0);
    gauge!(DRIFT_P75_SECONDS).set(0.0);
    gauge!(DRIFT_SAMPLE_COUNT).set(0.0);

    // Labeled counters — all reason labels pre-registered at zero.
    for reason in PreFilterRejectReason::ALL {
        counter!(SCP_PREFILTER_REJECTS_TOTAL, "reason" => reason.label()).absolute(0);
    }
    for reason in PostVerifyReason::ALL {
        counter!(SCP_POST_VERIFY_TOTAL, "reason" => reason.label()).absolute(0);
    }
}

// ── Scrape-time refresh ────────────────────────────────────────────────

/// Update scrape-time gauges and absolute counters from current App state.
///
/// Called by the `/metrics` handler immediately before `handle.render()`.
pub(crate) async fn refresh_gauges(state: &ServerState) {
    let _app_state = state.app.state().await;
    let uptime = state.start_time.elapsed().as_secs();
    let ledger_seq = state.app.ledger_info().ledger_seq;
    let peer_count = state.app.peer_snapshots().await.len();
    let pending_txs = state.app.pending_transaction_count() as u64;
    let app_info = state.app.info();

    // Stellar-compatible gauges.
    gauge!(LEDGER_SEQUENCE).set(ledger_seq as f64);
    gauge!(PEER_COUNT).set(peer_count as f64);
    gauge!(PENDING_TRANSACTIONS).set(pending_txs as f64);
    counter!(UPTIME_SECONDS).absolute(uptime);
    gauge!(IS_VALIDATOR).set(if app_info.is_validator { 1.0 } else { 0.0 });

    // Meta stream counters — only set when active (matching current conditional behavior).
    if app_info.meta_stream_bytes_total > 0 || app_info.meta_stream_writes_total > 0 {
        counter!(META_STREAM_BYTES_TOTAL).absolute(app_info.meta_stream_bytes_total);
        counter!(META_STREAM_WRITES_TOTAL).absolute(app_info.meta_stream_writes_total);
    }

    // SCP verify pipeline — absolute counters.
    let sv = &app_info.scp_verify;
    for (reason, &count) in sv.prefilter_counters.iter() {
        counter!(SCP_PREFILTER_REJECTS_TOTAL, "reason" => reason.label()).absolute(count);
    }
    counter!(SCP_POST_VERIFY_DROPS_TOTAL).absolute(sv.post_verify_drops);
    for (reason, &count) in sv.pv_counters.iter() {
        counter!(SCP_POST_VERIFY_TOTAL, "reason" => reason.label()).absolute(count);
    }

    // SCP verify pipeline — gauges.
    gauge!(SCP_VERIFY_INPUT_BACKLOG).set(sv.verify_input_backlog as f64);
    gauge!(SCP_VERIFY_OUTPUT_BACKLOG).set(sv.verify_output_backlog as f64);
    gauge!(SCP_VERIFIER_THREAD_STATE).set(sv.verifier_thread_state as f64);
    gauge!(SCP_VERIFY_LATENCY_US_SUM).set(sv.verify_latency_us_sum as f64);
    gauge!(SCP_VERIFY_LATENCY_US_COUNT).set(sv.verify_latency_count as f64);

    // Overlay fetch channel.
    gauge!(OVERLAY_FETCH_CHANNEL_DEPTH).set(app_info.overlay_fetch_channel.depth as f64);
    gauge!(OVERLAY_FETCH_CHANNEL_DEPTH_MAX).set(app_info.overlay_fetch_channel.depth_max as f64);

    // Catchup.
    counter!(POST_CATCHUP_HARD_RESET_TOTAL).absolute(app_info.post_catchup_hard_reset_total);

    // SCP/herder counters.
    let (scp_sent, scp_received) = state.app.scp_envelope_counters();
    counter!(SCP_ENVELOPE_EMIT_TOTAL).absolute(scp_sent);
    counter!(SCP_ENVELOPE_RECEIVE_TOTAL).absolute(scp_received);
    counter!(HERDER_LOST_SYNC_TOTAL).absolute(state.app.lost_sync_count());

    let herder = state.app.herder_stats();
    let herder_state_val = match herder.state {
        henyey_herder::HerderState::Booting => 0.0,
        henyey_herder::HerderState::Syncing => 1.0,
        henyey_herder::HerderState::Tracking => 2.0,
    };
    gauge!(HERDER_STATE).set(herder_state_val);
    gauge!(HERDER_PENDING_ENVELOPES).set(herder.pending_envelopes as f64);
    gauge!(HERDER_CACHED_TX_SETS).set(herder.cached_tx_sets as f64);

    let pstats = &herder.pending_envelope_stats;
    counter!(HERDER_PENDING_RECEIVED_TOTAL).absolute(pstats.received);
    counter!(HERDER_PENDING_DUPLICATES_TOTAL).absolute(pstats.duplicates);
    counter!(HERDER_PENDING_TOO_OLD_TOTAL).absolute(pstats.too_old);
    counter!(HERDER_PENDING_EVICTED_TOTAL).absolute(pstats.evicted);

    // Bucket merge counters.
    let mc = state.app.merge_counters_snapshot();
    counter!(BUCKET_MERGE_COMPLETED_TOTAL).absolute(mc.merges_completed);
    counter!(BUCKET_MERGE_TIME_US_TOTAL).absolute(mc.merge_time_us);
    counter!(BUCKET_MERGE_NEW_LIVE_TOTAL).absolute(mc.new_live_entries);
    counter!(BUCKET_MERGE_NEW_DEAD_TOTAL).absolute(mc.new_dead_entries);
    counter!(BUCKET_MERGE_NEW_INIT_TOTAL).absolute(mc.new_init_entries);
    counter!(BUCKET_MERGE_NEW_META_TOTAL).absolute(mc.new_meta_entries);
    counter!(BUCKET_MERGE_SHADOWED_TOTAL).absolute(mc.old_entries_shadowed);
    counter!(BUCKET_MERGE_ANNIHILATED_TOTAL).absolute(mc.entries_annihilated);

    // Overlay counters (if overlay is running).
    if let Some(ov) = state.app.overlay_metrics_snapshot().await {
        counter!(OVERLAY_MESSAGE_READ_TOTAL).absolute(ov.messages_read);
        counter!(OVERLAY_MESSAGE_WRITE_TOTAL).absolute(ov.messages_written);
        counter!(OVERLAY_MESSAGE_BROADCAST_TOTAL).absolute(ov.messages_broadcast);
        counter!(OVERLAY_ERROR_READ_TOTAL).absolute(ov.errors_read);
        counter!(OVERLAY_ERROR_WRITE_TOTAL).absolute(ov.errors_write);
        counter!(OVERLAY_TIMEOUT_IDLE_TOTAL).absolute(ov.timeouts_idle);
        counter!(OVERLAY_TIMEOUT_STRAGGLER_TOTAL).absolute(ov.timeouts_straggler);
    }

    // Ledger close stats (Phase 2).
    let lcs = state.app.last_close_stats();
    gauge!(LEDGER_CLOSE_TIME_MS).set(lcs.close_time_ms as f64);
    gauge!(LEDGER_TX_COUNT).set(lcs.tx_count as f64);
    gauge!(LEDGER_OP_COUNT).set(lcs.op_count as f64);
    gauge!(LEDGER_TX_SUCCESS_COUNT).set(lcs.tx_success_count as f64);
    gauge!(LEDGER_TX_FAILED_COUNT).set(lcs.tx_failed_count as f64);
    gauge!(LEDGER_TOTAL_FEES).set(lcs.total_fees as f64);
    gauge!(LEDGER_ENTRIES_CREATED).set(lcs.entries_created as f64);
    gauge!(LEDGER_ENTRIES_UPDATED).set(lcs.entries_updated as f64);
    gauge!(LEDGER_ENTRIES_DELETED).set(lcs.entries_deleted as f64);

    // Ledger apply timing (Phase 2).
    if let Some(perf) = state.app.last_close_perf() {
        gauge!(LEDGER_APPLY_US).set(perf.total_us as f64);
    }

    // Herder tx queue stats (Phase 2).
    let tq = &herder.tx_queue_stats;
    gauge!(HERDER_TX_QUEUE_ACCOUNTS).set(tq.account_count as f64);
    gauge!(HERDER_TX_QUEUE_BANNED).set(tq.banned_count as f64);
    gauge!(HERDER_TX_QUEUE_SEEN).set(tq.seen_count as f64);

    // Herder pending envelope stats — added + released (Phase 2).
    counter!(HERDER_PENDING_ADDED_TOTAL).absolute(pstats.added);
    counter!(HERDER_PENDING_RELEASED_TOTAL).absolute(pstats.released);

    // Clock drift (Phase 2) — always write, zeros when no completed window.
    if let Some(ds) = state.app.drift_stats() {
        gauge!(DRIFT_MIN_SECONDS).set(ds.min as f64);
        gauge!(DRIFT_MAX_SECONDS).set(ds.max as f64);
        gauge!(DRIFT_MEDIAN_SECONDS).set(ds.median as f64);
        gauge!(DRIFT_P75_SECONDS).set(ds.p75 as f64);
        gauge!(DRIFT_SAMPLE_COUNT).set(ds.sample_count as f64);
    } else {
        gauge!(DRIFT_MIN_SECONDS).set(0.0);
        gauge!(DRIFT_MAX_SECONDS).set(0.0);
        gauge!(DRIFT_MEDIAN_SECONDS).set(0.0);
        gauge!(DRIFT_P75_SECONDS).set(0.0);
        gauge!(DRIFT_SAMPLE_COUNT).set(0.0);
    }
}

// ── Test helper ────────────────────────────────────────────────────────

/// Install the metrics recorder once per test process and return a handle.
///
/// The `metrics` global recorder is one-shot per process. Since Rust tests
/// run in parallel within the same process, this helper ensures the recorder
/// is installed exactly once. Subsequent calls return the same handle.
pub fn ensure_test_recorder() -> &'static PrometheusHandle {
    static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
    HANDLE.get_or_init(|| {
        PrometheusBuilder::new()
            .set_buckets(&[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0])
            .expect("valid histogram buckets")
            .install_recorder()
            .expect("metrics recorder should install successfully")
    })
}

/// Install the production metrics recorder.
///
/// Returns the `PrometheusHandle` for use by the `/metrics` endpoint.
///
/// This is safe to call from `main()` before constructing `RunOptions`, or
/// from `run_node()` as a fallback when no handle was provided. If a
/// recorder is already installed (e.g. by a library consumer), this panics
/// — callers who need tolerance for that should pre-install and pass the
/// handle via `RunOptions::prometheus_handle`.
pub fn install_recorder() -> PrometheusHandle {
    let handle = PrometheusBuilder::new()
        .set_buckets(&[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0])
        .expect("valid histogram buckets")
        .install_recorder()
        .expect("metrics recorder should install successfully");
    describe_metrics();
    register_label_series();
    handle
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_describe_metrics_registers_help_lines() {
        let handle = ensure_test_recorder();
        describe_metrics();
        register_label_series();
        let output = handle.render();

        // Verify HELP lines are present for key metrics.
        assert!(
            output.contains("# HELP stellar_ledger_sequence"),
            "missing HELP for ledger_sequence"
        );
        assert!(
            output.contains("# HELP stellar_uptime_seconds"),
            "missing HELP for uptime_seconds"
        );
        assert!(
            output.contains("# HELP henyey_scp_prefilter_rejects_total"),
            "missing HELP for prefilter_rejects_total"
        );
        assert!(
            output.contains("# HELP henyey_scp_post_verify_total"),
            "missing HELP for post_verify_total"
        );
        assert!(
            output.contains("# HELP henyey_post_catchup_hard_reset_total"),
            "missing HELP for hard_reset_total"
        );

        // Phase 1: SCP/herder.
        assert!(
            output.contains("# HELP stellar_scp_envelope_emit_total"),
            "missing HELP for scp_envelope_emit_total"
        );
        assert!(
            output.contains("# HELP stellar_herder_state"),
            "missing HELP for herder_state"
        );
        assert!(
            output.contains("# HELP stellar_herder_pending_envelopes"),
            "missing HELP for herder_pending_envelopes"
        );

        // Phase 1: Bucket merge.
        assert!(
            output.contains("# HELP stellar_bucket_merge_completed_total"),
            "missing HELP for bucket_merge_completed_total"
        );
        assert!(
            output.contains("# HELP stellar_bucket_merge_shadowed_total"),
            "missing HELP for bucket_merge_shadowed_total"
        );

        // Phase 1: Overlay.
        assert!(
            output.contains("# HELP stellar_overlay_message_read_total"),
            "missing HELP for overlay_message_read_total"
        );
        assert!(
            output.contains("# HELP stellar_overlay_timeout_idle_total"),
            "missing HELP for overlay_timeout_idle_total"
        );
    }

    #[test]
    fn test_type_annotations_present() {
        let handle = ensure_test_recorder();
        describe_metrics();
        register_label_series();
        let output = handle.render();

        // Gauges must have TYPE gauge.
        assert!(
            output.contains("# TYPE stellar_ledger_sequence gauge"),
            "missing TYPE gauge for ledger_sequence"
        );
        assert!(
            output.contains("# TYPE stellar_peer_count gauge"),
            "missing TYPE gauge for peer_count"
        );
        assert!(
            output.contains("# TYPE henyey_scp_verify_latency_us_sum gauge"),
            "missing TYPE gauge for latency_us_sum"
        );
        assert!(
            output.contains("# TYPE henyey_scp_verify_latency_us_count gauge"),
            "missing TYPE gauge for latency_us_count"
        );

        // Counters must have TYPE counter.
        assert!(
            output.contains("# TYPE stellar_uptime_seconds counter"),
            "missing TYPE counter for uptime_seconds"
        );
        assert!(
            output.contains("# TYPE henyey_scp_prefilter_rejects_total counter"),
            "missing TYPE counter for prefilter_rejects_total"
        );
        assert!(
            output.contains("# TYPE henyey_post_catchup_hard_reset_total counter"),
            "missing TYPE counter for hard_reset_total"
        );

        // Phase 1: SCP/herder types.
        assert!(
            output.contains("# TYPE stellar_scp_envelope_emit_total counter"),
            "missing TYPE counter for scp_envelope_emit_total"
        );
        assert!(
            output.contains("# TYPE stellar_herder_state gauge"),
            "missing TYPE gauge for herder_state"
        );
        assert!(
            output.contains("# TYPE stellar_herder_pending_received_total counter"),
            "missing TYPE counter for herder_pending_received_total"
        );

        // Phase 1: Bucket merge types.
        assert!(
            output.contains("# TYPE stellar_bucket_merge_completed_total counter"),
            "missing TYPE counter for bucket_merge_completed_total"
        );
        assert!(
            output.contains("# TYPE stellar_bucket_merge_annihilated_total counter"),
            "missing TYPE counter for bucket_merge_annihilated_total"
        );

        // Phase 1: Overlay types.
        assert!(
            output.contains("# TYPE stellar_overlay_message_read_total counter"),
            "missing TYPE counter for overlay_message_read_total"
        );
        assert!(
            output.contains("# TYPE stellar_overlay_error_write_total counter"),
            "missing TYPE counter for overlay_error_write_total"
        );
    }

    #[test]
    fn test_labeled_series_present_at_zero() {
        let handle = ensure_test_recorder();
        describe_metrics();
        register_label_series();
        let output = handle.render();

        // All prefilter reason labels should appear.
        use henyey_herder::scp_verify::PreFilterRejectReason;
        for reason in PreFilterRejectReason::ALL {
            let label = format!(
                "henyey_scp_prefilter_rejects_total{{reason=\"{}\"}}",
                reason.label()
            );
            assert!(
                output.contains(&label),
                "missing pre-registered label for reason={}; output:\n{}",
                reason.label(),
                output
            );
        }

        // All post-verify reason labels should appear.
        use henyey_herder::scp_verify::PostVerifyReason;
        for reason in PostVerifyReason::ALL {
            let label = format!(
                "henyey_scp_post_verify_total{{reason=\"{}\"}}",
                reason.label()
            );
            assert!(
                output.contains(&label),
                "missing pre-registered label for reason={}; output:\n{}",
                reason.label(),
                output
            );
        }
    }

    #[test]
    fn test_recorder_install_is_idempotent() {
        // Both calls should return the same handle without panicking.
        let h1 = ensure_test_recorder();
        let h2 = ensure_test_recorder();
        // They should be the same reference (OnceLock returns the same value).
        assert!(std::ptr::eq(h1, h2));
    }

    #[test]
    fn test_removed_overlay_metrics_absent() {
        let handle = ensure_test_recorder();
        describe_metrics();
        register_label_series();
        let output = handle.render();

        // These overlay metrics were intentionally removed because they lack
        // production producers. Verify they don't silently reappear.
        let removed = [
            "stellar_overlay_message_drop_total",
            "stellar_overlay_byte_read_total",
            "stellar_overlay_byte_write_total",
            "stellar_overlay_pending_peers",
            "stellar_overlay_authenticated_peers",
            "stellar_overlay_flood_demanded_total",
            "stellar_overlay_flood_fulfilled_total",
            "stellar_overlay_demand_timeout_total",
            "stellar_overlay_connection_latency_us_sum",
            "stellar_overlay_connection_latency_us_count",
            "stellar_overlay_tx_pull_latency_us_sum",
            "stellar_overlay_tx_pull_latency_us_count",
        ];
        for name in &removed {
            assert!(
                !output.contains(&format!("# HELP {}", name)),
                "metric {} should not be registered (no production producer)",
                name
            );
        }
    }

    #[test]
    fn test_phase2_ledger_metrics_present() {
        let handle = ensure_test_recorder();
        describe_metrics();
        register_label_series();
        let output = handle.render();

        // Ledger close gauges.
        let ledger_metrics = [
            LEDGER_CLOSE_TIME_MS,
            LEDGER_TX_COUNT,
            LEDGER_OP_COUNT,
            LEDGER_TX_SUCCESS_COUNT,
            LEDGER_TX_FAILED_COUNT,
            LEDGER_TOTAL_FEES,
            LEDGER_ENTRIES_CREATED,
            LEDGER_ENTRIES_UPDATED,
            LEDGER_ENTRIES_DELETED,
            LEDGER_APPLY_US,
        ];
        for name in &ledger_metrics {
            assert!(
                output.contains(&format!("# TYPE {} gauge", name)),
                "missing TYPE gauge for {}",
                name
            );
            assert!(
                output.contains(&format!("# HELP {}", name)),
                "missing HELP for {}",
                name
            );
        }
    }

    #[test]
    fn test_phase2_herder_metrics_present() {
        let handle = ensure_test_recorder();
        describe_metrics();
        register_label_series();
        let output = handle.render();

        // Tx queue gauges.
        let queue_gauges = [
            HERDER_TX_QUEUE_ACCOUNTS,
            HERDER_TX_QUEUE_BANNED,
            HERDER_TX_QUEUE_SEEN,
        ];
        for name in &queue_gauges {
            assert!(
                output.contains(&format!("# TYPE {} gauge", name)),
                "missing TYPE gauge for {}",
                name
            );
        }

        // Pending envelope counters.
        let pending_counters = [HERDER_PENDING_ADDED_TOTAL, HERDER_PENDING_RELEASED_TOTAL];
        for name in &pending_counters {
            assert!(
                output.contains(&format!("# TYPE {} counter", name)),
                "missing TYPE counter for {}",
                name
            );
        }
    }

    #[test]
    fn test_phase2_drift_metrics_present() {
        let handle = ensure_test_recorder();
        describe_metrics();
        register_label_series();
        let output = handle.render();

        let drift_metrics = [
            DRIFT_MIN_SECONDS,
            DRIFT_MAX_SECONDS,
            DRIFT_MEDIAN_SECONDS,
            DRIFT_P75_SECONDS,
            DRIFT_SAMPLE_COUNT,
        ];
        for name in &drift_metrics {
            assert!(
                output.contains(&format!("# TYPE {} gauge", name)),
                "missing TYPE gauge for {}",
                name
            );
            // All drift gauges should be pre-registered at 0.
            assert!(
                output.contains(&format!("{} 0", name)),
                "drift metric {} should be pre-registered at 0",
                name
            );
        }
    }

    #[test]
    fn test_phase2_ledger_metrics_pre_registered_at_zero() {
        let handle = ensure_test_recorder();
        describe_metrics();
        register_label_series();
        let output = handle.render();

        // Before any close, all ledger gauges should be 0.
        let zero_metrics = [
            LEDGER_CLOSE_TIME_MS,
            LEDGER_TX_COUNT,
            LEDGER_OP_COUNT,
            LEDGER_TX_SUCCESS_COUNT,
            LEDGER_TX_FAILED_COUNT,
            LEDGER_TOTAL_FEES,
            LEDGER_ENTRIES_CREATED,
            LEDGER_ENTRIES_UPDATED,
            LEDGER_ENTRIES_DELETED,
            LEDGER_APPLY_US,
        ];
        for name in &zero_metrics {
            assert!(
                output.contains(&format!("{} 0", name)),
                "ledger metric {} should be pre-registered at 0; output:\n{}",
                name,
                output
            );
        }
    }
}
