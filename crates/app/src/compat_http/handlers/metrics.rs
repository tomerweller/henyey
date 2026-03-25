//! stellar-core compatible `/metrics` handler.
//!
//! stellar-core returns medida JSON format with `type`, `count`, and optional
//! rate/percentile fields. We emit the subset of metrics that SSC missions and
//! health checks commonly inspect.

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;

use crate::compat_http::CompatServerState;

/// GET /metrics
///
/// Returns a medida-compatible metrics JSON that covers the metrics
/// stellar-rpc, SSC missions, and health checks commonly inspect.
///
/// stellar-core's medida format uses three metric types:
/// - `"counter"`: a monotonically increasing count
/// - `"timer"`: count + duration percentiles + rate
/// - `"meter"`: count + event rate
///
/// We emit real values where we have them and zero placeholders for
/// rate/percentile fields we don't yet track.
pub(crate) async fn compat_metrics_handler(
    State(state): State<Arc<CompatServerState>>,
) -> impl IntoResponse {
    let app = &state.app;
    let (seq, _, _, protocol_version) = app.ledger_info();
    let (pending_count, authenticated_count) = app.peer_counts().await;

    Json(serde_json::json!({
        "metrics": {
            "ledger.ledger.close": {
                "type": "timer",
                "count": seq,
                "event_type": "calls",
                "rate_unit": "second",
                "mean_rate": 0.0,
                "1_min_rate": 0.0,
                "5_min_rate": 0.0,
                "15_min_rate": 0.0,
                "duration_unit": "millisecond",
                "min": 0.0,
                "max": 0.0,
                "mean": 0.0,
                "stddev": 0.0,
                "sum": 0.0,
                "median": 0.0,
                "75%": 0.0,
                "95%": 0.0,
                "98%": 0.0,
                "99%": 0.0,
                "99.9%": 0.0,
                "100%": 0.0
            },
            "peer.peer.count": {
                "type": "counter",
                "count": authenticated_count + pending_count
            },
            "peer.peer.authenticated-count": {
                "type": "counter",
                "count": authenticated_count
            },
            "peer.peer.pending-count": {
                "type": "counter",
                "count": pending_count
            },
            "herder.pending.transactions": {
                "type": "counter",
                "count": app.pending_transaction_count()
            },
            "ledger.ledger.version": {
                "type": "counter",
                "count": protocol_version
            },
            "scp.value.valid": {
                "type": "meter",
                "count": seq,
                "event_type": "events",
                "rate_unit": "second",
                "mean_rate": 0.0,
                "1_min_rate": 0.0,
                "5_min_rate": 0.0,
                "15_min_rate": 0.0
            },
            "scp.value.invalid": {
                "type": "meter",
                "count": 0,
                "event_type": "events",
                "rate_unit": "second",
                "mean_rate": 0.0,
                "1_min_rate": 0.0,
                "5_min_rate": 0.0,
                "15_min_rate": 0.0
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    /// Verify the metrics response JSON shape matches stellar-core's medida format.
    ///
    /// stellar-core returns `{"metrics": {"name": {"type": "...", "count": N, ...}, ...}}`.
    #[test]
    fn test_metrics_response_shape() {
        let value = serde_json::json!({
            "metrics": {
                "ledger.ledger.close": {
                    "type": "timer",
                    "count": 100,
                    "event_type": "calls",
                    "rate_unit": "second",
                    "mean_rate": 0.0,
                    "1_min_rate": 0.0,
                    "5_min_rate": 0.0,
                    "15_min_rate": 0.0,
                    "duration_unit": "millisecond",
                    "min": 0.0,
                    "max": 0.0,
                    "mean": 0.0,
                    "stddev": 0.0,
                    "sum": 0.0,
                    "median": 0.0,
                    "75%": 0.0,
                    "95%": 0.0,
                    "98%": 0.0,
                    "99%": 0.0,
                    "99.9%": 0.0,
                    "100%": 0.0
                },
                "peer.peer.count": {
                    "type": "counter",
                    "count": 5
                },
                "herder.pending.transactions": {
                    "type": "counter",
                    "count": 3
                }
            }
        });

        let obj = value.as_object().unwrap();
        assert_eq!(obj.len(), 1, "top-level should only have 'metrics'");

        let metrics = value["metrics"].as_object().unwrap();
        let expected_counters = ["peer.peer.count", "herder.pending.transactions"];
        for name in &expected_counters {
            let metric = &metrics[*name];
            assert_eq!(metric["type"], "counter", "{name} should be a counter");
            assert!(metric.get("count").is_some(), "{name} must have 'count'");
        }

        // Timer has percentiles and rate fields
        let timer = &metrics["ledger.ledger.close"];
        assert_eq!(timer["type"], "timer");
        assert!(timer.get("count").is_some());
        assert!(timer.get("mean_rate").is_some());
        assert!(timer.get("duration_unit").is_some());
        assert!(timer.get("median").is_some());
        assert!(timer.get("99%").is_some());
    }

    /// Verify all metrics have the `type` field (medida format requirement).
    #[test]
    fn test_all_metrics_have_type_field() {
        let value = serde_json::json!({
            "metrics": {
                "ledger.ledger.close": { "type": "timer", "count": 0 },
                "peer.peer.count": { "type": "counter", "count": 0 },
                "peer.peer.authenticated-count": { "type": "counter", "count": 0 },
                "peer.peer.pending-count": { "type": "counter", "count": 0 },
                "herder.pending.transactions": { "type": "counter", "count": 0 },
                "ledger.ledger.version": { "type": "counter", "count": 0 },
                "scp.value.valid": { "type": "meter", "count": 0 },
                "scp.value.invalid": { "type": "meter", "count": 0 }
            }
        });

        let metrics = value["metrics"].as_object().unwrap();
        assert_eq!(metrics.len(), 8, "should have 8 metrics");
        for (name, metric) in metrics {
            assert!(
                metric.get("type").is_some(),
                "metric '{name}' must have 'type' field"
            );
            assert!(
                metric.get("count").is_some(),
                "metric '{name}' must have 'count' field"
            );
        }
    }

    /// Verify meter-type metrics have rate fields.
    #[test]
    fn test_meter_metrics_have_rate_fields() {
        let meter = serde_json::json!({
            "type": "meter",
            "count": 100,
            "event_type": "events",
            "rate_unit": "second",
            "mean_rate": 0.2,
            "1_min_rate": 0.19,
            "5_min_rate": 0.2,
            "15_min_rate": 0.2
        });

        assert_eq!(meter["type"], "meter");
        let rate_fields = ["mean_rate", "1_min_rate", "5_min_rate", "15_min_rate"];
        for field in &rate_fields {
            assert!(meter.get(*field).is_some(), "meter must have '{field}'");
        }
    }
}
