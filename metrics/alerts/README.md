# Henyey SLO Alert Rules

Grafana alert provisioning rules for henyey validator metrics. These rules
wire alerting to the visual thresholds already defined in the henyey
monitoring dashboards.

## Alert Rules

| Rule | Metric | Condition | For | Severity |
|------|--------|-----------|-----|----------|
| Invariant Failure | `stellar_ledger_invariant_failure_total` | `increase(...[10m]) > 0` | 0s | critical |
| TX Internal Error Rate | `stellar_ledger_transaction_internal_error_total` | `rate(...[5m]) > 0.01` | 5m | critical |
| Quorum Fail At (warn) | `stellar_quorum_fail_at` | `== 1` | 5m | warning |
| Quorum Fail At (crit) | `stellar_quorum_fail_at` | `< 1` | 5m | critical |
| Process Down | `up` | `== 0` | 2m | critical |

## Prerequisites

- **Grafana ≥ 9.x** with unified alerting enabled (legacy alerting is not
  supported).
- **Contact points** and **notification policies** must already be configured
  in your Grafana instance. These rules define alert conditions only — they do
  not configure notification routing. If no contact points exist, alerts will
  fire but produce no notifications.
- **Prometheus datasource** configured and scraping the henyey process.

## Deployment

1. Copy `henyey-slo-alerts.yaml` to your Grafana provisioning directory:

   ```bash
   cp henyey-slo-alerts.yaml /etc/grafana/provisioning/alerting/
   ```

   The default path is `/etc/grafana/provisioning/alerting/`. Check your
   Grafana configuration (`grafana.ini` → `[paths]` → `provisioning`) if
   your installation uses a different path.

2. Reload Grafana's provisioning:

   ```bash
   # Via API (requires admin credentials):
   curl -X POST http://admin:admin@localhost:3000/api/admin/provisioning/alerting/reload

   # Or restart Grafana:
   systemctl restart grafana-server
   ```

3. Verify the rules loaded:

   ```bash
   curl -s http://localhost:3000/api/v1/provisioning/alert-rules | jq '.[] | .title'
   ```

   You should see 5 rules in the `Henyey` folder under the `henyey-slo`
   rule group.

## Configuration

### Datasource UID

The alert rules ship with datasource UID `000000001`, which matches the
henyey monitoring dashboards. If your Prometheus datasource uses a different
UID, update all `datasourceUid` fields in the YAML file:

```bash
# Find your Prometheus datasource UID:
curl -s http://localhost:3000/api/datasources | jq '.[] | select(.type == "prometheus") | .uid'

# Replace in the YAML (example: changing to "abc123"):
sed -i 's/000000001/abc123/g' henyey-slo-alerts.yaml
```

### Alert folder

Rules are provisioned into a folder named `Henyey`. Grafana creates this
folder automatically on first load if it doesn't exist.

## Design Notes

### noDataState

The **Invariant Failure** and **TX Internal Error Rate** rules use
`noDataState: OK`. This means if the henyey process goes down and Prometheus
stops receiving these metrics, these alerts will **not** fire.

This is intentional: "no data" for these counters means "no failures
occurred" — which is the normal state. The companion **Process Down** rule
(`up{job="henyey"} == 0`) covers the gap: if henyey crashes (including from
strict invariant panics), the process-down alert fires within 2 minutes.

The **Quorum Fail At** rules use `noDataState: Alerting` because a
disappearing quorum metric indicates a serious problem that warrants
investigation.

### Panel vs. alert window divergence

Dashboard panel 26 (Invariant Failures) uses a 24-hour window
(`increase(...[24h])`) while the corresponding alert uses a 10-minute window.
These serve different purposes:

- **Panel (24h):** Visual context — "did anything go wrong today?" Stays
  highlighted for a full day to ensure operators notice during their next
  dashboard check.
- **Alert (10m):** Operational urgency — "is something going wrong right now?"
  Fires and auto-resolves quickly so pages reflect current state.

### Strict vs. non-strict invariant failures

Strict invariant failures increment `stellar_ledger_invariant_failure_total`
and then immediately `panic!()` (see `crates/invariant/src/lib.rs:276-292`).
The process may crash before Prometheus scrapes the new counter value. The
Invariant Failure alert is therefore a **best-effort** mechanism for strict
failures — it reliably catches non-strict failures (which log and continue)
and catches strict failures only if the scrape happens before the panic.

Strict failure detection is primarily covered by the Process Down alert,
which fires when the henyey process stops responding to scrapes.

## Testing

To verify alerts are working:

1. **Check rule evaluation:** In the Grafana UI, navigate to Alerting →
   Alert Rules → Henyey folder. Each rule should show its current state
   (Normal, Pending, or Firing).

2. **Test with synthetic data:** Use Prometheus recording rules or push
   gateway to inject test metric values that should trigger each alert.

3. **Verify notification routing:** Configure a test contact point and
   trigger an alert to confirm notifications are delivered.
