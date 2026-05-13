# Henyey SLO Alert Rules

<!-- rule_count: 19 -->

Grafana alert provisioning rules for henyey validator metrics. Rules are
split into two categories:

- **Dashboard-derived** alerts mirror visual thresholds from the henyey
  monitoring dashboard panels.
- **Policy-based** alerts cover henyey-specific operational metrics that
  have no dashboard panel but have clear alerting significance. Thresholds
  are explicitly tunable.

> **Related:** This is one of two alarm surfaces. The other is the monitor-tick
> alarm catalog at `.claude/skills/shared/metric-alarms.toml`. See
> `.claude/skills/shared/ALARM_SURFACES.md` for the ownership policy,
> overlap rules, and reconciliation table between the two surfaces.

## Alert Rules

### Phase 1: Dashboard-Threshold Alerts

| # | Rule | Metric | Condition | For | Severity |
|---|------|--------|-----------|-----|----------|
| 1 | Invariant Failure | `stellar_ledger_invariant_failure_total` | `increase(...[10m]) > 0` | 0s | critical |
| 2 | TX Internal Error Rate | `stellar_ledger_transaction_internal_error_total` | `rate(...[5m]) > 0.01` | 5m | critical |
| 3a | Quorum Fail At (warn) | `stellar_quorum_fail_at` | `== 1` | 5m | warning |
| 3b | Quorum Fail At (crit) | `stellar_quorum_fail_at` | `< 1` | 5m | critical |
| 4 | Process Down | `up` | `== 0` | 2m | critical |

### Phase 2: Henyey-Specific Alerts

#### Policy-Based (no dashboard panel)

| # | Rule | Metric | Condition | For | Severity |
|---|------|--------|-----------|-----|----------|
| 5 | Post-Catchup Hard Reset | `henyey_post_catchup_hard_reset_total` | `increase(...[10m]) > 0` | 0s | critical |
| 6 | Recovery Stalled | `henyey_recovery_stalled_tick_total` | `increase(...{reason="forcing_catchup_behind"}[10m]) >= 3` | 0s | warning |
| 7 | Recovery TX Set Stuck | `henyey_recovery_tx_set_stuck_seconds` | `> 60` | 0s | warning |
| 8 | Overlay Fetch Channel Depth | `henyey_overlay_fetch_channel_depth` | `> 128` | 5m | warning |

#### Dashboard-Derived

| # | Rule | Metric | Condition | For | Severity | Panel |
|---|------|--------|-----------|-----|----------|-------|
| 9a | FD Exhaustion (warn) | `open_fds / max_fds` | `> 0.6` | 5m | warning | id=10 |
| 9b | FD Exhaustion (crit) | `open_fds / max_fds` | `> 0.8` | 5m | critical | id=10 |
| 10a | Ledger Age (warn) | `stellar_ledger_age_current_seconds` | `> 10` (tracking only) | 5m | warning | id=2 |
| 10b | Ledger Age (crit) | `stellar_ledger_age_current_seconds` | `> 30` (tracking only) | 5m | critical | id=2 |
| 11 | Quorum Missing Peers | `stellar_quorum_missing` | `>= 1` | 5m | warning | id=7 |
| 12a | Peer Count (warn) | `stellar_peer_count` | `< 8` | 5m | warning | id=5 |
| 12b | Peer Count (crit) | `stellar_peer_count` | `< 3` | 5m | critical | id=5 |

### Phase 3: Remaining Dashboard-Threshold Alerts

Four dashboard panels were assessed for alerting. Two were added as alert
rules; two were classified as diagnostic-only (visual indicators, not
alertable conditions).

#### Active Rules

| # | Rule | Metric | Condition | For | Severity | Panel |
|---|------|--------|-----------|-----|----------|-------|
| 13 | Validator Not Tracking | `stellar_herder_state` | `!= bool 2` | 20m | warning | id=4 |
| 14 | Fragmentation | `henyey_jemalloc_fragmentation_pct` | `> 50` | 15m | warning | — |
| 15 | Quorum Intersection Lost | `stellar_quorum_transitive_intersection` | `< 1` | 5m | critical | — |

#### Diagnostic-Only Panels (No Alert)

| Panel | Metric | Dashboard Threshold | Assessment |
|-------|--------|---------------------|------------|
| Bucket Cache Hit Ratio | `henyey_ledger_bucket_cache_hit_ratio` | red < 0.5, green ≥ 0.5 | Low values expected (secondary cache behind snapshot prefetch). No actionable response. |
| Snapshot Cache Hit Ratio | `henyey_ledger_snapshot_cache_hit_ratio` | red < 0.5, green ≥ 0.5 | No stable baseline; low ratios normal after restart/catchup. No ops-defined threshold. |

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

   You should see the alert rules in the `Henyey` folder under the `henyey-slo`
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

The **Quorum Fail At (Critical)** rule uses `noDataState: Alerting` because a
disappearing quorum metric indicates a serious problem that warrants
investigation.

The **Quorum Fail At (Warning)** rule uses `noDataState: OK` because its
PromQL query (`stellar_quorum_fail_at == 1`) returns empty results for both
healthy values (> 1) and critical values (< 1). Empty results here mean
"not in warning state," not "metric missing." Process-down coverage handles
the case where the metric truly disappears.

### execErrState

If Grafana cannot evaluate a rule (e.g., datasource timeout, PromQL error):

- **Invariant Failure**, **Quorum Fail At** (both), and **Process Down** use
  `execErrState: Alerting` — a broken evaluation pipeline for these critical
  rules should page, because silent evaluation failures mask real problems.
- **TX Internal Error Rate** uses `execErrState: Error` — transient evaluation
  errors for a rate-based metric are less urgent and should surface as Grafana
  health errors rather than false pages.

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

### Phase 2 design notes

#### Recovery Stalled — label filtering

The `henyey_recovery_stalled_tick_total` counter is partitioned by a
`reason` label with values: `backoff_active`, `forcing_catchup_not_behind`,
`forcing_catchup_behind`, `at_tip_no_scp_hard_reset`, and
`archive_behind_peer_ahead_hard_reset`. Only `forcing_catchup_behind` is
operationally significant — the others are transient/debug signals. The
alert filters to `reason="forcing_catchup_behind"` and uses a threshold
of `>= 3` increments in 10 minutes, matching the streak threshold from
the ops guidance in `.claude/skills/shared/metric-alarms.toml`.

#### Overlay fetch channel depth vs depth_max

The issue references `henyey_overlay_fetch_channel_depth_max`, but this
metric is a monotonic high-water mark that never decreases — alerting on
it would fire permanently after a single spike. Instead, the alert uses
`henyey_overlay_fetch_channel_depth` (the current instantaneous depth),
which reflects real-time backpressure. The channel is unbounded (tokio
mpsc), so the threshold (128) is a tunable policy value.

#### FD exhaustion — absent denominator

`henyey_process_max_fds` is not emitted when `RLIMIT_NOFILE` is infinity
or on non-Linux platforms (`crates/app/src/metrics.rs:1223-1239`). When
the denominator is absent, PromQL division yields no result. Combined
with `noDataState: OK`, the alert is silently disabled — this is
intentional, as infinite FD limits don't need exhaustion alerts.

#### Ledger age — herder state filter

The ledger age alerts use `and stellar_herder_state == 2` to fire only
when the herder is in Tracking state. During Syncing or Booting, high
ledger age is expected and not actionable. This matches the dashboard
panel query (panel id=2).

#### Quorum missing vs quorum fail-at — layered severity

The Quorum Missing alert fires at `warning` severity despite the
dashboard's red threshold at ≥ 1. Missing peers are upstream network
conditions, not henyey bugs. The existing Quorum Fail At alerts (3a/3b)
already cover the downstream quorum-loss risk at `critical` severity.
This provides layered escalation: "peers dropping" (warning) →
"quorum at risk" (critical).

#### Peer count — noDataState: OK

The Peer Count alerts use `noDataState: OK`, consistent with most other
alerts. `stellar_peer_count` is a pre-registered gauge that is always
emitted when the henyey process is running. If it disappears, the process
has crashed — which is already covered by the Process Down alert. Using
`noDataState: OK` avoids duplicate no-data pages.

### Phase 3 design notes

#### Validator Not Tracking — PromQL pattern

The alert uses `stellar_herder_state != bool 2` instead of `!= 2`. Plain
`!= 2` returns no series when the value equals 2 (healthy), which would
trigger `noDataState` handling. The `bool` modifier always returns a series
(0 when healthy, 1 when not tracking), making the threshold evaluation
reliable.

#### Validator Not Tracking — for: 20m gating

Ops guidance defines three deadlines for reaching Tracking state:
- Normal: 15m
- Fresh start: 20m
- Crash recovery: 60m

`for: 20m` covers normal and fresh-start scenarios. During crash recovery
(~60m), the warning-severity alert may fire transiently but auto-resolves.
This is acceptable because warning does not page on-call, crash recovery
is rare, and encoding full 3-tier gating in PromQL adds complexity
disproportionate to the benefit.

#### Fragmentation — dashboard vs alert threshold divergence

The dashboard panel uses yellow=15% and red=30% as visual color bands.
Normal steady-state fragmentation is ~18% (per ops guidance), which sits
between these visual thresholds. Alerting at 15% or 30% would cause
constant false positives.

The alert threshold of >50% comes from ops guidance
(`.claude/skills/monitor-tick/SKILL.md:627`), which treats this as the
actionable level. Post-restart fragmentation ramps to ~35-45% before
settling. `for: 15m` avoids transient spikes during warmup.

#### Bucket and Snapshot Cache — diagnostic-only classification

Both cache hit ratio panels use red/green visual thresholds at 0.5, but
these are diagnostic indicators, not alertable conditions:

- **Bucket cache:** Dashboard description explicitly states low values are
  expected because the snapshot prefetch cache absorbs most lookups.
- **Snapshot cache:** No stable baseline exists — the ratio depends on
  workload mix, cache warmth, and protocol version. Low ratios after
  restart, catchup, or burst transactions are normal. No ops guidance
  defines a threshold. The only response to sustained low ratios is
  development investigation (cache sizing), not operational action.

## Testing

To verify alerts are working:

1. **Check rule evaluation:** In the Grafana UI, navigate to Alerting →
   Alert Rules → Henyey folder. Each rule should show its current state
   (Normal, Pending, or Firing).

2. **Test with synthetic data:** Use Prometheus recording rules or push
   gateway to inject test metric values that should trigger each alert.

3. **Verify notification routing:** Configure a test contact point and
   trigger an alert to confirm notifications are delivered.

## Post-Refactor Verification

After modifying alarm rules or the evaluator, verify no regressions:

1. **Run the point-in-time regression check:**
   ```bash
   scripts/dev/replay-alarms-on-history.sh [~/data/$SESSION]
   ```
   This validates the alarm catalog schema and runs a single evaluation
   against the most recent `current.prom` + `prev.prom` snapshot pair.

2. **Review firing results** — check that expected alarms fire and no
   unexpected alarms appear.

3. **Investigate any divergence** — alarms that should have fired but didn't,
   or new false positives.

> **Historical replay.** Weekly alarm regression replay is now implemented.
> `monitor-tick` Step 8 schedules it: `replay-alarms-on-history.sh --replay`
> evaluates archived snapshot pairs through the current alarm catalog, then
> `check-alarm-regression.sh` compares the result against two baselines:
> a **rolling baseline** (updated each clean run, catches sudden regressions)
> and a **frozen stable baseline** (never auto-updated, catches gradual decay
> where an alarm silently drifts from active to silent over successive runs).
> Both baselines carry provenance metadata including a catalog checksum and
> per-alarm `alarm_versions` map; when the catalog changes, only alarms whose
> `baseline_version` was bumped (semantic changes) are invalidated — other
> alarms' baselines and acknowledgments are preserved. Cosmetic-only edits
> (notes, filing text, severity) trigger no invalidation. To force a manual
> refresh, delete `replay-baseline-stable.json` and re-run.
>
> **Pre-refactor limitation.** Pre-#2566 runtime equivalence cannot be
> proven — no pre-refactor snapshots or baseline exist. The original
> refactor's correctness is partially evidenced by TOML schema validation,
> source-grep checks, and golden-fixture tests, but these do not constitute
> proof of pre-/post-refactor runtime equivalence.
