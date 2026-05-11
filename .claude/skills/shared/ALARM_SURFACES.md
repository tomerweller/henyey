# Alarm Surfaces Policy

This document defines the relationship between the two alarm surfaces in henyey
and the policy for managing overlaps between them.

## Surfaces

### 1. Monitor-tick (`metric-alarms.toml`)

- **Location:** `.claude/skills/shared/metric-alarms.toml`
- **Consumer:** `scripts/lib/eval-alarms.py`, invoked by the `monitor-tick` LLM skill
- **Runs:** Inside the validator process session, every ~20 minutes
- **Capabilities:** In-process action — can file GitHub issues, trigger restarts,
  initiate wipe-recovery, adjust operational state
- **Semantics:** Per-tick delta comparison (current vs previous scrape), gauge
  threshold checks, multi-tick persistence (`for_ticks`)

### 2. Grafana SLO alerts (`henyey-slo-alerts.yaml`)

- **Location:** `metrics/alerts/henyey-slo-alerts.yaml`
- **Consumer:** Prometheus Alertmanager via Grafana provisioning
- **Runs:** Continuously via Prometheus scraping (~15s interval)
- **Capabilities:** Operator paging, fleet aggregation, historical context,
  cross-validator queries, SLO tracking
- **Semantics:** PromQL `rate()`, `increase()` over time windows (5m, 10m),
  `for`-duration persistence

## Ownership Policy

| Alarm class | Primary surface | Rationale |
|---|---|---|
| In-process action (restart, wipe, issue filing) | monitor-tick | Needs process-local context to act |
| SLO/operator paging | Grafana | Needs historical context, fleet-wide view |
| Process health (up/down) | Grafana | Process-down makes in-process alarms unreachable |
| Quorum/consensus health | Both | Monitor-tick files issues; Grafana pages operators |
| Counter spikes (invariant, tx error) | Both | Monitor-tick for immediate filing; Grafana for rate-based SLO |

## Overlap Policy

When an alarm legitimately belongs in both surfaces:

1. The TOML entry includes a `# mirrors:` comment naming the corresponding
   Grafana rule(s), e.g.:
   ```toml
   # mirrors: henyey-slo-alerts.yaml rule 1 (critical, increase > 0 over 10m)
   ```

2. **Thresholds and severities may intentionally differ.** Monitor-tick uses
   per-tick deltas and gauge snapshots; Grafana uses `rate()`/`increase()` over
   time windows. A monitor-tick `threshold = 1` on a counter is not equivalent
   to a Grafana `increase(...[10m]) > 0` — the former detects any single-tick
   increment, the latter smooths over a 10-minute window. These are
   **surface mirrors, not threshold-identical mirrors.**

3. When adding or modifying a mirrored alarm, check the other surface and
   update its `# mirrors:` comment or threshold if warranted.

## Reconciliation Table

| Alarm | monitor-tick | Grafana | Notes |
|---|---|---|---|
| Invariant failure | `ledger-invariant-failure`: counter ≥ 1, ACTION | Rule 1: `increase > 0` over 10m, critical | Monitor-tick best-effort for strict (panic before scrape) |
| TX internal error | `tx-internal-error`: counter ≥ 1, ACTION | Rule 2: `rate > 0.01` over 5m, critical | Different detection semantics (any vs rate) |
| Quorum fail-at | `quorum-fail-at-low`: gauge ≤ 1, WARN, 3 ticks | Rules 3a/3b: `== 1` warn/`< 1` critical, 5m | Monitor-tick collapses tiers; Grafana escalates |
| Post-catchup reset | `post-catchup-hard-reset`: counter ≥ 1, ACTION | Rule 5: `increase > 0` over 10m, critical | |
| Fetch channel depth | `fetch-channel-deep`: gauge > 500, WARN, 2 ticks | Rule 8: `> 128`, warning, 5m | Different thresholds |
| Fragmentation | `jemalloc-frag-high`: gauge > 50, WARN, 2 ticks | Rule (jemalloc): `> 50%`, warning | Matching thresholds |

## Default for New Alarms

1. New alarms go to `metric-alarms.toml` first (in-process action).
2. Add a Grafana rule when operator paging, fleet-wide visibility, or
   time-windowed rate analysis is needed.
3. Document the overlap with a `# mirrors:` comment in the TOML entry.
