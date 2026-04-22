---
name: monitor-tick
description: One tick of the henyey mainnet monitor — checks, metrics scan, deploy, status report
---

# Monitor Tick

One invocation of the monitor loop. Intended to be called on a ~10-minute
cadence by an external orchestrator (crontab, systemd timer, CI) via
`claude -p '/monitor-tick'`, or by a Claude-internal `/loop 10m /monitor-tick`.

## Preconditions

This skill expects `/home/tomer/data/monitor-loop.env` to exist — it is
written by `/monitor-loop` at startup and contains the runtime config.
If the file is missing, **bail out immediately** with:

```
ERROR: /home/tomer/data/monitor-loop.env not found — run /monitor-loop first.
```

Load the env file at the start of the tick:

```bash
set -a
source /home/tomer/data/monitor-loop.env
set +a
```

Variables provided by the env file (all required):

- `MONITOR_SESSION_ID` — 8-char session id, e.g. `74535976`
- `MONITOR_MODE` — `validator` or `watcher`
- `MONITOR_CONFIG` — path to the TOML config, e.g. `configs/validator-mainnet-rpc.toml`
- `MONITOR_ADMIN_PORT` — `11627` (validator) or `11727` (watcher)
- `MONITOR_RPC_PORT` — `8000` (validator) or empty (watcher)
- `MONITOR_RUN_FLAGS` — `--validator` (validator) or empty (watcher)

Throughout this skill, substitute those values for the `$MONITOR_*` references below.

## Fresh-start state

Determine once at the top of the tick: if `/home/tomer/data/mainnet/mainnet.db`
does NOT exist, set `FRESH_START=yes` (sync deadline = 4h). Otherwise
`FRESH_START=no` (sync deadline = 15m). Use this when evaluating check (2).

## Health checks

**(1) Log scan** — `tail -n 500 /home/tomer/data/$MONITOR_SESSION_ID/logs/monitor.log`.
Scan for hash mismatches ("hash mismatch", "HashMismatch", differing expected/actual
hashes), panics/crashes ("panic", "thread.*panicked", "SIGABRT", "SIGSEGV"),
ERROR-level log lines, assertion failures ("assertion failed").

**(2) Ledger progression & sync deadline** — persist ledger progression across
ticks so STUCK can be detected by a single invocation:

- Read `/home/tomer/data/$MONITOR_SESSION_ID/last_ledger` (if it exists) —
  format is `"<ledger>|<unix-timestamp>"`.
- Extract the current ledger from the most recent Heartbeat line in the log tail.
- If the file exists and its ledger equals the current ledger and the recorded
  timestamp is more than 600s old, flag STUCK.
- If the ledger has advanced or the file is missing, overwrite
  `/home/tomer/data/$MONITOR_SESSION_ID/last_ledger` with `"<current-ledger>|<now>"`.
- Check node uptime: `ps -o etime= -p $(pgrep -f 'henyey.*run' | head -1)`.
  Compare uptime against the deadline from `FRESH_START`.
- If uptime exceeds the deadline and the node is not yet in real-time sync:
  check the latest Heartbeat for the gap between `ledger` and `latest_ext` —
  if gap > 5, or if RPC status is `unhealthy` (i.e. `age` > 30s), or if
  `heard_from_quorum=false`, flag SYNC FAILURE.

**"Real-time sync" means `age < 30s`, NOT just Heartbeat gap=0** — gap is the
node's local view (`latest_ext - ledger`) and stays at 0 even when the node is
minutes behind the network if it hasn't received those externalization messages
yet. The authoritative wall-clock signal is RPC `age`. If `age` is persistently
> 30s for a non-fresh-start node past the 15m deadline, the node is lagging
network tip; treat as SYNC FAILURE even with gap=0 and heard_from_quorum=true.
Do NOT report this as a WARNING and wait. Investigate the catchup path: check
for checkpoint-boundary stalls ("failed to download header"), hash mismatches,
or event loop freezes in the log. If `FRESH_START=yes` and uptime is under 4h,
a large gap is expected — report CATCHING UP instead of SYNC FAILURE.

**(3) Process alive** — `pgrep -af 'henyey.*run'`. If not running, before relaunching:

1. `rm -f /home/tomer/data/mainnet/mainnet.lock` to clear any stale lockfile.
2. Preserve the prior session's log:
   `mv /home/tomer/data/$MONITOR_SESSION_ID/logs/monitor.log /home/tomer/data/$MONITOR_SESSION_ID/logs/monitor.log.crashed-$(date -u +%Y%m%dT%H%M%SZ) 2>/dev/null || true`
3. Relaunch with append redirection so interleaving restart pathways don't nuke history:
   ```
   RUST_LOG=info nohup /home/tomer/data/$MONITOR_SESSION_ID/cargo-target/release/henyey \
     --mainnet run $MONITOR_RUN_FLAGS -c $MONITOR_CONFIG \
     >> /home/tomer/data/$MONITOR_SESSION_ID/logs/monitor.log 2>&1 &
   ```

**(4) Memory** — `ps -o rss= -p $(pgrep -f 'henyey.*run' | head -1)`, convert to MB.
If RSS > 12 GB, flag HIGH MEMORY. If RSS > 16 GB or system `available` memory
(from `free -m`) < 4 GB, restart the node (`kill <PID>`, wait 10s, `kill -9`
if still alive, then relaunch as in check 3). Use the `available` column — NOT
`free` — to avoid false positives from reclaimable kernel cache (buff/cache).

**(5) Disk** — `df -h /home/tomer/data | tail -1`. If usage > 85%, flag LOW DISK.
Then clean up old rotated log archives (keep 3 most recent per category):

```bash
if test -d /home/tomer/data/$MONITOR_SESSION_ID/logs; then
  for pat in preredeploy crashed stuck; do
    ls -1r /home/tomer/data/$MONITOR_SESSION_ID/logs/monitor.log.$pat-* 2>/dev/null \
      | tail -n +4 | xargs -r rm -f
  done
fi
```

The ISO 8601 timestamp suffix sorts lexicographically, so `ls -1r`
(reverse alphabetical) gives newest-first; `tail -n +4` skips the 3 newest
and outputs the rest for deletion. Report how many files were removed if any.

**(6) Session disk** — `du -sh /home/tomer/data/$MONITOR_SESSION_ID/`
and `du -sh /home/tomer/data/mainnet/`. If combined > 200 GB, flag SESSION DISK HIGH.

**(7) Memory report** — `grep 'Memory report summary' /home/tomer/data/$MONITOR_SESSION_ID/logs/monitor.log | tail -1`.
If grep returns no output, flag WARNING memory-report-missing (log format may have
changed). Otherwise extract `jemalloc_allocated_mb`, `jemalloc_resident_mb`,
`fragmentation_pct`, `heap_components_mb`, `mmap_mb`, `unaccounted_mb`,
`unaccounted_sign`. If `fragmentation_pct > 50`, flag HIGH FRAGMENTATION.
If `unaccounted_mb > 1000` with sign `+`, note it (known jemalloc overhead,
not a bug — but verify `heap_components` is stable; if it is growing, investigate).

**(8) RPC health** (validator mode only — skip in watcher mode) —
`curl -s -X POST http://localhost:$MONITOR_RPC_PORT -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}'`.
Verify response is non-empty and `status` is `healthy`. Check pruning:
`latestLedger - oldestLedger` should be ≤ `retention_window + 250` (allows
one full maintenance cycle's worth of new ledgers — maintenance every 900s ≈
180 ledgers at 5s/ledger, +70 headroom). If gap > `retention_window + 500`,
flag PRUNING STALLED. If RPC is not responding, flag RPC DOWN.

**(9) OBSRVR Radar** (validator mode only — skip in watcher mode) — get
public key from `curl -s http://localhost:$MONITOR_ADMIN_PORT/info`
(extract `public_key`). Then `curl -s https://radar.withobsrvr.com/api/v1/nodes/<PUBLIC_KEY>`.
Check:
- `isValidating` — if false and node running > 30 min, flag NOT VALIDATING.
- `validating24HoursPercentage` — if < 50 and running > 6 hours, flag LOW VALIDATION RATE.
- `lag` — if > 500, flag HIGH LAG.

If the API errors out, emit `obsrvr: N/A (api-error)` instead of omitting the field.

**(12) Metrics scan** — scrape `/metrics` and evaluate the alert catalog.

1. `mkdir -p /home/tomer/data/$MONITOR_SESSION_ID/metrics`.
2. `mv /home/tomer/data/$MONITOR_SESSION_ID/metrics/current.prom /home/tomer/data/$MONITOR_SESSION_ID/metrics/prev.prom 2>/dev/null || true`.
3. `curl -s http://localhost:$MONITOR_ADMIN_PORT/metrics > /home/tomer/data/$MONITOR_SESSION_ID/metrics/current.prom`.
4. Restart detection: for any counter, if `current < prev`, treat delta as
   `current` (node restarted this tick or last tick). If check (3) or (10)
   restarted the node this tick OR the prior tick, skip
   `henyey_jemalloc_fragmentation_pct` gauge alerts and skip
   counter-started-at-zero alerts (warmup allowance — 2 ticks).

### Metric alert catalog

**COUNTERS** (fire on `delta ≥ threshold`):

- `stellar_herder_lost_sync_total` ≥1 → SYNC
- `henyey_post_catchup_hard_reset_total` ≥1 → ACTION
- `henyey_recovery_stalled_tick_total` ≥5 → WARN
- `stellar_ledger_apply_failure_total` ≥90000 → WARN (baselined ~8755/tick 2026-04-22, threshold ~10× baseline)
- `stellar_herder_pending_too_old_total` ≥100 → WARN
- `(stellar_overlay_timeout_idle_total + stellar_overlay_timeout_straggler_total)` ≥5× prior-tick-sum → WARN
- `(stellar_overlay_error_read_total + stellar_overlay_error_write_total)` ≥50 → WARN
- `henyey_archive_cache_refresh_error_total` ≥1 → NONC
- `henyey_archive_cache_refresh_timeout_total` ≥3 → NONC
- `henyey_scp_post_verify_drops_total` ≥2000000 → WARN (baselined ~172k/tick 2026-04-22, threshold ~10× baseline)

**GAUGES** (fire on absolute threshold against current snapshot):

- `stellar_peer_count` <8 → WARN
- `henyey_jemalloc_fragmentation_pct` >50 on two consecutive ticks → WARN
- `stellar_ledger_age_current_seconds` >30 → SYNC
- `stellar_herder_state` !=2 when uptime >15m → SYNC
- `henyey_scp_verify_input_backlog` >100 → WARN
- `henyey_scp_verifier_thread_state` !=0 → WARN (0=Running, 1=Stopping, 2=Dead)
- `stellar_herder_pending_envelopes` >2000 → WARN
- `henyey_overlay_fetch_channel_depth_max` >500 → WARN
- `(henyey_process_open_fds / henyey_process_max_fds)` >0.85 → WARN
- `henyey_herder_drift_max_seconds` >10 → NONC

`quorum_agree` / `quorum_missing` / `quorum_fail_at` are intentionally NOT
monitored — they snapshot the tracking slot's QuorumInfo and return
false-positive noise between externalizations; see `monitor-loop/SKILL.md`
Metrics Scan section for the code-path explanation.

**HISTOGRAMS** (fire on p99 bucket of per-tick delta): for each histogram H,

```
bucket_delta[le] = H_bucket_current[le] - H_bucket_prev[le]
count_delta = H_count_current - H_count_prev
```

Skip if `count_delta < 20`. Compute cumulative bucket delta at upper edge L:
`sum(bucket_delta[le] for le ≤ L)`. The smallest L where cumulative ≥
`0.99 * count_delta` is the p99 upper bound.

Thresholds (all WARN):

- `henyey_close_cycle_seconds` p99 >5s
- `henyey_ledger_close_tx_exec_seconds` p99 >1s
- `henyey_ledger_close_soroban_exec_seconds` p99 >1s
- `henyey_ledger_close_commit_seconds` p99 >0.5s
- `henyey_ledger_close_soroban_state_seconds` p99 >0.5s
- `henyey_close_complete_tx_queue_seconds` p99 >0.5s

Mean check (`sum_delta / count_delta`) is a cheaper fallback — fire on whichever breaches.

### Firing alerts — cooldown + filing

For each firing alert:

1. Read `/home/tomer/data/$MONITOR_SESSION_ID/metrics/anomaly_cooldown.json`
   (create empty `{}` if missing).
2. If `now - last_filed[<metric>] < 7200s` (2h), include the alert in the
   status report but SKIP file/comment.
3. Otherwise follow the BUG FILING WORKFLOW:
   - Search `gh issue list --search "metrics: <metric-name>" --state open`.
   - If one matches, `gh issue comment <N>` with the new evidence (current/prev
     values, delta, threshold, ledger, binary sha, sibling metrics) and ensure
     `ready` label is set.
   - If no match, `gh issue create --label ready` with:
     - Title: `Non-critical: metrics: <metric>` (NONC tier) or `metrics: <metric> — <symptom>` (WARN/SYNC tier).
     - Body: current/prev values, delta, threshold, ledger, binary sha, related
       sibling metrics, file:line citation from `grep -n "<metric_name_without_prefix>" crates/ -r`,
       and a suggested fix.
4. Update `anomaly_cooldown.json` with `{"<metric>": <now>}`.
5. For SYNC-tier alerts, ALSO update the `sync:` line in the status report
   (not just `metrics:`).

### Watcher mode

If `$MONITOR_MODE = watcher`, run check (12) with a reduced catalog: only
process (open_fds, max_fds), jemalloc, and overlay counters/gauges. Skip
SCP, quorum, herder_state, and histogram p99 alerts.

## Remote sync & redeploy

**(10) Remote sync** — first sanity-check the working tree:

- If `git status --porcelain` reports any output, ABORT the deploy path for
  this tick. Report: `DEPLOY SKIPPED (dirty tree)` with the list of dirty
  paths. Do not run `git pull` against a dirty tree; do not kill the node.
  Investigate the dirty tree before the next tick.
- If clean, `git fetch origin main`. If in detached HEAD state
  (`git symbolic-ref HEAD` fails), `git checkout main` first.
- Compare `git rev-parse HEAD` vs `git rev-parse origin/main`.

If they differ (origin/main is ahead):

1. Check CI status on origin/main: `gh run list --branch main --limit 3 --json conclusion --jq '.[].conclusion'`.
   If any recent run has conclusion `failure`, do NOT deploy — route the failure
   through check (11) and wait.
2. If all conclusions are `success` (ignore `""` for in-progress and `cancelled`):
   `git pull --rebase`, `CARGO_TARGET_DIR=/home/tomer/data/$MONITOR_SESSION_ID/cargo-target cargo build --release -p henyey`.
3. If build succeeds: preserve the log, then kill the node (`kill <PID>`,
   wait 10s, `kill -9` if still alive), restart with the launch command from
   check (3) (append redirection), report:
   `DEPLOY — pulled <N> commits (<old-sha>..<new-sha>), rebuilt, restarted at L<ledger>`.
4. If build fails: report `BUILD FAILED`, do NOT restart — the old binary is
   still running. Route the build error through check (11).

If `HEAD == origin/main`: no action (already up to date).

## CI check workflow

**(11) CI check** — scope and levels of detection.

**(11a) Scope**: only inspect workflows that run on branch main.
`gh run list --branch main --limit 10 --json databaseId,name,status,conclusion,headSha,createdAt --jq '.[] | "\(.name)|\(.status)|\(.conclusion)|\(.headSha[:8])|\(.databaseId)|\(.createdAt)"'`.
Ignore runs triggered by PRs on other branches. Scan for completed runs with
conclusion `failure`.

**(11b) Job-level** (CRITICAL — catches continue-on-error failures): For the
latest completed run of EACH distinct workflow name (enumerate dynamically
from 11a, do NOT hard-code names), check individual jobs:
`gh run view <ID> --json jobs --jq '.jobs[] | select(.conclusion == "failure") | "\(.name)|\(.conclusion)"'`.
Workflows with continue-on-error jobs report run-level conclusion `success`
even when jobs fail — you MUST check job-level conclusions. If any jobs have
conclusion `failure`, treat it the same as a run-level failure.

**REPORTING RULE** — NEVER report `ci: all green` if ANY job has conclusion
`failure`, even if the run-level conclusion is `success`. The `ci:` line in
the status report MUST reflect the WORST job-level result across all
workflows. A continue-on-error job failure is NOT green — it is RED. Do not
qualify failures as "known", "pre-existing", or "cosmetic".

Only act on failures from the last 2 hours (compare `createdAt` with
`date -u +%Y-%m-%dT%H:%M:%SZ`). For each failure:

1. `gh run view <ID> --log-failed 2>&1 | tail -80`.
2. Categorize: build error, test failure, timeout, flaky, infrastructure.
3. Check for an existing open issue:
   `gh issue list --search "<workflow name + signature>" --state open`.
   If one matches, `gh issue comment <N>` with the new evidence (sha, log
   snippet, timestamp) and ensure it has the `ready` label
   (`gh issue edit <N> --add-label ready`).
4. Otherwise, file a new issue: `gh issue create --label ready --title "<workflow>: <short signature>" --body "..."` with investigation findings.
5. Do NOT commit a fix. Report: `CI ISSUE FILED — <workflow> failed on <sha>, filed/commented #<N>`.

## Bug filing workflow

Applies to node bugs, metric alerts, and CI failures:

1. Identify the failing signature (ledger + error type for node bugs; metric
   + threshold for alerts; workflow + job + error type for CI).
2. Investigate to root cause — read source code, trace code paths.
3. Check for an existing open issue: `gh issue list --search "<keywords>" --state open`.
   If a match exists, verify its state is OPEN
   (`gh issue view <N> --json state -q .state`) and then `gh issue comment <N>`
   with the new evidence and ensure the `ready` label is set, and STOP.
4. If no OPEN match, file a new issue using `gh issue create --label ready`
   with a self-contained proposal body (symptom, evidence, suspected root cause,
   fix sketch with file:line references).
5. Do NOT spawn agents. Do NOT edit the main checkout. The next redeploy tick
   (check 10) will pick up whatever lands on main.

**Recurrence policy**: If a previously-filed bug recurs with material new
evidence, prefer commenting on the existing issue when it is the same bug at
the same site AND the issue is OPEN. If the prior issue is CLOSED, file a new
`ready`-labeled issue with `Related to #<prior> (closed)` in the body and a
note on why the prior fix did not cover this case; do NOT comment on the
closed issue. File a new issue (still referencing `Related to #<prior>` with
one-line scope-diff) when new evidence points at a different named subsystem,
phase/mark, root-cause hypothesis, or candidate site set.

**Commit policy**: the monitor does NOT commit code. All fixes are delegated
via `gh issue` with the `ready` label.

**Deploy regression policy**: If the node fails after a deploy, (a) file or
comment on a `ready`-labeled GitHub issue with the regression details
(commit range, symptoms, watchdog data); (b) restart the node on the last
known-good binary (rebuild from the previous commit) while waiting for the
fix. Do NOT revert commits inline.

## Investigation

For ANY anomaly, investigate to root cause — read source code, check logs,
trace code paths. Never dismiss as "expected". Produce a `ready`-labeled
GitHub issue (or comment on an existing one) for every anomaly that isn't
immediately explained. **Only exception**: anomalies whose root cause turns
out to be literal expected-correct behavior per the code — document the code
path in the status report and skip the filing.

## Output

Print a multiline status report:

```
MONITOR <OK|WARNING|ACTION> — L<ledger> — <timestamp>
  node:    mode=<MODE> session=<session-id> pid=<PID> fresh_start=<yes|no>
  sync:    <synced | CATCHING UP (gap=N, uptime=Xm, deadline=<15m|4h>) | SYNC FAILURE (gap=N, uptime=Xm — filed/commented #<N>)>
  mem:     <RSS_MB>MB rss | alloc=<alloc>MB resident=<resident>MB frag=<pct>%
           heap=<heap>MB mmap=<mmap>MB unaccounted=<sign><unaccounted>MB
  disk:    <used>/<total> (<pct>%) | session+data=<size>
  rpc:     <healthy|unhealthy|N/A> oldestL=<X> latestL=<Y> window=<Z>
  obsrvr:  <validating=<Y/N> val24h=<pct>% lag=<N> | N/A (watcher) | N/A (api-error)>
  metrics: <clean | N alerts (<metric1>,<metric2>,...) — filed/commented #<N>,#<M> | N alerts, K suppressed by cooldown>
  deploy:  <up-to-date | pulled N commits (old..new) | SKIPPED (dirty-tree|ci-red|build-failed, filed/commented #<N>)>
  ci:      <all green (run+job level) | WORKFLOW failed — filed/commented #<N> | WORKFLOW jobs FAILED (continue-on-error) — NAME|conclusion listed, filed/commented #<N>>
```

Use WARNING for threshold breaches. Use ACTION when a corrective action was
taken (restart, deploy, filed a new issue, commented on an existing issue).
Use SYNC FAILURE (not WARNING) when the node has exceeded the active sync
deadline (15m populated / 4h fresh-start) but is not closing ledgers in
real-time — this is a bug that requires immediate investigation AND
filing/commenting on a `ready`-labeled issue.
