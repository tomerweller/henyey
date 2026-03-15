---
name: mainnet-monitor
description: Run and monitor a henyey mainnet node, automatically fixing bugs when found
argument-hint: [--watcher]
---

Parse `$ARGUMENTS`:
- If `--watcher` is present, set `$MODE = watcher`. Otherwise set `$MODE = validator`.

# Mainnet Monitor

Run a henyey mainnet node and monitor it for errors, automatically fixing
bugs when they are discovered. This is a lightweight monitoring skill — no
sweepers, no code maintenance, just a running node with automated log
checking and bug fixing.

**Mainnet operation is explicitly authorized** — this overrides the
testnet-only guideline in CLAUDE.md.

## Investigation Policy

**Every anomaly must be investigated to root cause.** When a check reveals
something unexpected — a threshold exceeded, a warning in logs, a value that
doesn't change when it should — you MUST investigate. Specifically:

- **Never rationalize away an issue.** "This is probably expected" or "it
  should fix itself" are not acceptable conclusions. If you don't know why
  something is happening, that's a bug until proven otherwise.
- **Follow the evidence.** Read the relevant source code, check the database,
  examine the data structures. The answer is in the code, not in speculation.
- **Trace the full path.** If maintenance is running but pruning isn't
  working, read the maintenance code to understand what it actually prunes.
  If a value isn't changing, find the code that's supposed to change it.
- **Report what you found.** Even if the investigation reveals the behavior
  is correct, document *why* — citing the specific code path, not just
  a guess.
- **Fix or file.** If investigation reveals a bug, follow the Bug Fix
  Workflow. If it reveals a missing feature or config issue, fix the config
  or report it clearly with the code-level explanation.

## Startup

1. Generate a session ID (8-char random hex). All session data goes
   under `~/data/<session-id>/`.
2. Create directories:
   ```
   mkdir -p ~/data/<session-id>/{logs,cache,cargo-target}
   ```
3. Build the binary:
   ```
   CARGO_TARGET_DIR=~/data/<session-id>/cargo-target cargo build --release
   ```
4. Check if a henyey node is already running:
   ```
   pgrep -af 'henyey.*run'
   ```
   If a process is found, print its PID and ask whether to attach to its
   existing log or kill and restart it. If attaching, skip to step 7.

5. Select config and command based on `$MODE`:
   - **validator** (default):
     ```
     ~/data/<session-id>/cargo-target/release/henyey run --validator \
       -c configs/validator-mainnet-rpc.toml \
       2>&1 | tee ~/data/<session-id>/logs/monitor.log
     ```
   - **watcher**:
     ```
     ~/data/<session-id>/cargo-target/release/henyey run \
       -c configs/mainnet.toml \
       2>&1 | tee ~/data/<session-id>/logs/monitor.log
     ```
   Start the node in the background.

6. Wait 10 seconds, then tail the last 30 lines of the log to confirm
   the node is starting (look for "Starting", "Catching up", or ledger
   close messages).

7. Print a startup summary:
   ```
   ═══ MAINNET MONITOR STARTED ═══
   Session:  <session-id>
   Mode:     <validator|watcher>
   Config:   configs/<config-file>
   Binary:   ~/data/<session-id>/cargo-target/release/henyey
   Log:      ~/data/<session-id>/logs/monitor.log
   PID:      <pid>

   Next check in ~10 minutes via /loop.
   ════════════════════════════════
   ```

8. Schedule the monitoring loop by invoking `/loop` with a fully
   self-contained prompt. Substitute the real `<session-id>`, `<RUN_CMD>`
   (the full run command from step 5), and `<MODE>` before calling `/loop`:

   ```
   /loop 10m Check the henyey mainnet monitor log at ~/data/<session-id>/logs/monitor.log. Run: tail -n 500 ~/data/<session-id>/logs/monitor.log. Scan for: (1) hash mismatches (lines containing "hash mismatch", "HashMismatch", or differing expected/actual hashes), (2) panics or crashes ("panic", "thread.*panicked", "SIGABRT", "SIGSEGV"), (3) ERROR-level log lines, (4) assertion failures ("assertion failed"), (5) stuck ledger progression (same ledger number for the last 10+ minutes). Also check if the process is alive: pgrep -af 'henyey.*run'. If the process is not running, restart it in the background: <RUN_CMD>. Check resource usage: (6) memory — run: ps -o rss= -p $(pgrep -f 'henyey.*run' | head -1) and convert to MB; if RSS exceeds 24 GB, flag as HIGH MEMORY and investigate per the Resource Investigation section, (7) disk — run: df -h ~/data | tail -1; if usage exceeds 85%, flag as LOW DISK and investigate per the Resource Investigation section, (8) session disk — run: du -s ~/data/<session-id>/ and the mainnet data directory (typically ~/data/mainnet/) and convert to human-readable; if session+mainnet data has grown by more than 20 GB since the last check or exceeds 200 GB total, flag as SESSION DISK HIGH and investigate per the Resource Investigation section. (9) RPC pruning check — run: curl -s -X POST http://localhost:8000 -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}'. Parse the JSON response for oldestLedger, latestLedger, and ledgerRetentionWindow. Verify: RPC is responding (non-empty response), status is "healthy", latestLedger - oldestLedger <= retention_window + 100 (allow ~100 ledger slack for maintenance cycle timing). If latestLedger - oldestLedger > retention_window + 500, flag as PRUNING STALLED — pruning is not keeping up, and investigate per the Pruning Stalled section. If RPC is not responding, flag as RPC DOWN and attempt to check if the process is still running. For ANY anomaly detected (threshold exceeded, unexpected warnings, values not changing as expected), you MUST investigate to root cause by reading source code, checking logs, and tracing the code path. Never dismiss an issue as "expected" or "probably fine". The investigation sections below describe starting points, but always follow the evidence wherever it leads — including into the source code. If everything looks healthy, print one line: MONITOR OK — L<latest-ledger> — <timestamp> — mode: <MODE> — session: <session-id> — mem: <RSS_MB>MB — disk: <used>/<total> (<pct>%) — session+data: <size> — rpc: healthy oldestL=<X> latestL=<Y> window=<Z>. If a bug is found, follow the Bug Fix Workflow: (1) identify the failing ledger number and error type from the log, (2) reproduce offline: ~/data/<session-id>/cargo-target/release/henyey --mainnet verify-execution --from LEDGER --to LEDGER --stop-on-error --show-diff --cache-dir ~/data/<session-id>/cache, (3) write a failing unit test that isolates the bug — it must fail before the fix, (4) fix the code in the main worktree, (5) verify the unit test passes, (6) run cargo test --all to check for regressions, (7) commit fix and regression test together with an imperative message, (8) git push (if rejected: git pull --rebase && git push), (9) run /review-fix --apply on the commit, (10) rebuild: CARGO_TARGET_DIR=~/data/<session-id>/cargo-target cargo build --release, (11) kill the old henyey process and restart it in the background: <RUN_CMD>, (12) report the fix: ledger number, error type, commit hash, one-line summary.
   ```

## Bug Fix Workflow

When a hash mismatch, error, or crash is found (whether detected by the
loop or discovered manually):

1. **Identify** the failing ledger number and error type from the log.
2. **Reproduce** with a targeted offline test:
   ```
   ~/data/<session-id>/cargo-target/release/henyey --mainnet verify-execution \
     --from <LEDGER> --to <LEDGER> \
     --stop-on-error --show-diff \
     --cache-dir ~/data/<session-id>/cache
   ```
3. **Write a failing unit test** that isolates the bug. The test must
   fail before the fix.
4. **Fix the code** in the main worktree.
5. **Verify** the unit test passes.
6. **Run `cargo test --all`** to check for regressions.
7. **Commit** the fix and regression test together:
   ```
   git add <files>
   git commit -m "<Imperative description of fix>"
   ```
8. **Push** immediately: `git push` (if rejected: `git pull --rebase && git push`).
9. **Run `/review-fix --apply`** on the commit.
10. **Rebuild** the binary:
    ```
    CARGO_TARGET_DIR=~/data/<session-id>/cargo-target cargo build --release
    ```
11. **Restart** the node: kill the old process, then start it again
    with the same command from Startup step 5.
12. **Report** what was fixed: ledger number, error type, commit hash,
    and a one-line summary.

## Resource Investigation

When a memory or disk alert is triggered, investigate before taking action.

### High Memory (RSS > 24 GB)

Note: A mainnet validator's steady-state RSS is typically 18-22 GB due to
the in-memory offer store (~5-10 GB) and InMemorySorobanState (~2-5 GB).
These are fundamental data structures, not leaks.

1. **Collect details**:
   ```
   ps -o rss=,vsz=,etime= -p <PID>
   ```
   Check whether RSS is still growing by comparing with the previous
   check, or sample twice 60 seconds apart.

2. **Check for a leak**: If RSS has grown by more than 2 GB since the
   last check (or is consistently growing across multiple checks), this
   likely indicates a memory leak. Growth during the first 30 minutes
   after startup is expected (cache warmup, bucket loading).

3. **Capture diagnostic info**:
   ```
   cat /proc/<PID>/status | grep -E 'VmRSS|VmPeak|VmSwap|Threads'
   cat /proc/<PID>/smaps_rollup
   ```
   Record the latest ledger number and uptime. Check the log for any
   unusual patterns around the time memory started growing (e.g., large
   transaction sets, merge activity, catchup).

4. **If the cause isn't obvious** from process stats and logs, read the
   source code for the hot path (ledger close, Soroban execution, bucket
   merges) to understand allocation patterns. Profile or trace what's
   consuming memory rather than guessing.

5. **If RSS exceeds 28 GB or available system memory is < 4 GB**:
   This is critical. Restart the node to prevent OOM kill:
   - Kill the process gracefully (`kill <PID>`, wait 10s, then
     `kill -9` if needed).
   - Restart with the same command from Startup step 5.
   - Report: `RESOURCE ACTION — restarted node due to memory pressure
     (RSS was <X> GB at L<ledger>)`.

6. **If RSS is between 24–28 GB and stable (not growing)**: Flag it but
   do not restart. Report: `RESOURCE WARNING — RSS <X> GB at L<ledger>,
   stable — monitoring`.

### Session Disk Growth (> 200 GB or +20 GB between checks)

This tracks disk consumed specifically by this monitor session and its
mainnet data, independent of other processes on the machine.

1. **Measure**:
   ```
   du -sh ~/data/<session-id>/
   du -sh ~/data/mainnet/
   ```
   Sum both for the total. The mainnet data directory holds the
   database, buckets, and history — it is the primary growth driver.

2. **Drill into the mainnet data directory**:
   ```
   du -sh ~/data/mainnet/*/ | sort -rh | head -10
   ls -lhS ~/data/mainnet/buckets/ | head -20
   ```
   Check whether bucket files are accumulating (old permanent buckets
   not being cleaned up after merges) or the database is growing
   unexpectedly.

3. **If growth is unexpected**, read the source code that writes to the
   growing directory to understand what's being written and whether cleanup
   is implemented. For example, if buckets are accumulating, read the merge
   and cleanup code to verify old buckets are being removed after merges.

4. **Safe cleanup within the session**:
   - Incremental build caches:
     `rm -rf ~/data/<session-id>/cargo-target/release/incremental`
   - Old verify-execution cache entries (if any):
     `du -sh ~/data/<session-id>/cache/ && ls ~/data/<session-id>/cache/ | head`
     Remove cache entries older than 7 days if the cache exceeds 10 GB.
   - Check for stale `.tmp` or partial bucket files in the mainnet
     data directory.

5. **Report**: Include the breakdown in the monitor line. If growth is
   abnormal (e.g., buckets directory doubled), report:
   `RESOURCE WARNING — session+data disk at <X> GB (buckets: <Y> GB,
   db: <Z> GB) — investigating`.

### Pruning Stalled

When the gap between `latestLedger` and `oldestLedger` significantly exceeds
the configured `retention_window` (360 ledgers):

1. **Check if maintenance is running** — look for "Performing database
   maintenance" or "Maintenance complete" in recent logs:
   ```
   grep -i 'maintenance' ~/data/<session-id>/logs/monitor.log | tail -20
   ```

2. **Check if maintenance is taking too long** — look for "Maintenance took
   too long" warnings in the log.

3. **Read the maintenance/pruning source code** to understand what is
   actually being pruned. Search for the maintenance handler, trace what
   `count` controls, and verify that RPC data (ledger entries, transaction
   results, events) is included in the pruning path — not just ledger
   headers or other data. If the maintenance code doesn't prune RPC data,
   that's a bug or missing feature to fix.
   ```
   grep -r 'maintenance\|prune\|retention' crates/ --include='*.rs' -l
   ```
   Read the relevant files to understand the pruning pipeline.

4. **Check DB size**:
   ```
   ls -lh ~/data/mainnet/mainnet.db
   ```

5. **Trigger manual maintenance** if it hasn't run recently:
   ```
   curl -X POST http://localhost:11627/maintenance?count=100000
   ```

6. **If the gap keeps growing** after manual maintenance, the `count`
   parameter may be too low for the data volume. Increase it in the config
   or trigger with a higher count:
   ```
   curl -X POST http://localhost:11627/maintenance?count=500000
   ```

7. **Re-check** after manual maintenance:
   ```
   curl -s -X POST http://localhost:8000 -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}'
   ```
   Verify the gap is decreasing. If not, report:
   `RESOURCE WARNING — pruning stalled, gap=<N> after manual maintenance`.
   Revisit the source code findings from step 3 to determine if pruning
   covers all necessary data types.

### Low Disk (> 85% usage)

1. **Identify large consumers**:
   ```
   du -sh ~/data/*/ | sort -rh | head -10
   ```
   Then drill into the largest directories:
   ```
   du -sh ~/data/<largest-dir>/*/ | sort -rh | head -10
   ```

2. **Safe cleanup candidates** (delete without asking):
   - Cargo build artifacts from old sessions:
     `~/data/<old-session-id>/cargo-target/` where the session is not
     the current one and no henyey process is using that binary.
   - Stale cache directories from old sessions:
     `~/data/<old-session-id>/cache/` (same criteria).
   - Old log files: `~/data/<old-session-id>/logs/` (same criteria).
   - Rust incremental build caches: `find ~/data/*/cargo-target -name
     incremental -type d` — these can be safely removed.
   Before deleting, verify no running process references the directory:
   `ls -la /proc/*/exe 2>/dev/null | grep <session-id>`.

3. **Investigate if no obvious cleanup**: If disk usage is high and
   there are no stale sessions to clean, check whether the mainnet data
   directory (`~/data/mainnet/` or similar) is growing unexpectedly:
   ```
   du -sh ~/data/mainnet/*/  | sort -rh | head -10
   ls -lhrt ~/data/mainnet/buckets/ | tail -20
   ```
   Look for bucket files that are unreasonably large or accumulating.
   Check log files that may be growing unbounded.

4. **If disk exceeds 95%**: This is critical. Perform safe cleanup
   immediately (step 2). If still above 95% after cleanup, report to
   the user: `RESOURCE CRITICAL — disk at <pct>% after cleanup,
   manual intervention needed`.

5. **Report**: After any cleanup, report what was removed and the new
   disk usage percentage.

## Teardown

When stopping (user interrupts):
1. Kill the henyey process gracefully.
2. Print a final status: uptime, latest ledger seen, bugs found/fixed.
3. Do NOT remove logs or cache — they may be useful for debugging.
4. The `/loop` cron job dies automatically when the session exits.

## Guidelines

- Always build with `--release` — debug builds are too slow for mainnet.
- Follow the test-first bug fix workflow strictly. Do not skip writing a
  failing test.
- Commit bug fixes immediately after the test passes. Do not batch fixes.
- **Push after every fix commit** — do not accumulate unpushed commits.
- All commits must include the appropriate `Co-authored-by` trailer per
  CLAUDE.md.
- **Investigate every anomaly to root cause.** Never dismiss warnings,
  threshold breaches, or unexpected values as "expected" or "transient".
  Read the source code, trace the code path, and either fix the issue or
  document exactly why the behavior is correct (with code references).
- This skill does NOT manage sweepers or code maintenance. Use
  `/production-ops` for the full workload.
