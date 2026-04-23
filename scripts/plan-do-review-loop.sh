#!/usr/bin/env bash
# plan-do-review-loop.sh — endless worker that runs the copilot CLI with the
# `/plan-do-review` skill (no issue argument). The skill's built-in
# auto-selection picks the next eligible issue each iteration.
#
# Usage:
#   ./scripts/plan-do-review-loop.sh
#   LOOP_MODEL=claude-opus-4.6 ./scripts/plan-do-review-loop.sh
#
# Env vars:
#   LOOP_MODEL         AI model passed to copilot (default: claude-opus-4.6)
#   LOOP_EMPTY_SLEEP   Seconds to sleep between runs (default: 60)
#   LOOP_LOG_DIR       Directory for per-run logs (default: ~/data/plan-do-review-loop)

set -euo pipefail

LOOP_MODEL="${LOOP_MODEL:-claude-opus-4.6}"
LOOP_EMPTY_SLEEP="${LOOP_EMPTY_SLEEP:-60}"
LOOP_LOG_DIR="${LOOP_LOG_DIR:-$HOME/data/plan-do-review-loop}"

log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }

on_signal() {
  log "Received signal, shutting down."
  exit 0
}
trap on_signal INT TERM

# --- Preflight ---
command -v gh >/dev/null 2>&1 || { echo "ERROR: gh CLI not found" >&2; exit 1; }
command -v copilot >/dev/null 2>&1 || { echo "ERROR: copilot CLI not found" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "ERROR: gh not authenticated (run 'gh auth login')" >&2; exit 1; }

mkdir -p "$LOOP_LOG_DIR"

log "=== plan-do-review-loop ==="
log "Model:     $LOOP_MODEL"
log "Sleep:     ${LOOP_EMPTY_SLEEP}s"
log "Log dir:   $LOOP_LOG_DIR"

# --- Main loop ---
while true; do
  ts="$(date +%Y%m%d-%H%M%S)"
  logfile="$LOOP_LOG_DIR/${ts}-run.log"
  log "Starting copilot /plan-do-review (auto-select) → $logfile"

  set +e
  copilot \
    --model "$LOOP_MODEL" \
    --allow-all-tools \
    --allow-all-paths \
    --log-dir "$LOOP_LOG_DIR/copilot-logs" \
    -p "/plan-do-review" \
    2>&1 | tee "$logfile"
  rc="${PIPESTATUS[0]}"
  set -e

  if [[ "$rc" -ne 0 ]]; then
    log "copilot exited $rc"
  else
    log "copilot exited 0"
  fi

  log "Sleeping ${LOOP_EMPTY_SLEEP}s before next run…"
  sleep "$LOOP_EMPTY_SLEEP"
done
