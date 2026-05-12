#!/usr/bin/env bash
# replay-alarms-on-history.sh — Point-in-time alarm regression check.
#
# Validates the current alarm catalog against a session's most recent
# metrics snapshot pair. This is a schema + single-evaluation check,
# NOT a historical replay (only one current.prom/prev.prom pair is
# retained per session).
#
# Usage:
#   scripts/dev/replay-alarms-on-history.sh [SESSION_DIR]
#
# SESSION_DIR defaults to the most recent session under ~/data/.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EVAL_SCRIPT="$REPO_ROOT/scripts/lib/eval-alarms.py"
CATALOG="$REPO_ROOT/.claude/skills/shared/metric-alarms.toml"

if [[ ! -f "$EVAL_SCRIPT" ]]; then
  echo "ERROR: eval-alarms.py not found at $EVAL_SCRIPT" >&2
  exit 1
fi
if [[ ! -f "$CATALOG" ]]; then
  echo "ERROR: metric-alarms.toml not found at $CATALOG" >&2
  exit 1
fi

# Find session directory
if [[ $# -ge 1 ]]; then
  SESSION_DIR="$1"
else
  # Find the most recent session directory that has metrics/
  SESSION_DIR=""
  for d in "$HOME"/data/*/metrics; do
    if [[ -d "$d" ]]; then
      parent="$(dirname "$d")"
      if [[ -z "$SESSION_DIR" ]] || [[ "$parent" -nt "$SESSION_DIR" ]]; then
        SESSION_DIR="$parent"
      fi
    fi
  done
  if [[ -z "$SESSION_DIR" ]]; then
    echo "ERROR: No session directory with metrics/ found under ~/data/" >&2
    exit 1
  fi
fi

METRICS_DIR="$SESSION_DIR/metrics"
CURRENT="$METRICS_DIR/current.prom"
PREV="$METRICS_DIR/prev.prom"

echo "=== Alarm Regression Check ==="
echo "Session:  $SESSION_DIR"
echo "Catalog:  $CATALOG"
echo ""

# Step 1: Schema validation
echo "--- Step 1: Schema validation (--validate-only) ---"
if python3 "$EVAL_SCRIPT" --catalog "$CATALOG" --validate-only 2>&1; then
  echo "✓ Schema validation passed"
else
  echo "✗ Schema validation FAILED"
  exit 1
fi
echo ""

# Step 2: Single-evaluation pass (if snapshot pair exists)
if [[ -f "$CURRENT" ]] && [[ -f "$PREV" ]]; then
  echo "--- Step 2: Single-evaluation pass ---"
  echo "current.prom: $CURRENT ($(wc -l < "$CURRENT") lines)"
  echo "prev.prom:    $PREV ($(wc -l < "$PREV") lines)"
  echo ""

  # Create a temporary state dir for the evaluation
  STATE_DIR=$(mktemp -d)
  trap 'rm -rf "$STATE_DIR"' EXIT

  RESULT=$(MONITOR_MODE=validator UPTIME_SECONDS=900 WARMUP_TICKS_REMAINING=0 \
    python3 "$EVAL_SCRIPT" \
    --catalog "$CATALOG" \
    --current "$CURRENT" \
    --prev "$PREV" \
    --state-dir "$STATE_DIR" 2>/dev/null) || true

  if [[ -z "$RESULT" ]]; then
    echo "✗ Evaluation produced no output"
    exit 1
  fi

  # Parse and display results
  python3 -c "
import json, sys
try:
    data = json.loads(sys.argv[1])
    alarms = data.get('alarms', [])
    firing = [a for a in alarms if a.get('state') == 'firing']
    breach = [a for a in alarms if a.get('state') == 'breach']
    skipped = [a for a in alarms if a.get('state') == 'skipped']
    ok = [a for a in alarms if a.get('state') in ('ok', 'clear')]
    other = [a for a in alarms if a.get('state') not in ('firing', 'breach', 'skipped', 'ok', 'clear')]

    print(f'Total alarms evaluated: {len(alarms)}')
    print(f'  Firing:  {len(firing)}')
    print(f'  Breach:  {len(breach)}')
    print(f'  OK:      {len(ok)}')
    print(f'  Skipped: {len(skipped)}')
    if other:
        print(f'  Other:   {len(other)}')
    print()

    if firing:
        print('FIRING alarms:')
        for a in firing:
            print(f'  - {a[\"name\"]}: {a.get(\"details\", \"\")}')
        print()

    if breach:
        print('BREACH alarms (building persistence):')
        for a in breach:
            print(f'  - {a[\"name\"]}: {a.get(\"details\", \"\")}')
        print()

    if skipped:
        print('SKIPPED alarms (exempt or gated):')
        for a in skipped:
            print(f'  - {a[\"name\"]}')
        print()

    print('✓ Evaluation complete')
except Exception as e:
    print(f'Parse error: {e}', file=sys.stderr)
    print(sys.argv[1][:500])
    sys.exit(1)
" "$RESULT"
else
  echo "--- Step 2: SKIPPED (no snapshot pair found) ---"
  echo "  Expected: $CURRENT"
  echo "  Expected: $PREV"
  echo ""
  echo "NOTE: Only one current.prom/prev.prom pair is retained per session."
  echo "      Multi-day historical replay requires snapshot archiving"
  echo "      (not yet implemented)."
fi
