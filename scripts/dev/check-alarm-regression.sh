#!/usr/bin/env bash
# check-alarm-regression.sh — Baseline comparison and regression detection
# for alarm replay results.
#
# Compares current alarm replay JSON against a stored baseline to detect
# regressions (alarms that were meaningfully active but have gone silent).
#
# Usage:
#   scripts/dev/check-alarm-regression.sh SESSION_DIR [--current FILE] [--baseline FILE]
#
# If --current is omitted, runs replay-alarms-on-history.sh --replay --json
# internally. If --baseline is omitted, defaults to $METRICS_DIR/replay-baseline.json.
#
# Exit code: always 0 (regressions are informational, not failures).
# Stdout: JSON array of regression objects (empty [] if none).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REPLAY_SCRIPT="$REPO_ROOT/scripts/dev/replay-alarms-on-history.sh"

SESSION_DIR=""
CURRENT_FILE=""
BASELINE_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --current)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --current requires a file path argument" >&2
        exit 1
      fi
      CURRENT_FILE="$2"
      shift 2
      ;;
    --baseline)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --baseline requires a file path argument" >&2
        exit 1
      fi
      BASELINE_FILE="$2"
      shift 2
      ;;
    *)
      if [[ -z "$SESSION_DIR" ]]; then
        SESSION_DIR="$1"
      else
        echo "ERROR: Unexpected argument: $1" >&2
        exit 1
      fi
      shift
      ;;
  esac
done

if [[ -z "$SESSION_DIR" ]]; then
  echo "ERROR: SESSION_DIR is required as first positional argument" >&2
  exit 1
fi

METRICS_DIR="$SESSION_DIR/metrics"

if [[ -z "$BASELINE_FILE" ]]; then
  BASELINE_FILE="$METRICS_DIR/replay-baseline.json"
fi

# Get current replay JSON if not provided
if [[ -z "$CURRENT_FILE" ]]; then
  CURRENT_JSON=$("$REPLAY_SCRIPT" "$SESSION_DIR" --replay --json 2>/dev/null) || {
    echo "ERROR: Failed to run replay" >&2
    echo "[]"
    exit 0
  }
else
  if [[ ! -f "$CURRENT_FILE" ]]; then
    echo "ERROR: Current file not found: $CURRENT_FILE" >&2
    echo "[]"
    exit 0
  fi
  CURRENT_JSON=$(cat "$CURRENT_FILE")
fi

# If no baseline exists, establish one
if [[ ! -f "$BASELINE_FILE" ]]; then
  echo "$CURRENT_JSON" > "$BASELINE_FILE"
  ALARM_COUNT=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('alarms',{})))" 2>/dev/null || echo "0")
  EVAL_TICKS=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('evaluated_ticks',0))" 2>/dev/null || echo "0")
  echo "Baseline established ($ALARM_COUNT alarms, $EVAL_TICKS evaluated ticks)" >&2
  echo "[]"
  exit 0
fi

# Compare baseline vs current — compute regressions once, capture output
REGRESSION_OUTPUT=$(python3 -c "
import json, sys

baseline_file = sys.argv[1]
current_json_str = sys.argv[2]

with open(baseline_file) as f:
    baseline = json.load(f)

current = json.loads(current_json_str)

# Validate schema versions — exit 2 to signal error (distinct from exit 0 = success)
if baseline.get('schema_version') != 1:
    print('ERROR: Baseline has unexpected schema_version', file=sys.stderr)
    sys.exit(2)
if current.get('schema_version') != 1:
    print('ERROR: Current has unexpected schema_version', file=sys.stderr)
    sys.exit(2)

baseline_alarms = baseline.get('alarms', {})
current_alarms = current.get('alarms', {})
baseline_evaluated = baseline.get('evaluated_ticks', 0)
current_evaluated = current.get('evaluated_ticks', 0)

regressions = []

for alarm_name, b_counts in baseline_alarms.items():
    # Compute eligible samples (exclude skip and baseline/collecting_baseline)
    b_eligible = baseline_evaluated - b_counts.get('skip', 0) - b_counts.get('baseline', 0)
    if b_eligible < 10:
        continue  # Insufficient data in baseline

    b_fired_pct = b_counts.get('firing', 0) / b_eligible if b_eligible > 0 else 0

    if b_fired_pct < 0.05:
        continue  # Not meaningfully active in baseline

    # Check current
    if alarm_name not in current_alarms:
        regressions.append({
            'alarm': alarm_name,
            'baseline_fired_pct': round(b_fired_pct, 4),
            'current_fired_pct': 0.0,
            'baseline_evaluated': baseline_evaluated,
            'current_evaluated': current_evaluated,
            'reason': 'alarm absent from current replay (catalog drift?)',
        })
        continue

    c_counts = current_alarms[alarm_name]
    c_eligible = current_evaluated - c_counts.get('skip', 0) - c_counts.get('baseline', 0)
    if c_eligible < 10:
        continue  # Insufficient data in current

    c_firing = c_counts.get('firing', 0)
    if c_firing == 0:
        regressions.append({
            'alarm': alarm_name,
            'baseline_fired_pct': round(b_fired_pct, 4),
            'current_fired_pct': 0.0,
            'baseline_evaluated': baseline_evaluated,
            'current_evaluated': current_evaluated,
            'reason': 'alarm was active but is now silent',
        })

print(json.dumps(regressions))
" "$BASELINE_FILE" "$CURRENT_JSON")
COMPARE_EXIT=$?

if [[ $COMPARE_EXIT -ne 0 ]]; then
  echo "ERROR: Regression comparison failed (exit $COMPARE_EXIT)" >&2
  # Fail closed — do NOT update baseline, do NOT print success output
  exit 2
fi

# Print regression JSON to stdout
echo "$REGRESSION_OUTPUT"

# Count regressions
REGRESSION_COUNT=$(echo "$REGRESSION_OUTPUT" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")

if [[ "$REGRESSION_COUNT" == "0" ]]; then
  # No regressions — update baseline (rolling forward)
  echo "$CURRENT_JSON" > "$BASELINE_FILE"
  echo "No regressions found. Baseline updated." >&2
else
  # Regressions found — keep last-known-good baseline
  echo "$REGRESSION_COUNT regression(s) found. Baseline NOT updated (preserving last-known-good)." >&2

  # Ensure alarm-regression label exists
  gh label create alarm-regression --description "Alarm regression detected by replay" --color "d93f0b" 2>/dev/null || true

  # Get existing open alarm-regression issues for dedup (by title and body marker)
  EXISTING_ISSUES=$(gh issue list --label alarm-regression --state open --json title,body --jq '.[].title + "|||" + .body' 2>/dev/null) || true

  # File issues for each regression
  echo "$REGRESSION_OUTPUT" | python3 -c "
import json, sys
for r in json.load(sys.stdin):
    print(json.dumps(r))
" 2>/dev/null | while IFS= read -r regression_line; do
    [[ -z "$regression_line" ]] && continue
    ALARM_NAME=$(echo "$regression_line" | python3 -c "import json,sys; print(json.load(sys.stdin)['alarm'])" 2>/dev/null) || continue
    BASELINE_PCT=$(echo "$regression_line" | python3 -c "import json,sys; print(json.load(sys.stdin)['baseline_fired_pct'])" 2>/dev/null) || continue
    REASON=$(echo "$regression_line" | python3 -c "import json,sys; print(json.load(sys.stdin)['reason'])" 2>/dev/null) || continue

    EXPECTED_TITLE="Alarm regression: $ALARM_NAME"
    BODY_MARKER="<!-- alarm-regression-key: $ALARM_NAME -->"

    # Dedup: check for exact title match OR body marker match
    FOUND_DUP=false
    while IFS= read -r issue_line; do
      [[ -z "$issue_line" ]] && continue
      if echo "$issue_line" | grep -qF "$EXPECTED_TITLE" 2>/dev/null; then
        FOUND_DUP=true
        break
      fi
      if echo "$issue_line" | grep -qF "$BODY_MARKER" 2>/dev/null; then
        FOUND_DUP=true
        break
      fi
    done <<< "$EXISTING_ISSUES"

    if [[ "$FOUND_DUP" == true ]]; then
      echo "Skipping duplicate: $EXPECTED_TITLE" >&2
      continue
    fi

    # File new issue
    ISSUE_BODY="## Alarm Regression Detected

**Alarm**: \`$ALARM_NAME\`
**Baseline fired**: ${BASELINE_PCT} (${BASELINE_PCT}% of eligible ticks)
**Current fired**: 0%
**Reason**: $REASON

### Context
This regression was detected by the weekly alarm replay in \`monitor-tick\` Step 8.
The alarm was meaningfully active (≥5% of ticks) in the baseline but fires 0% in
the current replay window.

### Investigation
1. Check if the alarm was intentionally removed or its threshold changed
2. Check if the underlying metric is still being emitted
3. If the alarm should still be active, investigate why it stopped firing

<!-- alarm-regression-key: $ALARM_NAME -->"

    NEW_ISSUE=$(gh issue create \
      --title "$EXPECTED_TITLE" \
      --label alarm-regression \
      --body "$ISSUE_BODY" 2>/dev/null) || {
      echo "WARNING: Failed to file issue for $ALARM_NAME" >&2
      continue
    }

    # Extract issue number and board-route
    ISSUE_NUM=$(echo "$NEW_ISSUE" | grep -oP '\d+$') || true
    if [[ -n "$ISSUE_NUM" ]]; then
      bash "$REPO_ROOT/.github/skills/plan-do-review/scripts/move-issue-status.sh" "$ISSUE_NUM" Backlog 2>/dev/null || true
    fi

    echo "Filed: $NEW_ISSUE" >&2
  done
fi

exit 0
