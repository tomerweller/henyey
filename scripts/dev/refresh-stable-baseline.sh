#!/usr/bin/env bash
# refresh-stable-baseline.sh — Per-alarm targeted baseline refresh.
#
# Removes specified alarm entries from both the stable and rolling baselines,
# preventing false regression alerts for alarms whose behavior intentionally
# changed (e.g., after a bug fix). Also auto-revokes matching acknowledgments.
#
# The alarm will reappear in the rolling baseline on the next clean run
# (when check-alarm-regression.sh updates the rolling baseline on zero
# regressions). The stable baseline won't auto-repopulate — it's a
# long-term reference that only resets on catalog changes or manual
# re-creation. To restore stable-baseline coverage for a removed alarm,
# either delete the stable baseline file or use --force-baseline-update.
#
# Usage:
#   scripts/dev/refresh-stable-baseline.sh SESSION_DIR ALARM_NAME [ALARM_NAME ...]
#
# Exit codes:
#   0 — success
#   1 — usage error
#   2 — fatal error (invalid catalog, corrupt baseline)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 SESSION_DIR ALARM_NAME [ALARM_NAME ...]" >&2
  exit 1
fi

SESSION_DIR="$1"
shift
ALARM_NAMES=("$@")

METRICS_DIR="$SESSION_DIR/metrics"
BASELINE_FILE="$METRICS_DIR/replay-baseline.json"
STABLE_BASELINE_FILE="$METRICS_DIR/replay-baseline-stable.json"
CATALOG_FILE="$REPO_ROOT/.claude/skills/shared/metric-alarms.toml"
ACK_FILE="$METRICS_DIR/alarm-acknowledgments.json"
ACK_LOCK="$METRICS_DIR/alarm-acknowledgments.lock"

if [[ ! -f "$CATALOG_FILE" ]]; then
  echo "ERROR: Alarm catalog not found: $CATALOG_FILE" >&2
  exit 2
fi

# Validate that all requested alarms exist in the catalog
INVALID_ALARMS=$(python3 -c "
import sys
try:
    import tomllib
except ImportError:
    import tomli as tomllib
try:
    with open(sys.argv[1], 'rb') as f:
        catalog = tomllib.load(f)
except Exception as e:
    print('ERROR: Failed to parse alarm catalog: ' + str(e), file=sys.stderr)
    sys.exit(2)
valid = {a['name'] for a in catalog.get('alarm', [])}
if not valid:
    print('ERROR: Catalog has no alarm entries', file=sys.stderr)
    sys.exit(2)
invalid = [name for name in sys.argv[2:] if name not in valid]
if invalid:
    print(' '.join(invalid))
" "$CATALOG_FILE" "${ALARM_NAMES[@]}") || exit 2

if [[ -n "$INVALID_ALARMS" ]]; then
  echo "ERROR: Alarm(s) not found in catalog: $INVALID_ALARMS" >&2
  exit 1
fi

# Helper: remove alarms from a baseline file (atomic write)
remove_alarms_from_baseline() {
  local baseline_file="$1"
  local label="$2"
  shift 2
  local alarm_names=("$@")

  if [[ ! -f "$baseline_file" ]]; then
    echo "Skipping $label baseline: file not found ($baseline_file)" >&2
    return 0
  fi

  local tmpout="${baseline_file}.tmp.$$"

  # Remove specified alarms and report which were found
  local removed_list
  removed_list=$(python3 -c "
import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

removed = []
for name in sys.argv[3:]:
    if name in data.get('alarms', {}):
        del data['alarms'][name]
        removed.append(name)

with open(sys.argv[2], 'w') as f:
    json.dump(data, f, indent=2)

print(','.join(removed))
" "$baseline_file" "$tmpout" "${alarm_names[@]}" 2>/dev/null) || {
    rm -f "$tmpout"
    echo "ERROR: Failed to process $label baseline" >&2
    return 2
  }

  mv -f "$tmpout" "$baseline_file"

  if [[ -n "$removed_list" ]]; then
    echo "Removed from $label baseline: $removed_list" >&2
  else
    echo "No matching alarms found in $label baseline" >&2
  fi
}

# Remove alarms from both baselines
remove_alarms_from_baseline "$STABLE_BASELINE_FILE" "stable" "${ALARM_NAMES[@]}"
remove_alarms_from_baseline "$BASELINE_FILE" "rolling" "${ALARM_NAMES[@]}"

# Auto-revoke matching acknowledgments
if [[ -f "$ACK_FILE" ]]; then
  (
    flock -w 30 9 || { echo "ERROR: Could not acquire acknowledgment lock" >&2; exit 2; }

    ACK_DATA=$(python3 -c "
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except (json.JSONDecodeError, ValueError, OSError):
    print('ERROR: Acknowledgment file is not valid JSON: ' + sys.argv[1], file=sys.stderr)
    sys.exit(2)
if data.get('schema_version') != 1:
    print('ERROR: Acknowledgment file has unexpected schema_version', file=sys.stderr)
    sys.exit(2)
if not isinstance(data.get('alarms'), dict):
    print('ERROR: Acknowledgment file missing alarms object', file=sys.stderr)
    sys.exit(2)
print(json.dumps(data))
" "$ACK_FILE") || exit 2

    REVOKED_LIST=$(python3 -c "
import json, sys
data = json.loads(sys.argv[1])
revoked = [name for name in sys.argv[2:] if name in data.get('alarms', {})]
print(','.join(revoked))
" "$ACK_DATA" "${ALARM_NAMES[@]}" 2>/dev/null) || REVOKED_LIST=""

    NEW_ACK_JSON=$(python3 -c "
import json, sys
data = json.loads(sys.argv[1])
for name in sys.argv[2:]:
    data.get('alarms', {}).pop(name, None)
print(json.dumps(data))
" "$ACK_DATA" "${ALARM_NAMES[@]}" 2>/dev/null)

    tmpout="${ACK_FILE}.tmp.$$"
    echo "$NEW_ACK_JSON" > "$tmpout"
    mv -f "$tmpout" "$ACK_FILE"

    if [[ -n "$REVOKED_LIST" ]]; then
      echo "Revoked acknowledgments: $REVOKED_LIST" >&2
    fi
  ) 9>"$ACK_LOCK"
fi

echo "Baseline refresh complete for: ${ALARM_NAMES[*]}" >&2
