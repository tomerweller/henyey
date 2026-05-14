#!/usr/bin/env bash
# check-alarm-regression.sh — Baseline comparison and regression detection
# for alarm replay results.
#
# Compares current alarm replay JSON against two stored baselines to detect
# regressions (alarms that were meaningfully active but have gone silent):
#
#   - Rolling baseline (replay-baseline.json): updated on each clean run.
#     Catches sudden regressions from one run to the next.
#   - Stable baseline (replay-baseline-stable.json): frozen at creation time,
#     never auto-updated (except on catalog changes). Catches gradual decay
#     where an alarm that was historically active (≥5%) has silently drifted
#     to 0% over successive rolling-baseline updates. The stable baseline is
#     auto-invalidated and recreated when the alarm catalog (metric-alarms.toml)
#     changes. Per-alarm invalidation via baseline_version bumps, catalog
#     structural changes, and temporal provenance (semantic_change_date) ensures
#     contaminated data from pre-change replay windows is automatically detected.
#
# Only alarms present in the alarm catalog are considered; non-catalog alarm
# names (e.g. from stale baselines or test contamination) are silently pruned.
#
# Usage:
#   scripts/dev/check-alarm-regression.sh SESSION_DIR [--current FILE] \
#       [--baseline FILE] [--stable-baseline FILE] [--catalog FILE] \
#       [--force-baseline-update] [--no-file] \
#       [--acknowledge ALARM --ack-rationale TEXT] \
#       [--revoke-acknowledgment ALARM] [--list-acknowledgments]
#
# If --current is omitted, runs replay-alarms-on-history.sh --replay --json
# internally. If --baseline is omitted, defaults to $METRICS_DIR/replay-baseline.json.
# If --stable-baseline is omitted, defaults to $METRICS_DIR/replay-baseline-stable.json.
# If --catalog is omitted, defaults to $REPO_ROOT/.claude/skills/shared/metric-alarms.toml.
#
# --force-baseline-update: Force-update both rolling and stable baselines from
#   current replay data, even when regressions are detected. Issue filing is
#   suppressed. Use after investigating a regression and confirming it reflects
#   a legitimate improvement (e.g., alarm went silent because the underlying
#   condition was fixed).
#
# --no-file: Suppress all GitHub side effects (issue filing, comments, label
#   creation) and dedup file reads/writes. Regression JSON is still emitted to
#   stdout and baselines are still created/updated. Use in tests and local
#   reproductions to avoid accidentally filing real issues.
#
# --acknowledge ALARM_NAME: Record one alarm as acknowledged. Requires
#   --ack-rationale. Optional: --ack-issue NUMBER.
# --revoke-acknowledgment ALARM_NAME: Remove one acknowledgment.
# --list-acknowledgments: Print current acknowledgments.
#
# These three modes are mutually exclusive with each other and with
# --force-baseline-update. They short-circuit before replay/baseline logic.
#
# Exit codes:
#   0 — success (regressions are informational, not failures)
#   2 — fatal error (missing/invalid catalog, schema mismatch, corrupt baseline/ack file)
# Stdout: JSON array of regression objects (empty [] if none).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REPLAY_SCRIPT="$REPO_ROOT/scripts/dev/replay-alarms-on-history.sh"

SESSION_DIR=""
CURRENT_FILE=""
BASELINE_FILE=""
STABLE_BASELINE_FILE=""
CATALOG_FILE=""
FORCE_BASELINE_UPDATE=false
NO_FILE=false
ACKNOWLEDGE_ALARM=""
REVOKE_ALARM=""
LIST_ACKS=false
ACK_RATIONALE=""
ACK_ISSUE=""

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
    --stable-baseline)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --stable-baseline requires a file path argument" >&2
        exit 1
      fi
      STABLE_BASELINE_FILE="$2"
      shift 2
      ;;
    --catalog)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --catalog requires a file path argument" >&2
        exit 1
      fi
      CATALOG_FILE="$2"
      shift 2
      ;;
    --force-baseline-update)
      FORCE_BASELINE_UPDATE=true
      shift
      ;;
    --no-file)
      NO_FILE=true
      shift
      ;;
    --acknowledge)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --acknowledge requires an alarm name argument" >&2
        exit 1
      fi
      ACKNOWLEDGE_ALARM="$2"
      shift 2
      ;;
    --revoke-acknowledgment)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --revoke-acknowledgment requires an alarm name argument" >&2
        exit 1
      fi
      REVOKE_ALARM="$2"
      shift 2
      ;;
    --list-acknowledgments)
      LIST_ACKS=true
      shift
      ;;
    --ack-rationale)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --ack-rationale requires a text argument" >&2
        exit 1
      fi
      ACK_RATIONALE="$2"
      shift 2
      ;;
    --ack-issue)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --ack-issue requires a number argument" >&2
        exit 1
      fi
      ACK_ISSUE="$2"
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

# Mutual exclusion check for modes
MODE_COUNT=0
[[ "$FORCE_BASELINE_UPDATE" == true ]] && ((MODE_COUNT++)) || true
[[ -n "$ACKNOWLEDGE_ALARM" ]] && ((MODE_COUNT++)) || true
[[ -n "$REVOKE_ALARM" ]] && ((MODE_COUNT++)) || true
[[ "$LIST_ACKS" == true ]] && ((MODE_COUNT++)) || true
if [[ "$MODE_COUNT" -gt 1 ]]; then
  echo "ERROR: --force-baseline-update, --acknowledge, --revoke-acknowledgment, and --list-acknowledgments are mutually exclusive" >&2
  exit 1
fi

# Validate --acknowledge requirements
if [[ -n "$ACKNOWLEDGE_ALARM" ]]; then
  TRIMMED_RATIONALE=$(echo "$ACK_RATIONALE" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  if [[ -z "$TRIMMED_RATIONALE" ]]; then
    echo "ERROR: --acknowledge requires --ack-rationale with non-empty text" >&2
    exit 1
  fi
  if [[ -n "$ACK_ISSUE" ]]; then
    if ! [[ "$ACK_ISSUE" =~ ^[0-9]+$ ]] || [[ "$ACK_ISSUE" -le 0 ]]; then
      echo "ERROR: --ack-issue must be a positive integer" >&2
      exit 1
    fi
  fi
fi

if [[ -z "$SESSION_DIR" ]]; then
  echo "ERROR: SESSION_DIR is required as first positional argument" >&2
  exit 1
fi

METRICS_DIR="$SESSION_DIR/metrics"

if [[ -z "$BASELINE_FILE" ]]; then
  BASELINE_FILE="$METRICS_DIR/replay-baseline.json"
fi

if [[ -z "$STABLE_BASELINE_FILE" ]]; then
  STABLE_BASELINE_FILE="$METRICS_DIR/replay-baseline-stable.json"
fi

# Reject if rolling and stable point to the same file
ROLLING_CANONICAL=$(realpath --canonicalize-missing "$BASELINE_FILE" 2>/dev/null || readlink -f "$BASELINE_FILE" 2>/dev/null || echo "$BASELINE_FILE")
STABLE_CANONICAL=$(realpath --canonicalize-missing "$STABLE_BASELINE_FILE" 2>/dev/null || readlink -f "$STABLE_BASELINE_FILE" 2>/dev/null || echo "$STABLE_BASELINE_FILE")
if [[ "$ROLLING_CANONICAL" == "$STABLE_CANONICAL" ]]; then
  echo "ERROR: --baseline and --stable-baseline must be different files" >&2
  exit 2
fi

# Catalog: default to repo-root metric-alarms.toml (matching replay-alarms-on-history.sh)
if [[ -z "$CATALOG_FILE" ]]; then
  CATALOG_FILE="$REPO_ROOT/.claude/skills/shared/metric-alarms.toml"
fi

if [[ ! -f "$CATALOG_FILE" ]]; then
  echo "ERROR: Alarm catalog not found: $CATALOG_FILE" >&2
  exit 2
fi

# Compute provenance values once per run (prevents drift between calls)
CATALOG_CHECKSUM=$(sha256sum "$CATALOG_FILE" | cut -d' ' -f1)
PROVENANCE_COMMIT=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "unknown")
PROVENANCE_TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Helper: compute per-alarm version map from catalog.
# Outputs JSON object: {"alarm-name": version, ...}
# Validates: positive integer >= 1, no duplicate names. Exits 2 on failure.
compute_alarm_versions() {
  python3 -c "
import sys, json
try:
    import tomllib
except ImportError:
    import tomli as tomllib

catalog_path = sys.argv[1]
with open(catalog_path, 'rb') as f:
    catalog = tomllib.load(f)

alarms = catalog.get('alarm', [])
if not alarms:
    print('ERROR: Catalog has no alarm entries', file=sys.stderr)
    sys.exit(2)

versions = {}
for a in alarms:
    name = a.get('name', '')
    if not name:
        print('ERROR: Alarm entry missing name field', file=sys.stderr)
        sys.exit(2)
    if name in versions:
        print(f'ERROR: Duplicate alarm name in catalog: {name}', file=sys.stderr)
        sys.exit(2)
    v = a.get('baseline_version', 1)
    if not isinstance(v, int) or v < 1:
        print(f'ERROR: Invalid baseline_version for alarm {name}: {v!r} (must be integer >= 1)', file=sys.stderr)
        sys.exit(2)
    se = a.get('silence_expected')
    if se is not None and not isinstance(se, bool):
        print(f'ERROR: Invalid silence_expected for alarm {name}: {se!r} (must be boolean)', file=sys.stderr)
        sys.exit(2)
    versions[name] = v

print(json.dumps(versions, sort_keys=True))
" "$1"
}

# Compute per-alarm versions once per run
ALARM_VERSIONS_JSON=$(compute_alarm_versions "$CATALOG_FILE") || exit $?

# Extract per-alarm semantic_change_date timestamps (for temporal provenance checks)
compute_alarm_semantic_dates() {
  python3 -c "
import sys, json
try:
    import tomllib
except ImportError:
    import tomli as tomllib

with open(sys.argv[1], 'rb') as f:
    catalog = tomllib.load(f)

import re
ISO_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
dates = {}
for a in catalog.get('alarm', []):
    name = a.get('name', '')
    d = a.get('semantic_change_date')
    if d:
        if not isinstance(d, str) or not ISO_RE.match(d):
            print(f'ERROR: Invalid semantic_change_date for alarm {name}: {d!r} (must be YYYY-MM-DDTHH:MM:SSZ)', file=sys.stderr)
            sys.exit(2)
        dates[name] = d
print(json.dumps(dates, sort_keys=True))
" "$1"
}
ALARM_SEMANTIC_DATES_JSON=$(compute_alarm_semantic_dates "$CATALOG_FILE") || exit $?

ACK_FILE="$METRICS_DIR/alarm-acknowledgments.json"
ACK_LOCK="$METRICS_DIR/alarm-acknowledgments.lock"

# Helper: load and validate the acknowledgment file.
# Prints the JSON content to stdout. If the file is missing, prints empty default.
# If malformed or wrong schema_version, exits 2.
# Does NOT handle catalog provenance — caller must do that.
load_ack_file() {
  if [[ ! -f "$ACK_FILE" ]]; then
    echo '{"schema_version":1,"catalog_checksum":"","alarms":{}}'
    return 0
  fi
  python3 -c "
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
" "$ACK_FILE" || exit 2
}

# Helper: write acknowledgment file atomically via tmp+mv.
# Reads JSON from stdin.
write_ack_file() {
  local tmpout="${ACK_FILE}.tmp.$$"
  cat > "$tmpout"
  mv -f "$tmpout" "$ACK_FILE"
}

# Helper: check catalog provenance on ack data and invalidate if needed.
# Reads ack JSON from stdin, prints (possibly invalidated) JSON to stdout.
# Pure transformation — does NOT write to disk. Caller is responsible for
# persisting via write_ack_file() under flock.
check_ack_provenance() {
  python3 -c "
import json, sys
data = json.loads(sys.stdin.read())
current_checksum = sys.argv[1]
current_versions = json.loads(sys.argv[2])

stored_checksum = data.get('catalog_checksum', '')
stored_versions = data.get('alarm_versions')

# Legacy: no alarm_versions present — fail closed (fixes #2647).
# Treat all stored versions as unknown so version-bump and temporal
# invalidation checks can run.
if not isinstance(stored_versions, dict):
    if stored_checksum and stored_checksum != current_checksum:
        # Catalog changed with no version info — must wipe (legacy behavior)
        n = len(data.get('alarms', {}))
        if n > 0:
            print('Acknowledgment file invalidated: alarm catalog changed (legacy, was %s..., now %s...)' % (stored_checksum[:12], current_checksum[:12]), file=sys.stderr)
        data['alarms'] = {}
        data['catalog_checksum'] = current_checksum
        data['alarm_versions'] = current_versions
        print(json.dumps(data))
        sys.exit(0)
    stored_versions = {}
    # Fall through to version-bump + temporal checks

checksum_changed = (stored_checksum != current_checksum)

# Per-alarm invalidation (runs when checksum changed or legacy migration)
alarms = data.get('alarms', {})
current_names = set(current_versions.keys())
invalidated = []

if checksum_changed:
    stored_names = set(stored_versions.keys())

    # Remove acks for alarms removed from catalog
    for name in list(alarms.keys()):
        if name not in current_names:
            del alarms[name]
            invalidated.append(name)

    # Remove acks for alarms with version bumps
    for name in list(alarms.keys()):
        if name in current_versions:
            stored_v = stored_versions.get(name)
            if stored_v is None or stored_v != current_versions[name]:
                del alarms[name]
                invalidated.append(name)

# Temporal check — always runs regardless of checksum match (fixes #2647).
# Remove acks predating an alarm's semantic change (fail-closed: missing
# or malformed acknowledged_at is treated as stale)
import re
ACK_ISO_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
semantic_dates = json.loads(sys.argv[3])
for name in list(alarms.keys()):
    if name in invalidated:
        continue
    change_date = semantic_dates.get(name)
    if not change_date:
        continue
    ack_ts = alarms[name].get('acknowledged_at', '')
    if not ack_ts or not ACK_ISO_RE.match(ack_ts) or ack_ts < change_date:
        del alarms[name]
        invalidated.append(name)

if invalidated:
    print('Acknowledgments: per-alarm invalidation — removed %d ack(s): %s' % (len(invalidated), ', '.join(sorted(invalidated))), file=sys.stderr)

# Only update data if something changed
if invalidated or checksum_changed:
    data['alarms'] = alarms
    data['catalog_checksum'] = current_checksum
    data['alarm_versions'] = current_versions

print(json.dumps(data))
" "$CATALOG_CHECKSUM" "$ALARM_VERSIONS_JSON" "$ALARM_SEMANTIC_DATES_JSON"
}

# Helper: validate alarm name exists in catalog. Exit 2 if not.
validate_catalog_alarm() {
  local alarm_name="$1"
  python3 -c "
import sys
try:
    import tomllib
except ImportError:
    import tomli as tomllib
with open(sys.argv[1], 'rb') as f:
    catalog = tomllib.load(f)
valid = {a['name'] for a in catalog.get('alarm', [])}
if sys.argv[2] not in valid:
    print('ERROR: Alarm \"%s\" not found in catalog' % sys.argv[2], file=sys.stderr)
    sys.exit(2)
" "$CATALOG_FILE" "$alarm_name" || exit 2
}

# ── Acknowledgment mode short-circuits ───────────────────────────────────

if [[ -n "$ACKNOWLEDGE_ALARM" ]]; then
  mkdir -p "$METRICS_DIR"
  validate_catalog_alarm "$ACKNOWLEDGE_ALARM"
  (
    flock -w 30 9 || { echo "ERROR: Could not acquire acknowledgment lock" >&2; exit 2; }
    ACK_RAW=$(load_ack_file) || exit $?
    ACK_JSON=$(echo "$ACK_RAW" | check_ack_provenance) || exit $?
    ACK_JSON=$(echo "$ACK_JSON" | python3 -c "
import json, sys
data = json.loads(sys.stdin.read())
alarm_name = sys.argv[1]
rationale = sys.argv[2]
commit = sys.argv[3]
timestamp = sys.argv[4]
issue = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] else None
entry = {
    'acknowledged_at': timestamp,
    'acknowledged_commit': commit,
    'rationale': rationale,
}
if issue:
    entry['issue'] = int(issue)
data['alarms'][alarm_name] = entry
data['catalog_checksum'] = sys.argv[6]
print(json.dumps(data))
" "$ACKNOWLEDGE_ALARM" "$ACK_RATIONALE" "$PROVENANCE_COMMIT" "$PROVENANCE_TIMESTAMP" "$ACK_ISSUE" "$CATALOG_CHECKSUM")
    echo "$ACK_JSON" | write_ack_file
  ) 9>"$ACK_LOCK"
  echo "Acknowledged alarm: $ACKNOWLEDGE_ALARM" >&2
  exit 0
fi

if [[ -n "$REVOKE_ALARM" ]]; then
  if [[ ! -d "$METRICS_DIR" ]] || [[ ! -f "$ACK_FILE" ]]; then
    echo "No acknowledgment found for: $REVOKE_ALARM" >&2
    exit 0
  fi
  (
    flock -w 30 9 || { echo "ERROR: Could not acquire acknowledgment lock" >&2; exit 2; }
    ACK_RAW=$(load_ack_file) || exit $?
    ACK_JSON=$(echo "$ACK_RAW" | check_ack_provenance) || exit $?
    FOUND=$(echo "$ACK_JSON" | python3 -c "
import json, sys
data = json.loads(sys.stdin.read())
print('yes' if sys.argv[1] in data.get('alarms', {}) else 'no')
" "$REVOKE_ALARM")
    NEW_JSON=$(echo "$ACK_JSON" | python3 -c "
import json, sys
data = json.loads(sys.stdin.read())
data['alarms'].pop(sys.argv[1], None)
print(json.dumps(data))
" "$REVOKE_ALARM")
    echo "$NEW_JSON" | write_ack_file
    if [[ "$FOUND" == "yes" ]]; then
      echo "Revoked acknowledgment: $REVOKE_ALARM" >&2
    else
      echo "No acknowledgment found for: $REVOKE_ALARM" >&2
    fi
  ) 9>"$ACK_LOCK"
  exit 0
fi

if [[ "$LIST_ACKS" == true ]]; then
  if [[ ! -d "$METRICS_DIR" ]] || [[ ! -f "$ACK_FILE" ]]; then
    echo "No acknowledgments."
    exit 0
  fi
  # Load, validate, check provenance, and write back — all under lock
  list_exit=0
  ACK_JSON=$(
    (
      flock -w 30 9 || { echo "ERROR: Could not acquire acknowledgment lock" >&2; exit 2; }
      ACK_DATA=$(load_ack_file) || exit $?
      CHECKED=$(echo "$ACK_DATA" | check_ack_provenance) || exit $?
      echo "$CHECKED" | write_ack_file
      echo "$CHECKED"
    ) 9>"$ACK_LOCK"
  ) || list_exit=$?
  [[ "$list_exit" -ne 0 ]] && exit "$list_exit"
  python3 -c "
import json, sys
data = json.loads(sys.stdin.read())
alarms = data.get('alarms', {})
if not alarms:
    print('No acknowledgments.')
    sys.exit(0)
for name, meta in sorted(alarms.items()):
    issue_str = ' (issue #%s)' % meta['issue'] if 'issue' in meta else ''
    print('  %s: %s [%s, %s%s]' % (
        name, meta.get('rationale', ''), meta.get('acknowledged_at', '?'),
        meta.get('acknowledged_commit', '?')[:12], issue_str))
" <<< "$ACK_JSON"
  exit 0
fi

# ── Normal regression detection continues below ─────────────────────────
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

# Validate current replay data before any baseline writes
python3 -c "
import json, sys
try:
    data = json.loads(sys.argv[1])
except (json.JSONDecodeError, ValueError):
    print('ERROR: Current replay data is not valid JSON', file=sys.stderr)
    sys.exit(2)
if data.get('schema_version') != 1:
    print('ERROR: Current replay data has unexpected schema_version', file=sys.stderr)
    sys.exit(2)
if not isinstance(data.get('alarms'), dict):
    print('ERROR: Current replay data missing alarms object', file=sys.stderr)
    sys.exit(2)
if not isinstance(data.get('evaluated_ticks'), int) or data['evaluated_ticks'] < 0:
    print('ERROR: Current replay data has invalid evaluated_ticks', file=sys.stderr)
    sys.exit(2)
" "$CURRENT_JSON" || exit 2

# Helper: validate a baseline file (JSON, schema_version, structure)
# Returns 0 if valid, 1 if missing, 2 if corrupt/invalid
validate_baseline() {
  local file="$1"
  local label="$2"
  if [[ ! -f "$file" ]]; then
    return 1
  fi
  python3 -c "
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except (json.JSONDecodeError, ValueError, OSError):
    print('ERROR: %s baseline is not valid JSON: ' % sys.argv[2] + sys.argv[1], file=sys.stderr)
    sys.exit(2)
if data.get('schema_version') != 1:
    print('ERROR: %s baseline has unexpected schema_version' % sys.argv[2], file=sys.stderr)
    sys.exit(2)
if not isinstance(data.get('alarms'), dict):
    print('ERROR: %s baseline missing alarms object' % sys.argv[2], file=sys.stderr)
    sys.exit(2)
if not isinstance(data.get('evaluated_ticks'), int) or data['evaluated_ticks'] < 0:
    print('ERROR: %s baseline has invalid evaluated_ticks' % sys.argv[2], file=sys.stderr)
    sys.exit(2)
" "$file" "$label" || return 2
  return 0
}

# Helper: create a catalog-pruned baseline from current replay data with provenance.
# Uses atomic write (tmp + mv) to prevent corruption on failure.
create_baseline() {
  local output_file="$1"
  local tmpout="${output_file}.tmp.$$"
  python3 -c "
import json, sys
try:
    import tomllib
except ImportError:
    import tomli as tomllib
catalog_path = sys.argv[1]
current_str = sys.argv[2]
checksum = sys.argv[3]
commit = sys.argv[4]
timestamp = sys.argv[5]
alarm_versions_str = sys.argv[6]
with open(catalog_path, 'rb') as f:
    catalog = tomllib.load(f)
valid = {a['name'] for a in catalog.get('alarm', [])}
if not valid:
    print('ERROR: Catalog has no alarm entries', file=sys.stderr)
    sys.exit(2)
data = json.loads(current_str)
alarms = data.get('alarms', {})
data['alarms'] = {k: v for k, v in alarms.items() if k in valid}
alarm_versions = json.loads(alarm_versions_str)
data['provenance'] = {
    'created_at': timestamp,
    'created_commit': commit,
    'catalog_checksum': checksum,
    'alarm_versions': alarm_versions,
}
print(json.dumps(data))
" "$CATALOG_FILE" "$CURRENT_JSON" "$CATALOG_CHECKSUM" "$PROVENANCE_COMMIT" "$PROVENANCE_TIMESTAMP" "$ALARM_VERSIONS_JSON" > "$tmpout" || {
    echo "ERROR: Failed to create baseline: $output_file" >&2
    rm -f "$tmpout"
    exit 2
  }
  mv -f "$tmpout" "$output_file"
}

# Helper: extract catalog_checksum from a baseline's provenance.
# Prints the checksum if valid, empty string otherwise.
extract_catalog_checksum() {
  python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
p = d.get('provenance')
if isinstance(p, dict):
    cs = p.get('catalog_checksum', '')
    if isinstance(cs, str) and len(cs) > 0:
        print(cs)
" "$1" 2>/dev/null || true
}

# Helper: inject provenance into an existing baseline file, preserving its
# alarm data. Used for legacy/malformed baselines where the alarm payload is
# still valid signal. Writes atomically via tmp+mv.
inject_provenance() {
  local baseline_file="$1"
  local tmp_file="${baseline_file}.tmp.$$"
  python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
alarm_versions = json.loads(sys.argv[5])
d['provenance'] = {
    'created_at': sys.argv[2],
    'created_commit': sys.argv[3],
    'catalog_checksum': sys.argv[4],
    'alarm_versions': alarm_versions,
}
with open(sys.argv[6], 'w') as f:
    json.dump(d, f)
" "$baseline_file" "$PROVENANCE_TIMESTAMP" "$PROVENANCE_COMMIT" "$CATALOG_CHECKSUM" "$ALARM_VERSIONS_JSON" "$tmp_file"
  mv -f "$tmp_file" "$baseline_file"
}

# Helper: check a baseline's catalog checksum and invalidate/migrate if needed.
# $1 = baseline file path, $2 = label (for logging)
maybe_invalidate_baseline() {
  local baseline_file="$1"
  local label="$2"
  local tmp_file="${baseline_file}.tmp.$$"

  python3 -c "
import json, sys

baseline_path = sys.argv[1]
label = sys.argv[2]
current_checksum = sys.argv[3]
current_versions_str = sys.argv[4]
commit = sys.argv[5]
timestamp = sys.argv[6]

current_versions = json.loads(current_versions_str)
current_names = set(current_versions.keys())

with open(baseline_path) as f:
    data = json.load(f)

provenance = data.get('provenance')
if not isinstance(provenance, dict):
    provenance = {}

stored_versions = provenance.get('alarm_versions')

# Step 0: Legacy check — alarm_versions missing or not a valid dict.
# Non-destructive migration: preserve alarm data, stamp current provenance,
# but fall through to Step D (temporal check) instead of exiting.
# Previously this exited immediately, bypassing temporal invalidation.
# (Fixes #2647)
is_legacy = not isinstance(stored_versions, dict)
if is_legacy:
    print(f'Migrating {label} baseline: stamping per-alarm version provenance', file=sys.stderr)

stored_checksum = provenance.get('catalog_checksum', '') if not is_legacy else current_checksum
checksum_changed = (stored_checksum != current_checksum)

alarms = data.get('alarms', {})
invalidated = []

if checksum_changed:
    stored_names = set((stored_versions or {}).keys())

    # Step B: Structural check — removed alarms
    removed = stored_names - current_names
    for name in removed:
        if name in alarms:
            del alarms[name]
            invalidated.append(name)

    # Step C: Version check — version bumps
    for name, current_v in current_versions.items():
        stored_v = (stored_versions or {}).get(name)
        if stored_v is None or stored_v != current_v:
            if name in alarms:
                del alarms[name]
                invalidated.append(name)

# Step D: Temporal provenance — always runs regardless of checksum match.
# Catches contaminated baselines whose replay window predates an alarm's
# semantic_change_date (e.g. after a legacy migration stamped the current
# checksum but preserved stale alarm data).  (Fixes #2647)
import re
ISO_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
baseline_first_ts = data.get('first_ts', '')
if baseline_first_ts and ISO_RE.match(baseline_first_ts):
    semantic_dates = json.loads(sys.argv[8])
    for name in list(alarms.keys()):
        if name in invalidated:
            continue
        change_date = semantic_dates.get(name)
        if change_date and baseline_first_ts < change_date:
            del alarms[name]
            invalidated.append(name)

# Only write when something actually changed — avoid disk churn on no-op.
if not invalidated and not checksum_changed and not is_legacy:
    sys.exit(0)

data['alarms'] = alarms
data['provenance'] = {
    'created_at': timestamp,
    'created_commit': commit,
    'catalog_checksum': current_checksum,
    'alarm_versions': current_versions,
}

if invalidated:
    inv_list = ', '.join(sorted(invalidated))
    print(f'{label} baseline: per-alarm invalidation — removed {len(invalidated)} alarm(s): {inv_list}', file=sys.stderr)
elif checksum_changed:
    print(f'{label} baseline: catalog changed but no alarm versions differ — all data preserved', file=sys.stderr)

with open(sys.argv[7], 'w') as f:
    json.dump(data, f)
" "$baseline_file" "$label" "$CATALOG_CHECKSUM" "$ALARM_VERSIONS_JSON" "$PROVENANCE_COMMIT" "$PROVENANCE_TIMESTAMP" "$tmp_file" "$ALARM_SEMANTIC_DATES_JSON" || {
    echo "ERROR: Failed to invalidate $label baseline" >&2
    rm -f "$tmp_file"
    exit 2
  }

  # If the python script wrote a tmp file, atomically replace
  if [[ -f "$tmp_file" ]]; then
    mv -f "$tmp_file" "$baseline_file"
  fi
}

# Determine baseline states
ROLLING_STATE="missing"
STABLE_STATE="missing"

set +e
validate_baseline "$BASELINE_FILE" "Rolling"
case $? in
  0) ROLLING_STATE="valid" ;;
  1) ROLLING_STATE="missing" ;;
  2) exit 2 ;;
esac

validate_baseline "$STABLE_BASELINE_FILE" "Stable"
case $? in
  0) STABLE_STATE="valid" ;;
  1) STABLE_STATE="missing" ;;
  2) exit 2 ;;
esac
set -e

# Bootstrap: handle all missing/valid combinations
if [[ "$ROLLING_STATE" == "missing" && "$STABLE_STATE" == "missing" ]]; then
  # First run — create both baselines
  create_baseline "$BASELINE_FILE"
  cp "$BASELINE_FILE" "$STABLE_BASELINE_FILE"
  ALARM_COUNT=$(python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('alarms',{})))" < "$BASELINE_FILE" 2>/dev/null || echo "0")
  EVAL_TICKS=$(python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('evaluated_ticks',0))" < "$BASELINE_FILE" 2>/dev/null || echo "0")
  echo "Baseline established ($ALARM_COUNT alarms, $EVAL_TICKS evaluated ticks)" >&2
  echo "[]"
  exit 0
fi

if [[ "$ROLLING_STATE" == "valid" && "$STABLE_STATE" == "missing" ]]; then
  create_baseline "$STABLE_BASELINE_FILE"
  echo "Stable baseline established" >&2
fi

if [[ "$ROLLING_STATE" == "missing" && "$STABLE_STATE" == "valid" ]]; then
  create_baseline "$BASELINE_FILE"
  echo "Rolling baseline re-established" >&2
fi

# Both baselines now exist and are valid — check provenance and auto-invalidate if needed
maybe_invalidate_baseline "$BASELINE_FILE" "Rolling"
maybe_invalidate_baseline "$STABLE_BASELINE_FILE" "Stable"

# Load acknowledgments for regression filtering (all under flock to avoid TOCTOU)
ACK_SET_JSON="{}"
if [[ -f "$ACK_FILE" ]]; then
  ack_load_exit=0
  ACK_SET_JSON=$(
    (
      flock -w 30 9 || { echo "ERROR: Could not acquire acknowledgment lock" >&2; exit 2; }
      ACK_DATA=$(load_ack_file) || exit $?
      # Use unified per-alarm invalidation (same as check_ack_provenance)
      UPDATED=$(echo "$ACK_DATA" | check_ack_provenance) || exit $?
      # Write back if changed
      if [[ "$UPDATED" != "$ACK_DATA" ]]; then
        echo "$UPDATED" | write_ack_file
      fi
      echo "$UPDATED" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(json.dumps(d.get('alarms',{})))" 2>/dev/null || echo "{}"
    ) 9>"$ACK_LOCK"
  ) || ack_load_exit=$?
  if [[ "$ack_load_exit" -ne 0 ]]; then
    exit "$ack_load_exit"
  fi
fi

# Run dual comparison
set +e
REGRESSION_OUTPUT=$(python3 -c "
import json, sys

try:
    import tomllib
except ImportError:
    import tomli as tomllib

rolling_file = sys.argv[1]
stable_file = sys.argv[2]
current_json_str = sys.argv[3]
catalog_path = sys.argv[4]
ack_set_str = sys.argv[5]

# Load alarm catalog
with open(catalog_path, 'rb') as f:
    catalog = tomllib.load(f)
valid_alarms = {a['name'] for a in catalog.get('alarm', [])}
if not valid_alarms:
    print('ERROR: Catalog has no alarm entries', file=sys.stderr)
    sys.exit(2)

# Build silence_expected set — alarms where going to 0% is not a regression
silence_expected = set()
for a in catalog.get('alarm', []):
    se = a.get('silence_expected')
    if se is True:
        silence_expected.add(a['name'])
    elif se is not None and se is not False:
        aname = a['name']
        print(f'ERROR: alarm {aname}: silence_expected must be boolean, got {se!r}', file=sys.stderr)
        sys.exit(2)

# Load acknowledged alarms
acknowledged = set(json.loads(ack_set_str).keys())

with open(rolling_file) as f:
    rolling = json.load(f)
with open(stable_file) as f:
    stable = json.load(f)
current = json.loads(current_json_str)

current_alarms = current.get('alarms', {})
current_evaluated = current.get('evaluated_ticks', 0)

def compare_baseline(baseline_data, source_label):
    \"\"\"Compare a baseline against current data. Returns list of regression dicts.\"\"\"
    results = []
    baseline_alarms = baseline_data.get('alarms', {})
    baseline_evaluated = baseline_data.get('evaluated_ticks', 0)

    if source_label == 'rolling':
        absent_reason = 'alarm absent from current replay (catalog drift?)'
        silent_reason = 'alarm was active but is now silent'
    else:
        absent_reason = 'alarm absent from current replay but was active in stable baseline (gradual drift?)'
        silent_reason = 'alarm was active in stable baseline but has gradually decayed to silent'

    for alarm_name, b_counts in baseline_alarms.items():
        if alarm_name not in valid_alarms:
            continue

        if alarm_name in acknowledged:
            continue

        b_eligible = baseline_evaluated - b_counts.get('skip', 0) - b_counts.get('baseline', 0)
        if b_eligible < 10:
            continue

        b_fired_pct = b_counts.get('firing', 0) / b_eligible if b_eligible > 0 else 0
        if b_fired_pct < 0.05:
            continue

        if alarm_name not in current_alarms:
            results.append({
                'alarm': alarm_name,
                'baseline_source': source_label,
                'baseline_fired_pct': round(b_fired_pct, 4),
                'baseline_fired_pct_display': round(b_fired_pct * 100, 2),
                'current_fired_pct': 0.0,
                'baseline_evaluated': baseline_evaluated,
                'current_evaluated': current_evaluated,
                'reason': absent_reason,
            })
            continue

        c_counts = current_alarms[alarm_name]
        c_eligible = current_evaluated - c_counts.get('skip', 0) - c_counts.get('baseline', 0)
        if c_eligible < 10:
            continue

        c_firing = c_counts.get('firing', 0)
        if c_firing == 0:
            if alarm_name in silence_expected:
                continue
            results.append({
                'alarm': alarm_name,
                'baseline_source': source_label,
                'baseline_fired_pct': round(b_fired_pct, 4),
                'baseline_fired_pct_display': round(b_fired_pct * 100, 2),
                'current_fired_pct': 0.0,
                'baseline_evaluated': baseline_evaluated,
                'current_evaluated': current_evaluated,
                'reason': silent_reason,
            })
    return results

# Run both comparisons
rolling_regressions = compare_baseline(rolling, 'rolling')
stable_regressions = compare_baseline(stable, 'stable')

# Merge with stable-wins dedup (stable overwrites rolling on key collision)
merged = {}
for r in rolling_regressions:
    merged[r['alarm']] = r
for r in stable_regressions:
    merged[r['alarm']] = r  # stable wins

# Log acknowledged alarms that were skipped (deduplicated across both baselines)
if acknowledged:
    for name in sorted(acknowledged):
        print('Acknowledged alarm skipped: %s' % name, file=sys.stderr)

print(json.dumps(list(merged.values())))
" "$BASELINE_FILE" "$STABLE_BASELINE_FILE" "$CURRENT_JSON" "$CATALOG_FILE" "$ACK_SET_JSON")
COMPARE_EXIT=$?
set -e

if [[ $COMPARE_EXIT -ne 0 ]]; then
  echo "ERROR: Regression comparison failed (exit $COMPARE_EXIT)" >&2
  exit 2
fi

# Print regression JSON to stdout
echo "$REGRESSION_OUTPUT"

# Count regressions
REGRESSION_COUNT=$(echo "$REGRESSION_OUTPUT" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")

if [[ "$REGRESSION_COUNT" == "0" ]]; then
  # No regressions from either baseline — update rolling (stable is never updated)
  create_baseline "$BASELINE_FILE"
  echo "No regressions found. Rolling baseline updated." >&2
elif [[ "$FORCE_BASELINE_UPDATE" == true ]]; then
  # Regressions found but operator explicitly requested baseline update.
  # This acknowledges the regressions as legitimate (e.g., alarm went silent
  # because the underlying condition was fixed) and resets both baselines to
  # the current state. Issue filing is suppressed.
  echo "$REGRESSION_COUNT regression(s) found. Force-updating baselines (rolling + stable)." >&2
  create_baseline "$BASELINE_FILE"
  create_baseline "$STABLE_BASELINE_FILE"
  echo "Baselines force-updated. Regressions acknowledged." >&2
else
  # Regressions found — keep last-known-good rolling baseline
  echo "$REGRESSION_COUNT regression(s) found. Rolling baseline NOT updated (preserving last-known-good)." >&2

  if [[ "$NO_FILE" == true ]]; then
    echo "Filing suppressed (--no-file): $REGRESSION_COUNT regression(s) detected" >&2
  else

  # Ensure alarm-regression label exists
  gh label create alarm-regression --description "Alarm regression detected by replay" --color "d93f0b" 2>/dev/null || true

  # Serialize concurrent filing attempts with an exclusive lock.
  LOCK_FILE="$REPO_ROOT/.alarm-regression-filing.lock"
  (
    flock -w 30 9 || {
      echo "Could not acquire alarm-regression filing lock after 30s; skipping." >&2
      exit 0
    }

    declare -A FILED_THIS_RUN

    # Load and prune persistent cross-invocation dedup record (repo-global, under flock).
    # Uses shared dedup-filing library (scripts/lib/dedup-filing.sh).
    DEDUP_FILE="$REPO_ROOT/.alarm-regression-filed.json"
    source "$REPO_ROOT/scripts/lib/dedup-filing.sh"
    DEDUP_DATA=$(dedup_load "$DEDUP_FILE")
    DEDUP_DATA=$(dedup_prune "$DEDUP_DATA" "24h")

    # Prune entries for alarms not in the current catalog (test contamination defense).
    DEDUP_BEFORE_CATALOG_PRUNE="$DEDUP_DATA"
    DEDUP_DATA=$(printf '%s' "$DEDUP_DATA" | python3 -c "
import json, sys
data = json.loads(sys.stdin.read())
valid = set(json.loads(sys.argv[1]).keys())
filed = data.get('filed', {})
pruned = [k for k in filed if k not in valid]
for k in pruned:
    del filed[k]
    print('Pruned non-catalog dedup entry: %s' % k, file=sys.stderr)
data['filed'] = filed
print(json.dumps(data))
" "$ALARM_VERSIONS_JSON")
    # Write back if catalog pruning removed entries
    if [[ "$DEDUP_DATA" != "$DEDUP_BEFORE_CATALOG_PRUNE" ]]; then
      dedup_write "$DEDUP_FILE" "$DEDUP_DATA"
    fi

    while IFS= read -r regression_line; do
      [[ -z "$regression_line" ]] && continue
      ALARM_NAME=$(echo "$regression_line" | python3 -c "import json,sys; print(json.load(sys.stdin)['alarm'])" 2>/dev/null) || continue
      BASELINE_DISPLAY_PCT=$(echo "$regression_line" | python3 -c "import json,sys; print(json.load(sys.stdin)['baseline_fired_pct_display'])" 2>/dev/null) || continue
      BASELINE_SOURCE=$(echo "$regression_line" | python3 -c "import json,sys; print(json.load(sys.stdin)['baseline_source'])" 2>/dev/null) || continue
      REASON=$(echo "$regression_line" | python3 -c "import json,sys; print(json.load(sys.stdin)['reason'])" 2>/dev/null) || continue

      EXPECTED_TITLE="Alarm regression: $ALARM_NAME"
      BODY_MARKER="<!-- alarm-regression-key: $ALARM_NAME -->"

      # Defensive within-run dedup
      if [[ -n "${FILED_THIS_RUN[$ALARM_NAME]+x}" ]]; then
        echo "Skipping within-run duplicate: $EXPECTED_TITLE" >&2
        continue
      fi

      # Persistent cross-invocation dedup: skip if filed within the last 24 hours
      if dedup_check "$DEDUP_DATA" "$ALARM_NAME" >/dev/null 2>&1; then
        echo "Skipping cross-invocation duplicate (filed within 24h): $EXPECTED_TITLE" >&2
        continue
      fi

      # Per-alarm dedup: server-side narrowing + client-side exact verification.
      TITLE_CANDIDATES=$(gh issue list --label alarm-regression --state open \
        --search "in:title \"$ALARM_NAME\"" \
        --json number,title,body 2>/dev/null) || TITLE_CANDIDATES="[]"

      MARKER_CANDIDATES=$(gh issue list --label alarm-regression --state open \
        --search "in:body \"alarm-regression-key: $ALARM_NAME\"" \
        --json number,title,body 2>/dev/null) || MARKER_CANDIDATES="[]"

      FOUND_DUP=false
      DUP_ISSUE_NUMBER=""
      for candidate_json in "$TITLE_CANDIDATES" "$MARKER_CANDIDATES"; do
        while IFS= read -r candidate; do
          [[ -z "$candidate" ]] && continue
          c_title=$(echo "$candidate" | python3 -c "import json,sys; print(json.load(sys.stdin).get('title',''))" 2>/dev/null) || continue
          c_body=$(echo "$candidate" | python3 -c "import json,sys; print(json.load(sys.stdin).get('body',''))" 2>/dev/null) || continue
          c_number=$(echo "$candidate" | python3 -c "import json,sys; print(json.load(sys.stdin).get('number',''))" 2>/dev/null) || continue
          if [[ "$c_title" == "$EXPECTED_TITLE" ]] || echo "$c_body" | grep -qF "$BODY_MARKER" 2>/dev/null; then
            FOUND_DUP=true
            DUP_ISSUE_NUMBER="$c_number"
            break 2
          fi
        done < <(echo "$candidate_json" | python3 -c "import json,sys; [print(json.dumps(x)) for x in json.load(sys.stdin)]" 2>/dev/null)
      done

      if [[ "$FOUND_DUP" == true ]]; then
        echo "Skipping duplicate: $EXPECTED_TITLE" >&2

        # Auto-comment on existing issue with updated replay numbers (Gap 2b).
        if [[ -n "$DUP_ISSUE_NUMBER" ]]; then
          TODAY=$(date -u +%Y-%m-%d)
          UPDATE_MARKER="<!-- alarm-regression-update: $ALARM_NAME $TODAY -->"

          # Check if we already commented today
          ALREADY_COMMENTED=$(gh issue view "$DUP_ISSUE_NUMBER" --json comments \
            --jq "[.comments[].body] | map(select(contains(\"alarm-regression-update: $ALARM_NAME $TODAY\"))) | length" \
            2>/dev/null) || ALREADY_COMMENTED="0"

          if [[ "$ALREADY_COMMENTED" == "0" ]]; then
            CURRENT_FIRED_PCT=$(echo "$regression_line" | python3 -c "import json,sys; print(json.load(sys.stdin).get('current_fired_pct', 0))" 2>/dev/null) || CURRENT_FIRED_PCT="0"
            UPDATE_BODY="### Alarm Regression Update

**Alarm**: \`$ALARM_NAME\`
**Baseline source**: $BASELINE_SOURCE
**Baseline fired**: ${BASELINE_DISPLAY_PCT}% of eligible ticks
**Current fired**: ${CURRENT_FIRED_PCT}%
**Date**: $TODAY

This alarm regression is still active. The baseline still shows the alarm was historically active but it currently fires at the above rate.

$UPDATE_MARKER"
            if gh issue comment "$DUP_ISSUE_NUMBER" --body "$UPDATE_BODY" 2>/dev/null; then
              echo "Posted update comment on existing issue #$DUP_ISSUE_NUMBER for $ALARM_NAME" >&2
            else
              echo "WARNING: Failed to post update comment on #$DUP_ISSUE_NUMBER" >&2
            fi
          else
            echo "Skipping update comment (already posted today) on #$DUP_ISSUE_NUMBER for $ALARM_NAME" >&2
          fi
        fi

        continue
      fi

      # Build investigation steps based on baseline source
      if [[ "$BASELINE_SOURCE" == "stable" ]]; then
        INVESTIGATION_STEPS="1. Check if this alarm was intentionally removed or its threshold changed
2. If the alarm catalog changed: the stable baseline should auto-invalidate on the next run
3. If the alarm catalog did NOT change: investigate why the alarm stopped firing — it was historically active
4. Manual fallback: delete \`replay-baseline-stable.json\` to force a refresh"
      else
        INVESTIGATION_STEPS="1. Check if the alarm was intentionally removed or its threshold changed
2. Check if the underlying metric is still being emitted
3. If the alarm should still be active, investigate why it stopped firing"
      fi

      # File new issue
      ISSUE_BODY="## Alarm Regression Detected

**Alarm**: \`$ALARM_NAME\`
**Baseline source**: $BASELINE_SOURCE
**Baseline fired**: ${BASELINE_DISPLAY_PCT}% of eligible ticks
**Current fired**: 0%
**Reason**: $REASON

### Context
This regression was detected by the weekly alarm replay in \`monitor-tick\` Step 8.
The alarm was meaningfully active (≥5% of ticks) in the $BASELINE_SOURCE baseline but fires 0% in
the current replay window.

### Investigation
$INVESTIGATION_STEPS

<!-- alarm-regression-key: $ALARM_NAME -->"

      NEW_ISSUE=$(gh issue create \
        --title "$EXPECTED_TITLE" \
        --label alarm-regression \
        --body "$ISSUE_BODY" 2>/dev/null) || {
        echo "WARNING: Failed to file issue for $ALARM_NAME" >&2
        continue
      }

      FILED_THIS_RUN["$ALARM_NAME"]=1

      # Write persistent cross-invocation dedup record
      DEDUP_DATA=$(dedup_record "$DEDUP_DATA" "$ALARM_NAME" "issue_url=$NEW_ISSUE") || true
      dedup_write "$DEDUP_FILE" "$DEDUP_DATA"

      # Extract issue number and board-route
      ISSUE_NUM=$(echo "$NEW_ISSUE" | grep -oP '\d+$') || true
      if [[ -n "$ISSUE_NUM" ]]; then
        bash "$REPO_ROOT/.github/skills/plan-do-review/scripts/move-issue-status.sh" "$ISSUE_NUM" Backlog 2>/dev/null || true
      fi

      echo "Filed: $NEW_ISSUE" >&2
    done < <(echo "$REGRESSION_OUTPUT" | python3 -c "
import json, sys
for r in json.load(sys.stdin):
    print(json.dumps(r))
" 2>/dev/null)

  ) 9>"$LOCK_FILE"

  fi  # end --no-file guard
fi

# Emit warning for catalog alarms with no rolling baseline coverage
if [[ -f "$BASELINE_FILE" ]]; then
  python3 -c "
import json, sys
alarm_versions = json.loads(sys.argv[1])
with open(sys.argv[2]) as f:
    baseline = json.load(f)
baseline_alarms = set(baseline.get('alarms', {}).keys())
catalog_alarms = set(alarm_versions.keys())
uncovered = sorted(catalog_alarms - baseline_alarms)
if uncovered:
    print('WARNING: %d catalog alarm(s) have no rolling baseline coverage: %s' % (len(uncovered), ', '.join(uncovered)), file=sys.stderr)
    print('  (Rolling baseline only updates on clean runs with zero regressions)', file=sys.stderr)
" "$ALARM_VERSIONS_JSON" "$BASELINE_FILE" || true
fi

exit 0
