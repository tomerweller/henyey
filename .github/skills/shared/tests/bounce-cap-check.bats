#!/usr/bin/env bash
#
# Tests for .github/skills/shared/scripts/bounce-cap-check.sh
#
# This file is written in a BATS-compatible style (each test is a function
# named test_*) but also runs as a plain-bash script: if BATS is installed
# it can be invoked as `bats bounce-cap-check.bats`; otherwise this file is
# executed directly as a plain-bash TAP-style runner.
#
# Why both: the converged plan (issue #2787) prefers BATS but explicitly
# allows a plain-bash fallback when BATS isn't installed. We default to the
# fallback since BATS isn't part of the project's required toolchain.
#
# Mocking strategy: each test creates a temp dir, drops a `gh` shim script
# into it, prepends that dir to PATH, and runs the script under test. The
# shim reads the request URL/args from $@ and emits canned JSON. Tests assert
# on exit code and stdout summary.
#
# Usage:
#   bash .github/skills/shared/tests/bounce-cap-check.bats           # plain
#   bats .github/skills/shared/tests/bounce-cap-check.bats           # BATS
#
# Output: TAP (Test Anything Protocol) when run as plain bash.
# Exit: 0 if all tests pass, non-zero otherwise.

set -uo pipefail

# ── Locate the script under test ─────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
SCRIPT_UNDER_TEST="$REPO_ROOT/.github/skills/shared/scripts/bounce-cap-check.sh"

# ── TAP state ────────────────────────────────────────────────────────────────
TAP_CURRENT=0
TAP_FAILURES=0
TAP_OUTPUT=()

tap_ok() {
  TAP_CURRENT=$((TAP_CURRENT + 1))
  TAP_OUTPUT+=("ok $TAP_CURRENT - $1")
}

tap_fail() {
  TAP_CURRENT=$((TAP_CURRENT + 1))
  TAP_FAILURES=$((TAP_FAILURES + 1))
  TAP_OUTPUT+=("not ok $TAP_CURRENT - $1")
  if [ -n "${2:-}" ]; then
    TAP_OUTPUT+=("  ---")
    TAP_OUTPUT+=("  $2")
    TAP_OUTPUT+=("  ...")
  fi
}

# ── Mock gh shim builder ─────────────────────────────────────────────────────
# Creates a temp dir, writes a `gh` shim that returns canned JSON based on
# the request path, and prepends the temp dir to PATH. The shim distinguishes
# four request shapes used by the script:
#
#   1. `gh pr view <pr> --repo ... --json commits ...`
#        → emit COMMITS_JSON or HEAD_PUSHED_ISO
#   2. `gh api repos/.../issues/<n>/comments --paginate ...` matching Reset
#        → emit RESET_AT_ISO (string or empty)
#   3. `gh api repos/.../issues/<n>/comments --paginate ...` matching count
#        → emit COMMENT_COUNT (number)
#
# The shim pre-processes args to figure out which call this is; the test
# preloads the canned responses via env vars.
make_gh_shim() {
  local tmpdir="$1"
  local head_pushed_iso="$2"
  local reset_at_iso="$3"
  local bounces_after_baseline="$4"   # space-separated list of ISO timestamps
  local bounces_before_baseline="$5"  # space-separated list of ISO timestamps

  mkdir -p "$tmpdir"
  cat > "$tmpdir/gh" <<EOF
#!/usr/bin/env bash
# Mock gh — dispatch on argument shape.

# Concatenate all args for pattern matching.
args="\$*"

# Shape 1: pr view --json commits
if [[ "\$args" == *"pr view"* ]] && [[ "\$args" == *"--json commits"* ]]; then
  # The script applies a jq filter via --jq to extract the last committedDate.
  # We just emit the raw committedDate (the --jq is part of the command, gh
  # would normally apply it, but our shim returns the post-jq output for
  # simplicity). Look for --jq in args — if present, return the string;
  # otherwise return raw JSON.
  if [[ "\$args" == *"--jq"* ]]; then
    echo '$head_pushed_iso'
  else
    # Raw JSON form (not currently used by the script under test).
    echo '{"commits":[{"committedDate":"$head_pushed_iso"}]}'
  fi
  exit 0
fi

# Shape 2 & 3: gh api repos/.../issues/<n>/comments --paginate --jq ...
if [[ "\$args" == *"api"* ]] && [[ "\$args" == *"/comments"* ]]; then
  # Distinguish Reset query from Bounce-Back count query via the --jq body.
  if [[ "\$args" == *"Review: Reset"* ]]; then
    # Reset timestamp query — return the canned value or empty.
    echo '$reset_at_iso'
    exit 0
  fi
  if [[ "\$args" == *"Bounce-Back Cycle"* ]]; then
    # Count bounces — the script's --jq does a numeric comparison against
    # \$BASELINE_EPOCH. To keep the shim simple, we expose a pre-computed
    # answer instead of synthesizing JSON: the test pre-counts how many of
    # its bounces should be > BASELINE_EPOCH and passes that as a literal.
    # We do this by detecting the BASELINE_EPOCH in the jq query and
    # returning the right count. The query has the form:
    #   [.[] | select(.body | startswith("## Review: Bounce-Back Cycle")) |
    #          select((.created_at | fromdate) > <EPOCH>)] | length
    # which we match against to extract the epoch.
    baseline_epoch=\$(echo "\$args" | grep -oE 'fromdate\) > [0-9]+' | grep -oE '[0-9]+\$' || echo 0)
    # Count how many bounces have iso → epoch > baseline_epoch.
    count=0
    for iso in $bounces_after_baseline; do
      ep=\$(date -u -d "\$iso" +%s)
      if [ "\$ep" -gt "\$baseline_epoch" ]; then
        count=\$((count + 1))
      fi
    done
    for iso in $bounces_before_baseline; do
      ep=\$(date -u -d "\$iso" +%s)
      if [ "\$ep" -gt "\$baseline_epoch" ]; then
        count=\$((count + 1))
      fi
    done
    echo "\$count"
    exit 0
  fi
  # Other api/comments query — unexpected.
  echo "unexpected gh api call: \$args" >&2
  exit 99
fi

echo "unexpected gh call: \$args" >&2
exit 99
EOF
  chmod +x "$tmpdir/gh"
}

# ── Test driver ──────────────────────────────────────────────────────────────
# run_script_with_mock <tmpdir>
#   Prepends tmpdir to PATH and invokes the script with stub args. Captures
#   exit code in $LAST_EXIT and stdout in $LAST_STDOUT.
run_script_with_mock() {
  local tmpdir="$1"
  LAST_STDOUT=$(PATH="$tmpdir:$PATH" bash "$SCRIPT_UNDER_TEST" 1234 5678 2>&1)
  LAST_EXIT=$?
}

# ── Tests ────────────────────────────────────────────────────────────────────

# Test 1: zero bounces after baseline → exit 0, count 0.
test_bounce_cap_zero_bounces() {
  local tmpdir
  tmpdir=$(mktemp -d)
  trap "rm -rf '$tmpdir'" RETURN
  # Head pushed 2026-01-01, no Reset, no bounces.
  make_gh_shim "$tmpdir" "2026-01-01T00:00:00Z" "" "" ""
  run_script_with_mock "$tmpdir"
  if [ "$LAST_EXIT" -eq 0 ] && echo "$LAST_STDOUT" | grep -q "0"; then
    tap_ok "test_bounce_cap_zero_bounces — exit 0, count 0 reported"
  else
    tap_fail "test_bounce_cap_zero_bounces — exit=$LAST_EXIT stdout=$LAST_STDOUT"
  fi
}

# Test 2: 2 bounces BEFORE baseline (all older than head_pushed) → exit 0.
test_bounce_cap_bounces_before_baseline() {
  local tmpdir
  tmpdir=$(mktemp -d)
  trap "rm -rf '$tmpdir'" RETURN
  # Head pushed 2026-06-01. Bounces from 2026-01-01 and 2026-02-01 — both
  # before head, so not counted.
  make_gh_shim "$tmpdir" "2026-06-01T00:00:00Z" "" "" "2026-01-01T00:00:00Z 2026-02-01T00:00:00Z"
  run_script_with_mock "$tmpdir"
  if [ "$LAST_EXIT" -eq 0 ]; then
    tap_ok "test_bounce_cap_bounces_before_baseline — exit 0 (bounces excluded)"
  else
    tap_fail "test_bounce_cap_bounces_before_baseline — exit=$LAST_EXIT stdout=$LAST_STDOUT"
  fi
}

# Test 3: 2 bounces AFTER baseline → exit 0, count 2.
test_bounce_cap_bounces_after_baseline() {
  local tmpdir
  tmpdir=$(mktemp -d)
  trap "rm -rf '$tmpdir'" RETURN
  make_gh_shim "$tmpdir" "2026-01-01T00:00:00Z" "" "2026-02-01T00:00:00Z 2026-03-01T00:00:00Z" ""
  run_script_with_mock "$tmpdir"
  if [ "$LAST_EXIT" -eq 0 ] && echo "$LAST_STDOUT" | grep -q "2"; then
    tap_ok "test_bounce_cap_bounces_after_baseline — exit 0, count 2"
  else
    tap_fail "test_bounce_cap_bounces_after_baseline — exit=$LAST_EXIT stdout=$LAST_STDOUT"
  fi
}

# Test 4: exact cap (3 bounces) → exit 1.
test_bounce_cap_exact_cap() {
  local tmpdir
  tmpdir=$(mktemp -d)
  trap "rm -rf '$tmpdir'" RETURN
  make_gh_shim "$tmpdir" "2026-01-01T00:00:00Z" "" \
    "2026-02-01T00:00:00Z 2026-03-01T00:00:00Z 2026-04-01T00:00:00Z" ""
  run_script_with_mock "$tmpdir"
  if [ "$LAST_EXIT" -eq 1 ]; then
    tap_ok "test_bounce_cap_exact_cap — exit 1 (at cap)"
  else
    tap_fail "test_bounce_cap_exact_cap — exit=$LAST_EXIT stdout=$LAST_STDOUT"
  fi
}

# Test 5: over cap (4 bounces) → exit 1.
test_bounce_cap_over_cap() {
  local tmpdir
  tmpdir=$(mktemp -d)
  trap "rm -rf '$tmpdir'" RETURN
  make_gh_shim "$tmpdir" "2026-01-01T00:00:00Z" "" \
    "2026-02-01T00:00:00Z 2026-03-01T00:00:00Z 2026-04-01T00:00:00Z 2026-05-01T00:00:00Z" ""
  run_script_with_mock "$tmpdir"
  if [ "$LAST_EXIT" -eq 1 ]; then
    tap_ok "test_bounce_cap_over_cap — exit 1 (over cap)"
  else
    tap_fail "test_bounce_cap_over_cap — exit=$LAST_EXIT stdout=$LAST_STDOUT"
  fi
}

# Test 6: Reset marker NEWER than head → baseline = Reset, bounces before
# Reset are excluded.
test_bounce_cap_reset_marker_newer_than_head() {
  local tmpdir
  tmpdir=$(mktemp -d)
  trap "rm -rf '$tmpdir'" RETURN
  # Head: 2026-01-01. Reset: 2026-06-01. Bounces: 2 between head and Reset
  # (should NOT count), 1 after Reset (should count).
  make_gh_shim "$tmpdir" "2026-01-01T00:00:00Z" "2026-06-01T00:00:00Z" \
    "2026-07-01T00:00:00Z" \
    "2026-02-01T00:00:00Z 2026-03-01T00:00:00Z"
  run_script_with_mock "$tmpdir"
  # Expected: count = 1, exit 0.
  if [ "$LAST_EXIT" -eq 0 ] && echo "$LAST_STDOUT" | grep -q "1"; then
    tap_ok "test_bounce_cap_reset_marker_newer_than_head — baseline=Reset, only post-Reset bounces count"
  else
    tap_fail "test_bounce_cap_reset_marker_newer_than_head — exit=$LAST_EXIT stdout=$LAST_STDOUT"
  fi
}

# Test 7: HEAD newer than Reset → baseline = HEAD (Reset ignored). Also
# implicitly tests empty Reset case if you pass empty Reset.
test_bounce_cap_head_newer_than_reset() {
  local tmpdir
  tmpdir=$(mktemp -d)
  trap "rm -rf '$tmpdir'" RETURN
  # Head: 2026-06-01. Reset: 2026-01-01 (older). Bounces: 2 between Reset
  # and Head (should NOT count), 1 after Head (should count).
  make_gh_shim "$tmpdir" "2026-06-01T00:00:00Z" "2026-01-01T00:00:00Z" \
    "2026-07-01T00:00:00Z" \
    "2026-02-01T00:00:00Z 2026-03-01T00:00:00Z"
  run_script_with_mock "$tmpdir"
  # Expected: count = 1 (only the post-head bounce), exit 0.
  if [ "$LAST_EXIT" -eq 0 ] && echo "$LAST_STDOUT" | grep -q "1"; then
    tap_ok "test_bounce_cap_head_newer_than_reset — baseline=HEAD, Reset ignored"
  else
    tap_fail "test_bounce_cap_head_newer_than_reset — exit=$LAST_EXIT stdout=$LAST_STDOUT"
  fi
}

# ── Runner ───────────────────────────────────────────────────────────────────
main() {
  # Detect BATS — if running under BATS, individual @test blocks would have
  # been declared and this main() wouldn't fire. Since we're using the
  # plain-bash fallback, just call each test_* function in order.
  test_bounce_cap_zero_bounces
  test_bounce_cap_bounces_before_baseline
  test_bounce_cap_bounces_after_baseline
  test_bounce_cap_exact_cap
  test_bounce_cap_over_cap
  test_bounce_cap_reset_marker_newer_than_head
  test_bounce_cap_head_newer_than_reset

  echo "1..$TAP_CURRENT"
  for line in "${TAP_OUTPUT[@]}"; do
    echo "$line"
  done
  echo "# tests: $TAP_CURRENT  failures: $TAP_FAILURES"
  if [ "$TAP_FAILURES" -ne 0 ]; then
    exit 1
  fi
  exit 0
}

main "$@"
