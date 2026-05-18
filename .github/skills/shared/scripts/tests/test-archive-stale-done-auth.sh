#!/usr/bin/env bash
# test-archive-stale-done-auth.sh — regression tests for archive-stale-done.sh
# auth pre-flight behavior.
#
# Tests:
#   1. test_preflight_fails_with_bad_token
#        Runs the script with GH_TOKEN set to an invalid value. Asserts the
#        script exits non-zero AND output contains the structured
#        "ERROR: GH_TOKEN lacks org project scope" message rather than the
#        opaque GraphQL "Could not resolve to a ProjectV2" error. This is the
#        regression for issue #2777.
#   2. test_preflight_succeeds_with_dry_run
#        Runs with SKIP_PREFLIGHT=1 and --dry-run, mocking the gh binary so
#        no network call is made. Asserts exit 0 and no ERROR: in output.
#        Covers the happy path with the probe bypassed.
#
# Usage:
#   bash .github/skills/shared/scripts/tests/test-archive-stale-done-auth.sh
#
# Exits 0 if all tests pass, non-zero on any failure.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_SCRIPT="$SCRIPT_DIR/../archive-stale-done.sh"

if [ ! -x "$TARGET_SCRIPT" ]; then
  echo "FAIL: target script not found or not executable: $TARGET_SCRIPT" >&2
  exit 1
fi

FAILED=0
PASSED=0

# ---------------------------------------------------------------------------
# Test 1: pre-flight fails with bad token → structured error message
# ---------------------------------------------------------------------------
test_preflight_fails_with_bad_token() {
  local name="test_preflight_fails_with_bad_token"
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN

  # Mock `gh` to simulate the "Could not resolve to a ProjectV2" failure that
  # occurs when GH_TOKEN lacks org project scope. The real failure mode is a
  # non-zero exit with that exact stderr message; we reproduce it.
  cat >"$tmpdir/gh" <<'EOF'
#!/usr/bin/env bash
# Mock gh: simulate the underprivileged-token GraphQL failure.
if [[ "$1" == "api" && "$2" == "graphql" ]]; then
  echo "gh: Could not resolve to a ProjectV2 with the number 2." >&2
  exit 1
fi
exit 0
EOF
  chmod +x "$tmpdir/gh"

  local output
  local exit_code
  output=$(PATH="$tmpdir:$PATH" GH_TOKEN="dummy" bash "$TARGET_SCRIPT" --dry-run 2>&1)
  exit_code=$?

  if [ "$exit_code" -eq 0 ]; then
    echo "FAIL: $name — expected non-zero exit, got 0"
    echo "  output: $output"
    FAILED=$((FAILED + 1))
    return
  fi

  if ! grep -q "ERROR: GH_TOKEN lacks org project scope" <<<"$output"; then
    echo "FAIL: $name — output missing 'ERROR: GH_TOKEN lacks org project scope'"
    echo "  output: $output"
    FAILED=$((FAILED + 1))
    return
  fi

  echo "PASS: $name"
  PASSED=$((PASSED + 1))
}

# ---------------------------------------------------------------------------
# Test 2: SKIP_PREFLIGHT=1 + --dry-run → happy path, no error
# ---------------------------------------------------------------------------
test_preflight_succeeds_with_dry_run() {
  local name="test_preflight_succeeds_with_dry_run"
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN

  # Mock `gh` to return a minimal valid items page (empty nodes) so the main
  # GraphQL fetch in the script succeeds; the script should print
  # "No items to archive" and exit 0.
  cat >"$tmpdir/gh" <<'EOF'
#!/usr/bin/env bash
# Mock gh: return an empty items page for the main fetch.
if [[ "$1" == "api" && "$2" == "graphql" ]]; then
  cat <<'JSON'
{"data":{"organization":{"projectV2":{"items":{"pageInfo":{"endCursor":null,"hasNextPage":false},"nodes":[]}}}}}
JSON
  exit 0
fi
exit 0
EOF
  chmod +x "$tmpdir/gh"

  local output
  local exit_code
  output=$(PATH="$tmpdir:$PATH" GH_TOKEN="dummy" SKIP_PREFLIGHT=1 \
           bash "$TARGET_SCRIPT" --dry-run 2>&1)
  exit_code=$?

  if [ "$exit_code" -ne 0 ]; then
    echo "FAIL: $name — expected exit 0, got $exit_code"
    echo "  output: $output"
    FAILED=$((FAILED + 1))
    return
  fi

  if grep -q "^ERROR:" <<<"$output"; then
    echo "FAIL: $name — unexpected ERROR: line in output"
    echo "  output: $output"
    FAILED=$((FAILED + 1))
    return
  fi

  echo "PASS: $name"
  PASSED=$((PASSED + 1))
}

# ---------------------------------------------------------------------------
# Run all tests.
# ---------------------------------------------------------------------------
test_preflight_fails_with_bad_token
test_preflight_succeeds_with_dry_run

echo
echo "Results: ${PASSED} passed, ${FAILED} failed"
if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
exit 0
