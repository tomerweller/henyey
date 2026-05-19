#!/usr/bin/env bash
#
# Smoke-test harness for /review-pr skill shell snippets.
#
# Tests the shared verdict-validation library (scripts/lib/review-pr-verdicts.sh)
# using mock comment data. Verifies cutoff-aware filtering, shape validation,
# classification, and the expected audit artifacts for missing/malformed/stale
# verdict paths.
#
# Usage:
#   ./scripts/test-review-pr-skill-snippets.sh
#
# Output: TAP (Test Anything Protocol) on stdout, diagnostics on stderr.
# Exit: 0 = all pass, 1 = any fail.
#
# Portability: GNU/Linux only (Bash 4+, jq required).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_ROOT="$REPO_ROOT/data/test-review-pr-snippets"

# ── Source the library under test ─────────────────────────────────────────────
source "$SCRIPT_DIR/lib/review-pr-verdicts.sh"

# ── Cleanup ──────────────────────────────────────────────────────────────────
cleanup() {
  rm -rf "$TEST_ROOT" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
mkdir -p "$TEST_ROOT"

# ── TAP state ────────────────────────────────────────────────────────────────
TAP_PLAN=13
TAP_CURRENT=0
TAP_FAILURES=0

tap_plan() {
  echo "1..$TAP_PLAN"
}

tap_ok() {
  TAP_CURRENT=$((TAP_CURRENT + 1))
  echo "ok $TAP_CURRENT - $1"
}

tap_fail() {
  TAP_CURRENT=$((TAP_CURRENT + 1))
  TAP_FAILURES=$((TAP_FAILURES + 1))
  echo "not ok $TAP_CURRENT - $1"
  echo "# $2" >&2
}

assert_eq() {
  local expected="$1" actual="$2" desc="$3"
  if [[ "$expected" == "$actual" ]]; then
    tap_ok "$desc"
  else
    tap_fail "$desc" "expected='$expected' actual='$actual'"
  fi
}

# ── Helper: build a mock comment JSON ────────────────────────────────────────
# Usage: mock_comment ID CREATED_AT BODY
mock_comment() {
  local id="$1" created_at="$2" body="$3"
  jq -n --argjson id "$id" --arg created_at "$created_at" --arg body "$body" \
    '{id: $id, created_at: $created_at, body: $body}'
}

# Build a well-formed verdict body
verdict_body() {
  local reviewer="$1" verdict="$2" summary="${3:-Looks good.}"
  printf '## 🔍 Reviewer: %s\n\n**Verdict:** %s\n\n**Summary:** %s\n' "$reviewer" "$verdict" "$summary"
}

# ─────────────────────────────────────────────────────────────────────────────
tap_plan

# ══════════════════════════════════════════════════════════════════════════════
# TEST 1: stale reviewer verdict is ignored for the current baseline
# ══════════════════════════════════════════════════════════════════════════════
# Seed an older Correctness verdict (before baseline) and assert it's treated
# as "missing" when fetched with a cutoff after that comment's timestamp.

STALE_BODY=$(verdict_body "Correctness" "APPROVE" "All good.")
STALE_COMMENTS=$(jq -n --arg body "$STALE_BODY" '[
  { "id": 100, "created_at": "2026-05-18T01:00:00Z", "body": $body }
]')

echo "$STALE_COMMENTS" > "$TEST_ROOT/stale-comments.json"
export REVIEW_PR_COMMENTS_FILE="$TEST_ROOT/stale-comments.json"

# Fetch with cutoff AFTER the stale comment
VERDICTS=$(fetch_reviewer_verdict_comments 999 "2026-05-18T02:00:00Z")
STATE=$(latest_reviewer_verdict_state "Correctness" "$VERDICTS")
assert_eq "missing" "$STATE" "stale reviewer verdict is ignored for the current baseline"

# ══════════════════════════════════════════════════════════════════════════════
# TEST 2: missing reviewer verdict after one retry emits bounce artifact
# ══════════════════════════════════════════════════════════════════════════════
# When no fresh reviewer comment appears, classify_reviewer returns "missing".
# The /review-pr skill should then bounce. We verify the classification here.

EMPTY_COMMENTS='[]'
echo "$EMPTY_COMMENTS" > "$TEST_ROOT/empty-comments.json"
export REVIEW_PR_COMMENTS_FILE="$TEST_ROOT/empty-comments.json"

VERDICTS=$(fetch_reviewer_verdict_comments 999 "2026-05-18T02:00:00Z")
CLASS_A=$(classify_reviewer "Correctness" "$VERDICTS")
CLASS_B=$(classify_reviewer "Risk" "$VERDICTS")
assert_eq "missing" "$CLASS_A" "missing reviewer verdict classified as missing (Correctness)"
assert_eq "missing" "$CLASS_B" "missing reviewer verdict classified as missing (Risk)"

# ══════════════════════════════════════════════════════════════════════════════
# TEST 3: malformed reviewer verdict emits malformed-verdict artifact
# ══════════════════════════════════════════════════════════════════════════════
# Seed a fresh comment with the right header but no parseable **Verdict:** line.

MALFORMED_BODY=$(printf '## 🔍 Reviewer: Correctness\n\n**Summary:** Something but no verdict line.\n')
MALFORMED_COMMENTS=$(jq -n --arg body "$MALFORMED_BODY" '[
  { "id": 200, "created_at": "2026-05-19T03:00:00Z", "body": $body }
]')

echo "$MALFORMED_COMMENTS" > "$TEST_ROOT/malformed-comments.json"
export REVIEW_PR_COMMENTS_FILE="$TEST_ROOT/malformed-comments.json"

VERDICTS=$(fetch_reviewer_verdict_comments 999 "2026-05-19T01:00:00Z")
CLASS=$(classify_reviewer "Correctness" "$VERDICTS")
assert_eq "malformed:no **Verdict:** line" "$CLASS" "malformed reviewer verdict (no verdict line) classified correctly"

# Test malformed with invalid verdict value
MALFORMED_BODY2=$(printf '## 🔍 Reviewer: Correctness\n\n**Verdict:** MAYBE\n\n**Summary:** Unsure.\n')
MALFORMED_COMMENTS2=$(jq -n --arg body "$MALFORMED_BODY2" '[
  { "id": 201, "created_at": "2026-05-19T03:00:00Z", "body": $body }
]')

echo "$MALFORMED_COMMENTS2" > "$TEST_ROOT/malformed-comments2.json"
export REVIEW_PR_COMMENTS_FILE="$TEST_ROOT/malformed-comments2.json"

VERDICTS=$(fetch_reviewer_verdict_comments 999 "2026-05-19T01:00:00Z")
CLASS=$(classify_reviewer "Correctness" "$VERDICTS")
assert_eq "malformed:verdict line does not contain APPROVE or CHANGES_REQUESTED" "$CLASS" \
  "malformed reviewer verdict (invalid value) classified correctly"

# ══════════════════════════════════════════════════════════════════════════════
# TEST 4: fresh correctness and risk verdicts pass verification
# ══════════════════════════════════════════════════════════════════════════════

CORR_BODY=$(verdict_body "Correctness" "APPROVE" "Code is correct.")
RISK_BODY=$(verdict_body "Risk" "APPROVE" "No risk concerns.")
GOOD_COMMENTS=$(jq -n --arg corr "$CORR_BODY" --arg risk "$RISK_BODY" '[
  { "id": 300, "created_at": "2026-05-19T04:00:00Z", "body": $corr },
  { "id": 301, "created_at": "2026-05-19T04:01:00Z", "body": $risk }
]')

echo "$GOOD_COMMENTS" > "$TEST_ROOT/good-comments.json"
export REVIEW_PR_COMMENTS_FILE="$TEST_ROOT/good-comments.json"

VERDICTS=$(fetch_reviewer_verdict_comments 999 "2026-05-19T03:00:00Z")
CLASS_A=$(classify_reviewer "Correctness" "$VERDICTS")
CLASS_B=$(classify_reviewer "Risk" "$VERDICTS")
assert_eq "ok:APPROVE" "$CLASS_A" "fresh correctness verdict passes verification"
assert_eq "ok:APPROVE" "$CLASS_B" "fresh risk verdict passes verification"

# ══════════════════════════════════════════════════════════════════════════════
# TEST 5: fresh correctness and parity verdicts pass verification
# ══════════════════════════════════════════════════════════════════════════════

PARITY_BODY=$(verdict_body "Parity" "APPROVE" "Matches stellar-core behavior.")
PARITY_COMMENTS=$(jq -n --arg corr "$CORR_BODY" --arg par "$PARITY_BODY" '[
  { "id": 400, "created_at": "2026-05-19T04:00:00Z", "body": $corr },
  { "id": 401, "created_at": "2026-05-19T04:01:00Z", "body": $par }
]')

echo "$PARITY_COMMENTS" > "$TEST_ROOT/parity-comments.json"
export REVIEW_PR_COMMENTS_FILE="$TEST_ROOT/parity-comments.json"

VERDICTS=$(fetch_reviewer_verdict_comments 999 "2026-05-19T03:00:00Z")
CLASS_A=$(classify_reviewer "Correctness" "$VERDICTS")
CLASS_B=$(classify_reviewer "Parity" "$VERDICTS")
assert_eq "ok:APPROVE" "$CLASS_A" "fresh correctness verdict (parity PR) passes verification"
assert_eq "ok:APPROVE" "$CLASS_B" "fresh parity verdict passes verification"

# ══════════════════════════════════════════════════════════════════════════════
# TEST 6: CHANGES_REQUESTED verdict is correctly classified
# ══════════════════════════════════════════════════════════════════════════════

CR_BODY=$(verdict_body "Correctness" "CHANGES_REQUESTED" "Found issues with error handling.")
CR_COMMENTS=$(jq -n --arg cr "$CR_BODY" --arg risk "$RISK_BODY" '[
  { "id": 500, "created_at": "2026-05-19T04:00:00Z", "body": $cr },
  { "id": 501, "created_at": "2026-05-19T04:01:00Z", "body": $risk }
]')

echo "$CR_COMMENTS" > "$TEST_ROOT/cr-comments.json"
export REVIEW_PR_COMMENTS_FILE="$TEST_ROOT/cr-comments.json"

VERDICTS=$(fetch_reviewer_verdict_comments 999 "2026-05-19T03:00:00Z")
CLASS_A=$(classify_reviewer "Correctness" "$VERDICTS")
CLASS_B=$(classify_reviewer "Risk" "$VERDICTS")
assert_eq "ok:CHANGES_REQUESTED" "$CLASS_A" "CHANGES_REQUESTED verdict classified correctly"
assert_eq "ok:APPROVE" "$CLASS_B" "accompanying APPROVE verdict classified correctly"

# ══════════════════════════════════════════════════════════════════════════════
# TEST 7: validate_reviewer_verdict_shape rejects bad header
# ══════════════════════════════════════════════════════════════════════════════

BAD_HEADER=$(printf '## Review: Correctness\n\n**Verdict:** APPROVE\n\n**Summary:** Ok.\n')
SHAPE=$(validate_reviewer_verdict_shape "$BAD_HEADER")
assert_eq "malformed:missing or invalid header" "$SHAPE" "validate_reviewer_verdict_shape rejects bad header"

# ══════════════════════════════════════════════════════════════════════════════
# TEST 8: latest comment wins when multiple verdicts exist
# ══════════════════════════════════════════════════════════════════════════════

EARLY_CR=$(verdict_body "Correctness" "CHANGES_REQUESTED" "Issues found.")
LATE_APPROVE=$(verdict_body "Correctness" "APPROVE" "Issues resolved.")
MULTI_COMMENTS=$(jq -n --arg early "$EARLY_CR" --arg late "$LATE_APPROVE" '[
  { "id": 600, "created_at": "2026-05-19T04:00:00Z", "body": $early },
  { "id": 601, "created_at": "2026-05-19T05:00:00Z", "body": $late }
]')

echo "$MULTI_COMMENTS" > "$TEST_ROOT/multi-comments.json"
export REVIEW_PR_COMMENTS_FILE="$TEST_ROOT/multi-comments.json"

VERDICTS=$(fetch_reviewer_verdict_comments 999 "2026-05-19T03:00:00Z")
STATE=$(latest_reviewer_verdict_state "Correctness" "$VERDICTS")
assert_eq "APPROVE" "$STATE" "latest comment wins when multiple verdicts exist"

# ── Summary ──────────────────────────────────────────────────────────────────
unset REVIEW_PR_COMMENTS_FILE

echo ""
if [[ $TAP_FAILURES -gt 0 ]]; then
  echo "# FAILED: $TAP_FAILURES of $TAP_CURRENT tests failed" >&2
  exit 1
else
  echo "# All $TAP_CURRENT tests passed"
  exit 0
fi
