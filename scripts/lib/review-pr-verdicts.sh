#!/usr/bin/env bash
#
# Shared verdict-validation helpers for the /review-pr skill.
#
# Provides cutoff-aware fetching and classification of reviewer verdict
# comments on a PR. Used in Step 4 (post-dispatch verification), Step 6
# (decision matrix), and Step 2b.1 (lifetime-cap path).
#
# Requires: Bash 4+, jq, gh CLI authenticated.
# Does NOT set shell options (set -e, -u, etc.) — callers control strictness.
# Idempotent: safe to source multiple times.
#

[[ -n "${_REVIEW_PR_VERDICTS_LOADED:-}" ]] && return 0
_REVIEW_PR_VERDICTS_LOADED=1

# ─────────────────────────────────────────────────────────────────────────────
# fetch_reviewer_verdict_comments PR_NUM [CUTOFF_ISO]
#
# Fetch all PR-level comments matching the reviewer verdict header pattern
# (## 🔍 Reviewer: <name>). Optionally filter to only those created after
# CUTOFF_ISO (ISO 8601 timestamp). Without a cutoff, returns all matching
# comments across the PR's lifetime.
#
# Output: JSON array on stdout, each element:
#   { "id": <number>, "created_at": "<iso>", "reviewer": "<name>", "body": "<full>" }
#
# Returns: 0 on success, 1 on API failure.
# ─────────────────────────────────────────────────────────────────────────────
fetch_reviewer_verdict_comments() {
  local pr_num="$1"
  local cutoff="${2:-}"
  local repo="${REVIEW_PR_REPO:-stellar-experimental/henyey}"

  local raw
  raw=$(_review_pr_fetch_comments "$pr_num" "$repo") || return 1

  local jq_filter
  if [[ -n "$cutoff" ]]; then
    jq_filter='
      [.[] | select(.body | startswith("## 🔍 Reviewer:")) |
       select(.created_at > $cutoff) |
       { id: .id,
         created_at: .created_at,
         reviewer: (.body | split("\n")[0] | ltrimstr("## 🔍 Reviewer: ") | rtrimstr("\r")),
         body: .body }]'
    echo "$raw" | jq --arg cutoff "$cutoff" "$jq_filter"
  else
    jq_filter='
      [.[] | select(.body | startswith("## 🔍 Reviewer:")) |
       { id: .id,
         created_at: .created_at,
         reviewer: (.body | split("\n")[0] | ltrimstr("## 🔍 Reviewer: ") | rtrimstr("\r")),
         body: .body }]'
    echo "$raw" | jq "$jq_filter"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# latest_reviewer_verdict_state REVIEWER_NAME VERDICTS_JSON
#
# Given a reviewer name ("Correctness", "Parity", "Risk") and the JSON array
# from fetch_reviewer_verdict_comments, extract the verdict state of the
# latest comment for that reviewer.
#
# Output: one of "APPROVE", "CHANGES_REQUESTED", "malformed", or "missing"
#   on stdout.
#
# Returns: 0 always.
# ─────────────────────────────────────────────────────────────────────────────
latest_reviewer_verdict_state() {
  local reviewer_name="$1"
  local verdicts_json="$2"

  local latest_body
  latest_body=$(echo "$verdicts_json" | jq -r --arg name "$reviewer_name" '
    [.[] | select(.reviewer == $name)] | sort_by(.created_at) | last | .body // ""')

  if [[ -z "$latest_body" || "$latest_body" == "null" ]]; then
    echo "missing"
    return 0
  fi

  _extract_verdict_from_body "$latest_body"
}

# ─────────────────────────────────────────────────────────────────────────────
# validate_reviewer_verdict_shape BODY
#
# Check whether a verdict comment body has the required structure:
#   - Starts with ## 🔍 Reviewer: <name>
#   - Contains a **Verdict:** line with APPROVE or CHANGES_REQUESTED
#   - Contains a **Summary:** line
#
# Output: "ok" | "malformed:<reason>" on stdout.
# Returns: 0 always.
# ─────────────────────────────────────────────────────────────────────────────
validate_reviewer_verdict_shape() {
  local body="$1"

  # Check header
  if ! echo "$body" | head -1 | grep -qE '^## 🔍 Reviewer: (Correctness|Parity|Risk)'; then
    echo "malformed:missing or invalid header"
    return 0
  fi

  # Check verdict line
  local verdict_line
  verdict_line=$(echo "$body" | grep -m1 '^\*\*Verdict:\*\*' || true)
  if [[ -z "$verdict_line" ]]; then
    echo "malformed:no **Verdict:** line"
    return 0
  fi

  # Check verdict value
  if ! echo "$verdict_line" | grep -qE '(APPROVE|CHANGES_REQUESTED)'; then
    echo "malformed:verdict line does not contain APPROVE or CHANGES_REQUESTED"
    return 0
  fi

  # Check summary line
  if ! echo "$body" | grep -q '^\*\*Summary:\*\*'; then
    echo "malformed:no **Summary:** line"
    return 0
  fi

  echo "ok"
}

# ─────────────────────────────────────────────────────────────────────────────
# classify_reviewer REVIEWER_NAME VERDICTS_JSON
#
# Combines latest_reviewer_verdict_state with shape validation.
#
# Output: "ok:APPROVE" | "ok:CHANGES_REQUESTED" | "missing" | "malformed:<reason>"
# Returns: 0 always.
# ─────────────────────────────────────────────────────────────────────────────
classify_reviewer() {
  local reviewer_name="$1"
  local verdicts_json="$2"

  local latest_body
  latest_body=$(echo "$verdicts_json" | jq -r --arg name "$reviewer_name" '
    [.[] | select(.reviewer == $name)] | sort_by(.created_at) | last | .body // ""')

  if [[ -z "$latest_body" || "$latest_body" == "null" ]]; then
    echo "missing"
    return 0
  fi

  local shape
  shape=$(validate_reviewer_verdict_shape "$latest_body")
  if [[ "$shape" != "ok" ]]; then
    echo "$shape"
    return 0
  fi

  local verdict
  verdict=$(_extract_verdict_from_body "$latest_body")
  echo "ok:$verdict"
}

# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

# _review_pr_fetch_comments PR_NUM REPO
# Fetches all issue comments for a PR. Mockable via REVIEW_PR_COMMENTS_FILE.
_review_pr_fetch_comments() {
  local pr_num="$1"
  local repo="$2"

  if [[ -n "${REVIEW_PR_COMMENTS_FILE:-}" ]]; then
    cat "$REVIEW_PR_COMMENTS_FILE"
  else
    gh api "repos/$repo/issues/$pr_num/comments" --paginate
  fi
}

# _extract_verdict_from_body BODY
# Extracts APPROVE or CHANGES_REQUESTED from a verdict body. Outputs
# "malformed" if neither found.
_extract_verdict_from_body() {
  local body="$1"
  local verdict_line
  verdict_line=$(echo "$body" | grep -m1 '^\*\*Verdict:\*\*' || true)

  if echo "$verdict_line" | grep -q 'CHANGES_REQUESTED'; then
    echo "CHANGES_REQUESTED"
  elif echo "$verdict_line" | grep -q 'APPROVE'; then
    echo "APPROVE"
  else
    echo "malformed"
  fi
}
