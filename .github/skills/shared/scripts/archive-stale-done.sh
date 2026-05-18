#!/usr/bin/env bash
# archive-stale-done.sh — archive closed project items older than N days.
#
# Usage:
#   archive-stale-done.sh [--dry-run] [days]
#
# Default days = 2.
#
# Archives every project #2 item whose underlying Issue/PR is in state
# CLOSED and was closed at least N days ago, unless already archived.
# Idempotent and safe to run from cron / a scheduled GitHub Action /
# the plan-do-review-loop tick.
#
# Why not use the built-in "Auto-archive items" project workflow?
#   GitHub does not expose the workflow's filter/action via the public
#   GraphQL API — only its enabled flag. There is no
#   createProjectV2Workflow or updateProjectV2Workflow mutation. So a
#   from-scratch CLI implementation is the only "config-as-code" path.
set -euo pipefail

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
  shift
fi
DAYS="${1:-2}"

OWNER="stellar-experimental"
PROJECT_NUM=2
PROJECT_ID="PVT_kwDOD-vqsM4BWQnL"

# Pre-flight: probe whether GH_TOKEN has org-level project scope. The default
# GITHUB_TOKEN granted to GitHub Actions runs lacks the org-level read:project
# scope required for `organization(login:...).projectV2(...)` GraphQL queries —
# the `repository-projects: write` workflow permission only grants repo-level
# classic Projects access and does not help here. When the token is
# underprivileged, the GraphQL call below would fail with the opaque
# "Could not resolve to a ProjectV2 with the number 2." error, which doesn't
# tell the operator what to fix. This probe catches that case and emits a
# structured, actionable error message instead.
#
# SKIP_PREFLIGHT=1 is for test harnesses only; do not document or rely on it
# in production paths.
if [ "${SKIP_PREFLIGHT:-0}" != "1" ]; then
  probe_exit=0
  probe_output=$(gh api graphql -f query='
    query($org: String!, $proj: Int!) {
      organization(login: $org) { projectV2(number: $proj) { id } }
    }' -f org="$OWNER" -F proj="$PROJECT_NUM" 2>&1) || probe_exit=$?
  if [ "$probe_exit" -ne 0 ]; then
    if grep -q "Could not resolve to a ProjectV2" <<<"$probe_output"; then
      echo "ERROR: GH_TOKEN lacks org project scope — set PROJECT_BOARD_TOKEN secret with Projects:Read+Write on stellar-experimental" >&2
      exit 1
    fi
    # Different failure (network, 401, etc.) — surface it and exit so the
    # main fetch doesn't paper over a real error.
    echo "ERROR: pre-flight probe failed: $probe_output" >&2
    exit 1
  fi
fi

# Fetch all project items + their issue/PR state and closedAt.
# `--paginate` requires the cursor variable to be named $endCursor; jq -s
# is required because gh emits one JSON object per page.
items_json=$(gh api graphql --paginate -f query='
  query($org: String!, $proj: Int!, $endCursor: String) {
    organization(login: $org) {
      projectV2(number: $proj) {
        items(first: 100, after: $endCursor) {
          pageInfo { endCursor hasNextPage }
          nodes {
            id
            isArchived
            content {
              ... on Issue       { number state closedAt }
              ... on PullRequest { number state closedAt }
            }
          }
        }
      }
    }
  }' -f org="$OWNER" -F proj="$PROJECT_NUM")

# Eligible: not yet archived, has issue/PR content (skip drafts), state CLOSED,
# closedAt older than the cutoff.
to_archive=$(jq -rs --argjson days "$DAYS" '
  .[].data.organization.projectV2.items.nodes[]
  | select(.isArchived == false)
  | select(.content != null)
  | select(.content.state == "CLOSED")
  | select(.content.closedAt != null)
  | select((.content.closedAt | fromdateiso8601) < (now - ($days * 86400)))
  | "\(.id) \(.content.number) \(.content.closedAt)"
' <<<"$items_json")

if [ -z "$to_archive" ]; then
  echo "No items to archive (closed > ${DAYS} day(s) ago)."
  exit 0
fi

count=0
while IFS=' ' read -r item_id issue_num closed_at; do
  [ -z "$item_id" ] && continue
  if $DRY_RUN; then
    echo "[dry-run] would archive #${issue_num} (closed ${closed_at})"
  else
    gh api graphql -f query='
      mutation($projectId: ID!, $itemId: ID!) {
        archiveProjectV2Item(input: { projectId: $projectId, itemId: $itemId }) {
          item { id }
        }
      }' -f projectId="$PROJECT_ID" -f itemId="$item_id" >/dev/null
    echo "Archived #${issue_num} (closed ${closed_at})"
  fi
  count=$((count + 1))
done <<<"$to_archive"

if $DRY_RUN; then
  echo "Dry-run complete: ${count} item(s) would be archived."
else
  echo "Archived ${count} item(s)."
fi
