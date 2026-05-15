#!/usr/bin/env bash
# Usage: move-issue-status.sh <issue_number> <status_name>
#
# Accepts both legacy and new state names:
#   Legacy: Backlog, "in plan", "In progress", "In review", Done, Blocked
#   New:    backlog, ready-for-planning, ready-for-doing, in-review, done, blocked
#
# Idempotent: adds the issue to the henyey project if missing, then sets its
# Status field. Exits 0 on success, non-zero on any failure.
set -euo pipefail

ISSUE="${1:?issue number required}"
STATUS_INPUT="${2:?status name required}"

OWNER="stellar-experimental"
REPO="henyey"
PROJECT_NUM=2
PROJECT_ID="PVT_kwDOD-vqsM4BWQnL"
STATUS_FIELD_ID="PVTSSF_lADOD-vqsM4BWQnLzhRmYgI"

# Normalize: lowercase, collapse runs of whitespace.
STATUS_NORM=$(echo "$STATUS_INPUT" | tr '[:upper:]' '[:lower:]' | tr -s ' ')

case "$STATUS_NORM" in
  backlog)                          OPTION_ID="f75ad846" ;;
  "in plan"|ready-for-planning)     OPTION_ID="61e4505c" ;;
  "in progress"|ready-for-doing)    OPTION_ID="47fc9ee4" ;;
  "in review"|in-review)            OPTION_ID="df73e18b" ;;
  done)                             OPTION_ID="98236657" ;;
  blocked)                          OPTION_ID="53ce269e" ;;
  *) echo "ERROR: unknown status: $STATUS_INPUT" >&2; exit 2 ;;
esac

ISSUE_URL="https://github.com/$OWNER/$REPO/issues/$ISSUE"

ITEM_ID=$(gh api graphql -f query='
  query($owner: String!, $repo: String!, $num: Int!) {
    repository(owner: $owner, name: $repo) {
      issue(number: $num) {
        projectItems(first: 20) {
          nodes { id project { id } }
        }
      }
    }
  }' -f owner="$OWNER" -f repo="$REPO" -F num="$ISSUE" \
  --jq ".data.repository.issue.projectItems.nodes[]
        | select(.project.id == \"$PROJECT_ID\") | .id" | head -n1)

if [ -z "$ITEM_ID" ]; then
  ITEM_ID=$(gh project item-add "$PROJECT_NUM" \
    --owner "$OWNER" --url "$ISSUE_URL" --format json --jq '.id')
fi

gh project item-edit \
  --project-id "$PROJECT_ID" \
  --id "$ITEM_ID" \
  --field-id "$STATUS_FIELD_ID" \
  --single-select-option-id "$OPTION_ID" >/dev/null

echo "Moved #$ISSUE → $STATUS_INPUT"
