---
name: project-tick
description: |
  Dispatcher for the henyey project pipeline. One tick = pick one unassigned issue
  from the project board, assign yourself, and invoke the right specialist skill
  for its current state. Safe to run in parallel — concurrency via GitHub assignee
  race. Use proactively when the user asks to "run a tick", "pick up an issue",
  "process the board", or via the loop driver at scripts/project-tick-loop.sh.
---

# /project-tick — pipeline dispatcher

You are the dispatcher for the henyey project management pipeline. Your job is **not** to plan, implement, or review anything — that is what the specialist skills do. Your job is to:

1. Read the project board.
2. Pick exactly one issue that is ready for work.
3. Acquire it (assign yourself).
4. Dispatch the right specialist skill based on its current state.
5. Stop.

Multiple `/project-tick` invocations run in parallel safely. The GitHub assignee race ensures each tick grabs a distinct issue.

## Project board

- Repo: `stellar-experimental/henyey`
- Project: number `2`, ID `PVT_kwDOD-vqsM4BWQnL`
- Status field ID: `PVTSSF_lADOD-vqsM4BWQnLzhRmYgI`
- States (lowercase): `backlog`, `ready-for-planning`, `planning`, `ready-for-doing`, `doing`, `in-review`, `done`, `blocked`

## Dispatch table

| Status | Specialist | What it does |
|---|---|---|
| `backlog` | `/triage` | Validates the issue, labels it, advances to `ready-for-planning` (or `ready-for-doing` if trivial, or `blocked`) |
| `ready-for-planning` | `/plan` | Picks up the work; transitions to `planning` while drafting with parallel critics, then to `ready-for-doing` on convergence |
| `planning` | (no-op — actively assigned) | A `/plan` agent is currently drafting + running critics. Items in `planning` are always assigned; ticks filter them out automatically. |
| `ready-for-doing` | `/do` | Picks up the work; transitions to `doing` while implementing, then to `in-review` when PR is open |
| `doing` | (no-op — actively assigned) | A `/do` agent is currently implementing. Items in `doing` are always assigned; ticks filter them out automatically. |
| `in-review` | `/review-pr` | Two parallel reviewers + CI; auto-merges on triple-green; bounces back or blocks otherwise |
| `done`, `blocked` | (no-op) | Terminal / human-triaged |

## Algorithm

### Step 1 — Query the board

Single GraphQL call to fetch every open issue on the project with: assignees, status, labels, createdAt, linked PRs.

```bash
gh api graphql -f query='
  query {
    organization(login: "stellar-experimental") {
      projectV2(number: 2) {
        items(first: 100) {
          nodes {
            id
            content {
              ... on Issue {
                number
                title
                createdAt
                assignees(first: 5) { nodes { login } }
                labels(first: 20) { nodes { name } }
                closedByPullRequestsReferences(first: 5) { nodes { number state url } }
                state
              }
            }
            fieldValueByName(name: "Status") {
              ... on ProjectV2ItemFieldSingleSelectValue { name }
            }
          }
        }
      }
    }
  }
' --jq '.data.organization.projectV2.items.nodes'
```

If the query fails, retry once after 5 seconds. If still failing, exit non-zero — operator will see the failure in the loop log.

### Step 2 — Filter to actionable items

An item is **actionable** if all of:

- `content.state == "OPEN"` (don't act on closed issues)
- `fieldValueByName.name ∈ { backlog, ready-for-planning, ready-for-doing, in-review }`
- `assignees.nodes` is empty (nobody is working on it)

Skip items where any check fails. Skip items whose status is `planning` (always assigned), `doing` (always assigned), `done`, or `blocked`.

#### Step 2b — Skip in-review items whose CI is still pending

`/review-pr`'s only useful work when CI is pending is to post "Waiting on CI" and unassign. Picking such items burns 2 reviewer-agent spawns per tick (~2M tokens) just to find CI hasn't finished — wasteful and amplifies on multi-loop deployments. Filter them at the orchestrator:

For each in-review candidate after the actionability filter above, look up the linked PR's CI summary and skip the item if CI is still running:

```bash
for ISSUE in <in-review candidates>; do
  PR_NUM=$(gh issue view "$ISSUE" --repo stellar-experimental/henyey \
    --json closedByPullRequestsReferences \
    --jq '.closedByPullRequestsReferences | map(select(.state == "OPEN")) | .[0].number // empty')

  # No PR linked = broken state; let /review-pr handle the recovery.
  [ -z "$PR_NUM" ] && continue

  # Count CI checks not yet completed (status != "completed").
  CI_PENDING=$(gh pr view "$PR_NUM" --repo stellar-experimental/henyey \
    --json statusCheckRollup \
    --jq '[.statusCheckRollup[] | select(.status != "COMPLETED" and .status != "completed")] | length')

  # Also count failed; if any failed, CI is RED (not pending) — keep actionable so /review-pr can bounce.
  CI_FAILED=$(gh pr view "$PR_NUM" --repo stellar-experimental/henyey \
    --json statusCheckRollup \
    --jq '[.statusCheckRollup[] | select(.conclusion == "FAILURE" or .conclusion == "CANCELLED")] | length')

  if [ "$CI_PENDING" -gt 0 ] && [ "$CI_FAILED" -eq 0 ]; then
    # CI still running with no failures yet → skip this tick.
    SKIP_THIS_ISSUE=true
  fi
done
```

Rule summary:

- CI green → actionable (`/review-pr` will merge).
- CI red (any failure or cancellation) → actionable (`/review-pr` will bounce).
- CI still running with no failures yet → **NOT actionable this tick**. The next tick re-evaluates.
- No PR linked → actionable anyway (`/review-pr`'s no-PR recovery path runs).

This single change eliminates the wasted reviewer-spawn-during-CI-wait pattern. Wall-clock latency for the first review is unchanged in expectation because CI (10–30 min) dominates reviewer-agent time (2–3 min) — reviewers running in parallel with CI was an optimization the cost didn't justify.

### Step 3 — Pick one issue

Order actionable items by:

1. **Close-WIP-first state priority** — descending: `in-review` > `ready-for-doing` > `ready-for-planning` > `backlog`. Reason: prevents PRs from rotting in review while fresh backlog items pile up. (`planning` and `doing` items are never picked — they are always assigned and filtered out.)
2. **Label priority** within state — descending: `urgent` > `high` > `medium` > `low` > (no priority label).
3. **Age** within priority tier — oldest `createdAt` first.

Pick the head of the sorted list. If the list is empty, print `no actionable issues` and exit 0.

### Step 4 — Acquire the issue (sentinel-comment lock)

The assignee field alone is NOT enough to detect a race when multiple loops run as the same GitHub user — both can self-assign and both think they won (see #2739). The fix is a **sentinel-comment lock**: each tick posts a uniquely-tagged comment, then verifies via comment ordering that its comment was the earliest one posted within a short grace window.

```bash
# Generate a unique tick ID. Includes PID and nanosecond timestamp so two
# ticks in the same second still differ.
TICK_ID="tick-$(date +%s%N)-$$"

# Self-assign. This is necessary (so /project-tick filters us out of future
# picker runs) but no longer SUFFICIENT for race detection.
gh issue edit "$ISSUE" --repo stellar-experimental/henyey --add-assignee @me

# Post the sentinel comment. Capture the comment ID so we can clean it up.
SENTINEL_ID=$(gh api "repos/stellar-experimental/henyey/issues/$ISSUE/comments" \
  --method POST \
  -f body="## 🔒 acquired-by:$TICK_ID

posted=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ), host=$(hostname), pid=$$" \
  --jq '.id')

if [ -z "$SENTINEL_ID" ]; then
  echo "Sentinel post failed — backing off"
  gh issue edit "$ISSUE" --repo stellar-experimental/henyey --remove-assignee @me 2>/dev/null || true
  exit 0
fi

# Grace window — sleep long enough for any concurrent tick to also post
# its sentinel. 5 seconds is enough; the cost is bounded per tick.
sleep 5

# Fetch all recent sentinel comments and find the earliest one within the
# past 60 seconds. Tie-break by comment ID (which is monotonic at the API
# level). If our sentinel is the earliest, we won.
WINNER_TICK=$(gh api "repos/stellar-experimental/henyey/issues/$ISSUE/comments" \
  --paginate \
  --jq '[.[] | select(.body | startswith("## 🔒 acquired-by:")) |
    select(.created_at | fromdate > (now - 60)) |
    {id, created_at, tick: (.body | split("\n")[0] | sub("^## 🔒 acquired-by:"; ""))}] |
    sort_by(.created_at, .id) | .[0].tick // ""')

if [ "$WINNER_TICK" != "$TICK_ID" ]; then
  echo "race lost on #$ISSUE (winner: $WINNER_TICK, us: $TICK_ID) — exiting"
  # Clean up our sentinel and unassign.
  gh api "repos/stellar-experimental/henyey/issues/comments/$SENTINEL_ID" --method DELETE 2>/dev/null || true
  gh issue edit "$ISSUE" --repo stellar-experimental/henyey --remove-assignee @me 2>/dev/null || true
  exit 0
fi

echo "Won race on #$ISSUE (sentinel $TICK_ID is earliest). Proceeding."
```

If we lose the race, exit cleanly — the next `/project-tick` will pick a different issue.

**Sentinel cleanup** is important to avoid issues accumulating dozens of `## 🔒` comments over time. The losing tick deletes its sentinel immediately. The winning tick MUST delete its sentinel after the specialist returns (or on any exit path) — see Step 6.

### Step 5 — Dispatch

Based on the issue's status, invoke the specialist skill **as a foreground sub-agent** so its work stays in its own context window AND the parent waits for it. Use the `general-purpose` agent type with explicit instructions to run the slash command.

| Status | Sub-agent invocation |
|---|---|
| `backlog` | `Run /triage $ISSUE. Report the final state transition.` |
| `ready-for-planning` | `Run /plan $ISSUE. Report the final state transition.` |
| `ready-for-doing` | `Run /do $ISSUE. Report the final state transition.` |
| `in-review` | `Run /review-pr $ISSUE. Report the final state transition.` |

**Critical: the sub-agent MUST run in the foreground.** Do not set `run_in_background: true` on the Agent tool call. The dispatcher's job is to block until the specialist either completes the full state transition OR posts a failure marker (`## Blocked`, `## Plan: ...`, etc.) — anything less leaves work orphaned mid-flight (commit pushed but no PR open, etc.).

Wait for the sub-agent to complete. Do not try to summarize or second-guess its work — the specialist's commit history, issue comments, and PR reviews are the audit trail. After the sub-agent returns, report a one-line summary of the state transition it accomplished and exit.

### Step 6 — Cleanup

The specialist is responsible for:

- Moving the issue to its next state (via `move-issue-status.sh`).
- Unassigning itself on completion (`gh issue edit --remove-assignee @me`).
- Posting any required artifacts (triage report, converged plan, PR, review).

`/project-tick` IS responsible for one cleanup: **deleting its sentinel-lock comment** (from Step 4). Always run this, regardless of the specialist's exit status:

```bash
gh api "repos/stellar-experimental/henyey/issues/comments/$SENTINEL_ID" --method DELETE 2>/dev/null || true
```

If the sub-agent fails (non-zero exit), leave the issue's state and assignee as-is — the next tick will see we're still assigned and skip it. The operator will see the stuck assignment in the daily summary / loop log. The sentinel still gets deleted so it doesn't pollute future race detection.

## Flags

- `--dry-run` — Print the pick and dispatch decision, exit without acquiring. For sanity-checking the priority ordering.
- `--state=<state>` — Restrict pick to one state only (e.g. `--state=in-review` to drain reviews first). Useful for targeted catch-up.
- `--issue=<num>` — Skip the picker and dispatch directly to that issue's specialist. Useful for manual recovery.

## Examples

```bash
# Normal tick.
/project-tick

# Show what would happen, don't act.
/project-tick --dry-run

# Just drain in-review queue.
/project-tick --state=in-review

# Force a specific issue.
/project-tick --issue=2698
```

## Operational notes

- **Concurrency:** N parallel ticks are fine. Each grabs a distinct issue via the assignee race. The state-priority ordering means parallel ticks naturally distribute across states (one takes `in-review`, the next takes `ready-for-doing`, etc.).
- **Idempotency:** if a tick is interrupted between assignment and dispatch, the issue stays assigned to us. The next tick picks a different issue (we filter on `assignees empty`). The stuck issue surfaces in the daily summary as "assigned for >N hours" — operator unassigns it.
- **No retry on specialist failure:** if `/plan` exits with the issue still in `ready-for-planning` and assigned to us, that's a bug in `/plan`, not for `/project-tick` to paper over. The operator deals with it.
- **No archival:** `archive-stale-done.sh` runs as a separate scheduled GH workflow (`.github/workflows/archive-done.yml`), not inside this tick.

## When NOT to use

- **Do not** call `/project-tick` from inside `/plan`, `/do`, `/triage`, or `/review-pr` — it dispatches *to* them, not the other way around.
- **Do not** use this for one-off recovery — if you want to re-trigger a specific issue's specialist, use `--issue=<num>` directly, or invoke the specialist slash command yourself.
