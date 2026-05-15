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
- States (lowercase): `backlog`, `ready-for-planning`, `ready-for-doing`, `doing`, `in-review`, `done`, `blocked`

## Dispatch table

| Status | Specialist | What it does |
|---|---|---|
| `backlog` | `/triage` | Validates the issue, labels it, advances to `ready-for-planning` (or `ready-for-doing` if trivial, or `blocked`) |
| `ready-for-planning` | `/plan` | Adversarial plan drafting with parallel critics; advances to `ready-for-doing` |
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

Skip items where any check fails. Skip items whose status is `doing` (always assigned), `done`, or `blocked`.

### Step 3 — Pick one issue

Order actionable items by:

1. **Close-WIP-first state priority** — descending: `in-review` > `ready-for-doing` > `ready-for-planning` > `backlog`. Reason: prevents PRs from rotting in review while fresh backlog items pile up. (`doing` items are never picked — they are always assigned and filtered out.)
2. **Label priority** within state — descending: `urgent` > `high` > `medium` > `low` > (no priority label).
3. **Age** within priority tier — oldest `createdAt` first.

Pick the head of the sorted list. If the list is empty, print `no actionable issues` and exit 0.

### Step 4 — Acquire the issue

Race-safe assignment:

```bash
# Attempt assignment.
gh issue edit "$ISSUE" --repo stellar-experimental/henyey --add-assignee @me

# Read back the assignee list.
ASSIGNEES=$(gh issue view "$ISSUE" --repo stellar-experimental/henyey \
  --json assignees --jq '.assignees | map(.login) | join(",")')

# We win only if we are the sole assignee.
ME=$(gh api user --jq .login)
if [ "$ASSIGNEES" != "$ME" ]; then
  echo "race lost on #$ISSUE (assignees: $ASSIGNEES) — exiting"
  # Remove ourselves to clean up (someone else may have raced first)
  gh issue edit "$ISSUE" --repo stellar-experimental/henyey --remove-assignee @me 2>/dev/null || true
  exit 0
fi
```

If we lose the race, exit cleanly — the next `/project-tick` will pick a different issue.

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

`/project-tick` itself does no cleanup — exit 0 after the sub-agent returns. If the sub-agent fails (non-zero exit), leave the issue as-is with us still assigned — the next tick will see we're still assigned and skip it. The operator will see the stuck assignment in the daily summary / loop log.

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
