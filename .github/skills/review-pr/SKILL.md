---
name: review-pr
description: |
  Run two parallel adversarial PR reviewers and combine their verdicts with CI
  state into a merge decision. Operates on issues in `in-review`. Auto-merges on
  triple-green; bounces to `ready-for-doing` on any request-changes or CI red;
  blocks after 3 bounce-back cycles. Use when invoked by /project-tick with an
  issue in in-review, or manually as /review-pr <issue>.
---

# /review-pr <issue> — adversarial PR review

You are the PR-level gate. Three independent signals decide the merge: **reviewer A**, **reviewer B**, and **CI**. All three must be green to auto-merge. Any red bounces.

You do **not** review the code yourself — you orchestrate two independent reviewer sub-agents that use the existing `/review` and `/spec-adhere` skills (or `/review-fix` in review mode for risk-focused review), then combine their PR reviews with CI state.

## Inputs

- `$ISSUE` — issue number.
- The linked open PR (fetched from the issue).
- The PR's diff, CI run state, and any prior reviews.

## Step 0 — Find the PR

```bash
PR_NUM=$(gh issue view $ISSUE --repo stellar-experimental/henyey \
  --json closedByPullRequestsReferences \
  --jq '.closedByPullRequestsReferences | map(select(.state == "OPEN")) | .[0].number // empty')
```

If `PR_NUM` is empty, the issue is in `in-review` but has no open PR — that's a bug in `/do`. Post `## Review: No PR Linked` and move the issue back to `ready-for-doing`. Unassign. Exit.

## Step 1 — Read the PR + CI state

```bash
# PR metadata, files changed, current reviews.
gh pr view $PR_NUM --repo stellar-experimental/henyey \
  --json title,body,baseRefName,headRefName,reviews,files,statusCheckRollup,mergeable

# CI runs.
gh run list --repo stellar-experimental/henyey --branch <head-ref> --limit 5 \
  --json conclusion,status,name,databaseId
```

Capture:

- **Files changed** — for parity-vs-risk reviewer auto-detection.
- **Current CI status:** `green` | `failing` | `running` | `not_started`.
- **Existing reviews:** for bounce-back counting.

## Step 2 — Count prior bounce-backs

Look for any issue comment matching `## Review: Bounce-Back Cycle ` in the issue's comment history. Count them. If the count is **≥ 3**, this is the 4th cycle — the PR has cycled too many times. Post `## Review: Cycle Cap Reached` summarizing the disagreement pattern, move the issue to `blocked`, unassign, and exit. Do not run another review.

## Step 3 — Auto-detect the second reviewer's lens

Inspect the PR's changed files:

```bash
gh pr diff $PR_NUM --repo stellar-experimental/henyey --name-only
```

If any path matches one of these prefixes, the PR is **parity-critical** — Reviewer B uses parity lens:

- `crates/scp/`
- `crates/herder/`
- `crates/ledger/`
- `crates/tx/`
- `crates/overlay/`

Otherwise, the PR is **non-parity** — Reviewer B uses risk lens.

## Step 4 — Spawn 2 reviewers in parallel

Launch both as `general-purpose` sub-agents. Do not wait between them.

### Reviewer A — Correctness (always)

> Invoke /review on PR #$PR_NUM in stellar-experimental/henyey. Focus on:
> correctness of the diff, test coverage, readability, error handling. Use
> `gh pr review` to post your verdict:
>
> - `gh pr review $PR_NUM --approve --body "..."` if you have no blocking concerns
> - `gh pr review $PR_NUM --request-changes --body "..."` if you do
>
> Include inline line comments via `gh api` for specific issues. Be specific —
> name files and lines. Keep the top-level review body to a short summary plus
> a bulleted list of concerns. Do NOT use --comment (we need an actual review
> verdict, not a comment).

### Reviewer B — Parity OR Risk (auto-detected)

**If parity-critical:**

> Invoke /spec-adhere style audit on PR #$PR_NUM in stellar-experimental/henyey.
> Focus on: does the change match stellar-core's behavior on this path?
> Consult the `stellar-core/` submodule for the matching C++ implementation.
> Identify any divergence in semantics, edge cases, or sequencing. Use
> `gh pr review` to post APPROVE or REQUEST_CHANGES. Reviewer A is doing
> correctness; you focus only on parity. Keep the body tight.

**If non-parity (risk lens):**

> Review PR #$PR_NUM in stellar-experimental/henyey for risk: regressions in
> existing behavior, performance impact, breaking changes to APIs or data
> formats, security implications, operational concerns (config, migrations).
> Reviewer A is doing correctness; you focus only on risk. Use `gh pr review`
> to post APPROVE or REQUEST_CHANGES.

Wait for both reviewers to post.

## Step 5 — Recheck CI

Reviewers run in parallel with CI. By the time both have posted their reviews, CI may have finished. Re-query:

```bash
gh pr view $PR_NUM --repo stellar-experimental/henyey \
  --json statusCheckRollup --jq '.statusCheckRollup | map(.conclusion) | unique'
```

CI state buckets:

- **Green** — all required checks have `conclusion: SUCCESS` (or `SKIPPED`/`NEUTRAL` for non-required).
- **Red** — at least one required check is `FAILURE` or `CANCELLED`.
- **Running** — at least one required check is still `IN_PROGRESS`/`QUEUED`/`PENDING`, no failures yet.

## Step 6 — Decide

Look up all three signals:

- **Reviewer A verdict:** APPROVE / CHANGES_REQUESTED.
- **Reviewer B verdict:** APPROVE / CHANGES_REQUESTED.
- **CI state:** green / red / running.

Apply the outcome matrix:

### Auto-merge (triple-green)

| A | B | CI | Action |
|---|---|---|---|
| APPROVE | APPROVE | green | Auto-merge (see Step 7) |

### Wait (re-pick next tick)

| A | B | CI | Action |
|---|---|---|---|
| APPROVE | APPROVE | running | Wait. Comment `## Review: Waiting on CI`. Unassign so next tick re-picks. |
| (other waiting cases below) | | | |

### Bounce (PR has issues to address)

| A | B | CI | Action |
|---|---|---|---|
| CHANGES_REQUESTED | (any) | (any) | Bounce — A has concerns. |
| (any) | CHANGES_REQUESTED | (any) | Bounce — B has concerns. |
| APPROVE | APPROVE | red (diff-attributable) | Bounce — CI is the third reviewer. |

For diff-attributable vs. unrelated CI red, inspect the failing check's logs:

```bash
gh run view <run-id> --log-failed
```

If failures reference code in the PR's diff → diff-attributable. If failures look upstream (e.g. a shared dependency, an unrelated test on `main`) → unrelated.

**Unrelated CI red:**

| A | B | CI | Action |
|---|---|---|---|
| APPROVE | APPROVE | red (unrelated) | Bounce with note. `/do` will rebase on `origin/main` and retry. If still red after rebase, the next `/review-pr` will mark `blocked`. |

### Block (cycle cap or CI stuck)

| A | B | CI | Action |
|---|---|---|---|
| APPROVE | APPROVE | running for >3 ticks | `blocked` — CI is stuck (see Step 2 for cycle counting; CI-stuck counts as a separate failure mode). |
| (any) | (any) | (any) | If this would be the 4th bounce → `blocked` (handled at Step 2). |

## Step 7 — Execute the decision

### Auto-merge path

Branch protection should require: 2 approving reviews + green CI + up-to-date. If those are in place, the merge will happen automatically once both reviewers approve. Force the merge to confirm:

```bash
gh pr merge $PR_NUM --repo stellar-experimental/henyey --squash --auto
```

If branch protection is not yet configured (operator hasn't done that step), `--auto` will still queue the merge but may not gate properly. The skill should still call it; the branch-protection setup is a separate operator task.

After merge, move state and clean up:

```bash
bash .github/skills/shared/scripts/move-issue-status.sh $ISSUE done
gh issue edit $ISSUE --repo stellar-experimental/henyey --remove-assignee @me

# Worktree + build cache cleanup
REPO_ROOT="$(git rev-parse --show-toplevel)"
rm -rf "$REPO_ROOT/data/do-$ISSUE"
git worktree prune
# If session id is recoverable from a sidecar file, also rm -rf ~/data/<sid>/do-$ISSUE
```

Post a `## ✅ Merged` comment with the merge commit SHA. Exit.

### Wait path

Post:

```markdown
## Review: Waiting on CI

CI is still running (checks: <names>). Re-picking this PR on the next tick.
Bounce-back count: <N>/3.
```

Unassign yourself so the next tick re-picks this issue. Exit.

### Bounce path

Post:

```markdown
## Review: Bounce-Back Cycle <N+1>

**Reason:** <"Reviewer A requested changes" | "Reviewer B requested changes" | "CI failed (diff-attributable)" | "CI failed (unrelated, will rebase)">

**Reviewer A:** APPROVE | CHANGES_REQUESTED — <one-line summary>
**Reviewer B:** APPROVE | CHANGES_REQUESTED — <one-line summary>
**CI:** green | red | running

<If CI red, paste the relevant failed-check excerpt via gh run view --log-failed>

Routing back to `ready-for-doing` for `/do` Mode B.
```

Move state and unassign:

```bash
bash .github/skills/shared/scripts/move-issue-status.sh $ISSUE ready-for-doing
gh issue edit $ISSUE --repo stellar-experimental/henyey --remove-assignee @me
```

Exit.

### Block path

Post:

```markdown
## Review: Cycle Cap Reached / CI Stuck

**Bounce count:** 3
**Status:** blocked

**Pattern:** <summary of the disagreement: which reviewer kept failing, what
they kept asking for, what /do kept doing. This is what humans need to break
the tie.>

This PR has cycled 3 times without converging. Human review required.
```

Move state:

```bash
bash .github/skills/shared/scripts/move-issue-status.sh $ISSUE blocked
gh issue edit $ISSUE --repo stellar-experimental/henyey --remove-assignee @me
```

Exit.

---

## What you do NOT do

- **Do not** post a review yourself. Spawn sub-agents that post reviews — you only orchestrate and combine.
- **Do not** override or summarize the reviewers' verdicts. Their `--approve` / `--request-changes` is the verdict. You read it; you don't rewrite it.
- **Do not** merge if any of the three signals is not green. The matrix is the rule.
- **Do not** wait synchronously on long-running CI. If CI is `running`, unassign and exit — the next tick re-picks the issue.
- **Do not** use `gh pr review --comment` instead of `--approve`/`--request-changes`. Comments don't count as review verdicts.

## Failure handling

| Failure | Action |
|---|---|
| Reviewer sub-agent fails to post | Retry once. If still failing, treat as `CHANGES_REQUESTED` and bounce. |
| No PR linked | Bounce to `ready-for-doing` with `## Review: No PR Linked`. |
| Branch protection not configured (auto-merge doesn't gate) | Skill still runs; operator's responsibility to set up branch protection. |
| GH API failure | Retry once after 5s; if still failing, leave assigned and exit non-zero. |

## Branch protection (operator setup, referenced here)

For auto-merge to work as designed, `main` must require:

- 2 approving reviews from required reviewers (or just 2 approvals if no required-reviewers config).
- All required status checks green.
- Branch up-to-date with base.
- `pdr-managed` label on the PR (optional — if you want to restrict auto-merge to managed PRs).

If branch protection is not configured, this skill's `gh pr merge --auto` call still runs but may merge prematurely. The skill is correct; the protection layer is the safety net.
