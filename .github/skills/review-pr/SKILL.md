---
name: review-pr
description: |
  Run two parallel adversarial PR reviewers and combine their verdicts with CI
  state into a merge decision. Reviewers post structured comment verdicts (since
  the agent is the PR author and cannot self-approve via GH native review).
  Operates on issues in `in-review`. Auto-merges with --admin on triple-green
  (after filing follow-up issues for any unaddressed inline review comments,
  so non-critical feedback is preserved as backlog instead of dropped); bounces
  to `ready-for-doing` on any request-changes or CI red; blocks after 3
  bounce-back cycles. Use when invoked by /project-tick with an issue in
  in-review, or manually as /review-pr <issue>.
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

Launch both as `general-purpose` foreground sub-agents. Do not wait between them.

**Why structured comments, not `gh pr review --approve`:** the authenticated GH user is the PR author (the same user opened the PR via `/do` and now reviews it). GitHub disallows author self-approval, so `gh pr review --approve` is silently downgraded to a comment by `gh`. Instead, each reviewer posts a structured comment with a verdict marker that `/review-pr` parses in Step 6.

**Verdict comment format** — each reviewer MUST post exactly one comment with this exact shape:

```markdown
## 🔍 Reviewer: <Correctness|Parity|Risk>

**Verdict:** APPROVE | CHANGES_REQUESTED

**Summary:** <one or two lines>

<details>
<summary>Full review</summary>

<bulleted list of concerns, inline references, alternate approaches.
For CHANGES_REQUESTED, list every specific change `/do` Mode B should make.
Keep under 400 lines.>
</details>
```

Post via `gh pr comment $PR_NUM --repo stellar-experimental/henyey --body-file <tmpfile>` so multi-line bodies survive intact. Reviewers MAY also post inline line comments via `gh api repos/.../pulls/$PR_NUM/comments` for specific concerns — those don't count toward the verdict; only the top-level structured comment does.

**Inline-comment convention:** if a reviewer's concern is non-blocking (would be a `MINOR` note), they should APPROVE at the top level AND leave the concern as an inline comment. `/review-pr` will auto-file a follow-up issue for every unaddressed inline comment at merge time (see Step 7.2), so non-critical feedback is preserved as actionable backlog without blocking the merge. If a concern is blocking, use `**Verdict:** CHANGES_REQUESTED` at the top level; `/do` Mode B will address every inline in that case.

### Reviewer A — Correctness (always)

> Invoke /review on PR #$PR_NUM in stellar-experimental/henyey. Focus on:
> correctness of the diff, test coverage, readability, error handling. Post
> your verdict as a single PR-level comment using `gh pr comment`, headed
> `## 🔍 Reviewer: Correctness`, with `**Verdict:** APPROVE` or
> `**Verdict:** CHANGES_REQUESTED` on its own line. Inline line comments
> via `gh api` are welcome for specific concerns.

### Reviewer B — Parity OR Risk (auto-detected)

**If parity-critical:**

> Invoke /spec-adhere style audit on PR #$PR_NUM in stellar-experimental/henyey.
> Focus on: does the change match stellar-core's behavior on this path?
> Consult the `stellar-core/` submodule for the matching C++ implementation.
> Identify any divergence in semantics, edge cases, or sequencing. Post your
> verdict as a single PR-level comment via `gh pr comment`, headed
> `## 🔍 Reviewer: Parity`, with `**Verdict:**` on its own line. Reviewer A
> is doing correctness; you focus only on parity.

**If non-parity (risk lens):**

> Review PR #$PR_NUM in stellar-experimental/henyey for risk: regressions in
> existing behavior, performance impact, breaking changes to APIs or data
> formats, security implications, operational concerns (config, migrations).
> Reviewer A is doing correctness; you focus only on risk. Post your verdict
> as a single PR-level comment via `gh pr comment`, headed
> `## 🔍 Reviewer: Risk`, with `**Verdict:**` on its own line.

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

### 6.1 Parse the reviewer verdicts from PR comments

Fetch all PR-level comments and find the latest one matching each reviewer header. Use the most recent comment per reviewer (in case a reviewer posted, then re-posted):

```bash
gh api repos/stellar-experimental/henyey/issues/$PR_NUM/comments \
  --paginate --jq '.[] | select(.body | startswith("## 🔍 Reviewer:")) |
                   {created_at, body}' | jq -s 'sort_by(.created_at)'
```

For each comment, extract the reviewer name from the first line (`## 🔍 Reviewer: Correctness` etc.) and the verdict from the `**Verdict:**` line. Keep only the LATEST comment per reviewer name. The two reviewers we expect:

- `Correctness` (always)
- `Parity` or `Risk` (depending on parity-critical detection from Step 3)

If only one verdict is found, treat the missing one as **pending** (Wait). If both are present, use them. If a reviewer posted twice (e.g. revised verdict), the latest comment wins.

### 6.2 Combine with CI

Three signals — Reviewer A verdict, Reviewer B verdict, CI state.

- **Reviewer A verdict:** APPROVE / CHANGES_REQUESTED / pending.
- **Reviewer B verdict:** APPROVE / CHANGES_REQUESTED / pending.
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

### Block (cycle cap or CI genuinely stuck)

| A | B | CI | Action |
|---|---|---|---|
| APPROVE | APPROVE | running > **CI_STUCK_AFTER_MINUTES** (default 60) wall-clock since the oldest in-progress check started | `blocked` — CI is genuinely stuck (see Step 6.0 for the wall-clock check). |
| (any) | (any) | (any) | If this would be the 4th bounce → `blocked` (handled at Step 2). |

**Why wall-clock, not tick count:** henyey integration tests routinely take 25+ minutes. A tick-count threshold (e.g. "3 ticks") is too aggressive when the tick rate is faster than CI completion — it produces false-positive blocks on perfectly healthy slow CI. Use the actual start time of the oldest still-in-progress CI check; only block if the run has exceeded a generous wall-clock budget.

#### Step 6.0 — Compute CI age before applying the matrix

If CI is in the **running** bucket (Step 5), determine its wall-clock age via the oldest in-progress check's `startedAt`:

```bash
HEAD_REF=$(gh pr view $PR_NUM --repo stellar-experimental/henyey --json headRefName --jq '.headRefName')

CI_OLDEST_START=$(gh run list --repo stellar-experimental/henyey \
  --branch "$HEAD_REF" --limit 20 \
  --json startedAt,conclusion,status \
  --jq '[.[] | select(.status != "completed")] | min_by(.startedAt) | .startedAt // ""')

CI_AGE_MIN=0
if [ -n "$CI_OLDEST_START" ]; then
  NOW_EPOCH=$(date -u +%s)
  CI_START_EPOCH=$(date -u -d "$CI_OLDEST_START" +%s)
  CI_AGE_MIN=$(( (NOW_EPOCH - CI_START_EPOCH) / 60 ))
fi

# Default budget. Override with CI_STUCK_AFTER_MINUTES env var if running ops
# tests for short-budget environments. Production budget is 60 min.
CI_STUCK_AFTER_MINUTES="${CI_STUCK_AFTER_MINUTES:-60}"
```

Apply to the matrix: if `CI_AGE_MIN > CI_STUCK_AFTER_MINUTES` AND both reviewers APPROVE AND CI is still running → block. Otherwise → wait (re-pick next tick).

## Step 7 — Execute the decision

### Auto-merge path

The pipeline gates merges on its OWN signals (parsed verdicts + CI state), not GitHub's review-approval count. The reviewer comments are advisory metadata only — GitHub does not "know" they're approvals, because GitHub disallows author self-approval. So we merge with `--admin` to bypass GitHub's review-required gate (CI gates still apply via branch protection if configured).

**Before merging**, file follow-up issues for any UNADDRESSED inline (line-level) review comments. Reviewers can flag non-critical concerns inline without blocking the merge with `CHANGES_REQUESTED` — those concerns must be preserved as actionable backlog, not lost.

#### 7.1 Identify unaddressed inline comments

Fetch all inline-review threads via GraphQL (REST doesn't expose `isResolved`):

```bash
gh api graphql -f query='
query($owner: String!, $repo: String!, $pr: Int!) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $pr) {
      reviewThreads(first: 100) {
        nodes {
          isResolved
          comments(first: 50) {
            nodes {
              databaseId
              author { login }
              body
              path
              line
              url
            }
          }
        }
      }
    }
  }
}' -f owner=stellar-experimental -f repo=henyey -F pr=$PR_NUM \
  --jq '.data.repository.pullRequest.reviewThreads.nodes'
```

For each thread, classify it as **addressed** if any of:

- `isResolved == true` (GitHub-side thread resolution).
- The thread has at least one reply after the original comment AND the reply body contains any of: `Addressed in `, `Fixed in `, `Done in `, or a `<commit-sha>` reference.

Otherwise, classify as **unaddressed**.

#### 7.2 File one follow-up issue per unaddressed thread

For each unaddressed thread, create an issue:

```bash
gh issue create --repo stellar-experimental/henyey \
  --title "<short summary derived from first line of comment body, ≤80 chars>" \
  --body "$(cat <<EOF
Follow-up from PR #$PR_NUM (issue #$ISSUE). Non-critical inline review comment that was not addressed before merge.

## Concern

\`<path>:<line>\` — <full original comment body, indented or as-is>

## Source

[Original review comment](<thread.comments.nodes[0].url>) on PR #$PR_NUM.

## Severity

Low / non-blocking — reviewer chose to APPROVE rather than request changes. Filing as backlog so the concern isn't lost.
EOF
)" \
  --label "enhancement,low,follow-up"
```

If the comment's `path` matches a known crate prefix (`crates/<name>/...`), also add the `crate:<name>` label.

Collect the list of newly-filed issue numbers — they'll be referenced in the merge comment.

#### 7.3 Merge

```bash
gh pr merge $PR_NUM --repo stellar-experimental/henyey --squash --admin
```

The `--admin` flag means the agent must be authenticated as a repo admin. If your token doesn't have admin, the merge will fail — at which point operator intervention is needed (file a follow-up issue documenting the merge-permission gap; do NOT downgrade to non-admin merge that might silently bypass CI).

#### 7.4 Clean up

```bash
bash .github/skills/shared/scripts/move-issue-status.sh $ISSUE done
gh issue edit $ISSUE --repo stellar-experimental/henyey --remove-assignee @me

# Worktree + build cache cleanup
REPO_ROOT="$(git rev-parse --show-toplevel)"
rm -rf "$REPO_ROOT/data/do-$ISSUE"
git worktree prune
# If session id is recoverable from a sidecar file, also rm -rf ~/data/<sid>/do-$ISSUE
```

Post a `## ✅ Merged` comment with the merge commit SHA AND the list of follow-up issues filed:

```markdown
## ✅ Merged

**Commit:** <merge-commit-sha>

**Follow-up issues filed for unaddressed inline review comments:** #N1, #N2

(none if all inline comments were addressed)
```

Exit.

### Wait path

Post:

```markdown
## Review: Waiting on CI

CI is still running (checks: <names>). Re-picking this PR on the next tick.
CI age: <CI_AGE_MIN> min / budget <CI_STUCK_AFTER_MINUTES> min.
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

- **Do not** post a review yourself. Spawn sub-agents that post their own structured comments — you only orchestrate and combine.
- **Do not** override or summarize the reviewers' verdicts. Their `**Verdict:**` line is the verdict. You read it; you don't rewrite it.
- **Do not** merge if any of the three signals is not green. The matrix is the rule.
- **Do not** wait synchronously on long-running CI. If CI is `running`, unassign and exit — the next tick re-picks the issue.
- **Do not** use `gh pr review --approve` — GH silently downgrades it to a comment because the agent is the PR author. Use structured PR comments via `gh pr comment` instead.

## Failure handling

| Failure | Action |
|---|---|
| Reviewer sub-agent fails to post | Retry once. If still failing, treat as `CHANGES_REQUESTED` and bounce. |
| Reviewer's comment doesn't match the expected header/verdict shape | Treat as `pending`; if it stays malformed after Step 4 completes, bounce with a `## Review: Malformed Verdict` note. |
| No PR linked | Bounce to `ready-for-doing` with `## Review: No PR Linked`. |
| `gh pr merge --admin` fails (token lacks admin) | Leave the issue in `in-review`; file a follow-up issue documenting the gap; do NOT degrade to a non-admin merge that might bypass CI gates. |
| GH API failure | Retry once after 5s; if still failing, leave assigned and exit non-zero. |

## Branch protection

Because the pipeline gates merges on its own parsed verdicts (not GH-recognized approvals), `main` branch protection should NOT require pull-request approvals — that gate is impossible to satisfy when the agent is the PR author. Recommended branch protection:

- **Required:** all CI checks green (the names of every check in `.github/workflows/ci.yml`).
- **Required:** branch up-to-date with base.
- **Required approvals:** **0** — the pipeline's own reviewer verdicts gate merge.
- The agent's token must have `Pull requests: Read and write` and the user must be a repo admin for `--admin` merges to succeed.

The `pdr-managed` label on every pipeline-created PR distinguishes them from human PRs if you want to scope additional automation to managed ones only.
