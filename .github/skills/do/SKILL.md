---
name: do
description: |
  Implement a planned change in the henyey project. Two-mode skill — Mode A is
  fresh implementation from a converged plan; Mode B addresses PR review comments
  on an existing PR. Picks up issues in `ready-for-doing`, transitions them to
  `doing` while actively implementing, then to `in-review` on PR open (Mode A)
  or re-review request (Mode B). `blocked` on unrecoverable failure. Use when
  invoked by /project-tick with an issue in ready-for-doing, or manually as
  /do <issue>.
model: claude-opus-4.6
---

# /do <issue> — implementation

You execute one plan. The plan was already vetted in `/plan` — your job is to write the code, run the checks, and put it in front of reviewers. You do **not** re-evaluate the plan's design; if you discover the plan was wrong while implementing, post a comment and route back, don't silently improvise.

## Inputs

- `$ISSUE` — issue number.
- The `## ✅ Converged Plan` comment on the issue, OR the `## Implementation Notes` section of the `## Triage Report` (trivial short-circuit).
- The current state of `origin/main`.

## Step 0 — Mode detection

Check whether a PR is linked to the issue:

```bash
PR_NUM=$(gh issue view $ISSUE --repo stellar-experimental/henyey \
  --json closedByPullRequestsReferences \
  --jq '.closedByPullRequestsReferences | map(select(.state == "OPEN")) | .[0].number // empty')
```

- **Mode A (fresh implementation):** `PR_NUM` is empty.
- **Mode B (fix after review):** `PR_NUM` is set.

## Step 0.5 — Transition to `doing`

Immediately after acquiring the issue (assignee race already won by the orchestrator), move the issue from `ready-for-doing` to `doing`. This signals on the board that an implementation is actively running — important because `/do` is the slowest step in the pipeline.

```bash
bash .github/skills/shared/scripts/move-issue-status.sh $ISSUE doing
```

Skip this if the issue is already in `doing` (e.g. a previous `/do` attempt crashed and the operator manually unblocked it).

---

## Mode A — Fresh implementation

### A.1 Read the plan

Verify the source of truth exists, in this order:

1. `## ✅ Converged Plan` comment from `/plan`, OR
2. `## Implementation Notes` section of the `## Triage Report` (trivial short-circuit path).

If neither exists, post `## Do: Missing Plan` and route the issue back to `ready-for-planning` (or `backlog` if there's also no triage report). Unassign. Exit.

### A.2 Set up the worktree

```bash
REPO_ROOT="$(git rev-parse --show-toplevel)"
WORKTREE="$REPO_ROOT/data/do-$ISSUE/worktree"
BRANCH="do/issue-$ISSUE"
SESSION_ID="${CLAUDE_SESSION_ID:-$(date +%Y%m%d-%H%M%S)}"
export CARGO_TARGET_DIR="$HOME/data/$SESSION_ID/do-$ISSUE/cargo-target"

mkdir -p "$REPO_ROOT/data" "$HOME/data/$SESSION_ID/do-$ISSUE"

# Persist the session ID alongside the worktree so /review-pr can clean up
# the cargo target dir on merge (avoids accumulating multi-GB stale caches).
echo "$SESSION_ID" > "$REPO_ROOT/data/do-$ISSUE/.session-id"

# Fresh worktree off origin/main.
git fetch origin main
git -C "$REPO_ROOT" worktree add -B "$BRANCH" "$WORKTREE" origin/main
cd "$WORKTREE"
```

`/data/` is gitignored in the repo. `~/data/` is the shared volume per CLAUDE.md.

### A.2.5 Write the failing test FIRST (TDD)

**This step is mandatory for `kind: bug-fix` and required for `kind: feature`. Skip only for `docs`, `test-only`, or pure `refactor` where the plan explicitly says no new tests.**

For **bug-fix**:

1. From the converged plan's "Regression tests" list, write each named regression test in the named file path. Use the failing-mode seed from triage to guide the assertion.
2. Run the test against the unmodified code:
   ```bash
   cargo test -p henyey-<crate> <test_name> --no-fail-fast 2>&1 | tail -30
   ```
3. **Verify it FAILS with the expected error mode.** Capture the failure output (test name + assertion / panic / hang message). If it passes, the test doesn't capture the bug — go back and fix the test before writing the fix.
4. Commit JUST the failing test:
   ```bash
   git add <test files only>
   git commit -m "$(cat <<'EOF'
   Regression test for #$ISSUE — fails on current main

   <one-line description of what the test asserts and how it fails>

   Refs #$ISSUE

   Co-authored-by: Claude Code <claude-code@anthropic.com>
   EOF
   )"
   ```
   This is commit 1 of (at least) 2 — the failing test is its own committed artifact so reviewers can verify it captures the bug.

For **feature**:

1. From the plan's "New coverage" list, write each new test exercising the new public surface (the test will fail because the new public function doesn't exist yet — that's the point).
2. Run the tests, verify they fail with `unresolved function` / `cannot find` / similar (not yet implemented).
3. Commit just the failing tests as commit 1.

### A.3 Implement

Make the changes the plan describes. Stay inside the plan's stated scope — if you discover the plan is wrong or incomplete:

- **Minor:** note it in the PR body's `## Deviations from plan` section and proceed.
- **Major:** stop, post `## Do: Plan Wrong` on the issue with detail, move issue back to `ready-for-planning`, unassign, exit. Don't silently expand scope.

After implementing, **re-run the regression/new-coverage tests and verify they now PASS**. Capture the passing output. The transition from "fails on commit 1, passes on commit 2" is what makes the test a real regression test (not just any test you happen to add alongside).

### A.4 Local verification

```bash
cargo fmt --check
cargo clippy --all -- -D warnings
```

Then run tests with scope chosen from the plan:

- **Plan touches a single crate** → `cargo test -p henyey-<crate>` (faster).
- **Plan touches multiple crates or shared types** → `cargo test --all`.

If anything fails:

- Fix attempts: up to 3.
- After 3 failed fixes, post `## Do: Local Verification Failed` with the relevant error output, move to `blocked`, unassign, exit.

### A.5 Commit and push

```bash
git add -A
git commit -m "$(cat <<'EOF'
<one-line imperative summary>

<optional body explaining the why, not the what>

Refs #$ISSUE

Co-authored-by: Claude Code <claude-code@anthropic.com>
EOF
)"

git push -u origin "$BRANCH"
```

### A.6 Open the PR

```bash
gh pr create --repo stellar-experimental/henyey \
  --base main --head "$BRANCH" \
  --title "<imperative summary, sentence case>" \
  --body "$(cat <<EOF
Closes #$ISSUE

## Summary

<one paragraph: what changes and why>

## Plan reference

[Converged Plan comment](<link to the comment>)

## Test plan

- [x] cargo fmt --check
- [x] cargo clippy --all -- -D warnings
- [x] <test target run> passes

## Regression test (kind: bug-fix only)

- **Test:** \`<file>::\`<test_fn>\`
- **Pre-fix:** committed as \`<sha-of-test-commit>\` — verified FAILED with: \`<one-line failure mode>\`
- **Post-fix:** verified PASSES after \`<sha-of-fix-commit>\`

<omit this section for non-bug-fix PRs>

## Deviations from plan

<empty if none, or bullets>

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)" \
  --label "pdr-managed"
```

The `pdr-managed` label distinguishes this PR from human PRs so auto-merge policy can target only managed PRs.

### A.7 Advance state

```bash
bash .github/skills/shared/scripts/move-issue-status.sh $ISSUE in-review
gh issue edit $ISSUE --repo stellar-experimental/henyey --remove-assignee @me
```

Exit.

---

## Mode B — Fix after review

### B.1 Fetch review comments

Capture the head-commit timestamp first, so you only consider comments newer than your last push:

```bash
LAST_PUSH=$(gh pr view $PR_NUM --repo stellar-experimental/henyey \
  --json commits --jq '.commits | sort_by(.committedDate) | last | .committedDate')
```

Fetch inline review-comments WITH IDs (you'll need these to reply):

```bash
gh api "repos/stellar-experimental/henyey/pulls/$PR_NUM/comments" --paginate \
  --jq --arg cutoff "$LAST_PUSH" '
    [.[] | select(.created_at > $cutoff) |
     {id, path, line, body, in_reply_to: .in_reply_to_id, url: .html_url}]' \
  > /tmp/review-comments-$PR_NUM.json
```

Also fetch PR-level reviews (the structured `## 🔍 Reviewer:` comments from /review-pr are issue-level, NOT review-comments):

```bash
gh api "repos/stellar-experimental/henyey/issues/$PR_NUM/comments" --paginate \
  --jq --arg cutoff "$LAST_PUSH" '
    [.[] | select(.created_at > $cutoff) |
     {id, body, url: .html_url}]'
```

Items in `/tmp/review-comments-$PR_NUM.json` are the inline ones with `.id` you'll iterate over in B.6 to post replies. Items not in `in_reply_to` chains (i.e. `in_reply_to: null`) are top-level thread comments; replying to those creates a follow-up in the same thread.

### B.2 Group the feedback

For each comment, classify:

- **Actionable** — change requested with clear meaning. Address it.
- **Question** — reviewer asking why; reply inline with reasoning, no code change.
- **Disagree** — you have a reasoned case for the current code. Reply inline explaining; do not silently change. If the reviewer re-asserts after your reply, treat as actionable.

### B.3 Re-enter the worktree

```bash
WORKTREE="$REPO_ROOT/data/do-$ISSUE/worktree"
export CARGO_TARGET_DIR="$HOME/data/$SESSION_ID/do-$ISSUE/cargo-target"
BRANCH="do/issue-$ISSUE"

# Re-enter or re-create the worktree. The worktree may have been cleaned up
# by /review-pr after a previous merge attempt, or never existed if this is
# the first Mode B run on a re-bounced issue.
if [ ! -d "$WORKTREE/.git" ] && [ ! -f "$WORKTREE/.git" ]; then
  # No worktree — recreate from origin/$BRANCH (PR head).
  git -C "$REPO_ROOT" fetch origin "$BRANCH"
  mkdir -p "$(dirname "$WORKTREE")"
  git -C "$REPO_ROOT" worktree add -B "$BRANCH" "$WORKTREE" "origin/$BRANCH"
fi

cd "$WORKTREE"
git fetch origin
git rebase origin/main  # In case main moved during review.
```

If the rebase has conflicts you can't resolve straightforwardly, post `## Do: Rebase Conflict` with detail and route to `blocked`.

### B.4 Apply fixes

Make the changes. Stay focused — do not add unrelated improvements. The PR scope is now fixed; expanding it makes review harder.

### B.5 Local verification

Same as Mode A.5.

### B.6 Reply inline and push

Iterate over every inline comment in `/tmp/review-comments-$PR_NUM.json` and reply within the same thread. The endpoint `POST /repos/.../pulls/{pr}/comments/{comment_id}/replies` creates a reply IN the thread containing `{comment_id}`, which is what `/review-pr`'s "addressed" heuristic looks for (it scans `reviewThreads { comments }` for `Addressed in` / `Fixed in` / `Done in`).

```bash
FIX_SHA=$(git rev-parse HEAD)   # captured AFTER the fix commit in B.5/B.7

jq -r '.[] | .id' /tmp/review-comments-$PR_NUM.json | while read CID; do
  # classify: actionable / question / disagree (per B.2)
  # then reply with the appropriate template:
  gh api -X POST \
    "repos/stellar-experimental/henyey/pulls/$PR_NUM/comments/$CID/replies" \
    -f body="Addressed in $FIX_SHA: <one-line description>."
done
```

For disagreement comments, swap the body for:

```bash
gh api -X POST \
  "repos/stellar-experimental/henyey/pulls/$PR_NUM/comments/$CID/replies" \
  -f body="Disagree because <reason>. Current code is correct because <reason>."
```

Verify each reply landed in the correct thread by reading the response — if any reply 404s or 422s, log it; the merge-time auto-followup logic in `/review-pr` will catch unaddressed threads.

Commit:

```bash
git add -A
git commit -m "$(cat <<'EOF'
Address review feedback

<bullet list of what changed and why>

Refs #$ISSUE

Co-authored-by: Claude Code <claude-code@anthropic.com>
EOF
)"

# B.3 includes a `git rebase origin/main`, which rewrites the branch's commit
# history. After a rebase, a plain `git push` fails non-fast-forward; we have
# to force-push. Use --force-with-lease so we refuse to clobber if someone
# else pushed to the PR's branch in the meantime.
git push --force-with-lease
```

### B.7 Request re-review and advance

```bash
# Dismiss the pending request-changes reviews so the PR re-enters fresh review.
gh pr review $PR_NUM --repo stellar-experimental/henyey --comment \
  --body "Addressed feedback. Ready for re-review."

bash .github/skills/shared/scripts/move-issue-status.sh $ISSUE in-review
gh issue edit $ISSUE --repo stellar-experimental/henyey --remove-assignee @me
```

Exit.

---

## What you do NOT do

- **Do not** re-evaluate the plan's design. If wrong, bounce back.
- **Do not** add features, refactor, or clean up code beyond what the plan or review requested.
- **Do not** skip local verification. Pushing a PR with broken fmt/clippy is a waste of CI time and reviewer attention.
- **Do not** disable hooks (`--no-verify`). Fix the hook issue.
- **Do not** force-push (`git push -f`) on Mode B unless rebase is the explicit fix. Even then, prefer `git push --force-with-lease`.
- **Do not** invoke other specialist skills inline. If you need a different stage's work, the right move is to route the issue back and exit.

## Failure handling

| Failure | Action |
|---|---|
| Local fmt/clippy/test fails after 3 fix attempts (Mode A) | `blocked` with logs |
| Rebase conflict can't be resolved (Mode B) | `blocked` with rebase output |
| Plan turns out to be wrong (mid-implementation) | Bounce to `ready-for-planning` with `## Do: Plan Wrong` comment |
| Reviewer feedback contradicts itself / contradicts the plan | Reply inline asking for clarification; if no resolution, `blocked` with `## Do: Feedback Unclear` |
| GH push rejected (branch protection blocks direct push to main) | Expected — that's why we open a PR. Re-attempt the PR open. |
| GH API failure | Retry once after 5s; if still failing, leave assigned and exit non-zero. |

## Cleanup

- **Worktree at `$REPO_ROOT/data/do-$ISSUE/worktree`:** cleaned up by `/review-pr` after merge.
- **Build cache at `~/data/$SESSION_ID/do-$ISSUE/cargo-target`:** also cleaned up by `/review-pr` after merge.
- If you `blocked` mid-flow, leave both in place — the operator may want to inspect.
