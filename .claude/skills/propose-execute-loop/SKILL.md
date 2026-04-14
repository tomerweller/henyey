---
name: propose-execute-loop
description: Iterate over all open GitHub issues, AI-triage each for readiness, and call /propose-execute on actionable ones
argument-hint: "[--label <label>] [--model <model>] [--max-proposal-rounds N] [--max-review-rounds N] [--dry-run]"
---

Parse `$ARGUMENTS`:
- `--label <label>`: Optional extra label to filter issues (e.g., `proposal`).
  If omitted, all open issues are considered.
- `--model <model>`: Model for triage, critic, and review agents
  (default: `"gpt-5.4"`). Passed through to `/propose-execute`.
- `--max-proposal-rounds N`: Passed through to `/propose-execute` (default: 5).
- `--max-review-rounds N`: Passed through to `/propose-execute` (default: 3).
- `--dry-run`: Print the triaged queue only; do not execute anything.

# Propose-Execute Loop

Iterate over all open GitHub issues, use an AI triage agent to determine which
are well-defined and ready for implementation, then call `/propose-execute` on
each actionable issue sequentially.

The orchestrator (you) manages the queue, spawns triage agents, invokes
`/propose-execute`, handles failures, and tracks progress.

---

## Step 1: Query Open Issues

Fetch all open issues:

```bash
gh issue list --state open --json number,title,body,labels,assignees --limit 500
```

If `$LABEL` is set, add it to the filter:
```bash
gh issue list --state open --label $LABEL --json number,title,body,labels,assignees --limit 500
```

### Queue Ordering

Parse the `labels` array for each issue to determine priority. Sort the full
list in this order:

1. **critical** — issues with the `critical` label
2. **high** — issues with the `high` label
3. **medium** — issues with the `medium` label
4. **low** — issues with the `low` label
5. **informational** — issues with the `informational` label
6. **unlabeled** — issues with no priority label

Within the same priority tier, sort by issue number ascending (lowest number
first = oldest first).

Exclude issues that already have the `propose-execute-failed` label (these
were previously attempted and failed).

Ensure the `propose-execute-failed` label exists (create it if not):
```bash
gh label create propose-execute-failed --description "propose-execute-loop attempted and failed" --color D93F0B 2>/dev/null || true
```

Store the sorted list as the **queue**.

---

## Step 2: Print the Queue

Print the queue as a table:

```
═══ PROPOSE-EXECUTE QUEUE ═══
N issues to triage

  #  | Issue | Priority | Title
-----|-------|----------|------
  1  | #42   | HIGH     | Implement bucket merge optimization
  2  | #55   | MEDIUM   | Add missing validation for...
  3  | #12   | —        | Refactor overlay flow control
 ...
══════════════════════════════
```

If `--dry-run` is set, proceed to triage (Step 3) to evaluate which issues
are actionable, then **stop before execution** (Step 4). This lets you see
the full triaged queue without making any changes to the codebase or issues.

---

## Step 3: Triage Each Issue

For each issue in the queue, spawn triage agents to determine if the issue
is well-defined and ready for implementation.

Process triage in batches of up to **10 issues at a time** to avoid
overwhelming the system. Wait for each batch to complete before launching
the next.

### 3a: Spawn Triage Agent

Launch an agent using the Task tool:
- **agent_type**: `"explore"`
- **model**: `$MODEL`
- **name**: `"triage-{issue_number}"`
- **description**: `"Triage issue #{issue_number}"`
- **mode**: `"background"`

The triage agent prompt:

```
You are triaging a GitHub issue for the henyey project (a Rust implementation
of stellar-core) to determine if it is well-defined and ready for
implementation.

## The Issue

**#{issue_number}: {title}**

{issue_body}

## Your Task

Evaluate whether this issue is **actionable** — meaning a developer could
start implementing it right now with the information provided. Assess:

1. **Problem clarity**: Is the problem or desired behavior clearly stated?
   Would a developer know exactly what "done" looks like?
2. **Scope**: Is the scope concrete and bounded? A vague "improve X" is not
   actionable; "add validation for Y in file Z" is.
3. **Technical detail**: Is there enough technical context (file paths, code
   references, expected behavior, edge cases) to implement without extensive
   further research?
4. **Not a question/discussion**: Issues that are open-ended questions,
   discussion threads, or brainstorming are not actionable.
5. **Not blocked**: The issue should not depend on unresolved prerequisites
   or external decisions.

## Output

You MUST end your response with exactly one of:

VERDICT: ACTIONABLE
(The issue is well-defined, scoped, and ready for implementation.)

VERDICT: SKIP — <one-line reason>
(The issue is not ready. State the specific reason after the dash.)

Examples of SKIP reasons:
- "Too vague — no concrete acceptance criteria"
- "Discussion thread, not an implementation request"
- "Blocked on decision about X"
- "Already implemented (should be closed)"
- "Duplicate of #N"
```

### 3b: Process Triage Result

Read the agent result. Extract the verdict.

**If `VERDICT: ACTIONABLE`**:
- Add the issue to the **execution queue**.

**If `VERDICT: SKIP`**:
- Record the skip reason.
- Print: `  SKIP #<number> — <reason>`

**If verdict unclear** (agent error):
- Treat as `SKIP — triage agent did not produce a clear verdict`.

### 3c: Print Triage Summary

After all issues are triaged:

```
═══ TRIAGE COMPLETE ═══
Total issues:    N
Actionable:      A
Skipped:         S

Execution order:
  1. #42 — Implement bucket merge optimization
  2. #55 — Add missing validation for...
 ...
════════════════════════
```

If `--dry-run` is set, **stop here**. Do not execute.

---

## Step 4: Execute Loop

Process each actionable issue sequentially.

### 4a: Pre-flight Check

Before each issue:
1. Ensure the working tree is clean: `git status --porcelain`
   - If dirty, **stash** the changes rather than discarding them:
     ```bash
     git stash push -m "propose-execute-loop: stashed before issue #<number>"
     ```
   - If stash fails, abort the loop and report the dirty state to the user.
2. Pull latest: `git pull --rebase`
3. Re-check that the issue is still open and not assigned to someone else:
   ```bash
   gh issue view <number> --json state,assignees
   ```
   - If the issue is **closed**, skip it and print:
     `  SKIP #<number> — closed since triage`
   - If the issue has **assignees** (and was unassigned at triage time), skip
     it and print:
     `  SKIP #<number> — assigned to @<login> since triage`
4. Self-assign the issue to signal to other agents that work is in progress:
   ```bash
   gh issue edit <number> --add-assignee @me
   ```

### 4b: Invoke /propose-execute

Call the `propose-execute` skill with the issue number and all pass-through
flags:

```
/propose-execute <issue_number> --model $MODEL --max-proposal-rounds $MAX_PROPOSAL_ROUNDS --max-review-rounds $MAX_REVIEW_ROUNDS
```

This means: follow the full `propose-execute` skill protocol — fetch the
issue, run proposal convergence, implement, run review-fix loop, and post
completion comment.

### 4c: Handle Success

If `/propose-execute` completes successfully:
- Record the issue as completed.
- Print: `  ✓ #<number> — completed`

### 4c′: Timeout Guidance

If `/propose-execute` has been running for an unreasonably long time (e.g.,
more than 60 minutes on a single issue with no progress), treat it as a
failure and follow Step 4d.

### 4d: Handle Failure

If `/propose-execute` fails (build breaks, tests fail, review loop exhausted,
or any other error):

1. Revert uncommitted changes (only tracked files and files generated by the
   build — do **not** remove pre-existing untracked files):
   ```bash
   git checkout -- .
   git clean -fd --exclude='*.log' --exclude='local-data/'
   ```
2. Label the issue so it is excluded from future runs:
   ```bash
   gh issue edit <number> --add-label "propose-execute-failed"
   ```
3. Post a comment explaining the failure:
   ```bash
   gh issue comment <number> --body "## propose-execute-loop: Failed

   This issue was attempted by the propose-execute-loop skill but failed.

   **Reason:** <brief description of what went wrong>

   The issue has been labeled \`propose-execute-failed\` and will be skipped
   in future loop runs. Remove the label to retry.

   ---
   *Automated by the \`propose-execute-loop\` skill.*"
   ```
4. Record the issue as failed.
5. Print: `  ✗ #<number> — failed: <reason>`
6. Continue to the next issue.

### 4e: Re-query Before Next Iteration

Before picking the next issue, re-query open issues to refresh the queue:

```bash
gh issue list --state open --json number,title,body,labels,assignees --limit 500
```

(Include `$LABEL` filter if set.)

This is necessary because:
- The `/propose-execute` commit may close related issues via `Closes #N`.
- Other agents or humans may have closed, assigned, or labeled issues during
  execution.
- Issues labeled `propose-execute-failed` must be excluded.

Re-sort by priority, then issue number. Filter out closed, assigned (by
others), and `propose-execute-failed` issues. Intersect with the original
actionable set from triage — do not process issues that were triaged as SKIP.

If the re-queried actionable list is empty, exit the loop.

### 4f: Progress Update

After each issue, print a progress summary:

```
Progress: <processed>/<total_actionable> (<completed> completed, <failed> failed, <skipped> skipped) — <remaining> remaining
```

---

## Step 5: Completion Summary

After the loop exits:

```
═══ PROPOSE-EXECUTE LOOP COMPLETE ═══
Total issues triaged:  N
  Actionable:          A
  Skipped:             S

Actionable issues processed:  A
  Completed:           C
  Failed:              F

Commits:
  <hash1> — <message>
  <hash2> — <message>
  ...
══════════════════════════════════════
```

If there are failed issues, also print:

```
Failed issues (labeled propose-execute-failed):
  #<number> — <title> — <failure reason>
  ...
```

---

## Guidelines

- **One issue at a time.** Do not parallelize execution — each
  `/propose-execute` may modify the codebase in ways that affect subsequent
  issues.
- **Triage can be parallel.** Triage agents are read-only, so multiple triage
  agents may run concurrently for efficiency.
- **Clean state between issues.** Always ensure a clean working tree before
  starting the next issue. Revert any uncommitted changes from failures.
- **Pull between issues.** Run `git pull --rebase` before each issue to
  incorporate changes from the previous issue's push.
- **Label failures, don't retry.** If an issue fails, label it and move on.
  A human or future run (after removing the label) can retry.
- **Respect priority ordering.** Always process the highest-priority
  remaining issue next.
- **Re-query after each issue.** The queue is dynamic; implementations may
  close related issues. Always re-query before picking the next issue.
- **Self-assign before starting.** Assign yourself to the issue before
  invoking `/propose-execute` to prevent concurrent agents from picking
  the same issue.
- **Triage in batches.** Spawn at most 10 triage agents concurrently.
  Wait for each batch before launching the next.
- **Pass through flags.** All `--model`, `--max-proposal-rounds`, and
  `--max-review-rounds` flags are passed to each `/propose-execute`
  invocation.
- **The triage agent is the gatekeeper.** Only issues the triage agent
  deems ACTIONABLE get processed. This prevents wasting time on
  under-specified or discussion-only issues.
