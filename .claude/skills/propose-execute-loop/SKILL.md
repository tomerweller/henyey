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
5. **unlabeled** — issues with no priority label

Within the same priority tier, sort by issue number ascending (lowest number
first = oldest first).

Exclude issues that already have the `propose-execute-failed` label (these
were previously attempted and failed).

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

If `--dry-run` is set, proceed to triage (Step 3) but **stop before
execution** (Step 4). This lets you see what the AI considers actionable
without making any changes.

---

## Step 3: Triage Each Issue

For each issue in the queue, spawn a triage agent to determine if the issue
is well-defined and ready for implementation.

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
   - If dirty, run `git checkout -- .` to restore clean state.
2. Pull latest: `git pull --rebase`

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

### 4d: Handle Failure

If `/propose-execute` fails (build breaks, tests fail, review loop exhausted,
or any other error):

1. Revert uncommitted changes:
   ```bash
   git checkout -- .
   git clean -fd
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

### 4e: Progress Update

After each issue, print a progress summary:

```
Progress: <processed>/<total_actionable> (<completed> completed, <failed> failed) — <remaining> remaining
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
- **Pass through flags.** All `--model`, `--max-proposal-rounds`, and
  `--max-review-rounds` flags are passed to each `/propose-execute`
  invocation.
- **The triage agent is the gatekeeper.** Only issues the triage agent
  deems ACTIONABLE get processed. This prevents wasting time on
  under-specified or discussion-only issues.
