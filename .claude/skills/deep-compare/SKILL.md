---
name: deep-compare
description: Deep comparative analysis of a Henyey crate vs its stellar-core counterpart
argument-hint: <crate-path>
---

Parse `$ARGUMENTS`:
- The first argument is the crate path. Replace `$TARGET` with it.

# Deep Comparative Analysis

Perform a deep side-by-side analysis of the Rust crate at `$TARGET` against its
stellar-core counterpart. Focus on correctness, performance, and gaps.

## Crate-to-Upstream Mapping

| Crate | Upstream Directory |
|-------|--------------------|
| `crates/tx` | `stellar-core/src/transactions/` |
| `crates/scp` | `stellar-core/src/scp/` |
| `crates/db` | `stellar-core/src/database/` |
| `crates/common` | `stellar-core/src/util/` |
| `crates/crypto` | `stellar-core/src/crypto/` |
| `crates/ledger` | `stellar-core/src/ledger/` |
| `crates/bucket` | `stellar-core/src/bucket/` |
| `crates/herder` | `stellar-core/src/herder/` |
| `crates/overlay` | `stellar-core/src/overlay/` |
| `crates/history` | `stellar-core/src/history/` |
| `crates/historywork` | `stellar-core/src/historywork/` |
| `crates/work` | `stellar-core/src/work/` |
| `crates/app` | `stellar-core/src/main/` |
| `crates/henyey` | `stellar-core/src/main/` (CLI subset) |

## Analysis Process

Use subagents (Task tool with `Explore` type) to read both implementations in
parallel. Launch at minimum:

1. **Henyey exploration agent** — read every `.rs` file in `$TARGET/src/`.
   Catalog: module structure, public types, key algorithms, state machines,
   integration points (traits/callbacks), error handling strategy, and test
   inventory.

2. **Upstream exploration agent** — read every `.h` and `.cpp` file in the
   mapped upstream directory. Catalog the same dimensions as above.

After both complete, launch targeted comparison agents for each major subsystem
(e.g., the main state machine, quorum/validation logic, message handling,
timer logic). Each comparison agent should read the specific files from both
sides and produce a diff-style comparison.

## What to Compare

For every major component, evaluate along three axes:

### 1. Correctness

- **Algorithm equivalence**: Are the same operations performed in the same
  order? Pay attention to loop structures, predicate evaluation order, and
  edge case handling.
- **State machine parity**: Do phase transitions happen under identical
  conditions? Are invariants maintained equivalently?
- **Predicate logic**: Are quorum checks, validation checks, and threshold
  computations identical?
- **Edge cases**: Does Henyey handle the same boundary conditions (empty
  inputs, overflow, zero thresholds, maximum nesting depths)?
- **Error handling divergence**: Where stellar-core uses `assert`/`throw`,
  does Henyey use `Result`/`Option` equivalently? Could any divergence cause
  different observable behavior?

Flag any behavioral difference, no matter how minor. Classify each as:
- **Consensus-affecting**: Could cause nodes to disagree
- **Observability-affecting**: Different logging/metrics but same consensus
- **Cosmetic**: Different code structure, same behavior

### 2. Performance

- **Data structure choices**: Compare container types (e.g., `HashSet` vs
  `vector` with linear scan, `BTreeMap` vs `HashMap`). Note asymptotic
  differences.
- **Allocation patterns**: Owned values vs shared pointers vs borrows.
  Where does Henyey clone more or less than stellar-core copies?
- **Hot path efficiency**: In the main processing loop (e.g., `advance_slot`,
  `process_envelope`), are there unnecessary allocations, redundant lookups,
  or avoidable work?
- **Lock contention**: If either side uses locks, compare granularity and
  hold duration.

For each performance difference, assess whether it matters in practice
(consensus rounds are network-bound, so CPU micro-optimizations rarely matter;
but O(n) vs O(n^2) in quorum checks could matter for large validator sets).

### 3. Gaps

Identify functionality present in stellar-core but missing or incomplete in
Henyey. For each gap:

- **Description**: What's missing
- **Impact**: What breaks or degrades without it
- **Priority**: Using this rubric:
  - **P0 — Correctness**: Missing logic that could cause wrong consensus
    results, state divergence, or protocol violations
  - **P1 — Completeness**: Missing features needed for full protocol
    participation (e.g., recovery paths, edge case handling)
  - **P2 — Observability**: Missing diagnostics, metrics, or debug
    facilities that don't affect correctness
  - **P3 — Optimization**: Performance improvements present upstream but
    not in Henyey

Also identify the reverse: functionality in Henyey not present in
stellar-core (beneficial improvements, extra safety checks, etc.).

## Reading Strategy

- Read `.h` files first for upstream — they define the API surface concisely.
- Read Rust source files completely — don't skip test modules, they reveal
  what's actually exercised.
- Read `.cpp` files when the header is ambiguous or when you need to compare
  specific algorithmic steps line-by-line.
- For large files (>500 lines), focus comparison agents on specific function
  pairs rather than trying to compare everything at once.

## Output Format

Present findings as a structured report:

```
# Deep Comparison: henyey-<name> vs stellar-core

## Overview

| Metric | Henyey | stellar-core |
|--------|--------|--------------|
| Source files | ... | ... |
| Production LOC | ... | ... |
| Test LOC | ... | ... |

## Correctness Assessment

**Verdict**: Full parity / Minor divergences / Gaps found

(For each component, state whether it matches and cite specific file:line
references for any differences.)

### <Component Name>
- **Algorithm match**: Yes/No — details
- **Edge cases**: Covered/Missing — details
- **Divergences**: List with classification

## Performance Comparison

| Area | Henyey | stellar-core | Winner | Impact |
|------|--------|--------------|--------|--------|

(One row per meaningful difference.)

## Gaps (Henyey missing from stellar-core)

| # | Description | Impact | Priority | Location (upstream) |
|---|-------------|--------|----------|---------------------|

(Sorted by priority, P0 first.)

## Henyey Improvements (not in stellar-core)

| # | Description | Benefit |
|---|-------------|---------|

## Recommendations

Prioritized list of actions, highest impact first.
```

## Guidelines

- Be precise. Cite file:line for every claim.
- Do not speculate — if you're unsure whether a difference matters, read the
  code more carefully before reporting it.
- Distinguish between "different code, same behavior" and "different behavior".
  Only the latter is a finding.
- Keep the report concise. Summarize at the component level; only expand to
  function-level detail for actual divergences or gaps.
- If a crate's `PARITY_STATUS.md` exists, read it first — it may already
  document known gaps and architectural differences. Verify its claims rather
  than duplicating the work, but don't trust it blindly.
