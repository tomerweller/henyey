---
name: compare-pseudocode
description: Generate side-by-side pseudocode of a Rust file vs its stellar-core C++ counterpart
argument-hint: <rust-file-path>
---

Parse `$ARGUMENTS`:
- The first argument is the Rust file path or crate path. Replace `$TARGET` with it.

# Pseudocode Comparison

Generate side-by-side pseudocode for the Rust file at `$TARGET` and its
stellar-core C++ counterpart, for the purpose of spotting parity differences.

Use the pseudocode conventions defined in `.claude/skills/pseudocode/SKILL.md`
for all pseudocode generation. Read that file first.

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

## Process

### Step 1: Identify the file pair

`$TARGET` can be:
- A Rust file path (e.g., `crates/tx/src/operations/execute/manage_offer.rs`)
- A crate path (e.g., `crates/tx`) — in this case, ask the user which file to compare

Find the corresponding C++ file(s) in `stellar-core/` using the mapping table
and filename/type conventions. If the mapping isn't obvious, search by class
name, function name, or type name.

### Step 2: Read both sides

Use subagents to read the Rust and C++ files in parallel. For each side:
- Read the complete file (use offset/limit for large files)
- Skip test code — focus only on production logic
- Identify every public function and significant private function

### Step 3: Generate pseudocode

Generate pseudocode for both sides using the conventions from the `pseudocode`
skill, then present them side-by-side with comparison annotations.

Produce a single document with this structure:

```
## Pseudocode Comparison: <Rust file> vs <C++ file>

### Entry Points

  (How the functions are invoked — parameter mapping, wrappers)

### Phase N: <descriptive name>

=== RUST ===
  (pseudocode)

=== C++ ===
  (pseudocode)

  MATCH: <what's identical>
  DELTA: <what differs>

### Helper: <name>
  (shared logic or divergent helpers)

## Summary
  | Metric       | Rust source | C++ source | Pseudocode |
  |--------------|-------------|------------|------------|
  | Lines (logic)| ...         | ...        | ...        |
  | Functions    | ...         | ...        | ...        |
```

## Comparison Annotations

In addition to the standard pseudocode conventions, use these annotations
when comparing the two sides:

```
MATCH: <what's identical between Rust and C++>
DELTA: <what differs — be specific about the behavioral impact>
```

## Classification of Deltas

For every DELTA, classify it:

- **Behavioral**: Different observable outcome for some input. Flag these
  prominently — they may indicate a parity bug.
- **Structural**: Different code organization, same behavior (e.g., Rust has a
  dedicated `delete_offer()` function, C++ handles it inline in `doApply()`).
- **Scope**: One side implements something the other doesn't (e.g., liquidity
  pool crossing in C++ but not Rust).

## Guidelines

- Be precise. When noting a DELTA, cite the Rust line range and C++ line range.
- Do not speculate about whether a difference matters — just document it.
  The reader will decide.
- Preserve the **exact order** of checks. If Rust checks A-then-B and C++
  checks B-then-A, that's a DELTA even if both checks exist.
- Group related logic into named phases. Choose phase names that describe
  the *purpose* (e.g., "Trustline validation"), not the *mechanism*
  (e.g., "Load entries").
