# Code Simplification

Review the Rust crate at `$TARGET` and identify concrete simplifications.

## Mode

- **`$MODE = review`** (default): Produce a ranked list of findings with
  file:line references. Do NOT make any changes.
- **`$MODE = apply`**: Perform the simplifications directly. For each change,
  briefly state what you changed and why. Run `cargo clippy -p <crate>` and
  `cargo test -p <crate>` after each logical group of changes to verify
  correctness.

## Categories

For each finding, classify it into exactly one category:

### Structure
 1. **LARGE MODULE** — any single .rs file over 500 lines. Suggest how to split it
    into focused submodules with clear responsibilities.
 2. **GOD FUNCTION** — any function over 80 lines or with cyclomatic complexity
    that makes it hard to follow. Suggest extraction points and names for the
    extracted functions.
 3. **DEEP NESTING** — blocks indented 4+ levels. Suggest early returns, guard
    clauses, or extraction to flatten them.
 4. **LONG PARAMETER LIST** — functions taking 5+ parameters. Suggest grouping
    into a context/config struct.

### Redundancy
 5. **DEAD CODE** — functions, fields, methods, or branches that are never used
    or always return a fixed value. Include evidence (e.g., "no callers found").
 6. **DUPLICATION** — identical or near-identical logic repeated in multiple places.
    Show the locations and what a single shared implementation would look like.
 7. **DUPLICATE STATE** — the same truth tracked in two or more places that must
    be kept in sync manually. Suggest which copy to remove.
 8. **SCATTERED CONCERN** — a single logical operation (e.g., resetting tracking
    state) performed in multiple call sites instead of one function.
 9. **UNNECESSARY CLONING** — values cloned where a borrow or move would suffice.

### Naming & Constants
10. **MISLEADING NAMES** — identifiers whose name does not match their actual
    semantics. Suggest a better name.
11. **MAGIC NUMBERS** — hardcoded numeric or string literals that should be
    named constants.

### Clippy & Types
12. **CLIPPY SUPPRESSIONS** — any `#[allow(clippy::...)]` or `#[allow(dead_code)]`.
    For each, determine whether the underlying issue can be fixed so the
    suppression can be removed. If the suppression is genuinely necessary
    (e.g., false positive, upstream requirement), note why.
13. **TYPE COMPLEXITY** — types that are hard to read at a glance, especially
    those marked `#[allow(clippy::type_complexity)]`. Suggest type aliases,
    wrapper structs, or simplified signatures.

### Documentation
14. **STALE COMMENTS** — comments that no longer match the code they describe,
    or that reference removed/renamed items. Fix or remove.
15. **COMMENTED-OUT CODE** — dead code left as comments instead of being deleted.
    Remove it (git preserves history).
16. **TODO/FIXME/HACK** — unresolved markers. For each: still relevant? If yes,
    describe the fix. If no, remove the marker.
17. **MISSING MODULE DOC** — .rs files over 100 lines with no top-level `//!` doc
    comment explaining the module's purpose. Suggest a one-line summary.

## Ranking

Rank findings by impact: how much each fix would reduce complexity, improve
readability, or prevent bugs. High-impact first.

## Scope

Ignore test code and `.upstream-v25/`.

## Output Format (review mode only)

Per finding:

```
### [RANK]. [CATEGORY] — one-line summary
- **Location**: file:line (and file:line if duplicated)
- **Evidence**: why this qualifies
- **Suggestion**: concrete fix (keep it brief)
```

## Apply Mode Guidelines

When `$MODE = apply`:
- Work through findings in rank order (highest impact first).
- Make one logical change at a time — do not batch unrelated refactors.
- After each change, verify with `cargo clippy -p <crate>` and `cargo test -p <crate>`.
- If a change breaks tests or introduces warnings, revert it and move on.
- Stop and report if a change would alter observable behavior.
