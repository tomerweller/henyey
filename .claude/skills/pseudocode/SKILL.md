---
name: pseudocode
description: Generate language-agnostic pseudocode for a source file
argument-hint: <file-path>
---

Parse `$ARGUMENTS`:
- The first argument is the source file path. Replace `$TARGET` with it.

# Pseudocode Generation

Generate a language-agnostic pseudocode representation of the source file at
`$TARGET`, capturing its logic flow, guard checks, state mutations, and
decision points.

## Process

1. Read the complete file (use offset/limit for large files).
2. Skip test code — focus only on production logic.
3. Identify every public function and significant private function.
4. Generate pseudocode for each function using the conventions below.

## Output Structure

```
## Pseudocode: <file path>

### <function_name>

  (pseudocode)

### Helper: <name>
  (shared helpers referenced by main functions)

## Summary
  | Metric       | Source | Pseudocode |
  |--------------|--------|------------|
  | Lines (logic)| ...    | ...        |
  | Functions    | ...    | ...        |
```

## Pseudocode Conventions

The pseudocode must be **language-agnostic** — no Rust-isms (`Result`, `match`,
`Option`, `unwrap`), no C++-isms (`shared_ptr`, `throw`, `LedgerTxn` nesting).

Use these conventions consistently:

### Guard checks
```
GUARD <condition>    → <result code>
```
Guards are early returns on failure. **Order matters** — list them in the exact
order they appear in the code. Parity bugs most often hide in guard ordering.

### State mutations
```
MUTATE <target> <field> += <value>
```
Make every write to ledger state explicit.

### Control flow
```
if <condition>:
  ...
for each <item> in <collection>:
  ...
while <condition>:
  ...
→ <return value>
```

### Function calls
```
result = function_name(args)
→ delegate_to(other_function, args)
```

### Annotations
```
NOTE: <context that helps understand a non-obvious choice>
```

## What to Include

- **Guard check ordering** — this is the #1 priority; list every early-return
  check in exact source order
- **State mutations** — every write to accounts, trustlines, offers, balances,
  liabilities, sub-entries, sponsorship counts
- **Decision points** — every branch that affects which result code is returned
  or which state changes are made
- **Cross-function calls** — show the call graph for the main flow

## What to Omit

- Error type wrapping / propagation mechanics (`Result`, `try`, exceptions)
- Memory management, lifetimes, ownership, `clone()`
- Logging, tracing, metrics, profiling (`Tracy`, `tracing`)
- Type conversions and XDR serialization (unless they contain logic)
- Test code
- Legacy protocol version branches (pre-v24) — Henyey only supports p24+.
  Note their existence with a one-line comment but don't expand them.
- Result code mapping boilerplate (e.g., `make_sell_offer_result`)

## Guidelines

- Preserve the **exact order** of checks as they appear in the source.
- Keep pseudocode lines short. Aim for 60-80 chars max.
- Group related logic into named phases. Choose phase names that describe
  the *purpose* (e.g., "Trustline validation"), not the *mechanism*
  (e.g., "Load entries").
- If a function is called from multiple places, show it once as a
  `### Helper:` section and reference it from the phases.
