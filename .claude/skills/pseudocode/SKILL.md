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

### Assertions
```
ASSERT: <invariant that must hold>
```
Use for `releaseAssert`, `assert`, `dbgAssert`, or any runtime invariant check
that would crash/abort if violated. These encode critical correctness
assumptions. Preserve the exact condition.

### Protocol version branches
```
@version(≥N):
  <logic for protocol version N and above>
@version(<N):
  <logic for protocol versions below N>
```
Include **all** protocol version branches — every version, not just recent ones.
Use `@version` blocks to clearly delineate version-conditional logic. Nest them
when the source nests version checks:
```
@version(≥10):
  @version(≥13):
    <v13+ logic>
  @version(<13):
    <v10-v12 logic>
@version(<10):
  <pre-v10 logic>
```

### Source comments
```
"<text from source>"
```
Import comments from the original source using quoted strings. The quotes
alone distinguish them from pseudocode — no prefix needed. Place them:
- **Under a function heading** (before the code block) for function-level
  comments that describe purpose, invariants, or design rationale
- **Inline** within a code block for comments tied to specific logic

Import comments that convey:
- **Invariants** (e.g., "invariant: h.value = b.value")
- **Spec references** (e.g., "see CAP-0034", "SCP paper Step 9")
- **Ordering constraints** (e.g., "must happen before X")
- **Warnings** (e.g., "WARNING: offer deleted but account not updated")
- **Design rationale** (e.g., why a particular approach was chosen)
- **Domain knowledge** (e.g., rounding guarantees, protocol subtleties)

Do NOT import mechanical comments that merely restate the code, or comments
about logging, debugging, or build configuration.

### Cross-file references
```
REF: <file>::<function_name>
```
Add after any function call whose implementation lives in a different source
file. This creates a navigable web across pseudocode files:
```
result = apply_transaction(tx)    REF: TransactionFrame::apply
```

### Named constants
```
CONST <NAME> = <value>  // <meaning>
```
Define constants with semantic meaning at the top of the pseudocode or at first
use. Distinguish named constants from magic numbers:
```
CONST MAX_OPS_PER_TX = 100  // hard protocol limit per transaction
```

### State machines
When a file defines or drives an enum-based state machine, add a header block:
```
STATE_MACHINE: <name>
  STATES: [State1, State2, State3]
  TRANSITIONS:
    State1 → State2: <condition>
    State2 → State3: <condition>
    State3 → (terminal)
```
Place this before the functions that implement the state machine logic.

## What to Include

- **Guard check ordering** — this is the #1 priority; list every early-return
  check in exact source order
- **State mutations** — every write to accounts, trustlines, offers, balances,
  liabilities, sub-entries, sponsorship counts
- **Decision points** — every branch that affects which result code is returned
  or which state changes are made
- **Cross-function calls** — show the call graph for the main flow
- **All protocol version branches** — capture every `protocolVersionStartsFrom`,
  `protocolVersionIsBefore`, and similar version-conditional logic
- **Assertions** — every `releaseAssert` and runtime invariant check
- **Valuable source comments** — import comments that convey invariants,
  spec references, ordering constraints, warnings, or domain knowledge

## What to Omit

- Error type wrapping / propagation mechanics (`Result`, `try`, exceptions)
- Memory management, lifetimes, ownership, `clone()`
- Logging, tracing, metrics, profiling (`Tracy`, `tracing`)
- Type conversions and XDR serialization (unless they contain logic)
- Test code
- Result code mapping boilerplate (e.g., `make_sell_offer_result`)
- Comments that merely restate code or describe logging/debugging

## Guidelines

- Preserve the **exact order** of checks as they appear in the source.
- Keep pseudocode lines short. Aim for 60-80 chars max.
- Group related logic into named phases. Choose phase names that describe
  the *purpose* (e.g., "Trustline validation"), not the *mechanism*
  (e.g., "Load entries").
- If a function is called from multiple places, show it once as a
  `### Helper:` section and reference it from the phases.
- Place `REF:` annotations inline after the call they refer to, not on a
  separate line.
- Use source comments sparingly — only import comments that add understanding
  beyond what the pseudocode already expresses.
