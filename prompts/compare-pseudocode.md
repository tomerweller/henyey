# Pseudocode Comparison

Generate a side-by-side logic-flow pseudocode representation of the Rust file at
`$TARGET` and its stellar-core C++ counterpart, for the purpose of spotting
parity differences.

## Crate-to-Upstream Mapping

| Crate | Upstream Directory |
|-------|--------------------|
| `crates/tx` | `.upstream-v25/src/transactions/` |
| `crates/scp` | `.upstream-v25/src/scp/` |
| `crates/db` | `.upstream-v25/src/database/` |
| `crates/common` | `.upstream-v25/src/util/` |
| `crates/crypto` | `.upstream-v25/src/crypto/` |
| `crates/ledger` | `.upstream-v25/src/ledger/` |
| `crates/bucket` | `.upstream-v25/src/bucket/` |
| `crates/herder` | `.upstream-v25/src/herder/` |
| `crates/overlay` | `.upstream-v25/src/overlay/` |
| `crates/history` | `.upstream-v25/src/history/` |
| `crates/historywork` | `.upstream-v25/src/historywork/` |
| `crates/work` | `.upstream-v25/src/work/` |
| `crates/app` | `.upstream-v25/src/main/` |
| `crates/henyey` | `.upstream-v25/src/main/` (CLI subset) |

## Process

### Step 1: Identify the file pair

`$TARGET` can be:
- A Rust file path (e.g., `crates/tx/src/operations/execute/manage_offer.rs`)
- A crate path (e.g., `crates/tx`) — in this case, ask the user which file to compare

Find the corresponding C++ file(s) in `.upstream-v25/` using the mapping table
and filename/type conventions. If the mapping isn't obvious, search by class
name, function name, or type name.

### Step 2: Read both sides

Use subagents to read the Rust and C++ files in parallel. For each side:
- Read the complete file (use offset/limit for large files)
- Skip test code — focus only on production logic
- Identify every public function and significant private function

### Step 3: Generate pseudocode

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
MATCH: <what's identical between Rust and C++>
DELTA: <what differs — be specific about the behavioral impact>
NOTE:  <context that helps understand a non-obvious choice>
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
- Keep pseudocode lines short. Aim for 60-80 chars max.
- Group related logic into named phases. Choose phase names that describe
  the *purpose* (e.g., "Trustline validation"), not the *mechanism*
  (e.g., "Load entries").
- If a function is called from multiple places, show it once as a
  `### Helper:` section and reference it from the phases.
