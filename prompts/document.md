# Crate Documentation Review

Review the Rust crate at `$TARGET` and produce documentation artifacts.

## 1. Crate README

Write or update `$TARGET/README.md` with:
- One-paragraph purpose statement
- Key types and their roles
- A Mermaid diagram (see below)

## 2. Diagram

Pick the ONE diagram type that best clarifies this crate:

- **STATE MACHINE** — for crates with explicit state enums or modal behavior.
  Show states, transitions, and triggers.

- **DATA FLOW** — for crates that transform or route data.
  Show inputs, processing stages, and outputs.

- **MODULE DEPENDENCY** — for crates with 5+ internal modules.
  Show which modules depend on which.

- **SEQUENCE** — for crates with complex multi-step protocols.
  Show the order of operations between components.

Use Mermaid syntax so diagrams render on GitHub.
Keep diagrams focused — max 15 nodes. If more detail is needed,
suggest where a second diagram would help but don't create it.

## Scope

Ignore test code and `.upstream-v25/`.
