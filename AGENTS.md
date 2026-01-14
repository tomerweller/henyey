# Repository Guidelines

## Project Structure & Module Organization

- `crates/` contains the Rust workspace crates. Each module is a crate (e.g., `crates/stellar-core-ledger`, `crates/stellar-core-tx`, `crates/stellar-core-history`).
- `crates/rs-stellar-core/` is the main binary crate; other crates are libraries.
- Tests live alongside code in `crates/*/src` and in `crates/*/tests` for integration tests.
- Docs live in crate `README.md` files plus top-level `README.md` and `SPEC.md`.
- Config examples are in `configs/` and `*.toml` at the repo root.

## Build, Test, and Development Commands

- `cargo build --all` — build the entire workspace.
- `cargo test --all` — run all unit and integration tests.
- `cargo test -p stellar-core-ledger --tests` — run a focused crate’s integration tests.
- `cargo clippy --all` — run lint checks (recommended before PRs).

## Coding Style & Naming Conventions

- Follow standard Rust style (4-space indentation, snake_case for functions and modules, CamelCase for types).
- Keep modules small and focused; prefer adding logic inside the relevant crate instead of cross-crate helpers.
- Use descriptive error messages and map to XDR result codes where applicable.
- Fix cargo compiler warnings before submitting changes; keep the workspace warning-free where practical.

## Determinism & Parity

- Any observable behavior must be deterministic and identical to stellar-core (v25.x / p25).
- Align behavior by comparing against upstream test vectors and edge cases; do not introduce new semantics.
- For protocol or consensus behavior, consult `.upstream-v25/` to mirror upstream decisions and sequencing.
- Update the relevant crate's `PARITY_STATUS.md` and the parity column in the main `README.md` Crate Overview when implementing or removing functionality that affects C++ parity.

## Testing Guidelines

- Use Rust's built-in test framework (`#[test]`).
- Unit tests go in the same module; integration tests go in `crates/<crate>/tests/`.
- Name tests by behavior, e.g., `test_execute_transaction_min_seq_num_precondition`.
- Run focused tests when possible to speed iteration, then run `cargo test --all` before submitting.
- No fuzz testing is required for this project.
- No baseline transaction meta testing is required.
- Perform testing on testnet, not mainnet.

## Commit & Pull Request Guidelines

- Commit messages are short, imperative, and sentence case (examples: "Implement disk-backed bucket storage", "Optimize memory usage").
- **AI Agent Co-authorship**: Any commit that was authored or co-authored by an AI agent MUST include that agent (the tool/interface, not the underlying model) as a co-author using a Git trailer. Use the appropriate trailer for the agent involved:
  - GitHub Copilot (CLI or IDE): `Co-authored-by: GitHub Copilot <copilot@github.com>`
  - Codex: `Co-authored-by: Codex <codex@openai.com>`
  - Other agents: Use the agent/tool name, not the model name
- PRs should include: a clear description, the tests run, and documentation updates when behavior changes.
- Link related issues or upstream references (e.g., stellar-core v25) where relevant.
- When possible, fixes should be committed alongside regression tests that would have caught the bug.
- If a push is rejected, pull with rebase and retry the push.

## Agent Communication

- Format assistant messages in a Claude-like style: concise, direct, and structured with short sections or bullets when helpful.

## Configuration & Operational Notes

- SQLite is the only supported database backend.
- Protocol support is 23+ only; do not add legacy protocol behavior.
- The Stellar Core v25 C++ upstream is available locally under `.upstream-v25/` for parity checks.
