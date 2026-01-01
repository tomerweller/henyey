# stellar-core-work

Work scheduler and orchestration primitives for rs-stellar-core.

## Scope

- Minimal work abstraction (`Work`) with outcomes and retry support.
- Dependency-aware scheduler (`WorkScheduler`) with queue de-duplication.
- Work sequences (`WorkSequence`) and callback wrappers (`WorkWithCallback`).

## Status

Core parity with upstream work scheduling: cancellation, metrics, and
graph introspection are implemented. Remaining gaps are in app-wide
metrics export wiring.

## Usage

Use `WorkScheduler` to register work items and dependencies, then call
`run()` to execute until all work completes or a failure occurs.

See tests in `crates/stellar-core-work/tests/` for examples.
