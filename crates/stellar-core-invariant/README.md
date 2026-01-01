# stellar-core-invariant

Invariant framework for validating ledger transitions.

## Scope

- Invariant trait + registry (`InvariantManager`).
- Basic invariants: ledger sequence increment, bucket list hash match,
  conservation of lumens, and entry sanity checks.
- Hooked into ledger close when enabled.

## Status

Partial parity with upstream `src/invariant/*`. Additional core invariants,
replay hooks, and metrics are still missing.

## Usage

Register invariants via `LedgerManager::add_invariant()` or add to the
`InvariantManager` directly in tests. The `InvariantContext` includes
header transitions, deltas, and changed entries.
