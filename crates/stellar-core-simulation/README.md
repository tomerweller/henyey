# stellar-core-simulation

Simulation harness for multi-node overlay and consensus scenarios.

## Scope

- Lightweight overlay simulation scaffold for spawning nodes and
  broadcasting SCP messages.

## Status

Partial parity with upstream `src/simulation/*`. Load/tx generators and
scenario assertions are not yet implemented.

## Usage

The crate currently exposes an `OverlaySimulation` helper. Use
`start_with_seed()` for deterministic node keys and `shutdown()` to
stop spawned overlay managers in tests.

See `crates/stellar-core-simulation/tests/overlay_simulation.rs` for a
minimal integration example.
