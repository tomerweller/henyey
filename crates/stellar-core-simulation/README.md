# stellar-core-simulation

Simulation harness for multi-node overlay and consensus scenarios.

## Scope

- Lightweight overlay simulation scaffold for spawning nodes and
  broadcasting SCP messages.

## Architecture

- `OverlaySimulation` builds in-process overlay managers and wires their peers.
- Deterministic seeds generate stable node IDs and key material.
- Message delivery is synchronous in tests, avoiding real network IO.
- Helpers drive startup, broadcast, tick progression, and shutdown.

## Key Concepts

- **Deterministic seeds**: repeatable simulations for debugging.
- **In-process overlay**: avoids external networking for tests.
- **Tick driving**: tests advance time/slots explicitly for reproducibility.

## Status

Partial parity with upstream `src/simulation/*`. Load/tx generators and
scenario assertions are not yet implemented.

## Usage

The crate currently exposes an `OverlaySimulation` helper. Use
`start_with_seed()` for deterministic node keys and `shutdown()` to
stop spawned overlay managers in tests.

See `crates/stellar-core-simulation/tests/overlay_simulation.rs` for a
minimal integration example.
