# henyey-simulation

Deterministic multi-node simulation harness for henyey.

## Overview

`henyey-simulation` provides a lightweight simulation environment for
multi-node behavior checks with deterministic replay. It is designed to support
execution-plan validation for convergence, partition/recovery, and fault-tolerant
progress under bounded message loss.

## Components

| Type | Purpose |
|------|---------|
| `Simulation` | Main harness managing nodes, topology, and progression |
| `SimNode` | Simulated node state (id, key, ledger sequence/hash) |
| `SimulationMode` | Execution mode selector (`OverLoopback`, `OverTcp`) |
| `LoopbackNetwork` | Deterministic link model with partition/drop controls |
| `Topologies` | Topology builders (`core`, `core3`, `pair`, `cycle`, `separate`) |

## Current Status

- Deterministic loopback simulation is implemented and tested.
- Topology and fault scenarios are covered by integration tests.
- Initial app-backed TCP simulation support is implemented for node lifecycle,
  genesis bootstrapping, single-node manual ledger-close execution,
  multi-node startup/connectivity checks, and core3 multi-node ledger advancement.
- Real app-backed loopback simulation now works through an in-memory overlay
  connection factory alongside the TCP-backed path.
- Initial deterministic load/transaction generation scaffolding is available
  via `LoadGenerator` and `TxGenerator`, with pair-topology load execution
  tests running over both TCP and loopback.
- Full load execution parity and broader loopback scenario coverage remain
  follow-up work.

## Run Tests

```bash
cargo test -p henyey-simulation --tests
```
