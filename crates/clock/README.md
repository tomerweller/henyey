# henyey-clock

Clock abstractions for deterministic and reproducible runtime behavior.

## Overview

`henyey-clock` provides a small `Clock` trait and concrete implementations used
to decouple timing-sensitive logic from direct wall-clock calls. This enables
simulation and deterministic tests without changing production behavior.

## Components

| Type | Purpose |
|------|---------|
| `Clock` | Trait for `now`, `system_now`, `sleep`, and `interval` |
| `RealClock` | Production clock backed by `std::time` and `tokio::time` |
| `VirtualClock` | Test/simulation clock compatible with deterministic progression |

## Notes

- `RealClock` preserves existing runtime semantics.
- `VirtualClock` is intended for simulation and test harnesses.
- Determinism is achieved by injecting a clock into higher-level components.
