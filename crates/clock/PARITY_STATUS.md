# stellar-core Parity Status

**Crate**: `henyey-clock`
**Upstream**: `stellar-core/src/util/` time usage patterns
**Overall Parity**: 100%
**Last Updated**: 2026-03-06

## Summary

| Area | Status | Notes |
|------|--------|-------|
| Production timing behavior | Full | `RealClock` uses standard wall-clock and tokio timers |
| Deterministic simulation support | Full | `VirtualClock` enables controlled progression |
| API surface for injection | Full | Trait-based clock injection available |

## Scope

This crate does not change consensus semantics by itself. It provides timing
abstractions so higher-level crates can mirror stellar-core behavior while also
supporting deterministic simulation harnesses.
