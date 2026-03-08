# stellar-core Parity Status

**Crate**: `henyey-simulation`
**Upstream**: no direct stellar-core crate equivalent (test/harness utility)
**Overall Parity**: N/A (enabling infrastructure)
**Last Updated**: 2026-03-06

## Summary

| Area | Status | Notes |
|------|--------|-------|
| Deterministic replay | Full | Repeated runs produce identical ledger hashes |
| Topology modeling | Partial | Core, pair, cycle, cycle4, branched, hierarchical, custom-A, asymmetric |
| Fault modeling | Partial | Partition/heal and drop probability supported |
| App-level integration | Partial | App-backed TCP nodes can bootstrap, run, and expose simulation state |
| TCP mode | Partial | Single-node, pair, core3, and core4 app-backed closes pass |
| Loopback mode | Partial | App-backed pair/core3 loopback closes pass via in-memory transport |
| Load generation | Partial | Deterministic load plans execute on pair topology over TCP/loopback |

## Notes

This crate exists to validate deterministic behavior and scenario coverage for
henyey. It complements parity work in consensus/overlay/ledger crates.
