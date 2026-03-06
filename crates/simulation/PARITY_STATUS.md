# stellar-core Parity Status

**Crate**: `henyey-simulation`
**Upstream**: no direct stellar-core crate equivalent (test/harness utility)
**Overall Parity**: N/A (enabling infrastructure)
**Last Updated**: 2026-03-06

## Summary

| Area | Status | Notes |
|------|--------|-------|
| Deterministic replay | Full | Repeated runs produce identical ledger hashes |
| Topology modeling | Full | Core, pair, cycle, and separated clusters |
| Fault modeling | Partial | Partition/heal and drop probability supported |
| App-level integration | Partial | Harness-level simulation complete; deeper app transport integration pending |

## Notes

This crate exists to validate deterministic behavior and scenario coverage for
henyey. It complements parity work in consensus/overlay/ledger crates.
