# Pseudocode: crates/common/src/lib.rs

"Common types and utilities for rs-stellar-core."

## Module Declarations

```
modules:
  asset       "Asset validation, conversion, and balance utilities"
  config      "Configuration types for node setup"
  error       "Common error types"
  math        "128-bit arithmetic and overflow-safe math"
  meta        "Ledger metadata normalization for deterministic hashing"
  network     "Network identity from passphrases"
  protocol    "Protocol version constants and feature gating"
  resource    "Resource accounting for tx limits and surge pricing"
  time        "Unix/Stellar timestamp conversions"
  types       "Core types like Hash256"
  xdr_stream  "XDR size-prefixed binary frame I/O"
```

## Re-exports

```
re-export: Config, BucketListDbConfig   from config
re-export: Error, Result                from error
re-export: all                          from meta
re-export: NetworkId                    from network
re-export: all                          from protocol
re-export: all                          from resource
re-export: all                          from types
re-export: stellar_xdr                  "convenience re-export for downstream crates"
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 16     | 16         |
| Functions     | 0      | 0          |
