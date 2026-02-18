# Pseudocode: crates/common/src/error.rs

"Common error types for rs-stellar-core."

## Error Enum

```
ENUM Error:
  Xdr(xdr_error)             "XDR encoding/decoding failure"
  Io(io_error)               "File or network I/O failure"
  Config(message)            "Invalid or unparseable configuration"
  InvalidData(message)       "Data fails validation"
  NotFound(message)          "Requested resource does not exist"
  OperationFailed(message)   "Catch-all for other operation failures"
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 10     | 8          |
| Functions     | 0      | 0          |
