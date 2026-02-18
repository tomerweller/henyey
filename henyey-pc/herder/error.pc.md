## Pseudocode: crates/herder/src/error.rs

"Error types for Herder operations."

### HerderError (enum)

```
ENUM HerderError:
  TransactionValidationFailed(message)
  QueueFull
  Scp(scp_error)
  NotValidating
  LedgerClose(message)
  Internal(message)
  InvalidEnvelope(message)
```

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 14     | 9          |
| Functions    | 0      | 0          |
