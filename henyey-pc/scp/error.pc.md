## Pseudocode: crates/scp/src/error.rs

### Error Enum: ScpError

```
ENUM ScpError:
  InvalidMessage(message)       "SCP message is malformed or invalid"
  InvalidQuorumSet(message)     "Quorum set configuration is invalid"
  SignatureVerificationFailed   "Envelope signature failed verification"
  ValueValidationFailed(message)"Value being proposed/voted on is invalid"
  SlotNotFound(slot_index)      "Requested slot not found in slot map"
  InternalError(message)        "Internal state error / bug"
```

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 13     | 8          |
| Functions    | 0      | 0          |
