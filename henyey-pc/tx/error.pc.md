## Pseudocode: crates/tx/src/error.rs

"Error types for transaction processing."

### TxError (enum)

```
ENUM TxError:
  ValidationFailed(message)       "transaction validation failed"
  InvalidSignature                "invalid signature"
  InsufficientFee(required, provided)
  BadSequence(expected, actual)
  SourceAccountNotFound
  AccountNotFound(context)
  InsufficientBalance(required, available)
  OperationFailed(message)
  Soroban(message)
  LedgerError(message)
  Crypto(error)                   "from CryptoError"
  Xdr(error)                      "from XDR Error"
  Internal(message)
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 87     | 16         |
| Functions     | 0      | 0          |
