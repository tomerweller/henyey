## Pseudocode: crates/ledger/src/error.rs

### LedgerError (enum)

"Unified error type for all ledger-related operations."

```
ENUM LedgerError:
  EntryNotFound
    "A requested ledger entry was not found"

  InvalidSequence { expected, actual }
    "Ledger sequence number doesn't match expected value"

  HashMismatch { expected, actual }
    "Cryptographic hash mismatch — indicates data corruption"

  InvalidHeaderChain(message)
    "previous_ledger_hash or skip list entries don't match"

  Bucket(inner)
    "Error from bucket list operations"

  Xdr(inner)
    "XDR encoding or decoding error"

  Serialization(message)
    "Generic serialization error"

  NotInitialized
    "Operation attempted on uninitialized ledger manager"

  NotAlreadyInitialized
    "Attempted to initialize an already-initialized ledger manager"

  InvalidLedgerClose(message)
    "Invalid ledger close operation"

  DuplicateEntry(message)
    "Attempted to create an entry that already exists"

  MissingEntry(message)
    "Attempted to update or delete an entry that doesn't exist"

  Snapshot(message)
    "Snapshot-related error"

  Internal(message)
    "Internal error — indicates a bug"

  InvalidEntry(message)
    "Entry has an unexpected type or invalid state"
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 117    | 32         |
| Functions     | 0      | 0          |

NOTE: This file is purely declarative — it defines the error enum
with no procedural logic. All variants are listed for completeness
since they are referenced across the ledger crate.
