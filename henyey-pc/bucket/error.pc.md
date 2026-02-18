## Pseudocode: crates/bucket/src/error.rs

"Error types for bucket operations."

### BucketError (enum)

```
ENUM BucketError:
  NotFound(message)           // bucket file not found on disk
  HashMismatch(expected, actual)  // bucket hash verification failed
  Serialization(message)      // XDR serialization/deserialization failed
  Merge(message)              // bucket merge operation failed
  Io(io_error)                // file I/O operation failed
  Database(db_error)          // database operation failed
  BloomFilter(message)        // bloom filter construction/lookup failed
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 73     | 10         |
| Functions     | 0      | 0          |

NOTE: This is a pure error-type definition with no logic.
Error variants map to distinct failure modes in the bucket subsystem.
