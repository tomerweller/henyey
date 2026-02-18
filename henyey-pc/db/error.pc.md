# Pseudocode: crates/db/src/error.rs

Error type definitions for the database layer.

## DbError

Enumeration of all database error categories:

```
ERROR_TYPE DbError:
    Sqlite       — database engine error (query failures,
                   constraint violations, corruption)
    Pool         — connection pool exhaustion or config error
    Io           — filesystem error (file creation, directories)
    Xdr          — XDR serialization/deserialization failure
                   (data corruption or version mismatch)
    NotFound     — unexpected absence of required data
    Integrity    — data in unexpected state (invalid hashes,
                   missing fields, inconsistent relationships)
    Migration    — schema version incompatibility or
                   migration failure
```

NOTE: Sqlite, Pool, Io, and Xdr auto-convert from their
underlying error types.

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 46     | 13         |
| Functions    | 0      | 0          |
