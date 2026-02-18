# Pseudocode: crates/db/src/pool.rs

"Connection pool management. The Database type wraps an r2d2 connection
pool for SQLite, allowing multiple threads to access the database
concurrently."

## Struct: Database

```
struct Database:
    pool    — connection pool (thread-safe, cloneable)
```

### connection

```
function connection() -> pooled_connection:
    → pool.get()
```

### transaction

"If the closure returns success, the transaction is committed.
If it returns failure, the transaction is rolled back."

```
function transaction(callback) -> T:
    conn = connection()
    tx = conn.begin_transaction()
    result = callback(tx)
    tx.commit()
    → result
```

### with_connection

```
function with_connection(callback) -> T:
    conn = connection()
    → callback(conn)
```

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 32     | 12         |
| Functions    | 3      | 3          |
