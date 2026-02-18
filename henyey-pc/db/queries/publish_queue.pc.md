# Pseudocode: crates/db/src/queries/publish_queue.rs

"The publish queue tracks checkpoint ledgers that need to be published
to history archives. When a checkpoint is reached (every 64 ledgers),
the ledger is added to the queue. After successful publication, the
ledger is removed from the queue."

## Trait: PublishQueueQueries

### enqueue_publish

```
function enqueue_publish(ledger_seq):
    DB INSERT OR IGNORE INTO publishqueue
        (ledgerseq, state)
        VALUES (ledger_seq, 'pending')
```

### remove_publish

```
function remove_publish(ledger_seq):
    DB DELETE FROM publishqueue
        WHERE ledgerseq = ledger_seq
```

### load_publish_queue

```
function load_publish_queue(limit) -> list of integers:
    sql = "SELECT ledgerseq FROM publishqueue
           ORDER BY ledgerseq ASC"
    if limit is set:
        sql += " LIMIT limit"
    rows = DB EXECUTE sql
    → each row's ledgerseq as integer
```

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 33     | 15         |
| Functions    | 3      | 3          |
