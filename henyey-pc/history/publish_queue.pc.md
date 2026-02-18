## Pseudocode: crates/history/src/publish_queue.rs

"Persistent publish queue for history archive publishing.
 Crash-safe checkpoint queuing backed by SQLite."

"When a validator closes a checkpoint ledger, it:
 1. Queues the checkpoint with its HistoryArchiveState to the database
 2. Publishes the checkpoint files to history archives
 3. Dequeues the checkpoint after successful publication"

"Database schema:
 CREATE TABLE publishqueue (
   ledgerseq INTEGER PRIMARY KEY,
   state TEXT NOT NULL
 );"

---

### PublishQueue (struct)

```
STRUCT PublishQueue:
  db : Database (shared)
```

### new

```
function new(db):
  → PublishQueue { db }
```

### len

```
function len(self):
  → db.query("SELECT COUNT(*) FROM publishqueue")
```

### is_empty

```
function is_empty(self):
  → self.len() == 0
```

### min_ledger

```
function min_ledger(self):
  → db.query("SELECT MIN(ledgerseq) FROM publishqueue")
    // nil if queue is empty
```

### max_ledger

```
function max_ledger(self):
  → db.query("SELECT MAX(ledgerseq) FROM publishqueue")
    // nil if queue is empty
```

### ledger_range

"Returns (min, max) or (0, 0) if empty."

```
function ledger_range(self):
  min = self.min_ledger() or 0
  max = self.max_ledger() or 0
  → (min, max)
```

### enqueue

"Store checkpoint and its HAS for pending publication.
 No-op if checkpoint is already in the queue (INSERT OR REPLACE)."

```
function enqueue(self, ledger_seq, has):
  GUARD not is_checkpoint_ledger(ledger_seq)
    → error NotCheckpointLedger(ledger_seq)

  state_json = serialize_json(has)

  db.execute(
    "INSERT OR REPLACE INTO publishqueue
     (ledgerseq, state) VALUES (?1, ?2)",
    [ledger_seq, state_json])

  → ok
```

**Calls**: [is_checkpoint_ledger](checkpoint.pc.md#is_checkpoint_ledger)

### dequeue

"Remove checkpoint after successful publication.
 No-op if checkpoint is not in the queue."

```
function dequeue(self, ledger_seq):
  db.execute(
    "DELETE FROM publishqueue WHERE ledgerseq = ?1",
    [ledger_seq])
  → ok
```

### contains

```
function contains(self, ledger_seq):
  count = db.query(
    "SELECT COUNT(*) FROM publishqueue
     WHERE ledgerseq = ?1",
    [ledger_seq])
  → count > 0
```

### get_state

"Returns the HistoryArchiveState for a queued checkpoint,
 or nil if not found."

```
function get_state(self, ledger_seq):
  json = db.query(
    "SELECT state FROM publishqueue
     WHERE ledgerseq = ?1",
    [ledger_seq])

  if no rows found:
    → nil

  → deserialize_json(json) as HistoryArchiveState
```

### get_all

"Returns all queued checkpoints in ascending ledger order."

```
function get_all(self):
  rows = db.query(
    "SELECT ledgerseq, state FROM publishqueue
     ORDER BY ledgerseq ASC")

  results = []
  for each (ledger_seq, json) in rows:
    has = deserialize_json(json) as HistoryArchiveState
    results.append((ledger_seq, has))

  → results
```

### get_referenced_bucket_hashes

"Collect all bucket hashes referenced by queued checkpoints.
 Used to determine which buckets must be retained until published."

```
function get_referenced_bucket_hashes(self):
  checkpoints = self.get_all()
  hashes = new Set()

  for each (_, has) in checkpoints:
    for each bucket_hash in has.all_bucket_hashes():
      hashes.add(bucket_hash.to_hex())

  → hashes
```

### clear

```
function clear(self):
  db.execute("DELETE FROM publishqueue")
  → ok
```

### log_status

```
function log_status(self):
  len = self.len()
  if len == 0:
    log "Publish queue empty"
  else:
    (min, max) = self.ledger_range()
    log "Publish queue status: {len} checkpoints
         [{min}-{max}]"
  → ok
```

---

### PublishQueueStats (struct)

```
STRUCT PublishQueueStats:
  queue_length : integer
  min_ledger   : integer
  max_ledger   : integer
  bucket_count : integer
```

### stats

```
function stats(self):
  queue_length = self.len()
  (min_ledger, max_ledger) = self.ledger_range()
  bucket_count = length(self.get_referenced_bucket_hashes())

  → PublishQueueStats {
      queue_length, min_ledger, max_ledger, bucket_count }
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 336    | 112        |
| Functions     | 15     | 15         |
