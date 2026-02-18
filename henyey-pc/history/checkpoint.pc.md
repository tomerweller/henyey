## Pseudocode: crates/history/src/checkpoint.rs

"Stellar history is organized into checkpoints — groups of 64 ledgers.
 Checkpoints are identified by their final ledger sequence number,
 which satisfies (seq + 1) % 64 == 0."

```
CONST CHECKPOINT_FREQUENCY = 64
```

NOTE: `checkpoint_ledger`, `is_checkpoint_ledger`, `checkpoint_path`,
`bucket_path`, and `has_path` are re-exported from `paths` module.

REF: paths::checkpoint_ledger, paths::is_checkpoint_ledger,
     paths::checkpoint_path, paths::bucket_path, paths::has_path

---

### latest_checkpoint_before_or_at

"Returns the latest checkpoint that is <= seq.
 If seq is before the first checkpoint (< 63), returns None."

```
function latest_checkpoint_before_or_at(seq):
  GUARD seq < CHECKPOINT_FREQUENCY - 1  → nil

  containing = checkpoint_ledger(seq)
  if seq == containing:
    → seq
  else:
    → containing - CHECKPOINT_FREQUENCY
```

### next_checkpoint

```
function next_checkpoint(seq):
  containing = checkpoint_ledger(seq)
  if seq < containing:
    → containing
  else:
    → containing + CHECKPOINT_FREQUENCY
```

### checkpoint_start

"Get the first ledger in the checkpoint containing seq."

```
function checkpoint_start(seq):
  → (seq / CHECKPOINT_FREQUENCY) * CHECKPOINT_FREQUENCY
```

NOTE: `first_ledger_in_checkpoint_containing` is an alias for `checkpoint_start`.

### last_ledger_before_checkpoint_containing

"Returns the ledger immediately before the checkpoint containing seq.
 Returns nil if seq is in the first checkpoint (ledgers 0–63)."

```
function last_ledger_before_checkpoint_containing(seq):
  start = checkpoint_start(seq)
  GUARD start == 0  → nil
  → start - 1
```

### size_of_checkpoint_containing

```
function size_of_checkpoint_containing(seq):
  → CHECKPOINT_FREQUENCY
```

### checkpoint_range

"Returns (start, end) inclusive range for a checkpoint."

```
function checkpoint_range(checkpoint_ledger_seq):
  ASSERT: is_checkpoint_ledger(checkpoint_ledger_seq)

  if checkpoint_ledger_seq < CHECKPOINT_FREQUENCY:
    start = 0
  else:
    start = checkpoint_ledger_seq - CHECKPOINT_FREQUENCY + 1

  → (start, checkpoint_ledger_seq)
```

### ledger_to_trigger_catchup

"Given the first ledger of a buffered checkpoint range, returns the
 ledger that should trigger catchup processing (first_ledger + 1).
 Matches stellar-core's LedgerManager::ledgerToTriggerCatchup."

```
function ledger_to_trigger_catchup(first_ledger_of_buffered_checkpoint):
  ASSERT: first_ledger_of_buffered_checkpoint % CHECKPOINT_FREQUENCY == 0

  → first_ledger_of_buffered_checkpoint + 1
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 100    | 42         |
| Functions     | 7      | 7          |
