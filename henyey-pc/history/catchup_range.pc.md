## Pseudocode: crates/history/src/catchup_range.rs

"Catchup range calculation for history synchronization.
 Implements the stellar-core algorithm for determining which ledgers
 to download and replay during catchup operations."

"The algorithm handles five cases:
 | Case | Condition                        | Action                                      |
 | 1    | LCL > genesis                    | Replay from LCL+1 to target (no buckets)   |
 | 2    | count >= full replay count       | Full replay from genesis+1                  |
 | 3    | count=0 AND target is checkpoint | Buckets only, no replay                     |
 | 4    | target start in first checkpoint | Full replay from genesis+1                  |
 | 5    | default                          | Apply buckets at prior checkpoint, replay   |"

```
CONST GENESIS_LEDGER_SEQ = 1
```

---

### LedgerRange (struct)

"A half-open range of ledgers [first, first+count)."

```
STRUCT LedgerRange:
  first : integer
  count : integer
```

### LedgerRange.new

```
function new(first, count):
  → LedgerRange { first, count }
```

### LedgerRange.empty

```
function empty():
  → LedgerRange { first: 0, count: 0 }
```

### LedgerRange.is_empty

```
function is_empty(self):
  → self.count == 0
```

### LedgerRange.limit

```
function limit(self):
  → self.first + self.count
```

### LedgerRange.last

```
function last(self):
  ASSERT: self.count > 0
  → self.first + self.count - 1
```

---

### CatchupMode (enum)

```
ENUM CatchupMode:
  Minimal           // count = 0
  Complete          // count = MAX_U32
  Recent(n)         // count = n
```

### CatchupMode.count

```
function count(self):
  if self is Minimal:  → 0
  if self is Complete: → MAX_U32
  if self is Recent(n): → n
```

### CatchupMode.from_str

```
function from_str(s):
  if lowercase(s) == "minimal":  → Minimal
  if lowercase(s) == "complete": → Complete
  if s starts_with "recent:":
    n = parse_integer(strip_prefix(s, "recent:"))
    → Recent(n)
  → error("Unknown catchup mode")
```

---

### CatchupRange (struct)

```
STRUCT CatchupRange:
  apply_buckets            : boolean
  apply_buckets_at_ledger  : integer   // 0 if !apply_buckets
  replay_range             : LedgerRange
```

### CatchupRange.buckets_only

```
function buckets_only(apply_at):
  range = CatchupRange {
    apply_buckets: true,
    apply_buckets_at_ledger: apply_at,
    replay_range: LedgerRange.empty()
  }
  range.check_invariants()
  → range
```

### CatchupRange.replay_only

```
function replay_only(replay_range):
  range = CatchupRange {
    apply_buckets: false,
    apply_buckets_at_ledger: 0,
    replay_range: replay_range
  }
  range.check_invariants()
  → range
```

### CatchupRange.buckets_and_replay

```
function buckets_and_replay(apply_at, replay_range):
  range = CatchupRange {
    apply_buckets: true,
    apply_buckets_at_ledger: apply_at,
    replay_range: replay_range
  }
  range.check_invariants()
  → range
```

### CatchupRange.calculate

```
function calculate(lcl, target, mode):
  ASSERT: lcl >= GENESIS_LEDGER_SEQ
  ASSERT: target > lcl
  ASSERT: target > GENESIS_LEDGER_SEQ

  count = mode.count()
  full_replay_count = target - lcl

  // "Case 1: LCL is past genesis, replay from LCL+1"
  if lcl > GENESIS_LEDGER_SEQ:
    replay = LedgerRange.new(lcl + 1, full_replay_count)
    → replay_only(replay)

  ASSERT: lcl == GENESIS_LEDGER_SEQ
  full_replay = LedgerRange.new(
    GENESIS_LEDGER_SEQ + 1, full_replay_count)

  // "Case 2: count >= full replay count, do full replay"
  if count >= full_replay_count:
    → replay_only(full_replay)

  // "Case 3: count=0 and target is a checkpoint, buckets only"
  if count == 0 AND is_checkpoint_ledger(target):
    → buckets_only(target)

  // Calculate target start ledger (first ledger to replay)
  target_start = saturating_sub(target, count) + 1
  first_in_cp = first_ledger_in_checkpoint_containing(target_start)

  // "Case 4: target start is in first checkpoint, full replay"
  if first_in_cp <= GENESIS_LEDGER_SEQ:
    → replay_only(full_replay)

  // "Case 5: apply buckets at checkpoint before
  //  target_start, then replay"
  apply_at = last_ledger_before_checkpoint_containing(
               target_start)
  replay = LedgerRange.new(first_in_cp, target - apply_at)
  → buckets_and_replay(apply_at, replay)
```

**Calls**: [is_checkpoint_ledger](checkpoint.pc.md#is_checkpoint_ledger), [first_ledger_in_checkpoint_containing](checkpoint.pc.md#checkpoint_start), [last_ledger_before_checkpoint_containing](checkpoint.pc.md#last_ledger_before_checkpoint_containing)

### Helper: check_invariants

```
function check_invariants(self):
  ASSERT: self.apply_buckets OR self.replay_ledgers()

  if not self.apply_buckets AND self.replay_ledgers():
    // "Cases 1, 2, 4: no buckets, only replay"
    ASSERT: self.apply_buckets_at_ledger == 0
    ASSERT: self.replay_range.first != 0

  else if self.apply_buckets AND self.replay_ledgers():
    // "Case 5: buckets and replay"
    ASSERT: self.apply_buckets_at_ledger != 0
    ASSERT: self.replay_range.first != 0
    ASSERT: self.apply_buckets_at_ledger + 1
            == self.replay_range.first
    // "replay must start immediately after bucket apply"

  else:
    // "Case 3: buckets only, no replay"
    ASSERT: self.apply_buckets AND not self.replay_ledgers()
    ASSERT: self.replay_range.first == 0
```

### Accessors

```
function apply_buckets(self):       → self.apply_buckets
function bucket_apply_ledger(self):
  ASSERT: self.apply_buckets
  → self.apply_buckets_at_ledger
function replay_ledgers(self):      → self.replay_range.count > 0
function replay_range(self):        → self.replay_range
function replay_first(self):        → self.replay_range.first
function replay_count(self):        → self.replay_range.count
function replay_limit(self):        → self.replay_range.limit()

function first(self):
  if self.apply_buckets:
    → self.apply_buckets_at_ledger
  else:
    → self.replay_range.first

function last(self):
  if self.replay_range.count > 0:
    → self.replay_range.last()
  else:
    ASSERT: self.apply_buckets
    → self.apply_buckets_at_ledger

function count(self):
  if self.apply_buckets:
    → self.replay_range.count + 1
  else:
    → self.replay_range.count
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 348    | 149        |
| Functions     | 21     | 21         |
