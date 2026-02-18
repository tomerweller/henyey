# Pseudocode: crates/common/src/resource.rs

"Resource accounting for surge pricing and transaction limits."

## Constants

```
CONST NUM_CLASSIC_TX_RESOURCES       = 1  // operations only
CONST NUM_CLASSIC_TX_BYTES_RESOURCES = 2  // operations + bytes
CONST NUM_SOROBAN_TX_RESOURCES       = 7  // ops, instructions, bytes, disk reads, writes, read entries, write entries

ENUM ResourceType:
  Operations        = 0
  Instructions      = 1
  TxByteSize        = 2
  DiskReadBytes     = 3
  WriteBytes        = 4
  ReadLedgerEntries = 5
  WriteLedgerEntries = 6
```

## Data

```
STRUCT Resource:
  values : list<i64>   // length must be 1, 2, or 7
```

### Resource.new

```
function Resource.new(values) -> Resource:
  ASSERT: len(values) in {1, 2, 7}
  -> Resource { values }
```

### make_empty

```
function make_empty(count) -> Resource:
  -> Resource.new(zeroes of length count)
```

### make_empty_soroban

```
function make_empty_soroban() -> Resource:
  -> make_empty(7)
```

**Calls**: [make_empty](#make_empty)

### is_zero

```
function is_zero(self) -> bool:
  -> all values == 0
```

### any_positive

```
function any_positive(self) -> bool:
  -> any value > 0
```

### get_val / try_get_val

```
function get_val(self, type) -> i64:
  -> self.values[type as index]

function try_get_val(self, type) -> optional<i64>:
  -> self.values[type as index] if in bounds, else none
```

### set_val / try_set_val

```
function set_val(self, type, val):
  MUTATE self values[type as index] = val

function try_set_val(self, type, val) -> bool:
  if type in bounds:
    MUTATE self values[type as index] = val
    -> true
  -> false
```

### can_add

```
function can_add(self, other) -> bool:
  -> for all i: self.values[i] + other.values[i] does not overflow
```

### leq

"All dimensions of self <= corresponding dimensions of other."

```
function leq(self, other) -> bool:
  -> for all i: self.values[i] <= other.values[i]
```

### Arithmetic operators

```
function add(self, other) -> Resource:
  -> Resource where values[i] = self.values[i] + other.values[i]

function subtract(self, other) -> Resource:
  -> Resource where values[i] = self.values[i] - other.values[i]
```

### partial_cmp

"Two resources are comparable only if same number of dimensions."
"Partial order: all_le AND all_ge = Equal; all_le = Less; all_ge = Greater; else incomparable."

```
function partial_cmp(self, other) -> optional<Ordering>:
  all_le = self.leq(other)
  all_ge = other.leq(self)
  if all_le AND all_ge:  -> Equal
  if all_le:             -> Less
  if all_ge:             -> Greater
  -> none
```

**Calls**: [leq](#leq)

### any_less_than

```
function any_less_than(lhs, rhs) -> bool:
  -> any i where lhs.values[i] < rhs.values[i]
```

### any_greater

```
function any_greater(lhs, rhs) -> bool:
  -> any i where lhs.values[i] > rhs.values[i]
```

### subtract_non_negative

"Subtract, clamping each dimension to minimum 0."

```
function subtract_non_negative(lhs, rhs) -> Resource:
  -> Resource where values[i] = max(lhs[i] - rhs[i], 0)
```

### limit_to

"Clamp each dimension to a ceiling."

```
function limit_to(current, limit) -> Resource:
  -> Resource where values[i] = min(current[i], limit[i])
```

### multiply_by_double

```
function multiply_by_double(res, m) -> Resource:
  for each value v in res:
    result = v * m
    ASSERT: result >= 0
    ASSERT: is_representable_as_i64(result)
  -> Resource with scaled values
```

**Calls**: [is_representable_as_i64](math.pc.md#is_representable_as_i64)

### saturated_multiply_by_double

"Like multiply_by_double but saturates at I64_MAX instead of failing."

```
function saturated_multiply_by_double(res, m) -> Resource:
  for each value v in res:
    result = v * m
    ASSERT: result >= 0
    if not is_representable_as_i64(result):
      result = I64_MAX
  -> Resource with scaled values
```

**Calls**: [is_representable_as_i64](math.pc.md#is_representable_as_i64)

### big_divide_resource

"(resource * b) / c per dimension using 128-bit intermediate."

```
function big_divide_resource(res, b, c, rounding) -> Resource:
  for each value v in res:
    values[i] = big_divide_or_throw(v, b, c, rounding)
  -> Resource with divided values
```

**Calls**: [big_divide_or_throw](math.pc.md#big_divide_or_throw)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 185    | 100        |
| Functions     | 21     | 21         |
