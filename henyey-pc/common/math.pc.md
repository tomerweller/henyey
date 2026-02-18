# Pseudocode: crates/common/src/math.rs

"128-bit arithmetic and overflow-safe math operations."

## Types

```
ENUM Rounding:
  Down   "Round toward zero (truncate)"
  Up     "Round away from zero (ceiling)"

ENUM MathError:
  Overflow
  DivisionByZero
  NegativeInput
```

### big_divide

"Calculate A * B / C using 128-bit intermediate precision."

```
function big_divide(a: i64, b: i64, c: i64, rounding) -> i64:
  GUARD a < 0 OR b < 0   -> error(NegativeInput)
  GUARD c <= 0            -> error(DivisionByZero)

  result = big_divide_unsigned(a as u64, b as u64, c as u64, rounding)

  GUARD result > I64_MAX  -> error(Overflow)
  -> result as i64
```

**Calls**: [big_divide_unsigned](#big_divide_unsigned)

### big_divide_unsigned

"Calculate A * B / C using unsigned 128-bit intermediate."

```
function big_divide_unsigned(a: u64, b: u64, c: u64, rounding) -> u64:
  GUARD c == 0  -> error(DivisionByZero)

  product = (a as u128) * (b as u128)

  if rounding == Down:
    result = product / c
  if rounding == Up:
    adjusted = product + (c - 1)
    GUARD adjusted overflows u128  -> error(Overflow)
    result = adjusted / c

  GUARD result > U64_MAX  -> error(Overflow)
  -> result as u64
```

### big_divide_or_throw

```
function big_divide_or_throw(a, b, c, rounding) -> i64:
  -> big_divide(a, b, c, rounding)
```

**Calls**: [big_divide](#big_divide)

### big_divide_128

"Divide a 128-bit numerator by a 64-bit divisor."

```
function big_divide_128(a: u128, b: i64, rounding) -> i64:
  GUARD b <= 0            -> error(DivisionByZero)

  result = big_divide_unsigned_128(a, b as u64, rounding)

  GUARD result > I64_MAX  -> error(Overflow)
  -> result as i64
```

**Calls**: [big_divide_unsigned_128](#big_divide_unsigned_128)

### big_divide_unsigned_128

```
function big_divide_unsigned_128(a: u128, b: u64, rounding) -> u64:
  GUARD b == 0  -> error(DivisionByZero)

  if rounding == Down:
    result = a / b
  if rounding == Up:
    GUARD a > U128_MAX - (b - 1)  -> error(Overflow)
    result = ceiling_divide(a, b)

  GUARD result > U64_MAX  -> error(Overflow)
  -> result as u64
```

### big_multiply_unsigned

"u64 * u64 -> u128, cannot overflow."

```
function big_multiply_unsigned(a: u64, b: u64) -> u128:
  -> (a as u128) * (b as u128)
```

### big_multiply

```
function big_multiply(a: i64, b: i64) -> u128:
  ASSERT: a >= 0 AND b >= 0
  -> big_multiply_unsigned(a as u64, b as u64)
```

**Calls**: [big_multiply_unsigned](#big_multiply_unsigned)

### saturating_multiply

"Returns a * b, capped at I64_MAX on overflow."

```
function saturating_multiply(a: i64, b: i64) -> i64:
  ASSERT: a >= 0 AND b >= 0

  if a == 0 OR b == 0:
    -> 0

  "Check if multiplication would overflow"
  if a > I64_MAX / b:
    -> I64_MAX

  -> a * b
```

### saturating_add

```
function saturating_add(a, b) -> T:
  -> min(a + b, T_MAX)
```

### is_representable_as_i64

```
function is_representable_as_i64(d: double) -> bool:
  -> d >= I64_MIN AND d < I64_MAX
```

### double_to_clamped_u32

"NaN converts to U32_MAX."

```
function double_to_clamped_u32(d: double) -> u32:
  if d is NaN:
    -> U32_MAX
  -> clamp(d, 0.0, U32_MAX) as u32
```

### big_square_root

"Integer sqrt(a * b) using modified Babylonian method."

```
function big_square_root(a: u64, b: u64) -> u64:
  if a == 0 OR b == 0:
    -> 0

  sqrt_ceil = big_square_root_ceil(a, b)

  "Check if sqrt_ceil is exact"
  if sqrt_ceil * sqrt_ceil <= a * b:
    -> sqrt_ceil

  -> sqrt_ceil - 1
```

**Calls**: [big_square_root_ceil](#helper-big_square_root_ceil) | [big_multiply_unsigned](#big_multiply_unsigned)

## Helper: big_square_root_ceil

"ceil(sqrt(a * b)) via modified Babylonian method with 128-bit precision."

```
function big_square_root_ceil(a: u64, b: u64) -> u64:
  if a == 0 OR b == 0:
    -> 0

  R = (a * b) - 1                            // 128-bit

  "Seed with 2^(ceil(bits/2))"
  num_bits = 128 - leading_zeros(R)
  seed_bits = ceiling_divide(num_bits, 2)
  if seed_bits >= 64:
    x = U64_MAX
  else:
    x = 1 << seed_bits

  prev = 0
  while x != prev:
    prev = x
    y = ceiling_divide(R, x)                  // 128-bit division
    x = ceiling_divide(x + y, 2)              // handle u64 overflow via u128

  -> x
```

**Calls**: [big_divide_unsigned_128](#big_divide_unsigned_128)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 180    | 100        |
| Functions     | 13     | 13         |
