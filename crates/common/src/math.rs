//! Math utilities for 128-bit arithmetic and safe operations.
//!
//! This module provides high-precision arithmetic functions needed for
//! transaction processing, fee calculations, and other financial operations
//! in Stellar.
//!
//! # Key Functions
//!
//! - [`big_divide`] / [`big_divide_or_throw`]: Calculate `A * B / C` using
//!   128-bit intermediate precision to avoid overflow
//! - [`saturating_multiply`]: Overflow-safe multiplication capped at `i64::MAX`
//! - [`saturating_add`]: Overflow-safe addition capped at type maximum
//! - [`big_square_root`]: Square root of `a * b` using 128-bit precision
//!
//! # Rounding
//!
//! Division functions support two rounding modes:
//! - [`Rounding::Down`]: Round toward zero (truncate)
//! - [`Rounding::Up`]: Round away from zero (ceiling)
//!
//! # Example
//!
//! ```
//! use henyey_common::math::{big_divide_or_throw, Rounding};
//!
//! // Calculate (large_a * large_b) / divisor without overflow
//! let result = big_divide_or_throw(1_000_000_000, 1_000_000, 1000, Rounding::Down);
//! assert_eq!(result.unwrap(), 1_000_000_000_000);
//! ```

use std::num::TryFromIntError;

/// Rounding mode for division operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rounding {
    /// Round toward zero (truncate).
    Down,
    /// Round away from zero (ceiling for positive results).
    Up,
}

/// Error type for math operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MathError {
    /// The result overflows the target type.
    Overflow,
    /// Division by zero was attempted.
    DivisionByZero,
    /// An input was negative when non-negative was required.
    NegativeInput,
}

impl std::fmt::Display for MathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MathError::Overflow => write!(f, "overflow while performing big divide"),
            MathError::DivisionByZero => write!(f, "division by zero"),
            MathError::NegativeInput => write!(f, "negative input where non-negative required"),
        }
    }
}

impl std::error::Error for MathError {}

impl From<TryFromIntError> for MathError {
    fn from(_: TryFromIntError) -> Self {
        MathError::Overflow
    }
}

/// Calculates `A * B / C` when `A * B` might overflow 64 bits.
///
/// Uses 128-bit intermediate arithmetic to avoid overflow during the
/// multiplication step.
///
/// # Arguments
///
/// * `a` - First multiplicand (must be >= 0)
/// * `b` - Second multiplicand (must be >= 0)
/// * `c` - Divisor (must be > 0)
/// * `rounding` - Whether to round down (truncate) or up (ceiling)
///
/// # Returns
///
/// Returns `Ok(result)` if the calculation succeeds and fits in `i64`.
/// Returns `Err(MathError)` if inputs are invalid or result overflows.
///
/// # Example
///
/// ```
/// use henyey_common::math::{big_divide, Rounding};
///
/// let result = big_divide(1_000_000_000, 1_000_000, 1000, Rounding::Down);
/// assert_eq!(result, Ok(1_000_000_000_000));
/// ```
pub fn big_divide(a: i64, b: i64, c: i64, rounding: Rounding) -> Result<i64, MathError> {
    if a < 0 || b < 0 {
        return Err(MathError::NegativeInput);
    }
    if c <= 0 {
        return Err(MathError::DivisionByZero);
    }

    let result = big_divide_unsigned(a as u64, b as u64, c as u64, rounding)?;

    if result > i64::MAX as u64 {
        return Err(MathError::Overflow);
    }

    Ok(result as i64)
}

/// Calculates `A * B / C` using unsigned arithmetic.
///
/// Uses 128-bit intermediate arithmetic to avoid overflow.
///
/// # Arguments
///
/// * `a` - First multiplicand
/// * `b` - Second multiplicand
/// * `c` - Divisor (must be > 0)
/// * `rounding` - Whether to round down or up
///
/// # Returns
///
/// Returns `Ok(result)` if the calculation fits in `u64`.
/// Returns `Err(MathError::Overflow)` if result is too large.
pub fn big_divide_unsigned(a: u64, b: u64, c: u64, rounding: Rounding) -> Result<u64, MathError> {
    if c == 0 {
        return Err(MathError::DivisionByZero);
    }

    let a128 = a as u128;
    let b128 = b as u128;
    let c128 = c as u128;

    let product = a128 * b128;

    let result = match rounding {
        Rounding::Down => product / c128,
        Rounding::Up => {
            // (a * b + c - 1) / c, but check for overflow
            let adjusted = product.checked_add(c128 - 1).ok_or(MathError::Overflow)?;
            adjusted / c128
        }
    };

    if result > u64::MAX as u128 {
        return Err(MathError::Overflow);
    }

    Ok(result as u64)
}

/// Calculates `A * B / C`, throwing on overflow.
///
/// This is the throwing variant of [`big_divide`]. Use this when overflow
/// should be treated as a programming error rather than a recoverable condition.
///
/// # Panics
///
/// Panics if inputs are invalid (negative A/B, non-positive C) or if the
/// result overflows `i64`.
///
/// # Example
///
/// ```
/// use henyey_common::math::{big_divide_or_throw, Rounding};
///
/// let result = big_divide_or_throw(1_000_000, 1_000_000, 1000, Rounding::Down);
/// assert_eq!(result.unwrap(), 1_000_000_000);
/// ```
pub fn big_divide_or_throw(a: i64, b: i64, c: i64, rounding: Rounding) -> Result<i64, MathError> {
    big_divide(a, b, c, rounding)
}

/// Divides a 128-bit value by a 64-bit divisor.
///
/// Used when the numerator is already a 128-bit product.
///
/// # Arguments
///
/// * `a` - 128-bit numerator
/// * `b` - 64-bit divisor (must be > 0)
/// * `rounding` - Whether to round down or up
pub fn big_divide_128(a: u128, b: i64, rounding: Rounding) -> Result<i64, MathError> {
    if b <= 0 {
        return Err(MathError::DivisionByZero);
    }

    let result = big_divide_unsigned_128(a, b as u64, rounding)?;

    if result > i64::MAX as u64 {
        return Err(MathError::Overflow);
    }

    Ok(result as i64)
}

/// Divides a 128-bit value by a 64-bit unsigned divisor.
pub fn big_divide_unsigned_128(a: u128, b: u64, rounding: Rounding) -> Result<u64, MathError> {
    if b == 0 {
        return Err(MathError::DivisionByZero);
    }

    let b128 = b as u128;

    let result = match rounding {
        Rounding::Down => a / b128,
        Rounding::Up => {
            // Check for overflow in div_ceil
            if a > u128::MAX - (b128 - 1) {
                return Err(MathError::Overflow);
            }
            a.div_ceil(b128)
        }
    };

    if result > u64::MAX as u128 {
        return Err(MathError::Overflow);
    }

    Ok(result as u64)
}

/// Multiplies two u64 values, returning a u128 result.
///
/// This cannot overflow since u64 * u64 always fits in u128.
#[inline]
pub fn big_multiply_unsigned(a: u64, b: u64) -> u128 {
    (a as u128) * (b as u128)
}

/// Multiplies two non-negative i64 values, returning a u128 result.
///
/// # Panics
///
/// Panics if either input is negative.
#[inline]
pub fn big_multiply(a: i64, b: i64) -> u128 {
    assert!(
        a >= 0 && b >= 0,
        "big_multiply requires non-negative inputs"
    );
    big_multiply_unsigned(a as u64, b as u64)
}

/// Saturating multiplication: returns `a * b`, capped at `i64::MAX` on overflow.
///
/// Both inputs must be non-negative.
///
/// # Arguments
///
/// * `a` - First multiplicand (must be >= 0)
/// * `b` - Second multiplicand (must be >= 0)
///
/// # Returns
///
/// Returns `a * b` if it fits in `i64`, otherwise `i64::MAX`.
///
/// # Panics
///
/// Panics if either input is negative.
///
/// # Example
///
/// ```
/// use henyey_common::math::saturating_multiply;
///
/// assert_eq!(saturating_multiply(1000, 1000), 1_000_000);
/// assert_eq!(saturating_multiply(i64::MAX, 2), i64::MAX); // Saturates
/// ```
pub fn saturating_multiply(a: i64, b: i64) -> i64 {
    assert!(
        a >= 0 && b >= 0,
        "saturating_multiply requires non-negative inputs"
    );

    if a == 0 || b == 0 {
        return 0;
    }

    // Check if multiplication would overflow
    if a > i64::MAX / b {
        return i64::MAX;
    }

    a * b
}

/// Saturating addition: returns `a + b`, capped at type maximum on overflow.
///
/// # Example
///
/// ```
/// use henyey_common::math::saturating_add;
///
/// assert_eq!(saturating_add(100u64, 200u64), 300u64);
/// assert_eq!(saturating_add(u64::MAX, 1u64), u64::MAX); // Saturates
/// ```
#[inline]
pub fn saturating_add<T: SaturatingOps>(a: T, b: T) -> T {
    a.saturating_add(b)
}

/// Trait extension for saturating arithmetic.
pub trait SaturatingOps: Sized {
    /// Saturating addition.
    fn saturating_add(self, rhs: Self) -> Self;
}

impl SaturatingOps for u64 {
    #[inline]
    fn saturating_add(self, rhs: Self) -> Self {
        u64::saturating_add(self, rhs)
    }
}

impl SaturatingOps for u32 {
    #[inline]
    fn saturating_add(self, rhs: Self) -> Self {
        u32::saturating_add(self, rhs)
    }
}

impl SaturatingOps for i64 {
    #[inline]
    fn saturating_add(self, rhs: Self) -> Self {
        i64::saturating_add(self, rhs)
    }
}

/// Checks if a double can be safely converted to i64.
///
/// Returns true if the double value can be represented as an i64 without
/// undefined behavior.
pub fn is_representable_as_i64(d: f64) -> bool {
    d >= (i64::MIN as f64) && d < (i64::MAX as f64)
}

/// Converts a double to u32, clamping to the valid range.
///
/// NaN is converted to `u32::MAX`.
pub fn double_to_clamped_u32(d: f64) -> u32 {
    if d.is_nan() {
        return u32::MAX;
    }
    d.clamp(0.0, u32::MAX as f64) as u32
}

/// Computes the integer square root of `a * b`.
///
/// Returns x such that `x * x <= a * b < (x + 1) * (x + 1)`.
///
/// Uses the modified Babylonian method with 128-bit precision.
pub fn big_square_root(a: u64, b: u64) -> u64 {
    if a == 0 || b == 0 {
        return 0;
    }

    let sqrt_ceil = big_square_root_ceil(a, b);

    // Check if sqrt_ceil is exact
    if big_multiply_unsigned(sqrt_ceil, sqrt_ceil) <= big_multiply_unsigned(a, b) {
        return sqrt_ceil;
    }

    // sqrt_ceil > 0 because 0*0 <= a*b for all a, b
    sqrt_ceil - 1
}

/// Computes ceil(sqrt(a * b)) using the modified Babylonian method.
fn big_square_root_ceil(a: u64, b: u64) -> u64 {
    if a == 0 || b == 0 {
        return 0;
    }

    // R = a * b - 1
    let r = big_multiply_unsigned(a, b) - 1;

    // Seed with a reasonable estimate: 2^(ceil(bits/2))
    let num_bits = 128 - r.leading_zeros();
    let seed_bits = num_bits.div_ceil(2);
    let mut x = if seed_bits >= 64 {
        u64::MAX
    } else {
        1u64 << seed_bits
    };

    let mut prev = 0u64;
    while x != prev {
        prev = x;

        // y = ceil(R / x)
        let y = match big_divide_unsigned_128(r, x, Rounding::Up) {
            Ok(v) => v,
            Err(_) => return x, // Overflow means we're done
        };

        // x = ceil((x + y) / 2)
        if u64::MAX - x <= y {
            // Handle potential overflow
            let temp = (x as u128) + (y as u128);
            x = temp.div_ceil(2) as u64;
        } else {
            x = (x + y).div_ceil(2);
        }
    }

    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_big_divide_basic() {
        // Simple case: 10 * 20 / 5 = 40
        assert_eq!(big_divide(10, 20, 5, Rounding::Down), Ok(40));
        assert_eq!(big_divide(10, 20, 5, Rounding::Up), Ok(40));
    }

    #[test]
    fn test_big_divide_rounding() {
        // 10 * 3 / 4 = 7.5 -> 7 (down) or 8 (up)
        assert_eq!(big_divide(10, 3, 4, Rounding::Down), Ok(7));
        assert_eq!(big_divide(10, 3, 4, Rounding::Up), Ok(8));

        // 7 / 3 = 2.333... -> 2 (down) or 3 (up)
        assert_eq!(big_divide(7, 1, 3, Rounding::Down), Ok(2));
        assert_eq!(big_divide(7, 1, 3, Rounding::Up), Ok(3));
    }

    #[test]
    fn test_big_divide_large_numbers() {
        // Large multiplication that would overflow i64
        let a = 1_000_000_000_000i64;
        let b = 1_000_000_000i64;
        let c = 1_000_000i64;
        // a * b = 10^21, / c = 10^15
        assert_eq!(
            big_divide(a, b, c, Rounding::Down),
            Ok(1_000_000_000_000_000)
        );
    }

    #[test]
    fn test_big_divide_overflow() {
        // Result too large for i64
        let a = i64::MAX;
        let b = 2;
        let c = 1;
        assert_eq!(
            big_divide(a, b, c, Rounding::Down),
            Err(MathError::Overflow)
        );
    }

    #[test]
    fn test_big_divide_negative_inputs() {
        assert_eq!(
            big_divide(-1, 1, 1, Rounding::Down),
            Err(MathError::NegativeInput)
        );
        assert_eq!(
            big_divide(1, -1, 1, Rounding::Down),
            Err(MathError::NegativeInput)
        );
    }

    #[test]
    fn test_big_divide_zero_divisor() {
        assert_eq!(
            big_divide(1, 1, 0, Rounding::Down),
            Err(MathError::DivisionByZero)
        );
        assert_eq!(
            big_divide(1, 1, -1, Rounding::Down),
            Err(MathError::DivisionByZero)
        );
    }

    #[test]
    fn test_saturating_multiply() {
        assert_eq!(saturating_multiply(1000, 1000), 1_000_000);
        assert_eq!(saturating_multiply(0, 1000), 0);
        assert_eq!(saturating_multiply(1000, 0), 0);

        // Overflow should saturate
        assert_eq!(saturating_multiply(i64::MAX, 2), i64::MAX);
        assert_eq!(saturating_multiply(i64::MAX / 2 + 1, 2), i64::MAX);
    }

    #[test]
    #[should_panic]
    fn test_saturating_multiply_negative() {
        saturating_multiply(-1, 1);
    }

    #[test]
    fn test_saturating_add() {
        assert_eq!(saturating_add(100u64, 200u64), 300u64);
        assert_eq!(saturating_add(u64::MAX, 1u64), u64::MAX);
        assert_eq!(saturating_add(u64::MAX - 10, 20u64), u64::MAX);
    }

    #[test]
    fn test_is_representable_as_i64() {
        assert!(is_representable_as_i64(0.0));
        assert!(is_representable_as_i64(1000.0));
        assert!(is_representable_as_i64(-1000.0));
        assert!(is_representable_as_i64(i64::MIN as f64));
        assert!(!is_representable_as_i64(f64::MAX));
        assert!(!is_representable_as_i64(f64::MIN));
    }

    #[test]
    fn test_double_to_clamped_u32() {
        assert_eq!(double_to_clamped_u32(100.0), 100);
        assert_eq!(double_to_clamped_u32(0.0), 0);
        assert_eq!(double_to_clamped_u32(-100.0), 0);
        assert_eq!(double_to_clamped_u32(f64::MAX), u32::MAX);
        assert_eq!(double_to_clamped_u32(f64::NAN), u32::MAX);
    }

    #[test]
    fn test_big_multiply() {
        assert_eq!(big_multiply_unsigned(1000, 1000), 1_000_000u128);
        assert_eq!(
            big_multiply_unsigned(u64::MAX, u64::MAX),
            (u64::MAX as u128) * (u64::MAX as u128)
        );
    }

    #[test]
    fn test_big_square_root() {
        // sqrt(100) = 10
        assert_eq!(big_square_root(100, 1), 10);
        assert_eq!(big_square_root(10, 10), 10);

        // sqrt(99) = 9 (floor)
        assert_eq!(big_square_root(99, 1), 9);

        // sqrt(0) = 0
        assert_eq!(big_square_root(0, 100), 0);
        assert_eq!(big_square_root(100, 0), 0);

        // sqrt(1) = 1
        assert_eq!(big_square_root(1, 1), 1);

        // sqrt(4) = 2
        assert_eq!(big_square_root(4, 1), 2);
        assert_eq!(big_square_root(2, 2), 2);
    }

    #[test]
    fn test_big_square_root_large() {
        // sqrt(10^18) = 10^9
        let result = big_square_root(1_000_000_000, 1_000_000_000);
        assert_eq!(result, 1_000_000_000);

        // sqrt(10^18 - 1) should be 10^9 - 1 or close
        let result = big_square_root(999_999_999, 1_000_000_001);
        // 999999999 * 1000000001 = 10^18 - 1
        // sqrt should be very close to 10^9
        assert!(result >= 999_999_999 && result <= 1_000_000_000);
    }

    #[test]
    fn test_big_divide_unsigned() {
        assert_eq!(big_divide_unsigned(10, 20, 5, Rounding::Down), Ok(40));
        assert_eq!(
            big_divide_unsigned(u64::MAX, 2, 2, Rounding::Down),
            Ok(u64::MAX)
        );
    }

    #[test]
    fn test_big_divide_128() {
        let product = big_multiply_unsigned(1_000_000, 1_000_000);
        assert_eq!(
            big_divide_128(product, 1000, Rounding::Down),
            Ok(1_000_000_000)
        );
    }
}
