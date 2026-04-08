//! Checked arithmetic types for consensus-critical financial operations.
//!
//! These newtypes enforce explicit checked arithmetic at compile time by
//! deliberately NOT implementing `Add`, `Sub`, `AddAssign`, `SubAssign`,
//! or other arithmetic operator traits. Code that attempts `balance -= fee`
//! will fail to compile — callers must use `checked_sub()`, `saturating_sub()`,
//! etc. instead.
//!
//! This prevents the class of bugs found in AUDIT-004/#1106 (fee deduction
//! without balance cap), #1121 (num_sub_entries underflow), and similar
//! silent arithmetic errors in consensus-critical paths.

use std::fmt;

use stellar_xdr::curr::{
    AccountEntry, AccountEntryExt, Liabilities, TrustLineEntry, TrustLineEntryExt,
};

/// Error type for checked arithmetic operations on consensus-critical values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalanceError {
    /// Addition would exceed `i64::MAX`.
    Overflow,
    /// Subtraction would go below zero (or below `i64::MIN` for signed).
    Underflow,
    /// New balance would violate buying/selling liability constraints.
    LiabilityViolation,
    /// New trustline balance would exceed the trustline limit.
    ExceedsLimit,
}

impl fmt::Display for BalanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BalanceError::Overflow => write!(f, "arithmetic overflow"),
            BalanceError::Underflow => write!(f, "arithmetic underflow"),
            BalanceError::LiabilityViolation => write!(f, "liability constraint violated"),
            BalanceError::ExceedsLimit => write!(f, "exceeds limit"),
        }
    }
}

impl std::error::Error for BalanceError {}

/// Checked wrapper for `i64` balance and amount fields in consensus-critical code.
///
/// Covers: account balance, trustline balance, liquidity pool reserves,
/// pool shares, liabilities, and other financial `i64` values.
///
/// # Compile-time enforcement
///
/// This type deliberately does NOT implement `Add`, `Sub`, `AddAssign`,
/// `SubAssign`, `Mul`, `Div`, or any other arithmetic operator trait.
/// Attempting `amount + other` or `amount -= delta` is a compile error.
///
/// Instead, use the explicit checked/saturating methods:
/// ```ignore
/// let balance = CheckedAmount::new(account.balance);
/// let new_balance = balance.checked_sub(fee).ok_or(BalanceError::Underflow)?;
/// account.balance = new_balance.value();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CheckedAmount(i64);

impl CheckedAmount {
    /// Create a new `CheckedAmount` from a raw `i64`.
    pub fn new(value: i64) -> Self {
        Self(value)
    }

    /// Extract the inner `i64` value.
    pub fn value(self) -> i64 {
        self.0
    }

    /// Checked addition. Returns `None` on overflow.
    pub fn checked_add(self, rhs: i64) -> Option<Self> {
        self.0.checked_add(rhs).map(Self)
    }

    /// Checked subtraction. Returns `None` on underflow.
    pub fn checked_sub(self, rhs: i64) -> Option<Self> {
        self.0.checked_sub(rhs).map(Self)
    }

    /// Checked multiplication. Returns `None` on overflow.
    pub fn checked_mul(self, rhs: i64) -> Option<Self> {
        self.0.checked_mul(rhs).map(Self)
    }

    /// Checked division. Returns `None` on division by zero.
    pub fn checked_div(self, rhs: i64) -> Option<Self> {
        self.0.checked_div(rhs).map(Self)
    }

    /// Saturating addition. Clamps at `i64::MAX` on overflow.
    pub fn saturating_add(self, rhs: i64) -> Self {
        Self(self.0.saturating_add(rhs))
    }

    /// Saturating subtraction. Clamps at `i64::MIN` on underflow.
    pub fn saturating_sub(self, rhs: i64) -> Self {
        Self(self.0.saturating_sub(rhs))
    }

    /// Returns the minimum of `self` and `other`.
    pub fn min(self, other: Self) -> Self {
        Self(self.0.min(other.0))
    }

    /// Returns the maximum of `self` and `other`.
    pub fn max(self, other: Self) -> Self {
        Self(self.0.max(other.0))
    }

    /// Returns the absolute value, or `None` if `self == i64::MIN`.
    pub fn checked_abs(self) -> Option<Self> {
        self.0.checked_abs().map(Self)
    }

    /// Returns true if the value is zero.
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Returns true if the value is negative.
    pub fn is_negative(self) -> bool {
        self.0 < 0
    }
}

impl From<i64> for CheckedAmount {
    fn from(value: i64) -> Self {
        Self(value)
    }
}

impl From<CheckedAmount> for i64 {
    fn from(amount: CheckedAmount) -> Self {
        amount.0
    }
}

impl fmt::Display for CheckedAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Checked wrapper for `u32` counter fields in consensus-critical code.
///
/// Covers: `num_sub_entries` and similar counters that must never underflow.
///
/// Like [`CheckedAmount`], this type does NOT implement arithmetic operator
/// traits. Use `checked_add()` / `checked_sub()` explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CheckedCounter(u32);

impl CheckedCounter {
    /// Create a new `CheckedCounter` from a raw `u32`.
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Extract the inner `u32` value.
    pub fn value(self) -> u32 {
        self.0
    }

    /// Checked addition. Returns `None` on overflow.
    pub fn checked_add(self, rhs: u32) -> Option<Self> {
        self.0.checked_add(rhs).map(Self)
    }

    /// Checked subtraction. Returns `None` on underflow.
    pub fn checked_sub(self, rhs: u32) -> Option<Self> {
        self.0.checked_sub(rhs).map(Self)
    }

    /// Returns true if the value is zero.
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl From<u32> for CheckedCounter {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<CheckedCounter> for u32 {
    fn from(counter: CheckedCounter) -> Self {
        counter.0
    }
}

impl fmt::Display for CheckedCounter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Consensus-critical arithmetic helpers ────────────────────────────────
//
// These operate on XDR types (AccountEntry, TrustLineEntry) using
// CheckedAmount/CheckedCounter internally. Available to all crates that
// depend on henyey-common.

/// Extract liabilities from an account entry.
pub fn account_liabilities(account: &AccountEntry) -> Liabilities {
    match &account.ext {
        AccountEntryExt::V0 => Liabilities {
            buying: 0,
            selling: 0,
        },
        AccountEntryExt::V1(v1) => v1.liabilities.clone(),
    }
}

/// Extract liabilities from a trustline entry.
pub fn trustline_liabilities(trustline: &TrustLineEntry) -> Liabilities {
    match &trustline.ext {
        TrustLineEntryExt::V0 => Liabilities {
            buying: 0,
            selling: 0,
        },
        TrustLineEntryExt::V1(v1) => v1.liabilities.clone(),
    }
}

/// Credit `delta` to an account's native balance.
///
/// Returns `BalanceError::Overflow` if the addition overflows, or
/// `BalanceError::LiabilityViolation` if the new balance would violate
/// the buying liability constraint.
pub fn add_account_balance(account: &mut AccountEntry, delta: i64) -> Result<(), BalanceError> {
    let new_balance = CheckedAmount::new(account.balance)
        .checked_add(delta)
        .ok_or(BalanceError::Overflow)?;
    let buying = account_liabilities(account).buying;
    let ceiling = CheckedAmount::new(i64::MAX)
        .checked_sub(buying)
        .ok_or(BalanceError::Overflow)?;
    if new_balance > ceiling {
        return Err(BalanceError::LiabilityViolation);
    }
    account.balance = new_balance.value();
    Ok(())
}

/// Credit `delta` to a trustline balance.
///
/// Returns `BalanceError::ExceedsLimit` if the new balance would exceed the
/// trustline limit, or `BalanceError::LiabilityViolation` if it would violate
/// the buying liability constraint.
pub fn add_trustline_balance(tl: &mut TrustLineEntry, delta: i64) -> Result<(), BalanceError> {
    let headroom = CheckedAmount::new(tl.limit)
        .checked_sub(tl.balance)
        .ok_or(BalanceError::Overflow)?;
    if delta > headroom.value() {
        return Err(BalanceError::ExceedsLimit);
    }
    let new_balance = CheckedAmount::new(tl.balance)
        .checked_add(delta)
        .ok_or(BalanceError::Overflow)?;
    let buying = trustline_liabilities(tl).buying;
    let ceiling = CheckedAmount::new(tl.limit)
        .checked_sub(buying)
        .ok_or(BalanceError::Overflow)?;
    if new_balance > ceiling {
        return Err(BalanceError::LiabilityViolation);
    }
    tl.balance = new_balance.value();
    Ok(())
}

/// Subtract `amount` from an account's native balance.
///
/// Returns `BalanceError::Underflow` if the result would be negative.
/// No liability checks — used for debits where the caller has already validated.
pub fn sub_account_balance(account: &mut AccountEntry, amount: i64) -> Result<(), BalanceError> {
    let new_balance = CheckedAmount::new(account.balance)
        .checked_sub(amount)
        .ok_or(BalanceError::Underflow)?;
    if new_balance.is_negative() {
        return Err(BalanceError::Underflow);
    }
    account.balance = new_balance.value();
    Ok(())
}

/// Subtract `amount` from a trustline balance.
///
/// Returns `BalanceError::Underflow` if the result would be negative.
/// No liability or limit checks.
pub fn sub_trustline_balance(tl: &mut TrustLineEntry, amount: i64) -> Result<(), BalanceError> {
    let new_balance = CheckedAmount::new(tl.balance)
        .checked_sub(amount)
        .ok_or(BalanceError::Underflow)?;
    if new_balance.is_negative() {
        return Err(BalanceError::Underflow);
    }
    tl.balance = new_balance.value();
    Ok(())
}

/// Apply a checked delta to a pool reserve field.
///
/// Positive delta = deposit, negative delta = withdrawal. Returns
/// `BalanceError::Overflow` or `BalanceError::Underflow` on bounds violation.
pub fn add_pool_reserve(reserve: &mut i64, delta: i64) -> Result<(), BalanceError> {
    let new_val = CheckedAmount::new(*reserve)
        .checked_add(delta)
        .ok_or(BalanceError::Overflow)?;
    if new_val.is_negative() {
        return Err(BalanceError::Underflow);
    }
    *reserve = new_val.value();
    Ok(())
}

/// Apply a checked delta to total pool shares.
///
/// Positive delta = mint, negative delta = burn. Returns
/// `BalanceError::Overflow` or `BalanceError::Underflow` on bounds violation.
pub fn add_pool_shares(shares: &mut i64, delta: i64) -> Result<(), BalanceError> {
    let new_val = CheckedAmount::new(*shares)
        .checked_add(delta)
        .ok_or(BalanceError::Overflow)?;
    if new_val.is_negative() {
        return Err(BalanceError::Underflow);
    }
    *shares = new_val.value();
    Ok(())
}

/// Increment num_sub_entries by `n`.
///
/// Panics on overflow (matches stellar-core which asserts valid account state).
pub fn inc_sub_entries(account: &mut AccountEntry, n: u32) {
    account.num_sub_entries = account
        .num_sub_entries
        .checked_add(n)
        .expect("num_sub_entries overflow: too many sub-entries");
}

/// Decrement num_sub_entries by `n`.
///
/// Panics if the result would underflow (matches stellar-core which asserts
/// valid account state). See #1121.
pub fn dec_sub_entries(account: &mut AccountEntry, n: u32) {
    assert!(
        account.num_sub_entries >= n,
        "num_sub_entries underflow: cannot remove {n} sub-entries from account with {}",
        account.num_sub_entries
    );
    account.num_sub_entries -= n;
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── CheckedAmount ──

    #[test]
    fn test_checked_amount_new_and_value() {
        let a = CheckedAmount::new(42);
        assert_eq!(a.value(), 42);
        assert_eq!(i64::from(a), 42);
    }

    #[test]
    fn test_checked_amount_from_i64() {
        let a: CheckedAmount = 100i64.into();
        assert_eq!(a.value(), 100);
    }

    #[test]
    fn test_checked_amount_checked_add() {
        let a = CheckedAmount::new(100);
        assert_eq!(a.checked_add(50), Some(CheckedAmount::new(150)));
        assert_eq!(a.checked_add(-30), Some(CheckedAmount::new(70)));
    }

    #[test]
    fn test_checked_amount_checked_add_overflow() {
        let a = CheckedAmount::new(i64::MAX);
        assert_eq!(a.checked_add(1), None);
    }

    #[test]
    fn test_checked_amount_checked_sub() {
        let a = CheckedAmount::new(100);
        assert_eq!(a.checked_sub(30), Some(CheckedAmount::new(70)));
        assert_eq!(a.checked_sub(100), Some(CheckedAmount::new(0)));
    }

    #[test]
    fn test_checked_amount_checked_sub_underflow() {
        let a = CheckedAmount::new(i64::MIN);
        assert_eq!(a.checked_sub(1), None);
    }

    #[test]
    fn test_checked_amount_checked_mul() {
        let a = CheckedAmount::new(1_000_000);
        assert_eq!(
            a.checked_mul(1_000_000),
            Some(CheckedAmount::new(1_000_000_000_000))
        );
    }

    #[test]
    fn test_checked_amount_checked_mul_overflow() {
        let a = CheckedAmount::new(i64::MAX);
        assert_eq!(a.checked_mul(2), None);
    }

    #[test]
    fn test_checked_amount_checked_div() {
        let a = CheckedAmount::new(100);
        assert_eq!(a.checked_div(3), Some(CheckedAmount::new(33)));
    }

    #[test]
    fn test_checked_amount_checked_div_by_zero() {
        let a = CheckedAmount::new(100);
        assert_eq!(a.checked_div(0), None);
    }

    #[test]
    fn test_checked_amount_saturating_add() {
        let a = CheckedAmount::new(i64::MAX);
        assert_eq!(a.saturating_add(1), CheckedAmount::new(i64::MAX));
    }

    #[test]
    fn test_checked_amount_saturating_sub() {
        let a = CheckedAmount::new(i64::MIN);
        assert_eq!(a.saturating_sub(1), CheckedAmount::new(i64::MIN));
    }

    #[test]
    fn test_checked_amount_min_max() {
        let a = CheckedAmount::new(10);
        let b = CheckedAmount::new(20);
        assert_eq!(a.min(b), a);
        assert_eq!(a.max(b), b);
    }

    #[test]
    fn test_checked_amount_is_zero() {
        assert!(CheckedAmount::new(0).is_zero());
        assert!(!CheckedAmount::new(1).is_zero());
    }

    #[test]
    fn test_checked_amount_is_negative() {
        assert!(CheckedAmount::new(-1).is_negative());
        assert!(!CheckedAmount::new(0).is_negative());
        assert!(!CheckedAmount::new(1).is_negative());
    }

    #[test]
    fn test_checked_amount_ordering() {
        let values: Vec<CheckedAmount> = vec![
            CheckedAmount::new(3),
            CheckedAmount::new(1),
            CheckedAmount::new(2),
        ];
        let mut sorted = values.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            vec![
                CheckedAmount::new(1),
                CheckedAmount::new(2),
                CheckedAmount::new(3),
            ]
        );
    }

    // ── CheckedCounter ──

    #[test]
    fn test_checked_counter_new_and_value() {
        let c = CheckedCounter::new(5);
        assert_eq!(c.value(), 5);
        assert_eq!(u32::from(c), 5);
    }

    #[test]
    fn test_checked_counter_checked_add() {
        let c = CheckedCounter::new(10);
        assert_eq!(c.checked_add(5), Some(CheckedCounter::new(15)));
    }

    #[test]
    fn test_checked_counter_checked_add_overflow() {
        let c = CheckedCounter::new(u32::MAX);
        assert_eq!(c.checked_add(1), None);
    }

    #[test]
    fn test_checked_counter_checked_sub() {
        let c = CheckedCounter::new(10);
        assert_eq!(c.checked_sub(5), Some(CheckedCounter::new(5)));
        assert_eq!(c.checked_sub(10), Some(CheckedCounter::new(0)));
    }

    #[test]
    fn test_checked_counter_checked_sub_underflow() {
        let c = CheckedCounter::new(0);
        assert_eq!(c.checked_sub(1), None);
    }

    #[test]
    fn test_checked_counter_is_zero() {
        assert!(CheckedCounter::new(0).is_zero());
        assert!(!CheckedCounter::new(1).is_zero());
    }

    // ── BalanceError ──

    #[test]
    fn test_balance_error_display() {
        assert_eq!(BalanceError::Overflow.to_string(), "arithmetic overflow");
        assert_eq!(BalanceError::Underflow.to_string(), "arithmetic underflow");
        assert_eq!(
            BalanceError::LiabilityViolation.to_string(),
            "liability constraint violated"
        );
        assert_eq!(BalanceError::ExceedsLimit.to_string(), "exceeds limit");
    }
}
