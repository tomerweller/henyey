//! Resource accounting utilities for surge pricing and transaction limits.
//!
//! This module provides types and functions for tracking and managing
//! computational resources in Stellar transactions. Resources are used
//! for both classic transactions (operation counts) and Soroban smart
//! contract transactions (CPU instructions, storage I/O, etc.).
//!
//! # Resource Types
//!
//! Different transaction types have different resource dimensions:
//!
//! - **Classic transactions**: 1 resource (operations) or 2 (operations + bytes)
//! - **Soroban transactions**: 7 resources (operations, instructions, bytes, disk I/O, etc.)
//!
//! # Surge Pricing
//!
//! Resources are used to implement surge pricing, where transactions compete
//! for limited network capacity. When demand exceeds capacity, fees increase.
//!
//! # Example
//!
//! ```rust
//! use stellar_core_common::resource::{Resource, ResourceType, NUM_SOROBAN_TX_RESOURCES};
//!
//! // Create an empty Soroban resource vector
//! let mut resources = Resource::make_empty_soroban();
//!
//! // Set some resource values
//! resources.set_val(ResourceType::Operations, 1);
//! resources.set_val(ResourceType::Instructions, 1_000_000);
//!
//! // Check resource values
//! assert_eq!(resources.get_val(ResourceType::Operations), 1);
//! assert!(!resources.is_zero());
//! ```

use std::cmp::Ordering;
use std::ops::{Add, AddAssign, Sub, SubAssign};

/// Number of resource dimensions for classic transactions (operations only).
pub const NUM_CLASSIC_TX_RESOURCES: usize = 1;

/// Number of resource dimensions for classic transactions with byte tracking.
pub const NUM_CLASSIC_TX_BYTES_RESOURCES: usize = 2;

/// Number of resource dimensions for Soroban smart contract transactions.
///
/// Soroban transactions track:
/// 1. Operations
/// 2. CPU instructions
/// 3. Transaction byte size
/// 4. Disk read bytes
/// 5. Write bytes
/// 6. Read ledger entries
/// 7. Write ledger entries
pub const NUM_SOROBAN_TX_RESOURCES: usize = 7;

/// Enumeration of resource types tracked for transactions.
///
/// Each variant corresponds to a specific resource dimension that may be
/// limited or priced. The discriminant values are used as indices into
/// the [`Resource`] values vector.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResourceType {
    /// Number of operations in the transaction.
    Operations = 0,
    /// CPU instructions consumed (Soroban only).
    Instructions = 1,
    /// Transaction size in bytes.
    TxByteSize = 2,
    /// Bytes read from persistent storage (Soroban only).
    DiskReadBytes = 3,
    /// Bytes written to storage (Soroban only).
    WriteBytes = 4,
    /// Number of ledger entries read (Soroban only).
    ReadLedgerEntries = 5,
    /// Number of ledger entries written (Soroban only).
    WriteLedgerEntries = 6,
}

/// A multi-dimensional resource usage vector.
///
/// This struct tracks resource consumption across multiple dimensions.
/// The number of dimensions depends on the transaction type:
/// - Classic transactions: 1-2 dimensions
/// - Soroban transactions: 7 dimensions
///
/// Resources support arithmetic operations and partial ordering. Two resources
/// are comparable only if they have the same number of dimensions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resource {
    values: Vec<i64>,
}

impl Resource {
    /// Creates a new resource vector from the given values.
    ///
    /// # Panics
    ///
    /// Panics if the length is not 1, 2, or 7 (the valid resource dimensions).
    pub fn new(values: Vec<i64>) -> Self {
        let len = values.len();
        assert!(
            len == NUM_CLASSIC_TX_RESOURCES
                || len == NUM_CLASSIC_TX_BYTES_RESOURCES
                || len == NUM_SOROBAN_TX_RESOURCES,
            "invalid resource length: {}",
            len
        );
        Self { values }
    }

    /// Creates a zero-initialized resource vector with the specified number of dimensions.
    ///
    /// # Panics
    ///
    /// Panics if `count` is not 1, 2, or 7.
    pub fn make_empty(count: usize) -> Self {
        Self::new(vec![0; count])
    }

    /// Creates a zero-initialized Soroban resource vector (7 dimensions).
    pub fn make_empty_soroban() -> Self {
        Self::make_empty(NUM_SOROBAN_TX_RESOURCES)
    }

    /// Returns `true` if all resource values are zero.
    pub fn is_zero(&self) -> bool {
        self.values.iter().all(|v| *v == 0)
    }

    /// Returns `true` if any resource value is positive.
    pub fn any_positive(&self) -> bool {
        self.values.iter().any(|v| *v > 0)
    }

    /// Returns the number of resource dimensions.
    pub fn size(&self) -> usize {
        self.values.len()
    }

    /// Gets the value for a specific resource type.
    ///
    /// # Panics
    ///
    /// Panics if the resource type index is out of bounds for this resource vector.
    pub fn get_val(&self, ty: ResourceType) -> i64 {
        self.values[ty as usize]
    }

    /// Sets the value for a specific resource type.
    ///
    /// # Panics
    ///
    /// Panics if the resource type index is out of bounds for this resource vector.
    pub fn set_val(&mut self, ty: ResourceType, val: i64) {
        self.values[ty as usize] = val;
    }

    /// Returns `true` if adding `other` to this resource would not overflow.
    pub fn can_add(&self, other: &Resource) -> bool {
        self.values
            .iter()
            .zip(other.values.iter())
            .all(|(a, b)| a.checked_add(*b).is_some())
    }

    /// Returns `true` if all values in `self` are less than or equal to corresponding values in `other`.
    ///
    /// This is used to check if a resource usage fits within a limit.
    pub fn leq(&self, other: &Resource) -> bool {
        self.values
            .iter()
            .zip(other.values.iter())
            .all(|(a, b)| a <= b)
    }
}

impl AddAssign for Resource {
    fn add_assign(&mut self, other: Self) {
        for (a, b) in self.values.iter_mut().zip(other.values.into_iter()) {
            *a += b;
        }
    }
}

impl SubAssign for Resource {
    fn sub_assign(&mut self, other: Self) {
        for (a, b) in self.values.iter_mut().zip(other.values.into_iter()) {
            *a -= b;
        }
    }
}

impl Add for Resource {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        let mut out = self.clone();
        out += other;
        out
    }
}

impl Sub for Resource {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        let mut out = self.clone();
        out -= other;
        out
    }
}

impl PartialOrd for Resource {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let all_le = self.leq(other);
        let all_ge = other.leq(self);
        if all_le && all_ge {
            Some(Ordering::Equal)
        } else if all_le {
            Some(Ordering::Less)
        } else if all_ge {
            Some(Ordering::Greater)
        } else {
            None
        }
    }
}

/// Returns `true` if any dimension of `lhs` is less than the corresponding dimension of `rhs`.
///
/// This is useful for detecting when a resource vector has any dimension below a threshold.
pub fn any_less_than(lhs: &Resource, rhs: &Resource) -> bool {
    lhs.values
        .iter()
        .zip(rhs.values.iter())
        .any(|(a, b)| a < b)
}

/// Returns `true` if any dimension of `lhs` is greater than the corresponding dimension of `rhs`.
///
/// This is useful for detecting when a resource vector exceeds a limit in any dimension.
pub fn any_greater(lhs: &Resource, rhs: &Resource) -> bool {
    lhs.values
        .iter()
        .zip(rhs.values.iter())
        .any(|(a, b)| a > b)
}

/// Subtracts `rhs` from `lhs`, clamping each dimension to a minimum of 0.
///
/// This is useful for computing remaining capacity after deducting usage.
pub fn subtract_non_negative(lhs: &Resource, rhs: &Resource) -> Resource {
    Resource::new(
        lhs.values
            .iter()
            .zip(rhs.values.iter())
            .map(|(a, b)| (a - b).max(0))
            .collect(),
    )
}

/// Clamps each dimension of `current` to the corresponding dimension of `limit`.
///
/// Returns a new resource where each value is `min(current[i], limit[i])`.
pub fn limit_to(current: &Resource, limit: &Resource) -> Resource {
    Resource::new(
        current
            .values
            .iter()
            .zip(limit.values.iter())
            .map(|(a, b)| (*a).min(*b))
            .collect(),
    )
}
