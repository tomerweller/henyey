//! Resource accounting utilities for surge pricing and limits.

use std::cmp::Ordering;
use std::ops::{Add, AddAssign, Sub, SubAssign};

pub const NUM_CLASSIC_TX_RESOURCES: usize = 1;
pub const NUM_CLASSIC_TX_BYTES_RESOURCES: usize = 2;
pub const NUM_SOROBAN_TX_RESOURCES: usize = 7;

#[derive(Copy, Clone, Debug)]
pub enum ResourceType {
    Operations = 0,
    Instructions = 1,
    TxByteSize = 2,
    DiskReadBytes = 3,
    WriteBytes = 4,
    ReadLedgerEntries = 5,
    WriteLedgerEntries = 6,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resource {
    values: Vec<i64>,
}

impl Resource {
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

    pub fn make_empty(count: usize) -> Self {
        Self::new(vec![0; count])
    }

    pub fn make_empty_soroban() -> Self {
        Self::make_empty(NUM_SOROBAN_TX_RESOURCES)
    }

    pub fn is_zero(&self) -> bool {
        self.values.iter().all(|v| *v == 0)
    }

    pub fn any_positive(&self) -> bool {
        self.values.iter().any(|v| *v > 0)
    }

    pub fn size(&self) -> usize {
        self.values.len()
    }

    pub fn get_val(&self, ty: ResourceType) -> i64 {
        self.values[ty as usize]
    }

    pub fn set_val(&mut self, ty: ResourceType, val: i64) {
        self.values[ty as usize] = val;
    }

    pub fn can_add(&self, other: &Resource) -> bool {
        self.values
            .iter()
            .zip(other.values.iter())
            .all(|(a, b)| a.checked_add(*b).is_some())
    }

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

pub fn any_less_than(lhs: &Resource, rhs: &Resource) -> bool {
    lhs.values
        .iter()
        .zip(rhs.values.iter())
        .any(|(a, b)| a < b)
}

pub fn any_greater(lhs: &Resource, rhs: &Resource) -> bool {
    lhs.values
        .iter()
        .zip(rhs.values.iter())
        .any(|(a, b)| a > b)
}

pub fn subtract_non_negative(lhs: &Resource, rhs: &Resource) -> Resource {
    Resource::new(
        lhs.values
            .iter()
            .zip(rhs.values.iter())
            .map(|(a, b)| (a - b).max(0))
            .collect(),
    )
}

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
