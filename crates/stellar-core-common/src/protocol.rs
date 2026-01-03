//! Protocol version utilities.
//!
//! This module provides utilities for handling protocol versions and gating
//! features based on the current ledger protocol version.

/// Protocol version enumeration for version gating.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolVersion {
    V0 = 0,
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
    V6 = 6,
    V7 = 7,
    V8 = 8,
    V9 = 9,
    V10 = 10,
    V11 = 11,
    V12 = 12,
    V13 = 13,
    V14 = 14,
    V15 = 15,
    V16 = 16,
    V17 = 17,
    V18 = 18,
    V19 = 19,
    V20 = 20,
    V21 = 21,
    V22 = 22,
    V23 = 23,
    V24 = 24,
    V25 = 25,
}

impl ProtocolVersion {
    /// Convert to u32 value.
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// The protocol version when Soroban was first introduced.
pub const SOROBAN_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V20;

/// The protocol version when parallel Soroban execution was introduced.
pub const PARALLEL_SOROBAN_PHASE_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V23;

/// The protocol version when auto-restore was introduced.
pub const AUTO_RESTORE_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V23;

/// The protocol version when reusable module cache was introduced.
pub const REUSABLE_SOROBAN_MODULE_CACHE_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V23;

/// The current maximum supported ledger protocol version.
pub const CURRENT_LEDGER_PROTOCOL_VERSION: u32 = 25;

/// The minimum supported ledger protocol version for Soroban execution.
pub const MIN_SOROBAN_PROTOCOL_VERSION: u32 = 20;

/// Check if protocol version is strictly before a target.
#[inline]
pub fn protocol_version_is_before(version: u32, before: ProtocolVersion) -> bool {
    version < before.as_u32()
}

/// Check if protocol version is at or after a target (most commonly used).
#[inline]
pub fn protocol_version_starts_from(version: u32, from: ProtocolVersion) -> bool {
    version >= from.as_u32()
}

/// Check if protocol version equals a specific version.
#[inline]
pub fn protocol_version_equals(version: u32, equals: ProtocolVersion) -> bool {
    version == equals.as_u32()
}

/// Check if an upgrade to a target protocol version happened between prev and new versions.
#[inline]
pub fn needs_upgrade_to_version(target: ProtocolVersion, prev_version: u32, new_version: u32) -> bool {
    protocol_version_is_before(prev_version, target)
        && protocol_version_starts_from(new_version, target)
}

/// Check if Soroban is supported for the given protocol version.
#[inline]
pub fn soroban_supported(protocol_version: u32) -> bool {
    protocol_version_starts_from(protocol_version, SOROBAN_PROTOCOL_VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version_is_before() {
        assert!(protocol_version_is_before(19, ProtocolVersion::V20));
        assert!(!protocol_version_is_before(20, ProtocolVersion::V20));
        assert!(!protocol_version_is_before(21, ProtocolVersion::V20));
    }

    #[test]
    fn test_protocol_version_starts_from() {
        assert!(!protocol_version_starts_from(19, ProtocolVersion::V20));
        assert!(protocol_version_starts_from(20, ProtocolVersion::V20));
        assert!(protocol_version_starts_from(21, ProtocolVersion::V20));
    }

    #[test]
    fn test_needs_upgrade_to_version() {
        // Upgrading from 19 to 20 needs upgrade to V20
        assert!(needs_upgrade_to_version(ProtocolVersion::V20, 19, 20));
        // Already at 20, no upgrade needed
        assert!(!needs_upgrade_to_version(ProtocolVersion::V20, 20, 20));
        // Upgrading from 20 to 21 doesn't need upgrade to V20
        assert!(!needs_upgrade_to_version(ProtocolVersion::V20, 20, 21));
        // Upgrading from 19 to 21 needs upgrade to V20
        assert!(needs_upgrade_to_version(ProtocolVersion::V20, 19, 21));
    }

    #[test]
    fn test_soroban_supported() {
        assert!(!soroban_supported(19));
        assert!(soroban_supported(20));
        assert!(soroban_supported(24));
        assert!(soroban_supported(25));
    }
}
