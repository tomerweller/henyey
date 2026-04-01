//! Version string construction and protocol version invariant checking.
//!
//! This module centralizes all version-related logic for henyey. The versioning
//! scheme couples the major version number to the maximum supported ledger protocol
//! version, following stellar-core's convention:
//!
//! ```text
//! v{PROTOCOL}.{MINOR}.{PATCH}[-{STAGE}.{N}]
//! ```
//!
//! For example, `v25.0.0-alpha.1` targets ledger protocol 25.
//!
//! # Build Metadata
//!
//! Dev/CI builds append a short commit hash as semver build metadata:
//! `25.0.0-alpha.1+a1b2c3d`. This is informational only and does not affect
//! version precedence per the semver spec.
//!
//! # Protocol Invariant
//!
//! The major version number **must** equal [`CURRENT_LEDGER_PROTOCOL_VERSION`].
//! This is enforced at startup via [`check_version_protocol_invariant`].

use crate::protocol::CURRENT_LEDGER_PROTOCOL_VERSION;

/// Build a version string like `henyey-v25.0.0-alpha.1`.
///
/// This is the format used in HTTP `/info` responses and the `version` CLI command,
/// matching the format that stellar-rpc expects to parse.
pub fn build_version_string(pkg_version: &str) -> String {
    format!("henyey-v{pkg_version}")
}

/// Build a version string with commit hash metadata.
///
/// Used for P2P overlay HELLO messages and detailed version output.
/// Example: `henyey-v25.0.0-alpha.1+a1b2c3d`
pub fn build_version_string_full(pkg_version: &str, commit_hash: &str) -> String {
    if commit_hash.is_empty() || commit_hash.len() < 7 {
        build_version_string(pkg_version)
    } else {
        format!("henyey-v{pkg_version}+{}", &commit_hash[..7])
    }
}

/// Extract the major version number from a `CARGO_PKG_VERSION` string.
///
/// Parses `"25.0.0-alpha.1"` → `Some(25)`.
pub fn parse_major_version(pkg_version: &str) -> Option<u32> {
    pkg_version.split('.').next()?.parse().ok()
}

/// Check that the major version in `CARGO_PKG_VERSION` matches
/// [`CURRENT_LEDGER_PROTOCOL_VERSION`].
///
/// # Panics
///
/// Panics if the invariant is violated, preventing the binary from running
/// with a misconfigured version.
pub fn check_version_protocol_invariant(pkg_version: &str) {
    let major = parse_major_version(pkg_version).unwrap_or_else(|| {
        panic!("failed to parse major version from CARGO_PKG_VERSION: {pkg_version:?}")
    });
    assert_eq!(
        major, CURRENT_LEDGER_PROTOCOL_VERSION,
        "version/protocol mismatch: CARGO_PKG_VERSION major ({major}) \
         != CURRENT_LEDGER_PROTOCOL_VERSION ({CURRENT_LEDGER_PROTOCOL_VERSION}). \
         When bumping the protocol version, update the workspace version in Cargo.toml too."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_version_string() {
        assert_eq!(
            build_version_string("25.0.0-alpha.1"),
            "henyey-v25.0.0-alpha.1"
        );
        assert_eq!(build_version_string("25.1.0"), "henyey-v25.1.0");
    }

    #[test]
    fn test_build_version_string_full() {
        assert_eq!(
            build_version_string_full("25.0.0-alpha.1", "a1b2c3d4e5f6"),
            "henyey-v25.0.0-alpha.1+a1b2c3d"
        );
        // Short/empty hash falls back to basic version
        assert_eq!(build_version_string_full("25.0.0", ""), "henyey-v25.0.0");
        assert_eq!(build_version_string_full("25.0.0", "abc"), "henyey-v25.0.0");
    }

    #[test]
    fn test_parse_major_version() {
        assert_eq!(parse_major_version("25.0.0-alpha.1"), Some(25));
        assert_eq!(parse_major_version("25.1.0"), Some(25));
        assert_eq!(parse_major_version("1.0.0"), Some(1));
        assert_eq!(parse_major_version(""), None);
    }

    #[test]
    fn test_version_protocol_invariant_passes() {
        // Current version should pass (CARGO_PKG_VERSION major matches CURRENT_LEDGER_PROTOCOL_VERSION)
        check_version_protocol_invariant(env!("CARGO_PKG_VERSION"));
    }

    #[test]
    #[should_panic(expected = "version/protocol mismatch")]
    fn test_version_protocol_invariant_fails() {
        check_version_protocol_invariant("99.0.0");
    }
}
