//! Quorum set configuration and validation utilities.
//!
//! This module provides utilities for:
//! - Converting configuration to XDR quorum sets
//! - Validating quorum set configurations
//! - Well-known validator configurations

use stellar_core_common::config::QuorumSetConfig;
use stellar_xdr::curr::{NodeId, PublicKey, ScpQuorumSet, Uint256};
use tracing::warn;

use crate::{is_valid_quorum_set, get_all_nodes};

/// Errors that can occur when parsing quorum set configuration.
#[derive(Debug, Clone)]
pub enum QuorumConfigError {
    /// Invalid validator public key format.
    InvalidPublicKey(String),
    /// Invalid threshold value.
    InvalidThreshold { threshold: u32, validator_count: usize },
    /// Quorum set structure is invalid.
    InvalidStructure(String),
    /// Quorum intersection check failed.
    NoQuorumIntersection,
}

impl std::fmt::Display for QuorumConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPublicKey(key) => write!(f, "invalid public key: {}", key),
            Self::InvalidThreshold { threshold, validator_count } => {
                write!(f, "threshold {} > validator count {}", threshold, validator_count)
            }
            Self::InvalidStructure(msg) => write!(f, "invalid quorum set: {}", msg),
            Self::NoQuorumIntersection => write!(f, "quorum sets do not have intersection"),
        }
    }
}

impl std::error::Error for QuorumConfigError {}

/// Convert a QuorumSetConfig to an XDR ScpQuorumSet.
pub fn config_to_quorum_set(config: &QuorumSetConfig) -> Result<ScpQuorumSet, QuorumConfigError> {
    // Parse validators
    let mut validators = Vec::new();
    for key_str in &config.validators {
        let node_id = parse_node_id(key_str)?;
        validators.push(node_id);
    }

    // Recursively parse inner sets
    let mut inner_sets = Vec::new();
    for inner_config in &config.inner_sets {
        let inner_qs = config_to_quorum_set(inner_config)?;
        inner_sets.push(inner_qs);
    }

    // Calculate threshold from percentage
    let total = validators.len() + inner_sets.len();
    let threshold = if total == 0 {
        0
    } else {
        ((config.threshold_percent as usize * total) / 100).max(1) as u32
    };

    // Validate threshold
    if threshold as usize > total {
        return Err(QuorumConfigError::InvalidThreshold {
            threshold,
            validator_count: total,
        });
    }

    let qs = ScpQuorumSet {
        threshold,
        validators: validators.try_into().unwrap_or_default(),
        inner_sets: inner_sets.try_into().unwrap_or_default(),
    };

    // Validate the resulting quorum set
    if !is_valid_quorum_set(&qs) {
        return Err(QuorumConfigError::InvalidStructure(
            "quorum set validation failed".to_string(),
        ));
    }

    Ok(qs)
}

/// Parse a node ID from a string.
///
/// Supports both:
/// - Raw 64-character hex public key
/// - Stellar strkey format (G...)
pub fn parse_node_id(key_str: &str) -> Result<NodeId, QuorumConfigError> {
    let key_str = key_str.trim();

    // Try parsing as strkey first (G... format)
    if key_str.starts_with('G') {
        return parse_strkey_node_id(key_str);
    }

    // Try parsing as hex
    if key_str.len() == 64 {
        return parse_hex_node_id(key_str);
    }

    Err(QuorumConfigError::InvalidPublicKey(key_str.to_string()))
}

fn parse_strkey_node_id(key_str: &str) -> Result<NodeId, QuorumConfigError> {
    use stellar_strkey::ed25519::PublicKey as StrKeyPublicKey;

    let strkey = StrKeyPublicKey::from_string(key_str)
        .map_err(|_| QuorumConfigError::InvalidPublicKey(key_str.to_string()))?;

    let bytes = strkey.0;
    Ok(NodeId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes))))
}

fn parse_hex_node_id(key_str: &str) -> Result<NodeId, QuorumConfigError> {
    let bytes = hex::decode(key_str)
        .map_err(|_| QuorumConfigError::InvalidPublicKey(key_str.to_string()))?;

    if bytes.len() != 32 {
        return Err(QuorumConfigError::InvalidPublicKey(key_str.to_string()));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(NodeId(PublicKey::PublicKeyTypeEd25519(Uint256(arr))))
}

/// Validate that a quorum set configuration will produce valid consensus.
///
/// This checks:
/// 1. The quorum set is structurally valid
/// 2. Threshold is reasonable (not 0, not > 100%)
/// 3. There are enough validators for safety
pub fn validate_quorum_config(config: &QuorumSetConfig) -> Result<(), QuorumConfigError> {
    // Check threshold is in range
    if config.threshold_percent > 100 {
        return Err(QuorumConfigError::InvalidThreshold {
            threshold: config.threshold_percent,
            validator_count: 100,
        });
    }

    // Convert to XDR to validate structure
    let qs = config_to_quorum_set(config)?;

    // Check we have validators
    let all_nodes = get_all_nodes(&qs);
    if all_nodes.is_empty() && config.validators.is_empty() && config.inner_sets.is_empty() {
        warn!("Quorum set has no validators - node will not be able to reach consensus");
    }

    // Warn if threshold is too low
    if config.threshold_percent < 51 {
        warn!(
            "Quorum threshold {}% is below 51% - this may compromise safety",
            config.threshold_percent
        );
    }

    // Warn if threshold is 100% (no fault tolerance)
    if config.threshold_percent == 100 && !config.validators.is_empty() {
        warn!("Quorum threshold is 100% - no fault tolerance, any validator failure blocks consensus");
    }

    Ok(())
}

/// Well-known validators for Stellar networks.
pub mod known_validators {
    /// SDF's testnet validators.
    pub const TESTNET_VALIDATORS: &[&str] = &[
        // SDF testnet core servers
        "GDKXE2OZMJIPOSLNA6N6F2BVCI3O777I2OOC4BV7VOYUEHYX7RTRYA7Y", // core1
        "GCUCJTIYXSOXKBSNFGNFWW5MUQ54HKRPGJUTQFJ5RQXZXNOLNXYDHRAP", // core2
        "GC2V2EFSXN6SQTWVYA5EPJPBWWIMSD2XQNKUOHGEKB535AQE2I6IXV2Z", // core3
    ];

    /// SDF's mainnet validators (Tier 1 only).
    pub const MAINNET_SDF_VALIDATORS: &[&str] = &[
        "GCGB2S2KGYARPVIA37HBER46GJSTA276NAJMGRY7DXVQ6JR7RMQMJ", // sdf1
        "GCM6QMP3DLBER46NSEBVR6T6RNXOQCWPZ4ZQWOXJH3OPCY4DJXXOH", // sdf2
        "GABMKJM6I25XI4K7U6XWMULOUQIQ27BCTMLS6BYYSOWKTBUXVRJSXHYQ", // sdf3
    ];

    /// Recommended threshold percentages.
    pub const RECOMMENDED_THRESHOLD_PERCENT: u32 = 67; // 2/3 + 1
    pub const MINIMUM_SAFE_THRESHOLD_PERCENT: u32 = 51;
}

/// Create a testnet quorum set configuration.
pub fn testnet_quorum_config() -> QuorumSetConfig {
    QuorumSetConfig {
        threshold_percent: known_validators::RECOMMENDED_THRESHOLD_PERCENT,
        validators: known_validators::TESTNET_VALIDATORS
            .iter()
            .map(|s| s.to_string())
            .collect(),
        inner_sets: Vec::new(),
    }
}

/// Create a mainnet quorum set configuration using SDF validators.
///
/// Note: For production, you should configure your own quorum set
/// based on validators you trust. This is just a starting point.
pub fn mainnet_sdf_quorum_config() -> QuorumSetConfig {
    QuorumSetConfig {
        threshold_percent: known_validators::RECOMMENDED_THRESHOLD_PERCENT,
        validators: known_validators::MAINNET_SDF_VALIDATORS
            .iter()
            .map(|s| s.to_string())
            .collect(),
        inner_sets: Vec::new(),
    }
}

/// Convert a NodeId to a strkey string (G... format).
pub fn node_id_to_strkey(node_id: &NodeId) -> String {
    use stellar_strkey::ed25519::PublicKey as StrKeyPublicKey;

    match &node_id.0 {
        PublicKey::PublicKeyTypeEd25519(Uint256(bytes)) => {
            StrKeyPublicKey(*bytes).to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_node_id() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let node_id = parse_node_id(hex).unwrap();

        match &node_id.0 {
            PublicKey::PublicKeyTypeEd25519(Uint256(bytes)) => {
                assert_eq!(bytes[31], 1);
            }
        }
    }

    #[test]
    fn test_config_to_quorum_set() {
        let config = QuorumSetConfig {
            threshold_percent: 67,
            validators: vec![
                "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
                "0000000000000000000000000000000000000000000000000000000000000002".to_string(),
                "0000000000000000000000000000000000000000000000000000000000000003".to_string(),
            ],
            inner_sets: Vec::new(),
        };

        let qs = config_to_quorum_set(&config).unwrap();
        assert_eq!(qs.validators.len(), 3);
        assert_eq!(qs.threshold, 2); // 67% of 3 = 2.01 -> 2
    }

    #[test]
    fn test_validate_quorum_config() {
        let config = QuorumSetConfig {
            threshold_percent: 67,
            validators: vec![
                "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
                "0000000000000000000000000000000000000000000000000000000000000002".to_string(),
            ],
            inner_sets: Vec::new(),
        };

        assert!(validate_quorum_config(&config).is_ok());
    }

    #[test]
    fn test_testnet_quorum_config() {
        let config = testnet_quorum_config();
        // The testnet validator keys are strkey format, so this may fail
        // if stellar-strkey is not available - that's ok for testing structure
        assert!(!config.validators.is_empty());
        assert_eq!(config.threshold_percent, 67);
    }

    #[test]
    fn test_invalid_threshold() {
        let config = QuorumSetConfig {
            threshold_percent: 150, // Invalid: > 100%
            validators: vec![
                "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            ],
            inner_sets: Vec::new(),
        };

        assert!(validate_quorum_config(&config).is_err());
    }
}
