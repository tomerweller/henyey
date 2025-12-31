//! Network identity types.

use crate::types::Hash256;

/// Network identifier derived from network passphrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkId(pub Hash256);

impl NetworkId {
    /// Create a network ID from a passphrase.
    pub fn from_passphrase(passphrase: &str) -> Self {
        Self(Hash256::hash(passphrase.as_bytes()))
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Stellar public testnet.
    pub fn testnet() -> Self {
        Self::from_passphrase("Test SDF Network ; September 2015")
    }

    /// Stellar public mainnet.
    pub fn mainnet() -> Self {
        Self::from_passphrase("Public Global Stellar Network ; September 2015")
    }
}

impl From<NetworkId> for stellar_xdr::curr::Hash {
    fn from(id: NetworkId) -> Self {
        stellar_xdr::curr::Hash(id.0 .0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_id_testnet() {
        let id = NetworkId::testnet();
        // Known testnet network ID hash
        assert!(!id.0.is_zero());
    }

    #[test]
    fn test_network_id_mainnet() {
        let id = NetworkId::mainnet();
        // Known mainnet network ID hash
        assert!(!id.0.is_zero());
    }
}
