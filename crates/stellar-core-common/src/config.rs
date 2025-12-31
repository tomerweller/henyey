//! Configuration types for rs-stellar-core.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main configuration for rs-stellar-core.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Network configuration.
    pub network: NetworkConfig,

    /// Database configuration.
    pub database: DatabaseConfig,

    /// Node configuration.
    pub node: NodeConfig,

    /// History archive configuration.
    #[serde(default)]
    pub history: HistoryConfig,

    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network passphrase (e.g., "Test SDF Network ; September 2015").
    pub passphrase: String,

    /// Port to listen on for peer connections.
    #[serde(default = "default_peer_port")]
    pub peer_port: u16,

    /// Port for HTTP admin interface.
    #[serde(default = "default_http_port")]
    pub http_port: u16,

    /// Known peers to connect to.
    #[serde(default)]
    pub known_peers: Vec<String>,

    /// Preferred peers (always try to connect).
    #[serde(default)]
    pub preferred_peers: Vec<String>,

    /// Maximum number of peer connections.
    #[serde(default = "default_max_peers")]
    pub max_peer_connections: usize,

    /// Target number of peer connections.
    #[serde(default = "default_target_peers")]
    pub target_peer_connections: usize,
}

/// Database configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Path to the SQLite database file.
    pub path: PathBuf,
}

/// Node configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Whether this node is a validator.
    #[serde(default)]
    pub is_validator: bool,

    /// Node seed (secret key). Required for validators.
    pub node_seed: Option<String>,

    /// Quorum set configuration.
    #[serde(default)]
    pub quorum_set: QuorumSetConfig,
}

/// Quorum set configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuorumSetConfig {
    /// Threshold percentage (0-100).
    #[serde(default = "default_threshold")]
    pub threshold_percent: u32,

    /// Validator public keys.
    #[serde(default)]
    pub validators: Vec<String>,

    /// Inner quorum sets.
    #[serde(default)]
    pub inner_sets: Vec<QuorumSetConfig>,
}

/// History archive configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HistoryConfig {
    /// History archive URLs for reading.
    #[serde(default)]
    pub get_commands: Vec<HistoryArchiveConfig>,

    /// History archive URLs for writing (validators only).
    #[serde(default)]
    pub put_commands: Vec<HistoryArchiveConfig>,
}

/// Single history archive configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryArchiveConfig {
    /// Archive name.
    pub name: String,

    /// Get command template (use {0} for remote path, {1} for local path).
    pub get: String,

    /// Put command template (optional, for validators).
    #[serde(default)]
    pub put: Option<String>,

    /// Mkdir command template (optional, for validators).
    #[serde(default)]
    pub mkdir: Option<String>,
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log format (text or json).
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

fn default_peer_port() -> u16 {
    11625
}

fn default_http_port() -> u16 {
    11626
}

fn default_max_peers() -> usize {
    25
}

fn default_target_peers() -> usize {
    8
}

fn default_threshold() -> u32 {
    67
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, crate::Error> {
        let content = std::fs::read_to_string(path)?;
        toml::from_str(&content).map_err(|e| crate::Error::Config(e.to_string()))
    }

    /// Create a default testnet configuration.
    pub fn testnet() -> Self {
        Self {
            network: NetworkConfig {
                passphrase: "Test SDF Network ; September 2015".to_string(),
                peer_port: default_peer_port(),
                http_port: default_http_port(),
                known_peers: vec![
                    "core-testnet1.stellar.org:11625".to_string(),
                    "core-testnet2.stellar.org:11625".to_string(),
                    "core-testnet3.stellar.org:11625".to_string(),
                ],
                preferred_peers: vec![],
                max_peer_connections: default_max_peers(),
                target_peer_connections: default_target_peers(),
            },
            database: DatabaseConfig {
                path: PathBuf::from("stellar.db"),
            },
            node: NodeConfig {
                is_validator: false,
                node_seed: None,
                quorum_set: QuorumSetConfig::default(),
            },
            history: HistoryConfig {
                get_commands: vec![HistoryArchiveConfig {
                    name: "sdf1".to_string(),
                    get: "curl -sf https://history.stellar.org/prd/core-testnet/core_testnet_001/{0} -o {1}".to_string(),
                    put: None,
                    mkdir: None,
                }],
                put_commands: vec![],
            },
            logging: LoggingConfig::default(),
        }
    }
}
