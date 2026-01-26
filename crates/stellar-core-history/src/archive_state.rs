//! History Archive State (HAS) parsing and handling.
//!
//! The History Archive State is a JSON file that describes the current state
//! of a Stellar history archive, including the current ledger and bucket list hashes.

use serde::{Deserialize, Serialize};
use stellar_core_common::Hash256;

use crate::error::HistoryError;

/// History Archive State - the root JSON file describing archive state.
///
/// This is typically found at `.well-known/stellar-history.json` or at
/// checkpoint-specific paths like `history/00/00/00/history-0000003f.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryArchiveState {
    /// Format version (currently 2).
    pub version: u32,

    /// Server identifier (e.g., "stellar-core 25.0.1").
    #[serde(default)]
    pub server: Option<String>,

    /// Current ledger sequence.
    pub current_ledger: u32,

    /// Network passphrase.
    #[serde(default)]
    pub network_passphrase: Option<String>,

    /// Bucket list state (current buckets).
    pub current_buckets: Vec<HASBucketLevel>,

    /// Hot archive buckets (for hot archive state, if present).
    #[serde(default)]
    pub hot_archive_buckets: Option<Vec<HASBucketLevel>>,
}

/// A single level in the bucket list hierarchy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HASBucketLevel {
    /// Current bucket hash (hex-encoded).
    pub curr: String,

    /// Snapshot bucket hash (hex-encoded).
    pub snap: String,

    /// Next bucket state (for async merge tracking).
    #[serde(default)]
    pub next: HASBucketNext,
}

/// State of the next bucket merge operation.
///
/// States (matching C++ FutureBucket::State):
/// - 0 (FB_CLEAR): No pending merge
/// - 1 (FB_HASH_OUTPUT): Merge complete, output hash is known
/// - 2 (FB_HASH_INPUTS): Merge in progress, input hashes are stored
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HASBucketNext {
    /// Merge state (0 = clear, 1 = output, 2 = inputs).
    pub state: u32,

    /// Output bucket hash if merge is complete (state == 1).
    #[serde(default)]
    pub output: Option<String>,

    /// Input curr bucket hash for pending merge (state == 2).
    #[serde(default)]
    pub curr: Option<String>,

    /// Input snap bucket hash for pending merge (state == 2).
    #[serde(default)]
    pub snap: Option<String>,

    /// Shadow bucket hashes for pending merge (state == 2, pre-protocol 12).
    #[serde(default)]
    pub shadow: Option<Vec<String>>,
}

impl HistoryArchiveState {
    /// Parse a History Archive State from JSON.
    ///
    /// # Arguments
    ///
    /// * `json` - The JSON string to parse
    ///
    /// # Returns
    ///
    /// The parsed `HistoryArchiveState` or an error if parsing fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_core_history::archive_state::HistoryArchiveState;
    ///
    /// let json = r#"{
    ///     "version": 2,
    ///     "server": "stellar-core 25.0.1",
    ///     "currentLedger": 12345,
    ///     "networkPassphrase": "Test SDF Network ; September 2015",
    ///     "currentBuckets": [
    ///         {
    ///             "curr": "e113f8cc5468579cb57538e3204c8d3ecce59a0cdb47f6fa7e87ab4d9d8146fd",
    ///             "snap": "0000000000000000000000000000000000000000000000000000000000000000",
    ///             "next": { "state": 0 }
    ///         }
    ///     ]
    /// }"#;
    ///
    /// let has = HistoryArchiveState::from_json(json).unwrap();
    /// assert_eq!(has.current_ledger, 12345);
    /// ```
    pub fn from_json(json: &str) -> Result<Self, HistoryError> {
        serde_json::from_str(json).map_err(HistoryError::Json)
    }

    /// Serialize the History Archive State to JSON.
    pub fn to_json(&self) -> Result<String, HistoryError> {
        serde_json::to_string_pretty(self).map_err(HistoryError::Json)
    }

    /// Get the current ledger sequence.
    #[inline]
    pub fn current_ledger(&self) -> u32 {
        self.current_ledger
    }

    /// Get all bucket hashes referenced in this HAS.
    ///
    /// This returns all non-zero bucket hashes from both `curr` and `snap`
    /// fields of each bucket level, which are needed for catchup.
    ///
    /// # Returns
    ///
    /// A vector of all unique bucket hashes.
    pub fn all_bucket_hashes(&self) -> Vec<Hash256> {
        let zero_hash = "0".repeat(64);
        let mut hashes = Vec::new();

        for level in &self.current_buckets {
            // Add current bucket hash if non-zero
            if !level.curr.is_empty() && level.curr != zero_hash {
                if let Ok(h) = Hash256::from_hex(&level.curr) {
                    hashes.push(h);
                }
            }

            // Add snapshot bucket hash if non-zero
            if !level.snap.is_empty() && level.snap != zero_hash {
                if let Ok(h) = Hash256::from_hex(&level.snap) {
                    hashes.push(h);
                }
            }

            // Add next output if present and non-zero (state == 1)
            if let Some(ref output) = level.next.output {
                if !output.is_empty() && output != &zero_hash {
                    if let Ok(h) = Hash256::from_hex(output) {
                        hashes.push(h);
                    }
                }
            }

            // Add next input hashes if present and non-zero (state == 2)
            if level.next.state == 2 {
                if let Some(ref curr) = level.next.curr {
                    if !curr.is_empty() && curr != &zero_hash {
                        if let Ok(h) = Hash256::from_hex(curr) {
                            hashes.push(h);
                        }
                    }
                }
                if let Some(ref snap) = level.next.snap {
                    if !snap.is_empty() && snap != &zero_hash {
                        if let Ok(h) = Hash256::from_hex(snap) {
                            hashes.push(h);
                        }
                    }
                }
            }
        }

        // Also check hot archive buckets if present
        if let Some(ref hot_buckets) = self.hot_archive_buckets {
            for level in hot_buckets {
                if !level.curr.is_empty() && level.curr != zero_hash {
                    if let Ok(h) = Hash256::from_hex(&level.curr) {
                        hashes.push(h);
                    }
                }
                if !level.snap.is_empty() && level.snap != zero_hash {
                    if let Ok(h) = Hash256::from_hex(&level.snap) {
                        hashes.push(h);
                    }
                }
                // Add next output if present and non-zero (state == 1)
                if let Some(ref output) = level.next.output {
                    if !output.is_empty() && output != &zero_hash {
                        if let Ok(h) = Hash256::from_hex(output) {
                            hashes.push(h);
                        }
                    }
                }
                // Add next input hashes if present and non-zero (state == 2)
                if level.next.state == 2 {
                    if let Some(ref curr) = level.next.curr {
                        if !curr.is_empty() && curr != &zero_hash {
                            if let Ok(h) = Hash256::from_hex(curr) {
                                hashes.push(h);
                            }
                        }
                    }
                    if let Some(ref snap) = level.next.snap {
                        if !snap.is_empty() && snap != &zero_hash {
                            if let Ok(h) = Hash256::from_hex(snap) {
                                hashes.push(h);
                            }
                        }
                    }
                }
            }
        }

        hashes
    }

    /// Get the unique bucket hashes (deduplicated).
    ///
    /// This is useful when you want to avoid downloading the same bucket twice.
    pub fn unique_bucket_hashes(&self) -> Vec<Hash256> {
        let mut hashes = self.all_bucket_hashes();
        hashes.sort_by(|a, b| a.0.cmp(&b.0));
        hashes.dedup();
        hashes
    }

    /// Get the network passphrase if available.
    pub fn network_passphrase(&self) -> Option<&str> {
        self.network_passphrase.as_deref()
    }

    /// Get the server version string if available.
    pub fn server(&self) -> Option<&str> {
        self.server.as_deref()
    }

    /// Get the number of bucket levels.
    pub fn bucket_level_count(&self) -> usize {
        self.current_buckets.len()
    }

    /// Get bucket hashes for a specific level.
    ///
    /// # Arguments
    ///
    /// * `level` - The bucket level index (0 = most frequently updated)
    ///
    /// # Returns
    ///
    /// A tuple of (current_hash, snapshot_hash) if the level exists.
    pub fn bucket_hashes_at_level(
        &self,
        level: usize,
    ) -> Option<(Option<Hash256>, Option<Hash256>)> {
        self.current_buckets.get(level).map(|bucket_level| {
            let zero_hash = "0".repeat(64);

            let curr = if bucket_level.curr != zero_hash {
                Hash256::from_hex(&bucket_level.curr).ok()
            } else {
                None
            };

            let snap = if bucket_level.snap != zero_hash {
                Hash256::from_hex(&bucket_level.snap).ok()
            } else {
                None
            };

            (curr, snap)
        })
    }

    /// Get hot archive bucket hashes for a specific level.
    ///
    /// # Arguments
    ///
    /// * `level` - The bucket level index (0 = most frequently updated)
    ///
    /// # Returns
    ///
    /// A tuple of (current_hash, snapshot_hash) if the level exists.
    pub fn hot_archive_bucket_hashes_at_level(
        &self,
        level: usize,
    ) -> Option<(Option<Hash256>, Option<Hash256>)> {
        let hot_buckets = self.hot_archive_buckets.as_ref()?;
        hot_buckets.get(level).map(|bucket_level| {
            let zero_hash = "0".repeat(64);

            let curr = if bucket_level.curr != zero_hash {
                Hash256::from_hex(&bucket_level.curr).ok()
            } else {
                None
            };

            let snap = if bucket_level.snap != zero_hash {
                Hash256::from_hex(&bucket_level.snap).ok()
            } else {
                None
            };

            (curr, snap)
        })
    }

    /// Check if this HAS contains hot archive buckets.
    pub fn has_hot_archive_buckets(&self) -> bool {
        self.hot_archive_buckets
            .as_ref()
            .is_some_and(|v| !v.is_empty())
    }

    /// Get the number of hot archive bucket levels.
    pub fn hot_archive_bucket_level_count(&self) -> usize {
        self.hot_archive_buckets.as_ref().map_or(0, |v| v.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_has_json() -> &'static str {
        r#"{
            "version": 2,
            "server": "stellar-core 25.0.1.rc1 (ac5427a148203e8269294cf50866200cbe4ec1d3)",
            "currentLedger": 212735,
            "networkPassphrase": "Test SDF Network ; September 2015",
            "currentBuckets": [
                {
                    "curr": "e113f8cc5468579cb57538e3204c8d3ecce59a0cdb47f6fa7e87ab4d9d8146fd",
                    "next": { "state": 0 },
                    "snap": "02441d532a2aa2bbc5e2b025438572f5ea2e25205442c002e2c6e7636a54b0ef"
                },
                {
                    "curr": "a8a0ed4b478cda48066d06aff6f7ff9b089bbfb3effd3a6e52ce93caa71f0e1a",
                    "next": { "state": 0 },
                    "snap": "d5550575dff797042a61dd86adae42df96b0db9176fdf137e680c2dbac45ede9"
                },
                {
                    "curr": "0000000000000000000000000000000000000000000000000000000000000000",
                    "next": { "state": 0 },
                    "snap": "0000000000000000000000000000000000000000000000000000000000000000"
                }
            ]
        }"#
    }

    #[test]
    fn test_parse_has() {
        let has = HistoryArchiveState::from_json(sample_has_json()).unwrap();

        assert_eq!(has.version, 2);
        assert_eq!(has.current_ledger, 212735);
        assert_eq!(
            has.network_passphrase(),
            Some("Test SDF Network ; September 2015")
        );
        assert!(has.server().unwrap().contains("stellar-core"));
        assert_eq!(has.bucket_level_count(), 3);
    }

    #[test]
    fn test_all_bucket_hashes() {
        let has = HistoryArchiveState::from_json(sample_has_json()).unwrap();
        let hashes = has.all_bucket_hashes();

        // Should have 4 non-zero hashes (2 levels x 2 buckets each)
        assert_eq!(hashes.len(), 4);

        // Check first hash
        assert_eq!(
            hashes[0].to_hex(),
            "e113f8cc5468579cb57538e3204c8d3ecce59a0cdb47f6fa7e87ab4d9d8146fd"
        );
    }

    #[test]
    fn test_unique_bucket_hashes() {
        // Create HAS with duplicate hashes
        let json = r#"{
            "version": 2,
            "currentLedger": 100,
            "currentBuckets": [
                {
                    "curr": "e113f8cc5468579cb57538e3204c8d3ecce59a0cdb47f6fa7e87ab4d9d8146fd",
                    "snap": "e113f8cc5468579cb57538e3204c8d3ecce59a0cdb47f6fa7e87ab4d9d8146fd",
                    "next": { "state": 0 }
                }
            ]
        }"#;

        let has = HistoryArchiveState::from_json(json).unwrap();
        let unique = has.unique_bucket_hashes();

        // Should deduplicate to 1
        assert_eq!(unique.len(), 1);
    }

    #[test]
    fn test_bucket_hashes_at_level() {
        let has = HistoryArchiveState::from_json(sample_has_json()).unwrap();

        // Level 0 should have both hashes
        let (curr, snap) = has.bucket_hashes_at_level(0).unwrap();
        assert!(curr.is_some());
        assert!(snap.is_some());

        // Level 2 should have zero hashes (None)
        let (curr, snap) = has.bucket_hashes_at_level(2).unwrap();
        assert!(curr.is_none());
        assert!(snap.is_none());

        // Level 10 doesn't exist
        assert!(has.bucket_hashes_at_level(10).is_none());
    }

    #[test]
    fn test_serialize_has() {
        let has = HistoryArchiveState::from_json(sample_has_json()).unwrap();
        let json = has.to_json().unwrap();

        // Re-parse and verify
        let reparsed = HistoryArchiveState::from_json(&json).unwrap();
        assert_eq!(reparsed.current_ledger, has.current_ledger);
        assert_eq!(reparsed.version, has.version);
    }

    #[test]
    fn test_minimal_has() {
        let json = r#"{
            "version": 2,
            "currentLedger": 63,
            "currentBuckets": []
        }"#;

        let has = HistoryArchiveState::from_json(json).unwrap();
        assert_eq!(has.version, 2);
        assert_eq!(has.current_ledger, 63);
        assert!(has.network_passphrase().is_none());
        assert!(has.server().is_none());
        assert!(has.all_bucket_hashes().is_empty());
    }

    #[test]
    fn test_invalid_json() {
        let result = HistoryArchiveState::from_json("not valid json");
        assert!(result.is_err());
    }
}
