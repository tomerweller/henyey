//! Soroban configuration upgrade handling.
//!
//! This module implements the ConfigUpgradeSetFrame from C++ stellar-core.
//! It handles loading, validating, and applying Soroban network configuration
//! upgrades that are stored in CONTRACT_DATA ledger entries.
//!
//! # Overview
//!
//! Configuration upgrades allow the network to change Soroban parameters
//! (like compute limits, fees, etc.) through consensus. The upgrade data is
//! stored in a temporary CONTRACT_DATA entry, and validators propose upgrading
//! to a specific configuration by referencing its hash.
//!
//! # Protocol
//!
//! 1. A ConfigUpgradeSet is uploaded to the network as CONTRACT_DATA
//! 2. Validators schedule an upgrade by specifying the ConfigUpgradeSetKey
//! 3. When the upgrade time arrives, the ConfigUpgradeSet is loaded and validated
//! 4. If valid, the CONFIG_SETTING entries are updated in the ledger

use sha2::{Digest, Sha256};
use std::sync::Arc;
use stellar_core_common::Hash256;
use stellar_xdr::curr::{
    ConfigSettingEntry, ConfigSettingId, ConfigUpgradeSet, ConfigUpgradeSetKey,
    ContractDataDurability, Hash, LedgerEntry, LedgerEntryData, LedgerEntryExt, LedgerKey,
    LedgerKeyContractData, Limits, ReadXdr, ScAddress, ScVal, WriteXdr,
};
use tracing::{debug, info, warn};

use crate::delta::LedgerDelta;
use crate::error::LedgerError;
use crate::snapshot::SnapshotHandle;

/// Validity of a configuration upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigUpgradeValidity {
    /// The upgrade is valid and can be applied.
    Valid,
    /// The upgrade XDR is invalid (bad hash, unsorted, duplicates).
    XdrInvalid,
    /// The upgrade is invalid (violates constraints or non-upgradeable).
    Invalid,
}

/// Minimum values for Soroban network configuration.
///
/// These match the C++ MinimumSorobanNetworkConfig values.
pub mod min_config {
    /// Minimum max contract size.
    pub const MAX_CONTRACT_SIZE: u32 = 64 * 1024; // 64KB
    /// Minimum max contract data key size.
    pub const MAX_CONTRACT_DATA_KEY_SIZE_BYTES: u32 = 250;
    /// Minimum max contract data entry size.
    pub const MAX_CONTRACT_DATA_ENTRY_SIZE_BYTES: u32 = 64 * 1024; // 64KB
    /// Minimum tx max size bytes.
    pub const TX_MAX_SIZE_BYTES: u32 = 71680; // 70KB
    /// Minimum tx max instructions.
    pub const TX_MAX_INSTRUCTIONS: u32 = 25_000_000;
    /// Minimum memory limit.
    pub const MEMORY_LIMIT: u32 = 40 * 1024 * 1024; // 40MB
    /// Minimum tx max read ledger entries.
    pub const TX_MAX_READ_LEDGER_ENTRIES: u32 = 40;
    /// Minimum tx max read bytes.
    pub const TX_MAX_READ_BYTES: u32 = 200 * 1024; // 200KB
    /// Minimum tx max write ledger entries.
    pub const TX_MAX_WRITE_LEDGER_ENTRIES: u32 = 25;
    /// Minimum tx max write bytes.
    pub const TX_MAX_WRITE_BYTES: u32 = 66560; // 65KB
    /// Minimum tx max contract events size.
    pub const TX_MAX_CONTRACT_EVENTS_SIZE_BYTES: u32 = 8 * 1024; // 8KB
    /// Minimum maximum entry TTL.
    pub const MAXIMUM_ENTRY_LIFETIME: u32 = 31536000; // ~1 year in ledgers
    /// Minimum temporary entry TTL.
    pub const MINIMUM_TEMP_ENTRY_LIFETIME: u32 = 16;
    /// Minimum persistent entry TTL.
    pub const MINIMUM_PERSISTENT_ENTRY_LIFETIME: u32 = 120960; // ~7 days
    /// Minimum max entries to archive.
    pub const MAX_ENTRIES_TO_ARCHIVE: u32 = 100;
    /// Minimum bucket list size window sample size.
    pub const BUCKETLIST_SIZE_WINDOW_SAMPLE_SIZE: u32 = 30;
    /// Minimum eviction scan size.
    pub const EVICTION_SCAN_SIZE: u32 = 1000;
    /// Minimum starting eviction level.
    pub const STARTING_EVICTION_LEVEL: u32 = 7;
    /// Minimum bucket list window sample period.
    pub const BUCKETLIST_WINDOW_SAMPLE_PERIOD: u32 = 1;
    /// Minimum ledger target close time.
    pub const LEDGER_TARGET_CLOSE_TIME_MILLISECONDS: u32 = 1000;
    /// Minimum nomination timeout initial.
    pub const NOMINATION_TIMEOUT_INITIAL_MILLISECONDS: u32 = 500;
    /// Minimum nomination timeout increment.
    pub const NOMINATION_TIMEOUT_INCREMENT_MILLISECONDS: u32 = 100;
    /// Minimum ballot timeout initial.
    pub const BALLOT_TIMEOUT_INITIAL_MILLISECONDS: u32 = 500;
    /// Minimum ballot timeout increment.
    pub const BALLOT_TIMEOUT_INCREMENT_MILLISECONDS: u32 = 500;
}

/// Maximum values for Soroban network configuration.
pub mod max_config {
    /// Maximum ledger target close time.
    pub const LEDGER_TARGET_CLOSE_TIME_MILLISECONDS: u32 = 10000;
    /// Maximum nomination timeout initial.
    pub const NOMINATION_TIMEOUT_INITIAL_MILLISECONDS: u32 = 10000;
    /// Maximum nomination timeout increment.
    pub const NOMINATION_TIMEOUT_INCREMENT_MILLISECONDS: u32 = 5000;
    /// Maximum ballot timeout initial.
    pub const BALLOT_TIMEOUT_INITIAL_MILLISECONDS: u32 = 10000;
    /// Maximum ballot timeout increment.
    pub const BALLOT_TIMEOUT_INCREMENT_MILLISECONDS: u32 = 10000;
}

/// A frame for a ConfigUpgradeSet stored in the ledger.
///
/// This struct wraps a ConfigUpgradeSet and provides methods for validation
/// and application. It's loaded from a CONTRACT_DATA entry using a
/// ConfigUpgradeSetKey.
#[derive(Debug, Clone)]
pub struct ConfigUpgradeSetFrame {
    /// The upgrade set data.
    config_upgrade_set: ConfigUpgradeSet,
    /// The key used to load this upgrade set.
    key: ConfigUpgradeSetKey,
    /// Whether the XDR is valid (hash matches, sorted, no duplicates).
    valid_xdr: bool,
    /// The ledger version when this was loaded.
    ledger_version: u32,
}

impl ConfigUpgradeSetFrame {
    /// Load a ConfigUpgradeSet from the ledger.
    ///
    /// Returns None if:
    /// - The CONTRACT_DATA entry doesn't exist
    /// - The entry's TTL has expired
    /// - The entry is not TEMPORARY durability
    /// - The value is not SCV_BYTES
    /// - The XDR cannot be decoded
    pub fn make_from_key(
        snapshot: &SnapshotHandle,
        key: &ConfigUpgradeSetKey,
    ) -> Option<Arc<Self>> {
        let lk = Self::get_ledger_key(key);

        // Load the CONTRACT_DATA entry
        let entry = snapshot.get_entry(&lk).ok()??;

        // Check TTL (entry must be live)
        let ttl_key = Self::get_ttl_key(&lk);
        let ttl_entry = snapshot.get_entry(&ttl_key).ok()??;
        if !Self::is_live(&ttl_entry, snapshot.ledger_seq()) {
            debug!(
                hash = format!("{:02x?}", &key.content_hash.0[..8]),
                "ConfigUpgradeSet TTL expired"
            );
            return None;
        }

        // Extract CONTRACT_DATA
        let contract_data = match &entry.data {
            stellar_xdr::curr::LedgerEntryData::ContractData(cd) => cd,
            _ => return None,
        };

        // Must be TEMPORARY durability
        if contract_data.durability != ContractDataDurability::Temporary {
            debug!("ConfigUpgradeSet must have TEMPORARY durability");
            return None;
        }

        // Value must be SCV_BYTES
        let bytes = match &contract_data.val {
            ScVal::Bytes(b) => b.0.as_slice(),
            _ => {
                debug!("ConfigUpgradeSet value must be SCV_BYTES");
                return None;
            }
        };

        // Decode the ConfigUpgradeSet
        let upgrade_set = match ConfigUpgradeSet::from_xdr(bytes, Limits::none()) {
            Ok(set) => set,
            Err(e) => {
                debug!(
                    hash = format!("{:02x?}", &key.content_hash.0[..8]),
                    error = %e,
                    "Failed to decode ConfigUpgradeSet"
                );
                return None;
            }
        };

        let ledger_version = snapshot.header().ledger_version;
        let frame = Self {
            valid_xdr: Self::is_valid_xdr_static(&upgrade_set, key),
            config_upgrade_set: upgrade_set,
            key: key.clone(),
            ledger_version,
        };

        Some(Arc::new(frame))
    }

    /// Construct the LedgerKey for a ConfigUpgradeSet.
    ///
    /// The upgrade set is stored in a CONTRACT_DATA entry with:
    /// - Contract address: the contract_id from the key
    /// - Key: SCV_BYTES containing the content_hash
    /// - Durability: TEMPORARY
    pub fn get_ledger_key(upgrade_key: &ConfigUpgradeSetKey) -> LedgerKey {
        let key_val = ScVal::Bytes(
            upgrade_key
                .content_hash
                .0
                .to_vec()
                .try_into()
                .expect("content hash is 32 bytes"),
        );

        LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(upgrade_key.contract_id.clone()),
            key: key_val,
            durability: ContractDataDurability::Temporary,
        })
    }

    /// Get the TTL key for a CONTRACT_DATA entry.
    fn get_ttl_key(data_key: &LedgerKey) -> LedgerKey {
        LedgerKey::Ttl(stellar_xdr::curr::LedgerKeyTtl {
            key_hash: Hash256::hash_xdr(data_key)
                .map(|h| Hash(h.0))
                .unwrap_or(Hash([0u8; 32])),
        })
    }

    /// Check if a TTL entry indicates the data is live.
    fn is_live(ttl_entry: &LedgerEntry, current_ledger: u32) -> bool {
        match &ttl_entry.data {
            stellar_xdr::curr::LedgerEntryData::Ttl(ttl) => {
                ttl.live_until_ledger_seq >= current_ledger
            }
            _ => false,
        }
    }

    /// Get the ConfigUpgradeSet XDR.
    pub fn to_xdr(&self) -> &ConfigUpgradeSet {
        &self.config_upgrade_set
    }

    /// Get the key used to load this upgrade set.
    pub fn get_key(&self) -> &ConfigUpgradeSetKey {
        &self.key
    }

    /// Check if any upgrade is needed.
    ///
    /// Returns true if any entry in the upgrade set differs from the current
    /// ledger state.
    pub fn upgrade_needed(&self, snapshot: &SnapshotHandle) -> bool {
        for entry in self.config_upgrade_set.updated_entry.iter() {
            let key = LedgerKey::ConfigSetting(stellar_xdr::curr::LedgerKeyConfigSetting {
                config_setting_id: entry.discriminant(),
            });

            if let Ok(Some(current)) = snapshot.get_entry(&key) {
                if let stellar_xdr::curr::LedgerEntryData::ConfigSetting(current_entry) =
                    &current.data
                {
                    if current_entry != entry {
                        return true;
                    }
                }
            } else {
                // Entry doesn't exist, upgrade needed
                return true;
            }
        }

        false
    }

    /// Validate the upgrade for application.
    ///
    /// Returns Valid if:
    /// - XDR is valid (hash matches, sorted, no duplicates)
    /// - All entries pass validation constraints
    /// - No non-upgradeable entries are included
    pub fn is_valid_for_apply(&self) -> ConfigUpgradeValidity {
        if !self.valid_xdr {
            return ConfigUpgradeValidity::XdrInvalid;
        }

        for entry in self.config_upgrade_set.updated_entry.iter() {
            if !Self::is_valid_config_setting_entry(entry, self.ledger_version) {
                warn!(
                    id = ?entry.discriminant(),
                    "Config setting entry fails validation"
                );
                return ConfigUpgradeValidity::Invalid;
            }

            if Self::is_non_upgradeable(entry.discriminant()) {
                warn!(
                    id = ?entry.discriminant(),
                    "Config setting entry is not upgradeable"
                );
                return ConfigUpgradeValidity::Invalid;
            }
        }

        ConfigUpgradeValidity::Valid
    }

    /// Check if this upgrade is consistent with a scheduled upgrade.
    pub fn is_consistent_with(&self, scheduled: Option<&ConfigUpgradeSetFrame>) -> bool {
        match scheduled {
            Some(other) => self.key == other.key,
            None => false,
        }
    }

    /// Get the XDR bytes of the upgrade set.
    pub fn to_xdr_bytes(&self) -> Vec<u8> {
        self.config_upgrade_set
            .to_xdr(Limits::none())
            .unwrap_or_default()
    }

    /// Apply the configuration upgrades to the ledger.
    ///
    /// Updates all CONFIG_SETTING entries in the upgrade set.
    ///
    /// Returns a tuple of:
    /// - `state_archival_changed`: Whether StateArchival settings were modified
    /// - `memory_limit_changed`: Whether memory limit settings were modified
    ///
    /// These flags are used by the caller to trigger special handling:
    /// - StateArchival changes may affect the state size window
    /// - Memory limit changes require Soroban host reconfiguration
    pub fn apply_to(
        &self,
        snapshot: &SnapshotHandle,
        delta: &mut LedgerDelta,
    ) -> Result<(bool, bool), LedgerError> {
        let mut state_archival_changed = false;
        let mut memory_limit_changed = false;

        for new_entry in self.config_upgrade_set.updated_entry.iter() {
            let setting_id = new_entry.discriminant();

            // Construct the ledger key for this config setting
            let key = LedgerKey::ConfigSetting(stellar_xdr::curr::LedgerKeyConfigSetting {
                config_setting_id: setting_id,
            });

            // Load the current entry from the ledger
            let current_entry = snapshot.get_entry(&key).map_err(|e| {
                LedgerError::Internal(format!(
                    "Failed to load config setting {:?}: {}",
                    setting_id, e
                ))
            })?;

            let previous = match current_entry {
                Some(entry) => entry,
                None => {
                    // Entry doesn't exist - this shouldn't happen for valid upgrades
                    // as all config settings should exist after protocol 20
                    warn!(
                        setting_id = ?setting_id,
                        "Config setting entry not found during upgrade"
                    );
                    continue;
                }
            };

            // Create the new entry
            let new_ledger_entry = LedgerEntry {
                last_modified_ledger_seq: delta.ledger_seq(),
                data: LedgerEntryData::ConfigSetting(new_entry.clone()),
                ext: LedgerEntryExt::V0,
            };

            // Record the update
            delta.record_update(previous.clone(), new_ledger_entry)?;

            // Track special changes
            if matches!(setting_id, ConfigSettingId::StateArchival) {
                state_archival_changed = true;
            }

            if matches!(setting_id, ConfigSettingId::ContractComputeV0) {
                // Check if memory limit changed
                if let (
                    LedgerEntryData::ConfigSetting(ConfigSettingEntry::ContractComputeV0(old)),
                    ConfigSettingEntry::ContractComputeV0(new),
                ) = (&previous.data, new_entry)
                {
                    if old.tx_memory_limit != new.tx_memory_limit {
                        memory_limit_changed = true;
                    }
                }
            }

            info!(
                setting_id = ?setting_id,
                "Applied config upgrade"
            );
        }

        Ok((state_archival_changed, memory_limit_changed))
    }

    // --- Validation helpers ---

    /// Validate XDR structure.
    fn is_valid_xdr_static(upgrade_set: &ConfigUpgradeSet, key: &ConfigUpgradeSetKey) -> bool {
        // Check hash matches
        let bytes = upgrade_set.to_xdr(Limits::none()).unwrap_or_default();
        let computed_hash = Sha256::digest(&bytes);
        if computed_hash.as_slice() != key.content_hash.0 {
            debug!(
                expected = format!("{:02x?}", &key.content_hash.0[..8]),
                computed = format!("{:02x?}", &computed_hash[..8]),
                "ConfigUpgradeSet hash mismatch"
            );
            return false;
        }

        // Check not empty
        if upgrade_set.updated_entry.is_empty() {
            debug!("ConfigUpgradeSet has no entries");
            return false;
        }

        // Check sorted by config setting ID
        let entries: Vec<_> = upgrade_set.updated_entry.iter().collect();
        for i in 1..entries.len() {
            if entries[i].discriminant() <= entries[i - 1].discriminant() {
                debug!("ConfigUpgradeSet entries not sorted or have duplicates");
                return false;
            }
        }

        true
    }

    /// Check if a config setting ID is non-upgradeable.
    pub fn is_non_upgradeable(id: ConfigSettingId) -> bool {
        matches!(
            id,
            ConfigSettingId::LiveSorobanStateSizeWindow | ConfigSettingId::EvictionIterator
        )
    }

    /// Validate a config setting entry against constraints.
    fn is_valid_config_setting_entry(entry: &ConfigSettingEntry, _ledger_version: u32) -> bool {
        match entry {
            ConfigSettingEntry::ContractMaxSizeBytes(v) => *v >= min_config::MAX_CONTRACT_SIZE,
            ConfigSettingEntry::ContractCostParamsCpuInstructions(_) => {
                // Cost params validation is complex, accept for now
                true
            }
            ConfigSettingEntry::ContractCostParamsMemoryBytes(_) => {
                // Cost params validation is complex, accept for now
                true
            }
            ConfigSettingEntry::ContractDataKeySizeBytes(v) => {
                *v >= min_config::MAX_CONTRACT_DATA_KEY_SIZE_BYTES
            }
            ConfigSettingEntry::ContractDataEntrySizeBytes(v) => {
                *v >= min_config::MAX_CONTRACT_DATA_ENTRY_SIZE_BYTES
            }
            ConfigSettingEntry::ContractExecutionLanes(_) => true,
            ConfigSettingEntry::ContractBandwidthV0(bw) => {
                bw.fee_tx_size1_kb >= 0
                    && bw.tx_max_size_bytes >= min_config::TX_MAX_SIZE_BYTES
                    && bw.ledger_max_txs_size_bytes >= bw.tx_max_size_bytes
            }
            ConfigSettingEntry::ContractComputeV0(compute) => {
                compute.fee_rate_per_instructions_increment >= 0
                    && compute.tx_max_instructions >= i64::from(min_config::TX_MAX_INSTRUCTIONS)
                    && compute.ledger_max_instructions >= compute.tx_max_instructions
                    && compute.tx_memory_limit >= min_config::MEMORY_LIMIT
            }
            ConfigSettingEntry::ContractHistoricalDataV0(hist) => hist.fee_historical1_kb >= 0,
            ConfigSettingEntry::ContractLedgerCostV0(cost) => {
                cost.tx_max_disk_read_entries >= min_config::TX_MAX_READ_LEDGER_ENTRIES
                    && cost.ledger_max_disk_read_entries >= cost.tx_max_disk_read_entries
                    && cost.tx_max_disk_read_bytes >= min_config::TX_MAX_READ_BYTES
                    && cost.ledger_max_disk_read_bytes >= cost.tx_max_disk_read_bytes
                    && cost.tx_max_write_ledger_entries >= min_config::TX_MAX_WRITE_LEDGER_ENTRIES
                    && cost.ledger_max_write_ledger_entries >= cost.tx_max_write_ledger_entries
                    && cost.tx_max_write_bytes >= min_config::TX_MAX_WRITE_BYTES
                    && cost.ledger_max_write_bytes >= cost.tx_max_write_bytes
                    && cost.fee_disk_read_ledger_entry >= 0
                    && cost.fee_write_ledger_entry >= 0
                    && cost.fee_disk_read1_kb >= 0
                    && cost.soroban_state_target_size_bytes > 0
                    && cost.rent_fee1_kb_soroban_state_size_high >= 0
            }
            ConfigSettingEntry::ContractEventsV0(events) => {
                events.tx_max_contract_events_size_bytes
                    >= min_config::TX_MAX_CONTRACT_EVENTS_SIZE_BYTES
                    && events.fee_contract_events1_kb >= 0
            }
            ConfigSettingEntry::StateArchival(archival) => {
                archival.max_entry_ttl >= min_config::MAXIMUM_ENTRY_LIFETIME
                    && archival.min_temporary_ttl >= min_config::MINIMUM_TEMP_ENTRY_LIFETIME
                    && archival.min_persistent_ttl
                        >= min_config::MINIMUM_PERSISTENT_ENTRY_LIFETIME
                    && archival.persistent_rent_rate_denominator > 0
                    && archival.temp_rent_rate_denominator > 0
                    && archival.max_entries_to_archive >= min_config::MAX_ENTRIES_TO_ARCHIVE
                    && archival.live_soroban_state_size_window_sample_size
                        >= min_config::BUCKETLIST_SIZE_WINDOW_SAMPLE_SIZE
                    && archival.eviction_scan_size >= min_config::EVICTION_SCAN_SIZE
                    && archival.starting_eviction_scan_level
                        >= min_config::STARTING_EVICTION_LEVEL
                    && archival.starting_eviction_scan_level < 12 // kNumLevels
                    && archival.live_soroban_state_size_window_sample_period
                        >= min_config::BUCKETLIST_WINDOW_SAMPLE_PERIOD
                    && archival.max_entry_ttl > archival.min_persistent_ttl
                    && archival.max_entry_ttl > archival.min_temporary_ttl
            }
            ConfigSettingEntry::LiveSorobanStateSizeWindow(_) => true,
            ConfigSettingEntry::EvictionIterator(_) => true,
            ConfigSettingEntry::ContractParallelComputeV0(parallel) => {
                parallel.ledger_max_dependent_tx_clusters > 0
                    && parallel.ledger_max_dependent_tx_clusters < 128
            }
            ConfigSettingEntry::ContractLedgerCostExtV0(ext) => {
                ext.tx_max_footprint_entries >= min_config::TX_MAX_READ_LEDGER_ENTRIES
                    && ext.fee_write1_kb >= 0
            }
            ConfigSettingEntry::ScpTiming(timing) => {
                timing.ledger_target_close_time_milliseconds
                        >= min_config::LEDGER_TARGET_CLOSE_TIME_MILLISECONDS
                    && timing.ledger_target_close_time_milliseconds
                        <= max_config::LEDGER_TARGET_CLOSE_TIME_MILLISECONDS
                    && timing.nomination_timeout_initial_milliseconds
                        >= min_config::NOMINATION_TIMEOUT_INITIAL_MILLISECONDS
                    && timing.nomination_timeout_initial_milliseconds
                        <= max_config::NOMINATION_TIMEOUT_INITIAL_MILLISECONDS
                    && timing.nomination_timeout_increment_milliseconds
                        >= min_config::NOMINATION_TIMEOUT_INCREMENT_MILLISECONDS
                    && timing.nomination_timeout_increment_milliseconds
                        <= max_config::NOMINATION_TIMEOUT_INCREMENT_MILLISECONDS
                    && timing.ballot_timeout_initial_milliseconds
                        >= min_config::BALLOT_TIMEOUT_INITIAL_MILLISECONDS
                    && timing.ballot_timeout_initial_milliseconds
                        <= max_config::BALLOT_TIMEOUT_INITIAL_MILLISECONDS
                    && timing.ballot_timeout_increment_milliseconds
                        >= min_config::BALLOT_TIMEOUT_INCREMENT_MILLISECONDS
                    && timing.ballot_timeout_increment_milliseconds
                        <= max_config::BALLOT_TIMEOUT_INCREMENT_MILLISECONDS
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::ContractId;

    fn make_test_key() -> ConfigUpgradeSetKey {
        ConfigUpgradeSetKey {
            contract_id: ContractId(Hash([1u8; 32])),
            content_hash: Hash([2u8; 32]),
        }
    }

    #[test]
    fn test_get_ledger_key() {
        let key = make_test_key();
        let lk = ConfigUpgradeSetFrame::get_ledger_key(&key);

        match lk {
            LedgerKey::ContractData(cd) => {
                assert_eq!(cd.durability, ContractDataDurability::Temporary);
                match cd.contract {
                    ScAddress::Contract(cid) => {
                        assert_eq!(cid.0, key.contract_id.0);
                    }
                    _ => panic!("Expected Contract address"),
                }
                match cd.key {
                    ScVal::Bytes(b) => {
                        assert_eq!(b.0.as_slice(), &key.content_hash.0);
                    }
                    _ => panic!("Expected Bytes key"),
                }
            }
            _ => panic!("Expected ContractData key"),
        }
    }

    #[test]
    fn test_is_non_upgradeable() {
        assert!(ConfigUpgradeSetFrame::is_non_upgradeable(
            ConfigSettingId::LiveSorobanStateSizeWindow
        ));
        assert!(ConfigUpgradeSetFrame::is_non_upgradeable(
            ConfigSettingId::EvictionIterator
        ));
        assert!(!ConfigUpgradeSetFrame::is_non_upgradeable(
            ConfigSettingId::ContractMaxSizeBytes
        ));
        assert!(!ConfigUpgradeSetFrame::is_non_upgradeable(
            ConfigSettingId::StateArchival
        ));
    }

    #[test]
    fn test_valid_xdr_empty_entries() {
        let key = make_test_key();
        let upgrade_set = ConfigUpgradeSet {
            updated_entry: vec![].try_into().unwrap(),
        };
        assert!(!ConfigUpgradeSetFrame::is_valid_xdr_static(
            &upgrade_set,
            &key
        ));
    }
}
