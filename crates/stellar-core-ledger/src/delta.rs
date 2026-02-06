//! Change tracking for ledger close operations.
//!
//! This module provides [`LedgerDelta`], which accumulates all state changes
//! during the processing of a single ledger. The delta serves as the
//! transaction log for the ledger close, enabling:
//!
//! - **Bucket list updates**: Changes are applied to the Merkle tree
//! - **Transaction metadata**: Change history for each transaction
//! - **Database updates**: Persistent storage synchronization
//! - **Invariant checking**: Validation of state consistency
//!
//! # Change Semantics
//!
//! The delta tracks three types of changes via [`EntryChange`]:
//!
//! - **Created**: New entries that didn't exist before
//! - **Updated**: Existing entries with modified values
//! - **Deleted**: Entries that have been removed
//!
//! # Change Coalescing
//!
//! When multiple operations affect the same entry within a ledger, changes
//! are coalesced to produce the minimal final diff:
//!
//! - Create + Update = Create (with final value)
//! - Create + Delete = No change (entry never existed in previous state)
//! - Update + Update = Update (original previous, final current)
//! - Update + Delete = Delete (original previous)

use crate::{LedgerError, Result};
use std::collections::HashMap;
use stellar_xdr::curr::{LedgerEntry, LedgerKey, Limits, WriteXdr};

/// Represents a single change to a ledger entry.
///
/// Each change captures enough information to:
/// - Apply the change to the bucket list (forward)
/// - Reconstruct the previous state (backward)
/// - Generate transaction metadata
///
/// # Bucket List Categories
///
/// Changes map to bucket list update categories:
/// - `Created` entries go to the "init" batch
/// - `Updated` entries go to the "live" batch
/// - `Deleted` entries go to the "dead" batch
#[derive(Debug, Clone)]
pub enum EntryChange {
    /// A new entry was created (did not exist in previous ledger state).
    Created(LedgerEntry),
    /// An existing entry was modified.
    Updated {
        /// The entry value before the update (for rollback/metadata).
        previous: LedgerEntry,
        /// The entry value after the update.
        current: Box<LedgerEntry>,
    },
    /// An entry was deleted (existed in previous state, now gone).
    Deleted {
        /// The entry that was deleted (for rollback/metadata).
        previous: LedgerEntry,
    },
}

impl EntryChange {
    /// Get the ledger key for this change.
    pub fn key(&self) -> Result<LedgerKey> {
        match self {
            EntryChange::Created(entry) => entry_to_key(entry),
            EntryChange::Updated { current, .. } => entry_to_key(current),
            EntryChange::Deleted { previous } => entry_to_key(previous),
        }
    }

    /// Get the current entry value, if any.
    pub fn current_entry(&self) -> Option<&LedgerEntry> {
        match self {
            EntryChange::Created(entry) => Some(entry),
            EntryChange::Updated { current, .. } => Some(current.as_ref()),
            EntryChange::Deleted { .. } => None,
        }
    }

    /// Get the previous entry value, if any.
    pub fn previous_entry(&self) -> Option<&LedgerEntry> {
        match self {
            EntryChange::Created(_) => None,
            EntryChange::Updated { previous, .. } => Some(previous),
            EntryChange::Deleted { previous } => Some(previous),
        }
    }

    /// Check if this is a creation.
    pub fn is_created(&self) -> bool {
        matches!(self, EntryChange::Created(_))
    }

    /// Check if this is an update.
    pub fn is_updated(&self) -> bool {
        matches!(self, EntryChange::Updated { .. })
    }

    /// Check if this is a deletion.
    pub fn is_deleted(&self) -> bool {
        matches!(self, EntryChange::Deleted { .. })
    }
}

/// Extract the ledger key from a ledger entry.
///
/// Each ledger entry type has a corresponding key type that uniquely
/// identifies it. This function extracts the appropriate key fields
/// from the entry data.
///
/// # Supported Entry Types
///
/// - Account, Trustline, Offer, Data
/// - ClaimableBalance, LiquidityPool
/// - ContractData, ContractCode, ConfigSetting, Ttl (Soroban)
pub fn entry_to_key(entry: &LedgerEntry) -> Result<LedgerKey> {
    use stellar_xdr::curr::LedgerEntryData;

    let key = match &entry.data {
        LedgerEntryData::Account(account) => {
            LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
                account_id: account.account_id.clone(),
            })
        }
        LedgerEntryData::Trustline(trustline) => {
            LedgerKey::Trustline(stellar_xdr::curr::LedgerKeyTrustLine {
                account_id: trustline.account_id.clone(),
                asset: trustline.asset.clone(),
            })
        }
        LedgerEntryData::Offer(offer) => LedgerKey::Offer(stellar_xdr::curr::LedgerKeyOffer {
            seller_id: offer.seller_id.clone(),
            offer_id: offer.offer_id,
        }),
        LedgerEntryData::Data(data) => LedgerKey::Data(stellar_xdr::curr::LedgerKeyData {
            account_id: data.account_id.clone(),
            data_name: data.data_name.clone(),
        }),
        LedgerEntryData::ClaimableBalance(cb) => {
            LedgerKey::ClaimableBalance(stellar_xdr::curr::LedgerKeyClaimableBalance {
                balance_id: cb.balance_id.clone(),
            })
        }
        LedgerEntryData::LiquidityPool(pool) => {
            LedgerKey::LiquidityPool(stellar_xdr::curr::LedgerKeyLiquidityPool {
                liquidity_pool_id: pool.liquidity_pool_id.clone(),
            })
        }
        LedgerEntryData::ContractData(data) => {
            LedgerKey::ContractData(stellar_xdr::curr::LedgerKeyContractData {
                contract: data.contract.clone(),
                key: data.key.clone(),
                durability: data.durability,
            })
        }
        LedgerEntryData::ContractCode(code) => {
            LedgerKey::ContractCode(stellar_xdr::curr::LedgerKeyContractCode {
                hash: code.hash.clone(),
            })
        }
        LedgerEntryData::ConfigSetting(setting) => {
            LedgerKey::ConfigSetting(stellar_xdr::curr::LedgerKeyConfigSetting {
                config_setting_id: setting.discriminant(),
            })
        }
        LedgerEntryData::Ttl(ttl) => LedgerKey::Ttl(stellar_xdr::curr::LedgerKeyTtl {
            key_hash: ttl.key_hash.clone(),
        }),
    };

    Ok(key)
}

/// Serialize a ledger key to bytes for use as a hash map key.
///
/// Uses XDR encoding to produce a canonical byte representation of the key.
/// This ensures consistent hashing regardless of how the key was constructed.
pub fn key_to_bytes(key: &LedgerKey) -> Result<Vec<u8>> {
    key.to_xdr(Limits::none())
        .map_err(|e| LedgerError::Serialization(e.to_string()))
}

/// Accumulator for all ledger entry changes during a single ledger close.
///
/// `LedgerDelta` provides a transactional view of state changes, allowing
/// multiple operations to modify entries with automatic change coalescing.
/// The final delta represents the minimal diff between the previous and
/// new ledger state.
///
/// # Usage
///
/// ```ignore
/// let mut delta = LedgerDelta::new(ledger_seq);
///
/// // Record changes during transaction processing
/// delta.record_create(new_account)?;
/// delta.record_update(old_trustline, new_trustline)?;
/// delta.record_delete(expired_offer)?;
///
/// // Get categorized changes for bucket list update
/// let init_entries = delta.init_entries();   // Created
/// let live_entries = delta.live_entries();   // Updated
/// let dead_entries = delta.dead_entries();   // Deleted
/// ```
///
/// # Deterministic Ordering
///
/// Changes are tracked in insertion order to ensure deterministic iteration.
/// This is critical for producing consistent bucket list updates across nodes.
#[derive(Debug)]
pub struct LedgerDelta {
    /// The ledger sequence this delta applies to.
    ledger_seq: u32,

    /// All entry changes, keyed by XDR-encoded LedgerKey.
    changes: HashMap<Vec<u8>, EntryChange>,

    /// Keys in the order changes were first recorded (for deterministic iteration).
    change_order: Vec<Vec<u8>>,

    /// Net change to the fee pool (positive = fees collected).
    fee_pool_delta: i64,

    /// Net change to total coins in circulation.
    ///
    /// Typically zero, but can change due to inflation or fee burns.
    total_coins_delta: i64,
}

impl LedgerDelta {
    /// Create a new empty LedgerDelta.
    pub fn new(ledger_seq: u32) -> Self {
        Self {
            ledger_seq,
            changes: HashMap::new(),
            change_order: Vec::new(),
            fee_pool_delta: 0,
            total_coins_delta: 0,
        }
    }

    /// Get the ledger sequence this delta is for.
    pub fn ledger_seq(&self) -> u32 {
        self.ledger_seq
    }

    /// Record the creation of a new entry.
    ///
    /// If the entry already exists in the delta:
    /// - If it was created, update with the new value
    /// - If it was updated, keep original previous and update current
    /// - If it was deleted, return error (can't create a deleted entry)
    pub fn record_create(&mut self, entry: LedgerEntry) -> Result<()> {
        let key = entry_to_key(&entry)?;
        let key_bytes = key_to_bytes(&key)?;

        if let Some(existing) = self.changes.get(&key_bytes) {
            match existing {
                EntryChange::Created(_) => {
                    // Entry was already created, update with new value
                    self.changes.insert(key_bytes, EntryChange::Created(entry));
                }
                EntryChange::Updated { previous, .. } => {
                    // Entry was updated, keep original previous and update current
                    self.changes.insert(
                        key_bytes,
                        EntryChange::Updated {
                            previous: previous.clone(),
                            current: Box::new(entry),
                        },
                    );
                }
                EntryChange::Deleted { previous } => {
                    // Deleted then created = update (entry existed before the ledger,
                    // was deleted, then recreated - net effect is an update).
                    self.changes.insert(
                        key_bytes,
                        EntryChange::Updated {
                            previous: previous.clone(),
                            current: Box::new(entry),
                        },
                    );
                }
            }
        } else {
            self.change_order.push(key_bytes.clone());
            self.changes.insert(key_bytes, EntryChange::Created(entry));
        }
        Ok(())
    }

    /// Record an update to an existing entry.
    pub fn record_update(&mut self, previous: LedgerEntry, current: LedgerEntry) -> Result<()> {
        let key = entry_to_key(&current)?;
        let key_bytes = key_to_bytes(&key)?;

        // Check if we already have a change for this entry
        if let Some(existing) = self.changes.get(&key_bytes) {
            match existing {
                EntryChange::Created(_) => {
                    // If we created and then updated, just record as created with new value
                    self.changes
                        .insert(key_bytes, EntryChange::Created(current));
                }
                EntryChange::Updated { previous: orig, .. } => {
                    // Update the current value, keep original previous
                    self.changes.insert(
                        key_bytes,
                        EntryChange::Updated {
                            previous: orig.clone(),
                            current: Box::new(current),
                        },
                    );
                }
                EntryChange::Deleted { previous: orig } => {
                    // Deleted then updated = entry was deleted then came back
                    // (e.g., via fee refund restore). Keep original previous.
                    self.changes.insert(
                        key_bytes,
                        EntryChange::Updated {
                            previous: orig.clone(),
                            current: Box::new(current),
                        },
                    );
                }
            }
        } else {
            self.change_order.push(key_bytes.clone());
            self.changes
                .insert(key_bytes, EntryChange::Updated { previous, current: Box::new(current) });
        }

        Ok(())
    }

    /// Record the deletion of an entry.
    ///
    /// If the entry already exists in the delta:
    /// - If it was created, remove from delta entirely (create + delete = no-op)
    /// - If it was updated, record as deleted with original previous
    /// - If it was already deleted, skip (idempotent delete)
    pub fn record_delete(&mut self, entry: LedgerEntry) -> Result<()> {
        let key = entry_to_key(&entry)?;
        let key_bytes = key_to_bytes(&key)?;

        // Check if we already have a change for this entry
        if let Some(existing) = self.changes.get(&key_bytes) {
            match existing {
                EntryChange::Created(_) => {
                    // If we created and then deleted, remove from delta entirely
                    self.changes.remove(&key_bytes);
                    self.change_order.retain(|k| k != &key_bytes);
                }
                EntryChange::Updated { previous, .. } => {
                    // If we updated and then deleted, record as deleted with original previous
                    self.changes.insert(
                        key_bytes,
                        EntryChange::Deleted {
                            previous: previous.clone(),
                        },
                    );
                }
                EntryChange::Deleted { .. } => {
                    // Entry already deleted, this is a no-op (idempotent delete)
                    // This can happen during replay when entries are processed multiple times
                }
            }
        } else {
            self.change_order.push(key_bytes.clone());
            self.changes
                .insert(key_bytes, EntryChange::Deleted { previous: entry });
        }

        Ok(())
    }

    /// Record a fee pool change.
    pub fn record_fee_pool_delta(&mut self, delta: i64) {
        self.fee_pool_delta += delta;
    }

    /// Record a total coins change (e.g., from inflation).
    pub fn record_total_coins_delta(&mut self, delta: i64) {
        self.total_coins_delta += delta;
    }

    /// Get the fee pool delta.
    pub fn fee_pool_delta(&self) -> i64 {
        self.fee_pool_delta
    }

    /// Get the total coins delta.
    pub fn total_coins_delta(&self) -> i64 {
        self.total_coins_delta
    }

    /// Get all entry changes in the order they were recorded.
    pub fn changes(&self) -> impl Iterator<Item = &EntryChange> {
        self.change_order.iter().filter_map(|k| self.changes.get(k))
    }

    /// Get the number of changes.
    pub fn num_changes(&self) -> usize {
        self.changes.len()
    }

    /// Check if there are any changes.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Get all init entries (created) for bucket list update.
    pub fn init_entries(&self) -> Vec<LedgerEntry> {
        self.changes()
            .filter(|change| change.is_created())
            .filter_map(|change| change.current_entry().cloned())
            .collect()
    }

    /// Get all live entries (updated) for bucket list update.
    pub fn live_entries(&self) -> Vec<LedgerEntry> {
        self.changes()
            .filter(|change| change.is_updated())
            .filter_map(|change| change.current_entry().cloned())
            .collect()
    }

    /// Get all dead entries (deleted keys) for bucket list update.
    pub fn dead_entries(&self) -> Vec<LedgerKey> {
        self.changes()
            .filter(|change| change.is_deleted())
            .filter_map(|change| change.key().ok())
            .collect()
    }

    /// Get a specific change by key.
    pub fn get_change(&self, key: &LedgerKey) -> Result<Option<&EntryChange>> {
        let key_bytes = key_to_bytes(key)?;
        Ok(self.changes.get(&key_bytes))
    }

    /// Merge another delta into this one.
    ///
    /// This is useful when combining changes from multiple operations.
    pub fn merge(&mut self, other: LedgerDelta) -> Result<()> {
        for key_bytes in other.change_order {
            if let Some(change) = other.changes.get(&key_bytes) {
                match change {
                    EntryChange::Created(entry) => {
                        if let Some(existing) = self.changes.get(&key_bytes) {
                            match existing {
                                EntryChange::Deleted { previous } => {
                                    // Deleted then created = update
                                    self.changes.insert(
                                        key_bytes,
                                        EntryChange::Updated {
                                            previous: previous.clone(),
                                            current: Box::new(entry.clone()),
                                        },
                                    );
                                }
                                _ => {
                                    return Err(LedgerError::Internal(
                                        "invalid merge: create on existing entry".to_string(),
                                    ));
                                }
                            }
                        } else {
                            self.change_order.push(key_bytes.clone());
                            self.changes
                                .insert(key_bytes, EntryChange::Created(entry.clone()));
                        }
                    }
                    EntryChange::Updated { previous, current } => {
                        if let Some(existing) = self.changes.get(&key_bytes) {
                            match existing {
                                EntryChange::Created(_) => {
                                    self.changes
                                        .insert(key_bytes, EntryChange::Created(current.as_ref().clone()));
                                }
                                EntryChange::Updated { previous: orig, .. } => {
                                    self.changes.insert(
                                        key_bytes,
                                        EntryChange::Updated {
                                            previous: orig.clone(),
                                            current: current.clone(),
                                        },
                                    );
                                }
                                EntryChange::Deleted { .. } => {
                                    return Err(LedgerError::Internal(
                                        "invalid merge: update on deleted entry".to_string(),
                                    ));
                                }
                            }
                        } else {
                            // Entry not in target delta — insert the full update.
                            // This occurs when merging independent deltas (e.g. parallel
                            // cluster execution) where each delta carries its own
                            // previous/current state.
                            self.change_order.push(key_bytes.clone());
                            self.changes.insert(
                                key_bytes,
                                EntryChange::Updated {
                                    previous: previous.clone(),
                                    current: current.clone(),
                                },
                            );
                        }
                    }
                    EntryChange::Deleted { previous } => {
                        if let Some(existing) = self.changes.get(&key_bytes) {
                            match existing {
                                EntryChange::Created(_) => {
                                    // Created then deleted = no change
                                    self.changes.remove(&key_bytes);
                                    self.change_order.retain(|k| k != &key_bytes);
                                }
                                EntryChange::Updated { previous: orig, .. } => {
                                    self.changes.insert(
                                        key_bytes,
                                        EntryChange::Deleted {
                                            previous: orig.clone(),
                                        },
                                    );
                                }
                                EntryChange::Deleted { .. } => {
                                    return Err(LedgerError::Internal(
                                        "invalid merge: delete on deleted entry".to_string(),
                                    ));
                                }
                            }
                        } else {
                            self.change_order.push(key_bytes.clone());
                            self.changes.insert(
                                key_bytes,
                                EntryChange::Deleted {
                                    previous: previous.clone(),
                                },
                            );
                        }
                    }
                }
            }
        }

        self.fee_pool_delta += other.fee_pool_delta;
        self.total_coins_delta += other.total_coins_delta;

        Ok(())
    }

    /// Clear all changes.
    pub fn clear(&mut self) {
        self.changes.clear();
        self.change_order.clear();
        self.fee_pool_delta = 0;
        self.total_coins_delta = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        AccountEntry, AccountEntryExt, AccountId, LedgerEntryData, LedgerEntryExt, PublicKey,
        SequenceNumber, Thresholds, Uint256,
    };

    fn create_test_account(seed: u8) -> LedgerEntry {
        let mut key = [0u8; 32];
        key[0] = seed;

        LedgerEntry {
            last_modified_ledger_seq: 1,
            data: LedgerEntryData::Account(AccountEntry {
                account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key))),
                balance: 1000000000,
                seq_num: SequenceNumber(1),
                num_sub_entries: 0,
                inflation_dest: None,
                flags: 0,
                home_domain: stellar_xdr::curr::String32::default(),
                thresholds: Thresholds([1, 0, 0, 0]),
                signers: stellar_xdr::curr::VecM::default(),
                ext: AccountEntryExt::V0,
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    #[test]
    fn test_record_create() {
        let mut delta = LedgerDelta::new(1);
        let entry = create_test_account(1);

        delta.record_create(entry.clone()).unwrap();
        assert_eq!(delta.num_changes(), 1);

        let init = delta.init_entries();
        assert_eq!(init.len(), 1);
    }

    #[test]
    fn test_record_update() {
        let mut delta = LedgerDelta::new(1);
        let entry1 = create_test_account(1);
        let mut entry2 = entry1.clone();
        if let LedgerEntryData::Account(ref mut acc) = entry2.data {
            acc.balance = 2000000000;
        }

        delta.record_update(entry1, entry2).unwrap();
        assert_eq!(delta.num_changes(), 1);

        let changes: Vec<_> = delta.changes().collect();
        assert!(changes[0].is_updated());
    }

    #[test]
    fn test_record_delete() {
        let mut delta = LedgerDelta::new(1);
        let entry = create_test_account(1);

        delta.record_delete(entry).unwrap();
        assert_eq!(delta.num_changes(), 1);

        let dead = delta.dead_entries();
        assert_eq!(dead.len(), 1);
    }

    #[test]
    fn test_create_then_delete() {
        let mut delta = LedgerDelta::new(1);
        let entry = create_test_account(1);

        delta.record_create(entry.clone()).unwrap();
        delta.record_delete(entry).unwrap();

        // Should cancel out
        assert!(delta.is_empty());
    }

    #[test]
    fn test_create_then_update() {
        let mut delta = LedgerDelta::new(1);
        let entry1 = create_test_account(1);
        let mut entry2 = entry1.clone();
        if let LedgerEntryData::Account(ref mut acc) = entry2.data {
            acc.balance = 2000000000;
        }

        delta.record_create(entry1.clone()).unwrap();
        delta.record_update(entry1, entry2.clone()).unwrap();

        // Should be recorded as a create with the final value
        assert_eq!(delta.num_changes(), 1);
        let changes: Vec<_> = delta.changes().collect();
        assert!(changes[0].is_created());
    }
}
