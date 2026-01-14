//! BucketEntry implementation for bucket storage.
//!
//! This module defines the [`BucketEntry`] type and associated utilities for
//! working with entries stored in Stellar buckets. Bucket entries wrap ledger
//! entries with additional metadata for merge semantics.
//!
//! # Entry Types
//!
//! | Type       | Description                                      | Merge Behavior              |
//! |------------|--------------------------------------------------|-----------------------------|
//! | `Live`     | An active ledger entry                           | Newer shadows older         |
//! | `Dead`     | A tombstone marking deletion                     | Shadows any older entry     |
//! | `Init`     | Entry created in this merge window (CAP-0020)    | Special annihilation rules  |
//! | `Metadata` | Bucket metadata (protocol version, type)         | Merged by taking max version|
//!
//! # Key Ordering
//!
//! Entries in a bucket must be sorted by key for correct merge behavior.
//! The ordering is determined by:
//!
//! 1. Entry type discriminant (Account < Trustline < Offer < ...)
//! 2. Type-specific fields in lexicographic order
//!
//! See [`compare_keys`] for the detailed ordering rules.
//!
//! # Eviction Helpers
//!
//! This module also provides helper functions for Soroban state archival:
//!
//! - [`is_soroban_entry`]: Check if an entry is ContractData or ContractCode
//! - [`is_temporary_entry`]: Check if a ContractData entry is temporary
//! - [`is_persistent_entry`]: Check if an entry is persistent (archived on eviction)
//! - [`get_ttl_key`]: Get the TTL key for a Soroban entry
//! - [`is_ttl_expired`]: Check if a TTL entry has expired

use std::cmp::Ordering;

use stellar_xdr::curr::{
    BucketEntry as XdrBucketEntry, BucketEntryType, BucketMetadata, ContractDataDurability,
    Hash, LedgerEntry, LedgerEntryData, LedgerKey, LedgerKeyTtl, ReadXdr, WriteXdr, Limits,
};
use sha2::{Digest, Sha256};

use crate::{BucketError, Result};

/// An entry stored in a bucket.
///
/// Bucket entries wrap ledger entries with additional type information
/// that controls merge semantics. Entries are sorted by key for efficient
/// merging and binary search lookup.
///
/// # Entry Types and Merge Semantics (CAP-0020)
///
/// | Old Entry | New Entry | Result                           |
/// |-----------|-----------|----------------------------------|
/// | `Init`    | `Dead`    | Nothing (both annihilated)       |
/// | `Dead`    | `Init`    | `Live` (recreation)              |
/// | `Init`    | `Live`    | `Init` with new value            |
/// | `Live`    | `Dead`    | `Dead` (if keeping tombstones)   |
/// | `Live`    | `Live`    | Newer `Live` wins                |
///
/// The `Init` type is crucial for correctness: it marks entries created
/// within a merge window so that subsequent deletions can be properly
/// annihilated rather than leaving tombstones.
///
/// # Serialization
///
/// Bucket entries serialize to XDR's `BucketEntry` union type. The
/// discriminant values are:
/// - 0: `LIVEENTRY`
/// - 1: `INITENTRY`
/// - 2: `DEADENTRY`
/// - 3: `METAENTRY`
#[derive(Debug, Clone)]
pub enum BucketEntry {
    /// A live ledger entry (the current state of this key).
    Live(LedgerEntry),
    /// A tombstone marking that this key has been deleted.
    Dead(LedgerKey),
    /// An initialization entry with special CAP-0020 merge semantics.
    ///
    /// Init entries mark entries created within a merge window. When an
    /// Init entry is followed by a Dead entry, both are annihilated
    /// (removed entirely) rather than leaving a tombstone.
    Init(LedgerEntry),
    /// Bucket metadata (protocol version, bucket list type for p23+).
    Metadata(BucketMetadata),
}

impl BucketEntry {
    /// Parse a BucketEntry from XDR bytes.
    pub fn from_xdr(bytes: &[u8]) -> Result<Self> {
        let xdr_entry = XdrBucketEntry::from_xdr(bytes, Limits::none())
            .map_err(|e| BucketError::Serialization(format!("Failed to parse XDR: {}", e)))?;
        Self::from_xdr_entry(xdr_entry)
    }

    /// Convert from XDR BucketEntry.
    pub fn from_xdr_entry(xdr: XdrBucketEntry) -> Result<Self> {
        match xdr {
            XdrBucketEntry::Liveentry(entry) => Ok(BucketEntry::Live(entry)),
            XdrBucketEntry::Initentry(entry) => Ok(BucketEntry::Init(entry)),
            XdrBucketEntry::Deadentry(key) => Ok(BucketEntry::Dead(key)),
            XdrBucketEntry::Metaentry(meta) => Ok(BucketEntry::Metadata(meta)),
        }
    }

    /// Convert to XDR BucketEntry.
    pub fn to_xdr_entry(&self) -> XdrBucketEntry {
        match self {
            BucketEntry::Live(entry) => XdrBucketEntry::Liveentry(entry.clone()),
            BucketEntry::Init(entry) => XdrBucketEntry::Initentry(entry.clone()),
            BucketEntry::Dead(key) => XdrBucketEntry::Deadentry(key.clone()),
            BucketEntry::Metadata(meta) => XdrBucketEntry::Metaentry(meta.clone()),
        }
    }

    /// Serialize to XDR bytes.
    pub fn to_xdr(&self) -> Result<Vec<u8>> {
        self.to_xdr_entry()
            .to_xdr(Limits::none())
            .map_err(|e| BucketError::Serialization(format!("Failed to serialize XDR: {}", e)))
    }

    /// Get the LedgerKey for this entry.
    ///
    /// Returns None for metadata entries since they don't have a key.
    pub fn key(&self) -> Option<LedgerKey> {
        match self {
            BucketEntry::Live(entry) | BucketEntry::Init(entry) => {
                ledger_entry_to_key(entry)
            }
            BucketEntry::Dead(key) => Some(key.clone()),
            BucketEntry::Metadata(_) => None,
        }
    }

    /// Check if this entry is a metadata entry.
    pub fn is_metadata(&self) -> bool {
        matches!(self, BucketEntry::Metadata(_))
    }

    /// Check if this is a dead entry (tombstone).
    pub fn is_dead(&self) -> bool {
        matches!(self, BucketEntry::Dead(_))
    }

    /// Check if this is a live entry.
    pub fn is_live(&self) -> bool {
        matches!(self, BucketEntry::Live(_))
    }

    /// Check if this is an init entry.
    pub fn is_init(&self) -> bool {
        matches!(self, BucketEntry::Init(_))
    }

    /// Get the ledger entry if this is a live or init entry.
    pub fn as_ledger_entry(&self) -> Option<&LedgerEntry> {
        match self {
            BucketEntry::Live(entry) | BucketEntry::Init(entry) => Some(entry),
            _ => None,
        }
    }

    /// Get the bucket entry type.
    pub fn entry_type(&self) -> BucketEntryType {
        match self {
            BucketEntry::Live(_) => BucketEntryType::Liveentry,
            BucketEntry::Dead(_) => BucketEntryType::Deadentry,
            BucketEntry::Init(_) => BucketEntryType::Initentry,
            BucketEntry::Metadata(_) => BucketEntryType::Metaentry,
        }
    }
}

/// Extract a LedgerKey from a LedgerEntry.
pub fn ledger_entry_to_key(entry: &LedgerEntry) -> Option<LedgerKey> {
    use stellar_xdr::curr::*;

    let key = match &entry.data {
        LedgerEntryData::Account(account) => {
            LedgerKey::Account(LedgerKeyAccount {
                account_id: account.account_id.clone(),
            })
        }
        LedgerEntryData::Trustline(trustline) => {
            LedgerKey::Trustline(LedgerKeyTrustLine {
                account_id: trustline.account_id.clone(),
                asset: trustline.asset.clone(),
            })
        }
        LedgerEntryData::Offer(offer) => {
            LedgerKey::Offer(LedgerKeyOffer {
                seller_id: offer.seller_id.clone(),
                offer_id: offer.offer_id,
            })
        }
        LedgerEntryData::Data(data) => {
            LedgerKey::Data(LedgerKeyData {
                account_id: data.account_id.clone(),
                data_name: data.data_name.clone(),
            })
        }
        LedgerEntryData::ClaimableBalance(cb) => {
            LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
                balance_id: cb.balance_id.clone(),
            })
        }
        LedgerEntryData::LiquidityPool(pool) => {
            LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
                liquidity_pool_id: pool.liquidity_pool_id.clone(),
            })
        }
        LedgerEntryData::ContractData(contract_data) => {
            LedgerKey::ContractData(LedgerKeyContractData {
                contract: contract_data.contract.clone(),
                key: contract_data.key.clone(),
                durability: contract_data.durability,
            })
        }
        LedgerEntryData::ContractCode(contract_code) => {
            LedgerKey::ContractCode(LedgerKeyContractCode {
                hash: contract_code.hash.clone(),
            })
        }
        LedgerEntryData::ConfigSetting(config) => {
            LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
                config_setting_id: config.discriminant(),
            })
        }
        LedgerEntryData::Ttl(ttl) => {
            LedgerKey::Ttl(LedgerKeyTtl {
                key_hash: ttl.key_hash.clone(),
            })
        }
    };

    Some(key)
}

/// Compare two LedgerKeys for ordering.
///
/// Keys are sorted first by type discriminant, then by type-specific fields.
/// This ordering is critical for bucket merging to work correctly and must
/// match stellar-core's comparison exactly.
///
/// # Ordering Rules
///
/// 1. **By type discriminant** (as defined in `Stellar-ledger-entries.x`):
///    - Account (0) < Trustline (1) < Offer (2) < Data (3) < ...
///
/// 2. **Within each type**, by type-specific fields in XDR order:
///    - Account: by `account_id`
///    - Trustline: by `account_id`, then `asset`
///    - Offer: by `seller_id`, then `offer_id`
///    - ContractData: by `contract`, then `key`, then `durability`
///    - etc.
///
/// # Determinism
///
/// This function is deterministic and must produce the same ordering as
/// stellar-core's C++ implementation to ensure bucket hashes match.
pub fn compare_keys(a: &LedgerKey, b: &LedgerKey) -> Ordering {
    let a_type = ledger_key_type(a);
    let b_type = ledger_key_type(b);
    match a_type.cmp(&b_type) {
        Ordering::Equal => compare_keys_same_type(a, b),
        other => other,
    }
}

fn ledger_key_type(key: &LedgerKey) -> stellar_xdr::curr::LedgerEntryType {
    match key {
        LedgerKey::Account(_) => stellar_xdr::curr::LedgerEntryType::Account,
        LedgerKey::Trustline(_) => stellar_xdr::curr::LedgerEntryType::Trustline,
        LedgerKey::Offer(_) => stellar_xdr::curr::LedgerEntryType::Offer,
        LedgerKey::Data(_) => stellar_xdr::curr::LedgerEntryType::Data,
        LedgerKey::ClaimableBalance(_) => stellar_xdr::curr::LedgerEntryType::ClaimableBalance,
        LedgerKey::LiquidityPool(_) => stellar_xdr::curr::LedgerEntryType::LiquidityPool,
        LedgerKey::ContractData(_) => stellar_xdr::curr::LedgerEntryType::ContractData,
        LedgerKey::ContractCode(_) => stellar_xdr::curr::LedgerEntryType::ContractCode,
        LedgerKey::ConfigSetting(_) => stellar_xdr::curr::LedgerEntryType::ConfigSetting,
        LedgerKey::Ttl(_) => stellar_xdr::curr::LedgerEntryType::Ttl,
    }
}

fn compare_keys_same_type(a: &LedgerKey, b: &LedgerKey) -> Ordering {
    match (a, b) {
        (LedgerKey::Account(a), LedgerKey::Account(b)) => a.account_id.cmp(&b.account_id),
        (LedgerKey::Trustline(a), LedgerKey::Trustline(b)) => {
            a.account_id
                .cmp(&b.account_id)
                .then_with(|| a.asset.cmp(&b.asset))
        }
        (LedgerKey::Offer(a), LedgerKey::Offer(b)) => a
            .seller_id
            .cmp(&b.seller_id)
            .then_with(|| a.offer_id.cmp(&b.offer_id)),
        (LedgerKey::Data(a), LedgerKey::Data(b)) => a
            .account_id
            .cmp(&b.account_id)
            .then_with(|| a.data_name.cmp(&b.data_name)),
        (LedgerKey::ClaimableBalance(a), LedgerKey::ClaimableBalance(b)) => {
            a.balance_id.cmp(&b.balance_id)
        }
        (LedgerKey::LiquidityPool(a), LedgerKey::LiquidityPool(b)) => {
            a.liquidity_pool_id.cmp(&b.liquidity_pool_id)
        }
        (LedgerKey::ContractData(a), LedgerKey::ContractData(b)) => {
            compare_sc_address(&a.contract, &b.contract)
                .then_with(|| compare_sc_val(&a.key, &b.key))
                .then_with(|| a.durability.cmp(&b.durability))
        }
        (LedgerKey::ContractCode(a), LedgerKey::ContractCode(b)) => a.hash.cmp(&b.hash),
        (LedgerKey::ConfigSetting(a), LedgerKey::ConfigSetting(b)) => {
            a.config_setting_id.cmp(&b.config_setting_id)
        }
        (LedgerKey::Ttl(a), LedgerKey::Ttl(b)) => a.key_hash.cmp(&b.key_hash),
        _ => Ordering::Equal,
    }
}

fn compare_sc_address(
    a: &stellar_xdr::curr::ScAddress,
    b: &stellar_xdr::curr::ScAddress,
) -> Ordering {
    a.cmp(b)
}

fn compare_sc_val(
    a: &stellar_xdr::curr::ScVal,
    b: &stellar_xdr::curr::ScVal,
) -> Ordering {
    a.cmp(b)
}

/// Compare two BucketEntry values by key.
///
/// Metadata entries are always sorted first.
/// Returns None if either entry is metadata and the other is not.
pub fn compare_entries(a: &BucketEntry, b: &BucketEntry) -> Ordering {
    match (a.key(), b.key()) {
        (Some(key_a), Some(key_b)) => compare_keys(&key_a, &key_b),
        (None, Some(_)) => Ordering::Less,  // Metadata comes first
        (Some(_), None) => Ordering::Greater,
        (None, None) => Ordering::Equal,    // Both metadata
    }
}

// ============================================================================
// Eviction helper functions (Soroban State Archival)
// ============================================================================
//
// These functions support the incremental eviction scan for Soroban entries.
// Soroban uses a time-to-live (TTL) mechanism where entries expire and must
// be either deleted (temporary) or archived (persistent).

/// Check if a ledger entry is a Soroban entry (ContractData or ContractCode).
///
/// Soroban entries are the only entry types subject to eviction and state
/// archival. They have associated TTL entries that track when they expire.
///
/// # Returns
///
/// `true` if the entry is `ContractData` or `ContractCode`, `false` otherwise.
pub fn is_soroban_entry(entry: &LedgerEntry) -> bool {
    matches!(
        entry.data,
        LedgerEntryData::ContractData(_) | LedgerEntryData::ContractCode(_)
    )
}

/// Check if a ledger key is for a Soroban entry.
pub fn is_soroban_key(key: &LedgerKey) -> bool {
    matches!(key, LedgerKey::ContractData(_) | LedgerKey::ContractCode(_))
}

/// Check if a ledger entry is a temporary Soroban entry.
///
/// Temporary entries (ContractData with `Temporary` durability) are deleted
/// immediately on eviction and are NOT archived to the hot archive bucket list.
///
/// # Use Case
///
/// Temporary data is used for values that don't need to persist across
/// archival, such as caches or ephemeral state.
pub fn is_temporary_entry(entry: &LedgerEntry) -> bool {
    if let LedgerEntryData::ContractData(data) = &entry.data {
        data.durability == ContractDataDurability::Temporary
    } else {
        false
    }
}

/// Check if a ledger entry is a persistent Soroban entry.
///
/// Persistent entries (ContractCode or ContractData with `Persistent` durability)
/// are archived to the hot archive bucket list on eviction. They can later be
/// restored to the live bucket list by paying for additional TTL.
///
/// # Persistent Entry Types
///
/// - All `ContractCode` entries (WASM code is always persistent)
/// - `ContractData` entries with `Persistent` durability
pub fn is_persistent_entry(entry: &LedgerEntry) -> bool {
    match &entry.data {
        LedgerEntryData::ContractCode(_) => true,
        LedgerEntryData::ContractData(data) => {
            data.durability == ContractDataDurability::Persistent
        }
        _ => false,
    }
}

/// Get the TTL key for a Soroban entry.
///
/// Each Soroban entry has an associated TTL entry that tracks its expiration.
/// The TTL key is derived by hashing the original key with SHA-256.
///
/// # How TTL Works
///
/// TTL entries contain a `live_until_ledger_seq` field. When the current
/// ledger exceeds this value, the entry is considered expired and will be
/// evicted during the next eviction scan that encounters it.
///
/// # Returns
///
/// - `Some(LedgerKey::Ttl)` with the key hash for Soroban entries
/// - `None` for non-Soroban entries (they don't have TTL)
pub fn get_ttl_key(key: &LedgerKey) -> Option<LedgerKey> {
    if !is_soroban_key(key) {
        return None;
    }

    // Serialize the key to XDR and hash it
    let key_bytes = key.to_xdr(Limits::none()).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&key_bytes);
    let hash_result = hasher.finalize();

    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash_result);

    Some(LedgerKey::Ttl(LedgerKeyTtl {
        key_hash: Hash(hash_bytes),
    }))
}

/// Check if a TTL entry is expired at the given ledger sequence.
///
/// An entry is expired when its `live_until_ledger_seq` is less than the current ledger.
/// Returns None if the entry is not a TTL entry.
pub fn is_ttl_expired(ttl_entry: &LedgerEntry, current_ledger: u32) -> Option<bool> {
    get_ttl_live_until(ttl_entry).map(|live_until| live_until < current_ledger)
}

/// Get the live_until_ledger_seq from a TTL entry.
///
/// Returns None if the entry is not a TTL entry.
pub fn get_ttl_live_until(ttl_entry: &LedgerEntry) -> Option<u32> {
    if let LedgerEntryData::Ttl(ttl) = &ttl_entry.data {
        Some(ttl.live_until_ledger_seq)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;
    use crate::BucketEntry; // Re-import to shadow XDR's BucketEntry

    fn make_account_id(bytes: [u8; 32]) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes)))
    }

    fn make_account_entry(bytes: [u8; 32]) -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 1,
            data: LedgerEntryData::Account(AccountEntry {
                account_id: make_account_id(bytes),
                balance: 100,
                seq_num: SequenceNumber(1),
                num_sub_entries: 0,
                inflation_dest: None,
                flags: 0,
                home_domain: String32::default(),
                thresholds: Thresholds([1, 0, 0, 0]),
                signers: Vec::new().try_into().unwrap(),
                ext: AccountEntryExt::V0,
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    #[test]
    fn test_bucket_entry_key() {
        let entry = make_account_entry([1u8; 32]);
        let bucket_entry = BucketEntry::Live(entry.clone());

        let key = bucket_entry.key().unwrap();
        if let LedgerKey::Account(account_key) = key {
            assert_eq!(account_key.account_id, make_account_id([1u8; 32]));
        } else {
            panic!("Expected Account key");
        }
    }

    #[test]
    fn test_bucket_entry_dead() {
        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: make_account_id([2u8; 32]),
        });
        let bucket_entry = BucketEntry::Dead(key.clone());

        assert!(bucket_entry.is_dead());
        assert!(!bucket_entry.is_live());
        assert_eq!(bucket_entry.key().unwrap(), key);
    }

    #[test]
    fn test_compare_keys_same_type() {
        let key1 = LedgerKey::Account(LedgerKeyAccount {
            account_id: make_account_id([1u8; 32]),
        });
        let key2 = LedgerKey::Account(LedgerKeyAccount {
            account_id: make_account_id([2u8; 32]),
        });

        assert_eq!(compare_keys(&key1, &key2), Ordering::Less);
        assert_eq!(compare_keys(&key2, &key1), Ordering::Greater);
        assert_eq!(compare_keys(&key1, &key1), Ordering::Equal);
    }

    #[test]
    fn test_compare_entries() {
        let entry1 = BucketEntry::Live(make_account_entry([1u8; 32]));
        let entry2 = BucketEntry::Live(make_account_entry([2u8; 32]));

        assert_eq!(compare_entries(&entry1, &entry2), Ordering::Less);
    }

    #[test]
    fn test_entry_type() {
        let live = BucketEntry::Live(make_account_entry([1u8; 32]));
        let dead = BucketEntry::Dead(LedgerKey::Account(LedgerKeyAccount {
            account_id: make_account_id([1u8; 32]),
        }));
        let init = BucketEntry::Init(make_account_entry([1u8; 32]));

        assert_eq!(live.entry_type(), BucketEntryType::Liveentry);
        assert_eq!(dead.entry_type(), BucketEntryType::Deadentry);
        assert_eq!(init.entry_type(), BucketEntryType::Initentry);
    }

    #[test]
    fn test_ledger_entry_type_discriminants() {
        // These values MUST match stellar-core's XDR definition for correct sorting
        // See Stellar-ledger-entries.x in stellar/stellar-xdr
        assert_eq!(LedgerEntryType::Account as i32, 0);
        assert_eq!(LedgerEntryType::Trustline as i32, 1);
        assert_eq!(LedgerEntryType::Offer as i32, 2);
        assert_eq!(LedgerEntryType::Data as i32, 3);
        assert_eq!(LedgerEntryType::ClaimableBalance as i32, 4);
        assert_eq!(LedgerEntryType::LiquidityPool as i32, 5);
        assert_eq!(LedgerEntryType::ContractData as i32, 6);
        assert_eq!(LedgerEntryType::ContractCode as i32, 7);
        assert_eq!(LedgerEntryType::ConfigSetting as i32, 8);
        assert_eq!(LedgerEntryType::Ttl as i32, 9);
    }

    #[test]
    fn test_compare_keys_different_types() {
        // Ensure keys of different types are compared by type discriminant first
        let account_key = LedgerKey::Account(LedgerKeyAccount {
            account_id: make_account_id([255u8; 32]), // Highest possible account
        });
        let trustline_key = LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: make_account_id([0u8; 32]), // Lowest possible account
            asset: TrustLineAsset::Native,
        });

        // Account (type 0) should sort before Trustline (type 1), regardless of account bytes
        assert_eq!(compare_keys(&account_key, &trustline_key), Ordering::Less);
        assert_eq!(compare_keys(&trustline_key, &account_key), Ordering::Greater);
    }
}
