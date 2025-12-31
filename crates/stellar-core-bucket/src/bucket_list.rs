//! BucketList implementation - the full hierarchical bucket structure.
//!
//! The BucketList is Stellar's core data structure for storing ledger state.
//! It consists of 11 levels, where each level contains two buckets (curr and snap).
//!
//! Level 0 spills every ledger.
//! Level N spills every 2^(2N) ledgers.
//!
//! This creates a log-structured merge tree that efficiently handles
//! incremental updates while maintaining full history integrity.

use std::sync::Arc;

use sha2::{Digest, Sha256};
use stellar_xdr::curr::{LedgerEntry, LedgerKey};

use stellar_core_common::Hash256;

use crate::bucket::Bucket;
use crate::entry::BucketEntry;
use crate::merge::merge_buckets;
use crate::{BucketError, Result};

/// Number of levels in the BucketList.
pub const BUCKET_LIST_LEVELS: usize = 11;

/// A level in the BucketList, containing curr and snap buckets.
#[derive(Clone, Debug)]
pub struct BucketLevel {
    /// The current bucket being filled.
    pub curr: Bucket,
    /// The snapshot from the previous merge.
    pub snap: Bucket,
    /// The level number (0-10).
    level: usize,
}

impl BucketLevel {
    /// Create a new empty level.
    pub fn new(level: usize) -> Self {
        Self {
            curr: Bucket::empty(),
            snap: Bucket::empty(),
            level,
        }
    }

    /// Get the hash of this level: SHA256(curr_hash || snap_hash).
    ///
    /// This matches stellar-core's BucketLevel::getHash() implementation.
    pub fn hash(&self) -> Hash256 {
        let curr_hash = self.curr.hash();
        let snap_hash = self.snap.hash();

        // SHA256(curr_hash || snap_hash)
        let mut hasher = Sha256::new();
        hasher.update(curr_hash.as_bytes());
        hasher.update(snap_hash.as_bytes());
        let result = hasher.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Hash256::from_bytes(bytes)
    }

    /// Set the curr bucket.
    pub fn set_curr(&mut self, bucket: Bucket) {
        self.curr = bucket;
    }

    /// Set the snap bucket.
    pub fn set_snap(&mut self, bucket: Bucket) {
        self.snap = bucket;
    }

    /// Get the level number.
    pub fn level_number(&self) -> usize {
        self.level
    }
}

impl Default for BucketLevel {
    fn default() -> Self {
        Self::new(0)
    }
}

/// The complete BucketList structure.
///
/// Contains 11 levels of buckets that together represent
/// the entire ledger state at a given point in time.
///
/// Each level contains:
/// - `curr`: The current bucket being filled
/// - `snap`: The snapshot from the previous spill
///
/// Spill frequency:
/// - Level 0 spills every ledger
/// - Level N spills every 2^(2N) ledgers
#[derive(Clone)]
pub struct BucketList {
    /// The levels in the bucket list.
    levels: Vec<BucketLevel>,
    /// The current ledger sequence.
    ledger_seq: u32,
}

impl BucketList {
    /// Number of levels in the BucketList.
    pub const NUM_LEVELS: usize = BUCKET_LIST_LEVELS;

    /// Create a new empty BucketList.
    pub fn new() -> Self {
        let levels = (0..BUCKET_LIST_LEVELS)
            .map(BucketLevel::new)
            .collect();

        Self {
            levels,
            ledger_seq: 0,
        }
    }

    /// Get the hash of the entire BucketList.
    ///
    /// This is computed by hashing all level hashes together.
    pub fn hash(&self) -> Hash256 {
        let mut hasher = Sha256::new();

        for level in &self.levels {
            hasher.update(level.hash().as_bytes());
        }

        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Hash256::from_bytes(bytes)
    }

    /// Get the current ledger sequence.
    pub fn ledger_seq(&self) -> u32 {
        self.ledger_seq
    }

    /// Get a reference to a level.
    pub fn level(&self, idx: usize) -> Option<&BucketLevel> {
        self.levels.get(idx)
    }

    /// Get a mutable reference to a level.
    pub fn level_mut(&mut self, idx: usize) -> Option<&mut BucketLevel> {
        self.levels.get_mut(idx)
    }

    /// Get all levels.
    pub fn levels(&self) -> &[BucketLevel] {
        &self.levels
    }

    /// Look up an entry by its key.
    ///
    /// Searches from the newest (level 0) to oldest levels.
    /// Returns the first matching entry found, or None if not found.
    pub fn get(&self, key: &LedgerKey) -> Result<Option<LedgerEntry>> {
        // Search from newest to oldest
        for level in &self.levels {
            // Check curr bucket first (newer)
            if let Some(entry) = level.curr.get(key)? {
                return match entry {
                    BucketEntry::Live(e) | BucketEntry::Init(e) => Ok(Some(e.clone())),
                    BucketEntry::Dead(_) => Ok(None), // Entry is deleted
                    BucketEntry::Metadata(_) => continue,
                };
            }

            // Then check snap bucket
            if let Some(entry) = level.snap.get(key)? {
                return match entry {
                    BucketEntry::Live(e) | BucketEntry::Init(e) => Ok(Some(e.clone())),
                    BucketEntry::Dead(_) => Ok(None), // Entry is deleted
                    BucketEntry::Metadata(_) => continue,
                };
            }
        }

        Ok(None)
    }

    /// Check if an entry exists (is live) for the given key.
    pub fn contains(&self, key: &LedgerKey) -> Result<bool> {
        Ok(self.get(key)?.is_some())
    }

    /// Add ledger entries from a newly closed ledger.
    ///
    /// This method:
    /// 1. Creates a new bucket from the entries
    /// 2. Merges it into level 0
    /// 3. Spills to higher levels as needed
    pub fn add_batch(
        &mut self,
        ledger_seq: u32,
        live_entries: Vec<LedgerEntry>,
        dead_entries: Vec<LedgerKey>,
    ) -> Result<()> {
        // Build entries for the new bucket
        let mut entries: Vec<BucketEntry> = live_entries
            .into_iter()
            .map(BucketEntry::Live)
            .collect();

        entries.extend(dead_entries.into_iter().map(BucketEntry::Dead));

        // Create new bucket
        let new_bucket = Bucket::from_entries(entries)?;

        // Add to level 0 and spill as needed
        self.add_bucket(ledger_seq, new_bucket)?;

        self.ledger_seq = ledger_seq;

        Ok(())
    }

    /// Add a bucket to level 0 and handle spills.
    fn add_bucket(&mut self, ledger_seq: u32, new_bucket: Bucket) -> Result<()> {
        // Merge new bucket into level 0 curr
        let level0_curr = &self.levels[0].curr;
        let merged = merge_buckets(level0_curr, &new_bucket, /* keep_dead_entries */ true)?;
        self.levels[0].curr = merged;

        // Handle spills at each level
        for i in 0..BUCKET_LIST_LEVELS {
            if self.should_spill(ledger_seq, i) {
                self.spill(i)?;
            }
        }

        Ok(())
    }

    /// Check if a level should spill at the given ledger.
    ///
    /// Level 0 spills every ledger.
    /// Level N spills every 2^(2N) ledgers.
    fn should_spill(&self, ledger_seq: u32, level: usize) -> bool {
        if level == 0 {
            // Level 0 always spills
            true
        } else {
            // Level N spills every 2^(2N) ledgers
            let period = Self::spill_period(level);
            ledger_seq % period == 0
        }
    }

    /// Get the spill period for a level.
    ///
    /// Level 0: 1 (every ledger)
    /// Level 1: 4 (2^2)
    /// Level 2: 16 (2^4)
    /// Level N: 2^(2N)
    pub fn spill_period(level: usize) -> u32 {
        if level == 0 {
            1
        } else {
            1u32 << (2 * level)
        }
    }

    /// Spill a level to the next level.
    ///
    /// This:
    /// 1. Merges curr into snap
    /// 2. If there's a next level, merges snap into next level's curr
    /// 3. Clears curr (sets to empty)
    fn spill(&mut self, level: usize) -> Result<()> {
        // For level 0, we don't merge into snap - we replace snap with curr
        // and clear curr for new entries
        if level == 0 {
            // Move curr to snap (curr becomes the new snap)
            let curr = std::mem::replace(&mut self.levels[0].curr, Bucket::empty());

            // Merge old snap into level 1's curr (if not empty)
            let old_snap = std::mem::replace(&mut self.levels[0].snap, curr);

            if !old_snap.is_empty() && level + 1 < BUCKET_LIST_LEVELS {
                let level1_curr = &self.levels[1].curr;
                let merged = merge_buckets(level1_curr, &old_snap, true)?;
                self.levels[1].curr = merged;
            }
        } else if level < BUCKET_LIST_LEVELS {
            // For other levels:
            // 1. Merge curr with snap to create new snap
            let curr = &self.levels[level].curr;
            let snap = &self.levels[level].snap;

            let merged_snap = merge_buckets(snap, curr, true)?;

            // 2. Old snap gets spilled to next level
            let old_snap = std::mem::replace(&mut self.levels[level].snap, Bucket::empty());

            // 3. Update this level
            self.levels[level].curr = Bucket::empty();
            self.levels[level].snap = merged_snap;

            // 4. Spill old snap to next level (if exists)
            if !old_snap.is_empty() && level + 1 < BUCKET_LIST_LEVELS {
                let next_level_curr = &self.levels[level + 1].curr;
                let merged = merge_buckets(next_level_curr, &old_snap, true)?;
                self.levels[level + 1].curr = merged;
            }
        }

        Ok(())
    }

    /// Get all hashes in the bucket list (for serialization).
    pub fn all_bucket_hashes(&self) -> Vec<Hash256> {
        let mut hashes = Vec::with_capacity(BUCKET_LIST_LEVELS * 2);
        for level in &self.levels {
            hashes.push(level.curr.hash());
            hashes.push(level.snap.hash());
        }
        hashes
    }

    /// Restore a bucket list from hashes and a bucket lookup function.
    pub fn restore_from_hashes<F>(hashes: &[Hash256], mut load_bucket: F) -> Result<Self>
    where
        F: FnMut(&Hash256) -> Result<Bucket>,
    {
        if hashes.len() != BUCKET_LIST_LEVELS * 2 {
            return Err(BucketError::Serialization(format!(
                "Expected {} bucket hashes, got {}",
                BUCKET_LIST_LEVELS * 2,
                hashes.len()
            )));
        }

        let mut levels = Vec::with_capacity(BUCKET_LIST_LEVELS);

        for (i, chunk) in hashes.chunks(2).enumerate() {
            let curr_hash = &chunk[0];
            let snap_hash = &chunk[1];

            let curr = if curr_hash.is_zero() {
                Bucket::empty()
            } else {
                load_bucket(curr_hash)?
            };

            let snap = if snap_hash.is_zero() {
                Bucket::empty()
            } else {
                load_bucket(snap_hash)?
            };

            let mut level = BucketLevel::new(i);
            level.curr = curr;
            level.snap = snap;
            levels.push(level);
        }

        Ok(Self { levels, ledger_seq: 0 })
    }

    /// Get statistics about the bucket list.
    pub fn stats(&self) -> BucketListStats {
        let mut total_entries = 0;
        let mut total_buckets = 0;

        for level in &self.levels {
            if !level.curr.is_empty() {
                total_entries += level.curr.len();
                total_buckets += 1;
            }
            if !level.snap.is_empty() {
                total_entries += level.snap.len();
                total_buckets += 1;
            }
        }

        BucketListStats {
            num_levels: BUCKET_LIST_LEVELS,
            total_entries,
            total_buckets,
        }
    }
}

impl Default for BucketList {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for BucketList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BucketList")
            .field("ledger_seq", &self.ledger_seq)
            .field("hash", &self.hash().to_hex())
            .field("stats", &self.stats())
            .finish()
    }
}

/// Statistics about a BucketList.
#[derive(Debug, Clone)]
pub struct BucketListStats {
    /// Number of levels.
    pub num_levels: usize,
    /// Total number of entries across all buckets.
    pub total_entries: usize,
    /// Total number of non-empty buckets.
    pub total_buckets: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;
    use crate::BucketEntry; // Re-import to shadow XDR's BucketEntry

    fn make_account_id(bytes: [u8; 32]) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes)))
    }

    fn make_account_entry(bytes: [u8; 32], balance: i64) -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 1,
            data: LedgerEntryData::Account(AccountEntry {
                account_id: make_account_id(bytes),
                balance,
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

    fn make_account_key(bytes: [u8; 32]) -> LedgerKey {
        LedgerKey::Account(LedgerKeyAccount {
            account_id: make_account_id(bytes),
        })
    }

    #[test]
    fn test_new_bucket_list() {
        let bl = BucketList::new();
        assert_eq!(bl.levels().len(), BUCKET_LIST_LEVELS);
        assert_eq!(bl.ledger_seq(), 0);
    }

    #[test]
    fn test_add_batch_simple() {
        let mut bl = BucketList::new();

        let entry = make_account_entry([1u8; 32], 100);
        bl.add_batch(1, vec![entry], vec![]).unwrap();

        let key = make_account_key([1u8; 32]);
        let found = bl.get(&key).unwrap().unwrap();

        if let LedgerEntryData::Account(account) = &found.data {
            assert_eq!(account.balance, 100);
        } else {
            panic!("Expected Account entry");
        }
    }

    #[test]
    fn test_add_batch_update() {
        let mut bl = BucketList::new();

        // Add initial entry
        let entry1 = make_account_entry([1u8; 32], 100);
        bl.add_batch(1, vec![entry1], vec![]).unwrap();

        // Update entry
        let entry2 = make_account_entry([1u8; 32], 200);
        bl.add_batch(2, vec![entry2], vec![]).unwrap();

        let key = make_account_key([1u8; 32]);
        let found = bl.get(&key).unwrap().unwrap();

        if let LedgerEntryData::Account(account) = &found.data {
            assert_eq!(account.balance, 200);
        } else {
            panic!("Expected Account entry");
        }
    }

    #[test]
    fn test_add_batch_delete() {
        let mut bl = BucketList::new();

        // Add entry
        let entry = make_account_entry([1u8; 32], 100);
        bl.add_batch(1, vec![entry], vec![]).unwrap();

        // Delete entry
        let key = make_account_key([1u8; 32]);
        bl.add_batch(2, vec![], vec![key.clone()]).unwrap();

        // Should not be found
        let found = bl.get(&key).unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn test_spill_periods() {
        assert_eq!(BucketList::spill_period(0), 1);
        assert_eq!(BucketList::spill_period(1), 4);
        assert_eq!(BucketList::spill_period(2), 16);
        assert_eq!(BucketList::spill_period(3), 64);
        assert_eq!(BucketList::spill_period(4), 256);
        assert_eq!(BucketList::spill_period(5), 1024);
    }

    #[test]
    fn test_bucket_list_hash_changes() {
        let mut bl = BucketList::new();
        let hash1 = bl.hash();

        let entry = make_account_entry([1u8; 32], 100);
        bl.add_batch(1, vec![entry], vec![]).unwrap();
        let hash2 = bl.hash();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_contains() {
        let mut bl = BucketList::new();

        let key = make_account_key([1u8; 32]);
        assert!(!bl.contains(&key).unwrap());

        let entry = make_account_entry([1u8; 32], 100);
        bl.add_batch(1, vec![entry], vec![]).unwrap();

        assert!(bl.contains(&key).unwrap());
    }

    #[test]
    fn test_multiple_levels() {
        let mut bl = BucketList::new();

        // Add many entries to trigger spills to higher levels
        for i in 1..=20u32 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&i.to_be_bytes());
            let entry = make_account_entry(id, i as i64 * 100);
            bl.add_batch(i, vec![entry], vec![]).unwrap();
        }

        // Verify all entries are accessible
        for i in 1..=20u32 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&i.to_be_bytes());
            let key = make_account_key(id);
            let found = bl.get(&key).unwrap();
            assert!(found.is_some(), "Entry {} not found", i);
        }
    }
}
