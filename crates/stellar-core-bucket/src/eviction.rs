//! Eviction scan implementation for Soroban state archival.
//!
//! This module implements the incremental eviction scan that matches
//! C++ stellar-core's behavior. The eviction scan is responsible for
//! identifying expired Soroban entries (contract data, contract code)
//! and processing them for archival or deletion.
//!
//! ## Overview
//!
//! State archival in Soroban uses a time-to-live (TTL) mechanism where entries
//! have a `liveUntilLedger` value. When the current ledger exceeds this value,
//! the entry is considered expired and must be evicted:
//!
//! - **Temporary entries**: Deleted immediately (not archived)
//! - **Persistent entries**: Archived to the Hot Archive bucket list, then deleted
//!   from the live bucket list
//!
//! ## Incremental Scanning
//!
//! Unlike a full scan which would be expensive, eviction is performed incrementally:
//!
//! 1. Each ledger scans a limited number of bytes (default 100KB)
//! 2. Position is tracked with an `EvictionIterator`
//! 3. Scanning continues from where it left off on the next ledger
//! 4. When a bucket receives new data (spill), the iterator resets to the beginning
//!    of that bucket to ensure new entries are scanned
//!
//! ## Key Concepts
//!
//! - **EvictionIterator**: Tracks current scan position (level, curr/snap bucket, byte offset)
//! - **Scan Size**: Configurable bytes to scan per ledger (default 100KB)
//! - **Starting Level**: Minimum bucket list level to scan (default level 6, since lower
//!   levels update too frequently)
//! - **Spill Detection**: When a bucket receives new data from a level below spilling,
//!   the iterator resets to rescan from the beginning
//!
//! ## Bucket List Level Math
//!
//! The bucket list has a hierarchical structure where lower levels update more frequently:
//!
//! - `level_size(N)` = 4^(N+1): The idealized size boundary for level N
//! - `level_half(N)` = level_size(N) / 2: Half the level size
//! - `level_should_spill(ledger, N)`: Returns true when level N spills at the given ledger
//! - `bucket_update_period(N, is_curr)`: How often a bucket receives new data
//!
//! | Level | level_size | level_half | curr updates every | snap updates every |
//! |-------|------------|------------|--------------------|--------------------|
//! | 0     | 4          | 2          | 1 ledger           | 2 ledgers          |
//! | 1     | 16         | 8          | 2 ledgers          | 8 ledgers          |
//! | 2     | 64         | 32         | 8 ledgers          | 32 ledgers         |
//! | 3     | 256        | 128        | 32 ledgers         | 128 ledgers        |
//! | ...   | ...        | ...        | ...                | ...                |
//! | 6     | 16384      | 8192       | 2048 ledgers       | 8192 ledgers       |
//!
//! ## Example Usage
//!
//! ```ignore
//! use stellar_core_bucket::{EvictionIterator, StateArchivalSettings, update_starting_eviction_iterator};
//!
//! // Initialize iterator at default starting level (6)
//! let mut iter = EvictionIterator::default();
//!
//! // Before scanning each ledger, check if the iterator needs to reset
//! // (because the bucket received new data)
//! update_starting_eviction_iterator(&mut iter, 6, current_ledger);
//!
//! // Perform the scan (handled by BucketList::scan_for_eviction_incremental)
//! let result = bucket_list.scan_for_eviction_incremental(iter, current_ledger, &settings)?;
//!
//! // Update iterator for next ledger
//! iter = result.end_iterator;
//! ```
//!
//! ## References
//!
//! - C++ implementation: `src/bucket/BucketListBase.cpp`, `src/bucket/BucketManager.cpp`
//! - Eviction iterator: `src/ledger/NetworkConfig.h` (EvictionIterator struct)
//! - State archival CAP: CAP-0046 (Soroban State Archival)

use stellar_xdr::curr::{LedgerEntry, LedgerKey};

use crate::bucket_list::BUCKET_LIST_LEVELS;

/// Default eviction scan size in bytes per ledger (100 KB).
pub const DEFAULT_EVICTION_SCAN_SIZE: u64 = 100_000;

/// Default starting eviction scan level (level 6).
/// Lower levels update too frequently, so we start from level 6.
pub const DEFAULT_STARTING_EVICTION_SCAN_LEVEL: u32 = 6;

/// Eviction iterator that tracks the current scan position in the bucket list.
///
/// The iterator maintains state between ledgers, allowing the eviction scan
/// to resume where it left off. This enables incremental scanning without
/// processing the entire bucket list in a single ledger.
///
/// # Persistence
///
/// The iterator state is typically stored in the ledger header or network
/// config so it persists across restarts. This matches C++ stellar-core's
/// `EvictionIterator` from NetworkConfig.
///
/// # Scan Order
///
/// The scan proceeds in this order:
/// 1. Level N curr bucket
/// 2. Level N snap bucket
/// 3. Level N+1 curr bucket
/// 4. ... (continues to top level, then wraps to starting level)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvictionIterator {
    /// Current byte offset (or entry index) within the bucket.
    pub bucket_file_offset: u32,
    /// Current bucket list level being scanned (0 to NUM_LEVELS-1).
    pub bucket_list_level: u32,
    /// Whether scanning the curr bucket (true) or snap bucket (false).
    pub is_curr_bucket: bool,
}

impl Default for EvictionIterator {
    fn default() -> Self {
        Self::new(DEFAULT_STARTING_EVICTION_SCAN_LEVEL)
    }
}

impl EvictionIterator {
    /// Create a new eviction iterator starting at the given level.
    pub fn new(starting_level: u32) -> Self {
        Self {
            bucket_file_offset: 0,
            bucket_list_level: starting_level,
            is_curr_bucket: true,
        }
    }

    /// Reset the iterator to start of the current bucket.
    pub fn reset_offset(&mut self) {
        self.bucket_file_offset = 0;
    }

    /// Move to the next bucket in the scan order.
    ///
    /// Order: level N curr -> level N snap -> level N+1 curr -> ...
    /// Wraps back to starting level when reaching the top.
    ///
    /// Returns true if we've wrapped back to the starting position (completed a full cycle).
    pub fn advance_to_next_bucket(&mut self, starting_level: u32) -> bool {
        let mut wrapped = false;

        if self.is_curr_bucket {
            // Move from curr to snap at same level
            self.is_curr_bucket = false;
            self.bucket_file_offset = 0;
        } else {
            // Move from snap to curr at next level
            self.bucket_list_level += 1;
            self.is_curr_bucket = true;
            self.bucket_file_offset = 0;

            // Wrap around at top level
            if self.bucket_list_level >= BUCKET_LIST_LEVELS as u32 {
                self.bucket_list_level = starting_level;
                wrapped = true;
            }
        }

        wrapped
    }
}

/// Result of an eviction scan for a single ledger.
///
/// Contains the entries to archive, keys to delete, and updated iterator
/// position for the next scan. The caller is responsible for:
///
/// 1. Adding `archived_entries` to the hot archive bucket list
/// 2. Adding `evicted_keys` as dead entries to the live bucket list
/// 3. Persisting `end_iterator` for the next ledger's scan
#[derive(Debug, Default)]
pub struct EvictionResult {
    /// Persistent entries to archive to the hot archive bucket list.
    ///
    /// These are ContractCode or persistent ContractData entries that have
    /// expired but can be restored later by paying for TTL extension.
    pub archived_entries: Vec<LedgerEntry>,
    /// Keys of all evicted entries to delete from the live bucket list.
    ///
    /// Includes both temporary entries (deleted permanently) and persistent
    /// entries (moved to hot archive). These become dead entries in the
    /// live bucket list.
    pub evicted_keys: Vec<LedgerKey>,
    /// Updated iterator position for the next scan.
    pub end_iterator: EvictionIterator,
    /// Total bytes of entry data scanned during this ledger.
    pub bytes_scanned: u64,
    /// Whether the scan completed its byte quota (vs hitting bucket end early).
    pub scan_complete: bool,
}

/// Configuration settings for Soroban state archival.
///
/// These settings control the eviction scan behavior and are typically
/// sourced from network configuration (ConfigSetting entries).
#[derive(Debug, Clone, Copy)]
pub struct StateArchivalSettings {
    /// Maximum bytes to scan per ledger (default: 100 KB).
    ///
    /// Larger values process more entries per ledger but increase
    /// ledger close time. The scan stops when this limit is reached,
    /// even if in the middle of a bucket.
    pub eviction_scan_size: u64,
    /// Minimum bucket list level to scan (default: 6).
    ///
    /// Lower levels update too frequently to be worth scanning.
    /// Level 6 updates every 2048 ledgers, giving entries reasonable
    /// lifetime before they're scanned.
    pub starting_eviction_scan_level: u32,
}

impl Default for StateArchivalSettings {
    fn default() -> Self {
        Self {
            eviction_scan_size: DEFAULT_EVICTION_SCAN_SIZE,
            starting_eviction_scan_level: DEFAULT_STARTING_EVICTION_SCAN_LEVEL,
        }
    }
}

/// Calculate the idealized size of a bucket list level.
///
/// Formula: 4^(level+1) = 1 << (2 * (level + 1))
///
/// - Level 0: 4
/// - Level 1: 16
/// - Level 2: 64
/// - Level 3: 256
/// - ...
pub fn level_size(level: u32) -> u64 {
    1u64 << (2 * (level + 1))
}

/// Calculate half of the level size.
pub fn level_half(level: u32) -> u64 {
    level_size(level) >> 1
}

/// Round down a value to the nearest multiple of a power-of-2 modulo.
///
/// Formula: value & ~(modulo - 1)
fn round_down(value: u64, modulo: u64) -> u64 {
    value & !(modulo - 1)
}

/// Check if a level should spill at the given ledger.
///
/// A level spills when the ledger number is at a levelHalf or levelSize boundary.
/// The top level (level 10) never spills.
pub fn level_should_spill(ledger: u32, level: u32) -> bool {
    if level >= BUCKET_LIST_LEVELS as u32 - 1 {
        return false; // Top level never spills
    }

    let ledger = ledger as u64;
    let half = level_half(level);
    let size = level_size(level);

    ledger == round_down(ledger, half) || ledger == round_down(ledger, size)
}

/// Calculate how frequently a bucket receives new data (update period in ledgers).
///
/// - Level 0 curr: 1 ledger
/// - Level 0 snap: 2 ledgers
/// - Level 1 curr: 2 ledgers
/// - Level 1 snap: 8 ledgers
/// - Level N curr: 2^(2*N - 1) ledgers
pub fn bucket_update_period(level: u32, is_curr: bool) -> u32 {
    if !is_curr {
        // Snap bucket updates when the level below spills
        return bucket_update_period(level + 1, true);
    }

    if level == 0 {
        return 1;
    }

    // Formula: 2^(2*level - 1)
    1u32 << (2 * level - 1)
}

/// Update the eviction iterator based on bucket spills.
///
/// This resets the iterator's byte offset when a bucket has received new data
/// (invalidating the current scan position).
///
/// Returns true if the iterator was reset.
pub fn update_starting_eviction_iterator(
    iter: &mut EvictionIterator,
    first_scan_level: u32,
    ledger_seq: u32,
) -> bool {
    let mut was_reset = false;

    // If iterator level is below the minimum, reset to minimum
    if iter.bucket_list_level < first_scan_level {
        iter.bucket_file_offset = 0;
        iter.is_curr_bucket = true;
        iter.bucket_list_level = first_scan_level;
        was_reset = true;
    }

    // Check if the bucket we're scanning has received new data
    if iter.is_curr_bucket {
        // Curr bucket receives data when the level below spills
        if iter.bucket_list_level > 0 {
            let level_below = iter.bucket_list_level - 1;
            if level_should_spill(ledger_seq, level_below) {
                iter.bucket_file_offset = 0;
                was_reset = true;
            }
        } else {
            // Level 0 curr receives data every ledger
            iter.bucket_file_offset = 0;
            was_reset = true;
        }
    } else {
        // Snap bucket receives data when its own level spills
        if level_should_spill(ledger_seq, iter.bucket_list_level) {
            iter.bucket_file_offset = 0;
            was_reset = true;
        }
    }

    was_reset
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_level_size() {
        // Matches C++ BucketListBase::levelSize
        assert_eq!(level_size(0), 4);
        assert_eq!(level_size(1), 16);
        assert_eq!(level_size(2), 64);
        assert_eq!(level_size(3), 256);
        assert_eq!(level_size(4), 1024);
        assert_eq!(level_size(5), 4096);
        assert_eq!(level_size(6), 16384);
        assert_eq!(level_size(7), 65536);
        assert_eq!(level_size(8), 262144);
        assert_eq!(level_size(9), 1048576);
        assert_eq!(level_size(10), 4194304);
    }

    #[test]
    fn test_level_half() {
        // Matches C++ BucketListBase::levelHalf
        assert_eq!(level_half(0), 2);
        assert_eq!(level_half(1), 8);
        assert_eq!(level_half(2), 32);
        assert_eq!(level_half(3), 128);
        assert_eq!(level_half(4), 512);
    }

    #[test]
    fn test_level_should_spill() {
        // Level 0 spills at ledgers: 0, 2, 4, 6, 8...
        // (every levelHalf(0)=2 ledgers)
        assert!(level_should_spill(0, 0));
        assert!(!level_should_spill(1, 0));
        assert!(level_should_spill(2, 0));
        assert!(!level_should_spill(3, 0));
        assert!(level_should_spill(4, 0));

        // Level 1 spills at ledgers: 0, 8, 16, 24...
        // (every levelHalf(1)=8 ledgers)
        assert!(level_should_spill(0, 1));
        assert!(!level_should_spill(4, 1));
        assert!(level_should_spill(8, 1));
        assert!(!level_should_spill(12, 1));
        assert!(level_should_spill(16, 1));

        // Level 2 spills at ledgers: 0, 32, 64...
        assert!(level_should_spill(0, 2));
        assert!(!level_should_spill(16, 2));
        assert!(level_should_spill(32, 2));
        assert!(level_should_spill(64, 2));

        // Top level (10) never spills
        assert!(!level_should_spill(0, BUCKET_LIST_LEVELS as u32 - 1));
        assert!(!level_should_spill(1000000, BUCKET_LIST_LEVELS as u32 - 1));
    }

    #[test]
    fn test_bucket_update_period() {
        // Matches C++ bucketUpdatePeriod arithmetic test
        // Curr bucket at level 0 updates every ledger
        assert_eq!(bucket_update_period(0, true), 1);

        // Snap bucket at level 0 updates when level 1 curr updates
        assert_eq!(bucket_update_period(0, false), 2);

        // Curr bucket at level N (N>0) updates every 2^(2*N-1) ledgers
        assert_eq!(bucket_update_period(1, true), 2);
        assert_eq!(bucket_update_period(2, true), 8);
        assert_eq!(bucket_update_period(3, true), 32);
        assert_eq!(bucket_update_period(4, true), 128);
        assert_eq!(bucket_update_period(5, true), 512);
        assert_eq!(bucket_update_period(6, true), 2048);

        // Snap bucket at level N updates when level N+1 curr updates
        assert_eq!(bucket_update_period(1, false), 8);
        assert_eq!(bucket_update_period(2, false), 32);
        assert_eq!(bucket_update_period(3, false), 128);
    }

    #[test]
    fn test_bucket_update_period_arithmetic() {
        // Verify the relationship between update period and levelShouldSpill
        // This matches the C++ "bucketUpdatePeriod arithmetic" test
        for level in 0..BUCKET_LIST_LEVELS as u32 {
            let curr_period = bucket_update_period(level, true);
            let snap_period = bucket_update_period(level, false);

            // Curr bucket updates when level below spills (for level > 0)
            // or every ledger (for level 0)
            if level == 0 {
                assert_eq!(curr_period, 1);
            } else {
                // Verify spill occurs at multiples of period
                assert!(level_should_spill(curr_period, level - 1));
                if curr_period > 1 {
                    assert!(!level_should_spill(curr_period - 1, level - 1));
                }
            }

            // Snap bucket updates when its own level spills
            if level < BUCKET_LIST_LEVELS as u32 - 1 {
                assert!(level_should_spill(snap_period, level));
                if snap_period > 1 {
                    assert!(!level_should_spill(snap_period - 1, level));
                }
            }
        }
    }

    #[test]
    fn test_iterator_advance() {
        let mut iter = EvictionIterator::new(6);
        assert_eq!(iter.bucket_list_level, 6);
        assert!(iter.is_curr_bucket);

        // Advance: level 6 curr -> level 6 snap
        let wrapped = iter.advance_to_next_bucket(6);
        assert!(!wrapped);
        assert_eq!(iter.bucket_list_level, 6);
        assert!(!iter.is_curr_bucket);

        // Advance: level 6 snap -> level 7 curr
        let wrapped = iter.advance_to_next_bucket(6);
        assert!(!wrapped);
        assert_eq!(iter.bucket_list_level, 7);
        assert!(iter.is_curr_bucket);

        // Advance through remaining levels...
        for _ in 0..8 {
            // 7 snap, 8 curr, 8 snap, 9 curr, 9 snap, 10 curr, 10 snap, wrap to 6 curr
            iter.advance_to_next_bucket(6);
        }

        // Should be back at level 6 curr (wrapped)
        assert_eq!(iter.bucket_list_level, 6);
        assert!(iter.is_curr_bucket);
    }

    #[test]
    fn test_iterator_wrap_detection() {
        let mut iter = EvictionIterator::new(6);

        // Advance until we wrap
        let mut count = 0;
        loop {
            let wrapped = iter.advance_to_next_bucket(6);
            count += 1;
            if wrapped {
                break;
            }
            // Safety: prevent infinite loop
            assert!(count < 100, "Iterator didn't wrap");
        }

        // Should take 10 advances: 6c->6s, 6s->7c, 7c->7s, 7s->8c, 8c->8s, 8s->9c, 9c->9s, 9s->10c, 10c->10s, 10s->6c (wrap)
        assert_eq!(count, 10);
    }

    #[test]
    fn test_iterator_different_starting_levels() {
        // Test starting at level 0
        let mut iter = EvictionIterator::new(0);
        let mut count = 0;
        loop {
            let wrapped = iter.advance_to_next_bucket(0);
            count += 1;
            if wrapped {
                break;
            }
            assert!(count < 100);
        }
        // All 11 levels, 2 buckets each = 22 advances
        assert_eq!(count, 22);

        // Test starting at level 10 (top level)
        let mut iter = EvictionIterator::new(10);
        let wrapped = iter.advance_to_next_bucket(10);
        assert!(!wrapped); // 10 curr -> 10 snap
        assert_eq!(iter.bucket_list_level, 10);
        assert!(!iter.is_curr_bucket);

        let wrapped = iter.advance_to_next_bucket(10);
        assert!(wrapped); // 10 snap -> wraps to 10 curr
        assert_eq!(iter.bucket_list_level, 10);
        assert!(iter.is_curr_bucket);
    }

    #[test]
    fn test_update_starting_eviction_iterator_level_reset() {
        // Test that iterator resets when below minimum level
        let mut iter = EvictionIterator {
            bucket_file_offset: 1000,
            bucket_list_level: 3,
            is_curr_bucket: false,
        };

        let was_reset = update_starting_eviction_iterator(&mut iter, 6, 100);
        assert!(was_reset);
        assert_eq!(iter.bucket_file_offset, 0);
        assert_eq!(iter.bucket_list_level, 6);
        assert!(iter.is_curr_bucket);
    }

    #[test]
    fn test_update_starting_eviction_iterator_curr_bucket_reset() {
        // Level 6 curr bucket receives data when level 5 spills
        // level_half(5) = 2048, so level 5 spills at ledgers 0, 2048, 4096...
        let mut iter = EvictionIterator {
            bucket_file_offset: 5000,
            bucket_list_level: 6,
            is_curr_bucket: true,
        };

        // Ledger 2047 - level 5 doesn't spill, iterator should NOT reset
        let was_reset = update_starting_eviction_iterator(&mut iter, 6, 2047);
        assert!(!was_reset);
        assert_eq!(iter.bucket_file_offset, 5000);

        // Ledger 2048 - level 5 spills, iterator SHOULD reset
        let was_reset = update_starting_eviction_iterator(&mut iter, 6, 2048);
        assert!(was_reset);
        assert_eq!(iter.bucket_file_offset, 0);
    }

    #[test]
    fn test_update_starting_eviction_iterator_snap_bucket_reset() {
        // Level 6 snap bucket receives data when level 6 spills
        // level_half(6) = 8192, so level 6 spills at ledgers 0, 8192, 16384...
        let mut iter = EvictionIterator {
            bucket_file_offset: 5000,
            bucket_list_level: 6,
            is_curr_bucket: false,
        };

        // Ledger 8191 - level 6 doesn't spill, iterator should NOT reset
        let was_reset = update_starting_eviction_iterator(&mut iter, 6, 8191);
        assert!(!was_reset);
        assert_eq!(iter.bucket_file_offset, 5000);

        // Ledger 8192 - level 6 spills, iterator SHOULD reset
        let was_reset = update_starting_eviction_iterator(&mut iter, 6, 8192);
        assert!(was_reset);
        assert_eq!(iter.bucket_file_offset, 0);
    }

    #[test]
    fn test_update_starting_eviction_iterator_level_0_always_resets() {
        // Level 0 curr bucket receives data every ledger
        let mut iter = EvictionIterator {
            bucket_file_offset: 5000,
            bucket_list_level: 0,
            is_curr_bucket: true,
        };

        // Any ledger should reset level 0 curr
        for ledger in [1, 2, 3, 100, 1000] {
            iter.bucket_file_offset = 5000;
            let was_reset = update_starting_eviction_iterator(&mut iter, 0, ledger);
            assert!(was_reset, "Level 0 curr should reset at ledger {}", ledger);
            assert_eq!(iter.bucket_file_offset, 0);
        }
    }

    #[test]
    fn test_update_starting_eviction_iterator_preserves_position() {
        // When bucket hasn't received new data, position should be preserved
        let mut iter = EvictionIterator {
            bucket_file_offset: 12345,
            bucket_list_level: 7,
            is_curr_bucket: true,
        };

        // Level 7 curr receives data when level 6 spills
        // Level 6 spills at multiples of levelHalf(6) = 2048
        // Ledger 100 is not a spill point for level 6
        let was_reset = update_starting_eviction_iterator(&mut iter, 6, 100);
        assert!(!was_reset);
        assert_eq!(iter.bucket_file_offset, 12345);
        assert_eq!(iter.bucket_list_level, 7);
        assert!(iter.is_curr_bucket);
    }

    #[test]
    fn test_iterator_offset_tracking() {
        let mut iter = EvictionIterator::new(6);

        // Set some offset
        iter.bucket_file_offset = 50000;

        // Advancing resets the offset
        iter.advance_to_next_bucket(6);
        assert_eq!(iter.bucket_file_offset, 0);

        // Manual reset
        iter.bucket_file_offset = 99999;
        iter.reset_offset();
        assert_eq!(iter.bucket_file_offset, 0);
    }

    #[test]
    fn test_default_settings() {
        let settings = StateArchivalSettings::default();
        assert_eq!(settings.eviction_scan_size, DEFAULT_EVICTION_SCAN_SIZE);
        assert_eq!(settings.eviction_scan_size, 100_000);
        assert_eq!(
            settings.starting_eviction_scan_level,
            DEFAULT_STARTING_EVICTION_SCAN_LEVEL
        );
        assert_eq!(settings.starting_eviction_scan_level, 6);
    }

    #[test]
    fn test_eviction_iterator_default() {
        let iter = EvictionIterator::default();
        assert_eq!(iter.bucket_file_offset, 0);
        assert_eq!(iter.bucket_list_level, DEFAULT_STARTING_EVICTION_SCAN_LEVEL);
        assert!(iter.is_curr_bucket);
    }

    #[test]
    fn test_round_down() {
        // Test internal round_down function behavior
        // round_down(value, modulo) = value & !(modulo - 1)
        assert_eq!(round_down(0, 4), 0);
        assert_eq!(round_down(1, 4), 0);
        assert_eq!(round_down(3, 4), 0);
        assert_eq!(round_down(4, 4), 4);
        assert_eq!(round_down(5, 4), 4);
        assert_eq!(round_down(7, 4), 4);
        assert_eq!(round_down(8, 4), 8);

        assert_eq!(round_down(100, 32), 96);
        assert_eq!(round_down(127, 64), 64);
        assert_eq!(round_down(128, 64), 128);
    }
}
