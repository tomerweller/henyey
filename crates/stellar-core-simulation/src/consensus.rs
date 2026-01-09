//! Consensus verification utilities for simulation testing.
//!
//! This module provides utilities for verifying that nodes in a simulation
//! have reached consensus, matching the C++ `Simulation::haveAllExternalized()`
//! functionality.
//!
//! # Overview
//!
//! The main function [`have_all_externalized`] checks whether all nodes in a
//! simulation have closed at least up to a target ledger sequence, while also
//! verifying that nodes haven't diverged too far from each other.
//!
//! # Example
//!
//! ```ignore
//! use stellar_core_simulation::consensus::{have_all_externalized, ConsensusCheckResult};
//!
//! // Get ledger sequences from each node
//! let ledger_seqs = vec![100, 100, 99, 100]; // 4 nodes
//!
//! // Check if all nodes have externalized at least ledger 99
//! let result = have_all_externalized(&ledger_seqs, 99, 5);
//! match result {
//!     ConsensusCheckResult::AllExternalized => println!("All nodes synced!"),
//!     ConsensusCheckResult::NotYetExternalized { min, target } => {
//!         println!("Waiting: min={}, target={}", min, target);
//!     }
//!     ConsensusCheckResult::SpreadTooWide { min, max, max_spread } => {
//!         println!("Nodes diverged too far: {}-{} > {}", max, min, max_spread);
//!     }
//! }
//! ```

use std::fmt;

// =============================================================================
// Constants
// =============================================================================

/// Default maximum spread between nodes before considering them diverged.
pub const DEFAULT_MAX_SPREAD: u32 = 5;

// =============================================================================
// ConsensusCheckResult
// =============================================================================

/// Result of a consensus check across multiple nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusCheckResult {
    /// All nodes have externalized at least up to the target ledger.
    AllExternalized,

    /// Not all nodes have reached the target ledger yet.
    NotYetExternalized {
        /// Minimum ledger sequence across all nodes.
        min: u32,
        /// Target ledger sequence we're waiting for.
        target: u32,
    },

    /// Nodes have diverged too far from each other.
    SpreadTooWide {
        /// Minimum ledger sequence.
        min: u32,
        /// Maximum ledger sequence.
        max: u32,
        /// Maximum allowed spread.
        max_spread: u32,
    },
}

impl ConsensusCheckResult {
    /// Returns true if all nodes have externalized.
    pub fn is_externalized(&self) -> bool {
        matches!(self, ConsensusCheckResult::AllExternalized)
    }

    /// Returns true if the spread is too wide (nodes diverged).
    pub fn is_spread_too_wide(&self) -> bool {
        matches!(self, ConsensusCheckResult::SpreadTooWide { .. })
    }
}

impl fmt::Display for ConsensusCheckResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsensusCheckResult::AllExternalized => {
                write!(f, "All nodes externalized")
            }
            ConsensusCheckResult::NotYetExternalized { min, target } => {
                write!(
                    f,
                    "Not yet externalized: min ledger {} < target {}",
                    min, target
                )
            }
            ConsensusCheckResult::SpreadTooWide {
                min,
                max,
                max_spread,
            } => {
                write!(
                    f,
                    "Spread too wide: {}-{} = {} > max_spread {}",
                    max,
                    min,
                    max - min,
                    max_spread
                )
            }
        }
    }
}

// =============================================================================
// Consensus Check Functions
// =============================================================================

/// Checks if all nodes have externalized at least up to the target ledger.
///
/// This function matches the C++ `Simulation::haveAllExternalized()` behavior:
///
/// 1. Finds the minimum and maximum ledger sequences across all nodes
/// 2. If `max - min > max_spread`, returns [`ConsensusCheckResult::SpreadTooWide`]
/// 3. If `min >= target`, returns [`ConsensusCheckResult::AllExternalized`]
/// 4. Otherwise returns [`ConsensusCheckResult::NotYetExternalized`]
///
/// # Arguments
///
/// * `ledger_seqs` - Slice of last closed ledger sequences from each node
/// * `target` - Target ledger sequence to check against
/// * `max_spread` - Maximum allowed difference between highest and lowest ledgers
///
/// # Returns
///
/// A [`ConsensusCheckResult`] indicating the consensus state.
///
/// # Example
///
/// ```
/// use stellar_core_simulation::consensus::{have_all_externalized, ConsensusCheckResult};
///
/// // All nodes at ledger 100
/// let result = have_all_externalized(&[100, 100, 100], 100, 5);
/// assert!(result.is_externalized());
///
/// // Minimum is 98, target is 100
/// let result = have_all_externalized(&[98, 100, 99], 100, 5);
/// assert!(!result.is_externalized());
///
/// // Spread too wide (102 - 95 = 7 > 5)
/// let result = have_all_externalized(&[95, 102, 98], 90, 5);
/// assert!(result.is_spread_too_wide());
/// ```
pub fn have_all_externalized(
    ledger_seqs: &[u32],
    target: u32,
    max_spread: u32,
) -> ConsensusCheckResult {
    if ledger_seqs.is_empty() {
        return ConsensusCheckResult::AllExternalized;
    }

    let min = *ledger_seqs.iter().min().unwrap();
    let max = *ledger_seqs.iter().max().unwrap();

    // Check spread first
    if max - min > max_spread {
        return ConsensusCheckResult::SpreadTooWide {
            min,
            max,
            max_spread,
        };
    }

    // Check if all nodes have reached target
    if min >= target {
        ConsensusCheckResult::AllExternalized
    } else {
        ConsensusCheckResult::NotYetExternalized { min, target }
    }
}

/// Checks if all nodes have externalized with default max spread.
///
/// This is a convenience wrapper around [`have_all_externalized`] that uses
/// [`DEFAULT_MAX_SPREAD`] (5 ledgers).
pub fn have_all_externalized_default(ledger_seqs: &[u32], target: u32) -> ConsensusCheckResult {
    have_all_externalized(ledger_seqs, target, DEFAULT_MAX_SPREAD)
}

// =============================================================================
// ConsensusTracker
// =============================================================================

/// Tracks consensus progress across multiple nodes over time.
///
/// This struct maintains state for tracking how nodes progress through
/// consensus, useful for waiting until all nodes reach a target ledger.
#[derive(Debug, Clone)]
pub struct ConsensusTracker {
    /// Number of nodes being tracked.
    node_count: usize,
    /// Target ledger sequence.
    target: u32,
    /// Maximum allowed spread between nodes.
    max_spread: u32,
    /// Whether to only consider validator nodes.
    validators_only: bool,
    /// Last known ledger sequences per node.
    last_ledger_seqs: Vec<u32>,
    /// Count of checks performed.
    check_count: u64,
}

impl ConsensusTracker {
    /// Creates a new consensus tracker.
    ///
    /// # Arguments
    ///
    /// * `node_count` - Number of nodes to track
    /// * `target` - Target ledger sequence
    /// * `max_spread` - Maximum allowed spread between nodes
    pub fn new(node_count: usize, target: u32, max_spread: u32) -> Self {
        Self {
            node_count,
            target,
            max_spread,
            validators_only: false,
            last_ledger_seqs: vec![0; node_count],
            check_count: 0,
        }
    }

    /// Creates a new tracker with default max spread.
    pub fn with_target(node_count: usize, target: u32) -> Self {
        Self::new(node_count, target, DEFAULT_MAX_SPREAD)
    }

    /// Sets whether to only consider validator nodes.
    pub fn validators_only(mut self, validators_only: bool) -> Self {
        self.validators_only = validators_only;
        self
    }

    /// Updates the tracker with new ledger sequences and checks consensus.
    ///
    /// # Arguments
    ///
    /// * `ledger_seqs` - Current ledger sequences for each node
    ///
    /// # Returns
    ///
    /// The current consensus state.
    pub fn update(&mut self, ledger_seqs: &[u32]) -> ConsensusCheckResult {
        assert_eq!(
            ledger_seqs.len(),
            self.node_count,
            "Expected {} ledger sequences, got {}",
            self.node_count,
            ledger_seqs.len()
        );

        self.last_ledger_seqs.copy_from_slice(ledger_seqs);
        self.check_count += 1;

        have_all_externalized(ledger_seqs, self.target, self.max_spread)
    }

    /// Updates the tracker with ledger sequences and optional validator flags.
    ///
    /// If `validators_only` is set, only nodes with `is_validator[i] == true`
    /// are considered.
    pub fn update_with_validators(
        &mut self,
        ledger_seqs: &[u32],
        is_validator: &[bool],
    ) -> ConsensusCheckResult {
        assert_eq!(ledger_seqs.len(), self.node_count);
        assert_eq!(is_validator.len(), self.node_count);

        self.last_ledger_seqs.copy_from_slice(ledger_seqs);
        self.check_count += 1;

        let filtered: Vec<u32> = if self.validators_only {
            ledger_seqs
                .iter()
                .zip(is_validator.iter())
                .filter(|(_, &v)| v)
                .map(|(&seq, _)| seq)
                .collect()
        } else {
            ledger_seqs.to_vec()
        };

        have_all_externalized(&filtered, self.target, self.max_spread)
    }

    /// Returns the current target ledger.
    pub fn target(&self) -> u32 {
        self.target
    }

    /// Sets a new target ledger.
    pub fn set_target(&mut self, target: u32) {
        self.target = target;
    }

    /// Returns the number of checks performed.
    pub fn check_count(&self) -> u64 {
        self.check_count
    }

    /// Returns the last known ledger sequences.
    pub fn last_ledger_seqs(&self) -> &[u32] {
        &self.last_ledger_seqs
    }

    /// Returns the minimum ledger sequence across all nodes.
    pub fn min_ledger(&self) -> u32 {
        *self.last_ledger_seqs.iter().min().unwrap_or(&0)
    }

    /// Returns the maximum ledger sequence across all nodes.
    pub fn max_ledger(&self) -> u32 {
        *self.last_ledger_seqs.iter().max().unwrap_or(&0)
    }

    /// Returns the current spread between nodes.
    pub fn current_spread(&self) -> u32 {
        self.max_ledger() - self.min_ledger()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_have_all_externalized_success() {
        // All at target
        let result = have_all_externalized(&[100, 100, 100], 100, 5);
        assert_eq!(result, ConsensusCheckResult::AllExternalized);

        // All above target
        let result = have_all_externalized(&[105, 102, 103], 100, 5);
        assert_eq!(result, ConsensusCheckResult::AllExternalized);
    }

    #[test]
    fn test_have_all_externalized_not_yet() {
        let result = have_all_externalized(&[98, 100, 99], 100, 5);
        assert_eq!(
            result,
            ConsensusCheckResult::NotYetExternalized { min: 98, target: 100 }
        );
    }

    #[test]
    fn test_have_all_externalized_spread_too_wide() {
        let result = have_all_externalized(&[95, 102, 98], 90, 5);
        assert_eq!(
            result,
            ConsensusCheckResult::SpreadTooWide {
                min: 95,
                max: 102,
                max_spread: 5
            }
        );
    }

    #[test]
    fn test_have_all_externalized_empty() {
        let result = have_all_externalized(&[], 100, 5);
        assert_eq!(result, ConsensusCheckResult::AllExternalized);
    }

    #[test]
    fn test_have_all_externalized_single_node() {
        let result = have_all_externalized(&[100], 100, 5);
        assert_eq!(result, ConsensusCheckResult::AllExternalized);

        let result = have_all_externalized(&[99], 100, 5);
        assert_eq!(
            result,
            ConsensusCheckResult::NotYetExternalized { min: 99, target: 100 }
        );
    }

    #[test]
    fn test_consensus_check_result_display() {
        let result = ConsensusCheckResult::AllExternalized;
        assert_eq!(format!("{}", result), "All nodes externalized");

        let result = ConsensusCheckResult::NotYetExternalized { min: 98, target: 100 };
        assert!(format!("{}", result).contains("98"));
        assert!(format!("{}", result).contains("100"));

        let result = ConsensusCheckResult::SpreadTooWide {
            min: 95,
            max: 102,
            max_spread: 5,
        };
        assert!(format!("{}", result).contains("7")); // spread
        assert!(format!("{}", result).contains("5")); // max_spread
    }

    #[test]
    fn test_consensus_tracker_new() {
        let tracker = ConsensusTracker::new(3, 100, 5);
        assert_eq!(tracker.target(), 100);
        assert_eq!(tracker.check_count(), 0);
        assert_eq!(tracker.last_ledger_seqs().len(), 3);
    }

    #[test]
    fn test_consensus_tracker_update() {
        let mut tracker = ConsensusTracker::with_target(3, 100);

        // Initial update - not yet at target
        let result = tracker.update(&[98, 99, 97]);
        assert!(!result.is_externalized());
        assert_eq!(tracker.check_count(), 1);
        assert_eq!(tracker.min_ledger(), 97);
        assert_eq!(tracker.max_ledger(), 99);

        // Progress - still not at target
        let result = tracker.update(&[100, 99, 98]);
        assert!(!result.is_externalized());
        assert_eq!(tracker.check_count(), 2);

        // All at target
        let result = tracker.update(&[100, 100, 100]);
        assert!(result.is_externalized());
        assert_eq!(tracker.check_count(), 3);
    }

    #[test]
    fn test_consensus_tracker_with_validators() {
        let mut tracker = ConsensusTracker::with_target(4, 100).validators_only(true);

        // Node 0 and 2 are validators, 1 and 3 are not
        let is_validator = [true, false, true, false];

        // Only check validators: nodes 0 (98) and 2 (100)
        let result = tracker.update_with_validators(&[98, 50, 100, 50], &is_validator);
        // min of validators is 98, target is 100 -> not externalized
        assert!(!result.is_externalized());

        // Both validators at 100
        let result = tracker.update_with_validators(&[100, 50, 100, 50], &is_validator);
        assert!(result.is_externalized());
    }

    #[test]
    fn test_consensus_tracker_set_target() {
        let mut tracker = ConsensusTracker::with_target(3, 100);
        assert_eq!(tracker.target(), 100);

        tracker.set_target(200);
        assert_eq!(tracker.target(), 200);
    }

    #[test]
    fn test_consensus_tracker_current_spread() {
        let mut tracker = ConsensusTracker::with_target(3, 100);
        tracker.update(&[95, 100, 98]);
        assert_eq!(tracker.current_spread(), 5);
    }

    #[test]
    fn test_default_max_spread() {
        assert_eq!(DEFAULT_MAX_SPREAD, 5);
    }

    #[test]
    fn test_have_all_externalized_default() {
        let result = have_all_externalized_default(&[100, 100, 100], 100);
        assert!(result.is_externalized());
    }
}
