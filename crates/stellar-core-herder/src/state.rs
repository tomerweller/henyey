//! Herder state machine for consensus participation.
//!
//! This module defines the state machine that governs how the Herder participates
//! in network consensus. The Herder progresses through distinct states as it
//! synchronizes with the network and begins tracking or validating ledgers.
//!
//! # State Transitions
//!
//! ```text
//! Booting -> Syncing -> Tracking
//! ```
//!
//! - **Booting**: Initial state after startup, not connected to the network
//! - **Syncing**: Catching up to the network via history archives
//! - **Tracking**: Synchronized and following consensus in real-time

use std::fmt;

/// The state of the Herder with respect to network consensus.
///
/// The Herder transitions through these states as it synchronizes with the network
/// and begins participating in consensus. Each state determines which operations
/// are permitted (e.g., receiving transactions, processing SCP envelopes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[derive(Default)]
pub enum HerderState {
    /// Initial state after startup.
    /// The node is booting up and hasn't yet connected to the network.
    #[default]
    Booting,

    /// Syncing state during catchup.
    /// The node is catching up to the current network state by downloading
    /// ledgers from history archives or peers.
    Syncing,

    /// Tracking state after catchup completes.
    /// The node is synchronized with the network and tracking consensus,
    /// receiving and processing SCP messages from validators.
    Tracking,
}

impl HerderState {
    /// Check if the herder is in a state where it can receive SCP envelopes.
    pub fn can_receive_scp(&self) -> bool {
        matches!(self, HerderState::Syncing | HerderState::Tracking)
    }

    /// Check if the herder is in a state where it can receive transactions.
    pub fn can_receive_transactions(&self) -> bool {
        matches!(self, HerderState::Tracking)
    }

    /// Check if the herder is fully synchronized with the network.
    pub fn is_tracking(&self) -> bool {
        matches!(self, HerderState::Tracking)
    }

    /// Check if the herder is still booting up.
    pub fn is_booting(&self) -> bool {
        matches!(self, HerderState::Booting)
    }

    /// Check if the herder is in catchup/syncing mode.
    pub fn is_syncing(&self) -> bool {
        matches!(self, HerderState::Syncing)
    }

    /// Get the next expected state in the normal progression.
    pub fn next_state(&self) -> Option<HerderState> {
        match self {
            HerderState::Booting => Some(HerderState::Syncing),
            HerderState::Syncing => Some(HerderState::Tracking),
            HerderState::Tracking => None,
        }
    }
}


impl fmt::Display for HerderState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HerderState::Booting => write!(f, "Booting"),
            HerderState::Syncing => write!(f, "Syncing"),
            HerderState::Tracking => write!(f, "Tracking"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_transitions() {
        let state = HerderState::default();
        assert!(state.is_booting());
        assert!(!state.can_receive_scp());
        assert!(!state.can_receive_transactions());

        let syncing = state.next_state().unwrap();
        assert!(syncing.is_syncing());
        assert!(syncing.can_receive_scp());
        assert!(!syncing.can_receive_transactions());

        let tracking = syncing.next_state().unwrap();
        assert!(tracking.is_tracking());
        assert!(tracking.can_receive_scp());
        assert!(tracking.can_receive_transactions());

        assert!(tracking.next_state().is_none());
    }

    #[test]
    fn test_state_display() {
        assert_eq!(HerderState::Booting.to_string(), "Booting");
        assert_eq!(HerderState::Syncing.to_string(), "Syncing");
        assert_eq!(HerderState::Tracking.to_string(), "Tracking");
    }
}
