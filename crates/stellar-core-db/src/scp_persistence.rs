//! SQLite implementation of SCP state persistence.
//!
//! This module provides a SQLite-backed implementation of the `ScpStatePersistence`
//! trait from `stellar-core-herder`. It enables crash recovery by persisting SCP
//! state to the database.
//!
//! # Usage
//!
//! ```ignore
//! use stellar_core_db::{Database, SqliteScpPersistence};
//! use stellar_core_herder::ScpPersistenceManager;
//!
//! let db = Database::open("stellar.db")?;
//! let persistence = SqliteScpPersistence::new(db);
//! let manager = ScpPersistenceManager::new(Box::new(persistence));
//! ```

use std::sync::Arc;

use stellar_xdr::curr::Hash;
use tracing::debug;

use crate::error::DbError;
use crate::pool::Database;
use crate::queries::ScpStatePersistenceQueries;

/// SQLite implementation of SCP state persistence.
///
/// This implementation stores SCP state in the SQLite database using the
/// `storestate` table with appropriate prefixes for slot states and tx sets.
pub struct SqliteScpPersistence {
    db: Database,
}

impl SqliteScpPersistence {
    /// Create a new SQLite SCP persistence instance.
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Create a new SQLite SCP persistence instance from an Arc<Database>.
    pub fn from_arc(db: Arc<Database>) -> Self {
        // Clone the database handle (this clones the connection pool reference)
        Self { db: (*db).clone() }
    }

    fn map_error(e: DbError) -> String {
        format!("database error: {}", e)
    }
}

/// This module provides the trait implementation that bridges the herder's
/// persistence trait with the database queries.
///
/// Note: The actual trait implementation is in the herder crate to avoid
/// circular dependencies. This module provides the underlying functionality.
impl SqliteScpPersistence {
    /// Save SCP state for a slot.
    pub fn save_scp_state(&self, slot: u64, state_json: &str) -> Result<(), String> {
        self.db
            .with_connection(|conn| {
                conn.save_scp_slot_state(slot, state_json)?;
                Ok(())
            })
            .map_err(Self::map_error)
    }

    /// Load SCP state for a slot.
    pub fn load_scp_state(&self, slot: u64) -> Result<Option<String>, String> {
        self.db
            .with_connection(|conn| conn.load_scp_slot_state(slot))
            .map_err(Self::map_error)
    }

    /// Load SCP state for all slots.
    pub fn load_all_scp_states(&self) -> Result<Vec<(u64, String)>, String> {
        self.db
            .with_connection(|conn| conn.load_all_scp_slot_states())
            .map_err(Self::map_error)
    }

    /// Delete SCP state for slots below the given threshold.
    pub fn delete_scp_state_below(&self, slot: u64) -> Result<(), String> {
        self.db
            .with_connection(|conn| {
                conn.delete_scp_slot_states_below(slot)?;
                debug!("Deleted SCP state below slot {}", slot);
                Ok(())
            })
            .map_err(Self::map_error)
    }

    /// Save a transaction set.
    pub fn save_tx_set(&self, hash: &Hash, tx_set: &[u8]) -> Result<(), String> {
        self.db
            .with_connection(|conn| {
                conn.save_tx_set_data(hash, tx_set)?;
                Ok(())
            })
            .map_err(Self::map_error)
    }

    /// Load a transaction set.
    pub fn load_tx_set(&self, hash: &Hash) -> Result<Option<Vec<u8>>, String> {
        self.db
            .with_connection(|conn| conn.load_tx_set_data(hash))
            .map_err(Self::map_error)
    }

    /// Load all transaction sets.
    pub fn load_all_tx_sets(&self) -> Result<Vec<(Hash, Vec<u8>)>, String> {
        self.db
            .with_connection(|conn| conn.load_all_tx_set_data())
            .map_err(Self::map_error)
    }

    /// Check if a transaction set exists.
    pub fn has_tx_set(&self, hash: &Hash) -> Result<bool, String> {
        self.db
            .with_connection(|conn| conn.has_tx_set_data(hash))
            .map_err(Self::map_error)
    }

    /// Delete transaction sets for slots below the given threshold.
    pub fn delete_tx_sets_below(&self, slot: u64) -> Result<(), String> {
        self.db
            .with_connection(|conn| {
                conn.delete_old_tx_set_data(slot)?;
                Ok(())
            })
            .map_err(Self::map_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqlite_scp_persistence() {
        let db = Database::open_in_memory().unwrap();
        let persistence = SqliteScpPersistence::new(db);

        // Test slot state
        let state_json = r#"{"version":1,"envelopes":[],"quorum_sets":[]}"#;
        persistence.save_scp_state(100, state_json).unwrap();

        let loaded = persistence.load_scp_state(100).unwrap();
        assert_eq!(loaded, Some(state_json.to_string()));

        // Test all states
        persistence.save_scp_state(101, "state101").unwrap();
        let all = persistence.load_all_scp_states().unwrap();
        assert_eq!(all.len(), 2);

        // Test deletion
        persistence.delete_scp_state_below(101).unwrap();
        let remaining = persistence.load_all_scp_states().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].0, 101);
    }

    #[test]
    fn test_sqlite_tx_set_persistence() {
        let db = Database::open_in_memory().unwrap();
        let persistence = SqliteScpPersistence::new(db);

        let hash = Hash([1u8; 32]);
        let data = vec![1, 2, 3, 4, 5];

        // Save and load
        persistence.save_tx_set(&hash, &data).unwrap();
        assert!(persistence.has_tx_set(&hash).unwrap());

        let loaded = persistence.load_tx_set(&hash).unwrap();
        assert_eq!(loaded, Some(data.clone()));

        // Load all
        let all = persistence.load_all_tx_sets().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].0, hash);
        assert_eq!(all[0].1, data);
    }
}
