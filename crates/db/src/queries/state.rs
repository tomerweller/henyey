//! State queries for the storestate table.
//!
//! The `storestate` table is a simple key-value store used for persistent
//! node configuration and runtime state. It stores values like the network
//! passphrase, last closed ledger, and SCP state.
//!
//! See [`state_keys`] for well-known key constants.

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::DbError;
use crate::schema::state_keys;

/// Query trait for the storestate key-value table.
///
/// Provides generic get/set/delete operations as well as convenience
/// methods for commonly accessed state values.
pub trait StateQueries {
    /// Retrieves a state value by key.
    ///
    /// Returns `None` if the key does not exist.
    fn get_state(&self, key: &str) -> Result<Option<String>, DbError>;

    /// Stores a state value.
    ///
    /// If the key already exists, the value is replaced.
    fn set_state(&self, key: &str, value: &str) -> Result<(), DbError>;

    /// Deletes a state value.
    ///
    /// This is a no-op if the key does not exist.
    fn delete_state(&self, key: &str) -> Result<(), DbError>;

    /// Returns the last closed ledger sequence number.
    ///
    /// This is the primary indicator of the node's progress through the chain.
    fn get_last_closed_ledger(&self) -> Result<Option<u32>, DbError>;

    /// Records the last closed ledger sequence number.
    fn set_last_closed_ledger(&self, seq: u32) -> Result<(), DbError>;
}

impl StateQueries for Connection {
    fn get_state(&self, key: &str) -> Result<Option<String>, DbError> {
        let result = self
            .query_row(
                "SELECT state FROM storestate WHERE statename = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result)
    }

    fn set_state(&self, key: &str, value: &str) -> Result<(), DbError> {
        self.execute(
            "INSERT OR REPLACE INTO storestate (statename, state) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    fn delete_state(&self, key: &str) -> Result<(), DbError> {
        self.execute("DELETE FROM storestate WHERE statename = ?1", params![key])?;
        Ok(())
    }

    fn get_last_closed_ledger(&self) -> Result<Option<u32>, DbError> {
        let result: Option<String> = self.get_state(state_keys::LAST_CLOSED_LEDGER)?;
        match result {
            Some(s) => {
                let seq = s.parse::<u32>().map_err(|e| {
                    DbError::Integrity(format!("Invalid last closed ledger value: {}", e))
                })?;
                Ok(Some(seq))
            }
            None => Ok(None),
        }
    }

    fn set_last_closed_ledger(&self, seq: u32) -> Result<(), DbError> {
        self.set_state(state_keys::LAST_CLOSED_LEDGER, &seq.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE storestate (statename TEXT PRIMARY KEY, state TEXT NOT NULL);",
        )
        .unwrap();
        conn
    }

    #[test]
    fn test_get_set_state() {
        let conn = setup_db();

        // Initially no state
        assert!(conn.get_state("test_key").unwrap().is_none());

        // Set state
        conn.set_state("test_key", "test_value").unwrap();
        assert_eq!(
            conn.get_state("test_key").unwrap(),
            Some("test_value".to_string())
        );

        // Update state
        conn.set_state("test_key", "new_value").unwrap();
        assert_eq!(
            conn.get_state("test_key").unwrap(),
            Some("new_value".to_string())
        );
    }

    #[test]
    fn test_delete_state() {
        let conn = setup_db();

        conn.set_state("test_key", "test_value").unwrap();
        assert!(conn.get_state("test_key").unwrap().is_some());

        conn.delete_state("test_key").unwrap();
        assert!(conn.get_state("test_key").unwrap().is_none());
    }

    #[test]
    fn test_last_closed_ledger() {
        let conn = setup_db();

        // Initially no ledger
        assert!(conn.get_last_closed_ledger().unwrap().is_none());

        // Set ledger
        conn.set_last_closed_ledger(100).unwrap();
        assert_eq!(conn.get_last_closed_ledger().unwrap(), Some(100));

        // Update ledger
        conn.set_last_closed_ledger(200).unwrap();
        assert_eq!(conn.get_last_closed_ledger().unwrap(), Some(200));
    }
}
