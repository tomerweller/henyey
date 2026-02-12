//! Ban list queries.
//!
//! The ban table stores node IDs that should be excluded from consensus
//! and peer connections. Bans are typically applied to nodes that have
//! exhibited malicious behavior or protocol violations.
//!
//! Node IDs are stored as Stellar strkey format (e.g., `G...` public keys).

use rusqlite::{params, Connection};

use crate::error::DbError;

/// Query trait for node ban list operations.
///
/// Provides methods for managing the list of banned validator nodes.
pub trait BanQueries {
    /// Adds a node to the ban list.
    ///
    /// The node_id should be in Stellar strkey format.
    /// This is a no-op if the node is already banned.
    fn ban_node(&self, node_id: &str) -> Result<(), DbError>;

    /// Removes a node from the ban list.
    ///
    /// This is a no-op if the node is not banned.
    fn unban_node(&self, node_id: &str) -> Result<(), DbError>;

    /// Checks if a node is banned.
    fn is_banned(&self, node_id: &str) -> Result<bool, DbError>;

    /// Loads all banned node IDs.
    fn load_bans(&self) -> Result<Vec<String>, DbError>;
}

impl BanQueries for Connection {
    fn ban_node(&self, node_id: &str) -> Result<(), DbError> {
        self.execute(
            "INSERT OR IGNORE INTO ban (nodeid) VALUES (?1)",
            params![node_id],
        )?;
        Ok(())
    }

    fn unban_node(&self, node_id: &str) -> Result<(), DbError> {
        self.execute("DELETE FROM ban WHERE nodeid = ?1", params![node_id])?;
        Ok(())
    }

    fn is_banned(&self, node_id: &str) -> Result<bool, DbError> {
        let count: i64 = self.query_row(
            "SELECT COUNT(*) FROM ban WHERE nodeid = ?1",
            params![node_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    fn load_bans(&self) -> Result<Vec<String>, DbError> {
        let mut stmt = self.prepare("SELECT nodeid FROM ban")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(DbError::from)
    }
}
