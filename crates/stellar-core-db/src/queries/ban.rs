//! Ban list queries.

use rusqlite::{params, Connection};

use super::super::error::DbError;

/// Trait for querying and modifying the ban table.
pub trait BanQueries {
    /// Insert a ban for the given node ID (strkey).
    fn ban_node(&self, node_id: &str) -> Result<(), DbError>;

    /// Remove a ban for the given node ID (strkey).
    fn unban_node(&self, node_id: &str) -> Result<(), DbError>;

    /// Check if a node is banned.
    fn is_banned(&self, node_id: &str) -> Result<bool, DbError>;

    /// Load all banned node IDs.
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
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }
}
