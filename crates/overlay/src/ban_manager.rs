//! Ban manager for persistent peer banning.
//!
//! This module implements the BanManager from stellar-core, which maintains
//! a persistent list of banned nodes in a SQLite database.
//!
//! # Overview
//!
//! - Nodes are identified by their Ed25519 public key (NodeID)
//! - Bans are stored in SQLite for persistence across restarts
//! - The ban list is checked during peer connection acceptance
//!
//! # Database Schema
//!
//! ```sql
//! CREATE TABLE ban (
//!     nodeid CHARACTER(56) NOT NULL PRIMARY KEY
//! );
//! ```

use crate::{OverlayError, PeerId, Result};
use parking_lot::RwLock;
use rusqlite::Connection;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info};

/// Ban manager for maintaining a persistent ban list.
///
/// Thread-safe manager that stores banned node IDs in SQLite.
pub struct BanManager {
    /// In-memory cache of banned nodes for fast lookups.
    cache: RwLock<HashSet<PeerId>>,
    /// Database connection (optional - if None, bans are in-memory only).
    db: Option<Arc<RwLock<Connection>>>,
}

impl BanManager {
    /// Create a new ban manager with in-memory storage only.
    pub fn new_in_memory() -> Self {
        Self {
            cache: RwLock::new(HashSet::new()),
            db: None,
        }
    }

    /// Create a new ban manager with SQLite persistence.
    pub fn new_with_db(db_path: &Path) -> Result<Self> {
        let conn = Connection::open(db_path).map_err(|e| {
            OverlayError::DatabaseError(format!("Failed to open ban database: {}", e))
        })?;

        let manager = Self::from_connection(conn)?;
        let num_loaded = manager.cache.read().len();
        if num_loaded > 0 {
            info!("Loaded {} banned nodes from database", num_loaded);
        }
        Ok(manager)
    }

    /// Create a ban manager using an existing database connection.
    pub fn from_connection(conn: Connection) -> Result<Self> {
        // Create the ban table if it doesn't exist
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ban (
                nodeid CHARACTER(56) NOT NULL PRIMARY KEY
            )",
            [],
        )
        .map_err(|e| OverlayError::DatabaseError(format!("Failed to create ban table: {}", e)))?;

        // Load existing bans into cache
        let mut cache = HashSet::new();
        {
            let mut stmt = conn.prepare("SELECT nodeid FROM ban").map_err(|e| {
                OverlayError::DatabaseError(format!("Failed to prepare query: {}", e))
            })?;

            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|e| OverlayError::DatabaseError(format!("Failed to query bans: {}", e)))?;

            for row in rows.flatten() {
                if let Ok(peer_id) = PeerId::from_strkey(&row) {
                    cache.insert(peer_id);
                }
            }
        }

        #[allow(clippy::arc_with_non_send_sync)]
        let db = Arc::new(RwLock::new(conn));

        Ok(Self {
            cache: RwLock::new(cache),
            db: Some(db),
        })
    }

    /// Ban a node by its ID.
    ///
    /// If the node is already banned, this is a no-op.
    pub fn ban_node(&self, node_id: &PeerId) -> Result<()> {
        // Check cache first
        {
            let cache = self.cache.read();
            if cache.contains(node_id) {
                debug!("Node {} is already banned", node_id);
                return Ok(());
            }
        }

        let node_id_str = node_id.to_strkey();
        info!("Banning node {}", node_id_str);

        // Insert into database if available
        if let Some(ref db) = self.db {
            let conn = db.write();
            conn.execute(
                "INSERT OR IGNORE INTO ban (nodeid) VALUES (?1)",
                [&node_id_str],
            )
            .map_err(|e| OverlayError::DatabaseError(format!("Failed to insert ban: {}", e)))?;
        }

        // Update cache
        {
            let mut cache = self.cache.write();
            cache.insert(node_id.clone());
        }

        Ok(())
    }

    /// Unban a node by its ID.
    ///
    /// If the node is not banned, this is a no-op.
    pub fn unban_node(&self, node_id: &PeerId) -> Result<()> {
        let node_id_str = node_id.to_strkey();
        info!("Unbanning node {}", node_id_str);

        // Delete from database if available
        if let Some(ref db) = self.db {
            let conn = db.write();
            conn.execute("DELETE FROM ban WHERE nodeid = ?1", [&node_id_str])
                .map_err(|e| OverlayError::DatabaseError(format!("Failed to delete ban: {}", e)))?;
        }

        // Update cache
        {
            let mut cache = self.cache.write();
            cache.remove(node_id);
        }

        Ok(())
    }

    /// Check if a node is banned.
    pub fn is_banned(&self, node_id: &PeerId) -> bool {
        let cache = self.cache.read();
        cache.contains(node_id)
    }

    /// Get a list of all banned nodes as strkey strings.
    pub fn get_bans(&self) -> Vec<String> {
        let cache = self.cache.read();
        cache.iter().map(|id| id.to_strkey()).collect()
    }

    /// Get a list of all banned node IDs.
    pub fn get_banned_ids(&self) -> Vec<PeerId> {
        let cache = self.cache.read();
        cache.iter().cloned().collect()
    }

    /// Get the number of banned nodes.
    pub fn ban_count(&self) -> usize {
        let cache = self.cache.read();
        cache.len()
    }

    /// Clear all bans.
    pub fn clear_all(&self) -> Result<()> {
        info!("Clearing all bans");

        // Delete from database if available
        if let Some(ref db) = self.db {
            let conn = db.write();
            conn.execute("DELETE FROM ban", [])
                .map_err(|e| OverlayError::DatabaseError(format!("Failed to clear bans: {}", e)))?;
        }

        // Clear cache
        {
            let mut cache = self.cache.write();
            cache.clear();
        }

        Ok(())
    }

    /// Drop and recreate the ban table.
    ///
    /// This is useful for database migrations or resetting state.
    pub fn drop_and_create(&self) -> Result<()> {
        if let Some(ref db) = self.db {
            let conn = db.write();
            conn.execute("DROP TABLE IF EXISTS ban", []).map_err(|e| {
                OverlayError::DatabaseError(format!("Failed to drop ban table: {}", e))
            })?;
            conn.execute(
                "CREATE TABLE ban (
                    nodeid CHARACTER(56) NOT NULL PRIMARY KEY
                )",
                [],
            )
            .map_err(|e| {
                OverlayError::DatabaseError(format!("Failed to create ban table: {}", e))
            })?;
        }

        // Clear cache
        {
            let mut cache = self.cache.write();
            cache.clear();
        }

        Ok(())
    }
}

impl Default for BanManager {
    fn default() -> Self {
        Self::new_in_memory()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_peer_id(id: u8) -> PeerId {
        PeerId::from_bytes([id; 32])
    }

    #[test]
    fn test_ban_manager_in_memory() {
        let manager = BanManager::new_in_memory();
        let peer = make_peer_id(1);

        assert!(!manager.is_banned(&peer));
        assert_eq!(manager.ban_count(), 0);

        manager.ban_node(&peer).unwrap();
        assert!(manager.is_banned(&peer));
        assert_eq!(manager.ban_count(), 1);

        manager.unban_node(&peer).unwrap();
        assert!(!manager.is_banned(&peer));
        assert_eq!(manager.ban_count(), 0);
    }

    #[test]
    fn test_ban_manager_idempotent() {
        let manager = BanManager::new_in_memory();
        let peer = make_peer_id(1);

        // Banning twice should be idempotent
        manager.ban_node(&peer).unwrap();
        manager.ban_node(&peer).unwrap();
        assert_eq!(manager.ban_count(), 1);

        // Unbanning twice should be safe
        manager.unban_node(&peer).unwrap();
        manager.unban_node(&peer).unwrap();
        assert_eq!(manager.ban_count(), 0);
    }

    #[test]
    fn test_ban_manager_multiple_peers() {
        let manager = BanManager::new_in_memory();
        let peer1 = make_peer_id(1);
        let peer2 = make_peer_id(2);
        let peer3 = make_peer_id(3);

        manager.ban_node(&peer1).unwrap();
        manager.ban_node(&peer2).unwrap();
        manager.ban_node(&peer3).unwrap();

        assert!(manager.is_banned(&peer1));
        assert!(manager.is_banned(&peer2));
        assert!(manager.is_banned(&peer3));
        assert_eq!(manager.ban_count(), 3);

        let bans = manager.get_bans();
        assert_eq!(bans.len(), 3);
    }

    #[test]
    fn test_ban_manager_clear_all() {
        let manager = BanManager::new_in_memory();
        let peer1 = make_peer_id(1);
        let peer2 = make_peer_id(2);

        manager.ban_node(&peer1).unwrap();
        manager.ban_node(&peer2).unwrap();
        assert_eq!(manager.ban_count(), 2);

        manager.clear_all().unwrap();
        assert_eq!(manager.ban_count(), 0);
        assert!(!manager.is_banned(&peer1));
        assert!(!manager.is_banned(&peer2));
    }

    #[test]
    fn test_ban_manager_with_db() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("bans.db");

        let peer1 = make_peer_id(1);
        let peer2 = make_peer_id(2);

        // Create manager and add bans
        {
            let manager = BanManager::new_with_db(&db_path).unwrap();
            manager.ban_node(&peer1).unwrap();
            manager.ban_node(&peer2).unwrap();
            assert_eq!(manager.ban_count(), 2);
        }

        // Create new manager and verify bans persist
        {
            let manager = BanManager::new_with_db(&db_path).unwrap();
            assert_eq!(manager.ban_count(), 2);
            assert!(manager.is_banned(&peer1));
            assert!(manager.is_banned(&peer2));
        }
    }

    #[test]
    fn test_ban_manager_persistence_unban() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("bans.db");

        let peer1 = make_peer_id(1);
        let peer2 = make_peer_id(2);

        // Create manager, add bans, then unban one
        {
            let manager = BanManager::new_with_db(&db_path).unwrap();
            manager.ban_node(&peer1).unwrap();
            manager.ban_node(&peer2).unwrap();
            manager.unban_node(&peer1).unwrap();
            assert_eq!(manager.ban_count(), 1);
        }

        // Verify unban persisted
        {
            let manager = BanManager::new_with_db(&db_path).unwrap();
            assert_eq!(manager.ban_count(), 1);
            assert!(!manager.is_banned(&peer1));
            assert!(manager.is_banned(&peer2));
        }
    }

    #[test]
    fn test_ban_manager_drop_and_create() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("bans.db");

        let peer = make_peer_id(1);

        let manager = BanManager::new_with_db(&db_path).unwrap();
        manager.ban_node(&peer).unwrap();
        assert_eq!(manager.ban_count(), 1);

        manager.drop_and_create().unwrap();
        assert_eq!(manager.ban_count(), 0);
    }
}
