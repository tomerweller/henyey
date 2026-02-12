//! Peer record queries for the peers table.
//!
//! This module provides database operations for network peer management.
//! The peer table tracks known network peers with their connection state,
//! enabling persistent peer discovery and connection retry logic.
//!
//! # Peer Types
//!
//! Peers are categorized by type (typically inbound vs outbound connections).
//! The type value is application-defined but typically:
//! - 0: Inbound (peer connected to us)
//! - 1: Preferred (configured preferred peers)
//! - 2: Outbound (we connected to peer)

use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::error::DbError;

/// Extracts a `(host, port, PeerRecord)` tuple from a row.
fn peer_row(row: &Row<'_>) -> rusqlite::Result<(String, u16, PeerRecord)> {
    let host: String = row.get(0)?;
    let port: i64 = row.get(1)?;
    let record = PeerRecord {
        next_attempt: row.get(2)?,
        num_failures: row.get::<_, i64>(3)? as u32,
        peer_type: row.get(4)?,
    };
    Ok((host, port as u16, record))
}

/// Database representation of a peer record.
///
/// Tracks connection metadata for a network peer, including retry
/// scheduling and failure counting for connection management.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerRecord {
    /// Unix timestamp of when to next attempt connection.
    ///
    /// Used for exponential backoff on connection failures.
    pub next_attempt: i64,
    /// Number of consecutive connection failures.
    ///
    /// Used for pruning persistently unreachable peers.
    pub num_failures: u32,
    /// The type/category of this peer (application-defined).
    pub peer_type: i32,
}

impl PeerRecord {
    /// Creates a new peer record with the given parameters.
    pub fn new(next_attempt: i64, num_failures: u32, peer_type: i32) -> Self {
        Self {
            next_attempt,
            num_failures,
            peer_type,
        }
    }
}

/// Query trait for peer management operations.
///
/// Provides methods for CRUD operations on the `peers` table, as well as
/// specialized queries for peer selection during connection attempts.
pub trait PeerQueries {
    /// Loads a peer record by host and port.
    ///
    /// Returns `None` if the peer is not in the database.
    fn load_peer(&self, host: &str, port: u16) -> Result<Option<PeerRecord>, DbError>;

    /// Stores or updates a peer record.
    ///
    /// If a peer with the same host/port exists, it is replaced.
    fn store_peer(&self, host: &str, port: u16, record: PeerRecord) -> Result<(), DbError>;

    /// Loads peer records, optionally limited to a maximum count.
    fn load_peers(&self, limit: Option<usize>) -> Result<Vec<(String, u16, PeerRecord)>, DbError>;

    /// Loads random peers matching the specified constraints.
    ///
    /// Filters by:
    /// - `max_failures`: Maximum allowed failure count
    /// - `now`: Current timestamp (only peers with `next_attempt <= now`)
    /// - `peer_type`: Optional specific peer type to match
    ///
    /// Results are randomized to distribute connection attempts.
    fn load_random_peers(
        &self,
        limit: usize,
        max_failures: u32,
        now: i64,
        peer_type: Option<i32>,
    ) -> Result<Vec<(String, u16, PeerRecord)>, DbError>;

    /// Loads random outbound peers (excludes the specified inbound type).
    ///
    /// Respects both failure count and next attempt time constraints.
    fn load_random_peers_any_outbound(
        &self,
        limit: usize,
        max_failures: u32,
        now: i64,
        inbound_type: i32,
    ) -> Result<Vec<(String, u16, PeerRecord)>, DbError>;

    /// Loads random outbound peers, ignoring next attempt time.
    ///
    /// Useful for aggressive peer discovery when the peer table is sparse.
    fn load_random_peers_any_outbound_max_failures(
        &self,
        limit: usize,
        max_failures: u32,
        inbound_type: i32,
    ) -> Result<Vec<(String, u16, PeerRecord)>, DbError>;

    /// Loads random peers of a specific type, ignoring next attempt time.
    fn load_random_peers_by_type_max_failures(
        &self,
        limit: usize,
        max_failures: u32,
        peer_type: i32,
    ) -> Result<Vec<(String, u16, PeerRecord)>, DbError>;

    /// Removes peers that have exceeded the failure threshold.
    ///
    /// Used for garbage collection of persistently unreachable peers.
    fn remove_peers_with_failures(&self, min_failures: u32) -> Result<(), DbError>;
}

impl PeerQueries for Connection {
    fn load_peer(&self, host: &str, port: u16) -> Result<Option<PeerRecord>, DbError> {
        let result = self
            .query_row(
                "SELECT nextattempt, numfailures, type FROM peers WHERE ip = ?1 AND port = ?2",
                params![host, port as i64],
                |row| {
                    Ok(PeerRecord {
                        next_attempt: row.get(0)?,
                        num_failures: row.get::<_, i64>(1)? as u32,
                        peer_type: row.get(2)?,
                    })
                },
            )
            .optional()?;
        Ok(result)
    }

    fn store_peer(&self, host: &str, port: u16, record: PeerRecord) -> Result<(), DbError> {
        self.execute(
            "INSERT OR REPLACE INTO peers (ip, port, nextattempt, numfailures, type) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                host,
                port as i64,
                record.next_attempt,
                record.num_failures as i64,
                record.peer_type,
            ],
        )?;
        Ok(())
    }

    fn load_peers(&self, limit: Option<usize>) -> Result<Vec<(String, u16, PeerRecord)>, DbError> {
        let mut sql = String::from("SELECT ip, port, nextattempt, numfailures, type FROM peers");
        if limit.is_some() {
            sql.push_str(" LIMIT ?1");
        }

        let mut stmt = self.prepare(&sql)?;
        let rows = if let Some(limit) = limit {
            stmt.query_map(params![limit as i64], peer_row)?
        } else {
            stmt.query_map([], peer_row)?
        };
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(DbError::from)
    }

    fn load_random_peers(
        &self,
        limit: usize,
        max_failures: u32,
        now: i64,
        peer_type: Option<i32>,
    ) -> Result<Vec<(String, u16, PeerRecord)>, DbError> {
        let mut sql = String::from(
            "SELECT ip, port, nextattempt, numfailures, type FROM peers WHERE numfailures <= ?1 AND nextattempt <= ?2",
        );
        if peer_type.is_some() {
            sql.push_str(" AND type = ?3");
        }
        sql.push_str(" ORDER BY RANDOM() LIMIT ?4");

        let mut stmt = self.prepare(&sql)?;
        let rows = if let Some(peer_type) = peer_type {
            stmt.query_map(
                params![max_failures as i64, now, peer_type, limit as i64],
                peer_row,
            )?
        } else {
            stmt.query_map(params![max_failures as i64, now, limit as i64], peer_row)?
        };
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(DbError::from)
    }

    fn load_random_peers_any_outbound(
        &self,
        limit: usize,
        max_failures: u32,
        now: i64,
        inbound_type: i32,
    ) -> Result<Vec<(String, u16, PeerRecord)>, DbError> {
        let sql = "SELECT ip, port, nextattempt, numfailures, type FROM peers \
                   WHERE numfailures <= ?1 AND nextattempt <= ?2 AND type != ?3 \
                   ORDER BY RANDOM() LIMIT ?4";
        let mut stmt = self.prepare(sql)?;
        let rows = stmt.query_map(
            params![max_failures as i64, now, inbound_type, limit as i64],
            peer_row,
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(DbError::from)
    }

    fn load_random_peers_any_outbound_max_failures(
        &self,
        limit: usize,
        max_failures: u32,
        inbound_type: i32,
    ) -> Result<Vec<(String, u16, PeerRecord)>, DbError> {
        let sql = "SELECT ip, port, nextattempt, numfailures, type FROM peers \
                   WHERE numfailures <= ?1 AND type != ?2 \
                   ORDER BY RANDOM() LIMIT ?3";
        let mut stmt = self.prepare(sql)?;
        let rows = stmt.query_map(
            params![max_failures as i64, inbound_type, limit as i64],
            peer_row,
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(DbError::from)
    }

    fn load_random_peers_by_type_max_failures(
        &self,
        limit: usize,
        max_failures: u32,
        peer_type: i32,
    ) -> Result<Vec<(String, u16, PeerRecord)>, DbError> {
        let sql = "SELECT ip, port, nextattempt, numfailures, type FROM peers \
                   WHERE numfailures <= ?1 AND type = ?2 \
                   ORDER BY RANDOM() LIMIT ?3";
        let mut stmt = self.prepare(sql)?;
        let rows = stmt.query_map(
            params![max_failures as i64, peer_type, limit as i64],
            peer_row,
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(DbError::from)
    }

    fn remove_peers_with_failures(&self, min_failures: u32) -> Result<(), DbError> {
        self.execute(
            "DELETE FROM peers WHERE numfailures >= ?1",
            params![min_failures as i64],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE peers (ip TEXT NOT NULL, port INTEGER NOT NULL, nextattempt INTEGER NOT NULL, numfailures INTEGER NOT NULL, type INTEGER NOT NULL, PRIMARY KEY (ip, port));",
        )
        .unwrap();
        conn
    }

    #[test]
    fn test_store_and_load_peer() {
        let conn = setup_db();
        let record = PeerRecord::new(123, 2, 1);
        conn.store_peer("1.2.3.4", 11625, record).unwrap();

        let loaded = conn.load_peer("1.2.3.4", 11625).unwrap();
        assert_eq!(loaded, Some(record));
    }

    #[test]
    fn test_load_peers_limit() {
        let conn = setup_db();
        conn.store_peer("1.2.3.4", 1, PeerRecord::new(1, 0, 1))
            .unwrap();
        conn.store_peer("1.2.3.5", 2, PeerRecord::new(2, 0, 1))
            .unwrap();

        let peers = conn.load_peers(Some(1)).unwrap();
        assert_eq!(peers.len(), 1);
    }

    #[test]
    fn test_load_random_peers_any_outbound_max_failures() {
        let conn = setup_db();
        conn.store_peer("1.2.3.4", 1, PeerRecord::new(1, 0, 1))
            .unwrap();
        conn.store_peer("1.2.3.5", 2, PeerRecord::new(1, 0, 2))
            .unwrap();
        conn.store_peer("1.2.3.6", 3, PeerRecord::new(1, 5, 0))
            .unwrap();
        conn.store_peer("1.2.3.7", 4, PeerRecord::new(1, 11, 2))
            .unwrap();

        let peers = conn
            .load_random_peers_any_outbound_max_failures(10, 10, 0)
            .unwrap();
        assert!(peers.iter().all(|(_, _, rec)| rec.peer_type != 0));
        assert!(peers.iter().all(|(_, _, rec)| rec.num_failures <= 10));
    }

    #[test]
    fn test_load_random_peers_by_type_max_failures() {
        let conn = setup_db();
        conn.store_peer("1.2.3.4", 1, PeerRecord::new(1, 0, 1))
            .unwrap();
        conn.store_peer("1.2.3.5", 2, PeerRecord::new(1, 0, 2))
            .unwrap();
        conn.store_peer("1.2.3.6", 3, PeerRecord::new(1, 5, 2))
            .unwrap();
        conn.store_peer("1.2.3.7", 4, PeerRecord::new(1, 11, 2))
            .unwrap();

        let peers = conn
            .load_random_peers_by_type_max_failures(10, 10, 2)
            .unwrap();
        assert!(peers.iter().all(|(_, _, rec)| rec.peer_type == 2));
        assert!(peers.iter().all(|(_, _, rec)| rec.num_failures <= 10));
    }

    #[test]
    fn test_remove_peers_with_failures() {
        let conn = setup_db();
        conn.store_peer("1.2.3.4", 1, PeerRecord::new(1, 1, 1))
            .unwrap();
        conn.store_peer("1.2.3.5", 2, PeerRecord::new(2, 10, 1))
            .unwrap();

        conn.remove_peers_with_failures(5).unwrap();
        let peers = conn.load_peers(None).unwrap();
        assert_eq!(peers.len(), 1);
    }

    #[test]
    fn test_load_random_peers() {
        let conn = setup_db();
        conn.store_peer("1.2.3.4", 1, PeerRecord::new(1, 0, 1))
            .unwrap();
        conn.store_peer("1.2.3.5", 2, PeerRecord::new(2, 0, 2))
            .unwrap();

        let peers = conn.load_random_peers(1, 10, 10, Some(1)).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].0, "1.2.3.4");
    }
}
