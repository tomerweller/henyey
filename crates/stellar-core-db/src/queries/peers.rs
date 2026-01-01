//! Peer record queries for the peers table.

use rusqlite::{params, Connection, OptionalExtension};

use super::super::error::DbError;

/// Database representation of a peer record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerRecord {
    pub next_attempt: i64,
    pub num_failures: u32,
    pub peer_type: i32,
}

impl PeerRecord {
    pub fn new(next_attempt: i64, num_failures: u32, peer_type: i32) -> Self {
        Self {
            next_attempt,
            num_failures,
            peer_type,
        }
    }
}

/// Trait for querying and modifying the peers table.
pub trait PeerQueries {
    /// Load a peer record by address.
    fn load_peer(&self, host: &str, port: u16) -> Result<Option<PeerRecord>, DbError>;

    /// Insert or update a peer record.
    fn store_peer(&self, host: &str, port: u16, record: PeerRecord) -> Result<(), DbError>;

    /// Load peer records (optionally limited).
    fn load_peers(
        &self,
        limit: Option<usize>,
    ) -> Result<Vec<(String, u16, PeerRecord)>, DbError>;

    /// Load random peers matching constraints.
    fn load_random_peers(
        &self,
        limit: usize,
        max_failures: u32,
        now: i64,
        peer_type: Option<i32>,
    ) -> Result<Vec<(String, u16, PeerRecord)>, DbError>;

    /// Load random peers excluding an inbound type.
    fn load_random_peers_any_outbound(
        &self,
        limit: usize,
        max_failures: u32,
        now: i64,
        inbound_type: i32,
    ) -> Result<Vec<(String, u16, PeerRecord)>, DbError>;

    /// Load random peers excluding an inbound type (ignores next attempt).
    fn load_random_peers_any_outbound_max_failures(
        &self,
        limit: usize,
        max_failures: u32,
        inbound_type: i32,
    ) -> Result<Vec<(String, u16, PeerRecord)>, DbError>;

    /// Load random peers for an exact type (ignores next attempt).
    fn load_random_peers_by_type_max_failures(
        &self,
        limit: usize,
        max_failures: u32,
        peer_type: i32,
    ) -> Result<Vec<(String, u16, PeerRecord)>, DbError>;

    /// Remove peers with too many failures.
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

    fn load_peers(
        &self,
        limit: Option<usize>,
    ) -> Result<Vec<(String, u16, PeerRecord)>, DbError> {
        let mut sql = String::from("SELECT ip, port, nextattempt, numfailures, type FROM peers");
        if limit.is_some() {
            sql.push_str(" LIMIT ?1");
        }

        let mut results = Vec::new();
        let mut stmt = self.prepare(&sql)?;
        if let Some(limit) = limit {
            let rows = stmt.query_map(params![limit as i64], |row| {
                let host: String = row.get(0)?;
                let port: i64 = row.get(1)?;
                let record = PeerRecord {
                    next_attempt: row.get(2)?,
                    num_failures: row.get::<_, i64>(3)? as u32,
                    peer_type: row.get(4)?,
                };
                Ok((host, port as u16, record))
            })?;
            for row in rows {
                results.push(row?);
            }
        } else {
            let rows = stmt.query_map([], |row| {
                let host: String = row.get(0)?;
                let port: i64 = row.get(1)?;
                let record = PeerRecord {
                    next_attempt: row.get(2)?,
                    num_failures: row.get::<_, i64>(3)? as u32,
                    peer_type: row.get(4)?,
                };
                Ok((host, port as u16, record))
            })?;
            for row in rows {
                results.push(row?);
            }
        }
        Ok(results)
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

        let mut results = Vec::new();
        let mut stmt = self.prepare(&sql)?;
        if let Some(peer_type) = peer_type {
            let rows = stmt.query_map(
                params![max_failures as i64, now, peer_type, limit as i64],
                |row| {
                    let host: String = row.get(0)?;
                    let port: i64 = row.get(1)?;
                    let record = PeerRecord {
                        next_attempt: row.get(2)?,
                        num_failures: row.get::<_, i64>(3)? as u32,
                        peer_type: row.get(4)?,
                    };
                    Ok((host, port as u16, record))
                },
            )?;
            for row in rows {
                results.push(row?);
            }
        } else {
            let rows = stmt.query_map(
                params![max_failures as i64, now, limit as i64],
                |row| {
                    let host: String = row.get(0)?;
                    let port: i64 = row.get(1)?;
                    let record = PeerRecord {
                        next_attempt: row.get(2)?,
                        num_failures: row.get::<_, i64>(3)? as u32,
                        peer_type: row.get(4)?,
                    };
                    Ok((host, port as u16, record))
                },
            )?;
            for row in rows {
                results.push(row?);
            }
        }
        Ok(results)
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
            |row| {
                let host: String = row.get(0)?;
                let port: i64 = row.get(1)?;
                let record = PeerRecord {
                    next_attempt: row.get(2)?,
                    num_failures: row.get::<_, i64>(3)? as u32,
                    peer_type: row.get(4)?,
                };
                Ok((host, port as u16, record))
            },
        )?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
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
            |row| {
                let host: String = row.get(0)?;
                let port: i64 = row.get(1)?;
                let record = PeerRecord {
                    next_attempt: row.get(2)?,
                    num_failures: row.get::<_, i64>(3)? as u32,
                    peer_type: row.get(4)?,
                };
                Ok((host, port as u16, record))
            },
        )?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
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
            |row| {
                let host: String = row.get(0)?;
                let port: i64 = row.get(1)?;
                let record = PeerRecord {
                    next_attempt: row.get(2)?,
                    num_failures: row.get::<_, i64>(3)? as u32,
                    peer_type: row.get(4)?,
                };
                Ok((host, port as u16, record))
            },
        )?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
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

        let peers = conn
            .load_random_peers(1, 10, 10, Some(1))
            .unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].0, "1.2.3.4");
    }
}
