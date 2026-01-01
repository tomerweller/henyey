//! Bucket list snapshot queries.

use rusqlite::{Connection, params};
use stellar_core_common::Hash256;

use super::super::error::DbError;

/// Trait for querying and storing bucket list snapshots.
pub trait BucketListQueries {
    /// Store a bucket list snapshot for a ledger sequence.
    fn store_bucket_list(
        &self,
        ledger_seq: u32,
        levels: &[(Hash256, Hash256)],
    ) -> Result<(), DbError>;

    /// Load a bucket list snapshot by ledger sequence.
    fn load_bucket_list(
        &self,
        ledger_seq: u32,
    ) -> Result<Option<Vec<(Hash256, Hash256)>>, DbError>;
}

impl BucketListQueries for Connection {
    fn store_bucket_list(
        &self,
        ledger_seq: u32,
        levels: &[(Hash256, Hash256)],
    ) -> Result<(), DbError> {
        self.execute(
            "DELETE FROM bucketlist WHERE ledgerseq = ?1",
            params![ledger_seq],
        )?;
        for (idx, (curr, snap)) in levels.iter().enumerate() {
            self.execute(
                r#"
                INSERT INTO bucketlist (ledgerseq, level, currhash, snaphash)
                VALUES (?1, ?2, ?3, ?4)
                "#,
                params![
                    ledger_seq,
                    idx as u32,
                    curr.to_hex(),
                    snap.to_hex(),
                ],
            )?;
        }
        Ok(())
    }

    fn load_bucket_list(
        &self,
        ledger_seq: u32,
    ) -> Result<Option<Vec<(Hash256, Hash256)>>, DbError> {
        let mut stmt = self.prepare(
            r#"
            SELECT level, currhash, snaphash
            FROM bucketlist
            WHERE ledgerseq = ?1
            ORDER BY level ASC
            "#,
        )?;
        let rows = stmt.query_map(params![ledger_seq], |row| {
            let curr: String = row.get(1)?;
            let snap: String = row.get(2)?;
            Ok((row.get::<_, u32>(0)?, curr, snap))
        })?;

        let mut entries = Vec::new();
        for row in rows {
            let (level, curr, snap) = row?;
            let curr_hash = Hash256::from_hex(&curr)
                .map_err(|e| DbError::Integrity(format!("Invalid curr hash: {}", e)))?;
            let snap_hash = Hash256::from_hex(&snap)
                .map_err(|e| DbError::Integrity(format!("Invalid snap hash: {}", e)))?;
            entries.push((level, curr_hash, snap_hash));
        }

        if entries.is_empty() {
            return Ok(None);
        }

        let mut levels = Vec::with_capacity(entries.len());
        for (idx, (level, curr, snap)) in entries.into_iter().enumerate() {
            if level as usize != idx {
                return Err(DbError::Integrity(format!(
                    "bucket list level gap at ledger {}",
                    ledger_seq
                )));
            }
            levels.push((curr, snap));
        }

        Ok(Some(levels))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE bucketlist (
                ledgerseq INTEGER NOT NULL,
                level INTEGER NOT NULL,
                currhash TEXT NOT NULL,
                snaphash TEXT NOT NULL,
                PRIMARY KEY (ledgerseq, level)
            );
            "#,
        )
        .unwrap();
        conn
    }

    #[test]
    fn test_store_and_load_bucket_list() {
        let conn = setup_db();
        let levels = vec![
            (Hash256::hash(b"curr0"), Hash256::hash(b"snap0")),
            (Hash256::hash(b"curr1"), Hash256::hash(b"snap1")),
        ];

        conn.store_bucket_list(64, &levels).unwrap();
        let loaded = conn.load_bucket_list(64).unwrap().unwrap();
        assert_eq!(loaded, levels);
    }

    #[test]
    fn test_load_missing_bucket_list() {
        let conn = setup_db();
        assert!(conn.load_bucket_list(128).unwrap().is_none());
    }
}
