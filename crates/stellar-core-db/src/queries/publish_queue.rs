//! Publish queue queries.

use rusqlite::{params, Connection};

use super::super::error::DbError;

/// Trait for querying and modifying the publishqueue table.
pub trait PublishQueueQueries {
    /// Add a ledger to the publish queue.
    fn enqueue_publish(&self, ledger_seq: u32) -> Result<(), DbError>;

    /// Remove a ledger from the publish queue.
    fn remove_publish(&self, ledger_seq: u32) -> Result<(), DbError>;

    /// Load queued ledgers (ordered).
    fn load_publish_queue(&self, limit: Option<usize>) -> Result<Vec<u32>, DbError>;
}

impl PublishQueueQueries for Connection {
    fn enqueue_publish(&self, ledger_seq: u32) -> Result<(), DbError> {
        self.execute(
            "INSERT OR IGNORE INTO publishqueue (ledgerseq, state) VALUES (?1, 'pending')",
            params![ledger_seq as i64],
        )?;
        Ok(())
    }

    fn remove_publish(&self, ledger_seq: u32) -> Result<(), DbError> {
        self.execute(
            "DELETE FROM publishqueue WHERE ledgerseq = ?1",
            params![ledger_seq as i64],
        )?;
        Ok(())
    }

    fn load_publish_queue(&self, limit: Option<usize>) -> Result<Vec<u32>, DbError> {
        let mut sql = String::from("SELECT ledgerseq FROM publishqueue ORDER BY ledgerseq ASC");
        if limit.is_some() {
            sql.push_str(" LIMIT ?1");
        }
        let mut results = Vec::new();
        let mut stmt = self.prepare(&sql)?;
        if let Some(limit) = limit {
            let rows = stmt.query_map(params![limit as i64], |row| {
                row.get::<_, i64>(0).map(|value| value as u32)
            })?;
            for row in rows {
                results.push(row?);
            }
        } else {
            let rows = stmt.query_map([], |row| {
                row.get::<_, i64>(0).map(|value| value as u32)
            })?;
            for row in rows {
                results.push(row?);
            }
        }
        Ok(results)
    }
}
