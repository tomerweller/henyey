//! Publish queue queries.
//!
//! The publish queue tracks checkpoint ledgers that need to be published
//! to history archives. When a checkpoint is reached (every 64 ledgers),
//! the ledger is added to the queue. After successful publication, the
//! ledger is removed from the queue.
//!
//! This allows the node to resume publishing after a restart without
//! missing checkpoints.

use rusqlite::{params, Connection};

use crate::error::DbError;

/// Query trait for the history publish queue.
///
/// Provides methods for managing the queue of checkpoint ledgers
/// pending publication to history archives.
pub trait PublishQueueQueries {
    /// Adds a checkpoint ledger to the publish queue.
    ///
    /// This is a no-op if the ledger is already in the queue.
    fn enqueue_publish(&self, ledger_seq: u32) -> Result<(), DbError>;

    /// Removes a checkpoint ledger from the publish queue.
    ///
    /// Called after successful publication. This is a no-op if the
    /// ledger is not in the queue.
    fn remove_publish(&self, ledger_seq: u32) -> Result<(), DbError>;

    /// Loads queued checkpoint ledgers in ascending order.
    ///
    /// Optionally limited to a maximum count.
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
        let row_fn = |row: &rusqlite::Row<'_>| row.get::<_, i64>(0).map(|v| v as u32);
        let mut sql = String::from("SELECT ledgerseq FROM publishqueue ORDER BY ledgerseq ASC");
        if limit.is_some() {
            sql.push_str(" LIMIT ?1");
        }
        let mut stmt = self.prepare(&sql)?;
        let rows = if let Some(limit) = limit {
            stmt.query_map(params![limit as i64], row_fn)?
        } else {
            stmt.query_map([], row_fn)?
        };
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(DbError::from)
    }
}
