//! Database abstraction layer for rs-stellar-core.
//!
//! Provides SQLite-based persistence for ledger state, transaction history,
//! and SCP state.

pub mod error;
pub mod migrations;
pub mod pool;
pub mod queries;
pub mod schema;

pub use error::DbError;
pub use migrations::{run_migrations, verify_schema, needs_migration, CURRENT_VERSION};
pub use pool::{Database, PooledConnection};
pub use queries::*;

use std::path::Path;
use tracing::info;
use stellar_xdr::curr::{TransactionHistoryEntry, TransactionHistoryResultEntry};

/// Result type for database operations.
pub type Result<T> = std::result::Result<T, DbError>;

impl Database {
    /// Open a database at the given path, creating if necessary.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let manager = r2d2_sqlite::SqliteConnectionManager::file(path);
        let pool = r2d2::Pool::builder()
            .max_size(10)
            .build(manager)?;

        let db = Self { pool };
        db.initialize()?;
        Ok(db)
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self> {
        let manager = r2d2_sqlite::SqliteConnectionManager::memory();
        let pool = r2d2::Pool::builder()
            .max_size(1)
            .build(manager)?;

        let db = Self { pool };
        db.initialize()?;
        Ok(db)
    }

    fn initialize(&self) -> Result<()> {
        let conn = self.connection()?;

        // Configure SQLite for performance
        conn.execute_batch(r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -64000;
            PRAGMA foreign_keys = ON;
            PRAGMA temp_store = MEMORY;
        "#)?;

        // Check if this is a fresh database
        let tables_exist: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='storestate'",
            [],
            |row| row.get(0),
        ).unwrap_or(false);

        if tables_exist {
            // Existing database - check version and run migrations if needed
            if migrations::needs_migration(&conn)? {
                info!("Database requires migration");
                migrations::run_migrations(&conn)?;
            }
            migrations::verify_schema(&conn)?;
        } else {
            // Fresh database - initialize with current schema
            migrations::initialize_schema(&conn)?;
        }

        Ok(())
    }

    /// Upgrade the database schema to the latest version.
    ///
    /// This should be called when running the "upgrade-db" command.
    pub fn upgrade(&self) -> Result<()> {
        let conn = self.connection()?;
        migrations::run_migrations(&conn)
    }

    /// Get the current schema version.
    pub fn schema_version(&self) -> Result<i32> {
        let conn = self.connection()?;
        migrations::get_schema_version(&conn)
    }

    /// Get the latest ledger sequence number.
    pub fn get_latest_ledger_seq(&self) -> Result<Option<u32>> {
        self.with_connection(|conn| {
            use queries::LedgerQueries;
            conn.get_latest_ledger_seq()
        })
    }

    /// Get the stored network passphrase.
    pub fn get_network_passphrase(&self) -> Result<Option<String>> {
        self.with_connection(|conn| {
            use queries::StateQueries;
            conn.get_state(schema::state_keys::NETWORK_PASSPHRASE)
        })
    }

    /// Store the network passphrase.
    pub fn set_network_passphrase(&self, passphrase: &str) -> Result<()> {
        self.with_connection(|conn| {
            use queries::StateQueries;
            conn.set_state(schema::state_keys::NETWORK_PASSPHRASE, passphrase)
        })
    }

    /// Get a ledger header by sequence number.
    pub fn get_ledger_header(&self, seq: u32) -> Result<Option<stellar_xdr::curr::LedgerHeader>> {
        self.with_connection(|conn| {
            use queries::LedgerQueries;
            conn.load_ledger_header(seq)
        })
    }

    /// Get a ledger hash by sequence number.
    pub fn get_ledger_hash(&self, seq: u32) -> Result<Option<stellar_core_common::Hash256>> {
        self.with_connection(|conn| {
            use queries::LedgerQueries;
            conn.get_ledger_hash(seq)
        })
    }

    /// Get a transaction history entry (tx set) for a ledger.
    pub fn get_tx_history_entry(&self, seq: u32) -> Result<Option<TransactionHistoryEntry>> {
        self.with_connection(|conn| {
            use queries::HistoryQueries;
            conn.load_tx_history_entry(seq)
        })
    }

    /// Get a transaction history result entry (tx results) for a ledger.
    pub fn get_tx_result_entry(&self, seq: u32) -> Result<Option<TransactionHistoryResultEntry>> {
        self.with_connection(|conn| {
            use queries::HistoryQueries;
            conn.load_tx_result_entry(seq)
        })
    }

    /// Store SCP envelopes for a ledger.
    pub fn store_scp_history(
        &self,
        seq: u32,
        envelopes: &[stellar_xdr::curr::ScpEnvelope],
    ) -> Result<()> {
        self.with_connection(|conn| {
            use queries::ScpQueries;
            conn.store_scp_history(seq, envelopes)
        })
    }

    /// Load SCP envelopes for a ledger.
    pub fn load_scp_history(
        &self,
        seq: u32,
    ) -> Result<Vec<stellar_xdr::curr::ScpEnvelope>> {
        self.with_connection(|conn| {
            use queries::ScpQueries;
            conn.load_scp_history(seq)
        })
    }

    /// Store a quorum set by hash.
    pub fn store_scp_quorum_set(
        &self,
        hash: &stellar_core_common::Hash256,
        last_ledger_seq: u32,
        quorum_set: &stellar_xdr::curr::ScpQuorumSet,
    ) -> Result<()> {
        self.with_connection(|conn| {
            use queries::ScpQueries;
            conn.store_scp_quorum_set(hash, last_ledger_seq, quorum_set)
        })
    }

    /// Load a quorum set by hash.
    pub fn load_scp_quorum_set(
        &self,
        hash: &stellar_core_common::Hash256,
    ) -> Result<Option<stellar_xdr::curr::ScpQuorumSet>> {
        self.with_connection(|conn| {
            use queries::ScpQueries;
            conn.load_scp_quorum_set(hash)
        })
    }

    /// Store bucket list snapshot levels for a ledger.
    pub fn store_bucket_list(
        &self,
        seq: u32,
        levels: &[(stellar_core_common::Hash256, stellar_core_common::Hash256)],
    ) -> Result<()> {
        self.with_connection(|conn| {
            use queries::BucketListQueries;
            conn.store_bucket_list(seq, levels)
        })
    }

    /// Load bucket list snapshot levels for a ledger.
    pub fn load_bucket_list(
        &self,
        seq: u32,
    ) -> Result<Option<Vec<(stellar_core_common::Hash256, stellar_core_common::Hash256)>>> {
        self.with_connection(|conn| {
            use queries::BucketListQueries;
            conn.load_bucket_list(seq)
        })
    }

    /// Load peer records (optionally limited).
    pub fn load_peers(
        &self,
        limit: Option<usize>,
    ) -> Result<Vec<(String, u16, queries::PeerRecord)>> {
        self.with_connection(|conn| {
            use queries::PeerQueries;
            conn.load_peers(limit)
        })
    }

    /// Add a checkpoint ledger to the publish queue.
    pub fn enqueue_publish(&self, ledger_seq: u32) -> Result<()> {
        self.with_connection(|conn| {
            use queries::PublishQueueQueries;
            conn.enqueue_publish(ledger_seq)
        })
    }

    /// Remove a checkpoint ledger from the publish queue.
    pub fn remove_publish(&self, ledger_seq: u32) -> Result<()> {
        self.with_connection(|conn| {
            use queries::PublishQueueQueries;
            conn.remove_publish(ledger_seq)
        })
    }

    /// Load queued publish checkpoints.
    pub fn load_publish_queue(&self, limit: Option<usize>) -> Result<Vec<u32>> {
        self.with_connection(|conn| {
            use queries::PublishQueueQueries;
            conn.load_publish_queue(limit)
        })
    }

    /// Add a node ID to the ban list.
    pub fn ban_node(&self, node_id: &str) -> Result<()> {
        self.with_connection(|conn| {
            use queries::BanQueries;
            conn.ban_node(node_id)
        })
    }

    /// Remove a node ID from the ban list.
    pub fn unban_node(&self, node_id: &str) -> Result<()> {
        self.with_connection(|conn| {
            use queries::BanQueries;
            conn.unban_node(node_id)
        })
    }

    /// Check if a node ID is banned.
    pub fn is_banned(&self, node_id: &str) -> Result<bool> {
        self.with_connection(|conn| {
            use queries::BanQueries;
            conn.is_banned(node_id)
        })
    }

    /// Load all banned node IDs.
    pub fn load_bans(&self) -> Result<Vec<String>> {
        self.with_connection(|conn| {
            use queries::BanQueries;
            conn.load_bans()
        })
    }

    /// Store a peer record.
    pub fn store_peer(
        &self,
        host: &str,
        port: u16,
        record: queries::PeerRecord,
    ) -> Result<()> {
        self.with_connection(|conn| {
            use queries::PeerQueries;
            conn.store_peer(host, port, record)
        })
    }

    /// Load a peer record.
    pub fn load_peer(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Option<queries::PeerRecord>> {
        self.with_connection(|conn| {
            use queries::PeerQueries;
            conn.load_peer(host, port)
        })
    }

    /// Remove peers with too many failures.
    pub fn remove_peers_with_failures(&self, min_failures: u32) -> Result<()> {
        self.with_connection(|conn| {
            use queries::PeerQueries;
            conn.remove_peers_with_failures(min_failures)
        })
    }

    /// Load random peers matching filters.
    pub fn load_random_peers(
        &self,
        limit: usize,
        max_failures: u32,
        now: i64,
        peer_type: Option<i32>,
    ) -> Result<Vec<(String, u16, queries::PeerRecord)>> {
        self.with_connection(|conn| {
            use queries::PeerQueries;
            conn.load_random_peers(limit, max_failures, now, peer_type)
        })
    }

    /// Load random peers excluding inbound type.
    pub fn load_random_peers_any_outbound(
        &self,
        limit: usize,
        max_failures: u32,
        now: i64,
        inbound_type: i32,
    ) -> Result<Vec<(String, u16, queries::PeerRecord)>> {
        self.with_connection(|conn| {
            use queries::PeerQueries;
            conn.load_random_peers_any_outbound(limit, max_failures, now, inbound_type)
        })
    }

    /// Load random peers excluding inbound type (ignores next attempt).
    pub fn load_random_peers_any_outbound_max_failures(
        &self,
        limit: usize,
        max_failures: u32,
        inbound_type: i32,
    ) -> Result<Vec<(String, u16, queries::PeerRecord)>> {
        self.with_connection(|conn| {
            use queries::PeerQueries;
            conn.load_random_peers_any_outbound_max_failures(limit, max_failures, inbound_type)
        })
    }

    /// Load random peers for an exact type (ignores next attempt).
    pub fn load_random_peers_by_type_max_failures(
        &self,
        limit: usize,
        max_failures: u32,
        peer_type: i32,
    ) -> Result<Vec<(String, u16, queries::PeerRecord)>> {
        self.with_connection(|conn| {
            use queries::PeerQueries;
            conn.load_random_peers_by_type_max_failures(limit, max_failures, peer_type)
        })
    }
}
