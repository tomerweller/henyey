//! Database abstraction layer for rs-stellar-core.
//!
//! This crate provides SQLite-based persistence for the Stellar blockchain node,
//! handling storage and retrieval of:
//!
//! - **Ledger headers**: Block metadata including sequence numbers, hashes, and timestamps
//! - **Transaction history**: Transaction bodies, results, and metadata
//! - **SCP state**: Stellar Consensus Protocol envelopes and quorum sets
//! - **Bucket list snapshots**: Merkle tree state at checkpoint ledgers
//! - **Peer records**: Network peer discovery and connection tracking
//! - **Operational state**: Configuration and runtime state persistence
//!
//! # Architecture
//!
//! The crate is organized into several modules:
//!
//! - [`pool`]: Connection pool management using r2d2
//! - [`schema`]: Database schema definitions and table layouts
//! - [`migrations`]: Schema versioning and migration system
//! - [`queries`]: Typed query traits for each data domain
//! - [`error`]: Error types for database operations
//!
//! # Usage
//!
//! ```no_run
//! use henyey_db::Database;
//!
//! // Open a database (creates if it doesn't exist)
//! let db = Database::open("path/to/stellar.db")?;
//!
//! // Or use an in-memory database for testing
//! let test_db = Database::open_in_memory()?;
//!
//! // Query the latest ledger
//! if let Some(seq) = db.get_latest_ledger_seq()? {
//!     println!("Latest ledger: {}", seq);
//! }
//! # Ok::<(), henyey_db::DbError>(())
//! ```
//!
//! # Query Traits
//!
//! Query functionality is organized into domain-specific traits that extend
//! [`Connection`]. The [`Database`] type provides convenience methods
//! that wrap these traits for common operations.
//!
//! For advanced use cases, you can obtain a connection and use the traits directly:
//!
//! ```no_run
//! use henyey_db::{Database, queries::LedgerQueries};
//!
//! let db = Database::open_in_memory()?;
//! db.with_connection(|conn| {
//!     // Use trait methods directly on the connection
//!     let seq = conn.get_latest_ledger_seq()?;
//!     Ok(seq)
//! })?;
//! # Ok::<(), henyey_db::DbError>(())
//! ```

mod database;
pub mod error;
pub(crate) mod migrations;
pub(crate) mod pool;
pub mod queries;
pub mod schema;
pub mod scp_persistence;

pub use error::DbError;

pub use pool::Database;
pub use queries::*;
pub use scp_persistence::SqliteScpPersistence;

/// SQLite connection type used by [`Database`]'s closure-based APIs
/// (e.g. [`Database::with_connection`]).
///
/// This is a narrow alias for [`rusqlite::Connection`] rather than a broad
/// `pub use rusqlite;` re-export: the only `rusqlite` items intentionally
/// named in `henyey-db`'s public signatures are `Connection`, [`Transaction`],
/// and [`DbError::Sqlite`] (which wraps a [`rusqlite::Error`]). Other
/// top-level `rusqlite` items (the `params!` macro, `OptionalExtension`,
/// etc.) are *not* re-exported by name and callers cannot reach them through
/// `henyey-db` without adding a direct `rusqlite` dependency.
///
/// **Caveat — transparent aliases leak rusqlite types.** Because `Connection`
/// and `Transaction` are `pub type` aliases (not opaque newtype wrappers),
/// methods called on them still return raw `rusqlite` types — e.g.
/// `Connection::prepare` returns [`rusqlite::Statement`], `Statement::query`
/// returns [`rusqlite::Rows`], iteration yields [`rusqlite::Row`]. Callers
/// can name those types via type inference (`let stmt = conn.prepare(..)?;`)
/// without `use rusqlite::...`, so the alias is a *naming* boundary, not a
/// full encapsulation boundary.
///
/// What the narrowing actually buys: the named SemVer surface of `henyey-db`
/// is scoped to `Connection`, `Transaction`, and `DbError::Sqlite`. A
/// `rusqlite` major-version bump is a breaking change to `henyey-db` only if
/// it touches the method signatures reachable through those two aliases or
/// the [`rusqlite::Error`] type — bumps that only touch other top-level items
/// are not breaking changes to `henyey-db`'s API contract.
///
/// This is a deliberate two-step migration. A future follow-up to issue
/// #2748 may promote `Connection` / `Transaction` into fully opaque newtype
/// wrappers (and replace `DbError::Sqlite`'s public `rusqlite::Error` payload
/// with a crate-local error type) once the cost of migrating the internal
/// `impl XQueries for rusqlite::Connection` blocks is justified.
pub type Connection = rusqlite::Connection;

/// SQLite transaction type used by [`Database`]'s closure-based APIs
/// (e.g. [`Database::transaction`]).
///
/// See [`Connection`] for the rationale behind exposing this as a narrow
/// `pub type` alias rather than a broad `pub use rusqlite;` re-export.
pub type Transaction<'conn> = rusqlite::Transaction<'conn>;

/// Result type for database operations.
pub type Result<T> = std::result::Result<T, DbError>;
