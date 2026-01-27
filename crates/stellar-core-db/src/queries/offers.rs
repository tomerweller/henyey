//! SQL-backed offer storage matching C++ stellar-core.
//!
//! This module provides efficient offer queries using SQLite indexes,
//! replacing the in-memory offer cache for mainnet scalability.
//!
//! # Schema
//!
//! The offers table uses the following schema:
//!
//! ```sql
//! CREATE TABLE offers (
//!     sellerid         TEXT NOT NULL,      -- StrKey-encoded AccountID
//!     offerid          INTEGER NOT NULL PRIMARY KEY,
//!     sellingasset     TEXT NOT NULL,      -- Base64-encoded XDR Asset
//!     buyingasset      TEXT NOT NULL,      -- Base64-encoded XDR Asset
//!     amount           INTEGER NOT NULL,
//!     pricen           INTEGER NOT NULL,   -- Price numerator
//!     priced           INTEGER NOT NULL,   -- Price denominator
//!     price            REAL NOT NULL,      -- Precomputed n/d for sorting
//!     flags            INTEGER NOT NULL,
//!     lastmodified     INTEGER NOT NULL,
//!     extension        TEXT NOT NULL,      -- Base64-encoded XDR OfferEntry.ext
//!     ledgerext        TEXT NOT NULL       -- Base64-encoded XDR LedgerEntry.ext
//! );
//! ```
//!
//! # Indexes
//!
//! - `bestofferindex`: (sellingasset, buyingasset, price, offerid) - For order book queries
//! - `offerbyseller`: (sellerid) - For account-based queries
//!
//! # Usage
//!
//! ```ignore
//! use stellar_core_db::queries::offers;
//!
//! // Load best offers for an asset pair
//! let offers = offers::load_best_offers(&conn, &buying, &selling, 100)?;
//!
//! // Bulk upsert during ledger close
//! offers::bulk_upsert_offers(&tx, &entries)?;
//!
//! // Bulk delete
//! offers::bulk_delete_offers(&tx, &offer_ids)?;
//! ```

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rusqlite::{params, Connection, Transaction};
use stellar_xdr::curr::{
    AccountId, Asset, LedgerEntry, LedgerEntryData, LedgerEntryExt, Limits, OfferEntry,
    OfferEntryExt, Price, PublicKey, ReadXdr, Uint256, WriteXdr,
};

// Note: We don't use crate::Result here because we need custom error handling
// for XDR serialization and public key encoding.

/// SQL to create the offers table schema.
///
/// This matches the C++ stellar-core schema exactly.
pub const CREATE_OFFERS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS offers (
    sellerid         TEXT NOT NULL,
    offerid          INTEGER NOT NULL PRIMARY KEY,
    sellingasset     TEXT NOT NULL,
    buyingasset      TEXT NOT NULL,
    amount           INTEGER NOT NULL,
    pricen           INTEGER NOT NULL,
    priced           INTEGER NOT NULL,
    price            REAL NOT NULL,
    flags            INTEGER NOT NULL,
    lastmodified     INTEGER NOT NULL,
    extension        TEXT NOT NULL,
    ledgerext        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS bestofferindex ON offers (sellingasset, buyingasset, price, offerid);
CREATE INDEX IF NOT EXISTS offerbyseller ON offers (sellerid);
"#;

/// Drop and recreate the offers table.
///
/// Used during catchup to clear all offers before repopulating.
pub fn drop_offers(conn: &Connection) -> std::result::Result<(), OfferDbError> {
    conn.execute_batch(
        r#"
        DROP TABLE IF EXISTS offers;
    "#,
    )?;
    conn.execute_batch(CREATE_OFFERS_TABLE)?;
    Ok(())
}

/// Initialize the offers table schema if it doesn't exist.
pub fn initialize_schema(conn: &Connection) -> std::result::Result<(), OfferDbError> {
    conn.execute_batch(CREATE_OFFERS_TABLE)?;
    Ok(())
}

/// Error type for offer database operations.
#[derive(Debug, thiserror::Error)]
pub enum OfferDbError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("XDR serialization error: {0}")]
    Xdr(String),
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
}

impl From<stellar_xdr::curr::Error> for OfferDbError {
    fn from(e: stellar_xdr::curr::Error) -> Self {
        OfferDbError::Xdr(e.to_string())
    }
}

/// Encode a Stellar public key to StrKey format.
fn encode_public_key(account_id: &AccountId) -> String {
    match &account_id.0 {
        PublicKey::PublicKeyTypeEd25519(key) => {
            stellar_strkey::ed25519::PublicKey(key.0).to_string()
        }
    }
}

/// Decode a StrKey-encoded public key to AccountId.
fn decode_public_key(strkey: &str) -> std::result::Result<AccountId, OfferDbError> {
    let pk = stellar_strkey::ed25519::PublicKey::from_string(strkey)
        .map_err(|e| OfferDbError::InvalidPublicKey(e.to_string()))?;
    Ok(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk.0))))
}

/// Encode an Asset to base64-encoded XDR.
fn encode_asset(asset: &Asset) -> std::result::Result<String, OfferDbError> {
    let xdr_bytes = asset.to_xdr(Limits::none())?;
    Ok(BASE64.encode(&xdr_bytes))
}

/// Decode a base64-encoded XDR Asset.
fn decode_asset(encoded: &str) -> std::result::Result<Asset, OfferDbError> {
    let xdr_bytes = BASE64.decode(encoded)?;
    Ok(Asset::from_xdr(&xdr_bytes, Limits::none())?)
}

/// Encode OfferEntry extension to base64-encoded XDR.
fn encode_offer_ext(ext: &OfferEntryExt) -> std::result::Result<String, OfferDbError> {
    let xdr_bytes = ext.to_xdr(Limits::none())?;
    Ok(BASE64.encode(&xdr_bytes))
}

/// Decode base64-encoded XDR OfferEntry extension.
fn decode_offer_ext(encoded: &str) -> std::result::Result<OfferEntryExt, OfferDbError> {
    let xdr_bytes = BASE64.decode(encoded)?;
    Ok(OfferEntryExt::from_xdr(&xdr_bytes, Limits::none())?)
}

/// Encode LedgerEntry extension to base64-encoded XDR.
fn encode_ledger_ext(ext: &LedgerEntryExt) -> std::result::Result<String, OfferDbError> {
    let xdr_bytes = ext.to_xdr(Limits::none())?;
    Ok(BASE64.encode(&xdr_bytes))
}

/// Decode base64-encoded XDR LedgerEntry extension.
fn decode_ledger_ext(encoded: &str) -> std::result::Result<LedgerEntryExt, OfferDbError> {
    let xdr_bytes = BASE64.decode(encoded)?;
    Ok(LedgerEntryExt::from_xdr(&xdr_bytes, Limits::none())?)
}

/// Compute the floating-point price for sorting.
///
/// This matches C++ stellar-core's behavior:
/// ```cpp
/// double price = double(offer.price.n) / double(offer.price.d);
/// ```
fn compute_price_double(price: &Price) -> f64 {
    price.n as f64 / price.d as f64
}

/// Load a single offer by seller ID and offer ID.
///
/// This is the primary point lookup for offers.
///
/// # Arguments
///
/// * `conn` - Database connection
/// * `seller_id` - The seller's account ID
/// * `offer_id` - The unique offer ID
///
/// # Returns
///
/// The offer entry if found, or `None` if not found.
pub fn load_offer(
    conn: &Connection,
    seller_id: &AccountId,
    offer_id: i64,
) -> std::result::Result<Option<LedgerEntry>, OfferDbError> {
    if offer_id < 0 {
        return Ok(None);
    }

    let seller_strkey = encode_public_key(seller_id);

    let mut stmt = conn.prepare_cached(
        "SELECT sellerid, offerid, sellingasset, buyingasset, \
         amount, pricen, priced, flags, lastmodified, extension, ledgerext \
         FROM offers WHERE sellerid = ?1 AND offerid = ?2",
    )?;

    let mut rows = stmt.query(params![seller_strkey, offer_id])?;

    match rows.next()? {
        Some(row) => Ok(Some(row_to_ledger_entry(row)?)),
        None => Ok(None),
    }
}

/// Load a single offer by offer ID only.
///
/// This is useful when you don't know the seller ID.
pub fn load_offer_by_id(
    conn: &Connection,
    offer_id: i64,
) -> std::result::Result<Option<LedgerEntry>, OfferDbError> {
    if offer_id < 0 {
        return Ok(None);
    }

    let mut stmt = conn.prepare_cached(
        "SELECT sellerid, offerid, sellingasset, buyingasset, \
         amount, pricen, priced, flags, lastmodified, extension, ledgerext \
         FROM offers WHERE offerid = ?1",
    )?;

    let mut rows = stmt.query(params![offer_id])?;

    match rows.next()? {
        Some(row) => Ok(Some(row_to_ledger_entry(row)?)),
        None => Ok(None),
    }
}

/// Load the N best offers for an asset pair, ordered by price.
///
/// This is the primary order book query. Returns offers sorted by
/// (price ASC, offerid ASC) to match C++ behavior where older offers
/// have priority at the same price.
///
/// # Arguments
///
/// * `conn` - Database connection
/// * `buying` - The asset being bought
/// * `selling` - The asset being sold
/// * `limit` - Maximum number of offers to return
///
/// # Returns
///
/// A vector of offers sorted by best price first.
pub fn load_best_offers(
    conn: &Connection,
    buying: &Asset,
    selling: &Asset,
    limit: usize,
) -> std::result::Result<Vec<LedgerEntry>, OfferDbError> {
    let buying_encoded = encode_asset(buying)?;
    let selling_encoded = encode_asset(selling)?;

    let mut stmt = conn.prepare_cached(
        "SELECT sellerid, offerid, sellingasset, buyingasset, \
         amount, pricen, priced, flags, lastmodified, extension, ledgerext \
         FROM offers \
         WHERE sellingasset = ?1 AND buyingasset = ?2 \
         ORDER BY price, offerid LIMIT ?3",
    )?;

    let mut rows = stmt.query(params![selling_encoded, buying_encoded, limit as i64])?;
    let mut offers = Vec::with_capacity(limit);

    while let Some(row) = rows.next()? {
        offers.push(row_to_ledger_entry(row)?);
    }

    Ok(offers)
}

/// Load best offers worse than a given price/offerID threshold.
///
/// Used for paginated order book traversal during path finding.
/// Returns offers that are strictly worse than the given threshold.
///
/// # Arguments
///
/// * `conn` - Database connection
/// * `buying` - The asset being bought
/// * `selling` - The asset being sold
/// * `worse_than_price` - Only return offers with price > this value
/// * `worse_than_offer_id` - At equal price, only return offers with ID >= this + 1
/// * `limit` - Maximum number of offers to return
pub fn load_best_offers_worse_than(
    conn: &Connection,
    buying: &Asset,
    selling: &Asset,
    worse_than_price: f64,
    worse_than_offer_id: i64,
    limit: usize,
) -> std::result::Result<Vec<LedgerEntry>, OfferDbError> {
    if worse_than_offer_id == i64::MAX {
        return Err(OfferDbError::Xdr("maximum offerID encountered".to_string()));
    }

    let buying_encoded = encode_asset(buying)?;
    let selling_encoded = encode_asset(selling)?;
    let next_offer_id = worse_than_offer_id + 1;

    // This matches the C++ CTE query structure for pagination
    let mut stmt = conn.prepare_cached(
        "WITH r1 AS ( \
            SELECT sellerid, offerid, sellingasset, buyingasset, amount, price, \
            pricen, priced, flags, lastmodified, extension, ledgerext \
            FROM offers \
            WHERE sellingasset = ?1 AND buyingasset = ?2 AND price > ?3 \
            ORDER BY price, offerid LIMIT ?4 \
         ), \
         r2 AS ( \
            SELECT sellerid, offerid, sellingasset, buyingasset, amount, price, \
            pricen, priced, flags, lastmodified, extension, ledgerext \
            FROM offers \
            WHERE sellingasset = ?5 AND buyingasset = ?6 AND price = ?7 \
            AND offerid >= ?8 ORDER BY price, offerid LIMIT ?9 \
         ) \
         SELECT sellerid, offerid, sellingasset, buyingasset, \
         amount, pricen, priced, flags, lastmodified, extension, ledgerext \
         FROM (SELECT * FROM r1 UNION ALL SELECT * FROM r2) AS res \
         ORDER BY price, offerid LIMIT ?10",
    )?;

    let mut rows = stmt.query(params![
        selling_encoded,
        buying_encoded,
        worse_than_price,
        limit as i64,
        selling_encoded,
        buying_encoded,
        worse_than_price,
        next_offer_id,
        limit as i64,
        limit as i64,
    ])?;

    let mut offers = Vec::with_capacity(limit);
    while let Some(row) = rows.next()? {
        offers.push(row_to_ledger_entry(row)?);
    }

    Ok(offers)
}

/// Load all offers by account and asset.
///
/// Returns offers where the account is the seller AND either the buying
/// or selling asset matches the given asset.
///
/// Used by AllowTrust operations to find offers that might be affected
/// by a trustline change.
///
/// # Note
///
/// The asset parameter must not be ASSET_TYPE_NATIVE (matches C++ behavior).
pub fn load_offers_by_account_and_asset(
    conn: &Connection,
    account_id: &AccountId,
    asset: &Asset,
) -> std::result::Result<Vec<LedgerEntry>, OfferDbError> {
    if matches!(asset, Asset::Native) {
        return Err(OfferDbError::Xdr("Invalid asset type: native".to_string()));
    }

    let account_strkey = encode_public_key(account_id);
    let asset_encoded = encode_asset(asset)?;

    let mut stmt = conn.prepare_cached(
        "SELECT sellerid, offerid, sellingasset, buyingasset, \
         amount, pricen, priced, flags, lastmodified, extension, ledgerext \
         FROM offers WHERE sellerid = ?1 AND \
         (sellingasset = ?2 OR buyingasset = ?3)",
    )?;

    let mut rows = stmt.query(params![account_strkey, asset_encoded, asset_encoded])?;
    let mut offers = Vec::new();

    while let Some(row) = rows.next()? {
        offers.push(row_to_ledger_entry(row)?);
    }

    Ok(offers)
}

/// Load all offers from the database.
///
/// This is used during initialization or for bulk operations.
/// Warning: This can be memory-intensive for large offer sets.
pub fn load_all_offers(conn: &Connection) -> std::result::Result<Vec<LedgerEntry>, OfferDbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT sellerid, offerid, sellingasset, buyingasset, \
         amount, pricen, priced, flags, lastmodified, extension, ledgerext \
         FROM offers",
    )?;

    let mut rows = stmt.query([])?;
    let mut offers = Vec::new();

    while let Some(row) = rows.next()? {
        offers.push(row_to_ledger_entry(row)?);
    }

    Ok(offers)
}

/// Bulk load offers by offer IDs.
///
/// Efficiently loads multiple offers in a single query.
pub fn bulk_load_offers(
    conn: &Connection,
    offer_ids: &[i64],
) -> std::result::Result<Vec<LedgerEntry>, OfferDbError> {
    if offer_ids.is_empty() {
        return Ok(Vec::new());
    }

    // Build the query with placeholders
    let placeholders: Vec<String> = offer_ids.iter().map(|_| "?".to_string()).collect();
    let sql = format!(
        "SELECT sellerid, offerid, sellingasset, buyingasset, \
         amount, pricen, priced, flags, lastmodified, extension, ledgerext \
         FROM offers WHERE offerid IN ({})",
        placeholders.join(",")
    );

    let mut stmt = conn.prepare(&sql)?;

    // Convert offer_ids to rusqlite values
    let params: Vec<&dyn rusqlite::ToSql> = offer_ids
        .iter()
        .map(|id| id as &dyn rusqlite::ToSql)
        .collect();

    let mut rows = stmt.query(params.as_slice())?;
    let mut offers = Vec::with_capacity(offer_ids.len());

    while let Some(row) = rows.next()? {
        offers.push(row_to_ledger_entry(row)?);
    }

    Ok(offers)
}

/// Bulk upsert offers (INSERT OR REPLACE).
///
/// Efficiently inserts or updates multiple offers in a single transaction.
/// This is used during ledger close to apply offer changes.
///
/// # Arguments
///
/// * `tx` - Database transaction
/// * `entries` - The offer entries to upsert
///
/// # Returns
///
/// The number of offers upserted.
pub fn bulk_upsert_offers(
    tx: &Transaction,
    entries: &[LedgerEntry],
) -> std::result::Result<usize, OfferDbError> {
    if entries.is_empty() {
        return Ok(0);
    }

    let mut stmt = tx.prepare_cached(
        "INSERT INTO offers (sellerid, offerid, sellingasset, buyingasset, \
         amount, pricen, priced, price, flags, lastmodified, extension, ledgerext) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
         ON CONFLICT (offerid) DO UPDATE SET \
         sellerid = excluded.sellerid, \
         sellingasset = excluded.sellingasset, \
         buyingasset = excluded.buyingasset, \
         amount = excluded.amount, \
         pricen = excluded.pricen, \
         priced = excluded.priced, \
         price = excluded.price, \
         flags = excluded.flags, \
         lastmodified = excluded.lastmodified, \
         extension = excluded.extension, \
         ledgerext = excluded.ledgerext",
    )?;

    let mut count = 0;
    for entry in entries {
        let offer = match &entry.data {
            LedgerEntryData::Offer(o) => o,
            _ => continue, // Skip non-offer entries
        };

        let seller_strkey = encode_public_key(&offer.seller_id);
        let selling_encoded = encode_asset(&offer.selling)?;
        let buying_encoded = encode_asset(&offer.buying)?;
        let price_double = compute_price_double(&offer.price);
        let offer_ext = encode_offer_ext(&offer.ext)?;
        let ledger_ext = encode_ledger_ext(&entry.ext)?;

        stmt.execute(params![
            seller_strkey,
            offer.offer_id,
            selling_encoded,
            buying_encoded,
            offer.amount,
            offer.price.n,
            offer.price.d,
            price_double,
            offer.flags,
            entry.last_modified_ledger_seq,
            offer_ext,
            ledger_ext,
        ])?;
        count += 1;
    }

    Ok(count)
}

/// Bulk delete offers by offer ID.
///
/// Efficiently deletes multiple offers in a single transaction.
///
/// # Arguments
///
/// * `tx` - Database transaction
/// * `offer_ids` - The offer IDs to delete
///
/// # Returns
///
/// The number of offers deleted.
pub fn bulk_delete_offers(
    tx: &Transaction,
    offer_ids: &[i64],
) -> std::result::Result<usize, OfferDbError> {
    if offer_ids.is_empty() {
        return Ok(0);
    }

    let mut stmt = tx.prepare_cached("DELETE FROM offers WHERE offerid = ?1")?;

    let mut count = 0;
    for offer_id in offer_ids {
        count += stmt.execute(params![offer_id])?;
    }

    Ok(count)
}

/// Count the total number of offers in the database.
pub fn count_offers(conn: &Connection) -> std::result::Result<u64, OfferDbError> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM offers", [], |row| row.get(0))?;
    Ok(count as u64)
}

/// Convert a database row to a LedgerEntry.
fn row_to_ledger_entry(row: &rusqlite::Row) -> std::result::Result<LedgerEntry, OfferDbError> {
    let seller_strkey: String = row.get(0)?;
    let offer_id: i64 = row.get(1)?;
    let selling_encoded: String = row.get(2)?;
    let buying_encoded: String = row.get(3)?;
    let amount: i64 = row.get(4)?;
    let price_n: i32 = row.get(5)?;
    let price_d: i32 = row.get(6)?;
    let flags: i32 = row.get(7)?;
    let last_modified: i32 = row.get(8)?;
    let extension_encoded: String = row.get(9)?;
    let ledger_ext_encoded: String = row.get(10)?;

    let seller_id = decode_public_key(&seller_strkey)?;
    let selling = decode_asset(&selling_encoded)?;
    let buying = decode_asset(&buying_encoded)?;
    let offer_ext = decode_offer_ext(&extension_encoded)?;
    let ledger_ext = decode_ledger_ext(&ledger_ext_encoded)?;

    Ok(LedgerEntry {
        last_modified_ledger_seq: last_modified as u32,
        data: LedgerEntryData::Offer(OfferEntry {
            seller_id,
            offer_id,
            selling,
            buying,
            amount,
            price: Price {
                n: price_n,
                d: price_d,
            },
            flags: flags as u32,
            ext: offer_ext,
        }),
        ext: ledger_ext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{AccountId, AlphaNum4, AssetCode4, PublicKey, Uint256};

    fn make_account_id(byte: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([byte; 32])))
    }

    fn make_offer_entry(
        seller_byte: u8,
        offer_id: i64,
        selling: Asset,
        buying: Asset,
        amount: i64,
        price_n: i32,
        price_d: i32,
    ) -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 100,
            data: LedgerEntryData::Offer(OfferEntry {
                seller_id: make_account_id(seller_byte),
                offer_id,
                selling,
                buying,
                amount,
                price: Price {
                    n: price_n,
                    d: price_d,
                },
                flags: 0,
                ext: OfferEntryExt::V0,
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    fn make_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();
        conn
    }

    fn make_usd_asset() -> Asset {
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: make_account_id(1),
        })
    }

    fn make_eur_asset() -> Asset {
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"EUR\0"),
            issuer: make_account_id(2),
        })
    }

    #[test]
    fn test_initialize_schema() {
        let conn = make_test_db();
        // Schema should be initialized
        let count = count_offers(&conn).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_upsert_and_load_offer() {
        let conn = make_test_db();
        let tx = conn.unchecked_transaction().unwrap();

        let offer = make_offer_entry(10, 1, make_usd_asset(), Asset::Native, 1000, 1, 2);

        // Insert
        let count = bulk_upsert_offers(&tx, &[offer.clone()]).unwrap();
        assert_eq!(count, 1);
        tx.commit().unwrap();

        // Load by seller and offer ID
        let loaded = load_offer(&conn, &make_account_id(10), 1).unwrap();
        assert!(loaded.is_some());

        let loaded_offer = match &loaded.unwrap().data {
            LedgerEntryData::Offer(o) => o.clone(),
            _ => panic!("Expected offer"),
        };
        assert_eq!(loaded_offer.offer_id, 1);
        assert_eq!(loaded_offer.amount, 1000);

        // Load by offer ID only
        let loaded2 = load_offer_by_id(&conn, 1).unwrap();
        assert!(loaded2.is_some());
    }

    #[test]
    fn test_best_offers_ordering() {
        let conn = make_test_db();
        let tx = conn.unchecked_transaction().unwrap();

        let native = Asset::Native;
        let usd = make_usd_asset();

        // Create offers with different prices
        let offers = vec![
            make_offer_entry(1, 100, usd.clone(), native.clone(), 1000, 2, 3), // price = 0.67
            make_offer_entry(2, 101, usd.clone(), native.clone(), 1000, 1, 2), // price = 0.5 (best)
            make_offer_entry(3, 102, usd.clone(), native.clone(), 1000, 3, 4), // price = 0.75
            make_offer_entry(4, 99, usd.clone(), native.clone(), 1000, 1, 2),  // price = 0.5, older
        ];

        bulk_upsert_offers(&tx, &offers).unwrap();
        tx.commit().unwrap();

        // Load best offers
        let best = load_best_offers(&conn, &native, &usd, 10).unwrap();
        assert_eq!(best.len(), 4);

        // Check ordering: 0.5 (id=99), 0.5 (id=101), 0.67 (id=100), 0.75 (id=102)
        let ids: Vec<i64> = best
            .iter()
            .map(|e| match &e.data {
                LedgerEntryData::Offer(o) => o.offer_id,
                _ => panic!(),
            })
            .collect();

        assert_eq!(ids, vec![99, 101, 100, 102]);
    }

    #[test]
    fn test_best_offers_pagination() {
        let conn = make_test_db();
        let tx = conn.unchecked_transaction().unwrap();

        let native = Asset::Native;
        let usd = make_usd_asset();

        // Create 5 offers
        let offers: Vec<LedgerEntry> = (0..5i64)
            .map(|i| {
                make_offer_entry(
                    i as u8,
                    i + 1,
                    usd.clone(),
                    native.clone(),
                    1000,
                    1 + i as i32,
                    10,
                )
            })
            .collect();

        bulk_upsert_offers(&tx, &offers).unwrap();
        tx.commit().unwrap();

        // Load first 2
        let first_page = load_best_offers(&conn, &native, &usd, 2).unwrap();
        assert_eq!(first_page.len(), 2);

        // Get the worst offer from first page for pagination
        let worst_offer = match &first_page.last().unwrap().data {
            LedgerEntryData::Offer(o) => o,
            _ => panic!(),
        };
        let worse_than_price = compute_price_double(&worst_offer.price);

        // Load next page
        let second_page = load_best_offers_worse_than(
            &conn,
            &native,
            &usd,
            worse_than_price,
            worst_offer.offer_id,
            2,
        )
        .unwrap();

        assert_eq!(second_page.len(), 2);
    }

    #[test]
    fn test_offers_by_account_and_asset() {
        let conn = make_test_db();
        let tx = conn.unchecked_transaction().unwrap();

        let usd = make_usd_asset();
        let eur = make_eur_asset();

        // Offers from account 10
        let offers = vec![
            make_offer_entry(10, 1, usd.clone(), Asset::Native, 1000, 1, 2), // selling USD
            make_offer_entry(10, 2, Asset::Native, usd.clone(), 1000, 1, 2), // buying USD
            make_offer_entry(10, 3, eur.clone(), Asset::Native, 1000, 1, 2), // unrelated
            make_offer_entry(20, 4, usd.clone(), Asset::Native, 1000, 1, 2), // different account
        ];

        bulk_upsert_offers(&tx, &offers).unwrap();
        tx.commit().unwrap();

        // Load offers for account 10 and USD
        let result = load_offers_by_account_and_asset(&conn, &make_account_id(10), &usd).unwrap();
        assert_eq!(result.len(), 2); // offers 1 and 2
    }

    #[test]
    fn test_bulk_delete() {
        let conn = make_test_db();
        let tx = conn.unchecked_transaction().unwrap();

        let usd = make_usd_asset();
        let offers: Vec<LedgerEntry> = (0..5)
            .map(|i| make_offer_entry(i as u8, i + 1, usd.clone(), Asset::Native, 1000, 1, 2))
            .collect();

        bulk_upsert_offers(&tx, &offers).unwrap();
        tx.commit().unwrap();

        assert_eq!(count_offers(&conn).unwrap(), 5);

        // Delete 2 offers
        let tx2 = conn.unchecked_transaction().unwrap();
        let deleted = bulk_delete_offers(&tx2, &[1, 3]).unwrap();
        assert_eq!(deleted, 2);
        tx2.commit().unwrap();

        assert_eq!(count_offers(&conn).unwrap(), 3);

        // Verify specific offers are gone
        assert!(load_offer_by_id(&conn, 1).unwrap().is_none());
        assert!(load_offer_by_id(&conn, 3).unwrap().is_none());
        assert!(load_offer_by_id(&conn, 2).unwrap().is_some());
    }

    #[test]
    fn test_drop_offers() {
        let conn = make_test_db();
        let tx = conn.unchecked_transaction().unwrap();

        let usd = make_usd_asset();
        let offer = make_offer_entry(1, 1, usd, Asset::Native, 1000, 1, 2);
        bulk_upsert_offers(&tx, &[offer]).unwrap();
        tx.commit().unwrap();

        assert_eq!(count_offers(&conn).unwrap(), 1);

        // Drop and recreate
        drop_offers(&conn).unwrap();
        assert_eq!(count_offers(&conn).unwrap(), 0);
    }

    #[test]
    fn test_native_asset_rejected() {
        let conn = make_test_db();

        // Native asset should be rejected for account+asset queries
        let result = load_offers_by_account_and_asset(&conn, &make_account_id(1), &Asset::Native);
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_encoding_roundtrip() {
        let account_id = make_account_id(42);
        let encoded = encode_public_key(&account_id);
        let decoded = decode_public_key(&encoded).unwrap();

        match (&account_id.0, &decoded.0) {
            (PublicKey::PublicKeyTypeEd25519(orig), PublicKey::PublicKeyTypeEd25519(roundtrip)) => {
                assert_eq!(orig.0, roundtrip.0);
            }
        }
    }

    #[test]
    fn test_asset_encoding_roundtrip() {
        let assets = vec![
            Asset::Native,
            make_usd_asset(),
            Asset::CreditAlphanum12(stellar_xdr::curr::AlphaNum12 {
                asset_code: stellar_xdr::curr::AssetCode12(*b"LONGASSET123"),
                issuer: make_account_id(99),
            }),
        ];

        for asset in assets {
            let encoded = encode_asset(&asset).unwrap();
            let decoded = decode_asset(&encoded).unwrap();
            assert_eq!(asset, decoded);
        }
    }
}
