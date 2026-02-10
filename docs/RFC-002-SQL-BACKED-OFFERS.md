# RFC-002: SQL-Backed Offers

**Status:** Approved  
**Created:** 2026-01-27  
**Target:** Phase 2 of Mainnet Support (Bucket List DB Revamp)  
**Estimated Duration:** 2 weeks  
**Dependencies:** RFC-001 (Streaming Iterator) - Completed

## Summary

Replace the in-memory `Vec<LedgerEntry>` offer cache with a SQLite-backed offers table,
matching stellar-core's architecture. This eliminates offer-related memory usage and
provides efficient indexed queries for order book operations.

## Motivation

### Current Problem

The Rust implementation maintains all offers in memory:

```rust
// In LedgerManager
offer_cache: Arc<RwLock<Vec<LedgerEntry>>>,
```

**Memory Impact:**
- Testnet: ~500 MB (scales with offer count)
- Mainnet: Potentially several GB depending on DEX activity

**Functional Issues:**
- No efficient way to query "best N offers" for an asset pair
- Full scan required for order book matching
- Memory grows unbounded with offer count

### stellar-core Architecture (What We're Matching)

stellar-core stores offers in SQLite with indexed queries:

```cpp
// From LedgerTxnOfferSQL.cpp
loadBestOffers(offers, buying, selling, numOffers);
// Uses: ORDER BY price, offerid LIMIT :n
```

Key operations are backed by SQL:
- `loadOffer(sellerID, offerID)` - Point lookup by primary key
- `loadBestOffers(buying, selling, limit)` - Order book query
- `loadOffersByAccountAndAsset(account, asset)` - Account query
- Batch upsert/delete during ledger close

## Design

### Database Schema

```sql
-- Matches stellar-core LedgerTxnOfferSQL.cpp exactly
CREATE TABLE offers (
    sellerid         TEXT NOT NULL,      -- StrKey-encoded AccountID
    offerid          INTEGER NOT NULL PRIMARY KEY,
    sellingasset     BLOB NOT NULL,      -- XDR-encoded Asset
    buyingasset      BLOB NOT NULL,      -- XDR-encoded Asset
    amount           INTEGER NOT NULL,
    pricen           INTEGER NOT NULL,   -- Price numerator
    priced           INTEGER NOT NULL,   -- Price denominator
    price            REAL NOT NULL,      -- Precomputed n/d for sorting
    flags            INTEGER NOT NULL,
    lastmodified     INTEGER NOT NULL,
    extension        BLOB NOT NULL,      -- XDR-encoded OfferEntry.ext
    ledgerext        BLOB NOT NULL       -- XDR-encoded LedgerEntry.ext
);

-- Critical index for order book queries: find best offers for asset pair
CREATE INDEX bestofferindex ON offers (sellingasset, buyingasset, price, offerid);

-- Index for account-based queries (e.g., AllowTrust checks)
CREATE INDEX offerbyseller ON offers (sellerid);
```

### New Module: `henyey-ledger/src/offers_db.rs`

```rust
//! SQL-backed offer storage matching stellar-core.
//!
//! This module provides efficient offer queries using SQLite indexes,
//! replacing the in-memory offer cache for mainnet scalability.

use rusqlite::{params, Connection, Transaction};
use stellar_xdr::curr::*;

/// Load a single offer by seller and offer ID.
pub fn load_offer(
    conn: &Connection,
    seller_id: &AccountId,
    offer_id: i64,
) -> Result<Option<LedgerEntry>, OfferDbError>;

/// Load the N best offers for an asset pair, ordered by price.
///
/// This is the primary order book query. Returns offers sorted by
/// (price ASC, offerid ASC) to match stellar-core behavior where older offers
/// have priority at the same price.
pub fn load_best_offers(
    conn: &Connection,
    buying: &Asset,
    selling: &Asset,
    limit: usize,
) -> Result<Vec<LedgerEntry>, OfferDbError>;

/// Load best offers worse than a given price/offerID threshold.
///
/// Used for paginated order book traversal during path finding.
pub fn load_best_offers_worse_than(
    conn: &Connection,
    buying: &Asset,
    selling: &Asset,
    worse_than_price: f64,
    worse_than_offer_id: i64,
    limit: usize,
) -> Result<Vec<LedgerEntry>, OfferDbError>;

/// Load all offers by account and asset (used by AllowTrust).
pub fn load_offers_by_account_and_asset(
    conn: &Connection,
    account_id: &AccountId,
    asset: &Asset,
) -> Result<Vec<LedgerEntry>, OfferDbError>;

/// Bulk upsert offers (INSERT OR REPLACE).
pub fn bulk_upsert_offers(
    tx: &Transaction,
    entries: &[LedgerEntry],
) -> Result<usize, OfferDbError>;

/// Bulk delete offers by offer ID.
pub fn bulk_delete_offers(
    tx: &Transaction,
    offer_ids: &[i64],
) -> Result<usize, OfferDbError>;

/// Initialize the offers table schema.
pub fn initialize_schema(conn: &Connection) -> Result<(), OfferDbError>;

/// Drop and recreate the offers table (used during catchup).
pub fn drop_offers(conn: &Connection) -> Result<(), OfferDbError>;
```

### Integration with LedgerManager

#### Remove In-Memory Cache

```rust
// Before (current)
pub struct LedgerManager {
    offer_cache: Arc<RwLock<Vec<LedgerEntry>>>,
    offer_cache_initialized: Arc<RwLock<bool>>,
    // ...
}

// After
pub struct LedgerManager {
    // offer_cache removed - use SQL queries instead
    offers_db: Arc<RwLock<Connection>>,  // Or share with existing DB connection
    // ...
}
```

#### Catchup Integration

During `initialize_all_caches()` (using Phase 1's streaming iterator):

```rust
for entry_result in bucket_list.live_entries_iter() {
    let entry = entry_result?;
    
    match &entry.data {
        LedgerEntryData::Offer(_) => {
            // Batch collect for bulk insert
            offer_batch.push(entry);
            if offer_batch.len() >= BATCH_SIZE {
                bulk_upsert_offers(&tx, &offer_batch)?;
                offer_batch.clear();
            }
        }
        // ... other entry types
    }
}
// Flush remaining
if !offer_batch.is_empty() {
    bulk_upsert_offers(&tx, &offer_batch)?;
}
```

#### Ledger Close Integration

In `commit_close()`, apply offer changes from LedgerDelta:

```rust
fn apply_offer_changes(&self, delta: &LedgerDelta) -> Result<()> {
    let conn = self.offers_db.write();
    let tx = conn.transaction()?;
    
    // Collect changes
    let mut upserts = Vec::new();
    let mut deletes = Vec::new();
    
    for (key, change) in delta.changes() {
        if let LedgerKey::Offer(offer_key) = key {
            match change {
                Change::Created(entry) | Change::Updated(entry) => {
                    upserts.push(entry.clone());
                }
                Change::Deleted => {
                    deletes.push(offer_key.offer_id);
                }
            }
        }
    }
    
    // Apply in batch
    if !upserts.is_empty() {
        bulk_upsert_offers(&tx, &upserts)?;
    }
    if !deletes.is_empty() {
        bulk_delete_offers(&tx, &deletes)?;
    }
    
    tx.commit()?;
    Ok(())
}
```

### Order Book Query Changes

Update `SnapshotHandle` to use SQL queries:

```rust
// Before: entries_fn returns cached Vec
let entries_fn: EntriesLookupFn = Arc::new(move || {
    Ok(offer_cache.read().clone())
});

// After: query SQL directly
impl SnapshotHandle {
    pub fn load_best_offers(
        &self,
        buying: &Asset,
        selling: &Asset,
        limit: usize,
    ) -> Result<Vec<LedgerEntry>> {
        load_best_offers(&self.offers_db, buying, selling, limit)
    }
}
```

### Price Comparison (Matching stellar-core)

stellar-core uses a computed `price` column (DOUBLE PRECISION) for sorting:

```cpp
double price = double(offer.price.n) / double(offer.price.d);
```

Order is `(price ASC, offerid ASC)` - lower prices are better, and at equal prices,
older offers (lower offerid) have priority.

The `isBetterOffer()` function from stellar-core:
```cpp
bool isBetterOffer(OfferDescriptor const& lhs, OfferDescriptor const& rhs) {
    double lhsPrice = double(lhs.price.n) / double(lhs.price.d);
    double rhsPrice = double(rhs.price.n) / double(rhs.price.d);
    if (lhsPrice < rhsPrice) return true;
    if (lhsPrice == rhsPrice) return lhs.offerID < rhs.offerID;
    return false;
}
```

## Implementation Plan

### Week 1: Core SQL Infrastructure

| Day | Task |
|-----|------|
| 1 | Create `offers_db.rs` module with schema and basic types |
| 2 | Implement `load_offer`, `load_best_offers` queries |
| 3 | Implement `load_best_offers_worse_than`, `load_offers_by_account_and_asset` |
| 4 | Implement `bulk_upsert_offers`, `bulk_delete_offers` |
| 5 | Unit tests for all SQL operations |

### Week 2: Integration

| Day | Task |
|-----|------|
| 1-2 | Integrate with catchup (populate during `initialize_all_caches`) |
| 3 | Integrate with ledger close (apply delta changes) |
| 4 | Update `SnapshotHandle` and order book queries |
| 5 | Integration tests, remove old offer cache |

## Files to Create/Modify

| File | Action |
|------|--------|
| `crates/henyey-ledger/src/offers_db.rs` | **Create** - SQL offer operations |
| `crates/henyey-ledger/src/lib.rs` | Add `pub mod offers_db` |
| `crates/henyey-ledger/src/manager.rs` | Remove `offer_cache`, integrate SQL |
| `crates/henyey-ledger/src/snapshot.rs` | Update offer queries |
| `crates/henyey-db/src/migrations.rs` | Add offers table migration |

## Memory Impact

| Component | Before | After |
|-----------|--------|-------|
| Offer cache (testnet ~3k offers) | ~500 MB | 0 MB |
| Offer cache (mainnet) | Unbounded | 0 MB |
| SQLite overhead | 0 | ~50 MB (connection + cache) |
| **Net savings (mainnet)** | | **Several GB** |

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| SQL query performance | Proper indexes; benchmark against stellar-core |
| Transaction overhead | Batch operations; single transaction per ledger close |
| Schema migration | Automatic rebuild during catchup if table missing |

## Testing Strategy

1. **Unit tests**: Each SQL function in isolation
2. **Integration tests**: Catchup populates offers correctly
3. **Ledger close tests**: Delta changes applied correctly
4. **Order book tests**: Best offer queries return correct order
5. **Comparison tests**: Results match stellar-core behavior

## Success Criteria

1. All offer operations use SQL instead of in-memory cache
2. Memory usage reduced (no offer-related RAM growth)
3. Order book queries return identical results to stellar-core
4. No regression in ledger close performance

## References

- stellar-core Implementation: `.upstream-v25/src/ledger/LedgerTxnOfferSQL.cpp`
- RFC-001: Streaming Iterator (completed)
- Roadmap: `docs/BUCKET_LIST_DB_ROADMAP.md`
