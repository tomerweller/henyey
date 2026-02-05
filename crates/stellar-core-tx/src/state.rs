//! Ledger state management for transaction execution.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use stellar_xdr::curr::{
    AccountEntry, AccountEntryExt, AccountEntryExtensionV1, AccountEntryExtensionV1Ext,
    AccountEntryExtensionV2, AccountEntryExtensionV2Ext, AccountEntryExtensionV3, AccountId, Asset,
    ClaimableBalanceEntry, ClaimableBalanceId, ContractCodeEntry, ContractDataDurability,
    ContractDataEntry, DataEntry, ExtensionPoint, Hash, LedgerEntry, LedgerEntryData,
    LedgerEntryExt, LedgerEntryExtensionV1, LedgerEntryExtensionV1Ext, LedgerKey, LedgerKeyAccount,
    LedgerKeyClaimableBalance, LedgerKeyContractCode, LedgerKeyContractData, LedgerKeyData,
    LedgerKeyLiquidityPool, LedgerKeyOffer, LedgerKeyTrustLine, LedgerKeyTtl, Liabilities,
    LiquidityPoolEntry, OfferEntry, PoolId, Price, PublicKey, ScAddress, ScVal,
    SponsorshipDescriptor, TimePoint, TrustLineAsset, TrustLineEntry, TtlEntry, VecM,
};

use crate::apply::{DeltaLengths, LedgerDelta};
use crate::{Result, TxError};

/// Callback type for lazily loading ledger entries from the bucket list.
type EntryLoaderFn = dyn Fn(&LedgerKey) -> Result<Option<LedgerEntry>>;
type BatchEntryLoaderFn = dyn Fn(&[LedgerKey]) -> Result<Vec<LedgerEntry>>;

/// Soroban state extracted from LedgerStateManager for cheap cloning.
///
/// Path payment operations need to clone the entire state for speculative
/// orderbook exchange comparison against liquidity pools. By temporarily
/// extracting the large Soroban collections (which are never accessed during
/// orderbook exchange), the clone becomes much cheaper.
pub struct SorobanState {
    pub contract_data: HashMap<ContractDataKey, ContractDataEntry>,
    pub contract_code: HashMap<[u8; 32], ContractCodeEntry>,
    pub ttl_entries: HashMap<[u8; 32], TtlEntry>,
    pub ttl_bucket_list_snapshot: HashMap<[u8; 32], u32>,
}

/// Savepoint for rolling back state modifications within a transaction.
///
/// Used for per-operation rollback (failed operations have their state changes
/// undone so subsequent operations see clean state) and by
/// `convert_with_offers_and_pools` for speculative orderbook exchange.
///
/// The savepoint captures:
/// - Snapshot maps (to restore snapshot tracking state)
/// - Current entry values for snapshot'd entries (pre-savepoint values)
/// - Delta vector lengths (for truncation)
/// - Modified tracking vec lengths
/// - Entry metadata snapshot state
/// - Created entry sets
/// - ID pool value
#[allow(clippy::type_complexity)]
pub struct Savepoint {
    // Snapshot maps clones (small: only entries modified earlier in TX)
    offer_snapshots: HashMap<([u8; 32], i64), Option<OfferEntry>>,
    account_snapshots: HashMap<[u8; 32], Option<AccountEntry>>,
    trustline_snapshots: HashMap<([u8; 32], AssetKey), Option<TrustLineEntry>>,
    data_snapshots: HashMap<([u8; 32], String), Option<DataEntry>>,
    contract_data_snapshots: HashMap<ContractDataKey, Option<ContractDataEntry>>,
    contract_code_snapshots: HashMap<[u8; 32], Option<ContractCodeEntry>>,
    ttl_snapshots: HashMap<[u8; 32], Option<TtlEntry>>,
    claimable_balance_snapshots: HashMap<[u8; 32], Option<ClaimableBalanceEntry>>,
    liquidity_pool_snapshots: HashMap<[u8; 32], Option<LiquidityPoolEntry>>,

    // Pre-savepoint values of entries in snapshot maps.
    offer_pre_values: Vec<(([u8; 32], i64), Option<OfferEntry>)>,
    account_pre_values: Vec<([u8; 32], Option<AccountEntry>)>,
    trustline_pre_values: Vec<(([u8; 32], AssetKey), Option<TrustLineEntry>)>,
    data_pre_values: Vec<(([u8; 32], String), Option<DataEntry>)>,
    contract_data_pre_values: Vec<(ContractDataKey, Option<ContractDataEntry>)>,
    contract_code_pre_values: Vec<([u8; 32], Option<ContractCodeEntry>)>,
    ttl_pre_values: Vec<([u8; 32], Option<TtlEntry>)>,
    claimable_balance_pre_values: Vec<([u8; 32], Option<ClaimableBalanceEntry>)>,
    liquidity_pool_pre_values: Vec<([u8; 32], Option<LiquidityPoolEntry>)>,

    // Created entry sets
    created_offers: HashSet<([u8; 32], i64)>,
    created_accounts: HashSet<[u8; 32]>,
    created_trustlines: HashSet<([u8; 32], AssetKey)>,
    created_data: HashSet<([u8; 32], String)>,
    created_contract_data: HashSet<ContractDataKey>,
    created_contract_code: HashSet<[u8; 32]>,
    created_ttl: HashSet<[u8; 32]>,
    created_claimable_balances: HashSet<[u8; 32]>,
    created_liquidity_pools: HashSet<[u8; 32]>,

    // Delta vector lengths for truncation
    delta_lengths: DeltaLengths,

    // Modified tracking vec lengths
    modified_accounts_len: usize,
    modified_trustlines_len: usize,
    modified_offers_len: usize,
    modified_data_len: usize,
    modified_contract_data_len: usize,
    modified_contract_code_len: usize,
    modified_ttl_len: usize,
    modified_claimable_balances_len: usize,
    modified_liquidity_pools_len: usize,

    // Entry metadata snapshots
    entry_last_modified_snapshots: HashMap<LedgerKey, Option<u32>>,
    entry_last_modified_pre_values: Vec<(LedgerKey, Option<u32>)>,
    entry_sponsorship_snapshots: HashMap<LedgerKey, Option<AccountId>>,
    entry_sponsorship_ext_snapshots: HashMap<LedgerKey, bool>,
    entry_sponsorship_pre_values: Vec<(LedgerKey, Option<AccountId>)>,
    entry_sponsorship_ext_pre_values: Vec<(LedgerKey, bool)>,

    // Op entry snapshot keys (to remove entries added during speculation)
    op_entry_snapshot_keys: HashSet<LedgerKey>,

    // ID pool value for rollback
    id_pool: u64,
}

/// Trait for reading ledger entries from storage.
pub trait LedgerReader {
    /// Get a ledger entry by key.
    fn get_entry(&self, key: &LedgerKey) -> Option<LedgerEntry>;
}

/// Asset key for trustline lookup.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum AssetKey {
    /// Native XLM asset.
    Native,
    /// Credit alphanum4 asset (code, issuer).
    CreditAlphanum4([u8; 4], [u8; 32]),
    /// Credit alphanum12 asset (code, issuer).
    CreditAlphanum12([u8; 12], [u8; 32]),
    /// Pool share asset.
    PoolShare([u8; 32]),
}

/// Key for contract data lookup.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ContractDataKey {
    /// Contract address.
    pub contract: ScAddress,
    /// Data key.
    pub key: ScVal,
    /// Durability (temporary or persistent).
    pub durability: ContractDataDurability,
}

impl ContractDataKey {
    /// Create a new contract data key.
    pub fn new(contract: ScAddress, key: ScVal, durability: ContractDataDurability) -> Self {
        Self {
            contract,
            key,
            durability,
        }
    }
}

impl AssetKey {
    /// Create an AssetKey from an XDR Asset.
    pub fn from_asset(asset: &Asset) -> Self {
        match asset {
            Asset::Native => AssetKey::Native,
            Asset::CreditAlphanum4(a) => {
                let issuer = account_id_to_bytes(&a.issuer);
                AssetKey::CreditAlphanum4(a.asset_code.0, issuer)
            }
            Asset::CreditAlphanum12(a) => {
                let issuer = account_id_to_bytes(&a.issuer);
                AssetKey::CreditAlphanum12(a.asset_code.0, issuer)
            }
        }
    }

    /// Create an AssetKey from a TrustLineAsset.
    pub fn from_trustline_asset(asset: &TrustLineAsset) -> Self {
        match asset {
            TrustLineAsset::Native => AssetKey::Native,
            TrustLineAsset::CreditAlphanum4(a) => {
                let issuer = account_id_to_bytes(&a.issuer);
                AssetKey::CreditAlphanum4(a.asset_code.0, issuer)
            }
            TrustLineAsset::CreditAlphanum12(a) => {
                let issuer = account_id_to_bytes(&a.issuer);
                AssetKey::CreditAlphanum12(a.asset_code.0, issuer)
            }
            TrustLineAsset::PoolShare(pool_id) => AssetKey::PoolShare(pool_id.0 .0),
        }
    }
}

// ==================== Offer Index ====================
//
// The OfferIndex provides O(log n) lookups for best offers by asset pair,
// similar to C++ stellar-core's MultiOrderBook. This is critical for
// performance when executing path payments and manage offer operations.

use std::collections::BTreeMap;

/// Descriptor for an offer used in the order book index.
/// Offers are sorted by price (ascending) then offer ID (ascending).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferDescriptor {
    /// Price as n/d ratio.
    pub price: Price,
    /// Unique offer identifier.
    pub offer_id: i64,
}

impl OfferDescriptor {
    /// Create a new offer descriptor from an offer entry.
    pub fn from_offer(offer: &OfferEntry) -> Self {
        Self {
            price: offer.price.clone(),
            offer_id: offer.offer_id,
        }
    }
}

/// Comparator for offers: lower price is better, then lower offer ID.
impl Ord for OfferDescriptor {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Use floating-point comparison to match C++ stellar-core behavior.
        // The C++ code uses `double(price.n) / double(price.d)` for ordering.
        let self_price = self.price.n as f64 / self.price.d as f64;
        let other_price = other.price.n as f64 / other.price.d as f64;

        match self_price.partial_cmp(&other_price) {
            Some(std::cmp::Ordering::Equal) | None => self.offer_id.cmp(&other.offer_id),
            Some(ord) => ord,
        }
    }
}

impl PartialOrd for OfferDescriptor {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Key for an offer in the primary offers map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OfferKey {
    /// Seller account ID (32 bytes).
    pub seller: [u8; 32],
    /// Offer ID.
    pub offer_id: i64,
}

impl OfferKey {
    /// Create a new offer key.
    pub fn new(seller: [u8; 32], offer_id: i64) -> Self {
        Self { seller, offer_id }
    }

    /// Create from an offer entry.
    pub fn from_offer(offer: &OfferEntry) -> Self {
        Self {
            seller: account_id_to_bytes(&offer.seller_id),
            offer_id: offer.offer_id,
        }
    }
}

/// Asset pair key for order book lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AssetPair {
    /// Asset being bought.
    pub buying: AssetKey,
    /// Asset being sold.
    pub selling: AssetKey,
}

impl AssetPair {
    /// Create a new asset pair from XDR assets.
    pub fn new(buying: &Asset, selling: &Asset) -> Self {
        Self {
            buying: AssetKey::from_asset(buying),
            selling: AssetKey::from_asset(selling),
        }
    }
}

/// Order book for a single asset pair.
/// Offers are stored in a BTreeMap sorted by (price, offer_id) for O(log n) best offer lookup.
type OrderBook = BTreeMap<OfferDescriptor, OfferKey>;

/// Index of all offers organized by asset pair for efficient best-offer queries.
///
/// This mirrors C++ stellar-core's MultiOrderBook structure. Each asset pair
/// has its own order book (BTreeMap) where offers are sorted by price and offer ID.
///
/// # Performance
///
/// - `best_offer`: O(log n) where n is offers for the asset pair
/// - `add_offer`: O(log n)
/// - `remove_offer`: O(log n)
/// - `update_offer`: O(log n) for same asset pair, O(log n + log m) if assets change
#[derive(Debug, Clone, Default)]
pub struct OfferIndex {
    /// Order books keyed by (buying, selling) asset pair.
    order_books: HashMap<AssetPair, OrderBook>,
    /// Reverse index: offer key -> (asset pair, descriptor) for efficient removal.
    offer_locations: HashMap<OfferKey, (AssetPair, OfferDescriptor)>,
}

impl OfferIndex {
    /// Create a new empty offer index.
    pub fn new() -> Self {
        Self {
            order_books: HashMap::new(),
            offer_locations: HashMap::new(),
        }
    }

    /// Add an offer to the index.
    pub fn add_offer(&mut self, offer: &OfferEntry) {
        let key = OfferKey::from_offer(offer);
        let descriptor = OfferDescriptor::from_offer(offer);
        let asset_pair = AssetPair::new(&offer.buying, &offer.selling);

        // Add to order book
        let order_book = self.order_books.entry(asset_pair.clone()).or_default();
        order_book.insert(descriptor.clone(), key);

        // Add to reverse index
        self.offer_locations.insert(key, (asset_pair, descriptor));
    }

    /// Remove an offer from the index.
    pub fn remove_offer(&mut self, seller: &AccountId, offer_id: i64) {
        let key = OfferKey::new(account_id_to_bytes(seller), offer_id);
        self.remove_by_key(&key);
    }

    /// Remove an offer from the index by its key.
    pub fn remove_by_key(&mut self, key: &OfferKey) {
        // Look up location in reverse index
        if let Some((asset_pair, descriptor)) = self.offer_locations.remove(key) {
            // Remove from order book
            if let Some(order_book) = self.order_books.get_mut(&asset_pair) {
                order_book.remove(&descriptor);
                // Clean up empty order books
                if order_book.is_empty() {
                    self.order_books.remove(&asset_pair);
                }
            }
        }
    }

    /// Update an offer in the index.
    ///
    /// This handles the case where an offer's price or assets might change.
    pub fn update_offer(&mut self, offer: &OfferEntry) {
        // Remove old entry if exists
        self.remove_offer(&offer.seller_id, offer.offer_id);
        // Add with new values
        self.add_offer(offer);
    }

    /// Get the best (lowest price) offer for an asset pair.
    ///
    /// Returns the offer key if one exists.
    pub fn best_offer_key(&self, buying: &Asset, selling: &Asset) -> Option<OfferKey> {
        let asset_pair = AssetPair::new(buying, selling);
        self.order_books
            .get(&asset_pair)
            .and_then(|book| book.first_key_value())
            .map(|(_, key)| *key)
    }

    /// Get the best offer for an asset pair, excluding specific offers.
    ///
    /// This is used during offer crossing when we need to skip offers
    /// that have already been processed or belong to the same account.
    pub fn best_offer_key_filtered<F>(
        &self,
        buying: &Asset,
        selling: &Asset,
        mut filter: F,
    ) -> Option<OfferKey>
    where
        F: FnMut(&OfferKey) -> bool,
    {
        let asset_pair = AssetPair::new(buying, selling);
        self.order_books.get(&asset_pair).and_then(|book| {
            book.iter()
                .find(|(_, key)| filter(key))
                .map(|(_, key)| *key)
        })
    }

    /// Iterate over all offers for an asset pair in price order.
    pub fn offers_for_pair(
        &self,
        buying: &Asset,
        selling: &Asset,
    ) -> impl Iterator<Item = &OfferKey> {
        let asset_pair = AssetPair::new(buying, selling);
        self.order_books
            .get(&asset_pair)
            .into_iter()
            .flat_map(|book| book.values())
    }

    /// Check if the index contains any offers for an asset pair.
    pub fn has_offers(&self, buying: &Asset, selling: &Asset) -> bool {
        let asset_pair = AssetPair::new(buying, selling);
        self.order_books
            .get(&asset_pair)
            .is_some_and(|book| !book.is_empty())
    }

    /// Get the total number of offers in the index.
    pub fn len(&self) -> usize {
        self.offer_locations.len()
    }

    /// Check if the index is empty.
    pub fn is_empty(&self) -> bool {
        self.offer_locations.is_empty()
    }

    /// Clear all offers from the index.
    pub fn clear(&mut self) {
        self.order_books.clear();
        self.offer_locations.clear();
    }

    /// Get the number of asset pairs with offers.
    pub fn num_asset_pairs(&self) -> usize {
        self.order_books.len()
    }
}

// ==================== End Offer Index ====================

/// Ledger state manager for transaction execution.
///
/// This provides read/write access to ledger entries during transaction
/// execution, tracking all changes for later persistence.
#[derive(Clone)]
pub struct LedgerStateManager {
    /// Current ledger sequence.
    ledger_seq: u32,
    /// Base reserve in stroops (minimum balance per sub-entry).
    base_reserve: i64,
    /// ID pool for generating offer IDs.
    id_pool: u64,
    /// Account entries by account ID (32-byte public key).
    accounts: HashMap<[u8; 32], AccountEntry>,
    /// Trustline entries by (account, asset).
    trustlines: HashMap<([u8; 32], AssetKey), TrustLineEntry>,
    /// Offer entries by (seller, offer_id).
    offers: HashMap<([u8; 32], i64), OfferEntry>,
    /// Data entries by (account, name).
    data_entries: HashMap<([u8; 32], String), DataEntry>,
    /// Contract data entries by (contract, key, durability).
    contract_data: HashMap<ContractDataKey, ContractDataEntry>,
    /// Contract code entries by hash.
    contract_code: HashMap<[u8; 32], ContractCodeEntry>,
    /// TTL entries by key hash.
    ttl_entries: HashMap<[u8; 32], TtlEntry>,
    /// TTL values at ledger start (for Soroban execution).
    /// This is captured at the start of each ledger and remains read-only during execution.
    /// Soroban uses these values instead of ttl_entries to match C++ behavior where
    /// transactions see the bucket list state at ledger start, not changes from previous txs.
    ttl_bucket_list_snapshot: HashMap<[u8; 32], u32>,
    /// Claimable balance entries by balance ID.
    claimable_balances: HashMap<[u8; 32], ClaimableBalanceEntry>,
    /// Liquidity pool entries by pool ID.
    liquidity_pools: HashMap<[u8; 32], LiquidityPoolEntry>,
    /// Sponsoring account IDs for ledger entries (only when sponsored).
    entry_sponsorships: HashMap<LedgerKey, AccountId>,
    /// Ledger entries that have a sponsorship extension (even if not currently sponsored).
    entry_sponsorship_ext: HashSet<LedgerKey>,
    /// Last modified ledger sequence for each entry.
    entry_last_modified: HashMap<LedgerKey, u32>,
    /// Per-operation snapshot of entries before mutation.
    op_entry_snapshots: HashMap<LedgerKey, LedgerEntry>,
    /// Whether op-level snapshots are active.
    op_snapshots_active: bool,
    /// Whether we're in a multi-operation transaction.
    /// When true, flush_modified_entries records STATE/UPDATED for every access,
    /// even if values are identical.
    multi_op_mode: bool,
    /// Active sponsorship stack for the current transaction.
    sponsorship_stack: Vec<SponsorshipContext>,
    /// Changes made during execution.
    delta: LedgerDelta,
    /// Track which entries have been modified for rollback.
    modified_accounts: Vec<[u8; 32]>,
    /// Track which trustlines have been modified.
    modified_trustlines: Vec<([u8; 32], AssetKey)>,
    /// Track which offers have been modified.
    modified_offers: Vec<([u8; 32], i64)>,
    /// Track which data entries have been modified.
    modified_data: Vec<([u8; 32], String)>,
    /// Track which contract data entries have been modified.
    modified_contract_data: Vec<ContractDataKey>,
    /// Track which contract code entries have been modified.
    modified_contract_code: Vec<[u8; 32]>,
    /// Track which TTL entries have been modified.
    modified_ttl: Vec<[u8; 32]>,
    /// Deferred read-only TTL bumps. These are TTL updates for read-only entries
    /// where only the TTL changed. Per C++ stellar-core behavior:
    /// - They should NOT appear in transaction meta
    /// - They should be flushed to the delta at end of ledger (for bucket list)
    ///   Key is TTL key hash, value is the new live_until_ledger_seq.
    deferred_ro_ttl_bumps: HashMap<[u8; 32], u32>,
    /// Track which claimable balance entries have been modified.
    modified_claimable_balances: Vec<[u8; 32]>,
    /// Track which liquidity pool entries have been modified.
    modified_liquidity_pools: Vec<[u8; 32]>,
    /// Snapshot of accounts for rollback.
    account_snapshots: HashMap<[u8; 32], Option<AccountEntry>>,
    /// Snapshot of trustlines for rollback.
    trustline_snapshots: HashMap<([u8; 32], AssetKey), Option<TrustLineEntry>>,
    /// Snapshot of offers for rollback.
    offer_snapshots: HashMap<([u8; 32], i64), Option<OfferEntry>>,
    /// Snapshot of data entries for rollback.
    data_snapshots: HashMap<([u8; 32], String), Option<DataEntry>>,
    /// Snapshot of contract data entries for rollback.
    contract_data_snapshots: HashMap<ContractDataKey, Option<ContractDataEntry>>,
    /// Snapshot of contract code entries for rollback.
    contract_code_snapshots: HashMap<[u8; 32], Option<ContractCodeEntry>>,
    /// Snapshot of TTL entries for rollback.
    ttl_snapshots: HashMap<[u8; 32], Option<TtlEntry>>,
    /// Snapshot of claimable balance entries for rollback.
    claimable_balance_snapshots: HashMap<[u8; 32], Option<ClaimableBalanceEntry>>,
    /// Snapshot of liquidity pool entries for rollback.
    liquidity_pool_snapshots: HashMap<[u8; 32], Option<LiquidityPoolEntry>>,
    /// Snapshot of entry sponsorships for rollback.
    entry_sponsorship_snapshots: HashMap<LedgerKey, Option<AccountId>>,
    /// Snapshot of sponsorship extension presence for rollback.
    entry_sponsorship_ext_snapshots: HashMap<LedgerKey, bool>,
    /// Snapshot of last modified ledger sequence for rollback.
    entry_last_modified_snapshots: HashMap<LedgerKey, Option<u32>>,
    /// Track accounts created in this transaction (for rollback).
    created_accounts: HashSet<[u8; 32]>,
    /// Track trustlines created in this transaction (for rollback).
    created_trustlines: HashSet<([u8; 32], AssetKey)>,
    /// Track offers created in this transaction (for rollback).
    created_offers: HashSet<([u8; 32], i64)>,
    /// Track data entries created in this transaction (for rollback).
    created_data: HashSet<([u8; 32], String)>,
    /// Track contract data entries created in this transaction (for rollback).
    created_contract_data: HashSet<ContractDataKey>,
    /// Track contract code entries created in this transaction (for rollback).
    created_contract_code: HashSet<[u8; 32]>,
    /// Track TTL entries created in this transaction (for rollback).
    created_ttl: HashSet<[u8; 32]>,
    /// Track claimable balances created in this transaction (for rollback).
    created_claimable_balances: HashSet<[u8; 32]>,
    /// Track liquidity pools created in this transaction (for rollback).
    created_liquidity_pools: HashSet<[u8; 32]>,
    /// Track contract data entries deleted in this ledger.
    /// Used to prevent reloading deleted entries from bucket list during footprint loading.
    /// In C++ stellar-core, deleted entries are tracked in mThreadEntryMap as nullopt,
    /// which prevents subsequent transactions from seeing them.
    deleted_contract_data: HashSet<ContractDataKey>,
    /// Track contract code entries deleted in this ledger.
    deleted_contract_code: HashSet<[u8; 32]>,
    /// Track TTL entries deleted in this ledger.
    deleted_ttl: HashSet<[u8; 32]>,
    /// Snapshot of id_pool for rollback. When an ID is generated during a transaction
    /// that later fails, the id_pool must be restored to its pre-transaction value.
    id_pool_snapshot: Option<u64>,
    /// Snapshot of delta for rollback. Preserves committed changes from previous
    /// transactions so they're not lost when the current transaction fails.
    delta_snapshot: Option<LedgerDelta>,
    /// Index of offers by asset pair for efficient best-offer lookups.
    /// This mirrors C++ stellar-core's MultiOrderBook structure.
    offer_index: OfferIndex,
    /// Secondary index: (account_bytes, asset) → set of offer_ids.
    /// Each offer is indexed under both (seller, selling_asset) and (seller, buying_asset).
    /// Used for O(k) lookups in `remove_offers_by_account_and_asset`.
    account_asset_offers: HashMap<([u8; 32], AssetKey), HashSet<i64>>,
    /// Optional callback to lazily load ledger entries from the bucket list.
    /// Used during offer crossing to load seller accounts and trustlines
    /// on demand instead of preloading all offer dependencies upfront.
    entry_loader: Option<Arc<EntryLoaderFn>>,
    /// Optional batch callback for loading multiple entries in a single pass
    /// through the bucket list. Used by `ensure_offer_entries_loaded` to batch
    /// account + trustline lookups for offer sellers.
    batch_entry_loader: Option<Arc<BatchEntryLoaderFn>>,
}

#[derive(Debug, Clone)]
pub struct SponsorshipContext {
    pub sponsoring: AccountId,
    pub sponsored: AccountId,
}

impl LedgerStateManager {
    /// Create a new ledger state manager for the given ledger sequence.
    ///
    /// # Arguments
    ///
    /// * `base_reserve` - Base reserve in stroops (e.g., 5_000_000 for 0.5 XLM)
    /// * `ledger_seq` - The current ledger sequence number
    pub fn new(base_reserve: i64, ledger_seq: u32) -> Self {
        Self {
            ledger_seq,
            base_reserve,
            id_pool: 0,
            accounts: HashMap::new(),
            trustlines: HashMap::new(),
            offers: HashMap::new(),
            data_entries: HashMap::new(),
            contract_data: HashMap::new(),
            contract_code: HashMap::new(),
            ttl_entries: HashMap::new(),
            ttl_bucket_list_snapshot: HashMap::new(),
            claimable_balances: HashMap::new(),
            liquidity_pools: HashMap::new(),
            entry_sponsorships: HashMap::new(),
            entry_sponsorship_ext: HashSet::new(),
            entry_last_modified: HashMap::new(),
            op_entry_snapshots: HashMap::new(),
            op_snapshots_active: false,
            multi_op_mode: false,
            sponsorship_stack: Vec::new(),
            delta: LedgerDelta::new(ledger_seq),
            modified_accounts: Vec::new(),
            modified_trustlines: Vec::new(),
            modified_offers: Vec::new(),
            modified_data: Vec::new(),
            modified_contract_data: Vec::new(),
            modified_contract_code: Vec::new(),
            modified_ttl: Vec::new(),
            deferred_ro_ttl_bumps: HashMap::new(),
            modified_claimable_balances: Vec::new(),
            modified_liquidity_pools: Vec::new(),
            account_snapshots: HashMap::new(),
            trustline_snapshots: HashMap::new(),
            offer_snapshots: HashMap::new(),
            data_snapshots: HashMap::new(),
            contract_data_snapshots: HashMap::new(),
            contract_code_snapshots: HashMap::new(),
            ttl_snapshots: HashMap::new(),
            claimable_balance_snapshots: HashMap::new(),
            liquidity_pool_snapshots: HashMap::new(),
            entry_sponsorship_snapshots: HashMap::new(),
            entry_sponsorship_ext_snapshots: HashMap::new(),
            entry_last_modified_snapshots: HashMap::new(),
            created_accounts: HashSet::new(),
            created_trustlines: HashSet::new(),
            created_offers: HashSet::new(),
            created_data: HashSet::new(),
            created_contract_data: HashSet::new(),
            created_contract_code: HashSet::new(),
            created_ttl: HashSet::new(),
            created_claimable_balances: HashSet::new(),
            created_liquidity_pools: HashSet::new(),
            deleted_contract_data: HashSet::new(),
            deleted_contract_code: HashSet::new(),
            deleted_ttl: HashSet::new(),
            id_pool_snapshot: None,
            delta_snapshot: None,
            offer_index: OfferIndex::new(),
            account_asset_offers: HashMap::new(),
            entry_loader: None,
            batch_entry_loader: None,
        }
    }

    /// Insert an offer into the (account, asset) secondary index.
    fn aa_index_insert(&mut self, offer: &OfferEntry) {
        let seller = account_id_to_bytes(&offer.seller_id);
        let selling_key = AssetKey::from_asset(&offer.selling);
        let buying_key = AssetKey::from_asset(&offer.buying);
        self.account_asset_offers
            .entry((seller, selling_key))
            .or_default()
            .insert(offer.offer_id);
        self.account_asset_offers
            .entry((seller, buying_key))
            .or_default()
            .insert(offer.offer_id);
    }

    /// Remove an offer from the (account, asset) secondary index.
    fn aa_index_remove(&mut self, offer: &OfferEntry) {
        let seller = account_id_to_bytes(&offer.seller_id);
        let selling_key = AssetKey::from_asset(&offer.selling);
        let buying_key = AssetKey::from_asset(&offer.buying);
        if let Some(set) = self.account_asset_offers.get_mut(&(seller, selling_key)) {
            set.remove(&offer.offer_id);
        }
        if let Some(set) = self.account_asset_offers.get_mut(&(seller, buying_key)) {
            set.remove(&offer.offer_id);
        }
    }

    fn last_modified_for_key(&self, key: &LedgerKey) -> u32 {
        self.entry_last_modified
            .get(key)
            .copied()
            .unwrap_or(self.ledger_seq)
    }

    fn last_modified_snapshot_for_key(&self, key: &LedgerKey) -> Option<u32> {
        self.entry_last_modified_snapshots
            .get(key)
            .copied()
            .flatten()
    }

    fn snapshot_last_modified_key(&mut self, key: &LedgerKey) {
        if !self.entry_last_modified_snapshots.contains_key(key) {
            let snapshot = self.entry_last_modified.get(key).copied();
            self.entry_last_modified_snapshots
                .insert(key.clone(), snapshot);
        }
    }

    fn set_last_modified_key(&mut self, key: LedgerKey, seq: u32) {
        self.entry_last_modified.insert(key, seq);
    }

    fn remove_last_modified_key(&mut self, key: &LedgerKey) {
        self.entry_last_modified.remove(key);
    }

    fn ledger_entry_ext_for_snapshot(&self, key: &LedgerKey) -> LedgerEntryExt {
        let ext_present = self
            .entry_sponsorship_ext_snapshots
            .get(key)
            .copied()
            .unwrap_or_else(|| self.entry_sponsorship_ext.contains(key));
        let sponsor_snapshot = if let Some(snapshot) = self.entry_sponsorship_snapshots.get(key) {
            snapshot.clone()
        } else {
            self.entry_sponsorships.get(key).cloned()
        };

        if ext_present || sponsor_snapshot.is_some() {
            LedgerEntryExt::V1(LedgerEntryExtensionV1 {
                sponsoring_id: SponsorshipDescriptor(sponsor_snapshot),
                ext: LedgerEntryExtensionV1Ext::V0,
            })
        } else {
            LedgerEntryExt::V0
        }
    }

    pub fn begin_op_snapshot(&mut self) {
        self.op_entry_snapshots.clear();
        self.op_snapshots_active = true;
    }

    pub fn end_op_snapshot(&mut self) -> HashMap<LedgerKey, LedgerEntry> {
        self.op_snapshots_active = false;
        std::mem::take(&mut self.op_entry_snapshots)
    }

    /// Set multi-operation mode.
    ///
    /// When enabled, flush_modified_entries records STATE/UPDATED for every
    /// accessed entry even if values are identical.
    pub fn set_multi_op_mode(&mut self, enabled: bool) {
        self.multi_op_mode = enabled;
    }

    fn capture_op_snapshot_for_key(&mut self, key: &LedgerKey) {
        if !self.op_snapshots_active || self.op_entry_snapshots.contains_key(key) {
            return;
        }
        if let Some(entry) = self.get_entry(key) {
            // Debug logging for account snapshots
            if let LedgerKey::Account(k) = key {
                if let stellar_xdr::curr::LedgerEntryData::Account(acc) = &entry.data {
                    let key_bytes = account_id_to_bytes(&k.account_id);
                    tracing::debug!(
                        account_prefix = ?&key_bytes[0..4],
                        balance = acc.balance,
                        last_modified = entry.last_modified_ledger_seq,
                        "Capturing op snapshot for account"
                    );
                }
            }
            self.op_entry_snapshots.insert(key.clone(), entry);
        }
    }

    /// Compute the starting sequence number for new accounts.
    pub fn starting_sequence_number(&self) -> crate::Result<i64> {
        if self.ledger_seq > i32::MAX as u32 {
            return Err(crate::TxError::Internal(
                "overflowed starting sequence number".to_string(),
            ));
        }
        Ok((self.ledger_seq as i64) << 32)
    }

    /// Calculate the minimum balance required for an account.
    pub fn minimum_balance_for_account(
        &self,
        account: &AccountEntry,
        protocol_version: u32,
        additional_subentries: i64,
    ) -> Result<i64> {
        let num_sub_entries = account.num_sub_entries as i64 + additional_subentries;
        if num_sub_entries < 0 {
            return Err(TxError::Internal(
                "negative subentry count while computing minimum balance".to_string(),
            ));
        }
        let (num_sponsoring, num_sponsored) = sponsorship_counts(account);
        self.minimum_balance_with_counts(
            protocol_version,
            num_sub_entries,
            num_sponsoring,
            num_sponsored,
        )
    }

    /// Calculate the minimum balance for an account with sponsorship deltas.
    pub fn minimum_balance_for_account_with_deltas(
        &self,
        account: &AccountEntry,
        protocol_version: u32,
        additional_subentries: i64,
        delta_sponsoring: i64,
        delta_sponsored: i64,
    ) -> Result<i64> {
        let num_sub_entries = account.num_sub_entries as i64 + additional_subentries;
        if num_sub_entries < 0 {
            return Err(TxError::Internal(
                "negative subentry count while computing minimum balance".to_string(),
            ));
        }
        let (num_sponsoring, num_sponsored) = sponsorship_counts(account);
        let num_sponsoring = num_sponsoring + delta_sponsoring;
        let num_sponsored = num_sponsored + delta_sponsored;
        if num_sponsoring < 0 || num_sponsored < 0 {
            return Err(TxError::Internal(
                "negative sponsorship count while computing minimum balance".to_string(),
            ));
        }
        self.minimum_balance_with_counts(
            protocol_version,
            num_sub_entries,
            num_sponsoring,
            num_sponsored,
        )
    }

    /// Calculate the minimum balance for a hypothetical account state.
    pub fn minimum_balance_with_counts(
        &self,
        _protocol_version: u32,
        num_sub_entries: i64,
        num_sponsoring: i64,
        num_sponsored: i64,
    ) -> Result<i64> {
        let effective_entries = 2 + num_sub_entries + num_sponsoring - num_sponsored;

        if effective_entries < 0 {
            return Err(TxError::Internal(
                "unexpected account state while computing minimum balance".to_string(),
            ));
        }

        Ok(effective_entries * self.base_reserve)
    }

    /// Get the base reserve.
    pub fn base_reserve(&self) -> i64 {
        self.base_reserve
    }

    /// Get the current ID pool.
    pub fn id_pool(&self) -> u64 {
        self.id_pool
    }

    /// Set the current ID pool.
    pub fn set_id_pool(&mut self, id_pool: u64) {
        self.id_pool = id_pool;
    }

    /// Generate the next ID from the pool.
    ///
    /// The first call within a transaction snapshots the id_pool so it can be
    /// restored on rollback. This ensures that failed transactions don't consume
    /// offer IDs.
    pub fn next_id(&mut self) -> i64 {
        // Snapshot id_pool before first modification in this transaction
        if self.id_pool_snapshot.is_none() {
            self.id_pool_snapshot = Some(self.id_pool);
        }
        self.id_pool = self.id_pool.checked_add(1).expect("id_pool overflow");
        i64::try_from(self.id_pool).expect("id_pool exceeds i64::MAX")
    }

    /// Get the current ledger sequence.
    pub fn ledger_seq(&self) -> u32 {
        self.ledger_seq
    }

    /// Set the current ledger sequence.
    pub fn set_ledger_seq(&mut self, ledger_seq: u32) {
        self.ledger_seq = ledger_seq;
    }

    /// Set the entry loader callback for lazy loading from the bucket list.
    ///
    /// When set, `ensure_account_loaded` and `ensure_trustline_loaded` can
    /// fetch entries on demand during offer crossing instead of requiring
    /// all dependencies to be preloaded upfront.
    pub fn set_entry_loader(&mut self, loader: Arc<EntryLoaderFn>) {
        self.entry_loader = Some(loader);
    }

    /// Set a batch entry loader for loading multiple entries in one bucket list pass.
    pub fn set_batch_entry_loader(&mut self, loader: Arc<BatchEntryLoaderFn>) {
        self.batch_entry_loader = Some(loader);
    }

    /// Batch-load all entries needed to cross an offer (seller account + trustlines).
    ///
    /// This is significantly faster than separate `ensure_account_loaded` +
    /// `ensure_trustline_loaded` calls because it performs a single pass through
    /// the bucket list for all needed entries instead of 2-3 separate passes.
    pub fn ensure_offer_entries_loaded(
        &mut self,
        seller: &AccountId,
        selling: &Asset,
        buying: &Asset,
    ) -> Result<()> {
        let seller_bytes = account_id_to_bytes(seller);
        let mut needed_keys = Vec::new();

        if !self.accounts.contains_key(&seller_bytes) {
            needed_keys.push(LedgerKey::Account(LedgerKeyAccount {
                account_id: seller.clone(),
            }));
        }
        if !matches!(selling, Asset::Native) {
            let asset_key = AssetKey::from_asset(selling);
            if !self.trustlines.contains_key(&(seller_bytes, asset_key)) {
                let tl_asset = asset_to_trustline_asset(selling);
                needed_keys.push(LedgerKey::Trustline(LedgerKeyTrustLine {
                    account_id: seller.clone(),
                    asset: tl_asset,
                }));
            }
        }
        if !matches!(buying, Asset::Native) {
            let asset_key = AssetKey::from_asset(buying);
            if !self.trustlines.contains_key(&(seller_bytes, asset_key)) {
                let tl_asset = asset_to_trustline_asset(buying);
                needed_keys.push(LedgerKey::Trustline(LedgerKeyTrustLine {
                    account_id: seller.clone(),
                    asset: tl_asset,
                }));
            }
        }

        if needed_keys.is_empty() {
            return Ok(());
        }

        // Use batch loader for single-pass bucket list traversal
        if let Some(loader) = self.batch_entry_loader.take() {
            let entries = loader(&needed_keys);
            self.batch_entry_loader = Some(loader);
            for entry in entries? {
                self.load_entry(entry);
            }
        } else if let Some(loader) = self.entry_loader.take() {
            // Fallback to individual lookups
            for key in &needed_keys {
                if let Some(entry) = loader(key)? {
                    self.load_entry(entry);
                }
            }
            self.entry_loader = Some(loader);
        }

        Ok(())
    }

    /// Ensure an account is loaded in state, fetching lazily if needed.
    ///
    /// Returns `Ok(true)` if the account is available (already loaded or
    /// successfully fetched), `Ok(false)` if it doesn't exist.
    pub fn ensure_account_loaded(&mut self, account_id: &AccountId) -> Result<bool> {
        let key_bytes = account_id_to_bytes(account_id);
        if self.accounts.contains_key(&key_bytes) {
            return Ok(true);
        }
        if let Some(loader) = self.entry_loader.take() {
            let ledger_key = LedgerKey::Account(LedgerKeyAccount {
                account_id: account_id.clone(),
            });
            let result = loader(&ledger_key);
            self.entry_loader = Some(loader); // restore before handling result
            if let Some(entry) = result? {
                self.load_entry(entry);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Ensure a trustline is loaded in state, fetching lazily if needed.
    ///
    /// Returns `Ok(true)` if the trustline is available (already loaded or
    /// successfully fetched), `Ok(false)` if it doesn't exist.
    pub fn ensure_trustline_loaded(
        &mut self,
        account_id: &AccountId,
        asset: &Asset,
    ) -> Result<bool> {
        let account_key = account_id_to_bytes(account_id);
        let asset_key = AssetKey::from_asset(asset);
        if self.trustlines.contains_key(&(account_key, asset_key)) {
            return Ok(true);
        }
        if let Some(loader) = self.entry_loader.take() {
            let tl_asset = asset_to_trustline_asset(asset);
            let ledger_key = LedgerKey::Trustline(LedgerKeyTrustLine {
                account_id: account_id.clone(),
                asset: tl_asset,
            });
            let result = loader(&ledger_key);
            self.entry_loader = Some(loader); // restore before handling result
            if let Some(entry) = result? {
                self.load_entry(entry);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Temporarily remove large Soroban collections to make clone() cheap.
    ///
    /// Used by path payment operations that need to clone state for speculative
    /// orderbook exchange. The Soroban collections (contract data, code, TTL entries)
    /// are never accessed during orderbook exchange, so removing them before cloning
    /// and restoring after avoids copying millions of entries.
    pub fn take_soroban_state(&mut self) -> SorobanState {
        SorobanState {
            contract_data: std::mem::take(&mut self.contract_data),
            contract_code: std::mem::take(&mut self.contract_code),
            ttl_entries: std::mem::take(&mut self.ttl_entries),
            ttl_bucket_list_snapshot: std::mem::take(&mut self.ttl_bucket_list_snapshot),
        }
    }

    /// Restore previously extracted Soroban collections.
    pub fn restore_soroban_state(&mut self, soroban: SorobanState) {
        self.contract_data = soroban.contract_data;
        self.contract_code = soroban.contract_code;
        self.ttl_entries = soroban.ttl_entries;
        self.ttl_bucket_list_snapshot = soroban.ttl_bucket_list_snapshot;
    }

    /// Snapshot the delta before starting a transaction.
    ///
    /// This preserves committed changes from previous transactions so they're not lost
    /// if the current transaction fails and rolls back. Call this at the start of each
    /// transaction before any modifications.
    pub fn snapshot_delta(&mut self) {
        self.delta_snapshot = Some(self.delta.clone());
    }

    /// Clear all cached ledger entries.
    ///
    /// This clears all entry storage (accounts, trustlines, offers, etc.) while
    /// preserving ledger-level state like id_pool. Use this at the start of a new
    /// ledger in verification mode to ensure entries are reloaded from the
    /// authoritative bucket list state.
    pub fn clear_cached_entries(&mut self) {
        self.clear_cached_entries_inner(false);
    }

    /// Clear cached entries but preserve offers and the offer index.
    ///
    /// Offers are expensive to reload (~911K entries on mainnet, ~2.7s). Since
    /// the in-memory offer store is maintained incrementally, the executor's
    /// offer cache at the end of a ledger already reflects the correct post-ledger
    /// state. This method clears everything else so non-offer entries are reloaded
    /// from the authoritative bucket list.
    pub fn clear_cached_entries_preserving_offers(&mut self) {
        self.clear_cached_entries_inner(true);
    }

    fn clear_cached_entries_inner(&mut self, preserve_offers: bool) {
        self.accounts.clear();
        self.trustlines.clear();
        if !preserve_offers {
            self.offers.clear();
            self.offer_index.clear();
            self.account_asset_offers.clear();
        }
        self.data_entries.clear();
        self.contract_data.clear();
        self.contract_code.clear();
        self.ttl_entries.clear();
        self.ttl_bucket_list_snapshot.clear();
        self.claimable_balances.clear();
        self.liquidity_pools.clear();
        if preserve_offers {
            // Retain sponsorship/last_modified entries for Offer keys only
            self.entry_sponsorships
                .retain(|k, _| matches!(k, LedgerKey::Offer(_)));
            self.entry_sponsorship_ext
                .retain(|k| matches!(k, LedgerKey::Offer(_)));
            self.entry_last_modified
                .retain(|k, _| matches!(k, LedgerKey::Offer(_)));
        } else {
            self.entry_sponsorships.clear();
            self.entry_sponsorship_ext.clear();
            self.entry_last_modified.clear();
        }
        self.entry_loader = None;

        // Clear all transaction-level state
        self.op_entry_snapshots.clear();
        self.op_snapshots_active = false;
        self.multi_op_mode = false;
        self.sponsorship_stack.clear();
        self.delta = LedgerDelta::new(self.ledger_seq);
        self.delta_snapshot = None;

        self.modified_accounts.clear();
        self.modified_trustlines.clear();
        self.modified_offers.clear();
        self.modified_data.clear();
        self.modified_contract_data.clear();
        self.modified_contract_code.clear();
        self.modified_ttl.clear();
        self.modified_claimable_balances.clear();
        self.modified_liquidity_pools.clear();

        self.account_snapshots.clear();
        self.trustline_snapshots.clear();
        self.offer_snapshots.clear();
        self.data_snapshots.clear();
        self.contract_data_snapshots.clear();
        self.contract_code_snapshots.clear();
        self.ttl_snapshots.clear();
        self.claimable_balance_snapshots.clear();
        self.liquidity_pool_snapshots.clear();
        self.entry_sponsorship_snapshots.clear();
        self.entry_sponsorship_ext_snapshots.clear();
        self.entry_last_modified_snapshots.clear();

        self.created_accounts.clear();
        self.created_trustlines.clear();
        if !preserve_offers {
            self.created_offers.clear();
        }
        self.created_data.clear();
        self.created_contract_data.clear();
        self.created_contract_code.clear();
        self.created_ttl.clear();
        self.created_claimable_balances.clear();
        self.created_liquidity_pools.clear();
    }

    /// Clear active sponsorship state (start of a new transaction).
    pub fn clear_sponsorship_stack(&mut self) {
        self.sponsorship_stack.clear();
    }

    /// Check if there is any pending sponsorship.
    pub fn has_pending_sponsorship(&self) -> bool {
        !self.sponsorship_stack.is_empty()
    }

    /// Return the active sponsor for a sponsored account, if any.
    pub fn active_sponsor_for(&self, sponsored: &AccountId) -> Option<AccountId> {
        self.sponsorship_stack
            .iter()
            .rev()
            .find(|ctx| ctx.sponsored == *sponsored)
            .map(|ctx| ctx.sponsoring.clone())
    }

    /// Return true if an account is currently being sponsored.
    pub fn is_sponsored(&self, account_id: &AccountId) -> bool {
        self.sponsorship_stack
            .iter()
            .any(|ctx| ctx.sponsored == *account_id)
    }

    /// Return true if an account is currently sponsoring someone else.
    pub fn is_sponsoring(&self, account_id: &AccountId) -> bool {
        self.sponsorship_stack
            .iter()
            .any(|ctx| ctx.sponsoring == *account_id)
    }

    /// Push a new sponsorship context onto the stack.
    pub fn push_sponsorship(&mut self, sponsoring: AccountId, sponsored: AccountId) {
        self.sponsorship_stack.push(SponsorshipContext {
            sponsoring,
            sponsored,
        });
    }

    /// Pop the latest sponsorship context.
    pub fn pop_sponsorship(&mut self) -> Option<SponsorshipContext> {
        self.sponsorship_stack.pop()
    }

    /// Remove the most recent sponsorship for a sponsored account.
    pub fn remove_sponsorship_for(&mut self, sponsored: &AccountId) -> Option<SponsorshipContext> {
        if let Some(pos) = self
            .sponsorship_stack
            .iter()
            .rposition(|ctx| &ctx.sponsored == sponsored)
        {
            return Some(self.sponsorship_stack.remove(pos));
        }
        None
    }

    /// Return the sponsor for a ledger entry, if any.
    pub fn entry_sponsor(&self, key: &LedgerKey) -> Option<&AccountId> {
        self.entry_sponsorships.get(key)
    }

    fn snapshot_entry_sponsorship_ext(&mut self, key: &LedgerKey) {
        if !self.entry_sponsorship_ext_snapshots.contains_key(key) {
            self.entry_sponsorship_ext_snapshots
                .insert(key.clone(), self.entry_sponsorship_ext.contains(key));
        }
    }

    fn snapshot_entry_sponsorship_metadata(&mut self, key: &LedgerKey) {
        if !self.entry_sponsorship_snapshots.contains_key(key) {
            self.entry_sponsorship_snapshots
                .insert(key.clone(), self.entry_sponsorships.get(key).cloned());
        }
        self.snapshot_entry_sponsorship_ext(key);
    }

    fn clear_entry_sponsorship_metadata(&mut self, key: &LedgerKey) {
        self.snapshot_entry_sponsorship_metadata(key);
        self.entry_sponsorships.remove(key);
        self.entry_sponsorship_ext.remove(key);
    }

    /// Set the sponsor for a ledger entry.
    pub fn set_entry_sponsor(&mut self, key: LedgerKey, sponsor: AccountId) {
        self.snapshot_entry_sponsorship_metadata(&key);
        self.capture_op_snapshot_for_key(&key);
        self.entry_sponsorships.insert(key.clone(), sponsor);
        self.entry_sponsorship_ext.insert(key);
    }

    /// Remove and return the sponsor for a ledger entry, if any.
    pub fn remove_entry_sponsor(&mut self, key: &LedgerKey) -> Option<AccountId> {
        self.snapshot_entry_sponsorship_metadata(key);
        self.capture_op_snapshot_for_key(key);
        self.entry_sponsorship_ext.insert(key.clone());
        self.entry_sponsorships.remove(key)
    }

    /// Apply sponsorship to a newly created ledger entry owned by `sponsored`.
    pub fn apply_entry_sponsorship(
        &mut self,
        key: LedgerKey,
        sponsored: &AccountId,
        multiplier: i64,
    ) -> Result<Option<AccountId>> {
        let Some(sponsor) = self.active_sponsor_for(sponsored) else {
            return Ok(None);
        };
        self.apply_entry_sponsorship_with_sponsor(key, &sponsor, Some(sponsored), multiplier)?;
        Ok(Some(sponsor))
    }

    /// Apply sponsorship for a ledger entry with a known sponsor.
    pub fn apply_entry_sponsorship_with_sponsor(
        &mut self,
        key: LedgerKey,
        sponsor: &AccountId,
        sponsored: Option<&AccountId>,
        multiplier: i64,
    ) -> Result<()> {
        if multiplier < 0 {
            return Err(TxError::Internal(
                "negative sponsorship multiplier".to_string(),
            ));
        }
        self.set_entry_sponsor(key, sponsor.clone());
        self.update_num_sponsoring(sponsor, multiplier)?;
        if let Some(sponsored) = sponsored {
            self.update_num_sponsored(sponsored, multiplier)?;
        }
        Ok(())
    }

    /// Apply sponsorship to a newly created account entry (account not yet in state).
    pub fn apply_account_entry_sponsorship(
        &mut self,
        account: &mut AccountEntry,
        sponsor: &AccountId,
        multiplier: i64,
    ) -> Result<()> {
        if multiplier < 0 {
            return Err(TxError::Internal(
                "negative sponsorship multiplier".to_string(),
            ));
        }
        let ext = ensure_account_ext_v2(account);
        let updated = ext.num_sponsored as i64 + multiplier;
        if updated < 0 || updated > u32::MAX as i64 {
            return Err(TxError::Internal("num_sponsored out of range".to_string()));
        }
        ext.num_sponsored = updated as u32;
        self.update_num_sponsoring(sponsor, multiplier)?;
        Ok(())
    }

    /// Remove sponsorship for a ledger entry and update account counts.
    pub fn remove_entry_sponsorship_and_update_counts(
        &mut self,
        key: &LedgerKey,
        sponsored: &AccountId,
        multiplier: i64,
    ) -> Result<Option<AccountId>> {
        let Some(sponsor) = self.remove_entry_sponsor(key) else {
            return Ok(None);
        };
        if multiplier < 0 {
            return Err(TxError::Internal(
                "negative sponsorship multiplier".to_string(),
            ));
        }
        self.update_num_sponsoring(&sponsor, -multiplier)?;
        self.update_num_sponsored(sponsored, -multiplier)?;
        Ok(Some(sponsor))
    }

    /// Remove sponsorship for a ledger entry with optional sponsored account.
    pub fn remove_entry_sponsorship_with_sponsor_counts(
        &mut self,
        key: &LedgerKey,
        sponsored: Option<&AccountId>,
        multiplier: i64,
    ) -> Result<Option<AccountId>> {
        let Some(sponsor) = self.remove_entry_sponsor(key) else {
            return Ok(None);
        };
        if multiplier < 0 {
            return Err(TxError::Internal(
                "negative sponsorship multiplier".to_string(),
            ));
        }
        self.update_num_sponsoring(&sponsor, -multiplier)?;
        if let Some(sponsored) = sponsored {
            self.update_num_sponsored(sponsored, -multiplier)?;
        }
        Ok(Some(sponsor))
    }

    /// Update num_sponsoring for an account.
    pub fn update_num_sponsoring(&mut self, account_id: &AccountId, delta: i64) -> Result<()> {
        let account = self
            .get_account_mut(account_id)
            .ok_or(TxError::SourceAccountNotFound)?;
        let ext = ensure_account_ext_v2(account);
        let updated = ext.num_sponsoring as i64 + delta;
        if updated < 0 || updated > u32::MAX as i64 {
            return Err(TxError::Internal("num_sponsoring out of range".to_string()));
        }
        ext.num_sponsoring = updated as u32;
        Ok(())
    }

    /// Update num_sponsored for an account.
    pub fn update_num_sponsored(&mut self, account_id: &AccountId, delta: i64) -> Result<()> {
        let account = self
            .get_account_mut(account_id)
            .ok_or(TxError::SourceAccountNotFound)?;
        let ext = ensure_account_ext_v2(account);
        let updated = ext.num_sponsored as i64 + delta;
        if updated < 0 || updated > u32::MAX as i64 {
            return Err(TxError::Internal("num_sponsored out of range".to_string()));
        }
        ext.num_sponsored = updated as u32;
        Ok(())
    }

    /// Get sponsorship counts (num_sponsoring, num_sponsored) for an account.
    pub fn sponsorship_counts_for_account(&self, account_id: &AccountId) -> Option<(i64, i64)> {
        self.get_account(account_id).map(sponsorship_counts)
    }

    // ========================================================================
    // One-time (Pre-Auth TX) Signer Removal
    // ========================================================================

    /// Remove a one-time (pre-auth TX) signer from all source accounts in a transaction.
    ///
    /// Pre-auth TX signers are automatically consumed when a transaction they
    /// authorized is applied. This method removes the signer from all accounts
    /// that participated in the transaction.
    ///
    /// # Arguments
    ///
    /// * `tx_hash` - The transaction hash (used to create the signer key)
    /// * `source_accounts` - All source account IDs in the transaction
    /// * `protocol_version` - Current protocol version
    ///
    /// # Note
    ///
    /// This is a no-op for protocol version 7 (matches C++ behavior).
    pub fn remove_one_time_signers_from_all_sources(
        &mut self,
        tx_hash: &stellar_core_common::Hash256,
        source_accounts: &[AccountId],
        protocol_version: u32,
    ) {
        // Protocol 7 bypass (matches C++ behavior)
        if protocol_version == 7 {
            return;
        }

        // Create the pre-auth TX signer key from the transaction hash
        let signer_key =
            stellar_xdr::curr::SignerKey::PreAuthTx(stellar_xdr::curr::Uint256(tx_hash.0));

        // Remove from each source account
        for account_id in source_accounts {
            self.remove_account_signer(account_id, &signer_key);
        }
    }

    /// Remove a specific signer from an account.
    ///
    /// This handles the removal of any signer type and properly updates:
    /// - The signers vector
    /// - The num_sub_entries count
    /// - The sponsorship tracking (if the signer was sponsored)
    ///
    /// # Returns
    ///
    /// `true` if the signer was found and removed, `false` otherwise.
    pub fn remove_account_signer(
        &mut self,
        account_id: &AccountId,
        signer_key: &stellar_xdr::curr::SignerKey,
    ) -> bool {
        // Get mutable access to the account
        let Some(account) = self.get_account_mut(account_id) else {
            return false; // Account may have been removed (e.g., by merge)
        };

        // Find the signer index
        let signer_idx = account.signers.iter().position(|s| &s.key == signer_key);

        let Some(idx) = signer_idx else {
            return false; // Signer not found
        };

        // Remove the signer from the vec
        let mut new_signers: Vec<stellar_xdr::curr::Signer> =
            account.signers.iter().cloned().collect();
        new_signers.remove(idx);
        account.signers = new_signers.try_into().unwrap_or_default();

        // Decrement num_sub_entries
        if account.num_sub_entries > 0 {
            account.num_sub_entries -= 1;
        }

        // Handle sponsorship cleanup if applicable
        // The signer sponsorship is stored in the account's extension
        self.remove_signer_sponsorship(account_id, idx);

        true
    }

    /// Remove sponsorship tracking for a signer at the given index.
    ///
    /// When a signer is sponsored, the sponsoring account's ID is stored in
    /// the account's `signer_sponsoring_i_ds` vector (in AccountEntryExtensionV2).
    /// Removing a signer requires cleaning up this sponsorship relationship
    /// and updating the sponsor's `num_sponsoring` count.
    fn remove_signer_sponsorship(&mut self, account_id: &AccountId, signer_index: usize) {
        // Get the account to check for sponsorship
        let Some(account) = self.get_account(account_id) else {
            return;
        };

        // Check if the account has extension v2 with signer sponsorships
        let sponsor_id = match &account.ext {
            AccountEntryExt::V1(v1) => match &v1.ext {
                AccountEntryExtensionV1Ext::V2(v2) => {
                    // Check if this signer index has a sponsor
                    if signer_index < v2.signer_sponsoring_i_ds.len() {
                        v2.signer_sponsoring_i_ds[signer_index].0.clone()
                    } else {
                        None
                    }
                }
                AccountEntryExtensionV1Ext::V0 => None,
            },
            AccountEntryExt::V0 => None,
        };

        // If there was a sponsor, update the counts
        if let Some(sponsor) = sponsor_id {
            // Decrement sponsor's num_sponsoring
            if let Err(e) = self.update_num_sponsoring(&sponsor, -1) {
                // Log error but don't fail - this is cleanup
                tracing::warn!(
                    "Failed to update num_sponsoring during signer removal: {}",
                    e
                );
            }

            // Decrement sponsored account's num_sponsored
            if let Err(e) = self.update_num_sponsored(account_id, -1) {
                tracing::warn!(
                    "Failed to update num_sponsored during signer removal: {}",
                    e
                );
            }

            // Remove the sponsorship entry from signer_sponsoring_i_ds
            if let Some(account) = self.get_account_mut(account_id) {
                if let AccountEntryExt::V1(v1) = &mut account.ext {
                    if let AccountEntryExtensionV1Ext::V2(v2) = &mut v1.ext {
                        if signer_index < v2.signer_sponsoring_i_ds.len() {
                            let mut ids: Vec<_> =
                                v2.signer_sponsoring_i_ds.iter().cloned().collect();
                            ids.remove(signer_index);
                            v2.signer_sponsoring_i_ds = ids.try_into().unwrap_or_default();
                        }
                    }
                }
            }
        }
    }

    fn ledger_entry_ext_for(&self, key: &LedgerKey) -> LedgerEntryExt {
        let sponsor = self.entry_sponsorships.get(key).cloned();
        if self.entry_sponsorship_ext.contains(key) || sponsor.is_some() {
            LedgerEntryExt::V1(LedgerEntryExtensionV1 {
                sponsoring_id: SponsorshipDescriptor(sponsor),
                ext: LedgerEntryExtensionV1Ext::V0,
            })
        } else {
            LedgerEntryExt::V0
        }
    }

    /// Load initial state from a ledger reader.
    pub fn load_from_reader<R: LedgerReader>(&mut self, reader: &R, keys: &[LedgerKey]) {
        for key in keys {
            if let Some(entry) = reader.get_entry(key) {
                self.load_entry(entry);
            }
        }
    }

    /// Load a single entry into the state manager.
    pub fn load_entry(&mut self, entry: LedgerEntry) {
        let sponsor = sponsorship_from_entry_ext(&entry);
        let has_sponsorship_ext = matches!(entry.ext, LedgerEntryExt::V1(_));
        let last_modified = entry.last_modified_ledger_seq;
        match entry.data {
            LedgerEntryData::Account(account) => {
                let key = account_id_to_bytes(&account.account_id);
                let ledger_key = LedgerKey::Account(LedgerKeyAccount {
                    account_id: account.account_id.clone(),
                });
                self.accounts.insert(key, account);
                self.entry_last_modified
                    .insert(ledger_key.clone(), last_modified);
                if has_sponsorship_ext {
                    self.entry_sponsorship_ext.insert(ledger_key.clone());
                }
                if let Some(sponsor) = sponsor {
                    self.entry_sponsorships.insert(ledger_key, sponsor);
                }
            }
            LedgerEntryData::Trustline(trustline) => {
                let account_key = account_id_to_bytes(&trustline.account_id);
                let asset_key = AssetKey::from_trustline_asset(&trustline.asset);
                let ledger_key = LedgerKey::Trustline(LedgerKeyTrustLine {
                    account_id: trustline.account_id.clone(),
                    asset: trustline.asset.clone(),
                });
                self.trustlines.insert((account_key, asset_key), trustline);
                self.entry_last_modified
                    .insert(ledger_key.clone(), last_modified);
                if has_sponsorship_ext {
                    self.entry_sponsorship_ext.insert(ledger_key.clone());
                }
                if let Some(sponsor) = sponsor {
                    self.entry_sponsorships.insert(ledger_key, sponsor);
                }
            }
            LedgerEntryData::Offer(offer) => {
                let seller_key = account_id_to_bytes(&offer.seller_id);
                let ledger_key = LedgerKey::Offer(LedgerKeyOffer {
                    seller_id: offer.seller_id.clone(),
                    offer_id: offer.offer_id,
                });
                // Add to offer index for efficient best-offer lookups
                self.offer_index.add_offer(&offer);
                self.aa_index_insert(&offer);
                self.offers.insert((seller_key, offer.offer_id), offer);
                self.entry_last_modified
                    .insert(ledger_key.clone(), last_modified);
                if has_sponsorship_ext {
                    self.entry_sponsorship_ext.insert(ledger_key.clone());
                }
                if let Some(sponsor) = sponsor {
                    self.entry_sponsorships.insert(ledger_key, sponsor);
                }
            }
            LedgerEntryData::Data(data) => {
                let account_key = account_id_to_bytes(&data.account_id);
                let name = data_name_to_string(&data.data_name);
                let ledger_key = LedgerKey::Data(LedgerKeyData {
                    account_id: data.account_id.clone(),
                    data_name: data.data_name.clone(),
                });
                self.data_entries.insert((account_key, name), data);
                self.entry_last_modified
                    .insert(ledger_key.clone(), last_modified);
                if has_sponsorship_ext {
                    self.entry_sponsorship_ext.insert(ledger_key.clone());
                }
                if let Some(sponsor) = sponsor {
                    self.entry_sponsorships.insert(ledger_key, sponsor);
                }
            }
            LedgerEntryData::ContractData(contract_data) => {
                let key = ContractDataKey::new(
                    contract_data.contract.clone(),
                    contract_data.key.clone(),
                    contract_data.durability,
                );
                let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
                    contract: contract_data.contract.clone(),
                    key: contract_data.key.clone(),
                    durability: contract_data.durability,
                });
                self.contract_data.insert(key, contract_data);
                self.entry_last_modified
                    .insert(ledger_key.clone(), last_modified);
                if has_sponsorship_ext {
                    self.entry_sponsorship_ext.insert(ledger_key.clone());
                }
                if let Some(sponsor) = sponsor {
                    self.entry_sponsorships.insert(ledger_key, sponsor);
                }
            }
            LedgerEntryData::ContractCode(contract_code) => {
                let key = contract_code.hash.0;
                let ledger_key = LedgerKey::ContractCode(LedgerKeyContractCode {
                    hash: contract_code.hash.clone(),
                });
                self.contract_code.insert(key, contract_code);
                self.entry_last_modified
                    .insert(ledger_key.clone(), last_modified);
                if has_sponsorship_ext {
                    self.entry_sponsorship_ext.insert(ledger_key.clone());
                }
                if let Some(sponsor) = sponsor {
                    self.entry_sponsorships.insert(ledger_key, sponsor);
                }
            }
            LedgerEntryData::Ttl(ttl) => {
                let key = ttl.key_hash.0;
                let ledger_key = LedgerKey::Ttl(LedgerKeyTtl {
                    key_hash: ttl.key_hash.clone(),
                });
                // Capture the bucket list TTL value for Soroban.
                // Only capture if not already present - this ensures we keep the original
                // bucket list value even if the entry is reloaded later.
                self.ttl_bucket_list_snapshot
                    .entry(key)
                    .or_insert(ttl.live_until_ledger_seq);
                self.ttl_entries.insert(key, ttl);
                self.entry_last_modified
                    .insert(ledger_key.clone(), last_modified);
                if has_sponsorship_ext {
                    self.entry_sponsorship_ext.insert(ledger_key.clone());
                }
                if let Some(sponsor) = sponsor {
                    self.entry_sponsorships.insert(ledger_key, sponsor);
                }
            }
            LedgerEntryData::ClaimableBalance(cb) => {
                let key = claimable_balance_id_to_bytes(&cb.balance_id);
                let ledger_key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
                    balance_id: cb.balance_id.clone(),
                });
                self.claimable_balances.insert(key, cb);
                self.entry_last_modified
                    .insert(ledger_key.clone(), last_modified);
                if has_sponsorship_ext {
                    self.entry_sponsorship_ext.insert(ledger_key.clone());
                }
                if let Some(sponsor) = sponsor {
                    self.entry_sponsorships.insert(ledger_key, sponsor);
                }
            }
            LedgerEntryData::LiquidityPool(lp) => {
                let key = pool_id_to_bytes(&lp.liquidity_pool_id);
                let ledger_key = LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
                    liquidity_pool_id: lp.liquidity_pool_id.clone(),
                });
                self.liquidity_pools.insert(key, lp);
                self.entry_last_modified
                    .insert(ledger_key.clone(), last_modified);
                if has_sponsorship_ext {
                    self.entry_sponsorship_ext.insert(ledger_key.clone());
                }
                if let Some(sponsor) = sponsor {
                    self.entry_sponsorships.insert(ledger_key, sponsor);
                }
            }
            _ => {}
        }
    }

    /// Load a single entry into state WITHOUT setting up change tracking.
    /// This matches C++ stellar-core's `loadWithoutRecord()` behavior.
    /// Use this for entries that only need existence checks, not modification tracking.
    ///
    /// IMPORTANT: Entries loaded this way will NOT appear in transaction meta changes
    /// unless they are subsequently accessed via `get_*_mut()` or `record_*_access()`.
    pub fn load_entry_without_snapshot(&mut self, entry: LedgerEntry) {
        let sponsor = sponsorship_from_entry_ext(&entry);
        let has_sponsorship_ext = matches!(entry.ext, LedgerEntryExt::V1(_));
        let last_modified = entry.last_modified_ledger_seq;
        match entry.data {
            LedgerEntryData::Account(account) => {
                let key = account_id_to_bytes(&account.account_id);
                let ledger_key = LedgerKey::Account(LedgerKeyAccount {
                    account_id: account.account_id.clone(),
                });
                // Insert account but do NOT save snapshot or mark as modified
                self.accounts.insert(key, account);
                self.entry_last_modified
                    .insert(ledger_key.clone(), last_modified);
                if has_sponsorship_ext {
                    self.entry_sponsorship_ext.insert(ledger_key.clone());
                }
                if let Some(sponsor) = sponsor {
                    self.entry_sponsorships.insert(ledger_key, sponsor);
                }
            }
            // For other entry types, delegate to regular load_entry since they don't
            // have the same snapshotting concern
            other => {
                let entry = LedgerEntry {
                    last_modified_ledger_seq: last_modified,
                    data: other,
                    ext: if has_sponsorship_ext {
                        LedgerEntryExt::V1(stellar_xdr::curr::LedgerEntryExtensionV1 {
                            sponsoring_id: sponsor
                                .map(|s| SponsorshipDescriptor(Some(s)))
                                .unwrap_or(SponsorshipDescriptor(None)),
                            ext: stellar_xdr::curr::LedgerEntryExtensionV1Ext::V0,
                        })
                    } else {
                        LedgerEntryExt::V0
                    },
                };
                self.load_entry(entry);
            }
        }
    }

    // ==================== Account Operations ====================

    /// Load an account by ID and return a reference to it.
    ///
    /// This method is useful when you need to load an account from external storage
    /// and then access it.
    pub fn load_account(&mut self, account_id: &AccountId) -> Option<&AccountEntry> {
        let key = account_id_to_bytes(account_id);
        self.accounts.get(&key)
    }

    /// Get an account by ID (read-only).
    pub fn get_account(&self, account_id: &AccountId) -> Option<&AccountEntry> {
        let key = account_id_to_bytes(account_id);
        self.accounts.get(&key)
    }

    /// Get a mutable reference to an account by ID.
    ///
    /// This automatically tracks the modification for the delta.
    pub fn get_account_mut(&mut self, account_id: &AccountId) -> Option<&mut AccountEntry> {
        let key = account_id_to_bytes(account_id);
        if self.accounts.contains_key(&key) {
            // Save snapshot if not already saved or if it's None (for newly created entries).
            // For newly created entries, we update the snapshot to the current value so
            // subsequent operations can track changes with STATE/UPDATED pairs.
            // Rollback correctness is ensured by the created_accounts set.
            if !self
                .account_snapshots
                .get(&key)
                .is_some_and(|s| s.is_some())
            {
                let snapshot = self.accounts.get(&key).cloned();
                self.account_snapshots.insert(key, snapshot);
            }
            let ledger_key = LedgerKey::Account(LedgerKeyAccount {
                account_id: account_id.clone(),
            });
            self.capture_op_snapshot_for_key(&ledger_key);
            self.snapshot_last_modified_key(&ledger_key);
            // Track modification
            if !self.modified_accounts.contains(&key) {
                self.modified_accounts.push(key);
            }
            self.accounts.get_mut(&key)
        } else {
            None
        }
    }

    /// Record that an account was accessed during operation execution.
    ///
    /// This captures an op snapshot for the account so it appears in the delta
    /// even if only read (not modified). This matches C++ stellar-core behavior
    /// where `load()` records entries vs `loadWithoutRecord()` which doesn't.
    ///
    /// Use this when an operation loads an account that must appear in the
    /// transaction meta (e.g., issuer account in AllowTrust/SetTrustLineFlags).
    pub fn record_account_access(&mut self, account_id: &AccountId) {
        let key = account_id_to_bytes(account_id);
        // Only record if account exists in state
        if !self.accounts.contains_key(&key) {
            return;
        }
        // Save snapshot if not already saved (same as get_account_mut)
        if !self
            .account_snapshots
            .get(&key)
            .is_some_and(|s| s.is_some())
        {
            let snapshot = self.accounts.get(&key).cloned();
            self.account_snapshots.insert(key, snapshot);
        }
        let ledger_key = LedgerKey::Account(LedgerKeyAccount {
            account_id: account_id.clone(),
        });
        self.capture_op_snapshot_for_key(&ledger_key);
        self.snapshot_last_modified_key(&ledger_key);
        // Track as "modified" so it gets flushed to delta
        if !self.modified_accounts.contains(&key) {
            self.modified_accounts.push(key);
        }
    }

    /// Create a new account entry.
    pub fn create_account(&mut self, entry: AccountEntry) {
        let key = account_id_to_bytes(&entry.account_id);
        let ledger_key = LedgerKey::Account(LedgerKeyAccount {
            account_id: entry.account_id.clone(),
        });

        // Save snapshot (None because it didn't exist)
        self.account_snapshots.entry(key).or_insert(None);
        self.snapshot_last_modified_key(&ledger_key);
        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);

        // Record in delta
        let ledger_entry = self.account_to_ledger_entry(&entry);
        self.delta.record_create(ledger_entry);

        // Insert into state
        self.accounts.insert(key, entry);

        // Track that this entry was created in this transaction (for rollback)
        self.created_accounts.insert(key);

        // Track modification
        if !self.modified_accounts.contains(&key) {
            self.modified_accounts.push(key);
        }
    }

    /// Update an existing account entry.
    pub fn update_account(&mut self, entry: AccountEntry) {
        let key = account_id_to_bytes(&entry.account_id);
        let ledger_key = LedgerKey::Account(LedgerKeyAccount {
            account_id: entry.account_id.clone(),
        });

        // Save snapshot if not already saved (preserves original state from start of tx)
        if !self.account_snapshots.contains_key(&key) {
            let snapshot = self.accounts.get(&key).cloned();
            self.account_snapshots.insert(key, snapshot);
        }
        self.capture_op_snapshot_for_key(&ledger_key);
        self.snapshot_last_modified_key(&ledger_key);

        // Get pre-state (current value BEFORE this update)
        let pre_state = self
            .accounts
            .get(&key)
            .map(|acc| self.account_to_ledger_entry(acc));

        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);

        // Record in delta with pre-state
        let post_state = self.account_to_ledger_entry(&entry);
        if let Some(pre) = pre_state {
            self.delta.record_update(pre, post_state);
        }

        // Update state
        self.accounts.insert(key, entry.clone());

        // Update snapshot to current value so flush_modified_entries doesn't record a duplicate.
        // The update was already recorded above, so the snapshot should reflect the new state.
        self.account_snapshots.insert(key, Some(entry));
    }

    /// Set an account entry directly without delta tracking.
    ///
    /// This is used during verification to sync state with CDP without
    /// affecting the delta computation for subsequent transactions.
    pub fn set_account_no_tracking(&mut self, entry: AccountEntry) {
        let key = account_id_to_bytes(&entry.account_id);
        self.accounts.insert(key, entry);
    }

    /// Add or update an account entry (convenience alias for set_account_no_tracking).
    ///
    /// Use this for setting up test state or initializing accounts.
    pub fn put_account(&mut self, entry: AccountEntry) {
        self.set_account_no_tracking(entry);
    }

    /// Apply a ledger entry directly without delta tracking.
    ///
    /// This is used during verification to sync state with CDP without
    /// affecting the delta computation for subsequent transactions.
    pub fn apply_entry_no_tracking(&mut self, entry: &stellar_xdr::curr::LedgerEntry) {
        use stellar_xdr::curr::LedgerEntryData;
        match &entry.data {
            LedgerEntryData::Account(acc) => {
                let key = account_id_to_bytes(&acc.account_id);
                self.accounts.insert(key, acc.clone());
            }
            LedgerEntryData::Trustline(tl) => {
                let account_key = account_id_to_bytes(&tl.account_id);
                let asset_key = AssetKey::from_trustline_asset(&tl.asset);
                let key = (account_key, asset_key);
                self.trustlines.insert(key, tl.clone());
            }
            LedgerEntryData::Offer(offer) => {
                let key = (account_id_to_bytes(&offer.seller_id), offer.offer_id);
                self.offers.insert(key, offer.clone());
            }
            LedgerEntryData::Data(data) => {
                let name = data_name_to_string(&data.data_name);
                let key = (account_id_to_bytes(&data.account_id), name);
                self.data_entries.insert(key, data.clone());
            }
            LedgerEntryData::ClaimableBalance(cb) => {
                let key = claimable_balance_id_to_bytes(&cb.balance_id);
                self.claimable_balances.insert(key, cb.clone());
            }
            LedgerEntryData::LiquidityPool(lp) => {
                let key = pool_id_to_bytes(&lp.liquidity_pool_id);
                self.liquidity_pools.insert(key, lp.clone());
            }
            LedgerEntryData::ContractData(cd) => {
                let key = ContractDataKey::new(cd.contract.clone(), cd.key.clone(), cd.durability);
                self.contract_data.insert(key, cd.clone());
            }
            LedgerEntryData::ContractCode(cc) => {
                let key = cc.hash.0;
                self.contract_code.insert(key, cc.clone());
            }
            LedgerEntryData::Ttl(ttl) => {
                let key = ttl.key_hash.0;
                // Capture the bucket list TTL value for Soroban.
                // Only capture if not already present - this ensures we keep the original
                // bucket list value even if the entry is reloaded later.
                self.ttl_bucket_list_snapshot
                    .entry(key)
                    .or_insert(ttl.live_until_ledger_seq);
                self.ttl_entries.insert(key, ttl.clone());
            }
            LedgerEntryData::ConfigSetting(_) => {
                // Config settings not tracked
            }
        }
    }

    /// Delete a ledger entry directly without delta tracking.
    ///
    /// This is used during verification to sync state with CDP without
    /// affecting the delta computation for subsequent transactions.
    pub fn delete_entry_no_tracking(&mut self, key: &stellar_xdr::curr::LedgerKey) {
        use stellar_xdr::curr::LedgerKey;
        match key {
            LedgerKey::Account(k) => {
                let account_key = account_id_to_bytes(&k.account_id);
                self.accounts.remove(&account_key);
            }
            LedgerKey::Trustline(k) => {
                let account_key = account_id_to_bytes(&k.account_id);
                let asset_key = AssetKey::from_trustline_asset(&k.asset);
                self.trustlines.remove(&(account_key, asset_key));
            }
            LedgerKey::Offer(k) => {
                let offer_key = (account_id_to_bytes(&k.seller_id), k.offer_id);
                self.offers.remove(&offer_key);
            }
            LedgerKey::Data(k) => {
                let name = data_name_to_string(&k.data_name);
                let data_key = (account_id_to_bytes(&k.account_id), name);
                self.data_entries.remove(&data_key);
            }
            LedgerKey::ClaimableBalance(k) => {
                let cb_key = claimable_balance_id_to_bytes(&k.balance_id);
                self.claimable_balances.remove(&cb_key);
            }
            LedgerKey::LiquidityPool(k) => {
                let pool_key = pool_id_to_bytes(&k.liquidity_pool_id);
                self.liquidity_pools.remove(&pool_key);
            }
            LedgerKey::ContractData(k) => {
                let cd_key = ContractDataKey::new(k.contract.clone(), k.key.clone(), k.durability);
                self.contract_data.remove(&cd_key);
            }
            LedgerKey::ContractCode(k) => {
                let code_key = k.hash.0;
                self.contract_code.remove(&code_key);
            }
            LedgerKey::Ttl(k) => {
                let ttl_key = k.key_hash.0;
                self.ttl_entries.remove(&ttl_key);
            }
            LedgerKey::ConfigSetting(_) => {
                // Config settings not tracked
            }
        }

        self.entry_sponsorships.remove(key);
        self.entry_sponsorship_ext.remove(key);
        self.entry_last_modified.remove(key);
    }

    /// Delete an account entry.
    pub fn delete_account(&mut self, account_id: &AccountId) {
        let key = account_id_to_bytes(account_id);
        let ledger_key = LedgerKey::Account(LedgerKeyAccount {
            account_id: account_id.clone(),
        });

        // Save snapshot if not already saved
        if !self.account_snapshots.contains_key(&key) {
            let snapshot = self.accounts.get(&key).cloned();
            self.account_snapshots.insert(key, snapshot);
        }
        self.capture_op_snapshot_for_key(&ledger_key);
        self.snapshot_last_modified_key(&ledger_key);

        // Get pre-state (current value BEFORE deletion)
        let pre_state = self
            .accounts
            .get(&key)
            .map(|acc| self.account_to_ledger_entry(acc));

        // Record in delta with pre-state
        if let Some(pre) = pre_state {
            self.delta.record_delete(ledger_key.clone(), pre);
        }

        // Remove from state
        self.clear_entry_sponsorship_metadata(&ledger_key);
        self.accounts.remove(&key);
        self.remove_last_modified_key(&ledger_key);
    }

    // ==================== Trustline Operations ====================

    /// Get a trustline by account and asset (read-only).
    pub fn get_trustline(&self, account_id: &AccountId, asset: &Asset) -> Option<&TrustLineEntry> {
        let account_key = account_id_to_bytes(account_id);
        let asset_key = AssetKey::from_asset(asset);
        self.trustlines.get(&(account_key, asset_key))
    }

    /// Get a trustline by account and trustline asset (read-only).
    pub fn get_trustline_by_trustline_asset(
        &self,
        account_id: &AccountId,
        asset: &TrustLineAsset,
    ) -> Option<&TrustLineEntry> {
        let account_key = account_id_to_bytes(account_id);
        let asset_key = AssetKey::from_trustline_asset(asset);
        self.trustlines.get(&(account_key, asset_key))
    }

    /// Get a mutable reference to a trustline by trustline asset.
    pub fn get_trustline_by_trustline_asset_mut(
        &mut self,
        account_id: &AccountId,
        asset: &TrustLineAsset,
    ) -> Option<&mut TrustLineEntry> {
        let account_key = account_id_to_bytes(account_id);
        let asset_key = AssetKey::from_trustline_asset(asset);
        let key = (account_key, asset_key.clone());

        if self.trustlines.contains_key(&key) {
            // Save snapshot if not already saved or if it's None (for newly created entries).
            // For newly created entries, we update the snapshot to the current value so
            // subsequent operations can track changes with STATE/UPDATED pairs.
            // Rollback correctness is ensured by the created_trustlines set.
            if !self
                .trustline_snapshots
                .get(&key)
                .is_some_and(|s| s.is_some())
            {
                let snapshot = self.trustlines.get(&key).cloned();
                self.trustline_snapshots.insert(key.clone(), snapshot);
            }
            let ledger_key = LedgerKey::Trustline(LedgerKeyTrustLine {
                account_id: account_id.clone(),
                asset: asset.clone(),
            });
            self.capture_op_snapshot_for_key(&ledger_key);
            self.snapshot_last_modified_key(&ledger_key);
            // Track modification
            if !self.modified_trustlines.contains(&key) {
                self.modified_trustlines.push(key.clone());
            }
            self.trustlines.get_mut(&key)
        } else {
            None
        }
    }

    /// Get a mutable reference to a trustline.
    pub fn get_trustline_mut(
        &mut self,
        account_id: &AccountId,
        asset: &Asset,
    ) -> Option<&mut TrustLineEntry> {
        let account_key = account_id_to_bytes(account_id);
        let asset_key = AssetKey::from_asset(asset);
        let key = (account_key, asset_key.clone());

        if self.trustlines.contains_key(&key) {
            // Save snapshot if not already saved or if it's None (for newly created entries).
            // For newly created entries, we update the snapshot to the current value so
            // subsequent operations can track changes with STATE/UPDATED pairs.
            // Rollback correctness is ensured by the created_trustlines set.
            if !self
                .trustline_snapshots
                .get(&key)
                .is_some_and(|s| s.is_some())
            {
                let snapshot = self.trustlines.get(&key).cloned();
                self.trustline_snapshots.insert(key.clone(), snapshot);
            }
            let ledger_key = LedgerKey::Trustline(LedgerKeyTrustLine {
                account_id: account_id.clone(),
                asset: asset_to_trustline_asset(asset),
            });
            self.capture_op_snapshot_for_key(&ledger_key);
            self.snapshot_last_modified_key(&ledger_key);
            // Track modification
            if !self.modified_trustlines.contains(&key) {
                self.modified_trustlines.push(key.clone());
            }
            self.trustlines.get_mut(&key)
        } else {
            None
        }
    }

    /// Create a new trustline entry.
    pub fn create_trustline(&mut self, entry: TrustLineEntry) {
        let account_key = account_id_to_bytes(&entry.account_id);
        let asset_key = AssetKey::from_trustline_asset(&entry.asset);
        let key = (account_key, asset_key.clone());
        let ledger_key = LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: entry.account_id.clone(),
            asset: entry.asset.clone(),
        });

        // Save snapshot (None because it didn't exist)
        if !self.trustline_snapshots.contains_key(&key) {
            self.trustline_snapshots.insert(key.clone(), None);
        }
        self.snapshot_last_modified_key(&ledger_key);
        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);

        // Record in delta
        let ledger_entry = self.trustline_to_ledger_entry(&entry);
        self.delta.record_create(ledger_entry);

        // Insert into state
        self.trustlines.insert(key.clone(), entry);

        // Track that this entry was created in this transaction (for rollback)
        self.created_trustlines.insert(key.clone());

        // Track modification
        if !self.modified_trustlines.contains(&key) {
            self.modified_trustlines.push(key);
        }
    }

    /// Update an existing trustline entry.
    pub fn update_trustline(&mut self, entry: TrustLineEntry) {
        let account_key = account_id_to_bytes(&entry.account_id);
        let asset_key = AssetKey::from_trustline_asset(&entry.asset);
        let key = (account_key, asset_key.clone());
        let ledger_key = LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: entry.account_id.clone(),
            asset: entry.asset.clone(),
        });

        // Save snapshot if not already saved
        if !self.trustline_snapshots.contains_key(&key) {
            let snapshot = self.trustlines.get(&key).cloned();
            self.trustline_snapshots.insert(key.clone(), snapshot);
        }
        self.capture_op_snapshot_for_key(&ledger_key);
        self.snapshot_last_modified_key(&ledger_key);

        // Get pre-state (current value BEFORE this update)
        let pre_state = self
            .trustlines
            .get(&key)
            .map(|tl| self.trustline_to_ledger_entry(tl));

        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);

        // Record in delta with pre-state
        let post_state = self.trustline_to_ledger_entry(&entry);
        if let Some(pre) = pre_state {
            self.delta.record_update(pre, post_state);
        }

        // Update state
        self.trustlines.insert(key.clone(), entry.clone());

        // Do NOT add to modified_trustlines since we already recorded the update.
        // This prevents flush_modified_entries from recording a duplicate.
        // Classic operations use get_trustline_mut() which tracks modifications separately.
    }

    /// Delete a trustline entry.
    pub fn delete_trustline(&mut self, account_id: &AccountId, asset: &Asset) {
        let account_key = account_id_to_bytes(account_id);
        let asset_key = AssetKey::from_asset(asset);
        let key = (account_key, asset_key.clone());
        let ledger_key = LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: account_id.clone(),
            asset: asset_to_trustline_asset(asset),
        });

        // Save snapshot if not already saved
        if !self.trustline_snapshots.contains_key(&key) {
            let snapshot = self.trustlines.get(&key).cloned();
            self.trustline_snapshots.insert(key.clone(), snapshot);
        }
        self.capture_op_snapshot_for_key(&ledger_key);
        self.snapshot_last_modified_key(&ledger_key);

        // Get pre-state (current value BEFORE deletion)
        let pre_state = self
            .trustlines
            .get(&key)
            .map(|tl| self.trustline_to_ledger_entry(tl));

        // Record in delta with pre-state
        if let Some(pre) = pre_state {
            self.delta.record_delete(ledger_key.clone(), pre);
        }

        // Remove from state
        self.clear_entry_sponsorship_metadata(&ledger_key);
        self.trustlines.remove(&key);
        self.remove_last_modified_key(&ledger_key);
    }

    /// Delete a trustline entry by trustline asset.
    pub fn delete_trustline_by_trustline_asset(
        &mut self,
        account_id: &AccountId,
        asset: &TrustLineAsset,
    ) {
        let account_key = account_id_to_bytes(account_id);
        let asset_key = AssetKey::from_trustline_asset(asset);
        let key = (account_key, asset_key.clone());
        let ledger_key = LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: account_id.clone(),
            asset: asset.clone(),
        });

        // Save snapshot if not already saved
        if !self.trustline_snapshots.contains_key(&key) {
            let snapshot = self.trustlines.get(&key).cloned();
            self.trustline_snapshots.insert(key.clone(), snapshot);
        }
        self.capture_op_snapshot_for_key(&ledger_key);
        self.snapshot_last_modified_key(&ledger_key);

        // Get pre-state (current value BEFORE deletion)
        let pre_state = self
            .trustlines
            .get(&key)
            .map(|tl| self.trustline_to_ledger_entry(tl));

        // Record in delta with pre-state
        if let Some(pre) = pre_state {
            self.delta.record_delete(ledger_key.clone(), pre);
        }

        // Remove from state
        self.clear_entry_sponsorship_metadata(&ledger_key);
        self.trustlines.remove(&key);
        self.remove_last_modified_key(&ledger_key);
    }

    // ==================== Offer Operations ====================

    /// Get an offer by seller and offer ID (read-only).
    pub fn get_offer(&self, seller_id: &AccountId, offer_id: i64) -> Option<&OfferEntry> {
        let seller_key = account_id_to_bytes(seller_id);
        self.offers.get(&(seller_key, offer_id))
    }

    /// Get a mutable reference to an offer.
    pub fn get_offer_mut(
        &mut self,
        seller_id: &AccountId,
        offer_id: i64,
    ) -> Option<&mut OfferEntry> {
        let seller_key = account_id_to_bytes(seller_id);
        let key = (seller_key, offer_id);

        if self.offers.contains_key(&key) {
            // Save snapshot if not already saved or if it's None (for newly created entries).
            // For newly created entries, we update the snapshot to the current value so
            // subsequent operations can track changes with STATE/UPDATED pairs.
            // Rollback correctness is ensured by the created_offers set.
            if !self.offer_snapshots.get(&key).is_some_and(|s| s.is_some()) {
                let snapshot = self.offers.get(&key).cloned();
                self.offer_snapshots.insert(key, snapshot);
            }
            let ledger_key = LedgerKey::Offer(LedgerKeyOffer {
                seller_id: seller_id.clone(),
                offer_id,
            });
            self.capture_op_snapshot_for_key(&ledger_key);
            self.snapshot_last_modified_key(&ledger_key);
            // Track modification
            if !self.modified_offers.contains(&key) {
                self.modified_offers.push(key);
            }
            self.offers.get_mut(&key)
        } else {
            None
        }
    }

    /// Create a new offer entry.
    pub fn create_offer(&mut self, entry: OfferEntry) {
        let seller_key = account_id_to_bytes(&entry.seller_id);
        let key = (seller_key, entry.offer_id);
        let ledger_key = LedgerKey::Offer(LedgerKeyOffer {
            seller_id: entry.seller_id.clone(),
            offer_id: entry.offer_id,
        });

        // Save snapshot (None because it didn't exist)
        self.offer_snapshots.entry(key).or_insert(None);
        self.snapshot_last_modified_key(&ledger_key);
        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);

        // Record in delta
        let ledger_entry = self.offer_to_ledger_entry(&entry);
        self.delta.record_create(ledger_entry);

        // Add to offer index for efficient best-offer lookups
        self.offer_index.add_offer(&entry);
        self.aa_index_insert(&entry);

        // Insert into state
        self.offers.insert(key, entry);

        // Track that this entry was created in this transaction (for rollback)
        self.created_offers.insert(key);

        // Track modification
        if !self.modified_offers.contains(&key) {
            self.modified_offers.push(key);
        }
    }

    /// Update an existing offer entry.
    pub fn update_offer(&mut self, entry: OfferEntry) {
        let seller_key = account_id_to_bytes(&entry.seller_id);
        let key = (seller_key, entry.offer_id);
        let ledger_key = LedgerKey::Offer(LedgerKeyOffer {
            seller_id: entry.seller_id.clone(),
            offer_id: entry.offer_id,
        });

        // Save snapshot if not already saved (for rollback purposes)
        if !self.offer_snapshots.contains_key(&key) {
            let snapshot = self.offers.get(&key).cloned();
            self.offer_snapshots.insert(key, snapshot);
        }
        self.capture_op_snapshot_for_key(&ledger_key);
        self.snapshot_last_modified_key(&ledger_key);

        // Get pre-state from current state (value BEFORE this specific update)
        let pre_state = self
            .offers
            .get(&key)
            .map(|offer| self.offer_to_ledger_entry(offer));

        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);

        // Record in delta - each update gets its own STATE/UPDATED pair
        let post_state = self.offer_to_ledger_entry(&entry);
        if let Some(pre) = pre_state {
            self.delta.record_update(pre, post_state);
        }

        // Update offer index (handles price/asset changes)
        self.offer_index.update_offer(&entry);

        // Update (account, asset) secondary index: remove old, insert new
        let old_offer_clone = self.offers.get(&key).cloned();
        if let Some(ref old_offer) = old_offer_clone {
            self.aa_index_remove(old_offer);
        }
        self.aa_index_insert(&entry);

        // Update state
        self.offers.insert(key, entry.clone());

        // Do NOT track in modified_offers since we already recorded the update
        // This prevents flush_modified_entries from recording a duplicate
    }

    /// Delete an offer entry.
    pub fn delete_offer(&mut self, seller_id: &AccountId, offer_id: i64) {
        let seller_key = account_id_to_bytes(seller_id);
        let key = (seller_key, offer_id);
        let ledger_key = LedgerKey::Offer(LedgerKeyOffer {
            seller_id: seller_id.clone(),
            offer_id,
        });

        // Save snapshot if not already saved
        if !self.offer_snapshots.contains_key(&key) {
            let snapshot = self.offers.get(&key).cloned();
            self.offer_snapshots.insert(key, snapshot);
        }
        self.capture_op_snapshot_for_key(&ledger_key);
        self.snapshot_last_modified_key(&ledger_key);

        // Get pre-state (current value BEFORE deletion)
        let pre_state = self
            .offers
            .get(&key)
            .map(|offer| self.offer_to_ledger_entry(offer));

        // Record in delta with pre-state
        if let Some(pre) = pre_state {
            self.delta.record_delete(ledger_key.clone(), pre);
        }

        // Remove from offer index
        self.offer_index.remove_offer(seller_id, offer_id);

        // Remove from (account, asset) secondary index
        if let Some(offer) = self.offers.get(&key) {
            let offer_clone = offer.clone();
            self.aa_index_remove(&offer_clone);
        }

        // Remove from state
        self.clear_entry_sponsorship_metadata(&ledger_key);
        self.offers.remove(&key);
        self.remove_last_modified_key(&ledger_key);
    }

    /// Iterate over all offers.
    pub fn offers_iter(&self) -> impl Iterator<Item = &OfferEntry> {
        self.offers.values()
    }

    /// Get the best offer for a buying/selling pair (lowest price, then offer ID).
    ///
    /// Uses the offer index for O(log n) lookup instead of scanning all offers.
    pub fn best_offer(&self, buying: &Asset, selling: &Asset) -> Option<OfferEntry> {
        // Use the offer index for efficient lookup
        if let Some(key) = self.offer_index.best_offer_key(buying, selling) {
            return self.offers.get(&(key.seller, key.offer_id)).cloned();
        }
        None
    }

    /// Get the best offer for a buying/selling pair with an additional filter.
    ///
    /// Uses the offer index for efficient traversal in price order.
    pub fn best_offer_filtered<F>(
        &self,
        buying: &Asset,
        selling: &Asset,
        mut keep: F,
    ) -> Option<OfferEntry>
    where
        F: FnMut(&OfferEntry) -> bool,
    {
        // Use the offer index to iterate in price order
        for offer_key in self.offer_index.offers_for_pair(buying, selling) {
            if let Some(offer) = self.offers.get(&(offer_key.seller, offer_key.offer_id)) {
                if keep(offer) {
                    return Some(offer.clone());
                }
            }
        }
        None
    }

    /// Check if offers exist for a specific asset pair.
    pub fn has_offers_for_pair(&self, buying: &Asset, selling: &Asset) -> bool {
        self.offer_index.has_offers(buying, selling)
    }

    /// Get all offers for a specific buying/selling asset pair.
    ///
    /// Returns cloned OfferEntry values for each offer in the pair's order book.
    pub fn offers_for_asset_pair(&self, buying: &Asset, selling: &Asset) -> Vec<OfferEntry> {
        self.offer_index
            .offers_for_pair(buying, selling)
            .filter_map(|key| self.offers.get(&(key.seller, key.offer_id)).cloned())
            .collect()
    }

    /// Get the number of offers in the index.
    pub fn offer_index_size(&self) -> usize {
        self.offer_index.len()
    }

    /// Get the number of unique asset pairs with offers.
    pub fn offer_index_num_pairs(&self) -> usize {
        self.offer_index.num_asset_pairs()
    }

    /// Remove all offers owned by an account that are buying or selling a specific asset.
    /// This is used when revoking authorization on a trustline.
    /// Returns the list of OfferEntry that were removed (before deletion) so callers can
    /// handle liability release, subentry updates, and sponsorship adjustments.
    pub fn remove_offers_by_account_and_asset(
        &mut self,
        account_id: &AccountId,
        asset: &Asset,
    ) -> Vec<OfferEntry> {
        let account_key = account_id_to_bytes(account_id);
        let asset_key = AssetKey::from_asset(asset);

        // Look up offer IDs from secondary index
        let offer_ids: Vec<i64> = self
            .account_asset_offers
            .get(&(account_key, asset_key))
            .map(|ids| ids.iter().copied().collect())
            .unwrap_or_default();

        // Collect matching offers (verify they still match before removing)
        let offers_to_remove: Vec<OfferEntry> = offer_ids
            .iter()
            .filter_map(|&offer_id| {
                self.offers
                    .get(&(account_key, offer_id))
                    .cloned()
                    .filter(|offer| offer.buying == *asset || offer.selling == *asset)
            })
            .collect();

        // Remove each offer
        for offer in &offers_to_remove {
            self.delete_offer(&offer.seller_id, offer.offer_id);
        }

        offers_to_remove
    }

    // ==================== Data Entry Operations ====================

    /// Get a data entry by account and name (read-only).
    pub fn get_data(&self, account_id: &AccountId, name: &str) -> Option<&DataEntry> {
        let account_key = account_id_to_bytes(account_id);
        self.data_entries.get(&(account_key, name.to_string()))
    }

    /// Get a mutable reference to a data entry.
    pub fn get_data_mut(&mut self, account_id: &AccountId, name: &str) -> Option<&mut DataEntry> {
        let account_key = account_id_to_bytes(account_id);
        let key = (account_key, name.to_string());

        if self.data_entries.contains_key(&key) {
            // Save snapshot if not already saved or if it's None (for newly created entries).
            // For newly created entries, we update the snapshot to the current value so
            // subsequent operations can track changes with STATE/UPDATED pairs.
            // Rollback correctness is ensured by the created_data set.
            if !self.data_snapshots.get(&key).is_some_and(|s| s.is_some()) {
                let snapshot = self.data_entries.get(&key).cloned();
                self.data_snapshots.insert(key.clone(), snapshot);
            }
            if let Some(entry) = self.data_entries.get(&key) {
                let ledger_key = LedgerKey::Data(LedgerKeyData {
                    account_id: entry.account_id.clone(),
                    data_name: entry.data_name.clone(),
                });
                self.capture_op_snapshot_for_key(&ledger_key);
                self.snapshot_last_modified_key(&ledger_key);
            }
            // Track modification
            if !self.modified_data.contains(&key) {
                self.modified_data.push(key.clone());
            }
            self.data_entries.get_mut(&key)
        } else {
            None
        }
    }

    /// Create a new data entry.
    pub fn create_data(&mut self, entry: DataEntry) {
        let account_key = account_id_to_bytes(&entry.account_id);
        let name = data_name_to_string(&entry.data_name);
        tracing::debug!(
            "create_data: account_key={:02x?}, name={:?}, name_bytes={:?}",
            &account_key[..4],
            name,
            entry.data_name.as_vec()
        );
        let key = (account_key, name.clone());
        let ledger_key = LedgerKey::Data(LedgerKeyData {
            account_id: entry.account_id.clone(),
            data_name: entry.data_name.clone(),
        });

        // Save snapshot (None because it didn't exist)
        if !self.data_snapshots.contains_key(&key) {
            self.data_snapshots.insert(key.clone(), None);
        }
        self.snapshot_last_modified_key(&ledger_key);
        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);

        // Record in delta
        let ledger_entry = self.data_to_ledger_entry(&entry);
        self.delta.record_create(ledger_entry);

        // Insert into state
        self.data_entries.insert(key.clone(), entry);

        // Track that this entry was created in this transaction (for rollback)
        self.created_data.insert(key.clone());

        // Track modification
        if !self.modified_data.contains(&key) {
            self.modified_data.push(key);
        }
    }

    /// Update an existing data entry.
    pub fn update_data(&mut self, entry: DataEntry) {
        let account_key = account_id_to_bytes(&entry.account_id);
        let name = data_name_to_string(&entry.data_name);
        let key = (account_key, name.clone());
        let ledger_key = LedgerKey::Data(LedgerKeyData {
            account_id: entry.account_id.clone(),
            data_name: entry.data_name.clone(),
        });

        // Save snapshot if not already saved
        if !self.data_snapshots.contains_key(&key) {
            let snapshot = self.data_entries.get(&key).cloned();
            self.data_snapshots.insert(key.clone(), snapshot);
        }
        self.capture_op_snapshot_for_key(&ledger_key);
        self.snapshot_last_modified_key(&ledger_key);

        // Get pre-state (current value BEFORE this update)
        let pre_state = self
            .data_entries
            .get(&key)
            .map(|data| self.data_to_ledger_entry(data));

        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);

        // Record in delta with pre-state
        let post_state = self.data_to_ledger_entry(&entry);
        if let Some(pre) = pre_state {
            self.delta.record_update(pre, post_state);
        }

        // Update state
        self.data_entries.insert(key.clone(), entry.clone());

        // Update snapshot to current value so flush_modified_entries doesn't record a duplicate.
        self.data_snapshots.insert(key, Some(entry));
    }

    /// Delete a data entry.
    pub fn delete_data(&mut self, account_id: &AccountId, name: &str) {
        let account_key = account_id_to_bytes(account_id);
        let key = (account_key, name.to_string());

        // Save snapshot if not already saved
        if !self.data_snapshots.contains_key(&key) {
            let snapshot = self.data_entries.get(&key).cloned();
            self.data_snapshots.insert(key.clone(), snapshot);
        }

        // Record in delta - we need to get the data_name from the entry
        // Clone the entry first to avoid borrow checker issues
        if let Some(entry) = self.data_entries.get(&key).cloned() {
            let ledger_key = LedgerKey::Data(LedgerKeyData {
                account_id: account_id.clone(),
                data_name: entry.data_name.clone(),
            });
            self.capture_op_snapshot_for_key(&ledger_key);
            self.snapshot_last_modified_key(&ledger_key);

            // Get pre-state (current value BEFORE deletion)
            let pre_state = self.data_to_ledger_entry(&entry);
            self.delta.record_delete(ledger_key.clone(), pre_state);
            self.clear_entry_sponsorship_metadata(&ledger_key);
            self.remove_last_modified_key(&ledger_key);
        }

        // Remove from state
        self.data_entries.remove(&key);
    }

    // ==================== Contract Data Operations ====================

    /// Get a contract data entry by key (read-only).
    pub fn get_contract_data(
        &self,
        contract: &ScAddress,
        key: &ScVal,
        durability: ContractDataDurability,
    ) -> Option<&ContractDataEntry> {
        let lookup_key = ContractDataKey::new(contract.clone(), key.clone(), durability);
        self.contract_data.get(&lookup_key)
    }

    /// Get a mutable reference to a contract data entry.
    pub fn get_contract_data_mut(
        &mut self,
        contract: &ScAddress,
        key: &ScVal,
        durability: ContractDataDurability,
    ) -> Option<&mut ContractDataEntry> {
        let lookup_key = ContractDataKey::new(contract.clone(), key.clone(), durability);

        if self.contract_data.contains_key(&lookup_key) {
            // Save snapshot if not already saved or if it's None (for newly created entries).
            // For newly created entries, we update the snapshot to the current value so
            // subsequent operations can track changes with STATE/UPDATED pairs.
            // Rollback correctness is ensured by the created_contract_data set.
            if !self
                .contract_data_snapshots
                .get(&lookup_key)
                .is_some_and(|s| s.is_some())
            {
                let snapshot = self.contract_data.get(&lookup_key).cloned();
                self.contract_data_snapshots
                    .insert(lookup_key.clone(), snapshot);
            }
            let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
                contract: contract.clone(),
                key: key.clone(),
                durability,
            });
            self.capture_op_snapshot_for_key(&ledger_key);
            self.snapshot_last_modified_key(&ledger_key);
            // Track modification
            if !self.modified_contract_data.contains(&lookup_key) {
                self.modified_contract_data.push(lookup_key.clone());
            }
            self.contract_data.get_mut(&lookup_key)
        } else {
            None
        }
    }

    /// Create a new contract data entry.
    pub fn create_contract_data(&mut self, entry: ContractDataEntry) {
        let key = ContractDataKey::new(entry.contract.clone(), entry.key.clone(), entry.durability);
        let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: entry.contract.clone(),
            key: entry.key.clone(),
            durability: entry.durability,
        });

        // Save snapshot (None because it didn't exist)
        if !self.contract_data_snapshots.contains_key(&key) {
            self.contract_data_snapshots.insert(key.clone(), None);
        }
        self.snapshot_last_modified_key(&ledger_key);
        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);

        // Record in delta
        let ledger_entry = self.contract_data_to_ledger_entry(&entry);
        self.delta.record_create(ledger_entry);

        // Insert into state
        self.contract_data.insert(key.clone(), entry);

        // Track that this entry was created in this transaction (for rollback)
        self.created_contract_data.insert(key.clone());

        // Track modification
        if !self.modified_contract_data.contains(&key) {
            self.modified_contract_data.push(key);
        }
    }

    /// Update an existing contract data entry.
    pub fn update_contract_data(&mut self, entry: ContractDataEntry) {
        let key = ContractDataKey::new(entry.contract.clone(), entry.key.clone(), entry.durability);
        let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: entry.contract.clone(),
            key: entry.key.clone(),
            durability: entry.durability,
        });

        // Save snapshot if not already saved
        if !self.contract_data_snapshots.contains_key(&key) {
            let snapshot = self.contract_data.get(&key).cloned();
            self.contract_data_snapshots.insert(key.clone(), snapshot);
        }
        self.capture_op_snapshot_for_key(&ledger_key);
        self.snapshot_last_modified_key(&ledger_key);

        // Get pre-state (current value BEFORE this update)
        let pre_state = self
            .contract_data
            .get(&key)
            .map(|cd| self.contract_data_to_ledger_entry(cd));

        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);

        // Record in delta with pre-state
        let post_state = self.contract_data_to_ledger_entry(&entry);
        if let Some(pre) = pre_state {
            self.delta.record_update(pre, post_state);
        }

        // Update state
        self.contract_data.insert(key.clone(), entry.clone());

        // Update snapshot to current value so flush_modified_entries doesn't record a duplicate.
        self.contract_data_snapshots.insert(key, Some(entry));
    }

    /// Delete a contract data entry.
    pub fn delete_contract_data(
        &mut self,
        contract: &ScAddress,
        key: &ScVal,
        durability: ContractDataDurability,
    ) {
        let lookup_key = ContractDataKey::new(contract.clone(), key.clone(), durability);
        let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: contract.clone(),
            key: key.clone(),
            durability,
        });

        // Save snapshot if not already saved
        if !self.contract_data_snapshots.contains_key(&lookup_key) {
            let snapshot = self.contract_data.get(&lookup_key).cloned();
            self.contract_data_snapshots
                .insert(lookup_key.clone(), snapshot);
        }
        self.capture_op_snapshot_for_key(&ledger_key);
        self.snapshot_last_modified_key(&ledger_key);

        // Get pre-state (current value BEFORE deletion)
        let pre_state = self
            .contract_data
            .get(&lookup_key)
            .map(|cd| self.contract_data_to_ledger_entry(cd));

        // Record in delta with pre-state
        if let Some(pre) = pre_state {
            self.delta.record_delete(ledger_key.clone(), pre);
        }

        // Remove from state and track deletion
        self.clear_entry_sponsorship_metadata(&ledger_key);
        self.contract_data.remove(&lookup_key);
        self.remove_last_modified_key(&ledger_key);
        // Track this deletion to prevent reloading from bucket list
        self.deleted_contract_data.insert(lookup_key);
    }

    // ==================== Contract Code Operations ====================

    /// Get a contract code entry by hash (read-only).
    pub fn get_contract_code(&self, hash: &Hash) -> Option<&ContractCodeEntry> {
        self.contract_code.get(&hash.0)
    }

    /// Get a mutable reference to a contract code entry.
    pub fn get_contract_code_mut(&mut self, hash: &Hash) -> Option<&mut ContractCodeEntry> {
        let key = hash.0;

        if self.contract_code.contains_key(&key) {
            // Save snapshot if not already saved or if it's None (for newly created entries).
            // For newly created entries, we update the snapshot to the current value so
            // subsequent operations can track changes with STATE/UPDATED pairs.
            // Rollback correctness is ensured by the created_contract_code set.
            if !self
                .contract_code_snapshots
                .get(&key)
                .is_some_and(|s| s.is_some())
            {
                let snapshot = self.contract_code.get(&key).cloned();
                self.contract_code_snapshots.insert(key, snapshot);
            }
            let ledger_key = LedgerKey::ContractCode(LedgerKeyContractCode { hash: hash.clone() });
            self.capture_op_snapshot_for_key(&ledger_key);
            self.snapshot_last_modified_key(&ledger_key);
            // Track modification
            if !self.modified_contract_code.contains(&key) {
                self.modified_contract_code.push(key);
            }
            self.contract_code.get_mut(&key)
        } else {
            None
        }
    }

    /// Create a new contract code entry.
    pub fn create_contract_code(&mut self, entry: ContractCodeEntry) {
        let key = entry.hash.0;
        let ledger_key = LedgerKey::ContractCode(LedgerKeyContractCode {
            hash: entry.hash.clone(),
        });

        // Save snapshot (None because it didn't exist)
        self.contract_code_snapshots.entry(key).or_insert(None);
        self.snapshot_last_modified_key(&ledger_key);
        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);

        // Record in delta
        let ledger_entry = self.contract_code_to_ledger_entry(&entry);
        self.delta.record_create(ledger_entry);

        // Insert into state
        self.contract_code.insert(key, entry);

        // Track that this entry was created in this transaction (for rollback)
        self.created_contract_code.insert(key);

        // Track modification
        if !self.modified_contract_code.contains(&key) {
            self.modified_contract_code.push(key);
        }
    }

    /// Update an existing contract code entry.
    pub fn update_contract_code(&mut self, entry: ContractCodeEntry) {
        let key = entry.hash.0;
        let ledger_key = LedgerKey::ContractCode(LedgerKeyContractCode {
            hash: entry.hash.clone(),
        });

        // Save snapshot if not already saved
        if !self.contract_code_snapshots.contains_key(&key) {
            let snapshot = self.contract_code.get(&key).cloned();
            self.contract_code_snapshots.insert(key, snapshot);
        }
        self.capture_op_snapshot_for_key(&ledger_key);
        self.snapshot_last_modified_key(&ledger_key);

        // Get pre-state (current value BEFORE this update)
        let pre_state = self
            .contract_code
            .get(&key)
            .map(|cc| self.contract_code_to_ledger_entry(cc));

        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);

        // Record in delta with pre-state
        let post_state = self.contract_code_to_ledger_entry(&entry);
        if let Some(pre) = pre_state {
            self.delta.record_update(pre, post_state);
        }

        // Update state
        self.contract_code.insert(key, entry.clone());

        // Update snapshot to current value so flush_modified_entries doesn't record a duplicate.
        self.contract_code_snapshots.insert(key, Some(entry));

        // Track modification
        if !self.modified_contract_code.contains(&key) {
            self.modified_contract_code.push(key);
        }
    }

    /// Delete a contract code entry.
    pub fn delete_contract_code(&mut self, hash: &Hash) {
        let key = hash.0;
        let ledger_key = LedgerKey::ContractCode(LedgerKeyContractCode { hash: hash.clone() });

        // Save snapshot if not already saved
        if !self.contract_code_snapshots.contains_key(&key) {
            let snapshot = self.contract_code.get(&key).cloned();
            self.contract_code_snapshots.insert(key, snapshot);
        }
        self.capture_op_snapshot_for_key(&ledger_key);
        self.snapshot_last_modified_key(&ledger_key);

        // Get pre-state (current value BEFORE deletion)
        let pre_state = self
            .contract_code
            .get(&key)
            .map(|cc| self.contract_code_to_ledger_entry(cc));

        // Record in delta with pre-state
        if let Some(pre) = pre_state {
            self.delta.record_delete(ledger_key.clone(), pre);
        }

        // Remove from state and track deletion
        self.clear_entry_sponsorship_metadata(&ledger_key);
        self.contract_code.remove(&key);
        self.remove_last_modified_key(&ledger_key);
        // Track this deletion to prevent reloading from bucket list
        self.deleted_contract_code.insert(key);
    }

    // ==================== TTL Entry Operations ====================

    /// Get a TTL entry by key hash (read-only).
    pub fn get_ttl(&self, key_hash: &Hash) -> Option<&TtlEntry> {
        self.ttl_entries.get(&key_hash.0)
    }

    /// Get the TTL live_until_ledger_seq at ledger start.
    ///
    /// This returns the TTL value from the bucket list snapshot captured at the
    /// start of the ledger, before any transactions modified it. This is used
    /// by Soroban execution to match C++ stellar-core behavior where transactions
    /// see the bucket list state at ledger start, not changes from previous txs.
    pub fn get_ttl_at_ledger_start(&self, key_hash: &Hash) -> Option<u32> {
        self.ttl_bucket_list_snapshot.get(&key_hash.0).copied()
    }

    /// Capture the current TTL values as the bucket list snapshot.
    ///
    /// This should be called once at the start of each ledger, after loading
    /// state from the bucket list but before executing any transactions.
    /// The captured values will be used by Soroban for TTL lookups to ensure
    /// consistent behavior with C++ stellar-core.
    pub fn capture_ttl_bucket_list_snapshot(&mut self) {
        self.ttl_bucket_list_snapshot.clear();
        for (key_hash, ttl) in &self.ttl_entries {
            self.ttl_bucket_list_snapshot
                .insert(*key_hash, ttl.live_until_ledger_seq);
        }
    }

    /// Get a mutable reference to a TTL entry.
    pub fn get_ttl_mut(&mut self, key_hash: &Hash) -> Option<&mut TtlEntry> {
        let key = key_hash.0;

        if self.ttl_entries.contains_key(&key) {
            // Save snapshot if not already saved or if it's None (for newly created entries).
            // For newly created entries, we update the snapshot to the current value so
            // subsequent operations can track changes with STATE/UPDATED pairs.
            // Rollback correctness is ensured by the created_ttl set.
            if !self.ttl_snapshots.get(&key).is_some_and(|s| s.is_some()) {
                let snapshot = self.ttl_entries.get(&key).cloned();
                self.ttl_snapshots.insert(key, snapshot);
            }
            let ledger_key = LedgerKey::Ttl(LedgerKeyTtl {
                key_hash: key_hash.clone(),
            });
            self.capture_op_snapshot_for_key(&ledger_key);
            self.snapshot_last_modified_key(&ledger_key);
            // Track modification
            if !self.modified_ttl.contains(&key) {
                self.modified_ttl.push(key);
            }
            self.ttl_entries.get_mut(&key)
        } else {
            None
        }
    }

    /// Create a new TTL entry.
    pub fn create_ttl(&mut self, entry: TtlEntry) {
        let key = entry.key_hash.0;
        let ledger_key = LedgerKey::Ttl(LedgerKeyTtl {
            key_hash: entry.key_hash.clone(),
        });

        tracing::debug!(
            key_hash = ?entry.key_hash,
            live_until = entry.live_until_ledger_seq,
            "create_ttl: ENTERING"
        );

        // Save snapshot (None because it didn't exist)
        let existing_snapshot = self.ttl_snapshots.get(&key).cloned();
        self.ttl_snapshots.entry(key).or_insert(None);
        tracing::debug!(
            key_hash = ?entry.key_hash,
            ?existing_snapshot,
            "create_ttl: snapshot state"
        );
        self.snapshot_last_modified_key(&ledger_key);
        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);

        // Record in delta
        let ledger_entry = self.ttl_to_ledger_entry(&entry);
        tracing::debug!(
            key_hash = ?entry.key_hash,
            "create_ttl: calling record_create"
        );
        self.delta.record_create(ledger_entry);

        // Insert into state
        self.ttl_entries.insert(key, entry);

        // Track that this entry was created in this transaction (for rollback)
        self.created_ttl.insert(key);

        // Track modification
        if !self.modified_ttl.contains(&key) {
            self.modified_ttl.push(key);
        }
    }

    /// Update an existing TTL entry.
    ///
    /// This function only records a delta update if the TTL value actually changes.
    /// This is critical for correct bucket list behavior: when multiple transactions
    /// in the same ledger access the same entry, later transactions may call update_ttl
    /// with a value that earlier transactions already set. Recording a no-op update
    /// would cause bucket list divergence from C++ stellar-core.
    pub fn update_ttl(&mut self, entry: TtlEntry) {
        let key = entry.key_hash.0;
        let ledger_key = LedgerKey::Ttl(LedgerKeyTtl {
            key_hash: entry.key_hash.clone(),
        });

        tracing::debug!(
            key_hash = ?entry.key_hash,
            live_until = entry.live_until_ledger_seq,
            "update_ttl: ENTERING"
        );

        // Check if the TTL value is actually changing
        if let Some(existing) = self.ttl_entries.get(&key) {
            if existing.live_until_ledger_seq == entry.live_until_ledger_seq {
                // TTL value unchanged - skip recording any update.
                // This can happen when multiple transactions in the same ledger
                // access the same entry: TX 5 extends TTL to 700457, then TX 7
                // also tries to update to 700457. From the host's perspective
                // (using ledger-start TTL), TX 7's ttl_extended=true, but the
                // value is already 700457 in our state. Recording this no-op
                // would cause bucket list divergence.
                tracing::debug!(
                    ?key,
                    live_until = entry.live_until_ledger_seq,
                    "TTL update skipped: value unchanged"
                );
                return;
            }
        }

        // Save snapshot if not already saved
        if !self.ttl_snapshots.contains_key(&key) {
            let snapshot = self.ttl_entries.get(&key).cloned();
            self.ttl_snapshots.insert(key, snapshot);
        }
        self.capture_op_snapshot_for_key(&ledger_key);
        self.snapshot_last_modified_key(&ledger_key);

        // Get pre-state (current value BEFORE this update)
        let pre_state = self
            .ttl_entries
            .get(&key)
            .map(|ttl| self.ttl_to_ledger_entry(ttl));

        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);

        // Record in delta with pre-state
        let post_state = self.ttl_to_ledger_entry(&entry);
        if let Some(pre) = pre_state {
            self.delta.record_update(pre, post_state);
        }

        // Update state
        self.ttl_entries.insert(key, entry.clone());

        // Update snapshot to current value so flush_modified_entries doesn't record a duplicate.
        self.ttl_snapshots.insert(key, Some(entry));

        // Track modification
        if !self.modified_ttl.contains(&key) {
            self.modified_ttl.push(key);
        }
    }

    /// Update an existing TTL entry without recording in the delta.
    ///
    /// This is used for TTL-only auto-bump changes where the data entry wasn't modified
    /// but the TTL was extended. C++ stellar-core does NOT include these TTL updates
    /// in the transaction meta, so we must update state without creating delta entries.
    ///
    /// The state update is still needed for correct bucket list computation.
    pub fn update_ttl_no_delta(&mut self, entry: TtlEntry) {
        let key = entry.key_hash.0;
        let ledger_key = LedgerKey::Ttl(LedgerKeyTtl {
            key_hash: entry.key_hash.clone(),
        });

        tracing::debug!(
            key_hash = ?entry.key_hash,
            live_until = entry.live_until_ledger_seq,
            "update_ttl_no_delta: updating TTL state without delta"
        );

        // Check if the TTL value is actually changing
        if let Some(existing) = self.ttl_entries.get(&key) {
            if existing.live_until_ledger_seq == entry.live_until_ledger_seq {
                // TTL value unchanged - nothing to do
                return;
            }
        }

        // Update last_modified_key for bucket list computation
        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);

        // Update state only (no delta recording)
        self.ttl_entries.insert(key, entry.clone());

        // Update snapshot to prevent flush_modified_entries from recording this
        self.ttl_snapshots.insert(key, Some(entry));

        // Track modification (for bucket list, but not for delta/meta)
        if !self.modified_ttl.contains(&key) {
            self.modified_ttl.push(key);
        }
    }

    /// Record a read-only TTL bump in the delta for transaction meta, then defer
    /// the actual state update.
    ///
    /// Per C++ stellar-core behavior:
    /// - Transaction meta includes all TTL changes (including RO bumps)
    /// - RO TTL bumps are deferred for state visibility (subsequent TXs don't see them)
    /// - At end of ledger, deferred bumps are flushed to state for bucket list
    ///
    /// This method:
    /// 1. Records pre/post state in delta (for transaction meta)
    /// 2. Does NOT update ttl_entries (so subsequent TX lookups return old value)
    /// 3. Stores the bump for later flushing to state
    pub fn record_ro_ttl_bump_for_meta(&mut self, key_hash: &Hash, live_until_ledger_seq: u32) {
        let key = key_hash.0;
        let ledger_key = LedgerKey::Ttl(LedgerKeyTtl {
            key_hash: key_hash.clone(),
        });

        // Get pre-state (current value in ttl_entries, NOT including deferred bumps)
        let pre_state = self
            .ttl_entries
            .get(&key)
            .map(|ttl| self.ttl_to_ledger_entry(ttl));

        if pre_state.is_none() {
            tracing::warn!(
                key_hash = ?key_hash,
                live_until = live_until_ledger_seq,
                "record_ro_ttl_bump_for_meta: TTL entry not found for RO bump"
            );
            return;
        }

        // Check if TTL is actually changing
        if let Some(existing) = self.ttl_entries.get(&key) {
            if existing.live_until_ledger_seq == live_until_ledger_seq {
                // No change needed
                tracing::debug!(
                    key_hash = ?key_hash,
                    live_until = live_until_ledger_seq,
                    "record_ro_ttl_bump_for_meta: skipping - value unchanged"
                );
                return;
            }
        }

        // Capture op snapshot for correct transaction meta ordering
        self.capture_op_snapshot_for_key(&ledger_key);
        // Note: We do NOT call snapshot_last_modified_key or set_last_modified_key here
        // because RO TTL bumps should NOT affect the visible state for subsequent TXs.
        // The lastModifiedLedgerSeq for the pre_state should remain the original value.

        // Build post-state manually with the CURRENT ledger as lastModifiedLedgerSeq.
        // We do NOT call set_last_modified_key because we don't want subsequent TXs
        // to see this change in their pre-state lookups.
        let ttl_entry = TtlEntry {
            key_hash: key_hash.clone(),
            live_until_ledger_seq,
        };
        let post_state = LedgerEntry {
            last_modified_ledger_seq: self.ledger_seq,
            data: LedgerEntryData::Ttl(ttl_entry),
            ext: self.ledger_entry_ext_for(&ledger_key),
        };

        // Record in delta (for transaction meta) - pre_state -> post_state
        self.delta.record_update(pre_state.unwrap(), post_state);

        tracing::debug!(
            key_hash = ?key_hash,
            live_until = live_until_ledger_seq,
            "record_ro_ttl_bump_for_meta: recorded in delta, deferring state update"
        );

        // Also store for later flushing to state (for bucket list)
        // Only keep the highest TTL bump for each key
        let entry = self.deferred_ro_ttl_bumps.entry(key).or_insert(0);
        if live_until_ledger_seq > *entry {
            *entry = live_until_ledger_seq;
        }
    }

    /// Defer a read-only TTL bump for later flushing (legacy method, prefer record_ro_ttl_bump_for_meta).
    ///
    /// Read-only TTL bumps (TTL changes for entries in the read-only footprint where
    /// only the TTL changed) must NOT appear in transaction meta, but MUST be written
    /// to the bucket list. This matches C++ stellar-core's behavior where RO TTL bumps
    /// are accumulated in `mRoTTLBumps` and flushed at write barriers.
    ///
    /// Call `flush_deferred_ro_ttl_bumps()` at the end of ledger processing to add
    /// these bumps to the delta (after transaction meta is built, before bucket list
    /// is updated).
    pub fn defer_ro_ttl_bump(&mut self, key_hash: &Hash, live_until_ledger_seq: u32) {
        let key = key_hash.0;
        // Only keep the highest TTL bump for each key
        let entry = self.deferred_ro_ttl_bumps.entry(key).or_insert(0);
        if live_until_ledger_seq > *entry {
            *entry = live_until_ledger_seq;
        }
        tracing::debug!(
            key_hash = ?key_hash,
            live_until = live_until_ledger_seq,
            "defer_ro_ttl_bump: deferred TTL bump for bucket list"
        );
    }

    /// Flush deferred read-only TTL bumps to state.
    ///
    /// This should be called at the end of ledger processing, after all transaction
    /// meta has been built but before the bucket list is updated.
    ///
    /// Note: The delta already has the TTL changes (recorded by record_ro_ttl_bump_for_meta
    /// during transaction execution). This flush only updates the state (ttl_entries) so
    /// the bucket list sees the final values.
    pub fn flush_deferred_ro_ttl_bumps(&mut self) {
        let bumps = std::mem::take(&mut self.deferred_ro_ttl_bumps);
        tracing::debug!(
            count = bumps.len(),
            "flush_deferred_ro_ttl_bumps: starting flush"
        );
        for (key, live_until) in bumps {
            let key_hash = Hash(key);
            if let Some(existing) = self.ttl_entries.get(&key) {
                // Only update if the deferred bump is higher than current value
                if live_until > existing.live_until_ledger_seq {
                    let ttl = TtlEntry {
                        key_hash: key_hash.clone(),
                        live_until_ledger_seq: live_until,
                    };
                    tracing::debug!(
                        key_hash = ?key_hash,
                        old_live_until = existing.live_until_ledger_seq,
                        new_live_until = live_until,
                        "flush_deferred_ro_ttl_bumps: updating TTL state"
                    );
                    // Use update_ttl_no_delta since the delta already has the change
                    // from record_ro_ttl_bump_for_meta. We just need to update state
                    // for the bucket list to see the final value.
                    self.update_ttl_no_delta(ttl);
                } else {
                    tracing::debug!(
                        key_hash = ?key_hash,
                        existing_live_until = existing.live_until_ledger_seq,
                        deferred_live_until = live_until,
                        "flush_deferred_ro_ttl_bumps: skipping - deferred not higher"
                    );
                }
            } else {
                tracing::warn!(
                    key_hash = ?key_hash,
                    live_until = live_until,
                    "flush_deferred_ro_ttl_bumps: TTL entry not found in state"
                );
            }
        }
    }

    /// Extend the TTL of an entry to the specified ledger sequence.
    pub fn extend_ttl(&mut self, key_hash: &Hash, live_until_ledger_seq: u32) {
        let key = key_hash.0;

        if let Some(ttl_entry) = self.ttl_entries.get(&key).cloned() {
            // Only extend if the new TTL is greater
            if live_until_ledger_seq > ttl_entry.live_until_ledger_seq {
                // If this entry was created in this transaction, we should NOT emit
                // a STATE+UPDATED pair - the CREATED entry should reflect the final value.
                // We update the delta's created entry directly instead.
                if self.created_ttl.contains(&key) {
                    // Create updated entry
                    let updated = TtlEntry {
                        key_hash: ttl_entry.key_hash,
                        live_until_ledger_seq,
                    };
                    // Update the created entry in delta to reflect final value
                    self.delta.update_created_ttl(key_hash, &updated);
                    // Update state
                    self.ttl_entries.insert(key, updated);
                } else {
                    // Save snapshot if not already saved
                    self.ttl_snapshots
                        .entry(key)
                        .or_insert_with(|| Some(ttl_entry.clone()));
                    let ledger_key = LedgerKey::Ttl(LedgerKeyTtl {
                        key_hash: key_hash.clone(),
                    });
                    self.capture_op_snapshot_for_key(&ledger_key);
                    self.snapshot_last_modified_key(&ledger_key);

                    // Get pre-state (current value BEFORE this update)
                    let pre_state = self.ttl_to_ledger_entry(&ttl_entry);

                    self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);

                    // Create updated entry
                    let updated = TtlEntry {
                        key_hash: ttl_entry.key_hash,
                        live_until_ledger_seq,
                    };

                    // Record in delta with pre-state
                    let post_state = self.ttl_to_ledger_entry(&updated);
                    self.delta.record_update(pre_state, post_state);

                    // Update state
                    self.ttl_entries.insert(key, updated.clone());

                    // Update snapshot to current value so flush_modified_entries doesn't record a duplicate.
                    self.ttl_snapshots.insert(key, Some(updated));

                    // Track modification
                    if !self.modified_ttl.contains(&key) {
                        self.modified_ttl.push(key);
                    }
                }
            }
        }
    }

    /// Delete a TTL entry.
    pub fn delete_ttl(&mut self, key_hash: &Hash) {
        let key = key_hash.0;
        let ledger_key = LedgerKey::Ttl(LedgerKeyTtl {
            key_hash: key_hash.clone(),
        });

        // Save snapshot if not already saved
        if !self.ttl_snapshots.contains_key(&key) {
            let snapshot = self.ttl_entries.get(&key).cloned();
            self.ttl_snapshots.insert(key, snapshot);
        }
        self.capture_op_snapshot_for_key(&ledger_key);
        self.snapshot_last_modified_key(&ledger_key);

        // Get pre-state (current value BEFORE deletion)
        let pre_state = self
            .ttl_entries
            .get(&key)
            .map(|ttl| self.ttl_to_ledger_entry(ttl));

        // Record in delta with pre-state
        if let Some(pre) = pre_state {
            self.delta.record_delete(ledger_key.clone(), pre);
        }

        // Remove from state and track deletion
        self.clear_entry_sponsorship_metadata(&ledger_key);
        self.ttl_entries.remove(&key);
        self.remove_last_modified_key(&ledger_key);
        // Track this deletion to prevent reloading from bucket list
        self.deleted_ttl.insert(key);
    }

    /// Check if a TTL entry is live (not expired).
    pub fn is_entry_live(&self, key_hash: &Hash) -> bool {
        if let Some(ttl) = self.get_ttl(key_hash) {
            ttl.live_until_ledger_seq >= self.ledger_seq
        } else {
            false
        }
    }

    // ==================== Claimable Balance Operations ====================

    /// Get a claimable balance by ID (read-only).
    pub fn get_claimable_balance(
        &self,
        balance_id: &ClaimableBalanceId,
    ) -> Option<&ClaimableBalanceEntry> {
        let key = claimable_balance_id_to_bytes(balance_id);
        self.claimable_balances.get(&key)
    }

    /// Get a mutable reference to a claimable balance entry.
    pub fn get_claimable_balance_mut(
        &mut self,
        balance_id: &ClaimableBalanceId,
    ) -> Option<&mut ClaimableBalanceEntry> {
        let key = claimable_balance_id_to_bytes(balance_id);

        if self.claimable_balances.contains_key(&key) {
            if !self
                .claimable_balance_snapshots
                .get(&key)
                .is_some_and(|s| s.is_some())
            {
                let snapshot = self.claimable_balances.get(&key).cloned();
                self.claimable_balance_snapshots.insert(key, snapshot);
            }
            let ledger_key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
                balance_id: balance_id.clone(),
            });
            self.capture_op_snapshot_for_key(&ledger_key);
            self.snapshot_last_modified_key(&ledger_key);
            if !self.modified_claimable_balances.contains(&key) {
                self.modified_claimable_balances.push(key);
            }
            self.claimable_balances.get_mut(&key)
        } else {
            None
        }
    }

    /// Create a new claimable balance entry.
    pub fn create_claimable_balance(&mut self, entry: ClaimableBalanceEntry) {
        let key = claimable_balance_id_to_bytes(&entry.balance_id);
        let ledger_key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
            balance_id: entry.balance_id.clone(),
        });

        // Save snapshot (None because it didn't exist)
        self.claimable_balance_snapshots.entry(key).or_insert(None);
        self.snapshot_last_modified_key(&ledger_key);
        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);

        // Record in delta
        let ledger_entry = self.claimable_balance_to_ledger_entry(&entry);
        self.delta.record_create(ledger_entry);

        // Insert into state
        self.claimable_balances.insert(key, entry);

        // Track that this entry was created in this transaction (for rollback)
        self.created_claimable_balances.insert(key);

        // Track modification
        if !self.modified_claimable_balances.contains(&key) {
            self.modified_claimable_balances.push(key);
        }
    }

    /// Delete a claimable balance entry (when claimed).
    pub fn delete_claimable_balance(&mut self, balance_id: &ClaimableBalanceId) {
        let key = claimable_balance_id_to_bytes(balance_id);
        let ledger_key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
            balance_id: balance_id.clone(),
        });

        // Save snapshot if not already saved
        if !self.claimable_balance_snapshots.contains_key(&key) {
            let snapshot = self.claimable_balances.get(&key).cloned();
            self.claimable_balance_snapshots.insert(key, snapshot);
        }
        self.capture_op_snapshot_for_key(&ledger_key);
        self.snapshot_last_modified_key(&ledger_key);

        // Get pre-state (current value BEFORE deletion)
        let pre_state = self
            .claimable_balances
            .get(&key)
            .map(|e| self.claimable_balance_to_ledger_entry(e));

        // Record in delta with pre-state
        if let Some(pre) = pre_state {
            self.delta.record_delete(ledger_key.clone(), pre);
        }

        // Remove from state
        self.clear_entry_sponsorship_metadata(&ledger_key);
        self.claimable_balances.remove(&key);
        self.remove_last_modified_key(&ledger_key);
    }

    /// Update an existing claimable balance entry.
    pub fn update_claimable_balance(&mut self, entry: ClaimableBalanceEntry) {
        let key = claimable_balance_id_to_bytes(&entry.balance_id);
        let ledger_key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
            balance_id: entry.balance_id.clone(),
        });

        // Save snapshot if not already saved
        if !self.claimable_balance_snapshots.contains_key(&key) {
            let snapshot = self.claimable_balances.get(&key).cloned();
            self.claimable_balance_snapshots.insert(key, snapshot);
        }
        self.capture_op_snapshot_for_key(&ledger_key);
        self.snapshot_last_modified_key(&ledger_key);

        // Get pre-state (current value BEFORE this update)
        let pre_state = self
            .claimable_balances
            .get(&key)
            .map(|e| self.claimable_balance_to_ledger_entry(e));

        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);

        // Record in delta with pre-state
        let post_state = self.claimable_balance_to_ledger_entry(&entry);
        if let Some(pre) = pre_state {
            self.delta.record_update(pre, post_state);
        }

        // Update state
        self.claimable_balances.insert(key, entry.clone());

        // Update snapshot to current value so flush_modified_entries doesn't record a duplicate.
        self.claimable_balance_snapshots.insert(key, Some(entry));
    }

    // ==================== Liquidity Pool Operations ====================

    /// Get a liquidity pool by ID (read-only).
    pub fn get_liquidity_pool(&self, pool_id: &PoolId) -> Option<&LiquidityPoolEntry> {
        let key = pool_id_to_bytes(pool_id);
        self.liquidity_pools.get(&key)
    }

    /// Get a mutable reference to a liquidity pool.
    pub fn get_liquidity_pool_mut(&mut self, pool_id: &PoolId) -> Option<&mut LiquidityPoolEntry> {
        let key = pool_id_to_bytes(pool_id);
        if self.liquidity_pools.contains_key(&key) {
            // Save snapshot if not already saved or if it's None (for newly created entries).
            // For newly created entries, we update the snapshot to the current value so
            // subsequent operations can track changes with STATE/UPDATED pairs.
            // Rollback correctness is ensured by the created_liquidity_pools set.
            if !self
                .liquidity_pool_snapshots
                .get(&key)
                .is_some_and(|s| s.is_some())
            {
                let snapshot = self.liquidity_pools.get(&key).cloned();
                self.liquidity_pool_snapshots.insert(key, snapshot);
            }
            let ledger_key = LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
                liquidity_pool_id: pool_id.clone(),
            });
            self.capture_op_snapshot_for_key(&ledger_key);
            self.snapshot_last_modified_key(&ledger_key);
            // Track modification
            if !self.modified_liquidity_pools.contains(&key) {
                self.modified_liquidity_pools.push(key);
            }
            self.liquidity_pools.get_mut(&key)
        } else {
            None
        }
    }

    /// Create a new liquidity pool entry.
    pub fn create_liquidity_pool(&mut self, entry: LiquidityPoolEntry) {
        let key = pool_id_to_bytes(&entry.liquidity_pool_id);
        let ledger_key = LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: entry.liquidity_pool_id.clone(),
        });

        // Save snapshot (None because it didn't exist)
        self.liquidity_pool_snapshots.entry(key).or_insert(None);
        self.snapshot_last_modified_key(&ledger_key);
        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);

        // Record in delta
        let ledger_entry = self.liquidity_pool_to_ledger_entry(&entry);
        self.delta.record_create(ledger_entry);

        // Insert into state
        self.liquidity_pools.insert(key, entry);

        // Track that this entry was created in this transaction (for rollback)
        self.created_liquidity_pools.insert(key);

        // Track modification
        if !self.modified_liquidity_pools.contains(&key) {
            self.modified_liquidity_pools.push(key);
        }
    }

    /// Update an existing liquidity pool entry.
    pub fn update_liquidity_pool(&mut self, entry: LiquidityPoolEntry) {
        let key = pool_id_to_bytes(&entry.liquidity_pool_id);
        let ledger_key = LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: entry.liquidity_pool_id.clone(),
        });

        // Save snapshot if not already saved
        if !self.liquidity_pool_snapshots.contains_key(&key) {
            let snapshot = self.liquidity_pools.get(&key).cloned();
            self.liquidity_pool_snapshots.insert(key, snapshot);
        }
        self.capture_op_snapshot_for_key(&ledger_key);
        self.snapshot_last_modified_key(&ledger_key);

        // Get pre-state (current value BEFORE this update)
        let pre_state = self
            .liquidity_pools
            .get(&key)
            .map(|e| self.liquidity_pool_to_ledger_entry(e));

        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);

        // Record in delta with pre-state
        let post_state = self.liquidity_pool_to_ledger_entry(&entry);
        if let Some(pre) = pre_state {
            self.delta.record_update(pre, post_state);
        }

        // Update state
        self.liquidity_pools.insert(key, entry);

        // Track modification
        if !self.modified_liquidity_pools.contains(&key) {
            self.modified_liquidity_pools.push(key);
        }
    }

    /// Delete a liquidity pool entry (when pool_shares_trust_line_count reaches 0).
    pub fn delete_liquidity_pool(&mut self, pool_id: &PoolId) {
        let key = pool_id_to_bytes(pool_id);
        let ledger_key = LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: pool_id.clone(),
        });

        // Save snapshot if not already saved
        if !self.liquidity_pool_snapshots.contains_key(&key) {
            let snapshot = self.liquidity_pools.get(&key).cloned();
            self.liquidity_pool_snapshots.insert(key, snapshot);
        }
        self.capture_op_snapshot_for_key(&ledger_key);
        self.snapshot_last_modified_key(&ledger_key);

        // Get pre-state (current value BEFORE deletion)
        let pre_state = self
            .liquidity_pools
            .get(&key)
            .map(|e| self.liquidity_pool_to_ledger_entry(e));

        // Record in delta with pre-state
        if let Some(pre) = pre_state {
            self.delta.record_delete(ledger_key.clone(), pre);
        }

        // Remove from state
        self.clear_entry_sponsorship_metadata(&ledger_key);
        self.liquidity_pools.remove(&key);
        self.remove_last_modified_key(&ledger_key);

        // Track modification (for proper rollback handling)
        if !self.modified_liquidity_pools.contains(&key) {
            self.modified_liquidity_pools.push(key);
        }
    }

    // ==================== Generic Entry Operations ====================

    /// Get an entry by LedgerKey (read-only).
    pub fn get_entry(&self, key: &LedgerKey) -> Option<LedgerEntry> {
        match key {
            LedgerKey::Account(k) => self
                .get_account(&k.account_id)
                .map(|e| self.account_to_ledger_entry(e)),
            LedgerKey::Trustline(k) => {
                let account_key = account_id_to_bytes(&k.account_id);
                let asset_key = AssetKey::from_trustline_asset(&k.asset);
                self.trustlines
                    .get(&(account_key, asset_key))
                    .map(|e| self.trustline_to_ledger_entry(e))
            }
            LedgerKey::Offer(k) => self
                .get_offer(&k.seller_id, k.offer_id)
                .map(|e| self.offer_to_ledger_entry(e)),
            LedgerKey::Data(k) => {
                let name = data_name_to_string(&k.data_name);
                let account_key = account_id_to_bytes(&k.account_id);
                let result = self.get_data(&k.account_id, &name);
                tracing::debug!(
                    "get_entry for Data: account={:02x?}, name={:?}, name_bytes={:?}, found={}",
                    &account_key[..4],
                    name,
                    k.data_name.as_vec(),
                    result.is_some()
                );
                result.map(|e| self.data_to_ledger_entry(e))
            }
            LedgerKey::ContractData(k) => self
                .get_contract_data(&k.contract, &k.key, k.durability)
                .map(|e| self.contract_data_to_ledger_entry(e)),
            LedgerKey::ContractCode(k) => self
                .get_contract_code(&k.hash)
                .map(|e| self.contract_code_to_ledger_entry(e)),
            LedgerKey::Ttl(k) => self
                .get_ttl(&k.key_hash)
                .map(|e| self.ttl_to_ledger_entry(e)),
            LedgerKey::ClaimableBalance(k) => self
                .get_claimable_balance(&k.balance_id)
                .map(|e| self.claimable_balance_to_ledger_entry(e)),
            LedgerKey::LiquidityPool(k) => self
                .get_liquidity_pool(&k.liquidity_pool_id)
                .map(|e| self.liquidity_pool_to_ledger_entry(e)),
            _ => None,
        }
    }

    /// Check if an entry was deleted during this ledger (for Soroban entries).
    ///
    /// This is used to prevent reloading deleted entries from the bucket list.
    /// In C++ stellar-core, deleted entries are tracked in mThreadEntryMap as nullopt,
    /// which prevents subsequent transactions from seeing them. This method provides
    /// equivalent functionality.
    pub fn is_entry_deleted(&self, key: &LedgerKey) -> bool {
        match key {
            LedgerKey::ContractData(k) => {
                let lookup_key = ContractDataKey::new(k.contract.clone(), k.key.clone(), k.durability);
                self.deleted_contract_data.contains(&lookup_key)
            }
            LedgerKey::ContractCode(k) => self.deleted_contract_code.contains(&k.hash.0),
            LedgerKey::Ttl(k) => self.deleted_ttl.contains(&k.key_hash.0),
            _ => false,
        }
    }

    /// Convert an account entry into a ledger entry using current metadata.
    pub fn ledger_entry_for_account(&self, entry: &AccountEntry) -> LedgerEntry {
        self.account_to_ledger_entry(entry)
    }

    /// Get the pre-modification entry snapshot by LedgerKey.
    pub fn snapshot_entry(&self, key: &LedgerKey) -> Option<LedgerEntry> {
        let last_modified = self
            .last_modified_snapshot_for_key(key)
            .unwrap_or_else(|| self.last_modified_for_key(key));
        let ext = self.ledger_entry_ext_for_snapshot(key);

        match key {
            LedgerKey::Account(k) => {
                let account_key = account_id_to_bytes(&k.account_id);
                self.account_snapshots
                    .get(&account_key)
                    .and_then(|entry| entry.clone())
                    .map(|entry| LedgerEntry {
                        last_modified_ledger_seq: last_modified,
                        data: LedgerEntryData::Account(entry),
                        ext,
                    })
            }
            LedgerKey::Trustline(k) => {
                let account_key = account_id_to_bytes(&k.account_id);
                let asset_key = AssetKey::from_trustline_asset(&k.asset);
                self.trustline_snapshots
                    .get(&(account_key, asset_key))
                    .and_then(|entry| entry.clone())
                    .map(|entry| LedgerEntry {
                        last_modified_ledger_seq: last_modified,
                        data: LedgerEntryData::Trustline(entry),
                        ext,
                    })
            }
            LedgerKey::Offer(k) => {
                let seller_key = account_id_to_bytes(&k.seller_id);
                self.offer_snapshots
                    .get(&(seller_key, k.offer_id))
                    .and_then(|entry| entry.clone())
                    .map(|entry| LedgerEntry {
                        last_modified_ledger_seq: last_modified,
                        data: LedgerEntryData::Offer(entry),
                        ext,
                    })
            }
            LedgerKey::Data(k) => {
                let account_key = account_id_to_bytes(&k.account_id);
                let name = data_name_to_string(&k.data_name);
                self.data_snapshots
                    .get(&(account_key, name))
                    .and_then(|entry| entry.clone())
                    .map(|entry| LedgerEntry {
                        last_modified_ledger_seq: last_modified,
                        data: LedgerEntryData::Data(entry),
                        ext,
                    })
            }
            LedgerKey::ContractData(k) => {
                let lookup_key =
                    ContractDataKey::new(k.contract.clone(), k.key.clone(), k.durability);
                self.contract_data_snapshots
                    .get(&lookup_key)
                    .and_then(|entry| entry.clone())
                    .map(|entry| LedgerEntry {
                        last_modified_ledger_seq: last_modified,
                        data: LedgerEntryData::ContractData(entry),
                        ext,
                    })
            }
            LedgerKey::ContractCode(k) => self
                .contract_code_snapshots
                .get(&k.hash.0)
                .and_then(|entry| entry.clone())
                .map(|entry| LedgerEntry {
                    last_modified_ledger_seq: last_modified,
                    data: LedgerEntryData::ContractCode(entry),
                    ext,
                }),
            LedgerKey::Ttl(k) => self
                .ttl_snapshots
                .get(&k.key_hash.0)
                .and_then(|entry| entry.clone())
                .map(|entry| LedgerEntry {
                    last_modified_ledger_seq: last_modified,
                    data: LedgerEntryData::Ttl(entry),
                    ext,
                }),
            LedgerKey::ClaimableBalance(k) => {
                let key_bytes = claimable_balance_id_to_bytes(&k.balance_id);
                self.claimable_balance_snapshots
                    .get(&key_bytes)
                    .and_then(|entry| entry.clone())
                    .map(|entry| LedgerEntry {
                        last_modified_ledger_seq: last_modified,
                        data: LedgerEntryData::ClaimableBalance(entry),
                        ext,
                    })
            }
            LedgerKey::LiquidityPool(k) => {
                let key_bytes = pool_id_to_bytes(&k.liquidity_pool_id);
                self.liquidity_pool_snapshots
                    .get(&key_bytes)
                    .and_then(|entry| entry.clone())
                    .map(|entry| LedgerEntry {
                        last_modified_ledger_seq: last_modified,
                        data: LedgerEntryData::LiquidityPool(entry),
                        ext,
                    })
            }
            _ => None,
        }
    }

    // ==================== Delta Operations ====================

    /// Get the current delta (read-only).
    pub fn delta(&self) -> &LedgerDelta {
        &self.delta
    }

    /// Get the current delta (mutable).
    pub fn delta_mut(&mut self) -> &mut LedgerDelta {
        &mut self.delta
    }

    /// Consume self and return the delta.
    pub fn take_delta(self) -> LedgerDelta {
        self.delta
    }

    /// Check if there are any pending changes.
    pub fn has_changes(&self) -> bool {
        self.delta.has_changes()
    }

    /// Apply a fee refund to the most recent account update in the delta.
    ///
    /// In C++ stellar-core, fee refunds are NOT separate meta changes - they're
    /// incorporated into the final account balance of the existing update.
    /// This method finds the most recent update to the account and adds the refund.
    pub fn apply_refund_to_delta(&mut self, account_id: &AccountId, refund: i64) {
        // Find the most recent update to this account in the delta and add the refund
        self.delta.apply_refund_to_account(account_id, refund);
        // Also update the in-memory account state (without recording a new delta)
        let key = account_id_to_bytes(account_id);
        if let Some(acc) = self.accounts.get_mut(&key) {
            acc.balance += refund;
        }
    }

    // ==================== Savepoint Support ====================

    /// Create a savepoint capturing current state for potential rollback.
    ///
    /// Used for two purposes:
    /// 1. **Per-operation rollback**: Each operation in a multi-op transaction gets
    ///    a savepoint. If the operation fails, `rollback_to_savepoint()` undoes all
    ///    state changes so subsequent operations see clean state (matching C++ nested
    ///    `LedgerTxn` behavior).
    /// 2. **Path payment speculation**: `convert_with_offers_and_pools` runs the
    ///    orderbook path speculatively, rolling back if the pool provides a better rate.
    ///
    /// The savepoint records the current values of all modified entries so
    /// they can be restored if the operation fails or the speculative path is abandoned.
    pub fn create_savepoint(&self) -> Savepoint {
        Savepoint {
            // Clone snapshot maps (small: only entries modified in current TX)
            offer_snapshots: self.offer_snapshots.clone(),
            account_snapshots: self.account_snapshots.clone(),
            trustline_snapshots: self.trustline_snapshots.clone(),
            data_snapshots: self.data_snapshots.clone(),
            contract_data_snapshots: self.contract_data_snapshots.clone(),
            contract_code_snapshots: self.contract_code_snapshots.clone(),
            ttl_snapshots: self.ttl_snapshots.clone(),
            claimable_balance_snapshots: self.claimable_balance_snapshots.clone(),
            liquidity_pool_snapshots: self.liquidity_pool_snapshots.clone(),

            // Save current values of entries in snapshot maps (pre-savepoint values)
            offer_pre_values: self
                .offer_snapshots
                .keys()
                .map(|k| (*k, self.offers.get(k).cloned()))
                .collect(),
            account_pre_values: self
                .account_snapshots
                .keys()
                .map(|k| (*k, self.accounts.get(k).cloned()))
                .collect(),
            trustline_pre_values: self
                .trustline_snapshots
                .keys()
                .map(|k| (k.clone(), self.trustlines.get(k).cloned()))
                .collect(),
            data_pre_values: self
                .data_snapshots
                .keys()
                .map(|k| (k.clone(), self.data_entries.get(k).cloned()))
                .collect(),
            contract_data_pre_values: self
                .contract_data_snapshots
                .keys()
                .map(|k| (k.clone(), self.contract_data.get(k).cloned()))
                .collect(),
            contract_code_pre_values: self
                .contract_code_snapshots
                .keys()
                .map(|k| (*k, self.contract_code.get(k).cloned()))
                .collect(),
            ttl_pre_values: self
                .ttl_snapshots
                .keys()
                .map(|k| (*k, self.ttl_entries.get(k).cloned()))
                .collect(),
            claimable_balance_pre_values: self
                .claimable_balance_snapshots
                .keys()
                .map(|k| (*k, self.claimable_balances.get(k).cloned()))
                .collect(),
            liquidity_pool_pre_values: self
                .liquidity_pool_snapshots
                .keys()
                .map(|k| (*k, self.liquidity_pools.get(k).cloned()))
                .collect(),

            // Created entry sets
            created_offers: self.created_offers.clone(),
            created_accounts: self.created_accounts.clone(),
            created_trustlines: self.created_trustlines.clone(),
            created_data: self.created_data.clone(),
            created_contract_data: self.created_contract_data.clone(),
            created_contract_code: self.created_contract_code.clone(),
            created_ttl: self.created_ttl.clone(),
            created_claimable_balances: self.created_claimable_balances.clone(),
            created_liquidity_pools: self.created_liquidity_pools.clone(),

            // Delta and modified vec lengths
            delta_lengths: self.delta.snapshot_lengths(),
            modified_accounts_len: self.modified_accounts.len(),
            modified_trustlines_len: self.modified_trustlines.len(),
            modified_offers_len: self.modified_offers.len(),
            modified_data_len: self.modified_data.len(),
            modified_contract_data_len: self.modified_contract_data.len(),
            modified_contract_code_len: self.modified_contract_code.len(),
            modified_ttl_len: self.modified_ttl.len(),
            modified_claimable_balances_len: self.modified_claimable_balances.len(),
            modified_liquidity_pools_len: self.modified_liquidity_pools.len(),

            // Entry metadata
            entry_last_modified_snapshots: self.entry_last_modified_snapshots.clone(),
            entry_last_modified_pre_values: self
                .entry_last_modified_snapshots
                .keys()
                .map(|k| (k.clone(), self.entry_last_modified.get(k).cloned()))
                .collect(),
            entry_sponsorship_snapshots: self.entry_sponsorship_snapshots.clone(),
            entry_sponsorship_ext_snapshots: self.entry_sponsorship_ext_snapshots.clone(),
            entry_sponsorship_pre_values: self
                .entry_sponsorship_snapshots
                .keys()
                .map(|k| (k.clone(), self.entry_sponsorships.get(k).cloned()))
                .collect(),
            entry_sponsorship_ext_pre_values: self
                .entry_sponsorship_ext_snapshots
                .keys()
                .map(|k| (k.clone(), self.entry_sponsorship_ext.contains(k)))
                .collect(),

            op_entry_snapshot_keys: self.op_entry_snapshots.keys().cloned().collect(),
            id_pool: self.id_pool,
        }
    }

    /// Rollback state to a previously created savepoint.
    ///
    /// Undoes all modifications made since the savepoint was created,
    /// restoring entries to their pre-speculation values. This is O(k)
    /// where k = entries modified during speculation (typically < 50),
    /// compared to O(n) for cloning 911K+ offers.
    pub fn rollback_to_savepoint(&mut self, sp: Savepoint) {
        // Phase 1: Restore entries newly snapshot'd since the savepoint.
        // These entries have snapshots added after the savepoint, so their
        // snapshot values ARE their pre-savepoint (= pre-TX) values.

        // Offers: collect new snapshot keys first to avoid borrow conflict
        let new_offer_keys: Vec<_> = self
            .offer_snapshots
            .keys()
            .filter(|k| !sp.offer_snapshots.contains_key(k))
            .cloned()
            .collect();
        let new_offer_snapshots: Vec<_> = new_offer_keys
            .into_iter()
            .filter_map(|key| {
                self.offer_snapshots
                    .get(&key)
                    .map(|snap| (key, snap.clone()))
            })
            .collect();
        for (key, snapshot) in new_offer_snapshots {
            let offer_key = OfferKey::new(key.0, key.1);
            if let Some(current) = self.offers.get(&key).cloned() {
                self.aa_index_remove(&current);
            }
            match snapshot {
                Some(entry) => {
                    self.aa_index_insert(&entry);
                    self.offer_index.update_offer(&entry);
                    self.offers.insert(key, entry);
                }
                None => {
                    self.offer_index.remove_by_key(&offer_key);
                    self.offers.remove(&key);
                }
            }
        }

        // Accounts: restore newly snapshot'd entries
        let new_account_keys: Vec<_> = self
            .account_snapshots
            .keys()
            .filter(|k| !sp.account_snapshots.contains_key(*k))
            .cloned()
            .collect();
        for key in new_account_keys {
            if let Some(snapshot) = self.account_snapshots.get(&key) {
                match snapshot {
                    Some(entry) => {
                        self.accounts.insert(key, entry.clone());
                    }
                    None => {
                        self.accounts.remove(&key);
                    }
                }
            }
        }

        // Trustlines: restore newly snapshot'd entries
        let new_trustline_keys: Vec<_> = self
            .trustline_snapshots
            .keys()
            .filter(|k| !sp.trustline_snapshots.contains_key(k))
            .cloned()
            .collect();
        for key in new_trustline_keys {
            if let Some(snapshot) = self.trustline_snapshots.get(&key) {
                match snapshot {
                    Some(entry) => {
                        self.trustlines.insert(key.clone(), entry.clone());
                    }
                    None => {
                        self.trustlines.remove(&key);
                    }
                }
            }
        }

        // Data entries: restore newly snapshot'd entries
        let new_data_keys: Vec<_> = self
            .data_snapshots
            .keys()
            .filter(|k| !sp.data_snapshots.contains_key(k))
            .cloned()
            .collect();
        for key in new_data_keys {
            if let Some(snapshot) = self.data_snapshots.get(&key) {
                match snapshot {
                    Some(entry) => {
                        self.data_entries.insert(key, entry.clone());
                    }
                    None => {
                        self.data_entries.remove(&key);
                    }
                }
            }
        }

        // Contract data: restore newly snapshot'd entries
        let new_cd_keys: Vec<_> = self
            .contract_data_snapshots
            .keys()
            .filter(|k| !sp.contract_data_snapshots.contains_key(k))
            .cloned()
            .collect();
        for key in new_cd_keys {
            if let Some(snapshot) = self.contract_data_snapshots.get(&key) {
                match snapshot {
                    Some(entry) => {
                        self.contract_data.insert(key, entry.clone());
                    }
                    None => {
                        self.contract_data.remove(&key);
                    }
                }
            }
        }

        // Contract code: restore newly snapshot'd entries
        let new_cc_keys: Vec<_> = self
            .contract_code_snapshots
            .keys()
            .filter(|k| !sp.contract_code_snapshots.contains_key(*k))
            .copied()
            .collect();
        for key in new_cc_keys {
            if let Some(snapshot) = self.contract_code_snapshots.get(&key) {
                match snapshot {
                    Some(entry) => {
                        self.contract_code.insert(key, entry.clone());
                    }
                    None => {
                        self.contract_code.remove(&key);
                    }
                }
            }
        }

        // TTL entries: restore newly snapshot'd entries
        let new_ttl_keys: Vec<_> = self
            .ttl_snapshots
            .keys()
            .filter(|k| !sp.ttl_snapshots.contains_key(*k))
            .copied()
            .collect();
        for key in new_ttl_keys {
            if let Some(snapshot) = self.ttl_snapshots.get(&key) {
                match snapshot {
                    Some(entry) => {
                        self.ttl_entries.insert(key, entry.clone());
                    }
                    None => {
                        self.ttl_entries.remove(&key);
                    }
                }
            }
        }

        // Claimable balances: restore newly snapshot'd entries
        let new_cb_keys: Vec<_> = self
            .claimable_balance_snapshots
            .keys()
            .filter(|k| !sp.claimable_balance_snapshots.contains_key(*k))
            .copied()
            .collect();
        for key in new_cb_keys {
            if let Some(snapshot) = self.claimable_balance_snapshots.get(&key) {
                match snapshot {
                    Some(entry) => {
                        self.claimable_balances.insert(key, entry.clone());
                    }
                    None => {
                        self.claimable_balances.remove(&key);
                    }
                }
            }
        }

        // Liquidity pools: restore newly snapshot'd entries
        let new_lp_keys: Vec<_> = self
            .liquidity_pool_snapshots
            .keys()
            .filter(|k| !sp.liquidity_pool_snapshots.contains_key(*k))
            .copied()
            .collect();
        for key in new_lp_keys {
            if let Some(snapshot) = self.liquidity_pool_snapshots.get(&key) {
                match snapshot {
                    Some(entry) => {
                        self.liquidity_pools.insert(key, entry.clone());
                    }
                    None => {
                        self.liquidity_pools.remove(&key);
                    }
                }
            }
        }

        // Phase 2: Restore pre-savepoint values for entries already in snapshot maps.
        // These were modified before the savepoint AND potentially re-modified since.
        for (key, value) in sp.offer_pre_values {
            let offer_key = OfferKey::new(key.0, key.1);
            if let Some(current) = self.offers.get(&key).cloned() {
                self.aa_index_remove(&current);
            }
            match value {
                Some(entry) => {
                    self.aa_index_insert(&entry);
                    self.offer_index.update_offer(&entry);
                    self.offers.insert(key, entry);
                }
                None => {
                    self.offer_index.remove_by_key(&offer_key);
                    self.offers.remove(&key);
                }
            }
        }

        for (key, value) in sp.account_pre_values {
            match value {
                Some(entry) => {
                    self.accounts.insert(key, entry);
                }
                None => {
                    self.accounts.remove(&key);
                }
            }
        }

        for (key, value) in sp.trustline_pre_values {
            match value {
                Some(entry) => {
                    self.trustlines.insert(key, entry);
                }
                None => {
                    self.trustlines.remove(&key);
                }
            }
        }

        for (key, value) in sp.data_pre_values {
            match value {
                Some(entry) => {
                    self.data_entries.insert(key, entry);
                }
                None => {
                    self.data_entries.remove(&key);
                }
            }
        }

        for (key, value) in sp.contract_data_pre_values {
            match value {
                Some(entry) => {
                    self.contract_data.insert(key, entry);
                }
                None => {
                    self.contract_data.remove(&key);
                }
            }
        }

        for (key, value) in sp.contract_code_pre_values {
            match value {
                Some(entry) => {
                    self.contract_code.insert(key, entry);
                }
                None => {
                    self.contract_code.remove(&key);
                }
            }
        }

        for (key, value) in sp.ttl_pre_values {
            match value {
                Some(entry) => {
                    self.ttl_entries.insert(key, entry);
                }
                None => {
                    self.ttl_entries.remove(&key);
                }
            }
        }

        for (key, value) in sp.claimable_balance_pre_values {
            match value {
                Some(entry) => {
                    self.claimable_balances.insert(key, entry);
                }
                None => {
                    self.claimable_balances.remove(&key);
                }
            }
        }

        for (key, value) in sp.liquidity_pool_pre_values {
            match value {
                Some(entry) => {
                    self.liquidity_pools.insert(key, entry);
                }
                None => {
                    self.liquidity_pools.remove(&key);
                }
            }
        }

        // Phase 3: Restore snapshot maps and created sets
        self.offer_snapshots = sp.offer_snapshots;
        self.account_snapshots = sp.account_snapshots;
        self.trustline_snapshots = sp.trustline_snapshots;
        self.data_snapshots = sp.data_snapshots;
        self.contract_data_snapshots = sp.contract_data_snapshots;
        self.contract_code_snapshots = sp.contract_code_snapshots;
        self.ttl_snapshots = sp.ttl_snapshots;
        self.claimable_balance_snapshots = sp.claimable_balance_snapshots;
        self.liquidity_pool_snapshots = sp.liquidity_pool_snapshots;

        self.created_offers = sp.created_offers;
        self.created_accounts = sp.created_accounts;
        self.created_trustlines = sp.created_trustlines;
        self.created_data = sp.created_data;
        self.created_contract_data = sp.created_contract_data;
        self.created_contract_code = sp.created_contract_code;
        self.created_ttl = sp.created_ttl;
        self.created_claimable_balances = sp.created_claimable_balances;
        self.created_liquidity_pools = sp.created_liquidity_pools;

        // Phase 4: Truncate delta
        self.delta.truncate_to(&sp.delta_lengths);

        // Phase 5: Truncate modified tracking vecs
        self.modified_accounts.truncate(sp.modified_accounts_len);
        self.modified_trustlines
            .truncate(sp.modified_trustlines_len);
        self.modified_offers.truncate(sp.modified_offers_len);
        self.modified_data.truncate(sp.modified_data_len);
        self.modified_contract_data
            .truncate(sp.modified_contract_data_len);
        self.modified_contract_code
            .truncate(sp.modified_contract_code_len);
        self.modified_ttl.truncate(sp.modified_ttl_len);
        self.modified_claimable_balances
            .truncate(sp.modified_claimable_balances_len);
        self.modified_liquidity_pools
            .truncate(sp.modified_liquidity_pools_len);

        // Phase 6: Restore entry metadata

        // entry_last_modified: restore new entries from snapshots
        let new_lm_keys: Vec<_> = self
            .entry_last_modified_snapshots
            .keys()
            .filter(|k| !sp.entry_last_modified_snapshots.contains_key(k))
            .cloned()
            .collect();
        for key in new_lm_keys {
            if let Some(snapshot) = self.entry_last_modified_snapshots.get(&key) {
                match snapshot {
                    Some(seq) => {
                        self.entry_last_modified.insert(key, *seq);
                    }
                    None => {
                        self.entry_last_modified.remove(&key);
                    }
                }
            }
        }
        for (key, value) in sp.entry_last_modified_pre_values {
            match value {
                Some(seq) => {
                    self.entry_last_modified.insert(key, seq);
                }
                None => {
                    self.entry_last_modified.remove(&key);
                }
            }
        }
        self.entry_last_modified_snapshots = sp.entry_last_modified_snapshots;

        // entry_sponsorships: restore new entries from snapshots
        let new_sp_keys: Vec<_> = self
            .entry_sponsorship_snapshots
            .keys()
            .filter(|k| !sp.entry_sponsorship_snapshots.contains_key(k))
            .cloned()
            .collect();
        for key in new_sp_keys {
            if let Some(snapshot) = self.entry_sponsorship_snapshots.get(&key) {
                match snapshot {
                    Some(sponsor) => {
                        self.entry_sponsorships.insert(key, sponsor.clone());
                    }
                    None => {
                        self.entry_sponsorships.remove(&key);
                    }
                }
            }
        }
        for (key, value) in sp.entry_sponsorship_pre_values {
            match value {
                Some(sponsor) => {
                    self.entry_sponsorships.insert(key, sponsor);
                }
                None => {
                    self.entry_sponsorships.remove(&key);
                }
            }
        }
        self.entry_sponsorship_snapshots = sp.entry_sponsorship_snapshots;

        // entry_sponsorship_ext: restore
        let new_ext_keys: Vec<_> = self
            .entry_sponsorship_ext_snapshots
            .keys()
            .filter(|k| !sp.entry_sponsorship_ext_snapshots.contains_key(k))
            .cloned()
            .collect();
        for key in new_ext_keys {
            if let Some(&was_present) = self.entry_sponsorship_ext_snapshots.get(&key) {
                if was_present {
                    self.entry_sponsorship_ext.insert(key);
                } else {
                    self.entry_sponsorship_ext.remove(&key);
                }
            }
        }
        for (key, was_present) in sp.entry_sponsorship_ext_pre_values {
            if was_present {
                self.entry_sponsorship_ext.insert(key);
            } else {
                self.entry_sponsorship_ext.remove(&key);
            }
        }
        self.entry_sponsorship_ext_snapshots = sp.entry_sponsorship_ext_snapshots;

        // Phase 7: Restore op entry snapshots and id_pool
        self.op_entry_snapshots
            .retain(|k, _| sp.op_entry_snapshot_keys.contains(k));
        self.id_pool = sp.id_pool;
    }

    // ==================== Rollback Support ====================

    /// Rollback all changes since the state manager was created.
    ///
    /// This restores all entries to their original state and clears the delta.
    pub fn rollback(&mut self) {
        // Restore id_pool snapshot if present (must be done before entry snapshots
        // since offer IDs need to be correct for subsequent transactions)
        if let Some(snapshot) = self.id_pool_snapshot.take() {
            self.id_pool = snapshot;
        }

        // Restore account snapshots. Entries created in this transaction are removed,
        // others are restored from their snapshot.
        for (key, snapshot) in self.account_snapshots.drain() {
            if self.created_accounts.contains(&key) {
                // Entry was created in this transaction - remove it
                self.accounts.remove(&key);
            } else if let Some(entry) = snapshot {
                // Entry existed before - restore it
                self.accounts.insert(key, entry);
            }
        }
        self.created_accounts.clear();

        // Restore trustline snapshots
        for (key, snapshot) in self.trustline_snapshots.drain() {
            if self.created_trustlines.contains(&key) {
                self.trustlines.remove(&key);
            } else if let Some(entry) = snapshot {
                self.trustlines.insert(key, entry);
            }
        }
        self.created_trustlines.clear();

        // Restore offer snapshots and incrementally update the index.
        // Instead of rebuilding the full index from scratch (O(n log n) for all offers),
        // we only undo index changes for offers touched by this transaction.
        let offer_snapshots: Vec<_> = self.offer_snapshots.drain().collect();
        for (key, snapshot) in offer_snapshots {
            let offer_key = OfferKey::new(key.0, key.1);
            if self.created_offers.contains(&key) {
                // Offer was created in this transaction — remove from index and map.
                if let Some(current) = self.offers.get(&key).cloned() {
                    self.aa_index_remove(&current);
                }
                self.offer_index.remove_by_key(&offer_key);
                self.offers.remove(&key);
            } else if let Some(entry) = snapshot {
                // Offer existed before — restore it and update index.
                if let Some(current) = self.offers.get(&key).cloned() {
                    self.aa_index_remove(&current);
                }
                self.aa_index_insert(&entry);
                self.offer_index.update_offer(&entry);
                self.offers.insert(key, entry);
            }
        }
        self.created_offers.clear();

        // Restore data entry snapshots
        for (key, snapshot) in self.data_snapshots.drain() {
            if self.created_data.contains(&key) {
                self.data_entries.remove(&key);
            } else if let Some(entry) = snapshot {
                self.data_entries.insert(key, entry);
            }
        }
        self.created_data.clear();

        // Restore contract data snapshots
        for (key, snapshot) in self.contract_data_snapshots.drain() {
            if self.created_contract_data.contains(&key) {
                self.contract_data.remove(&key);
            } else if let Some(entry) = snapshot {
                self.contract_data.insert(key, entry);
            }
        }
        self.created_contract_data.clear();

        // Restore contract code snapshots
        for (key, snapshot) in self.contract_code_snapshots.drain() {
            if self.created_contract_code.contains(&key) {
                self.contract_code.remove(&key);
            } else if let Some(entry) = snapshot {
                self.contract_code.insert(key, entry);
            }
        }
        self.created_contract_code.clear();

        // Restore TTL entry snapshots
        for (key, snapshot) in self.ttl_snapshots.drain() {
            if self.created_ttl.contains(&key) {
                self.ttl_entries.remove(&key);
            } else if let Some(entry) = snapshot {
                self.ttl_entries.insert(key, entry);
            }
        }
        self.created_ttl.clear();

        // Restore claimable balance snapshots
        for (key, snapshot) in self.claimable_balance_snapshots.drain() {
            if self.created_claimable_balances.contains(&key) {
                self.claimable_balances.remove(&key);
            } else if let Some(entry) = snapshot {
                self.claimable_balances.insert(key, entry);
            }
        }
        self.created_claimable_balances.clear();

        // Restore liquidity pool snapshots
        for (key, snapshot) in self.liquidity_pool_snapshots.drain() {
            if self.created_liquidity_pools.contains(&key) {
                self.liquidity_pools.remove(&key);
            } else if let Some(entry) = snapshot {
                self.liquidity_pools.insert(key, entry);
            }
        }
        self.created_liquidity_pools.clear();

        // Restore entry sponsorship snapshots
        for (key, snapshot) in self.entry_sponsorship_snapshots.drain() {
            match snapshot {
                Some(entry) => {
                    self.entry_sponsorships.insert(key, entry);
                }
                None => {
                    self.entry_sponsorships.remove(&key);
                }
            }
        }

        // Restore sponsorship extension snapshots
        for (key, snapshot) in self.entry_sponsorship_ext_snapshots.drain() {
            if snapshot {
                self.entry_sponsorship_ext.insert(key);
            } else {
                self.entry_sponsorship_ext.remove(&key);
            }
        }

        // Restore last modified snapshots
        for (key, snapshot) in self.entry_last_modified_snapshots.drain() {
            match snapshot {
                Some(seq) => {
                    self.entry_last_modified.insert(key, seq);
                }
                None => {
                    self.entry_last_modified.remove(&key);
                }
            }
        }

        // Clear modification tracking
        self.modified_accounts.clear();
        self.modified_trustlines.clear();
        self.modified_offers.clear();
        self.modified_data.clear();
        self.modified_contract_data.clear();
        self.modified_contract_code.clear();
        self.modified_ttl.clear();
        self.modified_claimable_balances.clear();
        self.modified_liquidity_pools.clear();

        // Restore delta from snapshot if available, otherwise reset it.
        // This preserves committed changes from previous transactions in this ledger.
        // The fee for the current transaction was already added during fee deduction
        // phase (before operations ran) and is restored via restore_delta_entries()
        // in execution.rs after rollback() returns.
        if let Some(snapshot) = self.delta_snapshot.take() {
            self.delta = snapshot;
        } else {
            // No snapshot - reset delta but preserve fee_charged.
            let fee_charged = self.delta.fee_charged();
            self.delta = LedgerDelta::new(self.ledger_seq);
            if fee_charged != 0 {
                self.delta.add_fee(fee_charged);
            }
        }
    }

    /// Commit changes by clearing snapshots (changes become permanent).
    pub fn commit(&mut self) {
        // Clear id_pool snapshot (the incremented value is now committed)
        self.id_pool_snapshot = None;

        // NOTE: Do NOT clear delta_snapshot here. The delta_snapshot is used to preserve
        // committed changes from PREVIOUS transactions in a ledger, so it should only
        // be set/cleared at transaction boundaries (via snapshot_delta()) or when
        // starting a new ledger (via clear_cached_entries()).

        // Clear all snapshots
        self.account_snapshots.clear();
        self.trustline_snapshots.clear();
        self.offer_snapshots.clear();
        self.data_snapshots.clear();
        self.contract_data_snapshots.clear();
        self.contract_code_snapshots.clear();
        self.ttl_snapshots.clear();
        self.claimable_balance_snapshots.clear();
        self.liquidity_pool_snapshots.clear();
        self.entry_sponsorship_snapshots.clear();
        self.entry_last_modified_snapshots.clear();

        // Clear modification tracking
        self.modified_accounts.clear();
        self.modified_trustlines.clear();
        self.modified_offers.clear();
        self.modified_data.clear();
        self.modified_contract_data.clear();
        self.modified_contract_code.clear();
        self.modified_ttl.clear();
        self.modified_claimable_balances.clear();
        self.modified_liquidity_pools.clear();

        // Clear created entry tracking
        self.created_accounts.clear();
        self.created_trustlines.clear();
        self.created_offers.clear();
        self.created_data.clear();
        self.created_contract_data.clear();
        self.created_contract_code.clear();
        self.created_ttl.clear();
        self.created_claimable_balances.clear();
        self.created_liquidity_pools.clear();
    }

    /// Flush all pending account changes to the delta, excluding a specific account.
    ///
    /// This flushes only accounts, not trustlines or other entry types.
    /// Used when an operation needs to ensure all account changes are recorded
    /// before recording trustline changes (e.g., before deleting a trustline).
    ///
    /// The `exclude` parameter specifies an account to skip (e.g., an account
    /// that's about to be deleted). If None, all accounts are flushed.
    pub fn flush_all_accounts_except(&mut self, exclude: Option<&AccountId>) {
        let exclude_key = exclude.map(crate::account_id_to_key);
        let modified_accounts = std::mem::take(&mut self.modified_accounts);
        let mut remaining = Vec::new();
        for key in modified_accounts {
            if exclude_key == Some(key) {
                // Keep excluded account in modified list (will be handled by delete)
                remaining.push(key);
                continue;
            }
            if let Some(Some(snapshot_entry)) = self.account_snapshots.get(&key) {
                if let Some(entry) = self.accounts.get(&key).cloned() {
                    // Build ledger key for op_snapshot lookup
                    let ledger_key = LedgerKey::Account(LedgerKeyAccount {
                        account_id: entry.account_id.clone(),
                    });
                    // Record update if:
                    // 1. Entry was accessed during operation (in op_entry_snapshots) - C++ records all loadAccount calls
                    // 2. Entry actually changed - always record real value changes
                    // 3. multi_op_mode is enabled - record every access for multi-op transactions
                    let accessed_in_op = self.op_snapshots_active
                        && self.op_entry_snapshots.contains_key(&ledger_key);
                    let should_record =
                        accessed_in_op || self.multi_op_mode || &entry != snapshot_entry;
                    if should_record {
                        let pre_state = if self.op_snapshots_active {
                            self.op_entry_snapshots
                                .get(&ledger_key)
                                .cloned()
                                .unwrap_or_else(|| self.account_to_ledger_entry(snapshot_entry))
                        } else {
                            self.account_to_ledger_entry(snapshot_entry)
                        };
                        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);
                        let post_state = self.account_to_ledger_entry(&entry);
                        self.delta.record_update(pre_state, post_state);
                        self.account_snapshots.insert(key, Some(entry));
                    }
                }
            }
        }
        self.modified_accounts = remaining;
    }

    /// Flush all pending account changes to the delta.
    ///
    /// This flushes only accounts, not trustlines or other entry types.
    /// Used when an operation needs to ensure all account changes are recorded
    /// before recording trustline changes (e.g., before deleting a trustline).
    pub fn flush_all_accounts(&mut self) {
        self.flush_all_accounts_except(None);
    }

    /// Flush a specific account's changes to the delta.
    ///
    /// Returns true if the account was in the modified list and was flushed.
    pub fn flush_account(&mut self, account_id: &AccountId) -> bool {
        let key = crate::account_id_to_key(account_id);
        let pos = self.modified_accounts.iter().position(|k| k == &key);
        if let Some(pos) = pos {
            self.modified_accounts.remove(pos);
            if let Some(Some(snapshot_entry)) = self.account_snapshots.get(&key) {
                if let Some(entry) = self.accounts.get(&key).cloned() {
                    // For single-operation transactions, only record if entry actually changed.
                    // For multi-operation transactions, record for every access (even if no change)
                    // because C++ stellar-core records per-operation entries for multi-op txs.
                    let should_record = self.multi_op_mode || &entry != snapshot_entry;
                    if should_record {
                        let pre_state = self.account_to_ledger_entry(snapshot_entry);
                        let ledger_key = LedgerKey::Account(LedgerKeyAccount {
                            account_id: account_id.clone(),
                        });
                        self.set_last_modified_key(ledger_key, self.ledger_seq);
                        let post_state = self.account_to_ledger_entry(&entry);
                        self.delta.record_update(pre_state, post_state);
                        self.account_snapshots.insert(key, Some(entry));
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Record updates for mutated entries into the delta and clear modification tracking.
    ///
    /// This is needed for operations that mutate entries through `get_*_mut`,
    /// which do not call `record_update` directly.
    ///
    /// For per-operation STATE values, we use op_entry_snapshots (captured at access time)
    /// rather than transaction-level snapshots. This allows correct per-op change recording
    /// while preserving transaction-level snapshots for rollback.
    pub fn flush_modified_entries(&mut self) {
        let modified_accounts = std::mem::take(&mut self.modified_accounts);
        for key in modified_accounts {
            if let Some(Some(snapshot_entry)) = self.account_snapshots.get(&key) {
                if let Some(entry) = self.accounts.get(&key).cloned() {
                    // Build ledger key for op_snapshot lookup
                    let ledger_key = LedgerKey::Account(LedgerKeyAccount {
                        account_id: entry.account_id.clone(),
                    });
                    // Record update if:
                    // 1. Entry was accessed during operation (in op_entry_snapshots) - C++ records all loadAccount calls
                    // 2. Entry actually changed - always record real value changes
                    // Note: We use accessed_in_op for both single-op and multi-op transactions because
                    // C++ stellar-core records per-operation changes only for entries actually accessed.
                    let accessed_in_op = self.op_snapshots_active
                        && self.op_entry_snapshots.contains_key(&ledger_key);
                    let should_record = accessed_in_op || &entry != snapshot_entry;
                    if should_record {
                        // Use op_entry_snapshots for STATE if available (captures per-op state correctly)
                        // Otherwise fall back to transaction-level snapshot
                        let pre_state =
                            if let Some(op_snapshot) = self.op_entry_snapshots.get(&ledger_key) {
                                op_snapshot.clone()
                            } else {
                                self.account_to_ledger_entry(snapshot_entry)
                            };
                        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);
                        let post_state = self.account_to_ledger_entry(&entry);
                        self.delta.record_update(pre_state, post_state);
                        // DO NOT update account_snapshots - preserve for rollback
                    }
                }
            }
        }

        let modified_trustlines = std::mem::take(&mut self.modified_trustlines);
        for key in modified_trustlines {
            if let Some(Some(snapshot_entry)) = self.trustline_snapshots.get(&key) {
                if let Some(entry) = self.trustlines.get(&key).cloned() {
                    // Build ledger key for op_snapshot lookup
                    let ledger_key = LedgerKey::Trustline(LedgerKeyTrustLine {
                        account_id: entry.account_id.clone(),
                        asset: entry.asset.clone(),
                    });
                    // Record update if:
                    // 1. Entry was accessed during operation (in op_entry_snapshots) - C++ records all load calls
                    // 2. Entry actually changed - always record real value changes
                    let accessed_in_op = self.op_snapshots_active
                        && self.op_entry_snapshots.contains_key(&ledger_key);
                    let should_record = accessed_in_op || &entry != snapshot_entry;
                    if should_record {
                        // Use op_entry_snapshots for STATE if available (captures per-op state correctly)
                        // Otherwise fall back to transaction-level snapshot
                        let pre_state =
                            if let Some(op_snapshot) = self.op_entry_snapshots.get(&ledger_key) {
                                op_snapshot.clone()
                            } else {
                                self.trustline_to_ledger_entry(snapshot_entry)
                            };
                        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);
                        let post_state = self.trustline_to_ledger_entry(&entry);
                        self.delta.record_update(pre_state, post_state);
                        // DO NOT update trustline_snapshots - preserve for rollback
                    }
                }
            }
        }

        let modified_offers = std::mem::take(&mut self.modified_offers);
        for key in modified_offers {
            if let Some(Some(snapshot_entry)) = self.offer_snapshots.get(&key) {
                if let Some(entry) = self.offers.get(&key).cloned() {
                    let ledger_key = LedgerKey::Offer(LedgerKeyOffer {
                        seller_id: entry.seller_id.clone(),
                        offer_id: entry.offer_id,
                    });
                    // Record update if:
                    // 1. Entry was accessed during operation (in op_entry_snapshots) - C++ records all load calls
                    //    This is important for sponsorship-only changes where the entry data doesn't change
                    //    but the ext (sponsor) changes.
                    // 2. Entry actually changed - always record real value changes
                    let accessed_in_op = self.op_entry_snapshots.contains_key(&ledger_key);
                    let should_record = accessed_in_op || &entry != snapshot_entry;
                    if should_record {
                        // Use op_entry_snapshots for STATE if available (captures per-op state correctly)
                        // Otherwise fall back to transaction-level snapshot
                        let pre_state =
                            if let Some(op_snapshot) = self.op_entry_snapshots.get(&ledger_key) {
                                op_snapshot.clone()
                            } else {
                                self.offer_to_ledger_entry(snapshot_entry)
                            };
                        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);
                        let post_state = self.offer_to_ledger_entry(&entry);
                        self.delta.record_update(pre_state, post_state);
                        // DO NOT update offer_snapshots - preserve for rollback
                    }
                }
            }
        }

        let modified_data = std::mem::take(&mut self.modified_data);
        for key in modified_data {
            if let Some(Some(snapshot_entry)) = self.data_snapshots.get(&key) {
                if let Some(entry) = self.data_entries.get(&key).cloned() {
                    // Build ledger key for op_snapshot lookup
                    let ledger_key = LedgerKey::Data(LedgerKeyData {
                        account_id: entry.account_id.clone(),
                        data_name: entry.data_name.clone(),
                    });
                    // Record update if:
                    // 1. Entry was accessed during operation (in op_entry_snapshots) - C++ records all load calls
                    // 2. Entry actually changed - always record real value changes
                    let accessed_in_op = self.op_snapshots_active
                        && self.op_entry_snapshots.contains_key(&ledger_key);
                    let should_record = accessed_in_op || &entry != snapshot_entry;
                    if should_record {
                        // Use op_entry_snapshots for STATE if available (captures per-op state correctly)
                        // Otherwise fall back to transaction-level snapshot
                        let pre_state =
                            if let Some(op_snapshot) = self.op_entry_snapshots.get(&ledger_key) {
                                op_snapshot.clone()
                            } else {
                                self.data_to_ledger_entry(snapshot_entry)
                            };
                        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);
                        let post_state = self.data_to_ledger_entry(&entry);
                        self.delta.record_update(pre_state, post_state);
                        // DO NOT update data_snapshots - preserve for rollback
                    }
                }
            }
        }

        let modified_contract_data = std::mem::take(&mut self.modified_contract_data);
        for key in modified_contract_data {
            if let Some(Some(snapshot_entry)) = self.contract_data_snapshots.get(&key) {
                if let Some(entry) = self.contract_data.get(&key).cloned() {
                    // Only record update if entry actually changed from snapshot
                    if &entry != snapshot_entry {
                        let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
                            contract: entry.contract.clone(),
                            key: entry.key.clone(),
                            durability: entry.durability,
                        });
                        // Use op_entry_snapshots for STATE if available (captures per-op state correctly)
                        // Otherwise fall back to transaction-level snapshot
                        let pre_state =
                            if let Some(op_snapshot) = self.op_entry_snapshots.get(&ledger_key) {
                                op_snapshot.clone()
                            } else {
                                self.contract_data_to_ledger_entry(snapshot_entry)
                            };
                        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);
                        let post_state = self.contract_data_to_ledger_entry(&entry);
                        self.delta.record_update(pre_state, post_state);
                        // DO NOT update contract_data_snapshots - preserve for rollback
                    }
                }
            }
        }

        let modified_contract_code = std::mem::take(&mut self.modified_contract_code);
        for key in modified_contract_code {
            if let Some(Some(snapshot_entry)) = self.contract_code_snapshots.get(&key) {
                if let Some(entry) = self.contract_code.get(&key).cloned() {
                    // Only record update if entry actually changed from snapshot
                    if &entry != snapshot_entry {
                        let ledger_key = LedgerKey::ContractCode(LedgerKeyContractCode {
                            hash: entry.hash.clone(),
                        });
                        // Use op_entry_snapshots for STATE if available (captures per-op state correctly)
                        // Otherwise fall back to transaction-level snapshot
                        let pre_state =
                            if let Some(op_snapshot) = self.op_entry_snapshots.get(&ledger_key) {
                                op_snapshot.clone()
                            } else {
                                self.contract_code_to_ledger_entry(snapshot_entry)
                            };
                        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);
                        let post_state = self.contract_code_to_ledger_entry(&entry);
                        self.delta.record_update(pre_state, post_state);
                        // DO NOT update contract_code_snapshots - preserve for rollback
                    }
                }
            }
        }

        let modified_ttl = std::mem::take(&mut self.modified_ttl);
        for key in modified_ttl {
            // Skip entries that were created in this transaction - they already have CREATED recorded
            // and should not get an additional STATE+UPDATED pair
            if self.created_ttl.contains(&key) {
                continue;
            }
            let key_hash = Hash(key);
            tracing::debug!(?key_hash, "flush_modified_entries: processing TTL");
            if let Some(snapshot) = self.ttl_snapshots.get(&key).cloned() {
                tracing::debug!(
                    ?key_hash,
                    has_snapshot_value = snapshot.is_some(),
                    "flush_modified_entries: TTL snapshot state"
                );
                if let Some(snapshot_entry) = snapshot {
                    if let Some(entry) = self.ttl_entries.get(&key).cloned() {
                        // Only record update if entry actually changed from snapshot
                        if entry != snapshot_entry {
                            let ledger_key = LedgerKey::Ttl(LedgerKeyTtl {
                                key_hash: entry.key_hash.clone(),
                            });
                            // Use op_entry_snapshots for STATE if available (captures per-op state correctly)
                            // Otherwise fall back to transaction-level snapshot
                            let pre_state = if let Some(op_snapshot) =
                                self.op_entry_snapshots.get(&ledger_key)
                            {
                                op_snapshot.clone()
                            } else {
                                self.ttl_to_ledger_entry(&snapshot_entry)
                            };
                            self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);
                            let post_state = self.ttl_to_ledger_entry(&entry);
                            tracing::debug!(
                                ?key_hash,
                                pre_live_until = snapshot_entry.live_until_ledger_seq,
                                post_live_until = entry.live_until_ledger_seq,
                                "flush_modified_entries: TTL record_update"
                            );
                            self.delta.record_update(pre_state, post_state);
                            // DO NOT update ttl_snapshots - preserve for rollback
                        }
                    }
                }
            }
        }

        let modified_claimable_balances = std::mem::take(&mut self.modified_claimable_balances);
        for key in modified_claimable_balances {
            if let Some(Some(snapshot_entry)) = self.claimable_balance_snapshots.get(&key) {
                if let Some(entry) = self.claimable_balances.get(&key).cloned() {
                    let ledger_key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
                        balance_id: entry.balance_id.clone(),
                    });
                    // Record update if:
                    // 1. Entry was accessed during operation (in op_entry_snapshots) - C++ records all load calls
                    //    This is important for sponsorship-only changes where the entry data doesn't change
                    //    but the ext (sponsor) changes.
                    // 2. Entry actually changed - always record real value changes
                    let accessed_in_op = self.op_entry_snapshots.contains_key(&ledger_key);
                    let should_record = accessed_in_op || &entry != snapshot_entry;
                    if should_record {
                        // Use op_entry_snapshots for STATE if available (captures per-op state correctly)
                        // Otherwise fall back to transaction-level snapshot
                        let pre_state =
                            if let Some(op_snapshot) = self.op_entry_snapshots.get(&ledger_key) {
                                op_snapshot.clone()
                            } else {
                                self.claimable_balance_to_ledger_entry(snapshot_entry)
                            };
                        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);
                        let post_state = self.claimable_balance_to_ledger_entry(&entry);
                        self.delta.record_update(pre_state, post_state);
                        // DO NOT update claimable_balance_snapshots - preserve for rollback
                    }
                }
            }
        }

        let modified_liquidity_pools = std::mem::take(&mut self.modified_liquidity_pools);
        for key in modified_liquidity_pools {
            if let Some(Some(snapshot_entry)) = self.liquidity_pool_snapshots.get(&key) {
                if let Some(entry) = self.liquidity_pools.get(&key).cloned() {
                    let ledger_key = LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
                        liquidity_pool_id: entry.liquidity_pool_id.clone(),
                    });
                    // Record update if:
                    // 1. Entry was accessed during operation (in op_entry_snapshots) - C++ records all load calls
                    //    This is important for sponsorship-only changes where the entry data doesn't change
                    //    but the ext (sponsor) changes.
                    // 2. Entry actually changed - always record real value changes
                    let accessed_in_op = self.op_entry_snapshots.contains_key(&ledger_key);
                    let should_record = accessed_in_op || &entry != snapshot_entry;
                    if should_record {
                        // Use op_entry_snapshots for STATE if available (captures per-op state correctly)
                        // Otherwise fall back to transaction-level snapshot
                        let pre_state =
                            if let Some(op_snapshot) = self.op_entry_snapshots.get(&ledger_key) {
                                op_snapshot.clone()
                            } else {
                                self.liquidity_pool_to_ledger_entry(snapshot_entry)
                            };
                        self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);
                        let post_state = self.liquidity_pool_to_ledger_entry(&entry);
                        self.delta.record_update(pre_state, post_state);
                        // DO NOT update liquidity_pool_snapshots - preserve for rollback
                    }
                }
            }
        }
    }

    // ==================== Helper Methods ====================

    /// Convert an AccountEntry to a LedgerEntry.
    fn account_to_ledger_entry(&self, entry: &AccountEntry) -> LedgerEntry {
        let ledger_key = LedgerKey::Account(LedgerKeyAccount {
            account_id: entry.account_id.clone(),
        });
        let last_modified = self.last_modified_for_key(&ledger_key);
        LedgerEntry {
            last_modified_ledger_seq: last_modified,
            data: LedgerEntryData::Account(entry.clone()),
            ext: self.ledger_entry_ext_for(&ledger_key),
        }
    }

    /// Convert a TrustLineEntry to a LedgerEntry.
    fn trustline_to_ledger_entry(&self, entry: &TrustLineEntry) -> LedgerEntry {
        let ledger_key = LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: entry.account_id.clone(),
            asset: entry.asset.clone(),
        });
        let last_modified = self.last_modified_for_key(&ledger_key);
        LedgerEntry {
            last_modified_ledger_seq: last_modified,
            data: LedgerEntryData::Trustline(entry.clone()),
            ext: self.ledger_entry_ext_for(&ledger_key),
        }
    }

    /// Convert an OfferEntry to a LedgerEntry.
    fn offer_to_ledger_entry(&self, entry: &OfferEntry) -> LedgerEntry {
        let ledger_key = LedgerKey::Offer(LedgerKeyOffer {
            seller_id: entry.seller_id.clone(),
            offer_id: entry.offer_id,
        });
        let last_modified = self.last_modified_for_key(&ledger_key);
        LedgerEntry {
            last_modified_ledger_seq: last_modified,
            data: LedgerEntryData::Offer(entry.clone()),
            ext: self.ledger_entry_ext_for(&ledger_key),
        }
    }

    /// Convert a DataEntry to a LedgerEntry.
    fn data_to_ledger_entry(&self, entry: &DataEntry) -> LedgerEntry {
        let ledger_key = LedgerKey::Data(LedgerKeyData {
            account_id: entry.account_id.clone(),
            data_name: entry.data_name.clone(),
        });
        let last_modified = self.last_modified_for_key(&ledger_key);
        LedgerEntry {
            last_modified_ledger_seq: last_modified,
            data: LedgerEntryData::Data(entry.clone()),
            ext: self.ledger_entry_ext_for(&ledger_key),
        }
    }

    /// Convert a ContractDataEntry to a LedgerEntry.
    fn contract_data_to_ledger_entry(&self, entry: &ContractDataEntry) -> LedgerEntry {
        let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: entry.contract.clone(),
            key: entry.key.clone(),
            durability: entry.durability,
        });
        let last_modified = self.last_modified_for_key(&ledger_key);
        LedgerEntry {
            last_modified_ledger_seq: last_modified,
            data: LedgerEntryData::ContractData(entry.clone()),
            ext: self.ledger_entry_ext_for(&ledger_key),
        }
    }

    /// Convert a ContractCodeEntry to a LedgerEntry.
    fn contract_code_to_ledger_entry(&self, entry: &ContractCodeEntry) -> LedgerEntry {
        let ledger_key = LedgerKey::ContractCode(LedgerKeyContractCode {
            hash: entry.hash.clone(),
        });
        let last_modified = self.last_modified_for_key(&ledger_key);
        LedgerEntry {
            last_modified_ledger_seq: last_modified,
            data: LedgerEntryData::ContractCode(entry.clone()),
            ext: self.ledger_entry_ext_for(&ledger_key),
        }
    }

    /// Convert a TtlEntry to a LedgerEntry.
    fn ttl_to_ledger_entry(&self, entry: &TtlEntry) -> LedgerEntry {
        let ledger_key = LedgerKey::Ttl(LedgerKeyTtl {
            key_hash: entry.key_hash.clone(),
        });
        let last_modified = self.last_modified_for_key(&ledger_key);
        LedgerEntry {
            last_modified_ledger_seq: last_modified,
            data: LedgerEntryData::Ttl(entry.clone()),
            ext: self.ledger_entry_ext_for(&ledger_key),
        }
    }

    /// Convert a ClaimableBalanceEntry to a LedgerEntry.
    fn claimable_balance_to_ledger_entry(&self, entry: &ClaimableBalanceEntry) -> LedgerEntry {
        let ledger_key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
            balance_id: entry.balance_id.clone(),
        });
        let last_modified = self.last_modified_for_key(&ledger_key);
        LedgerEntry {
            last_modified_ledger_seq: last_modified,
            data: LedgerEntryData::ClaimableBalance(entry.clone()),
            ext: self.ledger_entry_ext_for(&ledger_key),
        }
    }

    /// Convert a LiquidityPoolEntry to a LedgerEntry.
    fn liquidity_pool_to_ledger_entry(&self, entry: &LiquidityPoolEntry) -> LedgerEntry {
        let ledger_key = LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: entry.liquidity_pool_id.clone(),
        });
        let last_modified = self.last_modified_for_key(&ledger_key);
        LedgerEntry {
            last_modified_ledger_seq: last_modified,
            data: LedgerEntryData::LiquidityPool(entry.clone()),
            ext: self.ledger_entry_ext_for(&ledger_key),
        }
    }
}

// ==================== Helper Functions ====================

/// Convert an AccountId to its raw bytes.
fn account_id_to_bytes(account_id: &AccountId) -> [u8; 32] {
    match &account_id.0 {
        PublicKey::PublicKeyTypeEd25519(key) => key.0,
    }
}

/// Convert a String64 data name to a String.
fn data_name_to_string(name: &stellar_xdr::curr::String64) -> String {
    String::from_utf8_lossy(name.as_vec()).to_string()
}

/// Convert an Asset to a TrustLineAsset.
fn asset_to_trustline_asset(asset: &Asset) -> TrustLineAsset {
    match asset {
        Asset::Native => TrustLineAsset::Native,
        Asset::CreditAlphanum4(a) => TrustLineAsset::CreditAlphanum4(a.clone()),
        Asset::CreditAlphanum12(a) => TrustLineAsset::CreditAlphanum12(a.clone()),
    }
}

/// Convert a ClaimableBalanceId to its raw bytes.
fn claimable_balance_id_to_bytes(balance_id: &ClaimableBalanceId) -> [u8; 32] {
    match balance_id {
        ClaimableBalanceId::ClaimableBalanceIdTypeV0(hash) => hash.0,
    }
}

/// Convert a PoolId to its raw bytes.
fn pool_id_to_bytes(pool_id: &PoolId) -> [u8; 32] {
    pool_id.0 .0
}

// These functions are kept for potential debugging use but are superseded by OfferIndex
#[allow(dead_code)]
fn compare_offer(lhs: &OfferEntry, rhs: &OfferEntry) -> std::cmp::Ordering {
    compare_price(&lhs.price, &rhs.price).then_with(|| lhs.offer_id.cmp(&rhs.offer_id))
}

#[allow(dead_code)]
fn compare_price(lhs: &Price, rhs: &Price) -> std::cmp::Ordering {
    // Use floating-point comparison to match C++ stellar-core behavior.
    // The C++ code stores `price = double(price.n) / double(price.d)` in the database
    // and uses `ORDER BY price` for offer ordering. The isBetterOffer function also
    // uses double comparison to match this SQL ordering.
    let lhs_price = lhs.n as f64 / lhs.d as f64;
    let rhs_price = rhs.n as f64 / rhs.d as f64;
    lhs_price
        .partial_cmp(&rhs_price)
        .unwrap_or(std::cmp::Ordering::Equal)
}

fn sponsorship_counts(account: &AccountEntry) -> (i64, i64) {
    match &account.ext {
        AccountEntryExt::V0 => (0, 0),
        AccountEntryExt::V1(v1) => match &v1.ext {
            AccountEntryExtensionV1Ext::V0 => (0, 0),
            AccountEntryExtensionV1Ext::V2(v2) => {
                (v2.num_sponsoring as i64, v2.num_sponsored as i64)
            }
        },
    }
}

fn sponsorship_from_entry_ext(entry: &LedgerEntry) -> Option<AccountId> {
    match &entry.ext {
        LedgerEntryExt::V0 => None,
        LedgerEntryExt::V1(v1) => v1.sponsoring_id.0.clone(),
    }
}

pub(crate) fn ensure_account_ext_v2(account: &mut AccountEntry) -> &mut AccountEntryExtensionV2 {
    let liabilities = match &account.ext {
        AccountEntryExt::V1(v1) => v1.liabilities.clone(),
        AccountEntryExt::V0 => Liabilities {
            buying: 0,
            selling: 0,
        },
    };

    match &account.ext {
        AccountEntryExt::V0 => {
            account.ext = AccountEntryExt::V1(AccountEntryExtensionV1 {
                liabilities,
                ext: AccountEntryExtensionV1Ext::V2(AccountEntryExtensionV2 {
                    num_sponsored: 0,
                    num_sponsoring: 0,
                    signer_sponsoring_i_ds: build_signer_sponsoring_ids(account.signers.len()),
                    ext: AccountEntryExtensionV2Ext::V0,
                }),
            });
        }
        AccountEntryExt::V1(v1) => {
            if matches!(v1.ext, AccountEntryExtensionV1Ext::V0) {
                account.ext = AccountEntryExt::V1(AccountEntryExtensionV1 {
                    liabilities,
                    ext: AccountEntryExtensionV1Ext::V2(AccountEntryExtensionV2 {
                        num_sponsored: 0,
                        num_sponsoring: 0,
                        signer_sponsoring_i_ds: build_signer_sponsoring_ids(account.signers.len()),
                        ext: AccountEntryExtensionV2Ext::V0,
                    }),
                });
            }
        }
    }

    if let AccountEntryExt::V1(v1) = &mut account.ext {
        if let AccountEntryExtensionV1Ext::V2(v2) = &mut v1.ext {
            ensure_signer_sponsoring_ids(v2, account.signers.len());
            return v2;
        }
    }

    unreachable!("account ext v2 should exist after ensure_account_ext_v2")
}

/// Update sequence metadata when an account's sequence number changes.
pub fn update_account_seq_info(account: &mut AccountEntry, ledger_seq: u32, close_time: u64) {
    let ext_v2 = ensure_account_ext_v2(account);
    let seq_time = TimePoint(close_time);
    match &mut ext_v2.ext {
        AccountEntryExtensionV2Ext::V0 => {
            ext_v2.ext = AccountEntryExtensionV2Ext::V3(AccountEntryExtensionV3 {
                ext: ExtensionPoint::V0,
                seq_ledger: ledger_seq,
                seq_time,
            });
        }
        AccountEntryExtensionV2Ext::V3(v3) => {
            v3.seq_ledger = ledger_seq;
            v3.seq_time = seq_time;
        }
    }
}

/// Get the sequence time from an account's extension V3.
/// Returns 0 if the account doesn't have extension V3.
pub fn get_account_seq_time(account: &AccountEntry) -> u64 {
    match &account.ext {
        AccountEntryExt::V0 => 0,
        AccountEntryExt::V1(ext_v1) => match &ext_v1.ext {
            AccountEntryExtensionV1Ext::V0 => 0,
            AccountEntryExtensionV1Ext::V2(ext_v2) => match &ext_v2.ext {
                AccountEntryExtensionV2Ext::V0 => 0,
                AccountEntryExtensionV2Ext::V3(ext_v3) => ext_v3.seq_time.0,
            },
        },
    }
}

/// Get the sequence ledger from an account's extension V3.
/// Returns 0 if the account doesn't have extension V3.
pub fn get_account_seq_ledger(account: &AccountEntry) -> u32 {
    match &account.ext {
        AccountEntryExt::V0 => 0,
        AccountEntryExt::V1(ext_v1) => match &ext_v1.ext {
            AccountEntryExtensionV1Ext::V0 => 0,
            AccountEntryExtensionV1Ext::V2(ext_v2) => match &ext_v2.ext {
                AccountEntryExtensionV2Ext::V0 => 0,
                AccountEntryExtensionV2Ext::V3(ext_v3) => ext_v3.seq_ledger,
            },
        },
    }
}

fn build_signer_sponsoring_ids(count: usize) -> VecM<SponsorshipDescriptor, 20> {
    let ids = vec![SponsorshipDescriptor(None); count];
    ids.try_into().unwrap_or_default()
}

fn ensure_signer_sponsoring_ids(v2: &mut AccountEntryExtensionV2, signer_count: usize) {
    let mut ids: Vec<SponsorshipDescriptor> = v2.signer_sponsoring_i_ds.iter().cloned().collect();
    if ids.len() < signer_count {
        ids.extend(std::iter::repeat(SponsorshipDescriptor(None)).take(signer_count - ids.len()));
    } else if ids.len() > signer_count {
        ids.truncate(signer_count);
    }
    v2.signer_sponsoring_i_ds = ids.try_into().unwrap_or_default();
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    fn create_test_account_id(seed: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([seed; 32])))
    }

    fn create_test_account_entry(seed: u8) -> AccountEntry {
        AccountEntry {
            account_id: create_test_account_id(seed),
            balance: 1000000000,
            seq_num: SequenceNumber(1),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: vec![].try_into().unwrap(),
            ext: AccountEntryExt::V0,
        }
    }

    #[test]
    fn test_state_manager_creation() {
        let manager = LedgerStateManager::new(5_000_000, 100);
        assert_eq!(manager.ledger_seq(), 100);
        assert_eq!(manager.base_reserve(), 5_000_000);
        assert!(!manager.has_changes());
    }

    #[test]
    fn test_minimum_balance() {
        let manager = LedgerStateManager::new(5_000_000, 100);
        let account = create_test_account_entry(1);
        // 0 sub-entries: (2 + 0) * 5_000_000 = 10_000_000
        assert_eq!(
            manager
                .minimum_balance_for_account(&account, 25, 0)
                .unwrap(),
            10_000_000
        );
        // 3 sub-entries: (2 + 3) * 5_000_000 = 25_000_000
        let mut account_with_subentries = account;
        account_with_subentries.num_sub_entries = 3;
        assert_eq!(
            manager
                .minimum_balance_for_account(&account_with_subentries, 25, 0)
                .unwrap(),
            25_000_000
        );
    }

    #[test]
    fn test_account_operations() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);
        let account = create_test_account_entry(1);
        let account_id = account.account_id.clone();

        // Create account
        manager.create_account(account.clone());
        assert!(manager.has_changes());
        assert!(manager.get_account(&account_id).is_some());

        // Update account
        let mut updated = account.clone();
        updated.balance = 2000000000;
        manager.update_account(updated);

        let stored = manager.get_account(&account_id).unwrap();
        assert_eq!(stored.balance, 2000000000);

        // Delete account
        manager.delete_account(&account_id);
        assert!(manager.get_account(&account_id).is_none());
    }

    #[test]
    fn test_rollback() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);
        let account = create_test_account_entry(1);
        let account_id = account.account_id.clone();

        // Create account
        manager.create_account(account.clone());
        assert!(manager.get_account(&account_id).is_some());

        // Rollback
        manager.rollback();
        assert!(manager.get_account(&account_id).is_none());
        assert!(!manager.has_changes());
    }

    #[test]
    fn test_rollback_preserves_fee_charged() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        // Add fee from first transaction
        manager.delta_mut().add_fee(400);
        assert_eq!(manager.delta().fee_charged(), 400);

        // Create an account (simulating transaction changes)
        let account1 = create_test_account_entry(1);
        manager.create_account(account1.clone());

        // Rollback first transaction (simulating failed tx)
        manager.rollback();
        // After rollback, fee should be preserved
        assert_eq!(
            manager.delta().fee_charged(),
            400,
            "Fee from first tx should be preserved after rollback"
        );

        // Add fee from second transaction
        manager.delta_mut().add_fee(100);
        assert_eq!(manager.delta().fee_charged(), 500, "Fee should accumulate");

        // Create another account
        let account2 = create_test_account_entry(2);
        manager.create_account(account2.clone());

        // Rollback second transaction
        manager.rollback();
        // After rollback, fees from both transactions should be preserved
        assert_eq!(
            manager.delta().fee_charged(),
            500,
            "Fees from both failed txs should be preserved"
        );

        // Add fee from third transaction (successful)
        manager.delta_mut().add_fee(100);
        assert_eq!(
            manager.delta().fee_charged(),
            600,
            "Total fees should be 600"
        );

        // Commit third transaction
        manager.commit();
        // Commit doesn't reset fee_charged
        assert_eq!(
            manager.delta().fee_charged(),
            600,
            "Total fees should remain after commit"
        );
    }

    #[test]
    fn test_commit() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);
        let account = create_test_account_entry(1);
        let account_id = account.account_id.clone();

        // Create account
        manager.create_account(account.clone());

        // Commit
        manager.commit();

        // Account should still exist
        assert!(manager.get_account(&account_id).is_some());

        // But snapshots should be cleared (can't rollback anymore)
        manager.rollback();
        assert!(manager.get_account(&account_id).is_some()); // Still there because commit cleared snapshots
    }

    #[test]
    fn test_take_delta() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);
        let account = create_test_account_entry(1);

        manager.create_account(account);

        let delta = manager.take_delta();
        assert_eq!(delta.ledger_seq(), 100);
        assert!(delta.has_changes());
        assert_eq!(delta.created_entries().len(), 1);
    }

    #[test]
    fn test_asset_key() {
        let native_key = AssetKey::from_asset(&Asset::Native);
        assert!(matches!(native_key, AssetKey::Native));

        let alphanum4 = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: create_test_account_id(1),
        });
        let key4 = AssetKey::from_asset(&alphanum4);
        assert!(matches!(key4, AssetKey::CreditAlphanum4(_, _)));
    }

    /// Test that ClaimableBalance sponsorship-only changes are recorded in delta.
    /// Regression test for ledger 80382 where RevokeSponsorship changed only the
    /// sponsor of a ClaimableBalance entry but the modification was not recorded.
    #[test]
    fn test_claimable_balance_sponsorship_only_change_recorded_in_delta() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        // Create a claimable balance ID
        let balance_id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([1u8; 32]));

        // Create a claimable balance entry
        let cb_entry = ClaimableBalanceEntry {
            balance_id: balance_id.clone(),
            claimants: vec![Claimant::ClaimantTypeV0(ClaimantV0 {
                destination: create_test_account_id(1),
                predicate: ClaimPredicate::Unconditional,
            })]
            .try_into()
            .unwrap(),
            asset: Asset::Native,
            amount: 1000000,
            ext: ClaimableBalanceEntryExt::V0,
        };

        // Create the claimable balance and set up initial sponsor
        manager.create_claimable_balance(cb_entry.clone());
        let ledger_key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
            balance_id: balance_id.clone(),
        });
        let initial_sponsor = create_test_account_id(2);
        manager.set_entry_sponsor(ledger_key.clone(), initial_sponsor);
        manager.commit();

        // Reset delta by creating a new manager with the same state
        // (simulating the start of a new transaction)
        manager.delta = LedgerDelta::new(100);

        // Now simulate what happens during RevokeSponsorship:
        // 1. Start operation snapshot mode
        manager.begin_op_snapshot();

        // 2. Access the claimable balance via get_claimable_balance_mut
        //    This puts it into op_entry_snapshots
        let _ = manager.get_claimable_balance_mut(&balance_id);

        // 3. Change the sponsor (but not the entry data itself)
        let new_sponsor = create_test_account_id(3);
        manager.set_entry_sponsor(ledger_key.clone(), new_sponsor);

        // 4. Apply modifications to delta (before end_op_snapshot, as in real execution)
        manager.flush_modified_entries();

        // 5. End operation snapshot
        let _ = manager.end_op_snapshot();

        // The claimable balance should be recorded in delta as updated
        // even though only the sponsor changed (not the entry data)
        let delta = manager.take_delta();

        // Check that an update was recorded
        assert!(
            !delta.updated_entries().is_empty(),
            "ClaimableBalance sponsorship-only change should be recorded in delta"
        );

        // Verify it's the claimable balance that was updated
        let has_cb_update = delta.updated_entries().iter().any(|entry| {
            matches!(
                &entry.data,
                LedgerEntryData::ClaimableBalance(cb) if cb.balance_id == balance_id
            )
        });
        assert!(
            has_cb_update,
            "The updated entry should be the ClaimableBalance"
        );
    }

    /// Test that LiquidityPool sponsorship-only changes are recorded in delta.
    /// Same fix as ClaimableBalance, applied for consistency.
    #[test]
    fn test_liquidity_pool_sponsorship_only_change_recorded_in_delta() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        // Create a liquidity pool ID
        let pool_id = PoolId(Hash([2u8; 32]));

        // Create a liquidity pool entry
        let lp_entry = LiquidityPoolEntry {
            liquidity_pool_id: pool_id.clone(),
            body: LiquidityPoolEntryBody::LiquidityPoolConstantProduct(
                LiquidityPoolEntryConstantProduct {
                    params: LiquidityPoolConstantProductParameters {
                        asset_a: Asset::Native,
                        asset_b: Asset::CreditAlphanum4(AlphaNum4 {
                            asset_code: AssetCode4([b'U', b'S', b'D', 0]),
                            issuer: create_test_account_id(1),
                        }),
                        fee: 30,
                    },
                    reserve_a: 1000000,
                    reserve_b: 1000000,
                    total_pool_shares: 1000000,
                    pool_shares_trust_line_count: 1,
                },
            ),
        };

        // Create the liquidity pool and set up initial sponsor
        manager.create_liquidity_pool(lp_entry.clone());
        let ledger_key = LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: pool_id.clone(),
        });
        let initial_sponsor = create_test_account_id(2);
        manager.set_entry_sponsor(ledger_key.clone(), initial_sponsor);
        manager.commit();

        // Reset delta by creating a new one (simulating the start of a new transaction)
        manager.delta = LedgerDelta::new(100);

        // Now simulate what happens during RevokeSponsorship:
        // 1. Start operation snapshot mode
        manager.begin_op_snapshot();

        // 2. Access the liquidity pool via get_liquidity_pool_mut
        //    This puts it into op_entry_snapshots
        let _ = manager.get_liquidity_pool_mut(&pool_id);

        // 3. Change the sponsor (but not the entry data itself)
        let new_sponsor = create_test_account_id(3);
        manager.set_entry_sponsor(ledger_key.clone(), new_sponsor);

        // 4. Apply modifications to delta (before end_op_snapshot, as in real execution)
        manager.flush_modified_entries();

        // 5. End operation snapshot
        let _ = manager.end_op_snapshot();

        // The liquidity pool should be recorded in delta as updated
        // even though only the sponsor changed (not the entry data)
        let delta = manager.take_delta();

        // Check that an update was recorded
        assert!(
            !delta.updated_entries().is_empty(),
            "LiquidityPool sponsorship-only change should be recorded in delta"
        );

        // Verify it's the liquidity pool that was updated
        let has_lp_update = delta.updated_entries().iter().any(|entry| {
            matches!(
                &entry.data,
                LedgerEntryData::LiquidityPool(lp) if lp.liquidity_pool_id == pool_id
            )
        });
        assert!(
            has_lp_update,
            "The updated entry should be the LiquidityPool"
        );
    }

    /// Test that Offer sponsorship-only changes are recorded in delta.
    /// Regression test for ledger 80387 where RevokeSponsorship changed only the
    /// sponsor of an Offer entry but the modification was not recorded, causing
    /// bucket list hash mismatch and a num_sponsoring underflow at ledger 80388.
    #[test]
    fn test_offer_sponsorship_only_change_recorded_in_delta() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        // Create an offer entry
        let seller_id = create_test_account_id(1);
        let offer_entry = OfferEntry {
            seller_id: seller_id.clone(),
            offer_id: 1254, // Same offer ID as in the real testnet case
            selling: Asset::Native,
            buying: Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'X', b'X', b'X', b'Y']),
                issuer: create_test_account_id(2),
            }),
            amount: 1000000,
            price: Price { n: 1, d: 1 },
            flags: 0,
            ext: OfferEntryExt::V0,
        };

        // Create the offer and set up initial sponsor
        manager.create_offer(offer_entry.clone());
        let ledger_key = LedgerKey::Offer(LedgerKeyOffer {
            seller_id: seller_id.clone(),
            offer_id: 1254,
        });
        let initial_sponsor = create_test_account_id(2);
        manager.set_entry_sponsor(ledger_key.clone(), initial_sponsor);
        manager.commit();

        // Reset delta by creating a new manager with the same state
        // (simulating the start of a new transaction)
        manager.delta = LedgerDelta::new(100);

        // Now simulate what happens during RevokeSponsorship:
        // 1. Start operation snapshot mode
        manager.begin_op_snapshot();

        // 2. Access the offer via get_offer_mut
        //    This puts it into op_entry_snapshots
        let _ = manager.get_offer_mut(&seller_id, 1254);

        // 3. Change the sponsor (but not the entry data itself)
        let new_sponsor = create_test_account_id(3);
        manager.set_entry_sponsor(ledger_key.clone(), new_sponsor);

        // 4. Apply modifications to delta (before end_op_snapshot, as in real execution)
        manager.flush_modified_entries();

        // 5. End operation snapshot
        let _ = manager.end_op_snapshot();

        // The offer should be recorded in delta as updated
        // even though only the sponsor changed (not the entry data)
        let delta = manager.take_delta();

        // Check that an update was recorded
        assert!(
            !delta.updated_entries().is_empty(),
            "Offer sponsorship-only change should be recorded in delta"
        );

        // Verify it's the offer that was updated
        let has_offer_update = delta.updated_entries().iter().any(|entry| {
            matches!(
                &entry.data,
                LedgerEntryData::Offer(offer) if offer.offer_id == 1254
            )
        });
        assert!(has_offer_update, "The updated entry should be the Offer");
    }

    // ==================== OfferIndex Tests ====================

    fn create_test_offer(seller_seed: u8, offer_id: i64, price_n: i32, price_d: i32) -> OfferEntry {
        OfferEntry {
            seller_id: create_test_account_id(seller_seed),
            offer_id,
            selling: Asset::Native,
            buying: Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', 0]),
                issuer: create_test_account_id(99),
            }),
            amount: 1000000,
            price: Price {
                n: price_n,
                d: price_d,
            },
            flags: 0,
            ext: OfferEntryExt::V0,
        }
    }

    #[test]
    fn test_offer_index_add_and_best_offer() {
        let mut index = OfferIndex::new();

        // Add offers with different prices
        let offer1 = create_test_offer(1, 100, 3, 1); // price = 3.0
        let offer2 = create_test_offer(2, 200, 1, 1); // price = 1.0 (best)
        let offer3 = create_test_offer(3, 300, 2, 1); // price = 2.0

        index.add_offer(&offer1);
        index.add_offer(&offer2);
        index.add_offer(&offer3);

        assert_eq!(index.len(), 3);

        // Best offer should be the one with lowest price (offer2)
        let best_key = index
            .best_offer_key(&offer1.buying, &offer1.selling)
            .unwrap();
        assert_eq!(best_key.offer_id, 200);
    }

    #[test]
    fn test_offer_index_best_offer_same_price_uses_offer_id() {
        let mut index = OfferIndex::new();

        // Add offers with same price, different offer IDs
        let offer1 = create_test_offer(1, 300, 1, 1); // price = 1.0, id = 300
        let offer2 = create_test_offer(2, 100, 1, 1); // price = 1.0, id = 100 (best)
        let offer3 = create_test_offer(3, 200, 1, 1); // price = 1.0, id = 200

        index.add_offer(&offer1);
        index.add_offer(&offer2);
        index.add_offer(&offer3);

        // Best offer should be the one with lowest offer ID (offer2)
        let best_key = index
            .best_offer_key(&offer1.buying, &offer1.selling)
            .unwrap();
        assert_eq!(best_key.offer_id, 100);
    }

    #[test]
    fn test_offer_index_remove_offer() {
        let mut index = OfferIndex::new();

        let offer1 = create_test_offer(1, 100, 2, 1); // price = 2.0
        let offer2 = create_test_offer(2, 200, 1, 1); // price = 1.0 (best)

        index.add_offer(&offer1);
        index.add_offer(&offer2);

        // Remove best offer
        index.remove_offer(&offer2.seller_id, offer2.offer_id);

        assert_eq!(index.len(), 1);

        // Now offer1 should be best
        let best_key = index
            .best_offer_key(&offer1.buying, &offer1.selling)
            .unwrap();
        assert_eq!(best_key.offer_id, 100);
    }

    #[test]
    fn test_offer_index_update_offer() {
        let mut index = OfferIndex::new();

        let offer1 = create_test_offer(1, 100, 2, 1); // price = 2.0
        index.add_offer(&offer1);

        // Update to better price
        let mut updated_offer = offer1.clone();
        updated_offer.price = Price { n: 1, d: 2 }; // price = 0.5
        index.update_offer(&updated_offer);

        assert_eq!(index.len(), 1);

        // Verify the offer is still there with updated price
        let best_key = index
            .best_offer_key(&offer1.buying, &offer1.selling)
            .unwrap();
        assert_eq!(best_key.offer_id, 100);
    }

    #[test]
    fn test_offer_index_different_asset_pairs() {
        let mut index = OfferIndex::new();

        let offer1 = create_test_offer(1, 100, 1, 1);

        // Create offer for different asset pair
        let mut offer2 = create_test_offer(2, 200, 1, 1);
        offer2.buying = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'E', b'U', b'R', 0]),
            issuer: create_test_account_id(98),
        });

        index.add_offer(&offer1);
        index.add_offer(&offer2);

        assert_eq!(index.len(), 2);
        assert_eq!(index.num_asset_pairs(), 2);

        // Each asset pair should have its own best offer
        let best1 = index
            .best_offer_key(&offer1.buying, &offer1.selling)
            .unwrap();
        assert_eq!(best1.offer_id, 100);

        let best2 = index
            .best_offer_key(&offer2.buying, &offer2.selling)
            .unwrap();
        assert_eq!(best2.offer_id, 200);
    }

    #[test]
    fn test_offer_index_empty() {
        let index = OfferIndex::new();

        let buying = Asset::Native;
        let selling = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', 0]),
            issuer: create_test_account_id(99),
        });

        assert!(index.is_empty());
        assert!(!index.has_offers(&buying, &selling));
        assert!(index.best_offer_key(&buying, &selling).is_none());
    }

    #[test]
    fn test_state_manager_best_offer_uses_index() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        // Create offers with different prices
        let offer1 = create_test_offer(1, 100, 3, 1); // price = 3.0
        let offer2 = create_test_offer(2, 200, 1, 1); // price = 1.0 (best)
        let offer3 = create_test_offer(3, 300, 2, 1); // price = 2.0

        manager.create_offer(offer1.clone());
        manager.create_offer(offer2.clone());
        manager.create_offer(offer3.clone());

        // Verify index stats
        assert_eq!(manager.offer_index_size(), 3);

        // Best offer should use the index
        let best = manager.best_offer(&offer1.buying, &offer1.selling).unwrap();
        assert_eq!(best.offer_id, 200);
    }

    #[test]
    fn test_state_manager_best_offer_filtered() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        let seller1 = create_test_account_id(1);
        let seller2 = create_test_account_id(2);

        // Create offers
        let mut offer1 = create_test_offer(1, 100, 1, 1); // price = 1.0 (best but excluded)
        offer1.seller_id = seller1.clone();
        let mut offer2 = create_test_offer(2, 200, 2, 1); // price = 2.0 (second best)
        offer2.seller_id = seller2.clone();

        manager.create_offer(offer1.clone());
        manager.create_offer(offer2.clone());

        // Get best offer excluding seller1
        let best = manager
            .best_offer_filtered(&offer1.buying, &offer1.selling, |o| o.seller_id != seller1)
            .unwrap();

        assert_eq!(best.offer_id, 200);
    }

    #[test]
    fn test_state_manager_offer_index_rollback() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        let offer1 = create_test_offer(1, 100, 1, 1);
        manager.create_offer(offer1.clone());
        assert_eq!(manager.offer_index_size(), 1);

        // Rollback should restore the index
        manager.rollback();
        assert_eq!(manager.offer_index_size(), 0);
        assert!(manager
            .best_offer(&offer1.buying, &offer1.selling)
            .is_none());
    }

    #[test]
    fn test_state_manager_offer_index_delete() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        let offer1 = create_test_offer(1, 100, 2, 1);
        let offer2 = create_test_offer(2, 200, 1, 1); // best

        manager.create_offer(offer1.clone());
        manager.create_offer(offer2.clone());

        // Delete best offer
        manager.delete_offer(&offer2.seller_id, offer2.offer_id);

        assert_eq!(manager.offer_index_size(), 1);

        // Now offer1 should be best
        let best = manager.best_offer(&offer1.buying, &offer1.selling).unwrap();
        assert_eq!(best.offer_id, 100);
    }

    // ==================== Account-Asset Secondary Index Tests ====================

    fn usd_asset() -> Asset {
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', 0]),
            issuer: create_test_account_id(99),
        })
    }

    fn eur_asset() -> Asset {
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'E', b'U', b'R', 0]),
            issuer: create_test_account_id(98),
        })
    }

    fn create_test_offer_with_assets(
        seller_seed: u8,
        offer_id: i64,
        selling: Asset,
        buying: Asset,
    ) -> OfferEntry {
        OfferEntry {
            seller_id: create_test_account_id(seller_seed),
            offer_id,
            selling,
            buying,
            amount: 1000000,
            price: Price { n: 1, d: 1 },
            flags: 0,
            ext: OfferEntryExt::V0,
        }
    }

    /// Helper to query the account_asset_offers index for a (seller, asset) pair.
    fn aa_index_get(manager: &LedgerStateManager, seller_seed: u8, asset: &Asset) -> HashSet<i64> {
        let seller = [seller_seed; 32];
        let asset_key = AssetKey::from_asset(asset);
        manager
            .account_asset_offers
            .get(&(seller, asset_key))
            .cloned()
            .unwrap_or_default()
    }

    #[test]
    fn test_account_asset_index_create_offer() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        // 2 offers for seller_1 (Native→USD)
        let offer1 = create_test_offer_with_assets(1, 100, Asset::Native, usd_asset());
        let offer2 = create_test_offer_with_assets(1, 200, Asset::Native, usd_asset());
        // 1 offer for seller_2 (Native→USD)
        let offer3 = create_test_offer_with_assets(2, 300, Asset::Native, usd_asset());

        manager.create_offer(offer1);
        manager.create_offer(offer2);
        manager.create_offer(offer3);

        // seller_1's Native key should have both offer IDs
        let s1_native = aa_index_get(&manager, 1, &Asset::Native);
        assert_eq!(s1_native, HashSet::from([100, 200]));

        // seller_1's USD key should have both offer IDs
        let s1_usd = aa_index_get(&manager, 1, &usd_asset());
        assert_eq!(s1_usd, HashSet::from([100, 200]));

        // seller_2's keys should have just one
        let s2_native = aa_index_get(&manager, 2, &Asset::Native);
        assert_eq!(s2_native, HashSet::from([300]));

        let s2_usd = aa_index_get(&manager, 2, &usd_asset());
        assert_eq!(s2_usd, HashSet::from([300]));

        // Total unique keys in the index: 4
        assert_eq!(manager.account_asset_offers.len(), 4);
    }

    #[test]
    fn test_account_asset_index_multi_asset() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        let offer1 = create_test_offer_with_assets(1, 100, Asset::Native, usd_asset());
        let offer2 = create_test_offer_with_assets(1, 200, Asset::Native, eur_asset());

        manager.create_offer(offer1);
        manager.create_offer(offer2);

        // Both offers sell Native, so (seller_1, Native) should have both
        let s1_native = aa_index_get(&manager, 1, &Asset::Native);
        assert_eq!(s1_native, HashSet::from([100, 200]));

        // Each buying asset only has its own offer
        let s1_usd = aa_index_get(&manager, 1, &usd_asset());
        assert_eq!(s1_usd, HashSet::from([100]));

        let s1_eur = aa_index_get(&manager, 1, &eur_asset());
        assert_eq!(s1_eur, HashSet::from([200]));
    }

    #[test]
    fn test_account_asset_index_delete_offer() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        let offer1 = create_test_offer_with_assets(1, 100, Asset::Native, usd_asset());
        let offer2 = create_test_offer_with_assets(1, 200, Asset::Native, usd_asset());
        let seller1 = create_test_account_id(1);

        manager.create_offer(offer1);
        manager.create_offer(offer2);

        // Delete offer1
        manager.delete_offer(&seller1, 100);

        // offer1 should be removed from both keys
        let s1_native = aa_index_get(&manager, 1, &Asset::Native);
        assert_eq!(s1_native, HashSet::from([200]));

        let s1_usd = aa_index_get(&manager, 1, &usd_asset());
        assert_eq!(s1_usd, HashSet::from([200]));
    }

    #[test]
    fn test_account_asset_index_update_offer() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        let offer = create_test_offer_with_assets(1, 100, Asset::Native, usd_asset());
        manager.create_offer(offer);

        // Verify initial state
        assert_eq!(
            aa_index_get(&manager, 1, &usd_asset()),
            HashSet::from([100])
        );
        assert_eq!(aa_index_get(&manager, 1, &eur_asset()), HashSet::new());

        // Update offer to change buying asset from USD to EUR
        let updated = create_test_offer_with_assets(1, 100, Asset::Native, eur_asset());
        manager.update_offer(updated);

        // offer_id should be removed from USD and added to EUR
        assert_eq!(aa_index_get(&manager, 1, &usd_asset()), HashSet::new());
        assert_eq!(
            aa_index_get(&manager, 1, &eur_asset()),
            HashSet::from([100])
        );

        // Native should still have the offer
        assert_eq!(
            aa_index_get(&manager, 1, &Asset::Native),
            HashSet::from([100])
        );
    }

    #[test]
    fn test_remove_offers_by_account_and_asset() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        // offer1: Native→USD, offer2: Native→EUR, offer3: EUR→USD
        let offer1 = create_test_offer_with_assets(1, 100, Asset::Native, usd_asset());
        let offer2 = create_test_offer_with_assets(1, 200, Asset::Native, eur_asset());
        let offer3 = create_test_offer_with_assets(1, 300, eur_asset(), usd_asset());
        let seller1 = create_test_account_id(1);

        manager.create_offer(offer1);
        manager.create_offer(offer2);
        manager.create_offer(offer3);

        // Remove all offers that touch USD for seller_1
        let removed = manager.remove_offers_by_account_and_asset(&seller1, &usd_asset());

        // Should return offer1 (Native→USD) and offer3 (EUR→USD)
        let removed_ids: HashSet<i64> = removed.iter().map(|o| o.offer_id).collect();
        assert_eq!(removed_ids, HashSet::from([100, 300]));

        // offer2 (Native→EUR) should remain
        let s1_native = aa_index_get(&manager, 1, &Asset::Native);
        assert_eq!(s1_native, HashSet::from([200]));

        let s1_eur = aa_index_get(&manager, 1, &eur_asset());
        assert_eq!(s1_eur, HashSet::from([200]));

        // USD index should be empty
        let s1_usd = aa_index_get(&manager, 1, &usd_asset());
        assert!(s1_usd.is_empty());
    }

    #[test]
    fn test_remove_offers_by_account_and_asset_isolation() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        let offer1 = create_test_offer_with_assets(1, 100, Asset::Native, usd_asset());
        let offer2 = create_test_offer_with_assets(2, 200, Asset::Native, usd_asset());
        let seller1 = create_test_account_id(1);

        manager.create_offer(offer1);
        manager.create_offer(offer2);

        // Remove only seller_1's offers touching USD
        let removed = manager.remove_offers_by_account_and_asset(&seller1, &usd_asset());
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].offer_id, 100);

        // seller_2's offer should be untouched
        let s2_native = aa_index_get(&manager, 2, &Asset::Native);
        assert_eq!(s2_native, HashSet::from([200]));

        let s2_usd = aa_index_get(&manager, 2, &usd_asset());
        assert_eq!(s2_usd, HashSet::from([200]));

        // seller_1's index should be empty
        let s1_native = aa_index_get(&manager, 1, &Asset::Native);
        assert!(s1_native.is_empty());
    }

    #[test]
    fn test_account_asset_index_rollback() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        let offer = create_test_offer_with_assets(1, 100, Asset::Native, usd_asset());
        manager.create_offer(offer);

        // Index should be populated
        assert_eq!(
            aa_index_get(&manager, 1, &Asset::Native),
            HashSet::from([100])
        );
        assert_eq!(
            aa_index_get(&manager, 1, &usd_asset()),
            HashSet::from([100])
        );

        // Rollback should remove the offer (it was created in this tx)
        manager.rollback();

        assert!(aa_index_get(&manager, 1, &Asset::Native).is_empty());
        assert!(aa_index_get(&manager, 1, &usd_asset()).is_empty());
    }

    #[test]
    fn test_account_asset_index_rollback_restore() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        // Create and commit offer1
        let offer1 = create_test_offer_with_assets(1, 100, Asset::Native, usd_asset());
        manager.create_offer(offer1);
        manager.commit();

        // Create offer2 in a new transaction, then rollback
        let offer2 = create_test_offer_with_assets(1, 200, Asset::Native, usd_asset());
        manager.create_offer(offer2);

        // Both should be in the index before rollback
        assert_eq!(
            aa_index_get(&manager, 1, &Asset::Native),
            HashSet::from([100, 200])
        );

        manager.rollback();

        // After rollback, only offer1 should remain
        assert_eq!(
            aa_index_get(&manager, 1, &Asset::Native),
            HashSet::from([100])
        );
        assert_eq!(
            aa_index_get(&manager, 1, &usd_asset()),
            HashSet::from([100])
        );
    }

    #[test]
    fn test_account_asset_index_savepoint() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        // Create and commit offer1
        let offer1 = create_test_offer_with_assets(1, 100, Asset::Native, usd_asset());
        manager.create_offer(offer1);
        manager.commit();

        // Create savepoint
        let sp = manager.create_savepoint();

        // Create offer2 after savepoint
        let offer2 = create_test_offer_with_assets(1, 200, Asset::Native, usd_asset());
        manager.create_offer(offer2);

        // Both should be in the index
        assert_eq!(
            aa_index_get(&manager, 1, &Asset::Native),
            HashSet::from([100, 200])
        );

        // Rollback to savepoint
        manager.rollback_to_savepoint(sp);

        // Only offer1 should remain
        assert_eq!(
            aa_index_get(&manager, 1, &Asset::Native),
            HashSet::from([100])
        );
        assert_eq!(
            aa_index_get(&manager, 1, &usd_asset()),
            HashSet::from([100])
        );
    }

    #[test]
    fn test_savepoint_rollback_accounts() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        // Create and commit an account
        let account = create_test_account_entry(1);
        let account_id = account.account_id.clone();
        manager.create_account(account);
        manager.commit();

        // Modify account balance
        if let Some(acc) = manager.get_account_mut(&account_id) {
            acc.balance = 500_000_000;
        }

        // Create savepoint after first modification
        let sp = manager.create_savepoint();

        // Modify account again after savepoint
        if let Some(acc) = manager.get_account_mut(&account_id) {
            acc.balance = 100_000;
        }
        assert_eq!(
            manager.get_account(&account_id).unwrap().balance,
            100_000
        );

        // Rollback — should restore to pre-savepoint value
        manager.rollback_to_savepoint(sp);
        assert_eq!(
            manager.get_account(&account_id).unwrap().balance,
            500_000_000
        );
    }

    #[test]
    fn test_savepoint_rollback_data_entries() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        // Create savepoint on empty state
        let sp = manager.create_savepoint();

        // Create a data entry after savepoint
        let data_entry = DataEntry {
            account_id: create_test_account_id(1),
            data_name: "test_key".as_bytes().to_vec().try_into().unwrap(),
            data_value: DataValue(vec![1, 2, 3].try_into().unwrap()),
            ext: DataEntryExt::V0,
        };
        manager.create_data(data_entry);

        assert!(manager.get_data(&create_test_account_id(1), "test_key").is_some());

        // Rollback — data entry should be gone
        manager.rollback_to_savepoint(sp);
        assert!(manager.get_data(&create_test_account_id(1), "test_key").is_none());
    }

    #[test]
    fn test_savepoint_rollback_claimable_balances() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        // Create savepoint
        let sp = manager.create_savepoint();

        // Create a claimable balance after savepoint
        let cb_id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([42; 32]));
        let cb_entry = ClaimableBalanceEntry {
            balance_id: cb_id.clone(),
            claimants: vec![].try_into().unwrap(),
            asset: Asset::Native,
            amount: 1_000_000,
            ext: ClaimableBalanceEntryExt::V0,
        };
        manager.create_claimable_balance(cb_entry);

        assert!(manager.get_claimable_balance(&cb_id).is_some());

        // Rollback — claimable balance should be gone
        manager.rollback_to_savepoint(sp);
        assert!(manager.get_claimable_balance(&cb_id).is_none());
    }

    #[test]
    fn test_savepoint_rollback_preserves_pre_savepoint_changes() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        // Create account and commit
        let account = create_test_account_entry(1);
        let account_id = account.account_id.clone();
        manager.create_account(account);
        manager.commit();

        // Modify balance to 500M (pre-savepoint change)
        if let Some(acc) = manager.get_account_mut(&account_id) {
            acc.balance = 500_000_000;
        }

        // Create savepoint
        let sp = manager.create_savepoint();

        // Create a new account and modify original after savepoint
        let account2 = create_test_account_entry(2);
        let account2_id = account2.account_id.clone();
        manager.create_account(account2);

        if let Some(acc) = manager.get_account_mut(&account_id) {
            acc.balance = 100;
        }

        // Rollback
        manager.rollback_to_savepoint(sp);

        // Original account should have pre-savepoint balance
        assert_eq!(
            manager.get_account(&account_id).unwrap().balance,
            500_000_000
        );
        // New account created after savepoint should be gone
        assert!(manager.get_account(&account2_id).is_none());
    }

    #[test]
    fn test_savepoint_rollback_restores_id_pool() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        let initial_id = manager.id_pool;
        let sp = manager.create_savepoint();

        // Advance id_pool (simulating offer creation)
        manager.id_pool += 5;
        assert_eq!(manager.id_pool, initial_id + 5);

        // Rollback — id_pool should be restored
        manager.rollback_to_savepoint(sp);
        assert_eq!(manager.id_pool, initial_id);
    }

    // ==================== Deleted Entry Tracking Tests ====================
    // These tests verify that deleted entries are tracked to prevent reloading
    // from the bucket list. This is essential for correct within-cluster
    // visibility in parallel Soroban execution.

    fn create_test_contract_address(seed: u8) -> ScAddress {
        ScAddress::Contract(Hash([seed; 32]).into())
    }

    fn create_test_contract_data_entry(seed: u8) -> ContractDataEntry {
        ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: create_test_contract_address(seed),
            key: ScVal::U32(seed as u32),
            durability: ContractDataDurability::Persistent,
            val: ScVal::U64(1000),
        }
    }

    fn create_test_contract_code_entry(seed: u8) -> ContractCodeEntry {
        ContractCodeEntry {
            ext: ContractCodeEntryExt::V0,
            hash: Hash([seed; 32]),
            code: vec![0, 1, 2, 3].try_into().unwrap(),
        }
    }

    fn create_test_ttl_entry(seed: u8) -> TtlEntry {
        TtlEntry {
            key_hash: Hash([seed; 32]),
            live_until_ledger_seq: 1000000,
        }
    }

    #[test]
    fn test_deleted_contract_data_tracking() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);
        let cd = create_test_contract_data_entry(1);
        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: cd.contract.clone(),
            key: cd.key.clone(),
            durability: cd.durability,
        });

        // Initially not deleted
        assert!(!manager.is_entry_deleted(&key));

        // Create and verify exists
        manager.create_contract_data(cd.clone());
        assert!(manager.get_contract_data(&cd.contract, &cd.key, cd.durability).is_some());
        assert!(!manager.is_entry_deleted(&key));

        // Delete and verify tracking
        manager.delete_contract_data(&cd.contract, &cd.key, cd.durability);
        assert!(manager.get_contract_data(&cd.contract, &cd.key, cd.durability).is_none());
        assert!(manager.is_entry_deleted(&key));
    }

    #[test]
    fn test_deleted_contract_code_tracking() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);
        let cc = create_test_contract_code_entry(2);
        let key = LedgerKey::ContractCode(LedgerKeyContractCode {
            hash: cc.hash.clone(),
        });

        // Initially not deleted
        assert!(!manager.is_entry_deleted(&key));

        // Create and verify exists
        manager.create_contract_code(cc.clone());
        assert!(manager.get_contract_code(&cc.hash).is_some());
        assert!(!manager.is_entry_deleted(&key));

        // Delete and verify tracking
        manager.delete_contract_code(&cc.hash);
        assert!(manager.get_contract_code(&cc.hash).is_none());
        assert!(manager.is_entry_deleted(&key));
    }

    #[test]
    fn test_deleted_ttl_tracking() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);
        let ttl = create_test_ttl_entry(3);
        let key = LedgerKey::Ttl(LedgerKeyTtl {
            key_hash: ttl.key_hash.clone(),
        });

        // Initially not deleted
        assert!(!manager.is_entry_deleted(&key));

        // Create and verify exists
        manager.create_ttl(ttl.clone());
        assert!(manager.get_ttl(&ttl.key_hash).is_some());
        assert!(!manager.is_entry_deleted(&key));

        // Delete and verify tracking
        manager.delete_ttl(&ttl.key_hash);
        assert!(manager.get_ttl(&ttl.key_hash).is_none());
        assert!(manager.is_entry_deleted(&key));
    }

    #[test]
    fn test_non_soroban_entries_not_tracked_as_deleted() {
        let manager = LedgerStateManager::new(5_000_000, 100);

        // Non-Soroban entry types should always return false for is_entry_deleted
        let account_key = LedgerKey::Account(LedgerKeyAccount {
            account_id: create_test_account_id(1),
        });
        assert!(!manager.is_entry_deleted(&account_key));

        let offer_key = LedgerKey::Offer(LedgerKeyOffer {
            seller_id: create_test_account_id(1),
            offer_id: 123,
        });
        assert!(!manager.is_entry_deleted(&offer_key));
    }

    #[test]
    fn test_deleted_entry_tracking_regression_842789() {
        // Regression test for ledger 842789 TX 5 mismatch.
        // When TX 4 deletes an entry, TX 5 should NOT reload it from bucket list.
        // This test verifies that deleted entries are properly tracked.
        let mut manager = LedgerStateManager::new(5_000_000, 842789);

        // Simulate TX 4 creating and then deleting a contract data entry
        let cd = create_test_contract_data_entry(4);
        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: cd.contract.clone(),
            key: cd.key.clone(),
            durability: cd.durability,
        });

        // TX 4: Create entry
        manager.create_contract_data(cd.clone());
        assert!(manager.get_entry(&key).is_some());

        // TX 4: Delete entry
        manager.delete_contract_data(&cd.contract, &cd.key, cd.durability);

        // TX 5: Should see entry as deleted, not reload from bucket list
        assert!(manager.get_entry(&key).is_none());
        assert!(manager.is_entry_deleted(&key));

        // This is the key check: is_entry_deleted prevents footprint loading
        // from reloading the entry from bucket list
    }
}
