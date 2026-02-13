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
type EntryLoaderFn = dyn Fn(&LedgerKey) -> Result<Option<LedgerEntry>> + Send + Sync;
type BatchEntryLoaderFn = dyn Fn(&[LedgerKey]) -> Result<Vec<LedgerEntry>> + Send + Sync;
/// Callback type for loading all offers by (account, asset) from the
/// authoritative offer store.  Used by `remove_offers_by_account_and_asset`
/// to mirror stellar-core `loadOffersByAccountAndAsset` which queries the SQL database.
type OffersByAccountAssetLoaderFn =
    dyn Fn(&AccountId, &Asset) -> Result<Vec<LedgerEntry>> + Send + Sync;

/// Soroban state extracted from LedgerStateManager for cheap cloning.
///
/// Path payment operations need to clone the entire state for speculative
/// orderbook exchange comparison against liquidity pools. By temporarily
/// extracting the large Soroban collections (which are never accessed during
/// orderbook exchange), the clone becomes much cheaper.

mod entries;
pub mod offer_index;
mod sponsorship;
mod ttl;

pub use offer_index::{AssetPair, OfferDescriptor, OfferIndex, OfferKey};

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
// similar to stellar-core's MultiOrderBook. This is critical for
// performance when executing path payments and manage offer operations.

use std::collections::BTreeMap;

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
    /// Soroban uses these values instead of ttl_entries to match stellar-core behavior where
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
    /// where only the TTL changed. Per stellar-core behavior:
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
    /// In stellar-core, deleted entries are tracked in mThreadEntryMap as nullopt,
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
    /// This mirrors stellar-core's MultiOrderBook structure.
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
    /// Optional callback to load all offers for a given (account, asset) pair
    /// from the authoritative offer store.  stellar-core uses SQL
    /// `loadOffersByAccountAndAsset` which always returns every matching offer.
    /// Without this loader the in-memory `account_asset_offers` index would
    /// only contain offers that happened to be loaded during prior TX execution,
    /// causing non-deterministic offer removal in `SetTrustLineFlags` / `AllowTrust`.
    offers_by_account_asset_loader: Option<Arc<OffersByAccountAssetLoaderFn>>,
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
            offers_by_account_asset_loader: None,
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

    /// Set the loader that returns all offers for a given (account, asset) pair.
    ///
    /// This mirrors stellar-core `loadOffersByAccountAndAsset` and is used by
    /// `remove_offers_by_account_and_asset` (called during authorization
    /// revocation) to ensure ALL matching offers are found, not just those
    /// that happened to be loaded during prior TX execution.
    pub fn set_offers_by_account_asset_loader(
        &mut self,
        loader: Arc<OffersByAccountAssetLoaderFn>,
    ) {
        self.offers_by_account_asset_loader = Some(loader);
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
        self.offers_by_account_asset_loader = None;

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

    // ========================================================================
    // One-time (Pre-Auth TX) Signer Removal
    // ========================================================================

    // ==================== Account Operations ====================

    // ==================== Trustline Operations ====================

    // ==================== Offer Operations ====================

    // ==================== Data Entry Operations ====================

    // ==================== Contract Data Operations ====================

    // ==================== Contract Code Operations ====================

    // ==================== TTL Entry Operations ====================

    // ==================== Claimable Balance Operations ====================

    // ==================== Liquidity Pool Operations ====================

    // ==================== Generic Entry Operations ====================

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
    /// In stellar-core, fee refunds are NOT separate meta changes - they're
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
    ///    state changes so subsequent operations see clean state (matching stellar-core nested
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
                    // 1. Entry was accessed during operation (in op_entry_snapshots) - stellar-core records all loadAccount calls
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
                    // because stellar-core records per-operation entries for multi-op txs.
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
                    // 1. Entry was accessed during operation (in op_entry_snapshots) - stellar-core records all loadAccount calls
                    // 2. Entry actually changed - always record real value changes
                    // Note: We use accessed_in_op for both single-op and multi-op transactions because
                    // stellar-core records per-operation changes only for entries actually accessed.
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
                    // 1. Entry was accessed during operation (in op_entry_snapshots) - stellar-core records all load calls
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
                    // 1. Entry was accessed during operation (in op_entry_snapshots) - stellar-core records all load calls
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
                    // 1. Entry was accessed during operation (in op_entry_snapshots) - stellar-core records all load calls
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
                    // 1. Entry was accessed during operation (in op_entry_snapshots) - stellar-core records all load calls
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
                    // 1. Entry was accessed during operation (in op_entry_snapshots) - stellar-core records all load calls
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
        assert_eq!(manager.get_account(&account_id).unwrap().balance, 100_000);

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

        assert!(manager
            .get_data(&create_test_account_id(1), "test_key")
            .is_some());

        // Rollback — data entry should be gone
        manager.rollback_to_savepoint(sp);
        assert!(manager
            .get_data(&create_test_account_id(1), "test_key")
            .is_none());
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
        assert!(manager
            .get_contract_data(&cd.contract, &cd.key, cd.durability)
            .is_some());
        assert!(!manager.is_entry_deleted(&key));

        // Delete and verify tracking
        manager.delete_contract_data(&cd.contract, &cd.key, cd.durability);
        assert!(manager
            .get_contract_data(&cd.contract, &cd.key, cd.durability)
            .is_none());
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

    /// Regression test for clear_cached_entries_preserving_offers.
    ///
    /// Verifies that clearing cached entries with preserve_offers=true retains
    /// the offer HashMap, OfferIndex, and account_asset_offers secondary index
    /// while clearing everything else (accounts, trustlines, etc.).
    ///
    /// This is critical for the offer cache persistence optimization: after a
    /// ledger close, the executor calls this to prepare for the next ledger
    /// without reloading ~911K offers.
    #[test]
    fn test_clear_cached_entries_preserving_offers() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        // Add an account
        let account = create_test_account_entry(1);
        manager.create_account(account.clone());

        // Add a trustline
        let trustline = TrustLineEntry {
            account_id: create_test_account_id(1),
            asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', 0]),
                issuer: create_test_account_id(99),
            }),
            balance: 1000,
            limit: 10000,
            flags: TrustLineFlags::AuthorizedFlag as u32,
            ext: TrustLineEntryExt::V0,
        };
        manager.create_trustline(trustline);

        // Add two offers
        let offer1 = create_test_offer(1, 100, 1, 1);
        let offer2 = create_test_offer(2, 200, 2, 1);
        manager.create_offer(offer1.clone());
        manager.create_offer(offer2.clone());

        // Commit so entries are in the base state
        manager.commit();

        // Verify everything is present before clear
        assert!(manager.get_account(&create_test_account_id(1)).is_some());
        assert!(manager.get_offer(&create_test_account_id(1), 100).is_some());
        assert!(manager.get_offer(&create_test_account_id(2), 200).is_some());

        // Clear preserving offers
        manager.clear_cached_entries_preserving_offers();

        // Accounts and trustlines should be cleared
        assert!(
            manager.get_account(&create_test_account_id(1)).is_none(),
            "Accounts should be cleared"
        );

        // Offers should be preserved
        assert!(
            manager.get_offer(&create_test_account_id(1), 100).is_some(),
            "Offer 1 should be preserved"
        );
        assert!(
            manager.get_offer(&create_test_account_id(2), 200).is_some(),
            "Offer 2 should be preserved"
        );

        // Offer index should still work (best_offer lookup)
        let best = manager.best_offer(&offer1.buying, &offer1.selling);
        assert!(best.is_some(), "OfferIndex should be preserved");
    }

    /// Regression test: clear_cached_entries (without preserving) clears everything.
    ///
    /// Contrast with test_clear_cached_entries_preserving_offers: when
    /// preserve_offers=false, all entries including offers should be cleared.
    #[test]
    fn test_clear_cached_entries_clears_offers() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);

        let offer1 = create_test_offer(1, 100, 1, 1);
        manager.create_offer(offer1);
        manager.commit();

        assert!(manager.get_offer(&create_test_account_id(1), 100).is_some());

        manager.clear_cached_entries();

        assert!(
            manager.get_offer(&create_test_account_id(1), 100).is_none(),
            "Offers should be cleared when preserve_offers=false"
        );
    }

    /// Regression test: remove_offers_by_account_and_asset must use the
    /// authoritative loader to discover offers not yet in the in-memory index.
    ///
    /// Mirrors stellar-core `loadOffersByAccountAndAsset` which queries the SQL database
    /// for ALL matching offers regardless of whether they were previously accessed.
    /// Without the loader, offers that exist in the bucket list but were never
    /// loaded into the state manager would be silently skipped, causing
    /// non-deterministic authorization revocation.
    #[test]
    fn test_remove_offers_by_account_and_asset_uses_loader() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);
        let seller1 = create_test_account_id(1);

        // Create offer1 directly (simulating it being loaded from bucket list
        // during a prior TX).
        let offer1 = create_test_offer_with_assets(1, 100, Asset::Native, usd_asset());
        manager.create_offer(offer1);
        manager.commit();

        // offer2 exists in the "authoritative store" but has NOT been loaded
        // into the state manager's in-memory index.
        let offer2 = create_test_offer_with_assets(1, 200, eur_asset(), usd_asset());

        // Set up the loader to return offer2 (simulating the manager's
        // complete offer store returning all offers for this account+asset).
        let offer2_entry = LedgerEntry {
            last_modified_ledger_seq: 100,
            data: LedgerEntryData::Offer(offer2),
            ext: LedgerEntryExt::V0,
        };
        let offer2_clone = offer2_entry.clone();
        manager.set_offers_by_account_asset_loader(Arc::new(move |_account_id, _asset| {
            Ok(vec![offer2_clone.clone()])
        }));

        // Before the fix, this would only find offer1 (the one already loaded).
        // With the fix, it uses the loader to discover offer2 as well.
        let removed = manager.remove_offers_by_account_and_asset(&seller1, &usd_asset());

        // Both offers should be removed: offer1 (Native→USD) and offer2 (EUR→USD)
        let removed_ids: HashSet<i64> = removed.iter().map(|o| o.offer_id).collect();
        assert_eq!(
            removed_ids,
            HashSet::from([100, 200]),
            "Both the pre-loaded offer and the loader-discovered offer should be removed"
        );
    }
}
