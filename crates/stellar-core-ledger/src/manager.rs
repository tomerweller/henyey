//! Core ledger state management and coordination.
//!
//! This module provides [`LedgerManager`], the central component for managing
//! ledger state in rs-stellar-core. It coordinates between multiple subsystems
//! to ensure consistent state transitions during ledger close.
//!
//! # Responsibilities
//!
//! The [`LedgerManager`] is responsible for:
//!
//! - **State Management**: Maintaining the current ledger header
//! - **Bucket List Integration**: Updating the Merkle tree of ledger entries
//! - **Transaction Execution**: Coordinating transaction processing via [`close_ledger`](LedgerManager::close_ledger)
//! - **Snapshots**: Providing consistent point-in-time views for queries
//!
//! # Thread Safety
//!
//! The [`LedgerManager`] uses internal locking (`RwLock`) to allow concurrent
//! reads while serializing writes. Multiple threads can safely query the current
//! state while ledger close operations are serialized.
//!
//! # Hot Archive Support
//!
//! Starting with Protocol 23, the manager supports a hot archive bucket list
//! for state archival. This stores archived/evicted entries separately from
//! the live bucket list, and both contribute to the header's bucket list hash.

use crate::{
    close::{
        LedgerCloseData, LedgerCloseResult, LedgerCloseStats, TransactionSetVariant, UpgradeContext,
    },
    delta::{EntryChange, LedgerDelta},
    execution::{
        execute_transaction_set, load_soroban_network_info, SorobanNetworkInfo,
        TransactionExecutionResult,
    },
    header::{compute_header_hash, create_next_header},
    snapshot::{LedgerSnapshot, SnapshotHandle},
    LedgerError, Result,
};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use stellar_core_bucket::{
    BucketEntry, BucketList, EvictionIterator, HotArchiveBucketList, StateArchivalSettings,
};
use stellar_core_common::{Hash256, NetworkId};
use stellar_core_tx::soroban::PersistentModuleCache;
use stellar_core_tx::state::AssetKey;
use stellar_core_tx::{ClassicEventConfig, TransactionFrame, TxEventManager};
use stellar_xdr::curr::{
    AccountEntry, AccountId, BucketListType, ConfigSettingEntry, ConfigSettingId,
    EvictionIterator as XdrEvictionIterator, GeneralizedTransactionSet, Hash, LedgerCloseMeta,
    LedgerCloseMetaExt, LedgerCloseMetaV2, LedgerEntry, LedgerEntryData, LedgerEntryExt,
    LedgerHeader, LedgerHeaderHistoryEntry, LedgerHeaderHistoryEntryExt, LedgerKey,
    LedgerKeyConfigSetting, TransactionEventStage, TransactionMeta, TransactionPhase,
    TransactionResultMetaV1, TransactionSetV1, TxSetComponent, TxSetComponentTxsMaybeDiscountedFee,
    UpgradeEntryMeta, VecM,
};
use tracing::{debug, info};

/// Secondary index type: (account_bytes, asset) → set of offer_ids.
type OfferAccountAssetIndex = HashMap<([u8; 32], AssetKey), HashSet<i64>>;

/// Extract the 32-byte public key from an AccountId.
fn account_id_bytes(account_id: &AccountId) -> [u8; 32] {
    match &account_id.0 {
        stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(key) => key.0,
    }
}

/// Insert an offer into the (account, asset) secondary index.
///
/// Each offer gets two entries: (seller, selling_asset) and (seller, buying_asset).
fn index_offer_insert(
    index: &mut OfferAccountAssetIndex,
    offer: &stellar_xdr::curr::OfferEntry,
) {
    let seller = account_id_bytes(&offer.seller_id);
    let selling_key = AssetKey::from_asset(&offer.selling);
    let buying_key = AssetKey::from_asset(&offer.buying);
    index
        .entry((seller, selling_key))
        .or_default()
        .insert(offer.offer_id);
    index
        .entry((seller, buying_key))
        .or_default()
        .insert(offer.offer_id);
}

/// Prepend a fee event to transaction metadata.
///
/// This adds a "NewFee" event at the beginning of the transaction's event list
/// to record the fee charged. Used for Protocol 20+ classic event emission.
///
/// # Arguments
///
/// * `meta` - The transaction metadata to modify
/// * `fee_source` - The account that paid the fee
/// * `fee_charged` - The amount of fee charged in stroops
/// * `protocol_version` - The current protocol version
/// * `network_id` - The network identifier
/// * `classic_events` - Classic event configuration
pub fn prepend_fee_event(
    meta: &mut TransactionMeta,
    fee_source: &AccountId,
    fee_charged: i64,
    protocol_version: u32,
    network_id: &NetworkId,
    classic_events: ClassicEventConfig,
) {
    if fee_charged == 0 || !classic_events.events_enabled(protocol_version) {
        return;
    }

    let mut manager = TxEventManager::new(true, protocol_version, *network_id, classic_events);
    manager.new_fee_event(fee_source, fee_charged, TransactionEventStage::BeforeAllTxs);
    let fee_events = manager.finalize();
    if fee_events.is_empty() {
        return;
    }

    if let TransactionMeta::V4(ref mut v4) = meta {
        let existing_events: Vec<stellar_xdr::curr::TransactionEvent> =
            v4.events.iter().cloned().collect();
        let mut combined = Vec::with_capacity(fee_events.len() + existing_events.len());
        combined.extend(fee_events);
        combined.extend(existing_events);
        v4.events = combined.try_into().unwrap_or_default();
    }
}

/// Protocol version that introduced persistent eviction/state archival.
const FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION: u32 = 23;

/// Load the EvictionIterator from the bucket list's ConfigSettingEntry.
///
/// The EvictionIterator tracks where the incremental eviction scan is positioned.
/// Returns `None` if no EvictionIterator entry exists (pre-protocol 23).
fn load_eviction_iterator_from_bucket_list(bucket_list: &BucketList) -> Option<EvictionIterator> {
    let key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
        config_setting_id: ConfigSettingId::EvictionIterator,
    });

    match bucket_list.get(&key) {
        Ok(Some(entry)) => {
            if let LedgerEntryData::ConfigSetting(ConfigSettingEntry::EvictionIterator(xdr_iter)) =
                entry.data
            {
                Some(EvictionIterator {
                    bucket_file_offset: xdr_iter.bucket_file_offset,
                    bucket_list_level: xdr_iter.bucket_list_level,
                    is_curr_bucket: xdr_iter.is_curr_bucket,
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Load StateArchivalSettings from the snapshot's ConfigSettingEntry.
fn load_state_archival_settings_from_snapshot(
    snapshot: &SnapshotHandle,
) -> Option<StateArchivalSettings> {
    let key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
        config_setting_id: ConfigSettingId::StateArchival,
    });

    match snapshot.get_entry(&key) {
        Ok(Some(entry)) => {
            if let LedgerEntryData::ConfigSetting(ConfigSettingEntry::StateArchival(settings)) =
                entry.data
            {
                Some(StateArchivalSettings {
                    eviction_scan_size: settings.eviction_scan_size as u64,
                    starting_eviction_scan_level: settings.starting_eviction_scan_level,
                    max_entries_to_archive: settings.max_entries_to_archive,
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Configuration options for the [`LedgerManager`].
///
/// This struct controls various aspects of ledger processing behavior,
/// including validation and event emission.
///
/// # Defaults
///
/// The default configuration enables all validation, which is appropriate
/// for production use. For testing, you may want to disable certain
/// validations for faster execution.
#[derive(Debug, Clone)]
pub struct LedgerManagerConfig {
    /// Whether to validate bucket list hashes against header values.
    ///
    /// When enabled, the computed bucket list hash is verified against the
    /// expected hash in the ledger header. Disable for replay-only scenarios
    /// where hash verification is not needed.
    pub validate_bucket_hash: bool,

    /// Whether to emit classic (non-Soroban) contract events.
    ///
    /// When enabled, SAC (Stellar Asset Contract) events are generated
    /// for classic operations like payments and trustline changes.
    pub emit_classic_events: bool,

    /// Whether to backfill Stellar Asset events for pre-protocol 23 ledgers.
    ///
    /// When enabled during catchup, classic events are generated for
    /// historical ledgers that predate native event support.
    pub backfill_stellar_asset_events: bool,
}

impl Default for LedgerManagerConfig {
    fn default() -> Self {
        Self {
            validate_bucket_hash: true,
            emit_classic_events: false,
            backfill_stellar_asset_events: false,
        }
    }
}

/// Internal state of the ledger manager.
///
/// This struct holds the mutable state that changes with each ledger close.
/// It is protected by an RwLock for thread-safe access.
struct LedgerState {
    /// Current ledger header (the most recently closed ledger).
    header: LedgerHeader,

    /// SHA-256 hash of the current header's XDR encoding.
    header_hash: Hash256,

    /// Whether the ledger manager has been initialized.
    ///
    /// The manager must be initialized (via `initialize` or
    /// by loading from database) before ledger close operations can begin.
    initialized: bool,
}

/// The core ledger manager for rs-stellar-core.
///
/// `LedgerManager` is the central coordinator for all ledger state operations.
/// It manages the lifecycle of ledger closes, from receiving externalized
/// transaction sets to committing the new ledger state.
///
/// # Architecture
///
/// The manager coordinates between several subsystems:
///
/// - **Bucket List**: The Merkle tree of all ledger entries, providing
///   cryptographic integrity for the state
/// - **Snapshots**: Point-in-time views for concurrent access
///
/// # Initialization
///
/// Before use, the manager must be initialized via one of:
///
/// - [`initialize`](Self::initialize): For catchup from history archives
/// - [`reset`](Self::reset): To clear state before re-initialization
///
/// # Ledger Close Flow
///
/// Call [`close_ledger`](Self::close_ledger) with the externalized data to
/// execute transactions and finalize the ledger in a single call.
///
/// # Thread Safety
///
/// All public methods are safe to call from multiple threads. Internal state
/// is protected by RwLocks to allow concurrent reads during ledger processing.
pub struct LedgerManager {
    /// Live bucket list containing all current ledger entries.
    ///
    /// Wrapped in Arc for efficient sharing with snapshots.
    bucket_list: Arc<RwLock<BucketList>>,

    /// Hot archive bucket list for Protocol 23+ state archival.
    ///
    /// Contains archived/evicted entries. When present, its hash is combined
    /// with the live bucket list hash for the header's bucket_list_hash.
    hot_archive_bucket_list: Arc<RwLock<Option<HotArchiveBucketList>>>,

    /// Network passphrase (e.g., "Public Global Stellar Network ; September 2015").
    network_passphrase: String,

    /// Network ID derived from SHA-256 of the passphrase.
    network_id: NetworkId,

    /// Current mutable ledger state.
    state: RwLock<LedgerState>,

    /// Configuration options.
    config: LedgerManagerConfig,

    /// Persistent module cache for Soroban WASM compilation.
    ///
    /// This cache stores pre-compiled WASM modules for contract code entries,
    /// significantly improving performance for Soroban transactions by avoiding
    /// repeated compilation of the same contract code.
    module_cache: RwLock<Option<PersistentModuleCache>>,

    /// Flag indicating whether the in-memory offer store has been populated.
    ///
    /// The offer store is populated once during initialization from the bucket list
    /// and updated as offers are created/modified/deleted during ledger closes.
    /// This avoids expensive full bucket list scans during orderbook operations.
    offers_initialized: Arc<RwLock<bool>>,

    /// In-memory cache of all live offers, keyed by offer_id.
    /// Populated during initialize_all_caches() and updated on each ledger close.
    /// Eliminates the need to query SQL for orderbook operations.
    offer_store: Arc<RwLock<HashMap<i64, LedgerEntry>>>,

    /// Secondary index: (account_bytes, asset) → set of offer_ids.
    ///
    /// Each offer is indexed under two keys: (seller, selling_asset) and (seller, buying_asset).
    /// Used for O(k) lookups in `load_offers_by_account_and_asset` instead of O(n) full scans.
    offer_account_asset_index: Arc<RwLock<OfferAccountAssetIndex>>,

    /// In-memory Soroban state for Protocol 20+ contract data/code tracking.
    ///
    /// This tracks all CONTRACT_DATA, CONTRACT_CODE, and TTL entries in memory,
    /// maintaining cumulative size totals that are updated incrementally during
    /// ledger close. This avoids expensive full bucket list scans for state
    /// size computation (used for LiveSorobanStateSizeWindow).
    soroban_state: Arc<crate::soroban_state::SharedSorobanState>,
}

impl LedgerManager {
    /// Create a new ledger manager.
    ///
    /// The ledger starts uninitialized and must be initialized via
    /// `initialize` before ledger close operations can begin.
    pub fn new(network_passphrase: String, config: LedgerManagerConfig) -> Self {
        let network_id = NetworkId::from_passphrase(&network_passphrase);

        Self {
            bucket_list: Arc::new(RwLock::new(BucketList::default())),
            hot_archive_bucket_list: Arc::new(RwLock::new(None)),
            network_passphrase,
            network_id,
            state: RwLock::new(LedgerState {
                header: create_genesis_header(),
                header_hash: Hash256::ZERO,
                initialized: false,
            }),
            config,
            module_cache: RwLock::new(None),
            offers_initialized: Arc::new(RwLock::new(false)),
            offer_store: Arc::new(RwLock::new(HashMap::new())),
            offer_account_asset_index: Arc::new(RwLock::new(HashMap::new())),
            soroban_state: Arc::new(crate::soroban_state::SharedSorobanState::new()),
        }
    }

    /// Get the network ID.
    pub fn network_id(&self) -> &NetworkId {
        &self.network_id
    }

    /// Get the network passphrase.
    pub fn network_passphrase(&self) -> &str {
        &self.network_passphrase
    }

    /// Check if the ledger has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.state.read().initialized
    }

    /// Get the current ledger sequence number.
    pub fn current_ledger_seq(&self) -> u32 {
        self.state.read().header.ledger_seq
    }

    /// Get the current ledger header.
    pub fn current_header(&self) -> LedgerHeader {
        self.state.read().header.clone()
    }

    /// Get the current header hash.
    pub fn current_header_hash(&self) -> Hash256 {
        self.state.read().header_hash
    }

    /// Get a reference to the shared Soroban state.
    pub fn soroban_state(&self) -> &Arc<crate::soroban_state::SharedSorobanState> {
        &self.soroban_state
    }

    /// Get a reference to the bucket list.
    pub fn bucket_list(&self) -> &Arc<RwLock<BucketList>> {
        &self.bucket_list
    }

    /// Get a reference to the hot archive bucket list.
    pub fn hot_archive_bucket_list(&self) -> &Arc<RwLock<Option<HotArchiveBucketList>>> {
        &self.hot_archive_bucket_list
    }

    /// Get a reference to the module cache.
    pub fn module_cache(&self) -> &RwLock<Option<PersistentModuleCache>> {
        &self.module_cache
    }

    /// Get the number of offers in the in-memory offer store.
    pub fn offer_store_count(&self) -> usize {
        self.offer_store.read().len()
    }

    /// Get the number of (account, asset) index entries.
    pub fn offer_account_asset_index_len(&self) -> usize {
        self.offer_account_asset_index.read().len()
    }

    /// Get the total number of offer_id entries across all (account, asset) buckets.
    pub fn offer_account_asset_index_total_ids(&self) -> usize {
        self.offer_account_asset_index
            .read()
            .values()
            .map(|s| s.len())
            .sum()
    }

    /// Get bucket list level hashes (curr, snap) for persistence.
    pub fn bucket_list_levels(&self) -> Vec<(Hash256, Hash256)> {
        let bucket_list = self.bucket_list.read();
        bucket_list
            .levels()
            .iter()
            .map(|level| (level.curr.hash(), level.snap.hash()))
            .collect()
    }

    /// Initialize the ledger from bucket list state.
    ///
    /// This is used during catchup from history archives.
    ///
    /// # Arguments
    ///
    /// * `bucket_list` - The live bucket list
    /// * `hot_archive_bucket_list` - The hot archive bucket list
    /// * `header` - The ledger header to initialize with
    /// * `header_hash` - The authoritative hash of the header from the history archive
    pub fn initialize(
        &self,
        bucket_list: BucketList,
        hot_archive_bucket_list: HotArchiveBucketList,
        header: LedgerHeader,
        header_hash: Hash256,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};

        let mut state = self.state.write();
        if state.initialized {
            return Err(LedgerError::AlreadyInitialized);
        }

        // Compute combined bucket list hash for verification
        let live_hash = bucket_list.hash();
        let hot_hash = hot_archive_bucket_list.hash();
        let mut hasher = Sha256::new();
        hasher.update(live_hash.as_bytes());
        hasher.update(hot_hash.as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        let computed_hash = Hash256::from_bytes(bytes);

        let expected_hash = Hash256::from(header.bucket_list_hash.0);

        // Debug: log the bucket level hashes
        tracing::debug!(
            header_ledger_seq = header.ledger_seq,
            expected = %expected_hash.to_hex(),
            computed = %computed_hash.to_hex(),
            live_hash = %live_hash.to_hex(),
            hot_archive_hash = %hot_hash.to_hex(),
            "Verifying bucket list hash"
        );
        for level_idx in 0..bucket_list.levels().len() {
            if let Some(level) = bucket_list.level(level_idx) {
                tracing::debug!(
                    level = level_idx,
                    curr_hash = %level.curr.hash().to_hex(),
                    snap_hash = %level.snap.hash().to_hex(),
                    level_hash = %level.hash().to_hex(),
                    "Live level hash"
                );
            }
        }

        if self.config.validate_bucket_hash && computed_hash != expected_hash {
            return Err(LedgerError::HashMismatch {
                expected: expected_hash.to_hex(),
                actual: computed_hash.to_hex(),
            });
        }

        // Update state
        *self.bucket_list.write() = bucket_list;
        *self.hot_archive_bucket_list.write() = Some(hot_archive_bucket_list);

        // Set the ledger sequence on bucket lists after restoring from history archive.
        // restore_from_hashes() sets ledger_seq to 0, but we need it set to the actual
        // ledger sequence to ensure proper bucket list advancement behavior. Without this,
        // advance_to_ledger() would try to advance from ledger 0 to the current ledger,
        // applying hundreds of thousands of empty batches and corrupting the bucket list.
        self.bucket_list.write().set_ledger_seq(header.ledger_seq);
        if let Some(ref mut habl) = *self.hot_archive_bucket_list.write() {
            habl.set_ledger_seq(header.ledger_seq);
        }

        state.header = header.clone();
        state.header_hash = header_hash;
        state.initialized = true;

        let ledger_seq = state.header.ledger_seq;
        let header_hash_hex = state.header_hash.to_hex();

        // Release state lock before initializing caches (which need bucket_list read lock)
        drop(state);

        // Initialize all caches in a single pass over live_entries().
        // This is a significant memory optimization - previously we called live_entries()
        // three times (for module cache, offer cache, and soroban state), each creating
        // a full copy of all entries. With millions of entries on testnet, this could
        // use several GB of temporary memory. The single-pass approach reduces peak
        // memory usage by ~66%.
        self.initialize_all_caches(header.ledger_version, ledger_seq)?;

        info!(
            ledger_seq,
            header_hash = %header_hash_hex,
            "Ledger initialized from buckets"
        );

        Ok(())
    }

    /// Reset the ledger manager state for re-initialization.
    ///
    /// This clears all caches, bucket lists, and state to allow a fresh
    /// `initialize` call. Used when catchup needs to reset
    /// state while the ledger manager was already initialized (e.g., after
    /// falling behind in live mode).
    pub fn reset(&self) {
        debug!("Resetting ledger manager for catchup");

        // Clear bucket lists
        *self.bucket_list.write() = BucketList::default();
        *self.hot_archive_bucket_list.write() = None;

        // Explicitly drop old module cache to release memory
        let _ = self.module_cache.write().take();

        *self.offers_initialized.write() = false;
        self.soroban_state.write().clear();

        // Reset state
        let mut state = self.state.write();
        state.header = create_genesis_header();
        state.header_hash = Hash256::ZERO;
        state.initialized = false;

        debug!("Ledger manager reset complete");
    }

    /// Initialize the persistent module cache from CONTRACT_CODE entries in the bucket list.
    ///
    /// This scans the bucket list for all contract code entries and pre-compiles them
    /// for reuse across transactions. This is only done for protocol versions that
    /// support Soroban (20+).
    ///
    /// Note: This function is kept for potential future use in selective reinitialization.
    /// Normal initialization uses `initialize_all_caches()` for better memory efficiency.
    #[allow(dead_code)]
    fn initialize_module_cache(&self, protocol_version: u32) -> Result<()> {
        use stellar_core_common::MIN_SOROBAN_PROTOCOL_VERSION;

        if protocol_version < MIN_SOROBAN_PROTOCOL_VERSION {
            // Soroban not supported at this protocol version
            *self.module_cache.write() = None;
            return Ok(());
        }

        // Create a new module cache for this protocol version
        let cache = match PersistentModuleCache::new_for_protocol(protocol_version) {
            Some(c) => c,
            None => {
                *self.module_cache.write() = None;
                return Ok(());
            }
        };

        // Scan bucket list for CONTRACT_CODE entries and pre-compile them
        let bucket_list = self.bucket_list.read();

        let mut contracts_added = 0;
        for entry_result in bucket_list.live_entries_iter() {
            let entry = entry_result.map_err(|e| {
                LedgerError::Internal(format!(
                    "Failed to iterate live entries for module cache: {}",
                    e
                ))
            })?;
            if let LedgerEntryData::ContractCode(contract_code) = &entry.data {
                if cache.add_contract(contract_code.code.as_slice(), protocol_version) {
                    contracts_added += 1;
                }
            }
        }

        info!(
            contracts_added,
            protocol_version, "Initialized module cache from bucket list"
        );

        *self.module_cache.write() = Some(cache);
        Ok(())
    }

    /// Initialize the in-memory Soroban state from CONTRACT_DATA, CONTRACT_CODE, and TTL entries.
    ///
    /// This scans the bucket list once during initialization to populate the state cache.
    /// After initialization, the state is maintained incrementally during ledger close.
    ///
    /// Note: This function is kept for potential future use in selective reinitialization.
    /// Normal initialization uses `initialize_all_caches()` for better memory efficiency.
    #[allow(dead_code)]
    fn initialize_soroban_state(&self, protocol_version: u32, ledger_seq: u32) -> Result<()> {
        use stellar_core_common::MIN_SOROBAN_PROTOCOL_VERSION;

        if protocol_version < MIN_SOROBAN_PROTOCOL_VERSION {
            // Soroban not supported at this protocol version
            return Ok(());
        }

        let bucket_list = self.bucket_list.read();

        // Load rent config for accurate code size calculation
        let rent_config = self.load_soroban_rent_config(&bucket_list);

        let mut soroban_state = self.soroban_state.write();
        soroban_state.clear();

        // Stream through entries and collect CONTRACT_DATA, CONTRACT_CODE, TTL, and ConfigSetting entries
        let mut data_count = 0u64;
        let mut code_count = 0u64;
        let mut ttl_count = 0u64;
        let mut config_count = 0u64;

        for entry_result in bucket_list.live_entries_iter() {
            let entry = entry_result.map_err(|e| {
                LedgerError::Internal(format!(
                    "Failed to iterate live entries for soroban state: {}",
                    e
                ))
            })?;
            match &entry.data {
                LedgerEntryData::ContractData(_) => {
                    if let Err(e) = soroban_state.create_contract_data(entry.clone()) {
                        tracing::warn!(error = %e, "Failed to add contract data to soroban state");
                    } else {
                        data_count += 1;
                    }
                }
                LedgerEntryData::ContractCode(_) => {
                    if let Err(e) = soroban_state.create_contract_code(
                        entry.clone(),
                        protocol_version,
                        rent_config.as_ref(),
                    ) {
                        tracing::warn!(error = %e, "Failed to add contract code to soroban state");
                    } else {
                        code_count += 1;
                    }
                }
                LedgerEntryData::Ttl(ttl) => {
                    let ttl_key = stellar_xdr::curr::LedgerKeyTtl {
                        key_hash: ttl.key_hash.clone(),
                    };
                    let ttl_data = crate::soroban_state::TtlData::new(
                        ttl.live_until_ledger_seq,
                        entry.last_modified_ledger_seq,
                    );
                    if let Err(e) = soroban_state.create_ttl(&ttl_key, ttl_data) {
                        tracing::trace!(error = %e, "Failed to add TTL to soroban state (may be pending)");
                    } else {
                        ttl_count += 1;
                    }
                }
                LedgerEntryData::ConfigSetting(_) => {
                    // ConfigSetting entries are cached for fast Soroban config loading
                    if let Err(e) = soroban_state.process_entry_create(
                        &entry,
                        protocol_version,
                        rent_config.as_ref(),
                    ) {
                        tracing::warn!(error = %e, "Failed to add config setting to soroban state");
                    } else {
                        config_count += 1;
                    }
                }
                _ => {}
            }
        }

        let total_size = soroban_state.total_size();
        let stats = soroban_state.stats();

        info!(
            ledger_seq,
            data_count,
            code_count,
            ttl_count,
            config_count,
            total_size,
            contract_data_size = stats.contract_data_size,
            contract_code_size = stats.contract_code_size,
            pending_ttl_count = stats.pending_ttl_count,
            "Initialized in-memory Soroban state from bucket list"
        );

        Ok(())
    }

    /// Load Soroban rent config from bucket list for code size calculation.
    fn load_soroban_rent_config(
        &self,
        bucket_list: &BucketList,
    ) -> Option<crate::soroban_state::SorobanRentConfig> {
        // Load CPU cost params
        let cpu_key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
            config_setting_id: ConfigSettingId::ContractCostParamsCpuInstructions,
        });
        let cpu_params = bucket_list.get(&cpu_key).ok()?.and_then(|e| {
            if let LedgerEntryData::ConfigSetting(
                ConfigSettingEntry::ContractCostParamsCpuInstructions(params),
            ) = e.data
            {
                Some(params)
            } else {
                None
            }
        })?;

        // Load memory cost params
        let mem_key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
            config_setting_id: ConfigSettingId::ContractCostParamsMemoryBytes,
        });
        let mem_params = bucket_list.get(&mem_key).ok()?.and_then(|e| {
            if let LedgerEntryData::ConfigSetting(
                ConfigSettingEntry::ContractCostParamsMemoryBytes(params),
            ) = e.data
            {
                Some(params)
            } else {
                None
            }
        })?;

        // Load compute settings for limits
        let compute_key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
            config_setting_id: ConfigSettingId::ContractComputeV0,
        });
        let (tx_max_instructions, tx_max_memory_bytes) =
            bucket_list.get(&compute_key).ok()?.and_then(|e| {
                if let LedgerEntryData::ConfigSetting(ConfigSettingEntry::ContractComputeV0(
                    compute,
                )) = e.data
                {
                    Some((
                        compute.tx_max_instructions as u64,
                        compute.tx_memory_limit as u64,
                    ))
                } else {
                    None
                }
            })?;

        Some(crate::soroban_state::SorobanRentConfig {
            cpu_cost_params: cpu_params,
            mem_cost_params: mem_params,
            tx_max_instructions,
            tx_max_memory_bytes,
        })
    }

    /// Initialize all caches from the bucket list using per-type scanning.
    ///
    /// Instead of iterating all ~60M entries with a single dedup HashSet (~8.6 GB
    /// on mainnet), this performs separate scans per entry type. Each scan maintains
    /// its own dedup set scoped to that type's keys, with peak memory ~240 MB
    /// (for ContractData with ~1.68M keys). The dedup set is freed between scans.
    ///
    /// Scan order:
    /// 1. Offers -> SQL bulk insert (dedup: ~912K keys, ~130 MB)
    /// 2. ContractCode -> module cache + soroban state (dedup: ~874 keys, tiny)
    /// 3. ContractData -> soroban state (dedup: ~1.68M keys, ~240 MB)
    /// 4. TTL -> soroban state (dedup: ~1.68M keys, ~240 MB)
    /// 5. ConfigSetting -> soroban state (dedup: ~17 keys, tiny)
    fn initialize_all_caches(&self, protocol_version: u32, ledger_seq: u32) -> Result<()> {
        use stellar_core_common::MIN_SOROBAN_PROTOCOL_VERSION;
        use stellar_xdr::curr::LedgerEntryType;

        let bucket_list = self.bucket_list.read();
        let cache_init_start = std::time::Instant::now();

        // Load rent config before scanning (uses point lookups, not full scan)
        let rent_config = self.load_soroban_rent_config(&bucket_list);

        // Create module cache if Soroban is supported
        let module_cache = if protocol_version >= MIN_SOROBAN_PROTOCOL_VERSION {
            PersistentModuleCache::new_for_protocol(protocol_version)
        } else {
            None
        };

        // Clear and prepare soroban state
        let mut soroban_state = self.soroban_state.write();
        soroban_state.clear();

        // --- Scan 1: Offers -> in-memory store ---
        info!("Cache init: scanning Offer entries...");
        let mut offer_count = 0u64;
        let mut mem_offers: HashMap<i64, LedgerEntry> = HashMap::new();

        bucket_list.scan_for_entries_of_type(LedgerEntryType::Offer, |be| {
            if let BucketEntry::Live(entry) | BucketEntry::Init(entry) = be {
                if let LedgerEntryData::Offer(ref offer) = entry.data {
                    mem_offers.insert(offer.offer_id, entry.clone());
                    offer_count += 1;
                }
            }
            true
        });

        // Build the (account, asset) secondary index from mem_offers
        let mut account_asset_idx: OfferAccountAssetIndex = HashMap::new();
        for entry in mem_offers.values() {
            if let LedgerEntryData::Offer(ref offer) = entry.data {
                index_offer_insert(&mut account_asset_idx, offer);
            }
        }

        // Store in persistent in-memory offer store
        *self.offer_store.write() = mem_offers;
        *self.offer_account_asset_index.write() = account_asset_idx;

        let offer_elapsed = cache_init_start.elapsed();
        info!(offer_count, elapsed_ms = offer_elapsed.as_millis() as u64, "Cache init: Offer scan complete");

        // --- Scan 2: ContractCode -> module cache + soroban state ---
        let mut contracts_added = 0u64;
        let mut code_count = 0u64;
        let mut last_scan_elapsed = offer_elapsed;
        if protocol_version >= MIN_SOROBAN_PROTOCOL_VERSION {
            info!("Cache init: scanning ContractCode entries...");
            bucket_list.scan_for_entries_of_type(LedgerEntryType::ContractCode, |be| {
                if let BucketEntry::Live(entry) | BucketEntry::Init(entry) = be {
                    if let LedgerEntryData::ContractCode(contract_code) = &entry.data {
                        if let Some(ref cache) = module_cache {
                            if cache.add_contract(contract_code.code.as_slice(), protocol_version) {
                                contracts_added += 1;
                            }
                        }
                    }
                    if let Err(e) = soroban_state.create_contract_code(
                        entry.clone(),
                        protocol_version,
                        rent_config.as_ref(),
                    ) {
                        tracing::warn!(error = %e, "Failed to add contract code to soroban state");
                    } else {
                        code_count += 1;
                    }
                }
                true
            });
            let now = cache_init_start.elapsed();
            info!(code_count, contracts_added,
                scan_ms = (now - last_scan_elapsed).as_millis() as u64,
                elapsed_ms = now.as_millis() as u64,
                "Cache init: ContractCode scan complete");
            last_scan_elapsed = now;
        }

        // --- Scan 3: ContractData -> soroban state ---
        let mut data_count = 0u64;
        if protocol_version >= MIN_SOROBAN_PROTOCOL_VERSION {
            info!("Cache init: scanning ContractData entries...");
            bucket_list.scan_for_entries_of_type(LedgerEntryType::ContractData, |be| {
                if let BucketEntry::Live(entry) | BucketEntry::Init(entry) = be {
                    if let Err(e) = soroban_state.create_contract_data(entry.clone()) {
                        tracing::warn!(error = %e, "Failed to add contract data to soroban state");
                    } else {
                        data_count += 1;
                    }
                }
                true
            });
            let now = cache_init_start.elapsed();
            info!(data_count,
                scan_ms = (now - last_scan_elapsed).as_millis() as u64,
                elapsed_ms = now.as_millis() as u64,
                "Cache init: ContractData scan complete");
            last_scan_elapsed = now;
        }

        // --- Scan 4: TTL -> soroban state ---
        let mut ttl_count = 0u64;
        if protocol_version >= MIN_SOROBAN_PROTOCOL_VERSION {
            info!("Cache init: scanning TTL entries...");
            bucket_list.scan_for_entries_of_type(LedgerEntryType::Ttl, |be| {
                if let BucketEntry::Live(entry) | BucketEntry::Init(entry) = be {
                    if let LedgerEntryData::Ttl(ttl) = &entry.data {
                        let ttl_key = stellar_xdr::curr::LedgerKeyTtl {
                            key_hash: ttl.key_hash.clone(),
                        };
                        let ttl_data = crate::soroban_state::TtlData::new(
                            ttl.live_until_ledger_seq,
                            entry.last_modified_ledger_seq,
                        );
                        if let Err(e) = soroban_state.create_ttl(&ttl_key, ttl_data) {
                            tracing::trace!(error = %e, "Failed to add TTL to soroban state (may be pending)");
                        } else {
                            ttl_count += 1;
                        }
                    }
                }
                true
            });
            let now = cache_init_start.elapsed();
            info!(ttl_count,
                scan_ms = (now - last_scan_elapsed).as_millis() as u64,
                elapsed_ms = now.as_millis() as u64,
                "Cache init: TTL scan complete");
        }

        // --- Scan 5: ConfigSetting -> soroban state ---
        let mut config_count = 0u64;
        {
            info!("Cache init: scanning ConfigSetting entries...");
            bucket_list.scan_for_entries_of_type(LedgerEntryType::ConfigSetting, |be| {
                if let BucketEntry::Live(entry) | BucketEntry::Init(entry) = be {
                    if let Err(e) = soroban_state.process_entry_create(
                        entry,
                        protocol_version,
                        rent_config.as_ref(),
                    ) {
                        tracing::warn!(error = %e, "Failed to add config setting to soroban state");
                    } else {
                        config_count += 1;
                    }
                }
                true
            });
            info!(config_count, elapsed_ms = cache_init_start.elapsed().as_millis() as u64, "Cache init: ConfigSetting scan complete");
        }

        // Drop bucket list lock before acquiring write locks
        drop(bucket_list);
        drop(soroban_state);

        // Store module cache
        *self.module_cache.write() = module_cache;

        // Mark offers as initialized
        *self.offers_initialized.write() = true;

        // Log initialization stats
        let soroban_stats = self.soroban_state.read().stats();
        info!(
            ledger_seq,
            contracts_added,
            offer_count,
            data_count,
            code_count,
            ttl_count,
            config_count,
            total_soroban_size =
                soroban_stats.contract_data_size + soroban_stats.contract_code_size,
            elapsed_ms = cache_init_start.elapsed().as_millis() as u64,
            "Initialized caches from bucket list (per-type scanning)"
        );

        Ok(())
    }

    /// Close a ledger by executing transactions and committing state changes.
    ///
    /// This is the main entry point for ledger close in live mode. It:
    /// 1. Validates the close data against current state
    /// 2. Executes all transactions in the set
    /// 3. Updates bucket list, soroban state, and other caches
    /// 4. Computes and returns the new ledger header
    ///
    /// # Example
    ///
    /// ```ignore
    /// let close_data = LedgerCloseData::new(seq, tx_set, close_time, prev_hash);
    /// let result = manager.close_ledger(close_data)?;
    /// println!("Closed ledger {}", result.ledger_seq());
    /// ```
    pub fn close_ledger(&self, close_data: LedgerCloseData) -> Result<LedgerCloseResult> {
        let mut ctx = self.begin_close(close_data)?;
        ctx.apply_transactions()?;
        ctx.commit()
    }

    /// Begin closing a new ledger (internal).
    ///
    /// Returns a LedgerCloseContext for applying transactions and
    /// committing the ledger. This is called by `close_ledger`.
    fn begin_close(&self, close_data: LedgerCloseData) -> Result<LedgerCloseContext<'_>> {
        let state = self.state.read();
        if !state.initialized {
            return Err(LedgerError::NotInitialized);
        }

        // Validate sequence
        let expected_seq = state.header.ledger_seq + 1;
        if close_data.ledger_seq != expected_seq {
            return Err(LedgerError::InvalidSequence {
                expected: expected_seq,
                actual: close_data.ledger_seq,
            });
        }

        // Validate previous hash
        if close_data.prev_ledger_hash != state.header_hash {
            // Describe the StellarValueExt for logging with details
            let stellar_value_ext_desc = match &state.header.scp_value.ext {
                stellar_xdr::curr::StellarValueExt::Basic => "Basic".to_string(),
                stellar_xdr::curr::StellarValueExt::Signed(sig) => {
                    let node_id_bytes = match &sig.node_id.0 {
                        stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(key) => key.0,
                    };
                    format!(
                        "Signed(node_id={}, sig_len={})",
                        Hash256::from_bytes(node_id_bytes).to_hex(),
                        sig.signature.len()
                    )
                }
            };

            // Compute recomputed hash to verify
            use stellar_xdr::curr::{Limits, WriteXdr};
            let header_xdr = state.header.to_xdr(Limits::none()).unwrap_or_default();
            let header_xdr_hex = Hash256::from_bytes({
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&header_xdr[..std::cmp::min(32, header_xdr.len())]);
                arr
            })
            .to_hex();
            tracing::error!(
                header_xdr_first_32_bytes = %header_xdr_hex,
                header_xdr_len = header_xdr.len(),
                "Header XDR bytes for debugging"
            );

            // Debug: Log header details to help diagnose hash mismatch
            let skip_list_0 = Hash256::from(state.header.skip_list[0].clone()).to_hex();
            let skip_list_1 = Hash256::from(state.header.skip_list[1].clone()).to_hex();
            let skip_list_2 = Hash256::from(state.header.skip_list[2].clone()).to_hex();
            let skip_list_3 = Hash256::from(state.header.skip_list[3].clone()).to_hex();
            tracing::error!(
                current_seq = state.header.ledger_seq,
                close_seq = close_data.ledger_seq,
                our_hash = %state.header_hash.to_hex(),
                network_prev_hash = %close_data.prev_ledger_hash.to_hex(),
                header_version = state.header.ledger_version,
                header_bucket_list_hash = %Hash256::from(state.header.bucket_list_hash.0).to_hex(),
                header_tx_result_hash = %Hash256::from(state.header.tx_set_result_hash.0).to_hex(),
                header_total_coins = state.header.total_coins,
                header_fee_pool = state.header.fee_pool,
                header_close_time = state.header.scp_value.close_time.0,
                header_tx_set_hash = %Hash256::from(state.header.scp_value.tx_set_hash.0).to_hex(),
                header_upgrades_count = state.header.scp_value.upgrades.len(),
                header_stellar_value_ext = %stellar_value_ext_desc,
                header_prev_ledger_hash = %Hash256::from(state.header.previous_ledger_hash.0).to_hex(),
                header_id_pool = state.header.id_pool,
                header_inflation_seq = state.header.inflation_seq,
                header_base_fee = state.header.base_fee,
                header_base_reserve = state.header.base_reserve,
                header_max_tx_set_size = state.header.max_tx_set_size,
                skip_list_0 = %skip_list_0,
                skip_list_1 = %skip_list_1,
                skip_list_2 = %skip_list_2,
                skip_list_3 = %skip_list_3,
                "Hash mismatch - our computed header hash differs from network's prev_ledger_hash"
            );

            // Log detailed bucket list state for debugging hash mismatch
            // This helps identify which specific level has diverged
            {
                let bucket_list = self.bucket_list.read();
                let live_hash = bucket_list.hash();
                tracing::error!(
                    ledger_seq = state.header.ledger_seq,
                    bucket_list_ledger_seq = bucket_list.ledger_seq(),
                    live_bucket_list_hash = %live_hash.to_hex(),
                    "HASH_MISMATCH_DEBUG: Live bucket list state"
                );

                // Log each level's curr and snap hashes
                for (level, level_hash, curr_hash, snap_hash) in bucket_list.level_hashes() {
                    tracing::error!(
                        ledger_seq = state.header.ledger_seq,
                        level = level,
                        level_hash = %level_hash.to_hex(),
                        curr_hash = %curr_hash.to_hex(),
                        snap_hash = %snap_hash.to_hex(),
                        "HASH_MISMATCH_DEBUG: Live bucket list level"
                    );
                }

                // Log hot archive state if present
                let hot_archive = self.hot_archive_bucket_list.read();
                if let Some(ref ha) = *hot_archive {
                    let hot_hash = ha.hash();
                    tracing::error!(
                        ledger_seq = state.header.ledger_seq,
                        hot_archive_ledger_seq = ha.ledger_seq(),
                        hot_archive_hash = %hot_hash.to_hex(),
                        "HASH_MISMATCH_DEBUG: Hot archive bucket list state"
                    );

                    for (level, level_hash, curr_hash, snap_hash) in ha.level_hashes() {
                        tracing::error!(
                            ledger_seq = state.header.ledger_seq,
                            level = level,
                            level_hash = %level_hash.to_hex(),
                            curr_hash = %curr_hash.to_hex(),
                            snap_hash = %snap_hash.to_hex(),
                            "HASH_MISMATCH_DEBUG: Hot archive bucket list level"
                        );
                    }

                    // Log the combined hash computation
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(live_hash.as_bytes());
                    hasher.update(hot_hash.as_bytes());
                    let result = hasher.finalize();
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(&result);
                    let combined_hash = Hash256::from_bytes(bytes);
                    tracing::error!(
                        ledger_seq = state.header.ledger_seq,
                        live_hash = %live_hash.to_hex(),
                        hot_hash = %hot_hash.to_hex(),
                        combined_hash = %combined_hash.to_hex(),
                        header_bucket_list_hash = %Hash256::from(state.header.bucket_list_hash.0).to_hex(),
                        "HASH_MISMATCH_DEBUG: Combined bucket list hash computation"
                    );
                } else {
                    tracing::error!(
                        ledger_seq = state.header.ledger_seq,
                        "HASH_MISMATCH_DEBUG: No hot archive bucket list present!"
                    );
                }
            }

            return Err(LedgerError::HashMismatch {
                expected: state.header_hash.to_hex(),
                actual: close_data.prev_ledger_hash.to_hex(),
            });
        }

        // Create snapshot of current state for reading during close
        let snapshot = self.create_snapshot()?;

        let mut upgrade_ctx = UpgradeContext::new(state.header.ledger_version);
        for upgrade in &close_data.upgrades {
            upgrade_ctx.add_upgrade(upgrade.clone());
        }

        Ok(LedgerCloseContext {
            manager: self,
            close_data,
            prev_header: state.header.clone(),
            prev_header_hash: state.header_hash,
            delta: LedgerDelta::new(expected_seq),
            snapshot,
            stats: LedgerCloseStats::new(),
            upgrade_ctx,
            id_pool: state.header.id_pool,
            tx_results: Vec::new(),
            tx_result_metas: Vec::new(),
            hot_archive_restored_keys: Vec::new(),
        })
    }

    /// Create a snapshot of the current ledger state.
    ///
    /// The snapshot includes a lookup function for entries not in the cache,
    /// which queries the bucket list for the entry.
    pub fn create_snapshot(&self) -> Result<SnapshotHandle> {
        let state = self.state.read();
        // Use an empty entry cache - all lookups go through lookup_fn which handles:
        // - Soroban types (CONTRACT_DATA, CONTRACT_CODE, TTL): O(1) via in-memory soroban_state
        // - Classic types (accounts, trustlines, offers, etc.): O(log n) via bucket list snapshot
        // This avoids cloning up to 100k entries on every ledger, which was causing severe
        // performance degradation (45ms per ledger once cache filled).
        let entries = HashMap::new();

        let snapshot = LedgerSnapshot::new(state.header.clone(), state.header_hash, entries);

        // Create a lookup function that checks in-memory Soroban state first for O(1) access,
        // then falls back to a bucket list snapshot for non-Soroban types or cache misses.
        // This optimization provides O(1) lookups for CONTRACT_DATA, CONTRACT_CODE, and TTL
        // entries instead of O(log n) bucket list B-tree traversals.
        //
        // We capture a BucketListSnapshot instead of the live Arc<RwLock<BucketList>> so that
        // point lookups during TX execution don't contend with the write lock held during
        // commit() (add_batch + hash computation). The snapshot holds Arc<Bucket> references
        // which are cheap clones and require no locking.
        let soroban_state_lookup = self.soroban_state.clone();
        let bucket_list_snapshot = Arc::new({
            let bl = self.bucket_list.read();
            stellar_core_bucket::BucketListSnapshot::new(&bl, state.header.clone())
        });
        let bls_for_lookup = bucket_list_snapshot.clone();
        let lookup_fn: crate::snapshot::EntryLookupFn = Arc::new(move |key: &LedgerKey| {
            // Check in-memory Soroban state first for Soroban entry types
            if crate::soroban_state::InMemorySorobanState::is_in_memory_type(key) {
                if let Some(entry) = soroban_state_lookup.read().get(key) {
                    return Ok(Some((*entry).clone()));
                }
            }
            // Fall back to bucket list snapshot for non-Soroban types or if not found in memory
            Ok(bls_for_lookup.get(key))
        });

        // Batch lookup function for loading multiple entries in a single pass.
        // Checks in-memory Soroban state first for ContractData/ContractCode/TTL/ConfigSetting
        // entries (O(1) cache hits), then batch-loads remaining keys from the bucket list
        // in a single traversal.
        let soroban_state_batch = self.soroban_state.clone();
        let bls_for_batch = bucket_list_snapshot.clone();
        let batch_lookup_fn: crate::snapshot::BatchEntryLookupFn =
            Arc::new(move |keys: &[LedgerKey]| {
                let mut result = Vec::new();
                let mut bucket_list_keys = Vec::new();

                // Check soroban state cache first for soroban types
                {
                    let soroban = soroban_state_batch.read();
                    for key in keys {
                        if crate::soroban_state::InMemorySorobanState::is_in_memory_type(key) {
                            if let Some(entry) = soroban.get(key) {
                                result.push((*entry).clone());
                                continue;
                            }
                        }
                        bucket_list_keys.push(key.clone());
                    }
                }

                // Batch-load remaining from bucket list in a single pass
                if !bucket_list_keys.is_empty() {
                    let bucket_entries = bls_for_batch
                        .load_keys_result(&bucket_list_keys)
                        .map_err(LedgerError::Bucket)?;
                    result.extend(bucket_entries);
                }

                Ok(result)
            });

        // Create entries function that reads from the in-memory offer store.
        // This avoids expensive SQL queries or bucket list scans during orderbook operations.
        // The in-memory store is populated at initialization and maintained incrementally.
        let offer_store = self.offer_store.clone();
        let offers_initialized = self.offers_initialized.clone();
        let bucket_list_entries = self.bucket_list.clone();
        let entries_fn: crate::snapshot::EntriesLookupFn = Arc::new(move || {
            // If offers are initialized, read from the in-memory store.
            if *offers_initialized.read() {
                let store = offer_store.read();
                return Ok(store.values().cloned().collect());
            }
            // Fall back to bucket list scan if offers not initialized.
            // Use streaming iterator to avoid excessive memory usage.
            let bucket_list = bucket_list_entries.read();
            let mut entries = Vec::new();
            for entry_result in bucket_list.live_entries_iter() {
                let entry = entry_result.map_err(LedgerError::Bucket)?;
                // Only collect offers for the offer cache fallback
                if matches!(entry.data, LedgerEntryData::Offer(_)) {
                    entries.push(entry);
                }
            }
            Ok(entries)
        });

        // Create index-based lookup for offers by (account, asset).
        let offer_store_idx = self.offer_store.clone();
        let offer_index = self.offer_account_asset_index.clone();
        let offers_init_idx = self.offers_initialized.clone();
        let bucket_list_idx = self.bucket_list.clone();
        let offers_by_account_asset_fn: crate::snapshot::OffersByAccountAssetFn = Arc::new(
            move |account_id: &AccountId, asset: &stellar_xdr::curr::Asset| {
                if !*offers_init_idx.read() {
                    // Fall back to bucket list scan
                    let bucket_list = bucket_list_idx.read();
                    let mut entries = Vec::new();
                    for entry_result in bucket_list.live_entries_iter() {
                        let entry = entry_result.map_err(LedgerError::Bucket)?;
                        if let LedgerEntryData::Offer(ref offer) = entry.data {
                            if offer.seller_id == *account_id
                                && (offer.buying == *asset || offer.selling == *asset)
                            {
                                entries.push(entry);
                            }
                        }
                    }
                    return Ok(entries);
                }

                let idx = offer_index.read();
                let store = offer_store_idx.read();
                let seller = account_id_bytes(account_id);
                let asset_key = AssetKey::from_asset(asset);

                let offer_ids = match idx.get(&(seller, asset_key)) {
                    Some(ids) => ids,
                    None => return Ok(Vec::new()),
                };

                let mut result = Vec::with_capacity(offer_ids.len());
                for &offer_id in offer_ids {
                    if let Some(entry) = store.get(&offer_id) {
                        result.push(entry.clone());
                    }
                }
                Ok(result)
            },
        );

        let mut handle = SnapshotHandle::with_lookups_and_entries(snapshot, lookup_fn, entries_fn);
        handle.set_batch_lookup(batch_lookup_fn);
        handle.set_offers_by_account_asset(offers_by_account_asset_fn);
        Ok(handle)
    }

    /// Commit a ledger close.
    ///
    /// This is called by LedgerCloseContext::commit().
    fn commit_close(
        &self,
        delta: LedgerDelta,
        new_header: LedgerHeader,
        new_header_hash: Hash256,
    ) -> Result<()> {
        // Note: Bucket list was already updated in LedgerCloseContext::commit()
        // Just validate the hash if configured
        if self.config.validate_bucket_hash {
            let bucket_list = self.bucket_list.read();
            let live_hash = bucket_list.hash();

            // Compute combined hash including hot archive
            let computed = {
                let hot_archive_guard = self.hot_archive_bucket_list.read();
                if let Some(ref hot_archive) = *hot_archive_guard {
                    use sha2::{Digest, Sha256};
                    let hot_hash = hot_archive.hash();
                    let mut hasher = Sha256::new();
                    hasher.update(live_hash.as_bytes());
                    hasher.update(hot_hash.as_bytes());
                    let result = hasher.finalize();
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(&result);
                    Hash256::from_bytes(bytes)
                } else {
                    live_hash
                }
            };

            let expected = Hash256::from(new_header.bucket_list_hash.0);
            if computed != expected {
                return Err(LedgerError::HashMismatch {
                    expected: expected.to_hex(),
                    actual: computed.to_hex(),
                });
            }
        }

        // Update in-memory offer store with offer changes
        if *self.offers_initialized.read() {
            let mut offer_upserts: Vec<LedgerEntry> = Vec::new();
            let mut offer_deletes: Vec<i64> = Vec::new();

            for change in delta.changes() {
                let key = change.key()?;
                // Only process offer entries
                if !matches!(key, LedgerKey::Offer(_)) {
                    continue;
                }

                match change {
                    EntryChange::Created(entry) => {
                        if matches!(entry.data, LedgerEntryData::Offer(_)) {
                            offer_upserts.push(entry.clone());
                        }
                    }
                    EntryChange::Updated { current, .. } => {
                        if matches!(current.data, LedgerEntryData::Offer(_)) {
                            offer_upserts.push(current.as_ref().clone());
                        }
                    }
                    EntryChange::Deleted { .. } => {
                        // Collect offer ID for deletion
                        if let LedgerKey::Offer(offer_key) = &key {
                            offer_deletes.push(offer_key.offer_id);
                        }
                    }
                }
            }

            // Update in-memory offer store
            if !offer_upserts.is_empty() || !offer_deletes.is_empty() {
                let mut store = self.offer_store.write();
                for entry in &offer_upserts {
                    if let LedgerEntryData::Offer(ref offer) = entry.data {
                        store.insert(offer.offer_id, entry.clone());
                    }
                }
                for offer_id in &offer_deletes {
                    store.remove(offer_id);
                }
            }
        }

        // Update state
        {
            let mut state = self.state.write();
            state.header = new_header;
            state.header_hash = new_header_hash;
        }

        Ok(())
    }

    /// Get Soroban network configuration information.
    ///
    /// Returns the Soroban-related configuration settings from the current ledger
    /// state, or `None` if not available (pre-protocol 20 or not initialized).
    pub fn soroban_network_info(&self) -> Option<SorobanNetworkInfo> {
        if !self.is_initialized() {
            return None;
        }
        let snapshot = self.create_snapshot().ok()?;
        load_soroban_network_info(&snapshot)
    }

    /// Look up a pending ConfigUpgradeSet by its key.
    ///
    /// This retrieves a ConfigUpgradeSet that has been uploaded to the network
    /// but not yet applied. Validators use this to validate scheduled upgrades.
    ///
    /// Returns `None` if:
    /// - The ledger is not initialized
    /// - The CONTRACT_DATA entry doesn't exist
    /// - The entry's TTL has expired
    /// - The entry is not TEMPORARY durability
    /// - The XDR cannot be decoded
    pub fn get_config_upgrade_set(
        &self,
        key: &stellar_xdr::curr::ConfigUpgradeSetKey,
    ) -> Option<std::sync::Arc<crate::config_upgrade::ConfigUpgradeSetFrame>> {
        if !self.is_initialized() {
            return None;
        }
        let snapshot = self.create_snapshot().ok()?;
        crate::config_upgrade::ConfigUpgradeSetFrame::make_from_key(&snapshot, key)
    }
}

/// Internal context for closing a single ledger.
///
/// This struct is used internally by [`LedgerManager::close_ledger`] to
/// process transactions and finalize the ledger.
struct LedgerCloseContext<'a> {
    manager: &'a LedgerManager,
    close_data: LedgerCloseData,
    prev_header: LedgerHeader,
    prev_header_hash: Hash256,
    delta: LedgerDelta,
    snapshot: SnapshotHandle,
    stats: LedgerCloseStats,
    upgrade_ctx: UpgradeContext,
    id_pool: u64,
    tx_results: Vec<stellar_xdr::curr::TransactionResultPair>,
    tx_result_metas: Vec<stellar_xdr::curr::TransactionResultMetaV1>,
    /// Keys of entries restored from hot archive during transaction execution.
    /// Passed to HotArchiveBucketList::add_batch to remove restored entries from archive.
    hot_archive_restored_keys: Vec<LedgerKey>,
}

#[allow(dead_code)]
impl<'a> LedgerCloseContext<'a> {
    /// Get the ledger sequence being closed.
    fn ledger_seq(&self) -> u32 {
        self.close_data.ledger_seq
    }

    /// Get the close time.
    fn close_time(&self) -> u64 {
        self.close_data.close_time
    }

    /// Get the snapshot for reading state.
    fn snapshot(&self) -> &SnapshotHandle {
        &self.snapshot
    }

    /// Get the delta for recording changes.
    fn delta(&self) -> &LedgerDelta {
        &self.delta
    }

    /// Get a mutable reference to the delta.
    fn delta_mut(&mut self) -> &mut LedgerDelta {
        &mut self.delta
    }

    /// Get the stats.
    fn stats(&self) -> &LedgerCloseStats {
        &self.stats
    }

    /// Load an entry from the snapshot.
    fn load_entry(&self, key: &LedgerKey) -> Result<Option<LedgerEntry>> {
        // First check if we have a pending change
        if let Some(change) = self.delta.get_change(key)? {
            return Ok(change.current_entry().cloned());
        }

        // Otherwise read from snapshot
        self.snapshot.get_entry(key)
    }

    /// Load an account from the snapshot.
    fn load_account(&self, id: &AccountId) -> Result<Option<AccountEntry>> {
        let key = LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
            account_id: id.clone(),
        });

        if let Some(entry) = self.load_entry(&key)? {
            if let LedgerEntryData::Account(account) = entry.data {
                return Ok(Some(account));
            }
        }

        Ok(None)
    }

    /// Record creation of a new entry.
    fn record_create(&mut self, entry: LedgerEntry) -> Result<()> {
        self.delta.record_create(entry)
    }

    /// Record update of an existing entry.
    fn record_update(&mut self, previous: LedgerEntry, current: LedgerEntry) -> Result<()> {
        self.delta.record_update(previous, current)
    }

    /// Record deletion of an entry.
    fn record_delete(&mut self, entry: LedgerEntry) -> Result<()> {
        self.delta.record_delete(entry)
    }

    /// Add an upgrade to apply.
    fn add_upgrade(&mut self, upgrade: stellar_xdr::curr::LedgerUpgrade) {
        self.upgrade_ctx.add_upgrade(upgrade);
    }

    /// Apply transactions from the transaction set.
    ///
    /// This executes all transactions in order, recording state changes
    /// to the delta and collecting results.
    fn apply_transactions(&mut self) -> Result<Vec<TransactionExecutionResult>> {
        let transactions = self.close_data.tx_set.transactions_with_base_fee();

        if transactions.is_empty() {
            self.tx_results.clear();
            return Ok(vec![]);
        }

        // Load SorobanConfig from ledger ConfigSettingEntry for accurate Soroban execution
        let soroban_config =
            crate::execution::load_soroban_config(&self.snapshot, self.prev_header.ledger_version);
        // Use transaction set hash as base PRNG seed for Soroban execution
        let soroban_base_prng_seed = self.close_data.tx_set_hash();
        let classic_events = ClassicEventConfig {
            emit_classic_events: self.manager.config.emit_classic_events,
            backfill_stellar_asset_events: self.manager.config.backfill_stellar_asset_events,
        };

        // Get reference to the module cache for Soroban contract execution.
        // The cache is pre-initialized from bucket list CONTRACT_CODE entries.
        let module_cache_guard = self.manager.module_cache.read();
        let module_cache = module_cache_guard.as_ref();

        // Get the hot archive for Protocol 23+ entry restoration.
        // We pass the Arc directly - the execution layer will check if it contains Some.
        let hot_archive = Some(self.manager.hot_archive_bucket_list.clone());

        let (results, tx_results, mut tx_result_metas, id_pool, hot_archive_restored_keys) =
            execute_transaction_set(
                &self.snapshot,
                &transactions,
                self.close_data.ledger_seq,
                self.close_data.close_time,
                self.prev_header.base_fee,
                self.prev_header.base_reserve,
                self.prev_header.ledger_version,
                self.manager.network_id,
                &mut self.delta,
                soroban_config,
                soroban_base_prng_seed.0,
                classic_events,
                module_cache,
                hot_archive,
            )?;
        if classic_events.events_enabled(self.prev_header.ledger_version) {
            for (idx, ((envelope, _), meta)) in transactions
                .iter()
                .zip(tx_result_metas.iter_mut())
                .enumerate()
            {
                let fee_charged = tx_results[idx].result.fee_charged;
                let frame =
                    TransactionFrame::with_network(envelope.clone(), self.manager.network_id);
                let fee_source = stellar_core_tx::muxed_to_account_id(&frame.fee_source_account());
                prepend_fee_event(
                    &mut meta.tx_apply_processing,
                    &fee_source,
                    fee_charged,
                    self.prev_header.ledger_version,
                    &self.manager.network_id,
                    classic_events,
                );
            }
        }
        self.id_pool = id_pool;
        self.tx_results = tx_results;
        self.tx_result_metas = tx_result_metas;
        self.hot_archive_restored_keys = hot_archive_restored_keys;

        // Update stats
        let tx_count = results.len();
        let success_count = results.iter().filter(|r| r.success).count();
        let op_count: usize = results.iter().map(|r| r.operation_results.len()).sum();
        let fees_collected: i64 = results.iter().map(|r| r.fee_charged).sum();

        self.stats
            .record_transactions(tx_count, success_count, op_count);
        self.stats.record_fees(fees_collected);

        Ok(results)
    }

    /// Commit the ledger close and produce the new header.
    fn commit(mut self) -> Result<LedgerCloseResult> {
        let start = std::time::Instant::now();
        tracing::debug!(
            ledger_seq = self.close_data.ledger_seq,
            "LedgerCloseContext::commit starting"
        );

        // Compute transaction result hash
        let result_set = stellar_xdr::curr::TransactionResultSet {
            results: self.tx_results.clone().try_into().unwrap_or_default(),
        };
        let tx_result_hash = Hash256::hash_xdr(&result_set).unwrap_or(Hash256::ZERO);

        // Log transaction results for debugging - helps identify tx execution differences
        tracing::info!(
            ledger_seq = self.close_data.ledger_seq,
            tx_count = self.tx_results.len(),
            tx_result_hash = %tx_result_hash.to_hex(),
            "TX_RESULT: Transaction result hash computed"
        );

        let mut upgraded_header = self.prev_header.clone();
        self.upgrade_ctx.apply_to_header(&mut upgraded_header);
        let protocol_version = upgraded_header.ledger_version;

        // Load state archival settings BEFORE acquiring bucket list lock to avoid deadlock.
        // The snapshot's lookup_fn tries to acquire a read lock on bucket_list, which would
        // deadlock if we're already holding the write lock.
        let eviction_settings = if protocol_version >= FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION
        {
            tracing::debug!(
                ledger_seq = self.close_data.ledger_seq,
                "Loading state archival settings"
            );
            let settings =
                load_state_archival_settings_from_snapshot(&self.snapshot).unwrap_or_default();
            tracing::debug!(
                ledger_seq = self.close_data.ledger_seq,
                "Loaded state archival settings"
            );
            Some(settings)
        } else {
            None
        };

        // Apply delta to bucket list FIRST, then compute its hash
        // This ensures the bucket_list_hash in the header matches the actual state
        tracing::debug!(
            ledger_seq = self.close_data.ledger_seq,
            "Acquiring bucket list write lock"
        );
        let bucket_list_hash = {
            let mut bucket_list = self.manager.bucket_list.write();
            tracing::debug!(
                ledger_seq = self.close_data.ledger_seq,
                "Acquired bucket list write lock"
            );
            let init_entries = self.delta.init_entries();
            let mut live_entries = self.delta.live_entries();
            let mut dead_entries = self.delta.dead_entries();

            // Filter out entries restored from hot archive that were then deleted.
            // These entries came from hot archive (not live bucket list), so deleting them
            // should NOT add them to the live bucket list's DEAD entries. The hot archive
            // restoration is handled separately via hot_archive_restored_keys.
            if !self.hot_archive_restored_keys.is_empty() {
                let restored_set: std::collections::HashSet<_> =
                    self.hot_archive_restored_keys.iter().collect();
                let before_count = dead_entries.len();
                dead_entries.retain(|key| !restored_set.contains(key));
                if dead_entries.len() != before_count {
                    tracing::debug!(
                        ledger_seq = self.close_data.ledger_seq,
                        before_count = before_count,
                        after_count = dead_entries.len(),
                        filtered_count = before_count - dead_entries.len(),
                        "Filtered hot archive restored entries from dead_entries"
                    );
                }
            }

            // Log bucket list entries for debugging hash mismatch
            tracing::debug!(
                ledger_seq = self.close_data.ledger_seq,
                init_count = init_entries.len(),
                live_count = live_entries.len(),
                dead_count = dead_entries.len(),
                "Bucket list entries from delta"
            );

            // Log first few entries for debugging
            for (i, entry) in init_entries.iter().take(5).enumerate() {
                let key = crate::delta::entry_to_key(entry).ok();
                tracing::debug!(
                    ledger_seq = self.close_data.ledger_seq,
                    index = i,
                    key = ?key,
                    last_modified = entry.last_modified_ledger_seq,
                    "INIT entry"
                );
            }
            for (i, entry) in live_entries.iter().take(5).enumerate() {
                let key = crate::delta::entry_to_key(entry).ok();
                tracing::debug!(
                    ledger_seq = self.close_data.ledger_seq,
                    index = i,
                    key = ?key,
                    last_modified = entry.last_modified_ledger_seq,
                    "LIVE entry"
                );
            }
            for (i, key) in dead_entries.iter().take(5).enumerate() {
                tracing::debug!(
                    ledger_seq = self.close_data.ledger_seq,
                    index = i,
                    key = ?key,
                    "DEAD entry"
                );
            }

            tracing::debug!(ledger_seq = self.close_data.ledger_seq, "Got delta entries");

            // Run incremental eviction scan for Protocol 23+
            // This must happen BEFORE applying transaction changes to match C++ stellar-core
            let mut archived_entries: Vec<LedgerEntry> = Vec::new();

            if protocol_version >= FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION {
                tracing::debug!(
                    ledger_seq = self.close_data.ledger_seq,
                    "Acquiring hot archive read lock"
                );
                let hot_archive_guard = self.manager.hot_archive_bucket_list.read();
                tracing::debug!(
                    ledger_seq = self.close_data.ledger_seq,
                    "Acquired hot archive read lock"
                );
                tracing::debug!(
                    ledger_seq = self.close_data.ledger_seq,
                    hot_archive_present = hot_archive_guard.is_some(),
                    "Checking hot archive presence"
                );
                if hot_archive_guard.is_some() {
                    tracing::debug!(
                        ledger_seq = self.close_data.ledger_seq,
                        "Dropping hot archive read lock"
                    );
                    drop(hot_archive_guard); // Release read lock before write operations
                    tracing::debug!(
                        ledger_seq = self.close_data.ledger_seq,
                        "Dropped hot archive read lock"
                    );

                    // Use pre-loaded eviction settings (loaded before bucket list lock)
                    let eviction_settings = eviction_settings.unwrap_or_default();

                    tracing::info!(
                        ledger_seq = self.close_data.ledger_seq,
                        "EVICTION: Loading eviction iterator from bucket list"
                    );
                    let eviction_iterator = load_eviction_iterator_from_bucket_list(&bucket_list);
                    tracing::info!(
                        ledger_seq = self.close_data.ledger_seq,
                        has_iterator = eviction_iterator.is_some(),
                        iter_level = eviction_iterator.as_ref().map(|i| i.bucket_list_level),
                        iter_is_curr = eviction_iterator.as_ref().map(|i| i.is_curr_bucket),
                        iter_offset = eviction_iterator.as_ref().map(|i| i.bucket_file_offset),
                        "EVICTION: Loaded eviction iterator from bucket list"
                    );

                    let iter = eviction_iterator.unwrap_or_else(|| {
                        tracing::info!(
                            ledger_seq = self.close_data.ledger_seq,
                            starting_level = eviction_settings.starting_eviction_scan_level,
                            "EVICTION: Creating new EvictionIterator (no entry found)"
                        );
                        EvictionIterator::new(eviction_settings.starting_eviction_scan_level)
                    });
                    tracing::info!(
                        ledger_seq = self.close_data.ledger_seq,
                        level = iter.bucket_list_level,
                        is_curr = iter.is_curr_bucket,
                        offset = iter.bucket_file_offset,
                        "EVICTION: EvictionIterator ready"
                    );

                    tracing::info!(
                        ledger_seq = self.close_data.ledger_seq,
                        start_level = iter.bucket_list_level,
                        start_is_curr = iter.is_curr_bucket,
                        start_offset = iter.bucket_file_offset,
                        scan_size = eviction_settings.eviction_scan_size,
                        max_entries_to_archive = eviction_settings.max_entries_to_archive,
                        "EVICTION: Starting eviction scan"
                    );

                    // Run eviction scan
                    let eviction_start = std::time::Instant::now();
                    let eviction_result = bucket_list
                        .scan_for_eviction_incremental(
                            iter,
                            self.close_data.ledger_seq,
                            &eviction_settings,
                        )
                        .map_err(LedgerError::Bucket)?;
                    let eviction_duration = eviction_start.elapsed();

                    tracing::info!(
                        ledger_seq = self.close_data.ledger_seq,
                        bytes_scanned = eviction_result.bytes_scanned,
                        archived_count = eviction_result.archived_entries.len(),
                        evicted_count = eviction_result.evicted_keys.len(),
                        end_level = eviction_result.end_iterator.bucket_list_level,
                        end_is_curr = eviction_result.end_iterator.is_curr_bucket,
                        end_offset = eviction_result.end_iterator.bucket_file_offset,
                        duration_ms = eviction_duration.as_millis(),
                        "EVICTION: Incremental eviction scan completed"
                    );

                    // Log archived entries for debugging
                    if !eviction_result.archived_entries.is_empty() {
                        for (i, entry) in eviction_result.archived_entries.iter().enumerate() {
                            let key_type = match &entry.data {
                                LedgerEntryData::ContractData(cd) => {
                                    format!("ContractData({:?})", cd.durability)
                                }
                                LedgerEntryData::ContractCode(_) => "ContractCode".to_string(),
                                _ => format!("{:?}", std::mem::discriminant(&entry.data)),
                            };
                            tracing::info!(
                                ledger_seq = self.close_data.ledger_seq,
                                entry_index = i,
                                key_type = %key_type,
                                last_modified = entry.last_modified_ledger_seq,
                                "EVICTION: Archived entry"
                            );
                        }
                    }

                    // Add evicted keys to dead entries
                    dead_entries.extend(eviction_result.evicted_keys);
                    archived_entries = eviction_result.archived_entries;

                    // Add EvictionIterator update to live entries
                    let eviction_iter_entry = LedgerEntry {
                        last_modified_ledger_seq: self.close_data.ledger_seq,
                        data: LedgerEntryData::ConfigSetting(ConfigSettingEntry::EvictionIterator(
                            XdrEvictionIterator {
                                bucket_file_offset: eviction_result.end_iterator.bucket_file_offset
                                    as u64,
                                bucket_list_level: eviction_result.end_iterator.bucket_list_level,
                                is_curr_bucket: eviction_result.end_iterator.is_curr_bucket,
                            },
                        )),
                        ext: LedgerEntryExt::V0,
                    };
                    live_entries.push(eviction_iter_entry);

                    tracing::debug!(
                        ledger_seq = self.close_data.ledger_seq,
                        level = eviction_result.end_iterator.bucket_list_level,
                        is_curr = eviction_result.end_iterator.is_curr_bucket,
                        offset = eviction_result.end_iterator.bucket_file_offset,
                        "Added EvictionIterator entry to live entries"
                    );
                }
            }

            // Update state size window (Protocol 20+)
            // IMPORTANT: Per C++ stellar-core, we snapshot the state size BEFORE flushing
            // the updated entries into in-memory state. So the snapshot taken at ledger N
            // will have the state size for ledger N-1. This is a protocol implementation detail.
            if protocol_version >= stellar_core_common::MIN_SOROBAN_PROTOCOL_VERSION {
                // Check if window entry was already added by transaction execution
                let has_window_entry = live_entries.iter().any(|e| {
                    matches!(
                        &e.data,
                        LedgerEntryData::ConfigSetting(
                            stellar_xdr::curr::ConfigSettingEntry::LiveSorobanStateSizeWindow(_)
                        )
                    )
                });

                if !has_window_entry {
                    // Check if this is a sample ledger before computing window entry
                    // Sample period is typically 64 ledgers
                    let archival_key = stellar_xdr::curr::LedgerKey::ConfigSetting(
                        stellar_xdr::curr::LedgerKeyConfigSetting {
                            config_setting_id: stellar_xdr::curr::ConfigSettingId::StateArchival,
                        },
                    );
                    let sample_period = bucket_list
                        .get(&archival_key)
                        .ok()
                        .flatten()
                        .and_then(|e| {
                            if let LedgerEntryData::ConfigSetting(
                                stellar_xdr::curr::ConfigSettingEntry::StateArchival(archival),
                            ) = e.data
                            {
                                Some(archival.live_soroban_state_size_window_sample_period)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(64); // Default to 64 if not found

                    // Only compute state size on sample ledgers
                    let is_sample_ledger =
                        sample_period > 0 && self.close_data.ledger_seq % sample_period == 0;

                    if is_sample_ledger {
                        // Use in-memory Soroban state total_size() - this is the state BEFORE
                        // this ledger's changes are applied (matching C++ behavior)
                        let soroban_state_size = self.manager.soroban_state.read().total_size();

                        if let Some(window_entry) =
                            crate::execution::compute_state_size_window_entry(
                                self.close_data.ledger_seq,
                                protocol_version,
                                &bucket_list,
                                soroban_state_size,
                            )
                        {
                            tracing::info!(
                                ledger_seq = self.close_data.ledger_seq,
                                soroban_state_size = soroban_state_size,
                                "Adding state size window entry to live entries (from in-memory state)"
                            );
                            live_entries.push(window_entry);
                        }
                    }
                }
            }

            // Update in-memory Soroban state with changes from this ledger.
            // This happens AFTER computing state size window (see comment above).
            if protocol_version >= stellar_core_common::MIN_SOROBAN_PROTOCOL_VERSION {
                // Load rent config for accurate code size calculation
                let rent_config = self.manager.load_soroban_rent_config(&bucket_list);
                let mut soroban_state = self.manager.soroban_state.write();

                // Process init entries (creates)
                for entry in &init_entries {
                    if let Err(e) = soroban_state.process_entry_create(
                        entry,
                        protocol_version,
                        rent_config.as_ref(),
                    ) {
                        tracing::trace!(error = %e, "Failed to process init entry in soroban state");
                    }
                }

                // Process live entries (updates)
                for entry in &live_entries {
                    if let Err(e) = soroban_state.process_entry_update(
                        entry,
                        protocol_version,
                        rent_config.as_ref(),
                    ) {
                        tracing::trace!(error = %e, "Failed to process live entry in soroban state");
                    }
                }

                // Process dead entries (deletes)
                for key in &dead_entries {
                    if let Err(e) = soroban_state.process_entry_delete(key) {
                        tracing::trace!(error = %e, "Failed to process dead entry in soroban state");
                    }

                    // Remove evicted contract code from the module cache to prevent
                    // unbounded memory growth.
                    if let LedgerKey::ContractCode(cc) = key {
                        let module_cache_guard = self.manager.module_cache.read();
                        if let Some(cache) = module_cache_guard.as_ref() {
                            if cache.remove_contract(&cc.hash.0) {
                                tracing::debug!(
                                    hash = ?cc.hash,
                                    "Removed evicted contract code from module cache"
                                );
                            }
                        }
                    }
                }

                tracing::debug!(
                    ledger_seq = self.close_data.ledger_seq,
                    total_size = soroban_state.total_size(),
                    data_count = soroban_state.contract_data_count(),
                    code_count = soroban_state.contract_code_count(),
                    "Updated in-memory Soroban state"
                );
            }

            // CRITICAL: Advance the bucket list through any skipped ledgers.
            // The bucket list merge algorithm depends on being called for every ledger
            // in sequence. In live mode, we may skip ledgers if there are no transactions
            // between consensus rounds. This ensures proper merge timing.
            let current_bl_ledger = bucket_list.ledger_seq();
            tracing::debug!(
                current_bl_ledger = current_bl_ledger,
                target_ledger = self.close_data.ledger_seq,
                needs_advance = current_bl_ledger < self.close_data.ledger_seq - 1,
                "Checking if bucket list advance is needed"
            );
            if current_bl_ledger < self.close_data.ledger_seq - 1 {
                let advance_from = current_bl_ledger + 1;
                let advance_to = self.close_data.ledger_seq;
                tracing::debug!(
                    current_bl_ledger = current_bl_ledger,
                    target_ledger = self.close_data.ledger_seq,
                    skipped_count = advance_to - advance_from,
                    "Advancing bucket list through empty ledgers"
                );
                bucket_list.advance_to_ledger(
                    self.close_data.ledger_seq,
                    protocol_version,
                    BucketListType::Live,
                )?;
            }

            // Log bucket list hash BEFORE add_batch
            let pre_add_batch_hash = bucket_list.hash();
            tracing::debug!(
                ledger_seq = self.close_data.ledger_seq,
                pre_add_batch_hash = %pre_add_batch_hash.to_hex(),
                init_count = init_entries.len(),
                live_count = live_entries.len(),
                dead_count = dead_entries.len(),
                "Bucket list state before add_batch"
            );

            // Detailed entry logging for debugging
            for (i, entry) in init_entries.iter().enumerate() {
                let key = stellar_core_bucket::ledger_entry_to_key(entry);
                tracing::trace!(
                    ledger_seq = self.close_data.ledger_seq,
                    idx = i,
                    entry_type = ?std::mem::discriminant(&entry.data),
                    key = ?key,
                    last_modified = entry.last_modified_ledger_seq,
                    "INIT entry"
                );
            }
            for (i, entry) in live_entries.iter().enumerate() {
                let key = stellar_core_bucket::ledger_entry_to_key(entry);
                // For ConfigSetting entries, log the data for comparison
                let config_data = match &entry.data {
                    LedgerEntryData::ConfigSetting(cs) => Some(format!("{:?}", cs)),
                    _ => None,
                };
                tracing::trace!(
                    ledger_seq = self.close_data.ledger_seq,
                    idx = i,
                    entry_type = ?std::mem::discriminant(&entry.data),
                    key = ?key,
                    last_modified = entry.last_modified_ledger_seq,
                    config_data = ?config_data,
                    "LIVE entry"
                );
            }
            for (i, key) in dead_entries.iter().enumerate() {
                tracing::trace!(
                    ledger_seq = self.close_data.ledger_seq,
                    idx = i,
                    key = ?key,
                    "DEAD entry"
                );
            }

            // Compute hashes of entries being added for debugging
            // This allows us to compare with expected values when a mismatch occurs
            let init_entries_hash = {
                use sha2::{Digest, Sha256};
                use stellar_xdr::curr::{Limits, WriteXdr};
                let mut hasher = Sha256::new();
                for entry in &init_entries {
                    if let Ok(xdr) = entry.to_xdr(Limits::none()) {
                        hasher.update(&xdr);
                    }
                }
                let result = hasher.finalize();
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&result);
                Hash256::from_bytes(bytes)
            };
            let live_entries_hash = {
                use sha2::{Digest, Sha256};
                use stellar_xdr::curr::{Limits, WriteXdr};
                let mut hasher = Sha256::new();
                for entry in &live_entries {
                    if let Ok(xdr) = entry.to_xdr(Limits::none()) {
                        hasher.update(&xdr);
                    }
                }
                let result = hasher.finalize();
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&result);
                Hash256::from_bytes(bytes)
            };
            let dead_entries_hash = {
                use sha2::{Digest, Sha256};
                use stellar_xdr::curr::{Limits, WriteXdr};
                let mut hasher = Sha256::new();
                for key in &dead_entries {
                    if let Ok(xdr) = key.to_xdr(Limits::none()) {
                        hasher.update(&xdr);
                    }
                }
                let result = hasher.finalize();
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&result);
                Hash256::from_bytes(bytes)
            };

            // Log the inputs to add_batch - this is critical for debugging mismatches
            tracing::info!(
                ledger_seq = self.close_data.ledger_seq,
                init_count = init_entries.len(),
                live_count = live_entries.len(),
                dead_count = dead_entries.len(),
                init_entries_hash = %init_entries_hash.to_hex(),
                live_entries_hash = %live_entries_hash.to_hex(),
                dead_entries_hash = %dead_entries_hash.to_hex(),
                pre_add_batch_hash = %bucket_list.hash().to_hex(),
                bucket_list_ledger_seq = bucket_list.ledger_seq(),
                "BUCKET_INPUT: Entries being added to live bucket list"
            );

            bucket_list.add_batch(
                self.close_data.ledger_seq,
                protocol_version,
                BucketListType::Live,
                init_entries,
                live_entries,
                dead_entries,
            )?;

            let live_hash = bucket_list.hash();

            tracing::info!(
                ledger_seq = self.close_data.ledger_seq,
                post_add_batch_hash = %live_hash.to_hex(),
                "BUCKET_OUTPUT: Live bucket list hash after add_batch"
            );

            // For Protocol 23+, update hot archive and combine bucket list hashes
            if protocol_version >= FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION {
                let mut hot_archive_guard = self.manager.hot_archive_bucket_list.write();
                if let Some(ref mut hot_archive) = *hot_archive_guard {
                    // Advance hot archive through any skipped ledgers (same as live bucket list)
                    let current_hot_ledger = hot_archive.ledger_seq();
                    if current_hot_ledger < self.close_data.ledger_seq - 1 {
                        tracing::debug!(
                            current_hot_ledger = current_hot_ledger,
                            target_ledger = self.close_data.ledger_seq,
                            skipped_count = self.close_data.ledger_seq - current_hot_ledger - 1,
                            "Advancing hot archive bucket list through empty ledgers"
                        );
                        hot_archive
                            .advance_to_ledger(self.close_data.ledger_seq, protocol_version)?;
                    }

                    // Add archived entries to hot archive bucket list
                    // Must call add_batch even with empty entries to maintain spill consistency
                    // restored_keys contains entries restored via RestoreFootprint or InvokeHostFunction
                    let pre_hot_hash = hot_archive.hash();

                    // Compute hashes of hot archive inputs for debugging
                    let archived_entries_hash = {
                        use sha2::{Digest, Sha256};
                        use stellar_xdr::curr::{Limits, WriteXdr};
                        let mut hasher = Sha256::new();
                        for entry in &archived_entries {
                            if let Ok(xdr) = entry.to_xdr(Limits::none()) {
                                hasher.update(&xdr);
                            }
                        }
                        let result = hasher.finalize();
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(&result);
                        Hash256::from_bytes(bytes)
                    };
                    let restored_keys_hash = {
                        use sha2::{Digest, Sha256};
                        use stellar_xdr::curr::{Limits, WriteXdr};
                        let mut hasher = Sha256::new();
                        for key in &self.hot_archive_restored_keys {
                            if let Ok(xdr) = key.to_xdr(Limits::none()) {
                                hasher.update(&xdr);
                            }
                        }
                        let result = hasher.finalize();
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(&result);
                        Hash256::from_bytes(bytes)
                    };

                    tracing::info!(
                        ledger_seq = self.close_data.ledger_seq,
                        archived_count = archived_entries.len(),
                        restored_count = self.hot_archive_restored_keys.len(),
                        archived_entries_hash = %archived_entries_hash.to_hex(),
                        restored_keys_hash = %restored_keys_hash.to_hex(),
                        pre_hot_hash = %pre_hot_hash.to_hex(),
                        hot_archive_ledger_seq = hot_archive.ledger_seq(),
                        "BUCKET_INPUT: Entries being added to hot archive bucket list"
                    );

                    hot_archive.add_batch(
                        self.close_data.ledger_seq,
                        protocol_version,
                        archived_entries.clone(),
                        self.hot_archive_restored_keys.clone(),
                    )?;

                    use sha2::{Digest, Sha256};
                    let hot_hash = hot_archive.hash();

                    tracing::info!(
                        ledger_seq = self.close_data.ledger_seq,
                        post_hot_hash = %hot_hash.to_hex(),
                        "BUCKET_OUTPUT: Hot archive bucket list hash after add_batch"
                    );

                    let mut hasher = Sha256::new();
                    hasher.update(live_hash.as_bytes());
                    hasher.update(hot_hash.as_bytes());
                    let result = hasher.finalize();
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(&result);
                    let combined_hash = Hash256::from_bytes(bytes);

                    tracing::info!(
                        ledger_seq = self.close_data.ledger_seq,
                        live_hash = %live_hash.to_hex(),
                        hot_hash = %hot_hash.to_hex(),
                        combined_hash = %combined_hash.to_hex(),
                        "BUCKET_OUTPUT: Combined bucket list hash"
                    );
                    combined_hash
                } else {
                    // No hot archive bucket list available, use live hash only
                    // This shouldn't happen for Protocol 23+ but fall back gracefully
                    tracing::warn!(
                        ledger_seq = self.close_data.ledger_seq,
                        protocol_version = protocol_version,
                        live_hash = %live_hash.to_hex(),
                        "HOT ARCHIVE IS NONE for Protocol 23+! Using live hash only - this WILL cause hash mismatch!"
                    );
                    live_hash
                }
            } else {
                live_hash
            }
        };

        // Log all inputs to create_next_header for debugging header mismatch
        let total_coins = self.prev_header.total_coins + self.delta.total_coins_delta();
        let fee_pool = self.prev_header.fee_pool + self.delta.fee_pool_delta();
        tracing::debug!(
            ledger_seq = self.close_data.ledger_seq,
            prev_header_hash = %self.prev_header_hash.to_hex(),
            prev_ledger_seq = self.prev_header.ledger_seq,
            close_time = self.close_data.close_time,
            tx_set_hash = %self.close_data.tx_set_hash().to_hex(),
            bucket_list_hash = %bucket_list_hash.to_hex(),
            tx_result_hash = %tx_result_hash.to_hex(),
            prev_total_coins = self.prev_header.total_coins,
            total_coins_delta = self.delta.total_coins_delta(),
            total_coins = total_coins,
            prev_fee_pool = self.prev_header.fee_pool,
            fee_pool_delta = self.delta.fee_pool_delta(),
            fee_pool = fee_pool,
            inflation_seq = self.prev_header.inflation_seq,
            prev_ledger_version = self.prev_header.ledger_version,
            prev_base_fee = self.prev_header.base_fee,
            prev_base_reserve = self.prev_header.base_reserve,
            prev_max_tx_set_size = self.prev_header.max_tx_set_size,
            "Header creation inputs"
        );

        // Create the new header
        let mut new_header = create_next_header(
            &self.prev_header,
            self.prev_header_hash,
            self.close_data.close_time,
            self.close_data.tx_set_hash(),
            bucket_list_hash,
            tx_result_hash,
            total_coins,
            fee_pool,
            self.prev_header.inflation_seq,
            self.close_data.stellar_value_ext.clone(),
        );

        // Apply upgrades to header fields (e.g., ledger_version, base_fee)
        self.upgrade_ctx.apply_to_header(&mut new_header);

        // Apply config upgrades (Soroban settings stored in CONTRACT_DATA)
        if self.upgrade_ctx.has_config_upgrades() {
            let (state_archival_changed, memory_limit_changed) = self
                .upgrade_ctx
                .apply_config_upgrades(&self.snapshot, &mut self.delta)?;

            if state_archival_changed {
                tracing::info!(
                    ledger_seq = self.close_data.ledger_seq,
                    "State archival settings changed via config upgrade"
                );
            }

            if memory_limit_changed {
                tracing::info!(
                    ledger_seq = self.close_data.ledger_seq,
                    "Memory limit settings changed via config upgrade"
                );
            }
        }

        // Also set the raw upgrades in scp_value.upgrades for correct header hash
        // The upgrades need to be XDR-encoded as UpgradeType (opaque bytes)
        let raw_upgrades: Vec<stellar_xdr::curr::UpgradeType> = self
            .close_data
            .upgrades
            .iter()
            .filter_map(|upgrade| {
                use stellar_xdr::curr::WriteXdr;
                upgrade
                    .to_xdr(stellar_xdr::curr::Limits::none())
                    .ok()
                    .and_then(|bytes| stellar_xdr::curr::UpgradeType::try_from(bytes).ok())
            })
            .collect();
        if let Ok(upgrades_vec) = raw_upgrades.try_into() {
            new_header.scp_value.upgrades = upgrades_vec;
        }

        new_header.id_pool = self.id_pool;

        // Compute header hash - add detailed XDR logging for debugging
        use stellar_xdr::curr::{Limits, WriteXdr};
        let header_xdr_bytes = new_header.to_xdr(Limits::none())?;
        let header_xdr_hex: String = header_xdr_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        tracing::debug!(
            ledger_seq = new_header.ledger_seq,
            header_xdr_len = header_xdr_bytes.len(),
            header_xdr_hex = %header_xdr_hex,
            "Full header XDR for hash debugging"
        );
        let header_hash = compute_header_hash(&new_header)?;

        // Record stats
        let entries_created = self.delta.changes().filter(|c| c.is_created()).count();
        let entries_updated = self.delta.changes().filter(|c| c.is_updated()).count();
        let entries_deleted = self.delta.changes().filter(|c| c.is_deleted()).count();
        self.stats
            .record_entry_changes(entries_created, entries_updated, entries_deleted);

        // Commit to manager
        self.manager
            .commit_close(self.delta, new_header.clone(), header_hash)?;

        self.stats
            .set_close_time(start.elapsed().as_millis() as u64);

        // Describe the StellarValueExt for logging
        let stellar_value_ext_desc = match &new_header.scp_value.ext {
            stellar_xdr::curr::StellarValueExt::Basic => "Basic".to_string(),
            stellar_xdr::curr::StellarValueExt::Signed(_) => "Signed".to_string(),
        };

        info!(
            ledger_seq = new_header.ledger_seq,
            tx_count = self.stats.tx_count,
            close_time_ms = self.stats.close_time_ms,
            computed_hash = %header_hash.to_hex(),
            bucket_list_hash = %bucket_list_hash.to_hex(),
            tx_result_hash = %tx_result_hash.to_hex(),
            total_coins = new_header.total_coins,
            fee_pool = new_header.fee_pool,
            close_time = new_header.scp_value.close_time.0,
            tx_set_hash = %Hash256::from(new_header.scp_value.tx_set_hash.0).to_hex(),
            upgrades_count = new_header.scp_value.upgrades.len(),
            stellar_value_ext = %stellar_value_ext_desc,
            prev_header_hash = %self.prev_header_hash.to_hex(),
            skip_list_0 = %Hash256::from(new_header.skip_list[0].clone()).to_hex(),
            skip_list_1 = %Hash256::from(new_header.skip_list[1].clone()).to_hex(),
            skip_list_2 = %Hash256::from(new_header.skip_list[2].clone()).to_hex(),
            skip_list_3 = %Hash256::from(new_header.skip_list[3].clone()).to_hex(),
            id_pool = new_header.id_pool,
            inflation_seq = new_header.inflation_seq,
            base_fee = new_header.base_fee,
            base_reserve = new_header.base_reserve,
            max_tx_set_size = new_header.max_tx_set_size,
            "Ledger closed"
        );

        let meta = build_ledger_close_meta(
            &self.close_data,
            &new_header,
            header_hash,
            &self.tx_result_metas,
        );

        Ok(LedgerCloseResult::new(new_header, header_hash)
            .with_tx_results(self.tx_results)
            .with_meta(meta))
    }

    /// Abort the ledger close without committing.
    fn abort(self) {
        debug!(
            ledger_seq = self.close_data.ledger_seq,
            "Ledger close aborted"
        );
        // Delta is dropped, no changes are committed
    }
}

fn build_generalized_tx_set(tx_set: &TransactionSetVariant) -> GeneralizedTransactionSet {
    match tx_set {
        TransactionSetVariant::Generalized(set) => set.clone(),
        TransactionSetVariant::Classic(set) => {
            let component = TxSetComponent::TxsetCompTxsMaybeDiscountedFee(
                TxSetComponentTxsMaybeDiscountedFee {
                    base_fee: None,
                    txs: set.txs.clone(),
                },
            );
            let phase = TransactionPhase::V0(vec![component].try_into().unwrap_or_default());
            GeneralizedTransactionSet::V1(TransactionSetV1 {
                previous_ledger_hash: set.previous_ledger_hash.clone(),
                phases: vec![phase].try_into().unwrap_or_default(),
            })
        }
    }
}

fn build_ledger_close_meta(
    close_data: &LedgerCloseData,
    header: &LedgerHeader,
    header_hash: Hash256,
    tx_result_metas: &[TransactionResultMetaV1],
) -> LedgerCloseMeta {
    let ledger_header = LedgerHeaderHistoryEntry {
        hash: Hash::from(header_hash),
        header: header.clone(),
        ext: LedgerHeaderHistoryEntryExt::V0,
    };

    let tx_set = build_generalized_tx_set(&close_data.tx_set);

    LedgerCloseMeta::V2(LedgerCloseMetaV2 {
        ext: LedgerCloseMetaExt::V0,
        ledger_header,
        tx_set,
        tx_processing: tx_result_metas.to_vec().try_into().unwrap_or_default(),
        upgrades_processing: VecM::<UpgradeEntryMeta>::default(),
        scp_info: close_data
            .scp_history
            .clone()
            .try_into()
            .unwrap_or_default(),
        total_byte_size_of_live_soroban_state: 0,
        evicted_keys: VecM::default(),
    })
}

/// Create a genesis ledger header.
fn create_genesis_header() -> LedgerHeader {
    LedgerHeader {
        ledger_version: 0,
        previous_ledger_hash: Hash([0u8; 32]),
        scp_value: stellar_xdr::curr::StellarValue {
            tx_set_hash: Hash([0u8; 32]),
            close_time: stellar_xdr::curr::TimePoint(0),
            upgrades: stellar_xdr::curr::VecM::default(),
            ext: stellar_xdr::curr::StellarValueExt::Basic,
        },
        tx_set_result_hash: Hash([0u8; 32]),
        bucket_list_hash: Hash([0u8; 32]),
        ledger_seq: 0,
        total_coins: 0,
        fee_pool: 0,
        inflation_seq: 0,
        id_pool: 0,
        base_fee: 100,
        base_reserve: 5_000_000,
        max_tx_set_size: 1000,
        skip_list: std::array::from_fn(|_| Hash([0u8; 32])),
        ext: stellar_xdr::curr::LedgerHeaderExt::V0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        LedgerScpMessages, ScpHistoryEntry, ScpHistoryEntryV0, TransactionSet,
    };

    // Note: These tests require proper mocking of BucketManager and Database
    // For now they are placeholder tests

    #[test]
    fn test_genesis_header() {
        let header = create_genesis_header();
        assert_eq!(header.ledger_seq, 0);
        assert_eq!(header.base_fee, 100);
    }

    #[test]
    fn test_ledger_manager_config_default() {
        let config = LedgerManagerConfig::default();
        assert!(config.validate_bucket_hash);
    }

    #[test]
    fn test_ledger_close_meta_includes_scp_history() {
        let scp_entry = ScpHistoryEntry::V0(ScpHistoryEntryV0 {
            quorum_sets: VecM::default(),
            ledger_messages: LedgerScpMessages {
                ledger_seq: 1,
                messages: VecM::default(),
            },
        });
        let close_data = LedgerCloseData::new(
            1,
            TransactionSetVariant::Classic(TransactionSet {
                previous_ledger_hash: Hash::from(Hash256::ZERO),
                txs: VecM::default(),
            }),
            0,
            Hash256::ZERO,
        )
        .with_scp_history(vec![scp_entry.clone()]);

        let header = create_genesis_header();
        let meta = build_ledger_close_meta(&close_data, &header, Hash256::ZERO, &[]);
        let scp_info_len = match meta {
            LedgerCloseMeta::V0(_) => 0,
            LedgerCloseMeta::V1(v1) => v1.scp_info.len(),
            LedgerCloseMeta::V2(v2) => v2.scp_info.len(),
        };
        assert_eq!(scp_info_len, 1);
    }
}
