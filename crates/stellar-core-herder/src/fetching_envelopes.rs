//! Fetching envelopes management.
//!
//! This module handles SCP envelopes that are waiting for their dependencies
//! (TxSets and QuorumSets) to be fetched from peers. When an envelope arrives
//! referencing data we don't have, we start fetching it and queue the envelope.
//! Once all dependencies are received, the envelope is ready for processing.
//!
//! This is the Rust equivalent of C++ stellar-core's `PendingEnvelopes` fetching logic.

use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use stellar_core_common::Hash256;
use stellar_core_overlay::{ItemFetcher, ItemFetcherConfig, ItemType, PeerId};
use stellar_core_scp::SlotIndex;
use stellar_xdr::curr::{Hash, Limits, ReadXdr, ScpEnvelope, ScpQuorumSet};
use tracing::{debug, trace};

/// Result of receiving an SCP envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvResult {
    /// Envelope is ready for processing (all dependencies available).
    Ready,
    /// Envelope is being fetched (waiting for dependencies).
    Fetching,
    /// Envelope was already processed or is a duplicate.
    AlreadyProcessed,
    /// Envelope was discarded (invalid or rejected).
    Discarded,
}

/// State of envelopes for a single slot.
#[derive(Default)]
pub struct SlotEnvelopes {
    /// Envelopes we have discarded.
    discarded: HashSet<Hash256>,
    /// Envelopes we have processed already.
    processed: HashSet<Hash256>,
    /// Envelopes we are fetching right now (hash -> received time).
    fetching: HashMap<Hash256, (ScpEnvelope, Instant)>,
    /// Envelopes that are ready to be processed.
    ready: Vec<ScpEnvelope>,
}

/// Configuration for fetching envelopes.
#[derive(Debug, Clone)]
pub struct FetchingConfig {
    /// Configuration for the TxSet fetcher.
    pub tx_set_fetcher_config: ItemFetcherConfig,
    /// Configuration for the QuorumSet fetcher.
    pub quorum_set_fetcher_config: ItemFetcherConfig,
    /// Maximum slots to track.
    pub max_slots: usize,
    /// Maximum tx sets to cache. Once exceeded, older slots' tx sets are evicted.
    pub max_tx_set_cache: usize,
    /// Maximum quorum sets to cache. Once exceeded, oldest entries are evicted.
    pub max_quorum_set_cache: usize,
}

impl Default for FetchingConfig {
    fn default() -> Self {
        Self {
            tx_set_fetcher_config: ItemFetcherConfig::default(),
            quorum_set_fetcher_config: ItemFetcherConfig::default(),
            max_slots: 12,
            max_tx_set_cache: 100,
            max_quorum_set_cache: 100,
        }
    }
}

/// Manages fetching of TxSets and QuorumSets for SCP envelopes.
///
/// When an SCP envelope references a TxSet or QuorumSet we don't have,
/// this manager starts fetching it from peers. Once received, envelopes
/// waiting for that data become ready for processing.
pub struct FetchingEnvelopes {
    /// Configuration.
    config: FetchingConfig,
    /// Per-slot envelope state.
    slots: DashMap<SlotIndex, SlotEnvelopes>,
    /// TxSet fetcher.
    tx_set_fetcher: ItemFetcher,
    /// QuorumSet fetcher.
    quorum_set_fetcher: ItemFetcher,
    /// Cached TxSets (hash -> (slot, data)).
    tx_set_cache: DashMap<Hash256, (SlotIndex, Vec<u8>)>,
    /// Cached QuorumSets (hash -> data).
    quorum_set_cache: DashMap<Hash256, Arc<ScpQuorumSet>>,
    /// Statistics.
    stats: RwLock<FetchingStats>,
}

/// Statistics about fetching.
#[derive(Debug, Clone, Default)]
pub struct FetchingStats {
    /// Total envelopes received.
    pub envelopes_received: u64,
    /// Envelopes that were immediately ready.
    pub envelopes_ready: u64,
    /// Envelopes waiting for fetching.
    pub envelopes_fetching: u64,
    /// Envelopes that were duplicates.
    pub envelopes_duplicate: u64,
    /// TxSets received.
    pub tx_sets_received: u64,
    /// QuorumSets received.
    pub quorum_sets_received: u64,
}

impl FetchingEnvelopes {
    /// Create a new fetching envelopes manager.
    pub fn new(config: FetchingConfig) -> Self {
        Self {
            tx_set_fetcher: ItemFetcher::new(ItemType::TxSet, config.tx_set_fetcher_config.clone()),
            quorum_set_fetcher: ItemFetcher::new(
                ItemType::QuorumSet,
                config.quorum_set_fetcher_config.clone(),
            ),
            config,
            slots: DashMap::new(),
            tx_set_cache: DashMap::new(),
            quorum_set_cache: DashMap::new(),
            stats: RwLock::new(FetchingStats::default()),
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(FetchingConfig::default())
    }

    /// Set the callback for requesting TxSets from peers.
    pub fn set_tx_set_ask_peer(&mut self, f: Box<dyn Fn(&PeerId, &Hash, ItemType) + Send + Sync>) {
        self.tx_set_fetcher.set_ask_peer(f);
    }

    /// Set the callback for requesting QuorumSets from peers.
    pub fn set_quorum_set_ask_peer(
        &mut self,
        f: Box<dyn Fn(&PeerId, &Hash, ItemType) + Send + Sync>,
    ) {
        self.quorum_set_fetcher.set_ask_peer(f);
    }

    /// Update the list of available peers.
    pub fn set_available_peers(&self, peers: Vec<PeerId>) {
        self.tx_set_fetcher.set_available_peers(peers.clone());
        self.quorum_set_fetcher.set_available_peers(peers);
    }

    /// Receive an SCP envelope.
    ///
    /// Returns the result indicating whether the envelope is ready, fetching,
    /// or was already processed/discarded.
    pub fn recv_envelope(&self, envelope: ScpEnvelope) -> RecvResult {
        let slot = envelope.statement.slot_index;
        let env_hash = Self::compute_envelope_hash(&envelope);

        self.stats.write().envelopes_received += 1;

        // Get or create slot state
        let mut slot_state = self.slots.entry(slot).or_default();

        // Check if already processed or discarded
        if slot_state.processed.contains(&env_hash) || slot_state.discarded.contains(&env_hash) {
            self.stats.write().envelopes_duplicate += 1;
            return RecvResult::AlreadyProcessed;
        }

        // Check if already fetching
        if slot_state.fetching.contains_key(&env_hash) {
            return RecvResult::Fetching;
        }

        // Check if we have all dependencies
        let (need_tx_set, need_quorum_set) = self.check_dependencies(&envelope);

        if !need_tx_set && !need_quorum_set {
            // All dependencies available - envelope is ready
            slot_state.ready.push(envelope);
            self.stats.write().envelopes_ready += 1;
            return RecvResult::Ready;
        }

        // Start fetching missing dependencies
        if need_tx_set {
            if let Some(tx_set_hash) = Self::extract_tx_set_hash(&envelope) {
                let hash = Hash(tx_set_hash.0);
                self.tx_set_fetcher.fetch(hash, &envelope);
            }
        }

        if need_quorum_set {
            if let Some(qs_hash) = Self::extract_quorum_set_hash(&envelope) {
                let hash = Hash(qs_hash.0);
                self.quorum_set_fetcher.fetch(hash, &envelope);
            }
        }

        // Add to fetching
        slot_state
            .fetching
            .insert(env_hash, (envelope, Instant::now()));
        self.stats.write().envelopes_fetching += 1;

        RecvResult::Fetching
    }

    /// Receive a TxSet.
    ///
    /// Returns true if the TxSet was needed and envelopes may be ready.
    pub fn recv_tx_set(&self, hash: Hash256, slot: SlotIndex, data: Vec<u8>) -> bool {
        // Check if we're fetching this TxSet
        if !self.tx_set_fetcher.is_tracking(&Hash(hash.0)) {
            trace!("Received unrequested TxSet {}", hex::encode(hash.0));
            return false;
        }

        self.stats.write().tx_sets_received += 1;

        // Evict old entries if cache is full
        self.evict_tx_set_cache_if_full(slot);

        // Cache the TxSet
        self.tx_set_cache.insert(hash, (slot, data));

        // Notify the fetcher and get waiting envelopes
        let waiting = self.tx_set_fetcher.recv(&Hash(hash.0));

        debug!(
            "Received TxSet {}, {} envelopes waiting",
            hex::encode(hash.0),
            waiting.len()
        );

        // Re-process waiting envelopes
        for env in waiting {
            self.check_and_move_to_ready(env);
        }

        true
    }

    /// Receive a QuorumSet.
    ///
    /// Returns true if the QuorumSet was needed and envelopes may be ready.
    pub fn recv_quorum_set(&self, hash: Hash256, quorum_set: ScpQuorumSet) -> bool {
        // Check if we're fetching this QuorumSet
        if !self.quorum_set_fetcher.is_tracking(&Hash(hash.0)) {
            trace!("Received unrequested QuorumSet {}", hex::encode(hash.0));
            return false;
        }

        self.stats.write().quorum_sets_received += 1;

        // Evict old entries if cache is full
        self.evict_quorum_set_cache_if_full();

        // Cache the QuorumSet
        self.quorum_set_cache.insert(hash, Arc::new(quorum_set));

        // Notify the fetcher and get waiting envelopes
        let waiting = self.quorum_set_fetcher.recv(&Hash(hash.0));

        debug!(
            "Received QuorumSet {}, {} envelopes waiting",
            hex::encode(hash.0),
            waiting.len()
        );

        // Re-process waiting envelopes
        for env in waiting {
            self.check_and_move_to_ready(env);
        }

        true
    }

    /// Handle DONT_HAVE response from a peer.
    pub fn peer_doesnt_have(&self, item_type: ItemType, hash: Hash256, peer: &PeerId) {
        match item_type {
            ItemType::TxSet => {
                self.tx_set_fetcher.doesnt_have(&Hash(hash.0), peer);
            }
            ItemType::QuorumSet => {
                self.quorum_set_fetcher.doesnt_have(&Hash(hash.0), peer);
            }
        }
    }

    /// Pop a ready envelope for the given slot.
    pub fn pop(&self, slot: SlotIndex) -> Option<ScpEnvelope> {
        let mut slot_state = self.slots.get_mut(&slot)?;
        let envelope = slot_state.ready.pop()?;

        // Mark as processed
        let env_hash = Self::compute_envelope_hash(&envelope);
        slot_state.processed.insert(env_hash);

        Some(envelope)
    }

    /// Get all ready slots.
    pub fn ready_slots(&self) -> Vec<SlotIndex> {
        self.slots
            .iter()
            .filter(|entry| !entry.value().ready.is_empty())
            .map(|entry| *entry.key())
            .collect()
    }

    /// Erase data for slots below the given threshold.
    pub fn erase_below(&self, slot_index: SlotIndex, slot_to_keep: SlotIndex) {
        // Remove old slots
        let slots_to_remove: Vec<SlotIndex> = self
            .slots
            .iter()
            .filter(|e| *e.key() < slot_index && *e.key() != slot_to_keep)
            .map(|e| *e.key())
            .collect();

        for slot in slots_to_remove {
            self.slots.remove(&slot);
        }

        // Evict old tx sets from cache (keeps memory bounded)
        let tx_sets_to_remove: Vec<Hash256> = self
            .tx_set_cache
            .iter()
            .filter(|e| e.value().0 < slot_index && e.value().0 != slot_to_keep)
            .map(|e| *e.key())
            .collect();

        let evicted_count = tx_sets_to_remove.len();
        for hash in tx_sets_to_remove {
            self.tx_set_cache.remove(&hash);
        }

        if evicted_count > 0 {
            debug!(
                evicted = evicted_count,
                slot_index,
                remaining = self.tx_set_cache.len(),
                "Evicted old TxSets from cache in erase_below"
            );
        }

        // Tell fetchers to stop fetching for old slots
        self.tx_set_fetcher
            .stop_fetching_below(slot_index, slot_to_keep);
        self.quorum_set_fetcher
            .stop_fetching_below(slot_index, slot_to_keep);
    }

    /// Process pending fetch requests (should be called periodically).
    pub fn process_pending(&self) -> usize {
        let tx_sent = self.tx_set_fetcher.process_pending();
        let qs_sent = self.quorum_set_fetcher.process_pending();
        tx_sent + qs_sent
    }

    /// Get statistics.
    pub fn stats(&self) -> FetchingStats {
        self.stats.read().clone()
    }

    /// Clear all caches and slot state.
    /// Called after catchup to release memory from stale data.
    pub fn clear_all(&self) {
        let tx_set_count = self.tx_set_cache.len();
        let quorum_set_count = self.quorum_set_cache.len();
        let slots_count = self.slots.len();

        self.tx_set_cache.clear();
        self.quorum_set_cache.clear();
        self.slots.clear();
        self.tx_set_fetcher.clear();
        self.quorum_set_fetcher.clear();

        if tx_set_count > 0 || quorum_set_count > 0 || slots_count > 0 {
            tracing::info!(
                tx_set_count,
                quorum_set_count,
                slots_count,
                "Cleared fetching_envelopes caches"
            );
        }
    }

    /// Trim stale data while preserving tx_sets for slots after catchup.
    /// Called after catchup to release memory from stale data while keeping
    /// tx_sets that will be needed for the ledgers immediately after catchup.
    ///
    /// This is critical for avoiding sync gaps: during catchup, we receive
    /// EXTERNALIZE envelopes and cache their tx_sets. After catchup completes,
    /// we need those tx_sets to apply the buffered ledgers. If we clear them,
    /// peers may have already evicted those old tx_sets, causing "DontHave"
    /// responses and sync failures.
    pub fn trim_stale(&self, keep_after_slot: SlotIndex) {
        let initial_tx_set_count = self.tx_set_cache.len();
        let initial_quorum_set_count = self.quorum_set_cache.len();
        let initial_slots_count = self.slots.len();

        // Clear slots for old ledgers only
        self.slots.retain(|slot, _| *slot > keep_after_slot);

        // Clear tx_sets for old ledgers only - KEEP tx_sets for slots > keep_after_slot
        self.tx_set_cache
            .retain(|_, (slot, _)| *slot > keep_after_slot);

        // Clear quorum_set_cache entirely - quorum sets are small and not needed
        // for applying buffered ledgers (they're only needed for SCP validation)
        self.quorum_set_cache.clear();

        // Clear fetchers - pending requests for old slots are stale
        self.tx_set_fetcher.clear();
        self.quorum_set_fetcher.clear();

        let kept_tx_sets = self.tx_set_cache.len();
        let kept_slots = self.slots.len();

        tracing::info!(
            initial_tx_set_count,
            initial_quorum_set_count,
            initial_slots_count,
            kept_tx_sets,
            kept_slots,
            keep_after_slot,
            "Trimmed stale fetching_envelopes caches, preserving future tx_sets"
        );
    }

    /// Get the number of cached TxSets.
    pub fn tx_set_cache_size(&self) -> usize {
        self.tx_set_cache.len()
    }

    /// Get the number of cached QuorumSets.
    pub fn quorum_set_cache_size(&self) -> usize {
        self.quorum_set_cache.len()
    }

    /// Get the number of slots being tracked.
    pub fn slots_count(&self) -> usize {
        self.slots.len()
    }

    /// Get the number of envelopes being fetched.
    pub fn fetching_count(&self) -> usize {
        self.slots
            .iter()
            .map(|entry| entry.value().fetching.len())
            .sum()
    }

    /// Get the number of ready envelopes.
    pub fn ready_count(&self) -> usize {
        self.slots
            .iter()
            .map(|entry| entry.value().ready.len())
            .sum()
    }

    /// Check if we have a cached TxSet.
    pub fn has_tx_set(&self, hash: &Hash256) -> bool {
        self.tx_set_cache.contains_key(hash)
    }

    /// Get a cached TxSet.
    pub fn get_tx_set(&self, hash: &Hash256) -> Option<Vec<u8>> {
        self.tx_set_cache.get(hash).map(|e| e.value().1.clone())
    }

    /// Check if we have a cached QuorumSet.
    pub fn has_quorum_set(&self, hash: &Hash256) -> bool {
        self.quorum_set_cache.contains_key(hash)
    }

    /// Get a cached QuorumSet.
    pub fn get_quorum_set(&self, hash: &Hash256) -> Option<Arc<ScpQuorumSet>> {
        self.quorum_set_cache.get(hash).map(|e| e.value().clone())
    }

    /// Add a TxSet to the cache directly (e.g., locally created).
    pub fn cache_tx_set(&self, hash: Hash256, slot: SlotIndex, data: Vec<u8>) {
        self.evict_tx_set_cache_if_full(slot);
        self.tx_set_cache.insert(hash, (slot, data));
    }

    /// Mark a TxSet as available and process any waiting envelopes.
    ///
    /// This is used when we receive a tx set through other means (not the fetcher)
    /// but want to notify waiting envelopes that the dependency is satisfied.
    pub fn tx_set_available(&self, hash: Hash256, slot: SlotIndex) {
        // Cache it (eviction handled in cache_tx_set)
        self.evict_tx_set_cache_if_full(slot);
        self.tx_set_cache.insert(hash, (slot, Vec::new()));

        // Try recv_tx_set which handles tracked items
        // (if not tracked, it will return early which is fine)
        let _ = self.recv_tx_set(hash, slot, Vec::new());

        // Also manually check all fetching envelopes for this hash
        // in case they weren't tracked through the fetcher
        self.move_ready_envelopes_for_tx_set(&hash);
    }

    /// Check all fetching envelopes and move any that are now ready.
    fn move_ready_envelopes_for_tx_set(&self, tx_set_hash: &Hash256) {
        // Iterate through all slots and check envelopes
        for slot_entry in self.slots.iter() {
            let slot = *slot_entry.key();
            let mut fetching_to_check: Vec<(Hash256, ScpEnvelope)> = Vec::new();

            // Collect envelopes that reference this tx set
            if let Some(slot_state) = self.slots.get(&slot) {
                for (env_hash, (envelope, _)) in slot_state.fetching.iter() {
                    if let Some(hash) = Self::extract_tx_set_hash(envelope) {
                        if &hash == tx_set_hash {
                            fetching_to_check.push((*env_hash, envelope.clone()));
                        }
                    }
                }
            }

            // Check each one
            for (_env_hash, envelope) in fetching_to_check {
                self.check_and_move_to_ready(envelope);
            }
        }
    }

    /// Add a QuorumSet to the cache directly.
    pub fn cache_quorum_set(&self, hash: Hash256, quorum_set: ScpQuorumSet) {
        self.evict_quorum_set_cache_if_full();
        self.quorum_set_cache.insert(hash, Arc::new(quorum_set));
    }

    // --- Internal helpers ---

    /// Evict old tx set cache entries if the cache is full.
    /// Evicts entries from the oldest slots first.
    fn evict_tx_set_cache_if_full(&self, current_slot: SlotIndex) {
        if self.tx_set_cache.len() < self.config.max_tx_set_cache {
            return;
        }

        // Find the oldest slot entry to evict
        let mut oldest_slot = current_slot;
        let mut oldest_hash = None;

        for entry in self.tx_set_cache.iter() {
            if entry.value().0 < oldest_slot {
                oldest_slot = entry.value().0;
                oldest_hash = Some(*entry.key());
            }
        }

        if let Some(hash) = oldest_hash {
            self.tx_set_cache.remove(&hash);
            debug!(
                evicted_slot = oldest_slot,
                cache_size = self.tx_set_cache.len(),
                "Evicted old TxSet from cache"
            );
        }
    }

    /// Evict old quorum set cache entries if the cache is full.
    /// Simply removes a random entry since quorum sets don't have slot info.
    fn evict_quorum_set_cache_if_full(&self) {
        if self.quorum_set_cache.len() < self.config.max_quorum_set_cache {
            return;
        }

        // Remove any entry
        if let Some(entry) = self.quorum_set_cache.iter().next() {
            let hash = *entry.key();
            drop(entry); // Release the iterator before removing
            self.quorum_set_cache.remove(&hash);
            debug!(
                cache_size = self.quorum_set_cache.len(),
                "Evicted old QuorumSet from cache"
            );
        }
    }

    /// Check what dependencies are missing for an envelope.
    ///
    /// NOTE: We currently skip the quorum set check because we don't have
    /// proper quorum set fetching wired up. The critical dependency for
    /// ledger closing is the tx set. Quorum sets are validated separately
    /// by the SCP layer.
    fn check_dependencies(&self, envelope: &ScpEnvelope) -> (bool, bool) {
        let need_tx_set = if let Some(hash) = Self::extract_tx_set_hash(envelope) {
            !self.tx_set_cache.contains_key(&hash)
        } else {
            false
        };

        // TODO: Re-enable quorum set fetching when we have proper peer fetching wired up
        // For now, assume quorum sets are available (SCP validates them separately)
        let need_quorum_set = false;
        // let need_quorum_set = if let Some(hash) = Self::extract_quorum_set_hash(envelope) {
        //     !self.quorum_set_cache.contains_key(&hash)
        // } else {
        //     false
        // };

        (need_tx_set, need_quorum_set)
    }

    /// Check if an envelope is now fully fetched and move to ready if so.
    fn check_and_move_to_ready(&self, envelope: ScpEnvelope) {
        let slot = envelope.statement.slot_index;
        let env_hash = Self::compute_envelope_hash(&envelope);

        let (need_tx_set, need_quorum_set) = self.check_dependencies(&envelope);

        if !need_tx_set && !need_quorum_set {
            // All dependencies available - move to ready
            if let Some(mut slot_state) = self.slots.get_mut(&slot) {
                if slot_state.fetching.remove(&env_hash).is_some() {
                    slot_state.ready.push(envelope);
                    debug!(slot, "Envelope ready after receiving dependencies");
                }
            }
        }
    }

    /// Extract TxSet hash from an envelope (if applicable).
    fn extract_tx_set_hash(envelope: &ScpEnvelope) -> Option<Hash256> {
        use stellar_xdr::curr::{ScpStatementPledges, StellarValue};

        let value = match &envelope.statement.pledges {
            ScpStatementPledges::Externalize(ext) => Some(&ext.commit.value),
            ScpStatementPledges::Confirm(confirm) => Some(&confirm.ballot.value),
            ScpStatementPledges::Prepare(prepare) => Some(&prepare.ballot.value),
            ScpStatementPledges::Nominate(_) => None,
        };

        if let Some(value) = value {
            if let Ok(sv) = StellarValue::from_xdr(&value.0, Limits::none()) {
                return Some(Hash256::from_bytes(sv.tx_set_hash.0));
            }
        }

        None
    }

    /// Extract QuorumSet hash from an envelope.
    fn extract_quorum_set_hash(envelope: &ScpEnvelope) -> Option<Hash256> {
        use stellar_xdr::curr::ScpStatementPledges;

        let hash = match &envelope.statement.pledges {
            ScpStatementPledges::Nominate(nom) => Some(&nom.quorum_set_hash),
            ScpStatementPledges::Prepare(prep) => Some(&prep.quorum_set_hash),
            ScpStatementPledges::Confirm(conf) => Some(&conf.quorum_set_hash),
            ScpStatementPledges::Externalize(ext) => Some(&ext.commit_quorum_set_hash),
        };

        hash.map(|h| Hash256::from_bytes(h.0))
    }

    /// Compute hash of an envelope for deduplication.
    fn compute_envelope_hash(envelope: &ScpEnvelope) -> Hash256 {
        Hash256::hash_xdr(envelope).unwrap_or(Hash256::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        NodeId as XdrNodeId, PublicKey, ScpNomination, ScpStatement, ScpStatementPledges,
        Signature, Uint256,
    };

    fn make_test_envelope(slot: SlotIndex, node_seed: u8) -> ScpEnvelope {
        let node_id = XdrNodeId(PublicKey::PublicKeyTypeEd25519(Uint256([node_seed; 32])));

        ScpEnvelope {
            statement: ScpStatement {
                node_id,
                slot_index: slot,
                pledges: ScpStatementPledges::Nominate(ScpNomination {
                    quorum_set_hash: Hash([1u8; 32]),
                    votes: vec![].try_into().unwrap(),
                    accepted: vec![].try_into().unwrap(),
                }),
            },
            signature: Signature(vec![0u8; 64].try_into().unwrap()),
        }
    }

    #[test]
    fn test_recv_envelope_nomination_no_dependencies() {
        let fetching = FetchingEnvelopes::with_defaults();

        let envelope = make_test_envelope(100, 1);
        let result = fetching.recv_envelope(envelope);

        // Nomination envelopes don't have tx set dependencies
        // and quorum set fetching is currently disabled, so envelope is ready
        assert_eq!(result, RecvResult::Ready);
        assert_eq!(fetching.ready_count(), 1);
    }

    #[test]
    fn test_recv_envelope_ready_when_cached() {
        let fetching = FetchingEnvelopes::with_defaults();

        // Pre-cache the quorum set (not strictly needed now since quorum set
        // fetching is disabled, but kept for when it's re-enabled)
        let qs_hash = Hash256::from_bytes([1u8; 32]);
        let quorum_set = ScpQuorumSet {
            threshold: 1,
            validators: vec![].try_into().unwrap(),
            inner_sets: vec![].try_into().unwrap(),
        };
        fetching.cache_quorum_set(qs_hash, quorum_set);

        let envelope = make_test_envelope(100, 1);
        let result = fetching.recv_envelope(envelope);

        // Should be ready because quorum set fetching is disabled for nominations
        assert_eq!(result, RecvResult::Ready);
        assert_eq!(fetching.ready_count(), 1);
    }

    #[test]
    fn test_cache_quorum_set() {
        let fetching = FetchingEnvelopes::with_defaults();

        // Verify we can cache and retrieve quorum sets
        let qs_hash = Hash256::from_bytes([1u8; 32]);
        let quorum_set = ScpQuorumSet {
            threshold: 1,
            validators: vec![].try_into().unwrap(),
            inner_sets: vec![].try_into().unwrap(),
        };
        fetching.cache_quorum_set(qs_hash, quorum_set);

        assert!(fetching.has_quorum_set(&qs_hash));
        let retrieved = fetching.get_quorum_set(&qs_hash);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().threshold, 1);
    }

    #[test]
    fn test_pop_marks_as_processed() {
        let fetching = FetchingEnvelopes::with_defaults();

        // Pre-cache quorum set
        let qs_hash = Hash256::from_bytes([1u8; 32]);
        fetching.cache_quorum_set(
            qs_hash,
            ScpQuorumSet {
                threshold: 1,
                validators: vec![].try_into().unwrap(),
                inner_sets: vec![].try_into().unwrap(),
            },
        );

        let envelope = make_test_envelope(100, 1);
        fetching.recv_envelope(envelope.clone());

        // Pop the envelope
        let popped = fetching.pop(100);
        assert!(popped.is_some());

        // Adding same envelope again should be duplicate
        let result = fetching.recv_envelope(envelope);
        assert_eq!(result, RecvResult::AlreadyProcessed);
    }

    #[test]
    fn test_erase_below() {
        let fetching = FetchingEnvelopes::with_defaults();

        // Pre-cache quorum set for all
        let qs_hash = Hash256::from_bytes([1u8; 32]);
        fetching.cache_quorum_set(
            qs_hash,
            ScpQuorumSet {
                threshold: 1,
                validators: vec![].try_into().unwrap(),
                inner_sets: vec![].try_into().unwrap(),
            },
        );

        // Add envelopes for different slots
        fetching.recv_envelope(make_test_envelope(100, 1));
        fetching.recv_envelope(make_test_envelope(101, 2));
        fetching.recv_envelope(make_test_envelope(102, 3));

        assert_eq!(fetching.ready_count(), 3);

        // Erase below 102, keeping 100
        fetching.erase_below(102, 100);

        // Slot 100 should be kept, 101 erased, 102 kept
        let ready_slots = fetching.ready_slots();
        assert!(ready_slots.contains(&100));
        assert!(!ready_slots.contains(&101));
        assert!(ready_slots.contains(&102));
    }

    #[test]
    fn test_trim_stale_preserves_future_tx_sets() {
        let fetching = FetchingEnvelopes::with_defaults();

        // Create distinct hashes for each tx_set
        let hash_old = Hash256::from_bytes([98u8; 32]);
        let hash_boundary = Hash256::from_bytes([99u8; 32]);
        let hash_future = Hash256::from_bytes([100u8; 32]);

        // Cache tx_sets for various slots (hash, slot, data)
        fetching.cache_tx_set(hash_old, 98, vec![1, 2, 3]);
        fetching.cache_tx_set(hash_boundary, 100, vec![4, 5, 6]);
        fetching.cache_tx_set(hash_future, 101, vec![7, 8, 9]);

        // Also add some quorum sets
        let qs_hash = Hash256::from_bytes([1u8; 32]);
        fetching.cache_quorum_set(
            qs_hash,
            ScpQuorumSet {
                threshold: 1,
                validators: vec![].try_into().unwrap(),
                inner_sets: vec![].try_into().unwrap(),
            },
        );

        // Verify all are cached before trim
        assert!(fetching.get_tx_set(&hash_old).is_some());
        assert!(fetching.get_tx_set(&hash_boundary).is_some());
        assert!(fetching.get_tx_set(&hash_future).is_some());
        assert!(fetching.has_quorum_set(&qs_hash));

        // Trim with keep_after_slot = 100
        // Should keep tx_sets for slots > 100, i.e., slot 101
        fetching.trim_stale(100);

        // Verify tx_sets: only future slot (101) should remain
        assert!(
            fetching.get_tx_set(&hash_future).is_some(),
            "tx_set for slot 101 should be preserved"
        );
        assert!(
            fetching.get_tx_set(&hash_old).is_none(),
            "tx_set for slot 98 should be removed"
        );
        assert!(
            fetching.get_tx_set(&hash_boundary).is_none(),
            "tx_set for slot 100 should be removed (boundary)"
        );

        // Verify quorum_set_cache is cleared
        assert!(
            !fetching.has_quorum_set(&qs_hash),
            "quorum sets should be cleared"
        );
    }
}
