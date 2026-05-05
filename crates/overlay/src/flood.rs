//! Flood gate for managing message propagation and duplicate detection.
//!
//! The Stellar overlay network propagates certain message types (transactions,
//! SCP messages, etc.) to all connected peers. To prevent infinite loops and
//! reduce bandwidth, the [`FloodGate`] tracks which messages have been seen
//! and from which peers.
//!
//! # Functionality
//!
//! - **Duplicate Detection**: Messages are identified by their BLAKE2b-256 hash
//!   (matching stellar-core's `xdrBlake2`). If we've seen a message before, it's not flooded again.
//!
//! - **Peer Tracking**: Records which peers have sent each message, so we
//!   don't forward messages back to peers that already have them.
//!
//! - **Ledger-boundary Cleanup**: Entries are removed at ledger close via
//!   [`FloodGate::clear_below`], matching stellar-core's `clearBelow()`.
//!   A secondary TTL check removes stale entries as a defensive measure.
//!
//! - **Rate Limiting**: Soft limit on messages per second to prevent
//!   overwhelming the node during traffic spikes.

use dashmap::DashMap;
use henyey_common::Hash256;
use parking_lot::{Mutex, RwLock};
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use stellar_xdr::curr::StellarMessage;
use tracing::{debug, trace, warn};

use crate::PeerId;

/// Internal result of recording a message hash in the [`FloodGate`].
///
/// **Module-private by design.** This enum is deliberately NOT exported from
/// the `flood` module. External callers interact via [`FloodGate::record_inbound_relay`]
/// and [`FloodGate::record_local_broadcast`], which return `()` — making it
/// structurally impossible to accidentally use relay status as a drop signal
/// (the c6118f2c / #2317 bug class).
///
/// Actual dedup happens downstream:
/// - SCP: `scp_scheduled_envelopes` in `pump_scp_intake`
/// - Tx: herder `receive_transaction` / tx queue
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayRecord {
    /// First time this hash was seen.
    New,
    /// Hash was already recorded.
    Repeated,
}

/// Default TTL for seen messages (5 minutes).
///
/// Used by [`FloodGate::clear_below`] as a secondary expiry mechanism
/// during ledger-boundary cleanup.
const DEFAULT_TTL_SECS: u64 = 300;

/// Hard cap for the flood seen map (entry count, not memory).
///
/// Bounds the number of tracked message hashes. Under normal mainnet
/// traffic (~1000 unique msgs/sec), the map holds ~5000 entries per
/// ledger close cycle. This cap exists to prevent OOM under adversarial
/// conditions (Sybil flooding with unique hashes).
///
/// Henyey-specific. stellar-core has no equivalent bound — its Floodgate
/// relies solely on `clearBelow()`.
const DEFAULT_MAX_SEEN_ENTRIES: usize = 1_000_000;

/// Default global rate limit (messages per second).
///
/// This is a node-wide aggregate backstop against Sybil attacks.
/// Per-peer rate limiting (in peer_loop.rs) is the primary enforcement;
/// this global limit is an emergency failsafe.
const DEFAULT_RATE_LIMIT_PER_SEC: u64 = 5000;

/// Internal tracking entry for a seen message.
struct SeenEntry {
    /// When the message was first seen.
    first_seen: Instant,
    /// Ledger sequence when the message was first seen.
    ledger_seq: u32,
    /// Set of peers that have sent us this message.
    peers: HashSet<PeerId>,
    /// Generation token for FIFO eviction queue consistency.
    generation: u64,
}

impl SeenEntry {
    /// Creates a new entry with the current timestamp, ledger sequence, and generation.
    fn new(ledger_seq: u32, generation: u64) -> Self {
        Self {
            first_seen: Instant::now(),
            ledger_seq,
            peers: HashSet::new(),
            generation,
        }
    }

    /// Records that a peer has sent this message.
    fn add_peer(&mut self, peer: PeerId) {
        self.peers.insert(peer);
    }

    /// Returns true if this entry has exceeded its TTL.
    fn is_expired(&self, ttl: Duration) -> bool {
        self.first_seen.elapsed() > ttl
    }
}

/// Flood gate for tracking seen messages and preventing duplicates.
///
/// The flood gate is the core of the overlay's message propagation system.
/// It ensures that each unique message is only flooded once, while tracking
/// which peers have already received each message.
///
/// # Thread Safety
///
/// All operations are thread-safe and can be called concurrently from
/// multiple peer message handlers.
///
/// # Example
///
/// ```rust,ignore
/// let gate = FloodGate::new();
///
/// // Record an inbound message with metric callbacks
/// let hash = compute_message_hash(&message);
/// gate.record_inbound_relay(hash, peer_id, current_ledger_seq,
///     || metrics.unique.inc(),
///     || metrics.duplicate.inc(),
/// );
/// // Message always continues to processing — no drop decision possible.
///
/// // Determine forwarding targets (excludes peers that already sent us this hash)
/// let forward_to = gate.get_forward_peers(&hash, &all_peers);
/// ```
pub struct FloodGate {
    /// Map of message hash to tracking entry.
    seen: DashMap<Hash256, SeenEntry>,
    /// FIFO eviction queue storing (hash, generation) pairs.
    /// May contain ghost entries (removed from `seen` by clear_below/forget).
    eviction_queue: Mutex<VecDeque<(Hash256, u64)>>,
    /// Monotonic counter for generation tokens.
    next_generation: AtomicU64,
    /// Hard capacity bound (entry count).
    max_entries: usize,
    /// Time-to-live for message entries (used by `clear_below`).
    ttl: Duration,
    /// Counter: total messages processed.
    messages_seen: AtomicU64,
    /// Counter: duplicate messages observed.
    messages_duplicate: AtomicU64,
    /// Counter: total entries evicted due to capacity overflow.
    evictions_total: AtomicU64,
    /// Maximum messages per second.
    rate_limit: u64,
    /// Start of current rate-limiting window.
    rate_window_start: RwLock<Instant>,
    /// Messages counted in current window.
    rate_window_count: AtomicU64,
    /// Whether an eviction warning has been emitted since last reset.
    eviction_warned: AtomicBool,
}

impl FloodGate {
    /// Creates a new flood gate with default settings (5 minute TTL, 1M entry cap).
    pub fn new() -> Self {
        Self::with_limits(
            Duration::from_secs(DEFAULT_TTL_SECS),
            DEFAULT_MAX_SEEN_ENTRIES,
        )
    }

    /// Creates a new flood gate with a custom TTL and default capacity.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self::with_limits(ttl, DEFAULT_MAX_SEEN_ENTRIES)
    }

    /// Creates a new flood gate with custom TTL and capacity.
    ///
    /// # Panics
    /// Panics if `max_entries == 0`.
    pub fn with_limits(ttl: Duration, max_entries: usize) -> Self {
        assert!(max_entries > 0, "FloodGate max_entries must be > 0");
        Self {
            seen: DashMap::new(),
            eviction_queue: Mutex::new(VecDeque::new()),
            next_generation: AtomicU64::new(0),
            max_entries,
            ttl,
            messages_seen: AtomicU64::new(0),
            messages_duplicate: AtomicU64::new(0),
            evictions_total: AtomicU64::new(0),
            rate_limit: DEFAULT_RATE_LIMIT_PER_SEC,
            rate_window_start: RwLock::new(Instant::now()),
            rate_window_count: AtomicU64::new(0),
            eviction_warned: AtomicBool::new(false),
        }
    }

    /// Records that a message has been seen, optionally from a specific peer.
    ///
    /// Returns [`RelayRecord::New`] if this is the first time seeing this
    /// message, or [`RelayRecord::Repeated`] if it was already recorded.
    ///
    /// **Private by design.** External callers use [`record_inbound_relay`] or
    /// [`record_local_broadcast`] which return `()`, preventing accidental use
    /// of relay status as a drop signal (c6118f2c / #2317 bug class).
    ///
    /// This is a pure insert/lookup operation with no automatic cleanup,
    /// matching stellar-core's `addRecord()`. Cleanup happens at ledger
    /// boundaries via [`clear_below`](FloodGate::clear_below).
    fn record_seen(
        &self,
        message_hash: Hash256,
        from_peer: Option<PeerId>,
        ledger_seq: u32,
    ) -> RelayRecord {
        self.messages_seen.fetch_add(1, Ordering::Relaxed);

        // Check if we've seen this message
        if let Some(mut entry) = self.seen.get_mut(&message_hash) {
            // Already seen, record the peer
            if let Some(peer) = from_peer {
                entry.add_peer(peer);
            }
            self.messages_duplicate.fetch_add(1, Ordering::Relaxed);
            trace!("Duplicate message: {}", message_hash);
            return RelayRecord::Repeated;
        }

        // New message — assign generation and insert
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let mut entry = SeenEntry::new(ledger_seq, generation);
        if let Some(peer) = from_peer {
            entry.add_peer(peer);
        }
        self.seen.insert(message_hash, entry);

        // Enqueue for FIFO eviction and check capacity
        let mut queue = self.eviction_queue.lock();
        queue.push_back((message_hash, generation));
        if self.seen.len() > self.max_entries {
            self.evict_to_target(&mut queue);
        }

        trace!("New message: {}", message_hash);
        RelayRecord::New
    }

    /// Checks if another message is allowed under the rate limit.
    ///
    /// Returns `true` if we're within the rate limit, `false` if we've
    /// exceeded it and should drop the message.
    pub fn allow_message(&self) -> bool {
        let now = Instant::now();
        {
            let mut start = self.rate_window_start.write();
            if now.duration_since(*start) >= Duration::from_secs(1) {
                *start = now;
                self.rate_window_count.store(0, Ordering::Relaxed);
            }
        }

        let count = self.rate_window_count.fetch_add(1, Ordering::Relaxed) + 1;
        count <= self.rate_limit
    }

    /// Drains the eviction queue until the map is at or below 75% capacity.
    ///
    /// Uses generation tokens to safely skip ghost entries and re-inserted
    /// entries whose original queue slot is stale.
    fn evict_to_target(&self, queue: &mut VecDeque<(Hash256, u64)>) {
        let target = self.max_entries * 3 / 4;
        let mut evicted = 0u64;
        while self.seen.len() > target {
            match queue.pop_front() {
                Some((hash, gen)) => {
                    // Only evict if generation matches (entry hasn't been
                    // forgotten and re-inserted with a new generation).
                    let should_remove = self.seen.get(&hash).map_or(false, |e| e.generation == gen);
                    if should_remove {
                        self.seen.remove(&hash);
                        evicted += 1;
                    }
                }
                None => break, // queue exhausted
            }
        }
        if evicted > 0 {
            self.evictions_total.fetch_add(evicted, Ordering::Relaxed);
            if !self.eviction_warned.swap(true, Ordering::Relaxed) {
                warn!(
                    evicted,
                    seen = self.seen.len(),
                    max = self.max_entries,
                    "FloodGate capacity overflow — evicted oldest entries"
                );
            }
        }
    }

    /// Record a locally-originated message for relay accounting (self-broadcast).
    ///
    /// Returns nothing — the message always continues to processing. This
    /// method is for messages this node originates or re-broadcasts, where
    /// no inbound peer needs recording and no metrics callback is needed.
    ///
    /// stellar-core parity: mirrors the `addRecord(hash, nullptr)` path in
    /// `Floodgate.cpp` for self-originated messages.
    pub(crate) fn record_local_broadcast(&self, message_hash: Hash256, ledger_seq: u32) {
        self.record_seen(message_hash, None, ledger_seq);
    }

    /// Record a flood-tracked message received from a peer and invoke metric callbacks.
    ///
    /// Returns nothing — the message always continues to processing. The
    /// caller never observes new-vs-repeated status directly; only the
    /// provided closures do. This prevents the accidental misuse pattern
    /// from c6118f2c (#2317) where relay status was used as a drop signal.
    ///
    /// # Arguments
    ///
    /// * `on_new` — called if this is the first time seeing this hash
    /// * `on_repeated` — called if the hash was already recorded
    ///
    /// stellar-core parity:
    /// - SCP: Peer.cpp:1667-1673 — recvFloodedMsgID then unconditional recvSCPEnvelope
    /// - Tx: OverlayManagerImpl.cpp:1224-1229 — recvFloodedMsgID then unconditional recvTransaction
    pub(crate) fn record_inbound_relay(
        &self,
        message_hash: Hash256,
        from_peer: PeerId,
        ledger_seq: u32,
        on_new: impl FnOnce(),
        on_repeated: impl FnOnce(),
    ) {
        match self.record_seen(message_hash, Some(from_peer), ledger_seq) {
            RelayRecord::New => on_new(),
            RelayRecord::Repeated => on_repeated(),
        }
    }

    /// Returns the list of peers to forward a message to.
    ///
    /// Excludes any peers that have already sent us this message (tracked
    /// via relay recording).
    pub(crate) fn get_forward_peers(
        &self,
        message_hash: &Hash256,
        all_peers: &[PeerId],
    ) -> Vec<PeerId> {
        let exclude: HashSet<PeerId> = self
            .seen
            .get(message_hash)
            .map(|entry| entry.peers.iter().cloned().collect())
            .unwrap_or_default();

        all_peers
            .iter()
            .filter(|p| !exclude.contains(*p))
            .cloned()
            .collect()
    }

    /// Returns true if this message has been seen before.
    /// Only available in tests — not part of the public API to prevent
    /// use as a drop-decision signal.
    #[cfg(test)]
    fn has_seen(&self, message_hash: &Hash256) -> bool {
        self.seen.contains_key(message_hash)
    }

    /// Removes a previously-seen message from the flood gate, allowing
    /// it to be treated as new on re-delivery.
    ///
    /// Mirrors stellar-core's `Floodgate::forgetRecord(Hash const& h)`
    /// (Floodgate.cpp:197-200). Called when a flood-tracked message is
    /// discarded after initial recording — e.g., SCP envelopes rejected
    /// by herder pre-filter or post-verify gate drift.
    pub(crate) fn forget(&self, message_hash: &Hash256) {
        self.seen.remove(message_hash);
    }

    /// Returns current statistics about the flood gate.
    pub fn stats(&self) -> FloodGateStats {
        FloodGateStats {
            seen_count: self.seen.len(),
            total_messages: self.messages_seen.load(Ordering::Relaxed),
            duplicate_messages: self.messages_duplicate.load(Ordering::Relaxed),
            evictions_total: self.evictions_total.load(Ordering::Relaxed),
        }
    }

    /// Removes flood records from ledgers before `ledger_seq`.
    ///
    /// Matches upstream stellar-core's `clearBelow(maxLedger)` which removes
    /// records from ledgers before `maxLedger`. Additionally removes
    /// TTL-expired entries as a henyey-specific defensive measure (stellar-core's
    /// `clearBelow` is purely ledger-based).
    pub fn clear_below(&self, ledger_seq: u32) {
        let ttl = self.ttl;
        let before_count = self.seen.len();
        self.seen
            .retain(|_, entry| entry.ledger_seq >= ledger_seq && !entry.is_expired(ttl));
        let removed = before_count.saturating_sub(self.seen.len());

        if removed > 0 {
            debug!(
                "FloodGate clear_below({}): removed {} entries",
                ledger_seq, removed
            );
        }

        // Reset eviction warning if map dropped well below capacity
        if self.seen.len() < self.max_entries / 2 {
            self.eviction_warned.store(false, Ordering::Relaxed);
        }

        // Queue compaction: if ghost buildup exceeds 2x capacity, clear the queue.
        // Entries currently in the map become "untracked" until their next
        // clear_below cycle. New inserts going forward are properly tracked.
        let mut queue = self.eviction_queue.lock();
        if queue.len() > self.max_entries * 2 {
            queue.clear();
        }
    }

    /// Clears all entries from the flood gate.
    ///
    /// Use with caution - this will allow previously-seen messages to be
    /// flooded again.
    pub fn clear(&self) {
        self.seen.clear();
        let mut queue = self.eviction_queue.lock();
        queue.clear();
        self.eviction_warned.store(false, Ordering::Relaxed);
    }
}

impl Default for FloodGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics snapshot from a [`FloodGate`].
#[derive(Debug, Clone)]
pub struct FloodGateStats {
    /// Number of unique messages currently being tracked.
    pub seen_count: usize,
    /// Total messages processed (including duplicates).
    pub total_messages: u64,
    /// Number of duplicate messages observed (relay accounting only).
    pub duplicate_messages: u64,
    /// Total entries evicted due to capacity overflow.
    pub evictions_total: u64,
}

impl FloodGateStats {
    /// Calculates the duplicate rate as a percentage.
    ///
    /// Returns 0.0 if no messages have been processed.
    pub fn duplicate_rate(&self) -> f64 {
        if self.total_messages == 0 {
            0.0
        } else {
            (self.duplicate_messages as f64 / self.total_messages as f64) * 100.0
        }
    }
}

/// Computes the BLAKE2b-256 hash of a message for flood tracking.
///
/// This matches stellar-core's `xdrBlake2()` used in `Floodgate::broadcast()`.
pub fn compute_message_hash(message: &StellarMessage) -> Hash256 {
    use stellar_xdr::curr::{Limits, WriteXdr};
    let bytes = message
        .to_xdr(Limits::none())
        .expect("XDR serialization of StellarMessage must not fail");
    henyey_crypto::blake2(&bytes)
}

/// A message queued for flooding, with tracking metadata.
///
/// Used internally to track messages that need to be forwarded to peers.
pub struct FloodRecord {
    /// BLAKE2b-256 hash of the message.
    pub hash: Hash256,
    /// The message to be flooded.
    pub message: StellarMessage,
    /// When the message was received.
    pub received: Instant,
    /// The peer that sent us this message (if any).
    pub from_peer: Option<PeerId>,
}

impl FloodRecord {
    /// Creates a new flood record for a message.
    pub fn new(message: StellarMessage, from_peer: Option<PeerId>) -> Self {
        let hash = compute_message_hash(&message);
        Self {
            hash,
            message,
            received: Instant::now(),
            from_peer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(v: u8) -> Hash256 {
        Hash256([v; 32])
    }

    fn make_peer_id(v: u8) -> PeerId {
        PeerId::from_bytes([v; 32])
    }

    #[test]
    fn test_flood_gate_basic() {
        let gate = FloodGate::new();

        let hash = make_hash(1);
        assert!(!gate.has_seen(&hash));

        // Record as seen
        assert_eq!(gate.record_seen(hash, None, 1), RelayRecord::New);

        // Should be seen now
        assert!(gate.has_seen(&hash));

        // Record again should return Repeated
        assert_eq!(gate.record_seen(hash, None, 1), RelayRecord::Repeated);
    }

    #[test]
    fn test_flood_gate_with_peers() {
        let gate = FloodGate::new();

        let hash = make_hash(1);
        let peer1 = make_peer_id(1);
        let peer2 = make_peer_id(2);
        let peer3 = make_peer_id(3);

        // First seen from peer1
        assert_eq!(
            gate.record_seen(hash, Some(peer1.clone()), 1),
            RelayRecord::New
        );

        // Also seen from peer2
        assert_eq!(
            gate.record_seen(hash, Some(peer2.clone()), 1),
            RelayRecord::Repeated
        );

        // Get forward peers - should exclude peer1 and peer2
        let all_peers = vec![peer1.clone(), peer2.clone(), peer3.clone()];
        let forward = gate.get_forward_peers(&hash, &all_peers);

        assert_eq!(forward.len(), 1);
        assert_eq!(forward[0], peer3);
    }

    #[test]
    fn test_flood_gate_stats() {
        let gate = FloodGate::new();

        let hash1 = make_hash(1);
        let hash2 = make_hash(2);

        let _ = gate.record_seen(hash1, None, 1);
        let _ = gate.record_seen(hash1, None, 1); // duplicate
        let _ = gate.record_seen(hash2, None, 1);

        let stats = gate.stats();
        assert_eq!(stats.seen_count, 2);
        assert_eq!(stats.total_messages, 3);
        assert_eq!(stats.duplicate_messages, 1);
    }

    #[test]
    fn test_flood_gate_expiry() {
        let gate = FloodGate::with_ttl(Duration::from_millis(10));

        let hash = make_hash(1);
        let _ = gate.record_seen(hash, None, 1);
        std::thread::sleep(Duration::from_millis(20));

        // clear_below with a high ledger seq removes expired entries
        gate.clear_below(u32::MAX);

        // Should not be seen anymore
        assert!(!gate.has_seen(&hash));
    }

    #[test]
    fn test_flood_record() {
        let message = StellarMessage::Peers(stellar_xdr::curr::VecM::default());
        let record = FloodRecord::new(message, None);

        assert!(!record.hash.is_zero());
        assert!(record.from_peer.is_none());
    }

    #[test]
    fn test_clear_below_removes_by_ledger() {
        let gate = FloodGate::with_ttl(Duration::from_secs(300));

        let hash1 = make_hash(1);
        let hash2 = make_hash(2);
        let hash3 = make_hash(3);
        // Record at different ledger sequences
        let _ = gate.record_seen(hash1, None, 50);
        let _ = gate.record_seen(hash2, None, 100);
        let _ = gate.record_seen(hash3, None, 150);

        assert_eq!(gate.stats().seen_count, 3);

        // clear_below(100) removes entries from ledgers < 100
        gate.clear_below(100);
        assert_eq!(gate.stats().seen_count, 2);
        assert!(!gate.has_seen(&hash1));
        assert!(gate.has_seen(&hash2));
        assert!(gate.has_seen(&hash3));
    }

    #[test]
    fn test_clear_below_removes_expired() {
        // Use a very short TTL so entries expire quickly
        let gate = FloodGate::with_ttl(Duration::from_millis(10));

        let hash1 = make_hash(1);
        let hash2 = make_hash(2);
        let _ = gate.record_seen(hash1, None, 100);
        let _ = gate.record_seen(hash2, None, 100);

        assert_eq!(gate.stats().seen_count, 2);

        // Wait for entries to expire
        std::thread::sleep(Duration::from_millis(20));

        // clear_below triggers cleanup of expired entries (even at same ledger)
        gate.clear_below(100);

        assert_eq!(gate.stats().seen_count, 0);
    }

    #[test]
    fn test_clear_below_preserves_recent() {
        // Use a long TTL so entries don't expire
        let gate = FloodGate::with_ttl(Duration::from_secs(300));

        let hash1 = make_hash(1);
        let hash2 = make_hash(2);
        let _ = gate.record_seen(hash1, None, 100);
        let _ = gate.record_seen(hash2, None, 100);

        // clear_below should not remove entries at or above the threshold
        gate.clear_below(100);

        assert_eq!(gate.stats().seen_count, 2);
        assert!(gate.has_seen(&hash1));
        assert!(gate.has_seen(&hash2));
    }

    /// Regression test for AUDIT-174: record_seen() must NOT trigger automatic
    /// cleanup. Expired entries should only be removed by explicit clear_below().
    #[test]
    fn test_record_seen_does_not_auto_cleanup() {
        // Use a short TTL so entries expire quickly
        let gate = FloodGate::with_ttl(Duration::from_millis(50));

        // Insert 5 entries at ledger 1
        for i in 0..5u8 {
            let _ = gate.record_seen(make_hash(i), None, 1);
        }
        assert_eq!(gate.stats().seen_count, 5);

        // Wait for all entries to expire (2x TTL for generous margin)
        std::thread::sleep(Duration::from_millis(100));

        // Insert 5 new entries at ledger 2 via record_seen
        for i in 10..15u8 {
            let _ = gate.record_seen(make_hash(i), None, 2);
        }

        // All 10 entries should still be present — record_seen does not clean up
        assert_eq!(gate.stats().seen_count, 10);

        // Now clear_below(2) should remove ledger-1 entries (and any expired)
        gate.clear_below(2);
        assert_eq!(gate.stats().seen_count, 5);

        // Only ledger-2 entries remain
        for i in 10..15u8 {
            assert!(gate.has_seen(&make_hash(i)));
        }
        for i in 0..5u8 {
            assert!(!gate.has_seen(&make_hash(i)));
        }
    }

    #[test]
    fn test_flood_gate_not_polluted_by_pull_control() {
        use crate::codec::helpers;

        let gate = FloodGate::new();

        // Simulate the corrected receive path: only record_seen for
        // is_flood_gate_tracked messages.
        let advert = StellarMessage::FloodAdvert(Default::default());
        let demand = StellarMessage::FloodDemand(Default::default());
        let tx = StellarMessage::Transaction(stellar_xdr::curr::TransactionEnvelope::TxV0(
            Default::default(),
        ));

        // Pull-control messages are flood messages but NOT gate-tracked
        assert!(helpers::is_flood_message(&advert));
        assert!(helpers::is_flood_message(&demand));
        assert!(!helpers::is_flood_gate_tracked(&advert));
        assert!(!helpers::is_flood_gate_tracked(&demand));

        // Simulating the fixed routing: only gate-tracked messages get recorded
        if helpers::is_flood_gate_tracked(&advert) {
            let _ = gate.record_seen(compute_message_hash(&advert), None, 1);
        }
        if helpers::is_flood_gate_tracked(&demand) {
            let _ = gate.record_seen(compute_message_hash(&demand), None, 1);
        }
        // FloodGate should be empty — pull-control does NOT pollute it
        assert_eq!(gate.seen.len(), 0);

        // Transaction IS gate-tracked and should be recorded
        assert!(helpers::is_flood_gate_tracked(&tx));
        if helpers::is_flood_gate_tracked(&tx) {
            let _ = gate.record_seen(compute_message_hash(&tx), None, 1);
        }
        assert_eq!(gate.seen.len(), 1);
    }

    #[test]
    fn test_flood_gate_forget_basic() {
        let gate = FloodGate::new();
        let hash = make_hash(1);

        // Record, then forget — has_seen returns false again.
        assert_eq!(gate.record_seen(hash, None, 1), RelayRecord::New);
        assert!(gate.has_seen(&hash));

        gate.forget(&hash);
        assert!(!gate.has_seen(&hash));
    }

    #[test]
    fn test_flood_gate_forget_nonexistent() {
        let gate = FloodGate::new();
        let hash = make_hash(42);

        // Forgetting a hash that was never recorded is a no-op.
        gate.forget(&hash);
        assert!(!gate.has_seen(&hash));
    }

    #[test]
    fn test_flood_gate_forget_redelivery() {
        let gate = FloodGate::new();
        let hash = make_hash(1);
        let peer_a = make_peer_id(1);
        let peer_b = make_peer_id(2);
        let peer_c = make_peer_id(3);
        let all_peers = vec![peer_a.clone(), peer_b.clone(), peer_c.clone()];

        // Peer A delivers the message.
        assert_eq!(
            gate.record_seen(hash, Some(peer_a.clone()), 1),
            RelayRecord::New
        );
        // Forward list excludes peer A.
        let fwd = gate.get_forward_peers(&hash, &all_peers);
        assert!(!fwd.contains(&peer_a));
        assert!(fwd.contains(&peer_b));

        // Forget the record (simulating herder discard).
        gate.forget(&hash);

        // Peer B re-delivers. FloodGate treats it as new.
        assert_eq!(
            gate.record_seen(hash, Some(peer_b.clone()), 1),
            RelayRecord::New
        );
        // Forward list now includes peer A (provenance reset).
        let fwd = gate.get_forward_peers(&hash, &all_peers);
        assert!(fwd.contains(&peer_a));
        assert!(!fwd.contains(&peer_b));
        assert!(fwd.contains(&peer_c));
    }

    #[test]
    fn test_record_local_broadcast() {
        let gate = FloodGate::new();
        let hash = make_hash(1);

        assert!(!gate.has_seen(&hash));
        gate.record_local_broadcast(hash, 1);
        assert!(gate.has_seen(&hash));

        // Calling again doesn't panic, just increments duplicate counter
        gate.record_local_broadcast(hash, 1);
        assert_eq!(gate.stats().duplicate_messages, 1);
    }

    #[test]
    fn test_record_inbound_relay_calls_on_new() {
        let gate = FloodGate::new();
        let hash = make_hash(1);
        let peer = make_peer_id(1);

        let mut new_called = false;
        let mut repeated_called = false;

        gate.record_inbound_relay(
            hash,
            peer,
            1,
            || new_called = true,
            || repeated_called = true,
        );

        assert!(new_called);
        assert!(!repeated_called);
        assert!(gate.has_seen(&hash));
    }

    #[test]
    fn test_record_inbound_relay_calls_on_repeated() {
        let gate = FloodGate::new();
        let hash = make_hash(1);
        let peer1 = make_peer_id(1);
        let peer2 = make_peer_id(2);

        // First record
        gate.record_inbound_relay(hash, peer1, 1, || {}, || {});

        // Second record from different peer
        let mut new_called = false;
        let mut repeated_called = false;
        gate.record_inbound_relay(
            hash,
            peer2,
            1,
            || new_called = true,
            || repeated_called = true,
        );

        assert!(!new_called);
        assert!(repeated_called);
    }

    #[test]
    fn test_record_inbound_relay_accumulates_peers() {
        let gate = FloodGate::new();
        let hash = make_hash(1);
        let peer1 = make_peer_id(1);
        let peer2 = make_peer_id(2);
        let peer3 = make_peer_id(3);

        gate.record_inbound_relay(hash, peer1.clone(), 1, || {}, || {});
        gate.record_inbound_relay(hash, peer2.clone(), 1, || {}, || {});

        // get_forward_peers should exclude peer1 and peer2
        let all_peers = vec![peer1.clone(), peer2.clone(), peer3.clone()];
        let forward = gate.get_forward_peers(&hash, &all_peers);
        assert_eq!(forward, vec![peer3]);
    }

    // --- Capacity eviction tests ---

    #[test]
    fn test_flood_gate_eviction_at_capacity() {
        let gate = FloodGate::with_limits(Duration::from_secs(300), 100);

        // Fill to capacity
        for i in 0..100u8 {
            let _ = gate.record_seen(make_hash(i), None, 1);
        }
        assert_eq!(gate.seen.len(), 100);

        // One more triggers eviction to 75% target
        let _ = gate.record_seen(make_hash(200), None, 1);
        assert!(gate.seen.len() <= 75);
        assert!(gate.stats().evictions_total > 0);
    }

    #[test]
    fn test_flood_gate_fifo_order() {
        let gate = FloodGate::with_limits(Duration::from_secs(300), 4);

        let ha = make_hash(1);
        let hb = make_hash(2);
        let hc = make_hash(3);
        let hd = make_hash(4);

        let _ = gate.record_seen(ha, None, 1);
        let _ = gate.record_seen(hb, None, 1);
        let _ = gate.record_seen(hc, None, 1);
        let _ = gate.record_seen(hd, None, 1);

        // Insert one more — triggers eviction. A (oldest) should be evicted.
        let he = make_hash(5);
        let _ = gate.record_seen(he, None, 1);

        // Target is 75% of 4 = 3. So we evict until <= 3.
        // After inserting 5th, we had 5 entries, evict oldest until <= 3.
        assert!(!gate.has_seen(&ha)); // A evicted (oldest)
        assert!(!gate.has_seen(&hb)); // B evicted
        assert!(gate.has_seen(&he)); // E (newest) survives
    }

    #[test]
    fn test_flood_gate_ghost_entries_skipped() {
        let gate = FloodGate::with_limits(Duration::from_secs(300), 10);

        // Insert entries at ledger 1 and ledger 2
        for i in 0..5u8 {
            let _ = gate.record_seen(make_hash(i), None, 1);
        }
        for i in 10..15u8 {
            let _ = gate.record_seen(make_hash(i), None, 2);
        }
        assert_eq!(gate.seen.len(), 10);

        // clear_below(2) removes ledger-1 entries → creates ghosts in queue
        gate.clear_below(2);
        assert_eq!(gate.seen.len(), 5);

        // Now fill up to trigger eviction. The 5 ghost entries should be skipped.
        for i in 20..30u8 {
            let _ = gate.record_seen(make_hash(i), None, 2);
        }
        // Should have triggered eviction; verify we're at or below cap
        assert!(gate.seen.len() <= 10);
    }

    #[test]
    fn test_flood_gate_forget_creates_ghost() {
        let gate = FloodGate::with_limits(Duration::from_secs(300), 4);

        let ha = make_hash(1);
        let hb = make_hash(2);
        let hc = make_hash(3);
        let hd = make_hash(4);

        let _ = gate.record_seen(ha, None, 1);
        let _ = gate.record_seen(hb, None, 1);
        let _ = gate.record_seen(hc, None, 1);
        let _ = gate.record_seen(hd, None, 1);

        // Forget B — creates a ghost in the queue
        gate.forget(&hb);
        assert_eq!(gate.seen.len(), 3);

        // Insert two more to trigger eviction
        let he = make_hash(5);
        let hf = make_hash(6);
        let _ = gate.record_seen(he, None, 1);
        // Now seen has 4 entries (A, C, D, E), at capacity
        let _ = gate.record_seen(hf, None, 1);
        // Now 5 entries, eviction triggered. Queue: [A, B(ghost), C, D, E, F]
        // Eviction pops A (evicted), B (ghost, skipped), C (evicted) → target is 3
        assert!(!gate.has_seen(&ha));
        assert!(gate.has_seen(&hf)); // newest survives
    }

    #[test]
    fn test_flood_gate_generation_prevents_stale_eviction() {
        let gate = FloodGate::with_limits(Duration::from_secs(300), 4);

        let ha = make_hash(1);
        let hb = make_hash(2);
        let hc = make_hash(3);
        let hd = make_hash(4);

        let _ = gate.record_seen(ha, None, 1);
        let _ = gate.record_seen(hb, None, 1);
        let _ = gate.record_seen(hc, None, 1);
        let _ = gate.record_seen(hd, None, 1);

        // Forget A, then re-insert A (new generation)
        gate.forget(&ha);
        let _ = gate.record_seen(ha, None, 2);
        // Queue: [(A,gen0), (B,gen1), (C,gen2), (D,gen3), (A,gen4)]
        // Map has: A(gen4), B(gen1), C(gen2), D(gen3) = 4 entries

        // Insert one more to trigger eviction
        let he = make_hash(5);
        let _ = gate.record_seen(he, None, 2);
        // 5 entries > cap of 4. Eviction pops (A,gen0) → map has A(gen4), mismatch → skip!
        // Then pops (B,gen1) → matches → evict. Then (C,gen2) → matches → evict.
        // Target is 3 (75% of 4).
        // A should survive because its generation was updated.
        assert!(gate.has_seen(&ha)); // Re-inserted A survives!
        assert!(gate.has_seen(&he)); // Newest survives
    }

    #[test]
    fn test_flood_gate_clear_resets_queue() {
        let gate = FloodGate::with_limits(Duration::from_secs(300), 100);

        for i in 0..50u8 {
            let _ = gate.record_seen(make_hash(i), None, 1);
        }
        assert_eq!(gate.seen.len(), 50);

        gate.clear();
        assert_eq!(gate.seen.len(), 0);
        let queue = gate.eviction_queue.lock();
        assert!(queue.is_empty());
    }

    #[test]
    fn test_flood_gate_queue_compaction() {
        // Cap of 5, so compaction triggers when queue > 10
        let gate = FloodGate::with_limits(Duration::from_secs(300), 5);

        // Insert 5 entries at ledger 1
        for i in 0..5u8 {
            let _ = gate.record_seen(make_hash(i), None, 1);
        }
        // Queue has 5 entries

        // Clear them all by ledger (creates 5 ghosts)
        gate.clear_below(2);
        assert_eq!(gate.seen.len(), 0);
        // Queue still has 5 ghost entries (below 2*5=10, no compaction yet)

        // Insert 5 more at ledger 2
        for i in 10..15u8 {
            let _ = gate.record_seen(make_hash(i), None, 2);
        }
        // Queue: 5 ghosts + 5 live = 10 entries

        // Clear again
        gate.clear_below(3);
        // Now queue has 10 ghosts (still 10, not > 10, so no compaction)

        // Insert 1 more to push queue over 10 (compaction threshold is > 2*5=10)
        let _ = gate.record_seen(make_hash(20), None, 3);
        // Queue has 11 entries. clear_below didn't compact because len was exactly 10.
        // But on next clear_below it should compact if > 10.

        // Force clear_below to trigger compaction check
        gate.clear_below(3);
        let queue = gate.eviction_queue.lock();
        // After compaction (queue.len() was 11 > 10), queue should be cleared
        assert!(queue.len() <= 1); // only the one live entry or empty after clear
    }

    #[test]
    fn test_flood_gate_eviction_stats() {
        let gate = FloodGate::with_limits(Duration::from_secs(300), 10);

        // Fill to capacity
        for i in 0..10u8 {
            let _ = gate.record_seen(make_hash(i), None, 1);
        }
        assert_eq!(gate.stats().evictions_total, 0);

        // Trigger eviction
        let _ = gate.record_seen(make_hash(100), None, 1);
        assert!(gate.stats().evictions_total > 0);
    }

    #[test]
    fn test_flood_gate_no_eviction_below_cap() {
        let gate = FloodGate::with_limits(Duration::from_secs(300), 100);

        for i in 0..50u8 {
            let _ = gate.record_seen(make_hash(i), None, 1);
        }
        assert_eq!(gate.seen.len(), 50);
        assert_eq!(gate.stats().evictions_total, 0);
    }

    #[test]
    #[should_panic(expected = "FloodGate max_entries must be > 0")]
    fn test_flood_gate_with_limits_panics_on_zero() {
        FloodGate::with_limits(Duration::from_secs(300), 0);
    }

    #[test]
    fn test_flood_gate_eviction_warn_resets() {
        let gate = FloodGate::with_limits(Duration::from_secs(300), 10);

        // Fill and trigger eviction → sets eviction_warned
        for i in 0..11u8 {
            let _ = gate.record_seen(make_hash(i), None, 1);
        }
        assert!(gate.eviction_warned.load(Ordering::Relaxed));

        // clear_below that brings map below 50% should reset the warning
        gate.clear_below(u32::MAX); // removes everything (ledger < MAX)
        assert!(!gate.eviction_warned.load(Ordering::Relaxed));
    }

    #[test]
    fn test_flood_gate_concurrent_bounded() {
        use std::sync::Arc;
        use std::thread;

        let gate = Arc::new(FloodGate::with_limits(Duration::from_secs(300), 1000));
        let num_threads = 8;
        let inserts_per_thread = 500;

        let handles: Vec<_> = (0..num_threads)
            .map(|t| {
                let gate = Arc::clone(&gate);
                thread::spawn(move || {
                    for i in 0..inserts_per_thread {
                        let hash = Hash256([(t * 100 + i) as u8; 32]);
                        let _ = gate.record_seen(hash, None, 1);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // After all threads complete, map should be at or below cap + bounded overshoot
        assert!(
            gate.seen.len() <= 1000 + num_threads,
            "seen.len() = {} exceeds expected bound",
            gate.seen.len()
        );
    }
}
