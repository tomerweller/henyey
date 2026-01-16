//! FutureBucket - Async bucket merging support.
//!
//! FutureBucket is a wrapper around async bucket merge operations, supporting
//! both in-progress and completed merges. It enables:
//!
//! - Background merge execution via async tasks
//! - Serialization/deserialization of merge state to HistoryArchiveState
//! - Restarting merges after deserialization
//!
//! # State Machine
//!
//! FutureBucket has five states:
//!
//! - `Clear`: No inputs or outputs
//! - `HashOutput`: Has output hash, but no live bucket reference
//! - `HashInputs`: Has input hashes, but no live bucket references
//! - `LiveOutput`: Has resolved output bucket
//! - `LiveInputs`: Merge in progress with live input references
//!
//! # Lifecycle
//!
//! 1. Created with inputs → starts merge → `LiveInputs`
//! 2. Merge completes → `resolve()` → `LiveOutput`
//! 3. Can be serialized (captures hashes) → `HashInputs` or `HashOutput`
//! 4. Can be deserialized and made live again → `makeLive()`

use std::sync::Arc;
use tokio::sync::oneshot;

use serde::{Deserialize, Serialize};
use stellar_core_common::Hash256;

use crate::bucket::Bucket;
use crate::merge::merge_buckets_with_options;
use crate::{BucketError, Result};

/// State of a FutureBucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FutureBucketState {
    /// No inputs; no outputs; no hashes.
    Clear,
    /// Output hash present; no live output bucket.
    HashOutput,
    /// Input hashes present; no live input buckets.
    HashInputs,
    /// Live output bucket available.
    LiveOutput,
    /// Live input buckets; merge in progress.
    LiveInputs,
}

/// Key identifying a unique merge operation.
///
/// Used to deduplicate concurrent merge requests for the same inputs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MergeKey {
    /// Whether tombstone entries are kept (level < 10).
    pub keep_tombstones: bool,
    /// Hash of the curr bucket.
    pub curr_hash: Hash256,
    /// Hash of the snap bucket.
    pub snap_hash: Hash256,
}

impl MergeKey {
    /// Create a new merge key.
    pub fn new(keep_tombstones: bool, curr_hash: Hash256, snap_hash: Hash256) -> Self {
        Self {
            keep_tombstones,
            curr_hash,
            snap_hash,
        }
    }
}

/// Serializable representation of a FutureBucket for HistoryArchiveState.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FutureBucketSnapshot {
    /// Current state.
    pub state: FutureBucketState,
    /// Curr bucket hash (when state is HashInputs or LiveInputs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curr: Option<String>,
    /// Snap bucket hash (when state is HashInputs or LiveInputs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snap: Option<String>,
    /// Output bucket hash (when state is HashOutput or LiveOutput).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

impl Default for FutureBucketSnapshot {
    fn default() -> Self {
        Self {
            state: FutureBucketState::Clear,
            curr: None,
            snap: None,
            output: None,
        }
    }
}

/// Async handle to receive the result of a background merge.
pub struct MergeHandle {
    receiver: oneshot::Receiver<Result<Bucket>>,
}

impl MergeHandle {
    /// Check if the merge is complete without blocking.
    pub fn is_complete(&mut self) -> bool {
        // Try to receive without blocking
        matches!(
            self.receiver.try_recv(),
            Ok(_) | Err(oneshot::error::TryRecvError::Closed)
        )
    }

    /// Wait for the merge to complete and return the result.
    pub async fn resolve(self) -> Result<Bucket> {
        self.receiver
            .await
            .map_err(|_| BucketError::Merge("merge task was cancelled".to_string()))?
    }
}

/// FutureBucket wraps an async bucket merge operation.
///
/// This enables background merging of buckets while the main thread continues
/// processing. The merge result can be retrieved when ready via `resolve()`.
pub struct FutureBucket {
    /// Current state of the future bucket.
    state: FutureBucketState,

    /// Live curr bucket (when state is LiveInputs).
    input_curr: Option<Arc<Bucket>>,
    /// Live snap bucket (when state is LiveInputs).
    input_snap: Option<Arc<Bucket>>,
    /// Live output bucket (when state is LiveOutput).
    output: Option<Arc<Bucket>>,

    /// Handle to the background merge task (when state is LiveInputs).
    merge_handle: Option<MergeHandle>,

    /// Curr bucket hash (for serialization).
    input_curr_hash: Option<Hash256>,
    /// Snap bucket hash (for serialization).
    input_snap_hash: Option<Hash256>,
    /// Output bucket hash (for serialization).
    output_hash: Option<Hash256>,

    /// Protocol version for the merge.
    protocol_version: u32,
    /// Whether to keep tombstone entries.
    keep_tombstones: bool,
    /// Whether to normalize INIT entries to LIVE.
    normalize_init: bool,
}

impl FutureBucket {
    /// Create a new FutureBucket in Clear state.
    pub fn clear() -> Self {
        Self {
            state: FutureBucketState::Clear,
            input_curr: None,
            input_snap: None,
            output: None,
            merge_handle: None,
            input_curr_hash: None,
            input_snap_hash: None,
            output_hash: None,
            protocol_version: 0,
            keep_tombstones: true,
            normalize_init: false,
        }
    }

    /// Create a new FutureBucket and start a merge operation.
    ///
    /// This immediately starts the merge in a background task.
    pub fn start_merge(
        curr: Arc<Bucket>,
        snap: Arc<Bucket>,
        protocol_version: u32,
        keep_tombstones: bool,
        normalize_init: bool,
    ) -> Self {
        let curr_hash = curr.hash();
        let snap_hash = snap.hash();

        // Create the oneshot channel for the merge result
        let (sender, receiver) = oneshot::channel();

        // Clone the buckets for the merge task
        let curr_clone = curr.clone();
        let snap_clone = snap.clone();

        // Spawn the merge task
        tokio::spawn(async move {
            let result = merge_buckets_with_options(
                &curr_clone,
                &snap_clone,
                keep_tombstones,
                protocol_version,
                normalize_init,
            );
            // Send the result, ignoring errors if the receiver was dropped
            let _ = sender.send(result);
        });

        Self {
            state: FutureBucketState::LiveInputs,
            input_curr: Some(curr),
            input_snap: Some(snap),
            output: None,
            merge_handle: Some(MergeHandle { receiver }),
            input_curr_hash: Some(curr_hash),
            input_snap_hash: Some(snap_hash),
            output_hash: None,
            protocol_version,
            keep_tombstones,
            normalize_init,
        }
    }

    /// Create a FutureBucket from a completed merge (already has output).
    pub fn from_output(bucket: Arc<Bucket>) -> Self {
        let hash = bucket.hash();
        Self {
            state: FutureBucketState::LiveOutput,
            input_curr: None,
            input_snap: None,
            output: Some(bucket),
            merge_handle: None,
            input_curr_hash: None,
            input_snap_hash: None,
            output_hash: Some(hash),
            protocol_version: 0,
            keep_tombstones: true,
            normalize_init: false,
        }
    }

    /// Create a FutureBucket from a snapshot (for deserialization).
    pub fn from_snapshot(snapshot: FutureBucketSnapshot) -> Result<Self> {
        match snapshot.state {
            FutureBucketState::Clear => Ok(Self::clear()),
            FutureBucketState::HashOutput => {
                let output_hash = snapshot
                    .output
                    .ok_or_else(|| BucketError::Serialization("missing output hash".to_string()))?;
                let hash = Hash256::from_hex(&output_hash).map_err(|e| {
                    BucketError::Serialization(format!("invalid output hash: {}", e))
                })?;
                Ok(Self {
                    state: FutureBucketState::HashOutput,
                    input_curr: None,
                    input_snap: None,
                    output: None,
                    merge_handle: None,
                    input_curr_hash: None,
                    input_snap_hash: None,
                    output_hash: Some(hash),
                    protocol_version: 0,
                    keep_tombstones: true,
                    normalize_init: false,
                })
            }
            FutureBucketState::HashInputs => {
                let curr_hash = snapshot
                    .curr
                    .ok_or_else(|| BucketError::Serialization("missing curr hash".to_string()))?;
                let snap_hash = snapshot
                    .snap
                    .ok_or_else(|| BucketError::Serialization("missing snap hash".to_string()))?;
                let curr = Hash256::from_hex(&curr_hash)
                    .map_err(|e| BucketError::Serialization(format!("invalid curr hash: {}", e)))?;
                let snap = Hash256::from_hex(&snap_hash)
                    .map_err(|e| BucketError::Serialization(format!("invalid snap hash: {}", e)))?;
                Ok(Self {
                    state: FutureBucketState::HashInputs,
                    input_curr: None,
                    input_snap: None,
                    output: None,
                    merge_handle: None,
                    input_curr_hash: Some(curr),
                    input_snap_hash: Some(snap),
                    output_hash: None,
                    protocol_version: 0,
                    keep_tombstones: true,
                    normalize_init: false,
                })
            }
            _ => Err(BucketError::Serialization(format!(
                "invalid deserialized state: {:?}",
                snapshot.state
            ))),
        }
    }

    /// Get the current state.
    pub fn state(&self) -> FutureBucketState {
        self.state
    }

    /// Check if this FutureBucket is in a live state (has bucket references).
    pub fn is_live(&self) -> bool {
        matches!(
            self.state,
            FutureBucketState::LiveInputs | FutureBucketState::LiveOutput
        )
    }

    /// Check if a merge is in progress.
    pub fn is_merging(&self) -> bool {
        self.state == FutureBucketState::LiveInputs
    }

    /// Check if this FutureBucket is clear (no data).
    pub fn is_clear(&self) -> bool {
        self.state == FutureBucketState::Clear
    }

    /// Check if this FutureBucket has hashes but no live references.
    pub fn has_hashes(&self) -> bool {
        matches!(
            self.state,
            FutureBucketState::HashInputs | FutureBucketState::HashOutput
        )
    }

    /// Check if the merge is complete (output is ready).
    ///
    /// Note: For LiveInputs state, use `is_ready()` which takes `&mut self`
    /// to properly check the oneshot channel status.
    pub fn merge_complete(&self) -> bool {
        match self.state {
            FutureBucketState::LiveOutput => true,
            FutureBucketState::LiveInputs => {
                // Conservative: return false since we can't check without mutable access
                // Use is_ready() for accurate checking
                false
            }
            _ => false,
        }
    }

    /// Check if the merge is ready without blocking.
    pub fn is_ready(&mut self) -> bool {
        if self.state == FutureBucketState::LiveOutput {
            return true;
        }
        if let Some(handle) = &mut self.merge_handle {
            handle.is_complete()
        } else {
            false
        }
    }

    /// Resolve the merge, waiting if necessary.
    ///
    /// After calling this, the FutureBucket will be in LiveOutput state.
    pub async fn resolve(&mut self) -> Result<Arc<Bucket>> {
        match self.state {
            FutureBucketState::LiveOutput => Ok(self.output.clone().expect("output should be set")),
            FutureBucketState::LiveInputs => {
                let handle = self.merge_handle.take().ok_or_else(|| {
                    BucketError::Merge("merge handle already consumed".to_string())
                })?;

                let bucket = handle.resolve().await?;
                let bucket = Arc::new(bucket);
                let hash = bucket.hash();

                // Clear inputs
                self.input_curr = None;
                self.input_snap = None;
                self.input_curr_hash = None;
                self.input_snap_hash = None;

                // Set output
                self.output = Some(bucket.clone());
                self.output_hash = Some(hash);
                self.state = FutureBucketState::LiveOutput;

                Ok(bucket)
            }
            _ => Err(BucketError::Merge(format!(
                "cannot resolve FutureBucket in state {:?}",
                self.state
            ))),
        }
    }

    /// Resolve synchronously (blocking).
    ///
    /// This is useful when you need the result immediately and are not in an async context.
    pub fn resolve_blocking(&mut self) -> Result<Arc<Bucket>> {
        match self.state {
            FutureBucketState::LiveOutput => Ok(self.output.clone().expect("output should be set")),
            FutureBucketState::LiveInputs => {
                // Do synchronous merge
                let curr = self
                    .input_curr
                    .as_ref()
                    .ok_or_else(|| BucketError::Merge("missing curr input".to_string()))?;
                let snap = self
                    .input_snap
                    .as_ref()
                    .ok_or_else(|| BucketError::Merge("missing snap input".to_string()))?;

                let bucket = merge_buckets_with_options(
                    curr,
                    snap,
                    self.keep_tombstones,
                    self.protocol_version,
                    self.normalize_init,
                )?;
                let bucket = Arc::new(bucket);
                let hash = bucket.hash();

                // Clear inputs
                self.input_curr = None;
                self.input_snap = None;
                self.input_curr_hash = None;
                self.input_snap_hash = None;
                self.merge_handle = None;

                // Set output
                self.output = Some(bucket.clone());
                self.output_hash = Some(hash);
                self.state = FutureBucketState::LiveOutput;

                Ok(bucket)
            }
            _ => Err(BucketError::Merge(format!(
                "cannot resolve FutureBucket in state {:?}",
                self.state
            ))),
        }
    }

    /// Get the output hash if available.
    pub fn output_hash(&self) -> Option<&Hash256> {
        self.output_hash.as_ref()
    }

    /// Get the output bucket if available.
    pub fn output(&self) -> Option<&Arc<Bucket>> {
        self.output.as_ref()
    }

    /// Get all hashes referenced by this FutureBucket.
    pub fn get_hashes(&self) -> Vec<Hash256> {
        let mut hashes = Vec::new();
        if let Some(h) = &self.input_curr_hash {
            hashes.push(h.clone());
        }
        if let Some(h) = &self.input_snap_hash {
            hashes.push(h.clone());
        }
        if let Some(h) = &self.output_hash {
            hashes.push(h.clone());
        }
        hashes
    }

    /// Create a snapshot for serialization.
    pub fn to_snapshot(&self) -> FutureBucketSnapshot {
        match self.state {
            FutureBucketState::Clear => FutureBucketSnapshot::default(),
            FutureBucketState::HashOutput | FutureBucketState::LiveOutput => FutureBucketSnapshot {
                state: FutureBucketState::HashOutput,
                curr: None,
                snap: None,
                output: self.output_hash.as_ref().map(|h| h.to_hex()),
            },
            FutureBucketState::HashInputs | FutureBucketState::LiveInputs => FutureBucketSnapshot {
                state: FutureBucketState::HashInputs,
                curr: self.input_curr_hash.as_ref().map(|h| h.to_hex()),
                snap: self.input_snap_hash.as_ref().map(|h| h.to_hex()),
                output: None,
            },
        }
    }

    /// Make this FutureBucket live by loading buckets from the provided loader.
    ///
    /// This is used after deserializing a FutureBucket to restart the merge.
    pub fn make_live<F>(
        &mut self,
        load_bucket: F,
        protocol_version: u32,
        keep_tombstones: bool,
        normalize_init: bool,
    ) -> Result<()>
    where
        F: Fn(&Hash256) -> Result<Bucket>,
    {
        match self.state {
            FutureBucketState::HashOutput => {
                let hash = self
                    .output_hash
                    .as_ref()
                    .ok_or_else(|| BucketError::Merge("missing output hash".to_string()))?;
                let bucket = load_bucket(hash)?;
                self.output = Some(Arc::new(bucket));
                self.state = FutureBucketState::LiveOutput;
                Ok(())
            }
            FutureBucketState::HashInputs => {
                let curr_hash = self
                    .input_curr_hash
                    .as_ref()
                    .ok_or_else(|| BucketError::Merge("missing curr hash".to_string()))?;
                let snap_hash = self
                    .input_snap_hash
                    .as_ref()
                    .ok_or_else(|| BucketError::Merge("missing snap hash".to_string()))?;

                let curr = Arc::new(load_bucket(curr_hash)?);
                let snap = Arc::new(load_bucket(snap_hash)?);

                // Start the merge
                let (sender, receiver) = oneshot::channel();

                let curr_clone = curr.clone();
                let snap_clone = snap.clone();

                tokio::spawn(async move {
                    let result = merge_buckets_with_options(
                        &curr_clone,
                        &snap_clone,
                        keep_tombstones,
                        protocol_version,
                        normalize_init,
                    );
                    let _ = sender.send(result);
                });

                self.input_curr = Some(curr);
                self.input_snap = Some(snap);
                self.merge_handle = Some(MergeHandle { receiver });
                self.protocol_version = protocol_version;
                self.keep_tombstones = keep_tombstones;
                self.normalize_init = normalize_init;
                self.state = FutureBucketState::LiveInputs;
                Ok(())
            }
            FutureBucketState::Clear => Ok(()), // Nothing to do
            _ => Err(BucketError::Merge(format!(
                "cannot make live in state {:?}",
                self.state
            ))),
        }
    }

    /// Get the merge key for this FutureBucket (for deduplication).
    pub fn merge_key(&self) -> Option<MergeKey> {
        match self.state {
            FutureBucketState::LiveInputs | FutureBucketState::HashInputs => Some(MergeKey::new(
                self.keep_tombstones,
                self.input_curr_hash.clone()?,
                self.input_snap_hash.clone()?,
            )),
            _ => None,
        }
    }
}

impl Default for FutureBucket {
    fn default() -> Self {
        Self::clear()
    }
}

impl std::fmt::Debug for FutureBucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FutureBucket")
            .field("state", &self.state)
            .field(
                "input_curr_hash",
                &self.input_curr_hash.as_ref().map(|h| h.to_hex()),
            )
            .field(
                "input_snap_hash",
                &self.input_snap_hash.as_ref().map(|h| h.to_hex()),
            )
            .field(
                "output_hash",
                &self.output_hash.as_ref().map(|h| h.to_hex()),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::BucketEntry;
    use stellar_xdr::curr::*;

    fn make_account_id(bytes: [u8; 32]) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes)))
    }

    fn make_account_entry(bytes: [u8; 32], balance: i64) -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 1,
            data: LedgerEntryData::Account(AccountEntry {
                account_id: make_account_id(bytes),
                balance,
                seq_num: SequenceNumber(1),
                num_sub_entries: 0,
                inflation_dest: None,
                flags: 0,
                home_domain: String32::default(),
                thresholds: Thresholds([1, 0, 0, 0]),
                signers: Vec::new().try_into().unwrap(),
                ext: AccountEntryExt::V0,
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    #[test]
    fn test_future_bucket_clear() {
        let fb = FutureBucket::clear();
        assert!(fb.is_clear());
        assert!(!fb.is_live());
        assert!(!fb.is_merging());
        assert!(!fb.has_hashes());
    }

    #[test]
    fn test_future_bucket_from_output() {
        let entry = make_account_entry([1u8; 32], 100);
        let bucket = Bucket::from_entries(vec![BucketEntry::Live(entry)]).unwrap();
        let hash = bucket.hash();
        let bucket = Arc::new(bucket);

        let fb = FutureBucket::from_output(bucket.clone());
        assert!(!fb.is_clear());
        assert!(fb.is_live());
        assert!(!fb.is_merging());
        assert_eq!(fb.output_hash(), Some(&hash));
        assert!(fb.output().is_some());
    }

    #[test]
    fn test_future_bucket_snapshot_roundtrip() {
        // Test Clear state
        let fb = FutureBucket::clear();
        let snapshot = fb.to_snapshot();
        let fb2 = FutureBucket::from_snapshot(snapshot).unwrap();
        assert!(fb2.is_clear());

        // Test HashOutput state
        let entry = make_account_entry([1u8; 32], 100);
        let bucket = Bucket::from_entries(vec![BucketEntry::Live(entry)]).unwrap();
        let bucket = Arc::new(bucket);
        let fb = FutureBucket::from_output(bucket);
        let snapshot = fb.to_snapshot();
        assert_eq!(snapshot.state, FutureBucketState::HashOutput);
        assert!(snapshot.output.is_some());

        let fb2 = FutureBucket::from_snapshot(snapshot).unwrap();
        assert_eq!(fb2.state(), FutureBucketState::HashOutput);
        assert!(fb2.output_hash().is_some());
    }

    #[test]
    fn test_future_bucket_resolve_blocking() {
        let entry1 = make_account_entry([1u8; 32], 100);
        let entry2 = make_account_entry([2u8; 32], 200);

        let bucket1 = Arc::new(Bucket::from_entries(vec![BucketEntry::Live(entry1)]).unwrap());
        let bucket2 = Arc::new(Bucket::from_entries(vec![BucketEntry::Live(entry2)]).unwrap());

        let mut fb = FutureBucket {
            state: FutureBucketState::LiveInputs,
            input_curr: Some(bucket1.clone()),
            input_snap: Some(bucket2.clone()),
            output: None,
            merge_handle: None,
            input_curr_hash: Some(bucket1.hash()),
            input_snap_hash: Some(bucket2.hash()),
            output_hash: None,
            protocol_version: 25,
            keep_tombstones: true,
            normalize_init: false,
        };

        let result = fb.resolve_blocking().unwrap();
        assert!(fb.is_live());
        assert!(!fb.is_merging());
        assert_eq!(fb.state(), FutureBucketState::LiveOutput);
        assert!(fb.output().is_some());
        // Result contains: metadata entry + 2 account entries = 3 entries
        assert!(result.len() >= 2); // At least both account entries merged
    }

    #[test]
    fn test_merge_key() {
        let hash1 = Hash256::from_bytes([1u8; 32]);
        let hash2 = Hash256::from_bytes([2u8; 32]);

        let key = MergeKey::new(true, hash1.clone(), hash2.clone());
        assert!(key.keep_tombstones);
        assert_eq!(key.curr_hash, hash1);
        assert_eq!(key.snap_hash, hash2);
    }

    #[test]
    fn test_get_hashes() {
        let entry = make_account_entry([1u8; 32], 100);
        let bucket = Bucket::from_entries(vec![BucketEntry::Live(entry)]).unwrap();
        let bucket = Arc::new(bucket);

        let fb = FutureBucket::from_output(bucket);
        let hashes = fb.get_hashes();
        assert_eq!(hashes.len(), 1);
    }
}
