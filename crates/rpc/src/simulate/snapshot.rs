use std::rc::Rc;

use henyey_bucket::SearchableBucketListSnapshot;
use soroban_env_host_p25 as soroban_host;
use stellar_xdr::curr::LedgerKey;

use soroban_host::storage::{EntryWithLiveUntil, SnapshotSource};
use soroban_host::HostError;

use crate::util::ttl_key_for_ledger_key;

/// Adapter that provides snapshot access to the bucket list for Soroban simulation.
///
/// Implements `SnapshotSource` from `soroban-env-host-p25` by wrapping a
/// `SearchableBucketListSnapshot`. This is used for `simulateTransaction`
/// where we need read-only access to the current ledger state.
pub(crate) struct BucketListSnapshotSource {
    snapshot: SearchableBucketListSnapshot,
    current_ledger: u32,
}

// Safety: BucketListSnapshotSource contains only owned, immutable data.
// SearchableBucketListSnapshot holds cloned data from the bucket list.
// It is safe to send across threads.
unsafe impl Send for BucketListSnapshotSource {}

impl BucketListSnapshotSource {
    pub(crate) fn new(snapshot: SearchableBucketListSnapshot, current_ledger: u32) -> Self {
        Self {
            snapshot,
            current_ledger,
        }
    }
}

impl SnapshotSource for BucketListSnapshotSource {
    fn get(&self, key: &Rc<LedgerKey>) -> Result<Option<EntryWithLiveUntil>, HostError> {
        // For contract data/code entries, we need to check TTL
        let live_until = get_entry_ttl(&self.snapshot, key.as_ref());

        // Check TTL expiration for contract entries
        if matches!(
            key.as_ref(),
            LedgerKey::ContractData(_) | LedgerKey::ContractCode(_)
        ) {
            match live_until {
                Some(ttl) if ttl >= self.current_ledger => {} // live, proceed
                _ => return Ok(None),                         // expired or no TTL
            }
        }

        // Look up the entry in the bucket list
        match self.snapshot.load(key.as_ref()) {
            Some(entry) => Ok(Some((Rc::new(entry), live_until))),
            None => Ok(None),
        }
    }
}

/// Get the TTL (live_until_ledger) for a ledger entry from the bucket list.
fn get_entry_ttl(snapshot: &SearchableBucketListSnapshot, key: &LedgerKey) -> Option<u32> {
    let ttl_key = ttl_key_for_ledger_key(key)?;

    // Look up the TTL entry
    let ttl_entry = snapshot.load(&ttl_key)?;
    match ttl_entry.data {
        stellar_xdr::curr::LedgerEntryData::Ttl(ttl_data) => Some(ttl_data.live_until_ledger_seq),
        _ => None,
    }
}
