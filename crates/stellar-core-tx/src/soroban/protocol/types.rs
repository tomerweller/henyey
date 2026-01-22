//! Shared types for protocol-versioned host implementations.

use stellar_xdr::curr::{ContractEvent, LedgerEntry, LedgerKey, ScVal};

/// Output from invoking a Soroban host function.
#[derive(Debug, Clone)]
pub struct InvokeHostFunctionOutput {
    /// The return value from the contract execution.
    pub return_value: ScVal,
    /// Changes to ledger entries.
    pub ledger_changes: Vec<LedgerEntryChange>,
    /// Decoded contract events for hash computation (Contract and System types only).
    /// These are the events that go into InvokeHostFunctionSuccessPreImage.
    pub contract_events: Vec<ContractEvent>,
    /// All encoded contract events (for diagnostic purposes).
    pub encoded_contract_events: Vec<EncodedContractEvent>,
    /// CPU instructions consumed.
    pub cpu_insns: u64,
    /// Memory bytes consumed.
    pub mem_bytes: u64,
    /// Entries restored from the live BucketList (expired TTL but not yet evicted).
    /// These need RESTORED ledger entry changes emitted in transaction meta.
    pub live_bucket_list_restores: Vec<LiveBucketListRestore>,
}

/// An entry restored from the live BucketList (had expired TTL but wasn't yet evicted).
#[derive(Debug, Clone)]
pub struct LiveBucketListRestore {
    /// The ledger key of the restored entry (ContractData or ContractCode).
    pub key: LedgerKey,
    /// The entry that was restored (pre-modification state).
    pub entry: LedgerEntry,
    /// The TTL key for this entry.
    pub ttl_key: LedgerKey,
    /// The TTL entry that was restored (pre-modification state with old expired TTL).
    pub ttl_entry: LedgerEntry,
}

/// A change to a ledger entry from contract execution.
#[derive(Debug, Clone)]
pub struct LedgerEntryChange {
    /// The ledger key that was changed.
    pub key: LedgerKey,
    /// The new entry value (None if deleted).
    pub new_entry: Option<LedgerEntry>,
    /// TTL change information if applicable.
    pub ttl_change: Option<TtlChange>,
    /// Old entry size for rent calculation.
    pub old_entry_size_bytes: u32,
}

/// TTL change information for a ledger entry.
#[derive(Debug, Clone, Copy)]
pub struct TtlChange {
    /// The old live_until ledger number (before the change).
    pub old_live_until_ledger: u32,
    /// The new live_until ledger number.
    pub new_live_until_ledger: u32,
}

impl TtlChange {
    /// Returns true if the TTL was actually extended (new > old).
    /// C++ stellar-core only emits TTL changes when TTL is extended.
    pub fn is_extended(&self) -> bool {
        self.new_live_until_ledger > self.old_live_until_ledger
    }
}

/// An encoded contract event from execution.
#[derive(Debug, Clone)]
pub struct EncodedContractEvent {
    /// The XDR-encoded event bytes.
    pub encoded_event: Vec<u8>,
    /// Whether this event was in a successful contract call.
    pub in_successful_call: bool,
}
