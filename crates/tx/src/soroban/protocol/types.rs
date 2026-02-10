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
    /// stellar-core only emits TTL changes when TTL is extended.
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

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        ContractDataDurability, ContractDataEntry, ContractId, ExtensionPoint, Hash,
        LedgerEntryData, LedgerEntryExt, LedgerKeyContractData, ScAddress,
    };

    fn test_ledger_key() -> LedgerKey {
        LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash([1u8; 32]))),
            key: ScVal::Void,
            durability: ContractDataDurability::Persistent,
        })
    }

    fn test_ledger_entry() -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 100,
            data: LedgerEntryData::ContractData(ContractDataEntry {
                ext: ExtensionPoint::V0,
                contract: ScAddress::Contract(ContractId(Hash([1u8; 32]))),
                key: ScVal::Void,
                durability: ContractDataDurability::Persistent,
                val: ScVal::I32(42),
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    // === TtlChange tests ===

    #[test]
    fn test_ttl_change_is_extended_true() {
        let change = TtlChange {
            old_live_until_ledger: 100,
            new_live_until_ledger: 200,
        };
        assert!(change.is_extended());
    }

    #[test]
    fn test_ttl_change_is_extended_false_same() {
        let change = TtlChange {
            old_live_until_ledger: 100,
            new_live_until_ledger: 100,
        };
        assert!(!change.is_extended());
    }

    #[test]
    fn test_ttl_change_is_extended_false_decreased() {
        let change = TtlChange {
            old_live_until_ledger: 200,
            new_live_until_ledger: 100,
        };
        assert!(!change.is_extended());
    }

    #[test]
    fn test_ttl_change_debug() {
        let change = TtlChange {
            old_live_until_ledger: 100,
            new_live_until_ledger: 200,
        };
        let debug_str = format!("{:?}", change);
        assert!(debug_str.contains("TtlChange"));
        assert!(debug_str.contains("100"));
        assert!(debug_str.contains("200"));
    }

    #[test]
    fn test_ttl_change_copy() {
        let change = TtlChange {
            old_live_until_ledger: 100,
            new_live_until_ledger: 200,
        };
        let copy = change;
        assert_eq!(copy.old_live_until_ledger, 100);
        assert_eq!(copy.new_live_until_ledger, 200);
    }

    // === LedgerEntryChange tests ===

    #[test]
    fn test_ledger_entry_change_create() {
        let change = LedgerEntryChange {
            key: test_ledger_key(),
            new_entry: Some(test_ledger_entry()),
            ttl_change: Some(TtlChange {
                old_live_until_ledger: 0,
                new_live_until_ledger: 1000,
            }),
            old_entry_size_bytes: 0,
        };

        assert!(change.new_entry.is_some());
        assert!(change.ttl_change.is_some());
        assert_eq!(change.old_entry_size_bytes, 0);
    }

    #[test]
    fn test_ledger_entry_change_update() {
        let change = LedgerEntryChange {
            key: test_ledger_key(),
            new_entry: Some(test_ledger_entry()),
            ttl_change: None,
            old_entry_size_bytes: 100,
        };

        assert!(change.new_entry.is_some());
        assert!(change.ttl_change.is_none());
        assert_eq!(change.old_entry_size_bytes, 100);
    }

    #[test]
    fn test_ledger_entry_change_delete() {
        let change = LedgerEntryChange {
            key: test_ledger_key(),
            new_entry: None,
            ttl_change: None,
            old_entry_size_bytes: 200,
        };

        assert!(change.new_entry.is_none());
        assert_eq!(change.old_entry_size_bytes, 200);
    }

    #[test]
    fn test_ledger_entry_change_debug() {
        let change = LedgerEntryChange {
            key: test_ledger_key(),
            new_entry: None,
            ttl_change: None,
            old_entry_size_bytes: 0,
        };
        let debug_str = format!("{:?}", change);
        assert!(debug_str.contains("LedgerEntryChange"));
    }

    // === LiveBucketListRestore tests ===

    #[test]
    fn test_live_bucket_list_restore_struct() {
        let restore = LiveBucketListRestore {
            key: test_ledger_key(),
            entry: test_ledger_entry(),
            ttl_key: test_ledger_key(),
            ttl_entry: test_ledger_entry(),
        };

        assert_eq!(restore.entry.last_modified_ledger_seq, 100);
        assert_eq!(restore.ttl_entry.last_modified_ledger_seq, 100);
    }

    #[test]
    fn test_live_bucket_list_restore_debug() {
        let restore = LiveBucketListRestore {
            key: test_ledger_key(),
            entry: test_ledger_entry(),
            ttl_key: test_ledger_key(),
            ttl_entry: test_ledger_entry(),
        };
        let debug_str = format!("{:?}", restore);
        assert!(debug_str.contains("LiveBucketListRestore"));
    }

    // === EncodedContractEvent tests ===

    #[test]
    fn test_encoded_contract_event_success() {
        let event = EncodedContractEvent {
            encoded_event: vec![1, 2, 3, 4],
            in_successful_call: true,
        };

        assert_eq!(event.encoded_event, vec![1, 2, 3, 4]);
        assert!(event.in_successful_call);
    }

    #[test]
    fn test_encoded_contract_event_failure() {
        let event = EncodedContractEvent {
            encoded_event: vec![5, 6, 7],
            in_successful_call: false,
        };

        assert_eq!(event.encoded_event, vec![5, 6, 7]);
        assert!(!event.in_successful_call);
    }

    #[test]
    fn test_encoded_contract_event_empty() {
        let event = EncodedContractEvent {
            encoded_event: vec![],
            in_successful_call: true,
        };

        assert!(event.encoded_event.is_empty());
    }

    #[test]
    fn test_encoded_contract_event_debug() {
        let event = EncodedContractEvent {
            encoded_event: vec![1, 2],
            in_successful_call: true,
        };
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("EncodedContractEvent"));
        assert!(debug_str.contains("true"));
    }

    // === InvokeHostFunctionOutput tests ===

    #[test]
    fn test_invoke_host_function_output_basic() {
        let output = InvokeHostFunctionOutput {
            return_value: ScVal::I32(42),
            ledger_changes: vec![],
            contract_events: vec![],
            encoded_contract_events: vec![],
            cpu_insns: 1000,
            mem_bytes: 2000,
            live_bucket_list_restores: vec![],
        };

        assert_eq!(output.cpu_insns, 1000);
        assert_eq!(output.mem_bytes, 2000);
        assert!(output.ledger_changes.is_empty());
    }

    #[test]
    fn test_invoke_host_function_output_with_changes() {
        let output = InvokeHostFunctionOutput {
            return_value: ScVal::Void,
            ledger_changes: vec![LedgerEntryChange {
                key: test_ledger_key(),
                new_entry: Some(test_ledger_entry()),
                ttl_change: None,
                old_entry_size_bytes: 0,
            }],
            contract_events: vec![],
            encoded_contract_events: vec![],
            cpu_insns: 500,
            mem_bytes: 1000,
            live_bucket_list_restores: vec![],
        };

        assert_eq!(output.ledger_changes.len(), 1);
        assert!(output.ledger_changes[0].new_entry.is_some());
    }

    #[test]
    fn test_invoke_host_function_output_with_restores() {
        let output = InvokeHostFunctionOutput {
            return_value: ScVal::Void,
            ledger_changes: vec![],
            contract_events: vec![],
            encoded_contract_events: vec![],
            cpu_insns: 0,
            mem_bytes: 0,
            live_bucket_list_restores: vec![LiveBucketListRestore {
                key: test_ledger_key(),
                entry: test_ledger_entry(),
                ttl_key: test_ledger_key(),
                ttl_entry: test_ledger_entry(),
            }],
        };

        assert_eq!(output.live_bucket_list_restores.len(), 1);
    }

    #[test]
    fn test_invoke_host_function_output_debug() {
        let output = InvokeHostFunctionOutput {
            return_value: ScVal::Void,
            ledger_changes: vec![],
            contract_events: vec![],
            encoded_contract_events: vec![],
            cpu_insns: 0,
            mem_bytes: 0,
            live_bucket_list_restores: vec![],
        };
        let debug_str = format!("{:?}", output);
        assert!(debug_str.contains("InvokeHostFunctionOutput"));
    }
}
