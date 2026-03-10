//! Shared types for protocol-versioned host implementations.

use stellar_xdr::curr::{LedgerEntry, LedgerKey};

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

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        ContractDataDurability, ContractDataEntry, ContractId, ExtensionPoint, Hash,
        LedgerEntryData, LedgerEntryExt, LedgerKeyContractData, ScAddress, ScVal,
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
}
