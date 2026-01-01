//! Ledger metadata normalization utilities.

use crate::Hash256;
use stellar_xdr::curr::{
    LedgerCloseMeta, LedgerEntry, LedgerEntryChange, LedgerEntryChanges, LedgerEntryData,
    LedgerKey, LedgerKeyAccount, LedgerKeyClaimableBalance, LedgerKeyContractCode,
    LedgerKeyContractData, LedgerKeyData, LedgerKeyLiquidityPool, LedgerKeyOffer,
    LedgerKeyTrustLine, LedgerKeyTtl, Limits, TransactionMeta, WriteXdr,
};

fn ledger_entry_key(entry: &LedgerEntry) -> LedgerKey {
    match &entry.data {
        LedgerEntryData::Account(account) => LedgerKey::Account(LedgerKeyAccount {
            account_id: account.account_id.clone(),
        }),
        LedgerEntryData::Trustline(trustline) => LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustline.account_id.clone(),
            asset: trustline.asset.clone(),
        }),
        LedgerEntryData::Offer(offer) => LedgerKey::Offer(LedgerKeyOffer {
            seller_id: offer.seller_id.clone(),
            offer_id: offer.offer_id,
        }),
        LedgerEntryData::Data(data) => LedgerKey::Data(LedgerKeyData {
            account_id: data.account_id.clone(),
            data_name: data.data_name.clone(),
        }),
        LedgerEntryData::ClaimableBalance(cb) => {
            LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
                balance_id: cb.balance_id.clone(),
            })
        }
        LedgerEntryData::LiquidityPool(pool) => LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: pool.liquidity_pool_id.clone(),
        }),
        LedgerEntryData::ContractData(data) => LedgerKey::ContractData(LedgerKeyContractData {
            contract: data.contract.clone(),
            key: data.key.clone(),
            durability: data.durability.clone(),
        }),
        LedgerEntryData::ContractCode(code) => LedgerKey::ContractCode(LedgerKeyContractCode {
            hash: code.hash.clone(),
        }),
        LedgerEntryData::ConfigSetting(setting) => {
            LedgerKey::ConfigSetting(stellar_xdr::curr::LedgerKeyConfigSetting {
                config_setting_id: setting.discriminant(),
            })
        }
        LedgerEntryData::Ttl(ttl) => LedgerKey::Ttl(LedgerKeyTtl {
            key_hash: ttl.key_hash.clone(),
        }),
    }
}

fn change_key(change: &LedgerEntryChange) -> LedgerKey {
    match change {
        LedgerEntryChange::State(entry) => ledger_entry_key(entry),
        LedgerEntryChange::Created(entry) => ledger_entry_key(entry),
        LedgerEntryChange::Updated(entry) => ledger_entry_key(entry),
        LedgerEntryChange::Removed(key) => key.clone(),
        LedgerEntryChange::Restored(entry) => ledger_entry_key(entry),
    }
}

fn change_type_order(change: &LedgerEntryChange) -> u8 {
    match change {
        LedgerEntryChange::State(_) => 0,
        LedgerEntryChange::Created(_) => 1,
        LedgerEntryChange::Updated(_) => 2,
        LedgerEntryChange::Removed(_) => 3,
        LedgerEntryChange::Restored(_) => 4,
    }
}

fn sort_changes(changes: &mut LedgerEntryChanges) -> Result<(), stellar_xdr::curr::Error> {
    let mut entries: Vec<(Vec<u8>, u8, [u8; 32], LedgerEntryChange)> = changes
        .0
        .iter()
        .cloned()
        .map(|change| {
            let key = change_key(&change);
            let key_bytes = key.to_xdr(Limits::none()).unwrap_or_default();
            let change_hash = Hash256::hash_xdr(&change)
                .map(|hash| hash.0)
                .unwrap_or([0u8; 32]);
            let order = change_type_order(&change);
            (key_bytes, order, change_hash, change)
        })
        .collect();

    entries.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| a.2.cmp(&b.2))
    });

    let sorted: Vec<LedgerEntryChange> = entries.into_iter().map(|(_, _, _, c)| c).collect();
    changes.0 = sorted.try_into().unwrap_or_default();
    Ok(())
}

fn normalize_ops_v0(ops: &mut stellar_xdr::curr::VecM<stellar_xdr::curr::OperationMeta>) {
    for op in ops.iter_mut() {
        let _ = sort_changes(&mut op.changes);
    }
}

fn normalize_ops_v2(ops: &mut stellar_xdr::curr::VecM<stellar_xdr::curr::OperationMetaV2>) {
    for op in ops.iter_mut() {
        let _ = sort_changes(&mut op.changes);
    }
}

/// Normalize transaction meta for deterministic hashing.
pub fn normalize_transaction_meta(
    meta: &mut TransactionMeta,
) -> Result<(), stellar_xdr::curr::Error> {
    match meta {
        TransactionMeta::V0(ops) => {
            normalize_ops_v0(ops);
        }
        TransactionMeta::V1(v1) => {
            sort_changes(&mut v1.tx_changes)?;
            normalize_ops_v0(&mut v1.operations);
        }
        TransactionMeta::V2(v2) => {
            sort_changes(&mut v2.tx_changes_before)?;
            sort_changes(&mut v2.tx_changes_after)?;
            normalize_ops_v0(&mut v2.operations);
        }
        TransactionMeta::V3(v3) => {
            sort_changes(&mut v3.tx_changes_before)?;
            sort_changes(&mut v3.tx_changes_after)?;
            normalize_ops_v0(&mut v3.operations);
        }
        TransactionMeta::V4(v4) => {
            sort_changes(&mut v4.tx_changes_before)?;
            sort_changes(&mut v4.tx_changes_after)?;
            normalize_ops_v2(&mut v4.operations);
        }
    }
    Ok(())
}

/// Normalize ledger close meta for deterministic hashing.
pub fn normalize_ledger_close_meta(
    meta: &mut LedgerCloseMeta,
) -> Result<(), stellar_xdr::curr::Error> {
    match meta {
        LedgerCloseMeta::V0(v0) => {
            for upgrade in v0.upgrades_processing.iter_mut() {
                sort_changes(&mut upgrade.changes)?;
            }
            for tx in v0.tx_processing.iter_mut() {
                sort_changes(&mut tx.fee_processing)?;
                normalize_transaction_meta(&mut tx.tx_apply_processing)?;
            }
        }
        LedgerCloseMeta::V1(v1) => {
            for upgrade in v1.upgrades_processing.iter_mut() {
                sort_changes(&mut upgrade.changes)?;
            }
            for tx in v1.tx_processing.iter_mut() {
                sort_changes(&mut tx.fee_processing)?;
                normalize_transaction_meta(&mut tx.tx_apply_processing)?;
            }
        }
        LedgerCloseMeta::V2(v2) => {
            for upgrade in v2.upgrades_processing.iter_mut() {
                sort_changes(&mut upgrade.changes)?;
            }
            for tx in v2.tx_processing.iter_mut() {
                sort_changes(&mut tx.fee_processing)?;
                normalize_transaction_meta(&mut tx.tx_apply_processing)?;
            }
        }
    }
    Ok(())
}
