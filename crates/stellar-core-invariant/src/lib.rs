//! Invariant framework for rs-stellar-core.

use stellar_core_common::Hash256;
use std::collections::HashMap;
use stellar_xdr::curr::{AccountId, LedgerEntry, LedgerEntryData, LedgerHeader};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InvariantError {
    #[error("invariant {name} failed: {details}")]
    Violated { name: String, details: String },
}

#[derive(Debug, Clone)]
pub enum LedgerEntryChange {
    Created { current: LedgerEntry },
    Updated { previous: LedgerEntry, current: LedgerEntry },
    Deleted { previous: LedgerEntry },
}

impl LedgerEntryChange {
    pub fn current_entry(&self) -> Option<&LedgerEntry> {
        match self {
            LedgerEntryChange::Created { current } => Some(current),
            LedgerEntryChange::Updated { current, .. } => Some(current),
            LedgerEntryChange::Deleted { .. } => None,
        }
    }

    pub fn previous_entry(&self) -> Option<&LedgerEntry> {
        match self {
            LedgerEntryChange::Created { .. } => None,
            LedgerEntryChange::Updated { previous, .. } => Some(previous),
            LedgerEntryChange::Deleted { previous } => Some(previous),
        }
    }
}

/// Context passed to invariants.
pub struct InvariantContext<'a> {
    pub prev_header: &'a LedgerHeader,
    pub curr_header: &'a LedgerHeader,
    pub bucket_list_hash: Hash256,
    pub fee_pool_delta: i64,
    pub total_coins_delta: i64,
    pub changes: &'a [LedgerEntryChange],
}

pub trait Invariant: Send + Sync {
    fn name(&self) -> &str;
    fn check(&self, ctx: &InvariantContext) -> Result<(), InvariantError>;
}

pub struct InvariantManager {
    invariants: Vec<Box<dyn Invariant>>,
}

impl InvariantManager {
    pub fn new() -> Self {
        Self { invariants: Vec::new() }
    }

    pub fn add<I: Invariant + 'static>(&mut self, invariant: I) {
        self.invariants.push(Box::new(invariant));
    }

    pub fn check_all(&self, ctx: &InvariantContext) -> Result<(), InvariantError> {
        for inv in &self.invariants {
            inv.check(ctx)?;
        }
        Ok(())
    }
}

/// Invariant: ledger sequence increments by 1.
pub struct LedgerSeqIncrement;

impl Invariant for LedgerSeqIncrement {
    fn name(&self) -> &str {
        "LedgerSeqIncrement"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<(), InvariantError> {
        if ctx.curr_header.ledger_seq != ctx.prev_header.ledger_seq + 1 {
            return Err(InvariantError::Violated {
                name: self.name().to_string(),
                details: format!(
                    "expected seq {}, got {}",
                    ctx.prev_header.ledger_seq + 1,
                    ctx.curr_header.ledger_seq
                ),
            });
        }
        Ok(())
    }
}

/// Invariant: bucket list hash matches header field.
pub struct BucketListHashMatchesHeader;

impl Invariant for BucketListHashMatchesHeader {
    fn name(&self) -> &str {
        "BucketListHashMatchesHeader"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<(), InvariantError> {
        let header_hash = Hash256::from(ctx.curr_header.bucket_list_hash.0);
        if header_hash != ctx.bucket_list_hash {
            return Err(InvariantError::Violated {
                name: self.name().to_string(),
                details: "bucket list hash mismatch".to_string(),
            });
        }
        Ok(())
    }
}

/// Invariant: ledger total coins and fee pool follow the recorded deltas.
pub struct ConservationOfLumens;

impl Invariant for ConservationOfLumens {
    fn name(&self) -> &str {
        "ConservationOfLumens"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<(), InvariantError> {
        let expected_total = ctx
            .prev_header
            .total_coins
            .checked_add(ctx.total_coins_delta)
            .ok_or_else(|| InvariantError::Violated {
                name: self.name().to_string(),
                details: "total coins overflow".to_string(),
            })?;
        if ctx.curr_header.total_coins != expected_total {
            return Err(InvariantError::Violated {
                name: self.name().to_string(),
                details: format!(
                    "total_coins mismatch: expected {}, got {}",
                    expected_total, ctx.curr_header.total_coins
                ),
            });
        }

        let expected_fee_pool = ctx
            .prev_header
            .fee_pool
            .checked_add(ctx.fee_pool_delta)
            .ok_or_else(|| InvariantError::Violated {
                name: self.name().to_string(),
                details: "fee pool overflow".to_string(),
            })?;
        if ctx.curr_header.fee_pool != expected_fee_pool {
            return Err(InvariantError::Violated {
                name: self.name().to_string(),
                details: format!(
                    "fee_pool mismatch: expected {}, got {}",
                    expected_fee_pool, ctx.curr_header.fee_pool
                ),
            });
        }

        Ok(())
    }
}

/// Invariant: basic ledger entry sanity checks.
pub struct LedgerEntryIsValid;

impl Invariant for LedgerEntryIsValid {
    fn name(&self) -> &str {
        "LedgerEntryIsValid"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<(), InvariantError> {
        let protocol = ctx.curr_header.ledger_version;
        if ctx.curr_header.ledger_seq > i32::MAX as u32 {
            return Err(InvariantError::Violated {
                name: self.name().to_string(),
                details: "ledger_seq exceeds i32::MAX".to_string(),
            });
        }
        for change in ctx.changes {
            let Some(entry) = change.current_entry() else {
                continue;
            };
            let previous = change.previous_entry();
            if protocol < 14 && matches!(entry.ext, stellar_xdr::curr::LedgerEntryExt::V1(_)) {
                return Err(InvariantError::Violated {
                    name: self.name().to_string(),
                    details: "ledger entry has v1 extension before protocol 14".to_string(),
                });
            }
            match &entry.data {
                LedgerEntryData::Account(account) => {
                    if account.balance < 0 {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "account balance negative".to_string(),
                        });
                    }
                    if account.seq_num.0 < 0 {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "account seq_num negative".to_string(),
                        });
                    }
                    if account.num_sub_entries > i32::MAX as u32 {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "account num_sub_entries exceeds i32::MAX".to_string(),
                        });
                    }
                    if !account_flags_valid(account.flags, protocol) {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "account flags are invalid".to_string(),
                        });
                    }
                    if !string32_is_valid(&account.home_domain) {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "account home_domain is invalid".to_string(),
                        });
                    }
                    if let stellar_xdr::curr::AccountEntryExt::V1(ext) = &account.ext {
                        if protocol < 14 {
                            return Err(InvariantError::Violated {
                                name: self.name().to_string(),
                                details: "account has v1 extension before protocol 14".to_string(),
                            });
                        }
                        if let stellar_xdr::curr::AccountEntryExtensionV1Ext::V2(v2) = &ext.ext {
                            if protocol < 18 {
                                return Err(InvariantError::Violated {
                                    name: self.name().to_string(),
                                    details: "account has v2 extension before protocol 18"
                                        .to_string(),
                                });
                            }
                            if account.signers.len() != v2.signer_sponsoring_i_ds.len() {
                                return Err(InvariantError::Violated {
                                    name: self.name().to_string(),
                                    details: "account signers not paired with sponsoring ids"
                                        .to_string(),
                                });
                            }
                            if protocol >= 18
                                && account.num_sub_entries > u32::MAX - v2.num_sponsoring
                            {
                                return Err(InvariantError::Violated {
                                    name: self.name().to_string(),
                                    details: "account num_sub_entries + num_sponsoring overflow"
                                        .to_string(),
                                });
                            }
                        }
                    }
                    if !signers_strictly_increasing(&account.signers) {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "account signers not strictly increasing".to_string(),
                        });
                    }
                    if protocol >= 10
                        && account
                            .signers
                            .iter()
                            .any(|s| s.weight == 0 || s.weight > u8::MAX as u32)
                    {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "account signer weight is invalid".to_string(),
                        });
                    }
                }
                LedgerEntryData::Trustline(trust) => {
                    if matches!(trust.asset, stellar_xdr::curr::TrustLineAsset::Native) {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "trustline asset is native".to_string(),
                        });
                    }
                    if !trustline_asset_valid(&trust.asset, protocol) {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "trustline asset is invalid".to_string(),
                        });
                    }
                    if trust.limit <= 0 {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "trustline limit is not positive".to_string(),
                        });
                    }
                    if trust.balance < 0 || trust.balance > trust.limit {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "trustline balance out of range".to_string(),
                        });
                    }
                    if !trustline_flags_valid(trust.flags, protocol) {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "trustline flags are invalid".to_string(),
                        });
                    }
                    if let Some(prev) = previous {
                        if let LedgerEntryData::Trustline(prev_trust) = &prev.data {
                            if !trustline_clawback_enabled(prev_trust)
                                && trustline_clawback_enabled(trust)
                            {
                                return Err(InvariantError::Violated {
                                    name: self.name().to_string(),
                                    details: "trustline clawback flag was enabled".to_string(),
                                });
                            }
                        }
                    }
                    if let stellar_xdr::curr::TrustLineEntryExt::V1(v1) = &trust.ext {
                        if matches!(trust.asset, stellar_xdr::curr::TrustLineAsset::PoolShare(_))
                            && (v1.liabilities.buying != 0 || v1.liabilities.selling != 0)
                        {
                            return Err(InvariantError::Violated {
                                name: self.name().to_string(),
                                details: "pool share trustline has liabilities".to_string(),
                            });
                        }
                        if let stellar_xdr::curr::TrustLineEntryV1Ext::V2(v2) = &v1.ext {
                            if protocol < 18 {
                                return Err(InvariantError::Violated {
                                    name: self.name().to_string(),
                                    details: "trustline has v2 extension before protocol 18"
                                        .to_string(),
                                });
                            }
                            if v2.liquidity_pool_use_count < 0 {
                                return Err(InvariantError::Violated {
                                    name: self.name().to_string(),
                                    details: "trustline liquidity_pool_use_count negative"
                                        .to_string(),
                                });
                            }
                        }
                    }
                }
                LedgerEntryData::Offer(offer) => {
                    if offer.offer_id <= 0 {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "offer id is not positive".to_string(),
                        });
                    }
                    if !asset_valid(&offer.selling) {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "offer selling asset is invalid".to_string(),
                        });
                    }
                    if !asset_valid(&offer.buying) {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "offer buying asset is invalid".to_string(),
                        });
                    }
                    if offer.amount <= 0 {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "offer amount not positive".to_string(),
                        });
                    }
                    if offer.price.n <= 0 || offer.price.d <= 0 {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "offer price invalid".to_string(),
                        });
                    }
                    if (offer.flags & !(stellar_xdr::curr::MASK_OFFERENTRY_FLAGS as u32)) != 0 {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "offer flags are invalid".to_string(),
                        });
                    }
                }
                LedgerEntryData::ClaimableBalance(balance) => {
                    match &entry.ext {
                        stellar_xdr::curr::LedgerEntryExt::V1(ext) => {
                            if ext.sponsoring_id.0.is_none() {
                                return Err(InvariantError::Violated {
                                    name: self.name().to_string(),
                                    details: "claimable balance is not sponsored".to_string(),
                                });
                            }
                        }
                        _ => {
                            return Err(InvariantError::Violated {
                                name: self.name().to_string(),
                                details: "claimable balance is not sponsored".to_string(),
                            });
                        }
                    }
                    if protocol < 17
                        && matches!(
                            balance.ext,
                            stellar_xdr::curr::ClaimableBalanceEntryExt::V1(_)
                        )
                    {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "claimable balance has v1 extension before protocol 17"
                                .to_string(),
                        });
                    }
                    if !asset_valid(&balance.asset) {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "claimable balance asset is invalid".to_string(),
                        });
                    }
                    if claimable_balance_clawback_enabled(balance)
                        && matches!(balance.asset, stellar_xdr::curr::Asset::Native)
                    {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "claimable balance clawback set on native asset".to_string(),
                        });
                    }
                    if !claimable_balance_flags_valid(balance) {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "claimable balance flags are invalid".to_string(),
                        });
                    }
                    if balance.claimants.is_empty() {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "claimable balance claimants empty".to_string(),
                        });
                    }
                    if balance.amount <= 0 {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "claimable balance amount not positive".to_string(),
                        });
                    }
                    for claimant in balance.claimants.iter() {
                        let pred = match claimant {
                            stellar_xdr::curr::Claimant::ClaimantTypeV0(v0) => &v0.predicate,
                        };
                        if !validate_claim_predicate(pred, 1) {
                            return Err(InvariantError::Violated {
                                name: self.name().to_string(),
                                details: "claimable balance predicate invalid".to_string(),
                            });
                        }
                    }
                    if let Some(prev) = previous {
                        if let LedgerEntryData::ClaimableBalance(prev_balance) = &prev.data {
                            if prev_balance != balance {
                                return Err(InvariantError::Violated {
                                    name: self.name().to_string(),
                                    details: "claimable balance cannot be modified".to_string(),
                                });
                            }
                        } else {
                            return Err(InvariantError::Violated {
                                name: self.name().to_string(),
                                details: "claimable balance used to be different type".to_string(),
                            });
                        }
                    }
                }
                LedgerEntryData::LiquidityPool(_) => {
                    if !matches!(entry.ext, stellar_xdr::curr::LedgerEntryExt::V0) {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "liquidity pool is sponsored".to_string(),
                        });
                    }
                    if protocol < 18 {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "liquidity pool only valid from protocol 18".to_string(),
                        });
                    }
                    let pool = match &entry.data {
                        LedgerEntryData::LiquidityPool(pool) => pool,
                        _ => unreachable!("entry data already matched"),
                    };
                    let cp = match &pool.body {
                        stellar_xdr::curr::LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) => cp,
                    };
                    if !asset_valid(&cp.params.asset_a) {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "liquidity pool asset_a is invalid".to_string(),
                        });
                    }
                    if !asset_valid(&cp.params.asset_b) {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "liquidity pool asset_b is invalid".to_string(),
                        });
                    }
                    if !(cp.params.asset_a < cp.params.asset_b) {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "liquidity pool assets out of order".to_string(),
                        });
                    }
                    if cp.params.fee != 30 {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "liquidity pool fee is not 30".to_string(),
                        });
                    }
                    if cp.reserve_a < 0 {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "liquidity pool reserve_a negative".to_string(),
                        });
                    }
                    if cp.reserve_b < 0 {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "liquidity pool reserve_b negative".to_string(),
                        });
                    }
                    if cp.total_pool_shares < 0 {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "liquidity pool total_pool_shares negative".to_string(),
                        });
                    }
                    if cp.pool_shares_trust_line_count < 0 {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "liquidity pool trustline count negative".to_string(),
                        });
                    }
                    if let Some(prev) = previous {
                        if let LedgerEntryData::LiquidityPool(prev_pool) = &prev.data {
                            let prev_body = match &prev_pool.body {
                                stellar_xdr::curr::LiquidityPoolEntryBody::LiquidityPoolConstantProduct(
                                    prev_cp,
                                ) => prev_cp,
                            };
                            if prev_body.params != cp.params {
                                return Err(InvariantError::Violated {
                                    name: self.name().to_string(),
                                    details: "liquidity pool parameters changed".to_string(),
                                });
                            }
                        } else {
                            return Err(InvariantError::Violated {
                                name: self.name().to_string(),
                                details: "liquidity pool used to be different type".to_string(),
                            });
                        }
                    }
                }
                LedgerEntryData::ContractCode(code) => {
                    let bytes: &[u8] = code.code.as_ref();
                    let computed = Hash256::hash(bytes);
                    if code.hash.0 != *computed.as_bytes() {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "contract code hash mismatch".to_string(),
                        });
                    }
                    if let Some(prev) = previous {
                        if let LedgerEntryData::ContractCode(prev_code) = &prev.data {
                            if prev_code.hash != code.hash {
                                return Err(InvariantError::Violated {
                                    name: self.name().to_string(),
                                    details: "contract code hash modified".to_string(),
                                });
                            }
                            if prev_code.code != code.code {
                                return Err(InvariantError::Violated {
                                    name: self.name().to_string(),
                                    details: "contract code modified".to_string(),
                                });
                            }
                        } else {
                            return Err(InvariantError::Violated {
                                name: self.name().to_string(),
                                details: "contract code used to be different type".to_string(),
                            });
                        }
                    }
                }
                LedgerEntryData::Ttl(ttl) => {
                    if let Some(prev) = previous {
                        if let LedgerEntryData::Ttl(prev_ttl) = &prev.data {
                            if prev_ttl.key_hash != ttl.key_hash {
                                return Err(InvariantError::Violated {
                                    name: self.name().to_string(),
                                    details: "ttl key_hash modified".to_string(),
                                });
                            }
                            if prev_ttl.live_until_ledger_seq > ttl.live_until_ledger_seq {
                                return Err(InvariantError::Violated {
                                    name: self.name().to_string(),
                                    details: "ttl live_until_ledger_seq decreased".to_string(),
                                });
                            }
                        } else {
                            return Err(InvariantError::Violated {
                                name: self.name().to_string(),
                                details: "ttl used to be different type".to_string(),
                            });
                        }
                    }
                }
                LedgerEntryData::Data(data) => {
                    if string64_is_empty(&data.data_name) {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "data name is empty".to_string(),
                        });
                    }
                    if !string64_is_valid(&data.data_name) {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "data name is invalid".to_string(),
                        });
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }
}

/// Invariant: sponsorship counts match sponsored entries.
pub struct SponsorshipCountIsValid;

impl Invariant for SponsorshipCountIsValid {
    fn name(&self) -> &str {
        "SponsorshipCountIsValid"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<(), InvariantError> {
        let protocol = ctx.curr_header.ledger_version;
        if protocol < 14 {
            return Ok(());
        }

        let mut num_sponsoring: HashMap<AccountId, i64> = HashMap::new();
        let mut num_sponsored: HashMap<AccountId, i64> = HashMap::new();
        let mut claimable_balance_reserve = 0i64;

        for change in ctx.changes {
            update_changed_sponsorship_counts(
                change,
                &mut num_sponsoring,
                &mut num_sponsored,
                &mut claimable_balance_reserve,
            )?;
        }

        for change in ctx.changes {
            let account_entry = change
                .current_entry()
                .or_else(|| change.previous_entry());
            let account = match account_entry {
                Some(entry) => match &entry.data {
                    LedgerEntryData::Account(account) => account,
                    _ => continue,
                },
                None => continue,
            };

            let account_id = account.account_id.clone();
            let mut delta_num_sponsoring = 0i64;
            let mut delta_num_sponsored = 0i64;

            get_delta_sponsoring_and_sponsored(change.current_entry(), &mut delta_num_sponsoring, &mut delta_num_sponsored, 1)?;
            get_delta_sponsoring_and_sponsored(change.previous_entry(), &mut delta_num_sponsoring, &mut delta_num_sponsored, -1)?;

            let expected_sponsoring = *num_sponsoring.get(&account_id).unwrap_or(&0);
            if expected_sponsoring != delta_num_sponsoring {
                return Err(InvariantError::Violated {
                    name: self.name().to_string(),
                    details: format!(
                        "change in account num_sponsoring ({}) does not match change in sponsored entries ({})",
                        delta_num_sponsoring, expected_sponsoring
                    ),
                });
            }

            let expected_sponsored = *num_sponsored.get(&account_id).unwrap_or(&0);
            if expected_sponsored != delta_num_sponsored {
                return Err(InvariantError::Violated {
                    name: self.name().to_string(),
                    details: format!(
                        "change in account num_sponsored ({}) does not match change in sponsored entries ({})",
                        delta_num_sponsored, expected_sponsored
                    ),
                });
            }

            num_sponsoring.remove(&account_id);
            num_sponsored.remove(&account_id);
        }

        for (account_id, delta) in num_sponsoring {
            if delta != 0 {
                return Err(InvariantError::Violated {
                    name: self.name().to_string(),
                    details: format!(
                        "change in account {:?} num_sponsoring (0) does not match change in sponsored entries ({})",
                        account_id, delta
                    ),
                });
            }
        }

        for (account_id, delta) in num_sponsored {
            if delta != 0 {
                return Err(InvariantError::Violated {
                    name: self.name().to_string(),
                    details: format!(
                        "change in account {:?} num_sponsored (0) does not match change in sponsored entries ({})",
                        account_id, delta
                    ),
                });
            }
        }

        Ok(())
    }
}

/// Invariant: account num_sub_entries matches changes in subentries.
pub struct AccountSubEntriesCountIsValid;

impl Invariant for AccountSubEntriesCountIsValid {
    fn name(&self) -> &str {
        "AccountSubEntriesCountIsValid"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<(), InvariantError> {
        let mut subentry_changes: HashMap<AccountId, SubEntriesChange> = HashMap::new();

        for change in ctx.changes {
            update_changed_subentries(&mut subentry_changes, change)?;
        }

        for (account_id, change) in &subentry_changes {
            if change.num_sub_entries != change.calculated_sub_entries {
                return Err(InvariantError::Violated {
                    name: self.name().to_string(),
                    details: format!(
                        "change in account {:?} num_sub_entries ({}) does not match change in subentries ({})",
                        account_id, change.num_sub_entries, change.calculated_sub_entries
                    ),
                });
            }
        }

        for change in ctx.changes {
            if let Some(previous) = change.previous_entry() {
                if change.current_entry().is_some() {
                    continue;
                }
                if let LedgerEntryData::Account(account) = &previous.data {
                    let account_id = account.account_id.clone();
                    if let Some(change) = subentry_changes.get(&account_id) {
                        let num_signers = account.num_sub_entries as i32
                            + change.num_sub_entries
                            - change.signers;
                        if num_signers != account.signers.len() as i32 {
                            let other_subentries =
                                account.num_sub_entries as i32 - account.signers.len() as i32;
                            return Err(InvariantError::Violated {
                                name: self.name().to_string(),
                                details: format!(
                                    "deleted account {:?} has {} subentries other than signers",
                                    account_id, other_subentries
                                ),
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Invariant: constant-product liquidity pools do not decrease k.
pub struct ConstantProductInvariant;

impl Invariant for ConstantProductInvariant {
    fn name(&self) -> &str {
        "ConstantProductInvariant"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<(), InvariantError> {
        for change in ctx.changes {
            let (previous, current) = match (change.previous_entry(), change.current_entry()) {
                (Some(previous), Some(current)) => (previous, current),
                _ => continue,
            };

            let (prev_pool, curr_pool) = match (&previous.data, &current.data) {
                (
                    LedgerEntryData::LiquidityPool(prev_pool),
                    LedgerEntryData::LiquidityPool(curr_pool),
                ) => (prev_pool, curr_pool),
                _ => continue,
            };

            let prev_cp = match &prev_pool.body {
                stellar_xdr::curr::LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) => cp,
            };
            let curr_cp = match &curr_pool.body {
                stellar_xdr::curr::LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) => cp,
            };

            if curr_cp.reserve_a < 0
                || curr_cp.reserve_b < 0
                || prev_cp.reserve_a < 0
                || prev_cp.reserve_b < 0
            {
                return Err(InvariantError::Violated {
                    name: self.name().to_string(),
                    details: "negative liquidity pool reserves".to_string(),
                });
            }

            let prev_product = (prev_cp.reserve_a as u128) * (prev_cp.reserve_b as u128);
            let curr_product = (curr_cp.reserve_a as u128) * (curr_cp.reserve_b as u128);

            if curr_product < prev_product {
                if curr_cp.total_pool_shares < prev_cp.total_pool_shares {
                    continue;
                }
                return Err(InvariantError::Violated {
                    name: self.name().to_string(),
                    details: format!(
                        "constant product invariant violated: crA={}, crB={}, prA={}, prB={}",
                        curr_cp.reserve_a, curr_cp.reserve_b, prev_cp.reserve_a, prev_cp.reserve_b
                    ),
                });
            }
        }

        Ok(())
    }
}

fn update_changed_sponsorship_counts(
    change: &LedgerEntryChange,
    num_sponsoring: &mut HashMap<AccountId, i64>,
    num_sponsored: &mut HashMap<AccountId, i64>,
    claimable_balance_reserve: &mut i64,
) -> Result<(), InvariantError> {
    if let Some(entry) = change.current_entry() {
        update_sponsorship_counters(
            entry,
            num_sponsoring,
            num_sponsored,
            claimable_balance_reserve,
            1,
        )?;
    }
    if let Some(entry) = change.previous_entry() {
        update_sponsorship_counters(
            entry,
            num_sponsoring,
            num_sponsored,
            claimable_balance_reserve,
            -1,
        )?;
    }
    Ok(())
}

fn update_sponsorship_counters(
    entry: &LedgerEntry,
    num_sponsoring: &mut HashMap<AccountId, i64>,
    num_sponsored: &mut HashMap<AccountId, i64>,
    claimable_balance_reserve: &mut i64,
    sign: i64,
) -> Result<(), InvariantError> {
    if let Some(sponsor) = entry_sponsoring_id(entry) {
        let mult = sign
            * get_sponsorship_multiplier(entry).ok_or_else(|| InvariantError::Violated {
                name: "SponsorshipCountIsValid".to_string(),
                details: "sponsored entry type is not supported".to_string(),
            })?;
        num_sponsoring
            .entry(sponsor.clone())
            .and_modify(|value| *value += mult)
            .or_insert(mult);

        if matches!(entry.data, LedgerEntryData::ClaimableBalance(_)) {
            *claimable_balance_reserve += mult;
        } else {
            let account_id =
                entry_account_id(entry).ok_or_else(|| InvariantError::Violated {
                    name: "SponsorshipCountIsValid".to_string(),
                    details: "sponsored entry missing account id".to_string(),
                })?;
            num_sponsored
                .entry(account_id)
                .and_modify(|value| *value += mult)
                .or_insert(mult);
        }
    }

    if let LedgerEntryData::Account(account) = &entry.data {
        if let Some(v2) = account_entry_ext_v2(account) {
            for sponsoring in v2.signer_sponsoring_i_ds.iter() {
                if let Some(account_id) = sponsoring.0.as_ref() {
                    num_sponsoring
                        .entry(account_id.clone())
                        .and_modify(|value| *value += sign)
                        .or_insert(sign);
                    num_sponsored
                        .entry(account.account_id.clone())
                        .and_modify(|value| *value += sign)
                        .or_insert(sign);
                }
            }
        }
    }

    Ok(())
}

fn get_delta_sponsoring_and_sponsored(
    entry: Option<&LedgerEntry>,
    num_sponsoring: &mut i64,
    num_sponsored: &mut i64,
    sign: i64,
) -> Result<(), InvariantError> {
    let Some(entry) = entry else {
        return Ok(());
    };
    let LedgerEntryData::Account(account) = &entry.data else {
        return Ok(());
    };
    if let Some(v2) = account_entry_ext_v2(account) {
        *num_sponsoring += sign * i64::from(v2.num_sponsoring);
        *num_sponsored += sign * i64::from(v2.num_sponsored);
    }
    Ok(())
}

fn entry_sponsoring_id(entry: &LedgerEntry) -> Option<&AccountId> {
    match &entry.ext {
        stellar_xdr::curr::LedgerEntryExt::V1(ext) => ext.sponsoring_id.0.as_ref(),
        _ => None,
    }
}

fn account_entry_ext_v2(
    account: &stellar_xdr::curr::AccountEntry,
) -> Option<&stellar_xdr::curr::AccountEntryExtensionV2> {
    match &account.ext {
        stellar_xdr::curr::AccountEntryExt::V1(ext) => match &ext.ext {
            stellar_xdr::curr::AccountEntryExtensionV1Ext::V2(v2) => Some(v2),
            _ => None,
        },
        _ => None,
    }
}

fn get_sponsorship_multiplier(entry: &LedgerEntry) -> Option<i64> {
    match &entry.data {
        LedgerEntryData::Account(_) => Some(2),
        LedgerEntryData::Trustline(trust) => match trust.asset {
            stellar_xdr::curr::TrustLineAsset::PoolShare(_) => Some(2),
            _ => Some(1),
        },
        LedgerEntryData::Offer(_) | LedgerEntryData::Data(_) => Some(1),
        LedgerEntryData::ClaimableBalance(balance) => {
            Some(balance.claimants.len() as i64)
        }
        LedgerEntryData::ContractData(_)
        | LedgerEntryData::ContractCode(_)
        | LedgerEntryData::ConfigSetting(_)
        | LedgerEntryData::Ttl(_)
        | LedgerEntryData::LiquidityPool(_) => None,
    }
}

fn entry_account_id(entry: &LedgerEntry) -> Option<AccountId> {
    match &entry.data {
        LedgerEntryData::Account(account) => Some(account.account_id.clone()),
        LedgerEntryData::Trustline(trustline) => Some(trustline.account_id.clone()),
        LedgerEntryData::Offer(offer) => Some(offer.seller_id.clone()),
        LedgerEntryData::Data(data) => Some(data.account_id.clone()),
        _ => None,
    }
}

#[derive(Debug, Default)]
struct SubEntriesChange {
    num_sub_entries: i32,
    signers: i32,
    calculated_sub_entries: i32,
}

fn update_changed_subentries(
    subentries: &mut HashMap<AccountId, SubEntriesChange>,
    change: &LedgerEntryChange,
) -> Result<(), InvariantError> {
    let current = change.current_entry();
    let previous = change.previous_entry();
    let valid = current.or(previous).ok_or_else(|| InvariantError::Violated {
        name: "AccountSubEntriesCountIsValid".to_string(),
        details: "missing entry for subentry accounting".to_string(),
    })?;

    match &valid.data {
        LedgerEntryData::Account(_) => {
            let account_id = entry_account_id(valid).ok_or_else(|| InvariantError::Violated {
                name: "AccountSubEntriesCountIsValid".to_string(),
                details: "account entry missing account id".to_string(),
            })?;
            let change_entry = subentries.entry(account_id).or_default();
            change_entry.num_sub_entries = current
                .and_then(|entry| match &entry.data {
                    LedgerEntryData::Account(account) => Some(account.num_sub_entries as i32),
                    _ => None,
                })
                .unwrap_or(0)
                - previous
                    .and_then(|entry| match &entry.data {
                        LedgerEntryData::Account(account) => Some(account.num_sub_entries as i32),
                        _ => None,
                    })
                    .unwrap_or(0);
            change_entry.signers = current
                .and_then(|entry| match &entry.data {
                    LedgerEntryData::Account(account) => Some(account.signers.len() as i32),
                    _ => None,
                })
                .unwrap_or(0)
                - previous
                    .and_then(|entry| match &entry.data {
                        LedgerEntryData::Account(account) => Some(account.signers.len() as i32),
                        _ => None,
                    })
                    .unwrap_or(0);
            change_entry.calculated_sub_entries += change_entry.signers;
        }
        LedgerEntryData::Trustline(trustline) => {
            let account_id = trustline.account_id.clone();
            let change_entry = subentries.entry(account_id).or_default();
            change_entry.calculated_sub_entries += calculate_subentry_delta(current, previous);
        }
        LedgerEntryData::Offer(offer) => {
            let account_id = offer.seller_id.clone();
            let change_entry = subentries.entry(account_id).or_default();
            change_entry.calculated_sub_entries += calculate_subentry_delta(current, previous);
        }
        LedgerEntryData::Data(data) => {
            let account_id = data.account_id.clone();
            let change_entry = subentries.entry(account_id).or_default();
            change_entry.calculated_sub_entries += calculate_subentry_delta(current, previous);
        }
        LedgerEntryData::ClaimableBalance(_)
        | LedgerEntryData::LiquidityPool(_)
        | LedgerEntryData::ContractData(_)
        | LedgerEntryData::ContractCode(_)
        | LedgerEntryData::ConfigSetting(_)
        | LedgerEntryData::Ttl(_) => {}
    }

    Ok(())
}

fn calculate_subentry_delta(
    current: Option<&LedgerEntry>,
    previous: Option<&LedgerEntry>,
) -> i32 {
    let mut delta = 0;
    if let Some(entry) = current {
        delta += if is_pool_share_trustline(entry) { 2 } else { 1 };
    }
    if let Some(entry) = previous {
        delta -= if is_pool_share_trustline(entry) { 2 } else { 1 };
    }
    delta
}

fn is_pool_share_trustline(entry: &LedgerEntry) -> bool {
    matches!(
        entry.data,
        LedgerEntryData::Trustline(stellar_xdr::curr::TrustLineEntry {
            asset: stellar_xdr::curr::TrustLineAsset::PoolShare(_),
            ..
        })
    )
}

fn signers_strictly_increasing(
    signers: &stellar_xdr::curr::VecM<stellar_xdr::curr::Signer, 20>,
) -> bool {
    let mut prev = None;
    for signer in signers.iter() {
        if let Some(prev_key) = prev {
            if signer.key <= prev_key {
                return false;
            }
        }
        prev = Some(signer.key.clone());
    }
    true
}

fn is_ascii_alphanumeric(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

fn asset_code_valid(code: &[u8], min_non_zero: usize) -> bool {
    let mut zeros = false;
    let mut non_zero = 0;
    for &b in code {
        if b == 0 {
            zeros = true;
            continue;
        }
        if zeros {
            return false;
        }
        if b > 0x7f || !is_ascii_alphanumeric(b) {
            return false;
        }
        non_zero += 1;
    }
    non_zero >= min_non_zero
}

fn asset_valid(asset: &stellar_xdr::curr::Asset) -> bool {
    match asset {
        stellar_xdr::curr::Asset::Native => true,
        stellar_xdr::curr::Asset::CreditAlphanum4(alpha) => {
            asset_code_valid(&alpha.asset_code.0, 1)
        }
        stellar_xdr::curr::Asset::CreditAlphanum12(alpha) => {
            asset_code_valid(&alpha.asset_code.0, 5)
        }
    }
}

fn trustline_asset_valid(asset: &stellar_xdr::curr::TrustLineAsset, protocol: u32) -> bool {
    match asset {
        stellar_xdr::curr::TrustLineAsset::Native => false,
        stellar_xdr::curr::TrustLineAsset::CreditAlphanum4(alpha) => {
            asset_code_valid(&alpha.asset_code.0, 1)
        }
        stellar_xdr::curr::TrustLineAsset::CreditAlphanum12(alpha) => {
            asset_code_valid(&alpha.asset_code.0, 5)
        }
        stellar_xdr::curr::TrustLineAsset::PoolShare(_) => protocol >= 18,
    }
}

fn account_flags_valid(flags: u32, protocol: u32) -> bool {
    let mask = if protocol < 17 {
        stellar_xdr::curr::MASK_ACCOUNT_FLAGS
    } else {
        stellar_xdr::curr::MASK_ACCOUNT_FLAGS_V17
    };
    if (flags & !(mask as u32)) != 0 {
        return false;
    }
    if protocol >= 17 {
        let clawback = stellar_xdr::curr::AccountFlags::ClawbackEnabledFlag as u32;
        let revocable = stellar_xdr::curr::AccountFlags::RevocableFlag as u32;
        if (flags & clawback != 0) && (flags & revocable == 0) {
            return false;
        }
    }
    true
}

fn trustline_flags_valid(flags: u32, protocol: u32) -> bool {
    let mask = if protocol < 13 {
        stellar_xdr::curr::MASK_TRUSTLINE_FLAGS
    } else if protocol < 17 {
        stellar_xdr::curr::MASK_TRUSTLINE_FLAGS_V13
    } else {
        stellar_xdr::curr::MASK_TRUSTLINE_FLAGS_V17
    };
    if (flags & !(mask as u32)) != 0 {
        return false;
    }
    if protocol >= 13 {
        let auth = stellar_xdr::curr::TrustLineFlags::AuthorizedFlag as u32;
        let auth_liabilities =
            stellar_xdr::curr::TrustLineFlags::AuthorizedToMaintainLiabilitiesFlag as u32;
        if (flags & (auth | auth_liabilities)) == (auth | auth_liabilities) {
            return false;
        }
    }
    true
}

fn trustline_clawback_enabled(trust: &stellar_xdr::curr::TrustLineEntry) -> bool {
    let flag = stellar_xdr::curr::TrustLineFlags::TrustlineClawbackEnabledFlag as u32;
    (trust.flags & flag) != 0
}

fn claimable_balance_clawback_enabled(entry: &stellar_xdr::curr::ClaimableBalanceEntry) -> bool {
    match &entry.ext {
        stellar_xdr::curr::ClaimableBalanceEntryExt::V1(ext) => {
            let flag =
                stellar_xdr::curr::ClaimableBalanceFlags::ClaimableBalanceClawbackEnabledFlag
                    as u32;
            (ext.flags & flag) != 0
        }
        _ => false,
    }
}

fn claimable_balance_flags_valid(entry: &stellar_xdr::curr::ClaimableBalanceEntry) -> bool {
    match &entry.ext {
        stellar_xdr::curr::ClaimableBalanceEntryExt::V1(ext) => {
            ext.flags == stellar_xdr::curr::MASK_CLAIMABLE_BALANCE_FLAGS as u32
        }
        _ => true,
    }
}

fn validate_claim_predicate(pred: &stellar_xdr::curr::ClaimPredicate, depth: u32) -> bool {
    if depth > 4 {
        return false;
    }
    match pred {
        stellar_xdr::curr::ClaimPredicate::Unconditional => true,
        stellar_xdr::curr::ClaimPredicate::And(preds) => {
            preds.len() == 2
                && validate_claim_predicate(&preds[0], depth + 1)
                && validate_claim_predicate(&preds[1], depth + 1)
        }
        stellar_xdr::curr::ClaimPredicate::Or(preds) => {
            preds.len() == 2
                && validate_claim_predicate(&preds[0], depth + 1)
                && validate_claim_predicate(&preds[1], depth + 1)
        }
        stellar_xdr::curr::ClaimPredicate::Not(pred) => pred
            .as_ref()
            .map(|inner| validate_claim_predicate(inner, depth + 1))
            .unwrap_or(false),
        stellar_xdr::curr::ClaimPredicate::BeforeAbsoluteTime(time) => *time >= 0,
        _ => false,
    }
}

fn string_is_valid(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte > 0x1f && *byte < 0x7f)
}

fn string32_is_valid(name: &stellar_xdr::curr::String32) -> bool {
    let inner: &stellar_xdr::curr::StringM<32> = name.as_ref();
    let bytes: &[u8] = inner.as_ref();
    string_is_valid(bytes)
}

fn string64_is_empty(name: &stellar_xdr::curr::String64) -> bool {
    let inner: &stellar_xdr::curr::StringM<64> = name.as_ref();
    let bytes: &[u8] = inner.as_ref();
    bytes.is_empty()
}

fn string64_is_valid(name: &stellar_xdr::curr::String64) -> bool {
    let inner: &stellar_xdr::curr::StringM<64> = name.as_ref();
    let bytes: &[u8] = inner.as_ref();
    string_is_valid(bytes)
}

/// Invariant: ledger close time does not move backwards.
pub struct CloseTimeNondecreasing;

impl Invariant for CloseTimeNondecreasing {
    fn name(&self) -> &str {
        "CloseTimeNondecreasing"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<(), InvariantError> {
        let prev = ctx.prev_header.scp_value.close_time.0;
        let curr = ctx.curr_header.scp_value.close_time.0;
        if curr < prev {
            return Err(InvariantError::Violated {
                name: self.name().to_string(),
                details: format!("close_time decreased: {} -> {}", prev, curr),
            });
        }
        Ok(())
    }
}

/// Invariant: ledger entry last_modified_ledger_seq matches current header.
pub struct LastModifiedLedgerSeqMatchesHeader;

impl Invariant for LastModifiedLedgerSeqMatchesHeader {
    fn name(&self) -> &str {
        "LastModifiedLedgerSeqMatchesHeader"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<(), InvariantError> {
        let expected = ctx.curr_header.ledger_seq;
        for change in ctx.changes {
            if let Some(entry) = change.current_entry() {
                if entry.last_modified_ledger_seq != expected {
                    return Err(InvariantError::Violated {
                        name: self.name().to_string(),
                        details: format!(
                            "last_modified_ledger_seq mismatch: expected {}, got {}",
                            expected, entry.last_modified_ledger_seq
                        ),
                    });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        AccountEntry, AccountEntryExt, AccountEntryExtensionV1, AccountEntryExtensionV1Ext,
        AccountEntryExtensionV2, AccountEntryExtensionV2Ext, AccountId, AlphaNum4, Asset,
        AssetCode4, BytesM,
        ClaimableBalanceEntry, ClaimableBalanceEntryExt, ClaimableBalanceEntryExtensionV1,
        ClaimableBalanceFlags, ClaimableBalanceId, ClaimPredicate, Claimant, ClaimantV0,
        ContractCodeEntry, ContractCodeEntryExt, DataEntry, DataEntryExt, Hash, LedgerEntryExt,
        LedgerEntryExtensionV1, LedgerEntryExtensionV1Ext, LedgerHeaderExt,
        LiquidityPoolConstantProductParameters, LiquidityPoolEntry, LiquidityPoolEntryBody,
        LiquidityPoolEntryConstantProduct, PoolId, Price, PublicKey, SequenceNumber, Signer,
        SignerKey, SponsorshipDescriptor, StellarValue, StellarValueExt, Thresholds, TimePoint,
        TrustLineAsset, TrustLineEntry, TrustLineEntryExt, TrustLineEntryExtensionV2,
        TrustLineEntryExtensionV2Ext, TrustLineEntryV1, TrustLineEntryV1Ext, TtlEntry, Uint256,
        VecM,
    };

    fn make_account_id(byte: u8) -> stellar_xdr::curr::AccountId {
        stellar_xdr::curr::AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([byte; 32])))
    }

    fn make_header(seq: u32, bucket_hash: Hash256) -> LedgerHeader {
        LedgerHeader {
            ledger_version: 25,
            previous_ledger_hash: Hash([0u8; 32]),
            scp_value: StellarValue {
                tx_set_hash: Hash([0u8; 32]),
                close_time: TimePoint(0),
                upgrades: VecM::default(),
                ext: StellarValueExt::Basic,
            },
            tx_set_result_hash: Hash([0u8; 32]),
            bucket_list_hash: Hash(*bucket_hash.as_bytes()),
            ledger_seq: seq,
            total_coins: 1,
            fee_pool: 0,
            inflation_seq: 0,
            id_pool: 0,
            base_fee: 100,
            base_reserve: 100,
            max_tx_set_size: 100,
            skip_list: [
                Hash([0u8; 32]),
                Hash([0u8; 32]),
                Hash([0u8; 32]),
                Hash([0u8; 32]),
            ],
            ext: LedgerHeaderExt::V0,
        }
    }

    fn make_account_entry(seq_num: i64, signers: Vec<Signer>) -> LedgerEntry {
        make_account_entry_with_flags(seq_num, signers, 0, Vec::new())
    }

    fn make_account_entry_with_flags(
        seq_num: i64,
        signers: Vec<Signer>,
        flags: u32,
        home_domain: Vec<u8>,
    ) -> LedgerEntry {
        make_account_entry_with_ext(seq_num, signers, flags, home_domain, 0, AccountEntryExt::V0)
    }

    fn make_account_entry_with_ext(
        seq_num: i64,
        signers: Vec<Signer>,
        flags: u32,
        home_domain: Vec<u8>,
        num_sub_entries: u32,
        ext: AccountEntryExt,
    ) -> LedgerEntry {
        let domain = if home_domain.is_empty() {
            stellar_xdr::curr::String32::default()
        } else {
            stellar_xdr::curr::String32(
                stellar_xdr::curr::StringM::try_from(home_domain).unwrap(),
            )
        };
        LedgerEntry {
            last_modified_ledger_seq: 2,
            data: LedgerEntryData::Account(AccountEntry {
                account_id: make_account_id(1),
                balance: 10_000_000,
                seq_num: SequenceNumber(seq_num),
                num_sub_entries,
                inflation_dest: None,
                flags,
                home_domain: domain,
                thresholds: Thresholds([1, 0, 0, 0]),
                signers: signers.try_into().unwrap_or_default(),
                ext,
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    fn make_account_entry_with_sponsoring(
        account_id: AccountId,
        num_sponsoring: u32,
        num_sponsored: u32,
    ) -> LedgerEntry {
        let v2 = AccountEntryExtensionV2 {
            num_sponsored,
            num_sponsoring,
            signer_sponsoring_i_ds: VecM::default(),
            ext: AccountEntryExtensionV2Ext::V0,
        };
        let ext = AccountEntryExt::V1(AccountEntryExtensionV1 {
            liabilities: stellar_xdr::curr::Liabilities { buying: 0, selling: 0 },
            ext: AccountEntryExtensionV1Ext::V2(v2),
        });
        let mut entry = make_account_entry_with_ext(1, Vec::new(), 0, Vec::new(), 0, ext);
        if let LedgerEntryData::Account(account) = &mut entry.data {
            account.account_id = account_id;
        }
        entry
    }

    fn make_sponsored_trustline_entry(
        account_id: AccountId,
        sponsor_id: AccountId,
    ) -> LedgerEntry {
        let mut entry = make_trustline_entry(1, 0);
        if let LedgerEntryData::Trustline(trustline) = &mut entry.data {
            trustline.account_id = account_id;
        }
        entry.ext = LedgerEntryExt::V1(LedgerEntryExtensionV1 {
            sponsoring_id: SponsorshipDescriptor(Some(sponsor_id)),
            ext: LedgerEntryExtensionV1Ext::V0,
        });
        entry
    }

    fn make_native_trustline_entry() -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 2,
            data: LedgerEntryData::Trustline(TrustLineEntry {
                account_id: make_account_id(2),
                asset: TrustLineAsset::Native,
                balance: 0,
                limit: 1,
                flags: 0,
                ext: TrustLineEntryExt::V0,
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    fn make_trustline_entry(limit: i64, flags: u32) -> LedgerEntry {
        let asset = TrustLineAsset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"TEST"),
            issuer: make_account_id(3),
        });
        make_trustline_entry_with_asset(limit, flags, asset)
    }

    fn make_trustline_entry_with_asset(
        limit: i64,
        flags: u32,
        asset: TrustLineAsset,
    ) -> LedgerEntry {
        make_trustline_entry_with_ext(limit, flags, asset, TrustLineEntryExt::V0)
    }

    fn make_trustline_entry_with_ext(
        limit: i64,
        flags: u32,
        asset: TrustLineAsset,
        ext: TrustLineEntryExt,
    ) -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 2,
            data: LedgerEntryData::Trustline(TrustLineEntry {
                account_id: make_account_id(2),
                asset,
                balance: 0,
                limit,
                flags,
                ext,
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    fn make_trustline_entry_for_account(account_id: AccountId) -> LedgerEntry {
        let mut entry = make_trustline_entry(1, 0);
        if let LedgerEntryData::Trustline(trustline) = &mut entry.data {
            trustline.account_id = account_id;
        }
        entry
    }

    fn make_offer_entry(offer_id: i64, amount: i64, price: Price) -> LedgerEntry {
        make_offer_entry_with_flags(offer_id, amount, price, 0)
    }

    fn make_offer_entry_with_flags(
        offer_id: i64,
        amount: i64,
        price: Price,
        flags: u32,
    ) -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 2,
            data: LedgerEntryData::Offer(stellar_xdr::curr::OfferEntry {
                seller_id: make_account_id(4),
                offer_id,
                selling: Asset::Native,
                buying: Asset::Native,
                amount,
                price,
                flags,
                ext: stellar_xdr::curr::OfferEntryExt::V0,
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    fn make_data_entry(name: &str) -> LedgerEntry {
        make_data_entry_bytes(name.as_bytes().to_vec())
    }

    fn make_data_entry_bytes(name: Vec<u8>) -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 2,
            data: LedgerEntryData::Data(DataEntry {
                account_id: make_account_id(5),
                data_name: stellar_xdr::curr::String64(
                    stellar_xdr::curr::StringM::try_from(name).unwrap(),
                ),
                data_value: stellar_xdr::curr::DataValue::default(),
                ext: DataEntryExt::V0,
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    fn make_claimant(predicate: ClaimPredicate) -> Claimant {
        Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: make_account_id(6),
            predicate,
        })
    }

    fn make_claimable_balance_entry(
        amount: i64,
        claimants: Vec<Claimant>,
        asset: Asset,
        ext: ClaimableBalanceEntryExt,
    ) -> LedgerEntry {
        make_claimable_balance_entry_with_entry_ext(
            amount,
            claimants,
            asset,
            ext,
            LedgerEntryExt::V0,
        )
    }

    fn make_claimable_balance_entry_with_entry_ext(
        amount: i64,
        claimants: Vec<Claimant>,
        asset: Asset,
        ext: ClaimableBalanceEntryExt,
        entry_ext: LedgerEntryExt,
    ) -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 2,
            data: LedgerEntryData::ClaimableBalance(ClaimableBalanceEntry {
                balance_id: ClaimableBalanceId::default(),
                claimants: claimants.try_into().unwrap_or_default(),
                asset,
                amount,
                ext,
            }),
            ext: entry_ext,
        }
    }

    fn make_liquidity_pool_entry(entry_ext: LedgerEntryExt) -> LedgerEntry {
        let params = LiquidityPoolConstantProductParameters {
            asset_a: Asset::Native,
            asset_b: Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"TEST"),
                issuer: make_account_id(7),
            }),
            fee: 30,
        };
        make_liquidity_pool_entry_with_params(params, 0, 0, 0, 0, entry_ext)
    }

    fn make_liquidity_pool_entry_with_params(
        params: LiquidityPoolConstantProductParameters,
        reserve_a: i64,
        reserve_b: i64,
        total_pool_shares: i64,
        pool_shares_trust_line_count: i64,
        entry_ext: LedgerEntryExt,
    ) -> LedgerEntry {
        let body = LiquidityPoolEntryBody::LiquidityPoolConstantProduct(
            LiquidityPoolEntryConstantProduct {
                params,
                reserve_a,
                reserve_b,
                total_pool_shares,
                pool_shares_trust_line_count,
            },
        );
        LedgerEntry {
            last_modified_ledger_seq: 2,
            data: LedgerEntryData::LiquidityPool(LiquidityPoolEntry {
                liquidity_pool_id: PoolId(Hash([0u8; 32])),
                body,
            }),
            ext: entry_ext,
        }
    }

    fn make_contract_code_entry(code: Vec<u8>, hash: Hash) -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 2,
            data: LedgerEntryData::ContractCode(ContractCodeEntry {
                ext: ContractCodeEntryExt::V0,
                hash,
                code: BytesM::try_from(code).unwrap(),
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    fn make_ttl_entry(key_hash: Hash, live_until: u32) -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 2,
            data: LedgerEntryData::Ttl(TtlEntry {
                key_hash,
                live_until_ledger_seq: live_until,
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    fn make_changes(entries: Vec<LedgerEntry>) -> Vec<LedgerEntryChange> {
        entries
            .into_iter()
            .map(|entry| LedgerEntryChange::Created { current: entry })
            .collect()
    }

    fn make_ctx<'a>(
        prev: &'a LedgerHeader,
        curr: &'a LedgerHeader,
        changes: &'a [LedgerEntryChange],
    ) -> InvariantContext<'a> {
        let ctx = InvariantContext {
            prev_header: prev,
            curr_header: curr,
            bucket_list_hash: Hash256::ZERO,
            fee_pool_delta: 0,
            total_coins_delta: 0,
            changes,
        };
        ctx
    }

    #[test]
    fn test_invariant_manager() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let entries: Vec<LedgerEntry> = Vec::new();
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let mut manager = InvariantManager::new();
        manager.add(LedgerSeqIncrement);
        manager.add(BucketListHashMatchesHeader);
        manager.add(ConservationOfLumens);
        manager.add(LedgerEntryIsValid);

        assert!(manager.check_all(&ctx).is_ok());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_large_ledger_seq() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header((i32::MAX as u32).saturating_add(1), Hash256::ZERO);
        let entries: Vec<LedgerEntry> = Vec::new();
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_entry_ext_v1_before_v14() {
        let prev = make_header(1, Hash256::ZERO);
        let mut curr = make_header(2, Hash256::ZERO);
        curr.ledger_version = 13;
        let mut entry = make_account_entry(1, Vec::new());
        entry.ext = LedgerEntryExt::V1(LedgerEntryExtensionV1 {
            sponsoring_id: SponsorshipDescriptor(None),
            ext: LedgerEntryExtensionV1Ext::V0,
        });
        let entries = vec![entry];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_negative_seq() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let entries = vec![make_account_entry(-1, Vec::new())];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_unsorted_signers() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let signer_a = Signer {
            key: SignerKey::Ed25519(Uint256([2u8; 32])),
            weight: 1,
        };
        let signer_b = Signer {
            key: SignerKey::Ed25519(Uint256([1u8; 32])),
            weight: 1,
        };
        let entries = vec![make_account_entry(1, vec![signer_a, signer_b])];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_native_trustline() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let entries = vec![make_native_trustline_entry()];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_non_positive_trustline_limit() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let entries = vec![make_trustline_entry(0, 0)];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_offer_id_non_positive() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let entries = vec![make_offer_entry(0, 1, Price { n: 1, d: 1 })];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_offer_amount_non_positive() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let entries = vec![make_offer_entry(1, 0, Price { n: 1, d: 1 })];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_offer_price_invalid() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let entries = vec![make_offer_entry(1, 1, Price { n: 0, d: 1 })];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_offer_flags_invalid() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let entries = vec![make_offer_entry_with_flags(1, 1, Price { n: 1, d: 1 }, 2)];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_offer_asset_invalid() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let selling = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', 0, b'S', b'D']),
            issuer: make_account_id(3),
        });
        let entries = vec![LedgerEntry {
            last_modified_ledger_seq: 2,
            data: LedgerEntryData::Offer(stellar_xdr::curr::OfferEntry {
                seller_id: make_account_id(4),
                offer_id: 1,
                selling,
                buying: Asset::Native,
                amount: 1,
                price: Price { n: 1, d: 1 },
                flags: 0,
                ext: stellar_xdr::curr::OfferEntryExt::V0,
            }),
            ext: LedgerEntryExt::V0,
        }];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_trustline_flags_invalid() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let flags = (stellar_xdr::curr::TrustLineFlags::AuthorizedFlag as u32)
            | (stellar_xdr::curr::TrustLineFlags::AuthorizedToMaintainLiabilitiesFlag as u32);
        let entries = vec![make_trustline_entry(1, flags)];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_trustline_v2_before_v18() {
        let prev = make_header(1, Hash256::ZERO);
        let mut curr = make_header(2, Hash256::ZERO);
        curr.ledger_version = 17;
        let asset = TrustLineAsset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"TEST"),
            issuer: make_account_id(3),
        });
        let ext = TrustLineEntryExt::V1(TrustLineEntryV1 {
            liabilities: stellar_xdr::curr::Liabilities { buying: 0, selling: 0 },
            ext: TrustLineEntryV1Ext::V2(TrustLineEntryExtensionV2 {
                liquidity_pool_use_count: 0,
                ext: TrustLineEntryExtensionV2Ext::V0,
            }),
        });
        let entries = vec![make_trustline_entry_with_ext(1, 0, asset, ext)];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_trustline_negative_pool_use_count() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let asset = TrustLineAsset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"TEST"),
            issuer: make_account_id(3),
        });
        let ext = TrustLineEntryExt::V1(TrustLineEntryV1 {
            liabilities: stellar_xdr::curr::Liabilities { buying: 0, selling: 0 },
            ext: TrustLineEntryV1Ext::V2(TrustLineEntryExtensionV2 {
                liquidity_pool_use_count: -1,
                ext: TrustLineEntryExtensionV2Ext::V0,
            }),
        });
        let entries = vec![make_trustline_entry_with_ext(1, 0, asset, ext)];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_trustline_clawback_enabled() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let asset = TrustLineAsset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"TEST"),
            issuer: make_account_id(3),
        });
        let prev_entry = make_trustline_entry_with_ext(1, 0, asset.clone(), TrustLineEntryExt::V0);
        let curr_entry = make_trustline_entry_with_ext(
            1,
            stellar_xdr::curr::TrustLineFlags::TrustlineClawbackEnabledFlag as u32,
            asset,
            TrustLineEntryExt::V0,
        );
        let changes = vec![LedgerEntryChange::Updated {
            previous: prev_entry,
            current: curr_entry,
        }];
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_pool_share_liabilities() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let asset = TrustLineAsset::PoolShare(stellar_xdr::curr::PoolId(Hash([0u8; 32])));
        let ext = TrustLineEntryExt::V1(TrustLineEntryV1 {
            liabilities: stellar_xdr::curr::Liabilities { buying: 1, selling: 0 },
            ext: TrustLineEntryV1Ext::V0,
        });
        let entries = vec![make_trustline_entry_with_ext(1, 0, asset, ext)];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_ttl_key_hash_modified() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let previous = make_ttl_entry(Hash([1u8; 32]), 10);
        let current = make_ttl_entry(Hash([2u8; 32]), 10);
        let changes = vec![LedgerEntryChange::Updated { previous, current }];
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_ttl_live_until_decreased() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let previous = make_ttl_entry(Hash([1u8; 32]), 10);
        let current = make_ttl_entry(Hash([1u8; 32]), 9);
        let changes = vec![LedgerEntryChange::Updated { previous, current }];
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_trustline_asset_invalid() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let asset = TrustLineAsset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', 0, b'S', b'D']),
            issuer: make_account_id(3),
        });
        let entries = vec![make_trustline_entry_with_asset(1, 0, asset)];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_pool_share_trustline_pre_v18() {
        let prev = make_header(1, Hash256::ZERO);
        let mut curr = make_header(2, Hash256::ZERO);
        curr.ledger_version = 17;
        let asset = TrustLineAsset::PoolShare(stellar_xdr::curr::PoolId(Hash([0u8; 32])));
        let entries = vec![make_trustline_entry_with_asset(1, 0, asset)];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_account_flags_outside_mask() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let entries = vec![make_account_entry_with_flags(1, Vec::new(), 0x10, Vec::new())];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_account_clawback_without_revocable() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let clawback = stellar_xdr::curr::AccountFlags::ClawbackEnabledFlag as u32;
        let entries = vec![make_account_entry_with_flags(1, Vec::new(), clawback, Vec::new())];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_account_home_domain_invalid() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let entries = vec![make_account_entry_with_flags(1, Vec::new(), 0, vec![0x7f])];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_account_ext_v1_before_v14() {
        let prev = make_header(1, Hash256::ZERO);
        let mut curr = make_header(2, Hash256::ZERO);
        curr.ledger_version = 13;
        let ext = AccountEntryExt::V1(AccountEntryExtensionV1 {
            liabilities: stellar_xdr::curr::Liabilities { buying: 0, selling: 0 },
            ext: AccountEntryExtensionV1Ext::V0,
        });
        let entries = vec![make_account_entry_with_ext(1, Vec::new(), 0, Vec::new(), 0, ext)];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_account_ext_v2_before_v18() {
        let prev = make_header(1, Hash256::ZERO);
        let mut curr = make_header(2, Hash256::ZERO);
        curr.ledger_version = 17;
        let v2 = AccountEntryExtensionV2 {
            num_sponsored: 0,
            num_sponsoring: 0,
            signer_sponsoring_i_ds: VecM::default(),
            ext: AccountEntryExtensionV2Ext::V0,
        };
        let ext = AccountEntryExt::V1(AccountEntryExtensionV1 {
            liabilities: stellar_xdr::curr::Liabilities { buying: 0, selling: 0 },
            ext: AccountEntryExtensionV1Ext::V2(v2),
        });
        let entries = vec![make_account_entry_with_ext(1, Vec::new(), 0, Vec::new(), 0, ext)];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_account_signers_not_paired_with_sponsors() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let signer = Signer {
            key: SignerKey::Ed25519(Uint256([3u8; 32])),
            weight: 1,
        };
        let v2 = AccountEntryExtensionV2 {
            num_sponsored: 0,
            num_sponsoring: 0,
            signer_sponsoring_i_ds: VecM::default(),
            ext: AccountEntryExtensionV2Ext::V0,
        };
        let ext = AccountEntryExt::V1(AccountEntryExtensionV1 {
            liabilities: stellar_xdr::curr::Liabilities { buying: 0, selling: 0 },
            ext: AccountEntryExtensionV1Ext::V2(v2),
        });
        let entries = vec![make_account_entry_with_ext(
            1,
            vec![signer],
            0,
            Vec::new(),
            0,
            ext,
        )];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_account_sponsoring_overflow() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let v2 = AccountEntryExtensionV2 {
            num_sponsored: 0,
            num_sponsoring: 1,
            signer_sponsoring_i_ds: VecM::default(),
            ext: AccountEntryExtensionV2Ext::V0,
        };
        let ext = AccountEntryExt::V1(AccountEntryExtensionV1 {
            liabilities: stellar_xdr::curr::Liabilities { buying: 0, selling: 0 },
            ext: AccountEntryExtensionV1Ext::V2(v2),
        });
        let entries = vec![make_account_entry_with_ext(
            1,
            Vec::new(),
            0,
            Vec::new(),
            u32::MAX,
            ext,
        )];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_empty_data_name() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let entries = vec![make_data_entry("")];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_invalid_data_name() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let entries = vec![make_data_entry_bytes(vec![0x7f])];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_contract_code_hash_mismatch() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let code = vec![1u8, 2, 3, 4];
        let bad_hash = Hash([0u8; 32]);
        let entries = vec![make_contract_code_entry(code, bad_hash)];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_contract_code_modified() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let code_prev = vec![1u8, 2, 3, 4];
        let hash_prev = Hash(*Hash256::hash(&code_prev).as_bytes());
        let code_curr = vec![5u8, 6, 7, 8];
        let hash_curr = Hash(*Hash256::hash(&code_curr).as_bytes());
        let previous = make_contract_code_entry(code_prev, hash_prev);
        let current = make_contract_code_entry(code_curr, hash_curr);
        let changes = vec![LedgerEntryChange::Updated { previous, current }];
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_claimable_balance_empty_claimants() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let entries = vec![make_claimable_balance_entry(
            1,
            Vec::new(),
            Asset::Native,
            ClaimableBalanceEntryExt::V0,
        )];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_claimable_balance_not_sponsored() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let claimant = make_claimant(ClaimPredicate::Unconditional);
        let entries = vec![make_claimable_balance_entry_with_entry_ext(
            1,
            vec![claimant],
            Asset::Native,
            ClaimableBalanceEntryExt::V0,
            LedgerEntryExt::V0,
        )];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_claimable_balance_asset_invalid() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let claimant = make_claimant(ClaimPredicate::Unconditional);
        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', 0, b'S', b'D']),
            issuer: make_account_id(3),
        });
        let entries = vec![make_claimable_balance_entry_with_entry_ext(
            1,
            vec![claimant],
            asset,
            ClaimableBalanceEntryExt::V0,
            LedgerEntryExt::V1(LedgerEntryExtensionV1 {
                sponsoring_id: SponsorshipDescriptor(Some(make_account_id(9))),
                ext: LedgerEntryExtensionV1Ext::V0,
            }),
        )];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_claimable_balance_amount_non_positive() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let claimant = make_claimant(ClaimPredicate::Unconditional);
        let entries = vec![make_claimable_balance_entry(
            0,
            vec![claimant],
            Asset::Native,
            ClaimableBalanceEntryExt::V0,
        )];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_liquidity_pool_sponsored() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let entry_ext = LedgerEntryExt::V1(LedgerEntryExtensionV1 {
            sponsoring_id: SponsorshipDescriptor(Some(make_account_id(8))),
            ext: LedgerEntryExtensionV1Ext::V0,
        });
        let entries = vec![make_liquidity_pool_entry(entry_ext)];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_liquidity_pool_before_v18() {
        let prev = make_header(1, Hash256::ZERO);
        let mut curr = make_header(2, Hash256::ZERO);
        curr.ledger_version = 17;
        let entries = vec![make_liquidity_pool_entry(LedgerEntryExt::V0)];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_liquidity_pool_asset_order() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let params = LiquidityPoolConstantProductParameters {
            asset_a: Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"ZZZZ"),
                issuer: make_account_id(7),
            }),
            asset_b: Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"AAAA"),
                issuer: make_account_id(7),
            }),
            fee: 30,
        };
        let entries = vec![make_liquidity_pool_entry_with_params(
            params,
            0,
            0,
            0,
            0,
            LedgerEntryExt::V0,
        )];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_liquidity_pool_invalid_fee() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let params = LiquidityPoolConstantProductParameters {
            asset_a: Asset::Native,
            asset_b: Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"TEST"),
                issuer: make_account_id(7),
            }),
            fee: 25,
        };
        let entries = vec![make_liquidity_pool_entry_with_params(
            params,
            0,
            0,
            0,
            0,
            LedgerEntryExt::V0,
        )];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_liquidity_pool_negative_reserve() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let params = LiquidityPoolConstantProductParameters {
            asset_a: Asset::Native,
            asset_b: Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"TEST"),
                issuer: make_account_id(7),
            }),
            fee: 30,
        };
        let entries = vec![make_liquidity_pool_entry_with_params(
            params,
            -1,
            0,
            0,
            0,
            LedgerEntryExt::V0,
        )];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_claimable_balance_invalid_predicate() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let claimant = make_claimant(ClaimPredicate::BeforeRelativeTime(1));
        let entries = vec![make_claimable_balance_entry(
            1,
            vec![claimant],
            Asset::Native,
            ClaimableBalanceEntryExt::V0,
        )];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_claimable_balance_clawback_native() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let claimant = make_claimant(ClaimPredicate::Unconditional);
        let ext = ClaimableBalanceEntryExt::V1(ClaimableBalanceEntryExtensionV1 {
            ext: stellar_xdr::curr::ClaimableBalanceEntryExtensionV1Ext::V0,
            flags: ClaimableBalanceFlags::ClaimableBalanceClawbackEnabledFlag as u32,
        });
        let entries = vec![make_claimable_balance_entry(
            1,
            vec![claimant],
            Asset::Native,
            ext,
        )];
        let changes = make_changes(entries);
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_ledger_entry_is_valid_rejects_claimable_balance_modified() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let claimant = make_claimant(ClaimPredicate::Unconditional);
        let entry_ext = LedgerEntryExt::V1(LedgerEntryExtensionV1 {
            sponsoring_id: SponsorshipDescriptor(Some(make_account_id(9))),
            ext: LedgerEntryExtensionV1Ext::V0,
        });
        let previous = make_claimable_balance_entry_with_entry_ext(
            1,
            vec![claimant.clone()],
            Asset::Native,
            ClaimableBalanceEntryExt::V0,
            entry_ext.clone(),
        );
        let current = make_claimable_balance_entry_with_entry_ext(
            2,
            vec![claimant],
            Asset::Native,
            ClaimableBalanceEntryExt::V0,
            entry_ext,
        );
        let changes = vec![LedgerEntryChange::Updated { previous, current }];
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = LedgerEntryIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_sponsorship_count_is_valid_accepts_matching_counts() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let sponsor = make_account_id(7);
        let sponsored = make_account_id(8);

        let prev_sponsor = make_account_entry_with_sponsoring(sponsor.clone(), 0, 0);
        let curr_sponsor = make_account_entry_with_sponsoring(sponsor.clone(), 1, 0);
        let prev_sponsored = make_account_entry_with_sponsoring(sponsored.clone(), 0, 0);
        let curr_sponsored = make_account_entry_with_sponsoring(sponsored.clone(), 0, 1);

        let trustline = make_sponsored_trustline_entry(sponsored.clone(), sponsor.clone());

        let changes = vec![
            LedgerEntryChange::Updated {
                previous: prev_sponsor,
                current: curr_sponsor,
            },
            LedgerEntryChange::Updated {
                previous: prev_sponsored,
                current: curr_sponsored,
            },
            LedgerEntryChange::Created { current: trustline },
        ];
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = SponsorshipCountIsValid;
        assert!(inv.check(&ctx).is_ok());
    }

    #[test]
    fn test_sponsorship_count_is_valid_rejects_mismatch() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let sponsor = make_account_id(7);
        let sponsored = make_account_id(8);

        let prev_sponsor = make_account_entry_with_sponsoring(sponsor.clone(), 0, 0);
        let curr_sponsor = make_account_entry_with_sponsoring(sponsor.clone(), 0, 0);
        let prev_sponsored = make_account_entry_with_sponsoring(sponsored.clone(), 0, 0);
        let curr_sponsored = make_account_entry_with_sponsoring(sponsored.clone(), 0, 1);

        let trustline = make_sponsored_trustline_entry(sponsored.clone(), sponsor.clone());

        let changes = vec![
            LedgerEntryChange::Updated {
                previous: prev_sponsor,
                current: curr_sponsor,
            },
            LedgerEntryChange::Updated {
                previous: prev_sponsored,
                current: curr_sponsored,
            },
            LedgerEntryChange::Created { current: trustline },
        ];
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = SponsorshipCountIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_account_subentries_count_is_valid_accepts_matching_delta() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let prev_account = make_account_entry_with_ext(1, Vec::new(), 0, Vec::new(), 0, AccountEntryExt::V0);
        let curr_account = make_account_entry_with_ext(1, Vec::new(), 0, Vec::new(), 1, AccountEntryExt::V0);
        let trustline = make_trustline_entry_for_account(make_account_id(1));

        let changes = vec![
            LedgerEntryChange::Updated {
                previous: prev_account,
                current: curr_account,
            },
            LedgerEntryChange::Created { current: trustline },
        ];
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = AccountSubEntriesCountIsValid;
        assert!(inv.check(&ctx).is_ok());
    }

    #[test]
    fn test_account_subentries_count_is_valid_rejects_mismatch() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let prev_account = make_account_entry_with_ext(1, Vec::new(), 0, Vec::new(), 0, AccountEntryExt::V0);
        let curr_account = make_account_entry_with_ext(1, Vec::new(), 0, Vec::new(), 0, AccountEntryExt::V0);
        let trustline = make_trustline_entry_for_account(make_account_id(1));

        let changes = vec![
            LedgerEntryChange::Updated {
                previous: prev_account,
                current: curr_account,
            },
            LedgerEntryChange::Created { current: trustline },
        ];
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = AccountSubEntriesCountIsValid;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_constant_product_invariant_accepts_non_decreasing() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let prev_entry = make_liquidity_pool_entry_with_params(
            LiquidityPoolConstantProductParameters {
                asset_a: Asset::Native,
                asset_b: Asset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4(*b"TEST"),
                    issuer: make_account_id(7),
                }),
                fee: 30,
            },
            10,
            10,
            100,
            0,
            LedgerEntryExt::V0,
        );
        let curr_entry = make_liquidity_pool_entry_with_params(
            LiquidityPoolConstantProductParameters {
                asset_a: Asset::Native,
                asset_b: Asset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4(*b"TEST"),
                    issuer: make_account_id(7),
                }),
                fee: 30,
            },
            12,
            9,
            100,
            0,
            LedgerEntryExt::V0,
        );
        let changes = vec![LedgerEntryChange::Updated {
            previous: prev_entry,
            current: curr_entry,
        }];
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = ConstantProductInvariant;
        assert!(inv.check(&ctx).is_ok());
    }

    #[test]
    fn test_constant_product_invariant_rejects_decrease() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let prev_entry = make_liquidity_pool_entry_with_params(
            LiquidityPoolConstantProductParameters {
                asset_a: Asset::Native,
                asset_b: Asset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4(*b"TEST"),
                    issuer: make_account_id(7),
                }),
                fee: 30,
            },
            10,
            10,
            100,
            0,
            LedgerEntryExt::V0,
        );
        let curr_entry = make_liquidity_pool_entry_with_params(
            LiquidityPoolConstantProductParameters {
                asset_a: Asset::Native,
                asset_b: Asset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4(*b"TEST"),
                    issuer: make_account_id(7),
                }),
                fee: 30,
            },
            9,
            9,
            100,
            0,
            LedgerEntryExt::V0,
        );
        let changes = vec![LedgerEntryChange::Updated {
            previous: prev_entry,
            current: curr_entry,
        }];
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = ConstantProductInvariant;
        assert!(inv.check(&ctx).is_err());
    }

    #[test]
    fn test_constant_product_invariant_skips_when_shares_decrease() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let prev_entry = make_liquidity_pool_entry_with_params(
            LiquidityPoolConstantProductParameters {
                asset_a: Asset::Native,
                asset_b: Asset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4(*b"TEST"),
                    issuer: make_account_id(7),
                }),
                fee: 30,
            },
            10,
            10,
            100,
            0,
            LedgerEntryExt::V0,
        );
        let curr_entry = make_liquidity_pool_entry_with_params(
            LiquidityPoolConstantProductParameters {
                asset_a: Asset::Native,
                asset_b: Asset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4(*b"TEST"),
                    issuer: make_account_id(7),
                }),
                fee: 30,
            },
            9,
            9,
            90,
            0,
            LedgerEntryExt::V0,
        );
        let changes = vec![LedgerEntryChange::Updated {
            previous: prev_entry,
            current: curr_entry,
        }];
        let ctx = make_ctx(&prev, &curr, &changes);

        let inv = ConstantProductInvariant;
        assert!(inv.check(&ctx).is_ok());
    }
}
