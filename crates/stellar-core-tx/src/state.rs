//! Ledger state management for transaction execution.

use std::collections::HashMap;

use stellar_xdr::curr::{
    AccountEntry, AccountEntryExt, AccountEntryExtensionV1, AccountEntryExtensionV1Ext,
    AccountEntryExtensionV2, AccountEntryExtensionV2Ext, AccountId, Asset, ClaimableBalanceEntry,
    ClaimableBalanceId,
    ContractCodeEntry, ContractDataDurability, ContractDataEntry, DataEntry, Hash, LedgerEntry,
    LedgerEntryData, LedgerEntryExt, LedgerEntryExtensionV1, LedgerEntryExtensionV1Ext, LedgerKey,
    LedgerKeyAccount, LedgerKeyClaimableBalance, LedgerKeyContractCode, LedgerKeyContractData,
    LedgerKeyData, LedgerKeyLiquidityPool, LedgerKeyOffer, LedgerKeyTrustLine, LedgerKeyTtl,
    Liabilities, LiquidityPoolEntry, OfferEntry, PoolId, Price, PublicKey, ScAddress, ScVal,
    SponsorshipDescriptor, TrustLineAsset, TrustLineEntry, TtlEntry, VecM,
};

use crate::apply::LedgerDelta;
use crate::{Result, TxError};

/// Trait for reading ledger entries from storage.
pub trait LedgerReader {
    /// Get a ledger entry by key.
    fn get_entry(&self, key: &LedgerKey) -> Option<LedgerEntry>;
}

/// Asset key for trustline lookup.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum AssetKey {
    /// Native XLM asset.
    Native,
    /// Credit alphanum4 asset (code, issuer).
    CreditAlphanum4([u8; 4], [u8; 32]),
    /// Credit alphanum12 asset (code, issuer).
    CreditAlphanum12([u8; 12], [u8; 32]),
    /// Pool share asset.
    PoolShare([u8; 32]),
}

/// Key for contract data lookup.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ContractDataKey {
    /// Contract address.
    pub contract: ScAddress,
    /// Data key.
    pub key: ScVal,
    /// Durability (temporary or persistent).
    pub durability: ContractDataDurability,
}

impl ContractDataKey {
    /// Create a new contract data key.
    pub fn new(contract: ScAddress, key: ScVal, durability: ContractDataDurability) -> Self {
        Self {
            contract,
            key,
            durability,
        }
    }
}

impl AssetKey {
    /// Create an AssetKey from an XDR Asset.
    pub fn from_asset(asset: &Asset) -> Self {
        match asset {
            Asset::Native => AssetKey::Native,
            Asset::CreditAlphanum4(a) => {
                let issuer = account_id_to_bytes(&a.issuer);
                AssetKey::CreditAlphanum4(a.asset_code.0, issuer)
            }
            Asset::CreditAlphanum12(a) => {
                let issuer = account_id_to_bytes(&a.issuer);
                AssetKey::CreditAlphanum12(a.asset_code.0, issuer)
            }
        }
    }

    /// Create an AssetKey from a TrustLineAsset.
    pub fn from_trustline_asset(asset: &TrustLineAsset) -> Self {
        match asset {
            TrustLineAsset::Native => AssetKey::Native,
            TrustLineAsset::CreditAlphanum4(a) => {
                let issuer = account_id_to_bytes(&a.issuer);
                AssetKey::CreditAlphanum4(a.asset_code.0, issuer)
            }
            TrustLineAsset::CreditAlphanum12(a) => {
                let issuer = account_id_to_bytes(&a.issuer);
                AssetKey::CreditAlphanum12(a.asset_code.0, issuer)
            }
            TrustLineAsset::PoolShare(pool_id) => AssetKey::PoolShare(pool_id.0.0),
        }
    }
}

/// Ledger state manager for transaction execution.
///
/// This provides read/write access to ledger entries during transaction
/// execution, tracking all changes for later persistence.
#[derive(Clone)]
pub struct LedgerStateManager {
    /// Current ledger sequence.
    ledger_seq: u32,
    /// Base reserve in stroops (minimum balance per sub-entry).
    base_reserve: i64,
    /// ID pool for generating offer IDs.
    id_pool: u64,
    /// Account entries by account ID (32-byte public key).
    accounts: HashMap<[u8; 32], AccountEntry>,
    /// Trustline entries by (account, asset).
    trustlines: HashMap<([u8; 32], AssetKey), TrustLineEntry>,
    /// Offer entries by (seller, offer_id).
    offers: HashMap<([u8; 32], i64), OfferEntry>,
    /// Data entries by (account, name).
    data_entries: HashMap<([u8; 32], String), DataEntry>,
    /// Contract data entries by (contract, key, durability).
    contract_data: HashMap<ContractDataKey, ContractDataEntry>,
    /// Contract code entries by hash.
    contract_code: HashMap<[u8; 32], ContractCodeEntry>,
    /// TTL entries by key hash.
    ttl_entries: HashMap<[u8; 32], TtlEntry>,
    /// Claimable balance entries by balance ID.
    claimable_balances: HashMap<[u8; 32], ClaimableBalanceEntry>,
    /// Liquidity pool entries by pool ID.
    liquidity_pools: HashMap<[u8; 32], LiquidityPoolEntry>,
    /// Sponsoring account IDs for ledger entries (only when sponsored).
    entry_sponsorships: HashMap<LedgerKey, AccountId>,
    /// Active sponsorship stack for the current transaction.
    sponsorship_stack: Vec<SponsorshipContext>,
    /// Changes made during execution.
    delta: LedgerDelta,
    /// Track which entries have been modified for rollback.
    modified_accounts: Vec<[u8; 32]>,
    /// Track which trustlines have been modified.
    modified_trustlines: Vec<([u8; 32], AssetKey)>,
    /// Track which offers have been modified.
    modified_offers: Vec<([u8; 32], i64)>,
    /// Track which data entries have been modified.
    modified_data: Vec<([u8; 32], String)>,
    /// Track which contract data entries have been modified.
    modified_contract_data: Vec<ContractDataKey>,
    /// Track which contract code entries have been modified.
    modified_contract_code: Vec<[u8; 32]>,
    /// Track which TTL entries have been modified.
    modified_ttl: Vec<[u8; 32]>,
    /// Track which claimable balance entries have been modified.
    modified_claimable_balances: Vec<[u8; 32]>,
    /// Track which liquidity pool entries have been modified.
    modified_liquidity_pools: Vec<[u8; 32]>,
    /// Snapshot of accounts for rollback.
    account_snapshots: HashMap<[u8; 32], Option<AccountEntry>>,
    /// Snapshot of trustlines for rollback.
    trustline_snapshots: HashMap<([u8; 32], AssetKey), Option<TrustLineEntry>>,
    /// Snapshot of offers for rollback.
    offer_snapshots: HashMap<([u8; 32], i64), Option<OfferEntry>>,
    /// Snapshot of data entries for rollback.
    data_snapshots: HashMap<([u8; 32], String), Option<DataEntry>>,
    /// Snapshot of contract data entries for rollback.
    contract_data_snapshots: HashMap<ContractDataKey, Option<ContractDataEntry>>,
    /// Snapshot of contract code entries for rollback.
    contract_code_snapshots: HashMap<[u8; 32], Option<ContractCodeEntry>>,
    /// Snapshot of TTL entries for rollback.
    ttl_snapshots: HashMap<[u8; 32], Option<TtlEntry>>,
    /// Snapshot of claimable balance entries for rollback.
    claimable_balance_snapshots: HashMap<[u8; 32], Option<ClaimableBalanceEntry>>,
    /// Snapshot of liquidity pool entries for rollback.
    liquidity_pool_snapshots: HashMap<[u8; 32], Option<LiquidityPoolEntry>>,
    /// Snapshot of entry sponsorships for rollback.
    entry_sponsorship_snapshots: HashMap<LedgerKey, Option<AccountId>>,
}

#[derive(Debug, Clone)]
pub struct SponsorshipContext {
    pub sponsoring: AccountId,
    pub sponsored: AccountId,
}

impl LedgerStateManager {
    /// Create a new ledger state manager for the given ledger sequence.
    ///
    /// # Arguments
    ///
    /// * `base_reserve` - Base reserve in stroops (e.g., 5_000_000 for 0.5 XLM)
    /// * `ledger_seq` - The current ledger sequence number
    pub fn new(base_reserve: i64, ledger_seq: u32) -> Self {
        Self {
            ledger_seq,
            base_reserve,
            id_pool: 0,
            accounts: HashMap::new(),
            trustlines: HashMap::new(),
            offers: HashMap::new(),
            data_entries: HashMap::new(),
            contract_data: HashMap::new(),
            contract_code: HashMap::new(),
            ttl_entries: HashMap::new(),
            claimable_balances: HashMap::new(),
            liquidity_pools: HashMap::new(),
            entry_sponsorships: HashMap::new(),
            sponsorship_stack: Vec::new(),
            delta: LedgerDelta::new(ledger_seq),
            modified_accounts: Vec::new(),
            modified_trustlines: Vec::new(),
            modified_offers: Vec::new(),
            modified_data: Vec::new(),
            modified_contract_data: Vec::new(),
            modified_contract_code: Vec::new(),
            modified_ttl: Vec::new(),
            modified_claimable_balances: Vec::new(),
            modified_liquidity_pools: Vec::new(),
            account_snapshots: HashMap::new(),
            trustline_snapshots: HashMap::new(),
            offer_snapshots: HashMap::new(),
            data_snapshots: HashMap::new(),
            contract_data_snapshots: HashMap::new(),
            contract_code_snapshots: HashMap::new(),
            ttl_snapshots: HashMap::new(),
            claimable_balance_snapshots: HashMap::new(),
            liquidity_pool_snapshots: HashMap::new(),
            entry_sponsorship_snapshots: HashMap::new(),
        }
    }

    /// Compute the starting sequence number for new accounts.
    pub fn starting_sequence_number(&self) -> crate::Result<i64> {
        if self.ledger_seq > i32::MAX as u32 {
            return Err(crate::TxError::Internal(
                "overflowed starting sequence number".to_string(),
            ));
        }
        Ok((self.ledger_seq as i64) << 32)
    }

    /// Calculate the minimum balance required for an account.
    pub fn minimum_balance_for_account(
        &self,
        account: &AccountEntry,
        protocol_version: u32,
        additional_subentries: i64,
    ) -> Result<i64> {
        let num_sub_entries = account.num_sub_entries as i64 + additional_subentries;
        if num_sub_entries < 0 {
            return Err(TxError::Internal(
                "negative subentry count while computing minimum balance".to_string(),
            ));
        }
        let (num_sponsoring, num_sponsored) = sponsorship_counts(account);
        self.minimum_balance_with_counts(
            protocol_version,
            num_sub_entries,
            num_sponsoring,
            num_sponsored,
        )
    }

    /// Calculate the minimum balance for an account with sponsorship deltas.
    pub fn minimum_balance_for_account_with_deltas(
        &self,
        account: &AccountEntry,
        protocol_version: u32,
        additional_subentries: i64,
        delta_sponsoring: i64,
        delta_sponsored: i64,
    ) -> Result<i64> {
        let num_sub_entries = account.num_sub_entries as i64 + additional_subentries;
        if num_sub_entries < 0 {
            return Err(TxError::Internal(
                "negative subentry count while computing minimum balance".to_string(),
            ));
        }
        let (num_sponsoring, num_sponsored) = sponsorship_counts(account);
        let num_sponsoring = num_sponsoring + delta_sponsoring;
        let num_sponsored = num_sponsored + delta_sponsored;
        if num_sponsoring < 0 || num_sponsored < 0 {
            return Err(TxError::Internal(
                "negative sponsorship count while computing minimum balance".to_string(),
            ));
        }
        self.minimum_balance_with_counts(
            protocol_version,
            num_sub_entries,
            num_sponsoring,
            num_sponsored,
        )
    }

    /// Calculate the minimum balance for a hypothetical account state.
    pub fn minimum_balance_with_counts(
        &self,
        protocol_version: u32,
        num_sub_entries: i64,
        num_sponsoring: i64,
        num_sponsored: i64,
    ) -> Result<i64> {
        if protocol_version < 14 && (num_sponsoring != 0 || num_sponsored != 0) {
            return Err(TxError::Internal(
                "unexpected sponsorship state for protocol < 14".to_string(),
            ));
        }

        let effective_entries = if protocol_version < 9 {
            2 + num_sub_entries
        } else {
            2 + num_sub_entries + num_sponsoring - num_sponsored
        };

        if effective_entries < 0 {
            return Err(TxError::Internal(
                "unexpected account state while computing minimum balance".to_string(),
            ));
        }

        Ok(effective_entries * self.base_reserve)
    }

    /// Get the base reserve.
    pub fn base_reserve(&self) -> i64 {
        self.base_reserve
    }

    /// Get the current ID pool.
    pub fn id_pool(&self) -> u64 {
        self.id_pool
    }

    /// Set the current ID pool.
    pub fn set_id_pool(&mut self, id_pool: u64) {
        self.id_pool = id_pool;
    }

    /// Generate the next ID from the pool.
    pub fn next_id(&mut self) -> i64 {
        self.id_pool = self.id_pool.checked_add(1).expect("id_pool overflow");
        i64::try_from(self.id_pool).expect("id_pool exceeds i64::MAX")
    }

    /// Get the current ledger sequence.
    pub fn ledger_seq(&self) -> u32 {
        self.ledger_seq
    }

    /// Clear active sponsorship state (start of a new transaction).
    pub fn clear_sponsorship_stack(&mut self) {
        self.sponsorship_stack.clear();
    }

    /// Check if there is any pending sponsorship.
    pub fn has_pending_sponsorship(&self) -> bool {
        !self.sponsorship_stack.is_empty()
    }

    /// Return the active sponsor for a sponsored account, if any.
    pub fn active_sponsor_for(&self, sponsored: &AccountId) -> Option<AccountId> {
        self.sponsorship_stack
            .iter()
            .rev()
            .find(|ctx| ctx.sponsored == *sponsored)
            .map(|ctx| ctx.sponsoring.clone())
    }

    /// Return true if an account is currently being sponsored.
    pub fn is_sponsored(&self, account_id: &AccountId) -> bool {
        self.sponsorship_stack
            .iter()
            .any(|ctx| ctx.sponsored == *account_id)
    }

    /// Return true if an account is currently sponsoring someone else.
    pub fn is_sponsoring(&self, account_id: &AccountId) -> bool {
        self.sponsorship_stack
            .iter()
            .any(|ctx| ctx.sponsoring == *account_id)
    }

    /// Push a new sponsorship context onto the stack.
    pub fn push_sponsorship(&mut self, sponsoring: AccountId, sponsored: AccountId) {
        self.sponsorship_stack.push(SponsorshipContext {
            sponsoring,
            sponsored,
        });
    }

    /// Pop the latest sponsorship context.
    pub fn pop_sponsorship(&mut self) -> Option<SponsorshipContext> {
        self.sponsorship_stack.pop()
    }

    /// Remove the most recent sponsorship for a sponsored account.
    pub fn remove_sponsorship_for(&mut self, sponsored: &AccountId) -> Option<SponsorshipContext> {
        if let Some(pos) = self
            .sponsorship_stack
            .iter()
            .rposition(|ctx| &ctx.sponsored == sponsored)
        {
            return Some(self.sponsorship_stack.remove(pos));
        }
        None
    }

    /// Return the sponsor for a ledger entry, if any.
    pub fn entry_sponsor(&self, key: &LedgerKey) -> Option<&AccountId> {
        self.entry_sponsorships.get(key)
    }

    /// Set the sponsor for a ledger entry.
    pub fn set_entry_sponsor(&mut self, key: LedgerKey, sponsor: AccountId) {
        if !self.entry_sponsorship_snapshots.contains_key(&key) {
            self.entry_sponsorship_snapshots
                .insert(key.clone(), self.entry_sponsorships.get(&key).cloned());
        }
        self.entry_sponsorships.insert(key, sponsor);
    }

    /// Remove and return the sponsor for a ledger entry, if any.
    pub fn remove_entry_sponsor(&mut self, key: &LedgerKey) -> Option<AccountId> {
        if !self.entry_sponsorship_snapshots.contains_key(key) {
            self.entry_sponsorship_snapshots
                .insert(key.clone(), self.entry_sponsorships.get(key).cloned());
        }
        self.entry_sponsorships.remove(key)
    }

    /// Apply sponsorship to a newly created ledger entry owned by `sponsored`.
    pub fn apply_entry_sponsorship(
        &mut self,
        key: LedgerKey,
        sponsored: &AccountId,
        multiplier: i64,
    ) -> Result<Option<AccountId>> {
        let Some(sponsor) = self.active_sponsor_for(sponsored) else {
            return Ok(None);
        };
        self.apply_entry_sponsorship_with_sponsor(key, &sponsor, Some(sponsored), multiplier)?;
        Ok(Some(sponsor))
    }

    /// Apply sponsorship for a ledger entry with a known sponsor.
    pub fn apply_entry_sponsorship_with_sponsor(
        &mut self,
        key: LedgerKey,
        sponsor: &AccountId,
        sponsored: Option<&AccountId>,
        multiplier: i64,
    ) -> Result<()> {
        if multiplier < 0 {
            return Err(TxError::Internal(
                "negative sponsorship multiplier".to_string(),
            ));
        }
        self.set_entry_sponsor(key, sponsor.clone());
        self.update_num_sponsoring(sponsor, multiplier)?;
        if let Some(sponsored) = sponsored {
            self.update_num_sponsored(sponsored, multiplier)?;
        }
        Ok(())
    }

    /// Apply sponsorship to a newly created account entry (account not yet in state).
    pub fn apply_account_entry_sponsorship(
        &mut self,
        account: &mut AccountEntry,
        sponsor: &AccountId,
        multiplier: i64,
    ) -> Result<()> {
        if multiplier < 0 {
            return Err(TxError::Internal(
                "negative sponsorship multiplier".to_string(),
            ));
        }
        let ext = ensure_account_ext_v2(account);
        let updated = ext.num_sponsored as i64 + multiplier;
        if updated < 0 || updated > u32::MAX as i64 {
            return Err(TxError::Internal(
                "num_sponsored out of range".to_string(),
            ));
        }
        ext.num_sponsored = updated as u32;
        self.update_num_sponsoring(sponsor, multiplier)?;
        Ok(())
    }

    /// Remove sponsorship for a ledger entry and update account counts.
    pub fn remove_entry_sponsorship_and_update_counts(
        &mut self,
        key: &LedgerKey,
        sponsored: &AccountId,
        multiplier: i64,
    ) -> Result<Option<AccountId>> {
        let Some(sponsor) = self.remove_entry_sponsor(key) else {
            return Ok(None);
        };
        if multiplier < 0 {
            return Err(TxError::Internal(
                "negative sponsorship multiplier".to_string(),
            ));
        }
        self.update_num_sponsoring(&sponsor, -multiplier)?;
        self.update_num_sponsored(sponsored, -multiplier)?;
        Ok(Some(sponsor))
    }

    /// Remove sponsorship for a ledger entry with optional sponsored account.
    pub fn remove_entry_sponsorship_with_sponsor_counts(
        &mut self,
        key: &LedgerKey,
        sponsored: Option<&AccountId>,
        multiplier: i64,
    ) -> Result<Option<AccountId>> {
        let Some(sponsor) = self.remove_entry_sponsor(key) else {
            return Ok(None);
        };
        if multiplier < 0 {
            return Err(TxError::Internal(
                "negative sponsorship multiplier".to_string(),
            ));
        }
        self.update_num_sponsoring(&sponsor, -multiplier)?;
        if let Some(sponsored) = sponsored {
            self.update_num_sponsored(sponsored, -multiplier)?;
        }
        Ok(Some(sponsor))
    }

    /// Update num_sponsoring for an account.
    pub fn update_num_sponsoring(&mut self, account_id: &AccountId, delta: i64) -> Result<()> {
        let account = self
            .get_account_mut(account_id)
            .ok_or(TxError::SourceAccountNotFound)?;
        let ext = ensure_account_ext_v2(account);
        let updated = ext.num_sponsoring as i64 + delta;
        if updated < 0 || updated > u32::MAX as i64 {
            return Err(TxError::Internal(
                "num_sponsoring out of range".to_string(),
            ));
        }
        ext.num_sponsoring = updated as u32;
        Ok(())
    }

    /// Update num_sponsored for an account.
    pub fn update_num_sponsored(&mut self, account_id: &AccountId, delta: i64) -> Result<()> {
        let account = self
            .get_account_mut(account_id)
            .ok_or(TxError::SourceAccountNotFound)?;
        let ext = ensure_account_ext_v2(account);
        let updated = ext.num_sponsored as i64 + delta;
        if updated < 0 || updated > u32::MAX as i64 {
            return Err(TxError::Internal(
                "num_sponsored out of range".to_string(),
            ));
        }
        ext.num_sponsored = updated as u32;
        Ok(())
    }

    /// Get sponsorship counts (num_sponsoring, num_sponsored) for an account.
    pub fn sponsorship_counts_for_account(&self, account_id: &AccountId) -> Option<(i64, i64)> {
        self.get_account(account_id).map(sponsorship_counts)
    }

    fn ledger_entry_ext_for(&self, key: &LedgerKey) -> LedgerEntryExt {
        if let Some(sponsor) = self.entry_sponsorships.get(key) {
            LedgerEntryExt::V1(LedgerEntryExtensionV1 {
                sponsoring_id: SponsorshipDescriptor(Some(sponsor.clone())),
                ext: LedgerEntryExtensionV1Ext::V0,
            })
        } else {
            LedgerEntryExt::V0
        }
    }

    /// Load initial state from a ledger reader.
    pub fn load_from_reader<R: LedgerReader>(&mut self, reader: &R, keys: &[LedgerKey]) {
        for key in keys {
            if let Some(entry) = reader.get_entry(key) {
                self.load_entry(entry);
            }
        }
    }

    /// Load a single entry into the state manager.
    pub fn load_entry(&mut self, entry: LedgerEntry) {
        let sponsor = sponsorship_from_entry_ext(&entry);
        match entry.data {
            LedgerEntryData::Account(account) => {
                let key = account_id_to_bytes(&account.account_id);
                let ledger_key = LedgerKey::Account(LedgerKeyAccount {
                    account_id: account.account_id.clone(),
                });
                self.accounts.insert(key, account);
                if let Some(sponsor) = sponsor {
                    self.entry_sponsorships.insert(ledger_key, sponsor);
                }
            }
            LedgerEntryData::Trustline(trustline) => {
                let account_key = account_id_to_bytes(&trustline.account_id);
                let asset_key = AssetKey::from_trustline_asset(&trustline.asset);
                let ledger_key = LedgerKey::Trustline(LedgerKeyTrustLine {
                    account_id: trustline.account_id.clone(),
                    asset: trustline.asset.clone(),
                });
                self.trustlines.insert((account_key, asset_key), trustline);
                if let Some(sponsor) = sponsor {
                    self.entry_sponsorships.insert(ledger_key, sponsor);
                }
            }
            LedgerEntryData::Offer(offer) => {
                let seller_key = account_id_to_bytes(&offer.seller_id);
                let ledger_key = LedgerKey::Offer(LedgerKeyOffer {
                    seller_id: offer.seller_id.clone(),
                    offer_id: offer.offer_id,
                });
                self.offers.insert((seller_key, offer.offer_id), offer);
                if let Some(sponsor) = sponsor {
                    self.entry_sponsorships.insert(ledger_key, sponsor);
                }
            }
            LedgerEntryData::Data(data) => {
                let account_key = account_id_to_bytes(&data.account_id);
                let name = data_name_to_string(&data.data_name);
                let ledger_key = LedgerKey::Data(LedgerKeyData {
                    account_id: data.account_id.clone(),
                    data_name: data.data_name.clone(),
                });
                self.data_entries.insert((account_key, name), data);
                if let Some(sponsor) = sponsor {
                    self.entry_sponsorships.insert(ledger_key, sponsor);
                }
            }
            LedgerEntryData::ContractData(contract_data) => {
                let key = ContractDataKey::new(
                    contract_data.contract.clone(),
                    contract_data.key.clone(),
                    contract_data.durability.clone(),
                );
                let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
                    contract: contract_data.contract.clone(),
                    key: contract_data.key.clone(),
                    durability: contract_data.durability.clone(),
                });
                self.contract_data.insert(key, contract_data);
                if let Some(sponsor) = sponsor {
                    self.entry_sponsorships.insert(ledger_key, sponsor);
                }
            }
            LedgerEntryData::ContractCode(contract_code) => {
                let key = contract_code.hash.0;
                let ledger_key = LedgerKey::ContractCode(LedgerKeyContractCode {
                    hash: contract_code.hash.clone(),
                });
                self.contract_code.insert(key, contract_code);
                if let Some(sponsor) = sponsor {
                    self.entry_sponsorships.insert(ledger_key, sponsor);
                }
            }
            LedgerEntryData::Ttl(ttl) => {
                let key = ttl.key_hash.0;
                let ledger_key = LedgerKey::Ttl(LedgerKeyTtl {
                    key_hash: ttl.key_hash.clone(),
                });
                self.ttl_entries.insert(key, ttl);
                if let Some(sponsor) = sponsor {
                    self.entry_sponsorships.insert(ledger_key, sponsor);
                }
            }
            LedgerEntryData::ClaimableBalance(cb) => {
                let key = claimable_balance_id_to_bytes(&cb.balance_id);
                let ledger_key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
                    balance_id: cb.balance_id.clone(),
                });
                self.claimable_balances.insert(key, cb);
                if let Some(sponsor) = sponsor {
                    self.entry_sponsorships.insert(ledger_key, sponsor);
                }
            }
            LedgerEntryData::LiquidityPool(lp) => {
                let key = pool_id_to_bytes(&lp.liquidity_pool_id);
                let ledger_key = LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
                    liquidity_pool_id: lp.liquidity_pool_id.clone(),
                });
                self.liquidity_pools.insert(key, lp);
                if let Some(sponsor) = sponsor {
                    self.entry_sponsorships.insert(ledger_key, sponsor);
                }
            }
            _ => {}
        }
    }

    // ==================== Account Operations ====================

    /// Load an account by ID and return a reference to it.
    ///
    /// This method is useful when you need to load an account from external storage
    /// and then access it.
    pub fn load_account(&mut self, account_id: &AccountId) -> Option<&AccountEntry> {
        let key = account_id_to_bytes(account_id);
        self.accounts.get(&key)
    }

    /// Get an account by ID (read-only).
    pub fn get_account(&self, account_id: &AccountId) -> Option<&AccountEntry> {
        let key = account_id_to_bytes(account_id);
        self.accounts.get(&key)
    }

    /// Get a mutable reference to an account by ID.
    ///
    /// This automatically tracks the modification for the delta.
    pub fn get_account_mut(&mut self, account_id: &AccountId) -> Option<&mut AccountEntry> {
        let key = account_id_to_bytes(account_id);
        if self.accounts.contains_key(&key) {
            // Save snapshot if not already saved
            if !self.account_snapshots.contains_key(&key) {
                let snapshot = self.accounts.get(&key).cloned();
                self.account_snapshots.insert(key, snapshot);
            }
            // Track modification
            if !self.modified_accounts.contains(&key) {
                self.modified_accounts.push(key);
            }
            self.accounts.get_mut(&key)
        } else {
            None
        }
    }

    /// Create a new account entry.
    pub fn create_account(&mut self, entry: AccountEntry) {
        let key = account_id_to_bytes(&entry.account_id);

        // Save snapshot (None because it didn't exist)
        if !self.account_snapshots.contains_key(&key) {
            self.account_snapshots.insert(key, None);
        }

        // Record in delta
        let ledger_entry = self.account_to_ledger_entry(&entry);
        self.delta.record_create(ledger_entry);

        // Insert into state
        self.accounts.insert(key, entry);

        // Track modification
        if !self.modified_accounts.contains(&key) {
            self.modified_accounts.push(key);
        }
    }

    /// Update an existing account entry.
    pub fn update_account(&mut self, entry: AccountEntry) {
        let key = account_id_to_bytes(&entry.account_id);

        // Save snapshot if not already saved
        if !self.account_snapshots.contains_key(&key) {
            let snapshot = self.accounts.get(&key).cloned();
            self.account_snapshots.insert(key, snapshot);
        }

        // Record in delta
        let ledger_entry = self.account_to_ledger_entry(&entry);
        self.delta.record_update(ledger_entry);

        // Update state
        self.accounts.insert(key, entry);

        // Track modification
        if !self.modified_accounts.contains(&key) {
            self.modified_accounts.push(key);
        }
    }

    /// Delete an account entry.
    pub fn delete_account(&mut self, account_id: &AccountId) {
        let key = account_id_to_bytes(account_id);

        // Save snapshot if not already saved
        if !self.account_snapshots.contains_key(&key) {
            let snapshot = self.accounts.get(&key).cloned();
            self.account_snapshots.insert(key, snapshot);
        }

        // Record in delta
        let ledger_key = LedgerKey::Account(LedgerKeyAccount {
            account_id: account_id.clone(),
        });
        self.delta.record_delete(ledger_key);

        // Remove from state
        self.accounts.remove(&key);
    }

    // ==================== Trustline Operations ====================

    /// Get a trustline by account and asset (read-only).
    pub fn get_trustline(&self, account_id: &AccountId, asset: &Asset) -> Option<&TrustLineEntry> {
        let account_key = account_id_to_bytes(account_id);
        let asset_key = AssetKey::from_asset(asset);
        self.trustlines.get(&(account_key, asset_key))
    }

    /// Get a trustline by account and trustline asset (read-only).
    pub fn get_trustline_by_trustline_asset(
        &self,
        account_id: &AccountId,
        asset: &TrustLineAsset,
    ) -> Option<&TrustLineEntry> {
        let account_key = account_id_to_bytes(account_id);
        let asset_key = AssetKey::from_trustline_asset(asset);
        self.trustlines.get(&(account_key, asset_key))
    }

    /// Get a mutable reference to a trustline by trustline asset.
    pub fn get_trustline_by_trustline_asset_mut(
        &mut self,
        account_id: &AccountId,
        asset: &TrustLineAsset,
    ) -> Option<&mut TrustLineEntry> {
        let account_key = account_id_to_bytes(account_id);
        let asset_key = AssetKey::from_trustline_asset(asset);
        let key = (account_key, asset_key.clone());

        if self.trustlines.contains_key(&key) {
            // Save snapshot if not already saved
            if !self.trustline_snapshots.contains_key(&key) {
                let snapshot = self.trustlines.get(&key).cloned();
                self.trustline_snapshots.insert(key.clone(), snapshot);
            }
            // Track modification
            if !self.modified_trustlines.contains(&key) {
                self.modified_trustlines.push(key.clone());
            }
            self.trustlines.get_mut(&key)
        } else {
            None
        }
    }

    /// Get a mutable reference to a trustline.
    pub fn get_trustline_mut(
        &mut self,
        account_id: &AccountId,
        asset: &Asset,
    ) -> Option<&mut TrustLineEntry> {
        let account_key = account_id_to_bytes(account_id);
        let asset_key = AssetKey::from_asset(asset);
        let key = (account_key, asset_key.clone());

        if self.trustlines.contains_key(&key) {
            // Save snapshot if not already saved
            if !self.trustline_snapshots.contains_key(&key) {
                let snapshot = self.trustlines.get(&key).cloned();
                self.trustline_snapshots.insert(key.clone(), snapshot);
            }
            // Track modification
            if !self.modified_trustlines.contains(&key) {
                self.modified_trustlines.push(key.clone());
            }
            self.trustlines.get_mut(&key)
        } else {
            None
        }
    }

    /// Create a new trustline entry.
    pub fn create_trustline(&mut self, entry: TrustLineEntry) {
        let account_key = account_id_to_bytes(&entry.account_id);
        let asset_key = AssetKey::from_trustline_asset(&entry.asset);
        let key = (account_key, asset_key.clone());

        // Save snapshot (None because it didn't exist)
        if !self.trustline_snapshots.contains_key(&key) {
            self.trustline_snapshots.insert(key.clone(), None);
        }

        // Record in delta
        let ledger_entry = self.trustline_to_ledger_entry(&entry);
        self.delta.record_create(ledger_entry);

        // Insert into state
        self.trustlines.insert(key.clone(), entry);

        // Track modification
        if !self.modified_trustlines.contains(&key) {
            self.modified_trustlines.push(key);
        }
    }

    /// Update an existing trustline entry.
    pub fn update_trustline(&mut self, entry: TrustLineEntry) {
        let account_key = account_id_to_bytes(&entry.account_id);
        let asset_key = AssetKey::from_trustline_asset(&entry.asset);
        let key = (account_key, asset_key.clone());

        // Save snapshot if not already saved
        if !self.trustline_snapshots.contains_key(&key) {
            let snapshot = self.trustlines.get(&key).cloned();
            self.trustline_snapshots.insert(key.clone(), snapshot);
        }

        // Record in delta
        let ledger_entry = self.trustline_to_ledger_entry(&entry);
        self.delta.record_update(ledger_entry);

        // Update state
        self.trustlines.insert(key.clone(), entry);

        // Track modification
        if !self.modified_trustlines.contains(&key) {
            self.modified_trustlines.push(key);
        }
    }

    /// Delete a trustline entry.
    pub fn delete_trustline(&mut self, account_id: &AccountId, asset: &Asset) {
        let account_key = account_id_to_bytes(account_id);
        let asset_key = AssetKey::from_asset(asset);
        let key = (account_key, asset_key.clone());

        // Save snapshot if not already saved
        if !self.trustline_snapshots.contains_key(&key) {
            let snapshot = self.trustlines.get(&key).cloned();
            self.trustline_snapshots.insert(key.clone(), snapshot);
        }

        // Record in delta
        let ledger_key = LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: account_id.clone(),
            asset: asset_to_trustline_asset(asset),
        });
        self.delta.record_delete(ledger_key);

        // Remove from state
        self.trustlines.remove(&key);
    }

    /// Delete a trustline entry by trustline asset.
    pub fn delete_trustline_by_trustline_asset(
        &mut self,
        account_id: &AccountId,
        asset: &TrustLineAsset,
    ) {
        let account_key = account_id_to_bytes(account_id);
        let asset_key = AssetKey::from_trustline_asset(asset);
        let key = (account_key, asset_key.clone());

        // Save snapshot if not already saved
        if !self.trustline_snapshots.contains_key(&key) {
            let snapshot = self.trustlines.get(&key).cloned();
            self.trustline_snapshots.insert(key.clone(), snapshot);
        }

        // Record in delta
        let ledger_key = LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: account_id.clone(),
            asset: asset.clone(),
        });
        self.delta.record_delete(ledger_key);

        // Remove from state
        self.trustlines.remove(&key);
    }

    // ==================== Offer Operations ====================

    /// Get an offer by seller and offer ID (read-only).
    pub fn get_offer(&self, seller_id: &AccountId, offer_id: i64) -> Option<&OfferEntry> {
        let seller_key = account_id_to_bytes(seller_id);
        self.offers.get(&(seller_key, offer_id))
    }

    /// Get a mutable reference to an offer.
    pub fn get_offer_mut(&mut self, seller_id: &AccountId, offer_id: i64) -> Option<&mut OfferEntry> {
        let seller_key = account_id_to_bytes(seller_id);
        let key = (seller_key, offer_id);

        if self.offers.contains_key(&key) {
            // Save snapshot if not already saved
            if !self.offer_snapshots.contains_key(&key) {
                let snapshot = self.offers.get(&key).cloned();
                self.offer_snapshots.insert(key, snapshot);
            }
            // Track modification
            if !self.modified_offers.contains(&key) {
                self.modified_offers.push(key);
            }
            self.offers.get_mut(&key)
        } else {
            None
        }
    }

    /// Create a new offer entry.
    pub fn create_offer(&mut self, entry: OfferEntry) {
        let seller_key = account_id_to_bytes(&entry.seller_id);
        let key = (seller_key, entry.offer_id);

        // Save snapshot (None because it didn't exist)
        if !self.offer_snapshots.contains_key(&key) {
            self.offer_snapshots.insert(key, None);
        }

        // Record in delta
        let ledger_entry = self.offer_to_ledger_entry(&entry);
        self.delta.record_create(ledger_entry);

        // Insert into state
        self.offers.insert(key, entry);

        // Track modification
        if !self.modified_offers.contains(&key) {
            self.modified_offers.push(key);
        }
    }

    /// Update an existing offer entry.
    pub fn update_offer(&mut self, entry: OfferEntry) {
        let seller_key = account_id_to_bytes(&entry.seller_id);
        let key = (seller_key, entry.offer_id);

        // Save snapshot if not already saved
        if !self.offer_snapshots.contains_key(&key) {
            let snapshot = self.offers.get(&key).cloned();
            self.offer_snapshots.insert(key, snapshot);
        }

        // Record in delta
        let ledger_entry = self.offer_to_ledger_entry(&entry);
        self.delta.record_update(ledger_entry);

        // Update state
        self.offers.insert(key, entry);

        // Track modification
        if !self.modified_offers.contains(&key) {
            self.modified_offers.push(key);
        }
    }

    /// Delete an offer entry.
    pub fn delete_offer(&mut self, seller_id: &AccountId, offer_id: i64) {
        let seller_key = account_id_to_bytes(seller_id);
        let key = (seller_key, offer_id);

        // Save snapshot if not already saved
        if !self.offer_snapshots.contains_key(&key) {
            let snapshot = self.offers.get(&key).cloned();
            self.offer_snapshots.insert(key, snapshot);
        }

        // Record in delta
        let ledger_key = LedgerKey::Offer(LedgerKeyOffer {
            seller_id: seller_id.clone(),
            offer_id,
        });
        self.delta.record_delete(ledger_key);

        // Remove from state
        self.offers.remove(&key);
    }

    /// Get the best offer for a buying/selling pair (lowest price, then offer ID).
    pub fn best_offer(&self, buying: &Asset, selling: &Asset) -> Option<OfferEntry> {
        self.offers
            .values()
            .filter(|offer| offer.buying == *buying && offer.selling == *selling)
            .min_by(|a, b| compare_offer(a, b))
            .cloned()
    }

    /// Get the best offer for a buying/selling pair with an additional filter.
    pub fn best_offer_filtered<F>(
        &self,
        buying: &Asset,
        selling: &Asset,
        mut keep: F,
    ) -> Option<OfferEntry>
    where
        F: FnMut(&OfferEntry) -> bool,
    {
        self.offers
            .values()
            .filter(|offer| offer.buying == *buying && offer.selling == *selling)
            .filter(|offer| keep(offer))
            .min_by(|a, b| compare_offer(a, b))
            .cloned()
    }

    // ==================== Data Entry Operations ====================

    /// Get a data entry by account and name (read-only).
    pub fn get_data(&self, account_id: &AccountId, name: &str) -> Option<&DataEntry> {
        let account_key = account_id_to_bytes(account_id);
        self.data_entries.get(&(account_key, name.to_string()))
    }

    /// Get a mutable reference to a data entry.
    pub fn get_data_mut(&mut self, account_id: &AccountId, name: &str) -> Option<&mut DataEntry> {
        let account_key = account_id_to_bytes(account_id);
        let key = (account_key, name.to_string());

        if self.data_entries.contains_key(&key) {
            // Save snapshot if not already saved
            if !self.data_snapshots.contains_key(&key) {
                let snapshot = self.data_entries.get(&key).cloned();
                self.data_snapshots.insert(key.clone(), snapshot);
            }
            // Track modification
            if !self.modified_data.contains(&key) {
                self.modified_data.push(key.clone());
            }
            self.data_entries.get_mut(&key)
        } else {
            None
        }
    }

    /// Create a new data entry.
    pub fn create_data(&mut self, entry: DataEntry) {
        let account_key = account_id_to_bytes(&entry.account_id);
        let name = data_name_to_string(&entry.data_name);
        let key = (account_key, name.clone());

        // Save snapshot (None because it didn't exist)
        if !self.data_snapshots.contains_key(&key) {
            self.data_snapshots.insert(key.clone(), None);
        }

        // Record in delta
        let ledger_entry = self.data_to_ledger_entry(&entry);
        self.delta.record_create(ledger_entry);

        // Insert into state
        self.data_entries.insert(key.clone(), entry);

        // Track modification
        if !self.modified_data.contains(&key) {
            self.modified_data.push(key);
        }
    }

    /// Update an existing data entry.
    pub fn update_data(&mut self, entry: DataEntry) {
        let account_key = account_id_to_bytes(&entry.account_id);
        let name = data_name_to_string(&entry.data_name);
        let key = (account_key, name.clone());

        // Save snapshot if not already saved
        if !self.data_snapshots.contains_key(&key) {
            let snapshot = self.data_entries.get(&key).cloned();
            self.data_snapshots.insert(key.clone(), snapshot);
        }

        // Record in delta
        let ledger_entry = self.data_to_ledger_entry(&entry);
        self.delta.record_update(ledger_entry);

        // Update state
        self.data_entries.insert(key.clone(), entry);

        // Track modification
        if !self.modified_data.contains(&key) {
            self.modified_data.push(key);
        }
    }

    /// Delete a data entry.
    pub fn delete_data(&mut self, account_id: &AccountId, name: &str) {
        let account_key = account_id_to_bytes(account_id);
        let key = (account_key, name.to_string());

        // Save snapshot if not already saved
        if !self.data_snapshots.contains_key(&key) {
            let snapshot = self.data_entries.get(&key).cloned();
            self.data_snapshots.insert(key.clone(), snapshot);
        }

        // Record in delta - we need to get the data_name from the entry
        if let Some(entry) = self.data_entries.get(&key) {
            let ledger_key = LedgerKey::Data(LedgerKeyData {
                account_id: account_id.clone(),
                data_name: entry.data_name.clone(),
            });
            self.delta.record_delete(ledger_key);
        }

        // Remove from state
        self.data_entries.remove(&key);
    }

    // ==================== Contract Data Operations ====================

    /// Get a contract data entry by key (read-only).
    pub fn get_contract_data(
        &self,
        contract: &ScAddress,
        key: &ScVal,
        durability: ContractDataDurability,
    ) -> Option<&ContractDataEntry> {
        let lookup_key = ContractDataKey::new(contract.clone(), key.clone(), durability);
        self.contract_data.get(&lookup_key)
    }

    /// Get a mutable reference to a contract data entry.
    pub fn get_contract_data_mut(
        &mut self,
        contract: &ScAddress,
        key: &ScVal,
        durability: ContractDataDurability,
    ) -> Option<&mut ContractDataEntry> {
        let lookup_key = ContractDataKey::new(contract.clone(), key.clone(), durability);

        if self.contract_data.contains_key(&lookup_key) {
            // Save snapshot if not already saved
            if !self.contract_data_snapshots.contains_key(&lookup_key) {
                let snapshot = self.contract_data.get(&lookup_key).cloned();
                self.contract_data_snapshots.insert(lookup_key.clone(), snapshot);
            }
            // Track modification
            if !self.modified_contract_data.contains(&lookup_key) {
                self.modified_contract_data.push(lookup_key.clone());
            }
            self.contract_data.get_mut(&lookup_key)
        } else {
            None
        }
    }

    /// Create a new contract data entry.
    pub fn create_contract_data(&mut self, entry: ContractDataEntry) {
        let key = ContractDataKey::new(
            entry.contract.clone(),
            entry.key.clone(),
            entry.durability.clone(),
        );

        // Save snapshot (None because it didn't exist)
        if !self.contract_data_snapshots.contains_key(&key) {
            self.contract_data_snapshots.insert(key.clone(), None);
        }

        // Record in delta
        let ledger_entry = self.contract_data_to_ledger_entry(&entry);
        self.delta.record_create(ledger_entry);

        // Insert into state
        self.contract_data.insert(key.clone(), entry);

        // Track modification
        if !self.modified_contract_data.contains(&key) {
            self.modified_contract_data.push(key);
        }
    }

    /// Update an existing contract data entry.
    pub fn update_contract_data(&mut self, entry: ContractDataEntry) {
        let key = ContractDataKey::new(
            entry.contract.clone(),
            entry.key.clone(),
            entry.durability.clone(),
        );

        // Save snapshot if not already saved
        if !self.contract_data_snapshots.contains_key(&key) {
            let snapshot = self.contract_data.get(&key).cloned();
            self.contract_data_snapshots.insert(key.clone(), snapshot);
        }

        // Record in delta
        let ledger_entry = self.contract_data_to_ledger_entry(&entry);
        self.delta.record_update(ledger_entry);

        // Update state
        self.contract_data.insert(key.clone(), entry);

        // Track modification
        if !self.modified_contract_data.contains(&key) {
            self.modified_contract_data.push(key);
        }
    }

    /// Delete a contract data entry.
    pub fn delete_contract_data(
        &mut self,
        contract: &ScAddress,
        key: &ScVal,
        durability: ContractDataDurability,
    ) {
        let lookup_key = ContractDataKey::new(contract.clone(), key.clone(), durability.clone());

        // Save snapshot if not already saved
        if !self.contract_data_snapshots.contains_key(&lookup_key) {
            let snapshot = self.contract_data.get(&lookup_key).cloned();
            self.contract_data_snapshots.insert(lookup_key.clone(), snapshot);
        }

        // Record in delta
        let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: contract.clone(),
            key: key.clone(),
            durability,
        });
        self.delta.record_delete(ledger_key);

        // Remove from state
        self.contract_data.remove(&lookup_key);
    }

    // ==================== Contract Code Operations ====================

    /// Get a contract code entry by hash (read-only).
    pub fn get_contract_code(&self, hash: &Hash) -> Option<&ContractCodeEntry> {
        self.contract_code.get(&hash.0)
    }

    /// Get a mutable reference to a contract code entry.
    pub fn get_contract_code_mut(&mut self, hash: &Hash) -> Option<&mut ContractCodeEntry> {
        let key = hash.0;

        if self.contract_code.contains_key(&key) {
            // Save snapshot if not already saved
            if !self.contract_code_snapshots.contains_key(&key) {
                let snapshot = self.contract_code.get(&key).cloned();
                self.contract_code_snapshots.insert(key, snapshot);
            }
            // Track modification
            if !self.modified_contract_code.contains(&key) {
                self.modified_contract_code.push(key);
            }
            self.contract_code.get_mut(&key)
        } else {
            None
        }
    }

    /// Create a new contract code entry.
    pub fn create_contract_code(&mut self, entry: ContractCodeEntry) {
        let key = entry.hash.0;

        // Save snapshot (None because it didn't exist)
        if !self.contract_code_snapshots.contains_key(&key) {
            self.contract_code_snapshots.insert(key, None);
        }

        // Record in delta
        let ledger_entry = self.contract_code_to_ledger_entry(&entry);
        self.delta.record_create(ledger_entry);

        // Insert into state
        self.contract_code.insert(key, entry);

        // Track modification
        if !self.modified_contract_code.contains(&key) {
            self.modified_contract_code.push(key);
        }
    }

    /// Update an existing contract code entry.
    pub fn update_contract_code(&mut self, entry: ContractCodeEntry) {
        let key = entry.hash.0;

        // Save snapshot if not already saved
        if !self.contract_code_snapshots.contains_key(&key) {
            let snapshot = self.contract_code.get(&key).cloned();
            self.contract_code_snapshots.insert(key, snapshot);
        }

        // Record in delta
        let ledger_entry = self.contract_code_to_ledger_entry(&entry);
        self.delta.record_update(ledger_entry);

        // Update state
        self.contract_code.insert(key, entry);

        // Track modification
        if !self.modified_contract_code.contains(&key) {
            self.modified_contract_code.push(key);
        }
    }

    /// Delete a contract code entry.
    pub fn delete_contract_code(&mut self, hash: &Hash) {
        let key = hash.0;

        // Save snapshot if not already saved
        if !self.contract_code_snapshots.contains_key(&key) {
            let snapshot = self.contract_code.get(&key).cloned();
            self.contract_code_snapshots.insert(key, snapshot);
        }

        // Record in delta
        let ledger_key = LedgerKey::ContractCode(LedgerKeyContractCode { hash: hash.clone() });
        self.delta.record_delete(ledger_key);

        // Remove from state
        self.contract_code.remove(&key);
    }

    // ==================== TTL Entry Operations ====================

    /// Get a TTL entry by key hash (read-only).
    pub fn get_ttl(&self, key_hash: &Hash) -> Option<&TtlEntry> {
        self.ttl_entries.get(&key_hash.0)
    }

    /// Get a mutable reference to a TTL entry.
    pub fn get_ttl_mut(&mut self, key_hash: &Hash) -> Option<&mut TtlEntry> {
        let key = key_hash.0;

        if self.ttl_entries.contains_key(&key) {
            // Save snapshot if not already saved
            if !self.ttl_snapshots.contains_key(&key) {
                let snapshot = self.ttl_entries.get(&key).cloned();
                self.ttl_snapshots.insert(key, snapshot);
            }
            // Track modification
            if !self.modified_ttl.contains(&key) {
                self.modified_ttl.push(key);
            }
            self.ttl_entries.get_mut(&key)
        } else {
            None
        }
    }

    /// Create a new TTL entry.
    pub fn create_ttl(&mut self, entry: TtlEntry) {
        let key = entry.key_hash.0;

        // Save snapshot (None because it didn't exist)
        if !self.ttl_snapshots.contains_key(&key) {
            self.ttl_snapshots.insert(key, None);
        }

        // Record in delta
        let ledger_entry = self.ttl_to_ledger_entry(&entry);
        self.delta.record_create(ledger_entry);

        // Insert into state
        self.ttl_entries.insert(key, entry);

        // Track modification
        if !self.modified_ttl.contains(&key) {
            self.modified_ttl.push(key);
        }
    }

    /// Update an existing TTL entry.
    pub fn update_ttl(&mut self, entry: TtlEntry) {
        let key = entry.key_hash.0;

        // Save snapshot if not already saved
        if !self.ttl_snapshots.contains_key(&key) {
            let snapshot = self.ttl_entries.get(&key).cloned();
            self.ttl_snapshots.insert(key, snapshot);
        }

        // Record in delta
        let ledger_entry = self.ttl_to_ledger_entry(&entry);
        self.delta.record_update(ledger_entry);

        // Update state
        self.ttl_entries.insert(key, entry);

        // Track modification
        if !self.modified_ttl.contains(&key) {
            self.modified_ttl.push(key);
        }
    }

    /// Extend the TTL of an entry to the specified ledger sequence.
    pub fn extend_ttl(&mut self, key_hash: &Hash, live_until_ledger_seq: u32) {
        let key = key_hash.0;

        if let Some(ttl_entry) = self.ttl_entries.get(&key).cloned() {
            // Only extend if the new TTL is greater
            if live_until_ledger_seq > ttl_entry.live_until_ledger_seq {
                // Save snapshot if not already saved
                if !self.ttl_snapshots.contains_key(&key) {
                    self.ttl_snapshots.insert(key, Some(ttl_entry.clone()));
                }

                // Create updated entry
                let updated = TtlEntry {
                    key_hash: ttl_entry.key_hash,
                    live_until_ledger_seq,
                };

                // Record in delta
                let ledger_entry = self.ttl_to_ledger_entry(&updated);
                self.delta.record_update(ledger_entry);

                // Update state
                self.ttl_entries.insert(key, updated);

                // Track modification
                if !self.modified_ttl.contains(&key) {
                    self.modified_ttl.push(key);
                }
            }
        }
    }

    /// Delete a TTL entry.
    pub fn delete_ttl(&mut self, key_hash: &Hash) {
        let key = key_hash.0;

        // Save snapshot if not already saved
        if !self.ttl_snapshots.contains_key(&key) {
            let snapshot = self.ttl_entries.get(&key).cloned();
            self.ttl_snapshots.insert(key, snapshot);
        }

        // Record in delta
        let ledger_key = LedgerKey::Ttl(LedgerKeyTtl {
            key_hash: key_hash.clone(),
        });
        self.delta.record_delete(ledger_key);

        // Remove from state
        self.ttl_entries.remove(&key);
    }

    /// Check if a TTL entry is live (not expired).
    pub fn is_entry_live(&self, key_hash: &Hash) -> bool {
        if let Some(ttl) = self.get_ttl(key_hash) {
            ttl.live_until_ledger_seq >= self.ledger_seq
        } else {
            false
        }
    }

    // ==================== Claimable Balance Operations ====================

    /// Get a claimable balance by ID (read-only).
    pub fn get_claimable_balance(
        &self,
        balance_id: &ClaimableBalanceId,
    ) -> Option<&ClaimableBalanceEntry> {
        let key = claimable_balance_id_to_bytes(balance_id);
        self.claimable_balances.get(&key)
    }

    /// Create a new claimable balance entry.
    pub fn create_claimable_balance(&mut self, entry: ClaimableBalanceEntry) {
        let key = claimable_balance_id_to_bytes(&entry.balance_id);

        // Save snapshot (None because it didn't exist)
        if !self.claimable_balance_snapshots.contains_key(&key) {
            self.claimable_balance_snapshots.insert(key, None);
        }

        // Record in delta
        let ledger_entry = self.claimable_balance_to_ledger_entry(&entry);
        self.delta.record_create(ledger_entry);

        // Insert into state
        self.claimable_balances.insert(key, entry);

        // Track modification
        if !self.modified_claimable_balances.contains(&key) {
            self.modified_claimable_balances.push(key);
        }
    }

    /// Delete a claimable balance entry (when claimed).
    pub fn delete_claimable_balance(&mut self, balance_id: &ClaimableBalanceId) {
        let key = claimable_balance_id_to_bytes(balance_id);

        // Save snapshot if not already saved
        if !self.claimable_balance_snapshots.contains_key(&key) {
            let snapshot = self.claimable_balances.get(&key).cloned();
            self.claimable_balance_snapshots.insert(key, snapshot);
        }

        // Record in delta
        let ledger_key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
            balance_id: balance_id.clone(),
        });
        self.delta.record_delete(ledger_key);

        // Remove from state
        self.claimable_balances.remove(&key);
    }

    /// Update an existing claimable balance entry.
    pub fn update_claimable_balance(&mut self, entry: ClaimableBalanceEntry) {
        let key = claimable_balance_id_to_bytes(&entry.balance_id);

        // Save snapshot if not already saved
        if !self.claimable_balance_snapshots.contains_key(&key) {
            let snapshot = self.claimable_balances.get(&key).cloned();
            self.claimable_balance_snapshots.insert(key, snapshot);
        }

        // Record in delta
        let ledger_entry = self.claimable_balance_to_ledger_entry(&entry);
        self.delta.record_update(ledger_entry);

        // Update state
        self.claimable_balances.insert(key, entry);

        // Track modification
        if !self.modified_claimable_balances.contains(&key) {
            self.modified_claimable_balances.push(key);
        }
    }

    // ==================== Liquidity Pool Operations ====================

    /// Get a liquidity pool by ID (read-only).
    pub fn get_liquidity_pool(&self, pool_id: &PoolId) -> Option<&LiquidityPoolEntry> {
        let key = pool_id_to_bytes(pool_id);
        self.liquidity_pools.get(&key)
    }

    /// Get a mutable reference to a liquidity pool.
    pub fn get_liquidity_pool_mut(&mut self, pool_id: &PoolId) -> Option<&mut LiquidityPoolEntry> {
        let key = pool_id_to_bytes(pool_id);
        if self.liquidity_pools.contains_key(&key) {
            // Save snapshot if not already saved
            if !self.liquidity_pool_snapshots.contains_key(&key) {
                let snapshot = self.liquidity_pools.get(&key).cloned();
                self.liquidity_pool_snapshots.insert(key, snapshot);
            }
            // Track modification
            if !self.modified_liquidity_pools.contains(&key) {
                self.modified_liquidity_pools.push(key);
            }
            self.liquidity_pools.get_mut(&key)
        } else {
            None
        }
    }

    /// Create a new liquidity pool entry.
    pub fn create_liquidity_pool(&mut self, entry: LiquidityPoolEntry) {
        let key = pool_id_to_bytes(&entry.liquidity_pool_id);

        // Save snapshot (None because it didn't exist)
        if !self.liquidity_pool_snapshots.contains_key(&key) {
            self.liquidity_pool_snapshots.insert(key, None);
        }

        // Record in delta
        let ledger_entry = self.liquidity_pool_to_ledger_entry(&entry);
        self.delta.record_create(ledger_entry);

        // Insert into state
        self.liquidity_pools.insert(key, entry);

        // Track modification
        if !self.modified_liquidity_pools.contains(&key) {
            self.modified_liquidity_pools.push(key);
        }
    }

    /// Update an existing liquidity pool entry.
    pub fn update_liquidity_pool(&mut self, entry: LiquidityPoolEntry) {
        let key = pool_id_to_bytes(&entry.liquidity_pool_id);

        // Save snapshot if not already saved
        if !self.liquidity_pool_snapshots.contains_key(&key) {
            let snapshot = self.liquidity_pools.get(&key).cloned();
            self.liquidity_pool_snapshots.insert(key, snapshot);
        }

        // Record in delta
        let ledger_entry = self.liquidity_pool_to_ledger_entry(&entry);
        self.delta.record_update(ledger_entry);

        // Update state
        self.liquidity_pools.insert(key, entry);

        // Track modification
        if !self.modified_liquidity_pools.contains(&key) {
            self.modified_liquidity_pools.push(key);
        }
    }

    // ==================== Generic Entry Operations ====================

    /// Get an entry by LedgerKey (read-only).
    pub fn get_entry(&self, key: &LedgerKey) -> Option<LedgerEntry> {
        match key {
            LedgerKey::Account(k) => {
                self.get_account(&k.account_id)
                    .map(|e| self.account_to_ledger_entry(e))
            }
            LedgerKey::Trustline(k) => {
                let account_key = account_id_to_bytes(&k.account_id);
                let asset_key = AssetKey::from_trustline_asset(&k.asset);
                self.trustlines
                    .get(&(account_key, asset_key))
                    .map(|e| self.trustline_to_ledger_entry(e))
            }
            LedgerKey::Offer(k) => {
                self.get_offer(&k.seller_id, k.offer_id)
                    .map(|e| self.offer_to_ledger_entry(e))
            }
            LedgerKey::Data(k) => {
                let name = data_name_to_string(&k.data_name);
                self.get_data(&k.account_id, &name)
                    .map(|e| self.data_to_ledger_entry(e))
            }
            LedgerKey::ContractData(k) => {
                self.get_contract_data(&k.contract, &k.key, k.durability.clone())
                    .map(|e| self.contract_data_to_ledger_entry(e))
            }
            LedgerKey::ContractCode(k) => {
                self.get_contract_code(&k.hash)
                    .map(|e| self.contract_code_to_ledger_entry(e))
            }
            LedgerKey::Ttl(k) => {
                self.get_ttl(&k.key_hash)
                    .map(|e| self.ttl_to_ledger_entry(e))
            }
            LedgerKey::ClaimableBalance(k) => {
                self.get_claimable_balance(&k.balance_id)
                    .map(|e| self.claimable_balance_to_ledger_entry(e))
            }
            LedgerKey::LiquidityPool(k) => {
                self.get_liquidity_pool(&k.liquidity_pool_id)
                    .map(|e| self.liquidity_pool_to_ledger_entry(e))
            }
            _ => None,
        }
    }

    // ==================== Delta Operations ====================

    /// Get the current delta (read-only).
    pub fn delta(&self) -> &LedgerDelta {
        &self.delta
    }

    /// Get the current delta (mutable).
    pub fn delta_mut(&mut self) -> &mut LedgerDelta {
        &mut self.delta
    }

    /// Consume self and return the delta.
    pub fn take_delta(self) -> LedgerDelta {
        self.delta
    }

    /// Check if there are any pending changes.
    pub fn has_changes(&self) -> bool {
        self.delta.has_changes()
    }

    // ==================== Rollback Support ====================

    /// Rollback all changes since the state manager was created.
    ///
    /// This restores all entries to their original state and clears the delta.
    pub fn rollback(&mut self) {
        // Restore account snapshots
        for (key, snapshot) in self.account_snapshots.drain() {
            match snapshot {
                Some(entry) => {
                    self.accounts.insert(key, entry);
                }
                None => {
                    self.accounts.remove(&key);
                }
            }
        }

        // Restore trustline snapshots
        for (key, snapshot) in self.trustline_snapshots.drain() {
            match snapshot {
                Some(entry) => {
                    self.trustlines.insert(key, entry);
                }
                None => {
                    self.trustlines.remove(&key);
                }
            }
        }

        // Restore offer snapshots
        for (key, snapshot) in self.offer_snapshots.drain() {
            match snapshot {
                Some(entry) => {
                    self.offers.insert(key, entry);
                }
                None => {
                    self.offers.remove(&key);
                }
            }
        }

        // Restore data entry snapshots
        for (key, snapshot) in self.data_snapshots.drain() {
            match snapshot {
                Some(entry) => {
                    self.data_entries.insert(key, entry);
                }
                None => {
                    self.data_entries.remove(&key);
                }
            }
        }

        // Restore contract data snapshots
        for (key, snapshot) in self.contract_data_snapshots.drain() {
            match snapshot {
                Some(entry) => {
                    self.contract_data.insert(key, entry);
                }
                None => {
                    self.contract_data.remove(&key);
                }
            }
        }

        // Restore contract code snapshots
        for (key, snapshot) in self.contract_code_snapshots.drain() {
            match snapshot {
                Some(entry) => {
                    self.contract_code.insert(key, entry);
                }
                None => {
                    self.contract_code.remove(&key);
                }
            }
        }

        // Restore TTL entry snapshots
        for (key, snapshot) in self.ttl_snapshots.drain() {
            match snapshot {
                Some(entry) => {
                    self.ttl_entries.insert(key, entry);
                }
                None => {
                    self.ttl_entries.remove(&key);
                }
            }
        }

        // Restore claimable balance snapshots
        for (key, snapshot) in self.claimable_balance_snapshots.drain() {
            match snapshot {
                Some(entry) => {
                    self.claimable_balances.insert(key, entry);
                }
                None => {
                    self.claimable_balances.remove(&key);
                }
            }
        }

        // Restore liquidity pool snapshots
        for (key, snapshot) in self.liquidity_pool_snapshots.drain() {
            match snapshot {
                Some(entry) => {
                    self.liquidity_pools.insert(key, entry);
                }
                None => {
                    self.liquidity_pools.remove(&key);
                }
            }
        }

        // Restore entry sponsorship snapshots
        for (key, snapshot) in self.entry_sponsorship_snapshots.drain() {
            match snapshot {
                Some(entry) => {
                    self.entry_sponsorships.insert(key, entry);
                }
                None => {
                    self.entry_sponsorships.remove(&key);
                }
            }
        }

        // Clear modification tracking
        self.modified_accounts.clear();
        self.modified_trustlines.clear();
        self.modified_offers.clear();
        self.modified_data.clear();
        self.modified_contract_data.clear();
        self.modified_contract_code.clear();
        self.modified_ttl.clear();
        self.modified_claimable_balances.clear();
        self.modified_liquidity_pools.clear();

        // Reset delta
        self.delta = LedgerDelta::new(self.ledger_seq);
    }

    /// Commit changes by clearing snapshots (changes become permanent).
    pub fn commit(&mut self) {
        // Clear all snapshots
        self.account_snapshots.clear();
        self.trustline_snapshots.clear();
        self.offer_snapshots.clear();
        self.data_snapshots.clear();
        self.contract_data_snapshots.clear();
        self.contract_code_snapshots.clear();
        self.ttl_snapshots.clear();
        self.claimable_balance_snapshots.clear();
        self.liquidity_pool_snapshots.clear();
        self.entry_sponsorship_snapshots.clear();

        // Clear modification tracking
        self.modified_accounts.clear();
        self.modified_trustlines.clear();
        self.modified_offers.clear();
        self.modified_data.clear();
        self.modified_contract_data.clear();
        self.modified_contract_code.clear();
        self.modified_ttl.clear();
        self.modified_claimable_balances.clear();
        self.modified_liquidity_pools.clear();
    }

    // ==================== Helper Methods ====================

    /// Convert an AccountEntry to a LedgerEntry.
    fn account_to_ledger_entry(&self, entry: &AccountEntry) -> LedgerEntry {
        let ledger_key = LedgerKey::Account(LedgerKeyAccount {
            account_id: entry.account_id.clone(),
        });
        LedgerEntry {
            last_modified_ledger_seq: self.ledger_seq,
            data: LedgerEntryData::Account(entry.clone()),
            ext: self.ledger_entry_ext_for(&ledger_key),
        }
    }

    /// Convert a TrustLineEntry to a LedgerEntry.
    fn trustline_to_ledger_entry(&self, entry: &TrustLineEntry) -> LedgerEntry {
        let ledger_key = LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: entry.account_id.clone(),
            asset: entry.asset.clone(),
        });
        LedgerEntry {
            last_modified_ledger_seq: self.ledger_seq,
            data: LedgerEntryData::Trustline(entry.clone()),
            ext: self.ledger_entry_ext_for(&ledger_key),
        }
    }

    /// Convert an OfferEntry to a LedgerEntry.
    fn offer_to_ledger_entry(&self, entry: &OfferEntry) -> LedgerEntry {
        let ledger_key = LedgerKey::Offer(LedgerKeyOffer {
            seller_id: entry.seller_id.clone(),
            offer_id: entry.offer_id,
        });
        LedgerEntry {
            last_modified_ledger_seq: self.ledger_seq,
            data: LedgerEntryData::Offer(entry.clone()),
            ext: self.ledger_entry_ext_for(&ledger_key),
        }
    }

    /// Convert a DataEntry to a LedgerEntry.
    fn data_to_ledger_entry(&self, entry: &DataEntry) -> LedgerEntry {
        let ledger_key = LedgerKey::Data(LedgerKeyData {
            account_id: entry.account_id.clone(),
            data_name: entry.data_name.clone(),
        });
        LedgerEntry {
            last_modified_ledger_seq: self.ledger_seq,
            data: LedgerEntryData::Data(entry.clone()),
            ext: self.ledger_entry_ext_for(&ledger_key),
        }
    }

    /// Convert a ContractDataEntry to a LedgerEntry.
    fn contract_data_to_ledger_entry(&self, entry: &ContractDataEntry) -> LedgerEntry {
        let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: entry.contract.clone(),
            key: entry.key.clone(),
            durability: entry.durability.clone(),
        });
        LedgerEntry {
            last_modified_ledger_seq: self.ledger_seq,
            data: LedgerEntryData::ContractData(entry.clone()),
            ext: self.ledger_entry_ext_for(&ledger_key),
        }
    }

    /// Convert a ContractCodeEntry to a LedgerEntry.
    fn contract_code_to_ledger_entry(&self, entry: &ContractCodeEntry) -> LedgerEntry {
        let ledger_key = LedgerKey::ContractCode(LedgerKeyContractCode {
            hash: entry.hash.clone(),
        });
        LedgerEntry {
            last_modified_ledger_seq: self.ledger_seq,
            data: LedgerEntryData::ContractCode(entry.clone()),
            ext: self.ledger_entry_ext_for(&ledger_key),
        }
    }

    /// Convert a TtlEntry to a LedgerEntry.
    fn ttl_to_ledger_entry(&self, entry: &TtlEntry) -> LedgerEntry {
        let ledger_key = LedgerKey::Ttl(LedgerKeyTtl {
            key_hash: entry.key_hash.clone(),
        });
        LedgerEntry {
            last_modified_ledger_seq: self.ledger_seq,
            data: LedgerEntryData::Ttl(entry.clone()),
            ext: self.ledger_entry_ext_for(&ledger_key),
        }
    }

    /// Convert a ClaimableBalanceEntry to a LedgerEntry.
    fn claimable_balance_to_ledger_entry(&self, entry: &ClaimableBalanceEntry) -> LedgerEntry {
        let ledger_key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
            balance_id: entry.balance_id.clone(),
        });
        LedgerEntry {
            last_modified_ledger_seq: self.ledger_seq,
            data: LedgerEntryData::ClaimableBalance(entry.clone()),
            ext: self.ledger_entry_ext_for(&ledger_key),
        }
    }

    /// Convert a LiquidityPoolEntry to a LedgerEntry.
    fn liquidity_pool_to_ledger_entry(&self, entry: &LiquidityPoolEntry) -> LedgerEntry {
        let ledger_key = LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: entry.liquidity_pool_id.clone(),
        });
        LedgerEntry {
            last_modified_ledger_seq: self.ledger_seq,
            data: LedgerEntryData::LiquidityPool(entry.clone()),
            ext: self.ledger_entry_ext_for(&ledger_key),
        }
    }
}

// ==================== Helper Functions ====================

/// Convert an AccountId to its raw bytes.
fn account_id_to_bytes(account_id: &AccountId) -> [u8; 32] {
    match &account_id.0 {
        PublicKey::PublicKeyTypeEd25519(key) => key.0,
    }
}

/// Convert a String64 data name to a String.
fn data_name_to_string(name: &stellar_xdr::curr::String64) -> String {
    String::from_utf8_lossy(name.as_vec()).to_string()
}

/// Convert an Asset to a TrustLineAsset.
fn asset_to_trustline_asset(asset: &Asset) -> TrustLineAsset {
    match asset {
        Asset::Native => TrustLineAsset::Native,
        Asset::CreditAlphanum4(a) => TrustLineAsset::CreditAlphanum4(a.clone()),
        Asset::CreditAlphanum12(a) => TrustLineAsset::CreditAlphanum12(a.clone()),
    }
}

/// Convert a ClaimableBalanceId to its raw bytes.
fn claimable_balance_id_to_bytes(balance_id: &ClaimableBalanceId) -> [u8; 32] {
    match balance_id {
        ClaimableBalanceId::ClaimableBalanceIdTypeV0(hash) => hash.0,
    }
}

/// Convert a PoolId to its raw bytes.
fn pool_id_to_bytes(pool_id: &PoolId) -> [u8; 32] {
    pool_id.0.0
}

fn compare_offer(lhs: &OfferEntry, rhs: &OfferEntry) -> std::cmp::Ordering {
    compare_price(&lhs.price, &rhs.price).then_with(|| lhs.offer_id.cmp(&rhs.offer_id))
}

fn compare_price(lhs: &Price, rhs: &Price) -> std::cmp::Ordering {
    let lhs_value = i128::from(lhs.n) * i128::from(rhs.d);
    let rhs_value = i128::from(rhs.n) * i128::from(lhs.d);
    lhs_value.cmp(&rhs_value)
}

fn sponsorship_counts(account: &AccountEntry) -> (i64, i64) {
    match &account.ext {
        AccountEntryExt::V0 => (0, 0),
        AccountEntryExt::V1(v1) => match &v1.ext {
            AccountEntryExtensionV1Ext::V0 => (0, 0),
            AccountEntryExtensionV1Ext::V2(v2) => {
                (v2.num_sponsoring as i64, v2.num_sponsored as i64)
            }
        },
    }
}

fn sponsorship_from_entry_ext(entry: &LedgerEntry) -> Option<AccountId> {
    match &entry.ext {
        LedgerEntryExt::V0 => None,
        LedgerEntryExt::V1(v1) => v1.sponsoring_id.0.clone(),
    }
}

pub(crate) fn ensure_account_ext_v2(account: &mut AccountEntry) -> &mut AccountEntryExtensionV2 {
    let liabilities = match &account.ext {
        AccountEntryExt::V1(v1) => v1.liabilities.clone(),
        AccountEntryExt::V0 => Liabilities { buying: 0, selling: 0 },
    };

    match &account.ext {
        AccountEntryExt::V0 => {
            account.ext = AccountEntryExt::V1(AccountEntryExtensionV1 {
                liabilities,
                ext: AccountEntryExtensionV1Ext::V2(AccountEntryExtensionV2 {
                    num_sponsored: 0,
                    num_sponsoring: 0,
                    signer_sponsoring_i_ds: build_signer_sponsoring_ids(account.signers.len()),
                    ext: AccountEntryExtensionV2Ext::V0,
                }),
            });
        }
        AccountEntryExt::V1(v1) => {
            if matches!(v1.ext, AccountEntryExtensionV1Ext::V0) {
                account.ext = AccountEntryExt::V1(AccountEntryExtensionV1 {
                    liabilities,
                    ext: AccountEntryExtensionV1Ext::V2(AccountEntryExtensionV2 {
                        num_sponsored: 0,
                        num_sponsoring: 0,
                        signer_sponsoring_i_ds: build_signer_sponsoring_ids(account.signers.len()),
                        ext: AccountEntryExtensionV2Ext::V0,
                    }),
                });
            }
        }
    }

    if let AccountEntryExt::V1(v1) = &mut account.ext {
        if let AccountEntryExtensionV1Ext::V2(v2) = &mut v1.ext {
            ensure_signer_sponsoring_ids(v2, account.signers.len());
            return v2;
        }
    }

    unreachable!("account ext v2 should exist after ensure_account_ext_v2")
}

fn build_signer_sponsoring_ids(count: usize) -> VecM<SponsorshipDescriptor, 20> {
    let ids = vec![SponsorshipDescriptor(None); count];
    ids.try_into().unwrap_or_default()
}

fn ensure_signer_sponsoring_ids(v2: &mut AccountEntryExtensionV2, signer_count: usize) {
    let mut ids: Vec<SponsorshipDescriptor> = v2.signer_sponsoring_i_ds.iter().cloned().collect();
    if ids.len() < signer_count {
        ids.extend(std::iter::repeat(SponsorshipDescriptor(None)).take(signer_count - ids.len()));
    } else if ids.len() > signer_count {
        ids.truncate(signer_count);
    }
    v2.signer_sponsoring_i_ds = ids.try_into().unwrap_or_default();
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    fn create_test_account_id(seed: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([seed; 32])))
    }

    fn create_test_account_entry(seed: u8) -> AccountEntry {
        AccountEntry {
            account_id: create_test_account_id(seed),
            balance: 1000000000,
            seq_num: SequenceNumber(1),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: vec![].try_into().unwrap(),
            ext: AccountEntryExt::V0,
        }
    }

    #[test]
    fn test_state_manager_creation() {
        let manager = LedgerStateManager::new(5_000_000, 100);
        assert_eq!(manager.ledger_seq(), 100);
        assert_eq!(manager.base_reserve(), 5_000_000);
        assert!(!manager.has_changes());
    }

    #[test]
    fn test_minimum_balance() {
        let manager = LedgerStateManager::new(5_000_000, 100);
        let account = create_test_account_entry(1);
        // 0 sub-entries: (2 + 0) * 5_000_000 = 10_000_000
        assert_eq!(
            manager
                .minimum_balance_for_account(&account, 25, 0)
                .unwrap(),
            10_000_000
        );
        // 3 sub-entries: (2 + 3) * 5_000_000 = 25_000_000
        let mut account_with_subentries = account;
        account_with_subentries.num_sub_entries = 3;
        assert_eq!(
            manager
                .minimum_balance_for_account(&account_with_subentries, 25, 0)
                .unwrap(),
            25_000_000
        );
    }

    #[test]
    fn test_account_operations() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);
        let account = create_test_account_entry(1);
        let account_id = account.account_id.clone();

        // Create account
        manager.create_account(account.clone());
        assert!(manager.has_changes());
        assert!(manager.get_account(&account_id).is_some());

        // Update account
        let mut updated = account.clone();
        updated.balance = 2000000000;
        manager.update_account(updated);

        let stored = manager.get_account(&account_id).unwrap();
        assert_eq!(stored.balance, 2000000000);

        // Delete account
        manager.delete_account(&account_id);
        assert!(manager.get_account(&account_id).is_none());
    }

    #[test]
    fn test_rollback() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);
        let account = create_test_account_entry(1);
        let account_id = account.account_id.clone();

        // Create account
        manager.create_account(account.clone());
        assert!(manager.get_account(&account_id).is_some());

        // Rollback
        manager.rollback();
        assert!(manager.get_account(&account_id).is_none());
        assert!(!manager.has_changes());
    }

    #[test]
    fn test_commit() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);
        let account = create_test_account_entry(1);
        let account_id = account.account_id.clone();

        // Create account
        manager.create_account(account.clone());

        // Commit
        manager.commit();

        // Account should still exist
        assert!(manager.get_account(&account_id).is_some());

        // But snapshots should be cleared (can't rollback anymore)
        manager.rollback();
        assert!(manager.get_account(&account_id).is_some()); // Still there because commit cleared snapshots
    }

    #[test]
    fn test_take_delta() {
        let mut manager = LedgerStateManager::new(5_000_000, 100);
        let account = create_test_account_entry(1);

        manager.create_account(account);

        let delta = manager.take_delta();
        assert_eq!(delta.ledger_seq(), 100);
        assert!(delta.has_changes());
        assert_eq!(delta.created_entries().len(), 1);
    }

    #[test]
    fn test_asset_key() {
        let native_key = AssetKey::from_asset(&Asset::Native);
        assert!(matches!(native_key, AssetKey::Native));

        let alphanum4 = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: create_test_account_id(1),
        });
        let key4 = AssetKey::from_asset(&alphanum4);
        assert!(matches!(key4, AssetKey::CreditAlphanum4(_, _)));
    }
}
