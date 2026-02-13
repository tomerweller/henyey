use super::*;

impl LedgerStateManager {
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

    fn snapshot_entry_sponsorship_ext(&mut self, key: &LedgerKey) {
        if !self.entry_sponsorship_ext_snapshots.contains_key(key) {
            self.entry_sponsorship_ext_snapshots
                .insert(key.clone(), self.entry_sponsorship_ext.contains(key));
        }
    }

    fn snapshot_entry_sponsorship_metadata(&mut self, key: &LedgerKey) {
        if !self.entry_sponsorship_snapshots.contains_key(key) {
            self.entry_sponsorship_snapshots
                .insert(key.clone(), self.entry_sponsorships.get(key).cloned());
        }
        self.snapshot_entry_sponsorship_ext(key);
    }

    pub(super) fn clear_entry_sponsorship_metadata(&mut self, key: &LedgerKey) {
        self.snapshot_entry_sponsorship_metadata(key);
        self.entry_sponsorships.remove(key);
        self.entry_sponsorship_ext.remove(key);
    }

    /// Set the sponsor for a ledger entry.
    pub fn set_entry_sponsor(&mut self, key: LedgerKey, sponsor: AccountId) {
        self.snapshot_entry_sponsorship_metadata(&key);
        self.capture_op_snapshot_for_key(&key);
        self.entry_sponsorships.insert(key.clone(), sponsor);
        self.entry_sponsorship_ext.insert(key);
    }

    /// Remove and return the sponsor for a ledger entry, if any.
    pub fn remove_entry_sponsor(&mut self, key: &LedgerKey) -> Option<AccountId> {
        self.snapshot_entry_sponsorship_metadata(key);
        self.capture_op_snapshot_for_key(key);
        self.entry_sponsorship_ext.insert(key.clone());
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
            return Err(TxError::Internal("num_sponsored out of range".to_string()));
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
    ///
    /// Lazily loads the account from the bucket list if not already in state.
    /// This is necessary because sponsored entries may reference a sponsor
    /// account that hasn't been loaded yet (e.g., during offer crossing when
    /// a sponsored offer is fully consumed and deleted).
    pub fn update_num_sponsoring(&mut self, account_id: &AccountId, delta: i64) -> Result<()> {
        self.ensure_account_loaded(account_id)?;
        let account = self
            .get_account_mut(account_id)
            .ok_or(TxError::SourceAccountNotFound)?;
        let ext = ensure_account_ext_v2(account);
        let updated = ext.num_sponsoring as i64 + delta;
        if updated < 0 || updated > u32::MAX as i64 {
            return Err(TxError::Internal("num_sponsoring out of range".to_string()));
        }
        ext.num_sponsoring = updated as u32;
        Ok(())
    }

    /// Update num_sponsored for an account.
    ///
    /// Lazily loads the account from the bucket list if not already in state.
    pub fn update_num_sponsored(&mut self, account_id: &AccountId, delta: i64) -> Result<()> {
        self.ensure_account_loaded(account_id)?;
        let account = self
            .get_account_mut(account_id)
            .ok_or(TxError::SourceAccountNotFound)?;
        let ext = ensure_account_ext_v2(account);
        let updated = ext.num_sponsored as i64 + delta;
        if updated < 0 || updated > u32::MAX as i64 {
            return Err(TxError::Internal("num_sponsored out of range".to_string()));
        }
        ext.num_sponsored = updated as u32;
        Ok(())
    }

    /// Get sponsorship counts (num_sponsoring, num_sponsored) for an account.
    pub fn sponsorship_counts_for_account(&self, account_id: &AccountId) -> Option<(i64, i64)> {
        self.get_account(account_id).map(sponsorship_counts)
    }

    /// Remove a one-time (pre-auth TX) signer from all source accounts in a transaction.
    ///
    /// Pre-auth TX signers are automatically consumed when a transaction they
    /// authorized is applied. This method removes the signer from all accounts
    /// that participated in the transaction.
    ///
    /// # Arguments
    ///
    /// * `tx_hash` - The transaction hash (used to create the signer key)
    /// * `source_accounts` - All source account IDs in the transaction
    /// * `protocol_version` - Current protocol version
    ///
    /// # Note
    ///
    /// This is a no-op for protocol version 7 (matches stellar-core behavior).
    pub fn remove_one_time_signers_from_all_sources(
        &mut self,
        tx_hash: &henyey_common::Hash256,
        source_accounts: &[AccountId],
        protocol_version: u32,
    ) {
        // Protocol 7 bypass (matches stellar-core behavior)
        if protocol_version == 7 {
            return;
        }

        // Create the pre-auth TX signer key from the transaction hash
        let signer_key =
            stellar_xdr::curr::SignerKey::PreAuthTx(stellar_xdr::curr::Uint256(tx_hash.0));

        // Remove from each source account
        for account_id in source_accounts {
            self.remove_account_signer(account_id, &signer_key);
        }
    }

    /// Remove a specific signer from an account.
    ///
    /// This handles the removal of any signer type and properly updates:
    /// - The signers vector
    /// - The num_sub_entries count
    /// - The sponsorship tracking (if the signer was sponsored)
    ///
    /// # Returns
    ///
    /// `true` if the signer was found and removed, `false` otherwise.
    pub fn remove_account_signer(
        &mut self,
        account_id: &AccountId,
        signer_key: &stellar_xdr::curr::SignerKey,
    ) -> bool {
        // Get mutable access to the account
        let Some(account) = self.get_account_mut(account_id) else {
            return false; // Account may have been removed (e.g., by merge)
        };

        // Find the signer index
        let signer_idx = account.signers.iter().position(|s| &s.key == signer_key);

        let Some(idx) = signer_idx else {
            return false; // Signer not found
        };

        // Remove the signer from the vec
        let mut new_signers: Vec<stellar_xdr::curr::Signer> =
            account.signers.iter().cloned().collect();
        new_signers.remove(idx);
        account.signers = new_signers.try_into().unwrap_or_default();

        // Decrement num_sub_entries
        if account.num_sub_entries > 0 {
            account.num_sub_entries -= 1;
        }

        // Handle sponsorship cleanup if applicable
        // The signer sponsorship is stored in the account's extension
        self.remove_signer_sponsorship(account_id, idx);

        true
    }

    /// Remove sponsorship tracking for a signer at the given index.
    ///
    /// When a signer is sponsored, the sponsoring account's ID is stored in
    /// the account's `signer_sponsoring_i_ds` vector (in AccountEntryExtensionV2).
    /// Removing a signer requires cleaning up this sponsorship relationship
    /// and updating the sponsor's `num_sponsoring` count.
    fn remove_signer_sponsorship(&mut self, account_id: &AccountId, signer_index: usize) {
        // Get the account to check for sponsorship
        let Some(account) = self.get_account(account_id) else {
            return;
        };

        // Check if the account has extension v2 with signer sponsorships
        let sponsor_id = match &account.ext {
            AccountEntryExt::V1(v1) => match &v1.ext {
                AccountEntryExtensionV1Ext::V2(v2) => {
                    // Check if this signer index has a sponsor
                    if signer_index < v2.signer_sponsoring_i_ds.len() {
                        v2.signer_sponsoring_i_ds[signer_index].0.clone()
                    } else {
                        None
                    }
                }
                AccountEntryExtensionV1Ext::V0 => None,
            },
            AccountEntryExt::V0 => None,
        };

        // If there was a sponsor, update the counts
        if let Some(sponsor) = sponsor_id {
            // Decrement sponsor's num_sponsoring
            if let Err(e) = self.update_num_sponsoring(&sponsor, -1) {
                // Log error but don't fail - this is cleanup
                tracing::warn!(
                    "Failed to update num_sponsoring during signer removal: {}",
                    e
                );
            }

            // Decrement sponsored account's num_sponsored
            if let Err(e) = self.update_num_sponsored(account_id, -1) {
                tracing::warn!(
                    "Failed to update num_sponsored during signer removal: {}",
                    e
                );
            }

            // Remove the sponsorship entry from signer_sponsoring_i_ds
            if let Some(account) = self.get_account_mut(account_id) {
                if let AccountEntryExt::V1(v1) = &mut account.ext {
                    if let AccountEntryExtensionV1Ext::V2(v2) = &mut v1.ext {
                        if signer_index < v2.signer_sponsoring_i_ds.len() {
                            let mut ids: Vec<_> =
                                v2.signer_sponsoring_i_ds.iter().cloned().collect();
                            ids.remove(signer_index);
                            v2.signer_sponsoring_i_ds = ids.try_into().unwrap_or_default();
                        }
                    }
                }
            }
        }
    }
}
