//! Ledger management for rs-stellar-core.
//!
//! This crate provides the core ledger state management and ledger close pipeline
//! for the Stellar network. It coordinates transaction execution, state updates,
//! bucket list modifications, and ledger metadata generation.
//!
//! # Architecture Overview
//!
//! The crate is organized around several key components:
//!
//! - [`LedgerManager`]: The central coordinator for all ledger operations
//! - [`LedgerCloseContext`]: Transaction context for closing a single ledger
//! - [`LedgerDelta`]: Accumulates state changes during ledger processing
//! - [`LedgerSnapshot`]: Point-in-time immutable view of ledger state
//!
//! # Ledger Close Process
//!
//! The ledger close process follows these steps:
//!
//! 1. **Receive externalized data**: SCP consensus provides a [`LedgerCloseData`]
//!    containing the transaction set, close time, and any protocol upgrades.
//!
//! 2. **Begin close**: [`LedgerManager::begin_close`] creates a [`LedgerCloseContext`]
//!    with a snapshot of the current state for consistent reads.
//!
//! 3. **Apply transactions**: Each transaction is executed in order, with state
//!    changes recorded in the [`LedgerDelta`].
//!
//! 4. **Update bucket list**: The delta is applied to the bucket list, computing
//!    the new Merkle root hash.
//!
//! 5. **Commit**: The new ledger header is constructed and the state is finalized.
//!
//! # State Model
//!
//! Ledger state consists of typed entries stored in the bucket list:
//!
//! - **Accounts**: XLM balances, sequence numbers, signers, thresholds
//! - **Trustlines**: Non-native asset balances and authorization
//! - **Offers**: Order book entries for the DEX
//! - **Data entries**: Arbitrary key-value data attached to accounts
//! - **Claimable balances**: Pending balance claims with predicates
//! - **Liquidity pools**: AMM pool state (Protocol 18+)
//! - **Contract data**: Soroban smart contract storage (Protocol 20+)
//! - **Contract code**: Soroban WASM bytecode (Protocol 20+)
//!
//! # Fee and Reserve Calculations
//!
//! The [`fees`] and [`reserves`] modules provide utilities for calculating:
//!
//! - Transaction fees based on operation count and base fee
//! - Account minimum balances based on sub-entries and sponsorship
//! - Available balance for spending (accounting for reserves and liabilities)
//!
//! # Example Usage
//!
//! ```ignore
//! use stellar_core_ledger::{LedgerManager, LedgerCloseData, TransactionSetVariant};
//!
//! // Create a ledger manager
//! let manager = LedgerManager::new(db, network_passphrase);
//!
//! // Initialize from buckets (during catchup)
//! manager.initialize_from_buckets(bucket_list, None, header, Some(header_hash))?;
//!
//! // Begin a ledger close
//! let close_data = LedgerCloseData::new(seq, tx_set, close_time, prev_hash);
//! let mut ctx = manager.begin_close(close_data)?;
//!
//! // Apply transactions (this handles fee charging and state updates)
//! let results = ctx.apply_transactions()?;
//!
//! // Commit the ledger and get the result
//! let result = ctx.commit()?;
//! println!("Closed ledger {}", result.ledger_seq());
//! ```
//!
//! # Protocol Compatibility
//!
//! This crate supports all Stellar protocol versions, with special handling for:
//!
//! - **Protocol 18**: Liquidity pools (AMM)
//! - **Protocol 20**: Soroban smart contracts
//! - **Protocol 23**: Hot archive bucket list for state archival

mod close;
pub mod config_upgrade;
mod delta;
mod error;
pub mod execution;
mod header;
mod manager;
pub mod offer;
mod snapshot;
mod soroban_state;

// Re-export main types
pub use close::{
    LedgerCloseData, LedgerCloseResult, LedgerCloseStats, TransactionSetVariant, UpgradeContext,
};
pub use config_upgrade::{ConfigUpgradeSetFrame, ConfigUpgradeValidity};
pub use delta::{entry_to_key, EntryChange, LedgerDelta};
pub use error::LedgerError;
pub use header::{
    close_time, compute_header_hash, compute_skip_list, create_next_header,
    is_before_protocol_version, protocol_version, skip_list_target_seq, verify_header_chain,
    verify_skip_list, SKIP_LIST_SIZE,
};
pub use execution::SorobanNetworkInfo;
pub use manager::{LedgerCloseContext, LedgerManager, LedgerManagerConfig, LedgerManagerStats};
pub use snapshot::{
    EntriesLookupFn, LedgerSnapshot, SnapshotBuilder, SnapshotHandle, SnapshotManager,
};
pub use soroban_state::{
    ContractCodeMapEntry, ContractDataMapEntry, InMemorySorobanState, SharedSorobanState,
    SorobanStateStats, TtlData,
};

/// Result type for ledger operations.
///
/// All fallible operations in this crate return this type, with errors
/// represented by [`LedgerError`].
pub type Result<T> = std::result::Result<T, LedgerError>;

/// Simplified view of the current ledger header.
///
/// This struct provides a convenient, flattened representation of the most
/// commonly needed ledger header fields. Use this when you need quick access
/// to ledger state without the full XDR `LedgerHeader` structure.
///
/// # Example
///
/// ```ignore
/// let header: LedgerHeader = /* ... */;
/// let info = LedgerInfo::from(&header);
/// println!("Ledger {} at protocol {}", info.sequence, info.protocol_version);
/// ```
#[derive(Debug, Clone)]
pub struct LedgerInfo {
    /// Ledger sequence number (monotonically increasing from genesis).
    pub sequence: u32,
    /// Hash of the previous ledger header (SHA-256).
    pub previous_ledger_hash: stellar_core_common::Hash256,
    /// Root hash of the bucket list Merkle tree.
    pub bucket_list_hash: stellar_core_common::Hash256,
    /// Ledger close time as a Unix timestamp (seconds since epoch).
    pub close_time: u64,
    /// Base fee per operation in stroops (1 stroop = 0.0000001 XLM).
    pub base_fee: u32,
    /// Base reserve per entry in stroops (typically 0.5 XLM = 5,000,000 stroops).
    pub base_reserve: u32,
    /// Protocol version number governing this ledger's behavior.
    pub protocol_version: u32,
}

impl From<&stellar_xdr::curr::LedgerHeader> for LedgerInfo {
    fn from(header: &stellar_xdr::curr::LedgerHeader) -> Self {
        Self {
            sequence: header.ledger_seq,
            previous_ledger_hash: stellar_core_common::Hash256::from(header.previous_ledger_hash.0),
            bucket_list_hash: stellar_core_common::Hash256::from(header.bucket_list_hash.0),
            close_time: header.scp_value.close_time.0,
            base_fee: header.base_fee,
            base_reserve: header.base_reserve,
            protocol_version: header.ledger_version,
        }
    }
}

/// A simplified representation of a ledger entry change.
///
/// This enum represents the three types of modifications that can occur
/// to ledger entries during transaction processing. It's a convenience
/// wrapper around the more detailed [`EntryChange`] type.
///
/// # Variants
///
/// - `Create`: A new entry that didn't exist before
/// - `Update`: An existing entry with modified values
/// - `Delete`: An entry that has been removed
#[derive(Debug, Clone)]
pub enum LedgerChange {
    /// A new entry was created (e.g., new account, trustline, or offer).
    Create(stellar_xdr::curr::LedgerEntry),
    /// An existing entry was modified (e.g., balance change, threshold update).
    Update(stellar_xdr::curr::LedgerEntry),
    /// An entry was deleted (e.g., account merge, offer fill, trustline removal).
    Delete(stellar_xdr::curr::LedgerKey),
}

/// Fee calculation utilities for transaction processing.
///
/// This module provides functions for computing transaction fees and checking
/// whether accounts have sufficient balance to pay fees. All fees are
/// denominated in stroops (1 XLM = 10,000,000 stroops).
///
/// # Fee Model
///
/// Stellar uses a simple fee model where fees are charged per operation:
///
/// - **Base fee**: Network-wide minimum fee per operation (typically 100 stroops)
/// - **Transaction fee**: `num_operations * base_fee` (minimum)
/// - **Surge pricing**: During high load, fees may exceed the base fee
///
/// The transaction's `fee` field represents the maximum the sender is willing
/// to pay. The actual charged fee is the minimum of this and the required fee.
pub mod fees {
    use stellar_xdr::curr::{AccountEntry, Transaction, TransactionEnvelope};

    /// Calculate the fee for a transaction.
    ///
    /// Computes the minimum required fee based on operation count and base fee.
    /// The actual charged fee is capped by the transaction's declared maximum.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to calculate fees for
    /// * `base_fee` - The network base fee per operation in stroops
    ///
    /// # Returns
    ///
    /// The fee amount in stroops that would be charged for this transaction.
    pub fn calculate_fee(tx: &Transaction, base_fee: u32) -> u64 {
        let num_ops = tx.operations.len() as u64;
        let min_fee = num_ops * base_fee as u64;

        // The transaction's fee field is the maximum the user is willing to pay
        std::cmp::min(tx.fee as u64, min_fee)
    }

    /// Calculate the fee for a transaction envelope.
    ///
    /// Handles all transaction envelope types (V0, V1, and fee bump).
    /// For fee bump transactions, uses the outer transaction's fee.
    ///
    /// # Arguments
    ///
    /// * `env` - The transaction envelope
    /// * `base_fee` - The network base fee per operation in stroops
    pub fn calculate_envelope_fee(env: &TransactionEnvelope, base_fee: u32) -> u64 {
        match env {
            TransactionEnvelope::TxV0(tx) => {
                let num_ops = tx.tx.operations.len() as u64;
                num_ops * base_fee as u64
            }
            TransactionEnvelope::Tx(tx) => calculate_fee(&tx.tx, base_fee),
            TransactionEnvelope::TxFeeBump(tx) => {
                // For fee bump, use the outer fee
                tx.tx.fee as u64
            }
        }
    }

    /// Check if an account can afford the fee.
    ///
    /// This checks the available balance (after accounting for selling liabilities)
    /// against the required fee amount.
    ///
    /// # Note
    ///
    /// This is a simplified check that doesn't account for minimum balance
    /// requirements. Use [`reserves::available_to_send`] for a complete check.
    pub fn can_afford_fee(account: &AccountEntry, fee: u64) -> bool {
        // Account must have enough XLM to pay the fee
        // considering selling liabilities
        let available = available_balance(account);
        available >= fee as i64
    }

    /// Calculate the available balance for fee payment.
    ///
    /// Returns the account balance minus selling liabilities. This represents
    /// the maximum amount that could be used for fees without affecting
    /// outstanding offers.
    ///
    /// # Note
    ///
    /// This does not subtract the minimum balance requirement. The returned
    /// value may exceed what's actually spendable.
    pub fn available_balance(account: &AccountEntry) -> i64 {
        let selling_liabilities = match &account.ext {
            stellar_xdr::curr::AccountEntryExt::V0 => 0,
            stellar_xdr::curr::AccountEntryExt::V1(v1) => v1.liabilities.selling,
        };

        // Available = balance - selling_liabilities
        // (reserves are checked separately)
        account.balance - selling_liabilities
    }
}

/// Reserve calculation utilities for account balance requirements.
///
/// This module provides functions for calculating minimum balance requirements
/// and available balances for Stellar accounts. These calculations are essential
/// for validating transactions and ensuring accounts maintain sufficient reserves.
///
/// # Reserve Model
///
/// Every Stellar account must maintain a minimum XLM balance based on:
///
/// - **Base entries**: Every account has 2 base entries (the account itself)
/// - **Sub-entries**: Each additional entry (trustline, offer, signer, data) adds 1
/// - **Sponsorship**: Sponsored entries reduce the owner's reserve requirement
///
/// The formula is: `(2 + num_sub_entries + num_sponsoring - num_sponsored) * base_reserve`
///
/// # Liabilities
///
/// Accounts also track buying and selling liabilities from open offers:
///
/// - **Selling liabilities**: XLM committed to sell in open offers
/// - **Buying liabilities**: XLM capacity reserved for incoming purchases
///
/// These affect the available balance for sending and receiving.
pub mod reserves {
    use stellar_xdr::curr::AccountEntry;

    /// Number of stroops per XLM (1 XLM = 10,000,000 stroops).
    pub const STROOPS_PER_XLM: i64 = 10_000_000;

    /// Calculate the minimum balance for an account.
    ///
    /// This is the amount of XLM that must be held in reserve and cannot
    /// be spent or sent. Attempting to reduce the balance below this
    /// threshold will fail.
    ///
    /// # Formula
    ///
    /// `(2 + num_sub_entries + num_sponsoring - num_sponsored) * base_reserve`
    ///
    /// # Arguments
    ///
    /// * `account` - The account to calculate minimum balance for
    /// * `base_reserve` - The network base reserve in stroops (typically 5,000,000)
    ///
    /// # Returns
    ///
    /// The minimum balance in stroops.
    pub fn minimum_balance(account: &AccountEntry, base_reserve: u32) -> i64 {
        let base = base_reserve as i64;

        // Get sponsorship info if available
        let (num_sponsoring, num_sponsored) = match &account.ext {
            stellar_xdr::curr::AccountEntryExt::V0 => (0, 0),
            stellar_xdr::curr::AccountEntryExt::V1(v1) => match &v1.ext {
                stellar_xdr::curr::AccountEntryExtensionV1Ext::V0 => (0, 0),
                stellar_xdr::curr::AccountEntryExtensionV1Ext::V2(v2) => {
                    (v2.num_sponsoring as i64, v2.num_sponsored as i64)
                }
            },
        };

        // Base account entries (2) + sub entries + sponsoring - sponsored
        let num_entries = 2 + account.num_sub_entries as i64 + num_sponsoring - num_sponsored;

        num_entries * base
    }

    /// Get the selling liabilities for an account's native (XLM) balance.
    ///
    /// Selling liabilities represent XLM that is committed to open sell offers
    /// and cannot be spent until those offers are cancelled or filled.
    ///
    /// # Returns
    ///
    /// The selling liabilities in stroops, or 0 for V0 accounts.
    pub fn selling_liabilities(account: &AccountEntry) -> i64 {
        match &account.ext {
            stellar_xdr::curr::AccountEntryExt::V0 => 0,
            stellar_xdr::curr::AccountEntryExt::V1(v1) => v1.liabilities.selling,
        }
    }

    /// Get the buying liabilities for an account's native (XLM) balance.
    ///
    /// Buying liabilities represent XLM that could be received from open buy
    /// offers. This affects how much additional XLM the account can receive
    /// before hitting the maximum balance.
    ///
    /// # Returns
    ///
    /// The buying liabilities in stroops, or 0 for V0 accounts.
    pub fn buying_liabilities(account: &AccountEntry) -> i64 {
        match &account.ext {
            stellar_xdr::curr::AccountEntryExt::V0 => 0,
            stellar_xdr::curr::AccountEntryExt::V1(v1) => v1.liabilities.buying,
        }
    }

    /// Calculate the available balance that can be sent from an account.
    ///
    /// This is the maximum amount of XLM that can be transferred out of the
    /// account while maintaining the minimum balance and honoring open offers.
    ///
    /// # Formula
    ///
    /// `balance - minimum_balance - selling_liabilities`
    ///
    /// # Returns
    ///
    /// The available balance in stroops. Returns 0 if the calculation would
    /// be negative (using saturating subtraction).
    pub fn available_to_send(account: &AccountEntry, base_reserve: u32) -> i64 {
        let min_bal = minimum_balance(account, base_reserve);
        let sell_liab = selling_liabilities(account);

        account
            .balance
            .saturating_sub(min_bal)
            .saturating_sub(sell_liab)
    }

    /// Calculate the available capacity to receive XLM.
    ///
    /// This is the maximum amount of XLM that can be received by the account
    /// before hitting the maximum balance limit (i64::MAX stroops).
    ///
    /// # Formula
    ///
    /// `i64::MAX - balance - buying_liabilities`
    ///
    /// # Returns
    ///
    /// The available receiving capacity in stroops.
    pub fn available_to_receive(account: &AccountEntry) -> i64 {
        let buy_liab = buying_liabilities(account);
        i64::MAX
            .saturating_sub(account.balance)
            .saturating_sub(buy_liab)
    }

    /// Check if an account can afford to add a new sub-entry.
    ///
    /// Adding a sub-entry (trustline, offer, signer, or data entry) increases
    /// the minimum balance requirement by one base reserve. This function
    /// checks whether the account has sufficient balance to support the new entry.
    ///
    /// # Arguments
    ///
    /// * `account` - The account to check
    /// * `base_reserve` - The network base reserve in stroops
    ///
    /// # Returns
    ///
    /// `true` if the account can afford the additional reserve requirement.
    pub fn can_add_sub_entry(account: &AccountEntry, base_reserve: u32) -> bool {
        let current_min = minimum_balance(account, base_reserve);
        let new_min = current_min + base_reserve as i64;
        let sell_liab = selling_liabilities(account);

        account.balance >= new_min + sell_liab
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        AccountEntry, AccountEntryExt, AccountId, PublicKey, SequenceNumber, Thresholds, Uint256,
    };

    fn create_test_account(balance: i64, num_sub_entries: u32) -> AccountEntry {
        AccountEntry {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32]))),
            balance,
            seq_num: SequenceNumber(1),
            num_sub_entries,
            inflation_dest: None,
            flags: 0,
            home_domain: stellar_xdr::curr::String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: stellar_xdr::curr::VecM::default(),
            ext: AccountEntryExt::V0,
        }
    }

    #[test]
    fn test_minimum_balance() {
        let account = create_test_account(100_000_000, 0);
        let base_reserve = 5_000_000; // 0.5 XLM

        // (2 + 0) * 5_000_000 = 10_000_000
        assert_eq!(
            reserves::minimum_balance(&account, base_reserve),
            10_000_000
        );

        let account2 = create_test_account(100_000_000, 3);
        // (2 + 3) * 5_000_000 = 25_000_000
        assert_eq!(
            reserves::minimum_balance(&account2, base_reserve),
            25_000_000
        );
    }

    #[test]
    fn test_available_to_send() {
        let account = create_test_account(100_000_000, 0);
        let base_reserve = 5_000_000;

        // 100_000_000 - 10_000_000 - 0 = 90_000_000
        assert_eq!(
            reserves::available_to_send(&account, base_reserve),
            90_000_000
        );
    }

    #[test]
    fn test_can_afford_fee() {
        let account = create_test_account(10_000, 0);
        assert!(fees::can_afford_fee(&account, 1000));
        assert!(fees::can_afford_fee(&account, 10_000));
        assert!(!fees::can_afford_fee(&account, 10_001));
    }
}
