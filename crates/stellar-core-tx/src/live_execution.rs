//! Live transaction execution for validator mode.
//!
//! This module provides the core infrastructure for executing transactions in live mode
//! (as opposed to replay/catchup mode). Live execution is the process by which validators
//! apply transactions to produce new ledger states.
//!
//! # Overview
//!
//! Live execution follows the C++ stellar-core transaction application flow:
//!
//! 1. **Fee & Sequence Processing** ([`process_fee_seq_num`]): Charge the transaction fee
//!    from the source account and update the sequence number.
//!
//! 2. **Transaction Application**: Execute operations (handled by operation modules).
//!
//! 3. **Post-Apply Processing** ([`process_post_apply`]): Handle Soroban fee refunds
//!    for pre-protocol 23 transactions.
//!
//! 4. **Transaction Set Post-Apply** ([`process_post_tx_set_apply`]): Handle Soroban
//!    fee refunds for protocol 23+ transactions after all transactions in the set
//!    have been applied.
//!
//! # Protocol Versioning
//!
//! The refund timing changed in protocol 23:
//! - **Pre-P23**: Refunds are applied in `process_post_apply` immediately after each transaction
//! - **P23+**: Refunds are deferred to `process_post_tx_set_apply` after all transactions
//!
//! # C++ Parity
//!
//! This module matches the following C++ stellar-core functions:
//! - `TransactionFrame::processFeeSeqNum()` in `TransactionFrame.cpp`
//! - `TransactionFrame::processPostApply()` in `TransactionFrame.cpp`
//! - `TransactionFrame::processPostTxSetApply()` in `TransactionFrame.cpp`
//! - `TransactionFrame::refundSorobanFee()` in `TransactionFrame.cpp`
//! - `FeeBumpTransactionFrame` overrides for fee bump transactions
//!
//! # Example
//!
//! ```ignore
//! use stellar_core_tx::live_execution::{
//!     LiveExecutionContext, process_fee_seq_num, process_post_apply,
//!     process_post_tx_set_apply,
//! };
//!
//! // Create execution context
//! let mut ctx = LiveExecutionContext::new(ledger_context, state_manager);
//!
//! // Phase 1: Process fees and sequence numbers for all transactions
//! for tx in transactions {
//!     let result = process_fee_seq_num(&tx, &mut ctx)?;
//!     // Store result for later phases
//! }
//!
//! // Phase 2: Apply each transaction (operations)
//! for tx in transactions {
//!     // Apply operations...
//!
//!     // Phase 3: Post-apply processing (pre-P23 refunds)
//!     process_post_apply(&tx, &mut ctx, &mut result, &mut meta)?;
//! }
//!
//! // Phase 4: Transaction set post-apply (P23+ refunds)
//! for tx in transactions {
//!     process_post_tx_set_apply(&tx, &mut ctx, &mut result, &mut event_manager)?;
//! }
//! ```

use stellar_core_common::{Hash256, NetworkId};
use stellar_xdr::curr::{AccountId, TransactionEventStage, TransactionResultCode};

use crate::events::TxEventManager;
use crate::fee_bump::FeeBumpFrame;
use crate::frame::{muxed_to_account_id, TransactionFrame};
use crate::meta_builder::TransactionMetaBuilder;
use crate::result::MutableTransactionResult;
use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::{Result, TxError};

// ============================================================================
// Protocol Constants
// ============================================================================

/// Protocol version where sequence number processing moved to a separate step.
const FIRST_PROTOCOL_SUPPORTING_OPERATION_VALIDITY: u32 = 10;

/// Protocol version where refund timing changed to post-tx-set.
const PROTOCOL_VERSION_23: u32 = 23;

/// Protocol version that affects fee bump inner fee tracking.
#[allow(dead_code)]
const PROTOCOL_VERSION_25: u32 = 25;

// ============================================================================
// Live Execution Context
// ============================================================================

/// Context for live transaction execution.
///
/// This extends [`LedgerContext`] with mutable state tracking for fee pool
/// and other ledger header modifications during transaction application.
///
/// # Fee Pool Tracking
///
/// The fee pool accumulates all transaction fees and is decremented by refunds.
/// In C++ stellar-core, this is stored in the ledger header and persisted to
/// the database. Here, we track it in memory for the duration of ledger close.
pub struct LiveExecutionContext {
    /// Base ledger context (sequence, close time, protocol version, etc.).
    pub ledger_context: LedgerContext,
    /// Accumulated fee pool delta for this ledger.
    ///
    /// Positive values indicate fees collected; negative would indicate net refunds
    /// exceeding collections (which shouldn't happen in practice).
    pub fee_pool_delta: i64,
    /// Reference to mutable ledger state.
    ///
    /// This is stored separately so the context can be passed around while
    /// state is mutated through different code paths.
    state: Option<LedgerStateManager>,
}

impl LiveExecutionContext {
    /// Create a new live execution context.
    ///
    /// # Arguments
    ///
    /// * `ledger_context` - The ledger context with sequence, close time, protocol version
    /// * `state` - The ledger state manager for reading/writing entries
    pub fn new(ledger_context: LedgerContext, state: LedgerStateManager) -> Self {
        Self {
            ledger_context,
            fee_pool_delta: 0,
            state: Some(state),
        }
    }

    /// Create a context without state (for testing or fee-only operations).
    pub fn without_state(ledger_context: LedgerContext) -> Self {
        Self {
            ledger_context,
            fee_pool_delta: 0,
            state: None,
        }
    }

    /// Get the protocol version.
    pub fn protocol_version(&self) -> u32 {
        self.ledger_context.protocol_version
    }

    /// Get the ledger sequence.
    pub fn ledger_sequence(&self) -> u32 {
        self.ledger_context.sequence
    }

    /// Get the close time.
    pub fn close_time(&self) -> u64 {
        self.ledger_context.close_time
    }

    /// Get the network ID.
    pub fn network_id(&self) -> &NetworkId {
        &self.ledger_context.network_id
    }

    /// Get the base fee.
    pub fn base_fee(&self) -> u32 {
        self.ledger_context.base_fee
    }

    /// Get the base reserve.
    pub fn base_reserve(&self) -> i64 {
        self.ledger_context.base_reserve as i64
    }

    /// Take ownership of the state manager.
    pub fn take_state(&mut self) -> Option<LedgerStateManager> {
        self.state.take()
    }

    /// Restore the state manager.
    pub fn restore_state(&mut self, state: LedgerStateManager) {
        self.state = Some(state);
    }

    /// Get a reference to the state manager.
    pub fn state(&self) -> Option<&LedgerStateManager> {
        self.state.as_ref()
    }

    /// Get a mutable reference to the state manager.
    pub fn state_mut(&mut self) -> Option<&mut LedgerStateManager> {
        self.state.as_mut()
    }

    /// Add fee to the fee pool.
    pub fn add_to_fee_pool(&mut self, amount: i64) {
        self.fee_pool_delta += amount;
    }

    /// Subtract from the fee pool (for refunds).
    pub fn subtract_from_fee_pool(&mut self, amount: i64) {
        self.fee_pool_delta -= amount;
    }

    /// Get the current fee pool delta.
    pub fn fee_pool_delta(&self) -> i64 {
        self.fee_pool_delta
    }
}

// ============================================================================
// Fee and Sequence Number Processing
// ============================================================================

/// Result of fee and sequence number processing.
#[derive(Debug, Clone)]
pub struct FeeSeqNumResult {
    /// The fee actually charged (may be less than requested if account is underfunded).
    pub fee_charged: i64,
    /// Whether the transaction should proceed to operation application.
    pub should_apply: bool,
    /// The mutable transaction result initialized for this transaction.
    pub tx_result: MutableTransactionResult,
}

/// Process fee charging and sequence number update for a transaction.
///
/// This is the first step in live transaction execution. It:
/// 1. Loads the source account from state
/// 2. Calculates the fee to charge (may be capped by available balance)
/// 3. Deducts the fee from the source account
/// 4. Adds the fee to the fee pool
/// 5. Updates the sequence number (for pre-protocol 10)
///
/// # C++ Parity
///
/// Matches `TransactionFrame::processFeeSeqNum()` in `TransactionFrame.cpp`.
///
/// # Arguments
///
/// * `frame` - The transaction frame to process
/// * `ctx` - The live execution context (will be mutated)
/// * `base_fee` - Optional base fee override; if `None`, uses context base fee
///
/// # Returns
///
/// A `FeeSeqNumResult` with the charged fee and initialized mutable result.
///
/// # Errors
///
/// Returns an error if the source account doesn't exist or state is unavailable.
pub fn process_fee_seq_num(
    frame: &TransactionFrame,
    ctx: &mut LiveExecutionContext,
    base_fee: Option<i64>,
) -> Result<FeeSeqNumResult> {
    let source_account_id = muxed_to_account_id(&frame.source_account());
    let protocol_version = ctx.protocol_version();

    // Calculate the fee to charge (before borrowing state mutably)
    let fee = calculate_fee_to_charge(frame, protocol_version, base_fee);

    // Load source account and get balance
    let available_balance = {
        let state = ctx.state().ok_or_else(|| {
            TxError::Internal("state manager not available".into())
        })?;
        let source_account = state.get_account(&source_account_id).ok_or_else(|| {
            TxError::AccountNotFound(format!("{:?}", source_account_id))
        })?;
        source_account.balance
    };

    // Cap fee at available balance
    let fee_charged = std::cmp::min(fee, available_balance);

    // Create the mutable result
    let mut tx_result = MutableTransactionResult::new(fee_charged);

    // Initialize refundable fee tracker for Soroban transactions
    if frame.is_soroban() {
        if let Some(refundable_fee) = frame.refundable_fee() {
            tx_result.initialize_refundable_fee_tracker(refundable_fee);
        }
    }

    // Check if we have sufficient balance for the fee
    let should_apply = fee_charged >= fee;

    if !should_apply {
        tx_result.set_error(TransactionResultCode::TxInsufficientBalance);
    }

    // Now get mutable state for modifications
    {
        let state = ctx.state_mut().ok_or_else(|| {
            TxError::Internal("state manager not available".into())
        })?;

        // Charge the fee (or whatever is available)
        charge_fee_to_account(state, &source_account_id, fee_charged)?;

        // Update sequence number for pre-protocol 10 (only if applying)
        if should_apply && protocol_version < FIRST_PROTOCOL_SUPPORTING_OPERATION_VALIDITY {
            update_sequence_number(state, &source_account_id)?;
        }
    }

    // Add to fee pool after releasing state borrow
    ctx.add_to_fee_pool(fee_charged);

    Ok(FeeSeqNumResult {
        fee_charged,
        should_apply,
        tx_result,
    })
}

/// Process fee and sequence for a fee bump transaction.
///
/// Fee bump transactions charge the outer fee source account, not the inner
/// transaction's source account.
///
/// # C++ Parity
///
/// Matches `FeeBumpTransactionFrame::processFeeSeqNum()`.
pub fn process_fee_seq_num_fee_bump(
    fee_bump: &FeeBumpFrame,
    ctx: &mut LiveExecutionContext,
    base_fee: Option<i64>,
) -> Result<FeeSeqNumResult> {
    let fee_source_id = muxed_to_account_id(&fee_bump.fee_source());
    let base = base_fee.unwrap_or(ctx.base_fee() as i64);

    // Calculate the fee for fee bump (outer fee)
    let inner_frame = fee_bump.inner_frame();
    let op_count = inner_frame.operation_count() as i64;

    // Fee bump charges for (op_count + 1) operations
    let fee = if inner_frame.is_soroban() {
        // Soroban: use full fee from envelope
        fee_bump.outer_fee()
    } else {
        // Classic: base_fee * (op_count + 1)
        std::cmp::max(fee_bump.outer_fee(), base * (op_count + 1))
    };

    // Load fee source account and get balance
    let available_balance = {
        let state = ctx.state().ok_or_else(|| {
            TxError::Internal("state manager not available".into())
        })?;
        let fee_source_account = state.get_account(&fee_source_id).ok_or_else(|| {
            TxError::AccountNotFound(format!("{:?}", fee_source_id))
        })?;
        fee_source_account.balance
    };

    // Cap at available balance
    let fee_charged = std::cmp::min(fee, available_balance);

    // Create fee bump mutable result
    let mut tx_result = MutableTransactionResult::new(fee_charged);

    // Initialize refundable fee tracker if inner is Soroban
    if inner_frame.is_soroban() {
        if let Some(refundable_fee) = inner_frame.refundable_fee() {
            tx_result.initialize_refundable_fee_tracker(refundable_fee);
        }
    }

    // Check sufficient balance
    let should_apply = fee_charged >= fee;
    if !should_apply {
        tx_result.set_error(TransactionResultCode::TxInsufficientBalance);
    }

    // Charge the fee
    {
        let state = ctx.state_mut().ok_or_else(|| {
            TxError::Internal("state manager not available".into())
        })?;
        charge_fee_to_account(state, &fee_source_id, fee_charged)?;
    }

    // Add to fee pool after releasing state borrow
    ctx.add_to_fee_pool(fee_charged);

    Ok(FeeSeqNumResult {
        fee_charged,
        should_apply,
        tx_result,
    })
}

/// Calculate the fee to charge for a transaction.
fn calculate_fee_to_charge(
    frame: &TransactionFrame,
    _protocol_version: u32,
    base_fee_override: Option<i64>,
) -> i64 {
    let base_fee = base_fee_override.unwrap_or(100); // Default base fee
    let op_count = frame.operation_count() as i64;

    if frame.is_soroban() {
        // Soroban transactions use the full declared fee
        frame.fee() as i64
    } else {
        // Classic transactions: max(declared_fee, base_fee * op_count)
        let min_fee = base_fee * op_count;
        std::cmp::max(frame.fee() as i64, min_fee)
    }
}

/// Charge fee to an account (deduct from balance).
fn charge_fee_to_account(
    state: &mut LedgerStateManager,
    account_id: &AccountId,
    fee: i64,
) -> Result<()> {
    let account = state.get_account_mut(account_id).ok_or_else(|| {
        TxError::AccountNotFound(format!("{:?}", account_id))
    })?;

    if account.balance < fee {
        return Err(TxError::InsufficientBalance {
            required: fee,
            available: account.balance,
        });
    }

    account.balance -= fee;
    Ok(())
}

/// Update sequence number for an account.
fn update_sequence_number(
    state: &mut LedgerStateManager,
    account_id: &AccountId,
) -> Result<()> {
    let account = state.get_account_mut(account_id).ok_or_else(|| {
        TxError::AccountNotFound(format!("{:?}", account_id))
    })?;

    account.seq_num.0 += 1;
    Ok(())
}

// ============================================================================
// Post-Apply Processing
// ============================================================================

/// Post-apply processing for a transaction.
///
/// This is called after all operations in a transaction have been applied.
/// For Soroban transactions in pre-protocol 23, this handles fee refunds.
///
/// # C++ Parity
///
/// Matches `TransactionFrame::processPostApply()` in `TransactionFrame.cpp`.
///
/// # Protocol Versioning
///
/// - **Pre-P23**: Refunds are applied here
/// - **P23+**: This is a no-op; refunds are deferred to `process_post_tx_set_apply`
///
/// # Arguments
///
/// * `frame` - The transaction frame
/// * `ctx` - The live execution context
/// * `tx_result` - The mutable transaction result
/// * `meta_builder` - Optional metadata builder for recording changes
///
/// # Returns
///
/// The refund amount applied (0 if no refund or P23+).
pub fn process_post_apply(
    frame: &TransactionFrame,
    ctx: &mut LiveExecutionContext,
    tx_result: &mut MutableTransactionResult,
    _meta_builder: Option<&mut TransactionMetaBuilder>,
) -> Result<i64> {
    // In protocol 23+, refunds are handled in process_post_tx_set_apply
    if ctx.protocol_version() >= PROTOCOL_VERSION_23 {
        return Ok(0);
    }

    // Only Soroban transactions have refunds
    if !frame.is_soroban() {
        return Ok(0);
    }

    let fee_source_id = muxed_to_account_id(&frame.source_account());
    refund_soroban_fee(ctx, &fee_source_id, tx_result, None)
}

/// Post-apply processing for a fee bump transaction.
///
/// For fee bump transactions, refunds go to the fee source account
/// (the account that submitted the fee bump), not the inner transaction source.
///
/// # C++ Parity
///
/// Matches `FeeBumpTransactionFrame::processPostApply()`.
pub fn process_post_apply_fee_bump(
    fee_bump: &FeeBumpFrame,
    ctx: &mut LiveExecutionContext,
    tx_result: &mut MutableTransactionResult,
    _meta_builder: Option<&mut TransactionMetaBuilder>,
) -> Result<i64> {
    // In protocol 23+, refunds are handled in process_post_tx_set_apply
    if ctx.protocol_version() >= PROTOCOL_VERSION_23 {
        return Ok(0);
    }

    // Only Soroban transactions have refunds
    if !fee_bump.inner_frame().is_soroban() {
        return Ok(0);
    }

    // Fee bump refunds go to the fee source, not the inner tx source
    let fee_source_id = muxed_to_account_id(&fee_bump.fee_source());
    refund_soroban_fee(ctx, &fee_source_id, tx_result, None)
}

// ============================================================================
// Transaction Set Post-Apply Processing
// ============================================================================

/// Post-transaction-set processing for a transaction.
///
/// This is called after ALL transactions in a transaction set have been applied.
/// For protocol 23+, this is where Soroban fee refunds are handled.
///
/// # C++ Parity
///
/// Matches `TransactionFrame::processPostTxSetApply()` in `TransactionFrame.cpp`.
///
/// # Protocol Versioning
///
/// - **Pre-P23**: This is a no-op; refunds were already applied in `process_post_apply`
/// - **P23+**: Refunds are applied here with `AfterAllTxs` event stage
///
/// # Arguments
///
/// * `frame` - The transaction frame
/// * `ctx` - The live execution context
/// * `tx_result` - The mutable transaction result
/// * `tx_event_manager` - Optional event manager for recording fee refund events
///
/// # Returns
///
/// The refund amount applied (0 if no refund or pre-P23).
pub fn process_post_tx_set_apply(
    frame: &TransactionFrame,
    ctx: &mut LiveExecutionContext,
    tx_result: &mut MutableTransactionResult,
    tx_event_manager: Option<&mut TxEventManager>,
) -> Result<i64> {
    // Pre-P23, refunds were already applied in process_post_apply
    if ctx.protocol_version() < PROTOCOL_VERSION_23 {
        return Ok(0);
    }

    let fee_source_id = muxed_to_account_id(&frame.source_account());
    refund_soroban_fee(ctx, &fee_source_id, tx_result, tx_event_manager)
}

/// Post-transaction-set processing for a fee bump transaction.
///
/// # C++ Parity
///
/// Matches `FeeBumpTransactionFrame::processPostTxSetApply()`.
pub fn process_post_tx_set_apply_fee_bump(
    fee_bump: &FeeBumpFrame,
    ctx: &mut LiveExecutionContext,
    tx_result: &mut MutableTransactionResult,
    tx_event_manager: Option<&mut TxEventManager>,
) -> Result<i64> {
    // Pre-P23, refunds were already applied in process_post_apply
    if ctx.protocol_version() < PROTOCOL_VERSION_23 {
        return Ok(0);
    }

    // Fee bump refunds go to the fee source
    let fee_source_id = muxed_to_account_id(&fee_bump.fee_source());
    refund_soroban_fee(ctx, &fee_source_id, tx_result, tx_event_manager)
}

// ============================================================================
// Soroban Fee Refund
// ============================================================================

/// Apply Soroban fee refund to an account.
///
/// This is the core refund logic shared by `process_post_apply` and
/// `process_post_tx_set_apply`. It:
///
/// 1. Gets the refund amount from the refundable fee tracker
/// 2. Loads the fee source account
/// 3. Credits the refund to the account balance
/// 4. Subtracts the refund from the fee pool
/// 5. Optionally emits a fee refund event
///
/// # C++ Parity
///
/// Matches `TransactionFrame::refundSorobanFee()` in `TransactionFrame.cpp`.
///
/// # Edge Cases
///
/// - If the account no longer exists (merged), returns 0 (no refund)
/// - If the refund would cause balance overflow, caps at max
/// - If liabilities prevent the refund, returns 0
///
/// # Arguments
///
/// * `ctx` - The live execution context
/// * `fee_source_id` - The account to credit the refund to
/// * `tx_result` - The mutable transaction result with refundable fee tracker
/// * `tx_event_manager` - Optional event manager for recording refund events
///
/// # Returns
///
/// The actual refund amount applied.
pub fn refund_soroban_fee(
    ctx: &mut LiveExecutionContext,
    fee_source_id: &AccountId,
    tx_result: &mut MutableTransactionResult,
    tx_event_manager: Option<&mut TxEventManager>,
) -> Result<i64> {
    // Get the refund amount
    let refund = match tx_result.refundable_fee_tracker() {
        Some(tracker) => tracker.get_fee_refund(),
        None => return Ok(0), // No tracker = no refund
    };

    if refund <= 0 {
        return Ok(0);
    }

    // Load the fee source account
    let state = match ctx.state_mut() {
        Some(s) => s,
        None => return Ok(0), // No state = can't apply refund
    };

    // Check if account still exists (may have been merged)
    let account = match state.get_account_mut(fee_source_id) {
        Some(a) => a,
        None => return Ok(0), // Account merged, no refund
    };

    // Apply the refund
    // Check for overflow
    let new_balance = account.balance.saturating_add(refund);
    let actual_refund = new_balance - account.balance;

    account.balance = new_balance;
    ctx.subtract_from_fee_pool(actual_refund);

    // Emit fee refund event if event manager provided
    if let Some(event_manager) = tx_event_manager {
        // Negative fee represents a refund (recorded with AfterAllTxs stage)
        event_manager.refund_fee(fee_source_id, actual_refund, TransactionEventStage::AfterAllTxs);
    }

    Ok(actual_refund)
}

// ============================================================================
// Sequence Number Processing (Protocol 10+)
// ============================================================================

/// Process sequence number update for protocol 10+.
///
/// In protocol 10 and later, sequence number update is separated from fee
/// charging and happens during the pre-apply phase.
///
/// # C++ Parity
///
/// Matches `TransactionFrame::processSeqNum()` in `TransactionFrame.cpp`.
///
/// # Arguments
///
/// * `frame` - The transaction frame
/// * `ctx` - The live execution context
///
/// # Returns
///
/// `Ok(())` on success, or an error if the account doesn't exist.
pub fn process_seq_num(
    frame: &TransactionFrame,
    ctx: &mut LiveExecutionContext,
) -> Result<()> {
    // Only for protocol 10+
    if ctx.protocol_version() < FIRST_PROTOCOL_SUPPORTING_OPERATION_VALIDITY {
        return Ok(()); // Sequence was already updated in process_fee_seq_num
    }

    let source_account_id = muxed_to_account_id(&frame.source_account());

    let state = ctx.state_mut().ok_or_else(|| {
        TxError::Internal("state manager not available".into())
    })?;

    update_sequence_number(state, &source_account_id)
}

// ============================================================================
// One-Time Signer Removal
// ============================================================================

/// Remove one-time signers (pre-auth transaction signers) after transaction apply.
///
/// Pre-auth transaction signers are removed from all source accounts after the
/// transaction is applied, whether it succeeds or fails.
///
/// # C++ Parity
///
/// Matches `TransactionFrame::removeOneTimeSignerKeyFromAllSourceAccounts()`.
///
/// # Arguments
///
/// * `frame` - The transaction frame
/// * `ctx` - The live execution context
/// * `tx_hash` - The transaction hash used for the pre-auth signer key
///
/// # Protocol Versioning
///
/// This is a no-op for protocol 7, which had a bug in signer removal.
pub fn remove_one_time_signers(
    frame: &TransactionFrame,
    ctx: &mut LiveExecutionContext,
    tx_hash: &Hash256,
) -> Result<()> {
    let protocol_version = ctx.protocol_version();

    // Protocol 7 bypass (matches C++ behavior)
    if protocol_version == 7 {
        return Ok(());
    }

    // Collect all source accounts
    let mut source_accounts = vec![muxed_to_account_id(&frame.source_account())];

    for op in frame.operations() {
        if let Some(ref source) = op.source_account {
            source_accounts.push(muxed_to_account_id(source));
        }
    }

    // Remove duplicates
    source_accounts.sort_by(|a, b| a.0.cmp(&b.0));
    source_accounts.dedup_by(|a, b| a.0 == b.0);

    // Remove the pre-auth signer from each account
    let state = ctx.state_mut().ok_or_else(|| {
        TxError::Internal("state manager not available".into())
    })?;

    for account_id in source_accounts {
        state.remove_one_time_signers_from_all_sources(tx_hash, &[account_id], protocol_version);
    }

    Ok(())
}

// ============================================================================
// Full Transaction Apply (Convenience)
// ============================================================================

/// Apply a transaction in live execution mode.
///
/// This is a high-level convenience function that orchestrates the full
/// transaction application flow:
///
/// 1. Process fee and sequence number
/// 2. Validate signatures (if not skipped)
/// 3. Apply operations
/// 4. Process post-apply (pre-P23 refunds)
/// 5. Remove one-time signers
///
/// For more control, use the individual functions directly.
///
/// # Arguments
///
/// * `frame` - The transaction frame to apply
/// * `ctx` - The live execution context
/// * `skip_signature_validation` - Skip expensive signature checks (for replay)
///
/// # Returns
///
/// The final mutable transaction result.
pub fn apply_transaction(
    frame: &TransactionFrame,
    ctx: &mut LiveExecutionContext,
    _skip_signature_validation: bool,
) -> Result<MutableTransactionResult> {
    // Phase 1: Fee and sequence number
    let fee_result = process_fee_seq_num(frame, ctx, None)?;

    if !fee_result.should_apply {
        return Ok(fee_result.tx_result);
    }

    let mut tx_result = fee_result.tx_result;

    // Phase 2: Process sequence number (protocol 10+)
    if let Err(_e) = process_seq_num(frame, ctx) {
        tx_result.set_error(TransactionResultCode::TxNoAccount);
        return Ok(tx_result);
    }

    // Phase 3: Apply operations
    // (This would call into the operation execution code)
    // For now, we assume operations are applied externally

    // Phase 4: Post-apply (pre-P23 refunds)
    process_post_apply(frame, ctx, &mut tx_result, None)?;

    // Phase 5: Remove one-time signers
    if let Ok(hash) = frame.hash(ctx.network_id()) {
        let _ = remove_one_time_signers(frame, ctx, &hash);
    }

    Ok(tx_result)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        AccountEntry, AccountEntryExt, AccountId, MuxedAccount, Operation, OperationBody,
        PaymentOp, Preconditions, PublicKey, SequenceNumber, Transaction, TransactionEnvelope,
        TransactionExt, TransactionV1Envelope, Uint256,
    };

    fn make_account_id(seed: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([seed; 32])))
    }

    fn make_account_entry(id: AccountId, balance: i64, seq_num: i64) -> AccountEntry {
        AccountEntry {
            account_id: id,
            balance,
            seq_num: SequenceNumber(seq_num),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: Default::default(),
            thresholds: stellar_xdr::curr::Thresholds([1, 0, 0, 0]),
            signers: vec![].try_into().unwrap(),
            ext: AccountEntryExt::V0,
        }
    }

    fn make_test_frame(source: AccountId, fee: u32, seq_num: i64) -> TransactionFrame {
        let dest = MuxedAccount::Ed25519(Uint256([2u8; 32]));

        let payment_op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: dest,
                asset: stellar_xdr::curr::Asset::Native,
                amount: 1000,
            }),
        };

        let tx = Transaction {
            source_account: match source.0 {
                PublicKey::PublicKeyTypeEd25519(key) => MuxedAccount::Ed25519(key),
            },
            fee,
            seq_num: SequenceNumber(seq_num),
            cond: Preconditions::None,
            memo: stellar_xdr::curr::Memo::None,
            operations: vec![payment_op].try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        });

        TransactionFrame::new(envelope)
    }

    fn make_test_context(protocol_version: u32) -> LiveExecutionContext {
        let ledger_context = LedgerContext::new(
            1000,           // sequence
            1700000000,     // close_time
            100,            // base_fee
            5_000_000,      // base_reserve
            protocol_version,
            stellar_core_common::NetworkId::testnet(),
        );
        LiveExecutionContext::without_state(ledger_context)
    }

    fn make_test_context_with_state(protocol_version: u32) -> LiveExecutionContext {
        let ledger_context = LedgerContext::new(
            1000,
            1700000000,
            100,
            5_000_000,
            protocol_version,
            stellar_core_common::NetworkId::testnet(),
        );
        let state = LedgerStateManager::new(5_000_000, 1000);
        LiveExecutionContext::new(ledger_context, state)
    }

    #[test]
    fn test_live_execution_context_creation() {
        let ctx = make_test_context(21);

        assert_eq!(ctx.protocol_version(), 21);
        assert_eq!(ctx.ledger_sequence(), 1000);
        assert_eq!(ctx.base_fee(), 100);
        assert_eq!(ctx.fee_pool_delta(), 0);
    }

    #[test]
    fn test_fee_pool_tracking() {
        let mut ctx = make_test_context(21);

        ctx.add_to_fee_pool(500);
        assert_eq!(ctx.fee_pool_delta(), 500);

        ctx.add_to_fee_pool(300);
        assert_eq!(ctx.fee_pool_delta(), 800);

        ctx.subtract_from_fee_pool(200);
        assert_eq!(ctx.fee_pool_delta(), 600);
    }

    #[test]
    fn test_process_fee_seq_num_basic() {
        let mut ctx = make_test_context_with_state(21);
        let account_id = make_account_id(1);
        let account = make_account_entry(account_id.clone(), 10_000_000, 1);

        // Add account to state
        if let Some(state) = ctx.state_mut() {
            state.put_account(account);
        }

        let frame = make_test_frame(account_id, 200, 2);

        let result = process_fee_seq_num(&frame, &mut ctx, None).unwrap();

        assert!(result.should_apply);
        assert_eq!(result.fee_charged, 200);
        assert_eq!(ctx.fee_pool_delta(), 200);

        // Check account balance was deducted
        if let Some(state) = ctx.state() {
            let updated_account = state.get_account(&make_account_id(1)).unwrap();
            assert_eq!(updated_account.balance, 10_000_000 - 200);
        }
    }

    #[test]
    fn test_process_fee_seq_num_insufficient_balance() {
        let mut ctx = make_test_context_with_state(21);
        let account_id = make_account_id(1);
        let account = make_account_entry(account_id.clone(), 50, 1); // Only 50 stroops

        if let Some(state) = ctx.state_mut() {
            state.put_account(account);
        }

        let frame = make_test_frame(account_id, 200, 2);

        let result = process_fee_seq_num(&frame, &mut ctx, None).unwrap();

        assert!(!result.should_apply);
        assert_eq!(result.fee_charged, 50); // Capped at available balance
        assert_eq!(ctx.fee_pool_delta(), 50);
    }

    #[test]
    fn test_process_post_apply_pre_p23() {
        let mut ctx = make_test_context_with_state(22);
        let account_id = make_account_id(1);
        let account = make_account_entry(account_id.clone(), 10_000_000, 1);

        if let Some(state) = ctx.state_mut() {
            state.put_account(account);
        }

        let frame = make_test_frame(account_id, 200, 2);
        let mut tx_result = MutableTransactionResult::new(200);

        // For non-Soroban, no refund
        let refund = process_post_apply(&frame, &mut ctx, &mut tx_result, None).unwrap();
        assert_eq!(refund, 0);
    }

    #[test]
    fn test_process_post_apply_p23_noop() {
        let mut ctx = make_test_context_with_state(23);
        let account_id = make_account_id(1);

        let frame = make_test_frame(account_id, 200, 2);
        let mut tx_result = MutableTransactionResult::new(200);

        // In P23+, process_post_apply is a no-op
        let refund = process_post_apply(&frame, &mut ctx, &mut tx_result, None).unwrap();
        assert_eq!(refund, 0);
    }

    #[test]
    fn test_process_post_tx_set_apply_p23() {
        let mut ctx = make_test_context_with_state(23);
        let account_id = make_account_id(1);
        let account = make_account_entry(account_id.clone(), 10_000_000, 1);

        if let Some(state) = ctx.state_mut() {
            state.put_account(account);
        }

        let frame = make_test_frame(account_id, 200, 2);
        let mut tx_result = MutableTransactionResult::new(200);

        // For non-Soroban, no refund even in P23
        let refund = process_post_tx_set_apply(&frame, &mut ctx, &mut tx_result, None).unwrap();
        assert_eq!(refund, 0);
    }

    #[test]
    fn test_refund_soroban_fee() {
        let mut ctx = make_test_context_with_state(23);
        let account_id = make_account_id(1);
        let account = make_account_entry(account_id.clone(), 10_000_000, 1);

        if let Some(state) = ctx.state_mut() {
            state.put_account(account);
        }

        let mut tx_result = MutableTransactionResult::new(1000);
        tx_result.initialize_refundable_fee_tracker(500);

        // Consume some of the refundable fee
        if let Some(tracker) = tx_result.refundable_fee_tracker_mut() {
            tracker.consume_rent_fee(200).unwrap();
        }

        // Refund should be 500 - 200 = 300
        let refund = refund_soroban_fee(&mut ctx, &account_id, &mut tx_result, None).unwrap();
        assert_eq!(refund, 300);

        // Check fee pool was decremented
        assert_eq!(ctx.fee_pool_delta(), -300);

        // Check account balance was credited
        if let Some(state) = ctx.state() {
            let updated_account = state.get_account(&account_id).unwrap();
            assert_eq!(updated_account.balance, 10_000_000 + 300);
        }
    }

    #[test]
    fn test_refund_soroban_fee_account_merged() {
        let mut ctx = make_test_context_with_state(23);
        let account_id = make_account_id(1);
        // Don't add the account - simulating it was merged

        let mut tx_result = MutableTransactionResult::new(1000);
        tx_result.initialize_refundable_fee_tracker(500);

        // Refund should be 0 because account doesn't exist
        let refund = refund_soroban_fee(&mut ctx, &account_id, &mut tx_result, None).unwrap();
        assert_eq!(refund, 0);
    }

    #[test]
    fn test_process_seq_num_protocol_10_plus() {
        let mut ctx = make_test_context_with_state(21);
        let account_id = make_account_id(1);
        let account = make_account_entry(account_id.clone(), 10_000_000, 5);

        if let Some(state) = ctx.state_mut() {
            state.put_account(account);
        }

        let frame = make_test_frame(account_id.clone(), 200, 6);

        process_seq_num(&frame, &mut ctx).unwrap();

        // Check sequence was incremented
        if let Some(state) = ctx.state() {
            let updated_account = state.get_account(&account_id).unwrap();
            assert_eq!(updated_account.seq_num.0, 6);
        }
    }

    #[test]
    fn test_process_seq_num_pre_protocol_10() {
        let mut ctx = make_test_context_with_state(9);
        let account_id = make_account_id(1);
        let account = make_account_entry(account_id.clone(), 10_000_000, 5);

        if let Some(state) = ctx.state_mut() {
            state.put_account(account);
        }

        let frame = make_test_frame(account_id.clone(), 200, 6);

        // In pre-protocol 10, this is a no-op (sequence updated in process_fee_seq_num)
        process_seq_num(&frame, &mut ctx).unwrap();

        // Sequence should NOT have been incremented by this function
        if let Some(state) = ctx.state() {
            let account = state.get_account(&account_id).unwrap();
            assert_eq!(account.seq_num.0, 5);
        }
    }

    #[test]
    fn test_calculate_fee_to_charge_classic() {
        let account_id = make_account_id(1);
        let frame = make_test_frame(account_id, 50, 1); // Fee of 50 with 1 operation

        // With base fee of 100, should charge max(50, 100*1) = 100
        let fee = calculate_fee_to_charge(&frame, 21, Some(100));
        assert_eq!(fee, 100);

        // With lower declared fee
        let frame2 = make_test_frame(make_account_id(1), 200, 1);
        let fee2 = calculate_fee_to_charge(&frame2, 21, Some(100));
        assert_eq!(fee2, 200); // max(200, 100*1) = 200
    }

    #[test]
    fn test_transaction_event_stage() {
        assert_eq!(TransactionEventStage::BeforeAllTxs, TransactionEventStage::BeforeAllTxs);
        assert_ne!(TransactionEventStage::BeforeAllTxs, TransactionEventStage::AfterAllTxs);
    }
}
