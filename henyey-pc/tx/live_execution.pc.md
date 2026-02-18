## Pseudocode: crates/tx/src/live_execution.rs

"Live transaction execution for validator mode.
This module provides the core infrastructure for executing transactions
in live mode (as opposed to replay/catchup mode)."

"Live execution follows the stellar-core transaction application flow:
1. Fee & Sequence Processing (process_fee_seq_num)
2. Transaction Application (operations)
3. Post-Apply Processing (process_post_apply) — Soroban refunds pre-P23
4. Transaction Set Post-Apply (process_post_tx_set_apply) — Soroban refunds P23+"

"Refund timing changed in protocol 23:
- Pre-P23: Refunds are applied in process_post_apply immediately after each tx
- P23+: Refunds are deferred to process_post_tx_set_apply after all txs"

### Constants

```
CONST FIRST_PROTOCOL_SUPPORTING_OPERATION_VALIDITY = 10
CONST PROTOCOL_VERSION_23 = 23
```

### LiveExecutionContext

```
struct LiveExecutionContext:
  ledger_context       // base context (sequence, close_time, protocol, etc.)
  fee_pool_delta: i64  // accumulated fee pool delta for this ledger
  state                // mutable ledger state manager (optional)

  function new(ledger_context, state):
    fee_pool_delta = 0

  function add_to_fee_pool(amount):
    fee_pool_delta += amount

  function subtract_from_fee_pool(amount):
    fee_pool_delta -= amount
```

### FeeSeqNumResult

```
struct FeeSeqNumResult:
  fee_charged: i64       // fee actually charged (may be capped)
  should_apply: bool     // whether tx should proceed to operation application
  tx_result              // mutable transaction result
```

### process_fee_seq_num

"Process fee charging and sequence number update for a transaction.
Matches TransactionFrame::processFeeSeqNum() in TransactionFrame.cpp."

```
function process_fee_seq_num(frame, ctx, base_fee):
  source_account_id = muxed_to_account_id(frame.source_account)
  protocol_version = ctx.protocol_version

  // --- Phase: Calculate fee ---
  fee = calculate_fee_to_charge(frame, protocol_version, base_fee)

  // --- Phase: Load source and cap fee ---
  available_balance = ctx.state.get_account(source_account_id).balance
  fee_charged = min(fee, available_balance)

  tx_result = new MutableTransactionResult(fee_charged)

  // --- Phase: Initialize Soroban refund tracker ---
  if frame.is_soroban:
    if frame.refundable_fee exists:
      tx_result.initialize_refundable_fee_tracker(frame.refundable_fee)

  // --- Phase: Check sufficient balance ---
  should_apply = (fee_charged >= fee)
  if not should_apply:
    tx_result.set_error(TX_INSUFFICIENT_BALANCE)

  // --- Phase: Charge fee and update seq ---
  MUTATE source_account balance -= fee_charged
```

**Calls:** [`charge_fee_to_account`](#helper-charge_fee_to_account)

```
  @version(<10):
    if should_apply:
      MUTATE source_account seq_num = frame.sequence_number
```

**Calls:** [`update_sequence_number`](#helper-update_sequence_number)

```
  ctx.add_to_fee_pool(fee_charged)
  → FeeSeqNumResult { fee_charged, should_apply, tx_result }
```

### process_fee_seq_num_fee_bump

"Fee bump transactions charge the outer fee source account,
not the inner transaction's source account.
Matches FeeBumpTransactionFrame::processFeeSeqNum()."

```
function process_fee_seq_num_fee_bump(fee_bump, ctx, base_fee):
  fee_source_id = muxed_to_account_id(fee_bump.fee_source)
  base = base_fee or ctx.base_fee
  inner_frame = fee_bump.inner_frame
  op_count = inner_frame.operation_count

  // --- Phase: Calculate fee bump fee ---
  "Fee bump charges for (op_count + 1) operations"
  if inner_frame.is_soroban:
    fee = fee_bump.outer_fee
  else:
    fee = max(fee_bump.outer_fee, base * (op_count + 1))

  // --- Phase: Load fee source and cap ---
  available_balance = ctx.state.get_account(fee_source_id).balance
  fee_charged = min(fee, available_balance)

  tx_result = new MutableTransactionResult(fee_charged)

  if inner_frame.is_soroban:
    if inner_frame.refundable_fee exists:
      tx_result.initialize_refundable_fee_tracker(
        inner_frame.refundable_fee)

  should_apply = (fee_charged >= fee)
  if not should_apply:
    tx_result.set_error(TX_INSUFFICIENT_BALANCE)

  // --- Phase: Charge fee ---
  MUTATE fee_source balance -= fee_charged
  ctx.add_to_fee_pool(fee_charged)
  → FeeSeqNumResult { fee_charged, should_apply, tx_result }
```

### Helper: calculate_fee_to_charge

"Matches stellar-core's TransactionFrame::getFee() behavior:
- For Soroban: resourceFee + min(inclusionFee, adjustedFee)
- For Classic: min(inclusionFee, adjustedFee)
Where adjustedFee = baseFee * numOperations"

```
function calculate_fee_to_charge(frame, protocol_version, base_fee_override):
  base_fee = base_fee_override or 100
  op_count = max(1, frame.operation_count)
  adjusted_fee = base_fee * op_count

  if frame.is_soroban:
    resource_fee = frame.declared_soroban_resource_fee
    inclusion_fee = frame.inclusion_fee
    → resource_fee + min(inclusion_fee, adjusted_fee)
  else:
    inclusion_fee = frame.fee
    → min(inclusion_fee, adjusted_fee)
```

### Helper: charge_fee_to_account

```
function charge_fee_to_account(state, account_id, fee):
  account = state.get_account_mut(account_id)
  GUARD account.balance < fee  → INSUFFICIENT_BALANCE
  MUTATE account balance -= fee
```

### Helper: update_sequence_number

"CAP-0021: Sets the account's seq_num to the transaction's seq_num.
This handles the case where minSeqNum allows sequence gaps."

```
function update_sequence_number(state, account_id, tx_seq_num):
  account = state.get_account_mut(account_id)
  MUTATE account seq_num = tx_seq_num
```

### process_post_apply

"Post-apply processing. Called after all operations in a tx have been applied.
Matches TransactionFrame::processPostApply().
Pre-P23: Soroban refunds applied here.
P23+: This is a no-op; refunds deferred to process_post_tx_set_apply."

```
function process_post_apply(frame, ctx, tx_result, meta_builder):
  @version(≥23):
    → 0    // no-op, refunds deferred

  if not frame.is_soroban:
    → 0

  fee_source_id = muxed_to_account_id(frame.source_account)
```

**Calls:** [`refund_soroban_fee`](#refund_soroban_fee)

```
  → refund_soroban_fee(ctx, fee_source_id, tx_result, none)
```

### process_post_apply_fee_bump

"For fee bump transactions, refunds go to the fee source account.
Matches FeeBumpTransactionFrame::processPostApply()."

```
function process_post_apply_fee_bump(fee_bump, ctx, tx_result, meta_builder):
  @version(≥23):
    → 0

  if not fee_bump.inner_frame.is_soroban:
    → 0

  fee_source_id = muxed_to_account_id(fee_bump.fee_source)
  → refund_soroban_fee(ctx, fee_source_id, tx_result, none)
```

### process_post_tx_set_apply

"Post-transaction-set processing. Called after ALL transactions applied.
Matches TransactionFrame::processPostTxSetApply().
Pre-P23: No-op (refunds already applied).
P23+: Soroban refunds applied here with AfterAllTxs event stage."

```
function process_post_tx_set_apply(frame, ctx, tx_result, tx_event_manager):
  @version(<23):
    → 0    // refunds already applied in process_post_apply

  fee_source_id = muxed_to_account_id(frame.source_account)
  → refund_soroban_fee(ctx, fee_source_id, tx_result, tx_event_manager)
```

### process_post_tx_set_apply_fee_bump

"Matches FeeBumpTransactionFrame::processPostTxSetApply()."

```
function process_post_tx_set_apply_fee_bump(fee_bump, ctx, tx_result, tx_event_manager):
  @version(<23):
    → 0

  fee_source_id = muxed_to_account_id(fee_bump.fee_source)
  → refund_soroban_fee(ctx, fee_source_id, tx_result, tx_event_manager)
```

### refund_soroban_fee

"Core refund logic shared by process_post_apply and process_post_tx_set_apply.
Matches TransactionFrame::refundSorobanFee() in TransactionFrame.cpp."

"Edge cases:
- If account no longer exists (merged), returns 0
- If refund would cause balance overflow, returns 0
- If buying liabilities prevent the refund, returns 0"

```
function refund_soroban_fee(ctx, fee_source_id, tx_result, tx_event_manager):
  // --- Phase: Get refund amount ---
  tracker = tx_result.refundable_fee_tracker
  if tracker is none:
    → 0
  refund = tracker.get_fee_refund()
  if refund <= 0:
    → 0

  // --- Phase: Load account ---
  account = ctx.state.get_account_mut(fee_source_id)
  if account not found:
    → 0   // account merged, no refund

  // --- Phase: Apply refund with addBalance semantics ---
  "stellar-core TransactionUtils.cpp:561-592"

  // 1. Check overflow
  GUARD (MAX_INT64 - account.balance) < refund  → 0

  new_balance = account.balance + refund

  // 2. Check buying liabilities
  buying_liabilities = account.buying_liabilities or 0
  GUARD new_balance > (MAX_INT64 - buying_liabilities)  → 0

  // --- Phase: Credit refund ---
  MUTATE account balance = new_balance
  ctx.subtract_from_fee_pool(refund)

  // --- Phase: Emit event ---
  if tx_event_manager is provided:
    "Negative fee represents a refund (AfterAllTxs stage)"
    tx_event_manager.refund_fee(
      fee_source_id, refund, AFTER_ALL_TXS)

  → refund
```

### process_seq_num

"Process sequence number update for protocol 10+.
In protocol 10+, seq num update is separated from fee charging.
Matches TransactionFrame::processSeqNum()."

```
function process_seq_num(frame, ctx):
  @version(<10):
    → ok   // sequence already updated in process_fee_seq_num

  source_account_id = muxed_to_account_id(frame.source_account)
```

**Calls:** [`update_sequence_number`](#helper-update_sequence_number)

```
  update_sequence_number(ctx.state, source_account_id,
                         frame.sequence_number)
```

### remove_one_time_signers

"Remove pre-auth transaction signers from all source accounts
after transaction apply, whether it succeeds or fails.
Matches TransactionFrame::removeOneTimeSignerKeyFromAllSourceAccounts().
This is a no-op for protocol 7 (which had a bug in signer removal)."

```
function remove_one_time_signers(frame, ctx, tx_hash):
  GUARD protocol_version == 7  → ok  // protocol 7 bypass

  // Collect all source accounts (tx source + op sources)
  source_accounts = [muxed_to_account_id(frame.source_account)]
  for each op in frame.operations:
    if op.source_account exists:
      source_accounts.append(muxed_to_account_id(op.source_account))

  // Remove duplicates
  sort and dedup source_accounts

  for each account_id in source_accounts:
    state.remove_one_time_signers_from_all_sources(
      tx_hash, [account_id], protocol_version)
```

### apply_transaction

"High-level convenience function that orchestrates the full
transaction application flow."

```
function apply_transaction(frame, ctx, skip_signature_validation):
  // Phase 1: Fee and sequence number
  fee_result = process_fee_seq_num(frame, ctx, none)
  if not fee_result.should_apply:
    → fee_result.tx_result

  tx_result = fee_result.tx_result

  // Phase 2: Process sequence number (protocol 10+)
  if process_seq_num(frame, ctx) fails:
    tx_result.set_error(TX_NO_ACCOUNT)
    → tx_result

  // Phase 3: Apply operations
  NOTE: operations applied externally

  // Phase 4: Post-apply (pre-P23 refunds)
  process_post_apply(frame, ctx, tx_result, none)

  // Phase 5: Remove one-time signers
  hash = frame.hash(ctx.network_id)
  remove_one_time_signers(frame, ctx, hash)

  → tx_result
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 856    | 213        |
| Functions     | 14     | 14         |
