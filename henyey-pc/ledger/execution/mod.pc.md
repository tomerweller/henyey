## Pseudocode: crates/ledger/src/execution/mod.rs

"Transaction execution during ledger close."
"This module bridges the ledger close process with the transaction processing
layer. It handles loading required state from snapshots, executing transactions
with proper fee handling, recording state changes to the LedgerDelta,
and generating transaction metadata for history."

---

### Data Structures

```
struct HotArchiveLookupImpl:
  hot_archive: shared RwLock<optional HotArchiveBucketList>

struct RefundableFeeTracker:
  non_refundable_fee       : i64
  max_refundable_fee       : i64
  consumed_event_size_bytes: u32
  consumed_rent_fee        : i64
  consumed_refundable_fee  : i64

struct TransactionExecutionResult:
  success               : bool
  fee_charged           : i64
  fee_refund            : i64
  operation_results     : list<OperationResult>
  error                 : optional string
  failure               : optional ExecutionFailure
  tx_meta               : optional TransactionMeta
  fee_changes           : optional LedgerEntryChanges
  post_fee_changes      : optional LedgerEntryChanges
  hot_archive_restored_keys: list<LedgerKey>
  op_type_timings       : map<OperationType, (u64, u32)>
  exec_time_us          : u64
```

```
enum ExecutionFailure:
  Malformed | MissingOperation | InvalidSignature
  | BadAuthExtra | BadMinSeqAgeOrGap | BadSequence
  | InsufficientFee | InsufficientBalance
  | NoAccount | TooEarly | TooLate | NotSupported
  | InternalError | BadSponsorship | OperationFailed

struct ValidatedTransaction:
  frame          : TransactionFrame
  fee_source_id  : AccountId
  inner_source_id: AccountId
  outer_hash     : Hash256
```

"Validation failure with additional context about the validation level reached.
Used to determine whether the sequence number should still be bumped
even though validation failed, matching stellar-core's ValidationType enum."

```
struct ValidationFailure:
  result        : TransactionExecutionResult
  past_seq_check: bool
```

```
struct TransactionExecutor:
  ledger_seq      : u32
  close_time      : u64
  base_reserve    : u32
  protocol_version: u32
  network_id      : NetworkId
  state           : LedgerStateManager
  loaded_accounts : map<[32]byte, bool>
  soroban_config  : SorobanConfig
  classic_events  : ClassicEventConfig
  module_cache    : optional PersistentModuleCache
  hot_archive     : optional shared HotArchiveBucketList
```

```
struct DeltaSnapshot:
  created, updated, deleted, change_order: usize

struct DeltaChanges:
  created      : list<LedgerEntry>
  updated      : list<LedgerEntry>
  update_states: list<LedgerEntry>
  deleted      : list<LedgerKey>
  delete_states: list<LedgerEntry>
  change_order : list<ChangeRef>

struct RestoredEntries:
  hot_archive            : set<LedgerKey>
  hot_archive_entries    : map<LedgerKey, LedgerEntry>
  live_bucket_list       : set<LedgerKey>
  live_bucket_list_entries: map<LedgerKey, LedgerEntry>

enum ThresholdLevel: Low | Medium | High

struct SignatureTracker:
  tx_hash   : Hash256
  signatures: list<DecoratedSignature>
  used      : list<bool>
```

CONST AUTHORIZED_FLAG = TrustLineFlags.AuthorizedFlag

```
struct SorobanNetworkInfo:
  "~40 fields: contract limits, fee rates,
   resource limits, archival settings, SCP timings"
```

```
struct SorobanContext:
  config         : SorobanConfig
  base_prng_seed : [32]byte
  classic_events : ClassicEventConfig
  module_cache   : optional PersistentModuleCache
  hot_archive    : optional shared HotArchiveBucketList
  runtime_handle : optional tokio Handle

struct ClusterParams:
  id_pool             : u64
  prior_stage_entries : list<LedgerEntry>
  pre_charged_fees    : list<PreChargedFee>

struct PreChargedFee:
  charged_fee : i64
  should_apply: bool
  fee_changes : LedgerEntryChanges
```

---

### HotArchiveLookupImpl.get

```
function get(key):
  guard = hot_archive.read_lock()
  GUARD guard is None         → None
  entry = guard.get(key)
  if entry found:
    → entry
  if error:
    → None
  → None
```

### Helper: RefundableFeeTracker.consume

"First check: rent fee alone must not exceed max refundable fee.
This matches stellar-core's consumeRefundableSorobanResources which checks
if (mMaximumRefundableFee < mConsumedRentFee) before computing events fee."

```
function consume(frame, protocol_version, config,
                 event_size_bytes, rent_fee):
  consumed_event_size_bytes += event_size_bytes
  consumed_rent_fee += rent_fee

  GUARD consumed_rent_fee > max_refundable_fee
                                        → false

  (_, refundable_fee) = compute_soroban_resource_fee(
    frame, protocol_version, config,
    consumed_event_size_bytes)
  GUARD computation failed              → false

  consumed_refundable_fee =
    consumed_rent_fee + refundable_fee

  "Second check: total consumed (rent + events)
   must not exceed max refundable fee."
  GUARD consumed_refundable_fee > max_refundable_fee
                                        → false
  → true
```

**Calls** [compute_soroban_resource_fee](config.pc.md#compute_soroban_resource_fee)

### Helper: RefundableFeeTracker.refund_amount

```
function refund_amount():
  if max_refundable_fee > consumed_refundable_fee:
    → max_refundable_fee - consumed_refundable_fee
  → 0
```

### Helper: RefundableFeeTracker.reset

"Mirrors stellar-core's RefundableFeeTracker::resetConsumedFee() which is called
by MutableTransactionResultBase::setError() when a transaction fails."

```
function reset():
  consumed_event_size_bytes = 0
  consumed_rent_fee         = 0
  consumed_refundable_fee   = 0
```

### Helper: failed_result

```
function failed_result(failure, error):
  → TransactionExecutionResult {
      success = false, fee_charged = 0,
      fee_refund = 0, operation_results = [],
      error = error, failure = failure,
      tx_meta = None, fee_changes = None,
      post_fee_changes = None,
      hot_archive_restored_keys = [],
      op_type_timings = {}, exec_time_us = 0 }
```

---

### TransactionExecutor.new

```
function new(context, id_pool, soroban_config,
             classic_events):
  state = LedgerStateManager.new(
    context.base_reserve, context.sequence)
  state.set_id_pool(id_pool)
  → TransactionExecutor {
      ledger_seq       = context.sequence,
      close_time       = context.close_time,
      base_reserve     = context.base_reserve,
      protocol_version = context.protocol_version,
      network_id       = context.network_id,
      state            = state,
      loaded_accounts  = {},
      soroban_config, classic_events,
      module_cache     = None,
      hot_archive      = None }
```

REF: henyey_tx::LedgerStateManager::new

### TransactionExecutor.advance_to_ledger

"Advance to a new ledger, preserving the current state."
NOTE: id_pool is NOT reset — the executor's internal id_pool
evolves correctly as transactions execute. The header's id_pool
is the POST-execution value.

```
function advance_to_ledger(ledger_seq, close_time,
    base_reserve, protocol_version, _id_pool,
    soroban_config):
  self.ledger_seq = ledger_seq
  self.close_time = close_time
  self.base_reserve = base_reserve
  self.protocol_version = protocol_version
  self.soroban_config = soroban_config
  "Do NOT reset id_pool - it should continue"
  state.set_ledger_seq(ledger_seq)
  NOTE: loaded_accounts cache is preserved
```

### TransactionExecutor.advance_to_ledger_with_fresh_state

"Used in verification mode — clears all cached entries."

```
function advance_to_ledger_with_fresh_state(...):
  "same field updates as advance_to_ledger"
  state.clear_cached_entries()
  loaded_accounts.clear()
```

### TransactionExecutor.advance_to_ledger_preserving_offers

"Offers are expensive to reload (~911K entries on mainnet).
The executor's offer cache is maintained correctly across
ledgers because TX execution modifies offers directly in state."

```
function advance_to_ledger_preserving_offers(...):
  "same field updates as advance_to_ledger"
  state.clear_cached_entries_preserving_offers()
  loaded_accounts.clear()
```

### TransactionExecutor.add_contract_to_cache

"Ensures subsequent transactions can use VmCachedInstantiation
instead of VmInstantiation for newly deployed contracts."

```
function add_contract_to_cache(code):
  if module_cache exists:
    module_cache.add_contract(code, protocol_version)
```

---

### TransactionExecutor.batch_load_keys

"Batch-load multiple entries from the bucket list in a single pass."

```
function batch_load_keys(snapshot, keys):
  needed = []
  for each key in keys:
    GUARD key in state.delta.deleted_keys → skip

    already_loaded =
      if key is Account:
        state has account OR loaded_accounts has key
      if key is Trustline:
        state has trustline
      if key is ClaimableBalance:
        state has claimable balance
      if key is LiquidityPool:
        state has liquidity pool
      if key is Offer:
        state has offer
      else: false

    if not already_loaded:
      append key to needed

  GUARD needed is empty → return

  for each account key in needed:
    mark key in loaded_accounts

  entries = snapshot.load_entries(needed)
  for each entry in entries:
    state.load_entry(entry)
```

REF: SnapshotHandle::load_entries

### TransactionExecutor.load_account

"Load an account from the snapshot into the state manager."

```
function load_account(snapshot, account_id):
  "Check if already in state (intra-ledger dep)"
  GUARD state has account         → true

  key_bytes = account_id_to_key(account_id)
  GUARD loaded_accounts has key   → false

  loaded_accounts[key_bytes] = true

  entry = snapshot.get_entry(AccountKey(account_id))
  if entry found:
    state.load_entry(entry)
    → true
  → false
```

### TransactionExecutor.load_account_without_record

"Matches stellar-core's loadAccountWithoutRecord() behavior.
Account is loaded into state so operations can check existence,
but it won't appear in the transaction meta STATE/UPDATED changes."

```
function load_account_without_record(snapshot, account_id):
  GUARD state has account          → true
  GUARD loaded_accounts has key    → false

  loaded_accounts[key_bytes] = true

  entry = snapshot.get_entry(AccountKey(account_id))
  if entry found:
    state.load_entry_without_snapshot(entry)
    → true
  → false
```

### TransactionExecutor.available_balance_for_fee

```
function available_balance_for_fee(account):
  min_balance = state.minimum_balance_for_account(
    account, protocol_version, 0)
  available = account.balance - min_balance
  @version(>=10):
    selling = account.ext.v1.liabilities.selling
    available -= selling
  → available
```

### TransactionExecutor.load_trustline

```
function load_trustline(snapshot, account_id, asset):
  GUARD state has trustline        → true
  GUARD state tracks this trustline (deleted within TX) → false

  key = TrustlineKey(account_id, asset)

  GUARD key in state.delta.deleted_keys → false

  entry = snapshot.get_entry(key)
  if entry found:
    state.load_entry(entry)
    → true
  → false
```

### TransactionExecutor.load_claimable_balance

```
function load_claimable_balance(snapshot, balance_id):
  GUARD state has claimable_balance → true
  GUARD state tracks this CB (deleted within TX) → false

  key = ClaimableBalanceKey(balance_id)
  GUARD key in state.delta.deleted_keys → false

  entry = snapshot.get_entry(key)
  if entry found:
    state.load_entry(entry)
    → true
  → false
```

### TransactionExecutor.load_data / load_data_raw

```
function load_data(snapshot, account_id, data_name):
  GUARD state has data entry       → true
  GUARD state tracks this data (deleted) → false

  key = DataKey(account_id, data_name)
  GUARD key in state.delta.deleted_keys → false

  entry = snapshot.get_entry(key)
  if entry found:
    state.load_entry(entry)
    → true
  → false
```

### TransactionExecutor.load_offer

```
function load_offer(snapshot, seller_id, offer_id):
  GUARD state has offer            → true
  GUARD state tracks this offer (deleted) → false

  key = OfferKey(seller_id, offer_id)
  GUARD key in state.delta.deleted_keys → false

  entry = snapshot.get_entry(key)
  if entry found:
    state.load_entry(entry)
    → true
  → false
```

### TransactionExecutor.load_offer_sponsor

```
function load_offer_sponsor(snapshot, seller_id, offer_id):
  if state.entry_sponsor(offer_key) is some sponsor:
    load_account(snapshot, sponsor)
```

### TransactionExecutor.load_asset_issuer

```
function load_asset_issuer(snapshot, asset):
  if asset is CreditAlphanum4 or CreditAlphanum12:
    load_account(snapshot, asset.issuer)
```

### TransactionExecutor.load_liquidity_pool

```
function load_liquidity_pool(snapshot, pool_id):
  GUARD state has pool              → pool
  GUARD state tracks pool (deleted) → None
  GUARD key in delta.deleted_keys   → None

  entry = snapshot.get_entry(LiqPoolKey(pool_id))
  if entry found and is LiquidityPool:
    state.load_entry(entry)
    → pool
  → None
```

### TransactionExecutor.load_liquidity_pool_dependencies

```
function load_liquidity_pool_dependencies(
    snapshot, op_source, pool_id):
  pool = load_liquidity_pool(snapshot, pool_id)
  if pool found:
    keys = [trustline_key(op_source, PoolShare(pool_id))]
    for asset in [pool.asset_a, pool.asset_b]:
      if non-native: keys += trustline_key(op_source, asset)
      if has issuer: keys += account_key(issuer)
    batch_load_keys(snapshot, keys)
```

### TransactionExecutor.load_path_payment_pools

"For each adjacent pair of assets in the conversion path,
compute the pool ID and attempt to load the pool."

```
function load_path_payment_pools(snapshot,
    send_asset, dest_asset, path):
  assets = [send_asset] + path + [dest_asset]
  for each window of 2 in assets:
    if asset_a == asset_b: continue
    (sorted_a, sorted_b) = sort(asset_a, asset_b)
    CONST LIQUIDITY_POOL_FEE_V18 = 30
    params = ConstantProduct(sorted_a, sorted_b, fee=30)
    pool_id = SHA256(params.to_xdr())
    load_liquidity_pool(snapshot, pool_id)
```

### TransactionExecutor.load_orderbook_offers

"Called once per ledger during initialization."

```
function load_orderbook_offers(snapshot):
  entries = snapshot.all_entries()
  for each entry in entries:
    if entry is Offer:
      state.load_entry(entry)
```

### TransactionExecutor.load_offers_by_account_and_asset

"Used when revoking trustline authorization — all offers for
the account/asset pair must be removed."

```
function load_offers_by_account_and_asset(
    snapshot, account_id, asset):
  offers = state.get_offers_by_account_and_asset(
    account_id, asset)
  for each offer in offers:
    if offer_key not in delta.deleted_keys:
      load_offer_dependencies(snapshot, offer)
```

### TransactionExecutor.load_entry

```
function load_entry(snapshot, key):
  GUARD state has entry            → true
  entry = snapshot.get_entry(key)
  if entry found:
    state.load_entry(entry)
    → true
  → false
```

### TransactionExecutor.load_soroban_footprint

"Load all entries from a Soroban footprint + their TTL keys
in a single bucket list pass."

```
function load_soroban_footprint(snapshot, footprint):
  all_keys = []
  for each key in (footprint.read_only + footprint.read_write):
    if state does NOT have entry AND entry NOT deleted:
      all_keys += key
    if key is ContractData or ContractCode:
      key_hash = SHA256(key.to_xdr())
      ttl_key = TtlKey(key_hash)
      if state does NOT have ttl AND ttl NOT deleted:
        all_keys += ttl_key

  GUARD all_keys is empty → return

  entries = snapshot.load_entries(all_keys)
  for each entry in entries:
    state.load_entry(entry)
```

### TransactionExecutor.apply_ledger_entry_changes

"Apply changes to state WITHOUT delta tracking.
Used during verification to sync state with CDP."

```
function apply_ledger_entry_changes(changes):
  for each change in changes:
    if Created or Updated or Restored:
      state.apply_entry_no_tracking(entry)
      if entry is ContractCode:
        add_contract_to_cache(entry.code)
    if Removed:
      state.delete_entry_no_tracking(key)
    if State:
      "informational only, no action"
  "Clear snapshots to prevent stale snapshot state"
  state.commit()
```

### TransactionExecutor.apply_ledger_entry_changes_preserve_seq

"Preserves the current sequence number for existing accounts.
Needed because CDP metadata can capture sequence numbers that
include effects from later transactions in the same ledger."

```
function apply_ledger_entry_changes_preserve_seq(changes):
  for each change in changes:
    if Updated:
      if entry is Account AND exists in state:
        our_seq = state.account.seq_num
        state.account = new_account
        state.account.seq_num = our_seq
        continue
      state.apply_entry_no_tracking(entry)
      if ContractCode: add_contract_to_cache(code)
    if Created or Restored:
      state.apply_entry_no_tracking(entry)
      if ContractCode: add_contract_to_cache(code)
    if Removed:
      state.delete_entry_no_tracking(key)
  state.commit()
```

### TransactionExecutor.apply_fee_refund

```
function apply_fee_refund(account_id, refund):
  if state has account:
    MUTATE account balance += refund
  state.commit()
```

---

### TransactionExecutor.execute_transaction

"Entry point: delegates with fee deduction enabled."

```
function execute_transaction(snapshot, tx_envelope,
    base_fee, soroban_prng_seed):
  → execute_transaction_with_fee_mode(
      snapshot, tx_envelope, base_fee,
      soroban_prng_seed, deduct_fee=true)
```

### TransactionExecutor.process_fee_only

"Batch fee processing — deducts fees before any TX is applied.
Matches stellar-core's processFeesSeqNums."

```
function process_fee_only(snapshot, tx_envelope, base_fee):
  frame = TransactionFrame(tx_envelope, network_id)
  fee_source_id  = muxed_to_account_id(frame.fee_source)
  inner_source_id= muxed_to_account_id(frame.inner_source)

  GUARD load_account(fee_source_id) fails   → error
  GUARD load_account(inner_source_id) fails → error

  num_ops = max(1, frame.operation_count)
  if frame.is_fee_bump:
    "Fee bumps pay baseFee * (numOps + 1)"
    required_fee = base_fee * (num_ops + 1)
  else:
    required_fee = base_fee * num_ops
  inclusion_fee = frame.inclusion_fee

  if frame.is_soroban:
    fee = declared_soroban_resource_fee
        + min(inclusion_fee, required_fee)
  else:
    fee = min(inclusion_fee, required_fee)

  GUARD fee == 0 → (empty_changes, 0)

  delta_before_fee = delta_snapshot(state)
  capture STATE overrides for fee_source, inner_source

  MUTATE fee_source.balance -= fee

  @version(<10):
    MUTATE inner_source.seq_num = frame.sequence_number
    update_account_seq_info(inner_source)

  state.delta.add_fee(fee)
  state.flush_modified_entries()
  fee_changes = build_entry_changes(...)
  state.commit()

  → (fee_changes, fee)
```

REF: henyey_tx::TransactionFrame::inclusion_fee

---

### TransactionExecutor.validate_preconditions

"Validate structure, accounts, fees, preconditions, sequence,
and signatures before any state changes."

```
function validate_preconditions(snapshot,
    tx_envelope, base_fee):
  frame = TransactionFrame(tx_envelope, network_id)
  fee_source_id  = muxed_to_account_id(frame.fee_source)
  inner_source_id= muxed_to_account_id(frame.inner_source)

  "Phase 1: Structure validation"
  GUARD not frame.is_valid_structure:
    if no operations → (MissingOperation, pre_seq)
    else             → (Malformed, pre_seq)

  "Phase 2: Account loading"
  GUARD load_account(fee_source_id) not found
    → (NoAccount, pre_seq)
  GUARD load_account(inner_source_id) not found
    → (NoAccount, pre_seq)

  fee_source_account = state.get_account(fee_source_id)
  source_account     = state.get_account(inner_source_id)
  GUARD either is None → (NoAccount, pre_seq)

  "Phase 3: Fee validation"
  if frame.is_fee_bump:
    outer_op_count = max(1, op_count + 1)
    outer_min_inclusion = base_fee * outer_op_count
    GUARD outer_inclusion < outer_min_inclusion
      → (InsufficientFee, pre_seq)
    "Cross-multiplication check for fee bump parity"
    if inner_inclusion >= 0:
      GUARD outer * inner_min < inner * outer_min
        → (InsufficientFee, pre_seq)
    else:
      GUARD not is_soroban → (OperationFailed, pre_seq)
  else:
    GUARD frame.fee < op_count * base_fee
      → (InsufficientFee, pre_seq)

  "Phase 4: Time/ledger bounds"
  GUARD time_bounds invalid:
    TooEarly or TooLate → (mapping, pre_seq)
  GUARD ledger_bounds invalid:
    TooEarly or TooLate → (mapping, pre_seq)

  "Phase 5: Sequence number validation"
  if ledger_seq <= INT32_MAX:
    starting_seq = ledger_seq << 32
    GUARD tx_seq == starting_seq
      → (BadSequence, pre_seq)

  if min_seq_num is set:
    is_bad_seq = (account_seq < min_seq)
              OR (account_seq >= tx_seq)
  else:
    is_bad_seq = (account_seq == INT64_MAX)
              OR (account_seq + 1 != tx_seq)
  GUARD is_bad_seq → (BadSequence, pre_seq)

  "--- Past this point, sequence check passed ---"
  NOTE: Failures after this point use post_seq_fail
  (sequence number should still be bumped).

  "Phase 5b: Min seq age/gap checks"
  if preconditions is V2:
    if min_seq_age > 0:
      GUARD close_time - min_seq_age < account_seq_time
        → (BadMinSeqAgeOrGap, post_seq)
    if min_seq_ledger_gap > 0:
      GUARD ledger_seq - gap < account_seq_ledger
        → (BadMinSeqAgeOrGap, post_seq)

  "Phase 6: Signature validation"
  GUARD validate_signatures fails
    → (InvalidSignature, post_seq)
  outer_hash = frame.hash(network_id)
  GUARD fee_source outer sig check fails
    → (InvalidSignature, post_seq)

  if frame.is_fee_bump:
    inner_hash = fee_bump_inner_hash(frame)
    GUARD inner source sig check fails
      → (InvalidSignature, post_seq)

  GUARD non-fee-bump source sig check fails
    → (InvalidSignature, post_seq)

  if preconditions.V2 has extra_signers:
    GUARD extra signer check fails
      → (BadAuthExtra, post_seq)

  → ValidatedTransaction {
      frame, fee_source_id,
      inner_source_id, outer_hash }
```

REF: henyey_tx::validation::validate_time_bounds
REF: henyey_tx::validation::validate_ledger_bounds
REF: henyey_tx::validation::validate_signatures

---

### TransactionExecutor.execute_transaction_with_fee_mode_and_pre_state

"The main transaction execution method. Orchestrates validation,
fee deduction, sequence bump, signer removal, operation execution,
rollback on failure, and metadata generation."

```
function execute_transaction_with_fee_mode_and_pre_state(
    snapshot, tx_envelope, base_fee,
    soroban_prng_seed, deduct_fee,
    fee_source_pre_state):

  "Compute max refundable fee BEFORE validation"
  if tx is Soroban:
    (non_refundable, _) = compute_soroban_resource_fee(
      frame, protocol_version, soroban_config, 0)
    soroban_max_refundable =
      declared_resource_fee - non_refundable
  else:
    soroban_max_refundable = 0

  "Phase 1-6: Validate preconditions"
  validated = validate_preconditions(
    snapshot, tx_envelope, base_fee)
  if validation failed:
    failure_result.fee_refund = soroban_max_refundable
    "If past_seq_check, bump sequence even on failure"
    if past_seq_check:
      MUTATE inner_source.seq_num = frame.seq
      update_account_seq_info(inner_source)
      state.flush + commit
    → failure_result

  "Compute fee to charge"
  num_ops = max(1, frame.operation_count)
  if frame.is_fee_bump:
    required_fee = base_fee * (num_ops + 1)
  else:
    required_fee = base_fee * num_ops
  inclusion_fee = frame.inclusion_fee
  if frame.is_soroban:
    fee = declared_resource_fee
        + min(inclusion_fee, required_fee)
  else:
    fee = min(inclusion_fee, required_fee)

  "Preflight balance check"
  if deduct_fee AND available_balance < fee:
    preflight_failure = InsufficientBalance

  "Initialize refundable fee tracker for Soroban"
  if frame.is_soroban:
    tracker = RefundableFeeTracker(
      non_refundable_fee, max_refundable_fee)

  "Fee deduction phase"
  if deduct_fee AND fee > 0:
    delta_before_fee = delta_snapshot(state)
    MUTATE fee_source.balance -= min(balance, fee)
    fee = charged amount
    state.delta.add_fee(fee)
    state.flush + commit

  "Fee bump wrapper changes (two-phase mode)"
  if not deduct_fee AND frame.is_fee_bump:
    "Capture STATE/UPDATED for fee source
     (removeOneTimeSignerKeyFromFeeSource)"

  "One-time signer removal (protocol != 7)"
  if protocol_version != 7:
    collect all source accounts (dedup, sorted)
    capture STATE overrides
    state.remove_one_time_signers_from_all_sources(
      outer_hash, source_accounts, protocol_version)
    state.flush

  "Sequence number bump"
  delta_before_seq = delta_snapshot(state)
  capture inner_source STATE override
  "CAP-0021: Set account seq_num = tx seq_num"
  MUTATE inner_source.seq_num = frame.sequence_number
  update_account_seq_info(inner_source)
  state.flush
  tx_changes_before = fee_bump_changes
                    + signer_changes
                    + seq_changes
  state.commit()

  "Create ledger context for operation execution"
  context = LedgerContext(ledger_seq, close_time,
    base_fee, base_reserve, protocol_version,
    network_id, prng_seed)

  "Load Soroban footprint"
  if tx has soroban_data:
    load_soroban_footprint(snapshot, footprint)

  state.clear_sponsorship_stack()

  "Pre-load sponsor accounts for
   BeginSponsoringFutureReserves"
  for each op in frame.operations:
    if op is BeginSponsoringFutureReserves:
      load_account(snapshot, sponsor_id)

  "Set up lazy entry loaders for offers"
  state.set_entry_loader(snapshot-based loader)
  state.set_batch_entry_loader(snapshot-based loader)
  state.set_offers_by_account_asset_loader(...)

  state.set_multi_op_mode(num_ops > 1)
  collected_hot_archive_keys = set<LedgerKey>

  "Per-operation signature checking (protocol v10+)"
  if no preflight_failure AND not Soroban:
    pre-load per-op source accounts
    sig_hash = inner_hash for fee-bump, else outer_hash
    if check_operation_signatures fails:
      all_success = false
      failure = signature failure

  "Operation execution loop"
  if no preflight_failure AND all_success:
    for each (op_index, op) in frame.operations:
      op_source = resolve_source(op, frame)
      op_delta_before = delta_snapshot(state)
      state.begin_op_snapshot()
      savepoint = state.create_savepoint()

      load_operation_accounts(snapshot, op, source_id)

      result = execute_single_operation(
        op, op_source, tx_source, tx_seq,
        op_index, context, soroban_data)

      if result is Ok:
        state.flush_modified_entries()

        "Check Soroban refundable fee"
        if has soroban_meta AND has tracker:
          if not tracker.consume(...):
            op_result = InsufficientRefundableFee
            all_success = false

        if op failed:
          all_success = false
          state.rollback_to_savepoint(savepoint)

        "Build operation changes + events"
        "Extract hot archive restored keys (Soroban)"
        "Build ledger entry changes for meta"

      if result is Err:
        state.rollback_to_savepoint(savepoint)
        all_success = false
        failure = InternalError
        break

  "Post-operation checks"
  if all_success AND state.has_pending_sponsorship:
    all_success = false
    failure = BadSponsorship

  "Rollback on failure"
  if not all_success:
    state.rollback()
    restore_delta_entries(fee_created, fee_updated, ...)
    if deduct_fee AND fee > 0:
      state.delta.add_fee(fee)
    restore_delta_entries(seq_created, seq_updated, ...)
    restore_delta_entries(signer entries)
    clear op_changes, op_events, diagnostic_events
    if has tracker: tracker.reset()
  else:
    state.commit()
    "Update module cache with new contract code"
    for each created entry:
      if ContractCode:
        add_contract_to_cache(code)

  "Compute fee refund"
  if has tracker:
    fee_refund = tracker.refund_amount()
    tx_event_manager.new_fee_event(
      fee_source, -refund, AfterAllTxs)

  tx_meta = build_transaction_meta(
    tx_changes_before, op_changes, op_events,
    tx_events, soroban_return_value,
    diagnostic_events, soroban_fee_info)

  → TransactionExecutionResult {
      success = all_success,
      fee_charged = fee - fee_refund,
      fee_refund,
      operation_results, failure,
      tx_meta, fee_changes,
      hot_archive_restored_keys, ... }
```

REF: henyey_tx::operations::execute::execute_operation_with_soroban

---

### TransactionExecutor.load_operation_accounts

"Load accounts, trustlines, and other entries needed for an operation."

```
function load_operation_accounts(snapshot, op, source_id):
  op_source = resolve_op_source(op, source_id)
  if op has explicit source:
    load_account(snapshot, op_source)

  "Phase 1: Batch-load statically-known keys"
  static_keys = collect_prefetch_keys(op.body, op_source)
  if not empty:
    batch_load_keys(snapshot, static_keys)

  "Phase 2: Conditional/secondary loading"
  NOTE: per-operation loading varies by operation type.
  Key patterns (abridged):

  CreateAccount:
    load destination account

  Payment:
    batch_load dest + trustlines + issuer

  AccountMerge:
    load destination account

  AllowTrust / SetTrustLineFlags:
    batch_load trustor + trustline
    load_offers_by_account_and_asset (for revoke)

  ClaimClaimableBalance:
    load CB + sponsor + asset trustline + issuer

  ManageSellOffer / ManageBuyOffer:
    batch_load selling/buying trustlines + issuers
    if offer_id != 0: load offer + sponsor

  CreatePassiveSellOffer:
    batch_load selling/buying trustlines + issuers

  PathPaymentStrictSend / StrictReceive:
    batch_load dest + send/dest trustlines + issuers
    load_path_payment_pools(send, dest, path)

  LiquidityPoolDeposit / Withdraw:
    load_liquidity_pool_dependencies(op_source, pool)

  ChangeTrust:
    load existing trustline
    if deleting (limit=0): load sponsor
    "load_account_without_record for issuer"
    if PoolShare: batch_load pool + asset trustlines

  ManageData:
    load_data_raw(op_source, data_name)

  RevokeSponsorship:
    load target entry + owner/sponsor accounts

  SetOptions:
    if inflation_dest set: load that account
    if signer change: load sponsor accounts

  BeginSponsoringFutureReserves:
    load sponsored_id account
```

REF: henyey_tx::collect_prefetch_keys

### TransactionExecutor.execute_single_operation

"Delegates to the central operation dispatcher."

```
function execute_single_operation(op, source,
    tx_source, tx_seq, op_index, context,
    soroban_data):
  hot_archive_ref = if hot_archive available:
    HotArchiveLookupImpl(hot_archive)
  → execute_operation_with_soroban(
      op, source, tx_source, tx_seq, op_index,
      state, context, soroban_data,
      soroban_config, module_cache,
      hot_archive_ref)
```

REF: henyey_tx::operations::execute::execute_operation_with_soroban

### TransactionExecutor.apply_to_delta

"Apply all state changes to the delta in chronological order."
"Critical for correctness when the same key is affected by
multiple transactions (e.g., TX1 deletes, TX2 recreates)."

```
function apply_to_delta(snapshot, delta):
  for each change_ref in state.delta.change_order:
    if Created:
      delta.record_create(entry)
    if Updated:
      delta.record_update(prev, entry)
    if Deleted:
      delta.record_delete(prev)
```

---

### SignatureTracker.check_signature

"Check signatures against account's signers."

```
function check_signature(account, needed_weight):
  signers = []
  master_weight = account.thresholds[0]
  if master_weight > 0:
    signers += (Ed25519(account.key), master_weight)
  for each signer in account.signers:
    signers += (signer.key, signer.weight)
  → check_signature_from_signers(signers, needed_weight)
```

### SignatureTracker.check_signature_no_account

"Creates a synthetic signer with the account's public key
at weight 1, needed threshold 0."

```
function check_signature_no_account(account_id):
  signers = [(Ed25519(account_id.key), weight=1)]
  → check_signature_from_signers(signers, needed=0)
```

### SignatureTracker.check_signature_from_signers

"Core signature checking logic matching stellar-core's
SignatureChecker::checkSignature(). Splits signers by type:
PRE_AUTH_TX, HASH_X, ED25519, ED25519_SIGNED_PAYLOAD."

```
function check_signature_from_signers(
    signers, needed_weight):
  total_weight = 0
  split signers into: pre_auth, hash_x,
                      ed25519, signed_payload

  "Check PRE_AUTH_TX (no envelope sig needed)"
  for each pre_auth signer:
    if signer.hash == tx_hash:
      total_weight += min(weight, 255)
      if total_weight >= needed_weight → true

  "Check HASH_X signers"
  for each signature in envelope:
    for each hash_x signer (not consumed):
      if hint matches AND SHA256(sig) == hash_key:
        mark sig used
        total_weight += min(weight, 255)
        mark signer consumed
        if total_weight >= needed_weight → true

  "Check ED25519 signers"
  for each signature in envelope:
    for each ed25519 signer (not consumed):
      if verify_signature(tx_hash, sig, pubkey):
        mark sig used
        total_weight += min(weight, 255)
        mark signer consumed
        if total_weight >= needed_weight → true

  "Check ED25519_SIGNED_PAYLOAD signers"
  for each signature in envelope:
    for each payload signer (not consumed):
      if has_signed_payload_match(sig, payload):
        mark sig used
        total_weight += min(weight, 255)
        mark signer consumed
        if total_weight >= needed_weight → true

  → total_weight >= needed_weight
```

### SignatureTracker.check_all_signatures_used

"Mirrors stellar-core's checkAllSignaturesUsed()."

```
function check_all_signatures_used():
  → all entries in used[] are true
```

---

### fee_source_account_id

```
function fee_source_account_id(env):
  if TxV0:    → env.source_account_ed25519
  if Tx:      → env.source_account
  if FeeBump: → env.fee_source
  (resolve MuxedEd25519 → AccountId)
```

### pre_deduct_soroban_fees

"Matches stellar-core processFeesSeqNums. Deducts ALL
Soroban transaction fees sequentially before any TX is applied."

```
function pre_deduct_soroban_fees(snapshot, phase,
    base_fee, network_id, ledger_seq, delta):
  pre_charged = []
  total_fee_pool = 0

  for each stage in phase.stages:
    for each cluster in stage:
      for each (tx, tx_base_fee) in cluster:
        fee = tx_base_fee or base_fee
        frame = TransactionFrame(tx, network_id)
        fee_source = fee_source_account_id(tx)

        num_ops = max(1, frame.op_count)
        if is_fee_bump:
          required = fee * (num_ops + 1)
        else:
          required = fee * num_ops
        inclusion = frame.inclusion_fee
        computed = declared_resource_fee
                 + min(inclusion, required)

        (charged, fee_changes) =
          delta.deduct_fee_from_account(
            fee_source, computed, snapshot, ledger_seq)
        should_apply = (charged >= computed)
        total_fee_pool += charged
        pre_charged += PreChargedFee { ... }

  → (pre_charged, total_fee_pool)
```

REF: LedgerDelta::deduct_fee_from_account

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 3655   | 510        |
| Functions     | 40     | 40         |
