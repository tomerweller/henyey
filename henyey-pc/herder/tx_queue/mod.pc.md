## Pseudocode: crates/herder/src/tx_queue/mod.rs

Transaction mempool/queue — manages pending transactions before consensus.
Handles fee-based ordering, per-account limits (one tx per sequence-number-source),
lane-based eviction (classic/DEX/Soroban), fee-bump replacement (10x multiplier),
aging/auto-ban, and fee-source balance validation.

### Constants

```
CONST MAX_TX_SET_ALLOWANCE_BYTES = 10 * 1024 * 1024  // 10 MiB total
CONST MAX_CLASSIC_BYTE_ALLOWANCE = MAX_TX_SET_ALLOWANCE_BYTES / 2
CONST MAX_SOROBAN_BYTE_ALLOWANCE = MAX_TX_SET_ALLOWANCE_BYTES / 2
CONST FEE_MULTIPLIER = 10         // replace-by-fee requires 10x fee rate
CONST DEFAULT_PENDING_DEPTH = 10  // ledgers before auto-ban
CONST DEFAULT_BAN_DEPTH = 10      // ledgers transactions stay banned
```

### Data Structures

```
enum TxQueueResult:
  Added, Duplicate, QueueFull, FeeTooLow,
  Invalid(code?), Banned, Filtered, TryAgainLater

struct ShiftResult:
  unbanned_count: int
  evicted_due_to_age: int

struct TxQueueConfig:
  max_size, max_age_secs, min_fee_per_op
  validate_signatures, validate_time_bounds
  network_id
  max_dex_ops?, max_classic_bytes?, max_dex_bytes?
  max_soroban_resources?, max_soroban_bytes?
  max_queue_dex_ops?, max_queue_soroban_resources?
  max_queue_ops?, max_queue_classic_bytes?
  filtered_operation_types: set of OperationType
  ledger_max_instructions, ledger_max_dependent_tx_clusters
  soroban_phase_min_stage_count, soroban_phase_max_stage_count

struct ValidationContext:
  ledger_seq, close_time, protocol_version, base_fee
  soroban_limits?: SorobanTxLimits

struct SorobanTxLimits:
  tx_max_instructions, tx_max_read_bytes, tx_max_write_bytes
  tx_max_read_ledger_entries, tx_max_write_ledger_entries
  tx_max_size_bytes

struct QueuedTransaction:
  envelope, hash, received_at, fee_per_op, op_count, total_fee

struct TimestampedTx:
  tx: QueuedTransaction

struct AccountState:
  total_fees: int       // sum of fees where this account is fee-source
  age: int              // ledgers since last inclusion (0 when no pending tx)
  transaction?: TimestampedTx  // the one pending tx for this seq-source
```

"The queue enforces one transaction per account (sequence-number-source).
Fee-bump transactions can replace an existing transaction with the same
sequence number if the new fee is at least 10x the existing fee rate."

```
struct TransactionQueue:
  config: TxQueueConfig
  by_hash: map[Hash256 → QueuedTransaction]
  seen: set of Hash256
  validation_context: ValidationContext
  classic_lane_evicted_inclusion_fee: list of (fee, ops)
  soroban_lane_evicted_inclusion_fee: list of (fee, ops)
  global_evicted_inclusion_fee: (fee, ops)
  banned_transactions: deque of set[Hash256]
  account_states: map[account_key_bytes → AccountState]
  pending_depth: int
  fee_balance_provider?: FeeBalanceProvider
```

---

### Helper: QueuedTransaction.new

```
function QueuedTransaction.new(envelope):
  hash = sha256_xdr(envelope)
  (fee, op_count) = extract_fee_and_ops(envelope)
  fee_per_op = fee / op_count  if op_count > 0  else 0
  → QueuedTransaction { envelope, hash, now(), fee_per_op,
                         op_count, total_fee: fee }
```

### Helper: extract_fee_and_ops

```
function extract_fee_and_ops(envelope):
  if envelope is TxV0:
    → (tx.fee, len(tx.operations))
  if envelope is Tx:
    → (tx.fee, len(tx.operations))
  if envelope is FeeBump:
    inner_ops = len(inner_tx.operations)
    → (outer_fee, inner_ops)
```

### Helper: fee_rate_cmp

"Cross-multiply to avoid division"

```
function fee_rate_cmp(a_fee, a_ops, b_fee, b_ops):
  left  = a_fee * b_ops    // 128-bit
  right = b_fee * a_ops    // 128-bit
  → compare(left, right)
```

### Helper: better_fee_ratio

```
function better_fee_ratio(new_tx, old_tx):
  cmp = fee_rate_cmp(new_tx.total_fee, new_tx.op_count,
                     old_tx.total_fee, old_tx.op_count)
  if cmp = Greater: → true
  if cmp = Less:    → false
  → new_tx.hash < old_tx.hash   // tie-break by hash
```

### Helper: compute_better_fee

```
function compute_better_fee(evicted_fee, evicted_ops, tx_ops):
  GUARD evicted_ops = 0 → 0
  base = (evicted_fee * tx_ops) / evicted_ops    // 128-bit
  → base + 1
```

### Helper: min_inclusion_fee_to_beat

```
function min_inclusion_fee_to_beat(evicted, tx):
  GUARD evicted.ops = 0 → 0
  if fee_rate_cmp(evicted.fee, evicted.ops, tx.total_fee, tx.op_count)
     is not Less:
    → compute_better_fee(evicted.fee, evicted.ops, tx.op_count)
  → 0
```

### Helper: can_replace_by_fee

"newFee / newOps >= FEE_MULTIPLIER * oldFee / oldOps"

```
function can_replace_by_fee(new_fee, new_ops, old_fee, old_ops):
  left  = new_fee * old_ops                       // 128-bit
  right = FEE_MULTIPLIER * old_fee * new_ops       // 128-bit
  if left < right:
    min_fee = ceil(right / old_ops)
    → error(min_fee)
  → ok
```

### Helper: account_key

```
function account_key(envelope):
  "Get sequence-number-source account (inner source for fee-bump)"
  source = inner_source_muxed_account(envelope)
  account_id = muxed_to_account_id(source)
  → xdr_encode(account_id)
```

**Calls:** [`muxed_to_account_id`](../../../crates/henyey-tx) — REF: henyey_tx::muxed_to_account_id

### Helper: fee_source_key

```
function fee_source_key(envelope):
  "For fee bump, this is the outer source; otherwise same as inner"
  if envelope is FeeBump:
    fee_source = tx.fee_source
  else:
    fee_source = tx.source_account
  account_id = muxed_to_account_id(fee_source)
  → xdr_encode(account_id)
```

### Helper: envelope_seq_num

```
function envelope_seq_num(envelope):
  if envelope is FeeBump:
    → inner_tx.seq_num
  → tx.seq_num
```

### Helper: is_filtered

```
function is_filtered(envelope):
  GUARD config.filtered_operation_types is empty → false
  ops = operations_from(envelope)
  → any op in ops where op.type in config.filtered_operation_types
```

---

### TransactionQueue.new / with_depths

```
function TransactionQueue.with_depths(config, ban_depth, pending_depth):
  ctx = ValidationContext { base_fee: config.min_fee_per_op, ... }
  banned = deque of ban_depth empty sets
  → TransactionQueue {
      config, by_hash: {}, seen: {}, validation_context: ctx,
      classic_lane_evicted_inclusion_fee: [],
      soroban_lane_evicted_inclusion_fee: [],
      global_evicted_inclusion_fee: (0, 0),
      banned: banned, account_states: {},
      pending_depth, fee_balance_provider: none }
```

---

### validate_transaction

"Validate a transaction before queueing"

```
function validate_transaction(envelope):
  frame = TransactionFrame(envelope, config.network_id)
  ctx = validation_context
  base_fee = max(ctx.base_fee, config.min_fee_per_op)

  GUARD not frame.is_valid_structure()
    → TxMalformed
  for each op in frame.operations():
    GUARD validate_operation(op) fails
      → TxMalformed
  GUARD not frame.validate_soroban_memo()
    → TxSorobanInvalid

  if config.validate_time_bounds:
    ledger_ctx = LedgerContext(ctx.ledger_seq, ctx.close_time,
                               base_fee, 5_000_000, ctx.protocol_version)
    GUARD validate_time_bounds(frame, ledger_ctx) fails
      → TxTooEarly
    GUARD validate_ledger_bounds(frame, ledger_ctx) fails
      → TxTooEarly

  if config.validate_signatures:
    ledger_ctx = LedgerContext(...)
    GUARD validate_signatures(frame, ledger_ctx) fails
      → TxBadAuth

  if preconditions are V2 and extra_signers not empty:
    GUARD not extra_signers_satisfied(envelope, network_id, extra_signers)
      → TxBadAuth

  → ok
```

**Calls:** [`validate_operation`](../../../crates/henyey-tx) — REF: henyey_tx::operations::validate_operation
**Calls:** [`validate_time_bounds`](../../../crates/henyey-tx) — REF: henyey_tx::validate_time_bounds
**Calls:** [`validate_signatures`](../../../crates/henyey-tx) — REF: henyey_tx::validate_signatures

---

### check_soroban_resources

"Parity: stellar-core TransactionFrame::checkSorobanResources()"

```
function check_soroban_resources(frame):
  limits = validation_context.soroban_limits
  GUARD limits is none   → ok   // no limits configured
  data = frame.soroban_data()
  GUARD data is none     → error("missing soroban data")
  resources = data.resources

  GUARD resources.instructions > limits.tx_max_instructions
    → error("instructions exceed limit")
  GUARD resources.disk_read_bytes > limits.tx_max_read_bytes
    → error("read bytes exceed limit")
  GUARD resources.write_bytes > limits.tx_max_write_bytes
    → error("write bytes exceed limit")

  write_entries = len(resources.footprint.read_write)
  read_entries  = len(resources.footprint.read_only)
  GUARD write_entries > limits.tx_max_write_ledger_entries
    → error("write entries exceed limit")
  GUARD read_entries + write_entries > limits.tx_max_read_ledger_entries
    → error("read entries exceed limit")

  tx_size = frame.tx_size_bytes()
  GUARD tx_size > limits.tx_max_size_bytes
    → error("tx size exceeds limit")

  → ok
```

---

### check_account_limit

"One pending transaction per sequence-number source"

```
function check_account_limit(queued, seq_source_key, new_seq, is_fee_bump):
  state = account_states[seq_source_key]
  GUARD state is none → ok(none)   // no existing tx

  current_tx = state.transaction
  GUARD current_tx is none → ok(none)

  GUARD current_tx.hash = queued.hash      → Duplicate
  GUARD new_seq < current_tx.seq_num       → Invalid(none)
  GUARD not is_fee_bump                    → TryAgainLater
  GUARD new_seq != current_tx.seq_num      → TryAgainLater
  GUARD can_replace_by_fee(queued.total_fee, queued.op_count,
          current_tx.total_fee, current_tx.op_count) fails
    → FeeTooLow

  → ok(current_tx)   // replacement approved
```

---

### collect_evictions_for_lane_config

```
function collect_evictions_for_lane_config(by_hash, queued,
    lane_config, ledger_version, exclude, filter, seed):
  queue = SurgePricingPriorityQueue(lane_config, seed)
  for each tx in by_hash:
    if tx.hash in exclude: continue
    if filter(tx):
      queue.add(tx, network_id, ledger_version)
  → queue.can_fit_with_eviction(queued, none, network_id, ledger_version)
```

**Calls:** [`SurgePricingPriorityQueue.can_fit_with_eviction`](../../surge_pricing) — REF: surge_pricing::SurgePricingPriorityQueue::can_fit_with_eviction

---

### check_and_collect_evictions

"Check lane-based eviction fees and collect evictions for all applicable lanes"

```
function check_and_collect_evictions(by_hash, queued,
    is_soroban, queued_frame, ledger_version, seed):

  // ----- Phase 1: Cheap fee-threshold checks (read-only) -----

  // Classic lane fee check
  if not is_soroban and (max_queue_classic_bytes? or max_queue_dex_ops?):
    build DexLimitingLaneConfig(generic_limit, dex_limit?)
    lane = lane_config.get_lane(queued_frame)
    min_fee = min_inclusion_fee_to_beat(classic_lane_fees[lane], queued)
    min_fee = max(min_fee,
                  min_inclusion_fee_to_beat(classic_lane_fees[GENERIC], queued))
    if max_queue_ops?:
      min_fee = max(min_fee,
                    min_inclusion_fee_to_beat(global_fee, queued))
    GUARD min_fee > 0 → FeeTooLow

  // Soroban lane fee check
  if is_soroban and max_queue_soroban_resources?:
    build SorobanGenericLaneConfig(limit)
    lane = lane_config.get_lane(queued_frame)
    min_fee = min_inclusion_fee_to_beat(soroban_lane_fees[lane], queued)
    min_fee = max(min_fee,
                  min_inclusion_fee_to_beat(soroban_lane_fees[GENERIC], queued))
    if max_queue_ops?:
      min_fee = max(min_fee,
                    min_inclusion_fee_to_beat(global_fee, queued))
    GUARD min_fee > 0 → FeeTooLow

  // Global ops fee check
  if max_queue_ops?:
    GUARD min_inclusion_fee_to_beat(global_fee, queued) > 0 → FeeTooLow

  // ----- Phase 2: Collect evictions (expensive, scans queue) -----

  pending_evictions = set of Hash256
  pending_eviction_list = []

  // Classic lane evictions
  if not is_soroban and (max_queue_classic_bytes? or max_queue_dex_ops?):
    evictions = collect_evictions_for_lane_config(by_hash, queued,
        DexLimitingLaneConfig, ledger_version, pending_evictions,
        filter=not_soroban, seed)
    GUARD evictions is none → QueueFull
    for each (evicted, due_to_lane_limit) in evictions:
      if evicted.hash already in pending_evictions: skip
      add evicted to pending_evictions and pending_eviction_list
      lane = lane_config.get_lane(evicted_frame)
      if due_to_lane_limit:
        MUTATE classic_lane_fees[lane] = (evicted.fee, evicted.ops)
      else:
        MUTATE classic_lane_fees[GENERIC] = (evicted.fee, evicted.ops)

  // Soroban lane evictions
  if is_soroban and max_queue_soroban_resources?:
    evictions = collect_evictions_for_lane_config(by_hash, queued,
        SorobanGenericLaneConfig, ledger_version, pending_evictions,
        filter=is_soroban, seed)
    GUARD evictions is none → QueueFull
    for each (evicted, due_to_lane_limit) in evictions:
      if evicted.hash already in pending_evictions: skip
      add evicted to pending_evictions and pending_eviction_list
      lane = lane_config.get_lane(evicted_frame)
      if due_to_lane_limit:
        MUTATE soroban_lane_fees[lane] = (evicted.fee, evicted.ops)
      else:
        MUTATE soroban_lane_fees[GENERIC] = (evicted.fee, evicted.ops)

  // Global ops evictions
  if max_queue_ops?:
    evictions = collect_evictions_for_lane_config(by_hash, queued,
        OpsOnlyLaneConfig, ledger_version, pending_evictions,
        filter=all, seed)
    GUARD evictions is none → QueueFull
    for each (evicted, _) in evictions:
      if evicted.hash already in pending_evictions: skip
      add evicted to pending_evictions and pending_eviction_list
      MUTATE global_evicted_fee = (evicted.fee, evicted.ops)

  → pending_eviction_list
```

---

### try_add

"Try to add a transaction to the queue"

```
function try_add(envelope):
  // --- Validation phase ---
  GUARD validate_transaction(envelope) fails with code
    → Invalid(code)
  queued = QueuedTransaction.new(envelope)
  GUARD construction fails          → Invalid(none)
  GUARD queued.hash in seen         → Duplicate
  GUARD is_banned(queued.hash)      → Banned
  GUARD is_filtered(queued.envelope) → Filtered

  min_fee_per_op = max(ctx.base_fee, config.min_fee_per_op)
  GUARD queued.fee_per_op < min_fee_per_op → FeeTooLow

  queued_frame = TransactionFrame(queued.envelope, network_id)
  is_soroban = queued_frame.is_soroban()

  if is_soroban:
    GUARD check_soroban_resources(queued_frame) fails → Invalid(none)

  GUARD queued.hash in by_hash      → Duplicate

  // --- Per-account limit check ---
  seq_source_key = account_key(envelope)
  new_seq = envelope_seq_num(envelope)
  is_fee_bump = is_fee_bump_envelope(envelope)
  new_fee_source_key = fee_source_key(envelope)

  replaced_tx = check_account_limit(queued, seq_source_key,
                                     new_seq, is_fee_bump)
  GUARD check returns error result → that result

  // --- Lane-based eviction ---
  seed = random()
  pending_eviction_list = check_and_collect_evictions(
      by_hash, queued, is_soroban, queued_frame, ledger_version, seed)
  GUARD check returns error result → that result

  for each evicted in pending_eviction_list:
    MUTATE by_hash remove evicted.hash

  // --- Queue size check / global eviction ---
  if len(by_hash) >= config.max_size:
    "Try to evict expired transactions"
    expired = [h for (h, tx) in by_hash if tx.is_expired(max_age)]
    for each h in expired:
      MUTATE by_hash remove h

    if len(by_hash) >= config.max_size:
      worst = by_hash entry with lowest fee rate (tie-break: hash desc)
      if queued.is_better_than(worst):
        MUTATE by_hash remove worst.hash
      else:
        → QueueFull

  // --- Fee balance validation ---
  if fee_balance_provider is set:
    fee_source_id = decode(new_fee_source_key)
    if replaced_tx exists and same fee source:
      net_new_fee = queued.total_fee - replaced_tx.total_fee
    else:
      net_new_fee = queued.total_fee

    current_total_fees = account_states[new_fee_source_key].total_fees
                         or 0
    available = provider.get_available_balance(fee_source_id)
    GUARD available is none           → Invalid(TxNoAccount)
    GUARD available - net_new_fee < current_total_fees
      → Invalid(TxInsufficientBalance)

  // --- Handle fee-bump replacement ---
  if replaced_tx exists:
    MUTATE by_hash remove replaced_tx.hash
    old_fee_source = fee_source_key(replaced_tx.envelope)
    if old_fee_source != new_fee_source_key:
      MUTATE account_states[old_fee_source].total_fees -= replaced_tx.total_fee
      if account_states[old_fee_source].is_empty():
        remove account_states[old_fee_source]

  // --- Insert into queue ---
  MUTATE account_states[seq_source_key].transaction = TimestampedTx(queued)

  if replaced_tx and same fee source:
    fee_to_add = queued.total_fee - replaced_tx.total_fee
  else:
    fee_to_add = queued.total_fee

  if seq_source_key = new_fee_source_key:
    MUTATE account_states[seq_source_key].total_fees += fee_to_add
  else:
    MUTATE account_states[new_fee_source_key].total_fees += fee_to_add

  MUTATE by_hash[queued.hash] = queued
  MUTATE seen add queued.hash

  → Added
```

---

### remove_applied_by_hash

```
function remove_applied_by_hash(tx_hashes):
  for each hash in tx_hashes:
    MUTATE by_hash remove hash
  NOTE: hashes kept in seen to prevent re-adding
```

---

### remove_applied

"Remove applied transactions from queue and reset source account ages.
Called after ledger close, before shift()."

```
function remove_applied(applied_txs: list of (envelope, seq_num)):
  GUARD applied_txs is empty → return

  fee_releases = []
  accounts_to_cleanup = []

  for each (envelope, applied_seq) in applied_txs:
    frame = TransactionFrame(envelope, network_id)
    seq_source_key = account_key(inner_source(frame))
    fee_source_key = account_key(fee_source(frame))

    state = account_states[seq_source_key]
    if state exists and state.transaction exists:
      if state.transaction.seq_num <= applied_seq:
        MUTATE by_hash remove state.transaction.hash
        fee_releases.push(
          fee_source_key_of(state.transaction), state.transaction.total_fee)
        MUTATE state.transaction = none
        MUTATE state.age = 0

    // Ban the applied tx hash (prevents re-submission)
    applied_hash = sha256_xdr(envelope)
    MUTATE banned_transactions.newest.add(applied_hash)

    accounts_to_cleanup.push(seq_source_key)
    accounts_to_cleanup.push(fee_source_key)

  // Apply fee releases
  for each (fee_key, tx_fee) in fee_releases:
    MUTATE account_states[fee_key].total_fees -= tx_fee

  // Clean up empty account states
  for each key in accounts_to_cleanup:
    if account_states[key].is_empty():
      remove account_states[key]
```

---

### shift

"Shift the queue after a ledger close.
Called after remove_applied(). Rotates bans, ages accounts, auto-bans stale txs."

```
function shift():
  // 1. Rotate ban deque: unban oldest, add empty set for new ledger
  unbanned_count = len(banned_transactions.pop_front())
  banned_transactions.push_back(empty set)

  evicted_due_to_age = 0
  fee_releases = []
  accounts_to_remove = []

  // 2. Age all accounts with pending transactions
  for each (account_key, state) in account_states:
    if state.transaction exists:
      MUTATE state.age += 1

      // 3. Auto-ban at pending_depth
      if state.age >= pending_depth:
        MUTATE banned_transactions.newest.add(state.transaction.hash)
        MUTATE by_hash remove state.transaction.hash
        fee_releases.push(fee_source_key(state.transaction.envelope),
                          state.transaction.total_fee)
        MUTATE state.transaction = none
        evicted_due_to_age += 1

        if state.total_fees = 0:
          accounts_to_remove.push(account_key)
        else:
          MUTATE state.age = 0

  // Apply fee releases
  for each (fee_key, tx_fee) in fee_releases:
    MUTATE account_states[fee_key].total_fees -= tx_fee
    if account_states[fee_key].is_empty():
      accounts_to_remove.push(fee_key)

  // Remove empty account states
  for each key in accounts_to_remove:
    remove account_states[key]

  // 4. Reset eviction thresholds for new ledger
  MUTATE classic_lane_evicted_inclusion_fee = []
  MUTATE soroban_lane_evicted_inclusion_fee = []
  MUTATE global_evicted_inclusion_fee = (0, 0)

  → ShiftResult { unbanned_count, evicted_due_to_age }
```

---

### reset_and_rebuild

"Reset and rebuild the queue after a protocol upgrade.
Parity: SorobanTransactionQueue::resetAndRebuild()"

```
function reset_and_rebuild():
  existing_txs = [tx.envelope for tx in by_hash.values()]

  // Clear all state except bans
  MUTATE by_hash = {}
  MUTATE seen = {}
  MUTATE account_states = {}
  MUTATE classic_lane_evicted_inclusion_fee = []
  MUTATE soroban_lane_evicted_inclusion_fee = []
  MUTATE global_evicted_inclusion_fee = (0, 0)

  // Re-add all transactions (surge pricing handles new limits)
  re_added = 0
  for each tx in existing_txs:
    if try_add(tx) = Added:
      re_added += 1
  → re_added
```

---

### ban

```
function ban(tx_hashes):
  GUARD tx_hashes is empty → return

  // Add to newest ban set
  for each hash in tx_hashes:
    MUTATE banned_transactions.newest.add(hash)

  // Also remove from queue
  for each hash in tx_hashes:
    MUTATE by_hash remove hash
```

### is_banned

```
function is_banned(hash):
  → any set in banned_transactions contains hash
```

---

### evict_expired

```
function evict_expired():
  MUTATE by_hash retain only tx where not tx.is_expired(max_age)

  "Mirror stellar-core: clear eviction thresholds after aging
   to avoid carrying stale min-fee requirements"
  MUTATE classic_lane_evicted_inclusion_fee = []
  MUTATE soroban_lane_evicted_inclusion_fee = []
  MUTATE global_evicted_inclusion_fee = (0, 0)
```

---

### pending_accounts

```
function pending_accounts():
  seen_accounts = set
  result = []
  for each tx in by_hash.values():
    account_id = account_id_from_envelope(tx.envelope)
    key = account_key(account_id)
    if key not in seen_accounts:
      seen_accounts.add(key)
      result.push(account_id)
  → result
```

### ordered_hashes_by_fee

```
function ordered_hashes_by_fee(limit):
  entries = [(tx.fee_per_op, tx.received_at, tx.hash) for tx in by_hash]
  sort entries by fee_per_op desc, received_at asc, hash asc
  → first `limit` hashes
```

### stats

```
function stats():
  accounts = unique account_keys from by_hash values
  → TxQueueStats {
      pending_count: len(by_hash),
      account_count: len(accounts),
      banned_count: sum(len(s) for s in banned_transactions),
      seen_count: len(seen) }
```

---

### Helper: extra_signers_satisfied

"Check V2 precondition extra signers against envelope signatures"

```
function extra_signers_satisfied(envelope, network_id, extra_signers):
  (tx_hash, signatures) = precondition_hash_and_signatures(
                             envelope, network_id)
  → all signers satisfied where:
    Ed25519(key):
      has_ed25519_signature(tx_hash, signatures, key)
    PreAuthTx(key):
      key = tx_hash
    HashX(key):
      has_hashx_signature(signatures, key)
    Ed25519SignedPayload(payload):
      has_signed_payload_signature(tx_hash, signatures, payload)
```

### Helper: precondition_hash_and_signatures

```
function precondition_hash_and_signatures(envelope, network_id):
  if envelope is TxV0 or Tx:
    hash = TransactionFrame(envelope).hash(network_id)
    → (hash, envelope.signatures)
  if envelope is FeeBump:
    NOTE: use inner transaction hash and inner signatures
    inner_frame = TransactionFrame(inner_envelope)
    hash = inner_frame.hash(network_id)
    → (hash, inner_envelope.signatures)
```

### Helper: has_ed25519_signature

```
function has_ed25519_signature(tx_hash, signatures, public_key):
  → any sig in signatures where
    verify_signature_with_key(tx_hash, sig, public_key)
```

**Calls:** [`verify_signature_with_key`](../../../crates/henyey-tx) — REF: henyey_tx::validation::verify_signature_with_key

### Helper: has_hashx_signature

```
function has_hashx_signature(signatures, key):
  → any sig in signatures where:
    len(sig.signature) = 32
    and sig.hint = last_4_bytes(key)
    and sha256(sig.signature) = key
```

### Helper: has_signed_payload_signature

```
function has_signed_payload_signature(tx_hash, signatures, payload):
  pk = PublicKey.from_bytes(payload.ed25519)
  data = tx_hash || payload.payload
  payload_hash = sha256(data)
  → any sig in signatures where
    verify_signature_with_key(payload_hash, sig, pk)
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~940   | ~370       |
| Functions     | 37     | 30         |

NOTE: Test code (lines 1944-4572, ~2628 lines — 57% of file) is excluded.
Submodules `selection` and `tx_set` have their own pseudocode files.
