## Pseudocode: crates/ledger/src/close.rs

"Ledger close data structures and transaction set handling."

### Data Structures

```
STRUCT LedgerCloseData:
  ledger_seq: u32
  tx_set: TransactionSetVariant
  close_time: u64                  // Unix timestamp
  upgrades: List<LedgerUpgrade>
  scp_history: List<ScpHistoryEntry>
  prev_ledger_hash: Hash256
  stellar_value_ext: StellarValueExt  // Basic or Signed

ENUM TransactionSetVariant:
  Classic(TransactionSet)          // pre-Protocol 20
  Generalized(GeneralizedTransactionSet)  // Protocol 20+

STRUCT SorobanPhaseStructure:
  base_fee: optional u32
  stages: List<List<List<TxWithFee>>>   // stages > clusters > txs

TYPE TxWithFee = (TransactionEnvelope, optional u32)

STRUCT LedgerCloseResult:
  header: LedgerHeader
  header_hash: Hash256
  tx_results: List<TransactionResultPair>
  meta: optional LedgerCloseMeta
  perf: optional LedgerClosePerf

STRUCT UpgradeContext:
  upgrades: List<LedgerUpgrade>
  current_version: u32

STRUCT LedgerCloseStats:
  tx_count, op_count: usize
  tx_success_count, tx_failed_count: usize
  total_fees: i64
  entries_created, entries_updated, entries_deleted: usize
  close_time_ms: u64
```

### TransactionSetVariant: num_transactions

```
function num_transactions(set) -> usize:
  if set is Classic:
    → set.txs.length

  if set is Generalized(V1):
    count = 0
    for each phase in set.phases:
      if phase is V0(components):
        for each comp in components:
          count += comp.txs.length
      if phase is V1(parallel):
        for each stage in parallel.execution_stages:
          for each cluster in stage:
            count += cluster.txs.length
    → count
```

### TransactionSetVariant: hash

```
function hash(set) -> Hash256:
  if set is Classic:
    hasher = SHA256()
    hasher.update(set.previous_ledger_hash)
    for each tx in set.txs:
      hasher.update(xdr_encode(tx))
    → hasher.finalize()

  if set is Generalized:
    → sha256(xdr_encode(set))
```

### TransactionSetVariant: transactions_with_base_fee

"Get owned transactions with optional per-component base fee overrides."

```
function transactions_with_base_fee(set) -> List<TxWithFee>:
  set_hash = hash(set)

  if set is Classic:
    txs = [(tx, null) for tx in set.txs]
    → sorted_for_apply_sequential(txs, set_hash)

  if set is Generalized(V1):
    result = []
    for each phase in set.phases:
      if phase is V0(components):
        phase_txs = []
        for each comp in components:
          base_fee = comp.base_fee (optional)
          phase_txs += [(tx, base_fee) for tx in comp.txs]
        result += sorted_for_apply_sequential(phase_txs, set_hash)

      if phase is V1(parallel):
        base_fee = parallel.base_fee (optional)
        result += sorted_for_apply_parallel(
                    parallel.execution_stages, set_hash, base_fee)
    → result
```

### TransactionSetVariant: soroban_phase_structure

"Extract the structured Soroban parallel phase, if present."

```
function soroban_phase_structure(set) -> optional SorobanPhaseStructure:
  if set is Classic: → null

  set_hash = hash(set)
  for each phase in set.phases:
    if phase is V1(parallel):
      base_fee = parallel.base_fee (optional)
      stages = sorted_stages_for_parallel(
                 parallel.execution_stages, set_hash, base_fee)
      if stages is empty: → null
      → SorobanPhaseStructure(base_fee, stages)
  → null
```

### Helper: tx_hash, less_than_xored, apply_sort_cmp

```
function tx_hash(tx) -> Hash256:
  → sha256(xdr_encode(tx))

function less_than_xored(left, right, x) -> bool:
  "XOR-based comparison for deterministic tx ordering"
  for i in 0..32:
    v1 = x[i] XOR left[i]
    v2 = x[i] XOR right[i]
    if v1 != v2: → v1 < v2
  → false

function apply_sort_cmp(a, b, set_hash) -> Ordering:
  left = tx_hash(a)
  right = tx_hash(b)
  if left == right: → Equal
  if less_than_xored(left, right, set_hash): → Less
  → Greater
```

### Helper: tx_source_id, tx_sequence_number

```
function tx_source_id(tx) -> AccountId:
  if tx is TxV0:      → muxed_to_account_id(tx.source_ed25519)
  if tx is Tx:         → muxed_to_account_id(tx.source_account)
  if tx is TxFeeBump:  → muxed_to_account_id(tx.inner_tx.source_account)
  NOTE: uses INNER source for fee bumps, not fee source

function tx_sequence_number(tx) -> i64:
  if tx is TxFeeBump: → tx.inner_tx.seq_num
  else:               → tx.seq_num
```

### Helper: sorted_for_apply_sequential

"Sort transactions for sequential apply: group by source account, sort each group by seq num, then interleave batches sorted by XOR hash."

```
function sorted_for_apply_sequential(txs, set_hash) -> List<TxWithFee>:
  if txs.length <= 1: → txs

  // Group by source account (inner source for fee bumps)
  by_account = group txs by tx_source_id → account_key
  queues = [sort each group by tx_sequence_number ascending]

  result = []
  while any queue is non-empty:
    batch = [pop_front from each non-empty queue]
    sort batch by apply_sort_cmp(set_hash)
    result += batch
  → result
```

### Helper: sort_parallel_stages

"Sort and canonicalize parallel execution stages."
"Clusters within a stage are NOT sorted -- they are independent."
"stellar-core preserves XDR order to keep deterministic result ordering."

```
function sort_parallel_stages(stages, set_hash)
    -> List<List<List<TxEnvelope>>>:

  stage_vec = deep_copy(stages)

  // Sort transactions WITHIN each cluster
  for each stage in stage_vec:
    for each cluster in stage:
      sort cluster by apply_sort_cmp(set_hash)

  // Sort stages by first tx of first cluster
  sort stage_vec by comparing first tx of first cluster
       using apply_sort_cmp(set_hash)

  → stage_vec
```

### UpgradeContext: apply_config_upgrades

"Apply all config upgrades to the ledger."

```
function apply_config_upgrades(ctx, snapshot, delta)
    -> (state_archival_changed, memory_cost_params_changed, per_upgrade_changes):

  state_archival_changed = false
  memory_cost_params_changed = false
  per_upgrade_changes = Map<bytes, LedgerEntryChanges>

  for each key in ctx.config_upgrade_keys():
    frame = ConfigUpgradeSetFrame.make_from_key(snapshot, key)
    if frame is null: continue

    validity = frame.is_valid_for_apply()
    if validity is XdrInvalid or Invalid: continue

    (archival, memory_cost, entry_changes) = frame.apply_to(snapshot, delta)
    state_archival_changed |= archival
    memory_cost_params_changed |= memory_cost

    key_bytes = xdr_encode(key)
    per_upgrade_changes[key_bytes] = entry_changes

  → (state_archival_changed, memory_cost_params_changed, per_upgrade_changes)
```

**Calls**: [ConfigUpgradeSetFrame.make_from_key](../config_upgrade.pc.md#make_from_key), [ConfigUpgradeSetFrame.apply_to](../config_upgrade.pc.md#apply_to)

### UpgradeContext: apply_to_header

```
function apply_to_header(ctx, header):
  for each upgrade in ctx.upgrades:
    if upgrade is Version(v):
      header.ledger_version = v
    if upgrade is BaseFee(fee):
      header.base_fee = fee
    if upgrade is MaxTxSetSize(size):
      header.max_tx_set_size = size
    if upgrade is BaseReserve(reserve):
      header.base_reserve = reserve
    if upgrade is Flags(flags):
      if header.ext is V1:
        header.ext.flags = flags
      else:
        header.ext = V1(flags: flags)
    if upgrade is Config: skip (handled separately)
    if upgrade is MaxSorobanTxSetSize: skip (handled separately)
```

### UpgradeContext: apply_max_soroban_tx_set_size

"Parity: Upgrades.cpp upgradeMaxSorobanTxSetSize()"

```
function apply_max_soroban_tx_set_size(ctx, snapshot, delta, ledger_seq)
    -> LedgerEntryChanges:

  new_size = ctx.max_soroban_tx_set_size_upgrade()
  GUARD new_size is null → empty_changes

  key = ConfigSettingKey(ContractExecutionLanes)

  // Load from delta or snapshot
  previous = delta.get_change(key)?.current_entry
           ?? snapshot.get_entry(key)
  GUARD previous is null → error("entry not found")

  updated = copy(previous)
  MUTATE updated.config.ledger_max_tx_count = new_size
  updated.last_modified_ledger_seq = ledger_seq

  delta.record_update(previous, updated)

  → [State(previous), Updated(updated)]
```

**Calls**: [LedgerDelta.record_update](delta.pc.md#record_update)

### LedgerCloseStats helpers

```
function record_success(stats, ops, fee):
  stats.tx_count += 1
  stats.op_count += ops
  stats.tx_success_count += 1
  stats.total_fees += fee

function record_failure(stats, fee):
  stats.tx_count += 1
  stats.tx_failed_count += 1
  stats.total_fees += fee

function record_entry_changes(stats, created, updated, deleted):
  stats.entries_created += created
  stats.entries_updated += updated
  stats.entries_deleted += deleted
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~1122  | ~210       |
| Functions     | 35     | 18         |
