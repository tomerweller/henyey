## Pseudocode: crates/herder/src/tx_queue_limiter.rs

"Resource-aware transaction queue limiting."
"Manages queue admission with multi-dimensional resource tracking and eviction."
"Corresponds to TxQueueLimiter.h in stellar-core v25."

### Helper: scale_resource

```
function scale_resource(resource, multiplier):
  values = []
  for each dimension i in resource:
    values.append(resource[i] * multiplier)   // saturating
  → Resource(values)
```

### Helper: compute_better_fee

"Computes the minimum fee needed to beat an evicted transaction."

```
function compute_better_fee(evicted_fee, evicted_ops,
                            new_fee, new_ops):
  GUARD evicted_ops == 0 → 0

  if fee_rate_cmp(evicted_fee, evicted_ops,
                  new_fee, new_ops) is not Greater:
    "New tx already beats evicted — no extra fee needed"
    → 0

  "Need: new_fee/new_ops > evicted_fee/evicted_ops"
  required = (evicted_fee * new_ops / evicted_ops) + 1
  → min(required, MAX_INT64)
```

**Calls:** [`fee_rate_cmp`](tx_queue/mod.pc.md#fee_rate_cmp)

### Data: TxQueueLimiter

```
TxQueueLimiter:
  max_resources:              Resource  // scaled by multiplier
  is_soroban:                 bool
  max_dex_operations:         Resource or null
  txs:                        SurgePricingPriorityQueue or null
  lane_config:                SurgePricingLaneConfig or null
  txs_to_flood:               SurgePricingPriorityQueue or null
  flood_lane_config:          SurgePricingLaneConfig or null
  lane_evicted_inclusion_fee: List<(fee: i64, ops: u32)>
  network_id:                 NetworkId
```

### new

```
function new(multiplier, max_ledger_resources, is_soroban,
             max_dex_ops, network_id):
  max_resources = scale_resource(
    max_ledger_resources, multiplier)

  max_dex_operations = null
  if not is_soroban and max_dex_ops is set:
    max_dex_operations = Resource([
      max_dex_ops * multiplier
    ])

  → TxQueueLimiter {
      max_resources, is_soroban, max_dex_operations,
      txs: null, lane_config: null,
      txs_to_flood: null, flood_lane_config: null,
      lane_evicted_inclusion_fee: [],
      network_id
    }
```

### reset

```
function reset(ledger_version):
  lane_config =
    if is_soroban:
      SorobanGenericLaneConfig(max_resources)
    else:
      DexLimitingLaneConfig(max_resources, max_dex_operations)

  seed = random()
  txs = SurgePricingPriorityQueue(
    DexLimitingLaneConfig(max_resources, max_dex_operations),
    seed
  )
  self.lane_config = lane_config
  reset_eviction_state()
```

**Calls:** [`SurgePricingPriorityQueue::new`](surge_pricing.pc.md#new)

### reset_best_fee_txs

```
function reset_best_fee_txs(ledger_version, seed):
  lane_config =
    if is_soroban:
      SorobanGenericLaneConfig(max_resources)
    else:
      DexLimitingLaneConfig(max_resources, max_dex_operations)

  txs_to_flood = SurgePricingPriorityQueue(
    DexLimitingLaneConfig(max_resources, max_dex_operations),
    seed
  )
  self.flood_lane_config = lane_config
```

### reset_eviction_state

```
function reset_eviction_state():
  if txs is set:
    lane_evicted_inclusion_fee = [(0,0)] * txs.num_lanes
  else:
    lane_evicted_inclusion_fee = []
```

### add_transaction

```
function add_transaction(tx, ledger_version):
  frame = TransactionFrame(tx.envelope, network_id)
  ASSERT: frame.is_soroban() == self.is_soroban
    "Transaction type mismatch"

  ensure_initialized(ledger_version)

  if txs is set:
    txs.add(tx, network_id, ledger_version)
  if txs_to_flood is set:
    txs_to_flood.add(tx, network_id, ledger_version)
```

**Calls:** [`SurgePricingPriorityQueue::add`](surge_pricing.pc.md#add)

### remove_transaction

```
function remove_transaction(tx, ledger_version):
  frame = TransactionFrame(tx.envelope, network_id)
  lane = lane_config.get_lane(frame) or GENERIC_LANE

  if txs is set:
    entry = QueueEntry(tx, 0)
    txs.remove_entry(lane, entry, ledger_version, network_id)
  if txs_to_flood is set:
    entry = QueueEntry(tx, 0)
    txs_to_flood.remove_entry(
      lane, entry, ledger_version, network_id)
```

### can_add_tx

"Check if a transaction can be added, possibly with evictions."

```
function can_add_tx(new_tx, old_tx, txs_to_evict,
                    ledger_version, broadcast_seed):

  frame = TransactionFrame(new_tx.envelope, network_id)
  ASSERT: frame.is_soroban() == self.is_soroban

  if old_tx is set:
    ASSERT: old_tx.is_soroban() == frame.is_soroban()

  ensure_initialized(ledger_version)
  ensure_flood_initialized(ledger_version, broadcast_seed)

  lane = lane_config.get_lane(frame) or GENERIC_LANE

  // --- Check against evicted fee thresholds ---
  evicted_lane_fee = lane_evicted_inclusion_fee[lane]
    or (0, 0)
  evicted_generic_fee = lane_evicted_inclusion_fee[GENERIC_LANE]
    or (0, 0)

  min_fee_lane = compute_better_fee(
    evicted_lane_fee.fee, evicted_lane_fee.ops,
    new_tx.total_fee, new_tx.op_count)
  min_fee_generic = compute_better_fee(
    evicted_generic_fee.fee, evicted_generic_fee.ops,
    new_tx.total_fee, new_tx.op_count)
  min_inclusion_fee = max(min_fee_lane, min_fee_generic)

  GUARD min_inclusion_fee > 0
    → (false, min_inclusion_fee)

  // --- Replace-by-fee discount ---
  old_tx_discount = null
  if old_tx is set:
    old_frame = TransactionFrame(old_tx.envelope, network_id)
    old_tx_discount = lane_config.tx_resources(
      old_frame, ledger_version)

  "Parity: update generic lane limit after upgrades"
  if txs is set:
    txs.update_generic_lane_limit(max_resources)

  GUARD txs is null → (false, 0)

  fit_result = txs.can_fit_with_eviction(
    new_tx, old_tx_discount, network_id, ledger_version)

  if fit_result has evictions:
    txs_to_evict = evictions
    → (true, 0)
  else:
    → (false, 0)
```

**Calls:** [`SurgePricingPriorityQueue::can_fit_with_eviction`](surge_pricing.pc.md#can_fit_with_eviction)

### evict_transactions

"Evict transactions to make room; records evicted fees per lane."

```
function evict_transactions(txs_to_evict, tx_to_fit,
                            ledger_version, evict_callback):

  frame = TransactionFrame(tx_to_fit.envelope, network_id)
  tx_to_fit_lane = lane_config.get_lane(frame) or GENERIC_LANE
  resources_to_fit = lane_config.tx_resources(
    frame, ledger_version)

  for each (tx, evicted_due_to_lane_limit) in txs_to_evict:
    evict_frame = TransactionFrame(tx.envelope, network_id)
    evict_lane = lane_config.get_lane(evict_frame)
      or GENERIC_LANE

    if evicted_due_to_lane_limit:
      MUTATE lane_evicted_inclusion_fee[evict_lane] =
        (tx.total_fee, tx.op_count)
    else:
      MUTATE lane_evicted_inclusion_fee[GENERIC_LANE] =
        (tx.total_fee, tx.op_count)

    evict_callback(tx)

    "Check if enough space freed"
    if txs is set:
      total = txs.total_resources()
      if (total + resources_to_fit) <= max_resources:
        if tx_to_fit_lane == GENERIC_LANE:
          break
        lane_res = txs.lane_resources(tx_to_fit_lane)
        lane_lim = txs.lane_limits(tx_to_fit_lane)
        if (lane_res + resources_to_fit) <= lane_lim:
          break
```

### mark_tx_for_flood

```
function mark_tx_for_flood(tx, ledger_version):
  if txs_to_flood is set:
    txs_to_flood.add(tx, network_id, ledger_version)
```

### visit_top_txs

```
function visit_top_txs(visitor, lane_resources_left,
                       ledger_version):
  if txs_to_flood is set:
    had_not_fitting = [false] * num_lanes
    txs_to_flood.pop_top_txs(
      false, network_id, ledger_version,
      visitor, lane_resources_left,
      had_not_fitting)
```

**Calls:** [`SurgePricingPriorityQueue::pop_top_txs`](surge_pricing.pc.md#pop_top_txs)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 488    | 155        |
| Functions     | 14     | 13         |
