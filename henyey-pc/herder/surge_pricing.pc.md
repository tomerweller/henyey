## Pseudocode: crates/herder/src/surge_pricing.rs

"Surge pricing lane configuration and priority queue helpers. Transactions are
organized into lanes (generic, DEX, Soroban) with independent resource limits,
and prioritized by fee rate within each lane."

"The generic lane acts as an umbrella — its limits apply to all transactions
regardless of their specific lane assignment."

### Constants

```
CONST GENERIC_LANE = 0
CONST DEX_LANE = 1
```

### Trait: SurgePricingLaneConfig

```
SurgePricingLaneConfig:
  get_lane(frame) → lane index
  lane_limits() → list<Resource>
  tx_resources(frame, ledger_version) → Resource
  update_generic_lane_limit(limit)
```

---

### DexLimitingLaneConfig

"Separates DEX transactions into their own lane, preventing DEX traffic
from crowding out other transaction types."

```
DexLimitingLaneConfig:
  lane_limits       // list<Resource>
  use_byte_limit    // bool
```

### DexLimitingLaneConfig::new

```
function new(limit, dex_limit) → DexLimitingLaneConfig:
  use_byte_limit = (limit.size == NUM_CLASSIC_TX_BYTES_RESOURCES)
  lane_limits = [limit]
  if dex_limit is not null:
    lane_limits.append(dex_limit)
  → DexLimitingLaneConfig { lane_limits, use_byte_limit }
```

### DexLimitingLaneConfig::get_lane

```
function get_lane(frame) → lane:
  if lane_limits.length > DEX_LANE and frame.has_dex_operations():
    → DEX_LANE
  → GENERIC_LANE
```

### DexLimitingLaneConfig::tx_resources

```
function tx_resources(frame, ledger_version) → Resource:
  → frame.resources(use_byte_limit, ledger_version)
```

---

### SorobanGenericLaneConfig

"Single-lane config for Soroban transactions with multi-dimensional
resource limits (instructions, memory, etc.)."

```
SorobanGenericLaneConfig:
  lane_limits       // list<Resource>
```

### SorobanGenericLaneConfig::get_lane

```
function get_lane(frame) → lane:
  ASSERT: frame.is_soroban()
  → GENERIC_LANE
```

### SorobanGenericLaneConfig::tx_resources

```
function tx_resources(frame, ledger_version) → Resource:
  → frame.resources(false, ledger_version)
```

---

### OpsOnlyLaneConfig

"Simple operation-count-only lane config for queue admission limits."

```
OpsOnlyLaneConfig:
  lane_limits       // list<Resource>
```

### OpsOnlyLaneConfig::tx_resources

```
function tx_resources(frame, _ledger_version) → Resource:
  → Resource([frame.operation_count()])
```

---

### Data: QueueEntry

"Wraps a QueuedTransaction with fee and ordering info. Ordered by fee rate
(fee/ops), with tie-breaking via deterministic seeded hash."

```
QueueEntry:
  total_fee         // u64
  op_count          // u32
  tie_breaker       // bytes[32]
  hash              // bytes[32]
  tx                // QueuedTransaction
```

### QueueEntry::new

```
function new(tx, seed) → QueueEntry:
  tie_breaker = copy of tx.hash
  if seed != 0:
    seed_bytes = seed as big-endian bytes
    for i in 0..len(seed_bytes):
      tie_breaker[i] ^= seed_bytes[i]
  → QueueEntry { total_fee: tx.total_fee, op_count: tx.op_count,
                  tie_breaker, hash: tx.hash, tx }
```

### QueueEntry comparison

```
function cmp(self, other) → Ordering:
  ord = fee_rate_cmp(self.total_fee, self.op_count,
                     other.total_fee, other.op_count)
  if ord != Equal:
    → ord
  "Tie-break: reverse order on tie_breaker, then hash"
  → compare(other.tie_breaker, self.tie_breaker)
      then compare(other.hash, self.hash)
```

**Calls:** [`fee_rate_cmp`](tx_queue.pc.md)

### Enum: VisitTxResult

```
VisitTxResult:
  Skipped       // e.g., sequence gap
  Rejected      // e.g., validation failure
  Processed     // successfully processed
```

---

### Data: SurgePricingPriorityQueue

```
SurgePricingPriorityQueue:
  lane_config           // SurgePricingLaneConfig
  lane_limits           // list<Resource> — per-lane limits
  lane_current_count    // list<Resource> — current usage per lane
  lanes                 // list<sorted_set<QueueEntry>> — one per lane
  seed                  // u64 for deterministic tie-breaking
```

### SurgePricingPriorityQueue::new

```
function new(lane_config, seed) → SurgePricingPriorityQueue:
  lane_limits = lane_config.lane_limits()
  resource_len = lane_limits[0].size or NUM_CLASSIC_TX_RESOURCES
  lane_current_count = [empty Resource(resource_len)] * len(lane_limits)
  lanes = [empty sorted_set] * len(lane_limits)
  → SurgePricingPriorityQueue { lane_config, lane_limits,
      lane_current_count, lanes, seed }
```

### update_generic_lane_limit

```
function update_generic_lane_limit(limit):
  lane_config.update_generic_lane_limit(limit)
  lane_limits[GENERIC_LANE] = limit
```

### total_resources

```
function total_resources() → Resource:
  → sum of all lane_current_count entries
```

### add

```
function add(tx, network_id, ledger_version):
  frame = TransactionFrame(tx.envelope, network_id)
  lane = lane_config.get_lane(frame)
  inserted = lanes[lane].insert(QueueEntry(tx, seed))
  if inserted:
    resources = lane_config.tx_resources(frame, ledger_version)
    lane_current_count[lane] += resources
```

### Helper: erase

```
function erase(lane, entry, ledger_version, network_id):
  if lanes[lane].remove(entry):
    frame = TransactionFrame(entry.tx.envelope, network_id)
    resources = lane_config.tx_resources(frame, ledger_version)
    lane_current_count[lane] -= resources
```

### peek_top

```
function peek_top() → (lane, QueueEntry)?:
  best = null
  for each lane in 0..num_lanes:
    entry = top of lanes[lane] (highest fee rate)
    if entry is null: continue
    if best is null or entry > best.entry:
      best = (lane, entry)
  → best
```

### pop_top_txs

"Select highest-fee transactions across all lanes, respecting per-lane
resource limits."

```
function pop_top_txs(allow_gaps, network_id, ledger_version, visitor,
                     lane_left_until_limit, had_tx_not_fitting_lane):
  lane_left_until_limit = copy of lane_limits
  had_tx_not_fitting_lane = [false] * num_lanes
  lane_active = [true] * num_lanes

  loop:
    "Find highest-fee entry across all active lanes"
    best = null
    for each lane where lane_active[lane]:
      entry = top of lanes[lane]
      if entry is null: continue
      if best is null or entry > best.entry:
        best = (lane, entry)

    if best is null:
      break

    (lane, entry) = best
    frame = TransactionFrame(entry.tx.envelope, network_id)
    resources = lane_config.tx_resources(frame, ledger_version)
    exceeds_lane = any_greater(resources, lane_left_until_limit[lane])
    exceeds_generic = any_greater(resources, lane_left_until_limit[GENERIC_LANE])

    if exceeds_lane or exceeds_generic:
      if allow_gaps:
        if exceeds_lane:
          had_tx_not_fitting_lane[lane] = true
        else:
          had_tx_not_fitting_lane[GENERIC_LANE] = true
        erase(lane, entry, ledger_version, network_id)
        continue
      else if lane != GENERIC_LANE and exceeds_lane:
        lane_active[lane] = false
        continue
      else:
        break

    visit_result = visitor(entry.tx)
    if visit_result == Processed:
      lane_left_until_limit[GENERIC_LANE] -= resources
      if lane != GENERIC_LANE:
        lane_left_until_limit[lane] -= resources
    else if visit_result == Rejected:
      had_tx_not_fitting_lane[GENERIC_LANE] = true
      had_tx_not_fitting_lane[lane] = true

    erase(lane, entry, ledger_version, network_id)
```

### can_fit_with_eviction

"Check if a transaction can fit, potentially by evicting lower-fee transactions."

```
function can_fit_with_eviction(tx, tx_discount, network_id, ledger_version)
    → list<(QueuedTransaction, bool)>?:

  frame = TransactionFrame(tx.envelope, network_id)
  lane = lane_config.get_lane(frame)
  tx_resources = lane_config.tx_resources(frame, ledger_version)
  if tx_discount is not null:
    tx_resources = subtract_non_negative(tx_resources, tx_discount)

  "Check if tx exceeds hard lane limits"
  GUARD any_greater(tx_resources, lane_limits[GENERIC_LANE])  → null
  GUARD any_greater(tx_resources, lane_limits[lane])          → null

  "Check for overflow"
  GUARD not total_resources().can_add(tx_resources)           → null
  GUARD not lane_current_count[lane].can_add(tx_resources)    → null

  "Check if fits without eviction"
  new_total = total_resources() + tx_resources
  new_lane = lane_current_count[lane] + tx_resources
  if new_total <= lane_limits[GENERIC_LANE]
     and new_lane <= lane_limits[lane]:
    → empty list (no evictions needed)

  "Need to evict — find lowest-fee txs to remove"
  needed_total = subtract_non_negative(new_total, lane_limits[GENERIC_LANE])
  needed_lane = subtract_non_negative(new_lane, lane_limits[lane])

  "Build cursors over each lane, sorted ascending by fee"
  cursors = [LaneCursor for each lane, pointing to lowest-fee entry]
  evictions = []
  tx_account = tx.account_key()

  while needed_total.any_positive() or needed_lane.any_positive():
    evicted_due_to_lane_limit = false

    "Find lowest-fee entry across all cursors"
    loop:
      best = lowest-fee entry across active cursors
      GUARD best is null   → null (cannot evict enough)

      (evict_lane, entry) = best

      can_evict = (lane == GENERIC_LANE)
                  or (lane == evict_lane)
                  or any_greater(needed_total, needed_lane)
      if not can_evict:
        evicted_due_to_lane_limit = true
        cursors[evict_lane].drop()
        continue
      break

    "Evicted tx must have strictly lower fee rate"
    GUARD fee_rate_cmp(entry, tx) != Less   → null

    "Cannot evict same account's transactions"
    GUARD entry.tx.account_key() == tx_account   → null

    evict_resources = lane_config.tx_resources(entry, ledger_version)
    evictions.append((entry.tx, evicted_due_to_lane_limit))

    needed_total = subtract_non_negative(needed_total, evict_resources)
    if lane == GENERIC_LANE or lane == evict_lane:
      needed_lane = subtract_non_negative(needed_lane, evict_resources)

    cursors[evict_lane].advance()

  → evictions
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~660   | ~210       |
| Functions     | 22     | 22         |
