## Pseudocode: crates/herder/src/scp_driver.rs

"The ScpDriver is the bridge between the SCP consensus layer and the
Herder's application logic. It provides value validation, candidate
combination, envelope signing/verification, transaction set caching,
externalization tracking, and quorum set management."

### Data Structures

```
ENUM ValueValidation:
  Valid, MaybeValid, Invalid

STRUCT ScpDriverConfig:
  node_id: PublicKey
  max_tx_set_cache: int      // default 100
  max_time_drift: u64        // default 60 seconds
  local_quorum_set: nullable ScpQuorumSet

STRUCT CachedTxSet:
  tx_set: TransactionSet
  cached_at: Timestamp
  request_count: u64

STRUCT ExternalizedSlot:
  slot: SlotIndex
  value: Value
  tx_set_hash: nullable Hash256
  close_time: u64
  externalized_at: Timestamp

STRUCT PendingTxSet:
  hash: Hash256
  slot: SlotIndex
  requested_at: Timestamp
  request_count: u32

STRUCT PendingQuorumSet:
  request_count: u32
  node_ids: Set<NodeId>

STRUCT ScpDriver:
  config: ScpDriverConfig
  secret_key: nullable SecretKey
  tx_set_cache: ConcurrentMap<Hash256, CachedTxSet>
  pending_tx_sets: ConcurrentMap<Hash256, PendingTxSet>
  pending_quorum_sets: ConcurrentMap<Hash256, PendingQuorumSet>
  externalized: Map<SlotIndex, ExternalizedSlot>
  latest_externalized: nullable SlotIndex
  envelope_sender: nullable callback(ScpEnvelope)
  network_id: Hash256
  quorum_sets: ConcurrentMap<[32]byte, ScpQuorumSet>
  quorum_sets_by_hash: ConcurrentMap<[32]byte, ScpQuorumSet>
  local_quorum_set: nullable ScpQuorumSet
  ledger_manager: nullable LedgerManager
  is_tracking: bool
  tracking_consensus_index: u64
  tracking_consensus_close_time: u64
```

### new

```
function new(config, network_id) -> ScpDriver:
  if config.local_quorum_set exists:
    hash = hash_quorum_set(quorum_set)
    quorum_sets_by_hash.insert(hash, quorum_set)
    quorum_sets.insert(config.node_id, quorum_set)

  → ScpDriver { is_tracking: false, tracking_consensus_index: 0, ... }
```

### set_tracking_state

```
function set_tracking_state(is_tracking, consensus_index,
    consensus_close_time):
  MUTATE is_tracking = is_tracking
  MUTATE tracking_consensus_index = consensus_index
  MUTATE tracking_consensus_close_time = consensus_close_time
```

### cache_tx_set

```
function cache_tx_set(tx_set):
  hash = tx_set.hash
  if tx_set_cache.len() >= config.max_tx_set_cache:
    oldest = tx_set_cache.min_by(cached_at)
    tx_set_cache.remove(oldest.key)

  tx_set_cache.insert(hash, CachedTxSet { tx_set, now(), 0 })
```

### request_tx_set

```
function request_tx_set(hash, slot) -> bool:
  GUARD tx_set_cache.contains(hash) → false  // already have it
  GUARD pending_tx_sets.contains(hash):
    pending_tx_sets[hash].request_count += 1
    → false  // already requested

  pending_tx_sets.insert(hash, PendingTxSet { hash, slot, now(), 1 })
  → true
```

### request_quorum_set

```
function request_quorum_set(hash, node_id) -> bool:
  if quorum_sets_by_hash.contains(hash):
    store_quorum_set(node_id, quorum_sets_by_hash[hash])
    → false

  if pending_quorum_sets.contains(hash):
    pending_quorum_sets[hash].request_count += 1
    pending_quorum_sets[hash].node_ids.insert(node_id)
    → false

  pending_quorum_sets.insert(hash, PendingQuorumSet {
    request_count: 1, node_ids: {node_id}
  })
  → true
```

### receive_tx_set

```
function receive_tx_set(tx_set) -> nullable SlotIndex:
  hash = tx_set.hash
  recomputed = tx_set.recompute_hash()
  GUARD recomputed is null → null
  GUARD recomputed != hash → null

  pending = pending_tx_sets.remove(hash)
  slot = pending.slot if pending exists

  cache_tx_set(tx_set)
  → slot
```

**Calls:** [cache_tx_set](#cache_tx_set)

### cleanup_pending_tx_sets

```
function cleanup_pending_tx_sets(max_age_secs):
  cutoff = now() - max_age_secs
  pending_tx_sets.retain(requested_at > cutoff)
```

### cleanup_old_pending_slots

```
function cleanup_old_pending_slots(current_slot) -> int:
  old_count = pending_tx_sets.len()
  pending_tx_sets.retain(slot >= current_slot)
  → old_count - pending_tx_sets.len()
```

### has_stale_pending_tx_set

```
function has_stale_pending_tx_set(max_wait_secs) -> bool:
  → any pending_tx_sets entry where
    elapsed(requested_at) >= max_wait_secs
```

### check_close_time

"Matches stellar-core HerderSCPDriver::checkCloseTime.
Returns true if: close_time > lastCloseTime AND
close_time <= now + MAX_TIME_SLIP_SECONDS."

```
function check_close_time(slot_index, last_close_time,
    close_time) -> bool:
  GUARD close_time <= last_close_time → false
  now = current_unix_time()
  GUARD close_time > now + config.max_time_drift → false
  → true
```

### validate_past_or_future_value

"Matches stellar-core HerderSCPDriver::validatePastOrFutureValue."

```
function validate_past_or_future_value(slot_index, close_time,
    lcl_seq, lcl_close_time, is_tracking, tracking_index,
    tracking_close_time) -> ValueValidation:

  GUARD slot_index == lcl_seq + 1 → Invalid
    NOTE: current ledger path — wrong function

  if slot_index == lcl_seq:
    "Previous ledger: close time must exactly match LCL"
    GUARD close_time != lcl_close_time → Invalid

  else if slot_index < lcl_seq:
    "Older than LCL: close time must be strictly less"
    GUARD close_time >= lcl_close_time → Invalid

  else:
    "Future slot: use checkCloseTime with LCL as reference"
    GUARD not check_close_time(slot_index, lcl_close_time,
      close_time) → Invalid

  GUARD not is_tracking → MaybeValid

  if tracking_index > slot_index:
    "Already moved on from this slot"
    → MaybeValid

  if tracking_index < slot_index:
    "Processing future message while tracking"
    → Invalid

  "tracking_index == slot_index: tighter check"
  GUARD not check_close_time(slot_index,
    tracking_close_time, close_time) → Invalid

  → MaybeValid
```

**Calls:** [check_close_time](#check_close_time)

### validate_value_impl

"Matches stellar-core HerderSCPDriver::validateValue."

```
function validate_value_impl(slot_index, value) -> ValueValidation:
  sv = decode StellarValue from value
  GUARD decode fails → Invalid

  "Parity: check STELLAR_VALUE_SIGNED"
  GUARD sv.ext is Basic → Invalid

  "Parity: verify the stellar value signature"
  GUARD not verify_stellar_value_signature(
    sig.node_id, sig.signature, sv.tx_set_hash, sv.close_time)
    → Invalid

  result = validate_value_against_local_state(slot_index, sv)
  GUARD result == Invalid → Invalid

  GUARD not check_upgrade_ordering(sv) → Invalid

  "Parity: validate each upgrade via isValid"
  GUARD not check_upgrades_valid(sv) → Invalid

  → result
```

**Calls:** [verify_stellar_value_signature](#helper-verify_stellar_value_signature), [validate_value_against_local_state](#validate_value_against_local_state), [check_upgrade_ordering](#helper-check_upgrade_ordering), [check_upgrades_valid](#helper-check_upgrades_valid)

### validate_value_against_local_state

"Matches stellar-core HerderSCPDriver::validateValueAgainstLocalState.
For LCL+1: full validation. For past/future: delegate."

```
function validate_value_against_local_state(slot_index, sv)
    -> ValueValidation:
  close_time = sv.close_time
  (lcl_seq, lcl_close_time) = ledger_manager data
    or latest externalized data or (0, 0)

  is_current_ledger = (slot_index == lcl_seq + 1)

  if is_current_ledger:
    GUARD not check_close_time(slot_index, lcl_close_time,
      close_time) → Invalid

    tx_set_hash = sv.tx_set_hash
    GUARD not has_tx_set(tx_set_hash) → MaybeValid

    tx_set = tx_set_cache.get(tx_set_hash)

    "Parity: verify hash integrity"
    computed = tx_set.recompute_hash()
    GUARD computed != tx_set_hash → Invalid

    "Parity: check previousLedgerHash matches LCL"
    if ledger_manager exists:
      lcl_hash = ledger_manager.current_header_hash()
      GUARD tx_set.previous_ledger_hash != lcl_hash → Invalid

    "Parity: validate tx set is well-formed"
    GUARD not is_tx_set_well_formed(tx_set) → Invalid

    → Valid

  else:
    → validate_past_or_future_value(slot_index, close_time,
        lcl_seq, lcl_close_time, is_tracking,
        tracking_index, tracking_close_time)
```

**Calls:** [validate_past_or_future_value](#validate_past_or_future_value), [is_tx_set_well_formed](#helper-is_tx_set_well_formed)

### Helper: check_upgrade_ordering

"Upgrades must be in strictly increasing type order."

```
function check_upgrade_ordering(sv) -> bool:
  CONST UPGRADE_ORDER:
    Version=0, BaseFee=1, MaxTxSetSize=2, BaseReserve=3,
    Flags=4, Config=5, MaxSorobanTxSetSize=6

  last_order = null
  for each upgrade_bytes in sv.upgrades:
    upgrade = decode LedgerUpgrade from upgrade_bytes
    GUARD decode fails → false
    order = UPGRADE_ORDER[upgrade.type]
    GUARD last_order exists and order <= last_order → false
    last_order = order

  → true
```

### Helper: check_upgrades_valid

"Parity: Upgrades.cpp isValid → isValidForApply."

```
function check_upgrades_valid(sv) -> bool:
  current_version = ledger_manager.current_header().ledger_version
    or return true  // no ledger manager — can't validate

  for each upgrade_bytes in sv.upgrades:
    upgrade = decode LedgerUpgrade or → false
    GUARD not is_valid_upgrade_for_apply(upgrade, current_version)
      → false

  → true
```

### Helper: is_valid_upgrade_for_apply

"Parity: Upgrades.cpp isValidForApply."

```
function is_valid_upgrade_for_apply(upgrade, current_version) -> bool:
  Version(v):  v > current_version and v <= CURRENT_LEDGER_PROTOCOL_VERSION
  BaseFee(f):  f != 0
  MaxTxSetSize: always valid
  BaseReserve(r): r != 0
  Flags(f):    current_version >= 18 and (f & ~0x7) == 0
  Config:      current_version >= MIN_SOROBAN_PROTOCOL_VERSION
  MaxSorobanTxSetSize: current_version >= MIN_SOROBAN_PROTOCOL_VERSION
```

### extract_valid_value_impl

"Parity: HerderSCPDriver::extractValidValue.
Does NOT check STELLAR_VALUE_SIGNED or verify signature.
Only returns a value when result is FullyValidated."

```
function extract_valid_value_impl(slot, value) -> nullable Value:
  GUARD value is empty → null
  sv = decode StellarValue from value or → null

  result = validate_value_against_local_state(slot, sv)
  GUARD result != Valid → null

  "Strip invalid upgrades, keeping valid ones in order"
  current_version = ledger_manager.current_header().ledger_version
  valid_upgrades = []
  last_upgrade_type = null

  for each upgrade_bytes in sv.upgrades:
    upgrade = decode LedgerUpgrade
    type_order = upgrade_type_order(upgrade)
    in_order = (last_upgrade_type is null) or (type_order > last_upgrade_type)
    if in_order and is_valid_upgrade_for_apply(upgrade, current_version):
      last_upgrade_type = type_order
      valid_upgrades.append(upgrade_bytes)

  if valid_upgrades.len() != sv.upgrades.len():
    sv.upgrades = valid_upgrades
    → encode sv

  → value
```

### combine_candidates_impl

"Parity: HerderSCPDriver::combineCandidates.
1. Collect upgrades from ALL candidates, merging by taking max
2. Select best tx set using compareTxSets
3. Compose result: best candidate's txSetHash/closeTime + merged upgrades."

```
function combine_candidates_impl(slot, values) -> Value:
  GUARD values is empty → default Value
  GUARD values has 1 entry → values[0]

  decoded = decode all values to StellarValue (skip failures)
  GUARD decoded is empty → values[0]

  "Filter out candidates with wrong previousLedgerHash"
  if ledger_manager exists:
    lcl_hash = ledger_manager.current_header_hash()
    decoded.retain(sv where
      tx_set.previous_ledger_hash == lcl_hash
      or tx_set not cached)
    GUARD decoded is empty → values[0]

  "Step 1: Compute candidates hash (XOR of all) for tiebreaking"
  candidates_hash = XOR of hash(each sv)

  "Step 2: Merge upgrades — take max of each upgrade type"
  merged_upgrades = BTreeMap<order, LedgerUpgrade>
  for each sv in decoded:
    for each upgrade in sv.upgrades:
      order = upgrade_type_order(upgrade)
      if merged_upgrades[order] < upgrade:
        merged_upgrades[order] = upgrade

  "Step 3: Select best candidate using compareTxSets"
  best = decoded.max_by(|a, b|
    compare_tx_sets(a.tx_set_hash, b.tx_set_hash,
      candidates_hash))

  "Step 4: Compose result"
  result = best with merged upgrades
  → encode result
```

**Calls:** [compare_tx_sets](#helper-compare_tx_sets)

### Helper: compare_tx_sets

"Parity: HerderSCPDriver.cpp compareTxSets.
Compares: num ops > total fees > XOR hash tiebreak."

```
function compare_tx_sets(a_hash, b_hash, candidates_hash)
    -> Ordering:
  a_set = tx_set_cache.get(a_hash)
  b_set = tx_set_cache.get(b_hash)

  if both sets available:
    a_ops = count_ops(a_set)
    b_ops = count_ops(b_set)
    if a_ops != b_ops: → compare(a_ops, b_ops)

    a_fees = total_fees(a_set)
    b_fees = total_fees(b_set)
    if a_fees != b_fees: → compare(a_fees, b_fees)

  a_xored = a_hash XOR candidates_hash
  b_xored = b_hash XOR candidates_hash
  → compare(a_xored, b_xored)
```

### Helper: compare_upgrades

```
function compare_upgrades(new, existing) -> bool:
  "Returns true if new > existing (same type)"
  Version:  new > existing
  BaseFee:  new > existing
  MaxTxSetSize: new > existing
  BaseReserve: new > existing
  Flags: new > existing
  Config: new > existing
  MaxSorobanTxSetSize: new > existing
```

### Helper: is_tx_set_well_formed

"Parity: TxSetUtils::checkValid() — sorted by hash, no duplicates."

```
function is_tx_set_well_formed(tx_set) -> bool:
  GUARD txs.len() <= 1 → true

  prev_hash = hash_xdr(txs[0])
  for each tx in txs[1..]:
    hash = hash_xdr(tx)
    GUARD hash <= prev_hash → false  // unsorted or duplicate
    prev_hash = hash

  → true
```

### Helper: verify_stellar_value_signature

"stellar-core signs: (networkID, ENVELOPE_TYPE_SCPVALUE, txSetHash, closeTime)."

```
function verify_stellar_value_signature(node_id, signature,
    tx_set_hash, close_time) -> bool:
  public_key = extract from node_id
  data = network_id
    + encode(ENVELOPE_TYPE_SCPVALUE)
    + encode(tx_set_hash)
    + encode(close_time)

  → public_key.verify(data, signature)
```

### sign_envelope

```
function sign_envelope(statement) -> nullable Signature:
  GUARD secret_key is null → null

  data = network_id
    + 1_i32_be   // ENVELOPE_TYPE_SCP
    + encode(statement)

  → secret_key.sign(data)
```

### verify_envelope

```
function verify_envelope(envelope) -> Result:
  public_key = extract from envelope.statement.node_id

  data = network_id
    + 1_i32_be   // ENVELOPE_TYPE_SCP
    + encode(envelope.statement)

  sig = extract 64-byte signature from envelope
  → public_key.verify(data, sig)
```

### record_externalized

```
function record_externalized(slot, value):
  sv = decode StellarValue from value
  tx_set_hash = sv.tx_set_hash if decode succeeds
  close_time = sv.close_time if decode succeeds

  "Check if overwriting with different content"
  if externalized[slot] exists and externalized[slot].value != value:
    WARN "Overwriting externalized value with DIFFERENT value"

  externalized[slot] = ExternalizedSlot {
    slot, value, tx_set_hash, close_time, now()
  }

  if latest_externalized is null or slot > latest_externalized:
    MUTATE latest_externalized = slot
```

### cleanup_externalized

```
function cleanup_externalized(keep_count):
  GUARD externalized.len() <= keep_count → return

  slots = externalized.keys().sorted()
  to_remove = externalized.len() - keep_count
  for each slot in slots[0..to_remove]:
    externalized.remove(slot)
```

### trim_stale_caches

```
function trim_stale_caches(keep_after_slot):
  pending_tx_sets.retain(slot > keep_after_slot)
  externalized.retain(slot > keep_after_slot)
  NOTE: tx_set_cache not trimmed — keyed by hash, not slot
```

### purge_slots_below

```
function purge_slots_below(slot):
  externalized.remove_all(s < slot)
  cleanup_old_pending_slots(slot)
```

### store_quorum_set

```
function store_quorum_set(node_id, quorum_set):
  key = node_id as [32]byte
  hash = hash_quorum_set(quorum_set)
  quorum_sets.insert(key, quorum_set)
  quorum_sets_by_hash.insert(hash, quorum_set)
  pending_quorum_sets.remove(hash)
```

### get_quorum_set

```
function get_quorum_set(node_id) -> nullable ScpQuorumSet:
  key = node_id as [32]byte
  if key == our node_id:
    → local_quorum_set
  → quorum_sets.get(key)
```

### set_local_quorum_set

```
function set_local_quorum_set(quorum_set):
  MUTATE local_quorum_set = quorum_set
  hash = hash_quorum_set(quorum_set)
  quorum_sets_by_hash.insert(hash, quorum_set)
  quorum_sets.insert(config.node_id, quorum_set)
  pending_quorum_sets.remove(hash)
```

---

## HerderScpCallback (SCPDriver trait)

"SCP callback implementation that wraps ScpDriver."

### validate_value (SCPDriver)

```
function validate_value(slot_index, value, nomination) -> ValidationLevel:
  → map validate_value_impl(slot_index, value):
    Valid      → FullyValidated
    MaybeValid → MaybeValid
    Invalid    → Invalid
```

### combine_candidates (SCPDriver)

```
function combine_candidates(slot_index, candidates) -> nullable Value:
  result = driver.combine_candidates_impl(slot_index, candidates)
  if result is empty: → null
  → result
```

### extract_valid_value (SCPDriver)

```
function extract_valid_value(slot_index, value) -> nullable Value:
  → driver.extract_valid_value_impl(slot_index, value)
```

### compute_hash_node (SCPDriver)

```
CONST HASH_N = 1
CONST HASH_P = 2

function compute_hash_node(slot_index, prev_value, is_priority,
    round, node_id) -> u64:
  tag = HASH_P if is_priority else HASH_N
  data = xdr(slot_index) + xdr(prev_value)
    + xdr(tag) + xdr(round) + xdr(node_id)
  hash = Hash256.hash(data)
  → first 8 bytes of hash as u64
```

### compute_value_hash (SCPDriver)

```
CONST HASH_K = 3

function compute_value_hash(slot_index, prev_value,
    round, value) -> u64:
  data = xdr(slot_index) + xdr(prev_value)
    + xdr(HASH_K) + xdr(round) + xdr(value)
  hash = Hash256.hash(data)
  → first 8 bytes of hash as u64
```

### compute_timeout (SCPDriver)

```
CONST MAX_TIMEOUT_MS = 30 * 60 * 1000

function compute_timeout(round, is_nomination) -> Duration:
  initial_ms = 1000
  increment_ms = 1000

  if ledger_manager exists and ledger_version >= 23:
    if soroban_network_info exists:
      if is_nomination:
        initial_ms = info.nomination_timeout_initial_ms
        increment_ms = info.nomination_timeout_increment_ms
      else:
        initial_ms = info.ballot_timeout_initial_ms
        increment_ms = info.ballot_timeout_increment_ms

  round = max(round, 1)
  timeout_ms = initial_ms + (round - 1) * increment_ms
  → Duration(min(timeout_ms, MAX_TIMEOUT_MS))
```

### has_upgrades (SCPDriver)

```
function has_upgrades(value) -> bool:
  sv = decode StellarValue from value or → false
  → sv.upgrades is not empty
```

### strip_all_upgrades (SCPDriver)

```
function strip_all_upgrades(value) -> nullable Value:
  sv = decode StellarValue from value or → null
  sv.upgrades = []
  → encode sv
```

### get_upgrade_nomination_timeout_limit (SCPDriver)

```
function get_upgrade_nomination_timeout_limit() -> u32:
  → MAX_U32  // never strip, matches stellar-core default
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~1634  | ~380       |
| Functions     | 55     | 38         |
