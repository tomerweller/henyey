## Pseudocode: crates/ledger/src/manager.rs

Core ledger state management and coordination. `LedgerManager` is the central
component for managing ledger state: maintaining the current header, updating
the bucket list Merkle tree, executing transactions, and providing snapshots.

---

CONST FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION = 23

### Types

```
type OfferAccountAssetIndex = Map<(account_bytes[32], AssetKey), Set<offer_id>>

struct PendingEvictionScan:
  handle: ThreadHandle<EvictionResult>
  target_ledger_seq: u32
  settings: StateArchivalSettings

struct CacheInitResult:
  offers: Map<offer_id, LedgerEntry>
  offer_index: OfferAccountAssetIndex
  module_cache: PersistentModuleCache or null
  soroban_state: InMemorySorobanState

struct LevelScanResult:
  entries: Map<LedgerKey, LedgerEntry>
  ttl_entries: Map<hash_bytes[32], (TtlKey, TtlData)>
  dead_keys: Set<LedgerKey>
  dead_ttl_keys: Set<hash_bytes[32]>

struct LedgerManagerConfig:
  validate_bucket_hash: bool
  emit_classic_events: bool
  backfill_stellar_asset_events: bool
  bucket_list_db: BucketListDbConfig
```

---

### Helper: index_offer_insert

```
fn index_offer_insert(index, offer):
  seller = account_id_bytes(offer.seller_id)
  selling_key = AssetKey.from(offer.selling)
  buying_key = AssetKey.from(offer.buying)
  MUTATE index[(seller, selling_key)] add offer.offer_id
  MUTATE index[(seller, buying_key)] add offer.offer_id
```

### Helper: index_offer_remove

```
fn index_offer_remove(index, offer):
  seller = account_id_bytes(offer.seller_id)
  selling_key = AssetKey.from(offer.selling)
  buying_key = AssetKey.from(offer.buying)
  if index has (seller, selling_key):
    MUTATE index[(seller, selling_key)] remove offer.offer_id
  if index has (seller, buying_key):
    MUTATE index[(seller, buying_key)] remove offer.offer_id
```

---

### prepend_fee_event

"Adds a NewFee event at the beginning of the transaction's event list
to record the fee charged. Used for Protocol 20+ classic event emission."

```
fn prepend_fee_event(meta, fee_source, fee_charged,
                     protocol_version, network_id, classic_events):
  GUARD fee_charged == 0 or not classic_events.events_enabled(protocol_version)
    → return (no-op)

  manager = new TxEventManager(enabled=true, protocol_version,
                                network_id, classic_events)
  manager.new_fee_event(fee_source, fee_charged, BeforeAllTxs)
  fee_events = manager.finalize()
  GUARD fee_events is empty → return

  if meta is V4:
    combined = fee_events + meta.events
    MUTATE meta.events = combined
```

**Calls:** [`TxEventManager::new_fee_event`](../tx/event_manager.pc.md), [`TxEventManager::finalize`](../tx/event_manager.pc.md)

---

### Helper: process_scan_entry

"Core logic for processing a single bucket entry during cache initialization scan."

```
fn process_scan_entry(entry, key, seen_keys, entries, ttl_entries,
                      dead_keys, dead_ttl_keys, soroban_enabled,
                      module_cache, protocol_version):
  GUARD key in seen_keys → return
  GUARD not soroban_enabled and key is not Offer → return

  MUTATE seen_keys add key

  if entry is Live or Init:
    le = entry.ledger_entry

    if le.data is ContractCode and module_cache exists:
      module_cache.add_contract(le.data.code, protocol_version)

    if le.data is Ttl:
      ttl_key = TtlKey(key_hash = le.data.key_hash)
      ttl_data = TtlData(live_until = le.data.live_until_ledger_seq,
                          last_modified = le.last_modified_ledger_seq)
      MUTATE ttl_entries[key_hash_bytes] = (ttl_key, ttl_data)
    else:
      MUTATE entries[key] = le

  else if entry is Dead:
    "Track dead keys so they shadow live entries at higher (older) levels."
    if key is Ttl:
      MUTATE dead_ttl_keys add key.key_hash_bytes
    MUTATE dead_keys add key
```

---

### scan_single_level

"Scan curr + snap buckets for a single level. Curr shadows snap within a level."

```
fn scan_single_level(curr, snap, soroban_enabled,
                     module_cache, protocol_version) -> LevelScanResult:
  entries = {}
  ttl_entries = {}
  seen_keys = {}
  dead_keys = {}
  dead_ttl_keys = {}

  "Scan curr first, then snap (curr shadows snap within a level)"
  for bucket in [curr, snap]:
    for entry in bucket.iter():
      key = entry.key()
      GUARD key is null → continue   // metadata entry
      GUARD key is not Offer, ContractCode, ContractData, Ttl,
            or ConfigSetting → continue

      process_scan_entry(entry, key, seen_keys, entries,
                         ttl_entries, dead_keys, dead_ttl_keys,
                         soroban_enabled, module_cache,
                         protocol_version)

  → LevelScanResult { entries, ttl_entries, dead_keys, dead_ttl_keys }
```

---

### merge_level_results

"Merge per-level scan results into a single CacheInitResult.
Processes levels in order (0 -> 10) so lower-numbered levels (newer data)
shadow higher-numbered levels."

```
fn merge_level_results(level_results, module_cache,
                       protocol_version, rent_config) -> CacheInitResult:
  soroban_state = new InMemorySorobanState
  mem_offers = {}
  global_seen = {}
  global_ttl_seen = {}

  for level_result in level_results:
    "Register dead keys from this level into global seen set."
    "Dead entries at lower (newer) levels shadow live entries at higher (older) levels."
    for dead_key in level_result.dead_keys:
      MUTATE global_seen add dead_key
    for dead_ttl_hash in level_result.dead_ttl_keys:
      MUTATE global_ttl_seen add dead_ttl_hash

    for (key, entry) in level_result.entries:
      GUARD key already in global_seen → continue
      MUTATE global_seen add key

      if entry.data is Offer:
        MUTATE mem_offers[offer.offer_id] = entry
      else if entry.data is ContractCode:
        soroban_state.create_contract_code(entry, protocol_version, rent_config)
      else if entry.data is ContractData:
        soroban_state.create_contract_data(entry)
      else if entry.data is ConfigSetting:
        soroban_state.process_entry_create(entry, protocol_version, rent_config)

    for (key_hash, (ttl_key, ttl_data)) in level_result.ttl_entries:
      GUARD key_hash already in global_ttl_seen → continue
      MUTATE global_ttl_seen add key_hash
      soroban_state.create_ttl(ttl_key, ttl_data)

  "Build the (account, asset) secondary index"
  offer_index = {}
  for entry in mem_offers.values():
    if entry.data is Offer:
      index_offer_insert(offer_index, entry.data)

  → CacheInitResult { offers: mem_offers, offer_index,
                       module_cache, soroban_state }
```

**Calls:** [`InMemorySorobanState::create_contract_code`](soroban_state.pc.md), [`InMemorySorobanState::create_contract_data`](soroban_state.pc.md), [`InMemorySorobanState::create_ttl`](soroban_state.pc.md)

---

### scan_parallel

"Spawn one OS thread per bucket level (11 levels), then merge results in level order."

```
fn scan_parallel(bucket_list, protocol_version, soroban_enabled,
                 rent_config, module_cache) -> CacheInitResult:
  shared_module_cache = shared_ref(module_cache)

  level_results = parallel for (level_idx, level) in bucket_list.levels():
    scan_single_level(level.curr, level.snap, soroban_enabled,
                      shared_module_cache, protocol_version)

  module_cache = unwrap_shared(shared_module_cache)
  → merge_level_results(level_results, module_cache,
                         protocol_version, rent_config)
```

---

### scan_bucket_list_for_caches

"Standalone bucket list scan that returns cache data. Can run on a background thread."

```
fn scan_bucket_list_for_caches(bucket_list, protocol_version) -> CacheInitResult:
  rent_config = load_soroban_rent_config_from_bucket_list(bucket_list)
  soroban_enabled = (protocol_version >= MIN_SOROBAN_PROTOCOL_VERSION)

  module_cache = null
  if soroban_enabled:
    module_cache = PersistentModuleCache.new_for_protocol(protocol_version)

  → scan_parallel(bucket_list, protocol_version, soroban_enabled,
                   rent_config, module_cache)
```

**Calls:** [`load_soroban_rent_config_from_bucket_list`](#helper-load_soroban_rent_config_from_bucket_list)

---

### Helper: load_soroban_rent_config_from_bucket_list

"Load Soroban rent config via point lookups on the bucket list."

```
fn load_soroban_rent_config_from_bucket_list(bucket_list) -> SorobanRentConfig or null:
  cpu_params = bucket_list.get(ConfigSetting:CpuInstructions)
  GUARD cpu_params is null → null
  mem_params = bucket_list.get(ConfigSetting:MemoryBytes)
  GUARD mem_params is null → null
  compute = bucket_list.get(ConfigSetting:ContractComputeV0)
  GUARD compute is null → null

  → SorobanRentConfig {
      cpu_cost_params: cpu_params,
      mem_cost_params: mem_params,
      tx_max_instructions: compute.tx_max_instructions,
      tx_max_memory_bytes: compute.tx_memory_limit
    }
```

---

### Helper: load_eviction_iterator_from_bucket_list

"Load EvictionIterator position from bucket list ConfigSettingEntry."

```
fn load_eviction_iterator_from_bucket_list(bucket_list) -> EvictionIterator or null:
  entry = bucket_list.get(ConfigSetting:EvictionIterator)
  GUARD entry is null → null
  if entry.data is ConfigSetting:EvictionIterator(iter):
    → EvictionIterator {
        bucket_file_offset: iter.bucket_file_offset,
        bucket_list_level: iter.bucket_list_level,
        is_curr_bucket: iter.is_curr_bucket
      }
  → null
```

---

STATE_MACHINE: LedgerManager
  STATES: [Uninitialized, Initialized]
  TRANSITIONS:
    Uninitialized -> Initialized: initialize() or verify_and_install_bucket_lists()
    Initialized -> Uninitialized: reset()

### LedgerManager Fields

```
struct LedgerManager:
  bucket_list: shared RwLock<BucketList>
  hot_archive_bucket_list: shared RwLock<HotArchiveBucketList or null>
  network_id: NetworkId
  state: RwLock<LedgerState { header, header_hash, initialized }>
  config: LedgerManagerConfig
  module_cache: RwLock<PersistentModuleCache or null>
  offers_initialized: shared RwLock<bool>
  offer_store: shared RwLock<Map<offer_id, LedgerEntry>>
  offer_account_asset_index: shared RwLock<OfferAccountAssetIndex>
  soroban_state: shared SharedSorobanState
  executor: Mutex<TransactionExecutor or null>
  pending_eviction_scan: Mutex<PendingEvictionScan or null>
```

---

### LedgerManager::new

```
fn new(network_passphrase, config) -> LedgerManager:
  network_id = NetworkId.from_passphrase(network_passphrase)
  → LedgerManager {
      bucket_list: default BucketList,
      hot_archive_bucket_list: null,
      network_id,
      state: { header: genesis_header(), header_hash: ZERO, initialized: false },
      config,
      module_cache: null,
      offers_initialized: false,
      offer_store: {},
      offer_account_asset_index: {},
      soroban_state: new SharedSorobanState,
      executor: null,
      pending_eviction_scan: null
    }
```

**Calls:** [`create_genesis_header`](#helper-create_genesis_header)

---

### LedgerManager::initialize

"Initialize from bucket list state during catchup from history archives."

```
fn initialize(bucket_list, hot_archive_bucket_list, header, header_hash):
  protocol_version = header.ledger_version
  verify_and_install_bucket_lists(bucket_list, hot_archive_bucket_list,
                                   header, header_hash)
  initialize_all_caches(protocol_version, 0)
```

**Calls:** [`verify_and_install_bucket_lists`](#ledgermanagerverify_and_install_bucket_lists), [`initialize_all_caches`](#ledgermanagerinitialize_all_caches)

---

### LedgerManager::verify_and_install_bucket_lists

```
fn verify_and_install_bucket_lists(bucket_list, hot_archive_bucket_list,
                                    header, header_hash):
  GUARD state.initialized → error AlreadyInitialized

  "Compute bucket list hash for verification"
  live_hash = bucket_list.hash()
  @version(>=23):
    hot_hash = hot_archive_bucket_list.hash()
    computed_hash = SHA256(live_hash || hot_hash)
  @version(<23):
    computed_hash = live_hash

  expected_hash = header.bucket_list_hash
  if config.validate_bucket_hash and computed_hash != expected_hash:
    → error HashMismatch

  MUTATE self.bucket_list = bucket_list
  MUTATE self.hot_archive_bucket_list = hot_archive_bucket_list
  MUTATE bucket_list.ledger_seq = header.ledger_seq
  MUTATE bucket_list.bucket_list_db_config = config.bucket_list_db
  if hot_archive exists:
    MUTATE hot_archive.ledger_seq = header.ledger_seq

  MUTATE state.header = header
  MUTATE state.header_hash = header_hash
  MUTATE state.initialized = true
```

---

### LedgerManager::reset

"Clear all caches, bucket lists, and state for re-initialization."

```
fn reset():
  MUTATE bucket_list = default BucketList
  MUTATE hot_archive_bucket_list = null
  MUTATE module_cache = null
  MUTATE offers_initialized = false
  MUTATE soroban_state.clear()
  MUTATE executor = null
  MUTATE pending_eviction_scan = null
  MUTATE state.header = genesis_header()
  MUTATE state.header_hash = ZERO
  MUTATE state.initialized = false
```

---

### LedgerManager::initialize_all_caches

"Single-pass scan of entire bucket list, dispatching each entry
to the appropriate handler. Reads ~24 GB once, instead of 5x with per-type scanning."

```
fn initialize_all_caches(protocol_version, _ledger_seq):
  cache_data = scan_bucket_list_for_caches(bucket_list, protocol_version)
  bucket_list.maybe_initialize_caches()

  MUTATE offer_store = cache_data.offers
  MUTATE offer_account_asset_index = cache_data.offer_index
  MUTATE module_cache = cache_data.module_cache
  MUTATE soroban_state = cache_data.soroban_state
  MUTATE offers_initialized = true
```

**Calls:** [`scan_bucket_list_for_caches`](#scan_bucket_list_for_caches)

---

### LedgerManager::close_ledger

"Main entry point for ledger close in live mode."

```
fn close_ledger(close_data, runtime_handle) -> LedgerCloseResult:
  ctx = begin_close(close_data)
  ctx.runtime_handle = runtime_handle

  ctx.apply_transactions()
  → ctx.commit()
```

**Calls:** [`begin_close`](#ledgermanagerbegin_close), [`LedgerCloseContext::apply_transactions`](#ledgerclosecontextapply_transactions), [`LedgerCloseContext::commit`](#ledgerclosecontextcommit)

---

### LedgerManager::begin_close

"Validate close data and create a LedgerCloseContext."

```
fn begin_close(close_data) -> LedgerCloseContext:
  GUARD not state.initialized → error NotInitialized

  version = state.header.ledger_version
  ASSERT: version >= MIN_LEDGER_PROTOCOL_VERSION
          and version <= CURRENT_LEDGER_PROTOCOL_VERSION
    NOTE: panics if outside range — node cannot process this ledger

  expected_seq = state.header.ledger_seq + 1
  GUARD close_data.ledger_seq != expected_seq → error InvalidSequence

  GUARD close_data.prev_ledger_hash != state.header_hash
    → error HashMismatch

  snapshot = create_snapshot()

  upgrade_ctx = new UpgradeContext(state.header.ledger_version)
  for upgrade in close_data.upgrades:
    upgrade_ctx.add_upgrade(upgrade)

  → LedgerCloseContext {
      manager: self,
      close_data,
      prev_header: state.header,
      prev_header_hash: state.header_hash,
      delta: new LedgerDelta(expected_seq),
      snapshot,
      stats: new LedgerCloseStats,
      upgrade_ctx,
      id_pool: state.header.id_pool,
      tx_results: [],
      tx_result_metas: [],
      hot_archive_restored_keys: [],
      ...
    }
```

**Calls:** [`create_snapshot`](#ledgermanagercreate_snapshot), [`UpgradeContext::new`](close.pc.md)

---

### LedgerManager::create_snapshot

"Create a snapshot with lookup functions that check in-memory Soroban state
first (O(1)) then fall back to bucket list snapshot (O(log n))."

```
fn create_snapshot() -> SnapshotHandle:
  snapshot = new LedgerSnapshot(state.header, state.header_hash, {})
  bucket_list_snapshot = new BucketListSnapshot(bucket_list, state.header)

  "Single-entry lookup:"
  lookup_fn = fn(key):
    if InMemorySorobanState.is_in_memory_type(key):
      → soroban_state.get(key)          // authoritative, no fallback
    → bucket_list_snapshot.get(key)

  "Batch lookup:"
  batch_lookup_fn = fn(keys):
    result = []
    bucket_keys = []
    for key in keys:
      if is_in_memory_type(key):
        if soroban_state has key:
          result.add(soroban_state.get(key))
        continue    // authoritative for in-memory types
      bucket_keys.add(key)

    if bucket_keys not empty:
      result.extend(bucket_list_snapshot.load_keys(bucket_keys))
    → result

  "Offer entries lookup:"
  entries_fn = fn():
    → offer_store.values()

  "Offers by (account, asset) lookup:"
  offers_by_account_asset_fn = fn(account_id, asset):
    seller = account_id_bytes(account_id)
    asset_key = AssetKey.from(asset)
    offer_ids = offer_account_asset_index[(seller, asset_key)]
    GUARD offer_ids is null → []
    result = []
    for offer_id in offer_ids:
      if offer_store has offer_id:
        result.add(offer_store[offer_id])
    → result

  handle = SnapshotHandle.with_lookups_and_entries(snapshot, lookup_fn, entries_fn)
  handle.set_batch_lookup(batch_lookup_fn)
  handle.set_offers_by_account_asset(offers_by_account_asset_fn)
  → handle
```

---

### LedgerManager::commit_close

"Validate bucket list hash and update in-memory offer store + state."

```
fn commit_close(delta, new_header, new_header_hash):
  if config.validate_bucket_hash:
    live_hash = bucket_list.hash()
    @version(>=23):
      if hot_archive exists:
        computed = SHA256(live_hash || hot_archive.hash())
      else:
        computed = live_hash
    @version(<23):
      computed = live_hash

    expected = new_header.bucket_list_hash
    GUARD computed != expected → error HashMismatch

  "Update in-memory offer store and secondary index"
  if offers_initialized:
    offer_upserts = []
    offer_deletes = []

    for change in delta.changes():
      key = change.key()
      GUARD key is not Offer → continue

      if change is Created and entry is Offer:
        offer_upserts.add(entry)
      else if change is Updated and current is Offer:
        offer_upserts.add(current)
        "Remove old index entries (asset pair may have changed)"
        index_offer_remove(offer_index, previous.offer)
      else if change is Deleted:
        offer_deletes.add(key.offer_id)
        index_offer_remove(offer_index, previous.offer)

    if offer_upserts or offer_deletes not empty:
      for entry in offer_upserts:
        MUTATE offer_store[offer.offer_id] = entry
        index_offer_insert(offer_index, offer)
      for offer_id in offer_deletes:
        MUTATE offer_store remove offer_id

  MUTATE state.header = new_header
  MUTATE state.header_hash = new_header_hash
```

---

### LedgerCloseContext Fields

```
struct LedgerCloseContext:
  manager: ref LedgerManager
  close_data: LedgerCloseData
  prev_header: LedgerHeader
  prev_header_hash: Hash256
  delta: LedgerDelta
  snapshot: SnapshotHandle
  stats: LedgerCloseStats
  upgrade_ctx: UpgradeContext
  id_pool: u64
  tx_results: [TransactionResultPair]
  tx_result_metas: [TransactionResultMetaV1]
  hot_archive_restored_keys: [LedgerKey]
  runtime_handle: tokio Handle or null
```

---

### LedgerCloseContext::load_entry

```
fn load_entry(key) -> LedgerEntry or null:
  if delta has pending change for key:
    → change.current_entry()
  → snapshot.get_entry(key)
```

---

### LedgerCloseContext::load_state_archival_settings

"Parity: eviction scan runs after config upgrades are applied, so it sees
the upgraded StateArchival settings. Check delta first, then snapshot."

```
fn load_state_archival_settings() -> StateArchivalSettings or null:
  entry = load_entry(ConfigSetting:StateArchival)
  GUARD entry is null → null
  if entry.data is ConfigSetting:StateArchival(settings):
    → StateArchivalSettings {
        eviction_scan_size: settings.eviction_scan_size,
        starting_eviction_scan_level: settings.starting_eviction_scan_level,
        max_entries_to_archive: settings.max_entries_to_archive
      }
  → null
```

---

### LedgerCloseContext::create_cost_types_for_v25

"Parity: NetworkConfig.cpp:1450-1457 createCostTypesForV25
Resizes CPU and memory cost param entries to include BN254 curve cost types."

```
CONST BN254_FR_INV = 84
CONST NEW_SIZE = 85   // BN254_FR_INV + 1

fn create_cost_types_for_v25():
  "--- Update CPU cost params ---"
  cpu_entry = load_entry(ConfigSetting:CpuInstructions)
  GUARD cpu_entry is null → error
  cpu_params = cpu_entry.data.params
  resize cpu_params to NEW_SIZE (fill with {0, 0})

  "Set BN254 CPU cost values (from NetworkConfig.cpp:556-629)"
  cpu_params[70] = {344, 0}     // Bn254EncodeFp
  cpu_params[71] = {476, 0}     // Bn254DecodeFp
  cpu_params[72] = {904, 0}     // Bn254G1CheckPointOnCurve
  cpu_params[73] = {2811, 0}    // Bn254G2CheckPointOnCurve
  cpu_params[74] = {2937755, 0} // Bn254G2CheckPointInSubgroup
  cpu_params[75] = {61, 0}      // Bn254G1ProjectiveToAffine
  cpu_params[76] = {3623, 0}    // Bn254G1Add
  cpu_params[77] = {1150435, 0} // Bn254G1Mul
  cpu_params[78] = {5263916, 392472814} // Bn254Pairing
  cpu_params[79] = {2052, 0}    // Bn254FrFromU256
  cpu_params[80] = {1133, 0}    // Bn254FrToU256
  cpu_params[81] = {74, 0}      // Bn254FrAddSub
  cpu_params[82] = {332, 0}     // Bn254FrMul
  cpu_params[83] = {755, 68930} // Bn254FrPow
  cpu_params[84] = {33151, 0}   // Bn254FrInv
  delta.record_update(cpu_entry, new_cpu_entry)

  "--- Update memory cost params ---"
  mem_entry = load_entry(ConfigSetting:MemoryBytes)
  GUARD mem_entry is null → error
  mem_params = mem_entry.data.params
  resize mem_params to NEW_SIZE (fill with {0, 0})

  "Most BN254 memory costs are {0,0} except:"
  mem_params[78] = {1821, 6232546} // Bn254Pairing
  mem_params[80] = {312, 0}        // Bn254FrToU256
  delta.record_update(mem_entry, new_mem_entry)
```

---

### LedgerCloseContext::apply_upgrades_to_delta

"Apply version upgrades, config upgrades, and Soroban state size recomputation."
"Returns (archival_changed, memory_cost_changed, upgrades_meta)."

"Parity: Upgrades.cpp:1229-1242 applyVersionUpgrade"

```
fn apply_upgrades_to_delta(prev_version, protocol_version)
    -> (bool, bool, [UpgradeEntryMeta]):

  version_upgrade_memory_cost_changed = false

  "--- Version upgrade side effects ---"
  if prev_version != protocol_version:
    delta_before = delta.num_changes()
    if prev_version < 25 and protocol_version >= 25:
      create_cost_types_for_v25()
      version_upgrade_memory_cost_changed = true
    version_changes = extract_changes(delta, from: delta_before)
  else:
    version_changes = []

  "--- Config upgrades ---"
  archival_changed = false
  memory_cost_changed = false
  per_config_changes = {}
  if upgrade_ctx.has_config_upgrades():
    (archival_changed, memory_cost_changed, per_config_changes) =
      upgrade_ctx.apply_config_upgrades(snapshot, delta)

  "--- MaxSorobanTxSetSize upgrade ---"
  max_soroban_changes = []
  if upgrade_ctx.max_soroban_tx_set_size_upgrade() exists:
    max_soroban_changes = upgrade_ctx.apply_max_soroban_tx_set_size(
                            snapshot, delta, close_data.ledger_seq)

  "--- Build UpgradeEntryMeta for each upgrade ---"
  upgrades_meta = []
  for upgrade in close_data.upgrades:
    if upgrade is Version:   changes = version_changes
    if upgrade is Config(k): changes = per_config_changes[k]
    if upgrade is MaxSorobanTxSetSize: changes = max_soroban_changes
    else:                    changes = []
    upgrades_meta.add(UpgradeEntryMeta { upgrade, changes })

  "Parity: Upgrades.cpp:1238-1242 and 1449-1453"
  "handleUpgradeAffectingSorobanInMemoryStateSize is called:"
  "1. After version upgrade to V23+"
  "2. After config upgrade that changes ContractCostParamsMemoryBytes"
  version_triggers = (prev_version != protocol_version
                      and protocol_version >= 23)
  if (memory_cost_changed or version_upgrade_memory_cost_changed
      or version_triggers)
     and protocol_version >= MIN_SOROBAN_PROTOCOL_VERSION:

    rent_config = load_rent_config_from_delta_or_snapshot()
    soroban_state.recompute_contract_code_sizes(protocol_version, rent_config)

    "Parity: NetworkConfig.cpp:2165 updateRecomputedSorobanStateSize"
    @version(>=23):
      new_size = soroban_state.total_size()
      window_entry = load from delta or snapshot (LiveSorobanStateSizeWindow)
      if window_entry exists:
        overwrite all window entries with new_size
        delta.record_update(previous_entry, new_window_entry)

  → (archival_changed, memory_cost_changed, upgrades_meta)
```

**Calls:** [`create_cost_types_for_v25`](#ledgerclosecontextcreate_cost_types_for_v25), [`UpgradeContext::apply_config_upgrades`](close.pc.md), [`UpgradeContext::apply_max_soroban_tx_set_size`](close.pc.md)

---

### LedgerCloseContext::apply_transactions

"Execute all transactions. Executor is persisted across ledger closes
to avoid reloading ~911K offers each time (~2.7s on mainnet)."

```
fn apply_transactions() -> [TransactionExecutionResult]:
  transactions = close_data.tx_set.transactions_with_base_fee()
  GUARD transactions is empty → return []

  soroban_config = load_soroban_config(snapshot, prev_header.ledger_version)
  soroban_base_prng_seed = close_data.tx_set_hash()
  classic_events = ClassicEventConfig {
    emit: manager.config.emit_classic_events,
    backfill: manager.config.backfill_stellar_asset_events
  }
  module_cache = manager.module_cache
  hot_archive = manager.hot_archive_bucket_list

  "Take persistent executor or create new one"
  executor = manager.executor.take()
  is_new = (executor is null)

  if executor is null:
    ctx = new LedgerContext(close_data.ledger_seq, close_data.close_time,
                            prev_header.base_fee, prev_header.base_reserve,
                            prev_header.ledger_version, manager.network_id)
    executor = new TransactionExecutor(ctx, id_pool, soroban_config,
                                        classic_events)

  if is_new:
    executor.set_module_cache(module_cache)
    executor.set_hot_archive(hot_archive)
    executor.load_orderbook_offers(snapshot)
  else:
    executor.advance_to_ledger_preserving_offers(
      close_data.ledger_seq, close_data.close_time,
      prev_header.base_reserve, prev_header.ledger_version,
      id_pool, soroban_config)
    executor.set_module_cache(module_cache)
    executor.set_hot_archive(hot_archive)

  "Check for structured Soroban phase (V1 TransactionPhase)"
  phase_structure = close_data.tx_set.soroban_phase_structure()
  has_parallel = phase_structure exists

  if has_parallel and protocol_version >= PARALLEL_SOROBAN_PHASE_PROTOCOL_VERSION:
    phase = phase_structure
    classic_txs = close_data.tx_set.classic_phase_transactions()

    "Pre-deduct ALL fees (classic + Soroban) before any TX body executes"
    "Parity: stellar-core processFeesSeqNums() processes all phases' fees first"
    (classic_pre_charged, soroban_pre_charged, total_fee_pool) =
      pre_deduct_all_fees_on_delta(classic_txs, phase,
        prev_header.base_fee, network_id,
        close_data.ledger_seq, delta, snapshot)
    delta.record_fee_pool_delta(total_fee_pool)

    "Pre-load fee-deducted accounts into executor"
    for entry in delta.current_entries():
      if entry.data is Account:
        executor.state.load_entry(entry)

    "Execute classic phase (fees already deducted)"
    classic_result = run_transactions_on_executor(
      executor, snapshot, classic_txs, prev_header.base_fee,
      soroban_base_prng_seed, fees_already_deducted=false,
      delta, classic_pre_charged)

    "Execute Soroban parallel phase"
    soroban_result = execute_soroban_parallel_phase(
      snapshot, phase, classic_txs.len(), ledger_context,
      delta, soroban_context, soroban_pre_charged)

    "Combine: classic first, then Soroban"
    tx_set_result = merge(classic_result, soroban_result)

  else:
    "Sequential path: run all transactions on persistent executor"
    tx_set_result = run_transactions_on_executor(
      executor, snapshot, transactions, prev_header.base_fee,
      soroban_base_prng_seed, deduct_fees=true, delta, null)

  "Store executor back for reuse on next ledger close"
  MUTATE manager.executor = executor

  "Prepend fee events for classic event emission"
  if classic_events.events_enabled(prev_header.ledger_version):
    all_txs = close_data.tx_set.transactions_with_base_fee()
    for (idx, (envelope, meta)) in zip(all_txs, tx_set_result.tx_result_metas):
      fee_charged = tx_set_result.tx_results[idx].result.fee_charged
      frame = TransactionFrame(envelope, manager.network_id)
      fee_source = muxed_to_account_id(frame.fee_source_account())
      prepend_fee_event(meta.tx_apply_processing, fee_source,
                        fee_charged, prev_header.ledger_version,
                        manager.network_id, classic_events)

  self.id_pool = tx_set_result.id_pool
  self.tx_results = tx_set_result.tx_results
  self.tx_result_metas = tx_set_result.tx_result_metas
  self.hot_archive_restored_keys = tx_set_result.hot_archive_restored_keys
  → tx_set_result.results
```

**Calls:** [`load_soroban_config`](execution.pc.md), [`pre_deduct_all_fees_on_delta`](execution.pc.md), [`run_transactions_on_executor`](execution.pc.md), [`execute_soroban_parallel_phase`](execution.pc.md), [`prepend_fee_event`](#prepend_fee_event)

---

### LedgerCloseContext::build_and_hash_header

```
fn build_and_hash_header(bucket_list_hash, tx_result_hash,
                          archival_changed, memory_cost_changed)
    -> (LedgerHeader, Hash256):

  total_coins = prev_header.total_coins + delta.total_coins_delta()
  fee_pool = prev_header.fee_pool + delta.fee_pool_delta()

  new_header = create_next_header(
    prev_header, prev_header_hash,
    close_data.close_time, close_data.tx_set_hash(),
    bucket_list_hash, tx_result_hash,
    total_coins, fee_pool,
    prev_header.inflation_seq,
    close_data.stellar_value_ext)

  upgrade_ctx.apply_to_header(new_header)

  "Encode raw upgrades in scp_value.upgrades for correct header hash"
  raw_upgrades = [xdr_encode(u) for u in close_data.upgrades]
  new_header.scp_value.upgrades = raw_upgrades
  new_header.id_pool = self.id_pool

  header_hash = compute_header_hash(new_header)
  → (new_header, header_hash)
```

**Calls:** [`create_next_header`](header.pc.md), [`compute_header_hash`](header.pc.md)

---

### LedgerCloseContext::commit

"Main commit function: eviction, bucket list update, header computation, meta."

```
fn commit() -> LedgerCloseResult:
  tx_result_hash = hash_xdr(TransactionResultSet { results: tx_results })

  "Determine protocol version after upgrades"
  upgraded_header = prev_header with upgrades applied
  protocol_version = upgraded_header.ledger_version
  prev_version = prev_header.ledger_version

  (archival_changed, memory_cost_changed, upgrades_meta) =
    apply_upgrades_to_delta(prev_version, protocol_version)

  init_entries = delta.init_entries()
  live_entries = delta.live_entries()
  dead_entries = delta.dead_entries()

  "Filter out hot-archive-restored entries from dead_entries"
  if hot_archive_restored_keys not empty:
    restored_set = Set(hot_archive_restored_keys)
    dead_entries.retain(key -> key not in restored_set)

  "Load state archival settings BEFORE acquiring bucket list lock"
  eviction_settings = null
  @version(>=23):
    eviction_settings = load_state_archival_settings()

  "--- Acquire bucket list write lock ---"
  acquire write lock on bucket_list

  "--- Eviction scan (Protocol 23+) ---"
  archived_entries = []
  evicted_meta_keys = []
  @version(>=23):
    if hot_archive exists:
      "Try background eviction scan from previous ledger"
      pending = manager.pending_eviction_scan.take()
      eviction_result = null
      if pending exists
         and pending.target_ledger_seq == close_data.ledger_seq
         and pending.settings == eviction_settings:
        eviction_result = pending.handle.join()
      if eviction_result is null:
        "Inline fallback"
        iter = load_eviction_iterator_from_bucket_list(bucket_list)
              or new EvictionIterator(eviction_settings.starting_level)
        eviction_result = bucket_list.scan_for_eviction_incremental(
                            iter, close_data.ledger_seq, eviction_settings)

      "Resolution: TTL filtering + max_entries limit"
      modified_ttl_keys = Set of TTL keys from init_entries + live_entries
      resolved = eviction_result.resolve(
                   eviction_settings.max_entries_to_archive,
                   modified_ttl_keys)
      evicted_meta_keys = resolved.evicted_keys
      dead_entries.extend(resolved.evicted_keys)
      archived_entries = resolved.archived_entries

      "Add updated EvictionIterator to live entries"
      live_entries.add(LedgerEntry {
        data: ConfigSetting:EvictionIterator(resolved.end_iterator),
        last_modified: close_data.ledger_seq
      })

  "--- State size window update (Protocol 20+) ---"
  @version(>=MIN_SOROBAN_PROTOCOL_VERSION):
    if no window entry already in live_entries:
      sample_period = load from bucket_list (default 64)
      if close_data.ledger_seq % sample_period == 0:
        "Snapshot state size BEFORE flushing this ledger's changes"
        soroban_state_size = manager.soroban_state.total_size()
        window_entry = compute_state_size_window_entry(
                         close_data.ledger_seq, protocol_version,
                         bucket_list, soroban_state_size)
        if window_entry exists:
          live_entries.add(window_entry)

  "--- Update in-memory Soroban state ---"
  @version(>=MIN_SOROBAN_PROTOCOL_VERSION):
    rent_config = load_soroban_rent_config(bucket_list)
    for entry in init_entries:
      soroban_state.process_entry_create(entry, protocol_version, rent_config)
    for entry in live_entries:
      soroban_state.process_entry_update(entry, protocol_version, rent_config)
    for key in dead_entries:
      soroban_state.process_entry_delete(key)
      if key is ContractCode:
        module_cache.remove_contract(key.hash)

  "--- Advance bucket list through any skipped ledgers ---"
  if bucket_list.ledger_seq < close_data.ledger_seq - 1:
    bucket_list.advance_to_ledger(close_data.ledger_seq,
                                   protocol_version, Live)

  "--- Add batch to live bucket list ---"
  bucket_list.add_batch(close_data.ledger_seq, protocol_version,
                         Live, init_entries, live_entries, dead_entries)
  live_hash = bucket_list.hash()

  "--- Hot archive update (Protocol 23+) ---"
  @version(>=23):
    if hot_archive exists:
      if hot_archive.ledger_seq < close_data.ledger_seq - 1:
        hot_archive.advance_to_ledger(close_data.ledger_seq,
                                       protocol_version)
      hot_archive.add_batch(close_data.ledger_seq, protocol_version,
                             archived_entries, hot_archive_restored_keys)
      hot_hash = hot_archive.hash()
      bucket_list_hash = SHA256(live_hash || hot_hash)
    else:
      bucket_list_hash = live_hash
  @version(<23):
    bucket_list_hash = live_hash

  "--- Start background eviction scan for next ledger ---"
  @version(>=23):
    if eviction_settings exists:
      snapshot = BucketListSnapshot(bucket_list, prev_header)
      iter = load_eviction_iterator(bucket_list) or new EvictionIterator
      target = close_data.ledger_seq + 1
      spawn thread: snapshot.scan_for_eviction_incremental(iter, target, settings)
      MUTATE manager.pending_eviction_scan = PendingEvictionScan { handle, target, settings }

  "release bucket list write lock"

  "--- Build and hash new header ---"
  (new_header, header_hash) = build_and_hash_header(
    bucket_list_hash, tx_result_hash,
    archival_changed, memory_cost_changed)

  "--- Commit to manager ---"
  manager.commit_close(delta, new_header, header_hash)

  "--- Build close meta ---"
  avg_soroban_state_size = average of LiveSorobanStateSizeWindow entries
  meta = build_ledger_close_meta(close_data, new_header, header_hash,
                                  tx_result_metas, evicted_meta_keys,
                                  avg_soroban_state_size, upgrades_meta)

  → LedgerCloseResult(new_header, header_hash)
      .with_tx_results(tx_results)
      .with_meta(meta)
      .with_perf(perf)
```

**Calls:** [`apply_upgrades_to_delta`](#ledgerclosecontextapply_upgrades_to_delta), [`BucketList::add_batch`](../bucket/bucket_list.pc.md), [`HotArchiveBucketList::add_batch`](../bucket/hot_archive.pc.md), [`build_and_hash_header`](#ledgerclosecontextbuild_and_hash_header), [`commit_close`](#ledgermanagercommit_close), [`build_ledger_close_meta`](#helper-build_ledger_close_meta)

---

### Helper: build_generalized_tx_set

```
fn build_generalized_tx_set(tx_set) -> GeneralizedTransactionSet:
  if tx_set is Generalized:
    → tx_set
  if tx_set is Classic(set):
    component = TxSetCompTxsMaybeDiscountedFee { base_fee: null, txs: set.txs }
    phase = V0([component])
    → V1 { previous_ledger_hash: set.previous_ledger_hash, phases: [phase] }
```

---

### Helper: build_ledger_close_meta

```
fn build_ledger_close_meta(close_data, header, header_hash,
                            tx_result_metas, evicted_keys,
                            live_soroban_state_size, upgrades_meta)
    -> LedgerCloseMeta:

  ledger_header = LedgerHeaderHistoryEntry {
    hash: header_hash, header: header }
  tx_set = build_generalized_tx_set(close_data.tx_set)

  → LedgerCloseMeta:V2 {
      ledger_header,
      tx_set,
      tx_processing: tx_result_metas,
      upgrades_processing: upgrades_meta,
      scp_info: close_data.scp_history,
      total_byte_size_of_live_soroban_state: live_soroban_state_size,
      evicted_keys
    }
```

---

### Helper: create_genesis_header

```
fn create_genesis_header() -> LedgerHeader:
  → LedgerHeader {
      ledger_version: 0,
      previous_ledger_hash: ZERO,
      scp_value: { tx_set_hash: ZERO, close_time: 0, upgrades: [], ext: Basic },
      tx_set_result_hash: ZERO,
      bucket_list_hash: ZERO,
      ledger_seq: 0,
      total_coins: 0,
      fee_pool: 0,
      inflation_seq: 0,
      id_pool: 0,
      base_fee: 100,
      base_reserve: 5_000_000,
      max_tx_set_size: 1000,
      skip_list: [ZERO, ZERO, ZERO, ZERO],
      ext: V0
    }
```

---

## Summary

| Metric        | Source  | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~3509  | ~530       |
| Functions     | 30     | 30         |
