## Pseudocode: crates/app/src/app/mod.rs

This is the central application coordinator for the Stellar node. It defines the
`App` struct, its initialization, state management, and callback implementations
for herder and sync recovery. Heavy subsystem logic is delegated to submodules:
`catchup_impl`, `consensus`, `ledger_close`, `lifecycle`, `peers`,
`survey_impl`, `tx_flooding`.

---

### Constants

```
CONST TIME_SLICED_PEERS_MAX = 25
CONST PEER_TYPE_OUTBOUND = 1
CONST PEER_TYPE_PREFERRED = 2
CONST PEER_TYPE_INBOUND = 0
CONST PEER_MAX_FAILURES_TO_SEND = 10
CONST TX_SET_REQUEST_WINDOW = 12
CONST MAX_TX_SET_REQUESTS_PER_TICK = 32

"Consensus stuck timeout matching stellar-core's
 CONSENSUS_STUCK_TIMEOUT_SECONDS"
CONST CONSENSUS_STUCK_TIMEOUT_SECS = 35

"Faster timeout when all peers report DontHave or disconnect"
CONST TX_SET_UNAVAILABLE_TIMEOUT_SECS = 5

"Number of consecutive recovery attempts without
 progress before escalating to SCP state requests"
CONST RECOVERY_ESCALATION_SCP_REQUEST = 6   // ~30s at 5s interval

"Number of consecutive recovery attempts before
 triggering full catchup"
CONST RECOVERY_ESCALATION_CATCHUP = 12      // ~60s at 5s interval

"Timeout for pending tx_set requests with no response"
CONST TX_SET_REQUEST_TIMEOUT_SECS = 10

CONST OUT_OF_SYNC_RECOVERY_TIMER_SECS = 10
CONST ARCHIVE_CHECKPOINT_CACHE_SECS = 60

"Post-catchup recovery window: prefer SCP recovery
 over another catchup for one full checkpoint cycle"
CONST POST_CATCHUP_RECOVERY_WINDOW_SECS = 300

CONST MAX_POST_CATCHUP_RECOVERY_ATTEMPTS = 3
```

---

### State Machines

```
STATE_MACHINE: AppState
  STATES: [Initializing, CatchingUp, Synced, Validating, ShuttingDown]
  TRANSITIONS:
    Initializing → CatchingUp:  when catchup is required
    Initializing → Synced:      when already up-to-date
    CatchingUp   → Synced:      when catchup completes
    Synced       → Validating:  when consensus participation begins (validators)
    Synced       → CatchingUp:  when node falls behind
    Any          → ShuttingDown: when shutdown requested
```

```
STATE_MACHINE: ConsensusStuckAction
  STATES: [Wait, AttemptRecovery, TriggerCatchup]
  NOTE: Evaluated when buffered ledgers exist but consensus stalls.
    Wait             → AttemptRecovery: timeout exceeded
    AttemptRecovery  → TriggerCatchup:  repeated failures
```

```
STATE_MACHINE: SurveySchedulerPhase
  STATES: [Idle, StartSent, RequestSent]
  TRANSITIONS:
    Idle        → StartSent:   survey start broadcast
    StartSent   → RequestSent: survey requests sent
    RequestSent → Idle:        survey complete / timeout
```

---

### CatchupTarget (enum)

```
CatchupTarget:
  Current       — catch up to latest
  Ledger(seq)   — catch up to specific ledger
  Checkpoint(n) — catch up to specific checkpoint
```

---

### App struct (fields summary)

```
App:
  config              — AppConfig
  state               — RWLock<AppState>
  db                  — Database
  keypair             — secret key
  bucket_manager      — shared BucketManager
  ledger_manager      — shared LedgerManager
  overlay             — RWLock<optional shared OverlayManager>
  herder              — shared Herder
  current_ledger      — RWLock<u32>
  is_validator        — bool

  // Channels & signals
  shutdown_tx/rx      — broadcast channel
  scp_envelope_tx/rx  — mpsc channel for outbound SCP envelopes

  // Sync tracking
  last_processed_slot       — RWLock<u64>
  catchup_in_progress       — atomic bool
  syncing_ledgers           — RWLock<BTreeMap<seq, LedgerCloseInfo>>
  last_externalized_slot    — atomic u64
  last_externalized_at      — RWLock<Instant>

  // Tx flooding
  tx_advert_queue/set       — pending tx hash adverts
  tx_adverts_by_peer        — per-peer advert tracking
  tx_demand_history         — demand pull history
  tx_set_dont_have          — per-txset DontHave tracking
  tx_set_last_request       — request throttling
  tx_set_all_peers_exhausted — atomic bool

  // Consensus stuck detection
  consensus_stuck_state     — RWLock<optional ConsensusStuckState>
  last_catchup_completed_at — RWLock<optional Instant>
  cached_archive_checkpoint — RWLock<optional (ledger, queried_at)>

  // Recovery
  sync_recovery_handle      — optional SyncRecoveryHandle
  sync_recovery_pending     — atomic bool
  recovery_attempts_without_progress — atomic u64
  recovery_baseline_ledger  — atomic u64
  lost_sync_count           — atomic u64

  // Survey
  survey_data, survey_scheduler, survey_nonce, etc.

  // Watchdog
  last_event_loop_tick_ms   — shared atomic u64
  event_loop_phase          — shared atomic u64 (phase codes 0-30)
```

---

### Helper: build_generalized_tx_set

```
build_generalized_tx_set(tx_set):
  component = TxSetComponentMaybeDiscountedFee(
    base_fee = null, txs = tx_set.transactions)
  phase = TransactionPhaseV0([component])
  → GeneralizedTransactionSetV1(
      previous_ledger_hash = tx_set.previous_ledger_hash,
      phases = [phase])
```

---

### Helper: decode_upgrades

```
decode_upgrades(upgrades):
  results = []
  for each upgrade in upgrades:
    decoded = LedgerUpgrade.from_xdr(upgrade.bytes)
    if decoded is valid:
      append decoded to results
    NOTE: skip invalid upgrades with warning
  → results
```

---

### App::new

```
new(config):
  config.validate()

  db_lock = acquire_db_lock(config)
  db = init_database(config)
  ensure_network_passphrase(db, config.network.passphrase)
  verify_on_disk_integrity(db)
  keypair = init_keypair(config)

  local_quorum_set = config.node.quorum_set.to_xdr()

  // Initialize subsystems
  bucket_manager = BucketManager(bucket_dir)
  ledger_manager = LedgerManager(config.network.passphrase, ...)
  herder = if config.is_validator:
             Herder.with_secret_key(herder_config, keypair)
           else:
             Herder(herder_config)
  herder.set_ledger_manager(ledger_manager)

  // Store local quorum set in DB
  if herder has local_quorum_set:
    db.store_scp_quorum_set(hash(qs), 0, qs)

  // Initialize metadata stream if configured
  meta_stream = MetaStreamManager(config.metadata) if configured

  // Create channels
  (shutdown_tx, shutdown_rx) = broadcast_channel(1)
  (scp_envelope_tx, scp_envelope_rx) = mpsc_channel(100)

  // Wire envelope sender for validators
  if config.is_validator:
    herder.set_envelope_sender(|envelope|
      scp_envelope_tx.try_send(envelope))

  → App { all fields initialized, state = Initializing }
```

**Calls**: [verify_on_disk_integrity](#appverify_on_disk_integrity), [ensure_network_passphrase](#appensure_network_passphrase), [init_database](#appinit_database), [acquire_db_lock](#appacquire_db_lock), [init_keypair](#appinit_keypair)

REF: BucketManager::new, LedgerManager::new, Herder::new, MetaStreamManager::new

---

### App::verify_on_disk_integrity

```
verify_on_disk_integrity(db):
  CONST VERIFY_DEPTH = 128

  latest = db.get_latest_ledger_seq()
  GUARD latest is null or 0     → ok (nothing to verify)

  current_seq = latest
  checked = 0
  while current_seq > 0 and checked < VERIFY_DEPTH:
    current = db.get_ledger_header(current_seq)
    GUARD current missing       → error
    prev = db.get_ledger_header(current_seq - 1)
    if prev missing:
      "Ledger header chain has a gap; skipping deeper checks"
      break
    prev_hash = compute_header_hash(prev)
    verify_header_chain(prev, prev_hash, current)
    current_seq -= 1
    checked += 1

  NOTE: "Skip list entries store bucket_list_hash values (not
  header hashes), so they cannot be verified by comparing against
  stored header hashes."
```

REF: henyey_ledger::compute_header_hash, henyey_ledger::verify_header_chain

---

### App::ensure_network_passphrase

```
ensure_network_passphrase(db, passphrase):
  stored = db.get_network_passphrase()
  if stored exists:
    GUARD stored != passphrase  → error "Network passphrase mismatch"
    → ok
  db.set_network_passphrase(passphrase)
```

---

### App::init_database

```
init_database(config):
  ensure parent directory exists
  db = Database.open(config.database.path)
  → db
```

---

### App::acquire_db_lock

```
acquire_db_lock(config):
  lock_path = config.database.path + ".lock"
  ensure parent directory exists
  file = open(lock_path, read+write+create+truncate)
  GUARD try_lock_exclusive fails → error "database is locked"
  → file
```

---

### App::init_keypair

```
init_keypair(config):
  if config.node.node_seed is set:
    → SecretKey.from_strkey(seed)
  else:
    → SecretKey.generate()    // ephemeral
```

---

### App::set_state

```
set_state(new_state):
  current = state.write()
  GUARD current == new_state    → no-op
  if current is (Synced or Validating) and new_state is CatchingUp:
    MUTATE lost_sync_count += 1
  current = new_state
```

---

### App::restore_operational_state

```
restore_operational_state():
  if is_validator:
    set_state(Validating)
  else:
    set_state(Synced)
```

---

### App::reset_tx_set_tracking

```
reset_tx_set_tracking():
  tx_set_all_peers_exhausted = false
  tx_set_dont_have.clear()
  tx_set_last_request.clear()
  tx_set_exhausted_warned.clear()
```

---

### App::manual_close_ledger

```
manual_close_ledger():
  GUARD not is_validator        → error "requires validator"
  GUARD not config.manual_close → error "manual close disabled"
  (current_ledger, _, _, _) = ledger_info()
  next = current_ledger + 1
  herder.trigger_next_ledger(next)
  → next
```

---

### App::self_check

```
self_check(depth):
  latest = db.get_latest_ledger_seq()
  GUARD latest is null or 0  → ok(checked=0)

  current_seq = latest
  checked = 0
  while current_seq > 0 and checked < depth:
    current = db.get_ledger_header(current_seq)
    prev = db.get_ledger_header(current_seq - 1)
    prev_hash = compute_header_hash(prev)
    verify_header_chain(prev, prev_hash, current)
    current_seq -= 1
    checked += 1

  → SelfCheckResult(ok=true, checked, last_verified)
```

---

### App::perform_maintenance

```
perform_maintenance(count):
  lcl = ledger_info().ledger_seq
  min_queued = db.load_publish_queue(limit=1).first()
  qmin = min(min_queued or lcl, lcl)
  lmin = qmin - CHECKPOINT_FREQUENCY

  db.delete_old_scp_entries(lmin, count)
  db.delete_old_ledger_headers(lmin, count)
```

---

### App::cleanup_stale_bucket_files_background

```
cleanup_stale_bucket_files_background():
  "Must resolve all pending async merges first: background merge
   threads may have already written output files to disk"
  spawn_blocking:
    ledger_manager.resolve_pending_bucket_merges()
    referenced = ledger_manager.all_referenced_bucket_hashes()
    bucket_manager.retain_buckets(referenced)
```

REF: LedgerManager::resolve_pending_bucket_merges, BucketManager::retain_buckets

---

### App::scp_slot_snapshots

```
scp_slot_snapshots(limit):
  GUARD herder.scp() is null  → empty list
  latest_slot = herder.latest_externalized_slot() or ledger_seq
  slot = latest_slot
  snapshots = []
  while slot > 0 and len(snapshots) < limit:
    state = scp.get_slot_state(slot)
    if state exists:
      envelopes = herder.get_scp_envelopes(slot)
      append snapshot(slot, state, envelopes) to snapshots
    slot -= 1
  → snapshots
```

---

### App::request_scp_state_from_peers

```
request_scp_state_from_peers():
  GUARD overlay is null        → return
  GUARD peer_count == 0        → return
  ledger_seq = herder.get_min_ledger_seq_to_ask_peers()
  overlay.request_scp_state(ledger_seq)
```

---

### HerderCallback::close_ledger

"Implementation of HerderCallback for App — enables the herder to trigger
ledger closes through the app."

```
close_ledger(ledger_seq, tx_set, close_time, upgrades, stellar_value_ext):
  prev_hash = tx_set.previous_ledger_hash

  tx_set_variant = if tx_set has generalized_tx_set:
                     Generalized(tx_set.generalized_tx_set)
                   else:
                     Classic(TransactionSet from tx_set)

  decoded_upgrades = decode_upgrades(upgrades)
  close_data = LedgerCloseData(ledger_seq, tx_set_variant,
                                close_time, prev_hash)
    .with_stellar_value_ext(stellar_value_ext)
  if decoded_upgrades is non-empty:
    close_data.with_upgrades(decoded_upgrades)
  if scp_history_entry exists for ledger_seq:
    close_data.with_scp_history([entry])

  set_applying_ledger(true)

  "Close the ledger on a blocking thread (yields the tokio worker)"
  result = spawn_blocking:
    ledger_manager.close_ledger(close_data)

  header_hash = result.header_hash if success
  success = handle_close_complete(pending, result)

  if success:
    → header_hash
  else:
    → error "Failed to close ledger"
```

**Calls**: [decode_upgrades](#helper-decode_upgrades), [handle_close_complete (ledger_close submodule)](../app/ledger_close.pc.md)

REF: LedgerManager::close_ledger

---

### HerderCallback::validate_tx_set

```
validate_tx_set(tx_set_hash):
  → true   NOTE: "accept all transaction sets for now"
```

---

### HerderCallback::broadcast_scp_message

```
broadcast_scp_message(envelope):
  scp_envelope_tx.try_send(envelope)
```

---

### SyncRecoveryCallback::on_lost_sync

```
on_lost_sync():
  MUTATE lost_sync_count += 1
  herder.set_state(Syncing)
```

---

### SyncRecoveryCallback::on_out_of_sync_recovery

```
on_out_of_sync_recovery():
  "Set flag so the main event loop will trigger recovery
   and buffered catchup"
  sync_recovery_pending = true
```

---

### SyncRecoveryCallback (other methods)

```
is_applying_ledger():
  → is_applying_ledger flag

is_tracking():
  → herder.is_tracking()

get_v_blocking_slots():
  tracking = herder.tracking_slot()
  → [tracking] if tracking > 0, else []

purge_slots_below(slot):
  herder.purge_slots_below(slot)

broadcast_latest_messages(from_slot):
  messages = herder.get_latest_messages(from_slot)
  for each envelope in messages:
    scp_envelope_tx.try_send(envelope)
```

---

### App::start_sync_recovery

```
start_sync_recovery():
  (handle, manager) = SyncRecoveryManager.new(self)
  sync_recovery_handle = handle
  spawn(manager.run())
```

REF: SyncRecoveryManager::new

---

### App::sync_recovery_heartbeat

```
sync_recovery_heartbeat():
  if sync_recovery_handle exists:
    handle.try_tracking_heartbeat()
```

---

### App::start_sync_recovery_tracking

```
start_sync_recovery_tracking():
  if sync_recovery_handle exists:
    handle.try_start_tracking()
```

---

### App::set_applying_ledger

```
set_applying_ledger(applying):
  is_applying_ledger = applying
  if sync_recovery_handle exists:
    handle.try_set_applying_ledger(applying)
```

---

### App::start_event_loop_watchdog

```
start_event_loop_watchdog():
  spawn OS thread "watchdog":
    loop:
      sleep(10s)
      last_tick = last_event_loop_tick_ms
      GUARD last_tick == 0  → continue (not started yet)

      stale_secs = (now_ms - last_tick) / 1000
      phase = event_loop_phase

      if stale_secs >= 30:
        ERROR "Event loop appears frozen!"
        log thread state summary from /proc
      else if stale_secs >= 15:
        WARN "Event loop slow"
```

---

### Helper: HerderScpCallback

"Adapter from the app's Herder to the overlay's ScpQueueCallback trait.
Bridges herder SCP state into overlay flow control for slot-age-aware trimming."

```
min_slot_to_remember():
  → herder.get_min_ledger_seq_to_remember()

most_recent_checkpoint_seq():
  → herder.get_most_recent_checkpoint_seq()
```

---

### Helper: update_peer_record

```
update_peer_record(db, event):
  now = current_epoch_seconds()

  if event is Connected(addr, peer_type):
    existing = db.load_peer(addr.host, addr.port)
    existing_type = existing.peer_type or PEER_TYPE_INBOUND
    mapped = resolve_peer_type(peer_type, existing_type)
    db.store_peer(addr.host, addr.port,
      PeerRecord(next_attempt=now, failures=0, type=mapped))

  if event is Failed(addr, peer_type):
    existing = db.load_peer(addr.host, addr.port)
    failures = (existing.num_failures or 0) + 1
    backoff = compute_peer_backoff_secs(failures)
    next_attempt = now + backoff
    mapped = resolve_peer_type(peer_type, existing_type)
    db.store_peer(addr.host, addr.port,
      PeerRecord(next_attempt, failures, mapped))
```

**Calls**: [compute_peer_backoff_secs](#helper-compute_peer_backoff_secs)

NOTE: Peer type resolution preserves PREFERRED if existing record is preferred;
preserves OUTBOUND for inbound connections from known outbound peers.

---

### Helper: compute_peer_backoff_secs

```
compute_peer_backoff_secs(failures):
  CONST SECONDS_PER_BACKOFF = 10
  CONST MAX_BACKOFF_EXPONENT = 10
  exp = min(failures, MAX_BACKOFF_EXPONENT)
  max = SECONDS_PER_BACKOFF * 2^exp
  → random(1..max)    // exponential backoff with jitter
```

---

### Helper: TxAdvertHistory

```
TxAdvertHistory(capacity):
  entries: map<Hash256, ledger_seq>
  order:   deque<(Hash256, ledger_seq)>

seen(hash):
  → hash in entries

remember(hash, ledger_seq):
  entries[hash] = ledger_seq
  order.push_back((hash, ledger_seq))
  while len(entries) > capacity:
    (old_hash, old_seq) = order.pop_front()
    if entries[old_hash] == old_seq:
      delete entries[old_hash]

clear_below(ledger_seq):
  remove all entries with seq < ledger_seq
```

---

### Helper: PeerTxAdverts

```
PeerTxAdverts:
  incoming: deque<Hash256>    — new adverts
  retry:    deque<Hash256>    — retries (priority)
  history:  TxAdvertHistory(50_000)

queue_incoming(hashes, ledger_seq, max_ops):
  for each hash in hashes:
    history.remember(hash, ledger_seq)
  start = len(hashes) - max_ops  // take last max_ops
  for each hash in hashes[start..]:
    incoming.push_back(hash)
  while size() > max_ops:
    pop_advert()

pop_advert():
  → retry.pop_front() or incoming.pop_front()
  NOTE: retries have priority over new adverts
```

---

### Helper: ScpLatencyTracker

```
ScpLatencyTracker:
  CONST MAX_SAMPLES = 256
  first_seen:  map<slot, Instant>
  self_sent:   map<slot, Instant>

record_first_seen(slot):
  first_seen.entry(slot).or_insert(now)

record_self_sent(slot):
  if first_seen[slot] exists:
    delta = now - first_seen[slot]
    push_sample(first_to_self_samples, delta)
  self_sent[slot] = now
  → delta (or null)

record_other_after_self(slot):
  GUARD already recorded for slot  → null
  if self_sent[slot] exists:
    delta = elapsed since self_sent[slot]
    push_sample(self_to_other_samples, delta)
    mark slot as recorded
    → delta
```

---

### Helper: SurveyScheduler

```
SurveyScheduler:
  phase = Idle
  next_action = now + 60s
  peers = []
  nonce = 0
  ledger_num = 0
```

---

### AppBuilder

```
AppBuilder:
  with_config(config) → self
  with_config_file(path) → self

  build():
    config = self.config
            or AppConfig.from_file(self.config_path)
            or AppConfig.default()
    → App.new(config)
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~2063  | ~380       |
| Functions     | ~40    | ~35        |

NOTE: The bulk of application logic (event loop, catchup, consensus,
ledger close, peer management, survey, tx flooding) lives in the
submodules: `catchup_impl`, `consensus`, `ledger_close`, `lifecycle`,
`peers`, `survey_impl`, `tx_flooding`. This file defines the App struct,
initialization, state management, callback implementations, and helper
data structures.
