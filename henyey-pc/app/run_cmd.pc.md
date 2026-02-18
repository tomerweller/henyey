## Pseudocode: crates/app/src/run_cmd.rs

### Enum: RunMode

```
enum RunMode:
  Full        // Standard node with catchup, tracks consensus
  Validator   // Active SCP participant, requires node_seed + quorum set
  Watcher     // Observe-only, no catchup, passive observer
```

### Struct: RunOptions

```
RunOptions:
  mode: RunMode                // default: Full
  force_catchup: bool          // default: false
  wait_for_sync: bool          // default: true
  max_ledger_age: u32          // default: 300 (~25 min at 5s close)
```

---

### run_node

"Run the node with the given configuration and options."

```
async function run_node(config, options):
  validate_run_options(config, options)
  app = new App(config)
  app.set_self_arc()

  "Set up shutdown handling"
  spawn: wait_for_shutdown_signal() → app.shutdown()

  "Start HTTP status server if enabled"
  if config.http.enabled:
    status_server = StatusServer.new(config.http.port, app)
    spawn: status_server.start()

  print_startup_info(app, options)
  run_main_loop(app, options)
```

---

### validate_run_options

```
function validate_run_options(config, options):
  if options.mode == Validator:
    GUARD not config.node.is_validator
      → error "Cannot run in validator mode"
    GUARD config.node.node_seed is null
      → error "Validators must have node_seed"
```

---

### run_main_loop

```
async function run_main_loop(app, options):
  "Phase 1: Attempt to restore from disk"
  if not options.force_catchup:
    restored = app.load_last_known_ledger()
    if restored:
      set_state(AppState.Synced)
      set_current_ledger(lcl_seq)
```

**Calls:** [`App::load_last_known_ledger`](app/ledger_close.pc.md#load_last_known_ledger)

```
  "Phase 2: Check if catchup needed"
  needs_catchup = check_needs_catchup(app, options)

  if needs_catchup:
    if options.mode == Watcher:
      NOTE: "Watcher mode: skipping catchup"
    else:
      "Start overlay BEFORE catchup to receive tx_sets during catchup"
      app.start_overlay()

      "Background: cache messages during catchup"
      catchup_message_handle = app.start_catchup_message_caching()

      "Background: request SCP state after peers connect"
      spawn:
        sleep(500ms)
        app.request_scp_state_from_peers()
```

**Calls:** [`App::catchup_with_mode`](app/catchup_impl.pc.md#catchup_with_mode)

```
      catchup_mode = config.catchup.to_mode()
      app.catchup_with_mode(CatchupTarget.Current, catchup_mode)

      "Stop catchup message caching"
      if catchup_message_handle:
        catchup_message_handle.abort()

  "Phase 3: Start main event loop"
  app.start_sync_recovery()
  spawn: app.run()

  if options.wait_for_sync:
    wait_for_sync(app)
```

---

### check_needs_catchup

```
async function check_needs_catchup(app, options):
  GUARD options.force_catchup → true

  current_state = app.state()
  GUARD current_state == Initializing → true

  (_, _, close_time, _) = app.ledger_info()
  now = current_unix_time()
  target_close_time = app.target_ledger_close_time()
  max_age_seconds = target_close_time * options.max_ledger_age

  → is_ledger_too_old(close_time, now, max_age_seconds)
```

---

### Helper: is_ledger_too_old

```
function is_ledger_too_old(close_time, now, max_age_seconds):
  if close_time == 0: → true
  if max_age_seconds == 0: → false
  → (now - close_time) > max_age_seconds
```

---

### wait_for_sync

```
async function wait_for_sync(app):
  loop every 1s:
    state = app.state()
    if state is Synced or Validating: break
    if state is ShuttingDown: break
```

---

### wait_for_shutdown_signal

```
async function wait_for_shutdown_signal():
  wait for first of:
    - Ctrl+C (SIGINT)
    - SIGTERM (unix only)
```

---

### StatusServer

"HTTP server for node status and control."

```
HTTP Endpoints:
  GET  /           → list endpoints
  GET  /info       → node info (version, name, public key, network, state, uptime)
  GET  /status     → node status (ledger, peers, consensus, pending txs)
  GET  /metrics    → Prometheus-format metrics
  GET  /peers      → connected peer list
  POST /connect    → connect to peer (query: addr or peer+port)
  POST /droppeer   → disconnect peer (query: peer_id or node, optional ban)
  GET  /bans       → list banned peers
  POST /unban      → remove peer ban (query: peer_id or node)
  GET  /ledger     → current ledger (seq, hash, close_time, protocol)
  GET  /upgrades   → current/proposed upgrade state
  POST /self-check → run self-check validation
  GET  /quorum     → local quorum set
  GET  /scp        → SCP slot summaries (query: limit, default 2, max 20)
  GET  /survey     → survey report
  POST /survey/start   → start survey collecting (query: nonce)
  POST /survey/stop    → stop survey collecting
  POST /survey/topology → queue topology request (query: node, inbound_index, outbound_index)
  POST /survey/reporting/stop → stop survey reporting
  POST /tx         → submit transaction (body: base64-encoded XDR envelope)
  POST /shutdown   → request graceful shutdown
  GET  /health     → health check (200 if Synced/Validating, 503 otherwise)
  GET|POST /ll     → get/set log levels (query: level, partition)
  POST /manualclose    → manual ledger close (validator + manual_close mode only)
  GET  /sorobaninfo    → Soroban network config (query: format=basic|detailed|upgrade_xdr)
  POST /clearmetrics   → clear metrics (query: domain)
  POST /logrotate      → trigger log rotation
  POST /maintenance    → DB maintenance (query: queue=true, count)
  GET  /dumpproposedsettings → dump ConfigUpgradeSet (query: blob=base64-xdr)
```

```
async function StatusServer.start():
  state = ServerState { app, start_time, log_handle }
  shutdown_rx = app.subscribe_shutdown()
  router = create_routes(state)
  listener = bind(0.0.0.0, port)
  serve(listener, router, graceful_shutdown=shutdown_rx)
```

---

### Handler: submit_tx_handler

```
async function submit_tx_handler(request):
  tx_bytes = base64_decode(request.tx)
  GUARD decode fails → 400 "Invalid base64"

  tx_env = parse TransactionEnvelope from XDR
  GUARD parse fails → 400 "Invalid XDR"

  network_id = NetworkId.from_passphrase(network_passphrase)
  hash = TransactionFrame.compute_hash(tx_env, network_id)
  result = app.submit_transaction(tx_env)

  "Map queue result to response"
  if result is Added:     → success
  if result is Duplicate: → success (with warning)
  if result is QueueFull: → error "Transaction queue full"
  if result is FeeTooLow: → error "Transaction fee too low"
  if result is Invalid:   → error "Transaction invalid: {code}"
  if result is Banned:    → error "Transaction from banned source"
  if result is Filtered:  → error "Transaction filtered by operation type"
  if result is TryAgainLater: → error "Account already has pending transaction"
```

---

### Handler: health_handler

```
async function health_handler():
  is_healthy = (state is Synced or Validating)
  → 200 if healthy, 503 if unhealthy
  → { status, state, ledger_seq, peer_count }
```

---

### Handler: ll_handler

"Get or set log levels dynamically."

```
async function ll_handler(params):
  GUARD log_handle is null → static "INFO" levels

  if params.level provided:
    if params.partition provided:
      log_handle.set_partition_level(partition, level)
    else:
      log_handle.set_level(level)

  → log_handle.get_levels()
```

---

### Handler: manualclose_handler

```
async function manualclose_handler(params):
  GUARD params.ledger_seq or params.close_time provided
    → 400 "Only accepted in RUN_STANDALONE mode"
  → app.manual_close_ledger()
```

---

### Handler: maintenance_handler

```
async function maintenance_handler(params):
  GUARD params.queue != "true" → "No work performed"
  count = params.count or 50000
  app.perform_maintenance(count)
```

---

### NodeRunner

"High-level node runner that wraps App for simpler lifecycle management."

```
struct NodeRunner:
  app, options, start_time, shutdown_tx

function NodeRunner.new(config, options):
  app = new App(config)
  app.set_self_arc()
  → NodeRunner { app, options, start_time: now(), shutdown_tx }

function NodeRunner.run():
  → run_main_loop(app, options)

function NodeRunner.shutdown():
  shutdown_tx.send(())
  app.shutdown()

async function NodeRunner.status():
  → NodeStatus from app.ledger_info() + app.herder_stats()
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~1100  | ~220       |
| Functions     | ~35    | 14         |

NOTE: ~1000 lines of the source are HTTP handler boilerplate and response type
definitions. The pseudocode summarizes the endpoint table and focuses on the
handlers with meaningful logic (submit_tx, health, ll, manualclose, maintenance).
