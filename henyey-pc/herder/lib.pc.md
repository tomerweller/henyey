## Pseudocode: crates/herder/src/lib.rs

"SCP coordination and ledger close orchestration."

### Module Map

```
MODULES:
  dead_node_tracker    "Missing/dead validator detection"
  drift_tracker        "Close time drift monitoring"
  fetching_envelopes   "Envelopes waiting for TxSet/QuorumSet"
  flow_control         "Transaction size limits"
  herder               "Main Herder implementation"
  herder_utils         "Value extraction, node ID formatting"
  json_api             "JSON structures for admin endpoints"
  ledger_close_data    "Ledger close data for consensus output"
  pending              "Pending SCP envelope management"
  persistence          "SCP state persistence (SQLite)"
  quorum_tracker       "Quorum participation tracking"
  scp_driver           "SCP integration callbacks"
  state                "Herder state machine"
  surge_pricing        "Lane configuration and priority queues"
  sync_recovery        "Out-of-sync detection and recovery"
  timer_manager        "SCP nomination/ballot timeout scheduling"
  tx_broadcast         "Periodic transaction flooding"
  tx_queue             "Transaction queue and set building"
  tx_queue_limiter     "Resource-aware queue limiting"
  tx_set_utils         "Transaction set validation utilities"
  upgrades             "Ledger upgrade scheduling"
  parallel_tx_set_builder  "Parallel tx set building"
```

### STATE_MACHINE: Herder

```
STATE_MACHINE: Herder
  STATES: [Booting, Syncing, Tracking]
  TRANSITIONS:
    Booting  → Syncing:  start_syncing() called
    Syncing  → Tracking: bootstrap(ledger_seq) / externalization
    Tracking → Tracking: advance on each externalized slot
```

### PendingTransaction (struct)

```
STRUCT PendingTransaction:
  envelope         "TransactionEnvelope with signatures"
  received_at      "When first received from network"
  broadcast_count  "Number of times seen/broadcast"
```

### ExternalizedValue (struct)

```
STRUCT ExternalizedValue:
  ledger_seq    "Ledger sequence number"
  tx_set_hash   "Hash of consensus transaction set"
  close_time    "Unix timestamp of ledger close"
```

### HerderCallback (trait)

```
TRAIT HerderCallback:
  close_ledger(ledger_seq, tx_set, close_time,
               upgrades, stellar_value_ext) → ledger_hash
  validate_tx_set(tx_set_hash) → boolean
  broadcast_scp_message(envelope)
```

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 60     | 47         |
| Functions    | 3      | 3          |
