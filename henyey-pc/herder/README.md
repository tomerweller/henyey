# herder

The Herder is the central coordination layer between SCP consensus, the ledger, the transaction pool, and the overlay network. It orchestrates consensus rounds, manages pending transactions and SCP envelopes, constructs and validates transaction sets with surge pricing, applies ledger upgrades, and monitors quorum health.

## Key Files

- [herder.pc.md](herder.pc.md) -- Core Herder implementation: consensus orchestration, envelope handling, and ledger close triggering
- [scp_driver.pc.md](scp_driver.pc.md) -- SCP driver bridging the Herder to consensus; handles value validation, signing, and externalization
- [tx_queue/mod.pc.md](tx_queue/mod.pc.md) -- Transaction mempool with fee-based ordering, lane eviction, and replace-by-fee logic
- [tx_queue/tx_set.pc.md](tx_queue/tx_set.pc.md) -- Transaction set construction, hashing, validation, and serialization
- [fetching_envelopes.pc.md](fetching_envelopes.pc.md) -- SCP envelope lifecycle: dependency fetching, queuing, and readiness tracking
- [surge_pricing.pc.md](surge_pricing.pc.md) -- Surge pricing lane configuration and priority queue helpers for transaction selection
- [upgrades.pc.md](upgrades.pc.md) -- Ledger upgrade scheduling, validation, and application for protocol parameters

## Architecture

The Herder operates as a state machine (Booting -> Syncing -> Tracking) defined in `state`. `herder` is the central coordinator: it receives SCP envelopes via `fetching_envelopes` and `pending`, delegates consensus decisions through `scp_driver`, and triggers ledger closes by passing `LedgerCloseData` to the LedgerManager. Transaction admission is managed by `tx_queue` with resource limiting from `tx_queue_limiter` and surge pricing from `surge_pricing`, while `tx_queue/selection` picks the highest-fee transactions for nomination. `parallel_tx_set_builder` partitions Soroban transactions into parallel execution stages. `persistence` handles crash recovery via SQLite, `quorum_tracker` monitors quorum participation, `dead_node_tracker` detects missing validators, `drift_tracker` watches for clock skew, `sync_recovery` handles stuck-consensus detection, `timer_manager` schedules SCP timeouts, `tx_broadcast` handles periodic flooding, and `upgrades` coordinates network-wide parameter changes.

## All Files

| File | Description |
|------|-------------|
| [dead_node_tracker.pc.md](dead_node_tracker.pc.md) | Detects missing and dead validators using a two-interval approach |
| [drift_tracker.pc.md](drift_tracker.pc.md) | Tracks close time drift for monitoring clock synchronization |
| [error.pc.md](error.pc.md) | Error types for Herder operations |
| [fetching_envelopes.pc.md](fetching_envelopes.pc.md) | Manages SCP envelopes waiting for TxSet/QuorumSet dependencies |
| [flow_control.pc.md](flow_control.pc.md) | Flow control constants and helpers for transaction size limits |
| [herder.pc.md](herder.pc.md) | Central Herder coordinator: consensus orchestration and ledger close |
| [herder_utils.pc.md](herder_utils.pc.md) | Utility functions for extracting StellarValues from SCP envelopes |
| [json_api.pc.md](json_api.pc.md) | JSON API structures for Herder diagnostics and monitoring |
| [ledger_close_data.pc.md](ledger_close_data.pc.md) | Data structure for passing ledger close information to LedgerManager |
| [lib.pc.md](lib.pc.md) | Module map and re-exports for the herder crate |
| [parallel_tx_set_builder.pc.md](parallel_tx_set_builder.pc.md) | Builds parallel Soroban transaction phases via conflict-aware bin-packing |
| [pending.pc.md](pending.pc.md) | Buffers SCP envelopes for future slots until they become active |
| [persistence.pc.md](persistence.pc.md) | SCP state persistence to SQLite for crash recovery |
| [quorum_tracker.pc.md](quorum_tracker.pc.md) | Tracks quorum participation and v-blocking set detection per slot |
| [scp_driver.pc.md](scp_driver.pc.md) | SCP integration: value validation, signing, caching, and externalization |
| [state.pc.md](state.pc.md) | Herder state machine: Booting -> Syncing -> Tracking |
| [surge_pricing.pc.md](surge_pricing.pc.md) | Surge pricing lane configuration and priority queues for tx selection |
| [sync_recovery.pc.md](sync_recovery.pc.md) | Out-of-sync detection and recovery when consensus is stuck |
| [timer_manager.pc.md](timer_manager.pc.md) | Schedules and fires SCP nomination and ballot timeouts per slot |
| [tx_broadcast.pc.md](tx_broadcast.pc.md) | Transaction broadcast management with surge-pricing order and rate limiting |
| [tx_queue/mod.pc.md](tx_queue/mod.pc.md) | Transaction mempool: fee ordering, lane eviction, banning, and replace-by-fee |
| [tx_queue/selection.pc.md](tx_queue/selection.pc.md) | Transaction selection for consensus nomination respecting lane limits |
| [tx_queue/tx_set.pc.md](tx_queue/tx_set.pc.md) | Transaction set construction, hashing, validation, and serialization |
| [tx_queue_limiter.pc.md](tx_queue_limiter.pc.md) | Resource-aware transaction queue limiting with multi-dimensional tracking |
| [tx_set_utils.pc.md](tx_set_utils.pc.md) | Filters invalid transactions from candidate sets during nomination |
| [upgrades.pc.md](upgrades.pc.md) | Ledger upgrade scheduling and validation for protocol parameters |
