# Testnet Validator Readiness Checklist (v25 target)

This checklist tracks what must be in place to safely join Stellar public testnet as a validator.
Items marked complete are implemented in this repo; unchecked items remain.

## Consensus / Herder

- [x] Quorum tracking (slot-level quorum/v-blocking detection wired).
- [x] SCP nomination/ballot edge cases and timeouts parity with v25.
  - [x] Nomination/ballot timeout scheduling wired into main loop.
  - [x] Timeout backoff uses linear growth + 30m cap (v25 baseline).
  - [x] Nomination/ballot timeout settings read from SCP timing config (protocol 23+).
  - [x] Ballot timeout rounds track the active ballot counter.
  - [x] SCP priority/value hashing uses XDR+SHA256 (deterministic parity).
  - [x] Nomination leaders selected via weighted priority over local quorum set.
  - [x] Nomination vote/accept monotonic checks and deterministic ordering.
  - [x] Ballot newer-statement ordering enforced for prepare/confirm/externalize.
  - [x] Local SCP envelopes recorded for quorum evaluation.
- [x] SCP envelope signing/verification pipeline for validators.
- [x] Proposed protocol upgrades flow into SCP value and ledger close.
- [x] Quorum set exchange and on-demand GetScpQuorumset support.

## Overlay / Network

- [x] Authenticated overlay handshake (Curve25519) with flow control.
- [x] Flood gate + rate limiting + duplicate suppression.
- [x] TxSet/GeneralizedTxSet request/response handling with DontHave.
- [x] Peer connector maintains preferred/target outbound peers.
- [x] Time-sliced survey encryption (sealed boxes).
- [x] Time-sliced survey payload parity (ranking; upstream metrics out of scope).
  - [x] Flood/fetch counters wired into survey payloads.
  - [x] Time-sliced p75 SCP latency sampling.
  - [x] Ping-based average latency per peer.
  - [x] Lost sync count + added/dropped peer deltas.
  - [x] Deterministic peer ordering for time-sliced responses.
  - [x] Local surveyor results seeded in reporting output.
  - [x] Time-sliced survey paging (request additional slices).
  - [x] Survey request/response limiter + throttle.
- [x] Tx advert/flood demand parity (per-peer queues, randomized demand scheduling, backoff/retry).
- [x] Peer manager/survey scheduling parity (selection, ranking, retries).
  - [x] Basic peer discovery via Peers exchange and periodic advertising.
  - [x] Discovered peers persisted to SQLite and reloaded on startup.
  - [x] Peer backoff/failure tracking persisted (next attempt with exponential jitter).
  - [x] Peer discovery respects backoff; peer lists exclude private/local addresses.
  - [x] Peer entries pruned when failure counts exceed threshold.
  - [x] Known peer list refreshed from config + SQLite cache before reconnects/advertising.
  - [x] Known peer connection attempts randomized to avoid ordering bias.
  - [x] Peer lists capped at 50 entries per message (matches upstream).
  - [x] Known peer list refreshed periodically to pick up expired backoff.
  - [x] Peer discovery respects outbound target/connection pool capacity.
  - [x] Peer discovery skips private/local addresses on ingest.
  - [x] Peer failure threshold is configurable.
  - [x] Config known/preferred peers reset backoff on startup.
  - [x] Survey reporting backlog + command endpoints wired.
  - [x] Survey scheduler skips when survey already active/reporting.
  - [x] Survey scheduler runs only when synced/validating.
  - [x] Automatic survey scheduling is unsupported (manual control matches upstream).
  - [x] Survey peer selection balances inbound/outbound deterministically.
  - [x] Survey topology command requires inbound/outbound indices (matches upstream).
  - [x] Survey scheduling parity (selection/ranking + permissions).
  - [x] Survey requests/responses relay when not targeting the local node.
  - [x] Survey messages use flood gate duplicate suppression.

- [x] Peer manager selection/ranking parity (DB-backed random selection, type filters, peer list serving).
  - [x] Peer discovery persisted with backoff and failure pruning.
  - [x] Peer lists filtered to public peers, capped at 50, and randomized.
  - [x] DB-backed peer selection with type filters (outbound/preferred).
  - [x] Peer records track inbound vs outbound connections.
  - [x] Peers advertisements use DB-backed inbound/outbound/preferred lists.
  - [x] Peer addresses use Hello listening_port for peer list serving.
  - [x] Peers advertisements prioritize outbound peers before inbound peers.
  - [x] Peer type updates preserve outbound/preferred on inbound observations.
  - [x] Peers advertisements ignore backoff timers (max failures only).
  - [x] Peer list ingestion/advertising ignores IPv6 addresses.
  - [x] Peers advertisements cap failures at 10 (upstream MAX_FAILURES).
  - [x] Surveyor permission gating (SURVEYOR_KEYS or local quorum set).

## Ledger Close / Transactions

- [ ] Ledger txn layering parity and replay semantics.
  - [x] Tx queue tie-breaker ordering is deterministic for equal fees.
  - [x] Nomination tx set size respects ledger header max_tx_set_size.
  - [x] Deterministic per-account layered selection by fee per op.
  - [ ] Per-account sequence layering and surge pricing parity.
    - [x] Per-account selection respects ledger starting sequence when snapshot is available.
    - [x] Tx selection enforces max ops and classic surge base fee override.
    - [x] Classic ops limit applies only to classic phase; Soroban uses resource limits.
    - [x] Resource accounting for surge pricing (classic ops + Soroban disk reads).
    - [ ] Surge pricing lane config + eviction parity (classic, Soroban, DEX lanes).
      - [x] DEX ops cap enforced during selection when configured.
      - [x] DEX lane byte limit uses classic byte allowance (MAX_CLASSIC_BYTE_ALLOWANCE parity).
      - [x] Generalized tx set groups classic DEX txs with discounted base fee when limited.
      - [x] Classic base fee in generalized tx sets triggers when classic ops overflow.
      - [x] Soroban byte limit enforced even without explicit Soroban resource limits.
  - [x] Queue admission supports optional DEX/Soroban lane limits with fee-based eviction.
  - [x] Queue admission eviction follows lane-aware ordering and prevents same-account eviction.
    - [x] Queue admission supports optional total ops limit with fee-based eviction.
    - [x] Classic byte allowance enforced for tx set selection and queue admission.
    - [x] Queue eviction prefers higher fee transactions when at capacity.
    - [x] Optional Soroban resource cap enforced during selection.
    - [x] Soroban byte allowance enforced during selection when configured.
    - [x] Soroban base fee override when resource limit trims txs.
    - [x] SurgePricingPriorityQueue parity (lane resource eviction order + tie-breaker seeding).
      - [x] Lane-aware priority queue selection wired for classic/Soroban.
      - [x] Tie-breaker seeding uses randomized seed in non-test builds.
  - [x] Soroban/classic phase splitting in generalized tx sets.
- [x] Transaction meta hash parity with golden vectors.
- [ ] Full operation coverage parity (classic + Soroban edge cases).
  - [x] Payment: credit issuer existence and trustline authorization checks.
  - [x] Payment: issuer-as-account bypass for trustline/balance checks.
  - [x] Payment: line-full/underfunded checks include liabilities.
  - [x] AccountMerge: dest-full + self-merge malformed + liabilities-aware receive.
  - [x] TrustFlags/AllowTrust: cannot revoke auth with outstanding liabilities.
  - [x] ManageOffer: issuer existence and trustline authorization checks.
  - [x] ManageOffer: low reserve checks for offer creation.
  - [x] ManageOffer: liabilities accounting + line-full checks for buying limits.
  - [x] ChangeTrust: NoIssuer/InvalidLimit checks and trustline flags on creation.
  - [x] ChangeTrust: pool share trustline creation + pool entry wiring.
  - [x] ChangeTrust: liquidity pool use-count tracking + delete guard.
  - [x] LiquidityPool: deposit/withdraw auth checks, line-full/pool-full, and deterministic math.
  - [x] PathPayment: strict send NoIssuer reports the failing asset for direct transfers.
  - [x] PathPayment: issuer existence and trustline authorization checks for direct transfers.
- [x] PathPayment: NoIssuer result reports the failing asset for direct transfers.
  - [x] PathPayment: line-full/underfunded checks include liabilities for direct transfers.
  - [x] PathPayment: order book + liquidity pool path crossing (strict send/receive).
- [x] Offer IDs use ledger id_pool and ledger close persists updated id_pool.
- [x] Generalized TxSet base-fee overrides honored in ledger close.
- [x] Ledger close meta v2+ produced; fee-bump results handled.

## History / Catchup

- [ ] Production-grade catchup/replay parity (buckets, historywork integration).
  - [x] Replay verifies per-ledger bucket list hash when enabled.
  - [x] Replay verifies tx result set hash when enabled.
  - [x] Catchup persists ledger headers and tx history/results into SQLite.
  - [x] Catchup persists SCP history and quorum sets when available.
- [x] History publish parity (validators only) and robustness checks.
  - [x] Ledger headers + tx history persisted to SQLite.
  - [x] Tx set + tx result history entries persisted to SQLite.
  - [x] Bucket list snapshots persisted for checkpoint ledgers.
  - [x] SCP history envelopes/quorum sets persisted and published.
  - [x] Publish command writes checkpoint files + root HAS to local archives.
  - [x] Publish command supports put/mkdir command templates for remote archives.
  - [x] Publish verifies tx set/result hashes before writing.
  - [x] Checkpoint publish queue persisted and consumed by publish-history.
- [x] Basic catchup and history archive access.

## Invariants / Safety

- [ ] Full invariant set (ConservationOfLumens, LedgerEntryIsValid, etc.).
  - [x] Invariant: last_modified_ledger_seq matches current ledger.
  - [x] Invariant: close_time does not decrease.
- [ ] Replay invariants and invariant failure handling parity.
  - [x] Replay enforces invariants during catchup re-execution.

## Ops / Process

- [x] Process lifecycle parity (signals, shutdown, restart safety).
  - [x] Overlay shutdown drains peers/tasks on shutdown.
  - [x] Survey reporting stops and clears secrets on shutdown.
  - [x] Exclusive DB lock prevents multiple node instances.
  - [x] HTTP status server shuts down with the app.
  - [x] Network passphrase mismatch is detected on startup.
- [x] Diagnostics/command handler parity (admin commands, info endpoints).
  - [x] /peers and /ledger endpoints backed by live overlay/ledger data.
  - [x] /quorum endpoint exposes local quorum set.
  - [x] /metrics exposes live ledger/peer counts.
  - [x] /health reports live ledger/peer counts.
  - [x] /tx submits transactions into herder queue.
  - [x] /status reports live node status.
  - [x] /scp exposes SCP slot summary.
  - [x] /connect and /droppeer handle manual peer connections.
  - [x] /bans and /unban manage banned peers (droppeer ban=1).
  - [x] Ban list persisted in SQLite and reloaded on startup.
  - [x] /upgrades exposes current and proposed upgrades.
  - [x] /self-check runs ledger chain validation.
  - [x] /shutdown requests graceful shutdown.
- [x] On-disk state integrity checks on startup.

## Testing / Verification

- [x] Golden-vector tests for tx meta hashes and ledger close outputs.
  - [x] Synthetic tx meta hash vectors in ledger tests (upstream fixtures pending).
  - [x] Ledger close header hash vectors from upstream ledger-close-meta JSON.
- [x] Multi-node SCP/overlay simulation parity tests.
  - [x] Overlay simulation broadcasts SCP messages across peers.
- [x] Basic integration tests (ledger close, tx execution, overlay/SCP).
