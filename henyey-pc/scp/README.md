# scp

Implementation of the Stellar Consensus Protocol (SCP), a federated Byzantine agreement protocol that enables nodes to reach consensus without closed membership or central authority. The module covers both phases of SCP -- nomination (proposing candidate values) and the ballot protocol (committing a single value) -- along with quorum management and driver callbacks.

## Key Files

- [scp.pc.md](scp.pc.md) — Top-level SCP controller managing slots and routing envelopes
- [slot.pc.md](slot.pc.md) — Per-slot consensus state orchestrating nomination and ballot protocol
- [ballot/mod.pc.md](ballot/mod.pc.md) — Ballot protocol data structures and phase state machine
- [ballot/state_machine.pc.md](ballot/state_machine.pc.md) — Ballot protocol state advancement logic
- [nomination.pc.md](nomination.pc.md) — Nomination phase with round-based candidate value promotion
- [driver.pc.md](driver.pc.md) — SCP driver trait defining application-layer callbacks
- [quorum.pc.md](quorum.pc.md) — Quorum set operations: slice checking, v-blocking, and threshold logic

## Architecture

`SCP` is the entry point -- it holds the local node identity and a map of `Slot` instances keyed by slot index (ledger sequence number). Each `Slot` owns a `NominationProtocol` and a `BallotProtocol`, running them in sequence: nomination produces candidate values, which the ballot protocol then drives through federated voting (prepare, confirm, externalize). The `SCPDriver` trait is the integration point where the application (e.g. Herder) provides hashing, value validation, and persistence callbacks. The ballot protocol is split across `ballot/mod` (structures and phase definitions), `ballot/state_machine` (advancement logic), `ballot/statements` (statement comparison), and `ballot/envelope` (envelope emission). `Quorum` and `QuorumConfig` provide quorum-set validation, threshold checks, and v-blocking detection. The `compare` module provides ordering functions for statements and ballots, while `format` and `info` support debugging and monitoring.

## All Files

| File | Description |
|------|-------------|
| [ballot/envelope.pc.md](ballot/envelope.pc.md) | Ballot envelope emission and statement construction |
| [ballot/mod.pc.md](ballot/mod.pc.md) | Ballot protocol data structures and phase state machine |
| [ballot/state_machine.pc.md](ballot/state_machine.pc.md) | Ballot protocol state advancement and transition logic |
| [ballot/statements.pc.md](ballot/statements.pc.md) | Statement comparison and ordering for ballot protocol |
| [compare.pc.md](compare.pc.md) | Ordering and comparison functions for SCP statements and ballots |
| [driver.pc.md](driver.pc.md) | SCP driver trait defining application-layer callbacks |
| [error.pc.md](error.pc.md) | Error types for SCP operations |
| [format.pc.md](format.pc.md) | Display formatting helpers for nodes, ballots, and envelopes |
| [info.pc.md](info.pc.md) | JSON-serializable SCP slot information for debugging |
| [lib.pc.md](lib.pc.md) | Top-level crate module with type aliases and shared context |
| [nomination.pc.md](nomination.pc.md) | Nomination phase with round-based candidate value promotion |
| [quorum.pc.md](quorum.pc.md) | Quorum set operations: slice checking, v-blocking, and thresholds |
| [quorum_config.pc.md](quorum_config.pc.md) | Quorum set configuration parsing and validation |
| [scp.pc.md](scp.pc.md) | Top-level SCP controller managing slots and routing envelopes |
| [slot.pc.md](slot.pc.md) | Per-slot consensus state orchestrating nomination and ballot protocol |
