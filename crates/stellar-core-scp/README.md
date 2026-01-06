# stellar-core-scp

Stellar Consensus Protocol (SCP) implementation.

## Overview

Implements nomination and ballot protocols, slot state tracking, and deterministic value hashing used for consensus. The module is designed to be deterministic and stable under replay.

## Architecture

- `SCP` owns slots and routes envelopes to nomination/ballot logic.
- `Slot` holds nomination and ballot protocol states per slot index.
- `NominationProtocol` selects values; `BallotProtocol` externalizes.

## Key Concepts

- **Value hash**: hash over XDR for deterministic comparison.
- **Slot index**: ledger sequence used as SCP slot number.
- **Quorum set**: trusted validator configuration for consensus.

## Upstream Mapping

- `src/scp/*` (SCP, Slot, BallotProtocol, NominationProtocol)

## Layout

```
crates/stellar-core-scp/
├── src/
│   ├── scp.rs
│   ├── slot.rs
│   ├── nomination.rs
│   ├── ballot.rs
│   └── error.rs
└── tests/
```

## Determinism Notes

- Hashes are computed over XDR bytes.
- Ordering of candidate values is deterministic.
- Timeout backoff is deterministic given config.

## Tests To Port

From `src/scp/test/`:
- Nomination/ballot edge cases.
- Slot recovery and externalization ordering.
