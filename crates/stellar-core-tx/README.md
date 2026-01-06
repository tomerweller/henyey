# stellar-core-tx

Transaction validation and execution for rs-stellar-core.

## Overview

Processes classic and Soroban transactions, including fee calculation, precondition checks, and operation execution. Produces per-tx metadata used by ledger close and history.

## Architecture

- `TransactionFrame` validates structure and preconditions.
- `processor` builds tx sets and drives execution order.
- `operations/*` implements classic operations and Soroban entrypoints.
- `fee` and `preconditions` provide shared validation logic.

## Upstream Mapping

- `src/transactions/*`
- Operation handlers under `src/operations/*`

## Layout

```
crates/stellar-core-tx/
├── src/
│   ├── frame.rs
│   ├── processor.rs
│   ├── fee.rs
│   ├── preconditions.rs
│   ├── soroban/
│   └── operations/
└── tests/
```

## Key Concepts

- `TransactionFrame` wraps XDR envelopes with network ID.
- Classic and Soroban phases are executed separately for generalized tx sets.
- Results map to XDR result codes for parity with stellar-core.
- **TxMeta**: per-transaction metadata used for history verification.

## Tests To Port

From `src/transactions/test/`:
- Per-operation edge cases (Offer/Trustline/ClaimableBalance/etc.).
- Soroban footprint and resource limit cases.
- Tx meta hash vectors.
