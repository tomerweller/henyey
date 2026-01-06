# stellar-core-overlay

P2P overlay networking layer for rs-stellar-core.

## Overview

Handles peer connections, authentication, message routing, flood control, surveys, and transaction advert/demand. Implements Stellar overlay protocol behavior for v25.

## Architecture

- `OverlayManager` owns peers, outbound connect loop, and message routing.
- `Peer` encapsulates handshake, auth, and per-connection state machines.
- `FlowControl` and `FloodGate` enforce rate limits and message budgets.
- Survey and transaction advert/fetch paths integrate with herder.

## Upstream Mapping

- `src/overlay/*` (OverlayManager, Peer, FlowControl, Survey)

## Layout

```
crates/stellar-core-overlay/
├── src/
│   ├── manager.rs
│   ├── peer.rs
│   ├── flow_control.rs
│   ├── survey.rs
│   ├── flood_gate.rs
│   ├── codec.rs
│   └── error.rs
└── tests/
```

## Key Concepts

- Authenticated handshake (Curve25519).
- Flood gate + rate limiting for inbound/outbound traffic.
- Peer discovery persistence and backoff.
- Tx advert/fetch queues with retry scheduling.
- **Preferred peers**: config-driven priority outbound selection.

## Tests To Port

From `src/overlay/test/`:
- Peer handshake and auth flows.
- Flood gate and rate-limiting behaviors.
- Survey encryption and paging.
