# Pseudocode: crates/overlay/src/error.rs

## Overview

Error type enumeration for overlay network operations. Defines `OverlayError`
with variants covering connection, authentication, protocol, peer management,
state, address, database, and internal errors. Includes classification helpers.

---

### OverlayError (enum)

```
ENUM OverlayError:
  "Connection Errors"
  ConnectionFailed(detail)
  ConnectionTimeout(detail)
  PeerDisconnected(detail)

  "Authentication Errors"
  AuthenticationFailed(detail)
  AuthenticationTimeout
  MacVerificationFailed

  "Protocol Errors"
  Message(detail)
  InvalidMessage(detail)
  VersionMismatch(detail)
  NetworkMismatch

  "Peer Management Errors"
  PeerLimitReached
  PeerNotFound(detail)
  PeerBanned(detail)
  AlreadyConnected

  "State Errors"
  NotStarted
  AlreadyStarted
  ShuttingDown

  "Address Errors"
  InvalidPeerAddress(detail)

  "Database Errors"
  DatabaseError(detail)

  "Wrapped Errors"
  Xdr(xdr_error)
  Crypto(crypto_error)
  Io(io_error)

  "Internal Errors"
  ChannelSend
  ChannelRecv
  Internal(detail)
```

---

### is_retriable

"Returns true if this error is transient and the operation could succeed on retry."

```
function is_retriable(self) → boolean:
  → self is ConnectionFailed
    or self is ConnectionTimeout
    or self is Io
```

---

### is_fatal

"Returns true if this error indicates a fundamental incompatibility."

```
function is_fatal(self) → boolean:
  → self is NetworkMismatch
    or self is VersionMismatch
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 155    | 48         |
| Functions     | 2      | 2          |
