# H-F001: Responder Sends Hello After Validation Instead of Before

**Date**: 2026-04-07
**Crate**: overlay
**Severity**: LOW
**Hypothesis by**: claude-opus-4.6

## Expected Behavior

In stellar-core, the responder (REMOTE_CALLED_US) sends its Hello message
immediately after receiving the initiator's Hello, BEFORE performing version,
network, and self-connection checks (Peer.cpp:1832-1838). The comment explains:
"Send a HELLO back, even if it's going to be followed immediately by ERROR, because
ERROR is an authenticated message type and the caller won't decode it right if still
waiting for an unauthenticated HELLO."

## Mechanism

In henyey, the responder handshake flow in `peer.rs:334-340` is:

```
recv_hello -> send_hello -> recv_auth -> send_auth
```

Where `recv_hello` calls `process_hello` which performs all validation checks
(network ID, version range, self-connection) before returning. If any check fails,
the connection is dropped WITHOUT sending a Hello back.

This means the initiator (stellar-core peer) never receives a Hello and times out
waiting, rather than receiving a clear error message.

## Attack Vector

No security impact. This is a usability/interoperability difference. When a
stellar-core peer connects to henyey with wrong network ID or incompatible version,
it would time out rather than receiving a descriptive error message.

## Target Code

- `crates/overlay/src/peer.rs:334-340` -- responder handshake ordering
- `crates/overlay/src/peer.rs:460-513` -- process_hello with validation checks
- `stellar-core/src/overlay/Peer.cpp:1832-1838` -- upstream sends Hello before checks

## Evidence

- In henyey, `recv_hello` returns Err on validation failure, skipping `send_hello`
- In stellar-core, sendHello() is called before any validation checks for REMOTE_CALLED_US

## Anti-Evidence

- The initiator still fails the connection (via timeout) -- the difference is only in the error message they see
- No security-critical state is changed
- Henyey is actually more conservative: it reveals less information to invalid peers

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-07
**Failed At**: hypothesis
**Reviewed by**: claude-opus-4.6

### Why It Failed

This is a behavioral/interoperability difference, not a security vulnerability. The
responder rejects invalid peers either way. The difference is only in whether the
initiator receives a descriptive error message or a timeout. No attacker benefit.
Falls under suppression rule 1 in spirit -- the core security behavior (rejecting
invalid peers) is the same, just the error reporting path differs.

### Lesson Learned

Handshake ordering differences that affect error reporting but not security outcomes
are usability issues, not vulnerabilities. Focus on whether validation is performed,
not when the error message is sent.