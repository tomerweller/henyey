# H-F002: Post-Auth Hello Messages Ignored Instead of Dropping Peer

**Date**: 2026-04-07
**Crate**: overlay
**Severity**: LOW
**Hypothesis by**: claude-opus-4.6

## Expected Behavior

In stellar-core, receiving a Hello message after authentication causes the peer to
be dropped immediately (Peer.cpp:1784-1788):

```cpp
if (getState(guard) >= GOT_HELLO) {
    drop("received unexpected HELLO", Peer::DropDirection::WE_DROPPED_REMOTE);
    return;
}
```

## Mechanism

In henyey, `route_received_message` (manager/peer_loop.rs:422-428) silently ignores
handshake messages from authenticated peers:

```rust
if helpers::is_handshake_message(message) {
    debug!("Ignoring handshake message from authenticated peer {}", peer_id);
    return Some(false);
}
```

A malicious peer could send Hello messages post-auth and the connection would remain
open, whereas stellar-core would disconnect.

## Attack Vector

A peer could send Hello messages after authentication to probe henyey's behavior or
consume resources from processing unauthenticated-format messages. However, these
messages still pass through full MAC verification (since the connection IS
authenticated), so they must have valid MACs and sequence numbers.

## Target Code

- `crates/overlay/src/manager/peer_loop.rs:422-428` -- ignores handshake messages
- `stellar-core/src/overlay/Peer.cpp:1784-1788` -- drops peer on duplicate Hello

## Evidence

- Post-auth Hello is silently ignored in henyey, not triggering disconnect
- Stellar-core explicitly drops the peer

## Anti-Evidence

- The Hello message still goes through full MAC verification (must have valid seq+MAC)
- An attacker cannot send a Hello without a valid MAC, so they gain nothing
- The message is simply ignored; no state changes occur
- This is a non-consensus overlay behavior difference

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-07
**Failed At**: hypothesis
**Reviewed by**: claude-opus-4.6

### Why It Failed

Post-auth Hello messages are MAC-verified before reaching the routing layer. An
attacker must have the shared secret to send them. The difference between "drop peer"
and "ignore message" has no security impact when the message requires authentication.
No amplification, no state corruption, no information leak.

### Lesson Learned

When a message type is ignored vs causing disconnect, check whether the message
requires authentication to send. If it does, the attacker already has the shared
secret and the behavioral difference is cosmetic.