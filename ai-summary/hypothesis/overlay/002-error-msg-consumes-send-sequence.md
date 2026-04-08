# H-002: ErrorMsg Consumes Send Sequence Number Unlike Stellar-Core

**Date**: 2026-04-07
**Crate**: overlay
**Severity**: LOW
**Hypothesis by**: claude-opus-4.6

## Expected Behavior

In stellar-core, ErrorMsg messages are sent without consuming a sequence number or
computing a MAC. In `Hmac::setAuthenticatedMessageBody` (Hmac.cpp:73-79):

```cpp
if (msg.type() != HELLO && msg.type() != ERROR_MSG) {
    aMsg.v0().sequence = mSendMacSeq;
    aMsg.v0().mac = hmacSha256(mSendMacKey, xdr::xdr_to_opaque(mSendMacSeq, msg));
    mSendMacSeq++;
}
```

ErrorMsg is explicitly excluded from sequence/MAC assignment, matching the receiver
side which also skips MAC verification for ErrorMsg (Peer.cpp:1032).

## Mechanism

In henyey, all post-authentication messages including ErrorMsg go through
`AuthContext::wrap_message` (auth.rs:576-592), which unconditionally assigns a
sequence number and computes a MAC:

```rust
let sequence = self.send_sequence;
self.send_sequence += 1;
let mac = self.compute_mac(send_key, sequence, &message)?;
```

This means that after sending an ErrorMsg, henyey's send sequence counter is one
ahead of what the peer expects. If a non-ErrorMsg message were sent after an
ErrorMsg to the same peer, the peer would reject it due to sequence mismatch.

## Attack Vector

In the current codebase, ErrorMsg is always the last message before disconnecting
(all callsites follow `send(ErrorMsg)` with `break` or `Shutdown`). This means the
sequence desync never manifests because no subsequent message is sent.

However, if future code sends an ErrorMsg as a non-fatal warning without
disconnecting, the sequence desync would cause all subsequent messages to fail MAC
verification at the peer, effectively killing the connection. This is a latent
correctness bug.

A malicious peer could also exploit this by triggering error conditions at henyey
(e.g., exceeding flow control capacity). The ErrorMsg sent by henyey would consume
a sequence number. If the connection were not immediately closed (due to a race
condition in the async send/break flow), any queued message after the error would
have the wrong sequence.

## Target Code

- `crates/overlay/src/auth.rs:wrap_message:576-592` -- unconditionally increments send_sequence
- `crates/overlay/src/manager/peer_loop.rs:620-625` -- sends ErrorMsg before break
- `crates/overlay/src/manager/peer_loop.rs:64-79` -- send_error_and_drop sends ErrorMsg+Shutdown
- `stellar-core/src/overlay/Hmac.cpp:73-79` -- upstream excludes ErrorMsg from sequence/MAC

## Evidence

- `wrap_message` has no special handling for ErrorMsg -- it increments `self.send_sequence` for all message types
- Stellar-core explicitly exempts ErrorMsg in `setAuthenticatedMessageBody`
- The XDR `Auth` flag on the wire includes `0x80000000` for ErrorMsg in henyey (since it's not Hello), meaning the receiver will see the auth bit set
- All current ErrorMsg sends are followed by disconnect, limiting practical impact

## Anti-Evidence

- ErrorMsg is always sent immediately before disconnect in all current code paths
- The receiving peer (both henyey and stellar-core) exempts ErrorMsg from MAC/sequence checking, so the wrong sequence on the ErrorMsg itself is harmless
- The async channel-based architecture (OutboundMessage::Send followed by OutboundMessage::Shutdown) makes it unlikely for messages to be interleaved after an error

