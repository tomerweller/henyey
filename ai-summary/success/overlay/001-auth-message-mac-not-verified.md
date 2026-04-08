# 001: Auth Message MAC Not Verified During Handshake

**Date**: 2026-04-07
**Severity**: LOW
**Crate**: overlay
**Final review by**: claude-opus-4.6

## Summary

Henyey's `AuthContext::unwrap_message` gates MAC verification on `self.is_authenticated()`, which requires `state == AuthState::Authenticated`. When the Auth message is received, the state is `HelloReceived` (not `Authenticated`), so the MAC on the Auth message is never verified. Stellar-core gates the equivalent check on `getState(guard) >= GOT_HELLO`, which includes the Auth receive phase and DOES verify the Auth MAC.

## Root Cause

In `auth.rs:627`, the MAC verification gate uses `self.is_authenticated()` (strict equality with `AuthState::Authenticated`). The Auth message arrives when state is `HelloReceived` or `AuthSent` -- neither satisfies this check. MAC keys ARE available (derived during `process_hello` at line 423-431), but the overly strict state gate prevents their use. A code comment at line 623-624 incorrectly claims this matches stellar-core's `>= GOT_HELLO` check.

## Attack Vector

A man-in-the-middle attacker who can modify bytes in transit (but cannot forge Ed25519 signatures) could:

1. Allow the Hello exchange to complete normally between two honest peers
2. Modify the Auth message in transit (corrupt MAC or alter flags field)
3. Henyey accepts the modified Auth message without MAC verification

Practical impact is limited because the Auth payload only contains an `i32` flags field (which is explicitly validated), and all subsequent post-Auth messages ARE MAC-verified. However, the missing MAC verification on Auth means the handshake does not cryptographically confirm that both sides derived the same shared secret until the first post-Auth message.

## Affected Code

- `crates/overlay/src/auth.rs:unwrap_message:627` -- MAC verification gated on `is_authenticated()` instead of a `>= HelloReceived` equivalent
- `crates/overlay/src/auth.rs:is_authenticated:314-316` -- strict equality check `state == AuthState::Authenticated`
- `crates/overlay/src/peer.rs:recv_auth:429` -- calls `unwrap_message` before `process_auth`
- `stellar-core/src/overlay/Peer.cpp:1032` -- upstream gates on `getState(guard) >= GOT_HELLO`

## PoC

- **Test file**: crates/overlay/tests/audit_poc_001.rs
- **Test name**: test_auth_message_mac_not_verified_poc
- **How to run**: `cargo test -p henyey-overlay --test audit_poc_001 -- --nocapture`

### Test Body
```rust
//! PoC: Auth message MAC is not verified during handshake (H-001)
//!
//! Demonstrates that corrupting the MAC on an Auth message does NOT cause
//! unwrap_message to fail, while the same corruption on a post-Auth message
//! correctly fails MAC verification.

use henyey_crypto::SecretKey;
use henyey_overlay::{AuthContext, AuthState, LocalNode, OverlayError};
use stellar_xdr::curr::{AuthenticatedMessage, StellarMessage, VecM};

/// Complete Hello exchange between initiator (A) and responder (B).
/// Returns both contexts in HelloReceived/AuthSent state with MAC keys derived.
fn setup_after_hello() -> (AuthContext, AuthContext) {
    let secret_a = SecretKey::generate();
    let secret_b = SecretKey::generate();
    let node_a = LocalNode::new_testnet(secret_a);
    let node_b = LocalNode::new_testnet(secret_b);

    let mut ctx_a = AuthContext::new(node_a, true);  // initiator
    let mut ctx_b = AuthContext::new(node_b, false); // responder

    // Exchange Hello messages
    let hello_a = ctx_a.create_hello();
    let hello_b = ctx_b.create_hello();

    ctx_a.hello_sent();
    ctx_b.hello_sent();

    ctx_b.process_hello(&hello_a).expect("B accepts A's hello");
    ctx_a.process_hello(&hello_b).expect("A accepts B's hello");

    // At this point MAC keys are derived but state is HelloReceived, not Authenticated
    assert_eq!(ctx_a.state(), AuthState::HelloReceived);
    assert_eq!(ctx_b.state(), AuthState::HelloReceived);
    assert!(!ctx_a.is_authenticated());
    assert!(!ctx_b.is_authenticated());

    (ctx_a, ctx_b)
}

#[test]
fn test_auth_message_mac_not_verified_poc() {
    let (mut ctx_a, mut ctx_b) = setup_after_hello();

    // A sends Auth: wrap_auth_message uses sequence 0 with a valid MAC
    let auth_msg = StellarMessage::Auth(stellar_xdr::curr::Auth { flags: 200 });
    let wrapped = ctx_a
        .wrap_auth_message(auth_msg)
        .expect("wrap_auth_message should succeed");

    // Corrupt the MAC bytes
    let corrupted = match wrapped {
        AuthenticatedMessage::V0(mut v0) => {
            // Flip every byte in the MAC to ensure it's completely wrong
            for byte in v0.mac.mac.iter_mut() {
                *byte ^= 0xFF;
            }
            AuthenticatedMessage::V0(v0)
        }
    };

    // VULNERABILITY: unwrap_message succeeds despite corrupted MAC
    // because state is HelloReceived, not Authenticated
    let result = ctx_b.unwrap_message(corrupted);
    assert!(
        result.is_ok(),
        "BUG CONFIRMED: unwrap_message should have rejected corrupted MAC, \
         but it succeeded because MAC verification is skipped for Auth messages. \
         Got error: {:?}",
        result.err()
    );
    println!(
        "POC PASS: Auth message with corrupted MAC was accepted (state={:?})",
        ctx_b.state()
    );

    // Now complete the handshake so both sides are Authenticated
    ctx_a.auth_sent();
    ctx_b.auth_sent();
    ctx_a.process_auth().expect("A completes auth");
    ctx_b.process_auth().expect("B completes auth");
    assert!(ctx_a.is_authenticated());
    assert!(ctx_b.is_authenticated());

    // Now show that a corrupted MAC on a post-Auth message IS rejected
    let post_auth_msg = StellarMessage::Peers(VecM::default());
    let wrapped_post = ctx_a
        .wrap_message(post_auth_msg)
        .expect("wrap_message should succeed");

    let corrupted_post = match wrapped_post {
        AuthenticatedMessage::V0(mut v0) => {
            for byte in v0.mac.mac.iter_mut() {
                *byte ^= 0xFF;
            }
            AuthenticatedMessage::V0(v0)
        }
    };

    let result_post = ctx_b.unwrap_message(corrupted_post);
    assert!(
        result_post.is_err(),
        "Post-auth corrupted MAC should be rejected"
    );
    assert!(
        matches!(result_post, Err(OverlayError::MacVerificationFailed)),
        "Error should be MacVerificationFailed, got: {:?}",
        result_post
    );
    println!(
        "CONTROL: Post-auth message with corrupted MAC was correctly rejected"
    );
}
```

## Expected vs Actual Behavior

- **Expected**: `unwrap_message` should verify the MAC on the Auth message (since MAC keys are already derived after Hello exchange), rejecting any message with a corrupted MAC. This matches stellar-core's behavior where `>= GOT_HELLO` includes the Auth receive phase.
- **Actual**: `unwrap_message` skips MAC verification entirely for the Auth message because the state gate (`is_authenticated()`) requires `Authenticated`, which is only set AFTER Auth processing. A corrupted MAC on the Auth message is silently accepted.

## Adversarial Review

1. Exercises claimed bug: YES -- The test wraps an Auth message with a valid MAC, corrupts every byte of the MAC, and demonstrates that `unwrap_message` still returns `Ok`. The control case proves post-Auth MAC verification works correctly.
2. Realistic preconditions: YES -- The test simulates a normal Hello exchange (realistic network condition). An attacker only needs to modify bytes in transit, which is a standard MITM capability.
3. Bug vs by-design: BUG -- The code comment at line 623-624 explicitly states the intent is to match stellar-core's `>= GOT_HELLO` check, but the implementation (`is_authenticated()`) does not achieve this. This is a residual bug from an incomplete prior fix.
4. Final severity: LOW -- The Auth message payload is only an `i32` flags field (explicitly validated), and all post-Auth messages ARE MAC-verified. The main concern is the missing key-confirmation step during handshake. The Ed25519 certificate signature still prevents MITM key substitution.
5. In scope: YES -- This is a parity deviation in the overlay crate's authentication protocol implementation.
6. Test correctness: CORRECT -- The test correctly sets up two AuthContext instances, completes the Hello exchange (deriving MAC keys), wraps an Auth message, corrupts the MAC, and verifies that unwrap_message accepts it. The control case validates that post-Auth MAC verification works.
7. Alternative explanations: NONE -- The code path is unambiguous: `is_authenticated()` is `state == Authenticated`, the state at Auth receipt is `HelloReceived`, and the MAC verification block is entirely skipped.
8. Suppression rules: NONE APPLY

## Suggested Fix

Change the MAC verification gate in `unwrap_message` from `self.is_authenticated()` to a check that MAC keys are available (e.g., `self.recv_mac_key.is_some()`), or introduce a helper `has_mac_keys()` that returns true when state is `>= HelloReceived`. This would match stellar-core's `>= GOT_HELLO` semantics. The `recv_sequence` handling also needs adjustment to verify sequence 0 for the Auth message.
