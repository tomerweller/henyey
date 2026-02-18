# Pseudocode: crates/overlay/src/auth.rs

## Overview

"Authentication for Stellar overlay connections."

Implements X25519 key exchange with HMAC-SHA256 message authentication.

**Handshake Protocol:**
1. Both peers exchange Hello messages (Ed25519 pubkey, ephemeral X25519 key, auth cert, nonce)
2. Verify peer's auth cert signature, perform X25519 DH, derive MAC keys via HKDF
3. Both peers send Auth messages with valid MAC to prove key derivation
4. All subsequent messages include sequence number + HMAC-SHA256

---

### STATE_MACHINE: AuthState

```
STATE_MACHINE: AuthState
  STATES: [Initial, HelloSent, HelloReceived, AuthSent, Authenticated, Failed]
  TRANSITIONS:
    Initial → HelloSent: after sending Hello
    HelloSent → HelloReceived: not used directly (process_hello sets HelloReceived)
    Initial → HelloReceived: after processing peer's Hello (process_hello)
    HelloReceived → AuthSent: after sending Auth
    AuthSent → Authenticated: after processing peer's Auth
    Any → Failed: on error
```

---

### STRUCT AuthCert

"Binds an ephemeral X25519 public key to a node's Ed25519 identity.
 Prevents MITM attacks during key exchange. Limited lifetime (~1 hour)."

```
STRUCT AuthCert:
  pubkey: bytes[32]        "ephemeral X25519 public key"
  expiration: integer      "Unix timestamp (seconds)"
  sig: bytes[64]           "Ed25519 signature"
```

**Signature format:**
```
Signed data = SHA-256(
  network_id (32 bytes) ||
  ENVELOPE_TYPE_AUTH (4 bytes, big-endian) ||
  expiration (8 bytes, big-endian) ||
  ephemeral_pubkey (32 bytes)
)
```

---

### AuthCert::new

```
function AuthCert::new(local_node, ephemeral_secret) → AuthCert:
  ephemeral_public = derive_public(ephemeral_secret)
  pubkey = ephemeral_public.bytes

  expiration = current_unix_time + 3600  "1 hour from now"

  sig = sign_cert(local_node, expiration, pubkey)
  → AuthCert { pubkey, expiration, sig }
```

**Calls**: [sign_cert](#sign_cert)

---

### sign_cert

"stellar-core signs the SHA-256 hash of the data, not the raw data"

```
function sign_cert(local_node, expiration, pubkey) → bytes[64]:
  data = network_id || ENVELOPE_TYPE_AUTH || expiration || pubkey
  hash = SHA-256(data)
  signature = local_node.secret_key.sign(hash)
  → signature.bytes
```

---

### AuthCert::verify

```
function verify(self, network_id, peer_public_key):
  "Check expiration"
  now = current_unix_time
  GUARD self.expiration <= now → error "auth cert expired"

  "Reconstruct the signed data"
  data = network_id || ENVELOPE_TYPE_AUTH || self.expiration || self.pubkey
  hash = SHA-256(data)

  "Verify signature over the hash"
  sig = Signature(self.sig)
  peer_public_key.verify(hash, sig)
  GUARD verification fails → error "invalid auth cert signature"
```

---

### STRUCT AuthContext

```
STRUCT AuthContext:
  local_node: LocalNode
  our_ephemeral_secret: optional X25519Secret
  our_ephemeral_public: optional X25519Public
  our_auth_cert: optional AuthCert
  our_nonce: bytes[32]
  peer_nonce: optional bytes[32]
  peer_auth_cert: optional AuthCert
  peer_public_key: optional Ed25519PublicKey
  peer_id: optional PeerId
  shared_secret: optional X25519SharedSecret
  send_mac_key: optional HmacSha256Key
  recv_mac_key: optional HmacSha256Key
  send_sequence: integer
  recv_sequence: integer
  state: AuthState
  we_called_remote: boolean
```

---

### AuthContext::new

```
function new(local_node, we_called_remote) → AuthContext:
  ephemeral_secret = generate random X25519 key pair
  ephemeral_public = derive_public(ephemeral_secret)
  auth_cert = AuthCert::new(local_node, ephemeral_secret)
  our_nonce = random 32 bytes

  → AuthContext {
      local_node, ephemeral_secret, ephemeral_public,
      auth_cert, our_nonce,
      all peer fields: none,
      send_sequence: 0, recv_sequence: 0,
      state: Initial, we_called_remote
    }
```

**Calls**: [AuthCert::new](#authcertnew)

---

### create_hello

```
function create_hello(self) → Hello:
  → Hello {
      ledger_version: local_node.ledger_version,
      overlay_version: local_node.overlay_version,
      overlay_min_version: local_node.overlay_min_version,
      network_id: local_node.network_id,
      version_str: local_node.version_string,
      listening_port: local_node.listening_port,
      peer_id: local_node.xdr_public_key(),
      cert: our_auth_cert.to_xdr(),
      nonce: our_nonce,
    }
```

---

### process_hello

"Core of the authentication handshake."

```
function process_hello(self, hello):
  "1. Check network ID"
  GUARD hello.network_id != local_node.network_id
    → error NetworkMismatch

  "2. Check overlay version"
  GUARD hello.overlay_version < local_node.overlay_min_version
    → error VersionMismatch

  "3. Extract peer public key"
  peer_pk_bytes = hello.peer_id.bytes
  peer_public_key = parse_ed25519(peer_pk_bytes)
  GUARD parse fails → error "invalid peer public key"

  "4. Verify auth cert"
  peer_auth_cert = AuthCert::from_xdr(hello.cert)
  peer_auth_cert.verify(local_node.network_id, peer_public_key)
  GUARD verification fails → propagate error

  "5. Store peer's nonce"
  MUTATE self.peer_nonce = hello.nonce

  "6. Perform X25519 key exchange"
  our_secret = consume our_ephemeral_secret
  GUARD already consumed → error "ephemeral secret already used"
  peer_ephemeral_public = X25519PublicKey(peer_auth_cert.pubkey)
  shared_secret = our_secret.diffie_hellman(peer_ephemeral_public)

  "7. Derive MAC keys"
  (send_key, recv_key) = derive_mac_keys(shared_secret, peer_auth_cert)

  "8. Store peer info"
  MUTATE self.peer_public_key = peer_public_key
  MUTATE self.peer_id = PeerId(peer_pk_bytes)
  MUTATE self.peer_auth_cert = peer_auth_cert
  MUTATE self.shared_secret = shared_secret
  MUTATE self.send_mac_key = send_key
  MUTATE self.recv_mac_key = recv_key
  MUTATE self.state = HelloReceived
```

**Calls**: [AuthCert::verify](#authcertverify) | [derive_mac_keys](#derive_mac_keys)

---

### derive_mac_keys

"HKDF key derivation following stellar-core's scheme."

```
function derive_mac_keys(self, shared_secret, peer_auth_cert)
    → (send_key, recv_key):

  our_public = our_ephemeral_public
  peer_nonce = self.peer_nonce

  "Step 1: HKDF-Extract"
  "IKM = ECDH_result || A_pub || B_pub"
  "where A is initiator (outbound), B is acceptor (inbound)"
  if we_called_remote:
    (a_pub, b_pub) = (our_public, peer_auth_cert.pubkey)
  else:
    (a_pub, b_pub) = (peer_auth_cert.pubkey, our_public)

  ikm = shared_secret || a_pub || b_pub

  "HKDF-Extract: PRK = HMAC-SHA256(salt=zeros, IKM)"
  prk = HMAC-SHA256(key=zeros[32], data=ikm)

  "Step 2: Determine prefixes"
  "Prefix 0 = A→B direction, Prefix 1 = B→A direction"
  if we_called_remote:
    "We are A: send A→B (prefix 0), receive B→A (prefix 1)"
    send_prefix = 0
    recv_prefix = 1
  else:
    "We are B: send B→A (prefix 1), receive A→B (prefix 0)"
    send_prefix = 1
    recv_prefix = 0

  "Step 3: HKDF-Expand for each direction"
  send_key = hkdf_expand(prk, send_prefix, our_nonce, peer_nonce)
  recv_key = hkdf_expand(prk, recv_prefix, peer_nonce, our_nonce)

  → (send_key, recv_key)
```

**Calls**: [hkdf_expand](#hkdf_expand)

---

### hkdf_expand

"HKDF-Expand: derives a MAC key from PRK using prefix and nonces."

```
function hkdf_expand(self, prk, prefix, nonce1, nonce2) → HmacSha256Key:
  info = prefix || nonce1 || nonce2

  "T(1) = HMAC-SHA256(PRK, info || 0x01)"
  key = HMAC-SHA256(key=prk, data=(info || 0x01))
  → HmacSha256Key { key }
```

---

### hello_sent

```
function hello_sent(self):
  if state == Initial:
    MUTATE state = HelloSent
```

---

### auth_sent

```
function auth_sent(self):
  if state == HelloReceived:
    MUTATE state = AuthSent
```

---

### process_auth

"Processes a received Auth message, completing the handshake."

```
function process_auth(self):
  "AUTH messages consume sequence 0 on both sides"
  "So first post-auth messages use sequence 1"
  MUTATE recv_sequence = 1
  MUTATE send_sequence = 1
  MUTATE state = Authenticated
```

---

### wrap_message

"Wraps a message with sequence number and MAC for sending."

```
function wrap_message(self, message) → AuthenticatedMessage:
  GUARD send_mac_key not established → error

  sequence = send_sequence
  MUTATE send_sequence += 1

  mac = compute_mac(send_mac_key, sequence, message)

  → AuthenticatedMessage::V0 { sequence, message, mac }
```

**Calls**: [compute_mac](#compute_mac)

---

### unwrap_message

"Unwraps and verifies a received message."

```
function unwrap_message(self, auth_msg, message_is_authenticated)
    → StellarMessage:
  v0 = auth_msg.v0

  "Only verify sequence and MAC when:
   1. Past the handshake phase
   2. Message actually has a MAC (bit 31 set)
   3. Not an ERROR message (errors skip MAC)"
  is_error = v0.message is ErrorMsg

  if is_authenticated AND message_is_authenticated AND NOT is_error:
    "Verify sequence number"
    GUARD v0.sequence != recv_sequence
      → error "sequence mismatch"
    MUTATE recv_sequence += 1

    "Verify MAC"
    recv_key = recv_mac_key
    GUARD recv_key not established → error

    expected_mac = compute_mac(recv_key, v0.sequence, v0.message)
    GUARD expected_mac != v0.mac → error MacVerificationFailed

  → v0.message
```

**Calls**: [compute_mac](#compute_mac)

---

### compute_mac

"Computes HMAC-SHA256 for a message."

```
function compute_mac(self, key, sequence, message) → HmacSha256Mac:
  message_bytes = serialize message to XDR

  mac = HMAC-SHA256(key=key.bytes)
  mac.update(sequence as 8 bytes big-endian)
  mac.update(message_bytes)

  → mac.finalize() as 32-byte HmacSha256Mac
```

---

### wrap_unauthenticated

"Hello messages use sequence 0 and zero MAC (sent before keys established)."

```
function wrap_unauthenticated(self, message) → AuthenticatedMessage:
  → AuthenticatedMessage::V0 {
      sequence: 0,
      message,
      mac: zeros[32]
    }
```

---

### wrap_auth_message

"Auth messages use sequence 0 but include a valid MAC to prove
 correct key derivation."

```
function wrap_auth_message(self, message) → AuthenticatedMessage:
  GUARD send_mac_key not established → error

  sequence = 0
  mac = compute_mac(send_mac_key, sequence, message)

  → AuthenticatedMessage::V0 { sequence, message, mac }
```

**Calls**: [compute_mac](#compute_mac)

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 718    | 186        |
| Functions     | 18     | 18         |
