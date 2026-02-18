# Pseudocode: crates/overlay/src/codec.rs

## Overview

"Message codec for Stellar overlay protocol."

Implements the framing layer for Stellar network messages. Each message on
the wire is prefixed with a 4-byte big-endian length field.

```
Wire format:
  +----------------+------------------+
  | Length (4 bytes) | XDR Message Body |
  +----------------+------------------+

Length Field:
  Bit 31 (MSB): Authentication flag
    Set   → message has valid MAC
    Clear → MAC field is all zeros (Hello/Auth during handshake)
  Bits 0-30: Actual message body length in bytes
```

```
CONST MAX_MESSAGE_SIZE = 32 MB     // prevents memory exhaustion
CONST MIN_MESSAGE_SIZE = 12 bytes  // authenticated message header minimum
```

---

### STRUCT MessageFrame

```
STRUCT MessageFrame:
  message: AuthenticatedMessage    "decoded message wrapper"
  raw_len: integer                 "body size in bytes, excl. length prefix"
  is_authenticated: boolean        "true if bit 31 was set"
```

---

### STATE_MACHINE: DecodeState

```
STATE_MACHINE: DecodeState
  STATES: [ReadingLength, ReadingBody]
  TRANSITIONS:
    ReadingLength → ReadingBody: when 4 bytes available, length validated
    ReadingBody → ReadingLength: when full body received and decoded
```

---

### encode_message (static)

"Encodes a message to bytes with length prefix."

```
function encode_message(message) → bytes:
  is_authenticated = message is NOT a Hello message

  xdr_bytes = serialize message to XDR
  len = xdr_bytes.length
  auth_bit = 0x80000000 if is_authenticated, else 0

  buf = allocate (4 + len) bytes
  write (len | auth_bit) as big-endian u32 to buf
  append xdr_bytes to buf
  → buf
```

---

### decode_message (static)

"Decodes XDR bytes to an authenticated message."

```
function decode_message(bytes) → AuthenticatedMessage:
  → deserialize bytes from XDR as AuthenticatedMessage
```

---

### decode (Decoder trait)

```
function decode(self, src_buffer) → optional MessageFrame:
  loop:
    if state is ReadingLength:
      GUARD src_buffer.length < 4 → return none (need more data)

      raw_len = read 4 bytes as big-endian u32
      is_authenticated = (raw_len & 0x80000000) != 0
      len = raw_len & 0x7FFFFFFF

      GUARD len < MIN_MESSAGE_SIZE → error "message too small"
      GUARD len > MAX_MESSAGE_SIZE → error "message too large"

      advance src_buffer past 4 bytes
      reserve len bytes in src_buffer
      transition to ReadingBody { len, is_authenticated }

    if state is ReadingBody { len, is_authenticated }:
      GUARD src_buffer.length < len → return none (need more data)

      body = extract len bytes from src_buffer
      message = decode_message(body)
      transition to ReadingLength

      → MessageFrame { message, raw_len: len, is_authenticated }
```

**Calls**: [decode_message](#decode_message-static)

---

### encode (Encoder trait)

```
function encode(self, message, dst_buffer):
  "HELLO messages are sent before keys are established, so they use
   sequence 0 and an all-zero MAC field - no auth bit.
   All other messages (AUTH and post-auth) have valid MACs and need
   the auth bit set so the receiver knows to verify the MAC."

  is_authenticated = message is NOT a Hello message

  xdr_bytes = serialize message to XDR

  GUARD xdr_bytes.length > MAX_MESSAGE_SIZE → error "message too large"

  len = xdr_bytes.length
  auth_bit = 0x80000000 if is_authenticated, else 0

  reserve (4 + len) bytes in dst_buffer
  write (len | auth_bit) as big-endian u32 to dst_buffer
  append xdr_bytes to dst_buffer
```

---

## helpers module

### message_hash

```
function message_hash(message) → Hash256:
  bytes = serialize message to XDR
  → SHA-256(bytes)
```

---

### is_flood_message

"Returns true if this message type should be flooded to peers."

```
function is_flood_message(message) → boolean:
  → message is one of:
    Transaction, ScpMessage,
    FloodAdvert, FloodDemand,
    TimeSlicedSurveyRequest, TimeSlicedSurveyResponse,
    TimeSlicedSurveyStartCollecting, TimeSlicedSurveyStopCollecting
```

---

### is_watcher_droppable

"Watchers don't need transaction flood, pull-based flood control, or survey
 messages. Dropping these at the overlay layer reduces broadcast channel
 pressure by ~90% on mainnet, preventing SCP message loss."

```
function is_watcher_droppable(message) → boolean:
  → message is one of:
    Transaction,
    FloodAdvert, FloodDemand,
    TimeSlicedSurveyRequest, TimeSlicedSurveyResponse,
    TimeSlicedSurveyStartCollecting, TimeSlicedSurveyStopCollecting
```

---

### is_handshake_message

```
function is_handshake_message(message) → boolean:
  → message is Hello or Auth
```

---

### message_type_name

```
function message_type_name(message) → string:
  → human-readable name for message type
    (e.g. "HELLO", "AUTH", "TRANSACTION", "SCP_MESSAGE", ...)
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 344    | 94         |
| Functions     | 9      | 9          |
