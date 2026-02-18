## Pseudocode: crates/overlay/src/peer.rs

### State Machine

```
STATE_MACHINE: PeerState
  STATES: [Connecting, Handshaking, Authenticated, Closing, Disconnected]
  TRANSITIONS:
    Connecting → Handshaking: handshake starts
    Handshaking → Authenticated: handshake complete
    Authenticated → Closing: close() called
    Closing → Disconnected: connection closed
    Authenticated → Disconnected: recv returns no data
```

### Data Structures

```
PeerInfo:
  peer_id: PeerId
  address: SocketAddr
  direction: Inbound | Outbound
  version_string: string
  overlay_version: int
  ledger_version: int
  connected_at: Timestamp
  original_address: PeerAddress or null

PeerStatsSnapshot:
  messages_sent: int
  messages_received: int
  bytes_sent: int
  bytes_received: int
  unique_flood_messages_recv: int
  duplicate_flood_messages_recv: int
  unique_flood_bytes_recv: int
  duplicate_flood_bytes_recv: int
  unique_fetch_messages_recv: int
  duplicate_fetch_messages_recv: int
  unique_fetch_bytes_recv: int
  duplicate_fetch_bytes_recv: int
```

### connect

```
async function connect(addr, local_node, timeout_secs):
  connection = Connection.connect(addr, timeout_secs)
```

**Calls** [Connection.connect](connection.pc.md#connect)

```
  auth = AuthContext(local_node, we_called_remote=true)

  peer = Peer {
    info: PeerInfo {
      peer_id: placeholder,
      address: connection.remote_addr,
      direction: Outbound,
      connected_at: now(),
      original_address: addr
    },
    state: Connecting,
    connection, auth
  }

  peer.handshake(timeout_secs)
  → peer
```

### accept

```
async function accept(connection, local_node, timeout_secs):
  auth = AuthContext(local_node, we_called_remote=false)

  peer = Peer {
    info: PeerInfo {
      peer_id: placeholder,
      address: connection.remote_addr,
      direction: Inbound,
      connected_at: now(),
      original_address: null
    },
    state: Connecting,
    connection, auth
  }

  peer.handshake(timeout_secs)
  → peer
```

### handshake

```
async function handshake(timeout_secs):
  MUTATE state = Handshaking

  "Send Hello"
  hello = auth.create_hello()
  send_raw(Hello(hello))
  auth.hello_sent()

  "Receive Hello"
  frame = connection.recv_timeout(timeout_secs)
  GUARD frame is null → error "no Hello received"
  message = auth.unwrap_message(frame)
  GUARD message is not Hello → error "expected Hello"
  process_hello(message.hello)

  "Send Auth with flow control flag"
  NOTE: AUTH_MSG_FLAG_FLOW_CONTROL_BYTES_REQUESTED = 200
  auth_msg = Auth { flags: 200 }
  send_auth(auth_msg)
  auth.auth_sent()

  "Receive Auth"
  frame = connection.recv_timeout(timeout_secs)
  GUARD frame is null → error "no Auth received"
  message = auth.unwrap_message(frame)

  if message is Auth:
    "Peers must set flag=200 to enable byte-based flow control"
    GUARD message.auth.flags != 200
      → error "Auth missing flow control flag"
    auth.process_auth()
  else if message is ErrorMsg:
    → error with peer's error message
  else:
    → error "expected Auth"

  MUTATE state = Authenticated

  "Send SEND_MORE_EXTENDED to enable flow control"
  NOTE: "Match stellar-core defaults: PEER_FLOOD_READING_CAPACITY=200, fcBytes=300000"
  send(SendMoreExtended { num_messages: 200, num_bytes: 300000 })

  "Ask for SCP data after flow control message"
  NOTE: "matches stellar-core recvAuth behavior"
  send(GetScpState(0))
```

**Calls** [auth.create_hello](auth.pc.md#create_hello), [auth.process_hello](auth.pc.md#process_hello), [auth.process_auth](auth.pc.md#process_auth)

### process_hello

```
function process_hello(hello):
  "State guard: reject if not in Handshaking state"
  GUARD state != Handshaking → error

  "Port validation: valid ports are 0-65535"
  GUARD hello.listening_port < 0
     or hello.listening_port > 65535 → error

  "Let auth context process it (network ID, version, cert checks)"
  auth.process_hello(hello)

  peer_id = auth.peer_id()
  GUARD peer_id is null → error "no peer ID"

  "Self-connection check"
  GUARD peer_id == auth.local_peer_id()
    → error "received Hello from self"

  MUTATE info.peer_id = peer_id
  MUTATE info.version_string = hello.version_str
  MUTATE info.overlay_version = hello.overlay_version
  MUTATE info.ledger_version = hello.ledger_version

  if hello.listening_port > 0:
    MUTATE info.address = (info.address.ip, hello.listening_port)
```

### send_raw

```
async function send_raw(message):
  size = msg_body_size(message)
  auth_msg = auth.wrap_unauthenticated(message)
  connection.send(auth_msg)
  MUTATE stats.messages_sent += 1
  MUTATE stats.bytes_sent += size
```

### send_auth

```
async function send_auth(message):
  size = msg_body_size(message)
  auth_msg = auth.wrap_auth_message(message)
  connection.send(auth_msg)
  MUTATE stats.messages_sent += 1
  MUTATE stats.bytes_sent += size
```

### send

```
async function send(message):
  GUARD state != Authenticated → error "not authenticated"
  size = msg_body_size(message)
  auth_msg = auth.wrap_message(message)
  connection.send(auth_msg)
  MUTATE stats.messages_sent += 1
  MUTATE stats.bytes_sent += size
```

### recv

```
async function recv():
  GUARD state != Authenticated → null
  frame = connection.recv()
  if frame is null:
    MUTATE state = Disconnected
    → null
  MUTATE stats.messages_received += 1
  MUTATE stats.bytes_received += frame.raw_len
  message = auth.unwrap_message(frame)
  → message
```

### recv_timeout

```
async function recv_timeout(timeout_secs):
  GUARD state != Authenticated → null
  frame = connection.recv_timeout(timeout_secs)
  if frame is null:
    MUTATE state = Disconnected
    → null
  MUTATE stats.messages_received += 1
  MUTATE stats.bytes_received += frame.raw_len
  message = auth.unwrap_message(frame)
  → message
```

### record_flood_stats

```
function record_flood_stats(unique, bytes):
  if unique:
    MUTATE stats.unique_flood_messages_recv += 1
    MUTATE stats.unique_flood_bytes_recv += bytes
  else:
    MUTATE stats.duplicate_flood_messages_recv += 1
    MUTATE stats.duplicate_flood_bytes_recv += bytes
```

### record_fetch_stats

```
function record_fetch_stats(unique, bytes):
  if unique:
    MUTATE stats.unique_fetch_messages_recv += 1
    MUTATE stats.unique_fetch_bytes_recv += bytes
  else:
    MUTATE stats.duplicate_fetch_messages_recv += 1
    MUTATE stats.duplicate_fetch_bytes_recv += bytes
```

### request_scp_state

```
async function request_scp_state(ledger_seq):
  send(GetScpState(ledger_seq))
```

### send_more

```
async function send_more(num_messages):
  send(SendMore { num_messages })
```

### send_more_extended

```
async function send_more_extended(num_messages, num_bytes):
  send(SendMoreExtended { num_messages, num_bytes })
```

### close

```
async function close():
  if state != Disconnected:
    MUTATE state = Closing
    connection.close()
    MUTATE state = Disconnected
```

### Accessor Functions

```
function id():        → info.peer_id
function info():      → info
function state():     → state
function is_connected(): → state is Handshaking or Authenticated
function is_ready():     → state is Authenticated
function stats():        → stats reference
function remote_addr():  → info.address
function direction():    → info.direction
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 649    | 190        |
| Functions     | 22     | 22         |
