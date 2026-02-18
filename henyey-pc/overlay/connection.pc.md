# Pseudocode: crates/overlay/src/connection.rs

## Overview

"Low-level TCP connection handling for the Stellar overlay."

Provides the transport layer: framed TCP connections with message codec,
a listener for inbound connections, and a connection pool with limits.

---

### ENUM ConnectionDirection

```
ENUM ConnectionDirection:
  Outbound   "we initiated (initiator in key derivation)"
  Inbound    "peer connected to us (acceptor in key derivation)"
```

### we_called_remote

```
function we_called_remote(self) → boolean:
  → self is Outbound
```

---

### STRUCT Connection

```
STRUCT Connection:
  framed: FramedStream<TcpStream, MessageCodec>
  remote_addr: SocketAddr
  direction: ConnectionDirection
  closed: boolean
```

---

### Connection::new

"Creates a connection from an existing TCP stream."

```
function new(stream, direction) → Connection:
  remote_addr = stream.peer_addr()

  "Disable Nagle's algorithm for lower latency"
  stream.set_nodelay(true)

  framed = Framed(stream, MessageCodec::new())

  → Connection { framed, remote_addr, direction, closed: false }
```

---

### Connection::connect

"Connects to a peer address with a timeout."

```
function connect(addr, timeout_secs) → Connection:
  socket_addr = addr.to_socket_addr()

  stream = TCP_connect(socket_addr)
            with timeout(timeout_secs)

  → Connection::new(stream, Outbound)
```

**Calls**: [new](#connectionnew)

---

### Connection::send

```
CONST SEND_TIMEOUT_SECS = 10

function send(self, message):
  GUARD self.closed → error "connection closed"

  result = send message via framed stream
            with timeout(SEND_TIMEOUT_SECS)

  if send error:
    MUTATE self.closed = true
    → propagate error
  if timeout:
    MUTATE self.closed = true
    → error "send timeout"
```

---

### Connection::recv

```
function recv(self) → optional MessageFrame:
  GUARD self.closed → return none

  frame = read next from framed stream

  if frame received:
    → frame
  if error:
    MUTATE self.closed = true
    → propagate error
  if stream ended:
    MUTATE self.closed = true
    → none
```

---

### Connection::recv_timeout

```
function recv_timeout(self, timeout_secs) → optional MessageFrame:
  result = recv() with timeout(timeout_secs)

  if timeout:
    MUTATE self.closed = true
    → error "receive timeout"
  → result
```

**Calls**: [recv](#connectionrecv)

---

### Connection::close

```
function close(self):
  if not self.closed:
    MUTATE self.closed = true
```

---

### Connection::split

"Splits connection into separate send and receive halves
 for concurrent sending and receiving."

```
function split(self) → (ConnectionSender, ConnectionReceiver):
  (sink, stream) = framed.split()
  → (ConnectionSender { sink, remote_addr },
     ConnectionReceiver { stream, remote_addr })
```

---

### ConnectionSender::send

```
CONST SEND_TIMEOUT_SECS = 10

function send(self, message):
  result = send message via sink
            with timeout(SEND_TIMEOUT_SECS)

  if send error → propagate error
  if timeout → error "send timeout"
```

---

### ConnectionReceiver::recv

```
function recv(self) → optional MessageFrame:
  frame = read next from stream

  if frame received → frame
  if error → propagate error
  if stream ended → none
```

---

### STRUCT Listener

```
STRUCT Listener:
  listener: TcpListener
  local_addr: SocketAddr
```

### Listener::bind

```
function bind(port) → Listener:
  listener = TcpListener::bind("0.0.0.0:{port}")
  local_addr = listener.local_addr()
  → Listener { listener, local_addr }
```

---

### Listener::accept

```
function accept(self) → Connection:
  (stream, remote_addr) = listener.accept()
  → Connection::new(stream, Inbound)
```

**Calls**: [Connection::new](#connectionnew)

---

### STRUCT ConnectionPool

"Thread-safe connection counter for enforcing connection limits.
 Supports 'possibly preferred' extra slots: connections from preferred
 IP addresses can exceed max_connections by up to possibly_preferred_extra
 slots, matching upstream's Config::POSSIBLY_PREFERRED_EXTRA."

```
STRUCT ConnectionPool:
  max_connections: integer
  possibly_preferred_extra: integer
  preferred_ips: Set<IpAddr>
  current_count: atomic integer
```

---

### ConnectionPool::new

```
function new(max_connections) → ConnectionPool:
  → ConnectionPool { max_connections, possibly_preferred_extra: 0,
                      preferred_ips: empty, current_count: 0 }
```

---

### ConnectionPool::with_preferred

```
function with_preferred(max, extra, preferred_ips) → ConnectionPool:
  → ConnectionPool { max, possibly_preferred_extra: extra,
                      preferred_ips, current_count: 0 }
```

---

### can_accept

```
function can_accept(self) → boolean:
  → current_count < max_connections
```

---

### try_reserve

```
function try_reserve(self) → boolean:
  → try_reserve_with_ip(none)
```

**Calls**: [try_reserve_with_ip](#try_reserve_with_ip)

---

### try_reserve_with_ip

"Attempts to reserve a slot. Preferred IPs may exceed base limit
 up to max_connections + possibly_preferred_extra."

```
function try_reserve_with_ip(self, ip) → boolean:
  current = load current_count

  loop:
    if current >= max_connections:
      "Over base limit -- only allow if IP is preferred"
      if ip is provided and ip in preferred_ips:
        effective_max = max_connections + possibly_preferred_extra
      else:
        effective_max = max_connections
    else:
      effective_max = max_connections

    if current >= effective_max:
      → false

    if compare_and_swap(current_count, current, current + 1):
      → true
    else:
      current = current_count  "retry with updated value"
```

---

### release

```
function release(self):
  MUTATE current_count -= 1
```

---

### count

```
function count(self) → integer:
  → current_count
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 484    | 137        |
| Functions     | 18     | 18         |
