# stellar-core-common

Common types and utilities for rs-stellar-core.

## Overview

This crate provides shared types, traits, and utilities used across all rs-stellar-core modules:

- **Configuration** - Unified configuration types
- **Error handling** - Common error types and result aliases
- **Network identifiers** - Network passphrase and ID handling
- **Time utilities** - Stellar time handling
- **Common types** - Hash256, primitives, and helpers

## Modules

| Module | Description |
|--------|-------------|
| `config` | Configuration types and defaults |
| `error` | Common error types |
| `network` | Network ID and passphrase handling |
| `time` | Time utilities for Stellar timestamps |
| `types` | Common types like Hash256 |

## Key Types

### Hash256

A 32-byte hash used throughout Stellar (ledger hashes, transaction hashes, etc.):

```rust
use stellar_core_common::Hash256;

// Create from bytes
let hash = Hash256::from_bytes([0u8; 32]);

// Hash data
let hash = Hash256::hash(b"some data");

// Convert to/from hex
let hex = hash.to_hex();
let hash = Hash256::from_hex(&hex)?;
```

### NetworkId

Network identifier derived from the network passphrase:

```rust
use stellar_core_common::NetworkId;

// Testnet
let network_id = NetworkId::testnet();

// Mainnet
let network_id = NetworkId::mainnet();

// Custom network
let network_id = NetworkId::from_passphrase("My Network ; 2024");
```

## Usage

```rust
use stellar_core_common::{Config, Error, Result, NetworkId, Hash256};

// Use common types across the codebase
fn process_ledger(hash: Hash256, network: &NetworkId) -> Result<()> {
    // ...
    Ok(())
}
```

## Re-exports

This crate re-exports `stellar_xdr` for convenience, so other crates can access XDR types through `stellar_core_common::stellar_xdr`.

## License

Apache 2.0
