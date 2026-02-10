# henyey-common

Common types and utilities for henyey.

## Overview

This crate provides shared types, traits, and utilities used across all henyey modules. It is designed to be dependency-light and contains pure data types and helpers with no I/O or side effects (except for configuration file loading), making it suitable as a foundation for all other crates in the workspace.

## Architecture

- **Small, dependency-light modules** to avoid dependency cycles across core crates
- **Pure data types and helpers** with minimal side effects
- **Re-exports XDR types** for convenient access across the workspace
- **Centralizes network ID and hash handling** for consistent behavior

## Modules

| Module | Description |
|--------|-------------|
| `asset` | Asset validation, comparison, balance utilities, price comparison, ledger key extraction, and string/numeric helpers |
| `config` | Configuration types for node setup (network, database, history archives, logging) |
| `error` | Common error types and the `Result` type alias |
| `math` | 128-bit arithmetic, overflow-safe math (`big_divide`, `saturating_multiply`, `big_square_root`) |
| `meta` | Ledger metadata normalization for deterministic hashing |
| `network` | Network identity derived from network passphrases |
| `protocol` | Protocol version constants and feature gating utilities |
| `resource` | Resource accounting for transaction limits and surge pricing |
| `time` | Time utilities for Unix/Stellar timestamp conversions |
| `types` | The `Hash256` type (32-byte SHA-256 hash) used throughout the codebase |

## Key Types

### Hash256

A 32-byte SHA-256 hash used throughout Stellar for ledger hashes, transaction hashes, and other cryptographic identifiers.

```rust
use henyey_common::Hash256;

// Hash some data
let hash = Hash256::hash(b"hello world");

// Convert to/from hex
let hex_str = hash.to_hex();
let parsed = Hash256::from_hex(&hex_str).unwrap();
assert_eq!(hash, parsed);

// Check for zero hash
assert!(!hash.is_zero());
assert!(Hash256::ZERO.is_zero());
```

### NetworkId

A unique identifier for a Stellar network, derived from the network passphrase. This prevents cross-network replay attacks by binding signatures to a specific network.

```rust
use henyey_common::NetworkId;

// Use standard networks
let testnet = NetworkId::testnet();   // "Test SDF Network ; September 2015"
let mainnet = NetworkId::mainnet();   // "Public Global Stellar Network ; September 2015"

// Create a custom network
let custom = NetworkId::from_passphrase("My Private Network ; 2024");
```

### Config

Main configuration struct for stellar-core nodes. Supports loading from TOML files or using preset configurations.

```rust
use henyey_common::Config;
use std::path::Path;

// Load from file
let config = Config::from_file(Path::new("config.toml")).unwrap();

// Or use testnet defaults
let config = Config::testnet();
```

### Error and Result

Common error handling types used throughout henyey.

```rust
use henyey_common::{Error, Result};

fn validate_data(data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Err(Error::InvalidData("data cannot be empty".to_string()));
    }
    Ok(())
}
```

## Protocol Versioning

The `protocol` module provides utilities for feature gating based on protocol versions:

```rust
use henyey_common::protocol::{
    protocol_version_starts_from, soroban_supported, ProtocolVersion
};

let current_version = 22;

// Check if Soroban smart contracts are supported (V20+)
if soroban_supported(current_version) {
    // Execute smart contract logic
}

// Check for specific version features
if protocol_version_starts_from(current_version, ProtocolVersion::V21) {
    // Use V21+ features
}
```

### Key Protocol Versions

- **V20**: Soroban smart contracts introduced
- **V23**: Parallel Soroban execution, auto-restore, reusable module cache

## Time Utilities

Stellar uses a custom epoch (January 1, 2000) for some internal timestamps:

```rust
use henyey_common::time::{
    unix_to_stellar_time, stellar_to_unix_time, current_timestamp, STELLAR_EPOCH
};

// Get current Unix timestamp
let now = current_timestamp();

// Convert between Unix and Stellar time
let stellar_time = unix_to_stellar_time(now);
let unix_time = stellar_to_unix_time(stellar_time);
assert_eq!(now, unix_time);
```

## Resource Accounting

Track computational resources for transaction limits and surge pricing:

```rust
use henyey_common::resource::{Resource, ResourceType};

// Create a Soroban resource vector (7 dimensions)
let mut resources = Resource::make_empty_soroban();
resources.set_val(ResourceType::Operations, 1);
resources.set_val(ResourceType::Instructions, 1_000_000);

// Check resource usage
assert!(!resources.is_zero());
assert!(resources.any_positive());
```

## Metadata Normalization

Normalize ledger metadata for deterministic hashing across validators:

```rust
use henyey_common::meta::normalize_ledger_close_meta;

// Normalize metadata for consistent hashing
// normalize_ledger_close_meta(&mut meta)?;
```

## Re-exports

This crate re-exports `stellar_xdr` for convenience:

```rust
use henyey_common::stellar_xdr;
// Access XDR types without adding a direct dependency
```

## Configuration File Format

Configuration is loaded from TOML files:

```toml
[network]
passphrase = "Test SDF Network ; September 2015"
peer_port = 11625
http_port = 11626
known_peers = ["core-testnet1.stellar.org:11625"]

[database]
path = "stellar.db"

[node]
is_validator = false

[logging]
level = "info"
format = "text"

[[history.get_commands]]
name = "sdf"
get = "curl -sf https://history.stellar.org/{0} -o {1}"
```

## stellar-core Parity Status

See [PARITY_STATUS.md](PARITY_STATUS.md) for detailed stellar-core parity analysis.

## License

Apache 2.0
