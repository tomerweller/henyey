# stellar-core-common

Common types and utilities for rs-stellar-core.

## Overview

This crate provides shared types, traits, and utilities used across all rs-stellar-core modules. It is designed to be dependency-light and contains pure data types and helpers with no I/O or side effects (except for configuration file loading), making it suitable as a foundation for all other crates in the workspace.

## Architecture

- **Small, dependency-light modules** to avoid dependency cycles across core crates
- **Pure data types and helpers** with minimal side effects
- **Re-exports XDR types** for convenient access across the workspace
- **Centralizes network ID and hash handling** for consistent behavior

## Modules

| Module | Description |
|--------|-------------|
| `config` | Configuration types for node setup (network, database, history archives, logging) |
| `error` | Common error types and the `Result` type alias |
| `meta` | Ledger metadata normalization for deterministic hashing |
| `network` | Network identity derived from network passphrases |
| `protocol` | Protocol version constants and feature gating utilities |
| `resource` | Resource accounting for transaction limits and surge pricing |
| `time` | Time utilities for Unix/Stellar timestamp conversions |
| `types` | Core types like `Hash256` used throughout the codebase |

## Key Types

### Hash256

A 32-byte SHA-256 hash used throughout Stellar for ledger hashes, transaction hashes, and other cryptographic identifiers.

```rust
use stellar_core_common::Hash256;

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
use stellar_core_common::NetworkId;

// Use standard networks
let testnet = NetworkId::testnet();   // "Test SDF Network ; September 2015"
let mainnet = NetworkId::mainnet();   // "Public Global Stellar Network ; September 2015"

// Create a custom network
let custom = NetworkId::from_passphrase("My Private Network ; 2024");
```

### Config

Main configuration struct for stellar-core nodes. Supports loading from TOML files or using preset configurations.

```rust
use stellar_core_common::Config;
use std::path::Path;

// Load from file
let config = Config::from_file(Path::new("config.toml")).unwrap();

// Or use testnet defaults
let config = Config::testnet();
```

### Error and Result

Common error handling types used throughout rs-stellar-core.

```rust
use stellar_core_common::{Error, Result};

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
use stellar_core_common::protocol::{
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
use stellar_core_common::time::{
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
use stellar_core_common::resource::{Resource, ResourceType};

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
use stellar_core_common::meta::normalize_ledger_close_meta;

// Normalize metadata for consistent hashing
// normalize_ledger_close_meta(&mut meta)?;
```

## Re-exports

This crate re-exports `stellar_xdr` for convenience:

```rust
use stellar_core_common::stellar_xdr;
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

## C++ Parity Status

This section documents the parity between this Rust crate and the C++ upstream utilities found in `.upstream-v25/src/util/` and related modules.

### Implemented

The following features from C++ stellar-core are implemented in this crate:

#### Protocol Version Utilities (`protocol.rs` <-> `ProtocolVersion.h/.cpp`)
- `ProtocolVersion` enum (V0-V25)
- `protocol_version_is_before()` - checks if version is strictly before target
- `protocol_version_starts_from()` - checks if version is at or after target
- `protocol_version_equals()` - checks if version equals target exactly
- `needs_upgrade_to_version()` - detects protocol upgrade crossing a boundary
- `soroban_supported()` - checks if Soroban is supported at given version
- Protocol version constants: `SOROBAN_PROTOCOL_VERSION`, `PARALLEL_SOROBAN_PHASE_PROTOCOL_VERSION`, `AUTO_RESTORE_PROTOCOL_VERSION`, `REUSABLE_SOROBAN_MODULE_CACHE_PROTOCOL_VERSION`

#### Resource Accounting (`resource.rs` <-> `TxResource.h/.cpp`)
- `Resource` struct with multi-dimensional resource vectors
- `ResourceType` enum (Operations, Instructions, TxByteSize, DiskReadBytes, WriteBytes, ReadLedgerEntries, WriteLedgerEntries)
- Resource dimension constants: `NUM_CLASSIC_TX_RESOURCES`, `NUM_CLASSIC_TX_BYTES_RESOURCES`, `NUM_SOROBAN_TX_RESOURCES`
- `Resource::new()`, `make_empty()`, `make_empty_soroban()`
- `is_zero()`, `any_positive()`, `size()`, `get_val()`, `set_val()`, `can_add()`, `leq()`
- Arithmetic operators: `+`, `-`, `+=`, `-=`
- Partial ordering with `PartialOrd`
- Helper functions: `any_less_than()`, `any_greater()`, `subtract_non_negative()`, `limit_to()`

#### Metadata Normalization (`meta.rs` <-> `MetaUtils.h/.cpp`)
- `normalize_transaction_meta()` - normalizes transaction metadata for deterministic hashing
- `normalize_ledger_close_meta()` - normalizes ledger close metadata
- `ledger_entry_key()` - extracts ledger key from entry
- Change sorting by (key, type, hash) for canonical ordering
- Support for all TransactionMeta versions (V0-V4)
- Support for all LedgerCloseMeta versions (V0-V2)

#### Core Types (`types.rs` <-> `types.h/.cpp`)
- `Hash256` type for 32-byte SHA-256 hashes
- `Hash256::hash()` - compute SHA-256 hash of data
- `Hash256::hash_xdr()` - compute SHA-256 hash of XDR-encoded data
- `is_zero()` - check for zero hash (equivalent to C++ `isZero()`)
- Hex encoding/decoding
- Conversions to/from `stellar_xdr::Hash`
- `LedgerEntryKey()` equivalent via `ledger_entry_key()` in meta.rs

#### Network Identity (`network.rs`)
- `NetworkId` type with passphrase-based derivation
- `from_passphrase()`, `testnet()`, `mainnet()`
- Conversion to `stellar_xdr::Hash`

#### Time Utilities (`time.rs`)
- `current_timestamp()` / `current_timestamp_ms()`
- `STELLAR_EPOCH` constant (January 1, 2000)
- `unix_to_stellar_time()` / `stellar_to_unix_time()` conversions
- `timestamp_to_system_time()` conversion

#### Configuration (`config.rs`)
- `Config` struct with network, database, node, history, and logging sections
- TOML file loading
- Testnet preset configuration

#### Error Handling (`error.rs`)
- `Error` enum with Xdr, Io, Config, InvalidData, NotFound, OperationFailed variants
- `Result<T>` type alias

### Not Yet Implemented (Gaps)

The following C++ utilities are not yet implemented in this crate:

#### Virtual Clock and Timer System (`Timer.h/.cpp`, `Scheduler.h/.cpp`)
- **VirtualClock** - Virtual time management for testing and simulation
- **VirtualTimer** - Timer that works with virtual or real time
- **Scheduler** - Fair time-slicing scheduler for action queues with load shedding
- Time mode switching (REAL_TIME vs VIRTUAL_TIME)
- System/wall clock conversions (`systemPointToTm`, `tmToISOString`, etc.)

#### Logging System (`Logging.h/.cpp`, `LogPartitions.def`)
- **Logging** class with partition-based log levels
- Log partitions (Fs, Bucket, History, Overlay, etc.)
- Log rotation and file output
- spdlog integration with color and formatting options
- `CLOG_*` macros for partition-aware logging

#### Math and Numeric Utilities (`Math.h/.cpp`, `numeric.h/.cpp`)
- `bigDivideOrThrow()` - 128-bit division with rounding
- `bigDivide()` - non-throwing version
- `bigSquareRoot()` - square root with 128-bit precision
- `saturatingMultiply()` - overflow-safe multiplication
- `saturatingAdd()` - overflow-safe addition
- `isRepresentableAsInt64()` - double-to-int64 conversion check
- `doubleToClampedUint32()` - clamped conversion
- `rand_fraction()`, `rand_flip()`, `rand_uniform()`, `rand_element()` - random utilities
- `k_means()`, `closest_cluster()` - clustering utilities
- `exponentialBackoff()` - backoff calculation

#### Filesystem Utilities (`Fs.h/.cpp`)
- `lockFile()` / `unlockFile()` - file locking
- `flushFileChanges()` - fsync wrapper
- `durableRename()` - atomic rename with fsync
- `exists()`, `deltree()`, `mkdir()`, `mkpath()` - file operations
- `findfiles()` - directory listing with predicate
- Path construction utilities (`hexStr`, `hexDir`, `baseName`, `remoteName`)
- Handle counting and limits

#### XDR Stream I/O (`XDRStream.h`, `XDRCereal.h/.cpp`)
- **XDRInputFileStream** - streaming XDR file reader
- **XDROutputFileStream** - streaming XDR file writer with durability options
- Incremental hashing during read/write
- Page-based reading with key search
- XDR to JSON serialization (`xdrToCerealString`)

#### Data Structures
- **RandomEvictionCache** (`RandomEvictionCache.h`) - LRU-2-random cache
- **BitSet** (`BitSet.h`) - Efficient bitset with set operations
- **TarjanSCCCalculator** (`TarjanSCCCalculator.h/.cpp`) - Strongly connected components

#### Type Utilities (`types.h/.cpp`)
- `LedgerKeySet` typedef
- `Hash` XOR operators (`operator^=`, `lessThanXored`)
- `isStringValid()` - ASCII printable validation
- `isAssetValid()` - asset validation with protocol version awareness
- `compareAsset()` - asset comparison
- `unsignedToSigned()` - checked conversions
- `formatSize()` - human-readable byte sizes
- `addBalance()` - safe balance arithmetic
- `iequals()` - case-insensitive string comparison
- `Price` comparison operators
- Asset code conversion utilities (`assetCodeToStr`, `strToAssetCode`, `assetToString`)
- `getIssuer()`, `isIssuer()` template functions
- `getBucketLedgerKey()` for bucket entries
- `roundDown()` template function

#### Resource Extensions (`TxResource.h/.cpp`)
- `multiplyByDouble()` - resource scaling
- `saturatedMultiplyByDouble()` - overflow-safe scaling
- `bigDivideOrThrow()` for resources
- `Resource::toString()` method
- `Resource::getStringFromType()` static method

#### Other Utilities
- **SecretValue** (`SecretValue.h/.cpp`) - wrapper for sensitive strings
- **StatusManager** (`StatusManager.h/.cpp`) - status tracking
- **GlobalChecks** (`GlobalChecks.h/.cpp`) - assertion macros (`releaseAssert`, `releaseAssertOrThrow`, `dbgAssert`)
- **NonCopyable** (`NonCopyable.h`) - CRTP base for non-copyable types
- **Backtrace** (`Backtrace.h/.cpp`) - stack trace utilities
- **Thread** (`Thread.h/.cpp`) - thread utilities
- **JitterInjection** (`JitterInjection.h/.cpp`) - timing jitter for testing
- **LogSlowExecution** (`LogSlowExecution.h/.cpp`) - performance logging
- **DebugMetaUtils** (`DebugMetaUtils.h/.cpp`) - debug metadata utilities
- **BinaryFuseFilter** (`BinaryFuseFilter.h/.cpp`) - probabilistic filter
- **RandHasher** (`RandHasher.h/.cpp`) - randomized hasher
- **MetricResetter** (`MetricResetter.h/.cpp`) - metric management

### Implementation Notes

#### Architectural Decisions

1. **Rust Idioms Over C++ Patterns**: The Rust implementation uses idiomatic Rust patterns rather than direct C++ translations:
   - `Resource` uses `Vec<i64>` instead of `std::vector<int64_t>`
   - Error handling uses `Result<T, E>` instead of exceptions
   - `Hash256` is a newtype wrapper rather than a typedef

2. **No Runtime/IO Dependencies**: This crate deliberately avoids runtime-dependent code:
   - No VirtualClock (would require async runtime)
   - No Logging system (deferred to the `tracing` ecosystem)
   - No filesystem utilities (standard library is sufficient for Rust)

3. **XDR Integration**: Uses the `stellar-xdr` crate for XDR types instead of xdrpp, with conversion traits implemented for interoperability.

4. **Metadata Normalization**: The Rust implementation matches C++ sorting behavior exactly (by key bytes, then change type, then full hash) to ensure cross-implementation compatibility.

5. **Protocol Version**: Uses an enum with explicit discriminants matching C++ values, with inline helper functions for version checks.

6. **Configuration**: Uses `serde` with TOML for configuration instead of C++ custom parsing, providing a more ergonomic API.

#### Notable Differences

| Aspect | C++ | Rust |
|--------|-----|------|
| Error handling | Exceptions + assertions | `Result<T, E>` + panics for invariants |
| Hashing | `sha256()` free function | `Hash256::hash()` method |
| Time | VirtualClock abstraction | Direct `std::time` usage |
| Logging | Custom partition system | Defer to `tracing` crate |
| Config | Custom text parsing | `serde` + `toml` crate |
| Resource arithmetic | Friend functions | Trait implementations |
| Assertions | `releaseAssert` macros | `assert!` / `panic!` |

#### Future Work Priority

Features likely needed for full parity (in rough priority order):

1. **Math utilities** (`bigDivide`, `saturatingMultiply`) - needed for transaction processing
2. **Type utilities** (`isAssetValid`, `addBalance`) - needed for ledger operations
3. **XDR streaming** - needed for history archive access
4. **RandomEvictionCache** - needed for performance optimization
5. **VirtualClock/Scheduler** - needed for testing infrastructure

## License

Apache 2.0
