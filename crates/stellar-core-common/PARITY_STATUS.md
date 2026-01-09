# C++ Parity Status

This document details the parity between `stellar-core-common` and the C++ upstream utilities found in `.upstream-v25/src/util/` and related modules.

## Summary

| Category | Status | Notes |
|----------|--------|-------|
| Protocol Version | Full | All version checks and constants match C++ |
| Resource Accounting | Partial | Core ops implemented; scaling/division missing |
| Metadata Normalization | Full | Matches C++ sorting behavior exactly |
| Hash/Types | Partial | Core Hash256 done; many type utilities missing |
| Network Identity | Full | Passphrase-based derivation matches C++ |
| Time Utilities | Partial | Basic conversions done; VirtualClock not implemented |
| Configuration | Rust-native | Uses TOML/serde instead of C++ custom parsing |
| Error Handling | Rust-native | Uses Result/Error instead of exceptions |

## Implemented Features

### Protocol Version Utilities (`protocol.rs` <-> `ProtocolVersion.h/.cpp`)

**Status: Full Parity**

| C++ Function | Rust Equivalent | Notes |
|--------------|-----------------|-------|
| `ProtocolVersion` enum (V_0 to V_25) | `ProtocolVersion` enum (V0 to V25) | Identical values |
| `protocolVersionIsBefore()` | `protocol_version_is_before()` | Identical behavior |
| `protocolVersionStartsFrom()` | `protocol_version_starts_from()` | Identical behavior |
| `protocolVersionEquals()` | `protocol_version_equals()` | Identical behavior |
| `SOROBAN_PROTOCOL_VERSION` | `SOROBAN_PROTOCOL_VERSION` | V20 |
| `PARALLEL_SOROBAN_PHASE_PROTOCOL_VERSION` | `PARALLEL_SOROBAN_PHASE_PROTOCOL_VERSION` | V23 |
| `AUTO_RESTORE_PROTOCOL_VERSION` | `AUTO_RESTORE_PROTOCOL_VERSION` | V23 |
| `REUSABLE_SOROBAN_MODULE_CACHE_PROTOCOL_VERSION` | `REUSABLE_SOROBAN_MODULE_CACHE_PROTOCOL_VERSION` | V23 |

Additional Rust utilities:
- `needs_upgrade_to_version()` - detects protocol upgrade boundary crossing
- `soroban_supported()` - convenience check for Soroban support (V20+)
- `CURRENT_LEDGER_PROTOCOL_VERSION` (25) and `MIN_SOROBAN_PROTOCOL_VERSION` (20)

### Resource Accounting (`resource.rs` <-> `TxResource.h/.cpp`)

**Status: Partial Parity**

| C++ Feature | Rust Equivalent | Status |
|-------------|-----------------|--------|
| `Resource` class | `Resource` struct | Implemented |
| `Resource::Type` enum | `ResourceType` enum | Implemented |
| `NUM_CLASSIC_TX_RESOURCES` (1) | `NUM_CLASSIC_TX_RESOURCES` | Implemented |
| `NUM_CLASSIC_TX_BYTES_RESOURCES` (2) | `NUM_CLASSIC_TX_BYTES_RESOURCES` | Implemented |
| `NUM_SOROBAN_TX_RESOURCES` (7) | `NUM_SOROBAN_TX_RESOURCES` | Implemented |
| `isZero()` | `is_zero()` | Implemented |
| `anyPositive()` | `any_positive()` | Implemented |
| `size()` | `size()` | Implemented |
| `getVal()` | `get_val()` / `try_get_val()` | Implemented |
| `setVal()` | `set_val()` / `try_set_val()` | Implemented |
| `makeEmpty()` | `make_empty()` | Implemented |
| `makeEmptySoroban()` | `make_empty_soroban()` | Implemented |
| `canAdd()` | `can_add()` | Implemented |
| `operator+=` | `AddAssign` trait | Implemented |
| `operator-=` | `SubAssign` trait | Implemented |
| `operator+` | `Add` trait | Implemented |
| `operator-` | `Sub` trait | Implemented |
| `operator<=` | `leq()` method | Implemented |
| `operator==` | `PartialEq` trait | Implemented |
| `anyLessThan()` | `any_less_than()` | Implemented |
| `anyGreater()` | `any_greater()` | Implemented |
| `subtractNonNegative()` | `subtract_non_negative()` | Implemented |
| `limitTo()` | `limit_to()` | Implemented |
| `toString()` | Not implemented | Missing |
| `getStringFromType()` | Not implemented | Missing |
| `multiplyByDouble()` | Not implemented | Missing |
| `saturatedMultiplyByDouble()` | Not implemented | Missing |
| `bigDivideOrThrow()` for Resource | Not implemented | Missing |

### Metadata Normalization (`meta.rs` <-> `MetaUtils.h/.cpp`)

**Status: Full Parity**

| C++ Feature | Rust Equivalent | Notes |
|-------------|-----------------|-------|
| `normalizeMeta(TransactionMeta&)` | `normalize_transaction_meta()` | Identical sorting |
| `normalizeMeta(LedgerCloseMeta&)` | `normalize_ledger_close_meta()` | Identical sorting |
| `CmpLedgerEntryChanges` comparator | `sort_changes()` with tuple sorting | Same order |
| Change type remapping (State=0, Created=1, Updated=2, Removed=3, Restored=4) | `change_type_order()` | Identical |
| Sort by (key, type, hash) | Sort by (key_bytes, order, change_hash) | Identical |
| Support for TransactionMeta V0-V4 | V0-V4 support | Full coverage |
| Support for LedgerCloseMeta V0-V2 | V0-V2 support | Full coverage |

### Core Types (`types.rs` <-> `types.h/.cpp`)

**Status: Partial Parity**

| C++ Feature | Rust Equivalent | Status |
|-------------|-----------------|--------|
| `Hash` type (xdr::opaque_array<32>) | `Hash256` | Implemented |
| `isZero(uint256 const&)` | `Hash256::is_zero()` | Implemented |
| `LedgerEntryKey()` | `ledger_entry_key()` in meta.rs | Implemented |
| `operator^=` for Hash | Not implemented | Missing |
| `lessThanXored()` | Not implemented | Missing |
| `isStringValid()` | Not implemented | Missing |
| `isAssetValid()` | Not implemented | Missing |
| `compareAsset()` | Not implemented | Missing |
| `unsignedToSigned()` | Not implemented | Missing |
| `formatSize()` | Not implemented | Missing |
| `addBalance()` | Not implemented | Missing |
| `iequals()` | Not implemented | Missing |
| `Price` comparison operators | Not implemented | Missing |
| `assetCodeToStr()` / `strToAssetCode()` | Not implemented | Missing |
| `assetToString()` | Not implemented | Missing |
| `getIssuer()` / `isIssuer()` | Not implemented | Missing |
| `getBucketLedgerKey()` | Not implemented | Missing |
| `roundDown()` | Not implemented | Missing |
| `LedgerKeySet` typedef | Not implemented | Missing |
| ASCII utilities (`isAsciiAlphaNumeric`, etc.) | Not implemented | Missing |

### Network Identity (`network.rs`)

**Status: Full Parity**

| C++ Equivalent | Rust Feature | Notes |
|----------------|--------------|-------|
| Network passphrase hashing | `NetworkId::from_passphrase()` | Uses SHA-256 |
| Testnet passphrase | `NetworkId::testnet()` | Identical |
| Mainnet passphrase | `NetworkId::mainnet()` | Identical |
| Conversion to Hash | `Into<stellar_xdr::curr::Hash>` | Implemented |

### Time Utilities (`time.rs`)

**Status: Partial Parity**

| C++ Feature | Rust Equivalent | Status |
|-------------|-----------------|--------|
| Current timestamp | `current_timestamp()` / `current_timestamp_ms()` | Implemented |
| Stellar epoch constant | `STELLAR_EPOCH` (946684800) | Implemented |
| Unix/Stellar time conversion | `unix_to_stellar_time()` / `stellar_to_unix_time()` | Implemented |
| `timestamp_to_system_time()` | `timestamp_to_system_time()` | Implemented |

### Configuration (`config.rs`)

**Status: Rust-Native Implementation**

The Rust implementation uses `serde` with TOML for configuration parsing instead of C++ custom parsing. This provides:
- `Config` struct with network, database, node, history, and logging sections
- `NetworkConfig` for peer settings
- `DatabaseConfig` for SQLite path
- `NodeConfig` for validator settings and quorum configuration
- `QuorumSetConfig` for SCP configuration
- `HistoryConfig` for archive commands
- `LoggingConfig` for log level and format
- `Config::from_file()` for TOML loading
- `Config::testnet()` preset

### Error Handling (`error.rs`)

**Status: Rust-Native Implementation**

Uses Rust's `Result<T, E>` pattern instead of C++ exceptions:
- `Error` enum with variants: Xdr, Io, Config, InvalidData, NotFound, OperationFailed
- `Result<T>` type alias for `Result<T, Error>`
- Automatic conversion from `stellar_xdr::curr::Error` and `std::io::Error`

## Not Implemented (Gaps)

### Virtual Clock and Timer System (`Timer.h/.cpp`, `Scheduler.h/.cpp`)

**Priority: Medium (needed for testing infrastructure)**

- `VirtualClock` class - Virtual time management for simulation and testing
- `VirtualTimer` class - Timer that works with virtual or real time
- `Scheduler` class - Fair time-slicing scheduler for action queues
- Time mode switching (REAL_TIME vs VIRTUAL_TIME)
- System/wall clock conversions (`systemPointToTm`, `tmToISOString`, etc.)
- Duration and time_point types

### Logging System (`Logging.h/.cpp`, `LogPartitions.def`)

**Priority: Low (deferred to `tracing` ecosystem)**

- `Logging` class with partition-based log levels
- Log partitions (Fs, Bucket, History, Overlay, Herder, etc.)
- `CLOG_*` macros for partition-aware logging
- Log rotation and file output
- spdlog integration

**Design Decision**: Rust implementation defers to the `tracing` crate ecosystem for logging.

### Math and Numeric Utilities (`Math.h/.cpp`, `numeric.h/.cpp`)

**Priority: High (needed for transaction processing)**

- `bigDivideOrThrow()` - 128-bit division with rounding (ROUND_DOWN, ROUND_UP)
- `bigDivide()` - non-throwing version returning success/failure
- `bigDivideUnsigned()` - unsigned variant
- `bigSquareRoot()` - square root with 128-bit precision
- `saturatingMultiply()` - overflow-safe multiplication
- `saturatingAdd()` - overflow-safe addition
- `isRepresentableAsInt64()` - double-to-int64 conversion check
- `doubleToClampedUint32()` - clamped conversion
- `Rounding` enum (ROUND_DOWN, ROUND_UP)
- Random utilities: `rand_fraction()`, `rand_flip()`, `rand_uniform()`, `rand_element()`
- Clustering: `k_means()`, `closest_cluster()`
- `exponentialBackoff()` - backoff calculation

### Filesystem Utilities (`Fs.h/.cpp`)

**Priority: Low (standard library sufficient)**

- `lockFile()` / `unlockFile()` - file locking
- `flushFileChanges()` - fsync wrapper
- `durableRename()` - atomic rename with fsync
- `exists()`, `deltree()`, `mkdir()`, `mkpath()` - file operations
- `findfiles()` - directory listing with predicate
- Path construction: `hexStr()`, `hexDir()`, `baseName()`, `remoteDir()`, `remoteName()`
- Handle counting: `getMaxHandles()`, `getOpenHandleCount()`

### XDR Stream I/O (`XDRStream.h`, `XDRCereal.h/.cpp`)

**Priority: Medium (needed for history archive access)**

- `XDRInputFileStream` - streaming XDR file reader with incremental hashing
- `XDROutputFileStream` - streaming XDR file writer with durability options
- Page-based reading with key search
- XDR to JSON serialization (`xdrToCerealString`)

### Data Structures

**Priority: Medium**

- `RandomEvictionCache` (`RandomEvictionCache.h`) - LRU-2-random cache for performance
- `BitSet` (`BitSet.h`) - Efficient bitset with set operations
- `TarjanSCCCalculator` (`TarjanSCCCalculator.h/.cpp`) - Strongly connected components

### Other Utilities

**Priority: Low**

- `SecretValue` (`SecretValue.h/.cpp`) - wrapper for sensitive strings
- `StatusManager` (`StatusManager.h/.cpp`) - status tracking
- `GlobalChecks` (`GlobalChecks.h/.cpp`) - assertion macros (`releaseAssert`, etc.)
- `NonCopyable` (`NonCopyable.h`) - CRTP base for non-copyable types
- `Backtrace` (`Backtrace.h/.cpp`) - stack trace utilities
- `Thread` (`Thread.h/.cpp`) - thread utilities
- `JitterInjection` (`JitterInjection.h/.cpp`) - timing jitter for testing
- `LogSlowExecution` (`LogSlowExecution.h/.cpp`) - performance logging
- `DebugMetaUtils` (`DebugMetaUtils.h/.cpp`) - debug metadata utilities
- `BinaryFuseFilter` (`BinaryFuseFilter.h/.cpp`) - probabilistic filter
- `RandHasher` (`RandHasher.h/.cpp`) - randomized hasher
- `MetricResetter` (`MetricResetter.h/.cpp`) - metric management
- `HashOfHash` (`HashOfHash.h/.cpp`) - hash utilities

## Architectural Decisions

### Design Philosophy

1. **Rust Idioms Over C++ Patterns**: The implementation uses idiomatic Rust rather than direct C++ translations:
   - `Resource` uses `Vec<i64>` instead of `std::vector<int64_t>`
   - Error handling uses `Result<T, E>` instead of exceptions
   - `Hash256` is a newtype wrapper with methods rather than a typedef

2. **No Runtime/IO Dependencies**: This crate deliberately avoids runtime-dependent code:
   - No VirtualClock (would require async runtime integration)
   - No custom logging system (defers to `tracing` ecosystem)
   - No filesystem utilities (standard library is sufficient for Rust)

3. **XDR Integration**: Uses the `stellar-xdr` crate for XDR types with conversion traits.

4. **Deterministic Behavior**: Metadata normalization matches C++ sorting exactly (by key bytes, then change type, then full hash).

### Notable Differences

| Aspect | C++ | Rust |
|--------|-----|------|
| Error handling | Exceptions + assertions | `Result<T, E>` + panics for invariants |
| Hashing | `sha256()` free function | `Hash256::hash()` method |
| Time | VirtualClock abstraction | Direct `std::time` usage |
| Logging | Custom partition system (spdlog) | Defer to `tracing` crate |
| Config | Custom text parsing | `serde` + `toml` crate |
| Resource arithmetic | Friend functions | Trait implementations |
| Assertions | `releaseAssert` macros | `assert!` / `panic!` |
| Random | Global engine with seed control | Standard library (or `rand` crate) |

## Future Work Priority

Features likely needed for full parity (in rough priority order):

1. **Math utilities** (`bigDivide`, `saturatingMultiply`) - Critical for transaction processing
2. **Type utilities** (`isAssetValid`, `addBalance`, asset conversions) - Needed for ledger operations
3. **Resource scaling** (`multiplyByDouble`, `bigDivideOrThrow` for Resource) - Needed for surge pricing
4. **XDR streaming** - Needed for history archive access
5. **RandomEvictionCache** - Needed for performance optimization
6. **VirtualClock/Scheduler** - Needed for testing infrastructure

## Verification

To verify parity:
1. Run `cargo test -p stellar-core-common` for unit tests
2. Compare behavior against C++ test vectors when available
3. Cross-reference sorting behavior in metadata normalization tests
