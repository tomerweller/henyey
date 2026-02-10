# stellar-core Parity Status

**Overall Parity: ~92%**

This document details the parity between `henyey-common` and stellar-core utilities found in `.upstream-v25/src/util/` and related modules.

## Summary

| Category | Status | Notes |
|----------|--------|-------|
| Protocol Version | Full | All version checks and constants match stellar-core |
| Resource Accounting | Full | All operations including scaling/division |
| Metadata Normalization | Full | Matches stellar-core sorting behavior exactly |
| Hash/Types | Full | Hash256, asset validation, balance utilities |
| Network Identity | Full | Passphrase-based derivation matches stellar-core |
| Time Utilities | Partial | Basic conversions done; VirtualClock not implemented |
| Math Utilities | Full | bigDivide, saturating ops, sqrt implemented |
| Configuration | Rust-native | Uses TOML/serde instead of stellar-core custom parsing |
| Error Handling | Rust-native | Uses Result/Error instead of exceptions |

## Implemented Features

### Protocol Version Utilities (`protocol.rs` <-> `ProtocolVersion.h/.cpp`)

**Status: Full Parity**

| stellar-core Function | Rust Equivalent | Notes |
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

**Status: Full Parity**

| stellar-core Feature | Rust Equivalent | Status |
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
| `toString()` | `Display` impl | Implemented |
| `getStringFromType()` | `ResourceType::as_str()` | Implemented |
| `multiplyByDouble()` | `multiply_by_double()` | Implemented |
| `saturatedMultiplyByDouble()` | `saturated_multiply_by_double()` | Implemented |
| `bigDivideOrThrow()` for Resource | `big_divide_resource()` | Implemented |

Additional Rust utilities:
- `ResourceType::all()` - Returns slice of all resource type variants
- `ResourceType::as_str()` - Returns display string for type

### Metadata Normalization (`meta.rs` <-> `MetaUtils.h/.cpp`)

**Status: Full Parity**

| stellar-core Feature | Rust Equivalent | Notes |
|-------------|-----------------|-------|
| `normalizeMeta(TransactionMeta&)` | `normalize_transaction_meta()` | Identical sorting |
| `normalizeMeta(LedgerCloseMeta&)` | `normalize_ledger_close_meta()` | Identical sorting |
| `CmpLedgerEntryChanges` comparator | `sort_changes()` with tuple sorting | Same order |
| Change type remapping (State=0, Created=1, Updated=2, Removed=3, Restored=4) | `change_type_order()` | Identical |
| Sort by (key, type, hash) | Sort by (key_bytes, order, change_hash) | Identical |
| Support for TransactionMeta V0-V4 | V0-V4 support | Full coverage |
| Support for LedgerCloseMeta V0-V2 | V0-V2 support | Full coverage |

### Core Types (`types.rs`, `asset.rs` <-> `types.h/.cpp`)

**Status: Full Parity**

| stellar-core Feature | Rust Equivalent | Status |
|-------------|-----------------|--------|
| `Hash` type (xdr::opaque_array<32>) | `Hash256` | Implemented |
| `isZero(uint256 const&)` | `Hash256::is_zero()` | Implemented |
| `LedgerEntryKey()` | `ledger_entry_key()` | Implemented |
| `operator^=` for Hash | `BitXorAssign` for Hash256 | Implemented |
| `lessThanXored()` | `less_than_xored()` | Implemented |
| `isStringValid()` | `is_string_valid()` | Implemented |
| `isAssetValid()` | `is_asset_valid()` | Implemented |
| `compareAsset()` | `compare_asset()` | Implemented |
| `unsignedToSigned()` | `unsigned_to_signed_32/64()` | Implemented |
| `formatSize()` | `format_size()` | Implemented |
| `addBalance()` | `add_balance()` | Implemented |
| `iequals()` | `iequals()` | Implemented |
| `Price` comparison operators | `price_ge()`, `price_gt()`, `price_eq()` | Implemented |
| `assetCodeToStr()` / `strToAssetCode()` | `asset_code_to_str()` / `str_to_asset_code()` | Implemented |
| `assetToString()` | `asset_to_string()` | Implemented |
| `getIssuer()` / `isIssuer()` | `get_issuer()` / `is_issuer()` | Implemented |
| `getBucketLedgerKey()` | `get_bucket_ledger_key()`, `get_hot_archive_bucket_ledger_key()` | Implemented |
| `roundDown()` | `round_down()` | Implemented |
| `LedgerKeySet` typedef | Use `std::collections::BTreeSet<LedgerKey>` | Rust idiom |
| `isAsciiAlphaNumeric()` | `is_ascii_alphanumeric()` | Implemented |
| `isAsciiNonControl()` | `is_ascii_non_control()` | Implemented |
| `toAsciiLower()` | `to_ascii_lower()` | Implemented |
| `isPoolShareAssetValid()` | Part of `is_change_trust_asset_valid()` | Implemented |
| `isTrustLineAssetValid()` | `is_trustline_asset_valid()` | Implemented |
| `isChangeTrustAssetValid()` | `is_change_trust_asset_valid()` | Implemented |

### Network Identity (`network.rs`)

**Status: Full Parity**

| stellar-core Equivalent | Rust Feature | Notes |
|----------------|--------------|-------|
| Network passphrase hashing | `NetworkId::from_passphrase()` | Uses SHA-256 |
| Testnet passphrase | `NetworkId::testnet()` | Identical |
| Mainnet passphrase | `NetworkId::mainnet()` | Identical |
| Conversion to Hash | `Into<stellar_xdr::curr::Hash>` | Implemented |

### Time Utilities (`time.rs`)

**Status: Partial Parity**

| stellar-core Feature | Rust Equivalent | Status |
|-------------|-----------------|--------|
| Current timestamp | `current_timestamp()` / `current_timestamp_ms()` | Implemented |
| Stellar epoch constant | `STELLAR_EPOCH` (946684800) | Implemented |
| Unix/Stellar time conversion | `unix_to_stellar_time()` / `stellar_to_unix_time()` | Implemented |
| `timestamp_to_system_time()` | `timestamp_to_system_time()` | Implemented |

### Configuration (`config.rs`)

**Status: Rust-Native Implementation**

The Rust implementation uses `serde` with TOML for configuration parsing instead of stellar-core custom parsing. This provides:
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

Uses Rust's `Result<T, E>` pattern instead of stellar-core exceptions:
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

**Status: Mostly Implemented** (in `math.rs`)

| stellar-core Feature | Rust Equivalent | Status |
|-------------|-----------------|--------|
| `bigDivideOrThrow()` | `big_divide_or_throw()` | Implemented |
| `bigDivide()` | `big_divide()` | Implemented |
| `bigDivideUnsigned()` | `big_divide_unsigned()` | Implemented |
| `bigSquareRoot()` | `big_square_root()` | Implemented |
| `saturatingMultiply()` | `saturating_multiply()` | Implemented |
| `saturatingAdd()` | `saturating_add()` | Implemented |
| `isRepresentableAsInt64()` | `is_representable_as_i64()` | Implemented |
| `doubleToClampedUint32()` | `double_to_clamped_u32()` | Implemented |
| `Rounding` enum | `Rounding` enum | Implemented |
| `bigMultiply()` | `big_multiply()` / `big_multiply_unsigned()` | Implemented |
| `bigDivide128()` | `big_divide_128()` / `big_divide_unsigned_128()` | Implemented |
| Random utilities | Not implemented | Not needed (use `rand` crate) |
| Clustering (`k_means`) | Not implemented | Low priority |
| `exponentialBackoff()` | Not implemented | Low priority |

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

1. **Rust Idioms Over stellar-core Patterns**: The implementation uses idiomatic Rust rather than direct stellar-core translations:
   - `Resource` uses `Vec<i64>` instead of `std::vector<int64_t>`
   - Error handling uses `Result<T, E>` instead of exceptions
   - `Hash256` is a newtype wrapper with methods rather than a typedef

2. **No Runtime/IO Dependencies**: This crate deliberately avoids runtime-dependent code:
   - No VirtualClock (would require async runtime integration)
   - No custom logging system (defers to `tracing` ecosystem)
   - No filesystem utilities (standard library is sufficient for Rust)

3. **XDR Integration**: Uses the `stellar-xdr` crate for XDR types with conversion traits.

4. **Deterministic Behavior**: Metadata normalization matches stellar-core sorting exactly (by key bytes, then change type, then full hash).

### Notable Differences

| Aspect | stellar-core | Rust |
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

1. **XDR streaming** - Needed for history archive access
2. **RandomEvictionCache** - Needed for performance optimization
3. **VirtualClock/Scheduler** - Needed for testing infrastructure

## Verification

To verify parity:
1. Run `cargo test -p henyey-common` for unit tests
2. Compare behavior against stellar-core test vectors when available
3. Cross-reference sorting behavior in metadata normalization tests
