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
