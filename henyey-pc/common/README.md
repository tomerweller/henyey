# common

Shared types and utilities used throughout rs-stellar-core. This crate provides fundamental types (Hash256), configuration loading, error definitions, 128-bit arithmetic, ledger metadata normalization, network identity, protocol version gating, resource accounting, timestamp conversions, and XDR stream I/O.

## Key Files

- [types.pc.md](types.pc.md) -- Fundamental Hash256 type with SHA-256 hashing and XDR serialization
- [config.pc.md](config.pc.md) -- Configuration types for node setup loaded from TOML
- [protocol.pc.md](protocol.pc.md) -- Protocol version constants and feature gating (v24+ only)
- [math.pc.md](math.pc.md) -- 128-bit arithmetic and overflow-safe math operations
- [meta.pc.md](meta.pc.md) -- Ledger metadata normalization for deterministic hashing
- [xdr_stream.pc.md](xdr_stream.pc.md) -- XDR size-prefixed binary frame I/O matching stellar-core format

## Architecture

The crate is organized as a flat collection of focused utility modules re-exported through `lib`. `types` defines `Hash256`, the foundational hash type used everywhere. `config` provides TOML-based node configuration, while `protocol` gates feature availability by version number. `math` supplies overflow-safe 128-bit arithmetic for fee and balance calculations. `meta` normalizes ledger metadata ordering for deterministic hashing across validators. `network` derives network identity from passphrases, `resource` tracks multi-dimensional transaction resource usage for surge pricing, `time` converts between Unix and Stellar timestamps, `asset` handles asset validation and conversions, and `xdr_stream` provides record-marked XDR binary I/O compatible with stellar-core.

## All Files

| File | Description |
|------|-------------|
| [asset.pc.md](asset.pc.md) | Asset validation, conversion, balance, and price comparison utilities |
| [config.pc.md](config.pc.md) | Configuration types for node setup loaded from TOML |
| [error.pc.md](error.pc.md) | Common error types: Xdr, Io, Config, InvalidData, NotFound |
| [lib.pc.md](lib.pc.md) | Crate root with module declarations and re-exports |
| [math.pc.md](math.pc.md) | 128-bit arithmetic and overflow-safe math with rounding modes |
| [meta.pc.md](meta.pc.md) | Ledger metadata normalization for deterministic cross-validator hashing |
| [network.pc.md](network.pc.md) | Network identity derived from SHA-256 of network passphrase |
| [protocol.pc.md](protocol.pc.md) | Protocol version constants and feature gating (v24+ only) |
| [resource.pc.md](resource.pc.md) | Multi-dimensional resource accounting for surge pricing and tx limits |
| [time.pc.md](time.pc.md) | Unix/Stellar timestamp conversions with epoch offset handling |
| [types.pc.md](types.pc.md) | Hash256 type with SHA-256 hashing, XDR serialization, and comparison |
| [xdr_stream.pc.md](xdr_stream.pc.md) | XDR size-prefixed binary frame I/O matching RFC 1832/4506 format |
