# Pseudocode: crates/common/src/protocol.rs

"Protocol version utilities and feature gating."

## Constants

```
ENUM ProtocolVersion: V0..V25  // discriminant = version number

CONST SOROBAN_PROTOCOL_VERSION                      = V20  // Soroban smart contracts introduced
CONST PARALLEL_SOROBAN_PHASE_PROTOCOL_VERSION       = V23  // Parallel Soroban execution
CONST AUTO_RESTORE_PROTOCOL_VERSION                 = V23  // Automatic TTL restoration
CONST REUSABLE_SOROBAN_MODULE_CACHE_PROTOCOL_VERSION = V23 // Reusable WASM module cache

CONST MIN_LEDGER_PROTOCOL_VERSION     = 24  // only protocol 24+ supported
CONST CURRENT_LEDGER_PROTOCOL_VERSION = 25  // highest supported version
CONST MIN_SOROBAN_PROTOCOL_VERSION    = 20  // minimum for Soroban execution
```

### protocol_version_is_before

```
function protocol_version_is_before(version, target) -> bool:
  -> version < target
```

### protocol_version_starts_from

```
function protocol_version_starts_from(version, target) -> bool:
  -> version >= target
```

### protocol_version_equals

```
function protocol_version_equals(version, target) -> bool:
  -> version == target
```

### needs_upgrade_to_version

"Detect when a protocol upgrade just crossed a boundary."

```
function needs_upgrade_to_version(target, prev_version, new_version) -> bool:
  -> prev_version < target AND new_version >= target
```

**Calls**: [protocol_version_is_before](#protocol_version_is_before) | [protocol_version_starts_from](#protocol_version_starts_from)

### soroban_supported

```
function soroban_supported(protocol_version) -> bool:
  -> protocol_version >= SOROBAN_PROTOCOL_VERSION
```

**Calls**: [protocol_version_starts_from](#protocol_version_starts_from)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 36     | 22         |
| Functions     | 5      | 5          |
