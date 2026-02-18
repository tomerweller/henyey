# Pseudocode: crates/common/src/network.rs

"Network identity derived from network passphrases."

## Data

```
STRUCT NetworkId:
  hash : Hash256
```

### from_passphrase

```
function from_passphrase(passphrase) -> NetworkId:
  hash = SHA256(passphrase as bytes)
  -> NetworkId(hash)
```

**Calls**: [Hash256.hash](types.pc.md#hash)

### as_bytes

```
function as_bytes(self) -> byte[32]:
  -> self.hash.bytes
```

### testnet

```
function testnet() -> NetworkId:
  -> from_passphrase("Test SDF Network ; September 2015")
```

**Calls**: [from_passphrase](#from_passphrase)

### mainnet

```
function mainnet() -> NetworkId:
  -> from_passphrase("Public Global Stellar Network ; September 2015")
```

**Calls**: [from_passphrase](#from_passphrase)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 16     | 12         |
| Functions     | 4      | 4          |
