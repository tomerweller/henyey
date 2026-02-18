# Pseudocode: crates/common/src/config.rs

"Configuration types for stellar-core nodes, loaded from TOML."

## Types

```
ENUM LogLevel: Trace | Debug | Info (default) | Warn | Error
ENUM LogFormat: Text (default) | Json

STRUCT ThresholdPercent:
  value : u32   // clamped to 0..100, default 67

STRUCT Config:
  network         : NetworkConfig
  database        : DatabaseConfig
  node            : NodeConfig
  history         : HistoryConfig
  logging         : LoggingConfig
  bucket_list_db  : BucketListDbConfig

STRUCT NetworkConfig:
  passphrase              : string
  peer_port               : u16       // default 11625
  http_port               : u16       // default 11626
  known_peers             : list<string>
  preferred_peers         : list<string>
  max_peer_connections    : uint      // default 25
  target_peer_connections : uint      // default 8

STRUCT DatabaseConfig:
  path : file_path                    // SQLite only

STRUCT NodeConfig:
  is_validator : bool                 // default false
  node_seed    : optional<string>     // Stellar secret seed, required for validators
  quorum_set   : QuorumSetConfig

STRUCT QuorumSetConfig:
  threshold_percent : ThresholdPercent // default 67
  validators        : list<string>    // public keys (start with 'G')
  inner_sets        : list<QuorumSetConfig>

STRUCT HistoryConfig:
  get_commands : list<HistoryArchiveConfig>
  put_commands : list<HistoryArchiveConfig>

STRUCT HistoryArchiveConfig:
  name  : string
  get   : string         // command template with {0}=remote, {1}=local
  put   : optional<string>
  mkdir : optional<string>

STRUCT BucketListDbConfig:
  index_page_size_exponent : u32    // default 14 (16 KB pages)
  index_cutoff_mb          : uint   // default 20 MB
  memory_for_caching_mb    : uint   // default 1024; 0 = disabled
  persist_index            : bool   // default true

STRUCT LoggingConfig:
  level  : LogLevel
  format : LogFormat
```

### ThresholdPercent.new

```
function ThresholdPercent.new(value) -> ThresholdPercent:
  -> ThresholdPercent(min(value, 100))
```

### ThresholdPercent deserialize

```
function ThresholdPercent.deserialize(value):
  GUARD value > 100  -> error("must be between 0 and 100")
  -> ThresholdPercent(value)
```

### BucketListDbConfig.page_size_bytes

```
function page_size_bytes(self) -> u64:
  -> 1 << self.index_page_size_exponent
```

### BucketListDbConfig.index_cutoff_bytes

```
function index_cutoff_bytes(self) -> u64:
  -> self.index_cutoff_mb * 1024 * 1024
```

### Config.from_file

```
function Config.from_file(path) -> Config:
  content = read_file(path)
  -> parse_toml(content)
```

### Config.testnet

"Default configuration for the Stellar public testnet."

```
function Config.testnet() -> Config:
  -> Config {
    network: {
      passphrase: "Test SDF Network ; September 2015"
      peer_port: 11625
      http_port: 11626
      known_peers: [
        "core-testnet1.stellar.org:11625"
        "core-testnet2.stellar.org:11625"
        "core-testnet3.stellar.org:11625"
      ]
      preferred_peers: []
      max_peer_connections: 25
      target_peer_connections: 8
    }
    database: { path: "stellar.db" }
    node: { is_validator: false, no seed, default quorum }
    history: {
      get_commands: [ sdf1 archive via curl ]
      put_commands: []
    }
    logging: defaults
    bucket_list_db: defaults
  }
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 130    | 86         |
| Functions     | 6      | 6          |
