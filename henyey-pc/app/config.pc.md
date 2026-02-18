## Pseudocode: crates/app/src/config.rs

### Constants (defaults)

```
CONST DEFAULT_NODE_NAME             = "henyey"
CONST DEFAULT_THRESHOLD_PERCENT     = 67
CONST DEFAULT_BASE_FEE              = 100          // stroops
CONST DEFAULT_BASE_RESERVE          = 5_000_000    // 0.5 XLM in stroops
CONST DEFAULT_PROTOCOL_VERSION      = 22
CONST DEFAULT_DB_PATH               = "stellar.db"
CONST DEFAULT_POOL_SIZE             = 10
CONST DEFAULT_BUCKET_DIR            = "buckets"
CONST DEFAULT_BUCKET_CACHE_SIZE     = 256
CONST DEFAULT_PEER_PORT             = 11625
CONST DEFAULT_MAX_INBOUND           = 64
CONST DEFAULT_MAX_OUTBOUND          = 8
CONST DEFAULT_TARGET_OUTBOUND       = 8
CONST DEFAULT_FLOOD_OP_RATE         = 1.0
CONST DEFAULT_FLOOD_SOROBAN_RATE    = 1.0
CONST DEFAULT_FLOOD_DEMAND_MS       = 200
CONST DEFAULT_FLOOD_ADVERT_MS       = 100
CONST DEFAULT_FLOOD_BACKOFF_MS      = 500
CONST DEFAULT_PEER_MAX_FAILURES     = 120
CONST DEFAULT_HTTP_PORT             = 11626
CONST DEFAULT_HTTP_ADDRESS          = "0.0.0.0"
CONST DEFAULT_CLASSIC_BYTE_ALLOW    = 5 * 1024 * 1024
CONST DEFAULT_SOROBAN_BYTE_ALLOW    = 5 * 1024 * 1024
```

### Data: AppConfig

```
AppConfig:
  node: NodeConfig
  network: NetworkConfig
  upgrades: UpgradeConfig
  database: DatabaseConfig
  buckets: BucketConfig
  history: HistoryConfig
  overlay: OverlayConfig
  logging: LoggingConfig
  http: HttpConfig
  surge_pricing: SurgePricingConfig
  events: EventsConfig
  metadata: MetadataConfig
  catchup: CatchupConfig
```

### Data: NodeConfig

```
NodeConfig:
  name: string                    // default "henyey"
  node_seed: optional<string>     // S... secret seed
  is_validator: boolean           // default false
  home_domain: optional<string>
  quorum_set: QuorumSetConfig
  manual_close: boolean           // default false
```

### Data: OverlayConfig

```
OverlayConfig:
  peer_port: u16
  max_inbound_peers: integer
  max_outbound_peers: integer
  target_outbound_peers: integer
  known_peers: list<string>
  preferred_peers: list<string>
  surveyor_keys: list<string>     // G... public keys
  auto_survey: boolean
  flood_op_rate_per_ledger: float
  flood_soroban_rate_per_ledger: float
  flood_demand_period_ms: u64
  flood_advert_period_ms: u64
  flood_demand_backoff_delay_ms: u64
  peer_max_failures: u32
```

### Data: CatchupConfig

```
CatchupConfig:
  complete: boolean     // default false
  recent: u32           // default 0
```

### CatchupConfig::to_mode

"Priority:
1. If complete is true -> Complete mode
2. If recent > 0 -> Recent(n) mode
3. Otherwise -> Minimal mode"

```
function to_mode():
  if self.complete:
    -> Complete
  else if self.recent > 0:
    -> Recent(self.recent)
  else:
    -> Minimal
```

### QuorumSetConfig::to_xdr

```
function to_xdr():
  validators = []
  for each v in self.validators:
    pubkey = parse_strkey(v)       REF: henyey_crypto::PublicKey::from_strkey
    GUARD pubkey parse fails -> null
    validators.push(NodeId(pubkey))

  inner_sets = []
  for each inner in self.inner_sets:
    inner_xdr = inner.to_xdr()     // recursive
    if inner_xdr is not null:
      inner_sets.push(inner_xdr)

  GUARD validators empty and inner_sets empty -> null

  total = validators.length + inner_sets.length
  threshold = max((total * threshold_percent) / 100, 1)

  quorum_set = ScpQuorumSet(threshold, validators, inner_sets)
  normalize_quorum_set(quorum_set)  REF: henyey_scp::normalize_quorum_set
  -> quorum_set
```

### UpgradeConfig::to_ledger_upgrades

```
function to_ledger_upgrades():
  upgrades = []
  if protocol_version is set:
    upgrades.push(LedgerUpgrade::Version(protocol_version))
  if base_fee is set:
    upgrades.push(LedgerUpgrade::BaseFee(base_fee))
  if base_reserve is set:
    upgrades.push(LedgerUpgrade::BaseReserve(base_reserve))
  if max_tx_set_size is set:
    upgrades.push(LedgerUpgrade::MaxTxSetSize(max_tx_set_size))
  -> upgrades
```

### AppConfig::from_file

```
function from_file(path):
  content = read_file(path)
  config = parse_toml(content)
  -> config
```

### AppConfig::from_file_with_env

```
function from_file_with_env(path):
  config = from_file(path)
  config.apply_env_overrides()
  -> config
```

### AppConfig::apply_env_overrides

"Environment variables use the pattern: RS_STELLAR_CORE_<SECTION>_<KEY>"

```
function apply_env_overrides():
  if env("RS_STELLAR_CORE_NODE_NAME"):       node.name = value
  if env("RS_STELLAR_CORE_NODE_SEED"):       node.node_seed = value
  if env("RS_STELLAR_CORE_NODE_VALIDATOR"):  node.is_validator = parse_bool(value)
  if env("RS_STELLAR_CORE_NETWORK_PASSPHRASE"): network.passphrase = value
  if env("RS_STELLAR_CORE_DATABASE_PATH"):   database.path = value
  if env("RS_STELLAR_CORE_BUCKETS_DIRECTORY"): buckets.directory = value
  if env("RS_STELLAR_CORE_OVERLAY_PEER_PORT"): overlay.peer_port = parse(value)
  if env("RS_STELLAR_CORE_LOG_LEVEL"):       logging.level = value
  if env("RS_STELLAR_CORE_LOG_FORMAT"):      logging.format = value
```

### AppConfig::validate

```
function validate():
  // Validator identity checks
  GUARD is_validator and node_seed is null
    -> error("Validators must have a node_seed configured")
  if node_seed is set:
    GUARD not starts_with("S") or length != 56
      -> error("Invalid node_seed format")

  // History archive requirement
  GUARD history.archives is empty
    -> error("At least one history archive must be configured")

  // Overlay flood parameter validation
  GUARD flood_op_rate_per_ledger <= 0        -> error
  GUARD flood_soroban_rate_per_ledger <= 0   -> error
  GUARD flood_demand_period_ms == 0          -> error
  GUARD flood_advert_period_ms == 0          -> error
  GUARD flood_demand_backoff_delay_ms == 0   -> error
  GUARD auto_survey                          -> error("not supported")

  // Surveyor key validation
  for each key in overlay.surveyor_keys:
    GUARD parse_strkey(key) fails -> error("Invalid surveyor key")

  // Surge pricing byte limit
  total_bytes = classic_byte_allowance + soroban_byte_allowance
  GUARD total_bytes > 10 MB -> error("exceeds 10MB total")

  // Events dependency
  GUARD backfill_stellar_asset_events and not emit_classic_events
    -> error("backfill requires emit_classic_events")

  // Port conflict
  GUARD http.enabled and http.port == overlay.peer_port
    -> error("HTTP port and peer port must be different")

  // Bucket index page size
  GUARD index_page_size_exponent < 4 or > 24
    -> error("must be between 4 and 24")

  // Validator quorum set checks
  if is_validator:
    GUARD quorum_set validators and inner_sets both empty
      -> error("Validators must have a quorum set")
    GUARD threshold_percent == 0
      -> error("threshold must be > 0")
    quorum_set = to_xdr()
    GUARD quorum_set is null -> error("Invalid quorum set config")
    is_quorum_set_sane(quorum_set, true)
      REF: henyey_scp::is_quorum_set_sane
    GUARD not sane -> error
```

### AppConfig::network_id

```
function network_id():
  -> sha256(network.passphrase)
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~1258  | ~155       |
| Functions     | 15     | 11         |
