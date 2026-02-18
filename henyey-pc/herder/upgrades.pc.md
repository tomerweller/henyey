## Pseudocode: crates/herder/src/upgrades.rs

"Ledger upgrade scheduling and validation. Matches stellar-core Upgrades class."

"Upgrades allow the network to coordinate changes to protocol parameters:
protocol version, base fee, max tx set size, base reserve, ledger flags,
and Soroban configuration."

### Constants

```
CONST DEFAULT_UPGRADE_EXPIRATION_HOURS = 12
CONST MASK_LEDGER_HEADER_FLAGS = 0x7    // bits 0-2
```

### Enum: UpgradeValidity

```
UpgradeValidity:
  Valid         // can be applied
  XdrInvalid    // could not deserialize
  Invalid       // invalid for other reason
```

### Data: UpgradeParameters

```
UpgradeParameters:
  upgrade_time                  // Unix timestamp for scheduled upgrade
  protocol_version              // nullable u32
  base_fee                      // nullable u32 (stroops)
  max_tx_set_size               // nullable u32 (operation count)
  base_reserve                  // nullable u32 (stroops)
  flags                         // nullable u32
  max_soroban_tx_set_size       // nullable u32
  config_upgrade_set_key        // nullable ConfigUpgradeSetKeyJson
  nomination_timeout_limit      // nullable u32
  expiration_minutes            // nullable u64
```

### Data: ConfigUpgradeSetKeyJson

```
ConfigUpgradeSetKeyJson:
  contract_id     // base64-encoded string (32 bytes)
  content_hash    // base64-encoded string (32 bytes)
```

### Data: CurrentLedgerState

```
CurrentLedgerState:
  close_time
  protocol_version
  base_fee
  max_tx_set_size
  base_reserve
  flags
  max_soroban_tx_set_size       // nullable
```

### Data: Upgrades

```
Upgrades:
  params    // UpgradeParameters
```

---

### ConfigUpgradeSetKeyJson::from_xdr

```
function from_xdr(key) → ConfigUpgradeSetKeyJson:
  → { contract_id: base64_encode(key.contract_id),
      content_hash: base64_encode(key.content_hash) }
```

### ConfigUpgradeSetKeyJson::to_xdr

```
function to_xdr() → ConfigUpgradeSetKey:
  contract_id = base64_decode(self.contract_id)
  content_hash = base64_decode(self.content_hash)
  GUARD len(contract_id) != 32   → error
  GUARD len(content_hash) != 32  → error
  → ConfigUpgradeSetKey { contract_id, content_hash }
```

---

### UpgradeParameters::new

```
function new(upgrade_time) → UpgradeParameters:
  → UpgradeParameters { upgrade_time, all others null }
```

### UpgradeParameters::from_now

```
function from_now(offset) → UpgradeParameters:
  → new(current_unix_time + offset_seconds)
```

### UpgradeParameters::has_any_upgrade

```
function has_any_upgrade() → bool:
  → protocol_version is set
    or base_fee is set
    or max_tx_set_size is set
    or base_reserve is set
    or flags is set
    or max_soroban_tx_set_size is set
    or config_upgrade_set_key is set
```

### UpgradeParameters::expiration_seconds

```
function expiration_seconds() → u64:
  if expiration_minutes is set:
    → expiration_minutes * 60
  → DEFAULT_UPGRADE_EXPIRATION_HOURS * 3600
```

### UpgradeParameters::is_expired

```
function is_expired(current_time) → bool:
  → current_time > upgrade_time + expiration_seconds()
```

---

### Upgrades::set_parameters

```
function set_parameters(params, max_protocol_version):
  if params.protocol_version is set:
    GUARD params.protocol_version > max_protocol_version
        → error "Protocol version error"
  self.params = params
```

### Upgrades::time_for_upgrade

```
function time_for_upgrade(current_time) → bool:
  → current_time >= params.upgrade_time
```

### Upgrades::create_upgrades_for

"Create upgrade proposals for parameters that differ from current values."

```
function create_upgrades_for(state) → list<LedgerUpgrade>:
  result = []

  if not time_for_upgrade(state.close_time):
    → result

  if params.protocol_version is set
     and state.protocol_version != params.protocol_version:
    result.append(LedgerUpgrade::Version(params.protocol_version))

  if params.base_fee is set
     and state.base_fee != params.base_fee:
    result.append(LedgerUpgrade::BaseFee(params.base_fee))

  if params.max_tx_set_size is set
     and state.max_tx_set_size != params.max_tx_set_size:
    result.append(LedgerUpgrade::MaxTxSetSize(params.max_tx_set_size))

  if params.base_reserve is set
     and state.base_reserve != params.base_reserve:
    result.append(LedgerUpgrade::BaseReserve(params.base_reserve))

  if params.flags is set
     and state.flags != params.flags:
    result.append(LedgerUpgrade::Flags(params.flags))

  "Only propose Soroban upgrades if we have Soroban enabled (protocol 20+)"
  if params.max_soroban_tx_set_size is set
     and state.max_soroban_tx_set_size is set
     and state.max_soroban_tx_set_size != params.max_soroban_tx_set_size:
    result.append(LedgerUpgrade::MaxSorobanTxSetSize(
        params.max_soroban_tx_set_size))

  "Config upgrade proposal — validation happens when applied"
  if params.config_upgrade_set_key is set:
    key = params.config_upgrade_set_key.to_xdr()
    if key is valid:
      result.append(LedgerUpgrade::Config(key))

  → result
```

### Upgrades::remove_upgrades

"Remove applied upgrades from scheduled parameters. Also removes all
upgrades if they have expired."

```
function remove_upgrades(applied_upgrades, close_time)
    → (UpgradeParameters, bool):

  result = copy of params
  updated = false

  "If upgrades have expired, remove all"
  if result.is_expired(close_time):
    had_any = result.has_any_upgrade()
    clear all upgrade fields in result
    → (result, had_any)

  "Remove individual applied upgrades"
  for each upgrade_bytes in applied_upgrades:
    upgrade = xdr_deserialize<LedgerUpgrade>(upgrade_bytes)
    if deserialize fails: continue

    case upgrade:
      Version(v):
        if result.protocol_version == v:
          result.protocol_version = null
          updated = true
      BaseFee(v):
        if result.base_fee == v:
          result.base_fee = null
          updated = true
      MaxTxSetSize(v):
        if result.max_tx_set_size == v:
          result.max_tx_set_size = null
          updated = true
      BaseReserve(v):
        if result.base_reserve == v:
          result.base_reserve = null
          updated = true
      Flags(v):
        if result.flags == v:
          result.flags = null
          updated = true
      MaxSorobanTxSetSize(v):
        if result.max_soroban_tx_set_size == v:
          result.max_soroban_tx_set_size = null
          updated = true
      Config(key):
        if result.config_upgrade_set_key is set:
          if result.config_upgrade_set_key.to_xdr() == key:
            result.config_upgrade_set_key = null
            updated = true

  → (result, updated)
```

---

### is_valid_for_apply

"Validate an upgrade for application."

```
function is_valid_for_apply(upgrade_bytes, current_version,
                            max_protocol_version)
    → (UpgradeValidity, LedgerUpgrade?):

  upgrade = xdr_deserialize<LedgerUpgrade>(upgrade_bytes)
  GUARD deserialize fails   → (XdrInvalid, null)

  valid = case upgrade:
    Version(new_version):
      new_version <= max_protocol_version
        and new_version > current_version

    BaseFee(fee):
      fee != 0

    MaxTxSetSize(_):
      true    // any size allowed

    BaseReserve(reserve):
      reserve != 0

    Flags(flags):
      "Flags upgrade requires protocol 18+"
      current_version >= 18
        and (flags & ~MASK_LEDGER_HEADER_FLAGS) == 0

    Config(_):
      "Config upgrade requires Soroban (protocol 20+)"
      current_version >= 20

    MaxSorobanTxSetSize(_):
      "Soroban tx set size requires protocol 20+"
      current_version >= 20

  if valid:
    → (Valid, upgrade)
  else:
    → (Invalid, upgrade)
```

### upgrade_to_string

```
function upgrade_to_string(upgrade) → string:
  case upgrade:
    Version(v):             → "protocolversion=<v>"
    BaseFee(v):             → "basefee=<v>"
    MaxTxSetSize(v):        → "maxtxsetsize=<v>"
    BaseReserve(v):         → "basereserve=<v>"
    Flags(v):               → "flags=<v>"
    Config(key):            → "configupgradesetkey=<hex(key.content_hash)>"
    MaxSorobanTxSetSize(v): → "maxsorobantxsetsize=<v>"
```

### parse_upgrade

```
function parse_upgrade(upgrade_bytes) → LedgerUpgrade?:
  → xdr_deserialize<LedgerUpgrade>(upgrade_bytes) or null
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~400   | ~165       |
| Functions     | 17     | 17         |
