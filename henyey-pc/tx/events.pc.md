## Pseudocode: crates/tx/src/events.rs

"Classic event emission for Stellar Asset Contract (SAC) events.
Handles SEP-0041 compatible events for classic Stellar operations.
Events: transfer, mint, burn, clawback, set_authorized, fee.
Protocol 23+: classic events natively emitted."

### ClassicEventConfig

```
struct ClassicEventConfig:
  emit_classic_events: bool
  backfill_stellar_asset_events: bool

  function events_enabled(protocol_version):
    → emit_classic_events

  function backfill_to_protocol23(protocol_version):
    → false
```

### OpEventManager

"Manages contract events for a single operation.
Issuer-aware transfer logic:
- Both parties are issuer → transfer event
- Sender is issuer → mint event
- Receiver is issuer → burn event
- Otherwise → transfer event"

```
struct OpEventManager:
  enabled: bool
  backfill_to_protocol23: bool
  events: list of ContractEvent
  network_id: NetworkId
  memo: Memo
  finalized: bool

  function new(meta_enabled, is_soroban, protocol_version,
               network_id, memo, config):
    enabled = meta_enabled
              and (is_soroban or config.events_enabled(protocol_version))
    backfill_to_protocol23 = config.backfill_to_protocol23(protocol_version)
```

### OpEventManager.events_for_claim_atoms

```
function events_for_claim_atoms(source, claim_atoms):
  if not enabled: return
  source_addr = make_muxed_account_address(source)

  for each atom in claim_atoms:
    if atom is OrderBook:
      seller = make_account_address(atom.seller_id)
      // buyer pays seller for asset_bought
      event_for_transfer_with_issuer_check(
        atom.asset_bought, source_addr, seller,
        atom.amount_bought, false)
      // seller pays buyer for asset_sold
      event_for_transfer_with_issuer_check(
        atom.asset_sold, seller, source_addr,
        atom.amount_sold, false)

    if atom is LiquidityPool:
      pool = ScAddress::LiquidityPool(atom.liquidity_pool_id)
      event_for_transfer_with_issuer_check(
        atom.asset_bought, source_addr, pool,
        atom.amount_bought, false)
      event_for_transfer_with_issuer_check(
        atom.asset_sold, pool, source_addr,
        atom.amount_sold, false)

    if atom is V0:
      seller = ScAddress::Account(atom.seller_ed25519)
      event_for_transfer_with_issuer_check(
        atom.asset_bought, source_addr, seller,
        atom.amount_bought, false)
      event_for_transfer_with_issuer_check(
        atom.asset_sold, seller, source_addr,
        atom.amount_sold, false)
```

### OpEventManager.event_for_transfer_with_issuer_check

```
function event_for_transfer_with_issuer_check(
    asset, from, to, amount, allow_muxed_id_or_memo):
  if not enabled: return

  from_is_issuer = is_issuer(from, asset)
  to_is_issuer = is_issuer(to, asset)

  if from_is_issuer and to_is_issuer:
    new_transfer_event(asset, from, to, amount, allow_muxed_id_or_memo)
  else if from_is_issuer:
    new_mint_event(asset, to, amount, allow_muxed_id_or_memo)
  else if to_is_issuer:
    new_burn_event(asset, from, amount)
  else:
    new_transfer_event(asset, from, to, amount, allow_muxed_id_or_memo)
```

### OpEventManager.new_transfer_event

```
function new_transfer_event(asset, from, to, amount,
                            allow_muxed_id_or_memo):
  if not enabled: return
  contract_id = get_asset_contract_id(network_id, asset)
  topics = [
    symbol("transfer"),
    Address(drop_muxed_info(from)),
    Address(drop_muxed_info(to)),
    sep0011_asset_string(asset)
  ]
  data = make_possible_muxed_data(to, amount, memo,
                                   allow_muxed_id_or_memo)
  events.push(make_event(contract_id, topics, data))
```

### OpEventManager.new_mint_event

```
function new_mint_event(asset, to, amount, allow_muxed_id_or_memo):
  → new_mint_event_internal(asset, to, amount,
      allow_muxed_id_or_memo, insert_at_beginning=false)
```

### OpEventManager.new_mint_event_at_beginning

"Used by LumenEventReconciler to insert synthetic mint events
for pre-protocol 8 XLM reconciliation."

```
function new_mint_event_at_beginning(asset, to, amount):
  → new_mint_event_internal(asset, to, amount, false,
      insert_at_beginning=true)
```

### OpEventManager.new_mint_event_internal

```
function new_mint_event_internal(asset, to, amount,
    allow_muxed_id_or_memo, insert_at_beginning):
  if not enabled or finalized: return
  contract_id = get_asset_contract_id(network_id, asset)
  topics = [
    symbol("mint"),
    Address(drop_muxed_info(to)),
    sep0011_asset_string(asset)
  ]
  data = make_possible_muxed_data(to, amount, memo,
                                   allow_muxed_id_or_memo)
  event = make_event(contract_id, topics, data)

  if insert_at_beginning:
    events.insert(0, event)
  else:
    events.push(event)
```

### OpEventManager.new_burn_event

```
function new_burn_event(asset, from, amount):
  if not enabled or finalized: return
  contract_id = get_asset_contract_id(network_id, asset)
  topics = [
    symbol("burn"),
    Address(drop_muxed_info(from)),
    sep0011_asset_string(asset)
  ]
  data = i128(amount)
  events.push(make_event(contract_id, topics, data))
```

### OpEventManager.new_clawback_event

```
function new_clawback_event(asset, from, amount):
  if not enabled or finalized: return
  contract_id = get_asset_contract_id(network_id, asset)
  topics = [
    symbol("clawback"),
    Address(drop_muxed_info(from)),
    sep0011_asset_string(asset)
  ]
  data = i128(amount)
  events.push(make_event(contract_id, topics, data))
```

### OpEventManager.new_set_authorized_event

```
function new_set_authorized_event(asset, account, authorize):
  if not enabled or finalized: return
  contract_id = get_asset_contract_id(network_id, asset)
  topics = [
    symbol("set_authorized"),
    Address(account),
    sep0011_asset_string(asset)
  ]
  data = Bool(authorize)
  events.push(make_event(contract_id, topics, data))
```

### OpEventManager.set_events

"Set events from external source (e.g., Soroban contract execution).
If backfill_to_protocol23 is enabled, transforms events to P23 format."

```
function set_events(events):
  if not enabled or finalized: return

  if not backfill_to_protocol23:
    self.events = events
    return

  // Backfill: transform Soroban events to match P23 format
  for each event in events:
    asset = get_asset_from_event(event, network_id)
    if asset is none: continue

    topics = event.body.topics
    if topics is empty: continue
    name = symbol_bytes(topics[0])

    if name == "transfer":
      if topics.length != 4: continue
      from = topics[1] as Address
      to = topics[2] as Address
      from_is_issuer = is_issuer(from, asset)
      to_is_issuer = is_issuer(to, asset)

      // Skip if both or neither are issuer (no transform needed)
      if (from_is_issuer and to_is_issuer) or
         (not from_is_issuer and not to_is_issuer):
        continue

      if from_is_issuer:
        // transfer from issuer → mint (remove "from" topic)
        topics[0] = symbol("mint")
        topics.remove(index=1)
      else:
        // transfer to issuer → burn (remove "to" topic)
        topics[0] = symbol("burn")
        topics.remove(index=2)

    if name in ["mint", "clawback", "set_authorized"]:
      if topics.length == 4:
        // Remove admin/issuer topic at index 1
        topics.remove(index=1)

  self.events = events
```

### OpEventManager.finalize

```
function finalize():
  finalized = true
  → take(events)  // returns events and empties list
```

### TxEventManager

"Manages transaction-level events (currently only fee events)."

```
struct TxEventManager:
  enabled: bool
  events: list of TransactionEvent
  network_id: NetworkId
  finalized: bool

  function new(meta_enabled, protocol_version, network_id, config):
    enabled = meta_enabled and config.events_enabled(protocol_version)
```

### TxEventManager.new_fee_event

"Fee events track XLM charged or refunded for transaction fees."

```
function new_fee_event(fee_source, amount, stage):
  if not enabled or finalized or amount == 0: return
  contract_id = get_asset_contract_id(network_id, Native)
  topics = [
    symbol("fee"),
    Address(fee_source)
  ]
  data = i128(amount)
  event = make_event(contract_id, topics, data)
  events.push(TransactionEvent { stage, event })
```

### TxEventManager.charge_fee

```
function charge_fee(fee_source, amount, stage):
  new_fee_event(fee_source, -abs(amount), stage)
```

### TxEventManager.refund_fee

```
function refund_fee(fee_source, amount, stage):
  new_fee_event(fee_source, abs(amount), stage)
```

### EventManagerHierarchy

"Composes all event managers for a transaction.
One TxEventManager for transaction-level fee events,
one OpEventManager per operation for operation-level events."

```
struct EventManagerHierarchy:
  tx_manager: TxEventManager
  op_managers: list of OpEventManager

  function new(meta_enabled, is_soroban, protocol_version,
               network_id, memo, config, operation_count):
    tx_manager = TxEventManager.new(
      meta_enabled, protocol_version, network_id, config)
    op_managers = [OpEventManager.new(
      meta_enabled, is_soroban, protocol_version,
      network_id, memo, config) for _ in 0..operation_count]

  function finalize():
    op_events = [m.finalize() for m in op_managers]
    tx_events = tx_manager.finalize()
    → (op_events, tx_events)
```

### Helper: make_muxed_account_address

```
function make_muxed_account_address(muxed):
  if muxed is Ed25519(pk):
    → ScAddress::Account(pk)
  if muxed is MuxedEd25519(m):
    → ScAddress::MuxedAccount(m.id, m.ed25519)
```

### Helper: get_address_with_dropped_muxed_info

```
function get_address_with_dropped_muxed_info(address):
  if address is MuxedAccount(muxed):
    → ScAddress::Account(muxed.ed25519)
  else:
    → address
```

### Helper: make_sep0011_asset_string_scval

```
function make_sep0011_asset_string_scval(asset):
  if asset is Native:
    → String("native")
  if asset is CreditAlphanum4(a):
    → String("{code}:{issuer_strkey}")
  if asset is CreditAlphanum12(a):
    → String("{code}:{issuer_strkey}")
```

### Helper: make_possible_muxed_data

```
function make_possible_muxed_data(to, amount, memo,
                                   allow_muxed_id_or_memo):
  is_to_muxed = (to is MuxedAccount)
  has_memo = (memo is not None)

  if not allow_muxed_id_or_memo or (not is_to_muxed and not has_memo):
    → i128(amount)

  map = [
    { key: symbol("amount"), val: i128(amount) },
    { key: symbol("to_muxed_id"),
      val: if to is MuxedAccount:
             u64(to.muxed_id)
           else:
             classic_memo_scval(memo) }
  ]
  → Map(map)
```

### Helper: is_issuer

```
function is_issuer(address, asset):
  if address is not Account: → false
  if asset is Native: → false
  if asset is CreditAlphanum4(a): → (a.issuer == address)
  if asset is CreditAlphanum12(a): → (a.issuer == address)
```

### Helper: get_asset_contract_id

```
function get_asset_contract_id(network_id, asset):
  preimage = HashIdPreimage::ContractId {
    network_id,
    contract_id_preimage: Asset(asset)
  }
  → ContractId(SHA256(XDR(preimage)))
```

### Helper: get_asset_from_event

"Reconstruct asset from a ContractEvent by parsing the asset string
topic and verifying the contract ID matches."

```
function get_asset_from_event(event, network_id):
  contract_id = event.contract_id
  if contract_id is none: → none

  asset_val = event.body.topics.last
  asset_str = asset_val as String

  // Parse "native" or "{code}:{issuer_strkey}"
  asset = parse_asset_string(asset_str)
  if asset is none: → none

  // Verify contract ID matches
  expected = get_asset_contract_id(network_id, asset)
  if expected != contract_id: → none
  → asset
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 981    | 269        |
| Functions     | 28     | 28         |
