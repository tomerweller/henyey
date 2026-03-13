# RPC Unit Test Plan

Comprehensive unit test plan for `henyey-rpc`, informed by bugs found during
testnet sanity testing and upstream test patterns from `stellar-rpc` (Go) and
`soroban-simulation` (Rust).

## Design Principles

1. **Test the bugs we found** — Every bug from the sanity test session gets a
   dedicated regression test (field naming, account V3 normalization,
   disk_read_entries counting, restored_rw_entry_indices ext).
2. **Pure functions first** — 14 of 15 key simulate functions are pure; test
   without mocking.
3. **Test helpers for complex types** — Create `test_soroban_network_info()`,
   `test_soroban_resources()`, etc. to reduce boilerplate.
4. **In-module tests for private types** — `LedgerEntryDiff`, `SorobanOp` are
   private, so tests must be `#[cfg(test)] mod tests` inside their module.
5. **Match upstream patterns** — Table-driven subtests, snapshot assertions,
   explicit edge cases.

---

## Category A: Snapshot Normalization (8 tests)

File: `crates/rpc/src/simulate/snapshot.rs`

Direct regression tests for the V3 normalization bug that caused
`ResourceLimitExceeded`.

| # | Test Name | Description |
|---|-----------|-------------|
| 1 | `test_normalize_account_v0_to_v3` | V0 -> V1(V2(V3)), liabilities zero, signer_sponsoring empty, seqLedger=0, seqTime=0 |
| 2 | `test_normalize_account_v1_to_v3` | V1 (has liabilities) -> V1(V2(V3)), liabilities preserved |
| 3 | `test_normalize_account_v2_to_v3` | V1(V2) -> V1(V2(V3)), sponsoring info preserved |
| 4 | `test_normalize_account_already_v3` | Already V3 -> unchanged |
| 5 | `test_normalize_account_with_signers` | V0 + 3 signers -> V3 with signer_sponsoring_ids length 3 |
| 6 | `test_normalize_non_account_unchanged` | ContractData entry -> no normalization |
| 7 | `test_normalize_preserves_other_fields` | accountID, balance, seqNum, etc. unchanged |
| 8 | `test_normalized_entry_xdr_size` | V0 account -> after normalize, LedgerEntry XDR is 144 bytes |

## Category B: Simulate Pure Functions (35+ tests)

File: `crates/rpc/src/simulate/mod.rs`

### B1. sim_adjust (5 tests)

| # | Test Name | Description |
|---|-----------|-------------|
| 1 | `test_sim_adjust_zero_returns_zero` | `sim_adjust(0, 1.04, 50_000) == 0` |
| 2 | `test_sim_adjust_additive_dominates` | `sim_adjust(100_000, 1.04, 50_000) == 154_000` |
| 3 | `test_sim_adjust_multiplicative_dominates` | `sim_adjust(10_000_000, 1.04, 50_000) == 10_400_000` |
| 4 | `test_sim_adjust_no_adjustment` | `sim_adjust(500, 1.0, 0) == 500` |
| 5 | `test_sim_adjust_saturating` | `sim_adjust(u32::MAX - 10, 1.04, 50_000) == u32::MAX` |

### B2. adjust_resources (3 tests)

| # | Test Name | Description |
|---|-----------|-------------|
| 1 | `test_adjust_resources_default` | (1.04, 50_000) for instructions, (1.0, 0) for bytes |
| 2 | `test_adjust_resources_custom_leeway` | leeway=200_000 -> additive=200_000 |
| 3 | `test_adjust_resources_zero_values` | All-zero -> remain zero |

### B3. validate_memo (4 tests)

| # | Test Name | Description |
|---|-----------|-------------|
| 1 | `test_validate_memo_none_ok` | Memo::None -> Ok |
| 2 | `test_validate_memo_text_28_ok` | 28-byte text -> Ok |
| 3 | `test_validate_memo_text_29_error` | 29-byte text -> error |
| 4 | `test_validate_memo_hash_ok` | Memo::Hash -> Ok |

### B4. resolve_auth_mode (6 tests)

| # | Test Name | Description |
|---|-----------|-------------|
| 1 | `test_resolve_auth_mode_default_no_auth` | ("", []) -> RecordingAuth |
| 2 | `test_resolve_auth_mode_default_with_auth` | ("", [entry]) -> EnforcingAuth |
| 3 | `test_resolve_auth_mode_record` | ("record", []) -> RecordingAuth |
| 4 | `test_resolve_auth_mode_record_with_auth_error` | ("record", [entry]) -> error |
| 5 | `test_resolve_auth_mode_enforce` | ("enforce", [entry]) -> EnforcingAuth |
| 6 | `test_resolve_auth_mode_invalid` | ("bogus", []) -> error |

### B5. muxed_to_account_id (2 tests)

| # | Test Name | Description |
|---|-----------|-------------|
| 1 | `test_muxed_ed25519` | Ed25519 -> AccountId same key |
| 2 | `test_muxed_ed25519_muxed` | MuxedEd25519 -> AccountId key, id stripped |

### B6. extract_soroban_op (6 tests)

| # | Test Name | Description |
|---|-----------|-------------|
| 1 | `test_extract_invoke_host_function` | InvokeHostFunction -> Ok |
| 2 | `test_extract_extend_ttl` | ExtendFootprintTtl -> Ok |
| 3 | `test_extract_restore` | RestoreFootprint -> Ok |
| 4 | `test_extract_non_soroban_op_error` | Payment -> error |
| 5 | `test_extract_multi_op_error` | 2 ops -> error |
| 6 | `test_extract_fee_bump_unwrap` | FeeBump wrapping Invoke -> unwraps |

### B7. insert_sim_xdr_field (4 tests) [REGRESSION]

| # | Test Name | Description |
|---|-----------|-------------|
| 1 | `test_sim_xdr_field_base64_unsuffixed` | Base64 -> key is "transactionData" |
| 2 | `test_sim_xdr_field_json_suffixed` | JSON -> key is "transactionDataJson" |
| 3 | `test_sim_xdr_array_base64_unsuffixed` | Base64 -> key is "events" |
| 4 | `test_sim_xdr_array_json_suffixed` | JSON -> key is "eventsJson" |

### B8. serialize_state_changes (4 tests)

| # | Test Name | Description |
|---|-----------|-------------|
| 1 | `test_state_changes_created` | None -> Some = "created" |
| 2 | `test_state_changes_updated` | Some -> Some = "updated" |
| 3 | `test_state_changes_deleted` | Some -> None = "deleted" |
| 4 | `test_state_changes_json_format` | JSON mode -> "keyJson" etc. |

### B9-B10. build_error_response / build_footprint_response (4 tests)

| # | Test Name | Description |
|---|-----------|-------------|
| 1 | `test_build_error_response_structure` | Has error, transactionData, events, etc. |
| 2 | `test_build_error_response_defaults` | transactionData="", events=[], fee="0" |
| 3 | `test_build_footprint_response_base64` | Has transactionData (base64), fee, cost |
| 4 | `test_build_footprint_response_json` | Has transactionDataJson (object) |

### B11. compute_invoke_resource_fee (4 tests) [REGRESSION]

| # | Test Name | Description |
|---|-----------|-------------|
| 1 | `test_disk_read_entries_excludes_soroban` | 1 Account + 1 ContractData in RO -> entries=1 |
| 2 | `test_disk_read_entries_includes_restored` | Empty footprint + restored=3 -> entries=3 |
| 3 | `test_disk_read_entries_mixed` | 2 accounts RO + 1 contract RW + 1 restored -> entries=3 |
| 4 | `test_refundable_fee_adjustment` | Refundable fee * 1.15 |

### B12. estimate_tx_size (2 tests)

| # | Test Name | Description |
|---|-----------|-------------|
| 1 | `test_tx_size_invoke_reasonable` | > 0, includes adjustment |
| 2 | `test_tx_size_extend_ttl` | > 0 |

## Category C: util.rs Gaps (12 tests)

File: `crates/rpc/src/util.rs`

| # | Test Name | Description |
|---|-----------|-------------|
| 1 | `test_parse_format_none` | Missing xdrFormat -> Base64 |
| 2 | `test_parse_format_json` | "json" -> Json |
| 3 | `test_parse_format_invalid` | "xml" -> error |
| 4 | `test_determine_tx_status_success` | TxSuccess -> "SUCCESS" |
| 5 | `test_determine_tx_status_failed` | TxFailed -> "FAILED" |
| 6 | `test_determine_tx_status_fee_bump_success` | TxFeeBumpInnerSuccess -> "SUCCESS" |
| 7 | `test_determine_tx_status_fee_bump_failed` | TxFeeBumpInnerFailed -> "FAILED" |
| 8 | `test_format_unix_epoch` | 0 -> "1970-01-01T00:00:00Z" |
| 9 | `test_format_known_date` | 1704067200 -> "2024-01-01T00:00:00Z" |
| 10 | `test_format_leap_year` | 1709208000 -> "2024-02-29T00:00:00Z" |
| 11 | `test_ttl_key_for_contract_data` | ContractData -> Some(Ttl key) |
| 12 | `test_ttl_key_for_account` | Account -> None |

## Category D: Event Filter Parsing (8 tests)

File: `crates/rpc/src/methods/get_events.rs`

| # | Test Name | Description |
|---|-----------|-------------|
| 1 | `test_parse_filters_empty` | No filters -> empty vec |
| 2 | `test_parse_filters_contract_id` | Single contract ID -> parsed |
| 3 | `test_parse_filters_topic_wildcard` | "*" segment -> wildcard |
| 4 | `test_parse_filters_topic_double_star` | "**" segment -> matches remaining |
| 5 | `test_parse_filters_max_exceeded` | 6 filters -> error |
| 6 | `test_parse_filters_max_contract_ids` | 6 contract IDs -> error |
| 7 | `test_parse_filters_max_topics` | 5 topic segments -> error |
| 8 | `test_parse_filters_diagnostic_rejected` | type: "diagnostic" -> error |

## Category E: send_transaction Helpers (3 tests)

File: `crates/rpc/src/methods/send_transaction.rs`

| # | Test Name | Description |
|---|-----------|-------------|
| 1 | `test_build_error_result_structure` | Has status, errorResultXdr, hash, latestLedger |
| 2 | `test_insert_empty_diagnostic_events` | Inserts diagnosticEventsXdr: [] |
| 3 | `test_build_error_result_codes` | Various result codes -> correct status strings |

## Category F: Server Request Handling (4 tests)

File: `crates/rpc/src/server.rs`

| # | Test Name | Description |
|---|-----------|-------------|
| 1 | `test_batch_request_rejected` | JSON array body -> error -32600 |
| 2 | `test_body_size_limit` | > 512KB -> rejected |
| 3 | `test_invalid_jsonrpc_version` | "1.0" -> error |
| 4 | `test_unknown_method` | "doesNotExist" -> error -32601 |

## Category G: Test Infrastructure

Shared helpers to reduce boilerplate:

| Helper | Purpose |
|--------|---------|
| `test_soroban_network_info()` | Default SorobanNetworkInfo with testnet values |
| `test_account_entry(key)` | Minimal V0 account entry |
| `test_account_entry_v3(key)` | Account with full V3 extensions |
| `test_contract_data_key(contract)` | ContractData ledger key |
| `test_account_key(key)` | Account ledger key |
| `test_soroban_resources(ro, rw)` | SorobanResources with given footprint |

---

## Total: ~75 tests across 6 categories + shared helpers

Priority order: A (critical regression), B7/B11 (critical regression), B1-B6
(high), D (high), C (medium), B8-B10/B12 (medium), E (medium), F (medium).
