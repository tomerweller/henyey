# tx

Transaction processing for henyey, providing the core transaction validation and execution logic for the Stellar network. Supports both classic Stellar operations (payments, offers, trustlines, account management) and Soroban smart contract execution, with full ledger state management and metadata building.

## Key Files

- [lib.pc.md](lib.pc.md) — Top-level crate module with validation/execution facades and re-exports
- [apply.pc.md](apply.pc.md) — LedgerDelta accumulator for ledger state changes during execution
- [live_execution.pc.md](live_execution.pc.md) — Live transaction execution pipeline for validator mode
- [validation.pc.md](validation.pc.md) — Transaction validation: structure, fees, time bounds, signatures
- [state/mod.pc.md](state/mod.pc.md) — Ledger state manager with snapshot, rollback, and delta tracking
- [operations/execute/mod.pc.md](operations/execute/mod.pc.md) — Operation dispatch and shared execution helpers
- [soroban/mod.pc.md](soroban/mod.pc.md) — Soroban smart contract integration pipeline

## Architecture

The tx crate is structured around a validation-then-execution pipeline. `TransactionFrame` wraps XDR envelopes and provides unified access across V0/V1/FeeBump types. Validation (`validation.pc.md`) checks structure, fees, time bounds, sequences, and signatures. Execution flows through `LiveExecutionContext` which orchestrates fee processing, operation application, and post-apply refunds. The `LedgerStateManager` (`state/`) tracks all ledger entry mutations with savepoint/rollback support, while `LedgerDelta` (`apply.pc.md`) accumulates changes for metadata construction. Classic operations are dispatched through `operations/execute/mod.pc.md` to individual operation executors (payments, offers, trustlines, etc.). Soroban execution (`soroban/`) handles host function invocation with protocol-versioned dispatch (P24/P25), budget tracking, and storage adaptation. The `MetaBuilder` assembles transaction metadata from deltas and events.

## All Files

| File | Description |
|------|-------------|
| [apply.pc.md](apply.pc.md) | LedgerDelta accumulator for ledger state changes |
| [error.pc.md](error.pc.md) | Error types for transaction processing |
| [events.pc.md](events.pc.md) | Classic SAC event emission (transfer, mint, burn, clawback) |
| [fee_bump.pc.md](fee_bump.pc.md) | Fee bump transaction handling (CAP-0015) |
| [frame.pc.md](frame.pc.md) | TransactionFrame wrapper for V0, V1, and FeeBump envelopes |
| [lib.pc.md](lib.pc.md) | Top-level module with validation/execution facades and re-exports |
| [live_execution.pc.md](live_execution.pc.md) | Live transaction execution pipeline for validator mode |
| [lumen_reconciler.pc.md](lumen_reconciler.pc.md) | XLM balance reconciliation for pre-protocol-8 edge cases |
| [meta_builder.pc.md](meta_builder.pc.md) | Transaction metadata building for live execution |
| [operations/mod.pc.md](operations/mod.pc.md) | Operation types, validation, and threshold classification |
| [operations/execute/account_merge.pc.md](operations/execute/account_merge.pc.md) | AccountMerge operation: merges source into destination |
| [operations/execute/bump_sequence.pc.md](operations/execute/bump_sequence.pc.md) | BumpSequence operation: advances account sequence number |
| [operations/execute/change_trust.pc.md](operations/execute/change_trust.pc.md) | ChangeTrust operation: creates, updates, or removes trustlines |
| [operations/execute/claimable_balance.pc.md](operations/execute/claimable_balance.pc.md) | CreateClaimableBalance and ClaimClaimableBalance operations |
| [operations/execute/clawback.pc.md](operations/execute/clawback.pc.md) | Clawback operation: issuer reclaims asset from trustline |
| [operations/execute/create_account.pc.md](operations/execute/create_account.pc.md) | CreateAccount operation with sponsorship support |
| [operations/execute/extend_footprint_ttl.pc.md](operations/execute/extend_footprint_ttl.pc.md) | ExtendFootprintTtl operation for Soroban contract data |
| [operations/execute/inflation.pc.md](operations/execute/inflation.pc.md) | Inflation operation (deprecated since protocol 12) |
| [operations/execute/invoke_host_function.pc.md](operations/execute/invoke_host_function.pc.md) | InvokeHostFunction: Soroban contract invocation and state application |
| [operations/execute/liquidity_pool.pc.md](operations/execute/liquidity_pool.pc.md) | LiquidityPoolDeposit and LiquidityPoolWithdraw operations |
| [operations/execute/manage_data.pc.md](operations/execute/manage_data.pc.md) | ManageData operation: attach key-value data to accounts |
| [operations/execute/manage_offer.pc.md](operations/execute/manage_offer.pc.md) | ManageSellOffer, ManageBuyOffer, and CreatePassiveSellOffer |
| [operations/execute/mod.pc.md](operations/execute/mod.pc.md) | Operation dispatch, shared helpers, and trustline flag utilities |
| [operations/execute/offer_exchange.pc.md](operations/execute/offer_exchange.pc.md) | Offer exchange math helpers and order book crossing logic |
| [operations/execute/path_payment.pc.md](operations/execute/path_payment.pc.md) | PathPaymentStrictReceive and PathPaymentStrictSend operations |
| [operations/execute/payment.pc.md](operations/execute/payment.pc.md) | Payment operation: transfers assets between accounts |
| [operations/execute/prefetch.pc.md](operations/execute/prefetch.pc.md) | Prefetch key collection for per-ledger batch loading |
| [operations/execute/restore_footprint.pc.md](operations/execute/restore_footprint.pc.md) | RestoreFootprint operation for archived Soroban entries |
| [operations/execute/set_options.pc.md](operations/execute/set_options.pc.md) | SetOptions operation: flags, thresholds, signers, home domain |
| [operations/execute/sponsorship.pc.md](operations/execute/sponsorship.pc.md) | BeginSponsoringFutureReserves, EndSponsoring, and RevokeSponsorship |
| [operations/execute/trust_flags.pc.md](operations/execute/trust_flags.pc.md) | AllowTrust and SetTrustLineFlags operations |
| [result.pc.md](result.pc.md) | Transaction and operation result wrapper types |
| [signature_checker.pc.md](signature_checker.pc.md) | Multi-signature weight checking across signer types |
| [soroban/budget.pc.md](soroban/budget.pc.md) | Soroban resource budget tracking (CPU and memory) |
| [soroban/error.pc.md](soroban/error.pc.md) | P24-to-P25 HostError and ScError type conversion |
| [soroban/events.pc.md](soroban/events.pc.md) | Soroban contract event handling and recording |
| [soroban/host.pc.md](soroban/host.pc.md) | Soroban execution result types and host invocation |
| [soroban/mod.pc.md](soroban/mod.pc.md) | Soroban integration pipeline with hot archive support |
| [soroban/protocol/mod.pc.md](soroban/protocol/mod.pc.md) | Protocol-versioned dispatch for Soroban host execution |
| [soroban/protocol/p24.pc.md](soroban/protocol/p24.pc.md) | Protocol 24 Soroban host implementation (versions 20-24) |
| [soroban/protocol/p25.pc.md](soroban/protocol/p25.pc.md) | Protocol 25 Soroban host implementation |
| [soroban/protocol/types.pc.md](soroban/protocol/types.pc.md) | Shared types for protocol-versioned host implementations |
| [soroban/storage.pc.md](soroban/storage.pc.md) | Soroban storage adapter integrating with LedgerStateManager |
| [state/entries.pc.md](state/entries.pc.md) | Typed CRUD operations for every ledger entry kind |
| [state/mod.pc.md](state/mod.pc.md) | Ledger state manager with snapshot, rollback, and delta tracking |
| [state/offer_index.pc.md](state/offer_index.pc.md) | Order book index with price-sorted offers and reverse lookup |
| [state/sponsorship.pc.md](state/sponsorship.pc.md) | Sponsorship stack management for reserve delegation |
| [state/ttl.pc.md](state/ttl.pc.md) | TTL entry operations and deferred read-only TTL bumps |
| [validation.pc.md](validation.pc.md) | Transaction validation: structure, fees, bounds, and signatures |
