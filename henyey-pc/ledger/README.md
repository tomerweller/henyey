# ledger

Core ledger state management and the ledger close pipeline for the Stellar network. Coordinates transaction execution, state updates, bucket list modifications, header construction, and ledger metadata generation.

## Key Files

- [manager.pc.md](manager.pc.md) -- Central LedgerManager: maintains current header, updates bucket list, executes transactions
- [execution/mod.pc.md](execution/mod.pc.md) -- Transaction execution bridge: loads state from snapshots, applies fees, records changes
- [header.pc.md](header.pc.md) -- Ledger header construction, hashing, skip list computation, and chain verification
- [delta.pc.md](delta.pc.md) -- Change tracking with coalescing logic for created, updated, and deleted entries
- [snapshot.pc.md](snapshot.pc.md) -- Point-in-time snapshots for concurrent reads during ledger close
- [close.pc.md](close.pc.md) -- Ledger close data structures and transaction set variant handling
- [config_upgrade.pc.md](config_upgrade.pc.md) -- Soroban configuration upgrade handling through consensus

## Architecture

The `manager` module is the central component, maintaining the current ledger header, coordinating the bucket list Merkle tree, and providing snapshots for concurrent access. During ledger close, `close` supplies the input data structures, `snapshot` freezes current state for reads, and the `execution` submodule handles the actual transaction processing. Within `execution`, `mod` orchestrates the pipeline, `tx_set` executes full transaction sets, `signatures` validates authentication, `result_mapping` converts execution failures to XDR result codes, `meta` generates transaction metadata, and `config` loads Soroban configuration from the ledger. `delta` tracks all state changes with deterministic ordering and coalescing, while `header` constructs the next header with skip list computation and hash chaining. `offer` provides DEX offer sorting, `soroban_state` manages in-memory Soroban contract data with TTL tracking, `config_upgrade` handles Soroban parameter changes via consensus, and `error` defines the unified error type.

## All Files

| File | Description |
|------|-------------|
| [close.pc.md](close.pc.md) | Ledger close data structures and transaction set variant handling |
| [config_upgrade.pc.md](config_upgrade.pc.md) | Soroban configuration upgrade validation and application |
| [delta.pc.md](delta.pc.md) | Change tracking with coalescing for created, updated, and deleted entries |
| [error.pc.md](error.pc.md) | Unified error type for all ledger-related operations |
| [execution/config.pc.md](execution/config.pc.md) | Loads Soroban cost parameters and limits from ledger config settings |
| [execution/meta.pc.md](execution/meta.pc.md) | Transaction metadata generation for history recording |
| [execution/mod.pc.md](execution/mod.pc.md) | Transaction execution bridge: state loading, fee handling, and delta recording |
| [execution/result_mapping.pc.md](execution/result_mapping.pc.md) | Maps execution failures to XDR TransactionResult codes |
| [execution/signatures.pc.md](execution/signatures.pc.md) | Signature verification and signer weight validation |
| [execution/tx_set.pc.md](execution/tx_set.pc.md) | Executes full transaction sets with ordering and fee handling |
| [header.pc.md](header.pc.md) | Header construction, hashing, skip list computation, and chain verification |
| [lib.pc.md](lib.pc.md) | Module map, core data structures, and re-exports for the ledger crate |
| [manager.pc.md](manager.pc.md) | Central LedgerManager: state coordination, bucket list, and snapshots |
| [offer.pc.md](offer.pc.md) | Offer sorting and comparison utilities for the Stellar DEX |
| [snapshot.pc.md](snapshot.pc.md) | Point-in-time ledger snapshots for concurrent reads during close |
| [soroban_state.pc.md](soroban_state.pc.md) | In-memory Soroban state management with TTL tracking |
