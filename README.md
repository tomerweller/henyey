# rs-stellar-core

A Rust reimplementation of Stellar Core focused on protocol v25 behavior and testnet sync. This is an educational experiment and **not** production-grade software.

## Overview

rs-stellar-core aims to mirror stellar-core v25.x behavior for ledger close, SCP, overlay, history/catchup, and transaction execution. The codebase is organized as a Rust workspace with focused crates for each subsystem.

Key constraints:
- Protocol 23+ only
- SQLite-only persistence
- Metrics parity is out of scope
- Deterministic, observable behavior should match upstream v25

## Status

Work in progress. See `PARITY_GAPS.md` for the current, module-by-module gap list.

## Build

```bash
cargo build --release
```

## Test

```bash
cargo test --all
```

## Run (Testnet)

```bash
# Use the packaged config
./target/release/rs-stellar-core --config configs/testnet.toml run

# Catch up first if needed
./target/release/rs-stellar-core --config configs/testnet.toml catchup current
```

## Configuration

Generate and edit a sample config:

```bash
./target/release/rs-stellar-core sample-config > my-config.toml
./target/release/rs-stellar-core --config my-config.toml run
```

Classic event emission (off by default) can be enabled in the config:

```toml
[events]
emit_classic_events = true
backfill_stellar_asset_events = false
```

## Repository Layout

- `crates/rs-stellar-core/` — main binary
- `crates/stellar-core-*/` — subsystem crates (ledger, herder, overlay, scp, history, tx, etc.)
- `configs/` — example configs
- `PARITY_GAPS.md` — master parity gap list

## Crate Manifest

- `crates/rs-stellar-core/` — CLI and entrypoint binary (`crates/rs-stellar-core/README.md`)
- `crates/stellar-core-app/` — app wiring, config, and run/catchup orchestration (`crates/stellar-core-app/README.md`)
- `crates/stellar-core-overlay/` — P2P overlay protocol, peers, and flood control (`crates/stellar-core-overlay/README.md`)
- `crates/stellar-core-scp/` — SCP nomination/ballot protocols and slot state (`crates/stellar-core-scp/README.md`)
- `crates/stellar-core-herder/` — consensus tracking, tx set management, and ledger close triggers (`crates/stellar-core-herder/README.md`)
- `crates/stellar-core-ledger/` — ledger close pipeline and ledger state updates (`crates/stellar-core-ledger/README.md`)
- `crates/stellar-core-tx/` — transaction validation/execution (classic + Soroban) (`crates/stellar-core-tx/README.md`)
- `crates/stellar-core-bucket/` — BucketList, merges, and on-disk state (`crates/stellar-core-bucket/README.md`)
- `crates/stellar-core-history/` — history archive I/O, replay, and catchup (`crates/stellar-core-history/README.md`)
- `crates/stellar-core-historywork/` — history work scheduling and publish/catchup tasks (`crates/stellar-core-historywork/README.md`)
- `crates/stellar-core-db/` — SQLite schema and query layer (`crates/stellar-core-db/README.md`)
- `crates/stellar-core-crypto/` — signing, hashing, strkey, and short-hash utilities (`crates/stellar-core-crypto/README.md`)
- `crates/stellar-core-common/` — shared types, config helpers, and utilities (`crates/stellar-core-common/README.md`)
- `crates/stellar-core-invariant/` — invariant checks for ledger transitions (`crates/stellar-core-invariant/README.md`)
- `crates/stellar-core-work/` — generic work scheduler primitives (`crates/stellar-core-work/README.md`)
- `crates/stellar-core-simulation/` — test/sim harness for overlay/SCP (`crates/stellar-core-simulation/README.md`)

## Contributing

- Keep behavior deterministic and aligned with stellar-core v25.x.
- Add or update tests when behavior changes.
- Update crate READMEs when modifying subsystem behavior.

## License

Apache 2.0
