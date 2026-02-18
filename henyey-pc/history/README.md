# history

History archive access and catchup for rs-stellar-core. Handles downloading, verifying, and replaying historical data from Stellar history archives, as well as publishing checkpoint data for validators.

## Key Files

- [catchup.pc.md](catchup.pc.md) -- Catchup orchestration: downloading, verifying, and replaying historical data
- [replay.pc.md](replay.pc.md) -- Ledger replay via re-execution or metadata replay with hash verification
- [verify.pc.md](verify.pc.md) -- Cryptographic verification of header chains, bucket hashes, and tx sets
- [archive.pc.md](archive.pc.md) -- History archive client for fetching state, headers, transactions, and buckets
- [publish.pc.md](publish.pc.md) -- History archive publishing for validators at each checkpoint
- [checkpoint_builder.pc.md](checkpoint_builder.pc.md) -- Crash-safe checkpoint building with atomic rename on commit
- [catchup_range.pc.md](catchup_range.pc.md) -- Catchup range calculation determining which ledgers to download and replay

## Architecture

The history crate is organized around the catchup and publish pipelines. `catchup` orchestrates the full sync flow (downloading HAS, buckets, ledger data, then verifying and replaying), with `catchup_range` computing which ledgers are needed. `archive` and `download` handle HTTP access to history archives with retry logic and XDR stream parsing, while `remote_archive` supports configurable shell commands for archive access. `verify` provides cryptographic chain verification and `replay` re-executes or replays ledgers against local state. On the publish side, `checkpoint_builder` writes checkpoint files crash-safely, `publish` uploads them to archives, and `publish_queue` persists the queue in SQLite. `paths` and `checkpoint` define the hierarchical file layout and 64-ledger checkpoint boundaries. `cdp` implements SEP-0054 for reading from the Composable Data Platform, and `archive_state` handles HAS JSON parsing.

## All Files

| File | Description |
|------|-------------|
| [archive.pc.md](archive.pc.md) | History archive client for fetching state, headers, and buckets |
| [archive_state.pc.md](archive_state.pc.md) | History Archive State (HAS) JSON parsing and bucket list hashes |
| [catchup.pc.md](catchup.pc.md) | Catchup manager orchestrating download, verify, and replay stages |
| [catchup_range.pc.md](catchup_range.pc.md) | Calculates which ledgers to download and replay during catchup |
| [cdp.pc.md](cdp.pc.md) | CDP Data Lake client for fetching LedgerCloseMeta via SEP-0054 |
| [checkpoint.pc.md](checkpoint.pc.md) | Checkpoint utilities: 64-ledger boundaries and path re-exports |
| [checkpoint_builder.pc.md](checkpoint_builder.pc.md) | Crash-safe checkpoint building with dirty files and atomic rename |
| [download.pc.md](download.pc.md) | Download utilities with retry logic, gzip decompression, and XDR parsing |
| [error.pc.md](error.pc.md) | Error types for network, parsing, verification, and catchup failures |
| [lib.pc.md](lib.pc.md) | Module map and re-exports for the history crate |
| [paths.pc.md](paths.pc.md) | Hierarchical hex-encoded path structure for history archive files |
| [publish.pc.md](publish.pc.md) | History archive publishing of headers, transactions, and buckets |
| [publish_queue.pc.md](publish_queue.pc.md) | Persistent publish queue backed by SQLite for crash-safe queuing |
| [remote_archive.pc.md](remote_archive.pc.md) | Remote archive operations using configurable shell commands |
| [replay.pc.md](replay.pc.md) | Ledger replay via re-execution or metadata replay with hash verification |
| [verify.pc.md](verify.pc.md) | Cryptographic verification of header chains, buckets, and tx sets |
