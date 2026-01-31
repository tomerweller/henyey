# Watcher Check Instructions

Check the rs-stellar-core testnet watcher status and fix any issues found.

## Context

- Watcher log: `/tmp/rs-stellar-core.log`
- Project directory: `/home/tomer/rs-stellar-core`
- Watcher command: `./target/release/rs-stellar-core run --watcher --testnet`
- Git remote: `origin` (github.com:tomerweller/rs-stellar-core.git)

## Tasks

### 1. Sync with Remote

1. Fetch latest changes: `git fetch origin main`
2. Check if there are new commits:
   ```bash
   LOCAL_HEAD=$(git rev-parse HEAD)
   REMOTE_HEAD=$(git rev-parse origin/main)
   echo "Local: $LOCAL_HEAD, Remote: $REMOTE_HEAD"
   ```
3. If there are new commits from remote:
   - Pull changes: `git pull origin main`
   - Rebuild: `cargo build --release`
   - Restart watcher:
     ```bash
     pkill -f "rs-stellar-core.*watcher"
     sleep 2
     cd /home/tomer/rs-stellar-core && nohup ./target/release/rs-stellar-core run --watcher --testnet > /tmp/rs-stellar-core.log 2>&1 &
     ```

### 2. Check Watcher Status

Run these diagnostic commands:
- Check if process is running: `pgrep -f "rs-stellar-core.*watcher"`
- Count ledgers closed: `grep -c 'closed successfully' /tmp/rs-stellar-core.log`
- Count hash mismatches: `grep -c 'Hash mismatch' /tmp/rs-stellar-core.log`
- Show recent closes: `grep 'closed successfully' /tmp/rs-stellar-core.log | tail -5`

### 3. If Hash Mismatches Found

1. Identify problematic ledger(s): `grep 'Hash mismatch' /tmp/rs-stellar-core.log`
2. Reproduce with offline verify: `cargo run --release --bin rs-stellar-core -- offline verify-execution --from <ledger> --to <ledger> --testnet --show-diff`
3. Investigate the diff output and relevant code
4. Implement fix in appropriate crate (stellar-core-tx, stellar-core-ledger, etc.)
5. Run tests: `cargo test -p stellar-core-tx --lib`
6. Verify fix resolves mismatch: `cargo run --release --bin rs-stellar-core -- offline verify-execution --from <ledger> --to <ledger> --testnet`
7. Commit and push (include `Co-authored-by: GitHub Copilot <copilot@github.com>`)
8. Rebuild: `cargo build --release`
9. Restart watcher:
   ```bash
   pkill -f "rs-stellar-core.*watcher"
   sleep 2
   cd /home/tomer/rs-stellar-core && nohup ./target/release/rs-stellar-core run --watcher --testnet > /tmp/rs-stellar-core.log 2>&1 &
   ```

### 4. If Watcher Not Running

1. Check for crash: `grep -i 'error\|panic' /tmp/rs-stellar-core.log | tail -20`
2. Restart: `cd /home/tomer/rs-stellar-core && nohup ./target/release/rs-stellar-core run --watcher --testnet > /tmp/rs-stellar-core.log 2>&1 &`

### 5. Report Summary

Include:
- Whether remote sync was needed
- Current ledger sequence
- Total ledgers closed since restart
- Any mismatches found and fixed
- Any commits pushed

## Previous Known Issues Fixed

- RestoreFootprint rent fee calculation for hot archive entries (commit 9e3d6c4)
- Compilation error in replay.rs after rebase (commit ee0daa3)
