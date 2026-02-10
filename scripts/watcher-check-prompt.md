# Watcher Check Instructions

Check the henyey testnet watcher status and fix any issues found.

## Context

- Watcher log: `~/data/watcher/testnet-watcher.log`
- Project directory: `/home/tomer/henyey-2`
- Config file: `configs/watcher-testnet.toml`
- Watcher command: `./target/release/henyey run --config configs/watcher-testnet.toml`
- Git remote: `origin` (github.com:tomerweller/henyey.git)

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
   - Rebuild: `cargo build --release -p henyey`
   - Restart watcher:
     ```bash
     pkill -f "henyey.*run"
     sleep 2
     cd /home/tomer/henyey-2 && nohup ./target/release/henyey run --config configs/watcher-testnet.toml > ~/data/watcher/testnet-watcher.log 2>&1 &
     ```

### 2. Check Watcher Status

Run these diagnostic commands:
- Check if process is running: `pgrep -f "henyey.*run"`
- Check current ledger: `tail -50 ~/data/watcher/testnet-watcher.log | grep "Ledger closed" | tail -1`
- Count ledgers closed: `grep -c 'Ledger closed successfully' ~/data/watcher/testnet-watcher.log`
- Count hash mismatches: `grep -c 'Hash mismatch' ~/data/watcher/testnet-watcher.log`
- Compare with network: `curl -s "https://horizon-testnet.stellar.org/" | jq '.history_latest_ledger'`

### 3. If Hash Mismatches Found

1. Identify problematic ledger(s): `grep 'Hash mismatch' ~/data/watcher/testnet-watcher.log`
2. Reproduce with offline verify: `cargo run --release --bin henyey -- offline verify-execution --from <ledger> --to <ledger> --testnet --show-diff`
3. Investigate the diff output and relevant code
4. Implement fix in appropriate crate (henyey-tx, henyey-ledger, etc.)
5. Run tests: `cargo test -p henyey-tx --lib`
6. Verify fix resolves mismatch: `cargo run --release --bin henyey -- offline verify-execution --from <ledger> --to <ledger> --testnet`
7. Commit and push (include `Co-authored-by: GitHub Copilot <copilot@github.com>`)
8. Rebuild: `cargo build --release -p henyey`
9. Restart watcher:
   ```bash
   pkill -f "henyey.*run"
   sleep 2
   cd /home/tomer/henyey-2 && nohup ./target/release/henyey run --config configs/watcher-testnet.toml > ~/data/watcher/testnet-watcher.log 2>&1 &
   ```

### 4. If Watcher Not Running

1. Check for crash: `grep -iE 'error|panic|WARN' ~/data/watcher/testnet-watcher.log | tail -20`
2. Restart: 
   ```bash
   cd /home/tomer/henyey-2 && nohup ./target/release/henyey run --config configs/watcher-testnet.toml > ~/data/watcher/testnet-watcher.log 2>&1 &
   ```

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
- Debug eprintln statements removed from Soroban execution (commit 34f3daa)
