#!/bin/bash
# Watcher Monitor Script
# Periodically launches OpenCode to check watcher status and fix any hash mismatches

# Configuration
INTERVAL_MINUTES=${1:-30}  # Default: check every 30 minutes
LOG_DIR="/home/tomer/rs-stellar-core/logs"
MONITOR_LOG="$LOG_DIR/monitor.log"
PROJECT_DIR="/home/tomer/rs-stellar-core"
WATCHER_LOG="/tmp/rs-stellar-core.log"

# Create logs directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Prompt for OpenCode
PROMPT="Check on watcher status for rs-stellar-core testnet watcher.

Context:
- Watcher log is at: /tmp/rs-stellar-core.log
- Project directory: /home/tomer/rs-stellar-core
- The watcher runs with: ./target/release/rs-stellar-core run --watcher --testnet
- Git remote: origin (github.com:tomerweller/rs-stellar-core.git)

Tasks:
1. Check watcher status:
   - Is the process running? (pgrep -f rs-stellar-core)
   - Count ledgers closed: grep -c 'closed successfully' /tmp/rs-stellar-core.log
   - Count hash mismatches: grep -c 'Hash mismatch' /tmp/rs-stellar-core.log
   - Show recent closes: grep 'closed successfully' /tmp/rs-stellar-core.log | tail -5

2. If hash mismatches found:
   - Identify the problematic ledger(s) from the log (grep 'Hash mismatch' to find ledger numbers)
   - Use offline verify-execution to reproduce: cargo run --release --bin rs-stellar-core -- offline verify-execution --from <ledger> --to <ledger> --testnet --show-diff
   - Investigate the root cause by examining the diff output and relevant code
   - Implement a fix in the appropriate crate (stellar-core-tx, stellar-core-ledger, etc.)
   - Run tests to ensure fix doesn't break anything: cargo test -p stellar-core-tx --lib
   - Verify the fix resolves the mismatch: cargo run --release --bin rs-stellar-core -- offline verify-execution --from <ledger> --to <ledger> --testnet
   - IMPORTANT: Commit and push verified fixes:
     * git add <modified files>
     * git commit -m 'Fix <description of issue>' with Co-authored-by: GitHub Copilot <copilot@github.com>
     * git pull --rebase origin main (if push rejected)
     * git push origin main
   - Rebuild: cargo build --release
   - Restart watcher with new code:
     * pkill -f rs-stellar-core
     * sleep 2
     * cd /home/tomer/rs-stellar-core && nohup ./target/release/rs-stellar-core run --watcher --testnet > /tmp/rs-stellar-core.log 2>&1 &

3. If watcher is not running:
   - Check if it crashed (look for errors/panics in log: grep -i 'error\|panic' /tmp/rs-stellar-core.log | tail -20)
   - Restart it: cd /home/tomer/rs-stellar-core && nohup ./target/release/rs-stellar-core run --watcher --testnet > /tmp/rs-stellar-core.log 2>&1 &

4. Report summary of findings and actions taken, including:
   - Current ledger sequence
   - Total ledgers closed since last restart
   - Any mismatches found and fixed
   - Any commits pushed

Previous known issues fixed:
- RestoreFootprint rent fee calculation for hot archive entries (commit 9e3d6c4)
- Compilation error in replay.rs after rebase (commit ee0daa3)"

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$MONITOR_LOG"
}

run_check() {
    log_message "Starting watcher check..."
    
    # Quick pre-check before launching OpenCode
    if pgrep -f "rs-stellar-core" > /dev/null; then
        PROCESS_STATUS="RUNNING"
    else
        PROCESS_STATUS="NOT RUNNING"
    fi
    
    CLOSED_COUNT=$(grep -c "closed successfully" "$WATCHER_LOG" 2>/dev/null || echo 0)
    MISMATCH_COUNT=$(grep -c "Hash mismatch" "$WATCHER_LOG" 2>/dev/null || echo 0)
    
    log_message "Pre-check: Process=$PROCESS_STATUS, Ledgers=$CLOSED_COUNT, Mismatches=$MISMATCH_COUNT"
    
    # Launch OpenCode with the prompt
    log_message "Launching OpenCode for detailed check..."
    cd "$PROJECT_DIR"
    
    # Run opencode with the prompt (non-interactive mode)
    echo "$PROMPT" | opencode --dangerously-skip-permissions 2>&1 | tee -a "$LOG_DIR/opencode-$(date '+%Y%m%d-%H%M%S').log"
    
    log_message "OpenCode check completed"
}

# Main loop
log_message "=== Watcher Monitor Started ==="
log_message "Check interval: $INTERVAL_MINUTES minutes"
log_message "Project directory: $PROJECT_DIR"
log_message "Watcher log: $WATCHER_LOG"

while true; do
    run_check
    
    log_message "Sleeping for $INTERVAL_MINUTES minutes..."
    sleep $((INTERVAL_MINUTES * 60))
done
