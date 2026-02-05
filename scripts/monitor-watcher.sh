#!/bin/bash
# Watcher Monitor Script
# Periodically launches OpenCode to check watcher status and fix any hash mismatches

set -euo pipefail

# Configuration
INTERVAL_MINUTES=${1:-30}  # Default: check every 30 minutes
LOG_DIR="$HOME/data/watcher-monitor"
MONITOR_LOG="$LOG_DIR/monitor.log"
PROJECT_DIR="/home/tomer/rs-stellar-core-2"
WATCHER_LOG="$HOME/data/watcher/testnet-watcher.log"
PROMPT_FILE="$PROJECT_DIR/scripts/watcher-check-prompt.md"
MODEL="github-copilot/claude-opus-4.5"

# OpenCode settings - increase bash timeout to 4 hours (14400000ms) for cargo builds and debugging
export OPENCODE_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS=14400000

# Create logs directory if it doesn't exist
mkdir -p "$LOG_DIR"

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$MONITOR_LOG"
}

run_check() {
    log_message "Starting watcher check..."
    cd "$PROJECT_DIR"
    
    OPENCODE_LOG="$LOG_DIR/opencode-$(date '+%Y%m%d-%H%M%S').log"
    
    # Check if prompt file exists
    if [[ ! -f "$PROMPT_FILE" ]]; then
        log_message "ERROR: Prompt file not found at $PROMPT_FILE"
        return 1
    fi
    
    # Run opencode with the prompt file
    # Use timeout to prevent hanging indefinitely (240 minutes to allow for builds and fixes)
    # Note: OPENCODE_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS is set above to allow long cargo builds
    # Note: message must come BEFORE --file flag to avoid being interpreted as a file path
    log_message "Running OpenCode with model $MODEL..."
    timeout 14400 opencode run \
        --model "$MODEL" \
        "Execute the watcher check instructions from the attached file" \
        --file "$PROMPT_FILE" \
        2>&1 | tee -a "$OPENCODE_LOG" || {
        log_message "WARNING: OpenCode timed out or failed (exit code: $?)"
    }
    
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
