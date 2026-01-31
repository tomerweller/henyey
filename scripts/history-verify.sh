#!/bin/bash
#
# History verification with auto-fix via OpenCode
#
# Runs verify-execution in batches on a specified network, persists progress,
# and invokes OpenCode to investigate and fix any header hash mismatches.
#
# Usage: ./scripts/history-verify.sh <testnet|mainnet>
#
# Environment variables:
#   BINARY       - Path to rs-stellar-core binary (default: ./target/release/rs-stellar-core)
#   BATCH_SIZE   - Override default batch size
#   START_LEDGER - Override starting ledger (ignores progress file)
#

set -euo pipefail

# --- Configuration ---
NETWORK="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="${BINARY:-$REPO_DIR/target/release/rs-stellar-core}"
PROGRESS_DIR="${HOME}/.rs-stellar-core"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Network-specific settings ---
case "$NETWORK" in
    testnet)
        DEFAULT_START_LEDGER=64
        DEFAULT_BATCH_SIZE=5000
        HORIZON_URL="https://horizon-testnet.stellar.org"
        ;;
    mainnet)
        DEFAULT_START_LEDGER=59501299
        DEFAULT_BATCH_SIZE=2500
        HORIZON_URL="https://horizon.stellar.org"
        ;;
    *)
        echo "Usage: $0 <testnet|mainnet>"
        echo ""
        echo "Runs verify-execution in batches, persisting progress to:"
        echo "  ~/.rs-stellar-core/history-verify-<network>.progress"
        echo ""
        echo "On header mismatch, invokes OpenCode to investigate and fix,"
        echo "then rebuilds and retries automatically."
        echo ""
        echo "Environment variables:"
        echo "  BINARY        - Path to rs-stellar-core binary"
        echo "  BATCH_SIZE    - Override default batch size"
        echo "  START_LEDGER  - Override starting ledger (ignores progress)"
        echo "  OPENCODE_MODEL - Model to use (default: github-copilot/claude-sonnet-4)"
        exit 1
        ;;
esac

BATCH_SIZE="${BATCH_SIZE:-$DEFAULT_BATCH_SIZE}"
PROGRESS_FILE="${PROGRESS_DIR}/history-verify-${NETWORK}.progress"

# --- Functions ---

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

get_latest_ledger() {
    local latest
    latest=$(curl -sf "${HORIZON_URL}/" | jq -r '.history_latest_ledger // empty')
    if [ -z "$latest" ]; then
        log_error "Could not fetch latest ledger from Horizon"
        exit 1
    fi
    echo "$latest"
}

# --- Initialization ---

# Check binary exists
if [ ! -x "$BINARY" ]; then
    log_error "Binary not found or not executable: $BINARY"
    echo "Run: cargo build --release -p rs-stellar-core"
    exit 1
fi

# Check opencode exists
if ! command -v opencode &> /dev/null; then
    log_error "opencode not found in PATH"
    exit 1
fi

# Create progress directory
mkdir -p "$PROGRESS_DIR"

# Determine starting ledger
if [ -n "${START_LEDGER:-}" ]; then
    # User override - ignore progress file
    CURRENT_LEDGER="$START_LEDGER"
    log_info "Starting from user-specified ledger $CURRENT_LEDGER (ignoring progress file)"
elif [ -f "$PROGRESS_FILE" ]; then
    # Resume from progress
    CURRENT_LEDGER=$(cat "$PROGRESS_FILE")
    log_info "Resuming from ledger $CURRENT_LEDGER (from progress file)"
else
    # Fresh start
    CURRENT_LEDGER="$DEFAULT_START_LEDGER"
    log_info "Starting fresh from ledger $CURRENT_LEDGER"
fi

# Get latest available ledger
log_info "Fetching latest $NETWORK ledger..."
LATEST_LEDGER=$(get_latest_ledger)

echo ""
echo "==========================================="
echo "History Verification - ${NETWORK^^}"
echo "==========================================="
echo "Binary:        $BINARY"
echo "Start ledger:  $CURRENT_LEDGER"
echo "Latest ledger: $LATEST_LEDGER"
echo "Batch size:    $BATCH_SIZE"
echo "Progress file: $PROGRESS_FILE"
echo "==========================================="
echo ""

# Check if already complete
if [ "$CURRENT_LEDGER" -ge "$LATEST_LEDGER" ]; then
    log_success "Already verified up to ledger $LATEST_LEDGER"
    echo "Nothing to do. Run again later when new ledgers are available."
    exit 0
fi

# --- Main verification loop ---

while [ "$CURRENT_LEDGER" -lt "$LATEST_LEDGER" ]; do
    END_LEDGER=$((CURRENT_LEDGER + BATCH_SIZE - 1))
    if [ "$END_LEDGER" -gt "$LATEST_LEDGER" ]; then
        END_LEDGER=$LATEST_LEDGER
    fi

    BATCH_COUNT=$((END_LEDGER - CURRENT_LEDGER + 1))
    log_info "Verifying ledgers $CURRENT_LEDGER - $END_LEDGER ($BATCH_COUNT ledgers)"

    # Run verify-execution with stop-on-error
    set +e
    OUTPUT=$("$BINARY" offline verify-execution \
        --${NETWORK} \
        --from "$CURRENT_LEDGER" \
        --to "$END_LEDGER" \
        --stop-on-error \
        --quiet 2>&1)
    EXIT_CODE=$?
    set -e

    if [ $EXIT_CODE -eq 0 ]; then
        # Success - move to next batch
        NEXT_LEDGER=$((END_LEDGER + 1))
        echo "$NEXT_LEDGER" > "$PROGRESS_FILE"
        log_success "Batch completed: ledgers $CURRENT_LEDGER - $END_LEDGER"
        echo ""
        CURRENT_LEDGER=$NEXT_LEDGER
    else
        # Parse failing ledger from "Header mismatch at ledger N" error
        FAILING_LEDGER=$(echo "$OUTPUT" | grep -oP 'Header mismatch at ledger \K\d+' || echo "")

        if [ -z "$FAILING_LEDGER" ]; then
            log_error "Unexpected failure (not a header mismatch)"
            echo ""
            echo "Output:"
            echo "$OUTPUT"
            exit 1
        fi

        log_error "Header mismatch at ledger $FAILING_LEDGER"
        echo ""

        # Build the reproduction command
        REPRO_CMD="$BINARY offline verify-execution --${NETWORK} --from $FAILING_LEDGER --to $FAILING_LEDGER --stop-on-error --show-diff"

        echo "Reproduction command:"
        echo "  $REPRO_CMD"
        echo ""
        log_info "Invoking OpenCode to investigate and fix..."
        echo ""

        # Invoke OpenCode with detailed prompt
        # Use heredoc to properly pass multi-line prompt
        PROMPT=$(cat <<'PROMPT_EOF'
Investigate and fix the header hash mismatch at ledger LEDGER_PLACEHOLDER on NETWORK_PLACEHOLDER.

## Reproduction Command

```bash
REPRO_CMD_PLACEHOLDER
```

## Instructions

1. Run the reproduction command to see the detailed diff output
2. Investigate why the header hash doesn't match. The mismatch could be in:
   - bucket_list_hash: Issue in bucket list computation (spills, merges, entry updates)
   - fee_pool: Issue in fee calculation or accumulation
   - tx_result_hash: Issue in transaction result computation
   - header_hash: Issue in header field computation
3. Find and fix the root cause in the appropriate crate (stellar-core-tx, stellar-core-ledger, stellar-core-bucket, etc.)
4. Add regression tests if applicable to prevent future regressions
5. Ensure `cargo test --all` passes
6. Ensure `cargo clippy --all` passes
7. Commit with a descriptive message
8. Push to remote

The script will automatically rebuild and retry verification after you're done.
PROMPT_EOF
)
        # Substitute placeholders
        PROMPT="${PROMPT//LEDGER_PLACEHOLDER/$FAILING_LEDGER}"
        PROMPT="${PROMPT//NETWORK_PLACEHOLDER/$NETWORK}"
        PROMPT="${PROMPT//REPRO_CMD_PLACEHOLDER/$REPRO_CMD}"

        # Run opencode with model specification
        opencode run -m "${OPENCODE_MODEL:-github-copilot/claude-sonnet-4}" "$PROMPT"

        echo ""
        log_info "OpenCode finished. Rebuilding binary..."
        (cd "$REPO_DIR" && cargo build --release -p rs-stellar-core)

        log_info "Retrying verification from ledger $CURRENT_LEDGER..."
        echo ""
        # Loop continues, will retry the same batch
    fi
done

echo ""
echo "==========================================="
log_success "Verification complete!"
echo "==========================================="
echo "Verified all ledgers from $DEFAULT_START_LEDGER to $LATEST_LEDGER"
echo ""
echo "Run again later to verify new ledgers as they become available."
