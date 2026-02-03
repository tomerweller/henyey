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
#   CACHE_DIR    - Override cache directory
#   OPENCODE_MODEL - Model to use (default: github-copilot/claude-opus-4.5)
#

set -euo pipefail

# --- Configuration ---
NETWORK="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="${BINARY:-$REPO_DIR/target/release/rs-stellar-core}"
PROGRESS_DIR="${HOME}/.rs-stellar-core"

# Extended timeout for bash commands in OpenCode (4 hours for cargo builds)
export OPENCODE_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS=14400000

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
        DEFAULT_CACHE_DIR="${HOME}/data/rs-stellar-core/cache"
        HORIZON_URL="https://horizon-testnet.stellar.org"
        ;;
    mainnet)
        DEFAULT_START_LEDGER=59501299
        DEFAULT_BATCH_SIZE=10000
        DEFAULT_CACHE_DIR="${HOME}/data/rs-stellar-core/cache"
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
        echo "  CACHE_DIR     - Override cache directory"
        echo "  OPENCODE_MODEL - Model to use (default: github-copilot/claude-opus-4.5)"
        exit 1
        ;;
esac

BATCH_SIZE="${BATCH_SIZE:-$DEFAULT_BATCH_SIZE}"
CACHE_DIR="${CACHE_DIR:-$DEFAULT_CACHE_DIR}"
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

# Create cache directory if it doesn't exist
mkdir -p "$CACHE_DIR"

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
echo "Cache dir:     $CACHE_DIR"
echo "Progress file: $PROGRESS_FILE"
echo "OpenCode model: ${OPENCODE_MODEL:-github-copilot/claude-opus-4.5}"
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
        --cache-dir "$CACHE_DIR" \
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
        REPRO_CMD="$BINARY offline verify-execution --${NETWORK} --from $FAILING_LEDGER --to $FAILING_LEDGER --cache-dir $CACHE_DIR --stop-on-error --show-diff"

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

1. **Reproduce**: Run the reproduction command to see the detailed diff output

2. **Classify the mismatch**: Determine the type:
   - Transaction execution mismatch (e.g., wrong operation result, OpTooManySubentries, etc.)
   - Ledger entry state mismatch (e.g., wrong balance, flags, liabilities)
   - Bucket list / header-only mismatch (meta differences but execution correct)
   - Soroban/InvokeHostFunction issue (host function execution divergence)

3. **Investigate**: Find the root cause in the appropriate crate:
   - `stellar-core-tx` - Transaction/operation execution (ChangeTrust, PathPayment, ManageOffer, etc.)
   - `stellar-core-ledger` - Ledger close, fee pool, header computation
   - `stellar-core-bucket` - Bucket list computation
   - `stellar-core-soroban` - Soroban host function execution

4. **Fix**: Implement the fix with clear comments explaining the bug

5. **Add regression tests**: Add unit tests in the relevant module to prevent future regressions

6. **Full test suite**: Run `cargo test --all` and ensure ALL tests pass

7. **Clippy**: Run `cargo clippy --all` and fix any warnings

8. **Verify fix**: Re-run the reproduction command to confirm the mismatch is resolved

9. **Check for regressions**: Verify a few ledgers before the failing one still pass:
   ```bash
   BINARY_PLACEHOLDER offline verify-execution --NETWORK_PLACEHOLDER --from PREV_LEDGER_PLACEHOLDER --to PREV_LEDGER_PLACEHOLDER --cache-dir CACHE_DIR_PLACEHOLDER
   ```

10. **Commit**: Create a descriptive commit message explaining:
    - What was broken (e.g., "ChangeTrust missing OpTooManySubentries check")
    - Why it was broken (e.g., "subentries limit not enforced before creating trustline")
    - How it was fixed (e.g., "added check for ACCOUNT_SUBENTRY_LIMIT before trustline creation")
    - Which ledger exposed the bug (e.g., "Bug discovered at mainnet ledger 54003784")

11. **Push**: Push to remote with `git push`

## Known Bug Patterns (for reference)

These bugs have been fixed previously - similar patterns may appear:

- **PathPayment liabilities ordering**: `cross_offer_v10` must release offer liabilities BEFORE calculating `can_sell_at_most`/`can_buy_at_most`. The seller's available balance depends on liabilities being released first.

- **ChangeTrust subentries limit**: Must check `num_sub_entries + multiplier > ACCOUNT_SUBENTRY_LIMIT` (1000) before creating new trustlines. Pool share trustlines count as 2 subentries.

- **ManageOffer subentries**: Similar limit checks required when creating new offers.

- **Sponsorship accounting**: `num_sponsoring`/`num_sponsored` counters must be updated correctly when creating/deleting sponsored entries.

- **Liabilities calculation**: Available balance = balance - selling_liabilities. Available limit = limit - balance - buying_liabilities.

## Important Notes

- The verification script will automatically rebuild and retry after you finish
- Always run the full test suite (`cargo test --all`) before committing
- If you cannot fix an issue after thorough investigation, document what you found and exit
- Prefer minimal, targeted fixes over broad refactoring
- Check the C++ stellar-core reference in `.upstream-v25/` for expected behavior
PROMPT_EOF
)
        # Substitute placeholders
        PROMPT="${PROMPT//LEDGER_PLACEHOLDER/$FAILING_LEDGER}"
        PROMPT="${PROMPT//NETWORK_PLACEHOLDER/$NETWORK}"
        PROMPT="${PROMPT//REPRO_CMD_PLACEHOLDER/$REPRO_CMD}"
        PROMPT="${PROMPT//BINARY_PLACEHOLDER/$BINARY}"
        PROMPT="${PROMPT//CACHE_DIR_PLACEHOLDER/$CACHE_DIR}"
        # Calculate previous ledger for regression check
        PREV_LEDGER=$((FAILING_LEDGER - 1))
        PROMPT="${PROMPT//PREV_LEDGER_PLACEHOLDER/$PREV_LEDGER}"

        # Run opencode with model specification and timeout (4 hours)
        # Use unbuffered output to show progress in real-time
        set +e
        echo ""
        echo "==========================================="
        echo "      OpenCode Investigation Started"
        echo "==========================================="
        echo ""
        echo "Model: ${OPENCODE_MODEL:-github-copilot/claude-opus-4.5}"
        echo "Timeout: 4 hours"
        echo ""
        echo "--- OpenCode Output Begin ---"
        echo ""
        
        # Run with unbuffered output (-u flag for stdbuf where available)
        # Use script command to preserve output in terminal and capture it
        OPENCODE_LOG="${PROGRESS_DIR}/opencode-${NETWORK}-${FAILING_LEDGER}.log"
        if command -v stdbuf &> /dev/null; then
            timeout 14400 stdbuf -oL -eL opencode run -m "${OPENCODE_MODEL:-github-copilot/claude-opus-4.5}" "$PROMPT" 2>&1 | tee "$OPENCODE_LOG"
            OPENCODE_EXIT=${PIPESTATUS[0]}
        else
            timeout 14400 opencode run -m "${OPENCODE_MODEL:-github-copilot/claude-opus-4.5}" "$PROMPT" 2>&1 | tee "$OPENCODE_LOG"
            OPENCODE_EXIT=${PIPESTATUS[0]}
        fi
        set -e
        
        echo ""
        echo "--- OpenCode Output End ---"
        echo ""
        echo "Full log saved to: $OPENCODE_LOG"
        echo ""

        if [ $OPENCODE_EXIT -eq 124 ]; then
            log_warn "OpenCode timed out after 4 hours"
        elif [ $OPENCODE_EXIT -ne 0 ]; then
            log_warn "OpenCode exited with code $OPENCODE_EXIT"
        else
            log_success "OpenCode completed successfully"
        fi

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
