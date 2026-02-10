#!/bin/bash
#
# Background wrapper for parallel testnet verification
# Runs verify-testnet.sh in the background with nohup so it survives disconnection
#

set -e

# Configuration - adjust these as needed
PARALLEL_JOBS="${PARALLEL_JOBS:-32}"       # Use all 32 cores
SEGMENT_SIZE="${SEGMENT_SIZE:-22000}"      # ~22k ledgers per segment (697k / 32 ~ 22k)
START_LEDGER="${START_LEDGER:-64}"
END_LEDGER="${END_LEDGER:-697279}"         # Current CDP edge

# Create timestamped results directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="${RESULTS_DIR:-/tmp/verify-testnet-${TIMESTAMP}}"
mkdir -p "$RESULTS_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

# Ensure binary is built
BINARY="${BINARY:-$REPO_DIR/target/release/henyey}"
if [ ! -f "$BINARY" ]; then
    echo "ERROR: Binary not found at $BINARY"
    echo "Run: cargo build --release -p henyey"
    exit 1
fi

echo "==========================================="
echo "Starting Background Parallel Verification"
echo "==========================================="
echo "Timestamp: $TIMESTAMP"
echo "Results directory: $RESULTS_DIR"
echo "Parallel jobs: $PARALLEL_JOBS"
echo "Segment size: $SEGMENT_SIZE ledgers"
echo "Ledger range: $START_LEDGER to $END_LEDGER"
echo ""

# Save configuration
cat > "$RESULTS_DIR/config.txt" << EOF
TIMESTAMP=$TIMESTAMP
PARALLEL_JOBS=$PARALLEL_JOBS
SEGMENT_SIZE=$SEGMENT_SIZE
START_LEDGER=$START_LEDGER
END_LEDGER=$END_LEDGER
BINARY=$BINARY
STARTED_AT=$(date)
EOF

# Create a script to check progress
cat > "$RESULTS_DIR/check-progress.sh" << 'PROGRESS_SCRIPT'
#!/bin/bash
RESULTS_DIR="$(dirname "${BASH_SOURCE[0]}")"

echo "=== Verification Progress ==="
echo ""

# Count segments
total=$(ls -1 "$RESULTS_DIR"/segment_*.result 2>/dev/null | wc -l)
success=$(grep -l "^SUCCESS" "$RESULTS_DIR"/segment_*.result 2>/dev/null | wc -l)
mismatch=$(grep -l "^MISMATCH" "$RESULTS_DIR"/segment_*.result 2>/dev/null | wc -l)
failed=$(grep -l "^FAILED" "$RESULTS_DIR"/segment_*.result 2>/dev/null | wc -l)

if [ -f "$RESULTS_DIR/segments.txt" ]; then
    expected=$(wc -l < "$RESULTS_DIR/segments.txt")
else
    expected="?"
fi

echo "Segments completed: $total / $expected"
echo "  Success: $success"
echo "  Mismatch: $mismatch"
echo "  Failed: $failed"
echo ""

# Check if still running
if pgrep -f "verify-testnet.sh" > /dev/null; then
    echo "Status: RUNNING"
    echo ""
    echo "Active processes:"
    ps aux | grep -E "verify-execution|verify-testnet" | grep -v grep | head -10
else
    echo "Status: COMPLETED (or not started)"
fi
echo ""

# Show latest activity
echo "=== Latest Completed Segments ==="
ls -t "$RESULTS_DIR"/segment_*.result 2>/dev/null | head -5 | while read f; do
    echo "$(basename $f): $(cat $f | cut -d' ' -f1-5)"
done
echo ""

# Show any failures
if [ "$failed" -gt 0 ]; then
    echo "=== FAILED Segments ==="
    grep -l "^FAILED" "$RESULTS_DIR"/segment_*.result 2>/dev/null | while read f; do
        echo "$(basename $f): $(cat $f)"
    done
fi

# Show summary if exists
if [ -f "$RESULTS_DIR/summary.txt" ]; then
    echo ""
    echo "=== Final Summary ==="
    cat "$RESULTS_DIR/summary.txt"
fi
PROGRESS_SCRIPT
chmod +x "$RESULTS_DIR/check-progress.sh"

# Create a script to watch live progress
cat > "$RESULTS_DIR/watch-progress.sh" << 'WATCH_SCRIPT'
#!/bin/bash
RESULTS_DIR="$(dirname "${BASH_SOURCE[0]}")"
watch -n 5 "$RESULTS_DIR/check-progress.sh"
WATCH_SCRIPT
chmod +x "$RESULTS_DIR/watch-progress.sh"

# Create a script to tail logs
cat > "$RESULTS_DIR/tail-logs.sh" << 'TAIL_SCRIPT'
#!/bin/bash
RESULTS_DIR="$(dirname "${BASH_SOURCE[0]}")"
tail -f "$RESULTS_DIR"/segment_*.log "$RESULTS_DIR/main.log" 2>/dev/null
TAIL_SCRIPT
chmod +x "$RESULTS_DIR/tail-logs.sh"

echo "Helper scripts created in $RESULTS_DIR:"
echo "  - check-progress.sh  : Show current progress"
echo "  - watch-progress.sh  : Live progress updates (every 5s)"
echo "  - tail-logs.sh       : Tail all log files"
echo ""

# Run the verification in background with nohup
echo "Starting verification in background..."
echo "Main log: $RESULTS_DIR/main.log"
echo ""

nohup env \
    BINARY="$BINARY" \
    PARALLEL_JOBS="$PARALLEL_JOBS" \
    SEGMENT_SIZE="$SEGMENT_SIZE" \
    START_LEDGER="$START_LEDGER" \
    END_LEDGER="$END_LEDGER" \
    RESULTS_DIR="$RESULTS_DIR" \
    "$SCRIPT_DIR/verify-testnet.sh" \
    > "$RESULTS_DIR/main.log" 2>&1 &

BG_PID=$!
echo $BG_PID > "$RESULTS_DIR/pid.txt"

echo "Background PID: $BG_PID"
echo "PID saved to: $RESULTS_DIR/pid.txt"
echo ""
echo "==========================================="
echo "Verification started in background!"
echo "==========================================="
echo ""
echo "To monitor progress:"
echo "  $RESULTS_DIR/check-progress.sh"
echo "  $RESULTS_DIR/watch-progress.sh"
echo ""
echo "To view logs:"
echo "  tail -f $RESULTS_DIR/main.log"
echo "  $RESULTS_DIR/tail-logs.sh"
echo ""
echo "To stop:"
echo "  kill $BG_PID"
echo ""
echo "Results will be saved to: $RESULTS_DIR"
