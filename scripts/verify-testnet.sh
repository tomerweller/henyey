#!/bin/bash
#
# Parallel testnet verification script
# Runs verify-execution in parallel segments across the entire testnet history
#

set -e

# Configuration
BINARY="${BINARY:-./target/release/rs-stellar-core}"
PARALLEL_JOBS="${PARALLEL_JOBS:-4}"      # Number of parallel verifications
SEGMENT_SIZE="${SEGMENT_SIZE:-10000}"    # Ledgers per segment
START_LEDGER="${START_LEDGER:-64}"       # First ledger (must be > 0, aligned to checkpoint)
END_LEDGER="${END_LEDGER:-}"             # Empty = latest available
RESULTS_DIR="${RESULTS_DIR:-/tmp/verify-testnet-results}"
LOG_FILE="${RESULTS_DIR}/verification.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create results directory
mkdir -p "$RESULTS_DIR"

echo "==========================================="
echo "Testnet Full Verification"
echo "==========================================="
echo "Binary: $BINARY"
echo "Parallel jobs: $PARALLEL_JOBS"
echo "Segment size: $SEGMENT_SIZE ledgers"
echo "Results dir: $RESULTS_DIR"
echo "Stats: ledgers/tx verified, tx match/mismatch, ledger tx/header mismatches, bucketlist-only vs tx-only"
echo ""

# Get the latest testnet ledger if END_LEDGER not specified
if [ -z "$END_LEDGER" ]; then
    echo "Fetching latest testnet ledger..."
    END_LEDGER=$(curl -s "https://horizon-testnet.stellar.org/" | jq -r '.history_latest_ledger // empty')
    if [ -z "$END_LEDGER" ]; then
        echo "ERROR: Could not fetch latest ledger from Horizon"
        exit 1
    fi
fi

echo "Ledger range: $START_LEDGER to $END_LEDGER"
TOTAL_LEDGERS=$((END_LEDGER - START_LEDGER))
NUM_SEGMENTS=$(( (TOTAL_LEDGERS + SEGMENT_SIZE - 1) / SEGMENT_SIZE ))
echo "Total segments: $NUM_SEGMENTS"
echo ""

# Function to run a single segment
run_segment() {
    local seg_num=$1
    local seg_start=$2
    local seg_end=$3
    local seg_log="${RESULTS_DIR}/segment_${seg_num}.log"
    local seg_result="${RESULTS_DIR}/segment_${seg_num}.result"

    # Skip if a prior result exists (SUCCESS or MISMATCH)
    if [ -f "$seg_result" ]; then
        local status=$(cut -d' ' -f1 "$seg_result")
        if [ "$status" = "SUCCESS" ] || [ "$status" = "MISMATCH" ]; then
            echo "Segment $seg_num already has a result ($status), skipping..."
            return 0
        fi
    fi

    echo "Starting segment $seg_num: ledgers $seg_start-$seg_end"

    # Run verification in quiet mode (suppress tracing logs too)
    local start_time=$(date +%s)
    if RUST_LOG=error "$BINARY" offline verify-execution --testnet --from "$seg_start" --to "$seg_end" --quiet > "$seg_log" 2>&1; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))

        # Extract results from output
        local verified=$(grep "Ledgers verified:" "$seg_log" | awk '{print $3}' || echo "0")
        local matched=$(grep "Phase 2 execution matched:" "$seg_log" | awk '{print $5}' || echo "0")
        local mismatched=$(grep "Phase 2 execution mismatched:" "$seg_log" | awk '{print $5}' || echo "0")
        local ledger_tx_mismatches=$(grep "Ledgers with tx mismatches:" "$seg_log" | awk '{print $5}' || echo "0")
        local ledger_header_mismatches=$(grep "Ledgers with header mismatches:" "$seg_log" | awk '{print $5}' || echo "0")
        local ledger_both_mismatches=$(grep "Ledgers with tx+header mismatches:" "$seg_log" | awk '{print $5}' || echo "0")
        local bucketlist_only=0
        local tx_only=0
        if [ "$ledger_header_mismatches" -ge "$ledger_both_mismatches" ]; then
            bucketlist_only=$((ledger_header_mismatches - ledger_both_mismatches))
        fi
        if [ "$ledger_tx_mismatches" -ge "$ledger_both_mismatches" ]; then
            tx_only=$((ledger_tx_mismatches - ledger_both_mismatches))
        fi

        if [ "$mismatched" = "0" ]; then
            echo "SUCCESS segment=$seg_num start=$seg_start end=$seg_end verified=$verified matched=$matched mismatched=$mismatched ledger_tx_mismatches=$ledger_tx_mismatches ledger_header_mismatches=$ledger_header_mismatches ledger_both_mismatches=$ledger_both_mismatches bucketlist_only=$bucketlist_only tx_only=$tx_only duration=${duration}s" > "$seg_result"
            echo -e "${GREEN}Segment $seg_num PASSED${NC} ($verified ledgers, ${duration}s)"
        else
            echo "MISMATCH segment=$seg_num start=$seg_start end=$seg_end verified=$verified matched=$matched mismatched=$mismatched ledger_tx_mismatches=$ledger_tx_mismatches ledger_header_mismatches=$ledger_header_mismatches ledger_both_mismatches=$ledger_both_mismatches bucketlist_only=$bucketlist_only tx_only=$tx_only duration=${duration}s" > "$seg_result"
            echo -e "${YELLOW}Segment $seg_num completed with $mismatched mismatches${NC}"
        fi
    else
        local exit_code=$?
        echo "FAILED segment=$seg_num start=$seg_start end=$seg_end exit_code=$exit_code" > "$seg_result"
        echo -e "${RED}Segment $seg_num FAILED${NC} (exit code $exit_code)"
    fi
}

export -f run_segment
export BINARY RESULTS_DIR RED GREEN YELLOW NC

# Generate segment list
SEGMENTS_FILE="${RESULTS_DIR}/segments.txt"
> "$SEGMENTS_FILE"
seg_num=1
seg_start=$START_LEDGER
while [ $seg_start -lt $END_LEDGER ]; do
    seg_end=$((seg_start + SEGMENT_SIZE - 1))
    if [ $seg_end -gt $END_LEDGER ]; then
        seg_end=$END_LEDGER
    fi
    echo "$seg_num $seg_start $seg_end" >> "$SEGMENTS_FILE"
    seg_start=$((seg_end + 1))
    seg_num=$((seg_num + 1))
done

echo "Starting parallel verification with $PARALLEL_JOBS jobs..."
echo "Progress will be logged to: $RESULTS_DIR/segment_*.log"
echo ""

# Run segments in parallel using GNU parallel or xargs
START_TIME=$(date +%s)

if command -v parallel &> /dev/null; then
    # Use GNU parallel if available
    cat "$SEGMENTS_FILE" | parallel -j "$PARALLEL_JOBS" --colsep ' ' run_segment {1} {2} {3}
else
    # Fallback to xargs
    cat "$SEGMENTS_FILE" | xargs -P "$PARALLEL_JOBS" -L 1 bash -c 'run_segment "$@"' _
fi

END_TIME=$(date +%s)
TOTAL_DURATION=$((END_TIME - START_TIME))

# Summarize results
echo ""
echo "==========================================="
echo "Verification Summary"
echo "==========================================="

TOTAL_SUCCESS=0
TOTAL_MISMATCH=0
TOTAL_FAILED=0
TOTAL_VERIFIED=0
TOTAL_TX_MATCHED=0
TOTAL_TX_MISMATCHED=0
TOTAL_LEDGER_TX_MISMATCHES=0
TOTAL_LEDGER_HEADER_MISMATCHES=0
TOTAL_LEDGER_BOTH_MISMATCHES=0
TOTAL_BUCKETLIST_ONLY=0
TOTAL_TX_ONLY=0

for result_file in "$RESULTS_DIR"/segment_*.result; do
    if [ -f "$result_file" ]; then
        status=$(cut -d' ' -f1 "$result_file")
        case $status in
            SUCCESS)
                TOTAL_SUCCESS=$((TOTAL_SUCCESS + 1))
                verified=$(grep -o 'verified=[0-9]*' "$result_file" | cut -d= -f2)
                matched=$(grep -o 'matched=[0-9]*' "$result_file" | head -1 | cut -d= -f2)
                ledger_tx_mismatches=$(grep -o 'ledger_tx_mismatches=[0-9]*' "$result_file" | cut -d= -f2)
                ledger_header_mismatches=$(grep -o 'ledger_header_mismatches=[0-9]*' "$result_file" | cut -d= -f2)
                ledger_both_mismatches=$(grep -o 'ledger_both_mismatches=[0-9]*' "$result_file" | cut -d= -f2)
                bucketlist_only=$(grep -o 'bucketlist_only=[0-9]*' "$result_file" | cut -d= -f2)
                tx_only=$(grep -o 'tx_only=[0-9]*' "$result_file" | cut -d= -f2)
                ledger_tx_mismatches=${ledger_tx_mismatches:-0}
                ledger_header_mismatches=${ledger_header_mismatches:-0}
                ledger_both_mismatches=${ledger_both_mismatches:-0}
                bucketlist_only=${bucketlist_only:-0}
                tx_only=${tx_only:-0}
                TOTAL_VERIFIED=$((TOTAL_VERIFIED + verified))
                TOTAL_TX_MATCHED=$((TOTAL_TX_MATCHED + matched))
                TOTAL_LEDGER_TX_MISMATCHES=$((TOTAL_LEDGER_TX_MISMATCHES + ledger_tx_mismatches))
                TOTAL_LEDGER_HEADER_MISMATCHES=$((TOTAL_LEDGER_HEADER_MISMATCHES + ledger_header_mismatches))
                TOTAL_LEDGER_BOTH_MISMATCHES=$((TOTAL_LEDGER_BOTH_MISMATCHES + ledger_both_mismatches))
                TOTAL_BUCKETLIST_ONLY=$((TOTAL_BUCKETLIST_ONLY + bucketlist_only))
                TOTAL_TX_ONLY=$((TOTAL_TX_ONLY + tx_only))
                ;;
            MISMATCH)
                TOTAL_MISMATCH=$((TOTAL_MISMATCH + 1))
                verified=$(grep -o 'verified=[0-9]*' "$result_file" | cut -d= -f2)
                matched=$(grep -o 'matched=[0-9]*' "$result_file" | head -1 | cut -d= -f2)
                mismatched=$(grep -o 'mismatched=[0-9]*' "$result_file" | tail -1 | cut -d= -f2)
                ledger_tx_mismatches=$(grep -o 'ledger_tx_mismatches=[0-9]*' "$result_file" | cut -d= -f2)
                ledger_header_mismatches=$(grep -o 'ledger_header_mismatches=[0-9]*' "$result_file" | cut -d= -f2)
                ledger_both_mismatches=$(grep -o 'ledger_both_mismatches=[0-9]*' "$result_file" | cut -d= -f2)
                bucketlist_only=$(grep -o 'bucketlist_only=[0-9]*' "$result_file" | cut -d= -f2)
                tx_only=$(grep -o 'tx_only=[0-9]*' "$result_file" | cut -d= -f2)
                ledger_tx_mismatches=${ledger_tx_mismatches:-0}
                ledger_header_mismatches=${ledger_header_mismatches:-0}
                ledger_both_mismatches=${ledger_both_mismatches:-0}
                bucketlist_only=${bucketlist_only:-0}
                tx_only=${tx_only:-0}
                TOTAL_VERIFIED=$((TOTAL_VERIFIED + verified))
                TOTAL_TX_MATCHED=$((TOTAL_TX_MATCHED + matched))
                TOTAL_TX_MISMATCHED=$((TOTAL_TX_MISMATCHED + mismatched))
                TOTAL_LEDGER_TX_MISMATCHES=$((TOTAL_LEDGER_TX_MISMATCHES + ledger_tx_mismatches))
                TOTAL_LEDGER_HEADER_MISMATCHES=$((TOTAL_LEDGER_HEADER_MISMATCHES + ledger_header_mismatches))
                TOTAL_LEDGER_BOTH_MISMATCHES=$((TOTAL_LEDGER_BOTH_MISMATCHES + ledger_both_mismatches))
                TOTAL_BUCKETLIST_ONLY=$((TOTAL_BUCKETLIST_ONLY + bucketlist_only))
                TOTAL_TX_ONLY=$((TOTAL_TX_ONLY + tx_only))
                ;;
            FAILED)
                TOTAL_FAILED=$((TOTAL_FAILED + 1))
                ;;
        esac
    fi
done

echo "Total segments: $NUM_SEGMENTS"
echo -e "  ${GREEN}Passed:${NC} $TOTAL_SUCCESS"
echo -e "  ${YELLOW}With mismatches:${NC} $TOTAL_MISMATCH"
echo -e "  ${RED}Failed:${NC} $TOTAL_FAILED"
echo ""
echo "Total ledgers verified: $TOTAL_VERIFIED"
echo "Total transactions matched: $TOTAL_TX_MATCHED"
echo "Total transactions mismatched: $TOTAL_TX_MISMATCHED"
echo "Total ledgers with tx mismatches: $TOTAL_LEDGER_TX_MISMATCHES"
echo "Total ledgers with header mismatches: $TOTAL_LEDGER_HEADER_MISMATCHES"
echo "Total ledgers with tx+header mismatches: $TOTAL_LEDGER_BOTH_MISMATCHES"
echo "Ledger mismatch breakdown: bucketlist-only=$TOTAL_BUCKETLIST_ONLY, tx-only=$TOTAL_TX_ONLY, both=$TOTAL_LEDGER_BOTH_MISMATCHES"
echo ""
echo "Total duration: ${TOTAL_DURATION}s ($(( TOTAL_DURATION / 60 ))m $(( TOTAL_DURATION % 60 ))s)"

if [ $TOTAL_VERIFIED -gt 0 ]; then
    RATE=$(( TOTAL_VERIFIED * 60 / TOTAL_DURATION ))
    echo "Average rate: $RATE ledgers/minute"
fi

# Save summary
{
    echo "Verification completed at: $(date)"
    echo "Ledger range: $START_LEDGER to $END_LEDGER"
    echo "Segments: $NUM_SEGMENTS (success=$TOTAL_SUCCESS, mismatch=$TOTAL_MISMATCH, failed=$TOTAL_FAILED)"
    echo "Ledgers verified: $TOTAL_VERIFIED"
    echo "Transactions matched: $TOTAL_TX_MATCHED"
    echo "Transactions mismatched: $TOTAL_TX_MISMATCHED"
    echo "Ledgers with tx mismatches: $TOTAL_LEDGER_TX_MISMATCHES"
    echo "Ledgers with header mismatches: $TOTAL_LEDGER_HEADER_MISMATCHES"
    echo "Ledgers with tx+header mismatches: $TOTAL_LEDGER_BOTH_MISMATCHES"
    echo "Ledger mismatch breakdown: bucketlist-only=$TOTAL_BUCKETLIST_ONLY, tx-only=$TOTAL_TX_ONLY, both=$TOTAL_LEDGER_BOTH_MISMATCHES"
    echo "Duration: ${TOTAL_DURATION}s"
} > "${RESULTS_DIR}/summary.txt"

echo ""
echo "Results saved to: $RESULTS_DIR"

# Exit with error if any failures
if [ $TOTAL_FAILED -gt 0 ]; then
    echo -e "${RED}Some segments failed! Check logs in $RESULTS_DIR${NC}"
    exit 1
fi

if [ $TOTAL_TX_MISMATCHED -gt 0 ]; then
    echo -e "${YELLOW}Some transactions had mismatches (order-independent meta comparison is used)${NC}"
fi

echo -e "${GREEN}Verification complete!${NC}"
