#!/usr/bin/env bash
#
# Smoke-test Stellar RPC endpoints using the stellar CLI + curl/jq.
# Defaults to public testnet; override with --rpc-url / --network-passphrase.
#
set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
RPC_URL=""
NETWORK_PASSPHRASE=""
CUSTOM_RPC=false
PASS_COUNT=0
FAIL_COUNT=0
FAILURES=()
ALICE_KEY="rpctest-alice-$$"
BOB_KEY="rpctest-bob-$$"

# ── Argument parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc-url)            RPC_URL="$2"; CUSTOM_RPC=true; shift 2 ;;
    --network-passphrase) NETWORK_PASSPHRASE="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [--rpc-url URL] [--network-passphrase PASSPHRASE]"
      exit 0 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

# When using a custom RPC URL, --network-passphrase is required by the CLI.
# When no custom URL is given, we use --network testnet and the CLI resolves everything.
if $CUSTOM_RPC; then
  if [[ -z "$NETWORK_PASSPHRASE" ]]; then
    NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
    echo "NOTE: No --network-passphrase given, defaulting to testnet passphrase."
  fi
  RPC_URL_FOR_CURL="$RPC_URL"
  # CLI args for stellar commands when using a custom RPC
  CLI_NET_ARGS=(--rpc-url "$RPC_URL" --network-passphrase "$NETWORK_PASSPHRASE")
else
  RPC_URL_FOR_CURL="https://soroban-testnet.stellar.org"
  CLI_NET_ARGS=(--network testnet)
fi

# ── Helpers ──────────────────────────────────────────────────────────────────
pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo "[PASS] $1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  FAILURES+=("$1")
  if [[ -n "${2:-}" ]]; then
    echo "[FAIL] $1 - $2"
  else
    echo "[FAIL] $1"
  fi
}

# JSON-RPC helper — prints response body, returns 0/1 based on HTTP success.
rpc_call() {
  local method="$1"
  local params="${2:-null}"
  curl -sf -X POST "$RPC_URL_FOR_CURL" \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}"
}

cleanup() {
  echo ""
  echo "── Cleanup ────────────────────────────────────────────────────────────"
  stellar keys rm "$ALICE_KEY" 2>/dev/null && echo "Removed key $ALICE_KEY" || true
  stellar keys rm "$BOB_KEY"   2>/dev/null && echo "Removed key $BOB_KEY"   || true
}
trap cleanup EXIT

# ── Preflight checks ────────────────────────────────────────────────────────
echo "── Preflight ──────────────────────────────────────────────────────────"
for cmd in stellar curl jq; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: '$cmd' not found in PATH. Install it and retry."
    exit 1
  fi
done
echo "All prerequisites found."
echo "RPC URL: $RPC_URL_FOR_CURL"
echo ""

# ── 1. JSON-RPC error handling ───────────────────────────────────────────────
echo "── JSON-RPC error handling ──────────────────────────────────────────"

# Unknown method
if resp=$(rpc_call nonExistentMethod) && \
   ERR_CODE=$(echo "$resp" | jq -e '.error.code') && [[ "$ERR_CODE" == "-32601" ]]; then
  pass "error: unknown method (code=$ERR_CODE)"
else
  fail "error: unknown method" "expected .error.code == -32601, got: $(echo "$resp" | jq -c '.error // empty')"
fi

# Invalid params for getLedgerEntries (empty keys array)
# Some implementations return -32602 (invalid params), others -32603 (internal error).
if resp=$(rpc_call getLedgerEntries '{"keys":[]}') && \
   ERR_CODE=$(echo "$resp" | jq -e '.error.code') && \
   [[ "$ERR_CODE" == "-32602" || "$ERR_CODE" == "-32603" ]]; then
  pass "error: getLedgerEntries empty keys (code=$ERR_CODE)"
else
  fail "error: getLedgerEntries empty keys" "expected .error.code == -32602 or -32603, got: $(echo "$resp" | jq -c '.error // empty')"
fi

# Invalid params for getEvents (missing startLedger)
if resp=$(rpc_call getEvents '{"filters":[]}') && \
   ERR_CODE=$(echo "$resp" | jq -e '.error.code') && [[ "$ERR_CODE" == "-32602" ]]; then
  pass "error: getEvents missing startLedger (code=$ERR_CODE)"
else
  fail "error: getEvents missing startLedger" "expected .error.code == -32602, got: $(echo "$resp" | jq -c '.error // empty')"
fi

echo ""

# ── 2. Direct JSON-RPC endpoint tests ───────────────────────────────────────
echo "── JSON-RPC endpoints ─────────────────────────────────────────────────"

HEALTH_LATEST_LEDGER=""
HEALTH_OLDEST_LEDGER=""

# getHealth
if resp=$(rpc_call getHealth) && echo "$resp" | jq -e '.result.status' &>/dev/null; then
  HEALTH_LATEST_LEDGER=$(echo "$resp" | jq -r '.result.latestLedger // empty')
  HEALTH_OLDEST_LEDGER=$(echo "$resp" | jq -r '.result.oldestLedger // empty')
  ok=true
  if [[ -n "$HEALTH_LATEST_LEDGER" ]] && [[ "$HEALTH_LATEST_LEDGER" -gt 0 ]]; then :; else
    fail "getHealth" "latestLedger missing or not > 0"; ok=false
  fi
  if [[ -n "$HEALTH_OLDEST_LEDGER" ]] && [[ "$HEALTH_OLDEST_LEDGER" -gt 0 ]]; then :; else
    fail "getHealth" "oldestLedger missing or not > 0"; ok=false
  fi
  RETENTION=$(echo "$resp" | jq -r '.result.ledgerRetentionWindow // empty')
  if [[ -n "$RETENTION" ]] && echo "$RETENTION" | grep -qE '^[0-9]+$'; then :; else
    fail "getHealth" "ledgerRetentionWindow not a number"; ok=false
  fi
  if $ok; then
    pass "getHealth (latest=$HEALTH_LATEST_LEDGER, oldest=$HEALTH_OLDEST_LEDGER, retention=$RETENTION)"
  fi
else
  fail "getHealth" "unhealthy or unreachable"
fi

# getNetwork
if resp=$(rpc_call getNetwork) && echo "$resp" | jq -e '.result.passphrase' &>/dev/null; then
  PROTO=$(echo "$resp" | jq -r '.result.protocolVersion // empty')
  if [[ -n "$PROTO" ]] && [[ "$PROTO" -gt 0 ]]; then
    pass "getNetwork (protocolVersion=$PROTO)"
  else
    fail "getNetwork" "protocolVersion missing or not > 0"
  fi
else
  fail "getNetwork" "no passphrase in response"
fi

# getLatestLedger
if resp=$(rpc_call getLatestLedger) && echo "$resp" | jq -e '.result.sequence' &>/dev/null; then
  LATEST_LEDGER=$(echo "$resp" | jq -r '.result.sequence')
  ok=true
  LEDGER_ID=$(echo "$resp" | jq -r '.result.id // empty')
  if [[ -n "$LEDGER_ID" ]] && echo "$LEDGER_ID" | grep -qE '^[a-f0-9]{64}$'; then :; else
    fail "getLatestLedger" "id not 64-char hex: $LEDGER_ID"; ok=false
  fi
  PROTO=$(echo "$resp" | jq -r '.result.protocolVersion // empty')
  if [[ -n "$PROTO" ]] && [[ "$PROTO" -gt 0 ]]; then :; else
    fail "getLatestLedger" "protocolVersion missing or not > 0"; ok=false
  fi
  if $ok; then
    pass "getLatestLedger (seq=$LATEST_LEDGER, id=${LEDGER_ID:0:12}...)"
  fi
else
  fail "getLatestLedger" "no sequence in response"
fi

# getFeeStats
if resp=$(rpc_call getFeeStats) && echo "$resp" | jq -e '.result' &>/dev/null; then
  FEE_LATEST=$(echo "$resp" | jq -r '.result.latestLedger // empty')
  if [[ -n "$FEE_LATEST" ]] && [[ "$FEE_LATEST" -gt 0 ]]; then
    pass "getFeeStats (latestLedger=$FEE_LATEST)"
  else
    fail "getFeeStats" "latestLedger missing or not > 0"
  fi
else
  fail "getFeeStats" "empty result"
fi

# getVersionInfo
if resp=$(rpc_call getVersionInfo) && echo "$resp" | jq -e '.result.version' &>/dev/null; then
  VERSION=$(echo "$resp" | jq -r '.result.version')
  PROTO=$(echo "$resp" | jq -r '.result.protocolVersion // empty')
  if [[ -n "$PROTO" ]] && [[ "$PROTO" -gt 0 ]]; then
    pass "getVersionInfo (version=$VERSION, protocolVersion=$PROTO)"
  else
    fail "getVersionInfo" "protocolVersion missing or not > 0"
  fi
else
  fail "getVersionInfo" "no version in response"
fi

echo ""

# ── 3. Setup accounts ───────────────────────────────────────────────────────
echo "── Account setup ────────────────────────────────────────────────────"

if stellar keys generate "$ALICE_KEY" --fund "${CLI_NET_ARGS[@]}" 2>/dev/null; then
  ALICE_ADDR=$(stellar keys address "$ALICE_KEY")
  echo "Alice: $ALICE_ADDR"
else
  fail "account setup (alice)" "key generation failed"
  echo "Cannot continue without accounts."
  echo ""
  echo "========"
  echo "$PASS_COUNT/$((PASS_COUNT + FAIL_COUNT)) passed"
  exit 1
fi

if stellar keys generate "$BOB_KEY" --fund "${CLI_NET_ARGS[@]}" 2>/dev/null; then
  BOB_ADDR=$(stellar keys address "$BOB_KEY")
  echo "Bob:   $BOB_ADDR"
else
  fail "account setup (bob)" "key generation failed"
  echo "Cannot continue without accounts."
  echo ""
  echo "========"
  echo "$PASS_COUNT/$((PASS_COUNT + FAIL_COUNT)) passed"
  exit 1
fi

pass "account setup"

# When using a custom RPC, wait for accounts to become visible in getLedgerEntries.
# Some nodes (e.g. henyey) catch up in batches and need time to index new accounts.
if $CUSTOM_RPC; then
  # stellar-cli >= 22.8 dropped positional-argument support for `xdr encode`
  # and requires the JSON payload on stdin. Pipe the payload in to stay
  # compatible with both old and new CLIs.
  ALICE_LEDGER_KEY=$(printf '{"account":{"account_id":"%s"}}' "$ALICE_ADDR" \
    | stellar xdr encode --type LedgerKey 2>/dev/null)
  if [[ -n "$ALICE_LEDGER_KEY" ]]; then
    echo "Waiting for accounts to appear in RPC node (up to 10 min)..."
    for _wait_i in $(seq 1 120); do
      if rpc_call getLedgerEntries "{\"keys\":[\"$ALICE_LEDGER_KEY\"]}" 2>/dev/null | \
         jq -e '.result.entries[0].xdr' &>/dev/null; then
        echo "Accounts visible after $((_wait_i * 5))s"
        break
      fi
      sleep 5
    done
  fi
fi

echo ""

# ── 4. Deploy SAC for native XLM ────────────────────────────────────────────
echo "── Deploy SAC (native XLM) ──────────────────────────────────────────"

# The native SAC may already be deployed (it's a singleton per network).
# Try deploying first; if it already exists, just look up the ID.
if CONTRACT_ID=$(stellar contract asset deploy \
    --asset native \
    --source "$ALICE_KEY" \
    "${CLI_NET_ARGS[@]}" 2>/dev/null); then
  echo "Contract: $CONTRACT_ID"
  pass "contract asset deploy (SAC)"
else
  # Already exists — look up the contract ID
  if CONTRACT_ID=$(stellar contract id asset \
      --asset native \
      "${CLI_NET_ARGS[@]}" 2>/dev/null); then
    echo "Contract (already deployed): $CONTRACT_ID"
    pass "contract asset deploy (SAC, already exists)"
  else
    fail "contract asset deploy (SAC)" "deploy failed and could not look up ID"
    CONTRACT_ID=""
  fi
fi

echo ""

# ── 5. getLedgerEntries — fetch Alice's account ─────────────────────────────
echo "── getLedgerEntries ─────────────────────────────────────────────────"

# Encode Alice's account as an XDR LedgerKey (base64). The stellar CLI
# takes the JSON payload on stdin (see note at first-use above).
if ALICE_LEDGER_KEY=$(printf '{"account":{"account_id":"%s"}}' "$ALICE_ADDR" \
    | stellar xdr encode --type LedgerKey 2>/dev/null); then
  PARAMS="{\"keys\":[\"$ALICE_LEDGER_KEY\"]}"
  if resp=$(rpc_call getLedgerEntries "$PARAMS") && \
     echo "$resp" | jq -e '.result.entries[0].xdr' &>/dev/null; then
    ok=true
    LAST_MOD=$(echo "$resp" | jq -r '.result.entries[0].lastModifiedLedgerSeq // empty')
    if [[ -z "$LAST_MOD" ]]; then
      fail "getLedgerEntries" "lastModifiedLedgerSeq missing"; ok=false
    fi
    LE_LATEST=$(echo "$resp" | jq -r '.result.latestLedger // empty')
    if [[ -z "$LE_LATEST" ]]; then
      fail "getLedgerEntries" "latestLedger missing"; ok=false
    fi
    if $ok; then
      pass "getLedgerEntries (lastModified=$LAST_MOD, latestLedger=$LE_LATEST)"
    fi
  else
    fail "getLedgerEntries" "no entry returned"
  fi
else
  # Fallback: try raw JSON-RPC with a known-good key encoding approach
  fail "getLedgerEntries" "could not encode ledger key"
fi

echo ""

# ── 6. Simulate + submit contract invocation ────────────────────────────────
echo "── Contract invoke (simulateTransaction + sendTransaction) ──────────"

TX_HASH=""

if [[ -n "$CONTRACT_ID" ]]; then
  # Simulate first
  if stellar contract invoke \
      --id "$CONTRACT_ID" \
      --source "$ALICE_KEY" \
      "${CLI_NET_ARGS[@]}" \
      --send no \
      -- transfer \
      --from "$ALICE_ADDR" \
      --to "$BOB_ADDR" \
      --amount 1000000000 &>/dev/null; then
    pass "simulateTransaction (via contract invoke --simulate-only)"
  else
    fail "simulateTransaction" "simulation failed"
  fi

  # Invoke for real — the CLI handles sendTransaction + polling getTransaction
  if INVOKE_OUTPUT=$(stellar contract invoke \
      --id "$CONTRACT_ID" \
      --source "$ALICE_KEY" \
      "${CLI_NET_ARGS[@]}" \
      -- transfer \
      --from "$ALICE_ADDR" \
      --to "$BOB_ADDR" \
      --amount 1000000000 2>&1); then
    pass "sendTransaction + getTransaction (via contract invoke)"
    # Try to extract the tx hash from stellar tx output
    TX_HASH=$(echo "$INVOKE_OUTPUT" | grep -oE '[a-f0-9]{64}' | head -1 || true)
  else
    fail "sendTransaction + getTransaction" "invoke failed"
    echo "  Output: $INVOKE_OUTPUT"
  fi
else
  fail "simulateTransaction" "skipped (no contract)"
  fail "sendTransaction + getTransaction" "skipped (no contract)"
fi

echo ""

# ── 7. getTransaction — fetch completed tx by hash ──────────────────────────
echo "── getTransaction (direct) ──────────────────────────────────────────"

TX_LEDGER=""
if [[ -n "$TX_HASH" ]]; then
  PARAMS="{\"hash\":\"$TX_HASH\"}"
  if resp=$(rpc_call getTransaction "$PARAMS") && \
     echo "$resp" | jq -e '.result.status' &>/dev/null; then
    TX_STATUS=$(echo "$resp" | jq -r '.result.status')
    TX_LEDGER=$(echo "$resp" | jq -r '.result.ledger // empty')
    pass "getTransaction (status=$TX_STATUS)"
  else
    fail "getTransaction" "no result for hash $TX_HASH"
  fi
else
  fail "getTransaction" "skipped (no tx hash available)"
fi

echo ""

# ── 8. getTransactions — query transactions in a ledger range ────────────────
echo "── getTransactions ──────────────────────────────────────────────────"

if [[ -n "$TX_LEDGER" ]]; then
  # Start at the exact tx ledger with a generous limit to ensure we capture our tx
  PARAMS=$(cat <<JSONEOF
{
  "startLedger": $TX_LEDGER,
  "pagination": {"limit": 200}
}
JSONEOF
)
  if resp=$(rpc_call getTransactions "$PARAMS") && \
     echo "$resp" | jq -e '.result.transactions[0]' &>/dev/null; then
    ok=true
    # Verify required fields on first transaction
    for field in txHash envelopeXdr resultXdr status ledger applicationOrder createdAt; do
      if ! echo "$resp" | jq -e ".result.transactions[0].$field" &>/dev/null; then
        fail "getTransactions" "missing field: $field"; ok=false; break
      fi
    done
    # Cross-check: one of the returned txHashes should match our TX_HASH
    if [[ -n "$TX_HASH" ]]; then
      HASH_MATCH=$(echo "$resp" | jq --arg h "$TX_HASH" \
        '[.result.transactions[] | select(.txHash == $h)] | length')
      if [[ "$HASH_MATCH" -eq 0 ]]; then
        fail "getTransactions" "none of the returned txHashes match $TX_HASH"; ok=false
      fi
    fi
    TX_COUNT=$(echo "$resp" | jq '.result.transactions | length')
    if $ok; then
      pass "getTransactions ($TX_COUNT txs, hash cross-check ok)"
    fi
  else
    fail "getTransactions" "no transactions returned"
  fi

  # Pagination test: limit=1, then use cursor.
  # Use the oldest ledger (not TX_LEDGER-1) so that genesis upgrade TXs are in
  # range, guaranteeing multiple TXs for a meaningful second-page test.
  START="${HEALTH_OLDEST_LEDGER:-$((TX_LEDGER - 1))}"
  if [[ $START -lt 1 ]]; then START=1; fi
  PARAMS_PAGE1=$(cat <<JSONEOF
{
  "startLedger": $START,
  "pagination": {"limit": 1}
}
JSONEOF
)
  if resp1=$(rpc_call getTransactions "$PARAMS_PAGE1") && \
     CURSOR=$(echo "$resp1" | jq -r '.result.cursor // empty') && [[ -n "$CURSOR" ]]; then
    PARAMS_PAGE2=$(cat <<JSONEOF
{
  "pagination": {"cursor": "$CURSOR", "limit": 1}
}
JSONEOF
)
    if resp2=$(rpc_call getTransactions "$PARAMS_PAGE2") && \
       echo "$resp2" | jq -e '.result.transactions[0]' &>/dev/null; then
      pass "getTransactions pagination (cursor=$CURSOR)"
    else
      fail "getTransactions pagination" "second page returned no results"
    fi
  else
    fail "getTransactions pagination" "no cursor in first page response"
  fi
else
  fail "getTransactions" "skipped (no tx ledger available)"
  fail "getTransactions pagination" "skipped (no tx ledger available)"
fi

echo ""

# ── 9. getLedgers — query ledgers by sequence range ──────────────────────────
echo "── getLedgers ────────────────────────────────────────────────────────"

if [[ -n "$TX_LEDGER" ]]; then
  START=$((TX_LEDGER - 1))
  if [[ $START -lt 1 ]]; then START=1; fi
  PARAMS=$(cat <<JSONEOF
{
  "startLedger": $START,
  "pagination": {"limit": 5}
}
JSONEOF
)
  if resp=$(rpc_call getLedgers "$PARAMS") && \
     echo "$resp" | jq -e '.result.ledgers[0]' &>/dev/null; then
    ok=true
    # Verify required fields
    for field in hash sequence headerXdr ledgerCloseTime; do
      if ! echo "$resp" | jq -e ".result.ledgers[0].$field" &>/dev/null; then
        fail "getLedgers" "missing field: $field"; ok=false; break
      fi
    done
    # Verify hash is 64-char hex
    LEDGER_HASH=$(echo "$resp" | jq -r '.result.ledgers[0].hash // empty')
    if ! echo "$LEDGER_HASH" | grep -qE '^[a-f0-9]{64}$'; then
      fail "getLedgers" "hash not 64-char hex: $LEDGER_HASH"; ok=false
    fi
    # Verify sequence is a number
    SEQ=$(echo "$resp" | jq -r '.result.ledgers[0].sequence // empty')
    if ! echo "$SEQ" | grep -qE '^[0-9]+$'; then
      fail "getLedgers" "sequence not a number: $SEQ"; ok=false
    fi
    # Cross-check: one of the returned sequences should match TX_LEDGER
    SEQ_MATCH=$(echo "$resp" | jq --argjson s "$TX_LEDGER" \
      '[.result.ledgers[] | select(.sequence == $s)] | length')
    if [[ "$SEQ_MATCH" -eq 0 ]]; then
      fail "getLedgers" "none of the returned sequences match TX_LEDGER=$TX_LEDGER"; ok=false
    fi
    LEDGER_COUNT=$(echo "$resp" | jq '.result.ledgers | length')
    if $ok; then
      pass "getLedgers ($LEDGER_COUNT ledgers, seq cross-check ok)"
    fi
  else
    fail "getLedgers" "no ledgers returned"
  fi
elif [[ -n "$LATEST_LEDGER" ]]; then
  # Fallback: use latest ledger range
  START=$((LATEST_LEDGER - 5))
  if [[ $START -lt 1 ]]; then START=1; fi
  PARAMS=$(cat <<JSONEOF
{
  "startLedger": $START,
  "pagination": {"limit": 5}
}
JSONEOF
)
  if resp=$(rpc_call getLedgers "$PARAMS") && \
     echo "$resp" | jq -e '.result.ledgers[0]' &>/dev/null; then
    LEDGER_COUNT=$(echo "$resp" | jq '.result.ledgers | length')
    pass "getLedgers (fallback, $LEDGER_COUNT ledgers, no tx to cross-check)"
  else
    fail "getLedgers" "no ledgers returned"
  fi
else
  fail "getLedgers" "skipped (no ledger info available)"
fi

echo ""

# ── 10. getEvents — query transfer events ────────────────────────────────────
echo "── getEvents ────────────────────────────────────────────────────────"

if [[ -n "$CONTRACT_ID" && -n "$TX_LEDGER" && -n "$ALICE_ADDR" ]]; then
  # Encode filter topics: transfer symbol + Alice's address as ScVal.
  # stellar-cli >= 22.8 reads the JSON payload from stdin only.
  TRANSFER_TOPIC=$(printf '{"symbol":"transfer"}' \
    | stellar xdr encode --type ScVal 2>/dev/null)
  ALICE_TOPIC=$(printf '{"address":"%s"}' "$ALICE_ADDR" \
    | stellar xdr encode --type ScVal 2>/dev/null)

  # Filter by contract + transfer topic + Alice as sender, starting from the tx ledger
  PARAMS=$(cat <<JSONEOF
{
  "startLedger": $TX_LEDGER,
  "filters": [{
    "type": "contract",
    "contractIds": ["$CONTRACT_ID"],
    "topics": [["$TRANSFER_TOPIC", "$ALICE_TOPIC", "*", "*"]]
  }],
  "pagination": {"limit": 10}
}
JSONEOF
)
  if resp=$(rpc_call getEvents "$PARAMS") && \
     echo "$resp" | jq -e '.result.events' &>/dev/null; then
    # Verify the events belong to our transaction
    MATCH_COUNT=$(echo "$resp" | jq --arg hash "$TX_HASH" \
      '[.result.events[] | select(.txHash == $hash)] | length')
    if [[ "$MATCH_COUNT" -gt 0 ]]; then
      pass "getEvents ($MATCH_COUNT transfer events from alice)"
    else
      EVENT_COUNT=$(echo "$resp" | jq '.result.events | length')
      fail "getEvents" "got $EVENT_COUNT events but none matched tx $TX_HASH"
    fi
  else
    fail "getEvents" "request failed"
  fi
elif [[ -n "$CONTRACT_ID" && -n "$LATEST_LEDGER" ]]; then
  # Fallback: no tx ledger known, use a broad window
  START_LEDGER=$((LATEST_LEDGER - 100))
  if [[ $START_LEDGER -lt 1 ]]; then START_LEDGER=1; fi
  PARAMS=$(cat <<JSONEOF
{
  "startLedger": $START_LEDGER,
  "filters": [{
    "type": "contract",
    "contractIds": ["$CONTRACT_ID"]
  }],
  "pagination": {"limit": 10}
}
JSONEOF
)
  if resp=$(rpc_call getEvents "$PARAMS") && \
     echo "$resp" | jq -e '.result.events[0]' &>/dev/null; then
    pass "getEvents (fallback, no tx hash to verify)"
  else
    fail "getEvents" "no events returned"
  fi
else
  fail "getEvents" "skipped (no contract or ledger info)"
fi

echo ""

# ── 11. Data consistency cross-checks ────────────────────────────────────────
echo "── Consistency cross-checks ─────────────────────────────────────────"

# Re-fetch health to get up-to-date ledger bounds (the initial call was before tx submission)
FRESH_HEALTH_LATEST=""
FRESH_HEALTH_OLDEST=""
if fresh_resp=$(rpc_call getHealth) && echo "$fresh_resp" | jq -e '.result.status' &>/dev/null; then
  FRESH_HEALTH_LATEST=$(echo "$fresh_resp" | jq -r '.result.latestLedger // empty')
  FRESH_HEALTH_OLDEST=$(echo "$fresh_resp" | jq -r '.result.oldestLedger // empty')
fi
# Also re-fetch getLatestLedger
FRESH_LATEST_LEDGER=""
if fresh_resp=$(rpc_call getLatestLedger) && echo "$fresh_resp" | jq -e '.result.sequence' &>/dev/null; then
  FRESH_LATEST_LEDGER=$(echo "$fresh_resp" | jq -r '.result.sequence')
fi

# getLatestLedger sequence >= getHealth latestLedger (they should match or be close)
if [[ -n "$FRESH_LATEST_LEDGER" && -n "$FRESH_HEALTH_LATEST" ]]; then
  if [[ "$FRESH_LATEST_LEDGER" -ge "$FRESH_HEALTH_LATEST" ]]; then
    pass "consistency: getLatestLedger ($FRESH_LATEST_LEDGER) >= getHealth latestLedger ($FRESH_HEALTH_LATEST)"
  else
    fail "consistency: getLatestLedger vs getHealth" \
      "getLatestLedger=$FRESH_LATEST_LEDGER < getHealth.latestLedger=$FRESH_HEALTH_LATEST"
  fi
else
  fail "consistency: getLatestLedger vs getHealth" "skipped (missing data)"
fi

# getTransaction ledger falls within getHealth [oldestLedger, latestLedger]
if [[ -n "$TX_LEDGER" && -n "$FRESH_HEALTH_OLDEST" && -n "$FRESH_HEALTH_LATEST" ]]; then
  if [[ "$TX_LEDGER" -ge "$FRESH_HEALTH_OLDEST" && "$TX_LEDGER" -le "$FRESH_HEALTH_LATEST" ]]; then
    pass "consistency: tx ledger ($TX_LEDGER) in range [$FRESH_HEALTH_OLDEST, $FRESH_HEALTH_LATEST]"
  else
    fail "consistency: tx ledger range" \
      "TX_LEDGER=$TX_LEDGER not in [$FRESH_HEALTH_OLDEST, $FRESH_HEALTH_LATEST]"
  fi
else
  fail "consistency: tx ledger range" "skipped (missing data)"
fi

echo ""

# ── Summary ──────────────────────────────────────────────────────────────────
TOTAL=$((PASS_COUNT + FAIL_COUNT))
echo "========"
echo "$PASS_COUNT/$TOTAL passed"

if [[ ${#FAILURES[@]} -gt 0 ]]; then
  echo ""
  echo "Failures:"
  for f in "${FAILURES[@]}"; do
    echo "  - $f"
  done
  exit 1
fi
