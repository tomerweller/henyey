#!/usr/bin/env bash
#
# Run stellar/quickstart locally with henyey as stellar-core.
#
# Usage:
#   ./scripts/quickstart-local.sh                          # local, core,rpc,horizon
#   ./scripts/quickstart-local.sh --enable core            # just core (fastest)
#   ./scripts/quickstart-local.sh --enable core,rpc        # core + rpc
#   ./scripts/quickstart-local.sh --no-build               # skip cargo build
#   ./scripts/quickstart-local.sh --keep                   # don't stop container on exit
#   ./scripts/quickstart-local.sh --logs                   # tail container logs
#   ./scripts/quickstart-local.sh --no-test                # skip tests, just start
#   ./scripts/quickstart-local.sh --network testnet        # use testnet instead of local
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Defaults
ENABLE="core,rpc,horizon"
NETWORK="local"
DO_BUILD=true
KEEP=false
LOGS=false
NO_TEST=false
CONTAINER_NAME="henyey-quickstart"
IMAGE_TAG="henyey-quickstart:local"
BASE_IMAGE="stellar/quickstart:testing"
HEALTH_TIMEOUT=300  # 5 minutes

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --enable)       ENABLE="$2"; shift 2 ;;
    --network)      NETWORK="$2"; shift 2 ;;
    --no-build)     DO_BUILD=false; shift ;;
    --keep)         KEEP=true; shift ;;
    --logs)         LOGS=true; shift ;;
    --no-test)      NO_TEST=true; shift ;;
    --timeout)      HEALTH_TIMEOUT="$2"; shift 2 ;;
    -h|--help)
      sed -n '3,12p' "$0" | sed 's/^# \?//'
      exit 0 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

# Cleanup handler
cleanup() {
  if [ "$KEEP" = false ] && docker ps -q -f name="$CONTAINER_NAME" | grep -q .; then
    echo "Stopping container..."
    docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
    docker rm "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fi
}

if [ "$KEEP" = false ]; then
  trap cleanup EXIT
fi

# ── Step 1: Build henyey ──────────────────────────────────────────────────────
if [ "$DO_BUILD" = true ]; then
  echo "==> Building henyey (release)..."
  cd "$PROJECT_ROOT"
  cargo build --release -p henyey 2>&1
  echo "    Done."
else
  if [ ! -f "$PROJECT_ROOT/target/release/henyey" ]; then
    echo "ERROR: target/release/henyey not found. Run without --no-build first."
    exit 1
  fi
  echo "==> Skipping build (--no-build)"
fi

# ── Step 2: Ensure base image exists ──────────────────────────────────────────
if ! docker image inspect "$BASE_IMAGE" >/dev/null 2>&1; then
  echo "==> Pulling $BASE_IMAGE..."
  docker pull "$BASE_IMAGE"
fi

# ── Step 3: Build overlay image ───────────────────────────────────────────────
echo "==> Building Docker image..."
cd "$PROJECT_ROOT"
docker build -f Dockerfile.quickstart-local -t "$IMAGE_TAG" . 2>&1
echo "    Done."

# ── Step 4: Stop existing container ───────────────────────────────────────────
if docker ps -aq -f name="$CONTAINER_NAME" | grep -q .; then
  echo "==> Stopping existing container..."
  docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
  docker rm "$CONTAINER_NAME" >/dev/null 2>&1 || true
fi

# ── Step 5: Start container ──────────────────────────────────────────────────
echo "==> Starting quickstart (network=$NETWORK, enable=$ENABLE)..."
docker run -d --name "$CONTAINER_NAME" \
  -p 8000:8000 \
  -p 11626:11626 \
  -p 11726:11726 \
  -p 11826:11826 \
  -e ENABLE_LOGS=true \
  -e "ENABLE=$ENABLE" \
  -e "NETWORK=$NETWORK" \
  "$IMAGE_TAG" >/dev/null

# ── Step 6: Tail logs if requested ────────────────────────────────────────────
if [ "$LOGS" = true ]; then
  echo "==> Tailing container logs (Ctrl-C to stop)..."
  docker logs -f "$CONTAINER_NAME"
  exit 0
fi

# ── Step 7: Wait for healthy ─────────────────────────────────────────────────
# Poll service endpoints directly to determine health.
# - Core: check /info returns "Synced!" state
# - RPC:  check getHealth returns "healthy" status
HAS_RPC=false
if [[ ",$ENABLE," == *",rpc,"* ]]; then
  HAS_RPC=true
fi

echo "==> Waiting for container to be healthy (timeout: ${HEALTH_TIMEOUT}s)..."
elapsed=0
while true; do
  # Check container is still running
  if ! docker ps -q -f name="$CONTAINER_NAME" | grep -q .; then
    echo "    Container exited unexpectedly after ${elapsed}s"
    docker logs --tail 50 "$CONTAINER_NAME" 2>/dev/null || true
    exit 1
  fi

  # Check core synced
  core_state=$(curl -sf http://localhost:11626/info 2>/dev/null | jq -r '.info.state' 2>/dev/null || echo "")
  core_ok=false
  if [ "$core_state" = "Synced!" ]; then
    core_ok=true
  fi

  # Check RPC healthy (if enabled)
  rpc_ok=true
  rpc_status=""
  if [ "$HAS_RPC" = true ]; then
    rpc_status=$(curl -sf http://localhost:8000/rpc -X POST \
      -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' 2>/dev/null \
      | jq -r '.result.status' 2>/dev/null || echo "")
    if [ "$rpc_status" != "healthy" ]; then
      rpc_ok=false
    fi
  fi

  if [ "$core_ok" = true ] && [ "$rpc_ok" = true ]; then
    echo "    All services healthy! (${elapsed}s)"
    break
  fi

  if [ "$elapsed" -ge "$HEALTH_TIMEOUT" ]; then
    echo "    TIMEOUT after ${HEALTH_TIMEOUT}s"
    echo "==> Container logs (last 100 lines):"
    docker logs --tail 100 "$CONTAINER_NAME"
    exit 1
  fi

  # Print progress every 15 seconds
  if [ $((elapsed % 15)) -eq 0 ] && [ "$elapsed" -gt 0 ]; then
    if [ "$HAS_RPC" = true ]; then
      echo "    Waiting... ${elapsed}s (core: $core_state, rpc: $rpc_status)"
    else
      echo "    Waiting... ${elapsed}s (core: $core_state)"
    fi
  fi

  sleep 5
  elapsed=$((elapsed + 5))
done

# ── Step 8: Run tests ────────────────────────────────────────────────────────
if [ "$NO_TEST" = true ]; then
  echo "==> Skipping tests (--no-test). Container is running."
  echo "    Logs:  docker logs -f $CONTAINER_NAME"
  echo "    Shell: docker exec -it $CONTAINER_NAME /bin/bash"
  echo "    Stop:  docker stop $CONTAINER_NAME"
  KEEP=true  # override cleanup
  exit 0
fi

PASS=0
FAIL=0
NETWORK_PASSPHRASE="Standalone Network ; February 2017"
if [ "$NETWORK" = "testnet" ]; then
  NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
elif [ "$NETWORK" = "pubnet" ]; then
  NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"
fi

# Test core is responding
echo "==> Testing core endpoint..."
if curl -sf http://localhost:11626/info | jq -r '.info.state' | grep -q 'Synced'; then
  echo "    PASS: core is synced"
  PASS=$((PASS + 1))
else
  echo "    FAIL: core not synced"
  FAIL=$((FAIL + 1))
fi

# Test Horizon if enabled
if [[ ",$ENABLE," == *",horizon,"* ]]; then
  echo "==> Running Horizon sanity tests..."
  if "$SCRIPT_DIR/test-horizon-sanity.sh" \
    --horizon-url http://localhost:8000 \
    --rpc-url http://localhost:8000/rpc \
    --network-passphrase "$NETWORK_PASSPHRASE"; then
    echo "    PASS: Horizon tests"
    PASS=$((PASS + 1))
  else
    echo "    FAIL: Horizon tests"
    FAIL=$((FAIL + 1))
  fi
fi

# Test RPC if enabled
if [[ ",$ENABLE," == *",rpc,"* ]]; then
  echo "==> Running RPC sanity tests..."
  if "$SCRIPT_DIR/test-rpc-sanity.sh" \
    --rpc-url http://localhost:8000/rpc \
    --network-passphrase "$NETWORK_PASSPHRASE"; then
    echo "    PASS: RPC tests"
    PASS=$((PASS + 1))
  else
    echo "    FAIL: RPC tests"
    FAIL=$((FAIL + 1))
  fi
fi

# ── Step 9: Summary ──────────────────────────────────────────────────────────
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "==> Container logs (last 200 lines):"
  docker logs --tail 200 "$CONTAINER_NAME"
  exit 1
fi

# ── Step 10: Cleanup ─────────────────────────────────────────────────────────
# (handled by trap unless --keep)
