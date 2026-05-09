#!/usr/bin/env bash
#
# watcher-ctl.sh — Manage a testnet henyey watcher process.
#
# Usage: watcher-ctl.sh {start|stop|status|restart}
#
# Per-user global singleton — exactly one testnet watcher at a time.
# Uses PID-file tracking with strong process identity verification
# (exe path + cmdline argv + config path).
#
# All paths are overridable via environment variables for testing.
#
set -euo pipefail

# Derive repo root from script location, not caller cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${PROJECT_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"

# Overridable configuration.
WATCHER_CONFIG="${WATCHER_CONFIG:-configs/watcher-testnet.toml}"
PID_FILE="${PID_FILE:-$HOME/data/watcher/testnet-watcher.pid}"
LOG_FILE="${LOG_FILE:-$HOME/data/watcher/testnet-watcher.log}"
BINARY="${BINARY:-$PROJECT_DIR/target/release/henyey}"
PROC_ROOT="${PROC_ROOT:-/proc}"

# Source shared cmdline parsing helper.
# shellcheck source=lib/monitor-decisions.sh
source "$SCRIPT_DIR/lib/monitor-decisions.sh"

# ─────────────────────────────────────────────────────────────────────────────
# _is_our_watcher PID
#
# Verify a PID is our testnet watcher using three signals:
#   1. exe symlink matches our expected binary (exact path)
#   2. cmdline contains both `run` and `--watcher` as standalone argv
#   3. parsed config path matches our expected config (normalized)
#
# Returns 0 if all checks pass, 1 otherwise.
# ─────────────────────────────────────────────────────────────────────────────
_is_our_watcher() {
    local pid="$1"
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    [[ -d "$PROC_ROOT/$pid" ]] || return 1

    # exe check: exact binary path match (strip " (deleted)" for rebuilt binaries)
    local exe
    exe=$(readlink "$PROC_ROOT/$pid/exe" 2>/dev/null || true)
    exe="${exe% (deleted)}"
    local expected_binary
    expected_binary="$(readlink -f "$BINARY" 2>/dev/null || echo "$BINARY")"
    [[ "$exe" == "$expected_binary" ]] || return 1

    # cmdline check: must have both `run` and `--watcher` as standalone argv
    local has_run=false has_watcher=false
    while IFS= read -r -d '' arg; do
        [[ "$arg" == "run" ]] && has_run=true
        [[ "$arg" == "--watcher" ]] && has_watcher=true
    done < "$PROC_ROOT/$pid/cmdline" 2>/dev/null
    $has_run || return 1
    $has_watcher || return 1

    # config check: parse config from cmdline, resolve relative paths
    # against the process's cwd for correct comparison
    local actual_config
    actual_config=$(_parse_cmdline_config "$PROC_ROOT/$pid/cmdline")
    [[ -n "$actual_config" ]] || return 1

    local expected_config
    expected_config="$(cd "$PROJECT_DIR" && readlink -f "$WATCHER_CONFIG")"

    if [[ "$actual_config" != /* ]]; then
        local proc_cwd
        proc_cwd=$(readlink "$PROC_ROOT/$pid/cwd" 2>/dev/null || echo "")
        if [[ -n "$proc_cwd" ]]; then
            actual_config="$(readlink -f "$proc_cwd/$actual_config" 2>/dev/null || echo "$actual_config")"
        fi
    else
        actual_config="$(readlink -f "$actual_config" 2>/dev/null || echo "$actual_config")"
    fi

    [[ "$actual_config" == "$expected_config" ]] || return 1
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# _find_untracked_watcher
#
# Scan /proc for any matching watcher process, regardless of PID file.
# Stdout: PID if found, empty otherwise.
# ─────────────────────────────────────────────────────────────────────────────
_find_untracked_watcher() {
    for p in "$PROC_ROOT"/[0-9]*; do
        [[ -d "$p" ]] || continue
        local pid
        pid=$(basename "$p")
        if _is_our_watcher "$pid"; then
            echo "$pid"
            return 0
        fi
    done
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# cmd_status
#
# Check watcher status. If PID file is stale, cleans it up. If an untracked
# watcher is found via /proc scan, adopts it into the PID file.
#
# Exit 0: watcher is running.  Exit 1: watcher is not running.
# ─────────────────────────────────────────────────────────────────────────────
cmd_status() {
    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid=$(cat "$PID_FILE")
        if _is_our_watcher "$pid"; then
            echo "Watcher running (PID $pid)"
            return 0
        fi
        echo "Stale PID file (removing)"
        rm -f "$PID_FILE"
    fi

    # Fallback: scan /proc for untracked watcher
    local untracked
    untracked=$(_find_untracked_watcher)
    if [[ -n "$untracked" ]]; then
        echo "Watcher running UNTRACKED (PID $untracked) — adopting"
        mkdir -p "$(dirname "$PID_FILE")"
        echo "$untracked" > "$PID_FILE"
        return 0
    fi

    echo "Watcher NOT running"
    return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# cmd_stop
#
# Stop the watcher. Fail-safe: retains PID file on kill timeout.
#
# Exit 0: watcher stopped (or none was running).
# Exit 1: kill failed or process did not exit within 15s.
# ─────────────────────────────────────────────────────────────────────────────
cmd_stop() {
    if ! cmd_status > /dev/null 2>&1; then
        echo "No watcher running"
        return 0
    fi

    local pid
    pid=$(cat "$PID_FILE")
    kill "$pid" 2>/dev/null || { echo "ERROR: kill $pid failed"; return 1; }

    local i
    for i in $(seq 1 15); do
        [[ -d "$PROC_ROOT/$pid" ]] || break
        sleep 1
    done

    if [[ -d "$PROC_ROOT/$pid" ]]; then
        echo "ERROR: PID $pid did not exit after 15s. PID file retained."
        echo "Manual intervention required: kill -9 $pid"
        return 1
    fi

    rm -f "$PID_FILE"
    echo "Watcher stopped (was PID $pid)"
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# cmd_start
#
# Start the watcher. Refuses if one is already running (tracked or untracked).
# Verifies child identity after a brief startup delay.
#
# Exit 0: watcher started.
# Exit 1: already running, binary missing, or startup crash.
# ─────────────────────────────────────────────────────────────────────────────
cmd_start() {
    mkdir -p "$(dirname "$PID_FILE")" "$(dirname "$LOG_FILE")"

    # Check for existing watcher (tracked or untracked)
    local existing
    existing=$(_find_untracked_watcher)
    if [[ -n "$existing" ]]; then
        echo "ERROR: Watcher already running (PID $existing). Stop it first."
        echo "$existing" > "$PID_FILE"
        return 1
    fi

    [[ -x "$BINARY" ]] || { echo "ERROR: Binary not found: $BINARY"; return 1; }

    cd "$PROJECT_DIR"
    nohup "$BINARY" run --watcher --config "$WATCHER_CONFIG" \
        > "$LOG_FILE" 2>&1 &
    local new_pid=$!

    # Brief delay for exec, then verify child identity
    sleep 1
    if ! _is_our_watcher "$new_pid"; then
        echo "ERROR: PID $new_pid identity check failed. Likely crashed at startup."
        wait "$new_pid" 2>/dev/null || true
        return 1
    fi

    echo "$new_pid" > "$PID_FILE"
    echo "Watcher started (PID $new_pid)"
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# cmd_restart
#
# Stop then start. Fails if stop fails.
# ─────────────────────────────────────────────────────────────────────────────
cmd_restart() {
    cmd_stop || return 1
    cmd_start
}

# ── Main dispatch ────────────────────────────────────────────────────────────
case "${1:-}" in
    start)   cmd_start ;;
    stop)    cmd_stop ;;
    status)  cmd_status ;;
    restart) cmd_restart ;;
    *)
        echo "Usage: $(basename "$0") {start|stop|status|restart}"
        echo ""
        echo "Manage a testnet henyey watcher process."
        echo "PID file: $PID_FILE"
        echo "Log file: $LOG_FILE"
        echo "Config:   $WATCHER_CONFIG"
        echo "Binary:   $BINARY"
        exit 1
        ;;
esac
