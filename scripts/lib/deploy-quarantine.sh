#!/usr/bin/env bash
#
# Deploy quarantine helpers for monitor-tick and monitor-loop skills.
#
# Provides testable, reusable functions for:
#   - Parsing deploy_quarantine.txt (validate SHAs, skip comments/blanks)
#   - Checking ancestry reachability (with fail-closed error handling)
#   - Appending entries idempotently
#   - Removing entries atomically
#
# File format (deploy_quarantine.txt):
#   - Line-oriented, default-whitespace-separated fields
#   - First field: 40 lowercase hex chars (commit SHA)
#   - Remaining fields: optional free-text reason (single line)
#   - Lines starting with # (after optional whitespace) are comments
#   - Blank/whitespace-only lines are skipped
#   - CRLF is stripped during parsing
#
# Concurrency: single-writer assumption (one monitor-tick agent at a time).
#
# Requires: Bash 4+, GNU/Linux (awk, grep, printf, mv).
# Does NOT set shell options — callers control strictness.
# Idempotent: safe to source multiple times.
#

[[ -n "${_DEPLOY_QUARANTINE_LOADED:-}" ]] && return 0
_DEPLOY_QUARANTINE_LOADED=1

# ─────────────────────────────────────────────────────────────────────────────
# parse_quarantine_file QUARANTINE_FILE
#
# Read-only. Parses the quarantine file into structured globals.
#
# Arguments:
#   QUARANTINE_FILE - Path to deploy_quarantine.txt
#
# Sets globals:
#   QUARANTINE_ENTRIES  - Newline-separated valid SHAs (order preserved)
#   QUARANTINE_WARNINGS - Comma-space-separated warning messages
#
# Returns:
#   0 — file parsed (missing/empty is OK; malformed entries produce warnings)
#   1 — file exists but is unreadable (fail-closed)
# ─────────────────────────────────────────────────────────────────────────────
parse_quarantine_file() {
  local file="$1"
  QUARANTINE_ENTRIES=""
  QUARANTINE_WARNINGS=""

  # Missing or empty file: clear, no warnings
  if [[ ! -e "$file" ]]; then
    return 0
  fi
  if [[ ! -s "$file" ]]; then
    return 0
  fi

  # Unreadable file: fail-closed
  if [[ ! -r "$file" ]]; then
    QUARANTINE_WARNINGS="unreadable: $file"
    return 1
  fi

  local line sha _rest
  while IFS= read -r line || [[ -n "$line" ]]; do
    # Strip CRLF
    line="${line%$'\r'}"

    # Trim leading whitespace
    local trimmed="${line#"${line%%[![:space:]]*}"}"

    # Skip blank lines
    [[ -z "$trimmed" ]] && continue

    # Skip comments
    [[ "$trimmed" == \#* ]] && continue

    # Extract first whitespace-delimited field
    read -r sha _rest <<< "$trimmed"

    # Validate: exactly 40 lowercase hex chars
    if [[ "$sha" =~ ^[0-9a-f]{40}$ ]]; then
      if [[ -n "$QUARANTINE_ENTRIES" ]]; then
        QUARANTINE_ENTRIES+=$'\n'"$sha"
      else
        QUARANTINE_ENTRIES="$sha"
      fi
    else
      local warning="malformed: ${sha:0:12}"
      [[ ${#sha} -gt 12 ]] && warning+="..."
      if [[ -n "$QUARANTINE_WARNINGS" ]]; then
        QUARANTINE_WARNINGS+=", $warning"
      else
        QUARANTINE_WARNINGS="$warning"
      fi
    fi
  done < "$file"

  return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# check_quarantine_ancestry QUARANTINE_FILE
#
# Read-only + git subprocess. Determines if any quarantined SHA is reachable
# from origin/main. Fail-closed on file-unreadable and git errors.
#
# Return convention: 0 = blocked (quarantine active), 1 = clear.
#
# Arguments:
#   QUARANTINE_FILE - Path to deploy_quarantine.txt
#
# Sets globals:
#   QUARANTINE_STATUS  - Machine-readable: blocked_unreadable | blocked_ancestor
#                        | blocked_git_error | clear
#   QUARANTINED_MATCH  - Matched SHA, "UNREADABLE", or "" (empty if clear)
#   QUARANTINE_WARNINGS - Accumulated warnings from parse + ancestry checks
#
# Returns:
#   0 — quarantined (deploy should be blocked)
#   1 — clear (no quarantine match, safe to proceed)
# ─────────────────────────────────────────────────────────────────────────────
check_quarantine_ancestry() {
  local file="$1"
  QUARANTINE_STATUS="clear"
  QUARANTINED_MATCH=""

  parse_quarantine_file "$file"
  local parse_rc=$?

  # File unreadable: fail-closed
  if [[ "$parse_rc" -eq 1 ]]; then
    QUARANTINE_STATUS="blocked_unreadable"
    QUARANTINED_MATCH="UNREADABLE"
    return 0
  fi

  # No entries: clear
  if [[ -z "$QUARANTINE_ENTRIES" ]]; then
    QUARANTINE_STATUS="clear"
    return 1
  fi

  # Check each SHA for ancestry
  local sha merge_base_rc
  while IFS= read -r sha; do
    [[ -z "$sha" ]] && continue

    merge_base_rc=0
    git merge-base --is-ancestor "$sha" origin/main 2>/dev/null || merge_base_rc=$?

    if [[ "$merge_base_rc" -eq 0 ]]; then
      # SHA is ancestor of origin/main — quarantined
      QUARANTINE_STATUS="blocked_ancestor"
      QUARANTINED_MATCH="$sha"
      return 0
    elif [[ "$merge_base_rc" -ge 128 ]]; then
      # Git error — fail-closed
      local warning="ancestry-check-error: ${sha:0:8} (rc=$merge_base_rc)"
      if [[ -n "$QUARANTINE_WARNINGS" ]]; then
        QUARANTINE_WARNINGS+=", $warning"
      else
        QUARANTINE_WARNINGS="$warning"
      fi
      QUARANTINE_STATUS="blocked_git_error"
      QUARANTINED_MATCH="$sha"
      return 0
    fi
    # rc=1: not ancestor — skip, continue to next
  done <<< "$QUARANTINE_ENTRIES"

  # No match
  QUARANTINE_STATUS="clear"
  return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# quarantine_append QUARANTINE_FILE SHA REASON
#
# I/O: creates/appends to the quarantine file. Idempotent — does not add
# duplicate entries.
#
# Arguments:
#   QUARANTINE_FILE - Path to deploy_quarantine.txt
#   SHA             - 40 lowercase hex chars
#   REASON          - Optional free-text reason (sanitized to single printable line)
#
# Returns:
#   0 — appended successfully or already present (no-op)
#   1 — invalid SHA format
#   2 — I/O error (mkdir, read, or write failure)
# ─────────────────────────────────────────────────────────────────────────────
quarantine_append() {
  local file="$1" sha="$2" reason="${3:-}"

  # Validate SHA
  if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
    return 1
  fi

  # Sanitize reason: strip control chars, truncate
  if [[ -n "$reason" ]]; then
    reason=$(printf '%s' "$reason" | tr -d '\n\t\r' | tr -cd '[:print:]')
    reason="${reason:0:200}"
  fi

  # Ensure parent directory exists
  local dir
  dir=$(dirname "$file")
  if ! mkdir -p "$dir" 2>/dev/null; then
    return 2
  fi

  # If file exists, check for duplicate
  if [[ -e "$file" ]]; then
    if [[ ! -r "$file" ]]; then
      # Cannot verify idempotency — fail
      return 2
    fi
    if awk -v sha="$sha" '$1 == sha { found=1; exit } END { exit !found }' "$file" 2>/dev/null; then
      # Already present
      return 0
    fi
  fi

  # Append entry
  if [[ -n "$reason" ]]; then
    printf '%s %s\n' "$sha" "$reason" >> "$file" 2>/dev/null || return 2
  else
    printf '%s\n' "$sha" >> "$file" 2>/dev/null || return 2
  fi

  return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# quarantine_remove QUARANTINE_FILE SHA
#
# I/O: atomically removes ALL entries matching SHA from the quarantine file.
# Idempotent — returns success if SHA is not present or file is missing.
#
# Arguments:
#   QUARANTINE_FILE - Path to deploy_quarantine.txt
#   SHA             - 40 lowercase hex chars
#
# Returns:
#   0 — removed or not present (including missing file)
#   1 — invalid SHA format
#   2 — I/O error (read, awk, or mv failure)
# ─────────────────────────────────────────────────────────────────────────────
quarantine_remove() {
  local file="$1" sha="$2"

  # Validate SHA
  if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
    return 1
  fi

  # Missing file: nothing to remove
  if [[ ! -e "$file" ]]; then
    return 0
  fi

  # Unreadable file: cannot safely modify
  if [[ ! -r "$file" ]]; then
    return 2
  fi

  # Atomic removal via tmp+mv
  local tmpfile="${file}.tmp"
  if ! awk -v sha="$sha" '$1 != sha' "$file" > "$tmpfile" 2>/dev/null; then
    rm -f "$tmpfile" 2>/dev/null
    return 2
  fi

  if ! mv "$tmpfile" "$file" 2>/dev/null; then
    rm -f "$tmpfile" 2>/dev/null
    return 2
  fi

  return 0
}
