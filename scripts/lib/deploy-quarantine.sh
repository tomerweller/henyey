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
# check_quarantine_active QUARANTINE_FILE
#
# Read-only + git subprocess. Determines if any quarantined SHA's *content*
# is still present in origin/main HEAD. Fail-closed on file-unreadable and
# git errors.
#
# Semantics differ from a pure ancestry check: a quarantined SHA only blocks
# deploy if its diff is still applied to origin/main. Once the offending
# changes are reverted, refactored away, or otherwise no longer present at
# the same lines, the gate auto-clears for that entry. This means a normal
# `git revert` (which adds a revert commit but leaves the bad SHA in
# ancestry) unblocks deploys without operator intervention.
#
# Algorithm per entry:
#   1. If SHA is NOT an ancestor of origin/main → not deployed, skip.
#   2. If SHA IS an ancestor → emit its diff via `git diff sha^..sha` and
#      test reverse-apply via `git apply --check --reverse`. Success means
#      the bad lines are still in the tree (BLOCK). Failure (rejected hunks,
#      missing files, context mismatch) means the bad code has been removed
#      or moved (CLEAR for this entry).
#   3. Hard git errors (rc>=128 from merge-base, rc>=128 from `git diff`
#      itself, missing parent) fail-closed: BLOCK with a warning.
#
# Arguments:
#   QUARANTINE_FILE - Path to deploy_quarantine.txt
#
# Sets globals:
#   QUARANTINE_STATUS  - Machine-readable: blocked_unreadable | blocked_active
#                        | blocked_git_error | clear
#   QUARANTINED_MATCH  - Matched SHA, "UNREADABLE", or "" (empty if clear)
#   QUARANTINE_WARNINGS - Accumulated warnings from parse + checks
#
# Returns:
#   0 — quarantined (deploy should be blocked)
#   1 — clear (no quarantine match, safe to proceed)
# ─────────────────────────────────────────────────────────────────────────────
check_quarantine_active() {
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

  local sha merge_base_rc apply_rc
  while IFS= read -r sha; do
    [[ -z "$sha" ]] && continue

    # Step 1: ancestry check. If SHA isn't reachable, its content can't
    # be in origin/main HEAD → skip.
    merge_base_rc=0
    git merge-base --is-ancestor "$sha" origin/main 2>/dev/null || merge_base_rc=$?

    if [[ "$merge_base_rc" -ge 128 ]]; then
      # Git error on ancestry check — fail-closed
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
    if [[ "$merge_base_rc" -eq 1 ]]; then
      # Not in ancestry — content cannot be present. Skip.
      continue
    fi

    # Step 2: content check. The SHA is an ancestor; ask whether its diff
    # would still reverse-apply cleanly. If YES, the offending lines are
    # in the current tree → BLOCK. If NO (rejected hunks, missing files,
    # context drift) the bad code is no longer present → CLEAR for this
    # entry.
    apply_rc=0
    git diff "${sha}^..${sha}" 2>/dev/null | git apply --check --reverse 2>/dev/null || apply_rc=$?

    if [[ "$apply_rc" -eq 0 ]]; then
      # Reverse-apply works → content still present → BLOCK
      QUARANTINE_STATUS="blocked_active"
      QUARANTINED_MATCH="$sha"
      return 0
    fi
    # rc != 0: bad code has been reverted or otherwise removed. Skip.
  done <<< "$QUARANTINE_ENTRIES"

  # No active match
  QUARANTINE_STATUS="clear"
  return 1
}

# Backward-compat alias: monitor-tick previously called
# `check_quarantine_ancestry`. The new content-aware check is a strict
# improvement (only blocks when the bad commit's diff is still applied),
# so the alias points at the new function. Existing call sites continue
# to work without modification.
check_quarantine_ancestry() {
  check_quarantine_active "$@"
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
