#!/usr/bin/env bash
# Shared dedup-filing library. Source this file; do not execute directly.
#
# All operations are stateless — callers MUST hold their own flock during
# the entire load → prune → check/act → record/update/remove → write sequence.
#
# Usage:
#   source scripts/lib/dedup-filing.sh
#   DEDUP_DATA=$(dedup_load "$DEDUP_FILE")
#   DEDUP_DATA=$(dedup_prune "$DEDUP_DATA" "24h")
#   if entry=$(dedup_check "$DEDUP_DATA" "$key"); then echo "hit: $entry"; fi
#   DEDUP_DATA=$(dedup_record "$DEDUP_DATA" "$key" "issue_number=123")
#   dedup_write "$DEDUP_FILE" "$DEDUP_DATA"

_DEDUP_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dedup-filing.py"

dedup_load()         { python3 "$_DEDUP_SCRIPT" load "$1"; }
dedup_prune()        { printf '%s' "$1" | python3 "$_DEDUP_SCRIPT" prune "$2"; }
dedup_check()        { printf '%s' "$1" | python3 "$_DEDUP_SCRIPT" check "$2"; }
dedup_record()       { printf '%s' "$1" | python3 "$_DEDUP_SCRIPT" record "$2" "${@:3}"; }
dedup_remove()       { printf '%s' "$1" | python3 "$_DEDUP_SCRIPT" remove "$2"; }
dedup_update_field() { printf '%s' "$1" | python3 "$_DEDUP_SCRIPT" update-field "$2" "$3" "$4"; }
dedup_write()        { printf '%s' "$2" | python3 "$_DEDUP_SCRIPT" write "$1"; }
