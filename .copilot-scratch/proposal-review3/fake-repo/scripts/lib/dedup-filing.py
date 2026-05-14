#!/usr/bin/env python3
"""Shared dedup-filing helper for JSON-backed issue dedup state.

All data-transforming operations read JSON from stdin and write to stdout.
The library is stateless and lock-free — callers MUST hold their own flock
during the entire load → prune → check/act → record/update/remove → write
sequence.

Usage:
    dedup-filing.py load <file>
    dedup-filing.py prune <ttl_spec>
    dedup-filing.py check <key>
    dedup-filing.py record <key> [k=v ...]
    dedup-filing.py remove <key>
    dedup-filing.py update-field <key> <field> <value>
    dedup-filing.py write <file>
"""

import json
import os
import re
import sys
from datetime import datetime, timezone, timedelta


EMPTY_SCHEMA = {"schema_version": 1, "filed": {}}
TTL_RE = re.compile(r"^(\d+)([hd])$")


def _utc_now_str():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_timestamp(ts_str):
    """Parse a timestamp string, accepting Z, +00:00, and fractional seconds."""
    s = ts_str.strip()
    # Normalize Z → +00:00 for fromisoformat compatibility
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def _parse_ttl(spec):
    """Parse TTL spec like '24h' or '30d' into a timedelta."""
    m = TTL_RE.match(spec)
    if not m:
        print(f"Invalid TTL spec: {spec!r} (expected format: <int>h or <int>d)", file=sys.stderr)
        sys.exit(1)
    value, unit = int(m.group(1)), m.group(2)
    if unit == "h":
        return timedelta(hours=value)
    return timedelta(days=value)


def _read_stdin():
    """Read and parse JSON from stdin."""
    try:
        return json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError) as e:
        print(f"Invalid JSON on stdin: {e}", file=sys.stderr)
        return None


def _output(data):
    """Write JSON to stdout with normalized schema."""
    data.setdefault("schema_version", 1)
    data.setdefault("filed", {})
    print(json.dumps(data))


def _coerce_value(v):
    """Coerce all-digit strings to int, otherwise return as string."""
    if v.isdigit():
        return int(v)
    return v


def cmd_load(args):
    """Load a dedup file. Always exits 0 — returns empty schema on error."""
    if len(args) < 1:
        print("Usage: dedup-filing.py load <file>", file=sys.stderr)
        _output(dict(EMPTY_SCHEMA))
        return
    filepath = args[0]
    if not os.path.exists(filepath):
        _output(dict(EMPTY_SCHEMA))
        return
    try:
        with open(filepath) as f:
            data = json.load(f)
        if not isinstance(data, dict) or data.get("schema_version") != 1:
            if os.path.getsize(filepath) > 0:
                print(f"WARNING: Corrupt or invalid dedup file {filepath} — treating as empty", file=sys.stderr)
            _output(dict(EMPTY_SCHEMA))
            return
        _output(data)
    except (json.JSONDecodeError, ValueError, OSError) as e:
        if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
            print(f"WARNING: Corrupt or invalid dedup file {filepath} — treating as empty", file=sys.stderr)
        _output(dict(EMPTY_SCHEMA))


def cmd_prune(args):
    """Prune entries older than TTL. Entries with bad filed_at are silently dropped."""
    if len(args) < 1:
        print("Usage: dedup-filing.py prune <ttl_spec>", file=sys.stderr)
        sys.exit(1)
    ttl = _parse_ttl(args[0])
    data = _read_stdin()
    if data is None:
        sys.exit(1)
    cutoff = datetime.now(timezone.utc) - ttl
    filed = data.get("filed", {})
    pruned = {}
    for key, info in filed.items():
        try:
            ts = _parse_timestamp(info["filed_at"])
            if ts > cutoff:
                pruned[key] = info
        except (KeyError, ValueError, TypeError):
            # Silently drop malformed entries (matches current behavior)
            pass
    data["filed"] = pruned
    _output(data)


def cmd_check(args):
    """Check if key exists. Exit 0 + entry JSON on hit, exit 1 on miss, exit 2 on bad input."""
    if len(args) < 1:
        print("Usage: dedup-filing.py check <key>", file=sys.stderr)
        sys.exit(2)
    key = args[0]
    data = _read_stdin()
    if data is None:
        sys.exit(2)
    filed = data.get("filed", {})
    entry = filed.get(key)
    if entry is not None:
        print(json.dumps(entry))
        sys.exit(0)
    else:
        sys.exit(1)


def cmd_record(args):
    """Record a new entry with filed_at auto-set. Accepts k=v pairs."""
    if len(args) < 1:
        print("Usage: dedup-filing.py record <key> [k=v ...]", file=sys.stderr)
        sys.exit(1)
    key = args[0]
    kv_args = args[1:]

    data = _read_stdin()
    if data is None:
        sys.exit(1)

    entry = data.get("filed", {}).get(key, {})
    for kv in kv_args:
        eq_idx = kv.find("=")
        if eq_idx < 1:
            print(f"Malformed field argument: {kv!r} (expected key=value)", file=sys.stderr)
            sys.exit(1)
        k, v = kv[:eq_idx], kv[eq_idx + 1:]
        entry[k] = _coerce_value(v)

    # Always overwrite filed_at
    entry["filed_at"] = _utc_now_str()

    data.setdefault("filed", {})[key] = entry
    _output(data)


def cmd_remove(args):
    """Remove a key from filed. No-op if absent."""
    if len(args) < 1:
        print("Usage: dedup-filing.py remove <key>", file=sys.stderr)
        sys.exit(1)
    key = args[0]
    data = _read_stdin()
    if data is None:
        sys.exit(1)
    data.get("filed", {}).pop(key, None)
    _output(data)


def cmd_update_field(args):
    """Update a single field on an existing entry."""
    if len(args) < 3:
        print("Usage: dedup-filing.py update-field <key> <field> <value>", file=sys.stderr)
        sys.exit(1)
    key, field, value = args[0], args[1], args[2]
    data = _read_stdin()
    if data is None:
        sys.exit(1)
    filed = data.get("filed", {})
    if key not in filed:
        print(f"Key not found: {key!r}", file=sys.stderr)
        sys.exit(1)
    filed[key][field] = _coerce_value(value)
    _output(data)


def cmd_write(args):
    """Atomic write: write to temp file in same dir, then os.replace."""
    if len(args) < 1:
        print("Usage: dedup-filing.py write <file>", file=sys.stderr)
        sys.exit(1)
    filepath = args[0]
    content = sys.stdin.read()

    # Validate it's valid JSON
    try:
        json.loads(content)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"Invalid JSON for write: {e}", file=sys.stderr)
        sys.exit(1)

    tmpfile = f"{filepath}.tmp.{os.getpid()}"
    try:
        with open(tmpfile, "w") as f:
            f.write(content)
            if not content.endswith("\n"):
                f.write("\n")
        os.replace(tmpfile, filepath)
    except OSError as e:
        print(f"Write failed: {e}", file=sys.stderr)
        try:
            os.unlink(tmpfile)
        except OSError:
            pass
        sys.exit(1)


COMMANDS = {
    "load": cmd_load,
    "prune": cmd_prune,
    "check": cmd_check,
    "record": cmd_record,
    "remove": cmd_remove,
    "update-field": cmd_update_field,
    "write": cmd_write,
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(f"Usage: {sys.argv[0]} <{'|'.join(COMMANDS)}> [args...]", file=sys.stderr)
        sys.exit(1)
    COMMANDS[sys.argv[1]](sys.argv[2:])


if __name__ == "__main__":
    main()
