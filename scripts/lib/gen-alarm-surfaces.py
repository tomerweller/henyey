#!/usr/bin/env python3
"""Generate reconciliation and non-overlaps tables in ALARM_SURFACES.md.

Reads alarm-surfaces.toml via the shared alarm_surfaces module and writes
the rendered tables between marker comments in ALARM_SURFACES.md.

Usage:
    gen-alarm-surfaces.py <surfaces-toml> <alarm-surfaces-md>
    gen-alarm-surfaces.py --check <surfaces-toml> <alarm-surfaces-md>

--check: Compare what the file would contain against the committed file.
         Exit 0 with "OK" message if up to date, exit 1 if stale.
"""

import os
import sys

# Add scripts/lib to path for alarm_surfaces import
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

import alarm_surfaces

BEGIN_RECON = "<!-- BEGIN GENERATED RECONCILIATION TABLE -->"
END_RECON = "<!-- END GENERATED RECONCILIATION TABLE -->"
BEGIN_NON = "<!-- BEGIN GENERATED NON-OVERLAPS TABLE -->"
END_NON = "<!-- END GENERATED NON-OVERLAPS TABLE -->"


def replace_between_markers(content, begin_marker, end_marker, replacement):
    """Replace content between begin and end markers (exclusive).

    Raises ValueError if markers are missing, duplicated, or out of order.
    """
    begin_count = content.count(begin_marker)
    end_count = content.count(end_marker)

    if begin_count == 0:
        raise ValueError(f"Missing marker: {begin_marker}")
    if end_count == 0:
        raise ValueError(f"Missing marker: {end_marker}")
    if begin_count > 1:
        raise ValueError(f"Duplicate marker: {begin_marker}")
    if end_count > 1:
        raise ValueError(f"Duplicate marker: {end_marker}")

    begin_idx = content.index(begin_marker) + len(begin_marker)
    end_idx = content.index(end_marker)

    if begin_idx > end_idx:
        raise ValueError(f"Markers out of order: {begin_marker} after {end_marker}")

    return content[:begin_idx] + "\n" + replacement + "\n" + content[end_idx:]


def main():
    check_mode = "--check" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--check"]

    if len(args) != 2:
        print(f"Usage: {sys.argv[0]} [--check] <surfaces-toml> <alarm-surfaces-md>",
              file=sys.stderr)
        sys.exit(2)

    surfaces_path, md_path = args

    surfaces = alarm_surfaces.load_surfaces(surfaces_path)

    # Validate file-local invariants
    errors = alarm_surfaces.validate_local(surfaces)
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    recon_table = alarm_surfaces.render_reconciliation_table(surfaces)
    non_table = alarm_surfaces.render_non_overlaps_table(surfaces)

    with open(md_path) as f:
        content = f.read()

    try:
        content = replace_between_markers(content, BEGIN_RECON, END_RECON, recon_table)
        content = replace_between_markers(content, BEGIN_NON, END_NON, non_table)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    if check_mode:
        with open(md_path) as f:
            committed = f.read()
        if committed == content:
            print("OK: ALARM_SURFACES.md is up to date")
            sys.exit(0)
        else:
            print("STALE: ALARM_SURFACES.md needs regeneration", file=sys.stderr)
            sys.exit(1)
    else:
        with open(md_path, "w") as f:
            f.write(content)
        print(f"Updated {md_path}")


if __name__ == "__main__":
    main()
