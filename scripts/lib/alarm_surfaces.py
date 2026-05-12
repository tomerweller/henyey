"""Alarm surface classification loader, validator, and renderer.

Single shared module used by gen-alarm-surfaces.py and the test suite.
Reads alarm-surfaces.toml and provides validation + markdown rendering.
"""

import re
import sys

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]


def load_surfaces(path):
    """Load and return the parsed alarm-surfaces.toml."""
    with open(path, "rb") as f:
        return tomllib.load(f)


def validate_local(surfaces):
    """Validate file-local schema invariants. Returns list of error strings."""
    errors = []
    mirrored = surfaces.get("mirrored", [])
    grafana_only = surfaces.get("grafana_only", [])

    # Unique toml_name
    toml_names = [e["toml_name"] for e in mirrored]
    seen = set()
    for name in toml_names:
        if name in seen:
            errors.append(f"duplicate toml_name: {name}")
        seen.add(name)

    # Non-empty grafana_uid lists
    for e in mirrored:
        if not e.get("grafana_uid"):
            errors.append(f"empty grafana_uid for {e.get('toml_name', '?')}")

    # No duplicate UIDs across all entries
    all_uids = []
    for e in mirrored:
        all_uids.extend(e.get("grafana_uid", []))
    for e in grafana_only:
        uid = e.get("grafana_uid", "")
        if uid:
            all_uids.append(uid)

    uid_seen = set()
    for uid in all_uids:
        if uid in uid_seen:
            errors.append(f"duplicate grafana_uid: {uid}")
        uid_seen.add(uid)

    return errors


def validate_cross(surfaces, toml_alarm_names, yaml_uids):
    """Validate cross-file invariants. Returns list of error strings.

    Args:
        surfaces: parsed alarm-surfaces.toml dict
        toml_alarm_names: set of alarm names from metric-alarms.toml
        yaml_uids: list of UIDs from henyey-slo-alerts.yaml (order preserved
                    for duplicate detection)
    """
    errors = []
    mirrored = surfaces.get("mirrored", [])
    grafana_only = surfaces.get("grafana_only", [])

    # YAML UID uniqueness
    yaml_uid_seen = set()
    for uid in yaml_uids:
        if uid in yaml_uid_seen:
            errors.append(f"duplicate YAML uid: {uid}")
        yaml_uid_seen.add(uid)
    yaml_uid_set = yaml_uid_seen

    # Every toml_name resolves to an alarm name in metric-alarms.toml
    for e in mirrored:
        if e["toml_name"] not in toml_alarm_names:
            errors.append(f"toml_name not in metric-alarms.toml: {e['toml_name']}")

    # Every grafana_uid resolves to a UID in henyey-slo-alerts.yaml
    classified_uids = set()
    for e in mirrored:
        for uid in e.get("grafana_uid", []):
            if uid not in yaml_uid_set:
                errors.append(f"mirrored uid not in YAML: {uid}")
            classified_uids.add(uid)
    for e in grafana_only:
        uid = e.get("grafana_uid", "")
        if uid:
            if uid not in yaml_uid_set:
                errors.append(f"grafana_only uid not in YAML: {uid}")
            classified_uids.add(uid)

    # Complete coverage: union == YAML set
    unclassified = yaml_uid_set - classified_uids
    if unclassified:
        errors.append(f"unclassified YAML UIDs: {', '.join(sorted(unclassified))}")

    stale = classified_uids - yaml_uid_set
    if stale:
        errors.append(f"stale UIDs not in YAML: {', '.join(sorted(stale))}")

    return errors


def render_reconciliation_table(surfaces):
    """Render the reconciliation table as a markdown string."""
    mirrored = surfaces.get("mirrored", [])
    lines = [
        "| Alarm | TOML name | Grafana UID(s) | monitor-tick | Grafana | Notes |",
        "|---|---|---|---|---|---|",
    ]
    for e in mirrored:
        uids = ", ".join(f"`{u}`" for u in e["grafana_uid"])
        notes = e.get("notes", "")
        lines.append(
            f"| {e['alarm']} | `{e['toml_name']}` | {uids} | {e['monitor_tick']} | {e['grafana']} | {notes} |"
        )
    return "\n".join(lines)


def render_non_overlaps_table(surfaces):
    """Render the intentional non-overlaps table as a markdown string."""
    grafana_only = surfaces.get("grafana_only", [])
    lines = [
        "| Grafana UID | Alert | Rationale |",
        "|---|---|---|",
    ]
    for e in grafana_only:
        lines.append(f"| `{e['grafana_uid']}` | {e['alarm']} | {e['rationale']} |")
    return "\n".join(lines)


def extract_toml_alarm_names(toml_path):
    """Extract all alarm names from metric-alarms.toml."""
    names = set()
    with open(toml_path) as f:
        for line in f:
            m = re.match(r'^name\s*=\s*"([^"]+)"', line.strip())
            if m:
                names.add(m.group(1))
    return names


def extract_yaml_uids(yaml_path):
    """Extract all UIDs from henyey-slo-alerts.yaml (preserving order for
    duplicate detection)."""
    uids = []
    with open(yaml_path) as f:
        for line in f:
            m = re.match(r'\s*-?\s*uid:\s+(\S+)', line)
            if m:
                uids.append(m.group(1))
    return uids
