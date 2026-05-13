"""Tests for check-alarm-versions.py."""

from __future__ import annotations

import os
import sys
import textwrap

import pytest

# Import the module under test
sys.path.insert(0, os.path.dirname(__file__))
from importlib import import_module

# Import as module (hyphen in filename requires importlib)
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "check_alarm_versions",
    os.path.join(os.path.dirname(__file__), "check-alarm-versions.py"),
)
_mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

check_alarm_versions = _mod.check_alarm_versions
parse_toml = _mod.parse_toml
SEMANTIC_FIELDS = _mod.SEMANTIC_FIELDS
NON_SEMANTIC_FIELDS = _mod.NON_SEMANTIC_FIELDS


def _write_toml(tmp_path, name: str, content: str) -> str:
    p = tmp_path / name
    p.write_text(textwrap.dedent(content))
    return str(p)


# ── Test 1: Semantic change without version bump → warning ────────────────

def test_semantic_change_no_bump(tmp_path):
    old = _write_toml(tmp_path, "old.toml", """\
        [[alarm]]
        name = "test-alarm"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    new = _write_toml(tmp_path, "new.toml", """\
        [[alarm]]
        name = "test-alarm"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 10
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    errors, warnings, notices, hard = check_alarm_versions(old, new)
    assert not hard
    assert len(warnings) == 1
    assert "threshold" in warnings[0]
    assert "not bumped" in warnings[0]


# ── Test 2: Semantic change with version bump → no warning ────────────────

def test_semantic_change_with_bump(tmp_path):
    old = _write_toml(tmp_path, "old.toml", """\
        [[alarm]]
        name = "test-alarm"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    new = _write_toml(tmp_path, "new.toml", """\
        [[alarm]]
        name = "test-alarm"
        baseline_version = 2
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 10
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    errors, warnings, notices, hard = check_alarm_versions(old, new)
    assert not hard
    assert len(warnings) == 0


# ── Test 3: Cosmetic-only changes → no warning ───────────────────────────

def test_cosmetic_only_changes(tmp_path):
    old = _write_toml(tmp_path, "old.toml", """\
        [[alarm]]
        name = "test-alarm"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "old title"
        filing_search = "old search"
        summary = "old summary"
        details = "old details"
        notes = "old notes"
    """)
    new = _write_toml(tmp_path, "new.toml", """\
        [[alarm]]
        name = "test-alarm"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        severity = "ACTION"
        gates = []
        cooldown_key = "bar"
        cooldown_seconds = 7200
        filing_title = "new title"
        filing_search = "new search"
        summary = "new summary"
        details = "new details"
        notes = "new notes"
    """)
    errors, warnings, notices, hard = check_alarm_versions(old, new)
    assert not hard
    assert len(warnings) == 0


# ── Test 4: New alarm added → no warning ──────────────────────────────────

def test_new_alarm(tmp_path):
    old = _write_toml(tmp_path, "old.toml", """\
        [[alarm]]
        name = "existing"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    new = _write_toml(tmp_path, "new.toml", """\
        [[alarm]]
        name = "existing"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""

        [[alarm]]
        name = "brand-new"
        kind = "counter"
        metric = "bar"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 1
        severity = "WARN"
        gates = []
        cooldown_key = "bar"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    errors, warnings, notices, hard = check_alarm_versions(old, new)
    assert not hard
    assert len(warnings) == 0


# ── Test 5: Alarm deleted → no warning ────────────────────────────────────

def test_alarm_deleted(tmp_path):
    old = _write_toml(tmp_path, "old.toml", """\
        [[alarm]]
        name = "to-delete"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    new = _write_toml(tmp_path, "new.toml", "")
    errors, warnings, notices, hard = check_alarm_versions(old, new)
    assert not hard
    assert len(warnings) == 0


# ── Test 6: Multiple alarms, mixed changes ────────────────────────────────

def test_multiple_alarms_mixed(tmp_path):
    old = _write_toml(tmp_path, "old.toml", """\
        [[alarm]]
        name = "alarm-a"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = []
        cooldown_key = "a"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""

        [[alarm]]
        name = "alarm-b"
        kind = "counter"
        metric = "bar"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 10
        severity = "WARN"
        gates = []
        cooldown_key = "b"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    new = _write_toml(tmp_path, "new.toml", """\
        [[alarm]]
        name = "alarm-a"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 99
        severity = "WARN"
        gates = []
        cooldown_key = "a"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""

        [[alarm]]
        name = "alarm-b"
        baseline_version = 2
        kind = "counter"
        metric = "bar"
        extraction = "form2"
        labels = []
        op = ">="
        threshold = 10
        severity = "WARN"
        gates = []
        cooldown_key = "b"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    errors, warnings, notices, hard = check_alarm_versions(old, new)
    assert not hard
    assert len(warnings) == 1
    assert "alarm-a" in warnings[0]


# ── Test 7: Duplicate alarm names → error ─────────────────────────────────

def test_duplicate_names(tmp_path):
    old = _write_toml(tmp_path, "old.toml", "")
    new = _write_toml(tmp_path, "new.toml", """\
        [[alarm]]
        name = "dupe"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 1
        severity = "WARN"
        gates = []
        cooldown_key = "d"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""

        [[alarm]]
        name = "dupe"
        kind = "counter"
        metric = "bar"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 2
        severity = "WARN"
        gates = []
        cooldown_key = "d2"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    errors, warnings, notices, hard = check_alarm_versions(old, new)
    assert hard
    assert any("Duplicate" in e for e in errors)


# ── Test 8: Decreased baseline_version → error ───────────────────────────

def test_decreased_version(tmp_path):
    old = _write_toml(tmp_path, "old.toml", """\
        [[alarm]]
        name = "test-alarm"
        baseline_version = 3
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    new = _write_toml(tmp_path, "new.toml", """\
        [[alarm]]
        name = "test-alarm"
        baseline_version = 2
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 10
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    errors, warnings, notices, hard = check_alarm_versions(old, new)
    assert hard
    assert any("decreased" in e for e in errors)


# ── Test 9: semantic_change_date only edit → no warning ───────────────────

def test_semantic_change_date_only(tmp_path):
    old = _write_toml(tmp_path, "old.toml", """\
        [[alarm]]
        name = "test-alarm"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    new = _write_toml(tmp_path, "new.toml", """\
        [[alarm]]
        name = "test-alarm"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        semantic_change_date = "2026-01-01T00:00:00Z"
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    errors, warnings, notices, hard = check_alarm_versions(old, new)
    assert not hard
    assert len(warnings) == 0


# ── Test 10: List field reordering → no warning ──────────────────────────

def test_list_reordering(tmp_path):
    old = _write_toml(tmp_path, "old.toml", """\
        [[alarm]]
        name = "test-alarm"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = ["warmup-2-ticks", "gate-b"]
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    new = _write_toml(tmp_path, "new.toml", """\
        [[alarm]]
        name = "test-alarm"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = ["gate-b", "warmup-2-ticks"]
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    errors, warnings, notices, hard = check_alarm_versions(old, new)
    assert not hard
    assert len(warnings) == 0


# ── Test 11: Mixed semantic + cosmetic → warning for semantic only ────────

def test_mixed_semantic_cosmetic(tmp_path):
    old = _write_toml(tmp_path, "old.toml", """\
        [[alarm]]
        name = "test-alarm"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "old"
        filing_search = "old"
        summary = "old"
        details = "old"
        notes = "old"
    """)
    new = _write_toml(tmp_path, "new.toml", """\
        [[alarm]]
        name = "test-alarm"
        kind = "counter"
        metric = "foo"
        extraction = "form2"
        labels = []
        op = ">="
        threshold = 5
        severity = "ACTION"
        gates = []
        cooldown_key = "bar"
        cooldown_seconds = 7200
        filing_title = "new"
        filing_search = "new"
        summary = "new"
        details = "new"
        notes = "new"
    """)
    errors, warnings, notices, hard = check_alarm_versions(old, new)
    assert not hard
    assert len(warnings) == 1
    assert "extraction" in warnings[0]


# ── Test 12: Empty old file → all new, no warnings ───────────────────────

def test_empty_old_file(tmp_path):
    old = _write_toml(tmp_path, "old.toml", "")
    new = _write_toml(tmp_path, "new.toml", """\
        [[alarm]]
        name = "new-alarm"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    errors, warnings, notices, hard = check_alarm_versions(old, new)
    assert not hard
    assert len(warnings) == 0


# ── Test 13: Version bumped without semantic_change_date → notice ─────────

def test_bump_without_semantic_change_date(tmp_path):
    old = _write_toml(tmp_path, "old.toml", """\
        [[alarm]]
        name = "test-alarm"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    new = _write_toml(tmp_path, "new.toml", """\
        [[alarm]]
        name = "test-alarm"
        baseline_version = 2
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 10
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    errors, warnings, notices, hard = check_alarm_versions(old, new)
    assert not hard
    assert len(warnings) == 0
    assert len(notices) == 1
    assert "semantic_change_date" in notices[0]


# ── Test 14: Unknown field → error ────────────────────────────────────────

def test_unknown_field(tmp_path):
    old = _write_toml(tmp_path, "old.toml", "")
    new = _write_toml(tmp_path, "new.toml", """\
        [[alarm]]
        name = "test-alarm"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
        brand_new_field = "surprise"
    """)
    errors, warnings, notices, hard = check_alarm_versions(old, new)
    assert hard
    assert any("unknown field" in e for e in errors)


# ── Test 15: Labels structural change → warning ──────────────────────────

def test_labels_structural_change(tmp_path):
    old = _write_toml(tmp_path, "old.toml", """\
        [[alarm]]
        name = "test-alarm"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""

        [[alarm.labels]]
        key = "reason"
        value = "old_value"
    """)
    new = _write_toml(tmp_path, "new.toml", """\
        [[alarm]]
        name = "test-alarm"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""

        [[alarm.labels]]
        key = "reason"
        value = "new_value"
    """)
    errors, warnings, notices, hard = check_alarm_versions(old, new)
    assert not hard
    assert len(warnings) == 1
    assert "labels" in warnings[0]


# ── Test 16: Adding explicit default → warning ───────────────────────────

def test_adding_explicit_default(tmp_path):
    old = _write_toml(tmp_path, "old.toml", """\
        [[alarm]]
        name = "test-alarm"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    new = _write_toml(tmp_path, "new.toml", """\
        [[alarm]]
        name = "test-alarm"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        for_ticks = 1
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    errors, warnings, notices, hard = check_alarm_versions(old, new)
    assert not hard
    assert len(warnings) == 1
    assert "for_ticks" in warnings[0]


# ── Test 17: Rename (delete + add) → no warning ──────────────────────────

def test_rename_as_delete_add(tmp_path):
    old = _write_toml(tmp_path, "old.toml", """\
        [[alarm]]
        name = "old-name"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    new = _write_toml(tmp_path, "new.toml", """\
        [[alarm]]
        name = "new-name"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    errors, warnings, notices, hard = check_alarm_versions(old, new)
    assert not hard
    assert len(warnings) == 0


# ── Test 18: Exempt field added → warning ─────────────────────────────────

def test_exempt_field_added(tmp_path):
    old = _write_toml(tmp_path, "old.toml", """\
        [[alarm]]
        name = "test-alarm"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    new = _write_toml(tmp_path, "new.toml", """\
        [[alarm]]
        name = "test-alarm"
        kind = "counter"
        metric = "foo"
        extraction = "form1"
        labels = []
        op = ">="
        threshold = 5
        exempt = true
        exempt_reason = "testing"
        severity = "WARN"
        gates = []
        cooldown_key = "foo"
        cooldown_seconds = 3600
        filing_title = "t"
        filing_search = "s"
        summary = "s"
        details = "d"
        notes = ""
    """)
    errors, warnings, notices, hard = check_alarm_versions(old, new)
    assert not hard
    assert len(warnings) == 1
    assert "exempt" in warnings[0]


# ── Test: Real alarm file validates without unknown fields ────────────────

def test_real_alarm_file_no_unknown_fields():
    """Validate the real metric-alarms.toml has no unknown fields."""
    # Find the real alarm file relative to this test
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    alarm_file = os.path.join(repo_root, ".claude", "skills", "shared", "metric-alarms.toml")
    if not os.path.exists(alarm_file):
        pytest.skip("Real alarm file not found")

    # Compare against itself — should produce no errors, warnings, or notices
    errors, warnings, notices, hard = check_alarm_versions(alarm_file, alarm_file)
    assert not hard, f"Unexpected errors: {errors}"
    assert len(warnings) == 0
    assert len(errors) == 0
