#!/usr/bin/env python3
"""Tests for scripts/lib/dedup-filing.py."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta

SCRIPT = os.path.join(os.path.dirname(__file__), "dedup-filing.py")


def run_cmd(subcmd, args=None, stdin_data=None):
    """Run dedup-filing.py with given subcommand and return (exit_code, stdout, stderr)."""
    cmd = [sys.executable, SCRIPT, subcmd] + (args or [])
    proc = subprocess.run(
        cmd,
        input=stdin_data,
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


class TestLoad(unittest.TestCase):
    def test_missing_file(self):
        rc, out, err = run_cmd("load", ["/nonexistent/file.json"])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["filed"], {})

    def test_corrupt_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json {{{")
            f.flush()
            rc, out, err = run_cmd("load", [f.name])
        os.unlink(f.name)
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["filed"], {})
        self.assertIn("WARNING", err)

    def test_invalid_schema_version(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"schema_version": 99, "filed": {}}, f)
            f.flush()
            rc, out, err = run_cmd("load", [f.name])
        os.unlink(f.name)
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["filed"], {})
        self.assertIn("WARNING", err)

    def test_valid_file(self):
        entry = {"filed_at": "2025-01-01T00:00:00Z", "issue_number": 42}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"schema_version": 1, "filed": {"key1": entry}}, f)
            f.flush()
            rc, out, err = run_cmd("load", [f.name])
        os.unlink(f.name)
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(data["filed"]["key1"]["issue_number"], 42)

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.flush()
            rc, out, err = run_cmd("load", [f.name])
        os.unlink(f.name)
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(data["filed"], {})


class TestPrune(unittest.TestCase):
    def _make_data(self, entries):
        return json.dumps({"schema_version": 1, "filed": entries})

    def test_prune_24h(self):
        now = datetime.now(timezone.utc)
        fresh = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        stale = (now - timedelta(hours=25)).strftime("%Y-%m-%dT%H:%M:%SZ")
        data = self._make_data({
            "fresh": {"filed_at": fresh, "issue_number": 1},
            "stale": {"filed_at": stale, "issue_number": 2},
        })
        rc, out, err = run_cmd("prune", ["24h"], stdin_data=data)
        self.assertEqual(rc, 0)
        result = json.loads(out)
        self.assertIn("fresh", result["filed"])
        self.assertNotIn("stale", result["filed"])

    def test_prune_30d(self):
        now = datetime.now(timezone.utc)
        fresh = (now - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        stale = (now - timedelta(days=31)).strftime("%Y-%m-%dT%H:%M:%SZ")
        data = self._make_data({
            "fresh": {"filed_at": fresh},
            "stale": {"filed_at": stale},
        })
        rc, out, err = run_cmd("prune", ["30d"], stdin_data=data)
        self.assertEqual(rc, 0)
        result = json.loads(out)
        self.assertIn("fresh", result["filed"])
        self.assertNotIn("stale", result["filed"])

    def test_prune_mixed_timestamps(self):
        now = datetime.now(timezone.utc)
        ts_z = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        ts_offset = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        ts_frac = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S") + ".123456+00:00"
        data = self._make_data({
            "a": {"filed_at": ts_z},
            "b": {"filed_at": ts_offset},
            "c": {"filed_at": ts_frac},
        })
        rc, out, err = run_cmd("prune", ["24h"], stdin_data=data)
        self.assertEqual(rc, 0)
        result = json.loads(out)
        self.assertEqual(len(result["filed"]), 3)

    def test_prune_malformed_entry_dropped(self):
        now = datetime.now(timezone.utc)
        fresh = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        data = self._make_data({
            "good": {"filed_at": fresh},
            "bad_ts": {"filed_at": "not-a-date"},
            "no_ts": {"issue_number": 1},
        })
        rc, out, err = run_cmd("prune", ["24h"], stdin_data=data)
        self.assertEqual(rc, 0)
        result = json.loads(out)
        self.assertIn("good", result["filed"])
        self.assertNotIn("bad_ts", result["filed"])
        self.assertNotIn("no_ts", result["filed"])

    def test_prune_invalid_ttl(self):
        data = self._make_data({})
        rc, out, err = run_cmd("prune", ["invalid"], stdin_data=data)
        self.assertEqual(rc, 1)
        self.assertIn("Invalid TTL spec", err)

    def test_prune_empty_filed(self):
        data = self._make_data({})
        rc, out, err = run_cmd("prune", ["24h"], stdin_data=data)
        self.assertEqual(rc, 0)
        result = json.loads(out)
        self.assertEqual(result["filed"], {})


class TestCheck(unittest.TestCase):
    def test_hit(self):
        data = json.dumps({"schema_version": 1, "filed": {
            "mykey": {"filed_at": "2025-01-01T00:00:00Z", "issue_number": 42}
        }})
        rc, out, err = run_cmd("check", ["mykey"], stdin_data=data)
        self.assertEqual(rc, 0)
        entry = json.loads(out)
        self.assertEqual(entry["issue_number"], 42)

    def test_miss(self):
        data = json.dumps({"schema_version": 1, "filed": {}})
        rc, out, err = run_cmd("check", ["mykey"], stdin_data=data)
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")

    def test_bad_json(self):
        rc, out, err = run_cmd("check", ["mykey"], stdin_data="not json")
        self.assertEqual(rc, 2)


class TestRecord(unittest.TestCase):
    def test_new_entry(self):
        data = json.dumps({"schema_version": 1, "filed": {}})
        rc, out, err = run_cmd("record", ["k1", "issue_number=42", "issue_url=http://example.com"], stdin_data=data)
        self.assertEqual(rc, 0)
        result = json.loads(out)
        entry = result["filed"]["k1"]
        self.assertEqual(entry["issue_number"], 42)
        self.assertEqual(entry["issue_url"], "http://example.com")
        self.assertIn("filed_at", entry)

    def test_filed_at_protected(self):
        data = json.dumps({"schema_version": 1, "filed": {}})
        rc, out, err = run_cmd("record", ["k1", "filed_at=1999-01-01T00:00:00Z"], stdin_data=data)
        self.assertEqual(rc, 0)
        result = json.loads(out)
        # filed_at should be current time, not the provided value
        self.assertNotEqual(result["filed"]["k1"]["filed_at"], "1999-01-01T00:00:00Z")

    def test_numeric_coercion(self):
        data = json.dumps({"schema_version": 1, "filed": {}})
        rc, out, err = run_cmd("record", ["k1", "issue_number=123", "name=abc"], stdin_data=data)
        self.assertEqual(rc, 0)
        result = json.loads(out)
        self.assertIsInstance(result["filed"]["k1"]["issue_number"], int)
        self.assertIsInstance(result["filed"]["k1"]["name"], str)

    def test_value_with_equals(self):
        data = json.dumps({"schema_version": 1, "filed": {}})
        rc, out, err = run_cmd("record", ["k1", "url=http://example.com?a=b"], stdin_data=data)
        self.assertEqual(rc, 0)
        result = json.loads(out)
        self.assertEqual(result["filed"]["k1"]["url"], "http://example.com?a=b")

    def test_malformed_kv(self):
        data = json.dumps({"schema_version": 1, "filed": {}})
        rc, out, err = run_cmd("record", ["k1", "noequalssign"], stdin_data=data)
        self.assertEqual(rc, 1)
        self.assertIn("Malformed", err)

    def test_preserves_unknown_fields(self):
        data = json.dumps({"schema_version": 1, "filed": {
            "k1": {"filed_at": "2025-01-01T00:00:00Z", "custom_field": "hello"}
        }})
        rc, out, err = run_cmd("record", ["k1", "issue_number=99"], stdin_data=data)
        self.assertEqual(rc, 0)
        result = json.loads(out)
        self.assertEqual(result["filed"]["k1"]["custom_field"], "hello")
        self.assertEqual(result["filed"]["k1"]["issue_number"], 99)


class TestRemove(unittest.TestCase):
    def test_existing_key(self):
        data = json.dumps({"schema_version": 1, "filed": {
            "k1": {"filed_at": "2025-01-01T00:00:00Z"}
        }})
        rc, out, err = run_cmd("remove", ["k1"], stdin_data=data)
        self.assertEqual(rc, 0)
        result = json.loads(out)
        self.assertNotIn("k1", result["filed"])

    def test_missing_key_noop(self):
        data = json.dumps({"schema_version": 1, "filed": {}})
        rc, out, err = run_cmd("remove", ["k1"], stdin_data=data)
        self.assertEqual(rc, 0)

    def test_bad_json(self):
        rc, out, err = run_cmd("remove", ["k1"], stdin_data="bad")
        self.assertEqual(rc, 1)


class TestUpdateField(unittest.TestCase):
    def test_update_existing(self):
        data = json.dumps({"schema_version": 1, "filed": {
            "k1": {"filed_at": "2025-01-01T00:00:00Z", "last_commented_date": ""}
        }})
        rc, out, err = run_cmd("update-field", ["k1", "last_commented_date", "2025-06-15"], stdin_data=data)
        self.assertEqual(rc, 0)
        result = json.loads(out)
        self.assertEqual(result["filed"]["k1"]["last_commented_date"], "2025-06-15")

    def test_missing_key_fails(self):
        data = json.dumps({"schema_version": 1, "filed": {}})
        rc, out, err = run_cmd("update-field", ["k1", "field", "value"], stdin_data=data)
        self.assertEqual(rc, 1)
        self.assertIn("Key not found", err)


class TestWrite(unittest.TestCase):
    def test_atomic_write(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            target = f.name
        data = json.dumps({"schema_version": 1, "filed": {"k1": {"filed_at": "2025-01-01T00:00:00Z"}}})
        rc, out, err = run_cmd("write", [target], stdin_data=data)
        self.assertEqual(rc, 0)
        with open(target) as f:
            content = f.read()
        os.unlink(target)
        result = json.loads(content)
        self.assertEqual(result["filed"]["k1"]["filed_at"], "2025-01-01T00:00:00Z")
        # Should end with newline
        self.assertTrue(content.endswith("\n"))

    def test_bad_json_fails(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            target = f.name
        rc, out, err = run_cmd("write", [target], stdin_data="not json")
        os.unlink(target)
        self.assertEqual(rc, 1)


class TestCompatibility(unittest.TestCase):
    """Tests for backward compatibility with existing dedup files."""

    def test_issue_url_entries_survive_roundtrip(self):
        """alarm-regression stores issue_url — verify it survives load→prune→check."""
        now = datetime.now(timezone.utc)
        fresh = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        data = {"schema_version": 1, "filed": {
            "lost-sync": {"filed_at": fresh, "issue_url": "https://github.com/org/repo/issues/123"}
        }}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            rc, out, _ = run_cmd("load", [f.name])
        os.unlink(f.name)
        self.assertEqual(rc, 0)

        # Prune
        rc, out, _ = run_cmd("prune", ["24h"], stdin_data=out)
        self.assertEqual(rc, 0)
        result = json.loads(out)
        self.assertEqual(result["filed"]["lost-sync"]["issue_url"], "https://github.com/org/repo/issues/123")

        # Check
        rc, entry_out, _ = run_cmd("check", ["lost-sync"], stdin_data=out)
        self.assertEqual(rc, 0)
        entry = json.loads(entry_out)
        self.assertEqual(entry["issue_url"], "https://github.com/org/repo/issues/123")

    def test_last_commented_date_survives(self):
        """monitor-tick stores last_commented_date — verify update-field works."""
        data = json.dumps({"schema_version": 1, "filed": {
            "abc123": {"filed_at": "2025-01-01T00:00:00Z", "issue_number": 42, "last_commented_date": "2025-01-01"}
        }})
        rc, out, _ = run_cmd("update-field", ["abc123", "last_commented_date", "2025-06-15"], stdin_data=data)
        self.assertEqual(rc, 0)
        result = json.loads(out)
        self.assertEqual(result["filed"]["abc123"]["last_commented_date"], "2025-06-15")
        self.assertEqual(result["filed"]["abc123"]["issue_number"], 42)

    def test_remove_and_refile(self):
        """monitor-tick closed-predecessor flow: remove old entry, record new one."""
        data = json.dumps({"schema_version": 1, "filed": {
            "sha1": {"filed_at": "2025-01-01T00:00:00Z", "issue_number": 100}
        }})
        # Remove
        rc, out, _ = run_cmd("remove", ["sha1"], stdin_data=data)
        self.assertEqual(rc, 0)
        result = json.loads(out)
        self.assertNotIn("sha1", result["filed"])

        # Record new
        rc, out, _ = run_cmd("record", ["sha1", "issue_number=200", "last_commented_date=2025-06-15"], stdin_data=out)
        self.assertEqual(rc, 0)
        result = json.loads(out)
        self.assertEqual(result["filed"]["sha1"]["issue_number"], 200)


class TestShellWrapper(unittest.TestCase):
    """End-to-end test via the shell wrapper."""

    def test_roundtrip(self):
        """load→prune→check→record→write→load round-trip."""
        wrapper = os.path.join(os.path.dirname(__file__), "dedup-filing.sh")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            target = f.name

        script = f"""
        source "{wrapper}"
        DATA=$(dedup_load "{target}")
        DATA=$(dedup_prune "$DATA" "24h")
        if dedup_check "$DATA" "testkey" >/dev/null 2>&1; then
            echo "UNEXPECTED_HIT"
            exit 1
        fi
        DATA=$(dedup_record "$DATA" "testkey" "issue_number=42")
        dedup_write "{target}" "$DATA"

        # Reload and verify
        DATA2=$(dedup_load "{target}")
        if entry=$(dedup_check "$DATA2" "testkey"); then
            echo "HIT:$entry"
        else
            echo "MISS"
            exit 1
        fi
        """
        proc = subprocess.run(
            ["bash", "-e", "-c", script],
            capture_output=True, text=True,
        )
        os.unlink(target)
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        self.assertIn("HIT:", proc.stdout)
        entry = json.loads(proc.stdout.split("HIT:")[1].strip())
        self.assertEqual(entry["issue_number"], 42)


if __name__ == "__main__":
    unittest.main()
