#!/usr/bin/env python3
"""Regression tests for histogram-p99 alarm threshold behavior after rebucketing (#2641).

Verifies that lc-dispatch-to-join-slow with p99_threshold=7.0 correctly:
- Does NOT fire when p99 resolves to buckets 5.5, 6.0, or 7.0
- DOES fire when p99 resolves to bucket 8.0+
- Mean threshold fires independently of p99
"""

import importlib.util
from pathlib import Path

# Import eval-alarms.py (uses hyphen in filename)
_spec = importlib.util.spec_from_file_location(
    "eval_alarms",
    Path(__file__).parent / "eval-alarms.py",
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

eval_histogram_p99 = _mod.eval_histogram_p99

# CLOSE_CADENCE_BUCKETS from crates/app/src/metrics.rs
CLOSE_CADENCE_BUCKETS = [
    0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 3.0, 4.0, 4.5, 5.0, 5.5, 6.0,
    7.0, 8.0, 10.0, 15.0, 20.0, 30.0, 60.0, float("inf"),
]

ALARM = {
    "name": "lc-dispatch-to-join-slow",
    "metric": "henyey_ledger_close_dispatch_to_join_seconds",
    "kind": "histogram-p99",
    "expected_suffixes": ["_bucket", "_sum", "_count"],
    "p99_threshold": 7.0,
    "mean_threshold": 5.0,
    "min_count_delta": 20,
    "severity": "WARN",
}

METRIC = "henyey_ledger_close_dispatch_to_join_seconds"


def make_histogram_data(p99_bucket: float, count: int = 100, mean: float = 4.0):
    """Build current and prev prometheus data where p99 lands in the given bucket.

    The p99 bucket is the smallest le where the algorithm's running sum of
    cumulative deltas >= 0.99 * count_delta. Prometheus buckets are cumulative.
    To place p99 at a specific bucket, we put all observations just below that
    boundary — so cumulative is 0 for le < p99_bucket and jumps to count at p99_bucket.
    """
    total_sum = mean * count

    # Build cumulative bucket counts: 0 below target, count at and above
    bucket_series_cur = []
    for le in CLOSE_CADENCE_BUCKETS:
        if le < p99_bucket:
            bucket_series_cur.append(({"le": str(le) if le != float("inf") else "+Inf"}, 0))
        else:
            bucket_series_cur.append(({"le": str(le) if le != float("inf") else "+Inf"}, count))

    current = {
        f"{METRIC}_bucket": bucket_series_cur,
        f"{METRIC}_sum": [([], total_sum)],
        f"{METRIC}_count": [([], count)],
    }
    # Prev with zero values (simulates fresh start after deploy)
    bucket_series_prev = [({"le": str(le) if le != float("inf") else "+Inf"}, 0) for le in CLOSE_CADENCE_BUCKETS]
    prev = {
        f"{METRIC}_bucket": bucket_series_prev,
        f"{METRIC}_sum": [([], 0)],
        f"{METRIC}_count": [([], 0)],
    }
    return current, prev


def test_p99_at_5_5_does_not_fire():
    """p99 at 5.5 bucket (≤ threshold 7.0) → should NOT fire."""
    current, prev = make_histogram_data(p99_bucket=5.5, mean=4.0)
    result = eval_histogram_p99(ALARM, current, prev, prev_prom_invalid=False)
    assert result["state"] == "ok", f"Expected 'ok', got '{result['state']}' (p99=5.5, threshold=7.0)"


def test_p99_at_6_0_does_not_fire():
    """p99 at 6.0 bucket (≤ threshold 7.0) → should NOT fire."""
    current, prev = make_histogram_data(p99_bucket=6.0, mean=4.0)
    result = eval_histogram_p99(ALARM, current, prev, prev_prom_invalid=False)
    assert result["state"] == "ok", f"Expected 'ok', got '{result['state']}' (p99=6.0, threshold=7.0)"


def test_p99_at_7_0_does_not_fire():
    """p99 at 7.0 bucket (= threshold 7.0, strict >) → should NOT fire."""
    current, prev = make_histogram_data(p99_bucket=7.0, mean=4.0)
    result = eval_histogram_p99(ALARM, current, prev, prev_prom_invalid=False)
    assert result["state"] == "ok", f"Expected 'ok', got '{result['state']}' (p99=7.0, threshold=7.0, strict >)"


def test_p99_at_8_0_fires():
    """p99 at 8.0 bucket (> threshold 7.0) → should fire."""
    current, prev = make_histogram_data(p99_bucket=8.0, mean=4.0)
    result = eval_histogram_p99(ALARM, current, prev, prev_prom_invalid=False)
    assert result["state"] == "firing", f"Expected 'firing', got '{result['state']}' (p99=8.0, threshold=7.0)"


def test_p99_at_10_0_fires():
    """p99 at 10.0 bucket (> threshold 7.0) → should fire."""
    current, prev = make_histogram_data(p99_bucket=10.0, mean=4.0)
    result = eval_histogram_p99(ALARM, current, prev, prev_prom_invalid=False)
    assert result["state"] == "firing", f"Expected 'firing', got '{result['state']}' (p99=10.0, threshold=7.0)"


def test_mean_fires_independently_of_p99():
    """Mean > 5.0 should fire even when p99 ≤ 7.0."""
    current, prev = make_histogram_data(p99_bucket=5.5, mean=6.0)
    result = eval_histogram_p99(ALARM, current, prev, prev_prom_invalid=False)
    assert result["state"] == "firing", f"Expected 'firing' from mean breach, got '{result['state']}' (mean=6.0, mean_threshold=5.0)"


def test_mean_below_threshold_does_not_fire():
    """Mean ≤ 5.0 with p99 ≤ 7.0 → should NOT fire."""
    current, prev = make_histogram_data(p99_bucket=5.5, mean=4.5)
    result = eval_histogram_p99(ALARM, current, prev, prev_prom_invalid=False)
    assert result["state"] == "ok", f"Expected 'ok', got '{result['state']}' (mean=4.5, p99=5.5)"


def test_prev_prom_invalid_skips():
    """PREV_PROM_INVALID=true → should skip."""
    current, prev = make_histogram_data(p99_bucket=8.0, mean=6.0)
    result = eval_histogram_p99(ALARM, current, prev, prev_prom_invalid=True)
    assert result["state"] == "skipped", f"Expected 'skipped', got '{result['state']}'"


if __name__ == "__main__":
    tests = [
        test_p99_at_5_5_does_not_fire,
        test_p99_at_6_0_does_not_fire,
        test_p99_at_7_0_does_not_fire,
        test_p99_at_8_0_fires,
        test_p99_at_10_0_fires,
        test_mean_fires_independently_of_p99,
        test_mean_below_threshold_does_not_fire,
        test_prev_prom_invalid_skips,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
            print(f"  PASS: {test.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL: {test.__name__}: {e}")

    print(f"\n{passed}/{passed + failed} tests passed")
    if failed:
        raise SystemExit(1)
