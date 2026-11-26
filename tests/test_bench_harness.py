"""GATE-43: the benchmark harness under bench/. These tests check the harness, never a speed.

They were committed before the harness. No test here sets a performance threshold: that is the
maintainer's to set, and a threshold on a shared CI machine would be noise.
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LINUX = sys.platform.startswith("linux")
needs_proc = pytest.mark.skipif(not LINUX, reason="the harness reads /proc")

try:
    from bench import harness
except (
    ImportError
):  # pragma: no cover - before the harness exists, so the tests fail as "not built"
    harness = None


def _h():
    assert harness is not None, "bench/harness.py is not built yet"
    return harness


class TestPercentile:
    def test_nearest_rank_on_a_known_list(self):
        values = list(range(1, 101))
        h = _h()
        assert h.percentile(values, 0.50) == 51
        assert h.percentile(values, 0.95) == 96
        assert h.percentile(values, 0.99) == 100
        assert h.percentile([7.0], 0.99) == 7.0

    def test_unsorted_input_and_no_mutation(self):
        values = [5, 1, 4, 2, 3]
        assert _h().percentile(values, 0.5) == 3
        assert values == [5, 1, 4, 2, 3]

    def test_empty_input_is_an_error_not_a_zero(self):
        with pytest.raises(ValueError):
            _h().percentile([], 0.5)


class TestFiller:
    @pytest.mark.parametrize("size", [100, 10 * 1024, 1024 * 1024])
    def test_it_is_exactly_the_size_asked_for_and_seeded(self, size):
        h = _h()
        a = h.filler(size, random.Random(20261126))
        b = h.filler(size, random.Random(20261126))
        assert len(a.encode("utf-8")) == size
        assert a == b, "the same seed gives the same string"
        assert a != h.filler(size, random.Random(1)) or size == 100

    def test_it_stays_below_the_secret_scan_entropy_threshold(self):
        from bawbel_gate.policy.manifest import _secret_scan

        h = _h()
        assert not _secret_scan(h.filler(1024 * 1024, random.Random(20261126)))


class TestSpecAndResult:
    def test_the_machine_spec_names_os_cpu_memory_and_python(self):
        spec = _h().machine_spec()
        for key in ("os", "cpu", "logical_cpus", "ram_mib", "python"):
            assert key in spec and spec[key] not in (None, "")

    def test_every_result_carries_the_spec_and_the_seed(self):
        result = _h().make_result("single", seed=20261126, metrics={"calls_per_s": 1.0})
        assert result["scenario"] == "single"
        assert result["seed"] == 20261126
        assert "cpu" in result["machine"]
        assert result["metrics"] == {"calls_per_s": 1.0}
        json.dumps(result)

    def test_the_text_form_prints_the_spec_and_the_seed_first(self):
        result = _h().make_result("single", seed=7, metrics={"calls_per_s": 1.0})
        lines = _h().render(result).splitlines()
        assert lines[0].startswith("machine:") and lines[1] == "seed: 7"

    @needs_proc
    def test_process_stats_read_this_process(self):
        stats = _h().proc_stats(os.getpid())
        assert (
            stats["fds"] >= 3 and stats["rss_mib"] > 0 and stats["peak_rss_mib"] >= stats["rss_mib"]
        )


class TestScenarios:
    def test_the_scenario_names_are_the_runbook_list(self):
        names = set(_h().SCENARIOS)
        assert names >= {
            "single",
            "concurrent-10",
            "concurrent-100",
            "args-100B",
            "args-10KiB",
            "args-1MiB",
            "approval-wait",
            "loop-10000",
            "stalled-upstream",
            "audit-write-fails",
            "telemetry-down",
        }

    def test_the_telemetry_scenario_is_skipped_with_a_reason_when_the_sdk_is_absent(
        self, monkeypatch
    ):
        h = _h()
        monkeypatch.setattr(h, "otel_sdk_available", lambda: False)
        result = h.run_scenario("telemetry-down", seed=1, calls=10)
        assert result["skipped"] and "OpenTelemetry" in result["skipped"]


@needs_proc
class TestSmoke:
    def test_a_short_single_session_run_works_end_to_end(self, tmp_path):
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(ROOT), str(ROOT / "src")]))
        out = subprocess.run(
            [
                sys.executable,
                "-m",
                "bench.run",
                "single",
                "--calls",
                "200",
                "--seed",
                "20261126",
                "--json",
            ],
            capture_output=True,
            text=True,
            cwd=ROOT,
            env=env,
            timeout=120,
            check=False,
        )
        assert out.returncode == 0, out.stderr[-400:]
        result = json.loads(out.stdout.strip().splitlines()[-1])
        assert result["scenario"] == "single" and result["seed"] == 20261126
        metrics = result["metrics"]
        for key in (
            "calls",
            "calls_per_s",
            "added_p50_ms",
            "added_p95_ms",
            "added_p99_ms",
            "cpu_s_per_1000_calls",
            "peak_rss_mib",
            "audit_bytes_per_s",
            "open_fds",
        ):
            assert key in metrics, key
        assert metrics["calls"] == 200
