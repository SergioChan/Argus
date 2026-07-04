from __future__ import annotations

import importlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class S1PerfScaleBatteryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.battery = importlib.import_module("scripts.run_s1_perf_scale_battery")

    def test_battery_covers_s1_tc33_tc34_tc35_with_real_counts(self) -> None:
        evidence = self.battery._run_battery(
            sequential_jobs=20,
            concurrent_jobs=12,
            scale_events=100,
            samples=10,
            accept_plan_slo_seconds=3.0,
            state_query_slo_seconds=0.5,
            max_workers=4,
        )

        checks = {check["test_case"]: check for check in evidence["checks"]}
        self.assertTrue(evidence["ok"])
        self.assertEqual(set(checks), {"S1-TC-33", "S1-TC-34", "S1-TC-35"})
        self.assertEqual(checks["S1-TC-33"]["sequential_jobs"], 20)
        self.assertEqual(checks["S1-TC-33"]["accepted_jobs"], 20)
        self.assertEqual(checks["S1-TC-33"]["planned_jobs"], 20)
        self.assertLessEqual(checks["S1-TC-33"]["accept_plan_p95_seconds"], 3.0)
        self.assertEqual(checks["S1-TC-34"]["concurrent_jobs"], 12)
        self.assertEqual(checks["S1-TC-34"]["terminal_jobs"], 12)
        self.assertEqual(checks["S1-TC-34"]["failures"], [])
        self.assertTrue(checks["S1-TC-34"]["event_log_consistent"])
        self.assertEqual(checks["S1-TC-35"]["scale_events"], 100)
        self.assertEqual(checks["S1-TC-35"]["lifecycle_artifacts"], 100)
        self.assertEqual(checks["S1-TC-35"]["sampled_terminal_jobs"], 10)
        self.assertEqual(checks["S1-TC-35"]["drift_count"], 0)
        self.assertLessEqual(checks["S1-TC-35"]["state_lineage_p95_seconds"], 0.5)

    def test_battery_fails_closed_when_declared_budget_is_missed(self) -> None:
        evidence = self.battery._run_battery(
            sequential_jobs=5,
            concurrent_jobs=4,
            scale_events=20,
            samples=3,
            accept_plan_slo_seconds=0.0,
            state_query_slo_seconds=0.5,
            max_workers=2,
        )

        checks = {check["test_case"]: check for check in evidence["checks"]}
        self.assertFalse(evidence["ok"])
        self.assertFalse(checks["S1-TC-33"]["ok"])
        self.assertIn("S1-TC-33", evidence["failed_test_cases"])

    def test_cli_writes_machine_readable_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            evidence_path = Path(tempdir) / "s1-perf-scale-evidence.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "run_s1_perf_scale_battery.py"),
                    "--sequential-jobs",
                    "5",
                    "--concurrent-jobs",
                    "4",
                    "--scale-events",
                    "20",
                    "--samples",
                    "3",
                    "--evidence-file",
                    str(evidence_path),
                ],
                cwd=ROOT,
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            self.assertTrue(evidence["ok"])
            self.assertEqual(evidence["battery"], "s1-perf-scale")


if __name__ == "__main__":
    unittest.main()
