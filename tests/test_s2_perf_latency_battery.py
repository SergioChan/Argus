from __future__ import annotations

import importlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class S2PerfLatencyBatteryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.battery = importlib.import_module("scripts.run_s2_perf_latency_battery")

    def test_battery_covers_s2_tc34_tc35_tc36_with_real_s2_paths(self) -> None:
        evidence = self.battery._run_battery(
            hpo_trials=6,
            hpo_workers=3,
            hpo_trial_delay_seconds=0.05,
            hpo_parallel_efficiency=0.7,
            hpo_scheduler_backend="threadpool",
            setup_latency_slo_seconds=10.0,
            freeze_replay_fraction_slo=0.05,
        )

        checks = {check["test_case"]: check for check in evidence["checks"]}
        self.assertTrue(evidence["ok"])
        self.assertEqual(set(checks), {"S2-TC34", "S2-TC35", "S2-TC36"})

        self.assertEqual(checks["S2-TC34"]["scheduled_trials"], 6)
        self.assertEqual(checks["S2-TC34"]["worker_count"], 3)
        self.assertEqual(checks["S2-TC34"]["single_worker_succeeded_trials"], 6)
        self.assertEqual(checks["S2-TC34"]["parallel_succeeded_trials"], 6)
        self.assertLessEqual(
            checks["S2-TC34"]["parallel_wallclock_seconds"],
            checks["S2-TC34"]["threshold_wallclock_seconds"],
        )

        self.assertLessEqual(checks["S2-TC35"]["setup_wallclock_seconds"], 10.0)
        self.assertEqual(checks["S2-TC35"]["spec_compiler_status"], "SUCCEEDED")
        self.assertEqual(checks["S2-TC35"]["data_manager_status"], "SUCCEEDED")
        self.assertEqual(checks["S2-TC35"]["feature_graph_status"], "SUCCEEDED")
        self.assertGreater(checks["S2-TC35"]["dataset_rows"], 0)

        self.assertTrue(checks["S2-TC36"]["self_replay_passed"])
        self.assertLessEqual(checks["S2-TC36"]["self_replay_fraction"], 0.05)
        self.assertGreater(checks["S2-TC36"]["build_wallclock_seconds"], 0.0)
        self.assertTrue(checks["S2-TC36"]["frozen_pipeline_ref"].startswith("c4://"))

    def test_battery_fails_closed_when_declared_latency_budget_is_missed(self) -> None:
        evidence = self.battery._run_battery(
            hpo_trials=2,
            hpo_workers=2,
            hpo_trial_delay_seconds=0.02,
            hpo_parallel_efficiency=0.7,
            hpo_scheduler_backend="threadpool",
            setup_latency_slo_seconds=0.0,
            freeze_replay_fraction_slo=0.05,
        )

        checks = {check["test_case"]: check for check in evidence["checks"]}
        self.assertFalse(evidence["ok"])
        self.assertFalse(checks["S2-TC35"]["ok"])
        self.assertIn("S2-TC35", evidence["failed_test_cases"])

    def test_cli_writes_machine_readable_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            evidence_path = Path(tempdir) / "s2-perf-latency-evidence.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "run_s2_perf_latency_battery.py"),
                    "--hpo-trials",
                    "2",
                    "--hpo-workers",
                    "2",
                    "--hpo-trial-delay-seconds",
                    "0.02",
                    "--hpo-scheduler-backend",
                    "threadpool",
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
            self.assertEqual(evidence["battery"], "s2-perf-latency")


if __name__ == "__main__":
    unittest.main()
