from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from argus_runtime.http_json import JsonRequest
from argus_runtime.s1_reference_demo_service import S1_REFERENCE_DEMO_ROUTE, build_app


ROOT = Path(__file__).resolve().parents[1]


class S1ReferenceDemoEntryPointTests(unittest.TestCase):
    def test_cli_runs_full_reference_harness_and_writes_observatory_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            evidence_file = out_dir / "evidence.json"
            env = {
                **os.environ,
                "PYTHONPATH": f"{ROOT / 'src'}:{ROOT}",
            }

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "argus_runtime.s1_reference_demo_service",
                    "--job-id",
                    "entrypoint-demo",
                    "--out-dir",
                    str(out_dir),
                    "--evidence-file",
                    str(evidence_file),
                ],
                cwd=ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(evidence_file.exists())
            evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
            self.assertEqual(evidence["demo"], "s1-reference-physics")
            self.assertEqual(evidence["job_id"], "entrypoint-demo")
            self.assertEqual(evidence["final_state"], "REPORTED")
            self.assertEqual(evidence["claim_tier"], "novel-needs-human")
            self.assertTrue(evidence["claim_tier_is_candidate"])
            self.assertTrue(evidence["observatory_trusted"])
            self.assertEqual(evidence["referee_id"], "s3-reference-verifier")
            self.assertEqual(evidence["signature_key_id"], "s3-reference-referee-key")
            self.assertEqual(evidence["lifecycle_methods"], ["accept", "plan", "build", "validate", "report"])
            self.assertEqual(
                {check["check"]: check["status"] for check in evidence["checks"]},
                {
                    "INJECTION": "PASS",
                    "NULL_CONTROL": "PASS",
                    "CROSS_CODE": "PASS",
                    "PHYSICAL_CONSISTENCY": "PASS",
                    "LEAKAGE": "PASS",
                    "CALIBRATION": "PASS",
                    "RECAP_BENCHMARK": "PASS",
                },
            )

            artifacts = evidence["artifacts"]
            report_path = Path(artifacts["validation_report_path"])
            subagent_report_path = Path(artifacts["subagent_report_path"])
            lineage_path = Path(artifacts["lineage_path"])
            observatory_path = Path(artifacts["observatory_html_path"])
            for path in (report_path, subagent_report_path, lineage_path, observatory_path):
                self.assertTrue(path.exists(), str(path))
                self.assertTrue(path.is_relative_to(out_dir), str(path))

            report = json.loads(report_path.read_text(encoding="utf-8"))
            subagent_report = json.loads(subagent_report_path.read_text(encoding="utf-8"))
            lineage = json.loads(lineage_path.read_text(encoding="utf-8"))
            html = observatory_path.read_text(encoding="utf-8")

            self.assertEqual(report["claim_tier"], "novel-needs-human")
            self.assertEqual(report["referee"]["referee_id"], "s3-reference-verifier")
            self.assertEqual(report["signature"]["key_id"], "s3-reference-referee-key")
            recap_check = next(check for check in report["checks"] if check["check"] == "RECAP_BENCHMARK")
            self.assertTrue(recap_check["metrics"]["recap_benchmark_pass"])
            self.assertFalse(recap_check["metrics"]["truth_bytes_delivered_to_sandbox"])
            self.assertFalse(recap_check["metrics"]["truth_hash_delivered_to_sandbox"])
            self.assertFalse(recap_check["metrics"]["raw_truth_exposed"])
            self.assertEqual(subagent_report["validation_report_ref"], evidence["validation_report_ref"])
            self.assertEqual(lineage["subject_ref"], evidence["promoted_artifact_ref"])
            self.assertEqual(lineage["report_ref"], evidence["validation_report_ref"])
            self.assertIn('data-verdict="VERIFIED"', html)

    def test_http_demo_route_rejects_invalid_job_id_without_disconnect(self) -> None:
        app = build_app()

        status, payload = app.http.handle(
            JsonRequest(
                method="POST",
                path=S1_REFERENCE_DEMO_ROUTE,
                query={},
                body={"job_id": ""},
            )
        )

        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "invalid_job_id")


if __name__ == "__main__":
    unittest.main()
