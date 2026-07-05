from __future__ import annotations

import io
import json
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import Mock, patch


class S1SubagentCliTests(unittest.TestCase):
    def test_pyproject_registers_argus_subagent_console_script(self) -> None:
        pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

        self.assertEqual(
            pyproject["project"]["scripts"]["argus-subagent"],
            "argus_runtime.s1_subagent_cli:main",
        )

    def test_init_validate_run_freeze_and_replay_local_e2e(self) -> None:
        from argus_runtime.s1_subagent_cli import main

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stdout = io.StringIO()
            self.assertEqual(main(["init", "ewpt-demo", "--out", str(root)], stdout=stdout), 0)
            scaffold = root / "ewpt-demo"
            descriptor_path = scaffold / "descriptor.json"
            job_path = scaffold / "job.json"
            subagent_ref = f"{scaffold / 'subagent.py'}:EwptDemoSubagent"

            self.assertTrue(descriptor_path.exists())
            self.assertTrue(job_path.exists())
            self.assertTrue((scaffold / "tests" / "test_subagent_smoke.py").exists())

            validate_out = io.StringIO()
            self.assertEqual(
                main(["validate-descriptor", "--descriptor", str(descriptor_path)], stdout=validate_out),
                0,
            )
            validated = json.loads(validate_out.getvalue())
            self.assertEqual(validated["status"], "valid")
            self.assertEqual(validated["c5_descriptor"]["kind"], "subagent")
            self.assertEqual(validated["c5_descriptor"]["entity_id"], "ewpt-demo")

            run_path = root / "run.json"
            self.assertEqual(
                main(
                    [
                        "run",
                        "--subagent",
                        subagent_ref,
                        "--job",
                        str(job_path),
                        "--output",
                        str(run_path),
                    ]
                ),
                0,
            )
            run_result = json.loads(run_path.read_text(encoding="utf-8"))
            self.assertEqual(run_result["status"], "reported")
            self.assertEqual(run_result["acceptance"]["accepted"], True)
            self.assertEqual(run_result["current_state"], "REPORTED")
            self.assertEqual(
                [event["to_state"] for event in run_result["events"]],
                ["ACCEPTED", "PLANNING", "BUILDING", "VALIDATING", "REPORTED"],
            )
            self.assertEqual(run_result["report"]["claim_tier"], "ran-toy")
            self.assertTrue(run_result["build_result"]["artifact_refs"][0].startswith("c4://artifact/"))
            self.assertTrue(run_result["ledger_refs"])

            freeze_path = root / "freeze.json"
            build_path = root / "build.json"
            build_path.write_text(json.dumps(run_result["build_result"]), encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "freeze",
                        "--job-id",
                        run_result["job_id"],
                        "--build",
                        str(build_path),
                        "--output",
                        str(freeze_path),
                    ]
                ),
                0,
            )
            frozen = json.loads(freeze_path.read_text(encoding="utf-8"))
            self.assertEqual(frozen["payload"]["schema"], "argus.s1.frozen_pipeline.v1")
            self.assertEqual(frozen["payload"]["artifact_refs"], run_result["build_result"]["artifact_refs"])
            self.assertTrue(frozen["frozen_pipeline_ref"].startswith("c4://artifact/"))

            replay_out = io.StringIO()
            self.assertEqual(main(["replay", "--run-output", str(run_path), "--job-id", run_result["job_id"]], stdout=replay_out), 0)
            replayed = json.loads(replay_out.getvalue())
            self.assertEqual(replayed["current_state"], "REPORTED")
            self.assertEqual(replayed["event_count"], 5)
            self.assertEqual(replayed["trajectory"][-1]["to_state"], "REPORTED")

    def test_conformance_cli_outputs_descriptor_ready_block_and_nonzero_failed_level(self) -> None:
        from argus_runtime.s1_subagent_cli import main

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(main(["init", "conf-demo", "--out", str(root)], stdout=io.StringIO()), 0)
            scaffold = root / "conf-demo"
            subagent_ref = f"{scaffold / 'subagent.py'}:ConfDemoSubagent"
            job_path = scaffold / "job.json"
            bronze_path = root / "bronze.json"
            descriptor_out = root / "descriptor-with-conformance.json"

            self.assertEqual(
                main(
                    [
                        "conformance",
                        "--subagent",
                        subagent_ref,
                        "--job",
                        str(job_path),
                        "--level",
                        "bronze",
                        "--conformance-expires-at",
                        "2099-01-01T00:00:00Z",
                        "--output",
                        str(bronze_path),
                        "--descriptor-output",
                        str(descriptor_out),
                        "--attestation-private-key-hex",
                        "11" * 32,
                    ]
                ),
                0,
            )
            bronze = json.loads(bronze_path.read_text(encoding="utf-8"))
            descriptor = json.loads(descriptor_out.read_text(encoding="utf-8"))
            self.assertTrue(bronze["aggregate_passed"])
            self.assertEqual(bronze["level_awarded"], "bronze")
            self.assertEqual(bronze["descriptor_conformance"]["level"], "bronze")
            self.assertEqual(descriptor["conformance"]["evidence_ref"], bronze["evidence_ref"])

            silver_out = io.StringIO()
            exit_code = main(
                [
                    "conformance",
                    "--subagent",
                    subagent_ref,
                    "--job",
                    str(job_path),
                    "--level",
                    "silver",
                ],
                stdout=silver_out,
            )
            self.assertEqual(exit_code, 1)
            silver = json.loads(silver_out.getvalue())
            self.assertFalse(silver["aggregate_passed"])
            self.assertEqual(silver["level_awarded"], "bronze")

    def test_validate_descriptor_fails_closed_for_invalid_or_incomplete_conformance(self) -> None:
        from argus_runtime.s1_subagent_cli import main

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad_descriptor = root / "bad.json"
            bad_descriptor.write_text(
                json.dumps(
                    {
                        "subagent_id": "bad",
                        "contract_version": "1.0.0",
                        "subtopics": ["ewpt"],
                        "revision": 1,
                        "conformance": {"level": "gold"},
                    }
                ),
                encoding="utf-8",
            )
            stderr = io.StringIO()
            self.assertEqual(
                main(["validate-descriptor", "--descriptor", str(bad_descriptor)], stderr=stderr),
                2,
            )
            self.assertIn("conformance missing required field", stderr.getvalue())

            missing_descriptor = root / "missing.json"
            missing_descriptor.write_text(json.dumps({"subagent_id": "missing"}), encoding="utf-8")
            stderr = io.StringIO()
            self.assertEqual(
                main(["validate-descriptor", "--descriptor", str(missing_descriptor)], stderr=stderr),
                2,
            )
            self.assertIn("contract_version", stderr.getvalue())

    def test_run_refusal_returns_rejected_payload_without_building(self) -> None:
        from argus_runtime.s1_subagent_cli import main

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(main(["init", "refusal-demo", "--out", str(root)], stdout=io.StringIO()), 0)
            scaffold = root / "refusal-demo"
            job_path = scaffold / "job.json"
            job = json.loads(job_path.read_text(encoding="utf-8"))
            job["subtopic"] = "out-of-scope"
            job_path.write_text(json.dumps(job), encoding="utf-8")

            stdout = io.StringIO()
            exit_code = main(
                [
                    "run",
                    "--subagent",
                    f"{scaffold / 'subagent.py'}:RefusalDemoSubagent",
                    "--job",
                    str(job_path),
                ],
                stdout=stdout,
            )
            self.assertEqual(exit_code, 1)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["status"], "rejected")
            self.assertEqual(result["acceptance"]["reason"], "OUT_OF_SCOPE")
            self.assertEqual(result["current_state"], "REJECTED")
            self.assertNotIn("build_result", result)

    def test_codegen_cli_delegates_check_and_propagates_exit_code(self) -> None:
        from argus_runtime.s1_subagent_cli import main

        success = Mock(returncode=0, stdout="bindings clean\n", stderr="")
        with patch("argus_runtime.s1_subagent_cli.subprocess.run", return_value=success) as run:
            stdout = io.StringIO()
            self.assertEqual(main(["codegen", "--check"], stdout=stdout), 0)
            self.assertIn("bindings clean", stdout.getvalue())
            self.assertIn("--check", run.call_args.args[0])

        failure = Mock(returncode=7, stdout="", stderr="drift\n")
        with patch("argus_runtime.s1_subagent_cli.subprocess.run", return_value=failure):
            stderr = io.StringIO()
            self.assertEqual(main(["codegen", "--check"], stderr=stderr), 7)
            self.assertIn("drift", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
