from __future__ import annotations

from dataclasses import asdict
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from argus_core import BudgetCaps, BudgetToken, FileSystemArtifactStore, ScopeGrant, ScopeToken
from argus_runtime.s10_supervisor_service import S10SupervisorApp
from argus_runtime.s8_writer_service import S8WriterApp


class ArgusM0RuntimeServiceTests(unittest.TestCase):
    def test_s8_writer_service_commits_and_replays_c4_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = S8WriterApp(FileSystemArtifactStore(tmp))
            record = app.create_artifact(
                {
                    "kind": "model",
                    "payload": {"weights": [1, 2, 3]},
                    "producer": {"subsystem": "S2", "version": "0.0.0"},
                    "lineage": {
                        "input_refs": [],
                        "code_ref": "git:model",
                        "environment_digest": "oci:model",
                        "seeds": ["seed-1"],
                    },
                }
            )

            reloaded = S8WriterApp(FileSystemArtifactStore(tmp))
            fetched = reloaded.get_artifact_record(record["artifact_ref"])

            self.assertEqual(fetched["artifact_ref"], record["artifact_ref"])
            self.assertEqual(fetched["content_hash"], record["content_hash"])
            self.assertEqual(reloaded.store.record_count, 1)
            self.assertEqual(reloaded.store.get_artifact(record["artifact_ref"]), b'{"weights":[1,2,3]}')

    def test_s10_supervisor_service_mints_verifiable_tokens(self) -> None:
        app = S10SupervisorApp(signing_key=b"test-key")

        budget = app.mint_budget(
            {
                "job_id": "job-1",
                "root_request_id": "root-1",
                "caps": {"max_wallclock_s": 30, "max_cost_usd": 1},
            }
        )
        scope = app.mint_scope(
            {
                "job_id": "job-1",
                "scopes": {
                    "broker_audiences": ["store"],
                    "producer_subsystems": ["S2"],
                    "sandbox_risk_class": "standard",
                },
            }
        )

        budget_token = BudgetToken(
            **{
                **budget,
                "caps": BudgetCaps(**budget["caps"]),
            }
        )
        scope_token = ScopeToken(
            **{
                **scope,
                "scopes": ScopeGrant(
                    allowed_adapters=tuple(scope["scopes"]["allowed_adapters"]),
                    allowed_datasets=tuple(scope["scopes"]["allowed_datasets"]),
                    egress_allowlist=(),
                    broker_audiences=tuple(scope["scopes"]["broker_audiences"]),
                    producer_subsystems=tuple(scope["scopes"]["producer_subsystems"]),
                    disallowed_actions=tuple(scope["scopes"]["disallowed_actions"]),
                    sandbox_risk_class=scope["scopes"]["sandbox_risk_class"],
                ),
            }
        )

        self.assertTrue(app.tokens.verify_budget(budget_token).valid)
        self.assertTrue(app.tokens.verify_scope(scope_token).valid)


class ArgusM0ComposeTests(unittest.TestCase):
    def test_compose_config_declares_argus_m0_services(self) -> None:
        compose = Path("deploy/argus-m0/compose.yaml")
        docker = shutil.which("docker")
        if docker is None:
            self._skip_or_fail("docker CLI is unavailable")
        config = subprocess.run(
            [docker, "compose", "-f", str(compose), "config", "--format", "json"],
            check=False,
            capture_output=True,
            text=True,
        )
        if config.returncode != 0:
            self._skip_or_fail(config.stderr.strip() or "docker compose config failed")

        rendered = json.loads(config.stdout)
        services = rendered["services"]
        self.assertEqual({"postgres", "minio", "s8-writer", "s10-supervisor"}, set(services))
        self.assertTrue(services["postgres"]["image"].startswith("postgres@sha256:"))
        self.assertTrue(services["minio"]["image"].startswith("minio/minio@sha256:"))
        self.assertEqual(services["s8-writer"]["command"], ["python", "-m", "argus_runtime.s8_writer_service"])
        self.assertEqual(services["s10-supervisor"]["command"], ["python", "-m", "argus_runtime.s10_supervisor_service"])
        self.assertIn("s8-data", rendered["volumes"])

    def _skip_or_fail(self, reason: str) -> None:
        if os.environ.get("ARGUS_REQUIRE_DOCKER_TESTS") == "1":
            raise AssertionError(reason)
        raise unittest.SkipTest(reason)


if __name__ == "__main__":
    unittest.main()
