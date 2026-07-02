from __future__ import annotations

from dataclasses import asdict
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from argus_core import BudgetCaps, BudgetToken, FileSystemArtifactStore, Lineage, Producer, ScopeGrant, ScopeToken
from argus_runtime.auth import RuntimeAuth, RuntimeIdentity
from argus_runtime.http_json import JsonRequest
from argus_runtime.s10_supervisor_service import S10SupervisorApp
from argus_runtime.s8_writer_service import S8WriterApp


AUTH_TOKEN = "test-runtime-token"


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

    def test_s8_writer_service_refreshes_file_ledger_before_reads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = S8WriterApp(FileSystemArtifactStore(tmp), data_dir=tmp)
            external = FileSystemArtifactStore(tmp).create_artifact(
                kind="model",
                payload={"weights": [3, 2, 1]},
                producer=Producer(subsystem="S2", version="0.0.0"),
                lineage=Lineage(input_refs=(), code_ref="git:model", environment_digest="oci:model"),
            )

            fetched = app.get_artifact_record(external.artifact_ref)

            self.assertEqual(fetched["artifact_ref"], external.artifact_ref)
            self.assertEqual(app.store.record_count, 1)

    def test_s8_writer_http_denies_direct_artifact_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = S8WriterApp(FileSystemArtifactStore(tmp), data_dir=tmp, auth=_runtime_auth())

            status, payload = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/artifacts",
                    query={},
                    body={
                        "kind": "model",
                        "payload": {"weights": [1]},
                        "producer": {"subsystem": "S2", "version": "0.0.0"},
                        "lineage": {
                            "input_refs": [],
                            "code_ref": "git:model",
                            "environment_digest": "oci:model",
                        },
                    },
                    headers=_auth_headers(),
                )
            )

            self.assertEqual(status, 403)
            self.assertEqual(payload["error"], "DirectWriteDenied")
            self.assertEqual(app.store.record_count, 0)

    def test_runtime_http_routes_require_bearer_authentication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            s8 = S8WriterApp(FileSystemArtifactStore(tmp), data_dir=tmp, auth=_runtime_auth())
            s10 = S10SupervisorApp(signing_key=b"test-key", auth=_runtime_auth())

            s8_status, s8_payload = s8.http.handle(
                JsonRequest(method="GET", path="/healthz", query={}, body=None)
            )
            s10_status, s10_payload = s10.http.handle(
                JsonRequest(method="POST", path="/v1/scope-tokens", query={}, body={})
            )

            self.assertEqual(s8_status, 401)
            self.assertEqual(s8_payload["error"], "Unauthorized")
            self.assertEqual(s10_status, 401)
            self.assertEqual(s10_payload["error"], "Unauthorized")

    def test_s10_http_mint_binds_tokens_to_authenticated_identity(self) -> None:
        app = S10SupervisorApp(signing_key=b"test-key", auth=_runtime_auth())

        budget_status, budget = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/budget-tokens",
                query={},
                body={"ttl_s": 120},
                headers=_auth_headers(),
            )
        )
        scope_status, scope = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/scope-tokens",
                query={},
                body={"ttl_s": 120},
                headers=_auth_headers(),
            )
        )
        override_status, override_payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/scope-tokens",
                query={},
                body={
                    "job_id": "attacker-selected-job",
                    "scopes": {"broker_audiences": ["store"], "producer_subsystems": ["S9"]},
                },
                headers=_auth_headers(),
            )
        )

        self.assertEqual(budget_status, 201)
        self.assertEqual(budget["job_id"], "job-auth")
        self.assertEqual(budget["root_request_id"], "root-auth")
        self.assertEqual(budget["caps"]["max_wallclock_s"], 30)
        self.assertEqual(scope_status, 201)
        self.assertEqual(scope["job_id"], "job-auth")
        self.assertEqual(scope["scopes"]["broker_audiences"], ("store",))
        self.assertEqual(scope["scopes"]["producer_subsystems"], ("S2",))
        self.assertEqual(override_status, 403)
        self.assertEqual(override_payload["error"], "IdentityOverrideError")

    def test_s10_store_artifact_rejects_scope_token_from_other_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = S10SupervisorApp(
                signing_key=b"test-key",
                artifact_store=FileSystemArtifactStore(tmp),
                artifact_store_path=tmp,
                auth=_runtime_auth(),
            )
            other_scope = app.mint_scope(
                {
                    "job_id": "other-job",
                    "scopes": {"broker_audiences": ["store"], "producer_subsystems": ["S2"]},
                }
            )

            status, payload = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/store/artifacts",
                    query={},
                    body={
                        "scope_token": other_scope,
                        "kind": "model",
                        "payload": {"weights": [1]},
                        "producer": {"subsystem": "S2", "version": "0.0.0"},
                        "lineage": {
                            "input_refs": [],
                            "code_ref": "git:model",
                            "environment_digest": "oci:model",
                        },
                    },
                    headers=_auth_headers(),
                )
            )

            self.assertEqual(status, 403)
            self.assertEqual(payload["error"], "PermissionError")
            self.assertEqual(app.artifacts.record_count, 0)

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

    def test_s10_supervisor_broker_writes_shared_s8_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = S10SupervisorApp(
                signing_key=b"test-key",
                artifact_store=FileSystemArtifactStore(tmp),
                artifact_store_path=tmp,
            )
            scope = app.mint_scope(
                {
                    "job_id": "job-1",
                    "scopes": {
                        "broker_audiences": ["store"],
                        "producer_subsystems": ["S2"],
                    },
                }
            )

            record = app.broker_put_artifact(
                {
                    "scope_token": scope,
                    "kind": "model",
                    "payload": {"weights": [1, 2, 3]},
                    "producer": {"subsystem": "S2", "version": "0.0.0"},
                    "lineage": {
                        "input_refs": [],
                        "code_ref": "git:model",
                        "environment_digest": "oci:model",
                    },
                }
            )
            s8 = S8WriterApp(FileSystemArtifactStore(tmp), data_dir=tmp)
            fetched = s8.get_artifact_record(record["artifact_ref"])

            self.assertEqual(fetched["artifact_ref"], record["artifact_ref"])
            self.assertEqual(fetched["producer"]["job_id"], "job-1")
            self.assertEqual(fetched["lineage"]["job_id"], "job-1")


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
            env={
                **os.environ,
                "ARGUS_RUNTIME_AUTH_TOKENS_JSON": json.dumps(_runtime_auth_config()),
                "ARGUS_M0_HEALTH_TOKEN": AUTH_TOKEN,
            },
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
        self.assertEqual(services["s8-writer"]["environment"]["ARGUS_S8_HOST"], "0.0.0.0")
        self.assertEqual(services["s10-supervisor"]["environment"]["ARGUS_S10_HOST"], "0.0.0.0")
        self.assertEqual(services["s8-writer"]["ports"][0]["host_ip"], "127.0.0.1")
        self.assertEqual(services["s10-supervisor"]["ports"][0]["host_ip"], "127.0.0.1")
        self.assertIn("ARGUS_RUNTIME_AUTH_TOKENS_JSON", services["s8-writer"]["environment"])
        self.assertIn("ARGUS_RUNTIME_AUTH_TOKENS_JSON", services["s10-supervisor"]["environment"])
        self.assertIn("/var/lib/argus/s8", services["s10-supervisor"]["volumes"][0]["target"])
        self.assertIn("s8-data", rendered["volumes"])

    def _skip_or_fail(self, reason: str) -> None:
        if os.environ.get("ARGUS_REQUIRE_DOCKER_TESTS") == "1":
            raise AssertionError(reason)
        raise unittest.SkipTest(reason)


def _runtime_auth() -> RuntimeAuth:
    return RuntimeAuth(
        {
            AUTH_TOKEN: RuntimeIdentity(
                caller_id="test-caller",
                job_id="job-auth",
                root_request_id="root-auth",
                scopes=ScopeGrant(broker_audiences=("store",), producer_subsystems=("S2",)),
                budget_caps=BudgetCaps(max_compute_units=10, max_wallclock_s=30, max_cost_usd=5),
                max_ttl_s=300,
            )
        }
    )


def _runtime_auth_config() -> dict[str, object]:
    return {
        AUTH_TOKEN: {
            "caller_id": "test-caller",
            "job_id": "job-auth",
            "root_request_id": "root-auth",
            "scopes": {"broker_audiences": ["store"], "producer_subsystems": ["S2"]},
            "budget_caps": {"max_compute_units": 10, "max_wallclock_s": 30, "max_cost_usd": 5},
            "max_ttl_s": 300,
        }
    }


def _auth_headers(token: str = AUTH_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


if __name__ == "__main__":
    unittest.main()
