from __future__ import annotations

from dataclasses import asdict
from hashlib import sha256
import hmac
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from argus_core import BudgetCaps, BudgetToken, FileSystemArtifactStore, Lineage, Producer, ScopeGrant, ScopeToken
from argus_core import canonical_json_bytes
from argus_runtime.auth import RuntimeAuth, RuntimeIdentity
from argus_runtime.http_json import JsonRequest
from argus_runtime.s10_supervisor_service import (
    RuntimeIdentityMintPolicy,
    S10SupervisorApp,
    build_app_from_env as build_s10_app_from_env,
)
from argus_runtime.s8_writer_service import S8WriterApp


AUTH_TOKEN = "test-runtime-token"
BOOTSTRAP_TOKEN = "test-bootstrap-token"
IDENTITY_SIGNING_KEY = b"test-identity-signing-key"
HEALTH_TOKEN = "test-health-token"
BROKER_WRITE_KEY = b"test-s8-broker-write-key"


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

    def test_s8_writer_http_reads_payload_through_verify_on_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = S8WriterApp(FileSystemArtifactStore(tmp), data_dir=tmp, auth=_runtime_auth())
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

            status, payload = app.http.handle(
                JsonRequest(
                    method="GET",
                    path=f"/v1/artifacts/{record['artifact_ref']}/payload",
                    query={},
                    body=None,
                    headers=_auth_headers(),
                )
            )

            self.assertEqual(status, 200)
            self.assertEqual(payload, {"weights": [1, 2, 3]})

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

    def test_s8_internal_broker_write_requires_signature_and_revalidates_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = S8WriterApp(
                FileSystemArtifactStore(tmp),
                data_dir=tmp,
                auth=_runtime_auth(),
                broker_write_key=BROKER_WRITE_KEY,
            )
            body = {
                "authorization": {
                    "audience": "store",
                    "scope_job_id": "job-1",
                    "producer_subsystems": ["S2"],
                },
                "kind": "model",
                "payload": {"weights": [1]},
                "producer": asdict(Producer(subsystem="S2", version="0.0.0", job_id="job-1")),
                "lineage": asdict(Lineage(input_refs=(), code_ref="git:model", environment_digest="oci:model", job_id="job-1")),
            }
            bad_body = {
                **body,
                "producer": asdict(Producer(subsystem="S9", version="0.0.0", job_id="job-1")),
            }

            unauthorized_status, unauthorized_payload = app.http.handle(
                JsonRequest(method="POST", path="/v1/internal/brokered-artifacts", query={}, body=body)
            )
            accepted_status, accepted_payload = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/internal/brokered-artifacts",
                    query={},
                    body=body,
                    headers=_broker_write_headers(body),
                )
            )
            rejected_status, rejected_payload = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/internal/brokered-artifacts",
                    query={},
                    body=bad_body,
                    headers=_broker_write_headers(bad_body),
                )
            )

            self.assertEqual(unauthorized_status, 401)
            self.assertEqual(unauthorized_payload["error"], "Unauthorized")
            self.assertEqual(accepted_status, 201)
            self.assertEqual(accepted_payload["producer"]["job_id"], "job-1")
            self.assertEqual(rejected_status, 403)
            self.assertEqual(rejected_payload["error"], "PermissionError")
            self.assertEqual(app.store.record_count, 1)

            external = FileSystemArtifactStore(tmp).create_artifact(
                kind="container",
                payload={"exec_environment_digest": "oci:runtime", "exec_environment": {}, "launch": {}},
                producer=Producer(subsystem="S10", version="0.0.0"),
                lineage=Lineage(
                    input_refs=(),
                    code_ref="busybox@sha256:test",
                    environment_digest="oci:runtime",
                    seeds=("trace-1",),
                ),
            )
            chained_body = {
                **body,
                "payload": {"weights": [2]},
                "lineage": asdict(
                    Lineage(
                        input_refs=(external.artifact_ref,),
                        code_ref="git:model",
                        environment_digest="oci:runtime",
                        seeds=("seed-1",),
                        job_id="job-1",
                    )
                ),
            }
            chained_status, chained_payload = app.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/internal/brokered-artifacts",
                    query={},
                    body=chained_body,
                    headers=_broker_write_headers(chained_body),
                )
            )
            reloaded = FileSystemArtifactStore(tmp)

            self.assertEqual(chained_status, 201)
            self.assertEqual(reloaded.get_artifact_record(chained_payload["artifact_ref"]).artifact_ref, chained_payload["artifact_ref"])
            self.assertEqual(reloaded.record_count, 3)

    def test_runtime_http_routes_require_bearer_authentication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            s8 = S8WriterApp(
                FileSystemArtifactStore(tmp),
                data_dir=tmp,
                auth=_signed_runtime_auth(),
                health_token=HEALTH_TOKEN,
            )
            s10 = S10SupervisorApp(
                signing_key=b"test-key",
                auth=_signed_runtime_auth(),
                runtime_identity_mint_policy=_runtime_identity_mint_policy(),
                health_token=HEALTH_TOKEN,
            )

            s8_no_auth_status, s8_no_auth_payload = s8.http.handle(
                JsonRequest(method="GET", path="/healthz", query={}, body=None)
            )
            s8_bootstrap_status, s8_bootstrap_payload = s8.http.handle(
                JsonRequest(
                    method="GET",
                    path="/healthz",
                    query={},
                    body=None,
                    headers=_auth_headers(BOOTSTRAP_TOKEN),
                )
            )
            s8_health_status, s8_health_payload = s8.http.handle(
                JsonRequest(method="GET", path="/healthz", query={}, body=None, headers=_auth_headers(HEALTH_TOKEN))
            )
            s10_no_auth_status, s10_no_auth_payload = s10.http.handle(
                JsonRequest(method="GET", path="/healthz", query={}, body=None)
            )
            s10_bootstrap_status, s10_bootstrap_payload = s10.http.handle(
                JsonRequest(
                    method="GET",
                    path="/healthz",
                    query={},
                    body=None,
                    headers=_auth_headers(BOOTSTRAP_TOKEN),
                )
            )
            s10_health_status, s10_health_payload = s10.http.handle(
                JsonRequest(method="GET", path="/healthz", query={}, body=None, headers=_auth_headers(HEALTH_TOKEN))
            )
            s10_scope_status, s10_scope_payload = s10.http.handle(
                JsonRequest(method="POST", path="/v1/scope-tokens", query={}, body={})
            )
            s10_mint_with_health_status, s10_mint_with_health_payload = s10.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/runtime-identities",
                    query={},
                    body={"caller_id": "sandbox-1"},
                    headers=_auth_headers(HEALTH_TOKEN),
                )
            )
            s8_write_with_health_status, s8_write_with_health_payload = s8.http.handle(
                JsonRequest(
                    method="POST",
                    path="/v1/artifacts",
                    query={},
                    body={},
                    headers=_auth_headers(HEALTH_TOKEN),
                )
            )

            self.assertEqual(s8_no_auth_status, 401)
            self.assertEqual(s8_no_auth_payload["error"], "Unauthorized")
            self.assertEqual(s8_bootstrap_status, 401)
            self.assertEqual(s8_bootstrap_payload["error"], "Unauthorized")
            self.assertEqual(s8_health_status, 200)
            self.assertEqual(s8_health_payload["status"], "ok")
            self.assertEqual(s10_no_auth_status, 401)
            self.assertEqual(s10_no_auth_payload["error"], "Unauthorized")
            self.assertEqual(s10_bootstrap_status, 401)
            self.assertEqual(s10_bootstrap_payload["error"], "Unauthorized")
            self.assertEqual(s10_health_status, 200)
            self.assertEqual(s10_health_payload["status"], "ok")
            self.assertEqual(s10_scope_status, 401)
            self.assertEqual(s10_scope_payload["error"], "Unauthorized")
            self.assertEqual(s10_mint_with_health_status, 401)
            self.assertEqual(s10_mint_with_health_payload["error"], "Unauthorized")
            self.assertEqual(s8_write_with_health_status, 401)
            self.assertEqual(s8_write_with_health_payload["error"], "Unauthorized")

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

    def test_s10_http_mints_runtime_identity_before_budget_scope_tokens(self) -> None:
        app = S10SupervisorApp(
            signing_key=b"test-key",
            auth=_signed_runtime_auth(),
            runtime_identity_mint_policy=_runtime_identity_mint_policy(),
        )

        identity_status, identity_payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/runtime-identities",
                query={},
                body={
                    "caller_id": "sandbox-1",
                    "ttl_s": 120,
                },
                headers=_auth_headers(BOOTSTRAP_TOKEN),
            )
        )
        bootstrap_budget_status, bootstrap_budget_payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/budget-tokens",
                query={},
                body={},
                headers=_auth_headers(BOOTSTRAP_TOKEN),
            )
        )
        runtime_headers = _auth_headers(identity_payload["access_token"])
        budget_status, budget = app.http.handle(
            JsonRequest(method="POST", path="/v1/budget-tokens", query={}, body={}, headers=runtime_headers)
        )
        scope_status, scope = app.http.handle(
            JsonRequest(method="POST", path="/v1/scope-tokens", query={}, body={}, headers=runtime_headers)
        )

        self.assertEqual(identity_status, 201)
        self.assertEqual(identity_payload["identity"]["job_id"], "job-launch")
        self.assertTrue(identity_payload["access_token"].startswith("argus-runtime-v1."))
        self.assertEqual(bootstrap_budget_status, 403)
        self.assertEqual(bootstrap_budget_payload["error"], "PermissionError")
        self.assertEqual(budget_status, 201)
        self.assertEqual(budget["job_id"], "job-launch")
        self.assertEqual(budget["root_request_id"], "root-launch")
        self.assertEqual(scope_status, 201)
        self.assertEqual(scope["job_id"], "job-launch")
        self.assertEqual(scope["scopes"]["producer_subsystems"], ("S2",))

    def test_s10_runtime_identity_mint_policy_rejects_overrides_unknown_callers_and_ttl_widening(self) -> None:
        app = S10SupervisorApp(
            signing_key=b"test-key",
            auth=_signed_runtime_auth(),
            runtime_identity_mint_policy=_runtime_identity_mint_policy(),
        )

        override_status, override_payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/runtime-identities",
                query={},
                body={"caller_id": "sandbox-1", "job_id": "attacker-selected-job"},
                headers=_auth_headers(BOOTSTRAP_TOKEN),
            )
        )
        unknown_status, unknown_payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/runtime-identities",
                query={},
                body={"caller_id": "unknown"},
                headers=_auth_headers(BOOTSTRAP_TOKEN),
            )
        )
        ttl_status, ttl_payload = app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/runtime-identities",
                query={},
                body={"caller_id": "sandbox-1", "ttl_s": 301},
                headers=_auth_headers(BOOTSTRAP_TOKEN),
            )
        )
        no_policy = S10SupervisorApp(signing_key=b"test-key", auth=_signed_runtime_auth())
        no_policy_status, no_policy_payload = no_policy.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/runtime-identities",
                query={},
                body={"caller_id": "sandbox-1"},
                headers=_auth_headers(BOOTSTRAP_TOKEN),
            )
        )

        self.assertEqual(override_status, 403)
        self.assertEqual(override_payload["error"], "IdentityOverrideError")
        self.assertEqual(unknown_status, 403)
        self.assertEqual(unknown_payload["error"], "PermissionError")
        self.assertEqual(ttl_status, 403)
        self.assertEqual(ttl_payload["error"], "PermissionError")
        self.assertEqual(no_policy_status, 403)
        self.assertEqual(no_policy_payload["error"], "PermissionError")
        caller_key_policy = RuntimeIdentityMintPolicy.from_json(
            json.dumps(
                {
                    "sandbox-1": {
                        "caller_id": "attacker-caller",
                        "job_id": "job-launch",
                        "root_request_id": "root-launch",
                        "budget_caps": {"max_compute_units": 10, "max_wallclock_s": 30, "max_cost_usd": 5},
                        "scopes": {"broker_audiences": ["store"], "producer_subsystems": ["S2"]},
                        "max_ttl_s": 300,
                    }
                }
            )
        )
        self.assertEqual(caller_key_policy.identity_for_request({"caller_id": "sandbox-1"}).caller_id, "sandbox-1")

    def test_s10_env_build_fails_closed_without_signing_key(self) -> None:
        with patch.dict(
            os.environ,
            {
                "ARGUS_RUNTIME_BOOTSTRAP_TOKEN": BOOTSTRAP_TOKEN,
                "ARGUS_RUNTIME_IDENTITY_SIGNING_KEY": IDENTITY_SIGNING_KEY.decode("utf-8"),
            },
            clear=True,
        ):
            with self.assertRaises(RuntimeError):
                build_s10_app_from_env()

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
                "ARGUS_RUNTIME_BOOTSTRAP_TOKEN": BOOTSTRAP_TOKEN,
                "ARGUS_RUNTIME_IDENTITY_SIGNING_KEY": IDENTITY_SIGNING_KEY.decode("utf-8"),
                "ARGUS_RUNTIME_IDENTITY_MINT_POLICY_JSON": _runtime_identity_mint_policy_json(),
                "ARGUS_M0_HEALTH_TOKEN": HEALTH_TOKEN,
                "ARGUS_S10_SIGNING_KEY": "test-s10-signing-key",
                "ARGUS_S8_BROKER_WRITE_KEY": BROKER_WRITE_KEY.decode("utf-8"),
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
        self.assertEqual(
            services["s8-writer"]["environment"]["ARGUS_S8_POSTGRES_DSN"],
            "postgresql://argus:argus-dev-password@postgres:5432/argus",
        )
        self.assertEqual(services["s8-writer"]["environment"]["ARGUS_S8_MINIO_ENDPOINT"], "minio:9000")
        self.assertEqual(services["s8-writer"]["environment"]["ARGUS_S8_MINIO_BUCKET"], "argus-s8-objects")
        self.assertNotIn("ARGUS_S8_DATA_DIR", services["s8-writer"]["environment"])
        self.assertEqual(services["s10-supervisor"]["environment"]["ARGUS_S10_HOST"], "0.0.0.0")
        self.assertEqual(services["s8-writer"]["ports"][0]["host_ip"], "127.0.0.1")
        self.assertEqual(services["s10-supervisor"]["ports"][0]["host_ip"], "127.0.0.1")
        self.assertNotIn("volumes", services["s8-writer"])
        self.assertIn("ARGUS_RUNTIME_BOOTSTRAP_TOKEN", services["s8-writer"]["environment"])
        self.assertIn("ARGUS_RUNTIME_IDENTITY_SIGNING_KEY", services["s8-writer"]["environment"])
        self.assertEqual(services["s8-writer"]["environment"]["ARGUS_M0_HEALTH_TOKEN"], HEALTH_TOKEN)
        self.assertNotEqual(services["s8-writer"]["environment"]["ARGUS_M0_HEALTH_TOKEN"], BOOTSTRAP_TOKEN)
        self.assertIn("ARGUS_RUNTIME_BOOTSTRAP_TOKEN", services["s10-supervisor"]["environment"])
        self.assertIn("ARGUS_RUNTIME_IDENTITY_SIGNING_KEY", services["s10-supervisor"]["environment"])
        self.assertIn("ARGUS_RUNTIME_IDENTITY_MINT_POLICY_JSON", services["s10-supervisor"]["environment"])
        self.assertEqual(services["s10-supervisor"]["environment"]["ARGUS_M0_HEALTH_TOKEN"], HEALTH_TOKEN)
        self.assertNotEqual(services["s10-supervisor"]["environment"]["ARGUS_M0_HEALTH_TOKEN"], BOOTSTRAP_TOKEN)
        self.assertIn("ARGUS_S8_BROKER_WRITE_KEY", services["s8-writer"]["environment"])
        self.assertEqual(
            services["s10-supervisor"]["environment"]["ARGUS_S8_BROKER_URL"],
            "http://s8-writer:8080/v1/internal/brokered-artifacts",
        )
        self.assertIn("ARGUS_S8_BROKER_WRITE_KEY", services["s10-supervisor"]["environment"])
        self.assertEqual(services["s10-supervisor"]["environment"]["ARGUS_S10_SIGNING_KEY"], "test-s10-signing-key")
        self.assertNotIn("volumes", services["s10-supervisor"])
        self.assertNotIn("s8-data", rendered["volumes"])
        self.assertIn("postgres-data", rendered["volumes"])
        self.assertIn("minio-data", rendered["volumes"])

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


def _signed_runtime_auth() -> RuntimeAuth:
    return RuntimeAuth.with_signed_identities(
        bootstrap_token=BOOTSTRAP_TOKEN,
        identity_signing_key=IDENTITY_SIGNING_KEY,
    )


def _runtime_identity_mint_policy() -> RuntimeIdentityMintPolicy:
    return RuntimeIdentityMintPolicy.from_json(_runtime_identity_mint_policy_json())


def _runtime_identity_mint_policy_json() -> str:
    return json.dumps(
        {
            "sandbox-1": {
                "job_id": "job-launch",
                "root_request_id": "root-launch",
                "budget_caps": {"max_compute_units": 10, "max_wallclock_s": 30, "max_cost_usd": 5},
                "scopes": {"broker_audiences": ["store"], "producer_subsystems": ["S2"]},
                "max_ttl_s": 300,
            }
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _auth_headers(token: str = AUTH_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _broker_write_headers(body: dict[str, object]) -> dict[str, str]:
    signature = hmac.new(BROKER_WRITE_KEY, canonical_json_bytes(body), sha256).hexdigest()
    return {"X-Argus-Store-Write-Signature": f"hmac-sha256:{signature}"}


if __name__ == "__main__":
    unittest.main()
