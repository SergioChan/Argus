from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import time
from threading import Thread
import unittest
from unittest.mock import patch

from argus_core import (
    BudgetCaps,
    C3ReportSigner,
    C3ReportVerifier,
    DockerSandboxSupervisor,
    EgressRule,
    FileSystemArtifactStore,
    GWSpectrumAdapter,
    InMemoryS10KmsVerifierKeyProvider,
    S10VerifierTrustStoreClient,
    ScopeGrant,
)
from argus_runtime.auth import RuntimeAuth, RuntimeIdentity
from argus_runtime.http_json import JsonRequest, serve_json_app
from argus_runtime.m1_reference_runtime import M1_REFERENCE_JOB_ID, M1ReferenceLifecycleRunner, REFERENCE_SANDBOX_IMAGE
from argus_runtime.m1_runtime_artifacts import RuntimeIdentitySession, S10S8ArtifactStore
from argus_runtime.s10_supervisor_service import RuntimeIdentityMintPolicy, S10SupervisorApp, S8BrokeredArtifactStoreClient
from argus_runtime.s11_reference_observatory_service import S11ReferenceObservatoryApp
from argus_runtime.s3_reference_referee_service import S3_REFERENCE_REFEREE_ROUTE, S3ReferenceRefereeApp
from argus_runtime.s7_reference_adapter_service import (
    S7ReferenceAdapterApp,
    build_app_from_env as build_s7_reference_adapter_app_from_env,
)
from argus_runtime.s8_persistence import HttpS10VerifierKeyProvider
from argus_runtime.s8_writer_service import S8WriterApp


class M1ReferenceLifecycleServiceTests(unittest.TestCase):
    def test_s7_reference_adapter_builds_from_access_token_only(self) -> None:
        with patch.dict(
            os.environ,
            {
                "ARGUS_S7_REFERENCE_ADAPTER_S10_URL": "http://s10.example",
                "ARGUS_S7_REFERENCE_ADAPTER_S8_URL": "http://s8.example",
                "ARGUS_S7_REFERENCE_ADAPTER_ACCESS_TOKEN": "preprovisioned-s7-token",
            },
            clear=True,
        ):
            app = build_s7_reference_adapter_app_from_env()

        self.assertEqual(app._caller_id, "m1-reference-s7")
        self.assertEqual(app._expected_job_id, M1_REFERENCE_JOB_ID)

    def test_real_http_lifecycle_uses_separate_s1_s3_s7_s11_identities_and_real_s10_sandbox(self) -> None:
        docker = _require_reference_image_or_skip(self)
        bootstrap_token = "m1-lifecycle-bootstrap"
        broker_write_key = b"m1-lifecycle-broker-write-key"
        verifier_key_token = "m1-lifecycle-verifier-key-token"
        signing_secret = b"m1-lifecycle-s3-signing-secret"
        auth = RuntimeAuth.with_signed_identities(
            bootstrap_token=bootstrap_token,
            identity_signing_key=b"m1-lifecycle-identity-signing-key",
        )
        identities = {
            "m1-reference-s1": _identity(
                caller_id="m1-reference-s1",
                producer_subsystems=("S1",),
                allowed_adapters=("gw_spectrum",),
                allowed_datasets=("c4://dataset/ewpt-reference/v1",),
                egress_allowlist=(
                    EgressRule("store.local", 443, "https"),
                    EgressRule("s7-reference-adapter", 443, "https"),
                ),
                broker_audiences=("store", "gw_spectrum"),
                budget_caps=BudgetCaps(max_compute_units=10, max_wallclock_s=30, max_cost_usd=1),
            ),
            "m1-reference-s3": _identity(caller_id="m1-reference-s3", producer_subsystems=("S3",)),
            "m1-reference-s7": _identity(caller_id="m1-reference-s7", producer_subsystems=("S7",)),
            "m1-reference-s11": _identity(caller_id="m1-reference-s11", producer_subsystems=("S11",)),
        }
        verifier_provider = InMemoryS10KmsVerifierKeyProvider()
        verifier_provider.register_verifier_key("s3-reference-referee-key", signing_secret)
        access_tokens = {
            caller_id: str(auth.mint_identity_token(identity, ttl_s=600)["access_token"])
            for caller_id, identity in identities.items()
        }

        with tempfile.TemporaryDirectory() as tmp:
            durable_store = FileSystemArtifactStore(
                tmp,
                report_verifier=C3ReportVerifier(
                    S10VerifierTrustStoreClient(verifier_provider)
                ),
            )
            s8 = S8WriterApp(durable_store, auth=auth, broker_write_key=broker_write_key)
            s8_url = _start_json_server(s8)
            s10 = S10SupervisorApp(
                signing_key=b"m1-lifecycle-s10-signing-key",
                artifact_store=S8BrokeredArtifactStoreClient(
                    endpoint_url=f"{s8_url}/v1/internal/brokered-artifacts",
                    broker_write_key=broker_write_key,
                ),
                auth=auth,
                runtime_identity_mint_policy=RuntimeIdentityMintPolicy(identities_by_caller=identities),
                verifier_key_provider=verifier_provider,
                verifier_key_auth_token=verifier_key_token,
                docker_supervisor=DockerSandboxSupervisor(docker_bin=docker),
            )
            s10_url = _start_json_server(s10)
            s7 = S7ReferenceAdapterApp(
                s10_url=s10_url,
                s8_url=s8_url,
                access_token=access_tokens["m1-reference-s7"],
                expected_job_id=M1_REFERENCE_JOB_ID,
            )
            s7_url = _start_json_server(s7)
            s3 = S3ReferenceRefereeApp(
                s10_url=s10_url,
                s8_url=s8_url,
                access_token=access_tokens["m1-reference-s3"],
                caller_id="m1-reference-s3",
                expected_job_id=M1_REFERENCE_JOB_ID,
                signer=C3ReportSigner(
                    key_id="s3-reference-referee-key",
                    secret=signing_secret,
                ),
                verifier_key_endpoint_url=f"{s10_url}/v1/internal/verifier-keys",
                verifier_key_auth_token=verifier_key_token,
                allow_insecure_verifier_key_store=True,
                require_s1_requester=True,
            )
            s3_url = _start_json_server(s3)
            s11 = S11ReferenceObservatoryApp(
                s10_url=s10_url,
                s8_url=s8_url,
                access_token=access_tokens["m1-reference-s11"],
                verifier_key_endpoint_url=f"{s10_url}/v1/internal/verifier-keys",
                verifier_key_auth_token=verifier_key_token,
                allow_insecure_verifier_key_store=True,
                expected_job_id=M1_REFERENCE_JOB_ID,
            )
            s11_url = _start_json_server(s11)
            runner = M1ReferenceLifecycleRunner(
                s10_url=s10_url,
                s8_url=s8_url,
                access_token=access_tokens["m1-reference-s1"],
                s7_url=s7_url,
                s3_url=s3_url,
                s11_url=s11_url,
                verifier_key_endpoint_url=f"{s10_url}/v1/internal/verifier-keys",
                verifier_key_auth_token=verifier_key_token,
                allow_insecure_verifier_key_store=True,
            )

            result = runner.run(job_id=M1_REFERENCE_JOB_ID)
            repeated_result = runner.run(job_id=M1_REFERENCE_JOB_ID)

            self.assertEqual(result.final_state, "REPORTED")
            self.assertEqual(result.lifecycle_methods, ("accept", "plan", "build", "validate", "report"))
            self.assertEqual(repeated_result.final_state, "REPORTED")
            self.assertEqual(repeated_result.dataset_ref, result.dataset_ref)
            self.assertTrue(result.observatory_trusted, result.observatory_failures)
            self.assertEqual(result.validation_report_payload["claim_tier"], "recapitulated-known")
            self.assertTrue(result.validation_report_payload["aggregate"]["passed"])
            self.assertEqual(
                {check["check"]: check["status"] for check in result.validation_report_payload["checks"]},
                {
                    "INJECTION": "PASS",
                    "NULL_CONTROL": "PASS",
                    "PHYSICAL_CONSISTENCY": "PASS",
                    "CALIBRATION": "PASS",
                    "RECAP_BENCHMARK": "PASS",
                },
            )

            s1_store = _runtime_store(
                s10_url=s10_url,
                s8_url=s8_url,
                bootstrap_token=bootstrap_token,
                caller_id="m1-reference-s1",
            )
            adapter_provenance_ref = str(result.build_payload["diagnostics"]["adapter_provenance_ref"])
            adapter_descriptor_ref = GWSpectrumAdapter().as_simple_adapter().descriptor.provenance_ref
            sandbox_ref = str(result.build_payload["diagnostics"]["sandbox"]["launch_provenance_ref"])
            records = {
                "dataset": s1_store.get_record(result.dataset_ref),
                "adapter_descriptor": s1_store.get_record(adapter_descriptor_ref),
                "adapter": s1_store.get_record(adapter_provenance_ref),
                "sandbox": s1_store.get_record(sandbox_ref),
                "report": s1_store.get_record(result.validation_report_ref),
                "subject": s1_store.get_record(result.promoted_artifact_ref),
                "observatory": s1_store.get_record(result.observatory_html_ref),
            }
            self.assertEqual(records["dataset"].producer.subsystem.upper(), "S1")
            self.assertEqual(records["adapter_descriptor"].kind, "adapter_descriptor")
            self.assertEqual(records["adapter_descriptor"].producer.subsystem, "S7")
            self.assertEqual(records["adapter"].producer.subsystem, "S7")
            self.assertEqual(records["adapter"].lineage.input_refs, (adapter_descriptor_ref,))
            self.assertEqual(records["sandbox"].producer.subsystem, "S10")
            self.assertEqual(records["report"].producer.subsystem, "S3")
            self.assertEqual(records["subject"].producer.subsystem, "S1")
            self.assertEqual(records["observatory"].producer.subsystem, "S11")
            self.assertIn(sandbox_ref, {node.artifact_ref for node in s1_store.get_lineage(result.promoted_artifact_ref).nodes})

            status, denied = s3.http.handle(
                JsonRequest(
                    method="POST",
                    path=S3_REFERENCE_REFEREE_ROUTE,
                    query={},
                    body={"job_id": M1_REFERENCE_JOB_ID},
                )
            )
            self.assertEqual(status, 403)
            self.assertEqual(denied["error"], "requester_unauthorized")


def _identity(
    *,
    caller_id: str,
    producer_subsystems: tuple[str, ...],
    allowed_adapters: tuple[str, ...] = (),
    allowed_datasets: tuple[str, ...] = (),
    egress_allowlist: tuple[EgressRule, ...] = (),
    broker_audiences: tuple[str, ...] = ("store",),
    budget_caps: BudgetCaps | None = None,
) -> RuntimeIdentity:
    return RuntimeIdentity(
        caller_id=caller_id,
        job_id=M1_REFERENCE_JOB_ID,
        root_request_id="m1-reference-root",
        scopes=ScopeGrant(
            allowed_adapters=allowed_adapters,
            allowed_datasets=allowed_datasets,
            egress_allowlist=egress_allowlist,
            broker_audiences=broker_audiences,
            capabilities=("s8.read",),
            producer_subsystems=producer_subsystems,
        ),
        budget_caps=budget_caps or BudgetCaps(max_compute_units=1, max_wallclock_s=60, max_cost_usd=1),
        max_ttl_s=600,
    )


def _runtime_store(*, s10_url: str, s8_url: str, bootstrap_token: str, caller_id: str) -> S10S8ArtifactStore:
    session = RuntimeIdentitySession.from_bootstrap(
        s10_url=s10_url,
        bootstrap_token=bootstrap_token,
        caller_id=caller_id,
        expected_job_id=M1_REFERENCE_JOB_ID,
    )
    return S10S8ArtifactStore(session=session, s8_url=s8_url)


def _require_reference_image_or_skip(test_case: unittest.TestCase) -> str:
    docker = shutil.which("docker")
    if docker is None:
        if os.environ.get("ARGUS_REQUIRE_DOCKER_TESTS") == "1":
            test_case.fail("docker CLI is required when ARGUS_REQUIRE_DOCKER_TESTS=1")
        test_case.skipTest("docker CLI is unavailable")
    inspected = subprocess.run(
        [docker, "image", "inspect", REFERENCE_SANDBOX_IMAGE],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if inspected.returncode != 0:
        pulled = subprocess.run(
            [docker, "pull", REFERENCE_SANDBOX_IMAGE],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        test_case.assertEqual(pulled.returncode, 0, pulled.stderr)
    return docker


def _start_json_server(app: object) -> str:
    port = _free_port()
    http = getattr(app, "http")
    thread = Thread(
        target=serve_json_app,
        kwargs={"app": http, "host": "127.0.0.1", "port": port},
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 5
    while True:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return f"http://127.0.0.1:{port}"
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


if __name__ == "__main__":
    unittest.main()
