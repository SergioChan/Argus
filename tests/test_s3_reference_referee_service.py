from __future__ import annotations

import json
import socket
import tempfile
import time
from threading import Thread
from types import SimpleNamespace
import unittest

from argus_core import (
    BudgetCaps,
    C3ReportVerifier,
    C3ReportSigner,
    FileSystemArtifactStore,
    FrozenPipelineRunner,
    InMemoryS10KmsVerifierKeyProvider,
    Lineage,
    Producer,
    ScopeGrant,
    S10VerifierTrustStoreClient,
    evaluate_sound_wave_spectrum,
)
from argus_core.s2 import (
    S2_FROZEN_PIPELINE_ENTRYPOINT_CONTRACT_VERSION,
    S2_FROZEN_PIPELINE_SCHEMA_VERSION,
)
from argus_runtime.auth import RuntimeAuth, RuntimeIdentity
from argus_runtime.http_json import JsonRequest, serve_json_app
from argus_runtime.m1_runtime_artifacts import RuntimeIdentitySession, S10S8ArtifactStore
from argus_runtime.s10_supervisor_service import (
    RuntimeIdentityMintPolicy,
    S10SupervisorApp,
    S8BrokeredArtifactStoreClient,
)
from argus_runtime.s3_reference_referee_service import (
    S3_REFERENCE_REFEREE_ROUTE,
    S3ReferenceRefereeApp,
)
from argus_runtime.s8_persistence import HttpS10VerifierKeyProvider
from argus_runtime.s8_writer_service import S8WriterApp


class S3ReferenceRefereeServiceTests(unittest.TestCase):
    def test_real_http_referee_reads_frozen_pipeline_and_persists_signed_report_through_s10_s8(self) -> None:
        bootstrap_token = "m1-reference-bootstrap"
        broker_write_key = b"m1-reference-broker-write-key"
        verifier_key_token = "m1-reference-verifier-key-token"
        signing_secret = b"m1-reference-s3-signing-secret"
        auth = RuntimeAuth.with_signed_identities(
            bootstrap_token=bootstrap_token,
            identity_signing_key=b"m1-reference-identity-signing-key",
        )
        identities = {
            "m1-reference-s1": _identity(
                caller_id="m1-reference-s1",
                producer_subsystems=("S1",),
            ),
            "m1-reference-s3": _identity(
                caller_id="m1-reference-s3",
                producer_subsystems=("S3",),
            ),
        }
        verifier_provider = InMemoryS10KmsVerifierKeyProvider()
        verifier_provider.register_verifier_key("s3-reference-referee-key", signing_secret)

        with tempfile.TemporaryDirectory() as tmp:
            durable_store = FileSystemArtifactStore(
                tmp,
                report_verifier=C3ReportVerifier(S10VerifierTrustStoreClient(verifier_provider)),
            )
            s8 = S8WriterApp(durable_store, auth=auth, broker_write_key=broker_write_key)
            s8_url = _start_json_server(s8)
            s10 = S10SupervisorApp(
                signing_key=b"m1-reference-s10-signing-key",
                artifact_store=S8BrokeredArtifactStoreClient(
                    endpoint_url=f"{s8_url}/v1/internal/brokered-artifacts",
                    broker_write_key=broker_write_key,
                ),
                auth=auth,
                runtime_identity_mint_policy=RuntimeIdentityMintPolicy(identities_by_caller=identities),
                verifier_key_provider=verifier_provider,
                verifier_key_auth_token=verifier_key_token,
            )
            s10_url = _start_json_server(s10)
            s1_store = _runtime_store(
                s10_url=s10_url,
                s8_url=s8_url,
                bootstrap_token=bootstrap_token,
                caller_id="m1-reference-s1",
            )
            refs = _seed_reference_pipeline(s1_store)
            runner_holder: dict[str, _ReferencePipelineRunner] = {}

            def runner_factory(store, _session, blind_data_manager):
                runner = _ReferencePipelineRunner(store, blind_data_manager)
                runner_holder["runner"] = runner
                return runner

            referee = S3ReferenceRefereeApp(
                s10_url=s10_url,
                s8_url=s8_url,
                bootstrap_token=bootstrap_token,
                caller_id="m1-reference-s3",
                expected_job_id="m1-reference-job",
                signer=C3ReportSigner(key_id="s3-reference-referee-key", secret=signing_secret),
                verifier_key_endpoint_url=f"{s10_url}/v1/internal/verifier-keys",
                verifier_key_auth_token=verifier_key_token,
                allow_insecure_verifier_key_store=True,
                pipeline_runner_factory=runner_factory,
            )

            status, response = referee.http.handle(
                JsonRequest(
                    method="POST",
                    path=S3_REFERENCE_REFEREE_ROUTE,
                    query={},
                    body={
                        "job_id": "m1-reference-job",
                        "profile_ref": refs["profile_ref"],
                        "frozen_pipeline_ref": refs["frozen_pipeline_ref"],
                        "artifact_refs": [refs["model_ref"]],
                        "blind_dataset_handle": "blind://m1-reference/recap",
                        "budget_token_ref": "budget://m1-reference/recap",
                        "trace_id": "trace:m1-reference-referee",
                    },
                )
            )

            self.assertEqual(status, 200, response)
            self.assertIn("validation_report_payload", response)
            self.assertIn("frozen_pipeline_execution_ref", response)
            self.assertIn("runner", runner_holder)
            self.assertEqual(
                runner_holder["runner"].execution_inputs,
                {"adapter_omega_scaled": {"value": runner_holder["runner"].scaled_omega, "units": "dimensionless"}},
            )
            self.assertIsNotNone(runner_holder["runner"].blind_data_stage)
            self.assertFalse(runner_holder["runner"].blind_data_stage.truth_bytes_delivered_to_sandbox)
            report_ref = str(response["validation_report_ref"])
            self.assertTrue(report_ref.startswith("c4://artifact/"))
            self.assertEqual(response["validation_report_payload"]["claim_tier"], "recapitulated-known")
            self.assertEqual(response["validation_report_payload"]["referee"]["referee_id"], "s3-reference-verifier")

            s3_store = _runtime_store(
                s10_url=s10_url,
                s8_url=s8_url,
                bootstrap_token=bootstrap_token,
                caller_id="m1-reference-s3",
            )
            persisted = s3_store.get_record(report_ref)
            persisted_report = json.loads(s3_store.get_artifact(report_ref).decode("utf-8"))
            lineage = s3_store.get_lineage(report_ref, direction="ancestors")
            blind_stage_payload = json.loads(
                s3_store.get_artifact(runner_holder["runner"].blind_data_stage.stage_evidence_ref).decode("utf-8")
            )
            remote_verifier = HttpS10VerifierKeyProvider(
                endpoint_url=f"{s10_url}/v1/internal/verifier-keys",
                auth_token=verifier_key_token,
                allow_insecure_verifier_key_store=True,
            )
            verification = S10VerifierTrustStoreClient(remote_verifier)

            self.assertEqual(persisted.kind, "report")
            self.assertEqual(persisted.producer.subsystem, "S3")
            self.assertEqual(persisted.producer.job_id, "m1-reference-job")
            self.assertEqual(persisted_report, response["validation_report_payload"])
            self.assertEqual(blind_stage_payload["dataset_kind"], "recap_benchmark")
            self.assertFalse(blind_stage_payload["truth_bytes_delivered_to_sandbox"])
            self.assertIn(refs["frozen_pipeline_ref"], {node.artifact_ref for node in lineage.nodes})
            self.assertIn(response["frozen_pipeline_execution_ref"], {node.artifact_ref for node in lineage.nodes})
            self.assertEqual(
                verification.verify_signature_value(
                    key_id="s3-reference-referee-key",
                    report_with_empty_signature={
                        **persisted_report,
                        "signature": {**persisted_report["signature"], "value": ""},
                    },
                    signature_value=persisted_report["signature"]["value"],
                ),
                "signature_accepted",
            )
            self.assertGreater(durable_store.record_count, 4)

    def test_referee_rejects_a_request_for_a_different_runtime_job_before_writing(self) -> None:
        referee = S3ReferenceRefereeApp(
            s10_url="http://s10.invalid",
            s8_url="http://s8.invalid",
            bootstrap_token="bootstrap",
            caller_id="m1-reference-s3",
            expected_job_id="m1-reference-job",
            signer=C3ReportSigner(key_id="s3-reference-referee-key", secret=b"test-secret"),
            verifier_key_endpoint_url="http://s10.invalid/v1/internal/verifier-keys",
            verifier_key_auth_token="verifier-token",
            allow_insecure_verifier_key_store=True,
        )

        status, response = referee.http.handle(
            JsonRequest(
                method="POST",
                path=S3_REFERENCE_REFEREE_ROUTE,
                query={},
                body={"job_id": "attacker-selected-job"},
            )
        )

        self.assertEqual(status, 403)
        self.assertEqual(response["error"], "job_id_mismatch")


def _identity(*, caller_id: str, producer_subsystems: tuple[str, ...]) -> RuntimeIdentity:
    return RuntimeIdentity(
        caller_id=caller_id,
        job_id="m1-reference-job",
        root_request_id="m1-reference-root",
        scopes=ScopeGrant(
            broker_audiences=("store",),
            capabilities=("s8.read",),
            producer_subsystems=producer_subsystems,
        ),
        budget_caps=BudgetCaps(max_compute_units=1, max_wallclock_s=60, max_cost_usd=1),
        max_ttl_s=600,
    )


def _runtime_store(*, s10_url: str, s8_url: str, bootstrap_token: str, caller_id: str) -> S10S8ArtifactStore:
    session = RuntimeIdentitySession.from_bootstrap(
        s10_url=s10_url,
        bootstrap_token=bootstrap_token,
        caller_id=caller_id,
        expected_job_id="m1-reference-job",
    )
    return S10S8ArtifactStore(session=session, s8_url=s8_url)


def _seed_reference_pipeline(store: S10S8ArtifactStore) -> dict[str, str]:
    omega = evaluate_sound_wave_spectrum(
        temperature_gev=100.0,
        alpha=0.2,
        beta_over_h=100.0,
        wall_velocity=0.7,
        frequency_hz=0.003,
    ).omega
    profile = store.create_artifact(
        kind="profile",
        artifact_ref="c4://profile/ewpt-reference/v1",
        payload={"profile": "ewpt-reference", "checks": ["injection", "null", "physical-consistency"]},
        producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.reference-profile"),
        lineage=_lineage("s1.reference-profile"),
    )
    scale = 1e-11
    dataset = store.create_artifact(
        kind="dataset",
        artifact_ref="c4://dataset/ewpt-reference/m1-runtime",
        payload={
            "rows": [
                {
                    "T_n": 100.0,
                    "alpha": 0.2,
                    "beta_over_H": 100.0,
                    "v_w": 0.7,
                    "frequency": 0.003,
                    "adapter_omega_scaled": omega / scale,
                    "omega_scaled": omega / scale,
                    "omega": omega,
                    "known_omega": omega,
                }
            ],
            "feature_scale": scale,
            "target_scale": scale,
            "reference_context": {},
        },
        producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.reference-dataset"),
        lineage=_lineage("s1.reference-dataset"),
    )
    frozen = store.create_artifact(
        kind="frozen_pipeline",
        payload={
            "schema_version": S2_FROZEN_PIPELINE_SCHEMA_VERSION,
            "entrypoint": "predict",
            "entrypoint_contract_version": S2_FROZEN_PIPELINE_ENTRYPOINT_CONTRACT_VERSION,
            "s3_executable": True,
            "container_digest": "sha256:" + "c" * 64,
            "self_replay_passed": True,
            "artifact_refs": [dataset.artifact_ref],
            "component_refs": {"input_refs": [dataset.artifact_ref]},
            "io_signature": {
                "inputs": {"adapter_omega_scaled": {"units": "dimensionless", "value_type": "float"}},
                "outputs": {"omega_scaled": {"units": "dimensionless", "value_type": "float"}},
            },
            "feature_graph": {
                "nodes": [
                    {
                        "node_id": "adapter_omega_scaled",
                        "feature": {"terms": [{"field_name": "adapter_omega_scaled", "exponent": 1}]},
                    }
                ]
            },
            "feature_set": {"selected_nodes": ["adapter_omega_scaled"]},
            "model_checkpoint": {
                "backend": "deterministic-linear",
                "model_state": {
                    "feature_names": ["adapter_omega_scaled"],
                    "weights": {"adapter_omega_scaled": 1.0},
                    "bias": 0.0,
                },
            },
            "uq_calibration": {
                "uncertainty_method": "split_conformal",
                "interval": {"kind": "symmetric_conformal", "radius": max(omega / scale * 0.01, 1e-12)},
            },
            "code_ref": "argus-core:s2.reference-physics.freeze",
            "environment_digest": "python:s2-reference-physics:v1",
        },
        producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.reference-physics"),
        lineage=_lineage("s1.reference-freeze", input_refs=(dataset.artifact_ref,)),
    )
    return {
        "profile_ref": profile.artifact_ref,
        "model_ref": dataset.artifact_ref,
        "frozen_pipeline_ref": frozen.artifact_ref,
    }


class _ReferencePipelineRunner:
    def __init__(self, store: S10S8ArtifactStore, blind_data_manager) -> None:
        self._store = store
        self._blind_data_manager = blind_data_manager
        self.execution_inputs: dict[str, object] | None = None
        self.scaled_omega = 0.0
        self.blind_data_stage = None

    def run(self, request, *, execution_inputs):
        self.execution_inputs = dict(execution_inputs)
        self.scaled_omega = float(execution_inputs["adapter_omega_scaled"]["value"])
        trace_id = request.get("trace_id")
        self.blind_data_stage = self._blind_data_manager.stage_for_pipeline(
            blind_data_handle=str(request["blind_dataset_handle"]),
            job_id=str(request["job_id"]),
            trace_id=trace_id if isinstance(trace_id, str) else None,
        )
        frozen_pipeline_ref = str(request["frozen_pipeline_ref"])
        pipeline = json.loads(self._store.get_artifact(frozen_pipeline_ref).decode("utf-8"))
        prediction = FrozenPipelineRunner(artifact_store=None).predict_payload(
            pipeline,
            execution_inputs,
            loaded_from_c4=True,
        )
        record = self._store.get_record(frozen_pipeline_ref)
        output = {
            "schema": "argus.s3.frozen_pipeline_execution_output.v1",
            "frozen_pipeline_ref": frozen_pipeline_ref,
            "frozen_pipeline_content_hash": record.content_hash,
            "entrypoint": "predict",
            "outputs_units_tagged": prediction.outputs_units_tagged,
            "uncertainty": prediction.uncertainty,
            "io_signature": prediction.io_signature,
            "diagnostics": prediction.diagnostics,
        }
        evidence = self._store.create_artifact(
            kind="s3_frozen_pipeline_run",
            payload={"schema": "argus.s3.frozen_pipeline_run_evidence.v1", "status": "SUCCEEDED"},
            producer=Producer(subsystem="S3", version="0.0.0", actor_id="s3-reference-verifier", job_id="m1-reference-job"),
            lineage=_lineage("s3.reference-sandbox", input_refs=(frozen_pipeline_ref,)),
        )
        return SimpleNamespace(
            status="SUCCEEDED",
            evidence_ref=evidence.artifact_ref,
            sandbox_id="sandbox-reference-test",
            execution=SimpleNamespace(stdout=json.dumps(output, separators=(",", ":"), sort_keys=True)),
            blind_data_stage=self.blind_data_stage,
        )


def _lineage(code_ref: str, *, input_refs: tuple[str, ...] = ()) -> Lineage:
    return Lineage(
        input_refs=input_refs,
        code_ref=code_ref,
        environment_digest="oci:m1-reference",
        seeds=("m1-reference-seed",),
        job_id="m1-reference-job",
    )


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
