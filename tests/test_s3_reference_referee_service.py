from __future__ import annotations

import json
import socket
import tempfile
import time
from threading import Thread
import unittest

from argus_core import (
    BudgetCaps,
    C3ReportVerifier,
    C3ReportSigner,
    FileSystemArtifactStore,
    InMemoryS10KmsVerifierKeyProvider,
    Lineage,
    Producer,
    ScopeGrant,
    S10VerifierTrustStoreClient,
    evaluate_sound_wave_spectrum,
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
            self.assertIn(refs["frozen_pipeline_ref"], {node.artifact_ref for node in lineage.nodes})
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
                    "known_omega": omega,
                }
            ]
        },
        producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.reference-dataset"),
        lineage=_lineage("s1.reference-dataset"),
    )
    model = store.create_artifact(
        kind="model",
        payload={
            "schema": "argus.s1.reference_physics_model.v1",
            "model_family": "ewpt-tabular-reference",
            "dataset_ref": dataset.artifact_ref,
            "adapter_outputs": {
                "omega": {
                    "value": omega,
                    "units": "dimensionless",
                    "uncertainty": {"kind": "interval", "radius": max(omega * 0.01, 1e-30)},
                }
            },
            "uncertainty_tag": {"kind": "interval", "source": "gw_spectrum"},
        },
        producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.reference-physics"),
        lineage=_lineage("s1.reference-model", input_refs=(dataset.artifact_ref,)),
    )
    frozen = store.create_artifact(
        kind="frozen_pipeline",
        payload={
            "schema": "argus.s1.frozen_pipeline.v1",
            "entrypoint": "predict",
            "model_ref": model.artifact_ref,
            "artifact_refs": [model.artifact_ref],
            "code_ref": "argus-core:s1.reference-physics.freeze",
            "environment_digest": "python:s1-reference-physics:v1",
        },
        producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.reference-physics"),
        lineage=_lineage("s1.reference-freeze", input_refs=(model.artifact_ref,)),
    )
    return {
        "profile_ref": profile.artifact_ref,
        "model_ref": model.artifact_ref,
        "frozen_pipeline_ref": frozen.artifact_ref,
    }


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
