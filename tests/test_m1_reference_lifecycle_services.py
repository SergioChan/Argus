from __future__ import annotations

import json
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
    InMemoryImageVerifier,
    InMemoryS10KmsVerifierKeyProvider,
    Lineage,
    Producer,
    S10VerifierTrustStoreClient,
    ScopeGrant,
    evaluate_sound_wave_spectrum,
)
from argus_runtime.auth import RuntimeAuth, RuntimeIdentity
from argus_runtime.http_json import JsonRequest, serve_json_app
from argus_runtime.m1_reference_runtime import (
    M1_REFERENCE_JOB_ID,
    M1_REFERENCE_SERVICE_REQUEST_TIMEOUT_S,
    M1ReferenceLifecycleRunner,
    REFERENCE_SANDBOX_IMAGE,
)
from argus_runtime.m1_runtime_artifacts import RuntimeIdentitySession, S10S8ArtifactStore
from argus_runtime.s10_supervisor_service import (
    CredentialedAdapterTarget,
    RuntimeIdentityMintPolicy,
    S10SupervisorApp,
    S8BrokeredArtifactStoreClient,
)
from argus_runtime.s11_reference_observatory_service import S11ReferenceObservatoryApp
from argus_runtime.s3_reference_referee_service import S3_REFERENCE_REFEREE_ROUTE, S3ReferenceRefereeApp
from argus_runtime.s2_reference_builder_service import (
    S2_REFERENCE_FINAL_MAX_EPOCHS,
    S2_REFERENCE_BUILDER_ROUTE,
    S2_REFERENCE_HPO_LEARNING_RATES,
    S2_REFERENCE_HPO_MAX_EPOCHS,
    S2_REFERENCE_MAX_PERSISTED_EPOCHS,
    S2_REFERENCE_OMEGA_SCALE,
    S2ReferenceBuilderApp,
    _reference_build_request,
    build_app_from_env as build_s2_reference_builder_app_from_env,
)
import argus_runtime.s2_reference_builder_service as s2_reference_builder_service
from argus_runtime.s7_reference_adapter_service import (
    S7_REFERENCE_ADAPTER_BROKER_CREDENTIAL_HEADER,
    S7_REFERENCE_ADAPTER_ROUTE,
    S7ReferenceAdapterApp,
    build_app_from_env as build_s7_reference_adapter_app_from_env,
)
from argus_runtime.s8_persistence import HttpS10VerifierKeyProvider
from argus_runtime.s8_writer_service import S8WriterApp


class M1ReferenceLifecycleServiceTests(unittest.TestCase):
    def test_m1_reference_lifecycle_uses_build_budget_for_remote_requests(self) -> None:
        runner = M1ReferenceLifecycleRunner(
            s10_url="http://s10.example",
            s8_url="http://s8.example",
            access_token="m1-reference-s1-token",
            secrets_broker_url="http://s10-broker.example",
            s2_url="http://s2.example",
            s3_url="http://s3.example",
            s11_url="http://s11.example",
            verifier_key_endpoint_url="http://s10.example/v1/internal/verifier-keys",
            verifier_key_auth_token="m1-reference-verifier-key-token",
            allow_insecure_verifier_key_store=True,
        )
        session = object()

        with patch(
            "argus_runtime.m1_reference_runtime.runtime_identity_session",
            return_value=session,
        ) as create_session:
            self.assertIs(runner._runtime_session(), session)

        self.assertEqual(
            create_session.call_args.kwargs["timeout_s"],
            M1_REFERENCE_SERVICE_REQUEST_TIMEOUT_S,
        )

    def test_s3_reference_referee_uses_build_budget_for_sandbox_requests(self) -> None:
        referee = S3ReferenceRefereeApp(
            s10_url="http://s10.example",
            s8_url="http://s8.example",
            access_token="m1-reference-s3-token",
            caller_id="m1-reference-s3",
            expected_job_id=M1_REFERENCE_JOB_ID,
            signer=C3ReportSigner(
                key_id="s3-reference-referee-key",
                secret=b"m1-reference-s3-signing-secret",
            ),
            verifier_key_endpoint_url="http://s10.example/v1/internal/verifier-keys",
            verifier_key_auth_token="m1-reference-verifier-key-token",
            allow_insecure_verifier_key_store=True,
        )
        session = object()

        with patch(
            "argus_runtime.s3_reference_referee_service.runtime_identity_session",
            return_value=session,
        ) as create_session:
            referee._artifact_store()

        self.assertEqual(
            create_session.call_args.kwargs["timeout_s"],
            M1_REFERENCE_SERVICE_REQUEST_TIMEOUT_S,
        )

    def test_s2_reference_builder_bounds_persisted_training_epochs(self) -> None:
        build_request = _reference_build_request(
            job_id=M1_REFERENCE_JOB_ID,
            dataset_ref="c4://artifact/m1-reference-training",
            profile_ref="c4://profile/ewpt-reference/v1",
        )

        self.assertEqual(build_request.hpo_max_epochs, S2_REFERENCE_HPO_MAX_EPOCHS)
        self.assertEqual(build_request.final_max_epochs, S2_REFERENCE_FINAL_MAX_EPOCHS)
        self.assertEqual(build_request.hpo_parameter_grid["learning_rate"], S2_REFERENCE_HPO_LEARNING_RATES)
        self.assertLessEqual(
            len(S2_REFERENCE_HPO_LEARNING_RATES) * S2_REFERENCE_HPO_MAX_EPOCHS
            + S2_REFERENCE_FINAL_MAX_EPOCHS,
            S2_REFERENCE_MAX_PERSISTED_EPOCHS,
        )
        with patch.object(
            s2_reference_builder_service,
            "S2_REFERENCE_MAX_PERSISTED_EPOCHS",
            S2_REFERENCE_MAX_PERSISTED_EPOCHS - 1,
        ):
            with self.assertRaisesRegex(ValueError, "persisted-epoch limit"):
                _reference_build_request(
                    job_id=M1_REFERENCE_JOB_ID,
                    dataset_ref="c4://artifact/m1-reference-training",
                    profile_ref="c4://profile/ewpt-reference/v1",
                )

    def test_s2_reference_builder_binds_the_frozen_pipeline_to_a_real_digest(self) -> None:
        pipeline_image = "sha256:" + "a" * 64

        build_request = _reference_build_request(
            job_id=M1_REFERENCE_JOB_ID,
            dataset_ref="c4://artifact/m1-reference-training",
            profile_ref="c4://profile/ewpt-reference/v1",
            pipeline_image=pipeline_image,
        )

        self.assertEqual(build_request.container_digest, pipeline_image)

    def test_s7_reference_adapter_builds_from_access_token_only(self) -> None:
        with patch.dict(
            os.environ,
            {
                "ARGUS_S7_REFERENCE_ADAPTER_S10_URL": "http://s10.example",
                "ARGUS_S7_REFERENCE_ADAPTER_S8_URL": "http://s8.example",
                "ARGUS_S7_REFERENCE_ADAPTER_ACCESS_TOKEN": "preprovisioned-s7-token",
                "ARGUS_S7_REFERENCE_ADAPTER_BROKER_CREDENTIAL": "preprovisioned-broker-credential",
            },
            clear=True,
        ):
            app = build_s7_reference_adapter_app_from_env()

        self.assertEqual(app._caller_id, "m1-reference-s7")
        self.assertEqual(app._expected_job_id, M1_REFERENCE_JOB_ID)

    def test_s2_reference_builder_builds_from_access_token_only(self) -> None:
        with patch.dict(
            os.environ,
            {
                "ARGUS_S2_REFERENCE_BUILDER_S10_URL": "http://s10.example",
                "ARGUS_S2_REFERENCE_BUILDER_S8_URL": "http://s8.example",
                "ARGUS_S2_REFERENCE_BUILDER_ACCESS_TOKEN": "preprovisioned-s2-token",
                "ARGUS_S2_REFERENCE_PIPELINE_IMAGE": "sha256:" + "a" * 64,
            },
            clear=True,
        ):
            app = build_s2_reference_builder_app_from_env()

        self.assertEqual(app._caller_id, "m1-reference-s2")
        self.assertEqual(app._expected_job_id, M1_REFERENCE_JOB_ID)

    def test_s2_reference_builder_requires_s1_and_persists_real_frozen_pipeline(self) -> None:
        bootstrap_token = "m1-s2-builder-bootstrap"
        broker_write_key = b"m1-s2-builder-broker-write-key"
        auth = RuntimeAuth.with_signed_identities(
            bootstrap_token=bootstrap_token,
            identity_signing_key=b"m1-s2-builder-identity-signing-key",
        )
        identities = {
            "m1-reference-s1": _identity(
                caller_id="m1-reference-s1",
                producer_subsystems=("S1",),
                allowed_adapters=("gw_spectrum",),
                allowed_datasets=("dataset:m1-reference-ewpt",),
                broker_audiences=("store", "gw_spectrum"),
            ),
            "m1-reference-s2": _identity(
                caller_id="m1-reference-s2",
                producer_subsystems=("S2",),
                allowed_datasets=("dataset:m1-reference-ewpt",),
            ),
        }
        access_tokens = {
            caller_id: str(auth.mint_identity_token(identity, ttl_s=600)["access_token"])
            for caller_id, identity in identities.items()
        }

        with tempfile.TemporaryDirectory() as tmp:
            durable_store = FileSystemArtifactStore(tmp)
            s8 = S8WriterApp(durable_store, auth=auth, broker_write_key=broker_write_key)
            s8_url = _start_json_server(s8)
            s10 = S10SupervisorApp(
                signing_key=b"m1-s2-builder-s10-signing-key",
                artifact_store=S8BrokeredArtifactStoreClient(
                    endpoint_url=f"{s8_url}/v1/internal/brokered-artifacts",
                    broker_write_key=broker_write_key,
                ),
                auth=auth,
                runtime_identity_mint_policy=RuntimeIdentityMintPolicy(identities_by_caller=identities),
            )
            s10_url = _start_json_server(s10)
            s1_session = RuntimeIdentitySession.from_access_token(
                s10_url=s10_url,
                access_token=access_tokens["m1-reference-s1"],
                caller_id="m1-reference-s1",
                expected_job_id=M1_REFERENCE_JOB_ID,
            )
            s1_store = S10S8ArtifactStore(session=s1_session, s8_url=s8_url)
            dataset = s1_store.create_artifact(
                kind="dataset",
                payload={
                    "schema": {"features": ["adapter_omega_scaled"], "target": "omega_scaled"},
                    "rows": _reference_builder_rows(),
                    "feature_scale": S2_REFERENCE_OMEGA_SCALE,
                    "target_scale": S2_REFERENCE_OMEGA_SCALE,
                },
                producer=Producer(
                    subsystem="S1",
                    version="0.0.0",
                    actor_id="s1.reference-input",
                    job_id=M1_REFERENCE_JOB_ID,
                ),
                lineage=Lineage(
                    input_refs=(),
                    code_ref="argus-test:m1-s2-reference-input",
                    environment_digest="python:m1-s2-reference-test",
                    job_id=M1_REFERENCE_JOB_ID,
                ),
            )
            builder = S2ReferenceBuilderApp(
                s10_url=s10_url,
                s8_url=s8_url,
                access_token=access_tokens["m1-reference-s2"],
                expected_job_id=M1_REFERENCE_JOB_ID,
                require_s1_requester=True,
                pipeline_image=REFERENCE_SANDBOX_IMAGE,
            )

            denied_status, denied = builder.http.handle(
                JsonRequest(
                    method="POST",
                    path=S2_REFERENCE_BUILDER_ROUTE,
                    query={},
                    body={"job_id": M1_REFERENCE_JOB_ID, "dataset_ref": dataset.artifact_ref},
                )
            )
            status, payload = builder.http.handle(
                JsonRequest(
                    method="POST",
                    path=S2_REFERENCE_BUILDER_ROUTE,
                    query={},
                    body={"job_id": M1_REFERENCE_JOB_ID, "dataset_ref": dataset.artifact_ref},
                    headers={"Authorization": f"Bearer {access_tokens['m1-reference-s1']}"},
                )
            )

            self.assertEqual(denied_status, 403)
            self.assertEqual(denied["error"], "requester_unauthorized")

            wrong_job_status, wrong_job = builder.http.handle(
                JsonRequest(
                    method="POST",
                    path=S2_REFERENCE_BUILDER_ROUTE,
                    query={},
                    body={"job_id": "attacker-selected-job", "dataset_ref": dataset.artifact_ref},
                    headers={"Authorization": f"Bearer {access_tokens['m1-reference-s1']}"},
                )
            )

            self.assertEqual(wrong_job_status, 403)
            self.assertEqual(wrong_job["error"], "job_id_mismatch")
            self.assertEqual(status, 200, payload)
            self.assertEqual(payload["claim_tier"], "ran-toy")
            self.assertTrue(payload["frozen_pipeline_ref"])
            self.assertTrue(payload["uq_calibration_ref"])
            self.assertTrue(payload["sandbox_evidence_ref"])

            s2_session = RuntimeIdentitySession.from_access_token(
                s10_url=s10_url,
                access_token=access_tokens["m1-reference-s2"],
                caller_id="m1-reference-s2",
                expected_job_id=M1_REFERENCE_JOB_ID,
            )
            s2_store = S10S8ArtifactStore(session=s2_session, s8_url=s8_url)
            frozen = s2_store.get_record(str(payload["frozen_pipeline_ref"]))
            calibration = s2_store.get_record(str(payload["uq_calibration_ref"]))
            sandbox_evidence = s2_store.get_record(str(payload["sandbox_evidence_ref"]))
            artifact_refs = payload["artifact_refs"]
            self.assertIsInstance(artifact_refs, list)
            self.assertGreater(len(artifact_refs), 0)
            for artifact_ref in artifact_refs:
                artifact = s2_store.get_record(str(artifact_ref))
                self.assertEqual(artifact.producer.subsystem, "S2")
                self.assertEqual(artifact.producer.job_id, M1_REFERENCE_JOB_ID)
                self.assertEqual(artifact.lineage.job_id, M1_REFERENCE_JOB_ID)
            self.assertEqual(frozen.kind, "frozen_pipeline")
            self.assertEqual(frozen.producer.subsystem, "S2")
            self.assertEqual(calibration.kind, "uq_calibration")
            self.assertEqual(calibration.producer.subsystem, "S2")
            self.assertEqual(sandbox_evidence.kind, "s2_sandbox_evidence")
            self.assertEqual(sandbox_evidence.producer.subsystem, "S2")

    def test_real_http_lifecycle_uses_separate_s1_s3_s7_s11_identities_and_real_s10_sandbox(self) -> None:
        docker = _require_reference_image_or_skip(self)
        pipeline_image = _require_reference_pipeline_image_or_skip(self, docker)
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
                    EgressRule("s10-supervisor", 443, "https"),
                ),
                broker_audiences=("store", "gw_spectrum"),
                budget_caps=BudgetCaps(max_compute_units=10, max_wallclock_s=30, max_cost_usd=1),
            ),
            "m1-reference-s2": _identity(
                caller_id="m1-reference-s2",
                producer_subsystems=("S2",),
                allowed_datasets=("dataset:m1-reference-ewpt",),
            ),
            "m1-reference-s3": _identity(
                caller_id="m1-reference-s3",
                producer_subsystems=("S3",),
                budget_caps=BudgetCaps(max_compute_units=10, max_wallclock_s=30, max_cost_usd=1),
            ),
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
            adapter_credential = "m1-lifecycle-adapter-broker-credential"
            s7_port = _free_port()
            s7_url = f"http://127.0.0.1:{s7_port}"
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
                image_verifier=InMemoryImageVerifier(
                    trusted_images=(REFERENCE_SANDBOX_IMAGE, pipeline_image),
                ),
                docker_supervisor=DockerSandboxSupervisor(docker_bin=docker),
                adapter_targets={
                    "gw_spectrum": CredentialedAdapterTarget(
                        adapter_id="gw_spectrum",
                        endpoint_url=f"{s7_url}{S7_REFERENCE_ADAPTER_ROUTE}",
                        credential_header=S7_REFERENCE_ADAPTER_BROKER_CREDENTIAL_HEADER,
                        credential=adapter_credential,
                    )
                },
            )
            s10_url = _start_json_server(s10)
            s7 = S7ReferenceAdapterApp(
                s10_url=s10_url,
                s8_url=s8_url,
                access_token=access_tokens["m1-reference-s7"],
                broker_credential=adapter_credential,
                expected_job_id=M1_REFERENCE_JOB_ID,
            )
            _start_json_server(s7, port=s7_port)
            s2 = S2ReferenceBuilderApp(
                s10_url=s10_url,
                s8_url=s8_url,
                access_token=access_tokens["m1-reference-s2"],
                expected_job_id=M1_REFERENCE_JOB_ID,
                require_s1_requester=True,
                pipeline_image=pipeline_image,
            )
            s2_url = _start_json_server(s2)
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
                secrets_broker_url=s10_url,
                s2_url=s2_url,
                s3_url=s3_url,
                s11_url=s11_url,
                verifier_key_endpoint_url=f"{s10_url}/v1/internal/verifier-keys",
                verifier_key_auth_token=verifier_key_token,
                allow_insecure_verifier_key_store=True,
            )

            lifecycle_events: list[dict[str, object]] = []
            result = runner.run(job_id=M1_REFERENCE_JOB_ID, event_sink=lifecycle_events.append)
            repeated_result = runner.run(job_id=M1_REFERENCE_JOB_ID)

            self.assertEqual(result.final_state, "REPORTED")
            self.assertEqual(result.lifecycle_methods, ("accept", "plan", "build", "validate", "report"))
            self.assertEqual(repeated_result.final_state, "REPORTED")
            self.assertEqual(repeated_result.dataset_ref, result.dataset_ref)
            self.assertTrue(result.observatory_trusted, result.observatory_failures)
            self.assertEqual(
                [(event["stage"], event["status"]) for event in lifecycle_events],
                [
                    ("runtime_identity", "started"),
                    ("runtime_identity", "completed"),
                    ("verifier_profile", "started"),
                    ("verifier_profile", "completed"),
                    ("reference_dataset", "started"),
                    ("reference_dataset", "completed"),
                    ("accept", "started"),
                    ("accept", "completed"),
                    ("plan", "started"),
                    ("plan", "completed"),
                    ("build", "started"),
                    ("build", "completed"),
                    ("validate", "started"),
                    ("validate", "completed"),
                    ("report", "started"),
                    ("report", "completed"),
                    ("observatory", "started"),
                    ("observatory", "completed"),
                    ("run", "completed"),
                ],
            )
            fresh_verification = runner.verify_artifact(result=result)
            self.assertTrue(fresh_verification.trusted, fresh_verification.failures)
            self.assertTrue(fresh_verification.report_matches_run_result)
            self.assertEqual(fresh_verification.subject_ref, result.promoted_artifact_ref)
            self.assertEqual(fresh_verification.report_ref, result.validation_report_ref)
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
            s2_training_dataset_ref = str(result.build_payload["diagnostics"]["s2_training_dataset_ref"])
            s2_frozen_pipeline_ref = str(
                result.build_payload["diagnostics"]["external_frozen_pipeline"]["artifact_ref"]
            )
            adapter_provenance_ref = str(result.build_payload["diagnostics"]["adapter_provenance_ref"])
            adapter_descriptor_ref = GWSpectrumAdapter().as_simple_adapter().descriptor.provenance_ref
            sandbox_ref = str(result.build_payload["diagnostics"]["sandbox"]["launch_provenance_ref"])
            records = {
                "dataset": s1_store.get_record(result.dataset_ref),
                "s2_training_dataset": s1_store.get_record(s2_training_dataset_ref),
                "s2_frozen_pipeline": s1_store.get_record(s2_frozen_pipeline_ref),
                "adapter_descriptor": s1_store.get_record(adapter_descriptor_ref),
                "adapter": s1_store.get_record(adapter_provenance_ref),
                "sandbox": s1_store.get_record(sandbox_ref),
                "report": s1_store.get_record(result.validation_report_ref),
                "subject": s1_store.get_record(result.promoted_artifact_ref),
                "observatory": s1_store.get_record(result.observatory_html_ref),
            }
            self.assertEqual(records["dataset"].producer.subsystem.upper(), "S1")
            self.assertEqual(records["s2_training_dataset"].producer.subsystem, "S1")
            self.assertEqual(records["s2_training_dataset"].producer.job_id, M1_REFERENCE_JOB_ID)
            training_dataset_payload = json.loads(
                s1_store.get_artifact(s2_training_dataset_ref).decode("utf-8")
            )
            training_rows = training_dataset_payload["rows"]
            self.assertGreaterEqual(len(training_rows), 12)
            self.assertTrue(all(row["adapter_provenance_ref"] for row in training_rows))
            self.assertTrue(
                set(row["adapter_provenance_ref"] for row in training_rows).issubset(
                    set(records["s2_training_dataset"].lineage.input_refs)
                )
            )
            for provenance_ref in {row["adapter_provenance_ref"] for row in training_rows}:
                self.assertEqual(s1_store.get_record(provenance_ref).producer.subsystem, "S7")
            self.assertEqual(records["s2_frozen_pipeline"].kind, "frozen_pipeline")
            self.assertEqual(records["s2_frozen_pipeline"].producer.subsystem, "S2")
            self.assertEqual(records["s2_frozen_pipeline"].producer.job_id, M1_REFERENCE_JOB_ID)
            self.assertIn(
                s2_training_dataset_ref,
                {node.artifact_ref for node in s1_store.get_lineage(s2_frozen_pipeline_ref).nodes},
            )
            self.assertEqual(
                result.validation_report_payload["frozen_pipeline_ref"],
                s2_frozen_pipeline_ref,
            )
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


def _reference_builder_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for index in range(60):
        alpha = 0.05 + (index % 10) * 0.02
        beta_over_h = 70.0 + (index // 10) * 12.0
        wall_velocity = 0.45 + (index % 6) * 0.07
        frequency_hz = 0.001 + (index % 8) * 0.0005
        omega = evaluate_sound_wave_spectrum(
            temperature_gev=100.0,
            alpha=alpha,
            beta_over_h=beta_over_h,
            wall_velocity=wall_velocity,
            frequency_hz=frequency_hz,
        ).omega
        rows.append(
            {
                "row_id": f"ewpt-{index:03d}",
                "adapter_omega": omega,
                "omega": omega,
                "adapter_omega_scaled": omega / S2_REFERENCE_OMEGA_SCALE,
                "omega_scaled": omega / S2_REFERENCE_OMEGA_SCALE,
                "role": "train",
            }
        )
    return rows


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


def _require_reference_pipeline_image_or_skip(test_case: unittest.TestCase, docker: str) -> str:
    image_tag = "argus-m1-reference-pipeline-test:local"
    built = subprocess.run(
        [
            docker,
            "build",
            "--file",
            "deploy/argus-m0/python-service.Dockerfile",
            "--tag",
            image_tag,
            ".",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=600,
    )
    test_case.assertEqual(built.returncode, 0, built.stderr)
    inspected = subprocess.run(
        [docker, "image", "inspect", "--format", "{{.Id}}", image_tag],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    test_case.assertEqual(inspected.returncode, 0, inspected.stderr)
    image_id = inspected.stdout.strip()
    test_case.assertRegex(image_id, r"^sha256:[0-9a-f]{64}$")
    return image_id


def _start_json_server(app: object, *, port: int | None = None) -> str:
    selected_port = port or _free_port()
    http = getattr(app, "http")
    thread = Thread(
        target=serve_json_app,
        kwargs={"app": http, "host": "127.0.0.1", "port": selected_port},
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 5
    while True:
        try:
            with socket.create_connection(("127.0.0.1", selected_port), timeout=0.2):
                return f"http://127.0.0.1:{selected_port}"
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
