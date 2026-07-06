from __future__ import annotations

import json
from pathlib import Path
import unittest

import grpc

from argus_core import (
    BudgetCaps,
    InMemoryArtifactStore,
    Lineage,
    Producer,
    ScopeGrant,
)
from argus_runtime.auth import RuntimeAuth, RuntimeIdentity
from argus_runtime.http_json import JsonRequest
from argus_runtime.s3_verifier_service import (
    S3_CLIENT_CERT_SUBJECT_HEADER,
    S3_VERIFY_CAPABILITY,
    S3VerifierApiApp,
    build_s3_grpc_server,
)


ROOT = Path(__file__).resolve().parents[1]


class S3VerifierApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.frozen_record = self.store.create_artifact(
            kind="frozen_pipeline",
            payload={
                "schema": "argus.s3.frozen_pipeline_entrypoint.v1",
                "entrypoint": "argus_core.s2.baseline.predict",
                "artifact_refs": ["c4://artifact/model"],
                "model_ref": "c4://artifact/model",
                "io_signature": {
                    "inputs": [{"name": "x", "dtype": "float64"}],
                    "outputs": [{"name": "prediction", "dtype": "float64"}],
                    "uncertainty": {"representation": "interval"},
                },
                "code_ref": "git:project-argus@s3-t02",
                "environment_digest": "oci:s3-verifier-api@sha256-s3-t02",
                "seeds": ["seed-s3-t02"],
                "self_replay_passed": True,
            },
            producer=Producer(subsystem="S3", version="0.0.0", actor_id="s3-t02"),
            lineage=Lineage(
                input_refs=("c4://artifact/model",),
                code_ref="git:project-argus@s3-t02",
                environment_digest="oci:s3-verifier-api@sha256-s3-t02",
                seeds=("seed-s3-t02",),
            ),
        )
        self.auth = RuntimeAuth(
            {
                "valid-token": RuntimeIdentity(
                    caller_id="s3-client",
                    job_id="job-s3-t02",
                    root_request_id="root-s3-t02",
                    scopes=ScopeGrant(capabilities=(S3_VERIFY_CAPABILITY,)),
                    budget_caps=BudgetCaps(),
                ),
                "no-scope-token": RuntimeIdentity(
                    caller_id="s3-client",
                    job_id="job-s3-t02",
                    root_request_id="root-s3-t02",
                    scopes=ScopeGrant(capabilities=()),
                    budget_caps=BudgetCaps(),
                ),
            }
        )
        self.app = S3VerifierApiApp(auth=self.auth, artifact_store=self.store, health_token="health")

    def test_http_authorized_call_dispatches_and_emits_trace(self) -> None:
        status, payload = self.app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/verifications",
                query={},
                body=self._verification_request(),
                headers=self._headers(),
            )
        )

        self.assertEqual(status, 202)
        self.assertEqual(payload["status"], "DISPATCHED")
        self.assertEqual(payload["transport"], "http-json")
        self.assertEqual(payload["trace_id"], "trace-s3-t02")
        self.assertEqual(payload["entrypoint_request"]["schema"], "argus.s3.frozen_pipeline_entrypoint_request.v1")
        self.assertEqual(payload["entrypoint_request"]["verification_request"]["frozen_pipeline_ref"], self.frozen_record.artifact_ref)
        self.assertEqual(len(self.app.dispatches), 1)

        spans = self.app.telemetry.spans(trace_id="trace-s3-t02")
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].name, "S3.verification.dispatch")
        self.assertEqual(spans[0].status, "OK")
        self.assertEqual(spans[0].attributes["caller_id"], "s3-client")
        self.assertEqual(spans[0].attributes["transport"], "http-json")

    def test_http_rejects_unauthorized_without_dispatch(self) -> None:
        status, payload = self.app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/verifications",
                query={},
                body=self._verification_request(),
                headers={S3_CLIENT_CERT_SUBJECT_HEADER: "s3-client"},
            )
        )

        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "Unauthorized")
        self.assertEqual(self.app.dispatches, ())
        self.assertEqual(self.app.telemetry.spans(trace_id="trace-s3-t02")[0].status, "UNAUTHORIZED")

    def test_http_rejects_missing_scope_before_dispatch(self) -> None:
        status, payload = self.app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/verifications",
                query={},
                body=self._verification_request(),
                headers=self._headers(token="no-scope-token"),
            )
        )

        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "ScopeDenied")
        self.assertIn(S3_VERIFY_CAPABILITY, payload["message"])
        self.assertEqual(self.app.dispatches, ())
        self.assertEqual(self.app.telemetry.spans(trace_id="trace-s3-t02")[0].status, "DENIED")

    def test_http_rejects_missing_mtls_subject(self) -> None:
        status, payload = self.app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/verifications",
                query={},
                body=self._verification_request(),
                headers={"authorization": "Bearer valid-token"},
            )
        )

        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "MutualTlsRequired")
        self.assertEqual(self.app.dispatches, ())

    def test_http_rejects_mtls_subject_mismatch_without_dispatch(self) -> None:
        headers = self._headers()
        headers[S3_CLIENT_CERT_SUBJECT_HEADER] = "other-client"

        status, payload = self.app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/verifications",
                query={},
                body=self._verification_request(),
                headers=headers,
            )
        )

        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "MutualTlsSubjectMismatch")
        self.assertEqual(self.app.dispatches, ())
        self.assertEqual(self.app.telemetry.spans(trace_id="trace-s3-t02")[0].status, "DENIED")

    def test_http_invalid_request_returns_422_without_dispatch(self) -> None:
        body = self._verification_request()
        del body["profile_ref"]

        status, payload = self.app.http.handle(
            JsonRequest(
                method="POST",
                path="/v1/verifications",
                query={},
                body=body,
                headers=self._headers(),
            )
        )

        self.assertEqual(status, 422)
        self.assertEqual(payload["error"], "S3_VERIFIER_PROFILE_REF_INVALID")
        self.assertEqual(self.app.dispatches, ())
        self.assertEqual(self.app.telemetry.spans(trace_id="trace-s3-t02")[0].status, "INVALID")

    def test_grpc_authorized_call_dispatches(self) -> None:
        server, port = build_s3_grpc_server(self.app, port=0)
        server.start()
        try:
            with grpc.insecure_channel(f"127.0.0.1:{port}") as channel:
                submit = channel.unary_unary(
                    "/argus.s3.VerifierApi/SubmitVerification",
                    request_serializer=lambda value: json.dumps(value, sort_keys=True).encode("utf-8"),
                    response_deserializer=lambda raw: json.loads(raw.decode("utf-8")),
                )
                payload = submit(
                    self._verification_request(),
                    metadata=(
                        ("authorization", "Bearer valid-token"),
                        (S3_CLIENT_CERT_SUBJECT_HEADER, "s3-client"),
                    ),
                    timeout=5,
                )
        finally:
            server.stop(0)

        self.assertEqual(payload["status"], "DISPATCHED")
        self.assertEqual(payload["transport"], "grpc-json")
        self.assertEqual(self.app.telemetry.spans(trace_id="trace-s3-t02")[-1].attributes["transport"], "grpc-json")

    def _headers(self, *, token: str = "valid-token") -> dict[str, str]:
        return {
            "authorization": f"Bearer {token}",
            S3_CLIENT_CERT_SUBJECT_HEADER: "s3-client",
        }

    def _verification_request(self) -> dict[str, object]:
        return {
            "job_id": "job-s3-t02",
            "profile_ref": "c4://profile/ewpt/v1",
            "frozen_pipeline_ref": self.frozen_record.artifact_ref,
            "artifact_refs": ["c4://artifact/model"],
            "blind_dataset_handle": "blind://vault/job-s3-t02/features",
            "budget_token_ref": "budget://token/job-s3-t02",
            "scope_token_ref": "scope://token/job-s3-t02",
            "trace_id": "trace-s3-t02",
        }


if __name__ == "__main__":
    unittest.main()
