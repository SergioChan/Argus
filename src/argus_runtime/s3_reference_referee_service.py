"""External S3 referee service for the M1 reference physics slice."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
from typing import Any, Mapping

from argus_core.s1_reference import (
    S1_REFERENCE_S3_REFEREE_KEY_ID,
    S1_REFERENCE_S3_VERIFIER_ID,
    ReferenceS3ValidationEngine,
)
from argus_core.s10 import S10VerifierTrustStoreClient
from argus_core.s3 import S3ReportBuilder, S3Verifier, build_frozen_pipeline_entrypoint_request
from argus_core.s8 import Producer
from argusverify import C3ReportVerifier

from .http_json import JsonHttpApp, JsonRequest, serve_json_app
from .m1_runtime_artifacts import RuntimeArtifactStoreError, RuntimeIdentitySession, S10S8ArtifactStore
from .s3_report_signer_service import RustS3ReportSigner
from .s8_persistence import HttpS10VerifierKeyProvider


S3_REFERENCE_REFEREE_NAME = "s3-reference-referee"
S3_REFERENCE_REFEREE_ROUTE = "/v1/reference-referee/validate"
S3_REFERENCE_REFEREE_DEFAULT_CALLER_ID = "m1-reference-s3"
S3_REFERENCE_REFEREE_DEFAULT_JOB_ID = "m1-reference-job"


class _RustReferenceReportSigner:
    def __init__(self, signer: RustS3ReportSigner) -> None:
        self._signer = signer

    @property
    def key_id(self) -> str:
        return self._signer.key_id

    def sign(self, report: dict[str, Any]) -> dict[str, Any]:
        return self._signer.sign(report).signed_report


class S3ReferenceRefereeApp:
    """A fail-closed, externally deployed S3 referee for the reference slice."""

    def __init__(
        self,
        *,
        s10_url: str,
        s8_url: str,
        bootstrap_token: str,
        caller_id: str,
        expected_job_id: str,
        signer: Any,
        verifier_key_endpoint_url: str,
        verifier_key_auth_token: str,
        allow_insecure_verifier_key_store: bool = False,
    ) -> None:
        if not caller_id:
            raise ValueError("S3 referee caller_id is required")
        if not expected_job_id:
            raise ValueError("S3 referee expected_job_id is required")
        if not bootstrap_token:
            raise ValueError("S3 referee bootstrap token is required")
        if not getattr(signer, "key_id", None) or not callable(getattr(signer, "sign", None)):
            raise ValueError("S3 referee signer must expose key_id and sign")
        self._s10_url = s10_url
        self._s8_url = s8_url
        self._bootstrap_token = bootstrap_token
        self._caller_id = caller_id
        self._expected_job_id = expected_job_id
        self._session: RuntimeIdentitySession | None = None
        self._store: S10S8ArtifactStore | None = None
        provider = HttpS10VerifierKeyProvider(
            endpoint_url=verifier_key_endpoint_url,
            auth_token=verifier_key_auth_token,
            allow_insecure_verifier_key_store=allow_insecure_verifier_key_store,
        )
        self._report_verifier = C3ReportVerifier(S10VerifierTrustStoreClient(provider))
        self._verifier = S3Verifier(
            verifier_id=S1_REFERENCE_S3_VERIFIER_ID,
            signer_key_id=str(signer.key_id),
            signer=signer,
        )
        self.http = JsonHttpApp()
        self._register_routes()

    def validate(self, request: Mapping[str, Any]) -> dict[str, Any]:
        request_payload = _request_mapping(request)
        job_id = request_payload.get("job_id")
        if job_id != self._expected_job_id:
            raise PermissionError("job_id_mismatch")
        store = self._artifact_store()
        build_frozen_pipeline_entrypoint_request(request_payload, artifact_store=store)
        engine = ReferenceS3ValidationEngine(
            artifact_store=store,
            verifier=self._verifier,
            contamination_index=None,
            contamination_snapshot=None,
            mode="happy",
        )
        report = engine.validate(request_payload)
        verification = self._report_verifier.verify(report)
        if not verification.valid:
            raise RuntimeArtifactStoreError(
                f"S3 generated report was rejected by the S10 verifier boundary: {verification.reason or 'invalid'}"
            )
        input_refs = _validation_input_refs(request_payload)
        committed = S3ReportBuilder(
            artifact_store=store,
            producer=Producer(
                subsystem="S3",
                version="0.0.0",
                actor_id=S1_REFERENCE_S3_VERIFIER_ID,
                job_id=self._expected_job_id,
            ),
            code_ref="argus-runtime:s3-reference-referee",
            environment_digest="oci:argus-s3-reference-referee:v1",
        ).commit_signed_report(
            report,
            input_refs=input_refs,
            job_id=self._expected_job_id,
        )
        persisted = store.get_record(committed.record.artifact_ref)
        persisted_payload = json.loads(store.get_artifact(committed.record.artifact_ref).decode("utf-8"))
        if persisted.kind != "report" or persisted.producer.subsystem != "S3":
            raise RuntimeArtifactStoreError("S3 report readback did not preserve report producer semantics")
        if persisted_payload != committed.report:
            raise RuntimeArtifactStoreError("S3 report C4 readback did not match the signed report")
        if request_payload["frozen_pipeline_ref"] not in persisted.lineage.input_refs:
            raise RuntimeArtifactStoreError("S3 report C4 lineage is missing the frozen pipeline")
        return {
            "validation_report_payload": committed.report,
            "validation_report_ref": committed.record.artifact_ref,
        }

    def _artifact_store(self) -> S10S8ArtifactStore:
        if self._store is None:
            self._session = RuntimeIdentitySession.from_bootstrap(
                s10_url=self._s10_url,
                bootstrap_token=self._bootstrap_token,
                caller_id=self._caller_id,
                expected_job_id=self._expected_job_id,
            )
            self._store = S10S8ArtifactStore(session=self._session, s8_url=self._s8_url)
        return self._store

    def _register_routes(self) -> None:
        @self.http.route("GET", "/healthz")
        def health(_request: JsonRequest) -> tuple[int, Any]:
            return 200, {
                "service": S3_REFERENCE_REFEREE_NAME,
                "status": "ok",
                "expected_job_id": self._expected_job_id,
                "signer_key_id": self._verifier.signer_key_id,
            }

        @self.http.route("POST", S3_REFERENCE_REFEREE_ROUTE)
        def validate(request: JsonRequest) -> tuple[int, Any]:
            if not isinstance(request.body, Mapping):
                return 400, {"error": "invalid_json_body"}
            try:
                return 200, self.validate(request.body)
            except PermissionError as exc:
                if str(exc) == "job_id_mismatch":
                    return 403, {"error": "job_id_mismatch"}
                return 403, {"error": type(exc).__name__, "message": str(exc)}
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}


def build_app_from_env() -> S3ReferenceRefereeApp:
    signer = _rust_signer_from_env()
    return S3ReferenceRefereeApp(
        s10_url=_required_env("ARGUS_S3_REFERENCE_REFEREE_S10_URL"),
        s8_url=_required_env("ARGUS_S3_REFERENCE_REFEREE_S8_URL"),
        bootstrap_token=_required_env("ARGUS_RUNTIME_BOOTSTRAP_TOKEN"),
        caller_id=os.environ.get("ARGUS_S3_REFERENCE_REFEREE_CALLER_ID", S3_REFERENCE_REFEREE_DEFAULT_CALLER_ID),
        expected_job_id=os.environ.get("ARGUS_S3_REFERENCE_REFEREE_JOB_ID", S3_REFERENCE_REFEREE_DEFAULT_JOB_ID),
        signer=signer,
        verifier_key_endpoint_url=os.environ.get(
            "ARGUS_S3_REFERENCE_REFEREE_VERIFIER_KEY_ENDPOINT_URL",
            "http://s10-supervisor:8080/v1/internal/verifier-keys",
        ),
        verifier_key_auth_token=_required_env("ARGUS_S10_VERIFIER_KEY_AUTH_TOKEN"),
        allow_insecure_verifier_key_store=_env_flag(
            os.environ.get("ARGUS_S3_REFERENCE_REFEREE_ALLOW_INSECURE_VERIFIER_KEY_STORE")
        ),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("ARGUS_S3_REFERENCE_REFEREE_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("ARGUS_S3_REFERENCE_REFEREE_PORT", "8080")))
    args = parser.parse_args(argv)
    serve_json_app(build_app_from_env().http, host=args.host, port=args.port)
    return 0


def _rust_signer_from_env() -> _RustReferenceReportSigner:
    key_id = os.environ.get("ARGUS_S3_REFERENCE_REFEREE_SIGNER_KEY_ID", S1_REFERENCE_S3_REFEREE_KEY_ID)
    secret = _required_env("ARGUS_S3_REFERENCE_REFEREE_SIGNER_SECRET")
    environment = {
        "ARGUS_S3_SIGNER_KEYS_JSON": json.dumps(
            {
                "provider": "rust-runtime-vault",
                "keys": [{"key_id": key_id, "secret": secret, "revoked": False}],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    }
    return _RustReferenceReportSigner(
        RustS3ReportSigner(
            command=_rust_signer_command(),
            key_id=key_id,
            environment=environment,
            timeout_s=float(os.environ.get("ARGUS_S3_REFERENCE_REFEREE_SIGNER_TIMEOUT_S", "30")),
        )
    )


def _rust_signer_command() -> tuple[str, ...]:
    configured = os.environ.get("ARGUS_S3_REPORT_SIGNER_COMMAND")
    if configured:
        return tuple(shlex.split(configured))
    installed = Path("/usr/local/bin/argus-s3-report-signer")
    if installed.exists():
        return (str(installed),)
    root = Path(__file__).resolve().parents[2]
    release_binary = root / "bindings/rust/target/release/argus-s3-report-signer"
    if release_binary.exists():
        return (str(release_binary),)
    return (
        "cargo",
        "run",
        "--quiet",
        "--manifest-path",
        str(root / "bindings/rust/Cargo.toml"),
        "--bin",
        "argus-s3-report-signer",
    )


def _request_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("S3 validation request must be an object")
    return {str(key): item for key, item in value.items()}


def _validation_input_refs(request: Mapping[str, Any]) -> tuple[str, ...]:
    refs: list[str] = []
    for value in (
        request.get("frozen_pipeline_ref"),
        request.get("profile_ref"),
        *(request.get("artifact_refs") if isinstance(request.get("artifact_refs"), list) else ()),
    ):
        if isinstance(value, str) and value and value not in refs:
            refs.append(value)
    return tuple(refs)


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _env_flag(value: str | None) -> bool:
    return value is not None and value.strip().lower() in {"1", "true", "yes", "on"}


if __name__ == "__main__":
    raise SystemExit(main())
