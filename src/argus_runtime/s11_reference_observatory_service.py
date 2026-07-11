"""Deployed S11 Observatory renderer for the M1 reference lifecycle."""

from __future__ import annotations

import json
import os
from typing import Any, Mapping

from argus_core.s10 import S10VerifierTrustStoreClient
from argus_core.s11 import ObservatoryLineageBundle, render_observatory_v0_html
from argus_core.s8 import Lineage, Producer
from argusverify import C3ReportVerifier

from .http_json import JsonHttpApp, JsonRequest, serve_json_app
from .m1_reference_service_auth import M1RequesterUnauthorized, require_m1_s1_requester
from .m1_runtime_artifacts import RuntimeIdentitySession, S10S8ArtifactStore, runtime_identity_session
from .s8_persistence import HttpS10VerifierKeyProvider


S11_REFERENCE_OBSERVATORY_NAME = "s11-reference-observatory"
S11_REFERENCE_OBSERVATORY_ROUTE = "/v1/reference-observatory/render"
S11_REFERENCE_OBSERVATORY_DEFAULT_CALLER_ID = "m1-reference-s11"
S11_REFERENCE_OBSERVATORY_DEFAULT_JOB_ID = "m1-reference-job"


class S11ReferenceObservatoryApp:
    """Renders a remote signed report and writes only S11-owned C4 output."""

    def __init__(
        self,
        *,
        s10_url: str,
        s8_url: str,
        bootstrap_token: str | None = None,
        access_token: str | None = None,
        verifier_key_endpoint_url: str,
        verifier_key_auth_token: str,
        allow_insecure_verifier_key_store: bool,
        caller_id: str = S11_REFERENCE_OBSERVATORY_DEFAULT_CALLER_ID,
        expected_job_id: str = S11_REFERENCE_OBSERVATORY_DEFAULT_JOB_ID,
    ) -> None:
        if bool(bootstrap_token) == bool(access_token):
            raise ValueError("S11 reference observatory requires exactly one runtime credential")
        self._s10_url = s10_url
        self._s8_url = s8_url
        self._bootstrap_token = bootstrap_token
        self._access_token = access_token
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
        self.http = JsonHttpApp()
        self._register_routes()

    def render(self, body: Mapping[str, Any]) -> dict[str, Any]:
        payload = _mapping(body, "reference observatory request")
        if payload.get("job_id") != self._expected_job_id:
            raise PermissionError("job_id_mismatch")
        subject_ref = _required_str(payload, "subject_ref", "reference observatory request")
        report_ref = _required_str(payload, "report_ref", "reference observatory request")
        store = self._artifact_store()
        try:
            report_payload = json.loads(store.get_artifact(report_ref).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("reference observatory report payload is invalid JSON") from exc
        if not isinstance(report_payload, dict):
            raise ValueError("reference observatory report payload must be an object")
        render = render_observatory_v0_html(
            report_payload=report_payload,
            lineage=ObservatoryLineageBundle(
                subject_ref=subject_ref,
                report_ref=report_ref,
                graph=store.get_lineage(subject_ref, direction="ancestors"),
            ),
            report_verifier=self._report_verifier,
        )
        record = store.create_artifact(
            kind="observatory_report",
            payload={
                "html": render.html,
                "trusted": render.verification.trusted,
                "subject_ref": subject_ref,
                "report_ref": report_ref,
                "failures": list(render.verification.failures),
            },
            producer=Producer(
                subsystem="S11",
                version="0.0.0",
                actor_id="s11.reference-observatory",
                job_id=self._expected_job_id,
            ),
            lineage=Lineage(
                input_refs=(subject_ref, report_ref),
                code_ref="argus-runtime:s11-reference-observatory",
                environment_digest="oci:argus-s11-reference-observatory:v1",
                job_id=self._expected_job_id,
            ),
        )
        return {
            "observatory_html_ref": record.artifact_ref,
            "observatory_html": render.html,
            "trusted": render.verification.trusted,
            "failures": list(render.verification.failures),
            "signature_key_id": render.verification.signature_key_id,
        }

    def _artifact_store(self) -> S10S8ArtifactStore:
        if self._store is None:
            self._session = runtime_identity_session(
                s10_url=self._s10_url,
                caller_id=self._caller_id,
                expected_job_id=self._expected_job_id,
                bootstrap_token=self._bootstrap_token,
                access_token=self._access_token,
            )
            self._store = S10S8ArtifactStore(session=self._session, s8_url=self._s8_url)
        return self._store

    def _register_routes(self) -> None:
        @self.http.route("GET", "/healthz")
        def health(_request: JsonRequest) -> tuple[int, Any]:
            return 200, {
                "service": S11_REFERENCE_OBSERVATORY_NAME,
                "status": "ok",
                "expected_job_id": self._expected_job_id,
            }

        @self.http.route("POST", S11_REFERENCE_OBSERVATORY_ROUTE)
        def render(request: JsonRequest) -> tuple[int, Any]:
            if not isinstance(request.body, Mapping):
                return 400, {"error": "invalid_json_body"}
            try:
                require_m1_s1_requester(
                    request,
                    s10_url=self._s10_url,
                    expected_job_id=self._expected_job_id,
                )
                return 200, self.render(request.body)
            except M1RequesterUnauthorized as exc:
                return 403, {"error": "requester_unauthorized", "message": str(exc)}
            except PermissionError as exc:
                return 403, {"error": str(exc)}
            except Exception as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}


def build_app_from_env() -> S11ReferenceObservatoryApp:
    return S11ReferenceObservatoryApp(
        s10_url=_required_env("ARGUS_S11_REFERENCE_OBSERVATORY_S10_URL"),
        s8_url=_required_env("ARGUS_S11_REFERENCE_OBSERVATORY_S8_URL"),
        access_token=_required_env("ARGUS_S11_REFERENCE_OBSERVATORY_ACCESS_TOKEN"),
        verifier_key_endpoint_url=os.environ.get(
            "ARGUS_S11_REFERENCE_OBSERVATORY_VERIFIER_KEY_ENDPOINT_URL",
            "http://s10-supervisor:8080/v1/internal/verifier-keys",
        ),
        verifier_key_auth_token=_required_env("ARGUS_S10_VERIFIER_KEY_AUTH_TOKEN"),
        allow_insecure_verifier_key_store=_env_flag(
            os.environ.get("ARGUS_S11_REFERENCE_OBSERVATORY_ALLOW_INSECURE_VERIFIER_KEY_STORE")
        ),
        caller_id=os.environ.get("ARGUS_S11_REFERENCE_OBSERVATORY_CALLER_ID", S11_REFERENCE_OBSERVATORY_DEFAULT_CALLER_ID),
        expected_job_id=os.environ.get(
            "ARGUS_S11_REFERENCE_OBSERVATORY_JOB_ID",
            S11_REFERENCE_OBSERVATORY_DEFAULT_JOB_ID,
        ),
    )


def main(argv: list[str] | None = None) -> int:
    del argv
    host = os.environ.get("ARGUS_S11_REFERENCE_OBSERVATORY_HOST", "127.0.0.1")
    port = int(os.environ.get("ARGUS_S11_REFERENCE_OBSERVATORY_PORT", "8080"))
    serve_json_app(build_app_from_env().http, host=host, port=port)
    return 0


def _mapping(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be an object")
    return dict(value)


def _required_str(value: Mapping[str, Any], field: str, context: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item:
        raise ValueError(f"{context} requires non-empty {field}")
    return item


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _env_flag(value: str | None) -> bool:
    return value is not None and value.strip().lower() in {"1", "true", "yes", "on"}


if __name__ == "__main__":
    raise SystemExit(main())
