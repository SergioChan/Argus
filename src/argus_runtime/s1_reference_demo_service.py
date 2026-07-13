"""Runnable S1 reference physics demo entrypoint for local deploy and M0 evidence."""

from __future__ import annotations

import argparse
from dataclasses import asdict, is_dataclass
from enum import Enum
import json
import os
from pathlib import Path
import shlex
from typing import Any, Mapping

from argus_core import S1ReferencePhysicsHarness, S1ReferencePhysicsRunResult

from .http_json import HttpResponse, JsonHttpApp, JsonRequest, serve_json_app
from .m1_pilot_console import (
    M1_PILOT_CONSOLE_CONFIG_ROUTE,
    M1_PILOT_RUNS_ROUTE,
    M1PilotRunManager,
    PilotArtifactNotReady,
    PilotConsoleError,
    PilotIntake,
    PilotIntakeError,
    PilotRunConflict,
    PilotRunNotFound,
    pilot_access_authorized,
    pilot_console_config,
    render_m1_pilot_console_html,
)
from .m1_reference_runtime import M1_REFERENCE_JOB_ID, M1ReferenceLifecycleRunner
from .s3_report_signer_service import RustS3ReportSigner


S1_REFERENCE_DEMO_NAME = "s1-reference-physics"
S1_REFERENCE_DEMO_ROUTE = "/v1/s1-reference-physics-demo"
S1_REFERENCE_DEMO_DEFAULT_JOB_ID = "s1-reference-demo"


def build_reference_demo(job_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    harness = S1ReferencePhysicsHarness(s3_signer_factory=_reference_rust_s3_signer_factory)
    result = harness.run_happy_path(job_id=job_id)
    lineage_payload = _lineage_payload(harness, result)
    evidence = _evidence_payload(result)
    artifacts = {
        "validation_report": result.validation_report_payload,
        "subagent_report": result.subagent_report,
        "lineage": lineage_payload,
        "observatory_html": result.observatory_render.html,
    }
    return evidence, artifacts


def write_reference_demo_artifacts(
    *,
    evidence: dict[str, Any],
    artifacts: dict[str, Any],
    out_dir: str | os.PathLike[str],
) -> dict[str, str]:
    output_dir = Path(out_dir).absolute()
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "validation_report_path": output_dir / "validation-report.json",
        "subagent_report_path": output_dir / "subagent-report.json",
        "lineage_path": output_dir / "lineage.json",
        "observatory_html_path": output_dir / "observatory.html",
    }
    _write_json(paths["validation_report_path"], artifacts["validation_report"])
    _write_json(paths["subagent_report_path"], artifacts["subagent_report"])
    _write_json(paths["lineage_path"], artifacts["lineage"])
    paths["observatory_html_path"].write_text(str(artifacts["observatory_html"]), encoding="utf-8")
    evidence["artifacts"] = {key: str(path) for key, path in paths.items()}
    return evidence["artifacts"]


class _ReferenceRustS3Signer:
    def __init__(self, *, signer: RustS3ReportSigner) -> None:
        self._signer = signer

    @property
    def key_id(self) -> str:
        return self._signer.key_id

    def sign(self, report: dict[str, Any]) -> dict[str, Any]:
        return self._signer.sign(report).signed_report


def _reference_rust_s3_signer_factory(key_id: str, key_material: bytes) -> _ReferenceRustS3Signer:
    return _ReferenceRustS3Signer(
        signer=RustS3ReportSigner(
            command=_rust_s3_report_signer_command(),
            key_id=key_id,
            environment=_rust_s3_report_signer_environment(key_id=key_id, key_material=key_material),
            timeout_s=float(os.environ.get("ARGUS_S1_REFERENCE_S3_SIGNER_TIMEOUT_S", "30")),
        )
    )


def _rust_s3_report_signer_command() -> tuple[str, ...]:
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


def _rust_s3_report_signer_environment(*, key_id: str, key_material: bytes) -> dict[str, str]:
    return {
        "ARGUS_S3_SIGNER_KEYS_JSON": json.dumps(
            {
                "provider": "rust-local-vault",
                "keys": [
                    {
                        "key_id": key_id,
                        "secret": key_material.decode("utf-8"),
                        "revoked": False,
                    }
                ],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    }


class S1ReferenceDemoApp:
    def __init__(
        self,
        *,
        lifecycle_runner: M1ReferenceLifecycleRunner | None = None,
        default_job_id: str = S1_REFERENCE_DEMO_DEFAULT_JOB_ID,
        pilot_access_token: str | None = None,
    ) -> None:
        self._lifecycle_runner = lifecycle_runner
        self._default_job_id = default_job_id
        self._pilot_access_token = pilot_access_token
        self._pilot_runs = M1PilotRunManager(lifecycle_runner=lifecycle_runner) if lifecycle_runner is not None else None
        self.http = JsonHttpApp()
        self._register_routes()

    def _register_routes(self) -> None:
        @self.http.route("GET", "/healthz")
        def health(_request: JsonRequest) -> tuple[int, Any]:
            return 200, {"status": "ok", "service": S1_REFERENCE_DEMO_NAME}

        @self.http.route("GET", "/")
        def pilot_console(_request: JsonRequest) -> tuple[int, Any]:
            return 200, HttpResponse(
                body=render_m1_pilot_console_html(),
                content_type="text/html; charset=utf-8",
                headers={
                    "Cache-Control": "no-store",
                    "Content-Security-Policy": (
                        "default-src 'self'; base-uri 'none'; connect-src 'self'; "
                        "form-action 'self'; frame-src 'self'; frame-ancestors 'none'; img-src 'self' data:; "
                        "script-src 'unsafe-inline'; style-src 'unsafe-inline'"
                    ),
                },
            )

        @self.http.route("GET", M1_PILOT_CONSOLE_CONFIG_ROUTE)
        def pilot_console_configuration(_request: JsonRequest) -> tuple[int, Any]:
            return 200, pilot_console_config(
                available=self._pilot_runs is not None,
                access_required=self._pilot_access_token is not None,
            )

        @self.http.route("POST", M1_PILOT_RUNS_ROUTE)
        def start_pilot_run(request: JsonRequest) -> tuple[int, Any]:
            authorized = self._require_pilot_access(request)
            if authorized is not None:
                return authorized
            if not isinstance(request.body, Mapping):
                return 400, {"error": "invalid_json_body"}
            try:
                snapshot = self._pilot_run_manager().start(PilotIntake.from_payload(request.body))
            except PilotIntakeError as exc:
                return 422, {"error": str(exc)}
            except PilotRunConflict as exc:
                return 409, {"error": str(exc)}
            return 202, snapshot

        @self.http.prefix("GET", f"{M1_PILOT_RUNS_ROUTE}/")
        def get_pilot_run(request: JsonRequest) -> tuple[int, Any]:
            authorized = self._require_pilot_access(request)
            if authorized is not None:
                return authorized
            run_id, suffix = _pilot_run_path(request.path)
            if run_id is None:
                return 404, {"error": "not_found"}
            try:
                if suffix == "":
                    return 200, self._pilot_run_manager().get_snapshot(run_id)
                if suffix == "observatory":
                    return 200, HttpResponse(
                        body=self._pilot_run_manager().get_observatory_html(run_id),
                        content_type="text/html; charset=utf-8",
                        headers={"Cache-Control": "no-store"},
                    )
            except PilotRunNotFound as exc:
                return 404, {"error": str(exc)}
            except PilotArtifactNotReady as exc:
                return 409, {"error": str(exc)}
            return 404, {"error": "not_found"}

        @self.http.prefix("POST", f"{M1_PILOT_RUNS_ROUTE}/")
        def reverify_pilot_run(request: JsonRequest) -> tuple[int, Any]:
            authorized = self._require_pilot_access(request)
            if authorized is not None:
                return authorized
            run_id, suffix = _pilot_run_path(request.path)
            if run_id is None or suffix != "verify":
                return 404, {"error": "not_found"}
            try:
                return 200, self._pilot_run_manager().reverify(run_id)
            except PilotRunNotFound as exc:
                return 404, {"error": str(exc)}
            except PilotArtifactNotReady as exc:
                return 409, {"error": str(exc)}
            except PilotRunConflict as exc:
                return 409, {"error": str(exc)}

        @self.http.route("POST", S1_REFERENCE_DEMO_ROUTE)
        def run_demo(request: JsonRequest) -> tuple[int, Any]:
            if request.body is not None and not isinstance(request.body, dict):
                return 400, {"error": "invalid_json_body"}
            body = request.body if isinstance(request.body, dict) else {}
            try:
                job_id = _job_id_from_body(body, default_job_id=self._default_job_id)
            except ValueError as exc:
                return 400, {"error": "invalid_job_id", "message": str(exc)}
            if self._lifecycle_runner is not None:
                try:
                    result = self._lifecycle_runner.run(job_id=job_id)
                except ValueError as exc:
                    return 403, {"error": str(exc)}
                except Exception as exc:
                    return 502, {"error": type(exc).__name__, "message": str(exc)}
                return 200, {**result.as_payload(), "observatory_html": result.observatory_html}
            evidence, artifacts = build_reference_demo(job_id)
            return 200, {**evidence, "observatory_html": artifacts["observatory_html"]}

    def _pilot_run_manager(self) -> M1PilotRunManager:
        if self._pilot_runs is None:
            raise PilotConsoleError("pilot_console_unavailable")
        return self._pilot_runs

    def _require_pilot_access(self, request: JsonRequest) -> tuple[int, Any] | None:
        if self._pilot_runs is None:
            return 503, {"error": "pilot_console_unavailable"}
        if not pilot_access_authorized(
            authorization_header=request.headers.get("authorization"),
            access_token=self._pilot_access_token,
        ):
            return 401, {"error": "pilot_access_unauthorized"}
        return None


def build_app() -> S1ReferenceDemoApp:
    return S1ReferenceDemoApp()


def build_app_from_env() -> S1ReferenceDemoApp:
    runner = M1ReferenceLifecycleRunner(
        s10_url=_required_env("ARGUS_S1_REFERENCE_DEMO_S10_URL"),
        s8_url=_required_env("ARGUS_S1_REFERENCE_DEMO_S8_URL"),
        access_token=_required_env("ARGUS_S1_REFERENCE_DEMO_ACCESS_TOKEN"),
        secrets_broker_url=_required_env("ARGUS_S1_REFERENCE_DEMO_SECRETS_BROKER_URL"),
        s2_url=_required_env("ARGUS_S1_REFERENCE_DEMO_S2_URL"),
        s3_url=_required_env("ARGUS_S1_REFERENCE_DEMO_S3_URL"),
        s11_url=_required_env("ARGUS_S1_REFERENCE_DEMO_S11_URL"),
        verifier_key_endpoint_url=os.environ.get(
            "ARGUS_S1_REFERENCE_DEMO_VERIFIER_KEY_ENDPOINT_URL",
            "http://s10-supervisor:8080/v1/internal/verifier-keys",
        ),
        verifier_key_auth_token=_required_env("ARGUS_S10_VERIFIER_KEY_AUTH_TOKEN"),
        allow_insecure_verifier_key_store=_env_flag(
            os.environ.get("ARGUS_S1_REFERENCE_DEMO_ALLOW_INSECURE_VERIFIER_KEY_STORE")
        ),
    )
    return S1ReferenceDemoApp(
        lifecycle_runner=runner,
        default_job_id=M1_REFERENCE_JOB_ID,
        pilot_access_token=_required_env("ARGUS_S1_REFERENCE_DEMO_PILOT_ACCESS_TOKEN"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job-id", default=S1_REFERENCE_DEMO_DEFAULT_JOB_ID)
    parser.add_argument("--out-dir")
    parser.add_argument("--evidence-file")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--host", default=os.environ.get("ARGUS_S1_REFERENCE_DEMO_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("ARGUS_S1_REFERENCE_DEMO_PORT", "8080")))
    args = parser.parse_args(argv)

    if args.serve:
        serve_json_app(build_app_from_env().http, host=args.host, port=args.port)
        return 0

    evidence, artifacts = build_reference_demo(args.job_id)
    if args.out_dir:
        write_reference_demo_artifacts(evidence=evidence, artifacts=artifacts, out_dir=args.out_dir)
    if args.evidence_file:
        evidence_path = Path(args.evidence_file).resolve()
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        _write_json(evidence_path, evidence)
    print(json.dumps(_jsonable(evidence), indent=2, sort_keys=True))
    return 0


def _evidence_payload(result: S1ReferencePhysicsRunResult) -> dict[str, Any]:
    report = result.validation_report_payload
    referee = _mapping(report.get("referee"))
    signature = _mapping(report.get("signature"))
    return {
        "demo": S1_REFERENCE_DEMO_NAME,
        "job_id": result.job_id,
        "final_state": result.final_state.value,
        "lifecycle_methods": list(result.lifecycle_methods),
        "artifact_refs": list(result.artifact_refs),
        "validation_report_ref": result.validation_report_ref,
        "promoted_artifact_ref": result.promoted_artifact.artifact_ref,
        "observatory_html_ref": result.observatory_html_ref,
        "observatory_trusted": result.observatory_render.verification.trusted,
        "observatory_failures": list(result.observatory_render.verification.failures),
        "claim_tier": str(report["claim_tier"]),
        "claim_tier_is_candidate": bool(report.get("claim_tier_is_candidate")),
        "referee_id": str(referee.get("referee_id", "")),
        "signature_key_id": str(signature.get("key_id", "")),
        "checks": [_check_summary(check) for check in _sequence(report.get("checks"))],
    }


def _lineage_payload(harness: S1ReferencePhysicsHarness, result: S1ReferencePhysicsRunResult) -> dict[str, Any]:
    graph = harness.artifact_store.get_lineage(result.promoted_artifact.artifact_ref, direction="ancestors")
    return {
        "subject_ref": result.promoted_artifact.artifact_ref,
        "report_ref": result.validation_report_ref,
        "nodes": [asdict(node) for node in graph.nodes],
        "edges": [asdict(edge) for edge in graph.edges],
    }


def _job_id_from_body(body: Mapping[str, Any], *, default_job_id: str = S1_REFERENCE_DEMO_DEFAULT_JOB_ID) -> str:
    job_id = body.get("job_id")
    if job_id is None:
        return default_job_id
    if not isinstance(job_id, str) or not job_id:
        raise ValueError("job_id must be a non-empty string")
    return job_id


def _pilot_run_path(path: str) -> tuple[str | None, str]:
    prefix = f"{M1_PILOT_RUNS_ROUTE}/"
    if not path.startswith(prefix):
        return None, ""
    parts = [part for part in path.removeprefix(prefix).split("/") if part]
    if len(parts) == 1:
        return parts[0], ""
    if len(parts) == 2:
        return parts[0], parts[1]
    return None, ""


def _check_summary(check: Any) -> dict[str, Any]:
    body = _mapping(check)
    return {
        "check": str(body.get("check", "")),
        "status": str(body.get("status", "")),
        "metrics": dict(_mapping(body.get("metrics"))),
        "evidence_refs": [str(ref) for ref in _sequence(body.get("evidence_refs"))],
    }


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> tuple[Any, ...]:
    return tuple(value) if isinstance(value, (list, tuple)) else ()


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(_jsonable(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _env_flag(value: str | None) -> bool:
    return value is not None and value.strip().lower() in {"1", "true", "yes", "on"}


if __name__ == "__main__":
    raise SystemExit(main())
