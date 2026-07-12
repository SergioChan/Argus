#!/usr/bin/env python3
"""Exercise the browser-facing M1 Pilot Console against a clean Argus Compose stack."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any, Mapping
from urllib import error as urlerror
from urllib import request as urlrequest
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from argus_runtime.m1_pilot_console import M1_PILOT_REFERENCE_SCOPE
from scripts.run_m0_spine_battery import (
    M1_REFERENCE_DEMO_E2E_TIMEOUT_S,
    _compose_environment,
    _free_port,
    _git_dirty,
    _git_head,
    _m0_runtime_secrets,
    _prepare_reference_pipeline_image,
    _run,
    _wait_health,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-file", default=str(ROOT / "deploy/argus-m0/compose.yaml"))
    parser.add_argument("--evidence-file")
    parser.add_argument("--keep-stack", action="store_true")
    args = parser.parse_args()

    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("docker CLI is required for the M1 pilot console battery")

    runtime_secrets = _m0_runtime_secrets()
    ports = {
        "ARGUS_M0_POSTGRES_PORT": str(_free_port()),
        "ARGUS_M0_MINIO_PORT": str(_free_port()),
        "ARGUS_M0_MINIO_CONSOLE_PORT": str(_free_port()),
        "ARGUS_M0_S8_PORT": str(_free_port()),
        "ARGUS_M0_S10_PORT": str(_free_port()),
        "ARGUS_M0_S1_DEMO_PORT": str(_free_port()),
        "ARGUS_M0_S2_REFERENCE_BUILDER_PORT": str(_free_port()),
        "ARGUS_M0_S3_REFERENCE_REFEREE_PORT": str(_free_port()),
    }
    compose_project_name = f"argus-m1-pilot-console-{uuid4().hex[:12]}"
    env = {
        **_compose_environment(runtime_secrets=runtime_secrets, ports=ports, now=int(time.time())),
        "COMPOSE_PROJECT_NAME": compose_project_name,
    }
    demo_url = f"http://127.0.0.1:{ports['ARGUS_M0_S1_DEMO_PORT']}"
    evidence: dict[str, Any] = {
        "battery": "M1 Pilot Console",
        "commit": _git_head(),
        "working_tree_dirty": _git_dirty(),
        "target": {
            "compose_file": str(Path(args.compose_file).resolve()),
            "compose_project_name": compose_project_name,
            "pilot_console_url": demo_url,
            "persistence": "postgres-minio",
            "execution_profile": M1_PILOT_REFERENCE_SCOPE,
        },
        "results": [],
    }

    try:
        pipeline_image = _prepare_reference_pipeline_image(
            docker=docker,
            compose_file=args.compose_file,
            env=env,
        )
        evidence["target"]["s2_reference_pipeline_image"] = pipeline_image
        _record(evidence, "build", "argus-m0 Compose built the fixed M1 pipeline image")
        _run([docker, "compose", "-f", args.compose_file, "up", "-d", "--wait"], env=env, timeout=240)
        _wait_health(f"{demo_url}/healthz", token=None)
        _record(evidence, "deploy", "argus-m0 Compose started the pilot console beside the M1 lifecycle")

        root_status, root_html, root_headers = _request_text("GET", f"{demo_url}/")
        if root_status != 200:
            raise AssertionError(f"pilot console returned unexpected page status: {root_status}")
        if root_headers.get("content-type", "").split(";", 1)[0] != "text/html":
            raise AssertionError("pilot console did not return HTML")
        if "Start verified run" not in root_html or "Re-verify artifact" not in root_html:
            raise AssertionError("pilot console HTML omitted the onboarding or verification controls")
        if "connect-src 'self'" not in root_headers.get("content-security-policy", ""):
            raise AssertionError("pilot console page omitted its same-origin content security policy")

        config = _request_json("GET", f"{demo_url}/v1/pilot-console/config", expected_status=200)
        if config.get("available") is not True or config.get("reference_scope", {}).get("id") != M1_PILOT_REFERENCE_SCOPE:
            raise AssertionError("pilot console did not advertise the fixed M1 reference profile")
        denied = _request_json(
            "POST",
            f"{demo_url}/v1/pilot-runs",
            payload=_pilot_intake_payload(),
            expected_status=401,
        )
        if denied.get("error") != "pilot_access_unauthorized":
            raise AssertionError("pilot console accepted an unauthenticated run request")

        pilot_token = runtime_secrets["m1_pilot_console_access_token"]
        started = _request_json(
            "POST",
            f"{demo_url}/v1/pilot-runs",
            payload=_pilot_intake_payload(),
            expected_status=202,
            token=pilot_token,
        )
        run_id = _required_str(started, "run_id")
        completed = _wait_for_terminal_run(demo_url, run_id=run_id, token=pilot_token)
        if completed.get("status") != "ready_for_review":
            raise AssertionError(f"pilot run did not produce an artifact for review: {completed}")
        intake = _required_dict(completed, "intake")
        if "research_question" in intake or "known_result" in intake:
            raise AssertionError("unshared pilot study context was returned by the service")
        stages = {(str(event.get("stage")), str(event.get("status"))) for event in _required_list(completed, "events")}
        required_stages = {
            ("runtime_identity", "completed"),
            ("build", "completed"),
            ("validate", "completed"),
            ("observatory", "completed"),
            ("run", "completed"),
        }
        if not required_stages.issubset(stages):
            raise AssertionError(f"pilot timeline omitted real lifecycle boundaries: {stages}")
        artifact = _required_dict(completed, "artifact")
        if artifact.get("observatory_trusted") is not True or artifact.get("final_state") != "REPORTED":
            raise AssertionError("pilot console presented an untrusted or incomplete M1 result")

        artifact_status, artifact_html, _ = _request_text(
            "GET",
            f"{demo_url}/v1/pilot-runs/{run_id}/observatory",
            token=pilot_token,
        )
        if artifact_status != 200 or 'data-verdict="VERIFIED"' not in artifact_html:
            raise AssertionError("pilot console did not return the signed Observatory artifact")
        reverified = _request_json(
            "POST",
            f"{demo_url}/v1/pilot-runs/{run_id}/verify",
            expected_status=200,
            token=pilot_token,
        )
        verification = _required_dict(reverified, "verification")
        if verification.get("trusted") is not True or verification.get("report_matches_run_result") is not True:
            raise AssertionError("fresh C3/C4 artifact verification did not pass")
        unsupported = _request_json(
            "POST",
            f"{demo_url}/v1/pilot-runs",
            payload=_pilot_intake_payload(reference_scope="unsupported-physics-topic"),
            expected_status=422,
            token=pilot_token,
        )
        if unsupported.get("error") != "unsupported_reference_scope":
            raise AssertionError("pilot console did not fail closed for an unsupported reference scope")
        _record(
            evidence,
            "pilot-console-e2e",
            "authenticated pilot intake reached the real M1 lifecycle, rendered S11 output, and passed a fresh C3/C4 verification",
            {
                "run_id": run_id,
                "final_state": artifact.get("final_state"),
                "claim_tier": artifact.get("claim_tier"),
                "report_ref": artifact.get("validation_report_ref"),
                "subject_ref": artifact.get("promoted_artifact_ref"),
                "observatory_ref": artifact.get("observatory_html_ref"),
                "event_count": len(completed.get("events", [])),
                "fresh_verification_trusted": verification.get("trusted"),
                "unshared_study_context": True,
                "unsupported_scope_error": unsupported.get("error"),
            },
        )
        print(json.dumps(evidence, indent=2, sort_keys=True))
        return 0
    finally:
        if not args.keep_stack:
            _run([docker, "compose", "-f", args.compose_file, "down", "--volumes"], env=env, timeout=120, check=False)
        if args.evidence_file:
            path = Path(args.evidence_file).resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _pilot_intake_payload(**overrides: Any) -> dict[str, Any]:
    payload = {
        "reference_scope": M1_PILOT_REFERENCE_SCOPE,
        "research_question": "How does the fixed EWPT sound-wave reference spectrum behave near its peak?",
        "known_result": "The known sound-wave spectrum has a bounded peak with physical consistency checks.",
        "baseline_minutes": 60,
        "scope_acknowledged": True,
        "share_with_operator": False,
    }
    payload.update(overrides)
    return payload


def _wait_for_terminal_run(base_url: str, *, run_id: str, token: str) -> dict[str, Any]:
    deadline = time.monotonic() + M1_REFERENCE_DEMO_E2E_TIMEOUT_S
    while True:
        snapshot = _request_json("GET", f"{base_url}/v1/pilot-runs/{run_id}", expected_status=200, token=token)
        if snapshot.get("status") not in {"queued", "running", "verifying"}:
            return snapshot
        if time.monotonic() >= deadline:
            raise AssertionError("pilot console lifecycle did not reach a terminal state before the M1 timeout")
        time.sleep(0.25)


def _request_json(
    method: str,
    url: str,
    *,
    payload: Mapping[str, Any] | None = None,
    expected_status: int,
    token: str | None = None,
) -> dict[str, Any]:
    status, body, _ = _request(method, url, payload=payload, token=token)
    if status != expected_status:
        raise AssertionError(f"{method} {url} returned {status}, expected {expected_status}: {body!r}")
    try:
        decoded = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssertionError(f"{method} {url} did not return JSON: {body!r}") from exc
    if not isinstance(decoded, dict):
        raise AssertionError(f"{method} {url} returned non-object JSON: {decoded!r}")
    return decoded


def _request_text(method: str, url: str, *, token: str | None = None) -> tuple[int, str, dict[str, str]]:
    status, body, headers = _request(method, url, token=token)
    try:
        return status, body.decode("utf-8"), headers
    except UnicodeDecodeError as exc:
        raise AssertionError(f"{method} {url} did not return UTF-8 text") from exc


def _request(
    method: str,
    url: str,
    *,
    payload: Mapping[str, Any] | None = None,
    token: str | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    headers = {"Accept": "application/json"}
    data = None
    if payload is not None:
        data = json.dumps(dict(payload), separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urlrequest.Request(url, data=data, headers=headers, method=method)
    try:
        with urlrequest.urlopen(request, timeout=20) as response:
            return response.status, response.read(), {key.lower(): value for key, value in response.headers.items()}
    except urlerror.HTTPError as exc:
        return exc.code, exc.read(), {key.lower(): value for key, value in exc.headers.items()}


def _required_dict(payload: Mapping[str, Any], field: str) -> dict[str, Any]:
    value = payload.get(field)
    if not isinstance(value, dict):
        raise AssertionError(f"response field {field} must be an object")
    return value


def _required_list(payload: Mapping[str, Any], field: str) -> list[dict[str, Any]]:
    value = payload.get(field)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise AssertionError(f"response field {field} must be an array of objects")
    return value


def _required_str(payload: Mapping[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise AssertionError(f"response field {field} must be a non-empty string")
    return value


def _record(evidence: dict[str, Any], item: str, message: str, detail: Mapping[str, Any] | None = None) -> None:
    record: dict[str, Any] = {"item": item, "message": message}
    if detail:
        record["detail"] = dict(detail)
    evidence["results"].append(record)


if __name__ == "__main__":
    raise SystemExit(main())
