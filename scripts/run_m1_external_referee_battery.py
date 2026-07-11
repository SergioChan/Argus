#!/usr/bin/env python3
"""Run the external S3 referee integration battery against a clean Argus Compose stack."""

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

from argus_core import (
    C3ReportVerifier,
    Lineage,
    Producer,
    S10VerifierTrustStoreClient,
    evaluate_sound_wave_spectrum,
)
from argus_runtime.m1_runtime_artifacts import RuntimeArtifactStoreError, RuntimeIdentitySession, S10S8ArtifactStore
from argus_runtime.s2_reference_builder_service import S2_REFERENCE_BUILDER_ROUTE, S2_REFERENCE_OMEGA_SCALE
from argus_runtime.s3_reference_referee_service import S3_REFERENCE_PROFILE_ROUTE, S3_REFERENCE_REFEREE_ROUTE
from argus_runtime.s8_persistence import HttpS10VerifierKeyProvider
from scripts.run_m0_spine_battery import (
    _compose_environment,
    _free_port,
    _git_dirty,
    _git_head,
    _m0_identity_mint_policy_json,
    _m0_runtime_secrets,
    _prepare_reference_pipeline_image,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-file", default=str(ROOT / "deploy/argus-m0/compose.yaml"))
    parser.add_argument("--evidence-file")
    parser.add_argument("--keep-stack", action="store_true")
    args = parser.parse_args()

    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("docker CLI is required for the M1 external referee battery")

    runtime_secrets = _m0_runtime_secrets()
    now = int(time.time())
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
    compose_project_name = _isolated_compose_project_name()
    env = {
        **_compose_environment(runtime_secrets=runtime_secrets, ports=ports, now=now),
        "COMPOSE_PROJECT_NAME": compose_project_name,
    }
    s8_url = f"http://127.0.0.1:{ports['ARGUS_M0_S8_PORT']}"
    s10_url = f"http://127.0.0.1:{ports['ARGUS_M0_S10_PORT']}"
    builder_url = f"http://127.0.0.1:{ports['ARGUS_M0_S2_REFERENCE_BUILDER_PORT']}"
    referee_url = f"http://127.0.0.1:{ports['ARGUS_M0_S3_REFERENCE_REFEREE_PORT']}"
    evidence: dict[str, Any] = {
        "battery": "M1 External S3 Reference Referee",
        "commit": _git_head(),
        "working_tree_dirty": _git_dirty(),
        "target": {
            "compose_file": str(Path(args.compose_file).resolve()),
            "compose_project_name": compose_project_name,
            "s8_url": s8_url,
            "s10_url": s10_url,
            "s2_reference_builder_url": builder_url,
            "s3_reference_referee_url": referee_url,
            "persistence": "postgres-minio",
            "reference_service_auth": "preprovisioned-runtime-identity-tokens",
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
        _record(
            evidence,
            "build",
            "argus-m0 Compose built the S3 nested frozen-pipeline image",
            {"pipeline_image": pipeline_image},
        )
        _run([docker, "compose", "-f", args.compose_file, "up", "-d", "--wait"], env=env, timeout=240)
        _assert_status_ok(f"{builder_url}/healthz")
        _assert_status_ok(f"{referee_url}/healthz")
        _record(evidence, "deploy", "argus-m0 Compose started the independent S2 builder and S3 reference-referee services")

        s1_session = RuntimeIdentitySession.from_bootstrap(
            s10_url=s10_url,
            bootstrap_token=runtime_secrets["bootstrap_token"],
            caller_id="m1-reference-s1",
            expected_job_id="m1-reference-job",
        )
        s1_store = S10S8ArtifactStore(session=s1_session, s8_url=s8_url)
        profile = _get_json(
            f"{referee_url}{S3_REFERENCE_PROFILE_ROUTE}",
            token=s1_session.access_token,
        )
        refs = _build_reference_pipeline(
            store=s1_store,
            builder_url=builder_url,
            profile_ref=_required_str(profile, "profile_ref"),
            token=s1_session.access_token,
        )
        denied = _assert_s1_cannot_write_s3_report(s1_store)
        rejected = _post_json(
            f"{referee_url}{S3_REFERENCE_REFEREE_ROUTE}",
            {"job_id": "attacker-selected-job"},
            expected_status=403,
            token=s1_session.access_token,
        )
        response = _post_json(
            f"{referee_url}{S3_REFERENCE_REFEREE_ROUTE}",
            {
                "job_id": "m1-reference-job",
                "profile_ref": refs["profile_ref"],
                "frozen_pipeline_ref": refs["frozen_pipeline_ref"],
                "artifact_refs": refs["artifact_refs"],
                "blind_dataset_handle": "blind://m1-reference/recap",
                "budget_token_ref": "budget://m1-reference/recap",
                "trace_id": "trace:m1-external-referee",
            },
            expected_status=200,
            token=s1_session.access_token,
        )
        s3_store = _runtime_store(
            s10_url=s10_url,
            s8_url=s8_url,
            bootstrap_token=runtime_secrets["bootstrap_token"],
            caller_id="m1-reference-s3",
        )
        report_ref = _required_str(response, "validation_report_ref")
        pipeline_run_ref = _required_str(response, "frozen_pipeline_execution_ref")
        report = _required_dict(response, "validation_report_payload")
        record = s3_store.get_record(report_ref)
        persisted = _json_object(s3_store.get_artifact(report_ref))
        pipeline_run_record = s3_store.get_record(pipeline_run_ref)
        pipeline_run = _json_object(s3_store.get_artifact(pipeline_run_ref))
        frozen_pipeline = _json_object(s3_store.get_artifact(refs["frozen_pipeline_ref"]))
        lineage = s3_store.get_lineage(report_ref, direction="ancestors")
        verifier = C3ReportVerifier(
            S10VerifierTrustStoreClient(
                HttpS10VerifierKeyProvider(
                    endpoint_url=f"{s10_url}/v1/internal/verifier-keys",
                    auth_token=runtime_secrets["s10_verifier_key_auth_token"],
                    allow_insecure_verifier_key_store=True,
                )
            )
        )
        verification = verifier.verify(report)
        expected_checks = {
            "CALIBRATION",
            "INJECTION",
            "NULL_CONTROL",
            "PHYSICAL_CONSISTENCY",
            "RECAP_BENCHMARK",
        }
        checks = {str(item["check"]): str(item["status"]) for item in report["checks"]}
        evidence["runtime_observation"] = {
            "validation_report_ref": report_ref,
            "frozen_pipeline_execution_ref": pipeline_run_ref,
            "nested_sandbox_id": response.get("nested_sandbox_id"),
            "checks": report.get("checks"),
            "aggregate": report.get("aggregate"),
            "frozen_pipeline_model_checkpoint": frozen_pipeline.get("model_checkpoint"),
            "nested_execution": {
                "status": pipeline_run.get("status"),
                "sandbox": pipeline_run.get("sandbox"),
                "execution_inputs": pipeline_run.get("execution_inputs"),
            },
        }
        if not verification.valid:
            raise AssertionError(f"S10 KMS trust client rejected the external S3 report: {verification.reason}")
        if record.kind != "report" or record.producer.subsystem != "S3":
            raise AssertionError("external referee report did not persist as an S3 C4 report")
        if record.producer.job_id != "m1-reference-job":
            raise AssertionError("external referee report was not sealed to the M1 reference job")
        if persisted != report:
            raise AssertionError("external referee C4 payload readback differs from the signed response")
        lineage_refs = {node.artifact_ref for node in lineage.nodes}
        if refs["frozen_pipeline_ref"] not in lineage_refs or pipeline_run_ref not in lineage_refs:
            raise AssertionError("external referee C4 lineage omits the frozen pipeline or nested execution evidence")
        if frozen_pipeline.get("container_digest") != pipeline_image:
            raise AssertionError("S2 frozen pipeline did not bind the Compose-built image ID")
        if pipeline_run_record.kind != "s3_frozen_pipeline_run" or pipeline_run_record.producer.subsystem != "S3":
            raise AssertionError("nested frozen-pipeline execution evidence was not persisted as an S3 C4 artifact")
        if pipeline_run.get("execution_boundary") != "nested_s10_sandbox":
            raise AssertionError("reference referee did not execute the frozen pipeline through nested S10")
        if pipeline_run.get("verifier_imported_pipeline_code") is not False:
            raise AssertionError("reference referee did not declare the verifier-process import boundary")
        launch_request = _required_dict(pipeline_run, "launch_request")
        if launch_request.get("image") != pipeline_image:
            raise AssertionError("nested S10 request did not use the S2 frozen pipeline image ID")
        execution_inputs = _required_dict(pipeline_run, "execution_inputs")
        if execution_inputs.get("top_level_fields") != ["adapter_omega_scaled"]:
            raise AssertionError("nested S10 request received non-opaque reference inputs")
        blind_stage = _required_dict(pipeline_run, "blind_data_stage")
        if blind_stage.get("truth_bytes_delivered_to_sandbox") is not False:
            raise AssertionError("blind reference labels were delivered to the nested S10 sandbox")
        blind_stage_evidence_ref = _required_str(blind_stage, "stage_evidence_ref")
        blind_stage_evidence = _json_object(s3_store.get_artifact(blind_stage_evidence_ref))
        if blind_stage_evidence.get("dataset_kind") != "recap_benchmark":
            raise AssertionError("nested S10 execution did not use the S3 recap benchmark blind-data stage")
        if blind_stage_evidence.get("truth_bytes_delivered_to_sandbox") is not False:
            raise AssertionError("S3 recap benchmark stage delivered blind labels to the nested S10 sandbox")
        if set(checks) != expected_checks or any(status != "PASS" for status in checks.values()):
            raise AssertionError(f"external referee did not emit the five passing reference checks: {checks}")
        if report.get("claim_tier") != "recapitulated-known" or report.get("claim_tier_is_candidate") is not False:
            raise AssertionError("external referee did not produce the expected recapitulated-known report")
        _record(
            evidence,
            "external-s3-reference-referee",
            "separate S3 service ran the S2 frozen pipeline in nested S10 and broker-persisted a KMS-verifiable report",
            {
                "report_ref": report_ref,
                "frozen_pipeline_execution_ref": pipeline_run_ref,
                "nested_sandbox_id": response.get("nested_sandbox_id"),
                "pipeline_image": pipeline_image,
                "report_producer": record.producer.subsystem,
                "report_job_id": record.producer.job_id,
                "claim_tier": report["claim_tier"],
                "checks": checks,
                "signature_key_id": report["signature"]["key_id"],
                "s1_cross_subsystem_write_denial": denied,
                "wrong_job_status": rejected.get("error"),
                "lineage_includes_frozen_pipeline": True,
                "lineage_includes_nested_execution": True,
                "blind_stage_evidence_ref": blind_stage_evidence_ref,
                "blind_stage_dataset_kind": blind_stage_evidence["dataset_kind"],
                "blind_truth_bytes_delivered_to_sandbox": False,
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


def _runtime_store(*, s10_url: str, s8_url: str, bootstrap_token: str, caller_id: str) -> S10S8ArtifactStore:
    session = RuntimeIdentitySession.from_bootstrap(
        s10_url=s10_url,
        bootstrap_token=bootstrap_token,
        caller_id=caller_id,
        expected_job_id="m1-reference-job",
    )
    return S10S8ArtifactStore(session=session, s8_url=s8_url)


def _isolated_compose_project_name() -> str:
    return f"argus-m1-external-referee-{uuid4().hex[:12]}"


def _build_reference_pipeline(
    *,
    store: S10S8ArtifactStore,
    builder_url: str,
    profile_ref: str,
    token: str,
) -> dict[str, Any]:
    dataset = store.create_artifact(
        kind="dataset",
        payload={
            "schema": {"features": ["adapter_omega_scaled"], "target": "omega_scaled"},
            "rows": _reference_rows(),
            "feature_scale": S2_REFERENCE_OMEGA_SCALE,
            "target_scale": S2_REFERENCE_OMEGA_SCALE,
            "source_class": "m1-external-referee-reference-input",
        },
        producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.external-referee-input"),
        lineage=_lineage("argus-runtime:m1-external-referee-reference-input"),
    )
    response = _post_json(
        f"{builder_url}{S2_REFERENCE_BUILDER_ROUTE}",
        {
            "job_id": "m1-reference-job",
            "dataset_ref": dataset.artifact_ref,
            "profile_ref": profile_ref,
        },
        expected_status=200,
        token=token,
        timeout=60,
    )
    artifact_refs = response.get("artifact_refs")
    if not isinstance(artifact_refs, list) or not artifact_refs or not all(
        isinstance(ref, str) and ref for ref in artifact_refs
    ):
        raise AssertionError("S2 builder response requires non-empty artifact_refs")
    return {
        "profile_ref": profile_ref,
        "dataset_ref": dataset.artifact_ref,
        "model_ref": _required_str(response, "model_ref"),
        "frozen_pipeline_ref": _required_str(response, "frozen_pipeline_ref"),
        "artifact_refs": list(artifact_refs),
    }


def _reference_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    samples: list[tuple[str, float, float, float, float]] = [
        ("s7-reference-base", 0.2, 100.0, 0.7, 0.003),
    ]
    samples.extend(
        (
            f"s7-reference-{index:03d}",
            0.05 + (index % 10) * 0.02,
            70.0 + (index // 10) * 12.0,
            0.45 + (index % 6) * 0.07,
            0.001 + (index % 8) * 0.0005,
        )
        for index in range(1, 16)
    )
    for row_id, alpha, beta_over_h, wall_velocity, frequency_hz in samples:
        omega = evaluate_sound_wave_spectrum(
            temperature_gev=100.0,
            alpha=alpha,
            beta_over_h=beta_over_h,
            wall_velocity=wall_velocity,
            frequency_hz=frequency_hz,
        ).omega
        rows.append(
            {
                "row_id": row_id,
                "T_n": 100.0,
                "alpha": alpha,
                "beta_over_H": beta_over_h,
                "v_w": wall_velocity,
                "frequency": frequency_hz,
                "adapter_omega": omega,
                "omega": omega,
                "known_omega": omega,
                "adapter_omega_scaled": omega / S2_REFERENCE_OMEGA_SCALE,
                "omega_scaled": omega / S2_REFERENCE_OMEGA_SCALE,
                "role": "train",
            }
        )
    return rows


def _assert_s1_cannot_write_s3_report(store: S10S8ArtifactStore) -> str:
    try:
        store.create_artifact(
            kind="report",
            payload={"invalid": "S1 may not write as S3"},
            producer=Producer(subsystem="S3", version="0.0.0", actor_id="s1.attacker"),
            lineage=_lineage("argus-runtime:forged-s3-report"),
        )
    except RuntimeArtifactStoreError as exc:
        return str(exc)
    raise AssertionError("S1 runtime identity unexpectedly wrote an S3 artifact")


def _lineage(code_ref: str, *, input_refs: tuple[str, ...] = ()) -> Lineage:
    return Lineage(
        input_refs=input_refs,
        code_ref=code_ref,
        environment_digest="oci:argus-m1-reference:v1",
        seeds=("m1-reference-seed",),
        job_id="m1-reference-job",
    )


def _assert_status_ok(url: str) -> None:
    payload = _get_json(url)
    if payload.get("status") != "ok":
        raise AssertionError(f"service health failed: {url} -> {payload}")


def _post_json(
    url: str,
    payload: dict[str, Any],
    *,
    expected_status: int,
    token: str | None = None,
    timeout: float = 30,
) -> dict[str, Any]:
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urlrequest.Request(url, data=encoded, method="POST", headers=headers)
    try:
        with urlrequest.urlopen(request, timeout=timeout) as response:
            status = response.status
            body = _json_object(response.read())
    except urlerror.HTTPError as exc:
        status = exc.code
        body = _json_object(exc.read())
    if status != expected_status:
        raise AssertionError(f"{url} expected HTTP {expected_status}, received {status}: {body}")
    return body


def _get_json(url: str, *, token: str | None = None) -> dict[str, Any]:
    headers = {} if token is None else {"Authorization": f"Bearer {token}"}
    request = urlrequest.Request(url, headers=headers)
    with urlrequest.urlopen(request, timeout=10) as response:
        return _json_object(response.read())


def _json_object(raw: bytes) -> dict[str, Any]:
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise AssertionError("expected an object JSON response")
    return value


def _required_str(value: dict[str, Any], field: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item:
        raise AssertionError(f"response requires non-empty {field}")
    return item


def _required_dict(value: dict[str, Any], field: str) -> dict[str, Any]:
    item = value.get(field)
    if not isinstance(item, dict):
        raise AssertionError(f"response requires object {field}")
    return item


def _record(evidence: dict[str, Any], item: str, summary: str, detail: dict[str, Any] | None = None) -> None:
    result: dict[str, Any] = {"item": item, "status": "pass", "summary": summary}
    if detail is not None:
        result["detail"] = detail
    evidence["results"].append(result)


def _run(command: list[str], *, env: dict[str, str], timeout: int, check: bool = True) -> None:
    completed = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=timeout, check=False)
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )


if __name__ == "__main__":
    raise SystemExit(main())
