#!/usr/bin/env python3
"""Run the deployed M1 S2 reference-builder battery against a clean Compose stack."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any, Mapping
from urllib import request as urlrequest
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from argus_core import Lineage, Producer, evaluate_sound_wave_spectrum
from argus_runtime.m1_runtime_artifacts import RuntimeIdentitySession, S10S8ArtifactStore
from argus_runtime.s2_reference_builder_service import S2_REFERENCE_BUILDER_ROUTE
from scripts.run_m0_spine_battery import (
    _compose_environment,
    _free_port,
    _git_dirty,
    _git_head,
    _m0_runtime_secrets,
    _m1_reference_service_access_tokens,
    _post_json,
)


COMPOSE_BUILD_TIMEOUT_S = 600
COMPOSE_UP_TIMEOUT_S = 240


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-file", default=str(ROOT / "deploy/argus-m0/compose.yaml"))
    parser.add_argument("--evidence-file")
    parser.add_argument("--keep-stack", action="store_true")
    args = parser.parse_args()

    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("docker CLI is required for the M1 S2 reference-builder battery")

    runtime_secrets = _m0_runtime_secrets()
    reference_service_tokens = _m1_reference_service_access_tokens(runtime_secrets)
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
    compose_project_name = f"argus-m1-s2-reference-builder-{uuid4().hex[:12]}"
    env = {
        **_compose_environment(runtime_secrets=runtime_secrets, ports=ports, now=int(time.time())),
        "COMPOSE_PROJECT_NAME": compose_project_name,
    }
    s8_url = f"http://127.0.0.1:{ports['ARGUS_M0_S8_PORT']}"
    s10_url = f"http://127.0.0.1:{ports['ARGUS_M0_S10_PORT']}"
    builder_url = f"http://127.0.0.1:{ports['ARGUS_M0_S2_REFERENCE_BUILDER_PORT']}"
    evidence: dict[str, Any] = {
        "battery": "M1 S2 Reference Builder",
        "commit": _git_head(),
        "working_tree_dirty": _git_dirty(),
        "target": {
            "compose_file": str(Path(args.compose_file).resolve()),
            "compose_project_name": compose_project_name,
            "s8_url": s8_url,
            "s10_url": s10_url,
            "s2_reference_builder_url": builder_url,
            "persistence": "postgres-minio",
            "reference_service_auth": "preprovisioned-runtime-identity-tokens",
        },
        "results": [],
    }

    try:
        _run(
            [docker, "compose", "-f", args.compose_file, "build"],
            env=env,
            timeout=COMPOSE_BUILD_TIMEOUT_S,
        )
        _record(evidence, "build", "argus-m0 Compose built the isolated S2 reference-builder stack")
        _run(
            [docker, "compose", "-f", args.compose_file, "up", "-d", "--wait"],
            env=env,
            timeout=COMPOSE_UP_TIMEOUT_S,
        )
        _assert_status_ok(f"{builder_url}/healthz")
        _record(evidence, "deploy", "argus-m0 Compose started the independent S2 reference-builder service")

        s1_session = RuntimeIdentitySession.from_access_token(
            s10_url=s10_url,
            access_token=reference_service_tokens["m1-reference-s1"],
            caller_id="m1-reference-s1",
            expected_job_id="m1-reference-job",
        )
        s1_store = S10S8ArtifactStore(session=s1_session, s8_url=s8_url)
        dataset = s1_store.create_artifact(
            kind="dataset",
            payload={
                "schema": {"features": ["adapter_omega"], "target": "omega"},
                "rows": _reference_rows(),
                "source_class": "m1-controlled-reference-input",
            },
            producer=Producer(
                subsystem="S1",
                version="0.0.0",
                actor_id="s1.reference-tabular-input",
                job_id="m1-reference-job",
            ),
            lineage=Lineage(
                input_refs=(),
                code_ref="argus-runtime:m1-s2-reference-input",
                environment_digest="oci:argus-m1-s2-reference-builder:v1",
                seeds=("m1-reference-s2-builder",),
                job_id="m1-reference-job",
            ),
        )
        rejected = _post_json(
            f"{builder_url}{S2_REFERENCE_BUILDER_ROUTE}",
            {"job_id": "attacker-selected-job", "dataset_ref": dataset.artifact_ref},
            expected_status=403,
            token=s1_session.access_token,
        )
        response = _post_json(
            f"{builder_url}{S2_REFERENCE_BUILDER_ROUTE}",
            {"job_id": "m1-reference-job", "dataset_ref": dataset.artifact_ref},
            expected_status=200,
            token=s1_session.access_token,
            timeout=60,
        )
        s2_session = RuntimeIdentitySession.from_access_token(
            s10_url=s10_url,
            access_token=reference_service_tokens["m1-reference-s2"],
            caller_id="m1-reference-s2",
            expected_job_id="m1-reference-job",
        )
        s2_store = S10S8ArtifactStore(session=s2_session, s8_url=s8_url)
        frozen_ref = _required_str(response, "frozen_pipeline_ref")
        calibration_ref = _required_str(response, "uq_calibration_ref")
        sandbox_ref = _required_str(response, "sandbox_evidence_ref")
        frozen = s2_store.get_record(frozen_ref)
        calibration = s2_store.get_record(calibration_ref)
        sandbox_evidence = s2_store.get_record(sandbox_ref)
        frozen_payload = _artifact_payload(s2_store, frozen_ref)
        lineage_refs = {node.artifact_ref for node in s2_store.get_lineage(frozen_ref, direction="ancestors").nodes}
        artifact_refs = response.get("artifact_refs")
        if not isinstance(artifact_refs, list) or not artifact_refs:
            raise AssertionError("S2 builder response requires non-empty artifact_refs")
        for artifact_ref in artifact_refs:
            if not isinstance(artifact_ref, str) or not artifact_ref:
                raise AssertionError("S2 builder response contains an invalid artifact_ref")
            artifact = s2_store.get_record(artifact_ref)
            if artifact.producer.subsystem != "S2":
                raise AssertionError("S2 builder returned an artifact with a non-S2 producer")
            if artifact.producer.job_id != "m1-reference-job" or artifact.lineage.job_id != "m1-reference-job":
                raise AssertionError("S2 builder returned an artifact outside the M1 root job")
        for record, kind in (
            (frozen, "frozen_pipeline"),
            (calibration, "uq_calibration"),
            (sandbox_evidence, "s2_sandbox_evidence"),
        ):
            if record.kind != kind or record.producer.subsystem != "S2":
                raise AssertionError(f"S2 builder did not persist {kind} through its S2 runtime identity")
            if record.producer.job_id != "m1-reference-job" or record.lineage.job_id != "m1-reference-job":
                raise AssertionError(f"S2 builder did not seal {kind} to the M1 root job")
        if response.get("claim_tier") != "ran-toy":
            raise AssertionError("S2 builder must retain the ran-toy claim-tier cap")
        if frozen_payload.get("self_replay", {}).get("status") != "PASS":
            raise AssertionError("S2 frozen pipeline did not pass its deterministic self-replay")
        if dataset.artifact_ref not in lineage_refs:
            raise AssertionError("S2 frozen pipeline lineage omits the S1 reference dataset")
        _record(
            evidence,
            "external-s2-reference-builder",
            "separate S2 service built and broker-persisted a deterministic UQ-calibrated frozen pipeline from S1-owned C4 data",
            {
                "dataset_ref": dataset.artifact_ref,
                "frozen_pipeline_ref": frozen_ref,
                "uq_calibration_ref": calibration_ref,
                "sandbox_evidence_ref": sandbox_ref,
                "artifact_count": len(artifact_refs),
                "claim_tier": response.get("claim_tier"),
                "self_replay": frozen_payload.get("self_replay", {}).get("status"),
                "lineage_includes_dataset": True,
                "wrong_job_status": rejected.get("error"),
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


def _reference_rows() -> list[dict[str, object]]:
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
                "role": "train",
            }
        )
    return rows


def _assert_status_ok(url: str) -> None:
    with urlrequest.urlopen(url, timeout=10) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        raise AssertionError(f"service health failed: {url} -> {payload}")


def _artifact_payload(store: S10S8ArtifactStore, artifact_ref: str) -> dict[str, Any]:
    payload = json.loads(store.get_artifact(artifact_ref).decode("utf-8"))
    if not isinstance(payload, dict):
        raise AssertionError("expected C4 artifact payload object")
    return payload


def _required_str(value: Mapping[str, Any], field: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item:
        raise AssertionError(f"response requires non-empty {field}")
    return item


def _record(evidence: dict[str, Any], item: str, summary: str, detail: dict[str, Any] | None = None) -> None:
    result: dict[str, Any] = {"item": item, "status": "pass", "summary": summary}
    if detail is not None:
        result["detail"] = detail
    evidence["results"].append(result)


def _run(command: list[str], *, env: Mapping[str, str], timeout: int, check: bool = True) -> None:
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=dict(env),
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"command timed out after {timeout}s: {' '.join(command)}\n"
            f"stdout:\n{_output_text(exc.stdout)}\n"
            f"stderr:\n{_output_text(exc.stderr)}"
        ) from exc
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )


def _output_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
