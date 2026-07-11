#!/usr/bin/env python3
"""Run the external S3 referee integration battery against a clean Argus Compose stack."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any, Mapping
from urllib import error as urlerror
from urllib import request as urlrequest

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
from argus_runtime.s3_reference_referee_service import S3_REFERENCE_REFEREE_ROUTE
from argus_runtime.s8_persistence import HttpS10VerifierKeyProvider
from scripts.run_m0_spine_battery import (
    M0_C3_VERIFIER_KEY_ID,
    M1_S3_REFERENCE_REFEREE_KEY_ID,
    _free_port,
    _git_dirty,
    _git_head,
    _m0_identity_mint_policy_json,
    _m1_reference_service_access_tokens,
    _m0_runtime_secrets,
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
        "ARGUS_M0_S3_REFERENCE_REFEREE_PORT": str(_free_port()),
    }
    env = _compose_environment(runtime_secrets=runtime_secrets, ports=ports, now=now)
    s8_url = f"http://127.0.0.1:{ports['ARGUS_M0_S8_PORT']}"
    s10_url = f"http://127.0.0.1:{ports['ARGUS_M0_S10_PORT']}"
    referee_url = f"http://127.0.0.1:{ports['ARGUS_M0_S3_REFERENCE_REFEREE_PORT']}"
    evidence: dict[str, Any] = {
        "battery": "M1 External S3 Reference Referee",
        "commit": _git_head(),
        "working_tree_dirty": _git_dirty(),
        "target": {
            "compose_file": str(Path(args.compose_file).resolve()),
            "s8_url": s8_url,
            "s10_url": s10_url,
            "s3_reference_referee_url": referee_url,
            "persistence": "postgres-minio",
            "reference_service_auth": "preprovisioned-runtime-identity-tokens",
        },
        "results": [],
    }

    try:
        _run([docker, "compose", "-f", args.compose_file, "up", "-d", "--build", "--wait"], env=env, timeout=240)
        _assert_status_ok(f"{referee_url}/healthz")
        _record(evidence, "deploy", "argus-m0 Compose started the independent S3 reference-referee service")

        s1_session = RuntimeIdentitySession.from_bootstrap(
            s10_url=s10_url,
            bootstrap_token=runtime_secrets["bootstrap_token"],
            caller_id="m1-reference-s1",
            expected_job_id="m1-reference-job",
        )
        s1_store = S10S8ArtifactStore(session=s1_session, s8_url=s8_url)
        refs = _seed_reference_pipeline(s1_store)
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
                "artifact_refs": [refs["model_ref"]],
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
        report = _required_dict(response, "validation_report_payload")
        record = s3_store.get_record(report_ref)
        persisted = _json_object(s3_store.get_artifact(report_ref))
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
        if not verification.valid:
            raise AssertionError(f"S10 KMS trust client rejected the external S3 report: {verification.reason}")
        if record.kind != "report" or record.producer.subsystem != "S3":
            raise AssertionError("external referee report did not persist as an S3 C4 report")
        if record.producer.job_id != "m1-reference-job":
            raise AssertionError("external referee report was not sealed to the M1 reference job")
        if persisted != report:
            raise AssertionError("external referee C4 payload readback differs from the signed response")
        if refs["frozen_pipeline_ref"] not in {node.artifact_ref for node in lineage.nodes}:
            raise AssertionError("external referee C4 lineage omits the frozen pipeline")
        if set(checks) != expected_checks or any(status != "PASS" for status in checks.values()):
            raise AssertionError(f"external referee did not emit the five passing reference checks: {checks}")
        if report.get("claim_tier") != "recapitulated-known" or report.get("claim_tier_is_candidate") is not False:
            raise AssertionError("external referee did not produce the expected recapitulated-known report")
        _record(
            evidence,
            "external-s3-reference-referee",
            "separate S3 service signed and broker-persisted a KMS-verifiable report over S1-seeded frozen artifacts",
            {
                "report_ref": report_ref,
                "report_producer": record.producer.subsystem,
                "report_job_id": record.producer.job_id,
                "claim_tier": report["claim_tier"],
                "checks": checks,
                "signature_key_id": report["signature"]["key_id"],
                "s1_cross_subsystem_write_denial": denied,
                "wrong_job_status": rejected.get("error"),
                "lineage_includes_frozen_pipeline": True,
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


def _compose_environment(
    *,
    runtime_secrets: Mapping[str, str],
    ports: Mapping[str, str],
    now: int,
) -> dict[str, str]:
    reference_service_tokens = _m1_reference_service_access_tokens(runtime_secrets)
    return {
        **os.environ,
        **ports,
        "ARGUS_RUNTIME_BOOTSTRAP_TOKEN": runtime_secrets["bootstrap_token"],
        "ARGUS_RUNTIME_IDENTITY_SIGNING_KEY": runtime_secrets["identity_signing_key"],
        "ARGUS_RUNTIME_IDENTITY_MINT_POLICY_JSON": _m0_identity_mint_policy_json(),
        "ARGUS_M0_HEALTH_TOKEN": runtime_secrets["health_token"],
        "ARGUS_S10_TOKEN_ED25519_PRIVATE_KEY_HEX": runtime_secrets["s10_token_ed25519_private_key_hex"],
        "ARGUS_S10_TOKEN_ED25519_PUBLIC_KEY_HEX": runtime_secrets["s10_token_ed25519_public_key_hex"],
        "ARGUS_S10_POLICY_SIGNING_KEY": runtime_secrets["s10_policy_signing_key"],
        "ARGUS_S10_CHECKPOINT_SIGNING_KEY": runtime_secrets["s10_checkpoint_signing_key"],
        "ARGUS_S10_CHECKPOINT_SIGNER_AUTH_TOKEN": runtime_secrets["s10_checkpoint_signer_auth_token"],
        "ARGUS_S10_VERIFIER_KEY_AUTH_TOKEN": runtime_secrets["s10_verifier_key_auth_token"],
        "ARGUS_S10_C3_VERIFIER_KEYS_JSON": json.dumps(
            {
                M0_C3_VERIFIER_KEY_ID: runtime_secrets["c3_verifier_signing_key"],
                M1_S3_REFERENCE_REFEREE_KEY_ID: runtime_secrets["s3_reference_referee_signing_key"],
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
        "ARGUS_S10_PRICE_TABLE_SIGNING_KEY": runtime_secrets["s10_price_table_signing_key"],
        "ARGUS_S10_PRICE_TABLE_ISSUED_AT": str(now - 60),
        "ARGUS_S10_PRICE_TABLE_EXPIRES_AT": str(now + 86_400),
        "ARGUS_S8_BROKER_WRITE_KEY": runtime_secrets["s8_broker_write_key"],
        "ARGUS_S3_REFERENCE_REFEREE_SIGNER_SECRET": runtime_secrets["s3_reference_referee_signing_key"],
        "ARGUS_S1_REFERENCE_DEMO_ACCESS_TOKEN": reference_service_tokens["m1-reference-s1"],
        "ARGUS_S3_REFERENCE_REFEREE_ACCESS_TOKEN": reference_service_tokens["m1-reference-s3"],
        "ARGUS_S7_REFERENCE_ADAPTER_ACCESS_TOKEN": reference_service_tokens["m1-reference-s7"],
        "ARGUS_S11_REFERENCE_OBSERVATORY_ACCESS_TOKEN": reference_service_tokens["m1-reference-s11"],
    }


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
        artifact_ref="c4://profile/ewpt-reference/m1-runtime",
        payload={"profile": "ewpt-reference", "checks": ["injection", "null", "physical-consistency"]},
        producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.reference-profile"),
        lineage=_lineage("argus-runtime:s1-reference-profile"),
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
        lineage=_lineage("argus-runtime:s1-reference-dataset"),
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
        lineage=_lineage("argus-runtime:s1-reference-model", input_refs=(dataset.artifact_ref,)),
    )
    frozen = store.create_artifact(
        kind="frozen_pipeline",
        payload={
            "schema": "argus.s1.frozen_pipeline.v1",
            "entrypoint": "predict",
            "model_ref": model.artifact_ref,
            "artifact_refs": [model.artifact_ref],
            "code_ref": "argus-runtime:s1-reference-freeze",
            "environment_digest": "oci:argus-s1-reference:v1",
        },
        producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.reference-physics"),
        lineage=_lineage("argus-runtime:s1-reference-freeze", input_refs=(model.artifact_ref,)),
    )
    return {
        "profile_ref": profile.artifact_ref,
        "model_ref": model.artifact_ref,
        "frozen_pipeline_ref": frozen.artifact_ref,
    }


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
) -> dict[str, Any]:
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urlrequest.Request(url, data=encoded, method="POST", headers=headers)
    try:
        with urlrequest.urlopen(request, timeout=30) as response:
            status = response.status
            body = _json_object(response.read())
    except urlerror.HTTPError as exc:
        status = exc.code
        body = _json_object(exc.read())
    if status != expected_status:
        raise AssertionError(f"{url} expected HTTP {expected_status}, received {status}: {body}")
    return body


def _get_json(url: str) -> dict[str, Any]:
    with urlrequest.urlopen(url, timeout=10) as response:
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
