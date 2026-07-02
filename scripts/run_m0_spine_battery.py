#!/usr/bin/env python3
"""Run the M0 Spine Integration Slice battery against the argus-m0 compose stack."""

from __future__ import annotations

import argparse
from contextlib import closing
from dataclasses import asdict, replace
from hashlib import sha256
import hmac
from io import BytesIO
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
from typing import Any
from urllib import error, request
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from argus_core import (
    ArtifactRecord,
    BudgetCaps,
    BudgetExceededError,
    BudgetToken,
    DockerSandboxOrchestrator,
    EgressRule,
    InMemoryAuditLedger,
    InMemoryQuotaLedger,
    InMemoryTokenService,
    LaunchEnvelope,
    LaunchRequest,
    Lineage,
    PolicyBundle,
    Producer,
    ResourceCeilings,
    ScopeGrant,
    ScopeToken,
    canonical_json_bytes,
)
from argusverify import C3ReportSigner, InMemoryVerifierTrustStore, verify_report


DEFAULT_IMAGE = "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-file", default=str(ROOT / "deploy/argus-m0/compose.yaml"))
    parser.add_argument("--image", default=os.environ.get("ARGUS_S10_TEST_IMAGE", DEFAULT_IMAGE))
    parser.add_argument("--evidence-file")
    parser.add_argument("--keep-stack", action="store_true")
    parser.add_argument("--skip-compose-up", action="store_true")
    args = parser.parse_args()

    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("docker CLI is required for the M0 spine battery")

    evidence: dict[str, Any] = {
        "battery": "M0 Spine Integration Slice",
        "commit": _git_head(),
        "working_tree_dirty": _git_dirty(),
        "results": [],
    }
    runtime_secrets = _m0_runtime_secrets()
    ports = {
        "ARGUS_M0_POSTGRES_PORT": str(_free_port()),
        "ARGUS_M0_MINIO_PORT": str(_free_port()),
        "ARGUS_M0_MINIO_CONSOLE_PORT": str(_free_port()),
        "ARGUS_M0_S8_PORT": str(_free_port()),
        "ARGUS_M0_S10_PORT": str(_free_port()),
    }
    env = {
        **os.environ,
        **ports,
        "ARGUS_RUNTIME_BOOTSTRAP_TOKEN": runtime_secrets["bootstrap_token"],
        "ARGUS_RUNTIME_IDENTITY_SIGNING_KEY": runtime_secrets["identity_signing_key"],
        "ARGUS_RUNTIME_IDENTITY_MINT_POLICY_JSON": _m0_identity_mint_policy_json(),
        "ARGUS_S10_SIGNING_KEY": runtime_secrets["s10_signing_key"],
        "ARGUS_S8_BROKER_WRITE_KEY": runtime_secrets["s8_broker_write_key"],
    }
    s8_url = f"http://127.0.0.1:{ports['ARGUS_M0_S8_PORT']}"
    s10_url = f"http://127.0.0.1:{ports['ARGUS_M0_S10_PORT']}"
    evidence["target"] = {
        "compose_file": str(Path(args.compose_file).resolve()),
        "s8_url": s8_url,
        "s10_url": s10_url,
        "ports": ports,
        "persistence": "postgres-minio",
        "auth_callers": ["health", "write", "spine", "halt"],
    }

    try:
        if not args.skip_compose_up:
            _record(evidence, "deploy", "argus-m0 compose up --build --wait")
            _run([docker, "compose", "-f", args.compose_file, "up", "-d", "--build", "--wait"], env=env, timeout=240)
        _wait_health(f"{s8_url}/healthz", token=runtime_secrets["bootstrap_token"])
        _wait_health(f"{s10_url}/healthz", token=runtime_secrets["bootstrap_token"])
        _battery_runtime_identity_mint_policy(evidence, s10_url, bootstrap_token=runtime_secrets["bootstrap_token"])
        auth_tokens = _mint_m0_runtime_identities(s10_url=s10_url, bootstrap_token=runtime_secrets["bootstrap_token"])
        _ensure_image(docker, args.image)

        _battery_a_contracts(evidence)
        _battery_runtime_auth_required(evidence, s8_url, s10_url)
        write_scope_json = _mint_store_scope(s10_url=s10_url, token=auth_tokens["write"])
        _battery_direct_s8_write_denied(evidence, s8_url, token=auth_tokens["health"])
        _battery_forged_scope_token_denied(evidence, s10_url, write_scope_json, token=auth_tokens["write"])
        _battery_b_incomplete_lineage(evidence, s10_url, write_scope_json, token=auth_tokens["write"])
        _battery_c_write_once(evidence, s10_url, write_scope_json, token=auth_tokens["write"])

        budget_json = _post_json(
            f"{s10_url}/v1/budget-tokens",
            {},
            expected_status=201,
            token=auth_tokens["spine"],
        )
        scope_json = _post_json(
            f"{s10_url}/v1/scope-tokens",
            {},
            expected_status=201,
            token=auth_tokens["spine"],
        )
        launch_result = _run_no_network_launch(
            image=args.image,
            budget=_budget_token_from_json(budget_json),
            scope=_scope_token_from_json(scope_json),
            s8_url=s8_url,
            s8_broker_write_key=runtime_secrets["s8_broker_write_key"].encode("utf-8"),
            read_token=auth_tokens["health"],
            signing_key=runtime_secrets["s10_signing_key"].encode("utf-8"),
        )
        model_record = _post_json(
            f"{s10_url}/v1/store/artifacts",
            {
                "scope_token": scope_json,
                "kind": "model",
                "payload": {"weights": [1, 2, 3], "source": "m0-spine"},
                "producer": {"subsystem": "S2", "version": "0.0.0"},
                "lineage": {
                    "input_refs": [launch_result["launch_provenance_ref"]],
                    "code_ref": "git:m0-spine-model",
                    "environment_digest": launch_result["exec_environment_digest"],
                    "seeds": ["seed-1"],
                },
            },
            expected_status=201,
            token=auth_tokens["spine"],
        )
        fetched = _get_json(f"{s8_url}/v1/artifacts/{model_record['artifact_ref']}/record", token=auth_tokens["health"])
        lineage = _get_json(
            f"{s8_url}/v1/lineage/{model_record['artifact_ref']}?direction=ancestors",
            token=auth_tokens["health"],
        )
        ancestor_refs = {node["artifact_ref"] for node in lineage["nodes"]}
        if fetched["producer"]["job_id"] != "m0-spine-job":
            raise AssertionError("broker did not seal producer job_id")
        if launch_result["launch_provenance_ref"] not in ancestor_refs:
            raise AssertionError("model lineage did not include launch provenance")
        _record(
            evidence,
            "f",
            "real Docker launch had no default route; S10 broker wrote model C4 record; S8 read and lineage passed",
            {
                "sandbox_stdout": launch_result["stdout"],
                "launch_provenance_ref": launch_result["launch_provenance_ref"],
                "model_ref": model_record["artifact_ref"],
            },
        )

        _battery_e_budget_halt(
            evidence,
            s10_url,
            args.image,
            s8_url,
            token=auth_tokens["halt"],
            read_token=auth_tokens["health"],
            s8_broker_write_key=runtime_secrets["s8_broker_write_key"].encode("utf-8"),
            signing_key=runtime_secrets["s10_signing_key"].encode("utf-8"),
        )
        _battery_g_argusverify(evidence)
        _battery_real_persistence(evidence, ports)
        _battery_d_tamper_detected(
            evidence,
            s8_url=s8_url,
            token=auth_tokens["health"],
            minio_port=ports["ARGUS_M0_MINIO_PORT"],
            model_record=model_record,
        )

        if args.evidence_file:
            Path(args.evidence_file).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        print(json.dumps(evidence, indent=2, sort_keys=True))
        return 0
    finally:
        if not args.skip_compose_up and not args.keep_stack:
            _run([docker, "compose", "-f", args.compose_file, "down", "--volumes"], env=env, timeout=120, check=False)


def _battery_a_contracts(evidence: dict[str, Any]) -> None:
    commands = [
        [sys.executable, "scripts/validate_schemas.py"],
        [sys.executable, "scripts/schema_compatibility.py", "--check-manifest"],
        [sys.executable, "scripts/generate_bindings.py", "--check"],
        ["npm", "ci", "--prefix", "bindings/typescript"],
        ["npm", "test", "--prefix", "bindings/typescript"],
        ["cargo", "test", "--manifest-path", "bindings/rust/Cargo.toml"],
    ]
    for command in commands:
        _run(command, timeout=120)
    _record(evidence, "a", "schemas meta-validated and Python/TypeScript/Rust binding gates passed")


def _m0_runtime_secrets() -> dict[str, str]:
    return {
        "bootstrap_token": f"argus-bootstrap-{uuid4().hex}",
        "identity_signing_key": f"argus-identity-key-{uuid4().hex}",
        "s10_signing_key": f"argus-s10-key-{uuid4().hex}",
        "s8_broker_write_key": f"argus-s8-broker-key-{uuid4().hex}",
    }


def _m0_identity_requests() -> dict[str, dict[str, Any]]:
    return {
        "health": {
            "caller_id": "m0-health",
            "job_id": "m0-health",
            "root_request_id": "m0-health-root",
        },
        "write": {
            "caller_id": "m0-spine-write",
            "job_id": "m0-spine-write-tests",
            "root_request_id": "m0-spine-write-root",
            "scopes": {
                "broker_audiences": ["store"],
                "producer_subsystems": ["S2"],
                "sandbox_risk_class": "standard",
            },
        },
        "spine": {
            "caller_id": "m0-spine-launch",
            "job_id": "m0-spine-job",
            "root_request_id": "m0-spine-root",
            "budget_caps": {"max_compute_units": 10, "max_wallclock_s": 10, "max_cost_usd": 5},
            "scopes": {
                "broker_audiences": ["store"],
                "producer_subsystems": ["S2"],
                "sandbox_risk_class": "standard",
            },
        },
        "halt": {
            "caller_id": "m0-budget-halt",
            "job_id": "m0-budget-halt-job",
            "root_request_id": "m0-budget-halt-root",
            "budget_caps": {"max_compute_units": 1, "max_wallclock_s": 1, "max_cost_usd": 5},
            "scopes": {"sandbox_risk_class": "standard"},
        },
    }


def _m0_identity_mint_policy_json() -> str:
    policy: dict[str, dict[str, Any]] = {}
    for body in _m0_identity_requests().values():
        caller_id = body["caller_id"]
        policy[caller_id] = {
            "job_id": body["job_id"],
            "root_request_id": body["root_request_id"],
            "scopes": body.get("scopes", {}),
            "budget_caps": body.get("budget_caps", {}),
            "max_ttl_s": 900,
        }
    return json.dumps(policy, separators=(",", ":"), sort_keys=True)


def _battery_runtime_identity_mint_policy(evidence: dict[str, Any], s10_url: str, *, bootstrap_token: str) -> None:
    override = _post_json(
        f"{s10_url}/v1/runtime-identities",
        {"caller_id": "m0-spine-launch", "job_id": "attacker-selected-job"},
        expected_status=403,
        token=bootstrap_token,
    )
    unknown = _post_json(
        f"{s10_url}/v1/runtime-identities",
        {"caller_id": "unknown-launcher"},
        expected_status=403,
        token=bootstrap_token,
    )
    ttl = _post_json(
        f"{s10_url}/v1/runtime-identities",
        {"caller_id": "m0-spine-launch", "ttl_s": 901},
        expected_status=403,
        token=bootstrap_token,
    )
    if override["error"] != "IdentityOverrideError":
        raise AssertionError(f"unexpected runtime identity override error: {override}")
    if unknown["error"] != "PermissionError" or ttl["error"] != "PermissionError":
        raise AssertionError(f"unexpected runtime identity policy errors: unknown={unknown}, ttl={ttl}")
    _record(
        evidence,
        "identity-policy",
        "bootstrap runtime identity mint is constrained by server-side caller policy",
        {
            "override": override["error"],
            "unknown_caller": unknown["error"],
            "ttl_ceiling": ttl["error"],
        },
    )


def _mint_m0_runtime_identities(*, s10_url: str, bootstrap_token: str) -> dict[str, str]:
    minted: dict[str, str] = {}
    for name, body in _m0_identity_requests().items():
        response = _post_json(
            f"{s10_url}/v1/runtime-identities",
            {"caller_id": body["caller_id"], "ttl_s": 900},
            expected_status=201,
            token=bootstrap_token,
        )
        minted[name] = response["access_token"]
    return minted


def _battery_runtime_auth_required(evidence: dict[str, Any], s8_url: str, s10_url: str) -> None:
    s8_health = _get_json(f"{s8_url}/healthz", expected_status=401)
    s10_scope = _post_json(f"{s10_url}/v1/scope-tokens", {}, expected_status=401)
    if s8_health["error"] != "Unauthorized" or s10_scope["error"] != "Unauthorized":
        raise AssertionError(f"unexpected auth denial payloads: {s8_health}, {s10_scope}")
    _record(
        evidence,
        "auth",
        "runtime HTTP routes require bearer authentication before health or token mint",
        {"s8_health": s8_health["error"], "s10_scope": s10_scope["error"]},
    )


def _battery_forged_scope_token_denied(
    evidence: dict[str, Any],
    s10_url: str,
    scope_json: dict[str, Any],
    *,
    token: str,
) -> None:
    forged_scope = {**scope_json, "signature": "hmac-sha256:" + "0" * 64}
    response = _post_json(
        f"{s10_url}/v1/store/artifacts",
        {
            "scope_token": forged_scope,
            "kind": "model",
            "payload": {"weights": [8]},
            "producer": {"subsystem": "S2", "version": "0.0.0"},
            "lineage": {"input_refs": [], "code_ref": "git:model", "environment_digest": "oci:model"},
        },
        expected_status=401,
        token=token,
    )
    if response["error"] != "TokenInvalidError":
        raise AssertionError(f"unexpected forged-token denial error: {response}")
    _record(evidence, "scope-forged", "brokered write with forged scope token rejected fail-closed", response)


def _mint_store_scope(*, s10_url: str, token: str) -> dict[str, Any]:
    return _post_json(
        f"{s10_url}/v1/scope-tokens",
        {},
        expected_status=201,
        token=token,
    )


def _battery_direct_s8_write_denied(evidence: dict[str, Any], s8_url: str, *, token: str) -> None:
    response = _post_json(
        f"{s8_url}/v1/artifacts",
        {
            "kind": "model",
            "payload": {"weights": [9]},
            "producer": {"subsystem": "S2", "version": "0.0.0"},
            "lineage": {"input_refs": [], "code_ref": "git:model", "environment_digest": "oci:model"},
        },
        expected_status=403,
        token=token,
    )
    if response["error"] != "DirectWriteDenied":
        raise AssertionError(f"unexpected direct-write denial error: {response}")
    _record(evidence, "f-direct", "direct S8 HTTP artifact write denied", response)


def _battery_b_incomplete_lineage(
    evidence: dict[str, Any],
    s10_url: str,
    scope_json: dict[str, Any],
    *,
    token: str,
) -> None:
    response = _post_json(
        f"{s10_url}/v1/store/artifacts",
        {
            "scope_token": scope_json,
            "kind": "model",
            "payload": {"weights": [0]},
            "producer": {"subsystem": "S2", "version": "0.0.0"},
            "lineage": {"input_refs": [], "code_ref": "", "environment_digest": ""},
        },
        expected_status=400,
        token=token,
    )
    if response["error"] != "IncompleteLineageError":
        raise AssertionError(f"unexpected incomplete-lineage error: {response}")
    _record(evidence, "b", "brokered incomplete lineage write rejected fail-closed", response)


def _battery_c_write_once(
    evidence: dict[str, Any],
    s10_url: str,
    scope_json: dict[str, Any],
    *,
    token: str,
) -> None:
    body = {
        "scope_token": scope_json,
        "artifact_ref": "c4://m0-spine/overwrite-guard",
        "kind": "model",
        "payload": {"weights": [1]},
        "producer": {"subsystem": "S2", "version": "0.0.0"},
        "lineage": {"input_refs": [], "code_ref": "git:model", "environment_digest": "oci:model"},
    }
    first = _post_json(f"{s10_url}/v1/store/artifacts", body, expected_status=201, token=token)
    second = _post_json(
        f"{s10_url}/v1/store/artifacts",
        {**body, "payload": {"weights": [2]}},
        expected_status=400,
        token=token,
    )
    if second["error"] != "WriteOnceViolationError":
        raise AssertionError(f"unexpected overwrite error: {second}")
    _record(
        evidence,
        "c",
        "brokered write-once overwrite blocked",
        {"artifact_ref": first["artifact_ref"], "error": second},
    )


class S8InternalArtifactStoreClient:
    def __init__(
        self,
        *,
        s8_url: str,
        broker_write_key: bytes,
        scope_job_id: str,
        producer_subsystems: tuple[str, ...],
    ) -> None:
        self._s8_url = s8_url.rstrip("/")
        self._broker_write_key = broker_write_key
        self._scope_job_id = scope_job_id
        self._producer_subsystems = producer_subsystems

    def create_artifact(
        self,
        *,
        kind: str,
        payload: Any,
        producer: Producer,
        lineage: Lineage,
        artifact_ref: str | None = None,
        claim_tier: str = "ran-toy",
        validation_report_ref: str | None = None,
    ) -> ArtifactRecord:
        sealed_producer = replace(producer, job_id=producer.job_id or self._scope_job_id)
        sealed_lineage = replace(lineage, job_id=lineage.job_id or self._scope_job_id)
        body = {
            "authorization": {
                "audience": "store",
                "scope_job_id": self._scope_job_id,
                "producer_subsystems": list(self._producer_subsystems),
            },
            "kind": kind,
            "payload": payload,
            "producer": asdict(sealed_producer),
            "lineage": asdict(sealed_lineage),
            "artifact_ref": artifact_ref,
            "claim_tier": claim_tier,
            "validation_report_ref": validation_report_ref,
        }
        response = _post_json(
            f"{self._s8_url}/v1/internal/brokered-artifacts",
            body,
            expected_status=201,
            headers=_broker_write_headers(body, self._broker_write_key),
        )
        return _artifact_record_from_json(response)


def _battery_real_persistence(evidence: dict[str, Any], ports: dict[str, str]) -> None:
    import psycopg
    from minio import Minio

    dsn = f"postgresql://argus:argus-dev-password@127.0.0.1:{ports['ARGUS_M0_POSTGRES_PORT']}/argus"
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM s8.schema_migration;")
            migration_count = int(cur.fetchone()[0])
            cur.execute("SELECT count(*) FROM s8.artifact_record;")
            record_count = int(cur.fetchone()[0])
            cur.execute("SELECT count(*) FROM s8.ledger_leaf;")
            leaf_count = int(cur.fetchone()[0])
            update_denied = _postgres_append_only_update_denied(cur)
    minio = Minio(
        f"127.0.0.1:{ports['ARGUS_M0_MINIO_PORT']}",
        access_key="argus",
        secret_key="argus-dev-password",
        secure=False,
    )
    object_count = sum(1 for _ in minio.list_objects("argus-s8-objects", recursive=True))
    if migration_count < 1 or record_count < 2 or leaf_count < 2 or object_count < 2 or not update_denied:
        raise AssertionError(
            "Postgres/MinIO persistence did not record expected deployed S8 artifacts: "
            f"migrations={migration_count} records={record_count} leaves={leaf_count} "
            f"objects={object_count} update_denied={update_denied}"
        )
    _record(
        evidence,
        "persist",
        "deployed S8 wrote C4 metadata to Postgres append-only ledger and payloads to MinIO",
        {
            "schema_migrations": migration_count,
            "artifact_records": record_count,
            "ledger_leaves": leaf_count,
            "minio_objects": object_count,
            "append_only_update_denied": update_denied,
        },
    )


def _postgres_append_only_update_denied(cur: Any) -> bool:
    try:
        cur.execute(
            """
            UPDATE s8.artifact_record
            SET kind = 'tampered'
            WHERE artifact_id = (
                SELECT artifact_id FROM s8.artifact_record ORDER BY merkle_seq LIMIT 1
            );
            """
        )
    except Exception as exc:
        message = str(exc)
        cur.connection.rollback()
        return "append-only table artifact_record" in message
    cur.connection.rollback()
    return False


def _battery_d_tamper_detected(
    evidence: dict[str, Any],
    *,
    s8_url: str,
    token: str,
    minio_port: str,
    model_record: dict[str, Any],
) -> None:
    from minio import Minio

    payload_url = f"{s8_url}/v1/artifacts/{model_record['artifact_ref']}/payload"
    _get_json(payload_url, token=token)
    minio = Minio(
        f"127.0.0.1:{minio_port}",
        access_key="argus",
        secret_key="argus-dev-password",
        secure=False,
    )
    key = _minio_object_key(minio, "argus-s8-objects", model_record["content_hash"])
    tampered = b'{"tampered":true}'
    minio.put_object("argus-s8-objects", key, BytesIO(tampered), length=len(tampered), content_type="application/json")
    response = _get_json(payload_url, token=token, expected_status=404)
    if response["error"] != "HashMismatchError":
        raise AssertionError(f"unexpected tamper detection payload: {response}")
    _record(
        evidence,
        "d",
        "tampered MinIO object bytes detected by S8 verify-on-read",
        {"error": response["error"], "artifact_ref": model_record["artifact_ref"]},
    )


def _minio_object_key(minio: Any, bucket: str, content_hash: str) -> str:
    object_name = content_hash.removeprefix("blake3:") if content_hash.startswith("blake3:") else content_hash.replace(":", "_")
    for item in minio.list_objects(bucket, recursive=True):
        if item.object_name and item.object_name.endswith("/" + object_name):
            return item.object_name
    raise KeyError(content_hash)


def _battery_e_budget_halt(
    evidence: dict[str, Any],
    s10_url: str,
    image: str,
    s8_url: str,
    *,
    token: str,
    read_token: str,
    s8_broker_write_key: bytes,
    signing_key: bytes,
) -> None:
    budget_json = _post_json(
        f"{s10_url}/v1/budget-tokens",
        {},
        expected_status=201,
        token=token,
    )
    scope_json = _post_json(
        f"{s10_url}/v1/scope-tokens",
        {},
        expected_status=201,
        token=token,
    )
    tokens = InMemoryTokenService(signing_key=signing_key)
    quota = InMemoryQuotaLedger()
    audit = InMemoryAuditLedger()
    orchestrator = DockerSandboxOrchestrator(
        token_service=tokens,
        quota_ledger=quota,
        audit_ledger=audit,
        policy_bundle=_policy_bundle(),
        artifact_store=S8InternalArtifactStoreClient(
            s8_url=s8_url,
            broker_write_key=s8_broker_write_key,
            scope_job_id="m0-budget-halt-job",
            producer_subsystems=("S10",),
        ),
    )
    request_obj = LaunchRequest(
        job_id="m0-budget-halt-job",
        subagent_id="m0-subagent",
        trace_id=f"trace-{uuid4()}",
        budget_token=_budget_token_from_json(budget_json),
        scope_token=_scope_token_from_json(scope_json),
        image=image,
        entrypoint=("sh",),
        args=("-c", "sleep 2"),
        env={},
        env_allowlist=(),
        requested_envelope=LaunchEnvelope(
            cpu_m=1000,
            mem_bytes=32 * 1024 * 1024,
            gpu_count=0,
            wallclock_s=1,
            scratch_bytes=1024 * 1024,
            pids=16,
            estimated_cost_usd=0,
        ),
    )
    try:
        orchestrator.launch_and_wait(request_obj)
    except BudgetExceededError:
        if request_obj.job_id != "m0-budget-halt-job":
            raise AssertionError("budget halt request job changed")
        events = [event.event_type for event in audit.events()]
        if "budget.halt" not in events:
            raise AssertionError("budget halt event missing")
        handle = next(iter(orchestrator._handles.values()))
        if handle.launch_provenance_ref is None:
            raise AssertionError("budget halt launch provenance missing")
        _get_json(f"{s8_url}/v1/artifacts/{handle.launch_provenance_ref}/record", token=read_token)
        _record(evidence, "e", "sandbox ran past budget and was halted with audit evidence", {"events": events})
        return
    raise AssertionError("budget halt launch unexpectedly completed without BudgetExceededError")


def _battery_g_argusverify(evidence: dict[str, Any]) -> None:
    trust_store = InMemoryVerifierTrustStore()
    trust_store.register_key("m0-verifier", b"m0-verifier-secret")
    report = {
        "report_id": "vr-m0-spine",
        "claim_tier": "validated",
        "aggregate": {"passed": True},
        "checks": [{"id": "stub", "passed": True}],
    }
    signed = C3ReportSigner(key_id="m0-verifier", secret=b"m0-verifier-secret").sign(report)
    valid = verify_report(signed, trust_store)
    tampered = json.loads(json.dumps(signed))
    tampered["aggregate"]["passed"] = False
    invalid = verify_report(tampered, trust_store)
    if not valid.valid or invalid.valid:
        raise AssertionError("argusverify signature validation/tamper rejection failed")
    _record(
        evidence,
        "g",
        "argusverify accepted signed report and rejected tampered signature",
        {"valid_key_id": valid.key_id, "tampered_reason": invalid.reason},
    )


def _run_no_network_launch(
    *,
    image: str,
    budget: BudgetToken,
    scope: ScopeToken,
    s8_url: str,
    s8_broker_write_key: bytes,
    read_token: str,
    signing_key: bytes,
) -> dict[str, Any]:
    tokens = InMemoryTokenService(signing_key=signing_key)
    quota = InMemoryQuotaLedger()
    audit = InMemoryAuditLedger()
    orchestrator = DockerSandboxOrchestrator(
        token_service=tokens,
        quota_ledger=quota,
        audit_ledger=audit,
        policy_bundle=_policy_bundle(),
        artifact_store=S8InternalArtifactStoreClient(
            s8_url=s8_url,
            broker_write_key=s8_broker_write_key,
            scope_job_id="m0-spine-job",
            producer_subsystems=("S10",),
        ),
    )
    launch = LaunchRequest(
        job_id="m0-spine-job",
        subagent_id="m0-subagent",
        trace_id=f"trace-{uuid4()}",
        budget_token=budget,
        scope_token=scope,
        image=image,
        entrypoint=("sh",),
        args=(
            "-c",
            "cat /proc/net/route; "
            "if grep -qE '^[^[:space:]]+[[:space:]]+00000000[[:space:]]' /proc/net/route; "
            "then echo default-route-found; exit 42; fi; "
            "echo no-default-route; echo ARGUS_UID=$(id -u)",
        ),
        env={"VISIBLE": "ok", "HIDDEN": "no"},
        env_allowlist=("VISIBLE",),
        requested_envelope=LaunchEnvelope(
            cpu_m=1000,
            mem_bytes=32 * 1024 * 1024,
            gpu_count=0,
            wallclock_s=5,
            scratch_bytes=1024 * 1024,
            pids=16,
            estimated_cost_usd=0,
        ),
    )
    result = orchestrator.launch_and_wait(launch)
    final_handle = result.handle
    stored_handle = orchestrator.get(result.handle.sandbox_id)
    if result.exit_code != 0 or "no-default-route" not in result.stdout or "HIDDEN" in result.stdout:
        raise AssertionError(f"no-network sandbox launch failed: exit={result.exit_code} stdout={result.stdout!r}")
    if stored_handle.launch_provenance_ref is None:
        raise AssertionError("launch provenance ref missing")
    payload = _get_json(f"{s8_url}/v1/artifacts/{stored_handle.launch_provenance_ref}/payload", token=read_token)
    return {
        "stdout": result.stdout,
        "launch_provenance_ref": stored_handle.launch_provenance_ref,
        "exec_environment_digest": payload["exec_environment_digest"],
        "audit_events": [event.event_type for event in audit.events()],
        "state": stored_handle.state,
        "runtime_class": final_handle.runtime_class,
    }


def _policy_bundle() -> PolicyBundle:
    return PolicyBundle(
        bundle_version="argus-m0-battery",
        egress_allowlist=(),
        resource_ceilings=ResourceCeilings(
            cpu_m=1000,
            mem_bytes=64 * 1024 * 1024,
            gpu_count=0,
            wallclock_s=10,
            max_cost_usd=5,
        ),
        risk_to_runtime={"standard": "docker"},
        seccomp_profile_hash="blake3:" + "0" * 64,
        signer_key_id="argus-m0-battery",
        signature="battery-policy-signature",
    )


def _budget_token_from_json(value: dict[str, Any]) -> BudgetToken:
    return BudgetToken(
        budget_id=value["budget_id"],
        job_id=value["job_id"],
        root_request_id=value["root_request_id"],
        budget_epoch=int(value["budget_epoch"]),
        caps=BudgetCaps(**dict(value["caps"])),
        risk_class=value["risk_class"],
        issued_at=int(value["issued_at"]),
        expires_at=int(value["expires_at"]),
        ttl_s=int(value["ttl_s"]),
        parent_budget_id=value.get("parent_budget_id"),
        signer_key_id=value["signer_key_id"],
        signature=value["signature"],
    )


def _scope_token_from_json(value: dict[str, Any]) -> ScopeToken:
    scopes = dict(value["scopes"])
    return ScopeToken(
        scope_id=value["scope_id"],
        job_id=value["job_id"],
        scopes=ScopeGrant(
            allowed_adapters=tuple(scopes.get("allowed_adapters") or ()),
            allowed_datasets=tuple(scopes.get("allowed_datasets") or ()),
            egress_allowlist=tuple(EgressRule(**rule) for rule in scopes.get("egress_allowlist") or ()),
            broker_audiences=tuple(scopes.get("broker_audiences") or ()),
            producer_subsystems=tuple(scopes.get("producer_subsystems") or ()),
            sandbox_risk_class=scopes.get("sandbox_risk_class", "standard"),
            disallowed_actions=tuple(scopes.get("disallowed_actions") or ()),
        ),
        issued_at=int(value["issued_at"]),
        expires_at=int(value["expires_at"]),
        ttl_s=int(value["ttl_s"]),
        parent_scope_id=value.get("parent_scope_id"),
        signer_key_id=value["signer_key_id"],
        signature=value["signature"],
    )


def _post_json(
    url: str,
    body: dict[str, Any],
    *,
    expected_status: int,
    token: str | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    encoded = json.dumps(body, sort_keys=True).encode("utf-8")
    request_headers = {"Content-Type": "application/json", **_auth_headers(token), **(headers or {})}
    req = request.Request(url, data=encoded, method="POST", headers=request_headers)
    return _open_json(req, expected_status=expected_status)


def _get_json(url: str, *, token: str | None = None, expected_status: int = 200) -> dict[str, Any]:
    return _open_json(request.Request(url, method="GET", headers=_auth_headers(token)), expected_status=expected_status)


def _auth_headers(token: str | None) -> dict[str, str]:
    if token is None:
        return {}
    return {"Authorization": f"Bearer {token}"}


def _broker_write_headers(body: dict[str, Any], broker_write_key: bytes) -> dict[str, str]:
    digest = hmac.new(broker_write_key, canonical_json_bytes(body), sha256).hexdigest()
    return {"X-Argus-Store-Write-Signature": f"hmac-sha256:{digest}"}


def _artifact_record_from_json(value: dict[str, Any]) -> ArtifactRecord:
    producer = Producer(**dict(value["producer"]))
    lineage_body = dict(value["lineage"])
    lineage_body["input_refs"] = tuple(lineage_body.get("input_refs") or ())
    lineage_body["seeds"] = tuple(lineage_body.get("seeds") or ())
    lineage = Lineage(**lineage_body)
    return ArtifactRecord(
        artifact_ref=value["artifact_ref"],
        kind=value["kind"],
        content_hash=value["content_hash"],
        size_bytes=int(value["size_bytes"]),
        producer=producer,
        lineage=lineage,
        claim_tier=value.get("claim_tier", "ran-toy"),
        validation_report_ref=value.get("validation_report_ref"),
        created_at=value.get("created_at", ""),
    )


def _open_json(req: request.Request, *, expected_status: int) -> dict[str, Any]:
    try:
        with request.urlopen(req, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
            status = response.status
    except error.HTTPError as exc:
        payload = json.loads(exc.read().decode("utf-8"))
        status = exc.code
    if status != expected_status:
        raise AssertionError(f"{req.full_url} returned {status}, expected {expected_status}: {payload}")
    return payload


def _wait_health(url: str, *, token: str, timeout_s: int = 60) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            payload = _get_json(url, token=token)
            if payload.get("status") == "ok":
                return
        except Exception:
            time.sleep(1)
    raise TimeoutError(f"health check did not pass: {url}")


def _ensure_image(docker: str, image: str) -> None:
    inspected = subprocess.run([docker, "image", "inspect", image], capture_output=True, text=True)
    if inspected.returncode == 0:
        return
    _run([docker, "pull", image], timeout=120)


def _run(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 60,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        timeout=timeout,
        check=False,
        capture_output=True,
        text=True,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            "command failed: "
            + " ".join(command)
            + f"\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def _record(evidence: dict[str, Any], item_id: str, summary: str, detail: Any | None = None) -> None:
    entry: dict[str, Any] = {"item": item_id, "status": "pass", "summary": summary}
    if detail is not None:
        entry["detail"] = detail
    evidence["results"].append(entry)


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _git_head() -> str:
    completed = _run(["git", "rev-parse", "HEAD"], timeout=10)
    return completed.stdout.strip()


def _git_dirty() -> bool:
    completed = _run(["git", "status", "--porcelain"], timeout=10)
    return bool(completed.stdout.strip())


if __name__ == "__main__":
    raise SystemExit(main())
