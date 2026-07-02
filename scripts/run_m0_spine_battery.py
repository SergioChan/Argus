#!/usr/bin/env python3
"""Run the M0 Spine Integration Slice battery against the argus-m0 compose stack."""

from __future__ import annotations

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib import error, request
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from argus_core import (
    BudgetCaps,
    BudgetExceededError,
    BudgetToken,
    DockerSandboxOrchestrator,
    EgressRule,
    FileSystemArtifactStore,
    InMemoryAuditLedger,
    InMemoryQuotaLedger,
    InMemoryTokenService,
    LaunchEnvelope,
    LaunchRequest,
    PolicyBundle,
    ResourceCeilings,
    ScopeGrant,
    ScopeToken,
)
from argus_core.s8 import LedgerReplayError
from argusverify import C3ReportSigner, InMemoryVerifierTrustStore, verify_report


DEFAULT_IMAGE = "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
SIGNING_KEY = b"argus-m0-dev-signing-key"


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
    data_tmp = tempfile.TemporaryDirectory(prefix="argus-m0-s8-")
    data_dir = Path(data_tmp.name)
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
        "ARGUS_M0_S8_DATA_DIR": str(data_dir),
    }
    s8_url = f"http://127.0.0.1:{ports['ARGUS_M0_S8_PORT']}"
    s10_url = f"http://127.0.0.1:{ports['ARGUS_M0_S10_PORT']}"
    evidence["target"] = {
        "compose_file": str(Path(args.compose_file).resolve()),
        "s8_url": s8_url,
        "s10_url": s10_url,
        "s8_data_dir": str(data_dir),
        "ports": ports,
    }

    try:
        if not args.skip_compose_up:
            _record(evidence, "deploy", "argus-m0 compose up --build --wait")
            _run([docker, "compose", "-f", args.compose_file, "up", "-d", "--build", "--wait"], env=env, timeout=240)
        _wait_health(f"{s8_url}/healthz")
        _wait_health(f"{s10_url}/healthz")
        _ensure_image(docker, args.image)

        _battery_a_contracts(evidence)
        _battery_b_incomplete_lineage(evidence, s8_url)
        _battery_c_write_once(evidence, s8_url)

        budget_json = _post_json(
            f"{s10_url}/v1/budget-tokens",
            {
                "job_id": "m0-spine-job",
                "root_request_id": "m0-spine-root",
                "caps": {"max_compute_units": 10, "max_wallclock_s": 10, "max_cost_usd": 5},
            },
            expected_status=201,
        )
        scope_json = _post_json(
            f"{s10_url}/v1/scope-tokens",
            {
                "job_id": "m0-spine-job",
                "scopes": {
                    "broker_audiences": ["store"],
                    "producer_subsystems": ["S2"],
                    "sandbox_risk_class": "standard",
                },
            },
            expected_status=201,
        )
        launch_result = _run_no_network_launch(
            image=args.image,
            budget=_budget_token_from_json(budget_json),
            scope=_scope_token_from_json(scope_json),
            data_dir=data_dir,
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
        )
        fetched = _get_json(f"{s8_url}/v1/artifacts/{model_record['artifact_ref']}/record")
        lineage = _get_json(f"{s8_url}/v1/lineage/{model_record['artifact_ref']}?direction=ancestors")
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

        _battery_e_budget_halt(evidence, s10_url, args.image, data_dir)
        _battery_g_argusverify(evidence)
        _battery_d_tamper_detected(evidence, data_dir)

        if args.evidence_file:
            Path(args.evidence_file).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        print(json.dumps(evidence, indent=2, sort_keys=True))
        return 0
    finally:
        if not args.skip_compose_up and not args.keep_stack:
            _run([docker, "compose", "-f", args.compose_file, "down", "--volumes"], env=env, timeout=120, check=False)
        data_tmp.cleanup()


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


def _battery_b_incomplete_lineage(evidence: dict[str, Any], s8_url: str) -> None:
    response = _post_json(
        f"{s8_url}/v1/artifacts",
        {
            "kind": "model",
            "payload": {"weights": [0]},
            "producer": {"subsystem": "S2", "version": "0.0.0"},
            "lineage": {"input_refs": [], "code_ref": "", "environment_digest": ""},
        },
        expected_status=400,
    )
    if response["error"] != "IncompleteLineageError":
        raise AssertionError(f"unexpected incomplete-lineage error: {response}")
    _record(evidence, "b", "incomplete lineage write rejected fail-closed", response)


def _battery_c_write_once(evidence: dict[str, Any], s8_url: str) -> None:
    body = {
        "artifact_ref": "c4://m0-spine/overwrite-guard",
        "kind": "model",
        "payload": {"weights": [1]},
        "producer": {"subsystem": "S2", "version": "0.0.0"},
        "lineage": {"input_refs": [], "code_ref": "git:model", "environment_digest": "oci:model"},
    }
    first = _post_json(f"{s8_url}/v1/artifacts", body, expected_status=201)
    second = _post_json(
        f"{s8_url}/v1/artifacts",
        {**body, "payload": {"weights": [2]}},
        expected_status=400,
    )
    if second["error"] != "WriteOnceViolationError":
        raise AssertionError(f"unexpected overwrite error: {second}")
    _record(evidence, "c", "write-once overwrite blocked", {"artifact_ref": first["artifact_ref"], "error": second})


def _battery_d_tamper_detected(evidence: dict[str, Any], data_dir: Path) -> None:
    store = FileSystemArtifactStore(data_dir)
    if not store.verify_audit_chain().valid:
        raise AssertionError("audit chain was invalid before tamper")
    ledger_path = data_dir / "artifact_ledger.jsonl"
    lines = ledger_path.read_text().splitlines()
    event = json.loads(lines[0])
    event["record"]["kind"] = "tampered"
    lines[0] = json.dumps(event, separators=(",", ":"), sort_keys=True)
    ledger_path.write_text("\n".join(lines) + "\n")
    try:
        FileSystemArtifactStore(data_dir)
    except LedgerReplayError as exc:
        _record(evidence, "d", "tampered committed ledger record detected during replay", {"error": str(exc)})
        return
    raise AssertionError("tampered ledger replay unexpectedly succeeded")


def _battery_e_budget_halt(evidence: dict[str, Any], s10_url: str, image: str, data_dir: Path) -> None:
    budget_json = _post_json(
        f"{s10_url}/v1/budget-tokens",
        {
            "job_id": "m0-budget-halt-job",
            "root_request_id": "m0-budget-halt-root",
            "caps": {"max_compute_units": 1, "max_wallclock_s": 1, "max_cost_usd": 5},
        },
        expected_status=201,
    )
    scope_json = _post_json(
        f"{s10_url}/v1/scope-tokens",
        {"job_id": "m0-budget-halt-job", "scopes": {"sandbox_risk_class": "standard"}},
        expected_status=201,
    )
    tokens = InMemoryTokenService(signing_key=SIGNING_KEY)
    quota = InMemoryQuotaLedger()
    audit = InMemoryAuditLedger()
    orchestrator = DockerSandboxOrchestrator(
        token_service=tokens,
        quota_ledger=quota,
        audit_ledger=audit,
        policy_bundle=_policy_bundle(),
        artifact_store=FileSystemArtifactStore(data_dir),
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
        events = [event.event_type for event in audit.events()]
        if "budget.halt" not in events:
            raise AssertionError("budget halt event missing")
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
    data_dir: Path,
) -> dict[str, Any]:
    tokens = InMemoryTokenService(signing_key=SIGNING_KEY)
    quota = InMemoryQuotaLedger()
    audit = InMemoryAuditLedger()
    orchestrator = DockerSandboxOrchestrator(
        token_service=tokens,
        quota_ledger=quota,
        audit_ledger=audit,
        policy_bundle=_policy_bundle(),
        artifact_store=FileSystemArtifactStore(data_dir),
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
    record = FileSystemArtifactStore(data_dir).get_record(stored_handle.launch_provenance_ref)
    payload = json.loads(FileSystemArtifactStore(data_dir).get_artifact(record.artifact_ref).decode("utf-8"))
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


def _post_json(url: str, body: dict[str, Any], *, expected_status: int) -> dict[str, Any]:
    encoded = json.dumps(body, sort_keys=True).encode("utf-8")
    req = request.Request(url, data=encoded, method="POST", headers={"Content-Type": "application/json"})
    return _open_json(req, expected_status=expected_status)


def _get_json(url: str) -> dict[str, Any]:
    return _open_json(request.Request(url, method="GET"), expected_status=200)


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


def _wait_health(url: str, *, timeout_s: int = 60) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            payload = _get_json(url)
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
