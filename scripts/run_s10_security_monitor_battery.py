#!/usr/bin/env python3
"""Run S10-T17 trust-write, escape, and clean-training cases under real gVisor."""

from __future__ import annotations

import argparse
from decimal import Decimal
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import sys
import tempfile
import time
from typing import Any, Mapping
from urllib import parse
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from argus_core import hash_bytes
from scripts import run_m0_spine_battery as m0_battery
from scripts import run_s10_gvisor_battery as gvisor_battery


TC01_JOB_ID = "s10-t17-tc01-job"
TC20_JOB_ID = "s10-t17-tc20-job"
TC21_JOB_ID = "m1-reference-job"
TRUST_TARGET = "/opt/argus/trust/verifier/verify.py"
MONITOR_ENGINE = "argus-host-security"
GVISOR_ENGINE = "gvisor-runtime-monitor"
MONITOR_URL = "http://s10-security-monitor:8765"
PROFILE_CONTAINER_PATH = "/etc/argus/s10/argus-gvisor-seccomp.json"
REQUIRED_BUILD_ARTIFACT_KINDS = frozenset(
    {
        "dataset_split",
        "feature_set",
        "hpo_selection",
        "training_log",
        "model_checkpoint",
        "uq_calibration",
        "advisory_self_check",
        "frozen_pipeline",
    }
)
SECURITY_EVENT_TYPES = frozenset(
    {
        "trustwrite.detected",
        "escape.detected",
        "security_monitor.unavailable",
        "sandbox.quarantined",
    }
)
_CONTENT_HASH = re.compile(r"blake3:[0-9a-f]{64}\Z")
_CONTAINER_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_FULL_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-file", default=str(ROOT / "deploy/argus-m0/compose.yaml"))
    parser.add_argument("--evidence-file", required=True)
    parser.add_argument("--gvisor-evidence-file", required=True)
    parser.add_argument("--docker-runtime", default="runsc-argus")
    parser.add_argument(
        "--seccomp-profile",
        default=str(ROOT / "deploy/argus-m0/security/argus-gvisor-seccomp.json"),
    )
    args = parser.parse_args()

    evidence_path = Path(args.evidence_file).resolve()
    gvisor_evidence_path = Path(args.gvisor_evidence_file).resolve()
    compose_file = str(Path(args.compose_file).resolve())
    profile_path = Path(args.seccomp_profile).resolve()
    docker = shutil.which("docker")
    runsc = shutil.which("runsc")
    evidence: dict[str, Any] = {
        "battery": "S10-T17 real host security monitor battery",
        "commit": _git_head(),
        "working_tree_dirty": _git_dirty(),
        "host": {"system": platform.system(), "machine": platform.machine()},
        "results": [],
        "passed": False,
    }
    compose_env: dict[str, str] | None = None
    try:
        if platform.system() != "Linux":
            raise RuntimeError("the S10-T17 real security battery requires Linux")
        if docker is None or runsc is None:
            raise RuntimeError("docker and runsc are required; this battery never skips")
        if evidence["working_tree_dirty"]:
            raise RuntimeError("the authoritative S10-T17 battery requires a clean checkout")
        profile_hash = hash_bytes(profile_path.read_bytes())
        daemon_runtime_config = gvisor_battery._docker_daemon_runtime_config(args.docker_runtime)
        _assert_runsc_runtime_config(daemon_runtime_config)
        evidence.update(
            {
                "runsc_version": m0_battery._run([runsc, "--version"]).stdout.strip(),
                "docker_runtime": args.docker_runtime,
                "docker_runtime_inventory": gvisor_battery._docker_runtime_inventory(docker),
                "docker_daemon_runtime_config": daemon_runtime_config,
                "seccomp_profile_hash": profile_hash,
            }
        )

        with tempfile.TemporaryDirectory(prefix="argus-s10-t17-") as temp_dir:
            temp_root = Path(temp_dir)
            verifier_dir = temp_root / "verifier"
            ledger_dir = temp_root / "ledger"
            verifier_dir.mkdir()
            ledger_dir.mkdir()
            verifier_file = verifier_dir / "verify.py"
            ledger_file = ledger_dir / "ledger.jsonl"
            verifier_file.write_text("VERIFIER = 'trusted'\n", encoding="utf-8")
            ledger_file.write_text('{"sequence":1,"event_hash":"trusted"}\n', encoding="utf-8")
            source_hashes_before = _source_hashes(verifier_file, ledger_file)
            runtime_secrets = m0_battery._m0_runtime_secrets()
            reference_tokens = m0_battery._m1_reference_service_access_tokens(runtime_secrets)
            ports = _compose_ports()
            compose_env = m0_battery._compose_environment(
                runtime_secrets=runtime_secrets,
                ports=ports,
                now=int(time.time()),
            )
            monitor_token = f"argus-s10-monitor-{uuid4().hex}"
            compose_env.update(
                {
                    "COMPOSE_PROJECT_NAME": f"argus-s10-t17-{uuid4().hex[:10]}",
                    "ARGUS_S10_DEFAULT_RUNTIME_CLASS": "gvisor",
                    "ARGUS_S10_GVISOR_RUNTIME_NAME": args.docker_runtime,
                    "ARGUS_S10_GVISOR_SECCOMP_PROFILE_PATH": PROFILE_CONTAINER_PATH,
                    "ARGUS_S10_GVISOR_TRUST_MOUNTS_JSON": json.dumps(
                        [
                            {
                                "name": "verifier-code",
                                "source": str(verifier_dir),
                                "target": "/opt/argus/trust/verifier",
                            },
                            {
                                "name": "provenance-ledger",
                                "source": str(ledger_dir),
                                "target": "/opt/argus/trust/ledger",
                            },
                        ],
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                    "ARGUS_S10_SECURITY_MONITOR_URL": MONITOR_URL,
                    "ARGUS_S10_SECURITY_MONITOR_AUTH_TOKEN": monitor_token,
                    "ARGUS_S10_ALLOW_INSECURE_SECURITY_MONITOR": "1",
                    "ARGUS_S10_SECURITY_MONITOR_TIMEOUT_S": "2.0",
                    "ARGUS_S10_METER_INTERVAL_S": "0.1",
                    "ARGUS_S10_METER_GAP_HALT_S": "2.0",
                }
            )
            s8_url = f"http://127.0.0.1:{ports['ARGUS_M0_S8_PORT']}"
            s10_url = f"http://127.0.0.1:{ports['ARGUS_M0_S10_PORT']}"
            try:
                pipeline_image = m0_battery._prepare_reference_pipeline_image(
                    docker=docker,
                    compose_file=compose_file,
                    env=compose_env,
                )
                _compose(
                    docker,
                    compose_file,
                    compose_env,
                    "build",
                    "s10-security-monitor",
                    timeout=900,
                )
                _compose(
                    docker,
                    compose_file,
                    compose_env,
                    "up",
                    "-d",
                    "--wait",
                    "s10-security-monitor",
                    timeout=240,
                    diagnostic_services=("s10-security-monitor",),
                )
                _compose(
                    docker,
                    compose_file,
                    compose_env,
                    "up",
                    "-d",
                    "--wait",
                    "s10-supervisor",
                    timeout=300,
                )
                m0_battery._wait_health(
                    f"{s8_url}/healthz",
                    token=runtime_secrets["health_token"],
                )
                m0_battery._wait_health(
                    f"{s10_url}/healthz",
                    token=runtime_secrets["health_token"],
                )
                monitor_health_before = _monitor_health(
                    docker=docker,
                    compose_file=compose_file,
                    compose_env=compose_env,
                )
                _assert_monitor_health(monitor_health_before)
                evidence["deployment"] = {
                    "compose_project": compose_env["COMPOSE_PROJECT_NAME"],
                    "compose_file": compose_file,
                    "pipeline_image": pipeline_image,
                    "s8_url": s8_url,
                    "s10_url": s10_url,
                    "monitor_health_before": monitor_health_before,
                }

                gvisor_evidence = _run_existing_gvisor_battery(
                    docker_runtime=args.docker_runtime,
                    seccomp_profile=profile_path,
                    evidence_path=gvisor_evidence_path,
                )
                evidence["gvisor_t06_evidence"] = {
                    "path": str(gvisor_evidence_path),
                    "passed": gvisor_evidence.get("passed"),
                    "commit": gvisor_evidence.get("commit"),
                    "results": gvisor_evidence.get("results"),
                }

                auth_tokens = m0_battery._mint_m0_runtime_identities(
                    s10_url=s10_url,
                    bootstrap_token=runtime_secrets["bootstrap_token"],
                )
                tc01 = _run_trust_write_case(
                    s10_url=s10_url,
                    s8_url=s8_url,
                    image=pipeline_image,
                    launch_token=auth_tokens["s10-t17-tc01"],
                    read_token=auth_tokens["read"],
                    audit_read_token=runtime_secrets["s10_audit_api_read_token"],
                    expected_profile_hash=profile_hash,
                )
                evidence["results"].append({"id": "S10-TC01", "status": "PASS", "detail": tc01})
                source_hashes_after_tc01 = _source_hashes(verifier_file, ledger_file)
                if source_hashes_after_tc01 != source_hashes_before:
                    raise AssertionError("TC01 changed an operator-owned trust source")

                tc20 = _run_escape_case(
                    s10_url=s10_url,
                    s8_url=s8_url,
                    image=pipeline_image,
                    launch_token=auth_tokens["s10-t17-tc20"],
                    read_token=auth_tokens["read"],
                    audit_read_token=runtime_secrets["s10_audit_api_read_token"],
                    expected_profile_hash=profile_hash,
                )
                evidence["results"].append({"id": "S10-TC20", "status": "PASS", "detail": tc20})

                tc21 = _run_clean_tc21_case(
                    s10_url=s10_url,
                    s8_url=s8_url,
                    image=pipeline_image,
                    launch_token=reference_tokens["m1-reference-s2"],
                    read_token=auth_tokens["read"],
                    audit_read_token=runtime_secrets["s10_audit_api_read_token"],
                    expected_profile_hash=profile_hash,
                )
                evidence["results"].append({"id": "S10-TC21", "status": "PASS", "detail": tc21})

                source_hashes_after = _source_hashes(verifier_file, ledger_file)
                if source_hashes_after != source_hashes_before:
                    raise AssertionError("a trust source changed during the S10-T17 battery")
                monitor_health_after = _monitor_health(
                    docker=docker,
                    compose_file=compose_file,
                    compose_env=compose_env,
                )
                _assert_monitor_health(monitor_health_after)
                audit_verification = m0_battery._get_json(
                    f"{s10_url}/v1/audit/verify",
                    token=runtime_secrets["s10_audit_api_read_token"],
                )
                if audit_verification.get("intact") is not True:
                    raise AssertionError(f"S10 audit chain did not verify: {audit_verification}")
                gvisor_logs = _gvisor_log_inventory(Path("/var/log/argus-runsc"))
                if gvisor_logs["container_count"] < 3 or gvisor_logs["json_log_count"] < 3:
                    raise AssertionError(f"gVisor debug audit logs are incomplete: {gvisor_logs}")
                evidence.update(
                    {
                        "source_hashes_before": source_hashes_before,
                        "source_hashes_after_tc01": source_hashes_after_tc01,
                        "source_hashes_after": source_hashes_after,
                        "monitor_health_after": monitor_health_after,
                        "audit_verification": audit_verification,
                        "gvisor_debug_logs": gvisor_logs,
                        "passed": True,
                    }
                )
            finally:
                _compose_down(docker=docker, compose_file=compose_file, compose_env=compose_env)
    except Exception as exc:
        evidence["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


def _run_trust_write_case(
    *,
    s10_url: str,
    s8_url: str,
    image: str,
    launch_token: str,
    read_token: str,
    audit_read_token: str,
    expected_profile_hash: str,
) -> dict[str, Any]:
    program = _trust_write_probe_program()
    response = _launch(
        s10_url=s10_url,
        token=launch_token,
        job_id=TC01_JOB_ID,
        image=image,
        entrypoint=("python",),
        args=("-c", program),
        wallclock_s=20,
        mem_bytes=64 * 1024 * 1024,
    )
    events = _audit_events(s10_url=s10_url, token=audit_read_token, job_id=TC01_JOB_ID)
    case = _assert_quarantined_security_case(
        response,
        events,
        event_type="trustwrite.detected",
        reason="trust_path_write",
        syscall="openat",
        expected_path=TRUST_TARGET,
    )
    provenance = _launch_provenance(
        s8_url=s8_url,
        token=read_token,
        response=response,
        expected_image=image,
        expected_profile_hash=expected_profile_hash,
    )
    spend = m0_battery._battery_spend_final(
        s8_url=s8_url,
        read_token=read_token,
        job_id=TC01_JOB_ID,
        launch_provenance_ref=provenance["artifact_ref"],
        expected_state="QUARANTINED",
    )
    return {**case, "launch_provenance": provenance, "spend_final": spend, "audit_events": events}


def _trust_write_probe_program() -> str:
    return (
        "import json,os,time;"
        f"path={TRUST_TARGET!r};"
        "result={'path':path,'write_succeeded':False};"
        "\ntry:\n fd=os.open(path,os.O_WRONLY|os.O_APPEND);os.close(fd);result['write_succeeded']=True"
        "\nexcept OSError as exc:\n result.update(errno=exc.errno,error=exc.strerror)"
        "\nprint(json.dumps(result,sort_keys=True),flush=True);time.sleep(20)"
    )


def _run_escape_case(
    *,
    s10_url: str,
    s8_url: str,
    image: str,
    launch_token: str,
    read_token: str,
    audit_read_token: str,
    expected_profile_hash: str,
) -> dict[str, Any]:
    sysno = _mount_syscall_number(platform.machine())
    program = _escape_probe_program(sysno)
    response = _launch(
        s10_url=s10_url,
        token=launch_token,
        job_id=TC20_JOB_ID,
        image=image,
        entrypoint=("python",),
        args=("-c", program),
        wallclock_s=20,
        mem_bytes=64 * 1024 * 1024,
    )
    events = _audit_events(s10_url=s10_url, token=audit_read_token, job_id=TC20_JOB_ID)
    case = _assert_quarantined_security_case(
        response,
        events,
        event_type="escape.detected",
        reason="escape_attempt",
        syscall="mount",
        expected_path=None,
    )
    provenance = _launch_provenance(
        s8_url=s8_url,
        token=read_token,
        response=response,
        expected_image=image,
        expected_profile_hash=expected_profile_hash,
    )
    spend = m0_battery._battery_spend_final(
        s8_url=s8_url,
        read_token=read_token,
        job_id=TC20_JOB_ID,
        launch_provenance_ref=provenance["artifact_ref"],
        expected_state="QUARANTINED",
    )
    return {**case, "launch_provenance": provenance, "spend_final": spend, "audit_events": events}


def _escape_probe_program(sysno: int) -> str:
    return (
        "import ctypes,json,time;"
        "libc=ctypes.CDLL(None,use_errno=True);"
        f"rc=libc.syscall({sysno},b'none',b'/tmp',b'tmpfs',0,None);"
        "print(json.dumps({'syscall':'mount','return_code':rc,'errno':ctypes.get_errno()},sort_keys=True),flush=True);"
        "time.sleep(20)"
    )


def _run_clean_tc21_case(
    *,
    s10_url: str,
    s8_url: str,
    image: str,
    launch_token: str,
    read_token: str,
    audit_read_token: str,
    expected_profile_hash: str,
) -> dict[str, Any]:
    response = _launch(
        s10_url=s10_url,
        token=launch_token,
        job_id=TC21_JOB_ID,
        image=image,
        entrypoint=("python",),
        args=(
            "-m",
            "argus_runtime.s2_isolated_training_entrypoint",
            "--container-digest",
            image,
        ),
        wallclock_s=20,
        mem_bytes=128 * 1024 * 1024,
        pids=128,
        scratch_bytes=64 * 1024 * 1024,
    )
    handle = response.get("handle") or {}
    if handle.get("state") != "SUCCEEDED" or response.get("exit_code") != 0:
        raise AssertionError(f"TC21 real S2 launch did not succeed: {response}")
    if response.get("partial_result") is not None:
        raise AssertionError(f"TC21 clean S2 launch emitted a partial result: {response}")
    if str(response.get("stderr") or ""):
        raise AssertionError(f"TC21 clean S2 launch wrote stderr: {response.get('stderr')!r}")
    output_lines = [line for line in str(response.get("stdout") or "").splitlines() if line.strip()]
    if len(output_lines) != 1 or len(output_lines[0].encode("utf-8")) >= 65_536:
        raise AssertionError("TC21 output must be one bounded JSON line")
    try:
        summary = json.loads(output_lines[0])
    except json.JSONDecodeError as exc:
        raise AssertionError("TC21 output is not valid JSON") from exc
    if not isinstance(summary, dict):
        raise AssertionError("TC21 output must be a JSON object")
    _assert_clean_tc21_summary(summary, expected_container_digest=image)
    events = _audit_events(s10_url=s10_url, token=audit_read_token, job_id=TC21_JOB_ID)
    unexpected = [event for event in events if event.get("event_type") in SECURITY_EVENT_TYPES]
    if unexpected:
        raise AssertionError(f"TC21 clean S2 emitted security events: {unexpected}")
    provenance = _launch_provenance(
        s8_url=s8_url,
        token=read_token,
        response=response,
        expected_image=image,
        expected_profile_hash=expected_profile_hash,
    )
    spend = m0_battery._battery_spend_final(
        s8_url=s8_url,
        read_token=read_token,
        job_id=TC21_JOB_ID,
        launch_provenance_ref=provenance["artifact_ref"],
        expected_state="SUCCEEDED",
    )
    if Decimal(spend["cost_usd_exact"]) > Decimal("1"):
        raise AssertionError(f"TC21 exceeded the signed S10 budget: {spend}")
    return {
        "summary": summary,
        "security_event_count": 0,
        "launch_provenance": provenance,
        "spend_final": spend,
        "audit_events": events,
    }


def _launch(
    *,
    s10_url: str,
    token: str,
    job_id: str,
    image: str,
    entrypoint: tuple[str, ...],
    args: tuple[str, ...],
    wallclock_s: int,
    mem_bytes: int,
    pids: int = 32,
    scratch_bytes: int = 8 * 1024 * 1024,
) -> dict[str, Any]:
    budget = m0_battery._post_json(
        f"{s10_url}/v1/budget-tokens",
        {},
        expected_status=201,
        token=token,
    )
    scope = m0_battery._post_json(
        f"{s10_url}/v1/scope-tokens",
        {},
        expected_status=201,
        token=token,
    )
    body = m0_battery._launch_request_json(
        job_id=job_id,
        image=image,
        budget=budget,
        scope=scope,
        args=args,
        env={},
        env_allowlist=(),
        wallclock_s=wallclock_s,
        estimated_cost_usd=0.1,
    )
    body.update(
        {
            "subagent_id": "s10-t17-security-battery",
            "entrypoint": list(entrypoint),
            "runtime_class_hint": "gvisor",
        }
    )
    body["requested_envelope"].update(
        {
            "mem_bytes": mem_bytes,
            "pids": pids,
            "scratch_bytes": scratch_bytes,
        }
    )
    return m0_battery._post_sandbox_launch(
        s10_url,
        body,
        expected_status=201,
        token=token,
        timeout=90,
    )


def _assert_quarantined_security_case(
    response: Mapping[str, Any],
    audit_events: list[dict[str, Any]],
    *,
    event_type: str,
    reason: str,
    syscall: str,
    expected_path: str | None,
) -> dict[str, Any]:
    handle = response.get("handle") or {}
    partial = response.get("partial_result") or {}
    halt = response.get("halt_telemetry") or {}
    if handle.get("state") != "QUARANTINED" or handle.get("runtime_class") != "gvisor":
        raise AssertionError(f"security case did not end in gVisor quarantine: {response}")
    if partial.get("reason") != reason:
        raise AssertionError(f"security case halted for the wrong reason: {partial}")
    for field in ("freeze_succeeded", "terminate_succeeded", "captured_after_freeze"):
        if partial.get(field) is not True:
            raise AssertionError(f"security case lacks physical {field} evidence: {partial}")
    if halt.get("reason") != reason:
        raise AssertionError(f"security halt telemetry has the wrong reason: {halt}")
    detected = _finite_non_negative(halt.get("halt_detected_elapsed_s"), "halt_detected_elapsed_s")
    freeze = _finite_non_negative(halt.get("freeze_completed_elapsed_s"), "freeze_completed_elapsed_s")
    terminate = _finite_non_negative(
        halt.get("terminate_completed_elapsed_s"),
        "terminate_completed_elapsed_s",
    )
    if freeze < detected or terminate < detected or freeze - detected > 2 or terminate - detected > 2:
        raise AssertionError(f"security halt exceeded the physical two-second bound: {halt}")

    security_events = [event for event in audit_events if event.get("event_type") == event_type]
    unavailable = [
        event for event in audit_events if event.get("event_type") == "security_monitor.unavailable"
    ]
    quarantines = [event for event in audit_events if event.get("event_type") == "sandbox.quarantined"]
    if len(security_events) != 1 or unavailable or len(quarantines) != 1:
        raise AssertionError(
            f"security case requires one event, no source loss, and one quarantine: {audit_events}"
        )
    event_payload = security_events[0].get("payload") or {}
    quarantine_payload = quarantines[0].get("payload") or {}
    sandbox_id = handle.get("sandbox_id")
    job_id = handle.get("job_id")
    if (
        event_payload.get("sandbox_id") != sandbox_id
        or event_payload.get("job_id") != job_id
        or event_payload.get("severity") != "Sev-1"
        or event_payload.get("engine") != GVISOR_ENGINE
        or event_payload.get("isolation_class") != "gvisor"
        or event_payload.get("syscall") != syscall
        or not isinstance(event_payload.get("result"), int)
        or int(event_payload["result"]) >= 0
    ):
        raise AssertionError(f"security event is not bound to the admitted gVisor sandbox: {event_payload}")
    if expected_path is not None and event_payload.get("path") != expected_path:
        raise AssertionError(f"security event reported the wrong trust path: {event_payload}")
    event_id = event_payload.get("event_id")
    if not isinstance(event_id, str) or not event_id:
        raise AssertionError(f"security event omitted event_id: {event_payload}")
    if (
        quarantine_payload.get("sandbox_id") != sandbox_id
        or quarantine_payload.get("job_id") != job_id
        or quarantine_payload.get("reason") != reason
        or quarantine_payload.get("state") != "QUARANTINED"
        or quarantine_payload.get("security_event_ids") != [event_id]
        or quarantine_payload.get("snapshot_refs") != []
        or quarantine_payload.get("forensic_snapshot_status") != "pending_s10_t18"
    ):
        raise AssertionError(f"quarantine evidence is incomplete or overclaims T18: {quarantine_payload}")
    return {
        "sandbox_id": sandbox_id,
        "security_event_id": event_id,
        "event_type": event_type,
        "reason": reason,
        "syscall": syscall,
        "event_result": event_payload["result"],
        "event_path": event_payload.get("path"),
        "partial_result": dict(partial),
        "halt_telemetry": dict(halt),
        "forensic_snapshot_status": "pending_s10_t18",
    }


def _assert_clean_tc21_summary(
    summary: Mapping[str, Any],
    *,
    expected_container_digest: str,
) -> None:
    diagnostics = summary.get("diagnostics") or {}
    if (
        summary.get("schema") != "argus.s2.isolated-training.v1"
        or summary.get("status") != "PASS"
        or diagnostics.get("status") != "SUCCEEDED"
        or diagnostics.get("s2_tc21") != "PASS"
        or summary.get("claim_tier") != "ran-toy"
    ):
        raise AssertionError(f"TC21 summary did not prove a real successful toy build: {summary}")
    if summary.get("container_digest") != expected_container_digest:
        raise AssertionError("TC21 summary is not bound to the launched image digest")
    if _CONTAINER_DIGEST.fullmatch(str(expected_container_digest)) is None:
        raise AssertionError("TC21 expected image is not a full sha256 digest")
    provenance_refs = summary.get("adapter_provenance_refs") or []
    if (
        summary.get("adapter_call_count") != 60
        or summary.get("adapter_provenance_count") != 60
        or summary.get("dataset_lineage_count") != 60
        or not isinstance(provenance_refs, list)
        or len(provenance_refs) != 60
        or len(set(provenance_refs)) != 60
    ):
        raise AssertionError("TC21 summary does not prove 60 unique S7 calls in dataset lineage")
    if int(summary.get("artifact_count") or 0) <= 8:
        raise AssertionError("TC21 summary contains too few C4 artifacts")
    if not REQUIRED_BUILD_ARTIFACT_KINDS.issubset(set(summary.get("build_artifact_kinds") or [])):
        raise AssertionError("TC21 summary omitted required S2 build artifacts")
    model_ref = summary.get("model_ref")
    uq_ref = summary.get("uq_calibration_ref")
    lineage = summary.get("frozen_pipeline_lineage") or []
    if model_ref not in lineage or uq_ref not in lineage:
        raise AssertionError("TC21 frozen pipeline lineage omitted model or UQ calibration")
    for field in ("model_content_hash", "frozen_pipeline_content_hash"):
        if _CONTENT_HASH.fullmatch(str(summary.get(field) or "")) is None:
            raise AssertionError(f"TC21 summary has an invalid {field}")
    if summary.get("self_replay") != "PASS":
        raise AssertionError("TC21 frozen pipeline self-replay did not pass")
    cost = float((summary.get("cost_actual") or {}).get("cost_usd") or 0)
    if not math.isfinite(cost) or cost <= 0:
        raise AssertionError("TC21 summary omitted a positive finite build cost")
    prediction = summary.get("prediction") or {}
    uncertainty = prediction.get("uncertainty") or {}
    value = _finite_number(prediction.get("value"), "prediction.value")
    lower = _finite_number(uncertainty.get("lower"), "prediction.uncertainty.lower")
    upper = _finite_number(uncertainty.get("upper"), "prediction.uncertainty.upper")
    if prediction.get("units") != "GeV" or uncertainty.get("kind") != "interval":
        raise AssertionError("TC21 prediction omitted GeV interval uncertainty")
    if lower > value or upper < value:
        raise AssertionError("TC21 prediction lies outside its uncertainty interval")


def _launch_provenance(
    *,
    s8_url: str,
    token: str,
    response: Mapping[str, Any],
    expected_image: str,
    expected_profile_hash: str,
) -> dict[str, Any]:
    handle = response.get("handle") or {}
    artifact_ref = handle.get("launch_provenance_ref")
    if not isinstance(artifact_ref, str) or not artifact_ref:
        raise AssertionError(f"sandbox response omitted launch provenance: {response}")
    payload = m0_battery._get_json(
        f"{s8_url}/v1/artifacts/{parse.quote(artifact_ref, safe='')}/payload",
        token=token,
    )
    environment = payload.get("exec_environment") or {}
    if (
        environment.get("image_digest") != expected_image
        or environment.get("runtime_class") != "gvisor"
        or environment.get("seccomp_profile_hash") != expected_profile_hash
        or environment.get("policy_bundle_version") != "argus-m0-dev"
        or not environment.get("seed_material")
    ):
        raise AssertionError(f"launch provenance omitted the gVisor trust boundary: {payload}")
    return {
        "artifact_ref": artifact_ref,
        "content": payload,
    }


def _audit_events(*, s10_url: str, token: str, job_id: str) -> list[dict[str, Any]]:
    payload = m0_battery._get_json(
        f"{s10_url}/v1/audit/query?{parse.urlencode({'job_id': job_id})}",
        token=token,
    )
    if not isinstance(payload, list) or any(not isinstance(event, dict) for event in payload):
        raise AssertionError(f"S10 audit query returned an invalid event list: {payload}")
    return payload


def _monitor_health(
    *,
    docker: str,
    compose_file: str,
    compose_env: dict[str, str],
) -> dict[str, Any]:
    script = (
        "import json,os,urllib.request;"
        "req=urllib.request.Request('http://s10-security-monitor:8765/healthz',"
        "headers={'Authorization':'Bearer '+os.environ['ARGUS_S10_SECURITY_MONITOR_AUTH_TOKEN']});"
        "print(json.dumps(json.load(urllib.request.urlopen(req,timeout=3)),sort_keys=True))"
    )
    return m0_battery._compose_exec_json(
        docker=docker,
        compose_file=compose_file,
        compose_env=compose_env,
        service="s10-supervisor",
        script=script,
    )


def _assert_monitor_health(health: Mapping[str, Any]) -> None:
    sources = health.get("sources") or {}
    if (
        health.get("service") != "argus-s10-security-monitor"
        or health.get("status") != "ok"
        or health.get("engine") != MONITOR_ENGINE
        or health.get("overflowed") is not False
        or set(sources) != {"falco-modern-ebpf", GVISOR_ENGINE}
    ):
        raise AssertionError(f"host security monitor is not healthy: {health}")
    for engine, source in sources.items():
        if (
            not isinstance(source, Mapping)
            or source.get("configured") is not True
            or source.get("running") is not True
            or source.get("degraded") is not False
        ):
            raise AssertionError(f"host security source {engine} is not healthy: {source}")


def _run_existing_gvisor_battery(
    *,
    docker_runtime: str,
    seccomp_profile: Path,
    evidence_path: Path,
) -> dict[str, Any]:
    m0_battery._run(
        [
            sys.executable,
            str(ROOT / "scripts/run_s10_gvisor_battery.py"),
            "--evidence-file",
            str(evidence_path),
            "--docker-runtime",
            docker_runtime,
            "--seccomp-profile",
            str(seccomp_profile),
        ],
        timeout=600,
    )
    payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("passed") is not True:
        raise AssertionError(f"existing S10-T06 gVisor battery did not pass: {payload}")
    return payload


def _assert_runsc_runtime_config(config: Mapping[str, Any]) -> None:
    args = config.get("runtimeArgs") or []
    required = {
        "--oci-seccomp",
        "--pod-init-config=/etc/argus/s10/gvisor-monitor-pod-init.json",
        "--debug",
        "--debug-command=boot",
        "--debug-log=/var/log/argus-runsc/%ID%/gvisor.%COMMAND%.json",
        "--debug-log-format=json",
    }
    if not isinstance(args, list) or not required.issubset(set(args)):
        raise RuntimeError(f"runsc runtime lacks S10-T17 monitoring flags: {config}")


def _compose_ports() -> dict[str, str]:
    return {
        "ARGUS_M0_POSTGRES_PORT": str(m0_battery._free_port()),
        "ARGUS_M0_MINIO_PORT": str(m0_battery._free_port()),
        "ARGUS_M0_MINIO_CONSOLE_PORT": str(m0_battery._free_port()),
        "ARGUS_M0_S8_PORT": str(m0_battery._free_port()),
        "ARGUS_M0_S10_PORT": str(m0_battery._free_port()),
        "ARGUS_M0_S1_DEMO_PORT": str(m0_battery._free_port()),
        "ARGUS_M0_S2_REFERENCE_BUILDER_PORT": str(m0_battery._free_port()),
        "ARGUS_M0_S3_REFERENCE_REFEREE_PORT": str(m0_battery._free_port()),
    }


def _compose(
    docker: str,
    compose_file: str,
    compose_env: dict[str, str],
    *args: str,
    timeout: int,
    diagnostic_services: tuple[str, ...] = (),
) -> None:
    command = [docker, "compose", "-f", compose_file, "--profile", "host-security", *args]
    try:
        m0_battery._run(command, env=compose_env, timeout=timeout)
    except RuntimeError as error:
        if not diagnostic_services:
            raise
        diagnostics = _compose_startup_diagnostics(
            docker=docker,
            compose_file=compose_file,
            compose_env=compose_env,
            services=diagnostic_services,
        )
        raise RuntimeError(f"{error}\n\nS10 compose startup diagnostics:\n{diagnostics}") from error


def _compose_startup_diagnostics(
    *,
    docker: str,
    compose_file: str,
    compose_env: dict[str, str],
    services: tuple[str, ...],
) -> str:
    base = [docker, "compose", "-f", compose_file, "--profile", "host-security"]
    commands = (
        ("compose ps", [*base, "ps", "--all", "--format", "json"]),
        (
            "compose logs",
            [*base, "logs", "--no-color", "--timestamps", "--tail", "200", *services],
        ),
    )
    sections: list[str] = []
    for label, command in commands:
        try:
            completed = m0_battery._run(
                command,
                env=compose_env,
                timeout=60,
                check=False,
            )
            output = "\n".join(
                part.strip()
                for part in (completed.stdout or "", completed.stderr or "")
                if part.strip()
            )
        except Exception as error:  # noqa: BLE001 - diagnostics must not hide the primary failure.
            output = f"diagnostic command failed: {type(error).__name__}: {error}"
        sections.append(f"[{label}]\n{output[:32768] or '<no output>'}")
    return "\n".join(sections)


def _compose_down(*, docker: str, compose_file: str, compose_env: dict[str, str]) -> None:
    m0_battery._run(
        [
            docker,
            "compose",
            "-f",
            compose_file,
            "--profile",
            "host-security",
            "down",
            "--volumes",
            "--remove-orphans",
        ],
        env=compose_env,
        timeout=180,
        check=False,
    )


def _source_hashes(verifier_file: Path, ledger_file: Path) -> dict[str, str]:
    return {
        "verifier-code": hash_bytes(verifier_file.read_bytes()),
        "provenance-ledger": hash_bytes(ledger_file.read_bytes()),
    }


def _gvisor_log_inventory(root: Path) -> dict[str, Any]:
    container_dirs = sorted(
        path.name for path in root.iterdir() if path.is_dir() and _FULL_CONTAINER_ID.fullmatch(path.name)
    )
    logs = sorted(
        str(path.relative_to(root))
        for container_id in container_dirs
        for path in (root / container_id).glob("*.json")
        if path.is_file()
    )
    return {
        "container_count": len(container_dirs),
        "json_log_count": len(logs),
        "container_ids": container_dirs,
        "logs": logs,
    }


def _mount_syscall_number(machine: str) -> int:
    normalized = machine.strip().lower()
    if normalized in {"x86_64", "amd64"}:
        return 165
    if normalized in {"aarch64", "arm64"}:
        return 40
    raise RuntimeError(f"unsupported architecture for TC20 mount probe: {machine!r}")


def _finite_non_negative(value: Any, field: str) -> float:
    numeric = _finite_number(value, field)
    if numeric < 0:
        raise AssertionError(f"{field} must be non-negative")
    return numeric


def _finite_number(value: Any, field: str) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise AssertionError(f"{field} must be numeric") from exc
    if not math.isfinite(numeric):
        raise AssertionError(f"{field} must be finite")
    return numeric


def _git_head() -> str:
    return m0_battery._run(["git", "rev-parse", "HEAD"]).stdout.strip()


def _git_dirty() -> bool:
    return bool(m0_battery._run(["git", "status", "--porcelain"]).stdout.strip())


if __name__ == "__main__":
    raise SystemExit(main())
