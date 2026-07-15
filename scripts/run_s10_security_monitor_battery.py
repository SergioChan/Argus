#!/usr/bin/env python3
"""Run S10-T17/T18 security, forensic quarantine, and shared-budget gVisor cases."""

from __future__ import annotations

import argparse
import base64
from decimal import Decimal
from io import BytesIO
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import sys
import tempfile
import tarfile
import threading
import time
from typing import Any, Mapping
from urllib import parse
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from argus_core import hash_bytes, hash_json
from argus_core.s10 import audit_event_hash
from scripts import run_m0_spine_battery as m0_battery
from scripts import run_s10_gvisor_battery as gvisor_battery


TC01_JOB_ID = "s10-t17-tc01-job"
TC20_JOB_ID = "s10-t17-tc20-job"
TC21_JOB_ID = "m1-reference-job"
TC22_JOB_ID = "s10-t18-tc22-job"
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
        "quarantine.open",
        "quarantine.page_delivered",
        "quarantine.page_failed",
        "quarantine.page_unconfigured",
        "quarantine.snapshot_durable",
        "quarantine.closed",
        "snapshot.captured",
        "snapshot.failed",
        "snapshot.spooled",
        "snapshot.recovered",
        "snapshot.spool_ack_failed",
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
        "battery": "S10-T17/T18 real security and forensic quarantine battery",
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

        with tempfile.TemporaryDirectory(prefix="argus-s10-t18-") as temp_dir:
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
            compose_env.update(_gvisor_trust_source_mount_environment(temp_root))
            monitor_token = f"argus-s10-monitor-{uuid4().hex}"
            compose_env.update(
                {
                    "COMPOSE_PROJECT_NAME": f"argus-s10-t18-{uuid4().hex[:10]}",
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
                    "ARGUS_S10_REFERENCE_SECURITY_PAGER_ENABLE_TEST_CONTROL": "1",
                    "ARGUS_S10_REFERENCE_SECURITY_PAGER_HOLD_DELIVERIES": "1",
                    "ARGUS_S10_SECURITY_PAGER_TIMEOUT_S": "30.0",
                }
            )
            s8_url = f"http://127.0.0.1:{ports['ARGUS_M0_S8_PORT']}"
            s10_url = f"http://127.0.0.1:{ports['ARGUS_M0_S10_PORT']}"
            pager_url = f"http://127.0.0.1:{ports['ARGUS_M0_S10_SECURITY_PAGER_PORT']}"
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
                m0_battery._wait_health(
                    f"{pager_url}/healthz",
                    token=runtime_secrets["s10_security_pager_read_token"],
                )
                s10_health = m0_battery._get_json(
                    f"{s10_url}/healthz",
                    token=runtime_secrets["health_token"],
                )
                if (
                    s10_health.get("security_monitor_configured") is not True
                    or s10_health.get("security_pager_configured") is not True
                    or s10_health.get("quarantine_review_api_configured") is not True
                    or s10_health.get("forensic_spool") != "filesystem"
                    or s10_health.get("forensic_spool_pending") != 0
                    or s10_health.get("forensic_spool_pending_ids") != []
                ):
                    raise AssertionError(f"S10 forensic deployment is incomplete: {s10_health}")
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
                    "pager_url": pager_url,
                    "monitor_health_before": monitor_health_before,
                    "s10_health": s10_health,
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
                    quarantine_review_token=runtime_secrets["s10_quarantine_review_token"],
                    pager_url=pager_url,
                    pager_read_token=runtime_secrets["s10_security_pager_read_token"],
                )
                evidence["results"].append({"id": "S10-TC01", "status": "PASS", "detail": tc01})
                evidence["results"].append(
                    {"id": "S10-TC35", "status": "PASS", "detail": tc01["tc35"]}
                )
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
                    quarantine_review_token=runtime_secrets["s10_quarantine_review_token"],
                    pager_url=pager_url,
                    pager_read_token=runtime_secrets["s10_security_pager_read_token"],
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

                tc22 = _run_shared_budget_tc22_case(
                    s10_url=s10_url,
                    s8_url=s8_url,
                    image=pipeline_image,
                    launch_token=auth_tokens["s10-t18-tc22"],
                    read_token=auth_tokens["read"],
                    audit_read_token=runtime_secrets["s10_audit_api_read_token"],
                )
                evidence["results"].append({"id": "S10-TC22", "status": "PASS", "detail": tc22})

                source_hashes_after = _source_hashes(verifier_file, ledger_file)
                if source_hashes_after != source_hashes_before:
                    raise AssertionError("a trust source changed during the S10-T17/T18 battery")
                monitor_health_after = _monitor_health(
                    docker=docker,
                    compose_file=compose_file,
                    compose_env=compose_env,
                )
                _assert_monitor_health(monitor_health_after)
                s10_health_after = m0_battery._get_json(
                    f"{s10_url}/healthz",
                    token=runtime_secrets["health_token"],
                )
                if (
                    s10_health_after.get("forensic_spool") != "filesystem"
                    or s10_health_after.get("forensic_spool_pending") != 0
                    or s10_health_after.get("forensic_spool_pending_ids") != []
                ):
                    raise AssertionError(
                        f"S10 left frozen evidence in the transient spool: {s10_health_after}"
                    )
                pager_health_after = m0_battery._get_json(
                    f"{pager_url}/healthz",
                    token=runtime_secrets["s10_security_pager_read_token"],
                )
                if pager_health_after.get("accepted_pages") != 2:
                    raise AssertionError(
                        f"Security Engineer pager did not receive both Sev-1 pages: {pager_health_after}"
                    )
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
                        "s10_health_after": s10_health_after,
                        "pager_health_after": pager_health_after,
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
    quarantine_review_token: str,
    pager_url: str,
    pager_read_token: str,
) -> dict[str, Any]:
    program = _trust_write_probe_program()
    response, pending_close = _launch_with_pending_close_probe(
        launch=lambda: _launch(
            s10_url=s10_url,
            token=launch_token,
            job_id=TC01_JOB_ID,
            image=image,
            entrypoint=("python",),
            args=("-c", program),
            wallclock_s=20,
            mem_bytes=64 * 1024 * 1024,
        ),
        s10_url=s10_url,
        pager_url=pager_url,
        pager_read_token=pager_read_token,
        quarantine_review_token=quarantine_review_token,
        expected_job_id=TC01_JOB_ID,
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
    forensic = _verify_forensic_artifacts(
        s8_url=s8_url,
        read_token=read_token,
        case=case,
        expected_image=image,
        required_event_type="trustwrite.detected",
    )
    lifecycle = _verify_page_and_close_quarantine(
        s10_url=s10_url,
        s8_url=s8_url,
        read_token=read_token,
        pager_url=pager_url,
        pager_read_token=pager_read_token,
        quarantine_review_token=quarantine_review_token,
        case=case,
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
    final_events = _audit_events(
        s10_url=s10_url,
        token=audit_read_token,
        job_id=TC01_JOB_ID,
    )
    if len([event for event in final_events if event.get("event_type") == "quarantine.closed"]) != 1:
        raise AssertionError("TC35 did not append exactly one quarantine.closed event")
    return {
        **case,
        "launch_provenance": provenance,
        "spend_final": spend,
        "forensic_artifacts": forensic,
        "quarantine_lifecycle": lifecycle,
        "tc35": {"pending_close": pending_close, "durable_close": lifecycle},
        "audit_events": final_events,
    }


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
    quarantine_review_token: str,
    pager_url: str,
    pager_read_token: str,
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
    forensic = _verify_forensic_artifacts(
        s8_url=s8_url,
        read_token=read_token,
        case=case,
        expected_image=image,
        required_event_type="escape.detected",
    )
    lifecycle = _verify_page_and_close_quarantine(
        s10_url=s10_url,
        s8_url=s8_url,
        read_token=read_token,
        pager_url=pager_url,
        pager_read_token=pager_read_token,
        quarantine_review_token=quarantine_review_token,
        case=case,
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
    return {
        **case,
        "launch_provenance": provenance,
        "spend_final": spend,
        "forensic_artifacts": forensic,
        "quarantine_lifecycle": lifecycle,
        "audit_events": _audit_events(
            s10_url=s10_url,
            token=audit_read_token,
            job_id=TC20_JOB_ID,
        ),
    }


def _escape_probe_program(sysno: int) -> str:
    return (
        "import ctypes,json,time;"
        "libc=ctypes.CDLL(None,use_errno=True);"
        f"rc=libc.syscall({sysno},b'none',b'/tmp',b'tmpfs',0,None);"
        "print(json.dumps({'syscall':'mount','return_code':rc,'errno':ctypes.get_errno()},sort_keys=True),flush=True);"
        "time.sleep(20)"
    )


def _launch_with_pending_close_probe(
    *,
    launch: Any,
    s10_url: str,
    pager_url: str,
    pager_read_token: str,
    quarantine_review_token: str,
    expected_job_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    responses: list[dict[str, Any]] = []
    errors: list[BaseException] = []

    def run_launch() -> None:
        try:
            responses.append(launch())
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=run_launch, daemon=True)
    thread.start()
    page: dict[str, Any] | None = None
    release_error: BaseException | None = None
    try:
        page = _wait_for_pager_page(
            pager_url=pager_url,
            pager_read_token=pager_read_token,
            job_id=expected_job_id,
        )
        quarantine_id = str(page["quarantine_id"])
        pending = m0_battery._get_json(
            f"{s10_url}/v1/quarantine/{parse.quote(quarantine_id, safe='')}",
            token=quarantine_review_token,
        )
        rejected = m0_battery._post_json(
            f"{s10_url}/v1/quarantine/{parse.quote(quarantine_id, safe='')}/close",
            {
                "reviewer": "security-engineer@argus.test",
                "disposition": "contained-after-forensic-review",
            },
            expected_status=409,
            token=quarantine_review_token,
        )
        if (
            pending.get("quarantine_id") != quarantine_id
            or pending.get("status") != "open"
            or pending.get("snapshot_status") != "pending"
            or pending.get("snapshot_refs") != []
            or pending.get("audit_slice_ref") is not None
            or pending.get("page_status") != "pending"
            or pending.get("forensic_spool_pending") is not True
            or re.fullmatch(
                r"forensic-spool:[0-9a-f]{64}",
                str(pending.get("forensic_spool_ref") or ""),
            )
            is None
            or rejected.get("error") != "QuarantineSnapshotPendingError"
        ):
            raise AssertionError(
                f"TC35 pending quarantine did not fail closed: pending={pending}, close={rejected}"
            )
    finally:
        try:
            m0_battery._post_json(
                f"{pager_url}/v1/test-control/release",
                {},
                expected_status=200,
                token=pager_read_token,
            )
        except BaseException as exc:
            release_error = exc
        thread.join(timeout=60)
    if thread.is_alive():
        raise TimeoutError("TC35 launch did not finish after pager delivery was released")
    if errors:
        raise errors[0]
    if release_error is not None:
        raise release_error
    if len(responses) != 1 or page is None:
        raise AssertionError("TC35 launch did not return exactly one response")
    return responses[0], {
        "quarantine_id": page["quarantine_id"],
        "pager_received": True,
        "snapshot_status": "pending",
        "snapshot_refs": [],
        "close_status": 409,
        "close_error": "QuarantineSnapshotPendingError",
        "pager_released": True,
    }


def _wait_for_pager_page(
    *,
    pager_url: str,
    pager_read_token: str,
    job_id: str,
    timeout_s: float = 10.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        pages = m0_battery._get_json(
            f"{pager_url}/v1/pages",
            token=pager_read_token,
        )
        if isinstance(pages, list):
            matching = [page for page in pages if isinstance(page, dict) and page.get("job_id") == job_id]
            if len(matching) == 1:
                return matching[0]
            if len(matching) > 1:
                raise AssertionError(f"pager received duplicate pages for {job_id}: {matching}")
        time.sleep(0.05)
    raise TimeoutError(f"pager did not receive a page for {job_id}")


def _verify_forensic_artifacts(
    *,
    s8_url: str,
    read_token: str,
    case: Mapping[str, Any],
    expected_image: str,
    required_event_type: str,
) -> dict[str, Any]:
    quarantine_id = str(case["quarantine_id"])
    job_id = str(case["job_id"] if "job_id" in case else "")
    sandbox_id = str(case["sandbox_id"])
    if not job_id:
        job_id = TC01_JOB_ID if required_event_type == "trustwrite.detected" else TC20_JOB_ID
    snapshot_refs = list(case["snapshot_refs"])
    component_summaries: list[dict[str, Any]] = []
    for component, artifact_ref in zip(
        ("rootfs", "scratch", "netlog"),
        snapshot_refs,
        strict=True,
    ):
        record, payload = _read_c4_artifact(
            s8_url=s8_url,
            read_token=read_token,
            artifact_ref=str(artifact_ref),
        )
        if (
            record.get("kind") != f"sandbox.forensic.{component}"
            or record.get("producer", {}).get("job_id") != job_id
            or record.get("lineage", {}).get("job_id") != job_id
            or payload.get("schema") != "argus.s10.forensic-snapshot.v1"
            or payload.get("component") != component
            or payload.get("quarantine_id") != quarantine_id
            or payload.get("job_id") != job_id
            or payload.get("sandbox_id") != sandbox_id
        ):
            raise AssertionError(f"forensic {component} artifact identity is invalid: {record}, {payload}")
        summary: dict[str, Any] = {
            "component": component,
            "artifact_ref": artifact_ref,
            "content_hash": record.get("content_hash"),
        }
        if component == "rootfs":
            evidence = payload.get("evidence")
            if (
                payload.get("image_digest") != expected_image
                or not isinstance(evidence, dict)
                or evidence.get("image_digest") != expected_image
                or evidence.get("read_only") is not True
                or hash_json(evidence) != payload.get("evidence_hash")
            ):
                raise AssertionError(f"rootfs evidence is not a read-only digest attestation: {payload}")
            summary["runtime"] = evidence.get("runtime")
        elif component == "scratch":
            try:
                archive = base64.b64decode(str(payload.get("archive_b64") or ""), validate=True)
                with tarfile.open(fileobj=BytesIO(archive), mode="r:*") as scratch_tar:
                    member_names = scratch_tar.getnames()
            except (ValueError, tarfile.TarError) as exc:
                raise AssertionError("scratch forensic artifact is not a readable tar archive") from exc
            if (
                not archive
                or len(archive) != payload.get("archive_bytes")
                or hash_bytes(archive) != payload.get("archive_hash")
                or payload.get("archive_format") != "application/x-tar"
                or not member_names
            ):
                raise AssertionError(f"scratch forensic bytes are incomplete: {payload}")
            summary.update({"archive_bytes": len(archive), "tar_members": member_names[:20]})
        else:
            summary.update(_verify_network_forensic_payload(payload))
        component_summaries.append(summary)

    audit_record, audit_payload = _read_c4_artifact(
        s8_url=s8_url,
        read_token=read_token,
        artifact_ref=str(case["audit_slice_ref"]),
    )
    events = audit_payload.get("events")
    if (
        audit_record.get("kind") != "sandbox.forensic.audit_slice"
        or audit_payload.get("schema") != "argus.s10.forensic-audit-slice.v1"
        or audit_payload.get("quarantine_id") != quarantine_id
        or audit_payload.get("job_id") != job_id
        or audit_payload.get("sandbox_id") != sandbox_id
        or audit_payload.get("chain_verification", {}).get("intact") is not True
        or not isinstance(events, list)
        or not events
    ):
        raise AssertionError(f"forensic audit slice is invalid: {audit_record}, {audit_payload}")
    expected_sequence = int(audit_payload["from_sequence"])
    previous_hash = str(events[0].get("previous_hash") or "")
    event_types: list[str] = []
    for event in events:
        if event.get("sequence") != expected_sequence or event.get("previous_hash") != previous_hash:
            raise AssertionError(f"forensic audit slice is not contiguous: {events}")
        expected_hash = audit_event_hash(
            expected_sequence,
            str(event.get("event_type")),
            dict(event.get("payload") or {}),
            previous_hash,
        )
        if event.get("event_hash") != expected_hash:
            raise AssertionError(f"forensic audit slice event hash mismatch: {event}")
        event_types.append(str(event["event_type"]))
        previous_hash = expected_hash
        expected_sequence += 1
    if expected_sequence - 1 != audit_payload.get("to_sequence"):
        raise AssertionError("forensic audit slice end sequence is invalid")
    required_event_types = {
        required_event_type,
        "quarantine.open",
        "snapshot.spooled",
        "quarantine.page_delivered",
    }
    if not required_event_types.issubset(event_types):
        raise AssertionError(f"forensic audit slice omitted quarantine evidence: {event_types}")

    quarantine_record, quarantine_payload = _read_c4_artifact(
        s8_url=s8_url,
        read_token=read_token,
        artifact_ref=str(case["quarantine_record_ref"]),
    )
    if (
        quarantine_record.get("kind") != "sandbox.quarantine_record"
        or quarantine_payload.get("schema") != "argus.s10.quarantine-record.v1"
        or quarantine_payload.get("quarantine_id") != quarantine_id
        or quarantine_payload.get("snapshot_status") != "durable"
        or quarantine_payload.get("status") != "open"
        or quarantine_payload.get("snapshot_refs") != snapshot_refs
        or quarantine_payload.get("audit_slice_ref") != case["audit_slice_ref"]
    ):
        raise AssertionError(f"durable quarantine C4 revision is invalid: {quarantine_payload}")
    return {
        "components": component_summaries,
        "audit_slice_ref": case["audit_slice_ref"],
        "audit_event_count": len(events),
        "audit_event_types": event_types,
        "durable_record_ref": case["quarantine_record_ref"],
    }


def _verify_network_forensic_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    network_mode = payload.get("network_mode")
    network_events = payload.get("events")
    proxy_manifest_hash = (
        network_mode.removeprefix("egress-proxy:")
        if isinstance(network_mode, str) and network_mode.startswith("egress-proxy:")
        else None
    )
    supported_mode = network_mode == "none" or (
        proxy_manifest_hash is not None and _CONTENT_HASH.fullmatch(proxy_manifest_hash) is not None
    )
    if (
        not supported_mode
        or not isinstance(network_events, list)
        or any(not isinstance(event, dict) for event in network_events)
        or (network_mode == "none" and network_events)
        or len(network_events) != payload.get("event_count")
        or hash_json(network_events) != payload.get("events_hash")
    ):
        raise AssertionError(f"network forensic evidence is invalid: {payload}")
    return {
        "network_mode": network_mode,
        "event_count": len(network_events),
        "events_hash": payload["events_hash"],
    }


def _verify_page_and_close_quarantine(
    *,
    s10_url: str,
    s8_url: str,
    read_token: str,
    pager_url: str,
    pager_read_token: str,
    quarantine_review_token: str,
    case: Mapping[str, Any],
) -> dict[str, Any]:
    quarantine_id = str(case["quarantine_id"])
    encoded_id = parse.quote(quarantine_id, safe="")
    page = m0_battery._get_json(
        f"{pager_url}/v1/pages/{encoded_id}",
        token=pager_read_token,
    )
    durable = m0_battery._get_json(
        f"{s10_url}/v1/quarantine/{encoded_id}",
        token=quarantine_review_token,
    )
    if (
        page.get("quarantine_id") != quarantine_id
        or page.get("job_id") != durable.get("job_id")
        or page.get("sandbox_id") != durable.get("sandbox_id")
        or page.get("severity") != "Sev-1"
        or page.get("reason") != durable.get("reason")
        or durable.get("status") != "open"
        or durable.get("snapshot_status") != "durable"
        or durable.get("snapshot_refs") != case["snapshot_refs"]
        or durable.get("audit_slice_ref") != case["audit_slice_ref"]
        or durable.get("page_status") != "delivered"
    ):
        raise AssertionError(f"durable quarantine review state is invalid: page={page}, state={durable}")
    close_body = {
        "reviewer": "security-engineer@argus.test",
        "disposition": "contained-after-forensic-review",
    }
    closed = m0_battery._post_json(
        f"{s10_url}/v1/quarantine/{encoded_id}/close",
        close_body,
        expected_status=200,
        token=quarantine_review_token,
    )
    repeated = m0_battery._post_json(
        f"{s10_url}/v1/quarantine/{encoded_id}/close",
        close_body,
        expected_status=200,
        token=quarantine_review_token,
    )
    fetched = m0_battery._get_json(
        f"{s10_url}/v1/quarantine/{encoded_id}",
        token=quarantine_review_token,
    )
    if (
        closed != repeated
        or fetched != closed
        or closed.get("status") != "closed"
        or closed.get("snapshot_status") != "durable"
        or closed.get("snapshot_refs") != case["snapshot_refs"]
        or closed.get("audit_slice_ref") != case["audit_slice_ref"]
        or closed.get("reviewer") != close_body["reviewer"]
        or closed.get("disposition") != close_body["disposition"]
        or not isinstance(closed.get("closed_at"), str)
        or not closed["closed_at"]
        or closed.get("record_ref") == durable.get("record_ref")
    ):
        raise AssertionError(f"quarantine close was not append-only and idempotent: {closed}")
    closed_record, closed_payload = _read_c4_artifact(
        s8_url=s8_url,
        read_token=read_token,
        artifact_ref=str(closed["record_ref"]),
    )
    if (
        closed_record.get("kind") != "sandbox.quarantine_record"
        or closed_payload.get("status") != "closed"
        or closed_payload.get("reviewer") != close_body["reviewer"]
        or closed_payload.get("disposition") != close_body["disposition"]
        or closed_payload.get("snapshot_refs") != case["snapshot_refs"]
    ):
        raise AssertionError(f"closed quarantine C4 revision is invalid: {closed_payload}")
    return {
        "quarantine_id": quarantine_id,
        "page_delivered": True,
        "snapshot_status": "durable",
        "closed": True,
        "durable_record_ref": durable["record_ref"],
        "closed_record_ref": closed["record_ref"],
        "idempotent_close": True,
    }


def _read_c4_artifact(
    *,
    s8_url: str,
    read_token: str,
    artifact_ref: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    encoded_ref = parse.quote(artifact_ref, safe="")
    record = m0_battery._get_json(
        f"{s8_url}/v1/artifacts/{encoded_ref}/record",
        token=read_token,
    )
    payload = m0_battery._get_json(
        f"{s8_url}/v1/artifacts/{encoded_ref}/payload",
        token=read_token,
    )
    if (
        record.get("artifact_ref") != artifact_ref
        or _CONTENT_HASH.fullmatch(str(record.get("content_hash"))) is None
        or hash_json(payload) != record.get("content_hash")
    ):
        raise AssertionError(f"C4 artifact did not resolve byte-identically: {record}")
    return record, payload


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
        cpu_m=500,
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


def _run_shared_budget_tc22_case(
    *,
    s10_url: str,
    s8_url: str,
    image: str,
    launch_token: str,
    read_token: str,
    audit_read_token: str,
) -> dict[str, Any]:
    generation_cap = 5
    budget = m0_battery._post_json(
        f"{s10_url}/v1/budget-tokens",
        {},
        expected_status=201,
        token=launch_token,
    )
    scope = m0_battery._post_json(
        f"{s10_url}/v1/scope-tokens",
        {},
        expected_status=201,
        token=launch_token,
    )
    caps = dict(budget.get("caps") or {})
    if (
        caps.get("max_compute_units") != 5
        or caps.get("max_wallclock_s") != 10
        or caps.get("max_cost_usd") != 1
    ):
        raise AssertionError(f"TC22 identity did not receive the bounded shared budget: {caps}")
    successful: list[dict[str, Any]] = []
    rejection: dict[str, Any] | None = None
    rejected_generation: int | None = None
    for generation in range(1, generation_cap + 1):
        body = _tc22_generation_request(
            generation=generation,
            image=image,
            budget=budget,
            scope=scope,
        )
        expected_status = 201 if generation == 1 else 403
        response = m0_battery._post_sandbox_launch(
            s10_url,
            body,
            expected_status=expected_status,
            token=launch_token,
            timeout=30,
        )
        if expected_status == 403:
            rejection = response
            rejected_generation = generation
            break
        handle = response.get("handle") or {}
        if handle.get("state") != "SUCCEEDED" or response.get("exit_code") != 0:
            raise AssertionError(f"TC22 generation {generation} did not complete: {response}")
        if response.get("quarantine") is not None or response.get("partial_result") is not None:
            raise AssertionError(f"TC22 generation {generation} emitted quarantine evidence")
        successful.append(response)
    if (
        len(successful) != 1
        or rejected_generation != 2
        or rejection is None
        or rejection.get("error") != "BudgetExceededError"
    ):
        raise AssertionError(
            f"TC22 loop did not halt deterministically at the shared budget: {successful}, {rejection}"
        )

    events = _audit_events(s10_url=s10_url, token=audit_read_token, job_id=TC22_JOB_ID)
    launched = [event for event in events if event.get("event_type") == "sandbox.launched"]
    rejects = [event for event in events if event.get("event_type") == "budget.reject"]
    spend_events = [event for event in events if event.get("event_type") == "spend.final"]
    if len(launched) != 1 or len(rejects) != 1 or len(spend_events) != 1:
        raise AssertionError(f"TC22 audit attribution is incomplete: {events}")
    reject_sequence = int(rejects[0]["sequence"])
    if any(
        event.get("event_type") == "sandbox.launched" and int(event["sequence"]) > reject_sequence
        for event in events
    ):
        raise AssertionError("TC22 admitted a sandbox after the shared budget rejection")
    unexpected_security = [
        event for event in events if event.get("event_type") in SECURITY_EVENT_TYPES
    ]
    if unexpected_security:
        raise AssertionError(f"TC22 clean generations emitted security events: {unexpected_security}")

    total_compute = 0.0
    total_wallclock = 0.0
    total_cost = Decimal("0")
    spend_refs: list[str] = []
    successful_sandbox_ids = {
        str(response["handle"]["sandbox_id"])
        for response in successful
    }
    attributed_sandbox_ids: set[str] = set()
    for event in spend_events:
        artifact_ref = str(event.get("payload", {}).get("artifact_ref") or "")
        _record, payload = _read_c4_artifact(
            s8_url=s8_url,
            read_token=read_token,
            artifact_ref=artifact_ref,
        )
        usage = payload.get("usage") or {}
        if (
            payload.get("schema") != "argus.s10.spend.final.v1"
            or payload.get("job_id") != TC22_JOB_ID
            or payload.get("budget_id") != budget.get("budget_id")
            or payload.get("final_state") != "SUCCEEDED"
        ):
            raise AssertionError(f"TC22 spend artifact is not attributed to the shared budget: {payload}")
        attributed_sandbox_ids.add(str(payload.get("sandbox_id")))
        total_compute += float(usage.get("compute_units") or 0)
        total_wallclock += float(usage.get("wallclock_s") or 0)
        total_cost += Decimal(str(payload.get("usd_rollup", {}).get("cost_usd_exact") or "0"))
        spend_refs.append(artifact_ref)
    if attributed_sandbox_ids != successful_sandbox_ids:
        raise AssertionError("TC22 generation spend attribution does not match launched sandboxes")
    if (
        total_compute > float(caps["max_compute_units"])
        or total_wallclock > float(caps["max_wallclock_s"])
        or total_cost > Decimal(str(caps["max_cost_usd"]))
    ):
        raise AssertionError(
            "TC22 cumulative spend exceeded the shared budget: "
            f"compute={total_compute}, wallclock={total_wallclock}, cost={total_cost}"
        )
    return {
        "generation_cap": generation_cap,
        "launched_generations": len(successful),
        "rejected_generation": rejected_generation,
        "termination_reason": "BUDGET",
        "budget_id": budget["budget_id"],
        "budget_caps": caps,
        "spend_final_refs": spend_refs,
        "cumulative_spend": {
            "compute_units": total_compute,
            "wallclock_s": total_wallclock,
            "cost_usd_exact": str(total_cost),
        },
        "no_sandbox_after_cap": True,
    }


def _tc22_generation_request(
    *,
    generation: int,
    image: str,
    budget: dict[str, Any],
    scope: dict[str, Any],
) -> dict[str, Any]:
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise ValueError("TC22 generation must be a positive integer")
    body = m0_battery._launch_request_json(
        job_id=TC22_JOB_ID,
        image=image,
        budget=budget,
        scope=scope,
        args=(
            "-c",
            (
                "import json,time;time.sleep(0.5);"
                f"print(json.dumps({{'generation':{generation},'status':'ok'}},sort_keys=True))"
            ),
        ),
        env={},
        env_allowlist=(),
        wallclock_s=10,
        estimated_cost_usd=0.01,
    )
    body.update(
        {
            "subagent_id": f"s10-t18-evolver-generation-{generation}",
            "entrypoint": ["python"],
            "runtime_class_hint": "gvisor",
        }
    )
    body["requested_envelope"].update(
        {
            "cpu_m": 500,
            "mem_bytes": 128 * 1024 * 1024,
            "pids": 32,
            "scratch_bytes": 1024 * 1024,
        }
    )
    return body


def _launch(
    *,
    s10_url: str,
    token: str,
    job_id: str,
    image: str,
    entrypoint: tuple[str, ...],
    args: tuple[str, ...],
    cpu_m: int = 1000,
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
            "cpu_m": cpu_m,
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
    quarantine = response.get("quarantine") or {}
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
    snapshot_refs = quarantine_payload.get("snapshot_refs")
    quarantine_id = quarantine_payload.get("quarantine_id")
    audit_slice_ref = quarantine_payload.get("audit_slice_ref")
    forensic_spool_ref = quarantine_payload.get("forensic_spool_ref")
    if (
        quarantine_payload.get("sandbox_id") != sandbox_id
        or quarantine_payload.get("job_id") != job_id
        or quarantine_payload.get("reason") != reason
        or quarantine_payload.get("state") != "QUARANTINED"
        or quarantine_payload.get("security_event_ids") != [event_id]
        or not isinstance(quarantine_id, str)
        or not quarantine_id
        or not isinstance(snapshot_refs, list)
        or len(snapshot_refs) != 3
        or any(not isinstance(ref, str) or not ref for ref in snapshot_refs)
        or len(set(snapshot_refs)) != 3
        or not isinstance(audit_slice_ref, str)
        or not audit_slice_ref
        or quarantine_payload.get("forensic_snapshot_status") != "durable"
        or quarantine_payload.get("page_status") != "delivered"
        or re.fullmatch(
            r"forensic-spool:[0-9a-f]{64}",
            str(forensic_spool_ref or ""),
        )
        is None
    ):
        raise AssertionError(f"quarantine evidence is not durable: {quarantine_payload}")
    if (
        quarantine.get("quarantine_id") != quarantine_id
        or quarantine.get("job_id") != job_id
        or quarantine.get("sandbox_id") != sandbox_id
        or quarantine.get("reason") != reason
        or quarantine.get("severity") != "Sev-1"
        or quarantine.get("snapshot_refs") != snapshot_refs
        or quarantine.get("audit_slice_ref") != audit_slice_ref
        or quarantine.get("status") != "open"
        or quarantine.get("snapshot_status") != "durable"
        or quarantine.get("page_status") != "delivered"
        or quarantine.get("forensic_spool_pending") is not False
        or quarantine.get("forensic_spool_ref") is not None
        or not isinstance(quarantine.get("record_ref"), str)
        or not quarantine["record_ref"]
    ):
        raise AssertionError(f"sandbox response omitted durable quarantine state: {quarantine}")
    return {
        "sandbox_id": sandbox_id,
        "job_id": job_id,
        "security_event_id": event_id,
        "event_type": event_type,
        "reason": reason,
        "syscall": syscall,
        "event_result": event_payload["result"],
        "event_path": event_payload.get("path"),
        "partial_result": dict(partial),
        "halt_telemetry": dict(halt),
        "quarantine_id": quarantine_id,
        "snapshot_refs": snapshot_refs,
        "audit_slice_ref": audit_slice_ref,
        "quarantine_record_ref": quarantine["record_ref"],
        "forensic_spool_ref": forensic_spool_ref,
        "page_status": "delivered",
        "forensic_snapshot_status": "durable",
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
        "ARGUS_M0_S10_SECURITY_PAGER_PORT": str(m0_battery._free_port()),
        "ARGUS_M0_S1_DEMO_PORT": str(m0_battery._free_port()),
        "ARGUS_M0_S2_REFERENCE_BUILDER_PORT": str(m0_battery._free_port()),
        "ARGUS_M0_S3_REFERENCE_REFEREE_PORT": str(m0_battery._free_port()),
    }


def _gvisor_trust_source_mount_environment(trust_root: Path) -> dict[str, str]:
    try:
        resolved_root = trust_root.resolve(strict=True)
    except FileNotFoundError as error:
        raise RuntimeError(
            f"gVisor trust source root does not exist: {trust_root}"
        ) from error
    if not resolved_root.is_dir():
        raise RuntimeError(
            f"gVisor trust source root is not a directory: {resolved_root}"
        )

    rendered_root = str(resolved_root)
    return {
        "ARGUS_S10_GVISOR_TRUST_SOURCE_ROOT": rendered_root,
        "ARGUS_S10_GVISOR_TRUST_SOURCE_ROOT_MOUNT_PATH": rendered_root,
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
