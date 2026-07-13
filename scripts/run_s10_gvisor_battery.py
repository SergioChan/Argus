#!/usr/bin/env python3
"""Run S10-T06 syscall and trust-mount probes in a real gVisor sandbox."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
from typing import Any
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from argus_core import (
    BudgetCaps,
    DockerSandboxOrchestrator,
    DockerSandboxSupervisor,
    GvisorRuntimeConfig,
    InMemoryArtifactStore,
    InMemoryAuditLedger,
    InMemoryPolicyBundleTrustStore,
    InMemoryPolicyService,
    InMemoryQuotaLedger,
    InMemoryTokenService,
    LaunchEnvelope,
    LaunchRequest,
    PolicyBundle,
    PolicyBundleSigner,
    ResourceCeilings,
    ScopeGrant,
    TrustMount,
    hash_bytes,
)


REQUIRED_SYSCALLS = ("bpf", "keyctl", "kexec_load", "mount", "ptrace")
TRUST_WRITE_ERRNOS = {13, 30}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-file", required=True)
    parser.add_argument("--docker-runtime", default="runsc-argus")
    parser.add_argument(
        "--seccomp-profile",
        default=str(ROOT / "deploy/argus-m0/security/argus-gvisor-seccomp.json"),
    )
    parser.add_argument(
        "--probe-dockerfile",
        default=str(ROOT / "deploy/argus-m0/security/gvisor-probe.Dockerfile"),
    )
    args = parser.parse_args()

    if platform.system() != "Linux":
        raise RuntimeError("the real gVisor battery requires a Linux host")
    docker = shutil.which("docker")
    runsc = shutil.which("runsc")
    if docker is None or runsc is None:
        raise RuntimeError("docker and runsc are required; this battery never skips")

    runtime_inventory = _docker_runtime_inventory(docker)
    if args.docker_runtime not in runtime_inventory:
        raise RuntimeError(f"Docker runtime {args.docker_runtime!r} is unavailable")
    daemon_runtime_config = _docker_daemon_runtime_config(args.docker_runtime)
    runsc_version = _run([runsc, "--version"]).stdout.strip()
    profile_path = Path(args.seccomp_profile).resolve()
    profile_bytes = profile_path.read_bytes()
    profile_hash = hash_bytes(profile_bytes)
    _validate_profile(profile_bytes)

    image_tag = f"argus-s10-gvisor-probe:{uuid4().hex}"
    evidence_path = Path(args.evidence_file)
    evidence: dict[str, Any] = {
        "battery": "S10-T06 real gVisor security battery",
        "commit": _git_head(),
        "working_tree_dirty": _git_dirty(),
        "host": {"system": platform.system(), "machine": platform.machine()},
        "runsc_version": runsc_version,
        "docker_runtime": args.docker_runtime,
        "docker_runtime_inventory": runtime_inventory,
        "docker_daemon_runtime_config": daemon_runtime_config,
        "seccomp_profile_hash": profile_hash,
        "results": [],
    }
    try:
        _run(
            [
                docker,
                "build",
                "--pull",
                "--file",
                str(Path(args.probe_dockerfile).resolve()),
                "--tag",
                image_tag,
                str(ROOT),
            ],
            timeout=300,
        )
        image_id = _run([docker, "image", "inspect", "--format", "{{.Id}}", image_tag]).stdout.strip()
        if not image_id.startswith("sha256:") or len(image_id) != 71:
            raise RuntimeError(f"probe image is not digest-pinned: {image_id!r}")
        evidence["probe_image"] = image_id

        with tempfile.TemporaryDirectory(prefix="argus-gvisor-trust-") as temp_dir:
            verifier_dir = Path(temp_dir) / "verifier"
            ledger_dir = Path(temp_dir) / "ledger"
            verifier_dir.mkdir()
            ledger_dir.mkdir()
            verifier_file = verifier_dir / "verify.py"
            ledger_file = ledger_dir / "ledger.jsonl"
            verifier_file.write_text("VERIFIER = 'trusted'\n", encoding="utf-8")
            ledger_file.write_text('{"sequence":1,"event_hash":"trusted"}\n', encoding="utf-8")
            source_hashes_before = {
                "verifier-code": hash_bytes(verifier_file.read_bytes()),
                "provenance-ledger": hash_bytes(ledger_file.read_bytes()),
            }
            config = GvisorRuntimeConfig(
                docker_runtime=args.docker_runtime,
                seccomp_profile_path=str(profile_path),
                kubernetes_runtime_class="gvisor",
                kubernetes_seccomp_profile="argus/argus-gvisor-seccomp.json",
                trust_mounts=(
                    TrustMount(
                        name="verifier-code",
                        source=str(verifier_dir),
                        target="/opt/argus/trust/verifier",
                    ),
                    TrustMount(
                        name="provenance-ledger",
                        source=str(ledger_dir),
                        target="/opt/argus/trust/ledger",
                    ),
                ),
            )
            result, audit, artifacts, bundle = _launch_probe(
                image_id=image_id,
                config=config,
                profile_hash=profile_hash,
            )
            if result.handle.state != "SUCCEEDED" or result.exit_code != 0:
                raise AssertionError(f"gVisor probe failed: {result.handle.state=} {result.stderr=}")
            probe = json.loads(result.stdout.strip())
            _assert_syscall_denials(probe)
            _assert_trust_mount_denials(probe)
            source_hashes_after = {
                "verifier-code": hash_bytes(verifier_file.read_bytes()),
                "provenance-ledger": hash_bytes(ledger_file.read_bytes()),
            }
            if source_hashes_after != source_hashes_before:
                raise AssertionError("a read-only trust mount source changed during the probe")

            events = [event for event in audit.events() if event.payload.get("job_id") == result.handle.job_id]
            event_types = [event.event_type for event in events]
            for required_event in ("runtime.attested", "seccomp.profile_applied", "trust.mounts_applied"):
                if event_types.count(required_event) != 1:
                    raise AssertionError(f"expected exactly one {required_event} event, got {event_types}")
            runtime_event = next(event for event in events if event.event_type == "runtime.attested")
            seccomp_event = next(event for event in events if event.event_type == "seccomp.profile_applied")
            mounts_event = next(event for event in events if event.event_type == "trust.mounts_applied")
            if runtime_event.payload.get("docker_runtime") != args.docker_runtime:
                raise AssertionError("runtime attestation did not identify the configured runsc runtime")
            if runtime_event.payload.get("attestation_source") != "docker-api-inspect":
                raise AssertionError("runtime attestation was not backed by Docker API inspect")
            if seccomp_event.payload.get("profile_hash") != profile_hash:
                raise AssertionError("seccomp audit hash differs from the signed policy")
            if mounts_event.payload.get("mount_count") != 2 or not mounts_event.payload.get("all_read_only"):
                raise AssertionError("trust mount audit does not prove two read-only mounts")

            provenance_ref = result.handle.launch_provenance_ref or ""
            provenance = json.loads(artifacts.get_artifact(provenance_ref).decode("utf-8"))
            if provenance["exec_environment"]["seccomp_profile_hash"] != bundle.seccomp_profile_hash:
                raise AssertionError("launch provenance lost the signed seccomp profile hash")
            evidence["probe"] = probe
            evidence["source_hashes_before"] = source_hashes_before
            evidence["source_hashes_after"] = source_hashes_after
            evidence["audit_events"] = [
                {"event_type": event.event_type, "payload": event.payload}
                for event in events
            ]
            evidence["launch_provenance_ref"] = provenance_ref
            evidence["policy_bundle"] = {
                "bundle_version": bundle.bundle_version,
                "signer_key_id": bundle.signer_key_id,
                "signature": bundle.signature,
                "seccomp_profile_hash": bundle.seccomp_profile_hash,
                "risk_to_runtime": bundle.risk_to_runtime,
            }
            evidence["results"] = [
                {
                    "id": "S10-TC02",
                    "status": "PASS",
                    "detail": "five dangerous syscalls returned EPERM under runsc with the signed OCI seccomp profile",
                },
                {
                    "id": "S10-TC01-ro-mount-control",
                    "status": "PASS",
                    "detail": "verifier and ledger writes returned EROFS/EACCES and host source hashes stayed unchanged",
                },
                {
                    "id": "S10-T06-runtime-attestation",
                    "status": "PASS",
                    "detail": "Docker API inspect attested runsc runtime, seccomp profile, and read-only bind mounts",
                },
            ]
            evidence["passed"] = True
    except Exception as exc:
        evidence["passed"] = False
        evidence["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        subprocess.run([docker, "image", "rm", "--force", image_tag], check=False, capture_output=True, text=True)
    return 0


def _launch_probe(
    *,
    image_id: str,
    config: GvisorRuntimeConfig,
    profile_hash: str,
):
    signer_key = b"argus-s10-gvisor-policy-signing-key"
    signer_key_id = "argus-s10-gvisor-ci"
    unsigned_bundle = PolicyBundle(
        bundle_version="2.0.0",
        egress_allowlist=(),
        resource_ceilings=ResourceCeilings(
            cpu_m=1_000,
            mem_bytes=256 * 1024 * 1024,
            gpu_count=0,
            wallclock_s=30,
            max_cost_usd=1,
        ),
        risk_to_runtime={"standard": "gvisor"},
        seccomp_profile_hash=profile_hash,
        signer_key_id="",
        signature="",
    )
    bundle = PolicyBundleSigner(key_id=signer_key_id, secret=signer_key).sign(unsigned_bundle)
    audit = InMemoryAuditLedger()
    policy_service = InMemoryPolicyService(
        initial_bundle=bundle,
        trust_store=InMemoryPolicyBundleTrustStore({signer_key_id: signer_key}),
        audit_ledger=audit,
    )
    tokens = InMemoryTokenService(signing_key=b"argus-s10-gvisor-token-key")
    job_id = f"job-gvisor-{uuid4()}"
    budget = tokens.mint_budget(
        caps=BudgetCaps(max_compute_units=100, max_wallclock_s=30, max_cost_usd=1),
        job_id=job_id,
        root_request_id=f"root-{uuid4()}",
    )
    scope = tokens.mint_scope(job_id=job_id, scopes=ScopeGrant(sandbox_risk_class="standard"))
    request = LaunchRequest(
        job_id=job_id,
        subagent_id="s10-gvisor-security-probe",
        trace_id=f"trace-{uuid4()}",
        budget_token=budget,
        scope_token=scope,
        image=image_id,
        entrypoint=("python3",),
        args=("/opt/argus/gvisor_security_probe.py",),
        env={},
        env_allowlist=(),
        requested_envelope=LaunchEnvelope(
            cpu_m=500,
            mem_bytes=128 * 1024 * 1024,
            gpu_count=0,
            wallclock_s=20,
            scratch_bytes=16 * 1024 * 1024,
            pids=32,
            estimated_cost_usd=0.01,
        ),
        runtime_class_hint="gvisor",
        policy_pin=bundle.bundle_version,
    )
    artifacts = InMemoryArtifactStore()
    orchestrator = DockerSandboxOrchestrator(
        token_service=tokens,
        quota_ledger=InMemoryQuotaLedger(),
        audit_ledger=audit,
        policy_service=policy_service,
        artifact_store=artifacts,
        supervisor=DockerSandboxSupervisor(gvisor_config=config, meter_interval_s=0.2),
    )
    return orchestrator.launch_and_wait(request), audit, artifacts, bundle


def _assert_syscall_denials(probe: dict[str, Any]) -> None:
    syscalls = probe.get("syscalls")
    if not isinstance(syscalls, dict) or set(syscalls) != set(REQUIRED_SYSCALLS):
        raise AssertionError(f"probe syscall set differs from TC02: {syscalls}")
    for name in REQUIRED_SYSCALLS:
        result = syscalls[name]
        if result.get("return_code") != -1 or result.get("errno") != 1:
            raise AssertionError(f"{name} was not denied with EPERM: {result}")


def _assert_trust_mount_denials(probe: dict[str, Any]) -> None:
    mounts = probe.get("trust_mounts")
    if not isinstance(mounts, dict) or len(mounts) != 2:
        raise AssertionError(f"probe did not exercise both trust mounts: {mounts}")
    for path, result in mounts.items():
        if result.get("write_succeeded"):
            raise AssertionError(f"trust mount write unexpectedly succeeded: {path}")
        if result.get("errno") not in TRUST_WRITE_ERRNOS:
            raise AssertionError(f"trust mount write did not return EROFS/EACCES: {path}: {result}")
        if not result.get("unchanged") or result.get("before_sha256") != result.get("after_sha256"):
            raise AssertionError(f"trust mount target changed: {path}: {result}")


def _validate_profile(profile_bytes: bytes) -> None:
    profile = json.loads(profile_bytes)
    rules = profile.get("syscalls") if isinstance(profile, dict) else None
    denied = {
        name
        for rule in rules or []
        if isinstance(rule, dict) and rule.get("action") == "SCMP_ACT_ERRNO" and rule.get("errnoRet") == 1
        for name in rule.get("names", [])
    }
    if not set(REQUIRED_SYSCALLS).issubset(denied):
        raise RuntimeError(f"seccomp profile does not deny the TC02 syscall set: {sorted(denied)}")


def _docker_runtime_inventory(docker: str) -> dict[str, Any]:
    raw = _run([docker, "info", "--format", "{{json .Runtimes}}"]).stdout
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise RuntimeError("Docker runtime inventory is not a JSON object")
    return parsed


def _docker_daemon_runtime_config(runtime_name: str) -> dict[str, Any]:
    daemon_config_path = Path("/etc/docker/daemon.json")
    try:
        daemon_config = json.loads(daemon_config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("Docker daemon config is unavailable for runsc attestation") from exc
    runtimes = daemon_config.get("runtimes") if isinstance(daemon_config, dict) else None
    runtime = runtimes.get(runtime_name) if isinstance(runtimes, dict) else None
    if not isinstance(runtime, dict):
        raise RuntimeError(f"Docker daemon config has no {runtime_name!r} runtime")
    path = runtime.get("path")
    args = runtime.get("runtimeArgs")
    if not isinstance(path, str) or Path(path).name != "runsc":
        raise RuntimeError(f"Docker runtime {runtime_name!r} is not backed by runsc")
    if not isinstance(args, list) or "--oci-seccomp" not in args:
        raise RuntimeError(f"Docker runtime {runtime_name!r} does not enable --oci-seccomp")
    return {"path": path, "runtimeArgs": args}


def _run(command: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def _git_head() -> str:
    return _run(["git", "rev-parse", "HEAD"]).stdout.strip()


def _git_dirty() -> bool:
    return bool(_run(["git", "status", "--porcelain"]).stdout.strip())


if __name__ == "__main__":
    raise SystemExit(main())
