#!/usr/bin/env python3
"""Run S10-T07 federated isolation probes in a real Firecracker microVM."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
from typing import Any
from uuid import uuid4

from blake3 import blake3

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from argus_core import (
    BudgetCaps,
    DockerSandboxOrchestrator,
    DockerSandboxSupervisor,
    FirecrackerRuntimeConfig,
    FirecrackerSandboxSupervisor,
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
    hash_bytes,
)


FIRECRACKER_VERSION = "1.15.1"
KERNEL_SHA256 = "e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2"
ROOTFS_SQUASHFS_SHA256 = "68321e0482baeb3844dafe8a6b08a6902401a7afc41fbfd8c3d9ea08aadd244f"
SCRATCH_BYTES = 16 * 1024 * 1024
GUEST_UID = 65532


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-file", required=True)
    parser.add_argument("--firecracker-bin", default="/usr/local/bin/firecracker")
    parser.add_argument("--jailer-bin", default="/usr/local/bin/jailer")
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--rootfs-squashfs", required=True)
    args = parser.parse_args()

    evidence_path = Path(args.evidence_file)
    firecracker_bin = Path(args.firecracker_bin).resolve()
    jailer_bin = Path(args.jailer_bin).resolve()
    kernel_path = Path(args.kernel).resolve()
    squashfs_path = Path(args.rootfs_squashfs).resolve()
    evidence: dict[str, Any] = {
        "battery": "S10-T07 real Firecracker federated isolation battery",
        "commit": _git_head(),
        "working_tree_dirty": _git_dirty(),
        "host": {
            "system": platform.system(),
            "machine": platform.machine(),
            "kernel": platform.release(),
            "effective_uid": os.geteuid(),
            "kvm_exists": Path("/dev/kvm").exists(),
            "kvm_read_write": os.access("/dev/kvm", os.R_OK | os.W_OK),
            "cgroup_v2": Path("/sys/fs/cgroup/cgroup.controllers").is_file(),
        },
        "firecracker_release": FIRECRACKER_VERSION,
        "results": [],
    }
    try:
        _validate_host(evidence["host"])
        _assert_sha256(kernel_path, KERNEL_SHA256, "kernel")
        _assert_sha256(squashfs_path, ROOTFS_SQUASHFS_SHA256, "rootfs squashfs")
        for binary in (firecracker_bin, jailer_bin):
            if not binary.is_file() or not os.access(binary, os.X_OK):
                raise RuntimeError(f"required executable is unavailable: {binary}")
        evidence.update(
            {
                "firecracker_binary_sha256": _sha256_file(firecracker_bin),
                "jailer_binary_sha256": _sha256_file(jailer_bin),
                "kernel_sha256": _sha256_file(kernel_path),
                "rootfs_squashfs_sha256": _sha256_file(squashfs_path),
            }
        )

        with tempfile.TemporaryDirectory(prefix="argus-firecracker-battery-") as temp_dir_raw:
            temp_dir = Path(temp_dir_raw)
            rootfs_path = _build_rootfs(squashfs_path, temp_dir)
            rootfs_sha256 = _sha256_file(rootfs_path)
            rootfs_hash = _blake3_file(rootfs_path)
            kernel_hash = _blake3_file(kernel_path)
            rootfs_image_ref = f"argus.local/firecracker-rootfs@sha256:{rootfs_sha256}"
            chroot_base = temp_dir / "jailer"
            chroot_base.mkdir(mode=0o700)

            config = FirecrackerRuntimeConfig(
                expected_version=FIRECRACKER_VERSION,
                kubernetes_runtime_class="firecracker",
                firecracker_bin=str(firecracker_bin),
                jailer_bin=str(jailer_bin),
                kernel_image_path=str(kernel_path),
                kernel_image_hash=kernel_hash,
                rootfs_image_path=str(rootfs_path),
                rootfs_image_hash=rootfs_hash,
                rootfs_image_ref=rootfs_image_ref,
                chroot_base_dir=str(chroot_base),
                jailer_uid=GUEST_UID,
                jailer_gid=GUEST_UID,
            )
            result, audit, artifacts, bundle, scope = _launch_probe(config)
            if result.handle.state != "SUCCEEDED" or result.exit_code != 0:
                raise AssertionError(
                    f"Firecracker probe failed: state={result.handle.state} "
                    f"exit={result.exit_code} stderr={result.stderr!r} stdout={result.stdout!r}"
                )
            probe = _parse_probe_output(result.stdout)
            _assert_probe(probe)
            _assert_audit(audit, result.handle.job_id, result.handle.sandbox_id, config)

            provenance_ref = result.handle.launch_provenance_ref or ""
            provenance = json.loads(artifacts.get_artifact(provenance_ref).decode("utf-8"))
            exec_environment = provenance["exec_environment"]
            if exec_environment.get("runtime_class") != "firecracker":
                raise AssertionError("signed risk mapping did not select Firecracker")
            if exec_environment.get("risk_class") != "federated":
                raise AssertionError("launch provenance lost the federated trust class")
            if exec_environment.get("egress_acl") != []:
                raise AssertionError("federated launch received an egress grant")
            scope_payload = asdict(scope.scopes)
            if scope_payload != asdict(ScopeGrant(sandbox_risk_class="federated")):
                raise AssertionError(f"federated scope gained additional capabilities: {scope_payload}")

            remaining_jails = [path for path in chroot_base.rglob("*") if path.is_dir() and path.name == "root"]
            if remaining_jails:
                raise AssertionError(f"Firecracker jail cleanup left microVM roots: {remaining_jails}")
            cgroup_path = Path("/sys/fs/cgroup/argus-firecracker") / result.handle.sandbox_id
            if cgroup_path.exists():
                raise AssertionError(f"Firecracker cleanup left a microVM cgroup: {cgroup_path}")

            events = [
                {"event_type": event.event_type, "payload": event.payload}
                for event in audit.events()
                if event.payload.get("job_id") == result.handle.job_id
            ]
            evidence.update(
                {
                    "rootfs_ext4_sha256": rootfs_sha256,
                    "rootfs_ext4_blake3": rootfs_hash,
                    "kernel_blake3": kernel_hash,
                    "rootfs_image_ref": rootfs_image_ref,
                    "probe": probe,
                    "runtime_result": {
                        "sandbox_id": result.handle.sandbox_id,
                        "runtime_class": result.handle.runtime_class,
                        "state": result.handle.state,
                        "exit_code": result.exit_code,
                        "duration_s": result.duration_s,
                        "budget_usage": asdict(result.budget_usage),
                    },
                    "scope": scope_payload,
                    "policy_bundle": {
                        "bundle_version": bundle.bundle_version,
                        "signer_key_id": bundle.signer_key_id,
                        "signature": bundle.signature,
                        "risk_to_runtime": bundle.risk_to_runtime,
                    },
                    "launch_provenance_ref": provenance_ref,
                    "launch_provenance": provenance,
                    "cleanup": {
                        "jail_removed": True,
                        "cgroup_removed": True,
                    },
                    "audit_events": events,
                    "results": [
                        {
                            "id": "S10-T07-risk-routing",
                            "status": "PASS",
                            "detail": "signed PolicyBundle mapped federated risk to an attested Firecracker v1.15.1 microVM",
                        },
                        {
                            "id": "S10-TC29-firecracker-isolation",
                            "status": "PASS",
                            "detail": "real guest trust write and disallowed egress attempts failed with no trust mounts, no NIC, and no default route",
                        },
                        {
                            "id": "S10-T07-jailer-boundary",
                            "status": "PASS",
                            "detail": "same-version jailer used non-root uid/gid, PID namespace, cgroup v2, the pinned built-in seccomp filter, read-only rootfs/input, and capped scratch",
                        },
                    ],
                    "boundary": {
                        "generic_sev1_detection": "S10-T17 pending",
                        "snapshot_and_quarantine": "S10-T18 pending",
                    },
                    "passed": True,
                }
            )
    except Exception as exc:
        evidence["passed"] = False
        evidence["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


def _build_rootfs(squashfs_path: Path, temp_dir: Path) -> Path:
    extracted = temp_dir / "rootfs"
    _run(["unsquashfs", "-no-progress", "-d", str(extracted), str(squashfs_path)], timeout=180)
    init_source = ROOT / "deploy/argus-m0/security/firecracker-guest-init.sh"
    probe_source = ROOT / "deploy/argus-m0/security/firecracker-federated-probe.sh"
    init_target = extracted / "sbin/argus-init"
    probe_target = extracted / "usr/local/bin/argus-federated-probe"
    init_target.parent.mkdir(parents=True, exist_ok=True)
    probe_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(init_source, init_target)
    shutil.copyfile(probe_source, probe_target)
    init_target.chmod(0o755)
    probe_target.chmod(0o755)
    trust_probe_dir = extracted / "opt/argus/trust/verifier"
    trust_probe_dir.mkdir(parents=True, exist_ok=True)
    trust_probe_dir.chmod(0o777)
    (extracted / "mnt/argus-input").mkdir(parents=True, exist_ok=True)
    (extracted / "mnt/scratch").mkdir(parents=True, exist_ok=True)

    used_bytes = int(_run(["du", "-s", "--block-size=1", str(extracted)]).stdout.split()[0])
    allocation_unit = 64 * 1024 * 1024
    image_bytes = max(
        1024 * 1024 * 1024,
        math.ceil((used_bytes * 1.35) / allocation_unit) * allocation_unit,
    )
    rootfs_path = temp_dir / "argus-rootfs.ext4"
    with rootfs_path.open("wb") as image:
        image.truncate(image_bytes)
    _run(
        [
            "mke2fs",
            "-q",
            "-F",
            "-t",
            "ext4",
            "-m",
            "0",
            "-d",
            str(extracted),
            str(rootfs_path),
        ],
        timeout=300,
    )
    return rootfs_path


def _launch_probe(config: FirecrackerRuntimeConfig):
    signer_key = b"argus-s10-firecracker-policy-signing-key"
    signer_key_id = "argus-s10-firecracker-ci"
    seccomp_identity = hash_bytes(
        f"firecracker-v{FIRECRACKER_VERSION}-built-in-seccomp-default".encode("utf-8")
    )
    unsigned_bundle = PolicyBundle(
        bundle_version="2.1.0",
        egress_allowlist=(),
        resource_ceilings=ResourceCeilings(
            cpu_m=1_000,
            mem_bytes=256 * 1024 * 1024,
            gpu_count=0,
            wallclock_s=30,
            max_cost_usd=1,
        ),
        risk_to_runtime={"standard": "gvisor", "federated": "firecracker"},
        seccomp_profile_hash=seccomp_identity,
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
    tokens = InMemoryTokenService(signing_key=b"argus-s10-firecracker-token-key")
    job_id = f"job-firecracker-{uuid4()}"
    budget = tokens.mint_budget(
        caps=BudgetCaps(max_compute_units=100, max_wallclock_s=30, max_cost_usd=1),
        job_id=job_id,
        root_request_id=f"root-{uuid4()}",
        risk_class="federated",
    )
    scope = tokens.mint_scope(
        job_id=job_id,
        scopes=ScopeGrant(sandbox_risk_class="federated"),
    )
    request = LaunchRequest(
        job_id=job_id,
        subagent_id="s12-gold-federated-firecracker-probe",
        trace_id=f"trace-{uuid4()}",
        budget_token=budget,
        scope_token=scope,
        image=config.rootfs_image_ref,
        entrypoint=("/usr/local/bin/argus-federated-probe",),
        args=(),
        env={},
        env_allowlist=(),
        requested_envelope=LaunchEnvelope(
            cpu_m=1_000,
            mem_bytes=256 * 1024 * 1024,
            gpu_count=0,
            wallclock_s=20,
            scratch_bytes=SCRATCH_BYTES,
            pids=64,
            estimated_cost_usd=0.01,
        ),
        runtime_class_hint="auto",
        policy_pin=bundle.bundle_version,
    )
    artifacts = InMemoryArtifactStore()
    microvm_supervisor = FirecrackerSandboxSupervisor(config=config, meter_interval_s=0.2)
    orchestrator = DockerSandboxOrchestrator(
        token_service=tokens,
        quota_ledger=InMemoryQuotaLedger(),
        audit_ledger=audit,
        policy_service=policy_service,
        artifact_store=artifacts,
        supervisor=DockerSandboxSupervisor(
            firecracker_supervisor=microvm_supervisor,
            meter_interval_s=0.2,
        ),
    )
    result = orchestrator.launch_and_wait(request)
    return result, audit, artifacts, bundle, scope


def _parse_probe_output(stdout: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in stdout.splitlines():
        if line.startswith("ARGUS_TC29_") and "=" in line:
            key, value = line.split("=", 1)
            parsed[key.removeprefix("ARGUS_TC29_").lower()] = value
    return parsed


def _assert_probe(probe: dict[str, str]) -> None:
    required = {
        "status",
        "trust_write_rc",
        "trust_write_error",
        "egress_rc",
        "egress_error",
        "interfaces",
        "default_route_count",
        "trust_mount_count",
        "root_options",
        "input_options",
        "scratch_options",
        "scratch_bytes",
        "guest_uid",
    }
    if not required.issubset(probe):
        raise AssertionError(f"Firecracker probe output is incomplete: {sorted(probe)}")
    if probe["status"] != "PASS":
        raise AssertionError(f"Firecracker guest isolation probe failed: {probe}")
    if (
        int(probe["trust_write_rc"]) == 0
        or "read-only file system" not in probe["trust_write_error"].lower()
    ):
        raise AssertionError("trust-path write was not denied by the read-only rootfs")
    if int(probe["egress_rc"]) == 0 or not probe["egress_error"]:
        raise AssertionError("disallowed guest egress unexpectedly connected")
    if probe["interfaces"] != "lo" or int(probe["default_route_count"]) != 0:
        raise AssertionError("Firecracker guest received a network interface or default route")
    if int(probe["trust_mount_count"]) != 0:
        raise AssertionError("federated Firecracker guest received a trust-path mount")
    if "ro" not in probe["root_options"].split(","):
        raise AssertionError("Firecracker rootfs was not mounted read-only")
    if "ro" not in probe["input_options"].split(","):
        raise AssertionError("Firecracker request drive was not mounted read-only")
    if "rw" not in probe["scratch_options"].split(","):
        raise AssertionError("Firecracker scratch drive was not writable")
    if not 0 < int(probe["scratch_bytes"]) <= SCRATCH_BYTES:
        raise AssertionError("Firecracker scratch filesystem exceeded its backing-file byte cap")
    if int(probe["guest_uid"]) != GUEST_UID:
        raise AssertionError("Firecracker guest workload did not drop to the sandbox uid")


def _assert_audit(
    audit: InMemoryAuditLedger,
    job_id: str,
    sandbox_id: str,
    config: FirecrackerRuntimeConfig,
) -> None:
    events = [event for event in audit.events() if event.payload.get("job_id") == job_id]
    event_types = [event.event_type for event in events]
    for required_event in ("runtime.attested", "microvm.security_applied", "trust.boundary_applied"):
        if event_types.count(required_event) != 1:
            raise AssertionError(f"expected exactly one {required_event} event, got {event_types}")
    runtime = next(event.payload for event in events if event.event_type == "runtime.attested")
    security = next(event.payload for event in events if event.event_type == "microvm.security_applied")
    trust = next(event.payload for event in events if event.event_type == "trust.boundary_applied")
    if runtime.get("sandbox_id") != sandbox_id or runtime.get("runtime_class") != "firecracker":
        raise AssertionError("runtime attestation does not identify the launched Firecracker sandbox")
    if runtime.get("firecracker_version") != FIRECRACKER_VERSION:
        raise AssertionError("runtime attestation lost the pinned Firecracker version")
    if runtime.get("jailer_version") != FIRECRACKER_VERSION:
        raise AssertionError("runtime attestation lost the same-version jailer")
    expected_security = {
        "kernel_image_hash": config.kernel_image_hash,
        "rootfs_image_hash": config.rootfs_image_hash,
        "scratch_bytes": SCRATCH_BYTES,
        "network_interface_count": 0,
        "jailer_uid": GUEST_UID,
        "jailer_gid": GUEST_UID,
        "pid_namespace_init": True,
        "cgroup_v2_path": f"/argus-firecracker/{sandbox_id}",
        "seccomp_enabled": True,
        "seccomp_filter_mode": "default-built-in",
        "read_only_rootfs": True,
    }
    if any(security.get(key) != value for key, value in expected_security.items()):
        raise AssertionError(f"microVM security audit differs from the launch contract: {security}")
    if int(security.get("seccomp_filter_count", 0)) < 1:
        raise AssertionError("microVM process did not expose an active seccomp filter")
    if trust.get("trust_class") != "federated":
        raise AssertionError("federated trust class was not preserved")
    if trust.get("federated_extra_access") or trust.get("trust_mount_count") != 0:
        raise AssertionError("federated Firecracker runtime gained elevated access")


def _validate_host(host: dict[str, Any]) -> None:
    if host["system"] != "Linux" or host["machine"] != "x86_64":
        raise RuntimeError("the pinned real Firecracker battery requires Linux x86_64")
    if host["effective_uid"] != 0:
        raise RuntimeError("the real Firecracker jailer battery must run as root")
    if not host["kvm_exists"] or not host["kvm_read_write"]:
        raise RuntimeError("/dev/kvm is unavailable; the real Firecracker battery never skips")
    if not host["cgroup_v2"]:
        raise RuntimeError("the real Firecracker battery requires cgroup v2")
    for command in ("unsquashfs", "mke2fs", "du"):
        if shutil.which(command) is None:
            raise RuntimeError(f"required host command is unavailable: {command}")


def _assert_sha256(path: Path, expected: str, label: str) -> None:
    actual = _sha256_file(path)
    if actual != expected:
        raise RuntimeError(f"{label} SHA-256 mismatch: expected {expected}, got {actual}")


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _blake3_file(path: Path) -> str:
    digest = blake3()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"blake3:{digest.hexdigest()}"


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
