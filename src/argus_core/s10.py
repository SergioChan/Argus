"""S10 token, quota, policy, and sandbox launch semantics."""

from __future__ import annotations

import http.client as http_client
import hmac
import ipaddress
import inspect
import json
import math
import os
import re
import selectors
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field, replace
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Iterable, Literal, Mapping, NoReturn, Protocol
from uuid import uuid4
from weakref import ref

from blake3 import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from argusverify import canonical_c3_json_bytes

from .canonical import canonical_json_bytes
from .c3 import C3_SIGNATURE_PREFIX, SIGNATURE_VERIFICATION_ACCEPTED, VerifierKey
from .hashing import BLAKE3_PREFIX, hash_bytes, hash_json
from .s8 import ArtifactRecord, InMemoryArtifactStore, Lineage, Producer


SIGNATURE_PREFIX = "hmac-sha256:"
TOKEN_ED25519_SIGNATURE_PREFIX = "ed25519:"
DOCKER_SANDBOX_USER = "65532:65532"
PARTIAL_RESULT_LOG_CAPTURE_LIMIT_BYTES = 64 * 1024
DEFAULT_EXFIL_SOFT_BYTES = 64 * 1024 * 1024
DEFAULT_EXFIL_HARD_BYTES = 128 * 1024 * 1024
SECRET_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"(?i)(password|secret|api[_-]?key|token)=?[A-Za-z0-9_./+=:-]{8,}"),
)
DIGEST_PINNED_IMAGE = re.compile(r"^(?:[^\s@]+@)?sha256:[0-9a-f]{64}$")
RuntimeClass = Literal["auto", "gvisor", "firecracker", "docker"]
RiskClass = Literal["standard", "federated", "high"]
EgressProto = Literal["https", "grpc", "tcp"]
SandboxState = Literal[
    "ADMITTED",
    "RUNNING",
    "SUCCEEDED",
    "FAILED",
    "TIMED_OUT",
    "FROZEN",
    "TERMINATED",
    "QUARANTINED",
]


class S10Error(Exception):
    """Base class for S10 semantic failures."""


class TokenInvalidError(S10Error):
    """Raised when a signed token cannot be trusted."""


class TokenMintUnavailableError(S10Error):
    """Raised when minting is unavailable and must fail closed."""


class ScopeWideningError(S10Error):
    """Raised when attenuation attempts to widen a capability."""


class ScopeDeniedError(S10Error):
    """Raised when a brokered action is outside the granted scope."""


class BudgetExceededError(S10Error):
    """Raised when reservation or consumption would exceed caps."""


class PolicyDeniedError(S10Error):
    """Raised when policy or admission denies a sandbox launch."""


class PolicyBundleSignatureError(S10Error):
    """Raised when a policy bundle signature cannot be trusted."""


class EgressProxyManifestError(S10Error):
    """Raised when a materialized egress sidecar manifest is invalid or has drifted."""


class PriceTableSignatureError(S10Error):
    """Raised when a signed price table cannot be trusted."""


class SandboxRuntimeUnavailableError(S10Error):
    """Raised when the configured sandbox runtime cannot be invoked."""


@dataclass(frozen=True)
class BudgetCaps:
    max_compute_units: float = 0.0
    max_gpu_seconds: float = 0.0
    max_model_tokens: float = 0.0
    max_wallclock_s: float = 0.0
    max_cost_usd: float = 0.0


@dataclass(frozen=True)
class BudgetUsage:
    compute_units: float = 0.0
    gpu_seconds: float = 0.0
    model_tokens: float = 0.0
    wallclock_s: float = 0.0
    cost_usd: float = 0.0


@dataclass(frozen=True)
class GpuTelemetrySnapshot:
    dcgm_available: bool = False
    nvidia_smi_available: bool = False
    gpu_count: int = 0
    gpu_models: tuple[str, ...] = ()
    mig_enabled: bool = False
    mig_instance_count: int = 0
    source: str = "unavailable"
    error: str = ""


@dataclass(frozen=True)
class DcgmMetricRow:
    entity: str
    entity_id: str
    gr_engine_active: float | None = None
    tensor_active: float | None = None
    dram_active: float | None = None


@dataclass(frozen=True)
class DcgmMetricSnapshot:
    available: bool = False
    source: str = "unavailable"
    rows: tuple[DcgmMetricRow, ...] = ()
    error: str = ""

    @property
    def row_count(self) -> int:
        return len(self.rows)

    @staticmethod
    def _max_metric(rows: tuple[DcgmMetricRow, ...], field_name: str) -> float:
        values = [float(value) for row in rows if (value := getattr(row, field_name)) is not None]
        return max(values, default=0.0)

    @property
    def max_gr_engine_active(self) -> float:
        return self._max_metric(self.rows, "gr_engine_active")

    @property
    def max_tensor_active(self) -> float:
        return self._max_metric(self.rows, "tensor_active")

    @property
    def max_dram_active(self) -> float:
        return self._max_metric(self.rows, "dram_active")


@dataclass(frozen=True)
class ResourceMeterSample:
    sample_seq: int
    elapsed_s: float
    cadence_s: float
    usage: BudgetUsage
    memory_bytes: int = 0
    source: str = "docker-api-cgroup"
    dcgm_available: bool = False
    nvidia_smi_available: bool = False
    gpu_count: int = 0
    gpu_models: tuple[str, ...] = ()
    mig_enabled: bool = False
    mig_instance_count: int = 0
    gpu_telemetry_source: str = "unavailable"
    gpu_telemetry_error: str = ""
    dcgm_metrics_available: bool = False
    dcgm_metric_source: str = "unavailable"
    dcgm_metric_error: str = ""
    dcgm_metric_rows: tuple[DcgmMetricRow, ...] = ()
    dcgm_gr_engine_active: float = 0.0
    dcgm_tensor_active: float = 0.0
    dcgm_dram_active: float = 0.0
    breached_dimensions: tuple[str, ...] = ()
    halted: bool = False
    conservative_gap_s: float = 0.0


@dataclass(frozen=True)
class PriceTable:
    price_table_version: str
    usd_per_cpu_second: str
    usd_per_gpu_second: Mapping[str, str] = field(default_factory=dict)
    usd_per_1k_model_tokens: Mapping[str, str] = field(default_factory=dict)
    issued_at: int = 0
    expires_at: int = 0
    signer_key_id: str = ""
    signature: str = ""


@dataclass(frozen=True)
class PriceTableRollup:
    usage: BudgetUsage
    cost_usd_exact: str
    price_table_hash: str
    price_table_version: str
    signer_key_id: str
    gpu_model: str
    model_id: str


class PriceTableSigner:
    kind = "hmac-sha256"

    def __init__(self, *, signer_key_id: str, signing_key: bytes) -> None:
        if not signer_key_id:
            raise ValueError("price table signer_key_id is required")
        if not signing_key:
            raise ValueError("price table signing key is required")
        self.signer_key_id = signer_key_id
        self._signing_key = bytes(signing_key)

    def sign(self, table: PriceTable) -> PriceTable:
        unsigned = replace(table, signer_key_id=self.signer_key_id, signature="")
        return replace(unsigned, signature=_price_table_signature(unsigned, self._signing_key))

    def trust_store(self, *, now_fn: Callable[[], int] | None = None) -> "PriceTableTrustStore":
        return PriceTableTrustStore({self.signer_key_id: self._signing_key}, now_fn=now_fn)


class PriceTableTrustStore:
    kind = "hmac-sha256"

    def __init__(self, keys: Mapping[str, bytes], *, now_fn: Callable[[], int] | None = None) -> None:
        self._keys = {key_id: bytes(secret) for key_id, secret in keys.items()}
        self._now_fn = now_fn or (lambda: int(time.time()))

    def verify(self, table: PriceTable) -> None:
        if not table.signature.startswith(SIGNATURE_PREFIX):
            raise PriceTableSignatureError("price table signature is missing or unsupported")
        key = self._keys.get(table.signer_key_id)
        if key is None:
            raise PriceTableSignatureError("unknown price table signer")
        if table.expires_at <= self._now_fn():
            raise PriceTableSignatureError("price table is stale")
        expected = _price_table_signature(replace(table, signature=""), key)
        if not hmac.compare_digest(table.signature, expected):
            raise PriceTableSignatureError("price table signature invalid")


@dataclass(frozen=True)
class EgressRule:
    host: str
    port: int
    proto: EgressProto


@dataclass(frozen=True)
class ScopeGrant:
    allowed_adapters: tuple[str, ...] = ()
    allowed_datasets: tuple[str, ...] = ()
    egress_allowlist: tuple[EgressRule, ...] = ()
    broker_audiences: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    producer_subsystems: tuple[str, ...] = ()
    sandbox_risk_class: RiskClass = "standard"
    disallowed_actions: tuple[str, ...] = ()


@dataclass(frozen=True)
class BudgetToken:
    budget_id: str
    job_id: str
    root_request_id: str
    budget_epoch: int
    caps: BudgetCaps
    risk_class: RiskClass
    issued_at: int
    expires_at: int
    ttl_s: int
    parent_budget_id: str | None
    signer_key_id: str
    signature: str


@dataclass(frozen=True)
class ScopeToken:
    scope_id: str
    job_id: str
    scopes: ScopeGrant
    issued_at: int
    expires_at: int
    ttl_s: int
    parent_scope_id: str | None
    signer_key_id: str
    signature: str


@dataclass(frozen=True)
class TokenVerification:
    valid: bool
    reason: str | None = None


@dataclass(frozen=True)
class PolicyBundleVerification:
    valid: bool
    reason: str | None = None


@dataclass(frozen=True)
class QuotaState:
    caps: BudgetCaps
    reserved: BudgetUsage
    actual: BudgetUsage
    halted: bool = False


class QuotaLedger(Protocol):
    kind: str

    def register_budget(self, token: BudgetToken) -> None: ...

    def reserve(self, budget_id: str, usage: BudgetUsage) -> None: ...

    def consume(self, budget_id: str, usage: BudgetUsage) -> None: ...

    def halt(self, budget_id: str, *, reason: str) -> None: ...

    def release(self, budget_id: str, usage: BudgetUsage | None = None) -> None: ...

    def remaining(self, budget_id: str) -> BudgetUsage: ...

    def state(self, budget_id: str) -> QuotaState: ...


@dataclass(frozen=True)
class ResourceCeilings:
    cpu_m: int
    mem_bytes: int
    gpu_count: int
    wallclock_s: int
    max_cost_usd: float


@dataclass(frozen=True)
class ExfilThresholds:
    soft_bytes: int = DEFAULT_EXFIL_SOFT_BYTES
    hard_bytes: int = DEFAULT_EXFIL_HARD_BYTES

    def __post_init__(self) -> None:
        if (
            isinstance(self.soft_bytes, bool)
            or not isinstance(self.soft_bytes, int)
            or self.soft_bytes < 1
        ):
            raise ValueError("exfil soft byte threshold must be a positive integer")
        if (
            isinstance(self.hard_bytes, bool)
            or not isinstance(self.hard_bytes, int)
            or self.hard_bytes <= self.soft_bytes
        ):
            raise ValueError("exfil hard byte threshold must be an integer greater than soft_bytes")


@dataclass(frozen=True)
class PolicyBundle:
    bundle_version: str
    egress_allowlist: tuple[EgressRule, ...]
    resource_ceilings: ResourceCeilings
    risk_to_runtime: dict[RiskClass, RuntimeClass]
    seccomp_profile_hash: str
    signer_key_id: str
    signature: str
    exfil_thresholds: ExfilThresholds = field(default_factory=ExfilThresholds)


@dataclass(frozen=True)
class LaunchEnvelope:
    cpu_m: int
    mem_bytes: int
    gpu_count: int
    wallclock_s: int
    scratch_bytes: int
    pids: int
    estimated_cost_usd: float = 0.0

    def budget_usage(self) -> BudgetUsage:
        return BudgetUsage(
            compute_units=(self.cpu_m / 1000.0) * self.wallclock_s,
            gpu_seconds=self.gpu_count * self.wallclock_s,
            wallclock_s=self.wallclock_s,
            cost_usd=self.estimated_cost_usd,
        )


@dataclass(frozen=True)
class LaunchRequest:
    job_id: str
    subagent_id: str
    trace_id: str
    budget_token: BudgetToken
    scope_token: ScopeToken
    image: str
    entrypoint: tuple[str, ...]
    args: tuple[str, ...]
    env: dict[str, str]
    env_allowlist: tuple[str, ...]
    requested_envelope: LaunchEnvelope
    runtime_class_hint: RuntimeClass = "auto"
    policy_pin: str | None = None


@dataclass(frozen=True)
class PolicyVerdict:
    allowed: bool
    runtime_class: RuntimeClass | None
    egress_acl: tuple[EgressRule, ...]
    deny_reason: str | None = None


@dataclass(frozen=True)
class SandboxHandle:
    sandbox_id: str
    job_id: str
    runtime_class: RuntimeClass
    budget_epoch: int
    policy_bundle_version: str
    state: SandboxState
    launch_provenance_ref: str | None = None


@dataclass(frozen=True)
class SandboxPartialResult:
    reason: str
    stdout: str
    stderr: str
    captured_after_freeze: bool
    freeze_succeeded: bool
    terminate_succeeded: bool
    stdout_bytes: int
    stderr_bytes: int
    capture_error: str | None = None
    log_capture_limit_bytes: int = PARTIAL_RESULT_LOG_CAPTURE_LIMIT_BYTES
    logs_truncated: bool = False
    frozen_state: Literal["FROZEN"] = "FROZEN"
    terminated_state: Literal["TERMINATED"] = "TERMINATED"


@dataclass(frozen=True)
class SandboxExecutionResult:
    handle: SandboxHandle
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_s: float
    budget_usage: BudgetUsage
    partial_result: SandboxPartialResult | None = None


@dataclass(frozen=True)
class SandboxHaltTelemetry:
    """Runtime-only timing evidence for a physical sandbox halt."""

    reason: str
    halt_detected_elapsed_s: float
    freeze_completed_elapsed_s: float | None
    terminate_completed_elapsed_s: float | None
    revocation_ack_to_detect_s: float | None
    revocation_ack_to_freeze_s: float | None
    revocation_ack_to_terminate_s: float | None


@dataclass(frozen=True)
class _RuntimeHaltSignal:
    reason: str
    dimensions: tuple[str, ...]
    revocation_acknowledged_at: float | None = None
    source: str = "runtime-token-verifier"


@dataclass(frozen=True)
class _DockerLogCapture:
    stdout: str
    stderr: str
    stdout_bytes: int
    stderr_bytes: int
    log_capture_limit_bytes: int
    truncated: bool


@dataclass(frozen=True)
class TrustMount:
    """Operator-owned host path exposed read-only inside a sandbox."""

    name: str
    source: str
    target: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", self.name):
            raise ValueError("trust mount name must be a lowercase DNS label")
        if "," in self.source or "," in self.target:
            raise ValueError("trust mount paths cannot contain commas")
        if not os.path.isabs(self.source):
            raise ValueError("trust mount source must be an absolute host path")
        if not os.path.isabs(self.target):
            raise ValueError("trust mount target must be an absolute sandbox path")
        if not self.target.startswith("/opt/argus/trust/"):
            raise ValueError("trust mount target must be under /opt/argus/trust")


@dataclass(frozen=True)
class GvisorRuntimeConfig:
    """Operator configuration required to materialize a gVisor launch."""

    docker_runtime: str
    seccomp_profile_path: str
    kubernetes_runtime_class: str
    kubernetes_seccomp_profile: str
    trust_mounts: tuple[TrustMount, ...]

    def __post_init__(self) -> None:
        if re.fullmatch(r"runsc(?:[-._][A-Za-z0-9]+)*", self.docker_runtime) is None:
            raise ValueError("gVisor Docker runtime name must identify runsc")
        if not os.path.isabs(self.seccomp_profile_path):
            raise ValueError("gVisor seccomp profile path must be absolute")
        if not self.kubernetes_runtime_class.strip():
            raise ValueError("gVisor Kubernetes RuntimeClass is required")
        if not self.kubernetes_seccomp_profile.strip() or os.path.isabs(self.kubernetes_seccomp_profile):
            raise ValueError("Kubernetes seccomp profile must be a non-empty kubelet-relative path")
        names = [mount.name for mount in self.trust_mounts]
        targets = [mount.target for mount in self.trust_mounts]
        if len(names) != len(set(names)):
            raise ValueError("trust mount names must be unique")
        if len(targets) != len(set(targets)):
            raise ValueError("trust mount targets must be unique")
        required_mounts = {"verifier-code", "provenance-ledger"}
        if not required_mounts.issubset(names):
            raise ValueError("gVisor config requires verifier-code and provenance-ledger trust mounts")


@dataclass(frozen=True)
class EgressSidecarRuntimeConfig:
    """Operator configuration for the Docker egress proxy sidecar."""

    image: str
    network_mode: str = "bridge"
    proxy_port: int = 15001
    proxy_uid: int = 65531
    proxy_gid: int = 65531
    sandbox_uid: int = 65532
    dns_servers: tuple[str, ...] = ()
    dns_port: int = 53
    startup_timeout_s: float = 5.0
    memory_bytes: int = 64 * 1024 * 1024
    pids: int = 64

    def __post_init__(self) -> None:
        if not _is_digest_pinned_image(self.image):
            raise ValueError("egress sidecar image must be digest-pinned")
        if (
            not self.network_mode
            or self.network_mode in {"none", "host"}
            or self.network_mode.startswith("container:")
        ):
            raise ValueError("egress sidecar requires an operator-owned routed network")
        if not 1 <= self.proxy_port <= 65535 or not 1 <= self.dns_port <= 65535:
            raise ValueError("egress sidecar port is invalid")
        if min(self.proxy_uid, self.proxy_gid, self.sandbox_uid) < 1:
            raise ValueError("egress sidecar users must be non-root")
        if self.proxy_uid == self.sandbox_uid:
            raise ValueError("egress proxy and sandbox UIDs must differ")
        for nameserver in self.dns_servers:
            try:
                ipaddress.ip_address(nameserver)
            except ValueError as exc:
                raise ValueError("egress DNS servers must be numeric IP addresses") from exc
        if self.startup_timeout_s <= 0:
            raise ValueError("egress sidecar startup timeout must be positive")
        if self.memory_bytes < 16 * 1024 * 1024 or self.pids < 8:
            raise ValueError("egress sidecar resource limits are too small")

    @property
    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.proxy_port}"


@dataclass(frozen=True)
class FirecrackerRuntimeConfig:
    """Operator-owned artifacts and jailer constraints for Firecracker launches."""

    expected_version: str
    kubernetes_runtime_class: str
    firecracker_bin: str
    jailer_bin: str
    kernel_image_path: str
    kernel_image_hash: str
    rootfs_image_path: str
    rootfs_image_hash: str
    rootfs_image_ref: str
    chroot_base_dir: str
    jailer_uid: int
    jailer_gid: int

    def __post_init__(self) -> None:
        if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.expected_version) is None:
            raise ValueError("Firecracker expected version must be an exact semantic version")
        if (
            len(self.kubernetes_runtime_class) > 253
            or re.fullmatch(
                r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?",
                self.kubernetes_runtime_class,
            )
            is None
        ):
            raise ValueError("Firecracker Kubernetes RuntimeClass must be a DNS subdomain")
        path_fields = {
            "firecracker binary": self.firecracker_bin,
            "jailer binary": self.jailer_bin,
            "kernel image": self.kernel_image_path,
            "rootfs image": self.rootfs_image_path,
            "jailer chroot base": self.chroot_base_dir,
        }
        for label, value in path_fields.items():
            if not os.path.isabs(value):
                raise ValueError(f"Firecracker {label} path must be absolute")
        for label, value in (
            ("kernel image", self.kernel_image_hash),
            ("rootfs image", self.rootfs_image_hash),
        ):
            if re.fullmatch(r"blake3:[0-9a-f]{64}", value) is None:
                raise ValueError(f"Firecracker {label} hash must be a BLAKE3 digest")
        if not _is_digest_pinned_image(self.rootfs_image_ref):
            raise ValueError("Firecracker rootfs image reference must be digest-pinned")
        if self.jailer_uid <= 0 or self.jailer_gid <= 0:
            raise ValueError("Firecracker jailer uid and gid must be non-root")


@dataclass(frozen=True)
class SandboxSecuritySpec:
    runtime_class: RuntimeClass
    docker_runtime: str | None = None
    seccomp_profile_hash: str | None = None
    seccomp_profile_path: str | None = None
    seccomp_profile_json: str | None = None
    trust_mounts: tuple[TrustMount, ...] = ()


@dataclass(frozen=True)
class DockerRuntimeLaunchEvidence:
    sandbox_id: str
    container_id: str
    runtime_class: RuntimeClass
    docker_runtime: str
    seccomp_profile_hash: str
    trust_mounts: tuple[TrustMount, ...]
    attestation_source: Literal["docker-api-inspect", "docker-cli-command"]


@dataclass(frozen=True)
class FirecrackerRuntimeLaunchEvidence:
    sandbox_id: str
    microvm_id: str
    runtime_class: Literal["firecracker"]
    firecracker_version: str
    jailer_version: str
    kernel_image_hash: str
    rootfs_image_hash: str
    request_drive_hash: str
    scratch_bytes: int
    network_interface_count: int
    jailer_uid: int
    jailer_gid: int
    pid_namespace_init: bool
    cgroup_v2_path: str
    seccomp_enabled: bool
    seccomp_filter_mode: Literal["default-built-in"]
    seccomp_filter_count: int
    read_only_rootfs: bool
    federated_extra_access: bool
    trust_mount_count: int
    attestation_source: Literal["firecracker-api+jailer-pid"]


RuntimeLaunchEvidence = DockerRuntimeLaunchEvidence | FirecrackerRuntimeLaunchEvidence


def materialize_gvisor_pod_spec(
    *,
    handle: SandboxHandle,
    request: LaunchRequest,
    policy_bundle: PolicyBundle,
    config: GvisorRuntimeConfig,
) -> dict[str, Any]:
    """Materialize the Kubernetes security boundary for a policy-selected gVisor launch."""

    security_spec = _materialize_gvisor_security_spec(handle, policy_bundle, config)
    materialized_env = materialize_sandbox_env(request.env, request.env_allowlist)
    envelope = request.requested_envelope
    trust_volumes = [
        {"name": mount.name, "hostPath": {"path": mount.source}}
        for mount in security_spec.trust_mounts
    ]
    trust_volume_mounts = [
        {"name": mount.name, "mountPath": mount.target, "readOnly": True}
        for mount in security_spec.trust_mounts
    ]
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": _kubernetes_name(f"argus-{handle.sandbox_id}"),
            "labels": {
                "app.kubernetes.io/name": "argus-sandbox",
                "argus.dev/job-id": request.job_id,
            },
            "annotations": {
                "argus.dev/policy-bundle-version": policy_bundle.bundle_version,
                "argus.dev/seccomp-profile-hash": policy_bundle.seccomp_profile_hash,
            },
        },
        "spec": {
            "runtimeClassName": config.kubernetes_runtime_class,
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "enableServiceLinks": False,
            "hostUsers": False,
            "containers": [
                {
                    "name": "sandbox",
                    "image": request.image,
                    "imagePullPolicy": "IfNotPresent",
                    "command": list(request.entrypoint),
                    "args": list(request.args),
                    "env": [{"name": key, "value": value} for key, value in sorted(materialized_env.items())],
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "privileged": False,
                        "readOnlyRootFilesystem": True,
                        "runAsNonRoot": True,
                        "runAsUser": 65532,
                        "runAsGroup": 65532,
                        "capabilities": {"drop": ["ALL"]},
                        "seccompProfile": {
                            "type": "Localhost",
                            "localhostProfile": config.kubernetes_seccomp_profile,
                        },
                    },
                    "resources": {
                        "requests": {
                            "cpu": f"{max(envelope.cpu_m, 1)}m",
                            "memory": str(max(envelope.mem_bytes, 4 * 1024 * 1024)),
                        },
                        "limits": {
                            "cpu": f"{max(envelope.cpu_m, 1)}m",
                            "memory": str(max(envelope.mem_bytes, 4 * 1024 * 1024)),
                        },
                    },
                    "volumeMounts": trust_volume_mounts
                    + [{"name": "scratch", "mountPath": "/tmp", "readOnly": False}],
                }
            ],
            "volumes": trust_volumes
            + [{"name": "scratch", "emptyDir": {"sizeLimit": str(max(envelope.scratch_bytes, 0))}}],
        },
    }


def _materialize_gvisor_security_spec(
    handle: SandboxHandle,
    policy_bundle: PolicyBundle,
    config: GvisorRuntimeConfig,
) -> SandboxSecuritySpec:
    if handle.runtime_class != "gvisor":
        raise SandboxRuntimeUnavailableError("gVisor security spec requires runtime_class=gvisor")
    if handle.policy_bundle_version != policy_bundle.bundle_version:
        raise SandboxRuntimeUnavailableError("sandbox policy bundle version does not match the pinned bundle")
    profile_path = Path(config.seccomp_profile_path)
    try:
        profile_bytes = profile_path.read_bytes()
    except OSError as exc:
        raise SandboxRuntimeUnavailableError(f"gVisor seccomp profile is unavailable: {profile_path}") from exc
    actual_hash = hash_bytes(profile_bytes)
    if actual_hash != policy_bundle.seccomp_profile_hash:
        raise SandboxRuntimeUnavailableError(
            "gVisor seccomp profile hash mismatch: "
            f"expected {policy_bundle.seccomp_profile_hash}, got {actual_hash}"
        )
    try:
        profile = json.loads(profile_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SandboxRuntimeUnavailableError("gVisor seccomp profile must be valid UTF-8 JSON") from exc
    if not isinstance(profile, dict) or not isinstance(profile.get("defaultAction"), str):
        raise SandboxRuntimeUnavailableError("gVisor seccomp profile must define defaultAction")
    if not isinstance(profile.get("syscalls"), list):
        raise SandboxRuntimeUnavailableError("gVisor seccomp profile must define syscall rules")
    for mount in config.trust_mounts:
        if not Path(mount.source).exists():
            raise SandboxRuntimeUnavailableError(f"gVisor trust mount source is unavailable: {mount.source}")
    return SandboxSecuritySpec(
        runtime_class="gvisor",
        docker_runtime=config.docker_runtime,
        seccomp_profile_hash=policy_bundle.seccomp_profile_hash,
        seccomp_profile_path=str(profile_path),
        seccomp_profile_json=json.dumps(profile, sort_keys=True, separators=(",", ":")),
        trust_mounts=config.trust_mounts,
    )


def materialize_firecracker_vm_spec(
    *,
    handle: SandboxHandle,
    request: LaunchRequest,
    policy_bundle: PolicyBundle,
    config: FirecrackerRuntimeConfig,
) -> dict[str, Any]:
    """Materialize a policy-bound Firecracker microVM specification before launch."""

    if handle.runtime_class != "firecracker":
        raise SandboxRuntimeUnavailableError("Firecracker VM spec requires runtime_class=firecracker")
    if handle.policy_bundle_version != policy_bundle.bundle_version:
        raise SandboxRuntimeUnavailableError("sandbox policy bundle version does not match the pinned bundle")
    risk_class = request.scope_token.scopes.sandbox_risk_class
    if policy_bundle.risk_to_runtime.get(risk_class) != "firecracker":
        raise SandboxRuntimeUnavailableError("signed policy does not select Firecracker for the requested risk class")
    if request.image != config.rootfs_image_ref:
        raise SandboxRuntimeUnavailableError("Firecracker rootfs image reference mismatch")
    _verify_firecracker_artifact_hash(
        label="kernel image",
        path=config.kernel_image_path,
        expected_hash=config.kernel_image_hash,
    )
    _verify_firecracker_artifact_hash(
        label="rootfs image",
        path=config.rootfs_image_path,
        expected_hash=config.rootfs_image_hash,
    )
    for label, path in (
        ("Firecracker binary", config.firecracker_bin),
        ("Firecracker jailer", config.jailer_bin),
        ("Firecracker chroot base", config.chroot_base_dir),
    ):
        if not Path(path).exists():
            raise SandboxRuntimeUnavailableError(f"{label} is unavailable: {path}")
    materialize_sandbox_env(request.env, request.env_allowlist)
    envelope = request.requested_envelope
    if envelope.scratch_bytes < 1024 * 1024:
        raise PolicyDeniedError("Firecracker scratch_bytes must be at least 1048576")
    min_guest_memory_bytes = 64 * 1024 * 1024
    vmm_headroom_bytes = 64 * 1024 * 1024
    min_host_memory_bytes = min_guest_memory_bytes + vmm_headroom_bytes
    if envelope.mem_bytes < min_host_memory_bytes:
        raise PolicyDeniedError(
            f"Firecracker mem_bytes must be at least {min_host_memory_bytes} bytes"
        )
    mem_size_mib = (envelope.mem_bytes - vmm_headroom_bytes) // (1024 * 1024)
    vcpu_count = max(math.ceil(envelope.cpu_m / 1000), 1)
    return {
        "microvm_id": handle.sandbox_id,
        "runtime_class": "firecracker",
        "risk_class": risk_class,
        "trust_class": risk_class,
        "federated_extra_access": False,
        "kernel_image_path": config.kernel_image_path,
        "kernel_image_hash": config.kernel_image_hash,
        "rootfs_image_ref": config.rootfs_image_ref,
        "rootfs_image_hash": config.rootfs_image_hash,
        "vmm_memory_headroom_bytes": vmm_headroom_bytes,
        "jailer": {
            "binary": config.jailer_bin,
            "firecracker_binary": config.firecracker_bin,
            "chroot_base_dir": config.chroot_base_dir,
            "uid": config.jailer_uid,
            "gid": config.jailer_gid,
            "cgroup_version": 2,
            "new_pid_namespace": True,
            "seccomp_enabled": True,
            "seccomp_filter_mode": "default-built-in",
            "resource_limits": {
                "memory.max": max(envelope.mem_bytes, 4 * 1024 * 1024),
                "pids.max": max(envelope.pids, 1),
                "cpu.max": f"{max(envelope.cpu_m, 1) * 100} 100000",
            },
        },
        "machine_config": {
            "vcpu_count": vcpu_count,
            "mem_size_mib": mem_size_mib,
            "smt": False,
            "track_dirty_pages": False,
        },
        "boot_source": {
            "kernel_image_path": config.kernel_image_path,
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off quiet loglevel=3 init=/sbin/argus-init",
        },
        "drives": [
            {
                "drive_id": "rootfs",
                "path_on_host": config.rootfs_image_path,
                "is_root_device": True,
                "is_read_only": True,
            },
            {
                "drive_id": "argus_input",
                "path_on_host": None,
                "is_root_device": False,
                "is_read_only": True,
            },
            {
                "drive_id": "scratch",
                "path_on_host": None,
                "is_root_device": False,
                "is_read_only": False,
                "size_limit_bytes": max(envelope.scratch_bytes, 0),
            },
        ],
        "network_interfaces": [],
    }


def materialize_firecracker_pod_spec(
    *,
    handle: SandboxHandle,
    request: LaunchRequest,
    policy_bundle: PolicyBundle,
    config: FirecrackerRuntimeConfig,
) -> dict[str, Any]:
    """Materialize the Kubernetes placement contract for a Firecracker launch."""

    vm_spec = materialize_firecracker_vm_spec(
        handle=handle,
        request=request,
        policy_bundle=policy_bundle,
        config=config,
    )
    materialized_env = materialize_sandbox_env(request.env, request.env_allowlist)
    envelope = request.requested_envelope
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": _kubernetes_name(f"argus-{handle.sandbox_id}"),
            "labels": {
                "app.kubernetes.io/name": "argus-sandbox",
                "argus.dev/job-id": request.job_id,
                "argus.dev/runtime-class": "firecracker",
            },
            "annotations": {
                "argus.dev/policy-bundle-version": policy_bundle.bundle_version,
                "argus.dev/risk-class": str(vm_spec["risk_class"]),
                "argus.dev/firecracker-kernel-hash": config.kernel_image_hash,
                "argus.dev/firecracker-rootfs-hash": config.rootfs_image_hash,
                "argus.dev/firecracker-network-interfaces": "0",
                "argus.dev/federated-extra-access": "false",
            },
        },
        "spec": {
            "runtimeClassName": config.kubernetes_runtime_class,
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "enableServiceLinks": False,
            "hostNetwork": False,
            "hostPID": False,
            "hostIPC": False,
            "hostUsers": False,
            "shareProcessNamespace": False,
            "dnsPolicy": "None",
            "dnsConfig": {"nameservers": ["127.0.0.1"]},
            "containers": [
                {
                    "name": "sandbox",
                    "image": request.image,
                    "imagePullPolicy": "IfNotPresent",
                    "command": list(request.entrypoint),
                    "args": list(request.args),
                    "env": [
                        {"name": key, "value": value}
                        for key, value in sorted(materialized_env.items())
                    ],
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "privileged": False,
                        "readOnlyRootFilesystem": True,
                        "runAsNonRoot": True,
                        "runAsUser": config.jailer_uid,
                        "runAsGroup": config.jailer_gid,
                        "capabilities": {"drop": ["ALL"]},
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "resources": {
                        "requests": {
                            "cpu": f"{max(envelope.cpu_m, 1)}m",
                            "memory": str(max(envelope.mem_bytes, 4 * 1024 * 1024)),
                        },
                        "limits": {
                            "cpu": f"{max(envelope.cpu_m, 1)}m",
                            "memory": str(max(envelope.mem_bytes, 4 * 1024 * 1024)),
                        },
                    },
                    "volumeMounts": [
                        {"name": "scratch", "mountPath": "/tmp", "readOnly": False},
                    ],
                }
            ],
            "volumes": [
                {
                    "name": "scratch",
                    "emptyDir": {"sizeLimit": str(max(envelope.scratch_bytes, 0))},
                }
            ],
        },
    }


def _verify_firecracker_artifact_hash(*, label: str, path: str, expected_hash: str) -> None:
    artifact_path = Path(path)
    try:
        digest = blake3()
        with artifact_path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        actual_hash = f"{BLAKE3_PREFIX}{digest.hexdigest()}"
    except OSError as exc:
        raise SandboxRuntimeUnavailableError(f"Firecracker {label} is unavailable: {artifact_path}") from exc
    if actual_hash != expected_hash:
        raise SandboxRuntimeUnavailableError(
            f"Firecracker {label} hash mismatch: expected {expected_hash}, got {actual_hash}"
        )


@dataclass(frozen=True)
class _FirecrackerProcessIdentity:
    pid: int
    start_time_ticks: int
    pid_namespace_ids: tuple[int, ...]
    cgroup_v2_path: str


@dataclass(frozen=True)
class _FirecrackerJailResources:
    jail_root: Path
    api_socket: Path
    pid_file: Path
    kernel_path: Path
    rootfs_path: Path
    request_drive_path: Path
    request_drive_hash: str
    scratch_path: Path
    scratch_bytes: int
    serial_path: Path
    log_path: Path


class FirecrackerSandboxSupervisor:
    """Node-level Firecracker supervisor using the same-version production jailer."""

    _API_SOCKET_IN_JAIL = "/run/firecracker.socket"
    _AF_UNIX_PATH_MAX_BYTES = 107
    _CGROUP_PARENT = "argus-firecracker"

    def __init__(
        self,
        *,
        config: FirecrackerRuntimeConfig,
        meter_interval_s: float = 1.0,
        kvm_path: str = "/dev/kvm",
        mke2fs_bin: str | None = None,
    ) -> None:
        self._config = config
        self._meter_interval_s = min(max(float(meter_interval_s), 0.1), 5.0)
        self._kvm_path = kvm_path
        self._mke2fs_bin = mke2fs_bin or shutil.which("mke2fs") or "mke2fs"

    @property
    def config(self) -> FirecrackerRuntimeConfig:
        return self._config

    @property
    def expected_version(self) -> str:
        return self._config.expected_version

    @property
    def resource_meter_kind(self) -> str:
        return "firecracker-host-cgroup-v2"

    def materialize_vm_spec(
        self,
        *,
        handle: SandboxHandle,
        request: LaunchRequest,
        policy_bundle: PolicyBundle,
    ) -> dict[str, Any]:
        return materialize_firecracker_vm_spec(
            handle=handle,
            request=request,
            policy_bundle=policy_bundle,
            config=self._config,
        )

    def materialize_pod_spec(
        self,
        *,
        handle: SandboxHandle,
        request: LaunchRequest,
        policy_bundle: PolicyBundle,
    ) -> dict[str, Any]:
        return materialize_firecracker_pod_spec(
            handle=handle,
            request=request,
            policy_bundle=policy_bundle,
            config=self._config,
        )

    def verify_runtime_versions(self) -> tuple[str, str]:
        firecracker_version = self._binary_version("firecracker", self._config.firecracker_bin)
        jailer_version = self._binary_version("jailer", self._config.jailer_bin)
        expected = self._config.expected_version
        if firecracker_version != expected:
            raise SandboxRuntimeUnavailableError(
                f"firecracker version mismatch: expected {expected}, got {firecracker_version}"
            )
        if jailer_version != expected:
            raise SandboxRuntimeUnavailableError(
                f"jailer version mismatch: expected {expected}, got {jailer_version}"
            )
        if firecracker_version != jailer_version:
            raise SandboxRuntimeUnavailableError("Firecracker and jailer versions differ")
        return firecracker_version, jailer_version

    def jailer_command(self, spec: Mapping[str, Any]) -> list[str]:
        jailer = spec["jailer"]
        limits = jailer["resource_limits"]
        return [
            self._config.jailer_bin,
            "--id",
            str(spec["microvm_id"]),
            "--exec-file",
            self._config.firecracker_bin,
            "--uid",
            str(jailer["uid"]),
            "--gid",
            str(jailer["gid"]),
            "--chroot-base-dir",
            self._config.chroot_base_dir,
            "--cgroup-version",
            "2",
            "--parent-cgroup",
            self._CGROUP_PARENT,
            "--cgroup",
            f"memory.max={limits['memory.max']}",
            "--cgroup",
            f"pids.max={limits['pids.max']}",
            "--cgroup",
            f"cpu.max={limits['cpu.max']}",
            "--resource-limit",
            "no-file=1024",
            "--resource-limit",
            f"fsize={max(int(limits['memory.max']), PARTIAL_RESULT_LOG_CAPTURE_LIMIT_BYTES)}",
            "--daemonize",
            "--new-pid-ns",
            "--",
            "--api-sock",
            self._API_SOCKET_IN_JAIL,
        ]

    def expected_api_configuration(self, spec: Mapping[str, Any]) -> dict[str, Any]:
        drives_by_id = {str(drive["drive_id"]): drive for drive in spec["drives"]}
        return {
            "machine-config": dict(spec["machine_config"]),
            "boot-source": {
                "kernel_image_path": "/vmlinux",
                "boot_args": str(spec["boot_source"]["boot_args"]),
            },
            "drives": [
                {
                    "drive_id": "rootfs",
                    "path_on_host": "/rootfs.ext4",
                    "is_root_device": True,
                    "is_read_only": bool(drives_by_id["rootfs"]["is_read_only"]),
                },
                {
                    "drive_id": "argus_input",
                    "path_on_host": "/argus-input.ext4",
                    "is_root_device": False,
                    "is_read_only": bool(drives_by_id["argus_input"]["is_read_only"]),
                },
                {
                    "drive_id": "scratch",
                    "path_on_host": "/scratch.ext4",
                    "is_root_device": False,
                    "is_read_only": bool(drives_by_id["scratch"]["is_read_only"]),
                },
            ],
            "network-interfaces": [],
        }

    def verify_api_attestation(self, *, spec: Mapping[str, Any], observed: Mapping[str, Any]) -> None:
        expected = self.expected_api_configuration(spec)
        if observed.get("network-interfaces") != []:
            raise SandboxRuntimeUnavailableError("Firecracker attestation reported a network interface")
        for device_key in ("vsock", "balloon", "mmds-config", "pmem"):
            if observed.get(device_key) not in (None, [], {}):
                raise SandboxRuntimeUnavailableError(
                    f"Firecracker attestation reported unexpected {device_key} access"
                )
        observed_machine = observed.get("machine-config")
        if not isinstance(observed_machine, Mapping) or any(
            observed_machine.get(key) != value
            for key, value in expected["machine-config"].items()
        ):
            raise SandboxRuntimeUnavailableError("Firecracker machine configuration attestation mismatch")
        observed_boot = observed.get("boot-source")
        if not isinstance(observed_boot, Mapping) or any(
            observed_boot.get(key) != value for key, value in expected["boot-source"].items()
        ):
            raise SandboxRuntimeUnavailableError("Firecracker boot source attestation mismatch")
        observed_drives = observed.get("drives")
        if not isinstance(observed_drives, list):
            raise SandboxRuntimeUnavailableError("Firecracker attestation omitted drive configuration")
        expected_drives = {
            drive["drive_id"]: {
                key: drive[key]
                for key in ("drive_id", "path_on_host", "is_root_device", "is_read_only")
            }
            for drive in expected["drives"]
        }
        normalized_observed: dict[str, dict[str, Any]] = {}
        for drive in observed_drives:
            if not isinstance(drive, Mapping) or not isinstance(drive.get("drive_id"), str):
                raise SandboxRuntimeUnavailableError("Firecracker drive configuration attestation is invalid")
            normalized_observed[str(drive["drive_id"])] = {
                key: drive.get(key)
                for key in ("drive_id", "path_on_host", "is_root_device", "is_read_only")
            }
        if normalized_observed != expected_drives:
            raise SandboxRuntimeUnavailableError("Firecracker drive configuration attestation mismatch")

    def run(
        self,
        *,
        handle: SandboxHandle,
        request: LaunchRequest,
        materialized_env: dict[str, str],
        meter_sample_sink: Callable[[ResourceMeterSample], None] | None = None,
        runtime_halt_probe: Callable[[], _RuntimeHaltSignal | tuple[str, tuple[str, ...]] | None] | None = None,
        halt_telemetry_sink: Callable[[SandboxHaltTelemetry], None] | None = None,
        policy_bundle: PolicyBundle | None = None,
        runtime_evidence_sink: Callable[[RuntimeLaunchEvidence], None] | None = None,
    ) -> SandboxExecutionResult:
        if policy_bundle is None:
            raise SandboxRuntimeUnavailableError("Firecracker launch requires its pinned policy bundle")
        if not request.entrypoint:
            raise PolicyDeniedError("entrypoint is required")
        expected_env = materialize_sandbox_env(request.env, request.env_allowlist)
        if materialized_env != expected_env:
            raise PolicyDeniedError("Firecracker materialized environment differs from the allowlisted request")
        spec = self.materialize_vm_spec(handle=handle, request=request, policy_bundle=policy_bundle)
        self._verify_host_runtime()
        firecracker_version, jailer_version = self.verify_runtime_versions()
        jail_root = self._jail_root(str(spec["microvm_id"]))
        self._validate_api_socket_path(str(spec["microvm_id"]))
        microvm_dir = jail_root.parent
        if microvm_dir.exists():
            raise SandboxRuntimeUnavailableError(f"Firecracker jail already exists: {microvm_dir}")

        process_identity: _FirecrackerProcessIdentity | None = None
        resources: _FirecrackerJailResources | None = None
        try:
            with tempfile.TemporaryDirectory(prefix="argus-firecracker-") as temp_dir:
                request_drive, request_hash, scratch_drive = self._create_drive_images(
                    Path(temp_dir), request, materialized_env
                )
                self._launch_jailer(spec)
                process_identity = self._wait_for_jailer_ready(str(spec["microvm_id"]), timeout_s=10.0)
                resources = self._stage_jail_resources(
                    microvm_id=str(spec["microvm_id"]),
                    request_drive=request_drive,
                    request_drive_hash=request_hash,
                    scratch_drive=scratch_drive,
                    scratch_bytes=request.requested_envelope.scratch_bytes,
                )
                evidence = self._configure_and_attest(
                    spec=spec,
                    resources=resources,
                    process_identity=process_identity,
                    firecracker_version=firecracker_version,
                    jailer_version=jailer_version,
                )
                self._firecracker_api_request(
                    resources.api_socket,
                    "PUT",
                    "/actions",
                    {"action_type": "InstanceStart"},
                    expected=(204,),
                )
                seccomp_filter_count = self._wait_for_process_seccomp(
                    process_identity,
                    timeout_s=2.0,
                )
                evidence = replace(evidence, seccomp_filter_count=seccomp_filter_count)
                if runtime_evidence_sink is not None:
                    runtime_evidence_sink(evidence)
                return self._wait_for_microvm(
                    handle=handle,
                    request=request,
                    resources=resources,
                    process_identity=process_identity,
                    meter_sample_sink=meter_sample_sink,
                    runtime_halt_probe=runtime_halt_probe,
                    halt_telemetry_sink=halt_telemetry_sink,
                )
        finally:
            if process_identity is not None and self._process_identity_is_alive(process_identity):
                self._signal_microvm(process_identity, signal.SIGKILL)
                self._wait_for_process_exit(process_identity, timeout_s=2.0)
            self._cleanup_microvm(str(spec["microvm_id"]), microvm_dir)

    def _binary_version(self, label: str, binary_path: str) -> str:
        if not os.access(binary_path, os.X_OK):
            raise SandboxRuntimeUnavailableError(f"{label} binary is not executable: {binary_path}")
        try:
            completed = subprocess.run(
                [binary_path, "--version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SandboxRuntimeUnavailableError(f"{label} version probe failed") from exc
        output = f"{completed.stdout}\n{completed.stderr}"
        match = re.search(r"\bv?([0-9]+\.[0-9]+\.[0-9]+)\b", output)
        if completed.returncode != 0 or match is None:
            raise SandboxRuntimeUnavailableError(f"{label} version probe returned invalid output")
        return match.group(1)

    def _verify_host_runtime(self) -> None:
        if os.uname().sysname != "Linux":
            raise SandboxRuntimeUnavailableError("Firecracker requires a Linux host")
        if os.geteuid() != 0:
            raise SandboxRuntimeUnavailableError("Firecracker jailer must run with root privileges")
        if not os.path.exists(self._kvm_path) or not os.access(self._kvm_path, os.R_OK | os.W_OK):
            raise SandboxRuntimeUnavailableError(f"Firecracker KVM device is unavailable: {self._kvm_path}")
        if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
            raise SandboxRuntimeUnavailableError("Firecracker requires a cgroup v2 host")
        if shutil.which(self._mke2fs_bin) is None and "/" not in self._mke2fs_bin:
            raise SandboxRuntimeUnavailableError("mke2fs is required for Firecracker request drives")
        if not os.access(self._config.chroot_base_dir, os.W_OK | os.X_OK):
            raise SandboxRuntimeUnavailableError("Firecracker jailer chroot base is not writable")

    def _jail_root(self, microvm_id: str) -> Path:
        return (
            Path(self._config.chroot_base_dir)
            / Path(self._config.firecracker_bin).name
            / microvm_id
            / "root"
        )

    def _api_socket_host_path(self, microvm_id: str) -> Path:
        return self._jail_root(microvm_id) / self._API_SOCKET_IN_JAIL.lstrip("/")

    def _validate_api_socket_path(self, microvm_id: str) -> None:
        socket_path = self._api_socket_host_path(microvm_id)
        path_bytes = len(os.fsencode(socket_path))
        if path_bytes > self._AF_UNIX_PATH_MAX_BYTES:
            raise SandboxRuntimeUnavailableError(
                "Firecracker host API socket path exceeds the Linux AF_UNIX limit: "
                f"{path_bytes} bytes > {self._AF_UNIX_PATH_MAX_BYTES}"
            )

    def _launch_jailer(self, spec: Mapping[str, Any]) -> None:
        try:
            completed = subprocess.run(
                self.jailer_command(spec),
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SandboxRuntimeUnavailableError("Firecracker jailer launch failed") from exc
        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout).strip()
            raise SandboxRuntimeUnavailableError(
                f"Firecracker jailer launch failed with {completed.returncode}: {message}"
            )

    def _create_drive_images(
        self,
        temp_dir: Path,
        request: LaunchRequest,
        materialized_env: Mapping[str, str],
    ) -> tuple[Path, str, Path]:
        request_dir = temp_dir / "request"
        request_dir.mkdir(mode=0o700)
        manifest = {
            "schema": "argus.firecracker.request.v1",
            "job_id": request.job_id,
            "subagent_id": request.subagent_id,
            "trace_id": request.trace_id,
            "risk_class": request.scope_token.scopes.sandbox_risk_class,
            "entrypoint": list(request.entrypoint),
            "args": list(request.args),
            "env": dict(sorted(materialized_env.items())),
        }
        (request_dir / "request.json").write_bytes(canonical_json_bytes(manifest))
        script = request_dir / "entrypoint.sh"
        script.write_text(
            self._guest_entrypoint_script(request, materialized_env),
            encoding="utf-8",
        )
        script.chmod(0o444)

        request_drive = temp_dir / "argus-input.ext4"
        self._make_ext4_image(request_drive, size_bytes=4 * 1024 * 1024, source_dir=request_dir)
        request_hash = hash_bytes(request_drive.read_bytes())
        scratch_drive = temp_dir / "scratch.ext4"
        self._make_ext4_image(
            scratch_drive,
            size_bytes=request.requested_envelope.scratch_bytes,
            source_dir=None,
        )
        return request_drive, request_hash, scratch_drive

    @staticmethod
    def _guest_entrypoint_script(request: LaunchRequest, materialized_env: Mapping[str, str]) -> str:
        lines = ["#!/bin/sh", "set +e"]
        for key, value in sorted(materialized_env.items()):
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None:
                raise PolicyDeniedError(f"invalid Firecracker env key: {key}")
            lines.append(f"export {key}={shlex.quote(value)}")
        command = shlex.join([*request.entrypoint, *request.args])
        lines.extend(
            (
                command,
                "exit $?",
            )
        )
        return "\n".join(lines) + "\n"

    def _make_ext4_image(self, path: Path, *, size_bytes: int, source_dir: Path | None) -> None:
        if size_bytes < 1024 * 1024:
            raise PolicyDeniedError("Firecracker scratch_bytes must be at least 1048576")
        with path.open("wb") as image:
            image.truncate(size_bytes)
        command = [
            self._mke2fs_bin,
            "-q",
            "-F",
            "-t",
            "ext4",
            "-b",
            "1024",
            "-I",
            "128",
            "-m",
            "0",
            "-N",
            "128",
            "-O",
            "^has_journal,^metadata_csum,^64bit",
        ]
        if source_dir is not None:
            command.extend(("-d", str(source_dir)))
        command.append(str(path))
        try:
            completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SandboxRuntimeUnavailableError("Firecracker ext4 drive creation failed") from exc
        if completed.returncode != 0:
            raise SandboxRuntimeUnavailableError(
                f"Firecracker ext4 drive creation failed: {(completed.stderr or completed.stdout).strip()}"
            )
        if path.stat().st_size != size_bytes:
            raise SandboxRuntimeUnavailableError("Firecracker ext4 drive size changed during creation")

    def _wait_for_jailer_ready(self, microvm_id: str, *, timeout_s: float) -> _FirecrackerProcessIdentity:
        jail_root = self._jail_root(microvm_id)
        api_socket = self._api_socket_host_path(microvm_id)
        pid_file = jail_root / f"{Path(self._config.firecracker_bin).name}.pid"
        deadline = time.monotonic() + timeout_s
        last_error = "jailer resources not created"
        last_verified_identity: _FirecrackerProcessIdentity | None = None
        while time.monotonic() < deadline:
            try:
                pid = int(pid_file.read_text(encoding="utf-8").strip())
                identity = self._verify_microvm_process(pid, microvm_id)
                last_verified_identity = identity
                if api_socket.is_socket():
                    return identity
                last_error = "API socket not ready"
            except (OSError, ValueError, SandboxRuntimeUnavailableError) as exc:
                last_error = str(exc)
            time.sleep(0.05)
        if last_verified_identity is not None and self._process_identity_is_alive(last_verified_identity):
            try:
                self._signal_microvm(last_verified_identity, signal.SIGKILL)
                self._wait_for_process_exit(last_verified_identity, timeout_s=2.0)
            except SandboxRuntimeUnavailableError as exc:
                last_error = f"{last_error}; cleanup failed: {exc}"
        raise SandboxRuntimeUnavailableError(f"Firecracker jailer did not become ready: {last_error}")

    def _stage_jail_resources(
        self,
        *,
        microvm_id: str,
        request_drive: Path,
        request_drive_hash: str,
        scratch_drive: Path,
        scratch_bytes: int,
    ) -> _FirecrackerJailResources:
        jail_root = self._jail_root(microvm_id)
        resources = _FirecrackerJailResources(
            jail_root=jail_root,
            api_socket=jail_root / self._API_SOCKET_IN_JAIL.lstrip("/"),
            pid_file=jail_root / f"{Path(self._config.firecracker_bin).name}.pid",
            kernel_path=jail_root / "vmlinux",
            rootfs_path=jail_root / "rootfs.ext4",
            request_drive_path=jail_root / "argus-input.ext4",
            request_drive_hash=request_drive_hash,
            scratch_path=jail_root / "scratch.ext4",
            scratch_bytes=scratch_bytes,
            serial_path=jail_root / "serial.log",
            log_path=jail_root / "firecracker.log",
        )
        for source, destination, mode in (
            (Path(self._config.kernel_image_path), resources.kernel_path, 0o400),
            (Path(self._config.rootfs_image_path), resources.rootfs_path, 0o400),
            (request_drive, resources.request_drive_path, 0o400),
            (scratch_drive, resources.scratch_path, 0o600),
        ):
            shutil.copyfile(source, destination)
            os.chown(destination, self._config.jailer_uid, self._config.jailer_gid)
            destination.chmod(mode)
        for destination in (resources.serial_path, resources.log_path):
            destination.touch(mode=0o600, exist_ok=False)
            os.chown(destination, self._config.jailer_uid, self._config.jailer_gid)
        _verify_firecracker_artifact_hash(
            label="jailed kernel image",
            path=str(resources.kernel_path),
            expected_hash=self._config.kernel_image_hash,
        )
        _verify_firecracker_artifact_hash(
            label="jailed rootfs image",
            path=str(resources.rootfs_path),
            expected_hash=self._config.rootfs_image_hash,
        )
        _verify_firecracker_artifact_hash(
            label="jailed request drive",
            path=str(resources.request_drive_path),
            expected_hash=request_drive_hash,
        )
        if resources.scratch_path.stat().st_size != scratch_bytes:
            raise SandboxRuntimeUnavailableError("Firecracker scratch drive exceeds the requested cap")
        return resources

    def _configure_and_attest(
        self,
        *,
        spec: Mapping[str, Any],
        resources: _FirecrackerJailResources,
        process_identity: _FirecrackerProcessIdentity,
        firecracker_version: str,
        jailer_version: str,
    ) -> FirecrackerRuntimeLaunchEvidence:
        expected = self.expected_api_configuration(spec)
        self._firecracker_api_request(
            resources.api_socket, "PUT", "/machine-config", expected["machine-config"], expected=(204,)
        )
        self._firecracker_api_request(
            resources.api_socket, "PUT", "/boot-source", expected["boot-source"], expected=(204,)
        )
        for drive in expected["drives"]:
            self._firecracker_api_request(
                resources.api_socket,
                "PUT",
                f"/drives/{drive['drive_id']}",
                drive,
                expected=(204,),
            )
        self._firecracker_api_request(
            resources.api_socket,
            "PUT",
            "/serial",
            {"serial_out_path": "/serial.log"},
            expected=(204,),
        )
        self._firecracker_api_request(
            resources.api_socket,
            "PUT",
            "/logger",
            {"level": "Warning", "log_path": "/firecracker.log", "show_level": True},
            expected=(204,),
        )
        observed = self._firecracker_api_request(
            resources.api_socket, "GET", "/vm/config", expected=(200,)
        )
        self.verify_api_attestation(spec=spec, observed=observed)
        version_payload = self._firecracker_api_request(
            resources.api_socket, "GET", "/version", expected=(200,)
        )
        if version_payload.get("firecracker_version") != firecracker_version:
            raise SandboxRuntimeUnavailableError("Firecracker API version differs from the verified binary")
        instance = self._firecracker_api_request(resources.api_socket, "GET", "/", expected=(200,))
        if instance.get("id") != spec["microvm_id"] or instance.get("state") != "Not started":
            raise SandboxRuntimeUnavailableError("Firecracker instance identity/state attestation mismatch")
        if instance.get("vmm_version") != firecracker_version:
            raise SandboxRuntimeUnavailableError("Firecracker instance version attestation mismatch")
        self._verify_microvm_process(process_identity.pid, str(spec["microvm_id"]), process_identity)
        return FirecrackerRuntimeLaunchEvidence(
            sandbox_id=str(spec["microvm_id"]),
            microvm_id=str(spec["microvm_id"]),
            runtime_class="firecracker",
            firecracker_version=firecracker_version,
            jailer_version=jailer_version,
            kernel_image_hash=self._config.kernel_image_hash,
            rootfs_image_hash=self._config.rootfs_image_hash,
            request_drive_hash=resources.request_drive_hash,
            scratch_bytes=resources.scratch_bytes,
            network_interface_count=0,
            jailer_uid=self._config.jailer_uid,
            jailer_gid=self._config.jailer_gid,
            pid_namespace_init=process_identity.pid_namespace_ids[-1] == 1,
            cgroup_v2_path=process_identity.cgroup_v2_path,
            seccomp_enabled=True,
            seccomp_filter_mode="default-built-in",
            seccomp_filter_count=0,
            read_only_rootfs=True,
            federated_extra_access=False,
            trust_mount_count=0,
            attestation_source="firecracker-api+jailer-pid",
        )

    def _firecracker_api_request(
        self,
        socket_path: Path,
        method: str,
        path: str,
        body: Mapping[str, Any] | None = None,
        *,
        expected: tuple[int, ...],
        timeout: float = 5.0,
    ) -> dict[str, Any]:
        encoded = None if body is None else json.dumps(body, sort_keys=True).encode("utf-8")
        connection = _UnixSocketHTTPConnection(str(socket_path), timeout=timeout)
        response: http_client.HTTPResponse | None = None
        payload = b""
        try:
            connection.request(
                method,
                path,
                body=encoded,
                headers={"Content-Type": "application/json"} if encoded is not None else {},
            )
            response = connection.getresponse()
            payload = response.read(PARTIAL_RESULT_LOG_CAPTURE_LIMIT_BYTES + 1)
        except socket.timeout as exc:
            raise TimeoutError(f"Firecracker API {method} {path} timed out") from exc
        except OSError as exc:
            raise SandboxRuntimeUnavailableError("Firecracker API socket is unavailable") from exc
        finally:
            connection.close()
        if response is None:
            raise SandboxRuntimeUnavailableError("Firecracker API returned no response")
        if len(payload) > PARTIAL_RESULT_LOG_CAPTURE_LIMIT_BYTES:
            raise SandboxRuntimeUnavailableError("Firecracker API response exceeded the control-plane limit")
        if response.status not in expected:
            raise SandboxRuntimeUnavailableError(
                f"Firecracker API {method} {path} returned {response.status}: "
                f"{payload.decode('utf-8', errors='replace')}"
            )
        if not payload:
            return {}
        try:
            decoded = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SandboxRuntimeUnavailableError("Firecracker API returned invalid JSON") from exc
        if not isinstance(decoded, dict):
            raise SandboxRuntimeUnavailableError("Firecracker API returned a non-object payload")
        return decoded

    def _wait_for_microvm(
        self,
        *,
        handle: SandboxHandle,
        request: LaunchRequest,
        resources: _FirecrackerJailResources,
        process_identity: _FirecrackerProcessIdentity,
        meter_sample_sink: Callable[[ResourceMeterSample], None] | None,
        runtime_halt_probe: Callable[[], _RuntimeHaltSignal | tuple[str, tuple[str, ...]] | None] | None,
        halt_telemetry_sink: Callable[[SandboxHaltTelemetry], None] | None,
    ) -> SandboxExecutionResult:
        started_at = time.monotonic()
        next_sample_at = started_at
        last_sample_at: float | None = None
        last_sample: ResourceMeterSample | None = None
        sample_seq = 0
        while self._process_identity_is_alive(process_identity):
            now = time.monotonic()
            elapsed_s = now - started_at
            runtime_halt = runtime_halt_probe() if runtime_halt_probe is not None else None
            if runtime_halt is not None:
                if isinstance(runtime_halt, _RuntimeHaltSignal):
                    reason = runtime_halt.reason
                    dimensions = runtime_halt.dimensions
                    acknowledged_at = runtime_halt.revocation_acknowledged_at
                else:
                    reason, dimensions = runtime_halt
                    acknowledged_at = None
                return self._halt_microvm(
                    handle=handle,
                    request=request,
                    resources=resources,
                    process_identity=process_identity,
                    started_at=started_at,
                    reason=reason,
                    dimensions=dimensions or (reason,),
                    meter_sample_sink=meter_sample_sink,
                    halt_telemetry_sink=halt_telemetry_sink,
                    revocation_acknowledged_at=acknowledged_at,
                    last_sample=last_sample,
                    sample_seq=sample_seq,
                )
            if now >= next_sample_at:
                sample_seq += 1
                sample = self._firecracker_resource_sample(
                    request=request,
                    microvm_id=handle.sandbox_id,
                    started_at=started_at,
                    sample_seq=sample_seq,
                    previous_sample_at=last_sample_at,
                )
                dimensions = _budget_usage_breach_dimensions(request.budget_token.caps, sample.usage)
                wallclock_exceeded = request.requested_envelope.wallclock_s > 0 and (
                    sample.elapsed_s >= request.requested_envelope.wallclock_s
                )
                sample = replace(sample, breached_dimensions=dimensions, halted=bool(dimensions) or wallclock_exceeded)
                if meter_sample_sink is not None:
                    meter_sample_sink(sample)
                last_sample = sample
                last_sample_at = time.monotonic()
                if sample.halted:
                    reason = "budget_caps" if dimensions else "wallclock_timeout"
                    return self._halt_microvm(
                        handle=handle,
                        request=request,
                        resources=resources,
                        process_identity=process_identity,
                        started_at=started_at,
                        reason=reason,
                        dimensions=dimensions or ("wallclock_s",),
                        meter_sample_sink=meter_sample_sink,
                        halt_telemetry_sink=halt_telemetry_sink,
                        last_sample=sample,
                        sample_seq=sample_seq,
                    )
                next_sample_at = time.monotonic() + self._meter_interval_s
            time.sleep(min(self._meter_interval_s / 4, 0.05))

        duration_s = time.monotonic() - started_at
        usage = _max_budget_usage(
            last_sample.usage if last_sample is not None else BudgetUsage(),
            _runtime_budget_usage(request.requested_envelope, duration_s),
        )
        if last_sample is None:
            sample_seq += 1
            if meter_sample_sink is not None:
                meter_sample_sink(
                    ResourceMeterSample(
                        sample_seq=sample_seq,
                        elapsed_s=duration_s,
                        cadence_s=0.0,
                        usage=usage,
                        source="firecracker-host-cgroup-v2-final",
                    )
                )
        stdout, stdout_truncated = self._read_bounded_file(resources.serial_path)
        stderr, stderr_truncated = self._read_bounded_file(resources.log_path)
        exit_match = re.findall(r"ARGUS_FIRECRACKER_EXIT_CODE=([0-9]{1,3})", stdout)
        exit_code = int(exit_match[-1]) if exit_match and int(exit_match[-1]) <= 255 else 1
        if not exit_match:
            message = "Firecracker guest exited without an Argus exit marker"
            stderr = f"{stderr}\n{message}".strip()
        if stdout_truncated or stderr_truncated:
            stderr = f"{stderr}\nArgus bounded Firecracker log capture was truncated".strip()
        return SandboxExecutionResult(
            handle=handle,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            timed_out=False,
            duration_s=duration_s,
            budget_usage=usage,
        )

    def _firecracker_resource_sample(
        self,
        *,
        request: LaunchRequest,
        microvm_id: str,
        started_at: float,
        sample_seq: int,
        previous_sample_at: float | None,
    ) -> ResourceMeterSample:
        now = time.monotonic()
        elapsed_s = now - started_at
        cgroup = Path("/sys/fs/cgroup") / self._CGROUP_PARENT / microvm_id
        memory_bytes = 0
        cpu_seconds = 0.0
        source = "firecracker-host-cgroup-v2"
        try:
            memory_bytes = int((cgroup / "memory.current").read_text(encoding="utf-8").strip())
            cpu_fields = {
                key: int(value)
                for key, value in (
                    line.split(maxsplit=1)
                    for line in (cgroup / "cpu.stat").read_text(encoding="utf-8").splitlines()
                    if " " in line
                )
            }
            cpu_seconds = cpu_fields.get("usage_usec", 0) / 1_000_000.0
        except (OSError, ValueError):
            source = "firecracker-host-cgroup-v2-unavailable"
        conservative = _runtime_budget_usage(request.requested_envelope, elapsed_s)
        usage = replace(conservative, compute_units=max(conservative.compute_units, cpu_seconds))
        return ResourceMeterSample(
            sample_seq=sample_seq,
            elapsed_s=elapsed_s,
            cadence_s=0.0 if previous_sample_at is None else max(now - previous_sample_at, 0.0),
            usage=usage,
            memory_bytes=memory_bytes,
            source=source,
        )

    def _halt_microvm(
        self,
        *,
        handle: SandboxHandle,
        request: LaunchRequest,
        resources: _FirecrackerJailResources,
        process_identity: _FirecrackerProcessIdentity,
        started_at: float,
        reason: str,
        dimensions: tuple[str, ...],
        meter_sample_sink: Callable[[ResourceMeterSample], None] | None,
        halt_telemetry_sink: Callable[[SandboxHaltTelemetry], None] | None,
        last_sample: ResourceMeterSample | None,
        sample_seq: int,
        revocation_acknowledged_at: float | None = None,
    ) -> SandboxExecutionResult:
        detected_at = time.monotonic()
        freeze_at: float | None = None
        terminate_at: float | None = None
        freeze_succeeded = False
        terminate_succeeded = False
        capture_error: str | None = None
        try:
            self._freeze_microvm(handle.sandbox_id)
            freeze_succeeded = True
            freeze_at = time.monotonic()
        except SandboxRuntimeUnavailableError as exc:
            capture_error = f"freeze_failed:{exc}"
        stdout, stdout_truncated = self._read_bounded_file(resources.serial_path)
        stderr, stderr_truncated = self._read_bounded_file(resources.log_path)
        try:
            if freeze_succeeded:
                self._unfreeze_microvm(handle.sandbox_id)
            self._signal_microvm(process_identity, signal.SIGKILL)
            terminate_succeeded = self._wait_for_process_exit(process_identity, timeout_s=2.0)
            terminate_at = time.monotonic() if terminate_succeeded else None
        except SandboxRuntimeUnavailableError as exc:
            message = f"terminate_failed:{exc}"
            capture_error = message if capture_error is None else f"{capture_error};{message}"
        if halt_telemetry_sink is not None:
            halt_telemetry_sink(
                SandboxHaltTelemetry(
                    reason=reason,
                    halt_detected_elapsed_s=max(detected_at - started_at, 0.0),
                    freeze_completed_elapsed_s=max(freeze_at - started_at, 0.0) if freeze_at else None,
                    terminate_completed_elapsed_s=max(terminate_at - started_at, 0.0) if terminate_at else None,
                    revocation_ack_to_detect_s=(
                        max(detected_at - revocation_acknowledged_at, 0.0)
                        if revocation_acknowledged_at is not None
                        else None
                    ),
                    revocation_ack_to_freeze_s=(
                        max(freeze_at - revocation_acknowledged_at, 0.0)
                        if freeze_at is not None and revocation_acknowledged_at is not None
                        else None
                    ),
                    revocation_ack_to_terminate_s=(
                        max(terminate_at - revocation_acknowledged_at, 0.0)
                        if terminate_at is not None and revocation_acknowledged_at is not None
                        else None
                    ),
                )
            )
        duration_s = time.monotonic() - started_at
        usage = _max_budget_usage(
            last_sample.usage if last_sample is not None else BudgetUsage(),
            _runtime_budget_usage(request.requested_envelope, duration_s),
        )
        sample_seq += 1
        final_sample = ResourceMeterSample(
            sample_seq=sample_seq,
            elapsed_s=duration_s,
            cadence_s=max(duration_s - (last_sample.elapsed_s if last_sample else 0.0), 0.0),
            usage=usage,
            source="firecracker-host-cgroup-v2-halt",
            breached_dimensions=dimensions,
            halted=True,
        )
        if meter_sample_sink is not None:
            meter_sample_sink(final_sample)
        partial = SandboxPartialResult(
            reason=reason,
            stdout=stdout,
            stderr=stderr,
            captured_after_freeze=freeze_succeeded,
            freeze_succeeded=freeze_succeeded,
            terminate_succeeded=terminate_succeeded,
            stdout_bytes=len(stdout.encode("utf-8")),
            stderr_bytes=len(stderr.encode("utf-8")),
            capture_error=capture_error,
            logs_truncated=stdout_truncated or stderr_truncated,
        )
        return SandboxExecutionResult(
            handle=handle,
            exit_code=None,
            stdout=stdout,
            stderr=f"{stderr}\nargus meter halted Firecracker microVM: {reason}".strip(),
            timed_out=True,
            duration_s=duration_s,
            budget_usage=usage,
            partial_result=partial,
        )

    @staticmethod
    def _read_bounded_file(path: Path) -> tuple[str, bool]:
        try:
            with path.open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                size = stream.tell()
                truncated = size > PARTIAL_RESULT_LOG_CAPTURE_LIMIT_BYTES
                if truncated:
                    stream.seek(-PARTIAL_RESULT_LOG_CAPTURE_LIMIT_BYTES, os.SEEK_END)
                else:
                    stream.seek(0)
                raw = stream.read(PARTIAL_RESULT_LOG_CAPTURE_LIMIT_BYTES)
        except OSError:
            return "", False
        return raw.decode("utf-8", errors="replace"), truncated

    def _verify_microvm_process(
        self,
        pid: int,
        microvm_id: str,
        expected_identity: _FirecrackerProcessIdentity | None = None,
    ) -> _FirecrackerProcessIdentity:
        if pid <= 1:
            raise SandboxRuntimeUnavailableError("Firecracker jailer returned an invalid PID")
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            start_time_ticks = self._proc_start_time_ticks(pid)
            status = self._proc_status(pid)
            cgroup_v2_path = self._proc_cgroup_v2_path(pid)
        except (OSError, ValueError) as exc:
            raise SandboxRuntimeUnavailableError("Firecracker PID is not live") from exc
        decoded = [item.decode("utf-8", errors="replace") for item in cmdline if item]
        expected_binary = Path(self._config.firecracker_bin).name
        if (
            len(decoded) < 3
            or Path(decoded[0]).name != expected_binary
            or decoded[1:3] != ["--id", microvm_id]
        ):
            raise SandboxRuntimeUnavailableError("Firecracker PID identity does not match the jail")
        if any(
            item == "--no-seccomp"
            or item == "--seccomp-filter"
            or item.startswith("--seccomp-filter=")
            for item in decoded
        ):
            raise SandboxRuntimeUnavailableError(
                "Firecracker PID disabled or replaced the pinned built-in seccomp filter"
            )
        try:
            pid_namespace_ids = tuple(int(value) for value in status["NSpid"].split())
        except (KeyError, ValueError) as exc:
            raise SandboxRuntimeUnavailableError(
                "Firecracker PID namespace evidence is unavailable"
            ) from exc
        if len(pid_namespace_ids) < 2 or pid_namespace_ids[-1] != 1:
            raise SandboxRuntimeUnavailableError(
                "Firecracker process is not PID 1 in a dedicated PID namespace"
            )
        expected_cgroup = f"/{self._CGROUP_PARENT}/{microvm_id}"
        if cgroup_v2_path != expected_cgroup:
            raise SandboxRuntimeUnavailableError(
                "Firecracker process is not in the dedicated cgroup v2 path"
            )
        identity = _FirecrackerProcessIdentity(
            pid=pid,
            start_time_ticks=start_time_ticks,
            pid_namespace_ids=pid_namespace_ids,
            cgroup_v2_path=cgroup_v2_path,
        )
        if expected_identity is not None and identity != expected_identity:
            raise SandboxRuntimeUnavailableError("Firecracker PID identity changed before attestation")
        return identity

    @staticmethod
    def _proc_start_time_ticks(pid: int) -> int:
        stat_payload = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        _, separator, suffix = stat_payload.rpartition(")")
        if not separator:
            raise ValueError("invalid proc stat")
        fields = suffix.strip().split()
        return int(fields[19])

    @staticmethod
    def _proc_status(pid: int) -> dict[str, str]:
        fields: dict[str, str] = {}
        for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition(":")
            if separator:
                fields[key] = value.strip()
        return fields

    @staticmethod
    def _proc_cgroup_v2_path(pid: int) -> str:
        for line in Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8").splitlines():
            hierarchy, controllers, path = line.split(":", 2)
            if hierarchy == "0" and controllers == "":
                return path
        raise ValueError("cgroup v2 process path is unavailable")

    def _wait_for_process_seccomp(
        self,
        identity: _FirecrackerProcessIdentity,
        *,
        timeout_s: float,
    ) -> int:
        deadline = time.monotonic() + timeout_s
        last_mode = "unavailable"
        last_filter_count = 0
        while time.monotonic() < deadline:
            if not self._process_identity_is_alive(identity):
                raise SandboxRuntimeUnavailableError(
                    "Firecracker process exited before seccomp attestation"
                )
            try:
                status = self._proc_status(identity.pid)
                last_mode = status.get("Seccomp", "unavailable")
                last_filter_count = int(status.get("Seccomp_filters", "0"))
            except (OSError, ValueError):
                last_mode = "unavailable"
                last_filter_count = 0
            if last_mode == "2" and last_filter_count >= 1:
                return last_filter_count
            time.sleep(0.01)
        raise SandboxRuntimeUnavailableError(
            "Firecracker built-in seccomp filter was not active after InstanceStart: "
            f"mode={last_mode}, filters={last_filter_count}"
        )

    def _process_identity_is_alive(self, identity: _FirecrackerProcessIdentity) -> bool:
        try:
            return self._proc_start_time_ticks(identity.pid) == identity.start_time_ticks
        except (OSError, ValueError):
            return False

    def _signal_microvm(self, identity: _FirecrackerProcessIdentity, sig: int) -> None:
        if not self._process_identity_is_alive(identity):
            raise SandboxRuntimeUnavailableError("Firecracker process identity is no longer live")
        try:
            os.kill(identity.pid, sig)
        except OSError as exc:
            raise SandboxRuntimeUnavailableError("Firecracker process signal failed") from exc

    def _freeze_microvm(self, microvm_id: str) -> None:
        cgroup = Path("/sys/fs/cgroup") / self._CGROUP_PARENT / microvm_id
        try:
            (cgroup / "cgroup.freeze").write_text("1\n", encoding="utf-8")
        except OSError as exc:
            raise SandboxRuntimeUnavailableError("Firecracker cgroup freeze failed") from exc
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                events = dict(
                    line.split(maxsplit=1)
                    for line in (cgroup / "cgroup.events").read_text(encoding="utf-8").splitlines()
                    if " " in line
                )
            except OSError as exc:
                raise SandboxRuntimeUnavailableError("Firecracker cgroup freeze evidence is unavailable") from exc
            if events.get("frozen") == "1":
                return
            time.sleep(0.01)
        raise SandboxRuntimeUnavailableError("Firecracker cgroup did not attest a frozen state")

    def _unfreeze_microvm(self, microvm_id: str) -> None:
        cgroup = Path("/sys/fs/cgroup") / self._CGROUP_PARENT / microvm_id
        try:
            (cgroup / "cgroup.freeze").write_text("0\n", encoding="utf-8")
        except OSError as exc:
            raise SandboxRuntimeUnavailableError("Firecracker cgroup unfreeze failed") from exc

    def _wait_for_process_exit(self, identity: _FirecrackerProcessIdentity, *, timeout_s: float) -> bool:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if not self._process_identity_is_alive(identity):
                return True
            time.sleep(0.02)
        return not self._process_identity_is_alive(identity)

    def _cleanup_microvm(self, microvm_id: str, microvm_dir: Path) -> None:
        if microvm_dir.exists():
            shutil.rmtree(microvm_dir, ignore_errors=True)
        cgroup_dir = Path("/sys/fs/cgroup") / self._CGROUP_PARENT / microvm_id
        try:
            cgroup_dir.rmdir()
        except OSError:
            pass


def _kubernetes_name(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-")
    return normalized[:63].rstrip("-") or "argus-sandbox"


@dataclass(frozen=True)
class _BoundedSubprocessResult:
    returncode: int | None
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool


@dataclass(frozen=True)
class EgressDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True)
class EgressProxyManifest:
    schema_version: int
    sandbox_id: str
    job_id: str
    scope_id: str
    policy_bundle_version: str
    policy_bundle_hash: str
    scope_token_hash: str
    exfil_thresholds: ExfilThresholds
    rules: tuple[EgressRule, ...]
    manifest_hash: str

    @classmethod
    def materialize(
        cls,
        *,
        sandbox_id: str,
        scope_token: ScopeToken,
        policy_bundle: PolicyBundle,
    ) -> "EgressProxyManifest":
        if not sandbox_id:
            raise EgressProxyManifestError("sandbox_id is required")
        rules = tuple(
            sorted(
                set(scope_token.scopes.egress_allowlist) & set(policy_bundle.egress_allowlist),
                key=lambda rule: (rule.host, rule.port, rule.proto),
            )
        )
        for rule in rules:
            _validate_egress_rule(rule)
        manifest = cls(
            schema_version=2,
            sandbox_id=sandbox_id,
            job_id=scope_token.job_id,
            scope_id=scope_token.scope_id,
            policy_bundle_version=policy_bundle.bundle_version,
            policy_bundle_hash=hash_json(asdict(policy_bundle)),
            scope_token_hash=hash_json(asdict(scope_token)),
            exfil_thresholds=policy_bundle.exfil_thresholds,
            rules=rules,
            manifest_hash="",
        )
        return replace(manifest, manifest_hash=manifest.computed_hash())

    @classmethod
    def from_json(cls, raw: str, *, expected_hash: str) -> "EgressProxyManifest":
        if not expected_hash.startswith(BLAKE3_PREFIX):
            raise EgressProxyManifestError("expected manifest hash is missing or unsupported")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise EgressProxyManifestError("egress proxy manifest is not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise EgressProxyManifestError("egress proxy manifest must be an object")
        expected_fields = {
            "schema_version",
            "sandbox_id",
            "job_id",
            "scope_id",
            "policy_bundle_version",
            "policy_bundle_hash",
            "scope_token_hash",
            "exfil_thresholds",
            "rules",
            "manifest_hash",
        }
        if set(parsed) != expected_fields:
            raise EgressProxyManifestError("egress proxy manifest fields are invalid")
        raw_rules = parsed.get("rules")
        if not isinstance(raw_rules, list):
            raise EgressProxyManifestError("egress proxy manifest rules must be an array")
        rules: list[EgressRule] = []
        for raw_rule in raw_rules:
            if not isinstance(raw_rule, dict) or set(raw_rule) != {"host", "port", "proto"}:
                raise EgressProxyManifestError("egress proxy manifest rule is invalid")
            if (
                not isinstance(raw_rule["host"], str)
                or isinstance(raw_rule["port"], bool)
                or not isinstance(raw_rule["port"], int)
                or not isinstance(raw_rule["proto"], str)
            ):
                raise EgressProxyManifestError("egress proxy manifest rule is invalid")
            rule = EgressRule(
                host=raw_rule["host"],
                port=raw_rule["port"],
                proto=raw_rule["proto"],
            )
            _validate_egress_rule(rule)
            rules.append(rule)
        raw_thresholds = parsed.get("exfil_thresholds")
        if not isinstance(raw_thresholds, dict) or set(raw_thresholds) != {"soft_bytes", "hard_bytes"}:
            raise EgressProxyManifestError("egress proxy manifest exfil thresholds are invalid")
        try:
            exfil_thresholds = ExfilThresholds(
                soft_bytes=raw_thresholds["soft_bytes"],
                hard_bytes=raw_thresholds["hard_bytes"],
            )
        except (TypeError, ValueError) as exc:
            raise EgressProxyManifestError("egress proxy manifest exfil thresholds are invalid") from exc
        scalar_fields = (
            "sandbox_id",
            "job_id",
            "scope_id",
            "policy_bundle_version",
            "policy_bundle_hash",
            "scope_token_hash",
            "manifest_hash",
        )
        if isinstance(parsed["schema_version"], bool) or not isinstance(parsed["schema_version"], int):
            raise EgressProxyManifestError("egress proxy manifest values are invalid")
        if any(not isinstance(parsed[field_name], str) for field_name in scalar_fields):
            raise EgressProxyManifestError("egress proxy manifest values are invalid")
        manifest = cls(
            schema_version=parsed["schema_version"],
            sandbox_id=parsed["sandbox_id"],
            job_id=parsed["job_id"],
            scope_id=parsed["scope_id"],
            policy_bundle_version=parsed["policy_bundle_version"],
            policy_bundle_hash=parsed["policy_bundle_hash"],
            scope_token_hash=parsed["scope_token_hash"],
            exfil_thresholds=exfil_thresholds,
            rules=tuple(rules),
            manifest_hash=parsed["manifest_hash"],
        )
        manifest._validate()
        if not hmac.compare_digest(manifest.manifest_hash, expected_hash):
            raise EgressProxyManifestError("egress proxy manifest expected hash mismatch")
        if not hmac.compare_digest(manifest.computed_hash(), manifest.manifest_hash):
            raise EgressProxyManifestError("egress proxy manifest content hash mismatch")
        return manifest

    def computed_hash(self) -> str:
        return hash_json(
            {
                "schema_version": self.schema_version,
                "sandbox_id": self.sandbox_id,
                "job_id": self.job_id,
                "scope_id": self.scope_id,
                "policy_bundle_version": self.policy_bundle_version,
                "policy_bundle_hash": self.policy_bundle_hash,
                "scope_token_hash": self.scope_token_hash,
                "exfil_thresholds": asdict(self.exfil_thresholds),
                "rules": [asdict(rule) for rule in self.rules],
            }
        )

    def to_json(self) -> str:
        self._validate()
        if not hmac.compare_digest(self.computed_hash(), self.manifest_hash):
            raise EgressProxyManifestError("egress proxy manifest content hash mismatch")
        return canonical_json_bytes(asdict(self)).decode("utf-8")

    def _validate(self) -> None:
        if self.schema_version != 2:
            raise EgressProxyManifestError("unsupported egress proxy manifest schema version")
        if not all((self.sandbox_id, self.job_id, self.scope_id, self.policy_bundle_version)):
            raise EgressProxyManifestError("egress proxy manifest identity fields are required")
        if not self.policy_bundle_hash.startswith(BLAKE3_PREFIX):
            raise EgressProxyManifestError("egress proxy manifest policy hash is invalid")
        if not self.scope_token_hash.startswith(BLAKE3_PREFIX):
            raise EgressProxyManifestError("egress proxy manifest scope hash is invalid")
        if tuple(sorted(self.rules, key=lambda rule: (rule.host, rule.port, rule.proto))) != self.rules:
            raise EgressProxyManifestError("egress proxy manifest rules must be sorted")
        if len(set(self.rules)) != len(self.rules):
            raise EgressProxyManifestError("egress proxy manifest rules must be unique")
        for rule in self.rules:
            _validate_egress_rule(rule)


@dataclass(frozen=True)
class AuditEvent:
    sequence: int
    event_type: str
    payload: dict[str, Any]
    previous_hash: str
    event_hash: str


@dataclass(frozen=True)
class AuditVerification:
    valid: bool
    break_sequence: int | None = None


@dataclass(frozen=True)
class StoreBrokerHandle:
    handle_id: str
    scope_id: str
    expires_at: int


@dataclass(frozen=True)
class S10VerifierKeyMetadata:
    key_id: str
    revoked: bool
    epoch: int


@dataclass(frozen=True)
class S8CheckpointSignature:
    sequence: int
    root: str
    signature: str
    signer_key_id: str


@dataclass(frozen=True)
class _S10VerifierKeyMaterial:
    key_id: str
    secret: bytes
    revoked: bool
    epoch: int


class S10VerifierKeyProvider(Protocol):
    """S10-owned verifier-key provider surface exposed to read-only trust-store clients."""

    def snapshot(self) -> tuple[int, tuple[S10VerifierKeyMetadata, ...]]:
        ...

    def verify_signature_value(
        self,
        *,
        key_id: str,
        report_with_empty_signature: dict[str, Any],
        signature_value: str,
    ) -> str | None:
        ...


class InMemoryS10KmsVerifierKeyProvider:
    """S10-owned verifier-key provider that exposes metadata snapshots and KMS-style verification."""

    def __init__(self) -> None:
        self._keys: dict[str, _S10VerifierKeyMaterial] = {}
        self._epoch = 0

    @property
    def epoch(self) -> int:
        return self._epoch

    def register_verifier_key(self, key_id: str, secret: bytes) -> None:
        self._epoch += 1
        self._keys[key_id] = _S10VerifierKeyMaterial(
            key_id=key_id,
            secret=bytes(secret),
            revoked=False,
            epoch=self._epoch,
        )

    def rotate_verifier_key(self, key_id: str, secret: bytes) -> None:
        self.register_verifier_key(key_id, secret)

    def revoke_verifier_key(self, key_id: str) -> None:
        key = self._keys[key_id]
        self._epoch += 1
        self._keys[key_id] = _S10VerifierKeyMaterial(
            key_id=key.key_id,
            secret=key.secret,
            revoked=True,
            epoch=self._epoch,
        )

    def snapshot(self) -> tuple[int, tuple[S10VerifierKeyMetadata, ...]]:
        metadata = tuple(
            S10VerifierKeyMetadata(key_id=key.key_id, revoked=key.revoked, epoch=key.epoch)
            for key in sorted(self._keys.values(), key=lambda item: item.key_id)
        )
        return self._epoch, metadata

    def verify_signature_value(
        self,
        *,
        key_id: str,
        report_with_empty_signature: dict[str, Any],
        signature_value: str,
    ) -> str | None:
        key = self._keys.get(key_id)
        if key is None:
            return "unknown_key"
        if key.revoked:
            return "revoked_key"
        digest = hmac.new(key.secret, canonical_c3_json_bytes(report_with_empty_signature), sha256).hexdigest()
        expected = f"{C3_SIGNATURE_PREFIX}{digest}"
        if not hmac.compare_digest(signature_value, expected):
            return "signature_invalid"
        return SIGNATURE_VERIFICATION_ACCEPTED


class InMemoryS10KmsCheckpointSigner:
    """S10-owned checkpoint signer that keeps S8 Merkle signing key material inside S10."""

    kind = "s10-kms"

    def __init__(self, *, signer_key_id: str, signing_key: bytes) -> None:
        if not signer_key_id:
            raise ValueError("checkpoint signer_key_id is required")
        if not signing_key:
            raise ValueError("checkpoint signing key is required")
        self.signer_key_id = signer_key_id
        self._signing_key = bytes(signing_key)

    def sign_checkpoint(self, *, sequence: int, root: str) -> S8CheckpointSignature:
        if sequence <= 0:
            raise ValueError("checkpoint sequence must be positive")
        if not root.startswith("blake3:"):
            raise ValueError("checkpoint root must be a BLAKE3 hash")
        digest = hmac.new(
            self._signing_key,
            s8_checkpoint_signature_payload(sequence=sequence, root=root, signer_key_id=self.signer_key_id).encode(
                "utf-8"
            ),
            sha256,
        ).hexdigest()
        return S8CheckpointSignature(
            sequence=sequence,
            root=root,
            signature=f"hmac-sha256:{digest}",
            signer_key_id=self.signer_key_id,
        )

    def verify_checkpoint(self, checkpoint: S8CheckpointSignature) -> bool:
        expected = self.sign_checkpoint(sequence=checkpoint.sequence, root=checkpoint.root)
        return checkpoint.signer_key_id == self.signer_key_id and hmac.compare_digest(
            checkpoint.signature,
            expected.signature,
        )


class S10VerifierTrustStoreClient:
    """Read-only S8/S3 trust-store client backed by an S10 KMS verifier-key provider."""

    def __init__(self, provider: S10VerifierKeyProvider) -> None:
        self._provider = provider
        self._epoch = -1
        self._keys: dict[str, VerifierKey] = {}

    @property
    def epoch(self) -> int:
        return self._epoch

    def refresh(self) -> int:
        epoch, metadata = self._provider.snapshot()
        if epoch != self._epoch:
            self._keys = {
                item.key_id: VerifierKey(key_id=item.key_id, secret=b"", revoked=item.revoked)
                for item in metadata
            }
            self._epoch = epoch
        return self._epoch

    def get_key(self, key_id: str) -> VerifierKey | None:
        self.refresh()
        return self._keys.get(key_id)

    def verify_signature_value(
        self,
        *,
        key_id: str,
        report_with_empty_signature: dict[str, Any],
        signature_value: str,
    ) -> str | None:
        self.refresh()
        return self._provider.verify_signature_value(
            key_id=key_id,
            report_with_empty_signature=report_with_empty_signature,
            signature_value=signature_value,
        )


def s8_checkpoint_signature_payload(*, sequence: int, root: str, signer_key_id: str) -> str:
    return (
        "argus-s8-merkle-checkpoint-v1\n"
        "algorithm:hmac-sha256\n"
        f"seq:{sequence}\n"
        f"root:{root}\n"
        f"signer_key_id:{signer_key_id}\n"
    )


def token_signature_payload(token: BudgetToken | ScopeToken) -> bytes:
    payload = asdict(token)
    payload["signature"] = ""
    return canonical_json_bytes(payload)


def price_table_signature_payload(table: PriceTable) -> bytes:
    return canonical_json_bytes(_price_table_payload(replace(table, signature="")))


def price_table_content_hash(table: PriceTable) -> str:
    return hash_json(_price_table_payload(table))


def roll_up_price_table_usage(
    usage: BudgetUsage,
    table: PriceTable,
    *,
    gpu_model: str = "default",
    model_id: str = "default",
) -> PriceTableRollup:
    cost = _price_table_cost_usd(usage, table, gpu_model=gpu_model, model_id=model_id)
    exact = _decimal_wire(cost)
    priced_usage = replace(usage, cost_usd=float(cost))
    return PriceTableRollup(
        usage=priced_usage,
        cost_usd_exact=exact,
        price_table_hash=price_table_content_hash(table),
        price_table_version=table.price_table_version,
        signer_key_id=table.signer_key_id,
        gpu_model=gpu_model,
        model_id=model_id,
    )


def _price_table_signature(table: PriceTable, signing_key: bytes) -> str:
    digest = hmac.new(signing_key, price_table_signature_payload(table), sha256).hexdigest()
    return f"{SIGNATURE_PREFIX}{digest}"


def _price_table_payload(table: PriceTable) -> dict[str, Any]:
    return {
        "price_table_version": table.price_table_version,
        "usd_per_cpu_second": _decimal_wire(_decimal(table.usd_per_cpu_second)),
        "usd_per_gpu_second": {
            key: _decimal_wire(_decimal(value)) for key, value in sorted(table.usd_per_gpu_second.items())
        },
        "usd_per_1k_model_tokens": {
            key: _decimal_wire(_decimal(value)) for key, value in sorted(table.usd_per_1k_model_tokens.items())
        },
        "issued_at": int(table.issued_at),
        "expires_at": int(table.expires_at),
        "signer_key_id": table.signer_key_id,
        "signature": table.signature,
    }


def _price_table_cost_usd(
    usage: BudgetUsage,
    table: PriceTable,
    *,
    gpu_model: str,
    model_id: str,
) -> Decimal:
    cpu_cost = _decimal(usage.compute_units) * _decimal(table.usd_per_cpu_second)
    gpu_rate = _price_table_rate(table.usd_per_gpu_second, gpu_model, "gpu", usage.gpu_seconds)
    token_rate = _price_table_rate(table.usd_per_1k_model_tokens, model_id, "model tokens", usage.model_tokens)
    gpu_cost = _decimal(usage.gpu_seconds) * gpu_rate
    token_cost = (_decimal(usage.model_tokens) / Decimal("1000")) * token_rate
    return cpu_cost + gpu_cost + token_cost


def _price_table_rate(rates: Mapping[str, str], key: str, dimension: str, amount: float) -> Decimal:
    if key in rates:
        return _decimal(rates[key])
    if "default" in rates:
        return _decimal(rates["default"])
    if amount > 0:
        raise PriceTableSignatureError(f"price table missing {dimension} rate for {key}")
    return Decimal("0")


def _decimal(value: Decimal | int | float | str) -> Decimal:
    return value if isinstance(value, Decimal) else Decimal(str(value))


def _decimal_wire(value: Decimal) -> str:
    normalized = value.normalize()
    if normalized == normalized.to_integral():
        return format(normalized.quantize(Decimal("1")), "f")
    return format(normalized, "f")


class InMemoryTokenRevocationStore:
    """Process-local token revocation store."""

    kind = "memory"

    def __init__(self, revoked_ids: tuple[str, ...] = ()) -> None:
        self._revoked_ids = set(revoked_ids)

    def revoke(self, token_id: str) -> None:
        self._revoked_ids.add(_validate_token_id(token_id))

    def is_revoked(self, token_id: str) -> bool:
        return _validate_token_id(token_id) in self._revoked_ids

    def snapshot(self) -> tuple[str, ...]:
        return tuple(sorted(self._revoked_ids))


class FileTokenRevocationStore:
    """Append-only JSONL token revocation store shared by token-service instances."""

    kind = "file"

    def __init__(self, path: str | os.PathLike[str], *, now_fn: Callable[[], int] | None = None) -> None:
        self._path = os.fspath(path)
        self._now_fn = now_fn or (lambda: int(time.time()))
        os.makedirs(os.path.dirname(os.path.abspath(self._path)), exist_ok=True)

    @property
    def path(self) -> str:
        return self._path

    def revoke(self, token_id: str) -> None:
        token_id = _validate_token_id(token_id)
        if self.is_revoked(token_id):
            return
        entry = {"token_id": token_id, "revoked_at": self._now_fn()}
        with open(self._path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")

    def is_revoked(self, token_id: str) -> bool:
        return _validate_token_id(token_id) in self._load_revoked_ids()

    def snapshot(self) -> tuple[str, ...]:
        return tuple(sorted(self._load_revoked_ids()))

    def _load_revoked_ids(self) -> set[str]:
        if not os.path.exists(self._path):
            return set()
        revoked: set[str] = set()
        with open(self._path, encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid token revocation entry at line {line_number}") from exc
                token_id = entry.get("token_id") if isinstance(entry, dict) else None
                if not isinstance(token_id, str) or not token_id:
                    raise ValueError(f"invalid token revocation token_id at line {line_number}")
                revoked.add(token_id)
        return revoked


class HmacTokenSigner:
    """Local HMAC token signer kept for compatibility with existing tests and baselines."""

    algorithm = "hmac-sha256"
    kind = "local-hmac"

    def __init__(self, *, signer_key_id: str, signing_key: bytes) -> None:
        if not signer_key_id:
            raise ValueError("signer_key_id is required")
        if not signing_key:
            raise ValueError("token signing key is required")
        self.signer_key_id = signer_key_id
        self._signing_key = bytes(signing_key)

    def sign(self, token: BudgetToken | ScopeToken) -> str:
        digest = hmac.new(self._signing_key, token_signature_payload(token), sha256).hexdigest()
        return f"{SIGNATURE_PREFIX}{digest}"

    def trust_store(self) -> "TokenSignatureTrustStore":
        return TokenSignatureTrustStore(hmac_keys={self.signer_key_id: self._signing_key})


class Ed25519KmsTokenSigner:
    """KMS-style Ed25519 token signer that exposes only public verification material."""

    algorithm = "ed25519"
    kind = "s10-kms-ed25519"

    def __init__(self, *, signer_key_id: str, private_key_bytes: bytes) -> None:
        if not signer_key_id:
            raise ValueError("signer_key_id is required")
        if len(private_key_bytes) != 32:
            raise ValueError("Ed25519 private key must be 32 raw bytes")
        self.signer_key_id = signer_key_id
        self._private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        self.public_key_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, token: BudgetToken | ScopeToken) -> str:
        signature = self._private_key.sign(token_signature_payload(token))
        return f"{TOKEN_ED25519_SIGNATURE_PREFIX}{signature.hex()}"

    def trust_store(self) -> "TokenSignatureTrustStore":
        return TokenSignatureTrustStore(ed25519_public_keys={self.signer_key_id: self.public_key_bytes})


class TokenSignatureTrustStore:
    """Offline verifier for S10 token signatures."""

    def __init__(
        self,
        *,
        hmac_keys: dict[str, bytes] | None = None,
        ed25519_public_keys: dict[str, bytes] | None = None,
    ) -> None:
        self._hmac_keys = {key_id: bytes(value) for key_id, value in (hmac_keys or {}).items()}
        self._ed25519_public_keys = {
            key_id: Ed25519PublicKey.from_public_bytes(bytes(value))
            for key_id, value in (ed25519_public_keys or {}).items()
        }
        if self._ed25519_public_keys and not self._hmac_keys:
            self.kind = "offline-ed25519-public"
        elif self._ed25519_public_keys and self._hmac_keys:
            self.kind = "offline-mixed"
        else:
            self.kind = "shared-secret-hmac"

    def verify(self, token: BudgetToken | ScopeToken) -> TokenVerification:
        if token.signature.startswith(SIGNATURE_PREFIX):
            return self._verify_hmac(token)
        if token.signature.startswith(TOKEN_ED25519_SIGNATURE_PREFIX):
            return self._verify_ed25519(token)
        return TokenVerification(valid=False, reason="signature_invalid")

    def _verify_hmac(self, token: BudgetToken | ScopeToken) -> TokenVerification:
        signing_key = self._hmac_keys.get(token.signer_key_id)
        if signing_key is None:
            return TokenVerification(valid=False, reason="unknown_signer")
        signature_hex = token.signature.removeprefix(SIGNATURE_PREFIX)
        if _lower_hex_to_bytes(signature_hex, expected_bytes=32) is None:
            return TokenVerification(valid=False, reason="signature_invalid")
        digest = hmac.new(signing_key, token_signature_payload(token), sha256).hexdigest()
        expected = f"{SIGNATURE_PREFIX}{digest}"
        if not hmac.compare_digest(token.signature, expected):
            return TokenVerification(valid=False, reason="signature_invalid")
        return TokenVerification(valid=True)

    def _verify_ed25519(self, token: BudgetToken | ScopeToken) -> TokenVerification:
        public_key = self._ed25519_public_keys.get(token.signer_key_id)
        if public_key is None:
            return TokenVerification(valid=False, reason="unknown_signer")
        signature = _lower_hex_to_bytes(
            token.signature.removeprefix(TOKEN_ED25519_SIGNATURE_PREFIX),
            expected_bytes=64,
        )
        if signature is None:
            return TokenVerification(valid=False, reason="signature_invalid")
        try:
            public_key.verify(signature, token_signature_payload(token))
        except InvalidSignature:
            return TokenVerification(valid=False, reason="signature_invalid")
        return TokenVerification(valid=True)


class OfflineTokenVerifier:
    """Full S10 token verifier that does not hold minting or private signing material."""

    def __init__(
        self,
        *,
        verifier: TokenSignatureTrustStore,
        revocation_store: InMemoryTokenRevocationStore | FileTokenRevocationStore | None = None,
        now_fn: Callable[[], int] | None = None,
    ) -> None:
        self._verifier = verifier
        self._revocation_store = revocation_store or InMemoryTokenRevocationStore()
        self._now_fn = now_fn or (lambda: int(time.time()))

    @property
    def verifier_kind(self) -> str:
        return self._verifier.kind

    @property
    def revocation_store_kind(self) -> str:
        return self._revocation_store.kind

    def verify_budget(self, token: BudgetToken) -> TokenVerification:
        return _verify_token_common(
            token=token,
            token_id=token.budget_id,
            verifier=self._verifier,
            revocation_store=self._revocation_store,
            now_fn=self._now_fn,
        )

    def verify_scope(self, token: ScopeToken) -> TokenVerification:
        return _verify_token_common(
            token=token,
            token_id=token.scope_id,
            verifier=self._verifier,
            revocation_store=self._revocation_store,
            now_fn=self._now_fn,
        )


def _validate_token_id(token_id: str) -> str:
    if not isinstance(token_id, str) or not token_id or "\n" in token_id:
        raise ValueError("token_id must be a non-empty single-line string")
    return token_id


def _lower_hex_to_bytes(value: str, *, expected_bytes: int) -> bytes | None:
    expected_len = expected_bytes * 2
    if len(value) != expected_len:
        return None
    if any(char not in "0123456789abcdef" for char in value):
        return None
    return bytes.fromhex(value)


def _verify_token_common(
    *,
    token: BudgetToken | ScopeToken,
    token_id: str,
    verifier: TokenSignatureTrustStore,
    revocation_store: InMemoryTokenRevocationStore | FileTokenRevocationStore,
    now_fn: Callable[[], int],
) -> TokenVerification:
    try:
        revoked = revocation_store.is_revoked(token_id)
    except (OSError, ValueError):
        return TokenVerification(valid=False, reason="revocation_store_unavailable")
    if revoked:
        return TokenVerification(valid=False, reason="revoked")
    if token.expires_at <= now_fn():
        return TokenVerification(valid=False, reason="expired")
    return verifier.verify(token)


class InMemoryTokenService:
    """Signed token service with attenuation and revocation semantics."""

    def __init__(
        self,
        *,
        signing_key: bytes | None = None,
        signer_key_id: str = "s10-test-key",
        signer: HmacTokenSigner | Ed25519KmsTokenSigner | None = None,
        verifier: TokenSignatureTrustStore | None = None,
        revocation_store: InMemoryTokenRevocationStore | FileTokenRevocationStore | None = None,
        now_fn: Callable[[], int] | None = None,
        monotonic_fn: Callable[[], float] | None = None,
    ) -> None:
        if signer is not None and signing_key is not None:
            raise ValueError("configure either signing_key or signer, not both")
        if signer is None:
            if signing_key is None:
                raise ValueError("signing_key or signer is required")
            signer = HmacTokenSigner(signer_key_id=signer_key_id, signing_key=signing_key)
        self._signer = signer
        self._verifier = verifier or signer.trust_store()
        self._revocation_store = revocation_store or InMemoryTokenRevocationStore()
        self._now_fn = now_fn or (lambda: int(time.time()))
        self._monotonic_fn = monotonic_fn or time.monotonic
        self._revocation_acknowledgements: dict[str, float] = {}
        self._revocation_acknowledgements_lock = threading.Lock()
        self.minting_enabled = True

    @property
    def signer_key_id(self) -> str:
        return self._signer.signer_key_id

    @property
    def signer_kind(self) -> str:
        return self._signer.kind

    @property
    def signature_algorithm(self) -> str:
        return self._signer.algorithm

    @property
    def verifier_kind(self) -> str:
        return self._verifier.kind

    @property
    def revocation_store_kind(self) -> str:
        return self._revocation_store.kind

    def mint_budget(
        self,
        *,
        caps: BudgetCaps,
        job_id: str,
        root_request_id: str,
        risk_class: str = "standard",
        ttl_s: int = 900,
        parent: BudgetToken | None = None,
    ) -> BudgetToken:
        self._assert_minting_enabled()
        if parent is not None:
            self._require_valid_budget(parent)
            self._assert_caps_subset(caps, parent.caps)
        issued_at = self._now()
        unsigned = BudgetToken(
            budget_id=str(uuid4()),
            job_id=job_id,
            root_request_id=root_request_id,
            budget_epoch=1,
            caps=caps,
            risk_class=risk_class,
            issued_at=issued_at,
            expires_at=issued_at + ttl_s,
            ttl_s=ttl_s,
            parent_budget_id=parent.budget_id if parent else None,
            signer_key_id=self.signer_key_id,
            signature="",
        )
        return replace(unsigned, signature=self._sign_token(unsigned))

    def mint_scope(
        self,
        *,
        scopes: ScopeGrant,
        job_id: str,
        ttl_s: int = 900,
        parent: ScopeToken | None = None,
    ) -> ScopeToken:
        self._assert_minting_enabled()
        if parent is not None:
            self._require_valid_scope(parent)
            self._assert_scope_subset(scopes, parent.scopes)
        issued_at = self._now()
        unsigned = ScopeToken(
            scope_id=str(uuid4()),
            job_id=job_id,
            scopes=scopes,
            issued_at=issued_at,
            expires_at=issued_at + ttl_s,
            ttl_s=ttl_s,
            parent_scope_id=parent.scope_id if parent else None,
            signer_key_id=self.signer_key_id,
            signature="",
        )
        return replace(unsigned, signature=self._sign_token(unsigned))

    def attenuate_budget(self, parent: BudgetToken, caps: BudgetCaps) -> BudgetToken:
        return self.mint_budget(
            caps=caps,
            job_id=parent.job_id,
            root_request_id=parent.root_request_id,
            risk_class=parent.risk_class,
            ttl_s=min(parent.ttl_s, max(parent.expires_at - self._now(), 0)),
            parent=parent,
        )

    def attenuate_scope(self, parent: ScopeToken, scopes: ScopeGrant) -> ScopeToken:
        return self.mint_scope(
            scopes=scopes,
            job_id=parent.job_id,
            ttl_s=min(parent.ttl_s, max(parent.expires_at - self._now(), 0)),
            parent=parent,
        )

    def verify_budget(self, token: BudgetToken) -> TokenVerification:
        return self._verify_token(token, token.budget_id)

    def verify_scope(self, token: ScopeToken) -> TokenVerification:
        return self._verify_token(token, token.scope_id)

    def revoke(self, token_id: str) -> float:
        token_id = _validate_token_id(token_id)
        self._revocation_store.revoke(token_id)
        acknowledged_at = self._monotonic_fn()
        with self._revocation_acknowledgements_lock:
            self._revocation_acknowledgements[token_id] = acknowledged_at
            while len(self._revocation_acknowledgements) > 4_096:
                self._revocation_acknowledgements.pop(next(iter(self._revocation_acknowledgements)))
        return acknowledged_at

    def revocation_acknowledged_at(self, token_id: str) -> float | None:
        token_id = _validate_token_id(token_id)
        with self._revocation_acknowledgements_lock:
            return self._revocation_acknowledgements.get(token_id)

    def _require_valid_budget(self, token: BudgetToken) -> None:
        verification = self.verify_budget(token)
        if not verification.valid:
            raise TokenInvalidError(verification.reason or "invalid budget token")

    def _require_valid_scope(self, token: ScopeToken) -> None:
        verification = self.verify_scope(token)
        if not verification.valid:
            raise TokenInvalidError(verification.reason or "invalid scope token")

    def _verify_token(self, token: BudgetToken | ScopeToken, token_id: str) -> TokenVerification:
        return _verify_token_common(
            token=token,
            token_id=token_id,
            verifier=self._verifier,
            revocation_store=self._revocation_store,
            now_fn=self._now,
        )

    def _sign_token(self, token: BudgetToken | ScopeToken) -> str:
        return self._signer.sign(token)

    def _assert_minting_enabled(self) -> None:
        if not self.minting_enabled:
            raise TokenMintUnavailableError("token minting is unavailable")

    @staticmethod
    def _assert_caps_subset(child: BudgetCaps, parent: BudgetCaps) -> None:
        for child_value, parent_value in zip(asdict(child).values(), asdict(parent).values()):
            if child_value > parent_value:
                raise ScopeWideningError("attenuated budget cannot widen caps")

    @staticmethod
    def _assert_scope_subset(child: ScopeGrant, parent: ScopeGrant) -> None:
        if set(child.allowed_adapters) - set(parent.allowed_adapters):
            raise ScopeWideningError("attenuated scope cannot add adapters")
        if set(child.allowed_datasets) - set(parent.allowed_datasets):
            raise ScopeWideningError("attenuated scope cannot add datasets")
        if set(child.egress_allowlist) - set(parent.egress_allowlist):
            raise ScopeWideningError("attenuated scope cannot add egress")
        if set(child.broker_audiences) - set(parent.broker_audiences):
            raise ScopeWideningError("attenuated scope cannot add broker audiences")
        if set(child.capabilities) - set(parent.capabilities):
            raise ScopeWideningError("attenuated scope cannot add capabilities")
        if set(child.producer_subsystems) - set(parent.producer_subsystems):
            raise ScopeWideningError("attenuated scope cannot add producer subsystems")
        if child.sandbox_risk_class != parent.sandbox_risk_class:
            raise ScopeWideningError("attenuated scope cannot change risk class")
        if set(parent.disallowed_actions) - set(child.disallowed_actions):
            raise ScopeWideningError("attenuated scope cannot remove disallowed actions")

    def _now(self) -> int:
        return self._now_fn()


class InMemoryQuotaLedger:
    """Reserve, consume, and release budget dimensions without negative remaining."""

    kind = "memory"

    def __init__(self) -> None:
        self._states: dict[str, QuotaState] = {}
        self._lock = threading.RLock()

    def register_budget(self, token: BudgetToken) -> None:
        with self._lock:
            self._states.setdefault(
                token.budget_id,
                QuotaState(caps=token.caps, reserved=BudgetUsage(), actual=BudgetUsage()),
            )

    def reserve(self, budget_id: str, usage: BudgetUsage) -> None:
        with self._lock:
            state = self._require_state(budget_id)
            self._assert_not_halted(budget_id, state)
            next_reserved = self._add_usage(state.reserved, usage)
            self._assert_within_caps(state.caps, next_reserved, state.actual, budget_id)
            self._states[budget_id] = replace(state, reserved=next_reserved)

    def consume(self, budget_id: str, usage: BudgetUsage) -> None:
        with self._lock:
            state = self._require_state(budget_id)
            self._assert_not_halted(budget_id, state)
            next_actual = self._add_usage(state.actual, usage)
            try:
                self._assert_actual_within_caps(state.caps, next_actual)
            except BudgetExceededError:
                self._states[budget_id] = replace(state, actual=next_actual, halted=True)
                raise
            self._states[budget_id] = replace(state, actual=next_actual)

    def halt(self, budget_id: str, *, reason: str) -> None:
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("quota halt reason is required")
        with self._lock:
            state = self._require_state(budget_id)
            self._states[budget_id] = replace(state, halted=True)

    def release(self, budget_id: str, usage: BudgetUsage | None = None) -> None:
        with self._lock:
            state = self._require_state(budget_id)
            released = usage or state.reserved
            self._states[budget_id] = replace(state, reserved=self._subtract_usage(state.reserved, released))

    def remaining(self, budget_id: str) -> BudgetUsage:
        with self._lock:
            state = self._require_state(budget_id)
            return self._subtract_usage(
                self._caps_to_usage(state.caps),
                self._add_usage(state.reserved, state.actual),
            )

    def state(self, budget_id: str) -> QuotaState:
        with self._lock:
            return self._require_state(budget_id)

    def _require_state(self, budget_id: str) -> QuotaState:
        if budget_id not in self._states:
            raise KeyError(f"unknown budget_id: {budget_id}")
        return self._states[budget_id]

    @staticmethod
    def _assert_not_halted(budget_id: str, state: QuotaState) -> None:
        if state.halted:
            raise BudgetExceededError(f"budget is halted: {budget_id}")

    @classmethod
    def _assert_within_caps(
        cls,
        caps: BudgetCaps,
        reserved: BudgetUsage,
        actual: BudgetUsage,
        budget_id: str,
    ) -> None:
        try:
            cls._assert_actual_within_caps(caps, cls._add_usage(reserved, actual))
        except BudgetExceededError as exc:
            raise BudgetExceededError(f"budget exceeded for {budget_id}") from exc

    @staticmethod
    def _assert_actual_within_caps(caps: BudgetCaps, usage: BudgetUsage) -> None:
        usage_values = asdict(usage)
        cap_values = {
            "compute_units": caps.max_compute_units,
            "gpu_seconds": caps.max_gpu_seconds,
            "model_tokens": caps.max_model_tokens,
            "wallclock_s": caps.max_wallclock_s,
            "cost_usd": caps.max_cost_usd,
        }
        for field, value in usage_values.items():
            if value < 0:
                raise BudgetExceededError(f"negative budget dimension: {field}")
            if value > cap_values[field]:
                raise BudgetExceededError(f"budget dimension exceeded: {field}")

    @staticmethod
    def _add_usage(left: BudgetUsage, right: BudgetUsage) -> BudgetUsage:
        return BudgetUsage(**{field: getattr(left, field) + getattr(right, field) for field in asdict(left)})

    @staticmethod
    def _subtract_usage(left: BudgetUsage, right: BudgetUsage) -> BudgetUsage:
        return BudgetUsage(
            **{field: max(getattr(left, field) - getattr(right, field), 0.0) for field in asdict(left)}
        )

    @staticmethod
    def _caps_to_usage(caps: BudgetCaps) -> BudgetUsage:
        return BudgetUsage(
            compute_units=caps.max_compute_units,
            gpu_seconds=caps.max_gpu_seconds,
            model_tokens=caps.max_model_tokens,
            wallclock_s=caps.max_wallclock_s,
            cost_usd=caps.max_cost_usd,
        )


def decide_policy(bundle: PolicyBundle, request: LaunchRequest) -> PolicyVerdict:
    """Pure S10 policy decision: no clock, IO, randomness, or mutation."""
    ceiling_violations = _policy_ceiling_violations(bundle, request)
    if ceiling_violations:
        return PolicyVerdict(False, None, (), ceiling_violations[0])
    if request.scope_token.scopes.sandbox_risk_class != request.budget_token.risk_class:
        return PolicyVerdict(False, None, (), "risk_class_mismatch")

    runtime_class = bundle.risk_to_runtime.get(request.scope_token.scopes.sandbox_risk_class)
    if runtime_class is None:
        return PolicyVerdict(False, None, (), "risk_class_unsupported")
    if request.runtime_class_hint != "auto":
        if request.runtime_class_hint != runtime_class:
            return PolicyVerdict(False, None, (), "runtime_class_hint_mismatch")

    egress_acl = tuple(
        sorted(
            set(request.scope_token.scopes.egress_allowlist) & set(bundle.egress_allowlist),
            key=lambda rule: (rule.host, rule.port, rule.proto),
        )
    )
    return PolicyVerdict(True, runtime_class, egress_acl)


def _policy_ceiling_violations(bundle: PolicyBundle, request: LaunchRequest) -> tuple[str, ...]:
    envelope = request.requested_envelope
    ceilings = bundle.resource_ceilings
    violations: list[str] = []
    if envelope.cpu_m > ceilings.cpu_m:
        violations.append("cpu_ceiling")
    if envelope.mem_bytes > ceilings.mem_bytes:
        violations.append("memory_ceiling")
    if envelope.gpu_count > ceilings.gpu_count:
        violations.append("gpu_ceiling")
    if envelope.wallclock_s > ceilings.wallclock_s:
        violations.append("wallclock_ceiling")
    if not math.isfinite(ceilings.max_cost_usd) or ceilings.max_cost_usd < 0:
        violations.append("cost_ceiling_invalid")
    elif not math.isfinite(envelope.estimated_cost_usd) or envelope.estimated_cost_usd < 0:
        violations.append("cost_estimate_invalid")
    elif envelope.estimated_cost_usd > ceilings.max_cost_usd:
        violations.append("cost_ceiling")
    return tuple(violations)


def _policy_ceiling_reject_payload(
    bundle: PolicyBundle,
    request: LaunchRequest,
    violations: tuple[str, ...],
) -> dict[str, Any]:
    requested_envelope = asdict(request.requested_envelope)
    resource_ceilings = asdict(bundle.resource_ceilings)
    requested_envelope["estimated_cost_usd"] = _json_safe_float(request.requested_envelope.estimated_cost_usd)
    resource_ceilings["max_cost_usd"] = _json_safe_float(bundle.resource_ceilings.max_cost_usd)
    return {
        "job_id": request.job_id,
        "within_ceiling": False,
        "violations": list(violations),
        "requested_envelope": requested_envelope,
        "resource_ceilings": resource_ceilings,
        "policy_bundle_version": bundle.bundle_version,
    }


def _json_safe_float(value: float) -> float | str:
    if math.isnan(value):
        return "nan"
    if value == math.inf:
        return "infinity"
    if value == -math.inf:
        return "-infinity"
    return value


def materialize_sandbox_env(env: dict[str, str], env_allowlist: tuple[str, ...]) -> dict[str, str]:
    """Return allowlisted env values, failing closed on secret-shaped material."""
    allowed_keys = set(env_allowlist)
    materialized: dict[str, str] = {}
    for key, value in env.items():
        if key not in allowed_keys:
            continue
        if _looks_secret_shaped(value):
            raise PolicyDeniedError(f"secret-shaped env value rejected for {key}")
        materialized[key] = value
    return materialized


def _looks_secret_shaped(value: str) -> bool:
    return any(pattern.search(value) for pattern in SECRET_VALUE_PATTERNS)


def _is_digest_pinned_image(image: str) -> bool:
    return DIGEST_PINNED_IMAGE.match(image) is not None


def _runtime_budget_usage(envelope: LaunchEnvelope, duration_s: float) -> BudgetUsage:
    bounded_wallclock_s = max(duration_s, 0.0)
    wallclock_ratio = bounded_wallclock_s / envelope.wallclock_s if envelope.wallclock_s > 0 else 1.0
    return BudgetUsage(
        compute_units=(envelope.cpu_m / 1000.0) * bounded_wallclock_s,
        gpu_seconds=envelope.gpu_count * bounded_wallclock_s,
        wallclock_s=bounded_wallclock_s,
        cost_usd=envelope.estimated_cost_usd * wallclock_ratio,
    )


def _max_budget_usage(left: BudgetUsage, right: BudgetUsage) -> BudgetUsage:
    return BudgetUsage(**{field: max(getattr(left, field), getattr(right, field)) for field in asdict(left)})


def _budget_usage_breach_dimensions(caps: BudgetCaps, usage: BudgetUsage) -> tuple[str, ...]:
    cap_values = {
        "compute_units": caps.max_compute_units,
        "gpu_seconds": caps.max_gpu_seconds,
        "model_tokens": caps.max_model_tokens,
        "wallclock_s": caps.max_wallclock_s,
        "cost_usd": caps.max_cost_usd,
    }
    breached: list[str] = []
    for field, value in asdict(usage).items():
        if value > cap_values[field]:
            breached.append(field)
    return tuple(breached)


def _token_runtime_halt(*, reason: str | None, token_dimension: str) -> tuple[str, tuple[str, ...]]:
    halt_reason = "token_revoked" if reason == "revoked" else "token_invalid"
    return halt_reason, (halt_reason, token_dimension)


def _merge_breach_dimensions(*groups: Iterable[str]) -> tuple[str, ...]:
    merged: list[str] = []
    for group in groups:
        for dimension in group:
            if dimension not in merged:
                merged.append(dimension)
    return tuple(merged)


def _run_gpu_telemetry_command(args: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        check=False,
        capture_output=True,
        text=True,
        timeout=2,
    )


def _safe_gpu_probe_error(value: str) -> str:
    return " ".join(value.strip().split())[:240]


def _parse_nvidia_smi_l(output: str) -> tuple[int, tuple[str, ...], int]:
    gpu_models: list[str] = []
    mig_instance_count = 0
    for line in output.splitlines():
        gpu_match = re.match(r"^GPU\s+\d+:\s*(.+?)(?:\s+\(UUID:.*)?$", line.strip())
        if gpu_match:
            gpu_models.append(gpu_match.group(1).strip())
            continue
        if re.match(r"^\s*MIG\s+.+Device\s+\d+:", line):
            mig_instance_count += 1
    return len(gpu_models), tuple(gpu_models), mig_instance_count


def discover_gpu_telemetry(
    *,
    command_runner: Callable[[tuple[str, ...]], subprocess.CompletedProcess[str]] | None = None,
    command_exists: Callable[[str], bool] | None = None,
) -> GpuTelemetrySnapshot:
    runner = command_runner or _run_gpu_telemetry_command
    exists = command_exists or (lambda command: shutil.which(command) is not None)
    sources: list[str] = []
    errors: list[str] = []
    dcgm_probe_ok = False
    nvidia_smi_available = False
    gpu_count = 0
    gpu_models: tuple[str, ...] = ()
    mig_instance_count = 0

    if exists("dcgmi"):
        sources.append("dcgmi")
        try:
            dcgm = runner(("dcgmi", "discovery", "-l"))
            dcgm_probe_ok = dcgm.returncode == 0
            if dcgm.returncode != 0:
                errors.append(f"dcgmi:{_safe_gpu_probe_error(dcgm.stderr or dcgm.stdout)}")
        except (FileNotFoundError, subprocess.TimeoutExpired, TimeoutError) as exc:
            errors.append(f"dcgmi:{type(exc).__name__}")

    if exists("nvidia-smi"):
        sources.append("nvidia-smi")
        try:
            nvidia = runner(("nvidia-smi", "-L"))
            nvidia_smi_available = nvidia.returncode == 0
            if nvidia.returncode == 0:
                gpu_count, gpu_models, mig_instance_count = _parse_nvidia_smi_l(nvidia.stdout or "")
            else:
                errors.append(f"nvidia-smi:{_safe_gpu_probe_error(nvidia.stderr or nvidia.stdout)}")
        except (FileNotFoundError, subprocess.TimeoutExpired, TimeoutError) as exc:
            errors.append(f"nvidia-smi:{type(exc).__name__}")

    return GpuTelemetrySnapshot(
        dcgm_available=dcgm_probe_ok and gpu_count > 0,
        nvidia_smi_available=nvidia_smi_available,
        gpu_count=gpu_count,
        gpu_models=gpu_models,
        mig_enabled=mig_instance_count > 0,
        mig_instance_count=mig_instance_count,
        source="+".join(sources) if sources else "unavailable",
        error="; ".join(error for error in errors if error),
    )


DCGM_DMON_METRIC_FIELDS: tuple[str, ...] = ("1001", "1004", "1005")
DCGM_DMON_METRIC_SOURCE = "dcgmi-dmon"


def _parse_dcgm_metric_value(value: str) -> float | None:
    normalized = value.strip()
    if not normalized or normalized.upper() in {"N/A", "NA", "NOT_SUPPORTED", "-"}:
        return None
    try:
        return float(normalized)
    except ValueError:
        return None


def _parse_dcgm_dmon_output(output: str) -> tuple[DcgmMetricRow, ...]:
    rows: list[DcgmMetricRow] = []
    header_fields: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            parts = stripped.lstrip("#").split()
            header_fields = [part for part in parts if part not in {"Entity", "Id"}]
            continue
        if stripped == "Id":
            continue
        metric_fields = header_fields or ["GRACT", "TENSO", "DRAMA"]
        parts = stripped.split()
        metric_count = len(metric_fields)
        if len(parts) <= metric_count:
            continue
        entity_tokens = parts[: len(parts) - metric_count]
        if len(entity_tokens) < 2:
            continue
        metric_values = parts[-metric_count:]
        parsed = {
            field: _parse_dcgm_metric_value(value)
            for field, value in zip(metric_fields, metric_values, strict=False)
        }
        rows.append(
            DcgmMetricRow(
                entity=entity_tokens[0],
                entity_id=" ".join(entity_tokens[1:]),
                gr_engine_active=parsed.get("GRACT"),
                tensor_active=parsed.get("TENSO"),
                dram_active=parsed.get("DRAMA"),
            )
        )
    return tuple(rows)


def collect_dcgm_metric_sample(
    *,
    command_runner: Callable[[tuple[str, ...]], subprocess.CompletedProcess[str]] | None = None,
    command_exists: Callable[[str], bool] | None = None,
    gpu_telemetry: GpuTelemetrySnapshot | None = None,
) -> DcgmMetricSnapshot:
    runner = command_runner or _run_gpu_telemetry_command
    exists = command_exists or (lambda command: shutil.which(command) is not None)
    if gpu_telemetry is not None and not gpu_telemetry.dcgm_available:
        return DcgmMetricSnapshot(source="unavailable")
    if not exists("dcgmi"):
        return DcgmMetricSnapshot(source="unavailable", error="dcgmi:not_found")

    command = ("dcgmi", "dmon", "-e", ",".join(DCGM_DMON_METRIC_FIELDS), "-c", "1")
    try:
        result = runner(command)
    except (FileNotFoundError, subprocess.TimeoutExpired, TimeoutError) as exc:
        return DcgmMetricSnapshot(
            source=DCGM_DMON_METRIC_SOURCE,
            error=f"{DCGM_DMON_METRIC_SOURCE}:{type(exc).__name__}",
        )
    if result.returncode != 0:
        return DcgmMetricSnapshot(
            source=DCGM_DMON_METRIC_SOURCE,
            error=f"{DCGM_DMON_METRIC_SOURCE}:{_safe_gpu_probe_error(result.stderr or result.stdout)}",
        )
    rows = _parse_dcgm_dmon_output(result.stdout or "")
    return DcgmMetricSnapshot(
        available=bool(rows),
        source=DCGM_DMON_METRIC_SOURCE,
        rows=rows,
        error="" if rows else f"{DCGM_DMON_METRIC_SOURCE}:no_rows",
    )


def _dcgm_metric_row_payload(row: DcgmMetricRow) -> dict[str, Any]:
    return {
        "entity": row.entity,
        "entity_id": row.entity_id,
        "gr_engine_active": None if row.gr_engine_active is None else round(row.gr_engine_active, 6),
        "tensor_active": None if row.tensor_active is None else round(row.tensor_active, 6),
        "dram_active": None if row.dram_active is None else round(row.dram_active, 6),
    }


def _resource_meter_sample_payload(sample: ResourceMeterSample) -> dict[str, Any]:
    return {
        "sample_seq": sample.sample_seq,
        "elapsed_s": round(sample.elapsed_s, 6),
        "cadence_s": round(sample.cadence_s, 6),
        "usage": asdict(sample.usage),
        "memory_bytes": sample.memory_bytes,
        "source": sample.source,
        "dcgm_available": sample.dcgm_available,
        "nvidia_smi_available": sample.nvidia_smi_available,
        "gpu_count": sample.gpu_count,
        "gpu_models": list(sample.gpu_models),
        "mig_enabled": sample.mig_enabled,
        "mig_instance_count": sample.mig_instance_count,
        "gpu_telemetry_source": sample.gpu_telemetry_source,
        "gpu_telemetry_error": sample.gpu_telemetry_error,
        "dcgm_metrics_available": sample.dcgm_metrics_available,
        "dcgm_metric_source": sample.dcgm_metric_source,
        "dcgm_metric_error": sample.dcgm_metric_error,
        "dcgm_metric_row_count": len(sample.dcgm_metric_rows),
        "dcgm_gr_engine_active": round(sample.dcgm_gr_engine_active, 6),
        "dcgm_tensor_active": round(sample.dcgm_tensor_active, 6),
        "dcgm_dram_active": round(sample.dcgm_dram_active, 6),
        "dcgm_metric_rows": [_dcgm_metric_row_payload(row) for row in sample.dcgm_metric_rows],
        "breached_dimensions": list(sample.breached_dimensions),
        "halted": sample.halted,
        "conservative_gap_s": round(sample.conservative_gap_s, 6),
    }


def _sandbox_halt_telemetry_payload(telemetry: SandboxHaltTelemetry) -> dict[str, Any]:
    return {
        "reason": telemetry.reason,
        "halt_detected_elapsed_s": round(telemetry.halt_detected_elapsed_s, 6),
        "freeze_completed_elapsed_s": (
            round(telemetry.freeze_completed_elapsed_s, 6)
            if telemetry.freeze_completed_elapsed_s is not None
            else None
        ),
        "terminate_completed_elapsed_s": (
            round(telemetry.terminate_completed_elapsed_s, 6)
            if telemetry.terminate_completed_elapsed_s is not None
            else None
        ),
        "revocation_ack_to_detect_s": (
            round(telemetry.revocation_ack_to_detect_s, 6)
            if telemetry.revocation_ack_to_detect_s is not None
            else None
        ),
        "revocation_ack_to_freeze_s": (
            round(telemetry.revocation_ack_to_freeze_s, 6)
            if telemetry.revocation_ack_to_freeze_s is not None
            else None
        ),
        "revocation_ack_to_terminate_s": (
            round(telemetry.revocation_ack_to_terminate_s, 6)
            if telemetry.revocation_ack_to_terminate_s is not None
            else None
        ),
    }


def _resource_metering_payload(
    samples: tuple[ResourceMeterSample, ...],
    *,
    requested_wallclock_s: float,
) -> dict[str, Any]:
    max_cadence_s = max((sample.cadence_s for sample in samples), default=0.0)
    halted_samples = tuple(sample for sample in samples if sample.halted)
    halt_latency_s = 0.0
    halt_detection_elapsed_s = 0.0
    halt_completion_elapsed_s = 0.0
    halt_completion_latency_s = 0.0
    freeze_capture_latency_s = 0.0
    if halted_samples:
        halt_detection_elapsed_s = halted_samples[0].elapsed_s
        halt_completion_elapsed_s = halted_samples[-1].elapsed_s
        halt_latency_s = max(halt_detection_elapsed_s - requested_wallclock_s, 0.0)
        halt_completion_latency_s = max(halt_completion_elapsed_s - requested_wallclock_s, 0.0)
        freeze_capture_latency_s = max(halt_completion_elapsed_s - halt_detection_elapsed_s, 0.0)
    return {
        "source": samples[-1].source if samples else "unavailable",
        "sample_count": len(samples),
        "max_cadence_s": round(max_cadence_s, 6),
        "halted_by_meter": bool(halted_samples),
        "halt_latency_s": round(halt_latency_s, 6),
        "halt_detection_elapsed_s": round(halt_detection_elapsed_s, 6),
        "halt_completion_elapsed_s": round(halt_completion_elapsed_s, 6),
        "halt_completion_latency_s": round(halt_completion_latency_s, 6),
        "freeze_capture_latency_s": round(freeze_capture_latency_s, 6),
        "dcgm_available": any(sample.dcgm_available for sample in samples),
        "nvidia_smi_available": any(sample.nvidia_smi_available for sample in samples),
        "gpu_count": max((sample.gpu_count for sample in samples), default=0),
        "gpu_models": sorted({model for sample in samples for model in sample.gpu_models}),
        "mig_enabled": any(sample.mig_enabled for sample in samples),
        "mig_instance_count": max((sample.mig_instance_count for sample in samples), default=0),
        "gpu_telemetry_source": samples[-1].gpu_telemetry_source if samples else "unavailable",
        "gpu_telemetry_error": samples[-1].gpu_telemetry_error if samples else "",
        "dcgm_metrics_available": any(sample.dcgm_metrics_available for sample in samples),
        "dcgm_metric_source": samples[-1].dcgm_metric_source if samples else "unavailable",
        "dcgm_metric_error": samples[-1].dcgm_metric_error if samples else "",
        "dcgm_metric_row_count": sum(len(sample.dcgm_metric_rows) for sample in samples),
        "dcgm_gr_engine_active": round(max((sample.dcgm_gr_engine_active for sample in samples), default=0.0), 6),
        "dcgm_tensor_active": round(max((sample.dcgm_tensor_active for sample in samples), default=0.0), 6),
        "dcgm_dram_active": round(max((sample.dcgm_dram_active for sample in samples), default=0.0), 6),
        "samples": [_resource_meter_sample_payload(sample) for sample in samples],
    }


def _append_bounded_stream(buffer: bytearray, chunk: bytes, *, max_bytes: int) -> bool:
    if not chunk:
        return False
    remaining = max(max_bytes - len(buffer), 0)
    if remaining > 0:
        buffer.extend(chunk[:remaining])
    return len(chunk) > remaining


def _decode_bounded_stream(buffer: bytearray, *, truncated: bool, stream_name: str, max_bytes: int) -> str:
    payload = bytes(buffer)
    if truncated:
        marker = f"\n[argus {stream_name} truncated at {max_bytes} bytes]".encode("utf-8")
        payload = payload[: max(max_bytes - len(marker), 0)] + marker
        payload = payload[:max_bytes]
    return payload.decode("utf-8", errors="replace")


def _run_subprocess_bounded(
    command: list[str],
    *,
    timeout_s: float,
    max_bytes: int = PARTIAL_RESULT_LOG_CAPTURE_LIMIT_BYTES,
) -> _BoundedSubprocessResult:
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert process.stdout is not None
    assert process.stderr is not None

    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = {"stdout": False, "stderr": False}
    streams = {
        process.stdout.fileno(): ("stdout", process.stdout),
        process.stderr.fileno(): ("stderr", process.stderr),
    }
    for fd, (stream_name, stream) in streams.items():
        os.set_blocking(fd, False)
        selector.register(fd, selectors.EVENT_READ, data=stream_name)

    deadline = time.monotonic() + max(timeout_s, 0.0)
    timed_out = False

    try:
        while selector.get_map():
            if not timed_out and process.poll() is None and time.monotonic() >= deadline:
                process.kill()
                timed_out = True

            if process.poll() is None:
                wait_s = 0.05 if timed_out else max(min(deadline - time.monotonic(), 0.05), 0.0)
                events = selector.select(wait_s)
                if not events:
                    continue
                keys = [key for key, _ in events]
            else:
                keys = list(selector.get_map().values())

            for key in keys:
                fd = int(key.fileobj)
                stream_name = str(key.data)
                try:
                    chunk = os.read(fd, 8192)
                except BlockingIOError:
                    continue
                except OSError:
                    chunk = b""
                if chunk:
                    truncated[stream_name] = (
                        _append_bounded_stream(buffers[stream_name], chunk, max_bytes=max_bytes)
                        or truncated[stream_name]
                    )
                    continue
                try:
                    selector.unregister(fd)
                except KeyError:
                    pass
                streams[fd][1].close()
        returncode = process.wait()
    finally:
        selector.close()
        for fd, (_, stream) in streams.items():
            if not stream.closed:
                stream.close()

    return _BoundedSubprocessResult(
        returncode=None if timed_out else returncode,
        stdout=_decode_bounded_stream(
            buffers["stdout"],
            truncated=truncated["stdout"],
            stream_name="stdout",
            max_bytes=max_bytes,
        ),
        stderr=_decode_bounded_stream(
            buffers["stderr"],
            truncated=truncated["stderr"],
            stream_name="stderr",
            max_bytes=max_bytes,
        ),
        stdout_truncated=truncated["stdout"],
        stderr_truncated=truncated["stderr"],
        timed_out=timed_out,
    )


def _resolve_docker_socket_path() -> str | None:
    docker_host = os.environ.get("DOCKER_HOST", "")
    candidates: list[str] = []
    if docker_host.startswith("unix://"):
        candidates.append(docker_host.removeprefix("unix://"))
    candidates.extend(("/var/run/docker.sock", os.path.expanduser("~/.docker/run/docker.sock")))
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    return None


class EgressProxy:
    """Default-deny egress decision helper."""

    def __init__(self, bundle: PolicyBundle) -> None:
        self._bundle = bundle

    def allowed_rules(self, scope_token: ScopeToken) -> tuple[EgressRule, ...]:
        rules = set(scope_token.scopes.egress_allowlist) & set(self._bundle.egress_allowlist)
        return tuple(sorted(rules, key=lambda rule: (rule.host, rule.port, rule.proto)))

    def decide(self, scope_token: ScopeToken, *, host: str, port: int, proto: str, sni: str) -> EgressDecision:
        try:
            requested = EgressRule(host=normalize_egress_host(host), port=int(port), proto=proto)
            _validate_egress_rule(requested)
            normalized_sni = normalize_egress_host(sni)
        except (EgressProxyManifestError, TypeError, ValueError):
            return EgressDecision(False, "invalid_destination")
        allowed = requested in self.allowed_rules(scope_token)
        if not allowed:
            return EgressDecision(False, "egress_denied")
        if normalized_sni != requested.host:
            return EgressDecision(False, "sni_mismatch")
        return EgressDecision(True, "allowed")


def normalize_egress_host(host: str) -> str:
    if not isinstance(host, str) or not host or host != host.strip():
        raise EgressProxyManifestError("egress host is invalid")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if host.endswith(".") or "*" in host or len(host) > 253:
        raise EgressProxyManifestError("egress host is invalid")
    try:
        normalized = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise EgressProxyManifestError("egress host is invalid") from exc
    labels = normalized.split(".")
    if any(
        not label
        or len(label) > 63
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
        for label in labels
    ):
        raise EgressProxyManifestError("egress host is invalid")
    return normalized


def _validate_egress_rule(rule: EgressRule) -> None:
    if normalize_egress_host(rule.host) != rule.host:
        raise EgressProxyManifestError("egress rule host must be canonical")
    if isinstance(rule.port, bool) or not isinstance(rule.port, int) or not 1 <= rule.port <= 65535:
        raise EgressProxyManifestError("egress rule port is invalid")
    if rule.proto not in {"https", "grpc", "tcp"}:
        raise EgressProxyManifestError("egress rule protocol is invalid")


class InMemoryAuditLedger:
    """Hash-chained audit ledger for S10 trust-boundary actions."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def append(self, event_type: str, payload: dict[str, Any]) -> AuditEvent:
        previous_hash = self._events[-1].event_hash if self._events else self._zero_hash()
        sequence = len(self._events) + 1
        event_hash = self._event_hash(sequence, event_type, payload, previous_hash)
        event = AuditEvent(
            sequence=sequence,
            event_type=event_type,
            payload=payload,
            previous_hash=previous_hash,
            event_hash=event_hash,
        )
        self._events.append(event)
        return event

    def verify_chain(self) -> AuditVerification:
        previous_hash = self._zero_hash()
        for event in self._events:
            expected = self._event_hash(event.sequence, event.event_type, event.payload, previous_hash)
            if event.previous_hash != previous_hash or event.event_hash != expected:
                return AuditVerification(valid=False, break_sequence=event.sequence)
            previous_hash = event.event_hash
        return AuditVerification(valid=True)

    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    @staticmethod
    def _event_hash(sequence: int, event_type: str, payload: dict[str, Any], previous_hash: str) -> str:
        return hash_json(
            {
                "sequence": sequence,
                "event_type": event_type,
                "payload": payload,
                "previous_hash": previous_hash,
            }
        )

    @staticmethod
    def _zero_hash() -> str:
        return f"{BLAKE3_PREFIX}{'0' * 64}"


class PolicyBundleSigner:
    """Signs S10 policy bundles for deterministic admission decisions."""

    def __init__(self, *, key_id: str, secret: bytes) -> None:
        self.key_id = key_id
        self._secret = bytes(secret)

    def sign(self, bundle: PolicyBundle) -> PolicyBundle:
        unsigned = replace(bundle, signer_key_id=self.key_id, signature="")
        return replace(unsigned, signature=self._signature_value(unsigned))

    def _signature_value(self, bundle: PolicyBundle) -> str:
        digest = hmac.new(self._secret, _policy_bundle_signature_payload(bundle), sha256).hexdigest()
        return f"{SIGNATURE_PREFIX}{digest}"


class InMemoryPolicyBundleTrustStore:
    """Fail-closed verifier for signed S10 policy bundles."""

    def __init__(self, keys: dict[str, bytes]) -> None:
        self._keys = {key_id: bytes(secret) for key_id, secret in keys.items()}

    def verify(self, bundle: PolicyBundle) -> PolicyBundleVerification:
        secret = self._keys.get(bundle.signer_key_id)
        if secret is None:
            return PolicyBundleVerification(False, "unknown_signer")
        if not bundle.signature.startswith(SIGNATURE_PREFIX):
            return PolicyBundleVerification(False, "signature_invalid")
        digest = hmac.new(secret, _policy_bundle_signature_payload(bundle), sha256).hexdigest()
        expected = f"{SIGNATURE_PREFIX}{digest}"
        if not hmac.compare_digest(bundle.signature, expected):
            return PolicyBundleVerification(False, "signature_invalid")
        return PolicyBundleVerification(True)


class InMemoryPolicyService:
    """Verified in-memory S10 policy bundle service with atomic rollout semantics."""

    def __init__(
        self,
        *,
        initial_bundle: PolicyBundle,
        trust_store: InMemoryPolicyBundleTrustStore,
        audit_ledger: InMemoryAuditLedger | None = None,
    ) -> None:
        self._trust_store = trust_store
        self._audit_ledger = audit_ledger
        self._bundles: dict[str, PolicyBundle] = {}
        self._active_version = ""
        self.publish(initial_bundle, initial=True)

    @property
    def active_bundle(self) -> PolicyBundle:
        return self._bundles[self._active_version]

    def bundle(self, bundle_version: str) -> PolicyBundle:
        try:
            return self._bundles[bundle_version]
        except KeyError as exc:
            raise PolicyDeniedError(f"policy bundle is unavailable: {bundle_version}") from exc

    def publish(self, bundle: PolicyBundle, *, initial: bool = False) -> None:
        verification = self._trust_store.verify(bundle)
        if not verification.valid:
            raise PolicyBundleSignatureError(verification.reason or "invalid policy bundle signature")
        previous_version = self._active_version or None
        self._bundles[bundle.bundle_version] = bundle
        self._active_version = bundle.bundle_version
        if self._audit_ledger is not None:
            self._audit_ledger.append(
                "policy.rollout",
                {
                    "bundle_version": bundle.bundle_version,
                    "previous_bundle_version": previous_version,
                    "initial": initial,
                    "signer_key_id": bundle.signer_key_id,
                },
            )

    def decide(self, request: LaunchRequest) -> PolicyVerdict:
        return decide_policy(self.active_bundle, request)


class _StaticPolicyService:
    def __init__(self, bundle: PolicyBundle) -> None:
        self._bundle = bundle

    @property
    def active_bundle(self) -> PolicyBundle:
        return self._bundle

    def bundle(self, bundle_version: str) -> PolicyBundle:
        if bundle_version != self._bundle.bundle_version:
            raise PolicyDeniedError(f"policy bundle is unavailable: {bundle_version}")
        return self._bundle

    def decide(self, request: LaunchRequest) -> PolicyVerdict:
        return decide_policy(self._bundle, request)


def _policy_bundle_signature_payload(bundle: PolicyBundle) -> bytes:
    return canonical_json_bytes({**asdict(bundle), "signature": ""})


class StoreWriterBroker:
    """Brokered S8 read/write path for sandbox-origin artifacts."""

    def __init__(
        self,
        *,
        token_service: InMemoryTokenService,
        artifact_store: InMemoryArtifactStore,
        audit_ledger: InMemoryAuditLedger,
    ) -> None:
        self._token_service = token_service
        self._artifact_store = artifact_store
        self._audit_ledger = audit_ledger
        self._capabilities: dict[str, ScopeToken] = {}
        self._endpoint = _StoreBrokerEndpoint(self)

    def client_for(self, scope_token: ScopeToken) -> "BrokeredStoreClient":
        handle = StoreBrokerHandle(
            handle_id=str(uuid4()),
            scope_id=scope_token.scope_id,
            expires_at=scope_token.expires_at,
        )
        self._capabilities[handle.handle_id] = scope_token
        return BrokeredStoreClient(handle=handle, endpoint=self._endpoint)

    def put_artifact(
        self,
        *,
        scope_token: ScopeToken,
        kind: str,
        payload: Any,
        producer: Producer,
        lineage: Lineage,
        artifact_ref: str | None = None,
        claim_tier: str = "ran-toy",
        validation_report_ref: str | None = None,
    ) -> ArtifactRecord:
        verification = self._token_service.verify_scope(scope_token)
        if not verification.valid:
            self._audit_ledger.append(
                "token.verify_fail",
                {"token": "scope", "reason": verification.reason, "audience": "store"},
            )
            raise TokenInvalidError(verification.reason or "invalid scope token")
        if "store" not in scope_token.scopes.broker_audiences:
            self._deny_store(scope_token=scope_token, reason="scope_denied")
        producer, lineage = self._seal_store_identity(
            scope_token=scope_token,
            producer=producer,
            lineage=lineage,
        )
        brokered_create = getattr(self._artifact_store, "create_brokered_artifact", None)
        if callable(brokered_create):
            record = brokered_create(
                scope_token=scope_token,
                kind=kind,
                payload=payload,
                producer=producer,
                lineage=lineage,
                artifact_ref=artifact_ref,
                claim_tier=claim_tier,
                validation_report_ref=validation_report_ref,
            )
        else:
            record = self._artifact_store.create_artifact(
                kind=kind,
                payload=payload,
                producer=producer,
                lineage=lineage,
                artifact_ref=artifact_ref,
                claim_tier=claim_tier,
                validation_report_ref=validation_report_ref,
            )
        self._audit_ledger.append(
            "store.put",
            {
                "audience": "store",
                "op": "put_artifact",
                "artifact_ref": record.artifact_ref,
                "scope_id": scope_token.scope_id,
                "job_id": scope_token.job_id,
                "producer_subsystem": producer.subsystem,
            },
        )
        return record

    def get_artifact(
        self,
        *,
        scope_token: ScopeToken,
        artifact_ref: str,
        representation: str,
    ) -> dict[str, Any]:
        verification = self._token_service.verify_scope(scope_token)
        if not verification.valid:
            self._audit_ledger.append(
                "token.verify_fail",
                {"token": "scope", "reason": verification.reason, "audience": "store"},
            )
            raise TokenInvalidError(verification.reason or "invalid scope token")
        if "store" not in scope_token.scopes.broker_audiences:
            self._deny_store(scope_token=scope_token, reason="scope_denied")
        if "s8.read" not in scope_token.scopes.capabilities:
            self._deny_store(scope_token=scope_token, reason="read_scope_denied")
        if not isinstance(artifact_ref, str) or not artifact_ref:
            raise ValueError("artifact_ref must be a non-empty string")
        if representation not in {"record", "payload"}:
            raise ValueError("representation must be record or payload")

        brokered_get = getattr(self._artifact_store, "get_brokered_artifact", None)
        if callable(brokered_get):
            response = brokered_get(
                scope_token=scope_token,
                artifact_ref=artifact_ref,
                representation=representation,
            )
        elif representation == "record":
            response = {
                "artifact_ref": artifact_ref,
                "representation": representation,
                "record": asdict(self._artifact_store.get_artifact_record(artifact_ref)),
            }
        else:
            response = {
                "artifact_ref": artifact_ref,
                "representation": representation,
                "payload": json.loads(self._artifact_store.get_artifact(artifact_ref).decode("utf-8")),
            }
        self._audit_ledger.append(
            "store.get",
            {
                "audience": "store",
                "op": "get_artifact",
                "artifact_ref": artifact_ref,
                "representation": representation,
                "scope_id": scope_token.scope_id,
                "job_id": scope_token.job_id,
            },
        )
        return dict(response)

    def deny_direct_write(self, *, scope_token: ScopeToken, op: str) -> None:
        self._audit_ledger.append(
            "store.direct_write_denied",
            {"audience": "store", "op": op, "scope_id": scope_token.scope_id},
        )
        raise ScopeDeniedError("direct S8 writes are denied; use StoreWriterBroker.put_artifact")

    def _put_artifact_by_handle(
        self,
        *,
        handle: StoreBrokerHandle,
        kind: str,
        payload: Any,
        producer: Producer,
        lineage: Lineage,
        artifact_ref: str | None = None,
        claim_tier: str = "ran-toy",
        validation_report_ref: str | None = None,
    ) -> ArtifactRecord:
        return self.put_artifact(
            scope_token=self._scope_for_handle(handle),
            kind=kind,
            payload=payload,
            producer=producer,
            lineage=lineage,
            artifact_ref=artifact_ref,
            claim_tier=claim_tier,
            validation_report_ref=validation_report_ref,
        )

    def _get_artifact_by_handle(
        self,
        *,
        handle: StoreBrokerHandle,
        artifact_ref: str,
        representation: str,
    ) -> dict[str, Any]:
        return self.get_artifact(
            scope_token=self._scope_for_handle(handle),
            artifact_ref=artifact_ref,
            representation=representation,
        )

    def _deny_direct_write_by_handle(self, *, handle: StoreBrokerHandle, op: str) -> NoReturn:
        self.deny_direct_write(scope_token=self._scope_for_handle(handle), op=op)

    def _scope_for_handle(self, handle: StoreBrokerHandle) -> ScopeToken:
        scope_token = self._capabilities.get(handle.handle_id)
        if scope_token is None or scope_token.scope_id != handle.scope_id:
            self._audit_ledger.append(
                "store.denied",
                {"audience": "store", "reason": "invalid_handle", "scope_id": handle.scope_id},
            )
            raise ScopeDeniedError("invalid store broker handle")
        return scope_token

    def _seal_store_identity(
        self,
        *,
        scope_token: ScopeToken,
        producer: Producer,
        lineage: Lineage,
    ) -> tuple[Producer, Lineage]:
        allowed_producers = scope_token.scopes.producer_subsystems
        if not allowed_producers:
            self._deny_store(scope_token=scope_token, reason="producer_scope_missing")
        if producer.subsystem not in allowed_producers:
            self._deny_store(
                scope_token=scope_token,
                reason="producer_scope_denied",
                producer_subsystem=producer.subsystem,
            )
        if producer.job_id is not None and producer.job_id != scope_token.job_id:
            self._deny_store(scope_token=scope_token, reason="producer_job_mismatch")
        if lineage.job_id is not None and lineage.job_id != scope_token.job_id:
            self._deny_store(scope_token=scope_token, reason="lineage_job_mismatch")
        return replace(producer, job_id=scope_token.job_id), replace(lineage, job_id=scope_token.job_id)

    def _deny_store(self, *, scope_token: ScopeToken, reason: str, **payload: Any) -> None:
        self._audit_ledger.append(
            "store.denied",
            {
                "audience": "store",
                "reason": reason,
                "scope_id": scope_token.scope_id,
                "job_id": scope_token.job_id,
                **payload,
            },
        )
        raise ScopeDeniedError(reason)


class _StoreBrokerEndpoint:
    """In-process broker endpoint; not a security boundary until moved out of process."""

    __slots__ = ("_broker_ref",)

    def __init__(self, broker: StoreWriterBroker) -> None:
        self._broker_ref = ref(broker)

    def put_artifact(
        self,
        *,
        handle: StoreBrokerHandle,
        kind: str,
        payload: Any,
        producer: Producer,
        lineage: Lineage,
        artifact_ref: str | None = None,
        claim_tier: str = "ran-toy",
        validation_report_ref: str | None = None,
    ) -> ArtifactRecord:
        return self._broker()._put_artifact_by_handle(
            handle=handle,
            kind=kind,
            payload=payload,
            producer=producer,
            lineage=lineage,
            artifact_ref=artifact_ref,
            claim_tier=claim_tier,
            validation_report_ref=validation_report_ref,
        )

    def deny_direct_write(self, *, handle: StoreBrokerHandle, op: str) -> NoReturn:
        self._broker()._deny_direct_write_by_handle(handle=handle, op=op)

    def get_artifact(
        self,
        *,
        handle: StoreBrokerHandle,
        artifact_ref: str,
        representation: str,
    ) -> dict[str, Any]:
        return self._broker()._get_artifact_by_handle(
            handle=handle,
            artifact_ref=artifact_ref,
            representation=representation,
        )

    def _broker(self) -> StoreWriterBroker:
        broker = self._broker_ref()
        if broker is None:
            raise ScopeDeniedError("store broker handle is no longer valid")
        return broker


class BrokeredStoreClient:
    """Sandbox-facing store client exposing only brokered artifact operations."""

    __slots__ = ("_handle", "_endpoint")

    def __init__(self, *, handle: StoreBrokerHandle, endpoint: _StoreBrokerEndpoint) -> None:
        self._handle = handle
        self._endpoint = endpoint

    def put_artifact(
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
        return self._endpoint.put_artifact(
            handle=self._handle,
            kind=kind,
            payload=payload,
            producer=producer,
            lineage=lineage,
            artifact_ref=artifact_ref,
            claim_tier=claim_tier,
            validation_report_ref=validation_report_ref,
        )

    def create_artifact(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._endpoint.deny_direct_write(handle=self._handle, op="create_artifact")

    def get_artifact(self, *, artifact_ref: str, representation: str = "payload") -> dict[str, Any]:
        return self._endpoint.get_artifact(
            handle=self._handle,
            artifact_ref=artifact_ref,
            representation=representation,
        )


class DockerSandboxSupervisor:
    """Node-level Docker supervisor that launches digest-pinned containers with no network."""

    def __init__(
        self,
        *,
        docker_bin: str | None = None,
        meter_interval_s: float = 1.0,
        meter_gap_halt_s: float = 5.0,
        gpu_telemetry: GpuTelemetrySnapshot | None = None,
        dcgm_metric_sampler: Callable[[], DcgmMetricSnapshot] | None = None,
        gvisor_config: GvisorRuntimeConfig | None = None,
        firecracker_supervisor: FirecrackerSandboxSupervisor | None = None,
        egress_sidecar_config: EgressSidecarRuntimeConfig | None = None,
    ) -> None:
        self._docker_bin = docker_bin or shutil.which("docker") or "docker"
        self._meter_interval_s = min(max(float(meter_interval_s), 0.1), 5.0)
        self._meter_gap_halt_s = max(float(meter_gap_halt_s), self._meter_interval_s)
        self._docker_socket_path = _resolve_docker_socket_path()
        self._gpu_telemetry = gpu_telemetry or discover_gpu_telemetry()
        self._dcgm_metric_sampler = dcgm_metric_sampler or (
            lambda: collect_dcgm_metric_sample(gpu_telemetry=self._gpu_telemetry)
        )
        self._gvisor_config = gvisor_config
        self._firecracker_supervisor = firecracker_supervisor
        self._egress_sidecar_config = egress_sidecar_config

    @property
    def resource_meter_kind(self) -> str:
        return "docker-api-cgroup+dcgm" if self._gpu_telemetry.dcgm_available else "docker-api-cgroup"

    @property
    def meter_interval_s(self) -> float:
        return self._meter_interval_s

    @property
    def meter_gap_halt_s(self) -> float:
        return self._meter_gap_halt_s

    @property
    def dcgm_available(self) -> bool:
        return self._gpu_telemetry.dcgm_available

    @property
    def nvidia_smi_available(self) -> bool:
        return self._gpu_telemetry.nvidia_smi_available

    @property
    def gpu_count(self) -> int:
        return self._gpu_telemetry.gpu_count

    @property
    def gpu_models(self) -> tuple[str, ...]:
        return self._gpu_telemetry.gpu_models

    @property
    def mig_enabled(self) -> bool:
        return self._gpu_telemetry.mig_enabled

    @property
    def mig_instance_count(self) -> int:
        return self._gpu_telemetry.mig_instance_count

    @property
    def gpu_telemetry_source(self) -> str:
        return self._gpu_telemetry.source

    @property
    def dcgm_metric_sampler_enabled(self) -> bool:
        return self._gpu_telemetry.dcgm_available

    @property
    def dcgm_metric_fields(self) -> tuple[str, ...]:
        return DCGM_DMON_METRIC_FIELDS

    @property
    def gvisor_configured(self) -> bool:
        return self._gvisor_config is not None

    @property
    def gvisor_docker_runtime(self) -> str | None:
        return self._gvisor_config.docker_runtime if self._gvisor_config is not None else None

    @property
    def firecracker_configured(self) -> bool:
        return self._firecracker_supervisor is not None

    @property
    def firecracker_version(self) -> str | None:
        return self._firecracker_supervisor.expected_version if self._firecracker_supervisor is not None else None

    @property
    def firecracker_resource_meter_kind(self) -> str | None:
        return (
            self._firecracker_supervisor.resource_meter_kind
            if self._firecracker_supervisor is not None
            else None
        )

    @property
    def egress_sidecar_configured(self) -> bool:
        return self._egress_sidecar_config is not None

    def materialize_security_spec(
        self,
        handle: SandboxHandle,
        policy_bundle: PolicyBundle | None,
    ) -> SandboxSecuritySpec:
        if handle.runtime_class == "docker":
            return SandboxSecuritySpec(runtime_class="docker")
        if handle.runtime_class == "gvisor":
            if policy_bundle is None:
                raise SandboxRuntimeUnavailableError("gVisor launch requires its pinned policy bundle")
            if self._gvisor_config is None:
                raise SandboxRuntimeUnavailableError("gVisor runtime is not configured")
            return _materialize_gvisor_security_spec(handle, policy_bundle, self._gvisor_config)
        raise SandboxRuntimeUnavailableError(f"sandbox runtime class is unavailable: {handle.runtime_class}")

    def _gpu_telemetry_sample_fields(self) -> dict[str, Any]:
        return {
            "dcgm_available": self._gpu_telemetry.dcgm_available,
            "nvidia_smi_available": self._gpu_telemetry.nvidia_smi_available,
            "gpu_count": self._gpu_telemetry.gpu_count,
            "gpu_models": self._gpu_telemetry.gpu_models,
            "mig_enabled": self._gpu_telemetry.mig_enabled,
            "mig_instance_count": self._gpu_telemetry.mig_instance_count,
            "gpu_telemetry_source": self._gpu_telemetry.source,
            "gpu_telemetry_error": self._gpu_telemetry.error,
        }

    def _dcgm_metric_sample_fields(self, snapshot: DcgmMetricSnapshot | None = None) -> dict[str, Any]:
        if snapshot is None:
            snapshot = DcgmMetricSnapshot(source="unavailable")
        return {
            "dcgm_metrics_available": snapshot.available,
            "dcgm_metric_source": snapshot.source,
            "dcgm_metric_error": snapshot.error,
            "dcgm_metric_rows": snapshot.rows,
            "dcgm_gr_engine_active": snapshot.max_gr_engine_active,
            "dcgm_tensor_active": snapshot.max_tensor_active,
            "dcgm_dram_active": snapshot.max_dram_active,
        }

    def _collect_dcgm_metric_snapshot(self) -> DcgmMetricSnapshot:
        if not self._gpu_telemetry.dcgm_available:
            return DcgmMetricSnapshot(source="unavailable")
        try:
            return self._dcgm_metric_sampler()
        except (FileNotFoundError, subprocess.TimeoutExpired, TimeoutError) as exc:
            return DcgmMetricSnapshot(
                source=DCGM_DMON_METRIC_SOURCE,
                error=f"{DCGM_DMON_METRIC_SOURCE}:{type(exc).__name__}",
            )

    def run(
        self,
        *,
        handle: SandboxHandle,
        request: LaunchRequest,
        materialized_env: dict[str, str],
        meter_sample_sink: Callable[[ResourceMeterSample], None] | None = None,
        runtime_halt_probe: Callable[[], _RuntimeHaltSignal | tuple[str, tuple[str, ...]] | None] | None = None,
        halt_telemetry_sink: Callable[[SandboxHaltTelemetry], None] | None = None,
        policy_bundle: PolicyBundle | None = None,
        runtime_evidence_sink: Callable[[RuntimeLaunchEvidence], None] | None = None,
        egress_audit_sink: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> SandboxExecutionResult:
        if not _is_digest_pinned_image(request.image):
            raise PolicyDeniedError("image must be digest-pinned")
        if not request.entrypoint:
            raise PolicyDeniedError("entrypoint is required")
        if handle.runtime_class == "firecracker":
            if self._firecracker_supervisor is None:
                raise SandboxRuntimeUnavailableError("Firecracker runtime is not configured")
            return self._firecracker_supervisor.run(
                handle=handle,
                request=request,
                materialized_env=materialized_env,
                meter_sample_sink=meter_sample_sink,
                runtime_halt_probe=runtime_halt_probe,
                halt_telemetry_sink=halt_telemetry_sink,
                policy_bundle=policy_bundle,
                runtime_evidence_sink=runtime_evidence_sink,
            )
        security_spec = self.materialize_security_spec(handle, policy_bundle)
        egress_manifest = self._materialize_egress_manifest(handle, request, policy_bundle)
        sidecar_required = self._egress_sidecar_config is not None and egress_manifest is not None
        if self._docker_socket_path is not None:
            try:
                return self._run_via_docker_api(
                    handle=handle,
                    request=request,
                    materialized_env=materialized_env,
                    meter_sample_sink=meter_sample_sink,
                    runtime_halt_probe=runtime_halt_probe,
                    halt_telemetry_sink=halt_telemetry_sink,
                    security_spec=security_spec,
                    runtime_evidence_sink=runtime_evidence_sink,
                    egress_manifest=egress_manifest,
                    egress_audit_sink=egress_audit_sink,
                )
            except SandboxRuntimeUnavailableError:
                if security_spec.runtime_class != "docker" or sidecar_required:
                    raise
                if shutil.which(self._docker_bin) is None and "/" not in self._docker_bin:
                    raise
        if sidecar_required:
            raise SandboxRuntimeUnavailableError("egress sidecar launch requires the Docker Engine API")
        if shutil.which(self._docker_bin) is None and "/" not in self._docker_bin:
            raise SandboxRuntimeUnavailableError("docker runtime is unavailable")

        container_name = f"argus-{handle.sandbox_id.replace('-', '')[:24]}"
        self._ensure_cli_runtime_available(security_spec)
        command = self._docker_command(container_name, request, materialized_env, security_spec)
        if runtime_evidence_sink is not None and security_spec.runtime_class == "gvisor":
            runtime_evidence_sink(
                self._runtime_launch_evidence(
                    handle=handle,
                    container_id=container_name,
                    security_spec=security_spec,
                    attestation_source="docker-cli-command",
                )
            )
        started_at = time.monotonic()
        try:
            completed = _run_subprocess_bounded(
                command,
                timeout_s=max(request.requested_envelope.wallclock_s, 1),
            )
            duration_s = time.monotonic() - started_at
            if completed.timed_out:
                self._force_remove(container_name)
            return SandboxExecutionResult(
                handle=handle,
                exit_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
                timed_out=completed.timed_out,
                duration_s=duration_s,
                budget_usage=_runtime_budget_usage(request.requested_envelope, duration_s),
            )
        except FileNotFoundError as exc:
            raise SandboxRuntimeUnavailableError("docker runtime is unavailable") from exc

    @staticmethod
    def _materialize_egress_manifest(
        handle: SandboxHandle,
        request: LaunchRequest,
        policy_bundle: PolicyBundle | None,
    ) -> EgressProxyManifest | None:
        if policy_bundle is None:
            return None
        if policy_bundle.bundle_version != handle.policy_bundle_version:
            raise SandboxRuntimeUnavailableError("egress policy bundle version differs from the admitted handle")
        return EgressProxyManifest.materialize(
            sandbox_id=handle.sandbox_id,
            scope_token=request.scope_token,
            policy_bundle=policy_bundle,
        )

    def _docker_command(
        self,
        container_name: str,
        request: LaunchRequest,
        env: dict[str, str],
        security_spec: SandboxSecuritySpec,
    ) -> list[str]:
        envelope = request.requested_envelope
        command = [
            self._docker_bin,
            "run",
            "--rm",
            "--pull=never",
            "--name",
            container_name,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            DOCKER_SANDBOX_USER,
            "--pids-limit",
            str(max(envelope.pids, 1)),
            "--memory",
            str(max(envelope.mem_bytes, 4 * 1024 * 1024)),
            "--cpus",
            f"{max(envelope.cpu_m, 1) / 1000:.3f}",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={max(envelope.scratch_bytes, 1024 * 1024)}",
        ]
        if security_spec.runtime_class == "gvisor":
            assert security_spec.docker_runtime is not None
            assert security_spec.seccomp_profile_path is not None
            command.extend(("--runtime", security_spec.docker_runtime))
            command.extend(("--security-opt", f"seccomp={security_spec.seccomp_profile_path}"))
            for mount in security_spec.trust_mounts:
                command.extend(
                    (
                        "--mount",
                        "type=bind,"
                        f"src={mount.source},dst={mount.target},readonly,bind-propagation=rprivate",
                    )
                )
        for key in sorted(env):
            command.extend(("--env", f"{key}={env[key]}"))
        command.extend(("--entrypoint", request.entrypoint[0]))
        command.append(request.image)
        command.extend(request.entrypoint[1:])
        command.extend(request.args)
        return command

    def _ensure_cli_runtime_available(self, security_spec: SandboxSecuritySpec) -> None:
        if security_spec.runtime_class != "gvisor":
            return
        completed = subprocess.run(
            [self._docker_bin, "info", "--format", "{{json .Runtimes}}"],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise SandboxRuntimeUnavailableError("Docker runtime inventory is unavailable")
        try:
            runtimes = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise SandboxRuntimeUnavailableError("Docker runtime inventory is invalid") from exc
        if not isinstance(runtimes, dict) or security_spec.docker_runtime not in runtimes:
            raise SandboxRuntimeUnavailableError(
                f"gVisor Docker runtime {security_spec.docker_runtime!r} is unavailable"
            )
        self._verify_gvisor_runtime_inventory_entry(
            security_spec.docker_runtime,
            runtimes[security_spec.docker_runtime],
        )

    def _force_remove(self, container_name: str) -> None:
        subprocess.run(
            [self._docker_bin, "rm", "-f", container_name],
            check=False,
            capture_output=True,
            text=True,
        )

    def _run_via_docker_api(
        self,
        *,
        handle: SandboxHandle,
        request: LaunchRequest,
        materialized_env: dict[str, str],
        meter_sample_sink: Callable[[ResourceMeterSample], None] | None = None,
        runtime_halt_probe: Callable[[], _RuntimeHaltSignal | tuple[str, tuple[str, ...]] | None] | None = None,
        halt_telemetry_sink: Callable[[SandboxHaltTelemetry], None] | None = None,
        security_spec: SandboxSecuritySpec,
        runtime_evidence_sink: Callable[[DockerRuntimeLaunchEvidence], None] | None = None,
        egress_manifest: EgressProxyManifest | None = None,
        egress_audit_sink: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> SandboxExecutionResult:
        container_name = f"argus-{handle.sandbox_id.replace('-', '')[:24]}"
        envelope = request.requested_envelope
        container_id: str | None = None
        sidecar_id: str | None = None
        seen_egress_events: list[tuple[str, dict[str, Any]]] = []
        started_at = time.monotonic()

        def probe_egress_halt() -> _RuntimeHaltSignal | None:
            if sidecar_id is None or egress_manifest is None:
                return None
            events = self._drain_egress_sidecar_events(
                sidecar_id=sidecar_id,
                manifest=egress_manifest,
                sink=egress_audit_sink,
                seen_events=seen_egress_events,
            )
            if any(event_type == "egress.exfil_hard_halt" for event_type, _ in events):
                return _RuntimeHaltSignal(
                    reason="exfil_hard_limit",
                    dimensions=("exfil_bytes",),
                    source="egress-sidecar-byte-meter",
                )
            return None

        try:
            self._ensure_docker_api_runtime_available(security_spec)
            if self._egress_sidecar_config is not None and egress_manifest is not None:
                sidecar_id = self._start_egress_sidecar(handle=handle, manifest=egress_manifest)
            effective_env = dict(materialized_env)
            sandbox_user = DOCKER_SANDBOX_USER
            if sidecar_id is not None:
                assert self._egress_sidecar_config is not None
                proxy_url = self._egress_sidecar_config.proxy_url
                sandbox_user = (
                    f"{self._egress_sidecar_config.sandbox_uid}:"
                    f"{self._egress_sidecar_config.sandbox_uid}"
                )
                effective_env.update(
                    {
                        "ALL_PROXY": proxy_url,
                        "HTTPS_PROXY": proxy_url,
                        "all_proxy": proxy_url,
                        "https_proxy": proxy_url,
                        "ARGUS_EGRESS_PROXY": proxy_url,
                        "NO_PROXY": "",
                        "no_proxy": "",
                    }
                )
            host_config: dict[str, Any] = {
                "AutoRemove": False,
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "NetworkMode": f"container:{sidecar_id}" if sidecar_id is not None else "none",
                "PidsLimit": max(envelope.pids, 1),
                "Memory": max(envelope.mem_bytes, 4 * 1024 * 1024),
                "NanoCpus": max(envelope.cpu_m, 1) * 1_000_000,
                "Tmpfs": {
                    "/tmp": f"rw,noexec,nosuid,nodev,size={max(envelope.scratch_bytes, 1024 * 1024)}"
                },
            }
            if security_spec.runtime_class == "gvisor":
                assert security_spec.docker_runtime is not None
                assert security_spec.seccomp_profile_json is not None
                host_config["Runtime"] = security_spec.docker_runtime
                host_config["SecurityOpt"].append(f"seccomp={security_spec.seccomp_profile_json}")
                host_config["Mounts"] = [
                    {
                        "Type": "bind",
                        "Source": mount.source,
                        "Target": mount.target,
                        "ReadOnly": True,
                        "BindOptions": {"Propagation": "rprivate"},
                    }
                    for mount in security_spec.trust_mounts
                ]
            create_response = self._docker_api_request(
                "POST",
                f"/containers/create?name={container_name}",
                {
                    "Image": request.image,
                    "Labels": {
                        "argus.dev/job-id": request.job_id,
                        "argus.dev/role": "sandbox",
                        "argus.dev/sandbox-id": handle.sandbox_id,
                    },
                    "Entrypoint": [request.entrypoint[0]],
                    "Cmd": list(request.entrypoint[1:]) + list(request.args),
                    "Env": [f"{key}={value}" for key, value in sorted(effective_env.items())],
                    "User": sandbox_user,
                    "NetworkDisabled": sidecar_id is None,
                    "HostConfig": host_config,
                },
                expected=(201,),
            )
            container_id = str(create_response.get("Id") or "")
            if not container_id:
                raise SandboxRuntimeUnavailableError("docker runtime did not return a container id")
            inspected: dict[str, Any] | None = None
            if security_spec.runtime_class == "gvisor" or sidecar_id is not None:
                inspected = self._docker_api_request(
                    "GET",
                    f"/containers/{container_id}/json",
                    expected=(200,),
                )
            if sidecar_id is not None:
                assert inspected is not None
                assert self._egress_sidecar_config is not None
                self._verify_sandbox_egress_attestation(
                    inspected,
                    sidecar_id=sidecar_id,
                    proxy_url=self._egress_sidecar_config.proxy_url,
                    sandbox_user=sandbox_user,
                )
            if security_spec.runtime_class == "gvisor":
                assert inspected is not None
                self._verify_docker_api_security_attestation(inspected, security_spec)
                if runtime_evidence_sink is not None:
                    runtime_evidence_sink(
                        self._runtime_launch_evidence(
                            handle=handle,
                            container_id=container_id,
                            security_spec=security_spec,
                            attestation_source="docker-api-inspect",
                        )
                    )
            self._docker_api_request("POST", f"/containers/{container_id}/start", expected=(204, 304))
            exit_code, timed_out, runtime_stderr, budget_usage, partial_result = self._wait_for_container_with_meter(
                container_id=container_id,
                request=request,
                started_at=started_at,
                meter_sample_sink=meter_sample_sink,
                runtime_halt_probe=runtime_halt_probe,
                pre_state_halt_probe=probe_egress_halt if sidecar_id is not None else None,
                halt_telemetry_sink=halt_telemetry_sink,
            )
            if partial_result is None:
                log_capture = self._docker_api_logs(container_id)
                stdout, stderr = log_capture.stdout, log_capture.stderr
            else:
                stdout, stderr = partial_result.stdout, partial_result.stderr
            duration_s = time.monotonic() - started_at
            if runtime_stderr:
                stderr = (stderr + ("\n" if stderr else "") + runtime_stderr).strip()
            return SandboxExecutionResult(
                handle=handle,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                timed_out=timed_out,
                duration_s=duration_s,
                budget_usage=_max_budget_usage(budget_usage, _runtime_budget_usage(envelope, duration_s)),
                partial_result=partial_result,
            )
        finally:
            active_error = sys.exception()
            cleanup_errors: list[Exception] = []
            if container_id:
                try:
                    self._docker_api_request(
                        "DELETE",
                        f"/containers/{container_id}?force=true",
                        expected=(204, 404),
                    )
                except Exception as exc:
                    cleanup_errors.append(exc)
            if sidecar_id:
                try:
                    assert egress_manifest is not None
                    self._collect_egress_sidecar_events(
                        sidecar_id=sidecar_id,
                        manifest=egress_manifest,
                        sink=egress_audit_sink,
                        seen_events=seen_egress_events,
                    )
                except Exception as exc:
                    cleanup_errors.append(exc)
                try:
                    self._docker_api_request(
                        "DELETE",
                        f"/containers/{sidecar_id}?force=true",
                        expected=(204, 404),
                    )
                except Exception as exc:
                    cleanup_errors.append(exc)
            if cleanup_errors:
                if active_error is not None:
                    for cleanup_error in cleanup_errors:
                        active_error.add_note(
                            "egress cleanup failure: "
                            f"{type(cleanup_error).__name__}: {cleanup_error}"
                        )
                else:
                    primary = cleanup_errors[0]
                    for additional in cleanup_errors[1:]:
                        primary.add_note(
                            "additional egress cleanup failure: "
                            f"{type(additional).__name__}: {additional}"
                        )
                    raise primary

    def _start_egress_sidecar(
        self,
        *,
        handle: SandboxHandle,
        manifest: EgressProxyManifest,
    ) -> str:
        config = self._egress_sidecar_config
        if config is None:
            raise SandboxRuntimeUnavailableError("egress sidecar is not configured")
        sidecar_name = f"argus-egress-{handle.sandbox_id.replace('-', '')[:20]}"
        environment = {
            "ARGUS_S10_EGRESS_DNS_PORT": str(config.dns_port),
            "ARGUS_S10_EGRESS_DNS_SERVERS": ",".join(config.dns_servers),
            "ARGUS_S10_EGRESS_LISTEN_HOST": "127.0.0.1",
            "ARGUS_S10_EGRESS_LISTEN_PORT": str(config.proxy_port),
            "ARGUS_S10_EGRESS_MANIFEST_HASH": manifest.manifest_hash,
            "ARGUS_S10_EGRESS_MANIFEST_JSON": manifest.to_json(),
            "ARGUS_S10_EGRESS_PROXY_GID": str(config.proxy_gid),
            "ARGUS_S10_EGRESS_PROXY_UID": str(config.proxy_uid),
            "ARGUS_S10_SANDBOX_UID": str(config.sandbox_uid),
        }
        response = self._docker_api_request(
            "POST",
            f"/containers/create?name={sidecar_name}",
            {
                "Image": config.image,
                "Labels": {
                    "argus.dev/job-id": manifest.job_id,
                    "argus.dev/role": "egress-sidecar",
                    "argus.dev/sandbox-id": manifest.sandbox_id,
                },
                "Entrypoint": ["python", "-m", "argus_runtime.s10_egress_proxy_service"],
                "Cmd": ["--apply-firewall"],
                "Env": [f"{key}={value}" for key, value in sorted(environment.items())],
                "User": "0:0",
                "NetworkDisabled": False,
                "HostConfig": {
                    "AutoRemove": False,
                    "ReadonlyRootfs": True,
                    "CapDrop": ["ALL"],
                    "CapAdd": ["NET_ADMIN", "NET_RAW", "SETGID", "SETUID"],
                    "SecurityOpt": ["no-new-privileges"],
                    "NetworkMode": config.network_mode,
                    "PidsLimit": config.pids,
                    "Memory": config.memory_bytes,
                    "NanoCpus": 250_000_000,
                    "Tmpfs": {"/run": "rw,noexec,nosuid,nodev,size=16777216"},
                },
            },
            expected=(201,),
        )
        sidecar_id = str(response.get("Id") or "")
        if not sidecar_id:
            raise SandboxRuntimeUnavailableError("docker runtime did not return an egress sidecar id")
        try:
            inspected = self._docker_api_request(
                "GET",
                f"/containers/{sidecar_id}/json",
                expected=(200,),
            )
            self._verify_egress_sidecar_attestation(inspected, config, manifest)
            self._docker_api_request("POST", f"/containers/{sidecar_id}/start", expected=(204, 304))
            self._wait_for_egress_sidecar_ready(
                sidecar_id=sidecar_id,
                manifest=manifest,
                timeout_s=config.startup_timeout_s,
            )
        except Exception as primary:
            try:
                self._docker_api_request(
                    "DELETE",
                    f"/containers/{sidecar_id}?force=true",
                    expected=(204, 404),
                )
            except Exception as cleanup_error:
                primary.add_note(
                    "egress sidecar startup cleanup failure: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            raise
        return sidecar_id

    @staticmethod
    def _verify_egress_sidecar_attestation(
        inspected: dict[str, Any],
        config: EgressSidecarRuntimeConfig,
        manifest: EgressProxyManifest,
    ) -> None:
        container_config = inspected.get("Config")
        host_config = inspected.get("HostConfig")
        if not isinstance(container_config, dict) or container_config.get("Image") != config.image:
            raise SandboxRuntimeUnavailableError("Docker did not bind the digest-pinned egress sidecar image")
        if container_config.get("User") != "0:0":
            raise SandboxRuntimeUnavailableError("egress sidecar bootstrap user differs from policy")
        if container_config.get("Entrypoint") != ["python", "-m", "argus_runtime.s10_egress_proxy_service"]:
            raise SandboxRuntimeUnavailableError("egress sidecar entrypoint differs from policy")
        if container_config.get("Cmd") != ["--apply-firewall"]:
            raise SandboxRuntimeUnavailableError("egress sidecar omitted fail-closed firewall setup")
        environment = container_config.get("Env")
        if not isinstance(environment, list) or (
            f"ARGUS_S10_EGRESS_MANIFEST_HASH={manifest.manifest_hash}" not in environment
        ):
            raise SandboxRuntimeUnavailableError("egress sidecar manifest hash binding is absent")
        if not isinstance(host_config, dict):
            raise SandboxRuntimeUnavailableError("Docker inspect omitted egress sidecar HostConfig")
        if host_config.get("NetworkMode") != config.network_mode:
            raise SandboxRuntimeUnavailableError("Docker changed the egress sidecar network")
        if not host_config.get("ReadonlyRootfs"):
            raise SandboxRuntimeUnavailableError("egress sidecar rootfs is not read-only")
        if host_config.get("CapDrop") != ["ALL"] or host_config.get("CapAdd") != [
            "NET_ADMIN",
            "NET_RAW",
            "SETGID",
            "SETUID",
        ]:
            raise SandboxRuntimeUnavailableError("egress sidecar capability boundary differs from policy")
        if "no-new-privileges" not in (host_config.get("SecurityOpt") or []):
            raise SandboxRuntimeUnavailableError("egress sidecar omitted no-new-privileges")

    @staticmethod
    def _verify_sandbox_egress_attestation(
        inspected: dict[str, Any],
        *,
        sidecar_id: str,
        proxy_url: str,
        sandbox_user: str,
    ) -> None:
        container_config = inspected.get("Config")
        host_config = inspected.get("HostConfig")
        if not isinstance(container_config, dict) or not isinstance(host_config, dict):
            raise SandboxRuntimeUnavailableError("Docker inspect omitted sandbox egress evidence")
        if host_config.get("NetworkMode") != f"container:{sidecar_id}":
            raise SandboxRuntimeUnavailableError("sandbox did not join the egress sidecar network namespace")
        if container_config.get("User") != sandbox_user:
            raise SandboxRuntimeUnavailableError("sandbox user differs from the firewall owner rule")
        environment = container_config.get("Env")
        required = {
            f"ALL_PROXY={proxy_url}",
            f"HTTPS_PROXY={proxy_url}",
            f"ARGUS_EGRESS_PROXY={proxy_url}",
        }
        if not isinstance(environment, list) or not required.issubset(environment):
            raise SandboxRuntimeUnavailableError("sandbox proxy environment differs from the sidecar binding")

    def _wait_for_egress_sidecar_ready(
        self,
        *,
        sidecar_id: str,
        manifest: EgressProxyManifest,
        timeout_s: float,
    ) -> None:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            inspected = self._docker_api_request(
                "GET",
                f"/containers/{sidecar_id}/json",
                expected=(200,),
                timeout=1,
            )
            state = inspected.get("State")
            if not isinstance(state, dict) or not state.get("Running", False):
                capture = self._docker_api_logs(sidecar_id)
                detail = " ".join((capture.stderr or capture.stdout).strip().split())[:1024]
                suffix = f": {detail}" if detail else ""
                raise SandboxRuntimeUnavailableError(
                    f"egress sidecar exited before it became ready{suffix}"
                )
            capture = self._docker_api_logs(sidecar_id)
            events = self._parse_egress_sidecar_events(capture, manifest)
            ready_payloads = [payload for event_type, payload in events if event_type == "egress.ready"]
            if len(ready_payloads) > 1:
                raise SandboxRuntimeUnavailableError("egress sidecar emitted multiple ready events")
            if ready_payloads:
                config = self._egress_sidecar_config
                if config is None:
                    raise SandboxRuntimeUnavailableError("egress sidecar readiness has no runtime config")
                payload = ready_payloads[0]
                expected = {
                    "effective_capabilities": "0000000000000000",
                    "listen_host": "127.0.0.1",
                    "listen_port": config.proxy_port,
                    "proxy_uid": config.proxy_uid,
                    "rule_count": len(manifest.rules),
                }
                for field_name, expected_value in expected.items():
                    if payload.get(field_name) != expected_value:
                        label = field_name.replace("_", " ")
                        raise SandboxRuntimeUnavailableError(
                            f"egress sidecar ready {label} differs from policy"
                        )
                return
            time.sleep(0.05)
        raise SandboxRuntimeUnavailableError("egress sidecar did not become ready before its deadline")

    def _collect_egress_sidecar_events(
        self,
        *,
        sidecar_id: str,
        manifest: EgressProxyManifest,
        sink: Callable[[str, dict[str, Any]], None] | None,
        seen_events: list[tuple[str, dict[str, Any]]],
    ) -> None:
        self._drain_egress_sidecar_events(
            sidecar_id=sidecar_id,
            manifest=manifest,
            sink=sink,
            seen_events=seen_events,
        )
        inspected = self._docker_api_request(
            "GET",
            f"/containers/{sidecar_id}/json",
            expected=(200, 404),
        )
        state = inspected.get("State") if isinstance(inspected, dict) else None
        if isinstance(state, dict) and not state.get("Running", False):
            if sink is not None:
                sink(
                    "egress.proxy_crashed",
                    {
                        "sandbox_id": manifest.sandbox_id,
                        "job_id": manifest.job_id,
                        "scope_id": manifest.scope_id,
                        "policy_bundle_version": manifest.policy_bundle_version,
                        "manifest_hash": manifest.manifest_hash,
                        "exit_code": state.get("ExitCode"),
                    },
                )

    def _drain_egress_sidecar_events(
        self,
        *,
        sidecar_id: str,
        manifest: EgressProxyManifest,
        sink: Callable[[str, dict[str, Any]], None] | None,
        seen_events: list[tuple[str, dict[str, Any]]],
    ) -> list[tuple[str, dict[str, Any]]]:
        capture = self._docker_api_logs(sidecar_id)
        events = self._parse_egress_sidecar_events(capture, manifest)
        if events[: len(seen_events)] != seen_events:
            raise SandboxRuntimeUnavailableError("egress sidecar audit stream changed after ingestion")
        new_events = events[len(seen_events) :]
        seen_events[:] = events
        if sink is not None:
            for event_type, payload in new_events:
                sink(event_type, payload)
        return new_events

    @staticmethod
    def _parse_egress_sidecar_events(
        capture: _DockerLogCapture,
        manifest: EgressProxyManifest,
    ) -> list[tuple[str, dict[str, Any]]]:
        if capture.truncated:
            raise SandboxRuntimeUnavailableError("egress sidecar audit log exceeded its bounded capture")
        events: list[tuple[str, dict[str, Any]]] = []
        for line in capture.stdout.splitlines():
            if not line.strip():
                continue
            try:
                raw_event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SandboxRuntimeUnavailableError("egress sidecar emitted invalid audit JSON") from exc
            if not isinstance(raw_event, dict) or set(raw_event) != {"event_type", "payload"}:
                raise SandboxRuntimeUnavailableError("egress sidecar emitted an invalid audit envelope")
            event_type = raw_event.get("event_type")
            payload = raw_event.get("payload")
            if not isinstance(event_type, str) or not event_type.startswith("egress."):
                raise SandboxRuntimeUnavailableError("egress sidecar emitted an invalid event type")
            if not isinstance(payload, dict):
                raise SandboxRuntimeUnavailableError("egress sidecar emitted an invalid event payload")
            for field_name, expected in (
                ("sandbox_id", manifest.sandbox_id),
                ("job_id", manifest.job_id),
                ("scope_id", manifest.scope_id),
                ("policy_bundle_version", manifest.policy_bundle_version),
                ("manifest_hash", manifest.manifest_hash),
            ):
                if payload.get(field_name) != expected:
                    raise SandboxRuntimeUnavailableError(
                        f"egress sidecar event {field_name} differs from the admitted manifest"
                    )
            events.append(
                (
                    event_type,
                    {
                        "scope_id": manifest.scope_id,
                        "policy_bundle_version": manifest.policy_bundle_version,
                        **payload,
                    },
                )
            )
        threshold_events = [
            (index, event_type, payload)
            for index, (event_type, payload) in enumerate(events)
            if event_type in {"egress.exfil_soft_alert", "egress.exfil_hard_halt"}
        ]
        threshold_types = [event_type for _, event_type, _ in threshold_events]
        if len(threshold_types) != len(set(threshold_types)):
            raise SandboxRuntimeUnavailableError("egress sidecar emitted duplicate exfil threshold events")
        if "egress.exfil_hard_halt" in threshold_types:
            if "egress.exfil_soft_alert" not in threshold_types or threshold_types.index(
                "egress.exfil_soft_alert"
            ) > threshold_types.index("egress.exfil_hard_halt"):
                raise SandboxRuntimeUnavailableError("egress sidecar hard threshold preceded its soft alert")
        for _, event_type, payload in threshold_events:
            expected_threshold = (
                manifest.exfil_thresholds.soft_bytes
                if event_type == "egress.exfil_soft_alert"
                else manifest.exfil_thresholds.hard_bytes
            )
            expected_action = "alert" if event_type == "egress.exfil_soft_alert" else "drop_and_halt"
            bytes_to_upstream = payload.get("bytes_to_upstream")
            attempted_bytes = payload.get("attempted_bytes")
            dropped_bytes = payload.get("dropped_bytes")
            if (
                isinstance(bytes_to_upstream, bool)
                or not isinstance(bytes_to_upstream, int)
                or bytes_to_upstream < expected_threshold
                or bytes_to_upstream > manifest.exfil_thresholds.hard_bytes
                or payload.get("threshold_bytes") != expected_threshold
                or payload.get("action") != expected_action
                or isinstance(dropped_bytes, bool)
                or not isinstance(dropped_bytes, int)
                or dropped_bytes < 0
                or isinstance(attempted_bytes, bool)
                or not isinstance(attempted_bytes, int)
                or attempted_bytes < bytes_to_upstream + dropped_bytes
            ):
                raise SandboxRuntimeUnavailableError("egress sidecar emitted invalid exfil threshold evidence")
            if event_type == "egress.exfil_hard_halt" and bytes_to_upstream != expected_threshold:
                raise SandboxRuntimeUnavailableError("egress sidecar hard threshold byte count differs from policy")
        return events

    def _ensure_docker_api_runtime_available(self, security_spec: SandboxSecuritySpec) -> None:
        if security_spec.runtime_class != "gvisor":
            return
        info = self._docker_api_request("GET", "/info", expected=(200,))
        runtimes = info.get("Runtimes")
        if not isinstance(runtimes, dict) or security_spec.docker_runtime not in runtimes:
            raise SandboxRuntimeUnavailableError(
                f"gVisor Docker runtime {security_spec.docker_runtime!r} is unavailable"
            )
        self._verify_gvisor_runtime_inventory_entry(
            security_spec.docker_runtime,
            runtimes[security_spec.docker_runtime],
        )

    @staticmethod
    def _verify_gvisor_runtime_inventory_entry(runtime_name: str | None, entry: Any) -> None:
        if not isinstance(entry, dict):
            return
        runtime_path = entry.get("path", entry.get("Path"))
        if isinstance(runtime_path, str) and runtime_path and Path(runtime_path).name != "runsc":
            raise SandboxRuntimeUnavailableError(
                f"gVisor Docker runtime {runtime_name!r} is not backed by runsc"
            )
        runtime_args = entry.get("args", entry.get("Args", entry.get("runtimeArgs")))
        if isinstance(runtime_args, list) and runtime_args and "--oci-seccomp" not in runtime_args:
            raise SandboxRuntimeUnavailableError(
                f"gVisor Docker runtime {runtime_name!r} does not enable --oci-seccomp"
            )

    @staticmethod
    def _verify_docker_api_security_attestation(
        inspected: dict[str, Any],
        security_spec: SandboxSecuritySpec,
    ) -> None:
        host_config = inspected.get("HostConfig")
        if not isinstance(host_config, dict):
            raise SandboxRuntimeUnavailableError("Docker inspect omitted HostConfig runtime evidence")
        if host_config.get("Runtime") != security_spec.docker_runtime:
            raise SandboxRuntimeUnavailableError("Docker did not bind the requested gVisor runtime")
        security_opts = host_config.get("SecurityOpt")
        expected_seccomp = f"seccomp={security_spec.seccomp_profile_json}"
        if not isinstance(security_opts, list) or expected_seccomp not in security_opts:
            raise SandboxRuntimeUnavailableError("Docker did not bind the verified seccomp profile")
        inspected_mounts = host_config.get("Mounts")
        if not isinstance(inspected_mounts, list):
            raise SandboxRuntimeUnavailableError("Docker inspect omitted trust mount evidence")
        expected_mounts = {
            (mount.source, mount.target): mount
            for mount in security_spec.trust_mounts
        }
        observed_mounts: dict[tuple[str, str], dict[str, Any]] = {}
        for mount in inspected_mounts:
            if isinstance(mount, dict):
                source = mount.get("Source")
                target = mount.get("Target")
                if isinstance(source, str) and isinstance(target, str):
                    observed_mounts[(source, target)] = mount
        if set(observed_mounts) != set(expected_mounts):
            raise SandboxRuntimeUnavailableError("Docker trust mount set differs from the operator-owned spec")
        if any(not observed_mounts[key].get("ReadOnly", False) for key in expected_mounts):
            raise SandboxRuntimeUnavailableError("Docker trust mount is not read-only")

    @staticmethod
    def _runtime_launch_evidence(
        *,
        handle: SandboxHandle,
        container_id: str,
        security_spec: SandboxSecuritySpec,
        attestation_source: Literal["docker-api-inspect", "docker-cli-command"],
    ) -> DockerRuntimeLaunchEvidence:
        assert security_spec.docker_runtime is not None
        assert security_spec.seccomp_profile_hash is not None
        return DockerRuntimeLaunchEvidence(
            sandbox_id=handle.sandbox_id,
            container_id=container_id,
            runtime_class=security_spec.runtime_class,
            docker_runtime=security_spec.docker_runtime,
            seccomp_profile_hash=security_spec.seccomp_profile_hash,
            trust_mounts=security_spec.trust_mounts,
            attestation_source=attestation_source,
        )

    def _wait_for_container_with_meter(
        self,
        *,
        container_id: str,
        request: LaunchRequest,
        started_at: float,
        meter_sample_sink: Callable[[ResourceMeterSample], None] | None,
        runtime_halt_probe: Callable[[], _RuntimeHaltSignal | tuple[str, tuple[str, ...]] | None] | None = None,
        pre_state_halt_probe: Callable[[], _RuntimeHaltSignal | tuple[str, tuple[str, ...]] | None] | None = None,
        halt_telemetry_sink: Callable[[SandboxHaltTelemetry], None] | None = None,
    ) -> tuple[int | None, bool, str, BudgetUsage, SandboxPartialResult | None]:
        envelope = request.requested_envelope
        sample_seq = 0
        last_sample_at: float | None = None
        last_sample: ResourceMeterSample | None = None
        next_sample_at = started_at

        def emit(sample: ResourceMeterSample) -> None:
            nonlocal last_sample, last_sample_at
            last_sample = sample
            last_sample_at = time.monotonic()
            if meter_sample_sink is not None:
                meter_sample_sink(sample)

        def halt_from_signal(
            signal_value: _RuntimeHaltSignal | tuple[str, tuple[str, ...]],
            *,
            now: float,
            elapsed_s: float,
            default_source: str,
        ) -> tuple[int | None, bool, str, BudgetUsage, SandboxPartialResult]:
            nonlocal sample_seq
            if isinstance(signal_value, _RuntimeHaltSignal):
                reason = signal_value.reason
                dimensions = signal_value.dimensions
                revocation_acknowledged_at = signal_value.revocation_acknowledged_at
                source = signal_value.source
            else:
                reason, dimensions = signal_value
                revocation_acknowledged_at = None
                source = default_source
            sample_seq += 1
            sample = ResourceMeterSample(
                sample_seq=sample_seq,
                elapsed_s=elapsed_s,
                cadence_s=0.0 if last_sample_at is None else max(now - last_sample_at, 0.0),
                usage=_runtime_budget_usage(envelope, elapsed_s),
                source=source,
                **self._gpu_telemetry_sample_fields(),
                breached_dimensions=dimensions or (reason,),
                halted=True,
            )
            emit(sample)
            return self._kill_metered_container(
                container_id=container_id,
                request=request,
                started_at=started_at,
                reason=reason,
                last_sample=sample,
                sample_seq=sample_seq,
                meter_sample_sink=meter_sample_sink,
                halt_telemetry_sink=halt_telemetry_sink,
                revocation_acknowledged_at=revocation_acknowledged_at,
            )

        while True:
            now = time.monotonic()
            elapsed_s = now - started_at
            if last_sample_at is not None and now - last_sample_at > self._meter_gap_halt_s:
                sample_seq += 1
                gap_s = now - last_sample_at
                sample = ResourceMeterSample(
                    sample_seq=sample_seq,
                    elapsed_s=elapsed_s,
                    cadence_s=gap_s,
                    usage=_runtime_budget_usage(envelope, elapsed_s),
                    source="docker-api-cgroup-gap",
                    **self._gpu_telemetry_sample_fields(),
                    breached_dimensions=("meter_gap",),
                    halted=True,
                    conservative_gap_s=gap_s,
                )
                emit(sample)
                return self._kill_metered_container(
                    container_id=container_id,
                    request=request,
                    started_at=started_at,
                    reason="meter_gap",
                    last_sample=sample,
                    sample_seq=sample_seq,
                    meter_sample_sink=meter_sample_sink,
                    halt_telemetry_sink=halt_telemetry_sink,
                )

            pre_state_halt = pre_state_halt_probe() if pre_state_halt_probe is not None else None
            if pre_state_halt is not None:
                return halt_from_signal(
                    pre_state_halt,
                    now=now,
                    elapsed_s=elapsed_s,
                    default_source="runtime-security-probe",
                )

            state = self._docker_api_request("GET", f"/containers/{container_id}/json", expected=(200,), timeout=1)
            container_state = state.get("State") or {}
            if not container_state.get("Running", False):
                duration_s = time.monotonic() - started_at
                usage = _max_budget_usage(
                    last_sample.usage if last_sample is not None else BudgetUsage(),
                    _runtime_budget_usage(envelope, duration_s),
                )
                if last_sample is None:
                    sample_seq += 1
                    emit(
                        ResourceMeterSample(
                            sample_seq=sample_seq,
                            elapsed_s=duration_s,
                            cadence_s=0.0,
                            usage=usage,
                            source="docker-api-cgroup-final",
                            **self._gpu_telemetry_sample_fields(),
                        )
                    )
                return int(container_state.get("ExitCode", 1)), False, "", usage, None

            runtime_halt = runtime_halt_probe() if runtime_halt_probe is not None else None
            if runtime_halt is not None:
                return halt_from_signal(
                    runtime_halt,
                    now=now,
                    elapsed_s=elapsed_s,
                    default_source="runtime-token-verifier",
                )

            if now >= next_sample_at:
                sample_seq += 1
                sample = self._docker_api_resource_sample(
                    container_id=container_id,
                    envelope=envelope,
                    started_at=started_at,
                    sample_seq=sample_seq,
                    previous_sample_at=last_sample_at,
                )
                breach_dimensions = _budget_usage_breach_dimensions(request.budget_token.caps, sample.usage)
                requested_wallclock_exceeded = envelope.wallclock_s > 0 and sample.elapsed_s >= envelope.wallclock_s
                halted = bool(breach_dimensions) or requested_wallclock_exceeded
                sample = replace(
                    sample,
                    breached_dimensions=breach_dimensions,
                    halted=halted,
                )
                emit(sample)
                if halted:
                    reason = "budget_caps" if breach_dimensions else "wallclock_timeout"
                    return self._kill_metered_container(
                        container_id=container_id,
                        request=request,
                        started_at=started_at,
                        reason=reason,
                        last_sample=sample,
                        sample_seq=sample_seq,
                        meter_sample_sink=meter_sample_sink,
                        halt_telemetry_sink=halt_telemetry_sink,
                    )
                next_sample_at = time.monotonic() + self._meter_interval_s
                if envelope.wallclock_s > 0:
                    next_sample_at = min(next_sample_at, started_at + envelope.wallclock_s)

            sleep_until = min(next_sample_at, started_at + max(envelope.wallclock_s, 0.0))
            sleep_s = max(min(sleep_until - time.monotonic(), self._meter_interval_s / 4, 0.1), 0.01)
            time.sleep(sleep_s)

    def _kill_metered_container(
        self,
        *,
        container_id: str,
        request: LaunchRequest,
        started_at: float,
        reason: str,
        last_sample: ResourceMeterSample,
        sample_seq: int,
        meter_sample_sink: Callable[[ResourceMeterSample], None] | None,
        halt_telemetry_sink: Callable[[SandboxHaltTelemetry], None] | None = None,
        revocation_acknowledged_at: float | None = None,
    ) -> tuple[int | None, bool, str, BudgetUsage, SandboxPartialResult]:
        halt_detected_at = time.monotonic()
        freeze_completed_at: float | None = None
        terminate_completed_at: float | None = None
        freeze_succeeded = False
        terminate_succeeded = False
        stdout = ""
        stderr = ""
        stdout_bytes = 0
        stderr_bytes = 0
        logs_captured = False
        capture_error: str | None = None
        log_capture_limit_bytes = PARTIAL_RESULT_LOG_CAPTURE_LIMIT_BYTES
        logs_truncated = False

        try:
            self._docker_api_request("POST", f"/containers/{container_id}/pause", expected=(204,), timeout=2)
            freeze_succeeded = True
            freeze_completed_at = time.monotonic()
        except (SandboxRuntimeUnavailableError, TimeoutError) as exc:
            capture_error = f"freeze_failed:{type(exc).__name__}:{exc}"

        try:
            log_capture = self._docker_api_logs(container_id)
            stdout, stderr = log_capture.stdout, log_capture.stderr
            stdout_bytes = log_capture.stdout_bytes
            stderr_bytes = log_capture.stderr_bytes
            logs_captured = True
            logs_truncated = log_capture.truncated
            log_capture_limit_bytes = log_capture.log_capture_limit_bytes
        except (SandboxRuntimeUnavailableError, TimeoutError) as exc:
            message = f"capture_failed:{type(exc).__name__}:{exc}"
            capture_error = message if capture_error is None else f"{capture_error};{message}"

        if freeze_succeeded:
            try:
                self._docker_api_request("POST", f"/containers/{container_id}/unpause", expected=(204,), timeout=2)
            except (SandboxRuntimeUnavailableError, TimeoutError) as exc:
                message = f"unpause_failed:{type(exc).__name__}:{exc}"
                capture_error = message if capture_error is None else f"{capture_error};{message}"

        try:
            self._docker_api_request("POST", f"/containers/{container_id}/kill", expected=(204, 304, 404, 409), timeout=2)
            terminate_succeeded = True
            terminate_completed_at = time.monotonic()
        except (SandboxRuntimeUnavailableError, TimeoutError) as exc:
            message = f"terminate_failed:{type(exc).__name__}:{exc}"
            capture_error = message if capture_error is None else f"{capture_error};{message}"

        if halt_telemetry_sink is not None:
            halt_telemetry_sink(
                SandboxHaltTelemetry(
                    reason=reason,
                    halt_detected_elapsed_s=max(halt_detected_at - started_at, 0.0),
                    freeze_completed_elapsed_s=(
                        max(freeze_completed_at - started_at, 0.0) if freeze_completed_at is not None else None
                    ),
                    terminate_completed_elapsed_s=(
                        max(terminate_completed_at - started_at, 0.0) if terminate_completed_at is not None else None
                    ),
                    revocation_ack_to_detect_s=(
                        max(halt_detected_at - revocation_acknowledged_at, 0.0)
                        if revocation_acknowledged_at is not None
                        else None
                    ),
                    revocation_ack_to_freeze_s=(
                        max(freeze_completed_at - revocation_acknowledged_at, 0.0)
                        if freeze_completed_at is not None and revocation_acknowledged_at is not None
                        else None
                    ),
                    revocation_ack_to_terminate_s=(
                        max(terminate_completed_at - revocation_acknowledged_at, 0.0)
                        if terminate_completed_at is not None and revocation_acknowledged_at is not None
                        else None
                    ),
                )
            )

        duration_s = time.monotonic() - started_at
        final_usage = _max_budget_usage(last_sample.usage, _runtime_budget_usage(request.requested_envelope, duration_s))
        final_breach_dimensions = _budget_usage_breach_dimensions(request.budget_token.caps, final_usage)
        final_sample = replace(
            last_sample,
            sample_seq=sample_seq + 1,
            elapsed_s=duration_s,
            cadence_s=max(duration_s - last_sample.elapsed_s, 0.0),
            usage=final_usage,
            breached_dimensions=_merge_breach_dimensions(
                last_sample.breached_dimensions,
                final_breach_dimensions,
            ),
            halted=True,
        )
        if meter_sample_sink is not None:
            meter_sample_sink(final_sample)
        partial_result = SandboxPartialResult(
            reason=reason,
            stdout=stdout,
            stderr=stderr,
            captured_after_freeze=freeze_succeeded and logs_captured,
            freeze_succeeded=freeze_succeeded,
            terminate_succeeded=terminate_succeeded,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
            capture_error=capture_error,
            log_capture_limit_bytes=log_capture_limit_bytes,
            logs_truncated=logs_truncated,
        )
        return None, True, f"argus meter halted container: {reason}", final_usage, partial_result

    def _docker_api_resource_sample(
        self,
        *,
        container_id: str,
        envelope: LaunchEnvelope,
        started_at: float,
        sample_seq: int,
        previous_sample_at: float | None,
    ) -> ResourceMeterSample:
        stats_started_at = time.monotonic()
        try:
            stats = self._docker_api_request(
                "GET",
                f"/containers/{container_id}/stats?stream=false&one-shot=true",
                expected=(200,),
                timeout=max(self._meter_interval_s, 1.0),
            )
            stats_received_at = time.monotonic()
            usage = self._usage_from_docker_stats(stats, envelope, stats_received_at - started_at)
            memory_bytes = int((stats.get("memory_stats") or {}).get("usage") or 0)
            source = "docker-api-cgroup"
            conservative_gap_s = 0.0
        except (SandboxRuntimeUnavailableError, TimeoutError):
            stats_received_at = time.monotonic()
            usage = _runtime_budget_usage(envelope, stats_received_at - started_at)
            memory_bytes = 0
            source = "docker-api-cgroup-unavailable"
            conservative_gap_s = max(stats_received_at - stats_started_at, 0.0)
        dcgm_metrics = self._collect_dcgm_metric_snapshot()
        if dcgm_metrics.available and source == "docker-api-cgroup":
            source = "docker-api-cgroup+dcgm"
        cadence_s = 0.0 if previous_sample_at is None else stats_received_at - previous_sample_at
        return ResourceMeterSample(
            sample_seq=sample_seq,
            elapsed_s=stats_received_at - started_at,
            cadence_s=cadence_s,
            usage=usage,
            memory_bytes=memory_bytes,
            source=source,
            **self._gpu_telemetry_sample_fields(),
            **self._dcgm_metric_sample_fields(dcgm_metrics),
            conservative_gap_s=conservative_gap_s,
        )

    @staticmethod
    def _usage_from_docker_stats(stats: dict[str, Any], envelope: LaunchEnvelope, elapsed_s: float) -> BudgetUsage:
        cpu_stats = stats.get("cpu_stats") or {}
        cpu_usage = cpu_stats.get("cpu_usage") or {}
        cgroup_cpu_seconds = float(cpu_usage.get("total_usage") or 0.0) / 1_000_000_000.0
        conservative_usage = _runtime_budget_usage(envelope, elapsed_s)
        return replace(
            conservative_usage,
            compute_units=max(cgroup_cpu_seconds, conservative_usage.compute_units),
        )

    def _docker_api_logs(self, container_id: str) -> _DockerLogCapture:
        raw, truncated = self._docker_api_request_bytes_limited(
            "GET",
            f"/containers/{container_id}/logs?stdout=1&stderr=1",
            expected=(200,),
            timeout=1,
            max_bytes=PARTIAL_RESULT_LOG_CAPTURE_LIMIT_BYTES,
        )
        stdout, stderr = _split_docker_log_stream(raw)
        return _DockerLogCapture(
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            stdout_bytes=len(stdout),
            stderr_bytes=len(stderr),
            log_capture_limit_bytes=PARTIAL_RESULT_LOG_CAPTURE_LIMIT_BYTES,
            truncated=truncated,
        )

    def _docker_api_request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        expected: tuple[int, ...],
        timeout: float = 10,
    ) -> dict[str, Any]:
        raw = self._docker_api_request_bytes(method, path, body, expected=expected, timeout=timeout)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def _docker_api_request_bytes(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        expected: tuple[int, ...],
        timeout: float = 10,
    ) -> bytes:
        payload, _ = self._docker_api_request_bytes_limited(
            method,
            path,
            body,
            expected=expected,
            timeout=timeout,
            max_bytes=None,
        )
        return payload

    def _docker_api_request_bytes_limited(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        expected: tuple[int, ...],
        timeout: float = 10,
        max_bytes: int | None,
    ) -> tuple[bytes, bool]:
        encoded = None if body is None else json.dumps(body, sort_keys=True).encode("utf-8")
        if self._docker_socket_path is None:
            raise SandboxRuntimeUnavailableError("docker API socket is unavailable")
        connection = _UnixSocketHTTPConnection(self._docker_socket_path, timeout=timeout)
        response: http_client.HTTPResponse | None = None
        payload = b""
        truncated = False
        try:
            connection.request(
                method,
                path,
                body=encoded,
                headers={"Content-Type": "application/json"} if encoded is not None else {},
            )
            response = connection.getresponse()
            if max_bytes is None:
                payload = response.read()
            else:
                if max_bytes < 1:
                    raise ValueError("max_bytes must be positive")
                payload, truncated = _read_http_response_bounded(
                    response,
                    connection,
                    max_bytes=max_bytes,
                )
        except socket.timeout as exc:
            raise TimeoutError("docker API request timed out") from exc
        except OSError as exc:
            raise SandboxRuntimeUnavailableError("docker runtime is unavailable") from exc
        finally:
            connection.close()
        if response is None:
            raise SandboxRuntimeUnavailableError("docker API returned no response")
        if response.status not in expected:
            message = payload.decode("utf-8", errors="replace")
            raise SandboxRuntimeUnavailableError(f"docker API {method} {path} returned {response.status}: {message}")
        return payload, truncated


class _UnixSocketHTTPConnection(http_client.HTTPConnection):
    def __init__(self, socket_path: str, *, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


def _split_docker_log_stream(raw: bytes) -> tuple[bytes, bytes]:
    stdout = bytearray()
    stderr = bytearray()
    index = 0
    parsed_frames = False
    while index + 8 <= len(raw):
        stream_type = raw[index]
        size = int.from_bytes(raw[index + 4 : index + 8], "big")
        index += 8
        available = min(size, len(raw) - index)
        chunk = raw[index : index + available]
        index += available
        parsed_frames = True
        if stream_type == 2:
            stderr.extend(chunk)
        else:
            stdout.extend(chunk)
        if available < size:
            return bytes(stdout), bytes(stderr)
    if index != len(raw):
        if parsed_frames:
            return bytes(stdout), bytes(stderr)
        return raw, b""
    return bytes(stdout), bytes(stderr)


def _read_http_response_bounded(
    response: http_client.HTTPResponse,
    connection: http_client.HTTPConnection,
    *,
    max_bytes: int,
) -> tuple[bytes, bool]:
    payload = bytearray()
    truncated = False
    while len(payload) <= max_bytes:
        remaining = max_bytes + 1 - len(payload)
        if remaining <= 0:
            break
        sock = connection.sock
        previous_timeout = sock.gettimeout() if sock is not None else None
        if sock is not None:
            sock.settimeout(0.5 if not payload else 0.02)
        try:
            chunk = response.read1(min(8192, remaining))
        except socket.timeout as exc:
            if not payload:
                break
            truncated = True
            break
        finally:
            if sock is not None:
                sock.settimeout(previous_timeout)
        if not chunk:
            break
        payload.extend(chunk)
        if len(payload) > max_bytes:
            truncated = True
            break
    if len(payload) > max_bytes:
        truncated = True
        del payload[max_bytes:]
    return bytes(payload), truncated


class InMemorySandboxOrchestrator:
    """Admission-only sandbox orchestrator for M0 S10 contract semantics."""

    def __init__(
        self,
        *,
        token_service: InMemoryTokenService,
        quota_ledger: QuotaLedger,
        audit_ledger: InMemoryAuditLedger,
        policy_bundle: PolicyBundle | None = None,
        policy_service: InMemoryPolicyService | None = None,
        artifact_store: InMemoryArtifactStore | None = None,
    ) -> None:
        if policy_service is None and policy_bundle is None:
            raise PolicyDeniedError("policy_bundle or policy_service is required")
        if policy_service is not None and policy_bundle is not None:
            raise PolicyDeniedError("policy_bundle and policy_service are mutually exclusive")
        if policy_service is None:
            assert policy_bundle is not None
            policy_service = _StaticPolicyService(policy_bundle)
        self._token_service = token_service
        self._quota_ledger = quota_ledger
        self._audit_ledger = audit_ledger
        self._policy_service = policy_service
        self._artifact_store = artifact_store
        self._handles: dict[str, SandboxHandle] = {}
        self._requests: dict[str, LaunchRequest] = {}

    def launch(self, request: LaunchRequest) -> SandboxHandle:
        self._verify_tokens_for_launch(request)
        policy_bundle = self._policy_service.active_bundle
        verdict = decide_policy(policy_bundle, request)
        if not verdict.allowed:
            ceiling_violations = _policy_ceiling_violations(policy_bundle, request)
            if ceiling_violations:
                self._audit_ledger.append(
                    "ceiling.reject",
                    _policy_ceiling_reject_payload(policy_bundle, request, ceiling_violations),
                )
            self._audit_ledger.append("sandbox.denied", {"reason": verdict.deny_reason, "job_id": request.job_id})
            raise PolicyDeniedError(verdict.deny_reason or "policy denied")
        try:
            materialize_sandbox_env(request.env, request.env_allowlist)
        except PolicyDeniedError as exc:
            self._audit_ledger.append(
                "env.denied",
                {"job_id": request.job_id, "env_keys": sorted(set(request.env) & set(request.env_allowlist))},
            )
            raise PolicyDeniedError("env contains secret-shaped value") from exc
        if not _is_digest_pinned_image(request.image):
            self._audit_ledger.append("image.verify_fail", {"image": request.image, "job_id": request.job_id})
            raise PolicyDeniedError("image must be digest-pinned")

        self._quota_ledger.register_budget(request.budget_token)
        try:
            self._quota_ledger.reserve(request.budget_token.budget_id, request.requested_envelope.budget_usage())
        except BudgetExceededError:
            self._audit_ledger.append(
                "budget.reject",
                {"budget_id": request.budget_token.budget_id, "job_id": request.job_id},
            )
            raise

        launch_provenance_ref = self._emit_launch_provenance(request, verdict, policy_bundle)
        handle = SandboxHandle(
            sandbox_id=str(uuid4()),
            job_id=request.job_id,
            runtime_class=verdict.runtime_class or "gvisor",
            budget_epoch=request.budget_token.budget_epoch,
            policy_bundle_version=policy_bundle.bundle_version,
            state="ADMITTED",
            launch_provenance_ref=launch_provenance_ref,
        )
        self._handles[handle.sandbox_id] = handle
        self._requests[handle.sandbox_id] = request
        self._audit_ledger.append(
            "sandbox.launched",
            {"sandbox_id": handle.sandbox_id, "job_id": request.job_id, "runtime_class": handle.runtime_class},
        )
        return handle

    def get(self, sandbox_id: str) -> SandboxHandle:
        return self._handles[sandbox_id]

    def cancel_sandbox_job(
        self,
        *,
        job_id: str,
        sandbox_id: str,
        reason: str,
        grace_seconds: float,
    ) -> dict[str, Any]:
        handle = self.get(sandbox_id)
        if handle.job_id != job_id:
            self._audit_ledger.append(
                "sandbox.cancel_denied",
                {"sandbox_id": sandbox_id, "job_id": job_id, "handle_job_id": handle.job_id},
            )
            raise PolicyDeniedError("sandbox job_id mismatch")
        request = self._requests.get(sandbox_id)
        partial_result_ref = self._emit_cancel_partial_result(
            request=request,
            handle=handle,
            reason=reason,
            grace_seconds=grace_seconds,
        )
        if request is not None:
            self._quota_ledger.release(request.budget_token.budget_id, request.requested_envelope.budget_usage())
        cancelled_handle = replace(handle, state="TERMINATED")
        self._handles[sandbox_id] = cancelled_handle
        payload = {
            "sandbox_id": sandbox_id,
            "job_id": job_id,
            "reason": reason,
            "grace_seconds": grace_seconds,
            "state": cancelled_handle.state,
            "terminate_succeeded": True,
            "partial_result_ref": partial_result_ref,
        }
        self._audit_ledger.append("sandbox.cancelled", payload)
        return payload

    def quarantine_sandbox_job(
        self,
        *,
        job_id: str,
        sandbox_id: str,
        reason: str,
        grace_seconds: float,
        error: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        handle = self.get(sandbox_id)
        if handle.job_id != job_id:
            self._audit_ledger.append(
                "sandbox.quarantine_denied",
                {"sandbox_id": sandbox_id, "job_id": job_id, "handle_job_id": handle.job_id},
            )
            raise PolicyDeniedError("sandbox job_id mismatch")
        request = self._requests.get(sandbox_id)
        error_payload = dict(error or {})
        partial_result_ref = self._emit_quarantine_partial_result(
            request=request,
            handle=handle,
            reason=reason,
            grace_seconds=grace_seconds,
            error=error_payload,
        )
        if request is not None:
            self._quota_ledger.release(request.budget_token.budget_id, request.requested_envelope.budget_usage())
        quarantined_handle = replace(handle, state="QUARANTINED")
        self._handles[sandbox_id] = quarantined_handle
        payload: dict[str, Any] = {
            "sandbox_id": sandbox_id,
            "job_id": job_id,
            "reason": reason,
            "grace_seconds": grace_seconds,
            "state": quarantined_handle.state,
            "terminate_succeeded": True,
            "partial_result_ref": partial_result_ref,
        }
        if error_payload:
            payload["error"] = error_payload
        self._audit_ledger.append("sandbox.quarantined", payload)
        return payload

    def _emit_cancel_partial_result(
        self,
        *,
        request: LaunchRequest | None,
        handle: SandboxHandle,
        reason: str,
        grace_seconds: float,
    ) -> str | None:
        if self._artifact_store is None or request is None:
            return None
        payload = {
            "schema": "argus.s10.partial_result.v1",
            "job_id": request.job_id,
            "sandbox_id": handle.sandbox_id,
            "reason": reason,
            "grace_seconds": grace_seconds,
            "frozen_state": "FROZEN",
            "terminated_state": "TERMINATED",
            "stdout": "",
            "stderr": "",
            "captured_after_freeze": True,
            "freeze_succeeded": True,
            "terminate_succeeded": True,
            "capture_error": None,
        }
        record = self._artifact_store.create_artifact(
            kind="sandbox.partial_result",
            payload=payload,
            producer=Producer(subsystem="S10", version=handle.policy_bundle_version, job_id=request.job_id),
            lineage=Lineage(
                input_refs=tuple(ref for ref in (handle.launch_provenance_ref,) if ref),
                code_ref="argus-core:s10.in-memory-cancel",
                environment_digest="python:s10-in-memory-cancel:v1",
                job_id=request.job_id,
            ),
        )
        self._audit_ledger.append(
            "sandbox.partial_result",
            {
                "sandbox_id": handle.sandbox_id,
                "job_id": request.job_id,
                "partial_result_ref": record.artifact_ref,
                "reason": reason,
            },
        )
        return record.artifact_ref

    def _emit_quarantine_partial_result(
        self,
        *,
        request: LaunchRequest | None,
        handle: SandboxHandle,
        reason: str,
        grace_seconds: float,
        error: Mapping[str, Any],
    ) -> str | None:
        if self._artifact_store is None or request is None:
            return None
        payload: dict[str, Any] = {
            "schema": "argus.s10.partial_result.v1",
            "job_id": request.job_id,
            "sandbox_id": handle.sandbox_id,
            "reason": reason,
            "grace_seconds": grace_seconds,
            "frozen_state": "FROZEN",
            "terminated_state": "TERMINATED",
            "stdout": "",
            "stderr": "",
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "log_capture_limit_bytes": PARTIAL_RESULT_LOG_CAPTURE_LIMIT_BYTES,
            "logs_truncated": False,
            "captured_after_freeze": True,
            "freeze_succeeded": True,
            "terminate_succeeded": True,
            "capture_error": None,
        }
        if error:
            payload["error"] = dict(error)
        record = self._artifact_store.create_artifact(
            kind="sandbox.partial_result",
            payload=payload,
            producer=Producer(subsystem="S10", version=handle.policy_bundle_version, job_id=request.job_id),
            lineage=Lineage(
                input_refs=tuple(ref for ref in (handle.launch_provenance_ref,) if ref),
                code_ref="argus-core:s10.in-memory-quarantine",
                environment_digest=hash_json(
                    {
                        "kind": "argus.s10.quarantine.env.v1",
                        "launch_provenance_ref": handle.launch_provenance_ref,
                        "reason": reason,
                        "error": dict(error),
                    }
                ),
                job_id=request.job_id,
            ),
        )
        self._audit_ledger.append(
            "sandbox.partial_result",
            {
                "sandbox_id": handle.sandbox_id,
                "job_id": request.job_id,
                "partial_result_ref": record.artifact_ref,
                "reason": reason,
            },
        )
        return record.artifact_ref

    def _verify_tokens_for_launch(self, request: LaunchRequest) -> None:
        budget_verification = self._token_service.verify_budget(request.budget_token)
        if not budget_verification.valid:
            self._audit_ledger.append(
                "token.verify_fail",
                {"token": "budget", "reason": budget_verification.reason, "job_id": request.job_id},
            )
            raise TokenInvalidError(budget_verification.reason or "invalid budget token")
        scope_verification = self._token_service.verify_scope(request.scope_token)
        if not scope_verification.valid:
            self._audit_ledger.append(
                "token.verify_fail",
                {"token": "scope", "reason": scope_verification.reason, "job_id": request.job_id},
            )
            raise TokenInvalidError(scope_verification.reason or "invalid scope token")

    def _emit_launch_provenance(
        self,
        request: LaunchRequest,
        verdict: PolicyVerdict,
        policy_bundle: PolicyBundle,
    ) -> str | None:
        if self._artifact_store is None:
            return None
        exec_environment = _launch_exec_environment(request, verdict, policy_bundle)
        exec_environment_digest = hash_json(exec_environment)
        payload = {
            "exec_environment_digest": exec_environment_digest,
            "exec_environment": exec_environment,
            "launch": {
                "job_id": request.job_id,
                "subagent_id": request.subagent_id,
                "trace_id": request.trace_id,
                "budget_id": request.budget_token.budget_id,
                "budget_epoch": request.budget_token.budget_epoch,
                "scope_id": request.scope_token.scope_id,
                "policy_pin": request.policy_pin,
            },
        }
        record = self._artifact_store.create_artifact(
            kind="container",
            payload=payload,
            producer=Producer(subsystem="S10", version=policy_bundle.bundle_version, job_id=request.job_id),
            lineage=Lineage(
                input_refs=(),
                code_ref=request.image,
                environment_digest=exec_environment_digest,
                seeds=(request.trace_id,),
                job_id=request.job_id,
            ),
        )
        return record.artifact_ref


def _launch_exec_environment(
    request: LaunchRequest,
    verdict: PolicyVerdict,
    policy_bundle: PolicyBundle,
) -> dict[str, Any]:
    return {
        "image_digest": request.image,
        "runtime_class": verdict.runtime_class or "gvisor",
        "runtime_user": DOCKER_SANDBOX_USER,
        "entrypoint": list(request.entrypoint),
        "args": list(request.args),
        "env_allowlist": sorted(request.env_allowlist),
        "egress_acl": [
            asdict(rule)
            for rule in sorted(verdict.egress_acl, key=lambda item: (item.host, item.port, item.proto))
        ],
        "exfil_thresholds": asdict(policy_bundle.exfil_thresholds),
        "cgroup_limits": asdict(request.requested_envelope),
        "policy_bundle_version": policy_bundle.bundle_version,
        "seccomp_profile_hash": policy_bundle.seccomp_profile_hash,
        "risk_class": request.scope_token.scopes.sandbox_risk_class,
        "seed_material": [request.trace_id],
        "node_kernel_caps_dropped": ["ALL"],
    }


class DockerSandboxOrchestrator(InMemorySandboxOrchestrator):
    """S10 admission path wired to the Docker node supervisor."""

    def __init__(
        self,
        *,
        token_service: InMemoryTokenService,
        quota_ledger: QuotaLedger,
        audit_ledger: InMemoryAuditLedger,
        policy_bundle: PolicyBundle | None = None,
        policy_service: InMemoryPolicyService | None = None,
        artifact_store: InMemoryArtifactStore | None = None,
        supervisor: DockerSandboxSupervisor | None = None,
        price_table: PriceTable | None = None,
        price_table_trust_store: PriceTableTrustStore | None = None,
        price_table_gpu_model: str = "default",
        price_table_model_id: str = "default",
    ) -> None:
        if artifact_store is None:
            raise PolicyDeniedError("artifact_store is required for Docker launch provenance")
        if price_table is not None and price_table_trust_store is None:
            raise PriceTableSignatureError("price table trust store is required")
        super().__init__(
            token_service=token_service,
            quota_ledger=quota_ledger,
            audit_ledger=audit_ledger,
            policy_bundle=policy_bundle,
            policy_service=policy_service,
            artifact_store=artifact_store,
        )
        self._supervisor = supervisor or DockerSandboxSupervisor()
        self._price_table = price_table
        self._price_table_trust_store = price_table_trust_store
        self._price_table_gpu_model = price_table_gpu_model
        self._price_table_model_id = price_table_model_id
        self._halt_telemetry_by_sandbox: dict[str, SandboxHaltTelemetry] = {}

    def _run_supervisor(self, **kwargs: Any) -> SandboxExecutionResult:
        parameters = inspect.signature(self._supervisor.run).parameters
        accepts_arbitrary_keywords = any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            for parameter in parameters.values()
        )
        if accepts_arbitrary_keywords:
            return self._supervisor.run(**kwargs)
        supported = {key: value for key, value in kwargs.items() if key in parameters}
        return self._supervisor.run(**supported)

    def launch_and_wait(self, request: LaunchRequest) -> SandboxExecutionResult:
        handle = super().launch(request)
        policy_bundle = self._policy_service.bundle(handle.policy_bundle_version)
        materialized_env = materialize_sandbox_env(request.env, request.env_allowlist)
        reserved_usage = request.requested_envelope.budget_usage()
        meter_samples: list[ResourceMeterSample] = []
        halt_telemetry_items: list[SandboxHaltTelemetry] = []
        runtime_evidence_items: list[RuntimeLaunchEvidence] = []
        meter_halt_recorded = False
        token_revocation_halt_recorded = False

        def record_meter_sample(sample: ResourceMeterSample) -> None:
            nonlocal meter_halt_recorded, token_revocation_halt_recorded
            meter_samples.append(sample)
            payload = {
                "sandbox_id": handle.sandbox_id,
                "job_id": request.job_id,
                **_resource_meter_sample_payload(sample),
            }
            self._audit_ledger.append("meter.sample", payload)
            if sample.conservative_gap_s > 0:
                self._audit_ledger.append("meter.gap", payload)
            if sample.halted and not meter_halt_recorded:
                meter_halt_recorded = True
                self._audit_ledger.append("meter.halt", payload)
            if (
                sample.halted
                and "token_revoked" in sample.breached_dimensions
                and not token_revocation_halt_recorded
            ):
                token_revocation_halt_recorded = True
                self._audit_ledger.append(
                    "token.revocation_halt",
                    {
                        "sandbox_id": handle.sandbox_id,
                        "job_id": request.job_id,
                        "budget_id": request.budget_token.budget_id,
                        "scope_id": request.scope_token.scope_id,
                        "breached_dimensions": list(sample.breached_dimensions),
                    },
                )

        def record_halt_telemetry(telemetry: SandboxHaltTelemetry) -> None:
            halt_telemetry_items.append(telemetry)

        def record_runtime_evidence(evidence: RuntimeLaunchEvidence) -> None:
            if evidence.sandbox_id != handle.sandbox_id:
                raise SandboxRuntimeUnavailableError("runtime evidence sandbox_id mismatch")
            if evidence.runtime_class != handle.runtime_class:
                raise SandboxRuntimeUnavailableError("runtime evidence class mismatch")
            runtime_evidence_items.append(evidence)
            if isinstance(evidence, DockerRuntimeLaunchEvidence):
                if evidence.seccomp_profile_hash != policy_bundle.seccomp_profile_hash:
                    raise SandboxRuntimeUnavailableError("runtime evidence seccomp hash mismatch")
                self._audit_ledger.append(
                    "runtime.attested",
                    {
                        "sandbox_id": handle.sandbox_id,
                        "job_id": request.job_id,
                        "runtime_class": evidence.runtime_class,
                        "docker_runtime": evidence.docker_runtime,
                        "container_id": evidence.container_id,
                        "attestation_source": evidence.attestation_source,
                    },
                )
                self._audit_ledger.append(
                    "seccomp.profile_applied",
                    {
                        "sandbox_id": handle.sandbox_id,
                        "job_id": request.job_id,
                        "profile_hash": evidence.seccomp_profile_hash,
                        "policy_bundle_version": handle.policy_bundle_version,
                    },
                )
                self._audit_ledger.append(
                    "trust.mounts_applied",
                    {
                        "sandbox_id": handle.sandbox_id,
                        "job_id": request.job_id,
                        "mount_count": len(evidence.trust_mounts),
                        "all_read_only": True,
                        "mounts": [
                            {"name": mount.name, "target": mount.target, "read_only": True}
                            for mount in evidence.trust_mounts
                        ],
                    },
                )
                return
            if evidence.network_interface_count != 0:
                raise SandboxRuntimeUnavailableError("Firecracker runtime evidence reported a guest network interface")
            if not evidence.read_only_rootfs:
                raise SandboxRuntimeUnavailableError("Firecracker runtime evidence reported a writable rootfs")
            if not evidence.pid_namespace_init:
                raise SandboxRuntimeUnavailableError(
                    "Firecracker runtime evidence did not attest a dedicated PID namespace"
                )
            expected_cgroup_path = f"/{FirecrackerSandboxSupervisor._CGROUP_PARENT}/{handle.sandbox_id}"
            if evidence.cgroup_v2_path != expected_cgroup_path:
                raise SandboxRuntimeUnavailableError(
                    "Firecracker runtime evidence did not attest the dedicated cgroup v2 path"
                )
            if (
                not evidence.seccomp_enabled
                or evidence.seccomp_filter_mode != "default-built-in"
                or evidence.seccomp_filter_count < 1
            ):
                raise SandboxRuntimeUnavailableError(
                    "Firecracker runtime evidence did not attest the built-in seccomp filter"
                )
            if evidence.federated_extra_access or evidence.trust_mount_count != 0:
                raise SandboxRuntimeUnavailableError("Firecracker federated runtime received elevated trust access")
            self._audit_ledger.append(
                "runtime.attested",
                {
                    "sandbox_id": handle.sandbox_id,
                    "job_id": request.job_id,
                    "runtime_class": evidence.runtime_class,
                    "microvm_id": evidence.microvm_id,
                    "firecracker_version": evidence.firecracker_version,
                    "jailer_version": evidence.jailer_version,
                    "attestation_source": evidence.attestation_source,
                },
            )
            self._audit_ledger.append(
                "microvm.security_applied",
                {
                    "sandbox_id": handle.sandbox_id,
                    "job_id": request.job_id,
                    "kernel_image_hash": evidence.kernel_image_hash,
                    "rootfs_image_hash": evidence.rootfs_image_hash,
                    "request_drive_hash": evidence.request_drive_hash,
                    "scratch_bytes": evidence.scratch_bytes,
                    "network_interface_count": evidence.network_interface_count,
                    "jailer_uid": evidence.jailer_uid,
                    "jailer_gid": evidence.jailer_gid,
                    "pid_namespace_init": evidence.pid_namespace_init,
                    "cgroup_v2_path": evidence.cgroup_v2_path,
                    "seccomp_enabled": evidence.seccomp_enabled,
                    "seccomp_filter_mode": evidence.seccomp_filter_mode,
                    "seccomp_filter_count": evidence.seccomp_filter_count,
                    "read_only_rootfs": evidence.read_only_rootfs,
                    "policy_bundle_version": handle.policy_bundle_version,
                },
            )
            self._audit_ledger.append(
                "trust.boundary_applied",
                {
                    "sandbox_id": handle.sandbox_id,
                    "job_id": request.job_id,
                    "trust_class": request.scope_token.scopes.sandbox_risk_class,
                    "federated_extra_access": evidence.federated_extra_access,
                    "trust_mount_count": evidence.trust_mount_count,
                },
            )

        def record_egress_event(event_type: str, payload: dict[str, Any]) -> None:
            if not event_type.startswith("egress."):
                raise SandboxRuntimeUnavailableError("egress sidecar emitted a non-egress audit event")
            if payload.get("sandbox_id") != handle.sandbox_id or payload.get("job_id") != request.job_id:
                raise SandboxRuntimeUnavailableError("egress sidecar audit identity mismatch")
            if payload.get("scope_id") != request.scope_token.scope_id:
                raise SandboxRuntimeUnavailableError("egress sidecar audit scope mismatch")
            if payload.get("policy_bundle_version") != handle.policy_bundle_version:
                raise SandboxRuntimeUnavailableError("egress sidecar audit policy version mismatch")
            self._audit_ledger.append(event_type, payload)

        self._audit_ledger.append(
            "sandbox.started",
            {"sandbox_id": handle.sandbox_id, "job_id": request.job_id, "runtime_class": handle.runtime_class},
        )
        try:
            result = self._run_supervisor(
                handle=handle,
                request=request,
                materialized_env=materialized_env,
                policy_bundle=policy_bundle,
                meter_sample_sink=record_meter_sample,
                runtime_halt_probe=self._runtime_halt_probe(request),
                halt_telemetry_sink=record_halt_telemetry,
                runtime_evidence_sink=record_runtime_evidence,
                egress_audit_sink=record_egress_event,
            )
        except Exception as exc:
            self._record_runtime_failure(handle, request, reserved_usage, exc)
            raise

        expected_runtime_evidence_count = 1 if handle.runtime_class in {"gvisor", "firecracker"} else 0
        if len(runtime_evidence_items) != expected_runtime_evidence_count:
            if handle.runtime_class == "firecracker":
                message = "Firecracker launch requires exactly one host-controlled runtime attestation"
            elif handle.runtime_class == "gvisor":
                message = "gVisor launch requires exactly one host-controlled runtime attestation"
            else:
                message = "Docker launch emitted unexpected runtime attestation"
            error = SandboxRuntimeUnavailableError(
                message
            )
            self._record_runtime_failure(handle, request, reserved_usage, error)
            raise error

        if len(halt_telemetry_items) > 1:
            self._record_runtime_failure(
                handle,
                request,
                reserved_usage,
                PolicyDeniedError("sandbox emitted multiple halt telemetry records"),
            )
            raise PolicyDeniedError("sandbox emitted multiple halt telemetry records")
        halt_telemetry = halt_telemetry_items[0] if halt_telemetry_items else None
        if halt_telemetry is not None:
            self._halt_telemetry_by_sandbox[handle.sandbox_id] = halt_telemetry
            self._audit_ledger.append(
                "sandbox.halt_completed",
                {
                    "sandbox_id": handle.sandbox_id,
                    "job_id": request.job_id,
                    **_sandbox_halt_telemetry_payload(halt_telemetry),
                },
            )

        try:
            price_rollup = self._roll_up_spend(result.budget_usage)
        except PriceTableSignatureError as exc:
            self._record_runtime_failure(handle, request, reserved_usage, exc)
            raise
        result = replace(result, budget_usage=price_rollup.usage)
        final_state = _final_sandbox_state(result)
        final_handle = replace(handle, state=final_state)
        self._handles[handle.sandbox_id] = final_handle
        partial_result_ref = self._emit_partial_result(
            request=request,
            handle=final_handle,
            result=result,
        )
        event_type = "sandbox.timeout" if result.timed_out else "sandbox.exited"
        self._audit_ledger.append(
            event_type,
            {
                "sandbox_id": handle.sandbox_id,
                "job_id": request.job_id,
                "exit_code": result.exit_code,
                "duration_s": round(result.duration_s, 6),
            },
        )
        try:
            self._quota_ledger.consume(request.budget_token.budget_id, result.budget_usage)
        except BudgetExceededError:
            self._release_runtime_reservation(request, reserved_usage)
            halted_handle = replace(handle, state="BUDGET_HALTED")
            self._handles[handle.sandbox_id] = halted_handle
            self._audit_ledger.append(
                "budget.halt",
                {
                    "sandbox_id": handle.sandbox_id,
                    "budget_id": request.budget_token.budget_id,
                    "job_id": request.job_id,
                    "usage": asdict(result.budget_usage),
                },
            )
            self._emit_spend_final(
                request=request,
                handle=halted_handle,
                usage=result.budget_usage,
                price_rollup=price_rollup,
                meter_samples=tuple(meter_samples),
                partial_result_ref=partial_result_ref,
                halt_telemetry=halt_telemetry,
            )
            raise
        self._audit_ledger.append(
            "budget.consume",
            {
                "sandbox_id": handle.sandbox_id,
                "budget_id": request.budget_token.budget_id,
                "job_id": request.job_id,
                "usage": asdict(result.budget_usage),
            },
        )
        self._release_runtime_reservation(request, reserved_usage)
        self._emit_spend_final(
            request=request,
            handle=final_handle,
            usage=result.budget_usage,
            price_rollup=price_rollup,
            meter_samples=tuple(meter_samples),
            partial_result_ref=partial_result_ref,
            halt_telemetry=halt_telemetry,
        )
        return replace(result, handle=final_handle)

    def _runtime_halt_probe(
        self,
        request: LaunchRequest,
    ) -> Callable[[], _RuntimeHaltSignal | None]:
        def probe() -> _RuntimeHaltSignal | None:
            budget_verification = self._token_service.verify_budget(request.budget_token)
            if not budget_verification.valid:
                reason, dimensions = _token_runtime_halt(
                    reason=budget_verification.reason,
                    token_dimension="budget_token",
                )
                return _RuntimeHaltSignal(
                    reason=reason,
                    dimensions=dimensions,
                    revocation_acknowledged_at=(
                        self._token_service.revocation_acknowledged_at(request.budget_token.budget_id)
                        if budget_verification.reason == "revoked"
                        else None
                    ),
                )
            scope_verification = self._token_service.verify_scope(request.scope_token)
            if not scope_verification.valid:
                reason, dimensions = _token_runtime_halt(
                    reason=scope_verification.reason,
                    token_dimension="scope_token",
                )
                return _RuntimeHaltSignal(
                    reason=reason,
                    dimensions=dimensions,
                    revocation_acknowledged_at=(
                        self._token_service.revocation_acknowledged_at(request.scope_token.scope_id)
                        if scope_verification.reason == "revoked"
                        else None
                    ),
                )
            return None

        return probe

    def halt_telemetry_for(self, sandbox_id: str) -> dict[str, Any] | None:
        telemetry = self._halt_telemetry_by_sandbox.get(sandbox_id)
        return _sandbox_halt_telemetry_payload(telemetry) if telemetry is not None else None

    @property
    def price_table_version(self) -> str | None:
        return self._price_table.price_table_version if self._price_table is not None else None

    @property
    def price_table_signer_key_id(self) -> str | None:
        return self._price_table.signer_key_id if self._price_table is not None else None

    def _roll_up_spend(self, usage: BudgetUsage) -> PriceTableRollup:
        if self._price_table is None:
            exact = _decimal_wire(_decimal(usage.cost_usd))
            return PriceTableRollup(
                usage=usage,
                cost_usd_exact=exact,
                price_table_hash="",
                price_table_version="unconfigured",
                signer_key_id="unconfigured",
                gpu_model=self._price_table_gpu_model,
                model_id=self._price_table_model_id,
            )
        assert self._price_table_trust_store is not None
        self._price_table_trust_store.verify(self._price_table)
        return roll_up_price_table_usage(
            usage,
            self._price_table,
            gpu_model=self._price_table_gpu_model,
            model_id=self._price_table_model_id,
        )

    def _emit_spend_final(
        self,
        *,
        request: LaunchRequest,
        handle: SandboxHandle,
        usage: BudgetUsage,
        price_rollup: PriceTableRollup,
        meter_samples: tuple[ResourceMeterSample, ...] = (),
        partial_result_ref: str | None = None,
        halt_telemetry: SandboxHaltTelemetry | None = None,
    ) -> str | None:
        if self._artifact_store is None:
            return None
        input_refs = tuple(
            ref for ref in (handle.launch_provenance_ref, partial_result_ref) if isinstance(ref, str) and ref
        )
        price_table_payload = None
        if self._price_table is not None:
            price_table_payload = {
                **_price_table_payload(self._price_table),
                "content_hash": price_rollup.price_table_hash,
            }
        payload = {
            "schema": "argus.s10.spend.final.v1",
            "job_id": request.job_id,
            "sandbox_id": handle.sandbox_id,
            "budget_id": request.budget_token.budget_id,
            "budget_epoch": request.budget_token.budget_epoch,
            "final_state": handle.state,
            "usage": asdict(usage),
            "partial_result_captured": partial_result_ref is not None,
            "partial_result_ref": partial_result_ref,
            "halt_telemetry": (
                _sandbox_halt_telemetry_payload(halt_telemetry) if halt_telemetry is not None else None
            ),
            "usd_rollup": {
                "cost_usd": usage.cost_usd,
                "cost_usd_exact": price_rollup.cost_usd_exact,
                "formula": "cpu_seconds*usd_per_cpu_second + gpu_seconds*usd_per_gpu_second + model_tokens/1000*usd_per_1k_model_tokens",
                "gpu_model": price_rollup.gpu_model,
                "model_id": price_rollup.model_id,
                "source": "signed_price_table" if self._price_table is not None else "runtime_usage",
            },
            "price_table": price_table_payload,
            "metering": _resource_metering_payload(
                meter_samples,
                requested_wallclock_s=request.requested_envelope.wallclock_s,
            ),
        }
        environment_digest = hash_json(
            {
                "kind": "argus.s10.spend.final.env.v1",
                "launch_provenance_ref": handle.launch_provenance_ref,
                "partial_result_ref": partial_result_ref,
                "halt_telemetry": (
                    _sandbox_halt_telemetry_payload(halt_telemetry) if halt_telemetry is not None else None
                ),
                "price_table_hash": price_rollup.price_table_hash,
                "price_table_version": price_rollup.price_table_version,
            }
        )
        record = self._artifact_store.create_artifact(
            kind="spend.final",
            payload=payload,
            producer=Producer(subsystem="S10", version=handle.policy_bundle_version, job_id=request.job_id),
            lineage=Lineage(
                input_refs=input_refs,
                code_ref="argus:s10/quota-cost",
                environment_digest=environment_digest,
                seeds=(request.trace_id,),
                job_id=request.job_id,
            ),
        )
        self._audit_ledger.append(
            "spend.final",
            {
                "sandbox_id": handle.sandbox_id,
                "budget_id": request.budget_token.budget_id,
                "job_id": request.job_id,
                "artifact_ref": record.artifact_ref,
                "price_table_version": price_rollup.price_table_version,
                "cost_usd_exact": price_rollup.cost_usd_exact,
            },
        )
        return record.artifact_ref

    def _emit_partial_result(
        self,
        *,
        request: LaunchRequest,
        handle: SandboxHandle,
        result: SandboxExecutionResult,
    ) -> str | None:
        if self._artifact_store is None or result.partial_result is None:
            return None
        partial = result.partial_result
        freeze_payload = {
            "sandbox_id": handle.sandbox_id,
            "job_id": request.job_id,
            "reason": partial.reason,
            "state": partial.frozen_state,
            "final_state": handle.state,
            "freeze_succeeded": partial.freeze_succeeded,
        }
        try:
            self._audit_ledger.append("sandbox.freeze", freeze_payload)
            payload = {
                "schema": "argus.s10.partial_result.v1",
                "job_id": request.job_id,
                "sandbox_id": handle.sandbox_id,
                "budget_id": request.budget_token.budget_id,
                "budget_epoch": request.budget_token.budget_epoch,
                "reason": partial.reason,
                "final_state": handle.state,
                "frozen_state": partial.frozen_state,
                "terminated_state": partial.terminated_state,
                "stdout": partial.stdout,
                "stderr": partial.stderr,
                "stdout_bytes": partial.stdout_bytes,
                "stderr_bytes": partial.stderr_bytes,
                "log_capture_limit_bytes": partial.log_capture_limit_bytes,
                "logs_truncated": partial.logs_truncated,
                "captured_after_freeze": partial.captured_after_freeze,
                "freeze_succeeded": partial.freeze_succeeded,
                "terminate_succeeded": partial.terminate_succeeded,
                "capture_error": partial.capture_error,
            }
            environment_digest = hash_json(
                {
                    "kind": "argus.s10.partial_result.env.v1",
                    "launch_provenance_ref": handle.launch_provenance_ref,
                    "reason": partial.reason,
                    "image": request.image,
                    "frozen_state": partial.frozen_state,
                    "terminated_state": partial.terminated_state,
                }
            )
            input_refs = (handle.launch_provenance_ref,) if handle.launch_provenance_ref else ()
            record = self._artifact_store.create_artifact(
                kind="sandbox.partial_result",
                payload=payload,
                producer=Producer(subsystem="S10", version=handle.policy_bundle_version, job_id=request.job_id),
                lineage=Lineage(
                    input_refs=input_refs,
                    code_ref=request.image,
                    environment_digest=environment_digest,
                    seeds=(request.trace_id,),
                    job_id=request.job_id,
                ),
            )
            self._audit_ledger.append(
                "sandbox.partial_result",
                {
                    "sandbox_id": handle.sandbox_id,
                    "job_id": request.job_id,
                    "artifact_ref": record.artifact_ref,
                    "stdout_bytes": partial.stdout_bytes,
                    "stderr_bytes": partial.stderr_bytes,
                    "log_capture_limit_bytes": partial.log_capture_limit_bytes,
                    "logs_truncated": partial.logs_truncated,
                    "captured_after_freeze": partial.captured_after_freeze,
                    "frozen_state": partial.frozen_state,
                    "terminated_state": partial.terminated_state,
                },
            )
            self._audit_ledger.append(
                "sandbox.terminate",
                {
                    "sandbox_id": handle.sandbox_id,
                    "job_id": request.job_id,
                    "reason": partial.reason,
                    "state": partial.terminated_state,
                    "final_state": handle.state,
                    "terminate_succeeded": partial.terminate_succeeded,
                },
            )
            return record.artifact_ref
        finally:
            self._handles[handle.sandbox_id] = handle

    def _release_runtime_reservation(self, request: LaunchRequest, reserved_usage: BudgetUsage) -> None:
        self._quota_ledger.release(request.budget_token.budget_id, reserved_usage)
        self._audit_ledger.append(
            "budget.release",
            {
                "budget_id": request.budget_token.budget_id,
                "job_id": request.job_id,
                "usage": asdict(reserved_usage),
            },
        )

    def _record_runtime_failure(
        self,
        handle: SandboxHandle,
        request: LaunchRequest,
        reserved_usage: BudgetUsage,
        exc: Exception,
    ) -> None:
        self._release_runtime_reservation(request, reserved_usage)
        failed_handle = replace(handle, state="FAILED")
        self._handles[handle.sandbox_id] = failed_handle
        self._audit_ledger.append(
            "sandbox.runtime_failed",
            {
                "sandbox_id": handle.sandbox_id,
                "job_id": request.job_id,
                "error_type": type(exc).__name__,
            },
        )


def _final_sandbox_state(result: SandboxExecutionResult) -> str:
    if result.timed_out:
        return "TIMED_OUT"
    if result.exit_code == 0:
        return "SUCCEEDED"
    return "FAILED"
