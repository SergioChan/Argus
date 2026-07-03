"""S10 token, quota, policy, and sandbox launch semantics."""

from __future__ import annotations

import http.client as http_client
import hmac
import json
import os
import re
import shutil
import socket
import subprocess
import time
from dataclasses import asdict, dataclass, field, replace
from decimal import Decimal
from hashlib import sha256
from typing import Any, Callable, Iterable, Literal, Mapping, NoReturn, Protocol
from uuid import uuid4
from weakref import ref

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_json_bytes
from .c3 import C3_SIGNATURE_PREFIX, SIGNATURE_VERIFICATION_ACCEPTED, VerifierKey
from .hashing import BLAKE3_PREFIX, hash_json
from .s8 import ArtifactRecord, InMemoryArtifactStore, Lineage, Producer


SIGNATURE_PREFIX = "hmac-sha256:"
TOKEN_ED25519_SIGNATURE_PREFIX = "ed25519:"
DOCKER_SANDBOX_USER = "65532:65532"
PARTIAL_RESULT_LOG_CAPTURE_LIMIT_BYTES = 64 * 1024
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
class PolicyBundle:
    bundle_version: str
    egress_allowlist: tuple[EgressRule, ...]
    resource_ceilings: ResourceCeilings
    risk_to_runtime: dict[RiskClass, RuntimeClass]
    seccomp_profile_hash: str
    signer_key_id: str
    signature: str


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
class _DockerLogCapture:
    stdout: str
    stderr: str
    stdout_bytes: int
    stderr_bytes: int
    log_capture_limit_bytes: int
    truncated: bool


@dataclass(frozen=True)
class EgressDecision:
    allowed: bool
    reason: str


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
        digest = hmac.new(key.secret, canonical_json_bytes(report_with_empty_signature), sha256).hexdigest()
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

    def revoke(self, token_id: str) -> None:
        self._revocation_store.revoke(token_id)

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

    def register_budget(self, token: BudgetToken) -> None:
        self._states.setdefault(
            token.budget_id,
            QuotaState(caps=token.caps, reserved=BudgetUsage(), actual=BudgetUsage()),
        )

    def reserve(self, budget_id: str, usage: BudgetUsage) -> None:
        state = self._require_state(budget_id)
        self._assert_not_halted(budget_id, state)
        next_reserved = self._add_usage(state.reserved, usage)
        self._assert_within_caps(state.caps, next_reserved, state.actual, budget_id)
        self._states[budget_id] = replace(state, reserved=next_reserved)

    def consume(self, budget_id: str, usage: BudgetUsage) -> None:
        state = self._require_state(budget_id)
        self._assert_not_halted(budget_id, state)
        next_actual = self._add_usage(state.actual, usage)
        try:
            self._assert_actual_within_caps(state.caps, next_actual)
        except BudgetExceededError:
            self._states[budget_id] = replace(state, actual=next_actual, halted=True)
            raise
        self._states[budget_id] = replace(state, actual=next_actual)

    def release(self, budget_id: str, usage: BudgetUsage | None = None) -> None:
        state = self._require_state(budget_id)
        released = usage or state.reserved
        self._states[budget_id] = replace(state, reserved=self._subtract_usage(state.reserved, released))

    def remaining(self, budget_id: str) -> BudgetUsage:
        state = self._require_state(budget_id)
        return self._subtract_usage(self._caps_to_usage(state.caps), self._add_usage(state.reserved, state.actual))

    def state(self, budget_id: str) -> QuotaState:
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
    envelope = request.requested_envelope
    ceilings = bundle.resource_ceilings
    if envelope.cpu_m > ceilings.cpu_m:
        return PolicyVerdict(False, None, (), "cpu_ceiling")
    if envelope.mem_bytes > ceilings.mem_bytes:
        return PolicyVerdict(False, None, (), "memory_ceiling")
    if envelope.gpu_count > ceilings.gpu_count:
        return PolicyVerdict(False, None, (), "gpu_ceiling")
    if envelope.wallclock_s > ceilings.wallclock_s:
        return PolicyVerdict(False, None, (), "wallclock_ceiling")
    if envelope.estimated_cost_usd > ceilings.max_cost_usd:
        return PolicyVerdict(False, None, (), "cost_ceiling")
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
        "breached_dimensions": list(sample.breached_dimensions),
        "halted": sample.halted,
        "conservative_gap_s": round(sample.conservative_gap_s, 6),
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
        "samples": [_resource_meter_sample_payload(sample) for sample in samples],
    }


def _timeout_stream(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


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

    def decide(self, scope_token: ScopeToken, *, host: str, port: int, proto: str, sni: str) -> EgressDecision:
        requested = EgressRule(host=host, port=port, proto=proto)
        allowed = requested in set(scope_token.scopes.egress_allowlist) & set(self._bundle.egress_allowlist)
        if not allowed:
            return EgressDecision(False, "egress_denied")
        if sni != host:
            return EgressDecision(False, "sni_mismatch")
        return EgressDecision(True, "allowed")


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

    def decide(self, request: LaunchRequest) -> PolicyVerdict:
        return decide_policy(self._bundle, request)


def _policy_bundle_signature_payload(bundle: PolicyBundle) -> bytes:
    return canonical_json_bytes({**asdict(bundle), "signature": ""})


class StoreWriterBroker:
    """Brokered S8 write path for sandbox-origin artifacts."""

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

    def _broker(self) -> StoreWriterBroker:
        broker = self._broker_ref()
        if broker is None:
            raise ScopeDeniedError("store broker handle is no longer valid")
        return broker


class BrokeredStoreClient:
    """Sandbox-facing store client exposing only the brokered artifact put path."""

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


class DockerSandboxSupervisor:
    """Node-level Docker supervisor that launches digest-pinned containers with no network."""

    def __init__(
        self,
        *,
        docker_bin: str | None = None,
        meter_interval_s: float = 1.0,
        meter_gap_halt_s: float = 5.0,
        gpu_telemetry: GpuTelemetrySnapshot | None = None,
    ) -> None:
        self._docker_bin = docker_bin or shutil.which("docker") or "docker"
        self._meter_interval_s = min(max(float(meter_interval_s), 0.1), 5.0)
        self._meter_gap_halt_s = max(float(meter_gap_halt_s), self._meter_interval_s)
        self._docker_socket_path = _resolve_docker_socket_path()
        self._gpu_telemetry = gpu_telemetry or discover_gpu_telemetry()

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

    def run(
        self,
        *,
        handle: SandboxHandle,
        request: LaunchRequest,
        materialized_env: dict[str, str],
        meter_sample_sink: Callable[[ResourceMeterSample], None] | None = None,
        runtime_halt_probe: Callable[[], tuple[str, tuple[str, ...]] | None] | None = None,
    ) -> SandboxExecutionResult:
        if not _is_digest_pinned_image(request.image):
            raise PolicyDeniedError("image must be digest-pinned")
        if not request.entrypoint:
            raise PolicyDeniedError("entrypoint is required")
        if self._docker_socket_path is not None:
            try:
                return self._run_via_docker_api(
                    handle=handle,
                    request=request,
                    materialized_env=materialized_env,
                    meter_sample_sink=meter_sample_sink,
                    runtime_halt_probe=runtime_halt_probe,
                )
            except SandboxRuntimeUnavailableError:
                if shutil.which(self._docker_bin) is None and "/" not in self._docker_bin:
                    raise
        if shutil.which(self._docker_bin) is None and "/" not in self._docker_bin:
            raise SandboxRuntimeUnavailableError("docker runtime is unavailable")

        container_name = f"argus-{handle.sandbox_id.replace('-', '')[:24]}"
        command = self._docker_command(container_name, request, materialized_env)
        started_at = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=max(request.requested_envelope.wallclock_s, 1),
            )
            duration_s = time.monotonic() - started_at
            return SandboxExecutionResult(
                handle=handle,
                exit_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
                timed_out=False,
                duration_s=duration_s,
                budget_usage=_runtime_budget_usage(request.requested_envelope, duration_s),
            )
        except FileNotFoundError as exc:
            raise SandboxRuntimeUnavailableError("docker runtime is unavailable") from exc
        except subprocess.TimeoutExpired as exc:
            self._force_remove(container_name)
            duration_s = time.monotonic() - started_at
            return SandboxExecutionResult(
                handle=handle,
                exit_code=None,
                stdout=_timeout_stream(exc.stdout),
                stderr=_timeout_stream(exc.stderr),
                timed_out=True,
                duration_s=duration_s,
                budget_usage=_runtime_budget_usage(request.requested_envelope, duration_s),
            )

    def _docker_command(self, container_name: str, request: LaunchRequest, env: dict[str, str]) -> list[str]:
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
        for key in sorted(env):
            command.extend(("--env", f"{key}={env[key]}"))
        command.extend(("--entrypoint", request.entrypoint[0]))
        command.append(request.image)
        command.extend(request.entrypoint[1:])
        command.extend(request.args)
        return command

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
        runtime_halt_probe: Callable[[], tuple[str, tuple[str, ...]] | None] | None = None,
    ) -> SandboxExecutionResult:
        container_name = f"argus-{handle.sandbox_id.replace('-', '')[:24]}"
        envelope = request.requested_envelope
        container_id: str | None = None
        started_at = time.monotonic()
        try:
            create_response = self._docker_api_request(
                "POST",
                f"/containers/create?name={container_name}",
                {
                    "Image": request.image,
                    "Entrypoint": [request.entrypoint[0]],
                    "Cmd": list(request.entrypoint[1:]) + list(request.args),
                    "Env": [f"{key}={value}" for key, value in sorted(materialized_env.items())],
                    "User": DOCKER_SANDBOX_USER,
                    "NetworkDisabled": True,
                    "HostConfig": {
                        "AutoRemove": False,
                        "ReadonlyRootfs": True,
                        "CapDrop": ["ALL"],
                        "SecurityOpt": ["no-new-privileges"],
                        "NetworkMode": "none",
                        "PidsLimit": max(envelope.pids, 1),
                        "Memory": max(envelope.mem_bytes, 4 * 1024 * 1024),
                        "NanoCpus": max(envelope.cpu_m, 1) * 1_000_000,
                        "Tmpfs": {
                            "/tmp": f"rw,noexec,nosuid,nodev,size={max(envelope.scratch_bytes, 1024 * 1024)}"
                        },
                    },
                },
                expected=(201,),
            )
            container_id = str(create_response.get("Id") or "")
            if not container_id:
                raise SandboxRuntimeUnavailableError("docker runtime did not return a container id")
            self._docker_api_request("POST", f"/containers/{container_id}/start", expected=(204, 304))
            exit_code, timed_out, runtime_stderr, budget_usage, partial_result = self._wait_for_container_with_meter(
                container_id=container_id,
                request=request,
                started_at=started_at,
                meter_sample_sink=meter_sample_sink,
                runtime_halt_probe=runtime_halt_probe,
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
            if container_id:
                self._docker_api_request("DELETE", f"/containers/{container_id}?force=true", expected=(204, 404))

    def _wait_for_container_with_meter(
        self,
        *,
        container_id: str,
        request: LaunchRequest,
        started_at: float,
        meter_sample_sink: Callable[[ResourceMeterSample], None] | None,
        runtime_halt_probe: Callable[[], tuple[str, tuple[str, ...]] | None] | None = None,
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
                reason, dimensions = runtime_halt
                sample_seq += 1
                sample = ResourceMeterSample(
                    sample_seq=sample_seq,
                    elapsed_s=elapsed_s,
                    cadence_s=0.0 if last_sample_at is None else max(now - last_sample_at, 0.0),
                    usage=_runtime_budget_usage(envelope, elapsed_s),
                    source="runtime-token-verifier",
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
    ) -> tuple[int | None, bool, str, BudgetUsage, SandboxPartialResult]:
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
        except (SandboxRuntimeUnavailableError, TimeoutError) as exc:
            message = f"terminate_failed:{type(exc).__name__}:{exc}"
            capture_error = message if capture_error is None else f"{capture_error};{message}"

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
        cadence_s = 0.0 if previous_sample_at is None else stats_received_at - previous_sample_at
        return ResourceMeterSample(
            sample_seq=sample_seq,
            elapsed_s=stats_received_at - started_at,
            cadence_s=cadence_s,
            usage=usage,
            memory_bytes=memory_bytes,
            source=source,
            **self._gpu_telemetry_sample_fields(),
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

    def launch(self, request: LaunchRequest) -> SandboxHandle:
        self._verify_tokens_for_launch(request)
        policy_bundle = self._policy_service.active_bundle
        verdict = self._policy_service.decide(request)
        if not verdict.allowed:
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
            self._audit_ledger.append("budget.reject", {"budget_id": request.budget_token.budget_id})
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
        self._audit_ledger.append(
            "sandbox.launched",
            {"sandbox_id": handle.sandbox_id, "job_id": request.job_id, "runtime_class": handle.runtime_class},
        )
        return handle

    def get(self, sandbox_id: str) -> SandboxHandle:
        return self._handles[sandbox_id]

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
        "cgroup_limits": asdict(request.requested_envelope),
        "policy_bundle_version": policy_bundle.bundle_version,
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

    def launch_and_wait(self, request: LaunchRequest) -> SandboxExecutionResult:
        handle = super().launch(request)
        materialized_env = materialize_sandbox_env(request.env, request.env_allowlist)
        reserved_usage = request.requested_envelope.budget_usage()
        meter_samples: list[ResourceMeterSample] = []
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

        self._audit_ledger.append(
            "sandbox.started",
            {"sandbox_id": handle.sandbox_id, "job_id": request.job_id, "runtime_class": handle.runtime_class},
        )
        try:
            try:
                result = self._supervisor.run(
                    handle=handle,
                    request=request,
                    materialized_env=materialized_env,
                    meter_sample_sink=record_meter_sample,
                    runtime_halt_probe=self._runtime_halt_probe(request),
                )
            except TypeError as exc:
                if "runtime_halt_probe" in str(exc):
                    try:
                        result = self._supervisor.run(
                            handle=handle,
                            request=request,
                            materialized_env=materialized_env,
                            meter_sample_sink=record_meter_sample,
                        )
                    except TypeError as meter_exc:
                        if "meter_sample_sink" not in str(meter_exc):
                            raise
                        result = self._supervisor.run(
                            handle=handle,
                            request=request,
                            materialized_env=materialized_env,
                        )
                elif "meter_sample_sink" in str(exc):
                    result = self._supervisor.run(
                        handle=handle,
                        request=request,
                        materialized_env=materialized_env,
                    )
                else:
                    raise
        except Exception as exc:
            self._record_runtime_failure(handle, request, reserved_usage, exc)
            raise

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
            )
            raise
        self._audit_ledger.append(
            "budget.consume",
            {
                "sandbox_id": handle.sandbox_id,
                "budget_id": request.budget_token.budget_id,
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
        )
        return replace(result, handle=final_handle)

    def _runtime_halt_probe(self, request: LaunchRequest) -> Callable[[], tuple[str, tuple[str, ...]] | None]:
        def probe() -> tuple[str, tuple[str, ...]] | None:
            budget_verification = self._token_service.verify_budget(request.budget_token)
            if not budget_verification.valid:
                return _token_runtime_halt(
                    reason=budget_verification.reason,
                    token_dimension="budget_token",
                )
            scope_verification = self._token_service.verify_scope(request.scope_token)
            if not scope_verification.valid:
                return _token_runtime_halt(
                    reason=scope_verification.reason,
                    token_dimension="scope_token",
                )
            return None

        return probe

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
            "freeze_succeeded": partial.freeze_succeeded,
        }
        self._audit_ledger.append("sandbox.freeze", freeze_payload)
        payload = {
            "schema": "argus.s10.partial_result.v1",
            "job_id": request.job_id,
            "sandbox_id": handle.sandbox_id,
            "budget_id": request.budget_token.budget_id,
            "budget_epoch": request.budget_token.budget_epoch,
            "reason": partial.reason,
            "final_state": handle.state,
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
            },
        )
        self._audit_ledger.append(
            "sandbox.terminate",
            {
                "sandbox_id": handle.sandbox_id,
                "job_id": request.job_id,
                "reason": partial.reason,
                "terminate_succeeded": partial.terminate_succeeded,
            },
        )
        return record.artifact_ref

    def _release_runtime_reservation(self, request: LaunchRequest, reserved_usage: BudgetUsage) -> None:
        self._quota_ledger.release(request.budget_token.budget_id, reserved_usage)
        self._audit_ledger.append(
            "budget.release",
            {
                "budget_id": request.budget_token.budget_id,
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
