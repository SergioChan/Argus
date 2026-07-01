"""In-memory S10 token, quota, policy, and sandbox admission semantics."""

from __future__ import annotations

import hmac
import time
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
from typing import Any, Callable
from uuid import uuid4

from .canonical import canonical_json_bytes
from .hashing import BLAKE3_PREFIX, hash_json


SIGNATURE_PREFIX = "hmac-sha256:"


class S10Error(Exception):
    """Base class for S10 semantic failures."""


class TokenInvalidError(S10Error):
    """Raised when a signed token cannot be trusted."""


class TokenMintUnavailableError(S10Error):
    """Raised when minting is unavailable and must fail closed."""


class ScopeWideningError(S10Error):
    """Raised when attenuation attempts to widen a capability."""


class BudgetExceededError(S10Error):
    """Raised when reservation or consumption would exceed caps."""


class PolicyDeniedError(S10Error):
    """Raised when policy or admission denies a sandbox launch."""


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
class EgressRule:
    host: str
    port: int
    proto: str


@dataclass(frozen=True)
class ScopeGrant:
    allowed_adapters: tuple[str, ...] = ()
    allowed_datasets: tuple[str, ...] = ()
    egress_allowlist: tuple[EgressRule, ...] = ()
    broker_audiences: tuple[str, ...] = ()
    sandbox_risk_class: str = "standard"
    disallowed_actions: tuple[str, ...] = ()


@dataclass(frozen=True)
class BudgetToken:
    budget_id: str
    job_id: str
    root_request_id: str
    budget_epoch: int
    caps: BudgetCaps
    risk_class: str
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
class QuotaState:
    caps: BudgetCaps
    reserved: BudgetUsage
    actual: BudgetUsage
    halted: bool = False


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
    risk_to_runtime: dict[str, str]
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
    runtime_class_hint: str = "auto"
    policy_pin: str | None = None


@dataclass(frozen=True)
class PolicyVerdict:
    allowed: bool
    runtime_class: str | None
    egress_acl: tuple[EgressRule, ...]
    deny_reason: str | None = None


@dataclass(frozen=True)
class SandboxHandle:
    sandbox_id: str
    job_id: str
    runtime_class: str
    budget_epoch: int
    policy_bundle_version: str
    seccomp_profile_hash: str
    state: str


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


class InMemoryTokenService:
    """Signed token service with attenuation and revocation semantics."""

    def __init__(
        self,
        *,
        signing_key: bytes,
        signer_key_id: str = "s10-test-key",
        now_fn: Callable[[], int] | None = None,
    ) -> None:
        self._signing_key = signing_key
        self._signer_key_id = signer_key_id
        self._now_fn = now_fn or (lambda: int(time.time()))
        self._revoked_ids: set[str] = set()
        self.minting_enabled = True

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
            signer_key_id=self._signer_key_id,
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
            signer_key_id=self._signer_key_id,
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
        self._revoked_ids.add(token_id)

    def _require_valid_budget(self, token: BudgetToken) -> None:
        verification = self.verify_budget(token)
        if not verification.valid:
            raise TokenInvalidError(verification.reason or "invalid budget token")

    def _require_valid_scope(self, token: ScopeToken) -> None:
        verification = self.verify_scope(token)
        if not verification.valid:
            raise TokenInvalidError(verification.reason or "invalid scope token")

    def _verify_token(self, token: BudgetToken | ScopeToken, token_id: str) -> TokenVerification:
        if token.signer_key_id != self._signer_key_id:
            return TokenVerification(valid=False, reason="unknown_signer")
        if token_id in self._revoked_ids:
            return TokenVerification(valid=False, reason="revoked")
        if token.expires_at <= self._now():
            return TokenVerification(valid=False, reason="expired")
        if not hmac.compare_digest(token.signature, self._sign_token(token)):
            return TokenVerification(valid=False, reason="signature_invalid")
        return TokenVerification(valid=True)

    def _sign_token(self, token: BudgetToken | ScopeToken) -> str:
        payload = asdict(token)
        payload["signature"] = ""
        digest = hmac.new(self._signing_key, canonical_json_bytes(payload), sha256).hexdigest()
        return f"{SIGNATURE_PREFIX}{digest}"

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
        if child.sandbox_risk_class != parent.sandbox_risk_class:
            raise ScopeWideningError("attenuated scope cannot change risk class")
        if set(parent.disallowed_actions) - set(child.disallowed_actions):
            raise ScopeWideningError("attenuated scope cannot remove disallowed actions")

    def _now(self) -> int:
        return self._now_fn()


class InMemoryQuotaLedger:
    """Reserve, consume, and release budget dimensions without negative remaining."""

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
        runtime_class = request.runtime_class_hint

    egress_acl = tuple(
        sorted(
            set(request.scope_token.scopes.egress_allowlist) & set(bundle.egress_allowlist),
            key=lambda rule: (rule.host, rule.port, rule.proto),
        )
    )
    return PolicyVerdict(True, runtime_class, egress_acl)


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


class InMemorySandboxOrchestrator:
    """Admission-only sandbox orchestrator for M0 S10 contract semantics."""

    def __init__(
        self,
        *,
        token_service: InMemoryTokenService,
        quota_ledger: InMemoryQuotaLedger,
        audit_ledger: InMemoryAuditLedger,
        policy_bundle: PolicyBundle,
    ) -> None:
        self._token_service = token_service
        self._quota_ledger = quota_ledger
        self._audit_ledger = audit_ledger
        self._policy_bundle = policy_bundle
        self._handles: dict[str, SandboxHandle] = {}

    def launch(self, request: LaunchRequest) -> SandboxHandle:
        self._verify_tokens_for_launch(request)
        verdict = decide_policy(self._policy_bundle, request)
        if not verdict.allowed:
            self._audit_ledger.append("sandbox.denied", {"reason": verdict.deny_reason, "job_id": request.job_id})
            raise PolicyDeniedError(verdict.deny_reason or "policy denied")
        if "@sha256:" not in request.image:
            self._audit_ledger.append("image.verify_fail", {"image": request.image, "job_id": request.job_id})
            raise PolicyDeniedError("image must be digest-pinned")

        self._quota_ledger.register_budget(request.budget_token)
        try:
            self._quota_ledger.reserve(request.budget_token.budget_id, request.requested_envelope.budget_usage())
        except BudgetExceededError:
            self._audit_ledger.append("budget.reject", {"budget_id": request.budget_token.budget_id})
            raise

        handle = SandboxHandle(
            sandbox_id=str(uuid4()),
            job_id=request.job_id,
            runtime_class=verdict.runtime_class or "gvisor",
            budget_epoch=request.budget_token.budget_epoch,
            policy_bundle_version=self._policy_bundle.bundle_version,
            seccomp_profile_hash=self._policy_bundle.seccomp_profile_hash,
            state="ADMITTED",
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
