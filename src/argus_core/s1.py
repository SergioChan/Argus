"""S1 lifecycle and tier-relay semantics for the subagent runtime."""

from __future__ import annotations

import ast
import inspect
import json
import textwrap
from abc import ABC, abstractmethod
from collections.abc import Mapping as CollectionsMapping
from dataclasses import asdict, dataclass, field, is_dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, NoReturn, final
from uuid import NAMESPACE_URL, uuid4, uuid5

from argusverify import C3ReportVerifier
from .hashing import hash_json
from .s6 import CapabilityDescriptor, InMemoryRegistry, S1ConformanceAttestationSigner
from .s7 import AdapterBroker, EvalRequest, EvalResult, Quantity, S7Error
from .s10 import (
    EgressRule,
    InMemoryAuditLedger,
    InMemoryTokenService,
    LaunchRequest,
    S10Error,
    SandboxExecutionResult,
    SandboxHandle,
    ScopeDeniedError,
    ScopeToken,
    TokenInvalidError,
)
from .s8 import (
    ArtifactRecord,
    InMemoryArtifactStore,
    Lineage,
    Producer,
    S8Error,
    assert_lineage_complete,
)


ERROR_CATEGORIES = frozenset(
    {
        "RETRYABLE",
        "PERMANENT",
        "BUDGET",
        "POLICY",
        "VERIFIER_UNAVAILABLE",
        "SANDBOX",
        "VALIDATION",
        "VERSION_UNSUPPORTED",
        "QUARANTINE",
        "NOT_FOUND",
    }
)


@dataclass(frozen=True)
class ErrorBehavior:
    retryable: bool
    terminal_status: str
    quarantine: bool = False


ERROR_BEHAVIORS: dict[str, ErrorBehavior] = {
    "RETRYABLE": ErrorBehavior(retryable=True, terminal_status="RETRYING"),
    "POLICY": ErrorBehavior(retryable=False, terminal_status="QUARANTINED", quarantine=True),
    "SANDBOX": ErrorBehavior(retryable=False, terminal_status="QUARANTINED", quarantine=True),
    "BUDGET": ErrorBehavior(retryable=False, terminal_status="QUARANTINED", quarantine=True),
    "QUARANTINE": ErrorBehavior(retryable=False, terminal_status="QUARANTINED", quarantine=True),
    "VERSION_UNSUPPORTED": ErrorBehavior(retryable=False, terminal_status="REJECTED"),
    "VERIFIER_UNAVAILABLE": ErrorBehavior(retryable=False, terminal_status="REJECTED"),
    "PERMANENT": ErrorBehavior(retryable=False, terminal_status="FAILED"),
    "VALIDATION": ErrorBehavior(retryable=False, terminal_status="FAILED"),
    "NOT_FOUND": ErrorBehavior(retryable=False, terminal_status="FAILED"),
}


def error_behavior(category: str) -> ErrorBehavior:
    try:
        return ERROR_BEHAVIORS[category]
    except KeyError as exc:
        raise ValueError(f"unknown C1 error category: {category}") from exc


def build_error_envelope(
    *,
    category: str,
    code: str,
    message: str,
    retry_after_seconds: int | None = None,
    provenance_ref: str | None = None,
) -> "ErrorEnvelope":
    behavior = error_behavior(category)
    return ErrorEnvelope(
        code=code,
        category=category,
        message=message,
        retryable=behavior.retryable,
        retry_after_seconds=retry_after_seconds,
        provenance_ref=provenance_ref,
    )


class LifecycleState(str, Enum):
    REGISTERED = "REGISTERED"
    ACCEPTED = "ACCEPTED"
    PLANNING = "PLANNING"
    BUILDING = "BUILDING"
    VALIDATING = "VALIDATING"
    REPORTED = "REPORTED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"
    QUARANTINED = "QUARANTINED"


TERMINAL_STATES = frozenset(
    {
        LifecycleState.REPORTED,
        LifecycleState.FAILED,
        LifecycleState.REJECTED,
        LifecycleState.CANCELLED,
        LifecycleState.QUARANTINED,
    }
)


LEGAL_TRANSITIONS: dict[LifecycleState, frozenset[LifecycleState]] = {
    LifecycleState.REGISTERED: frozenset({LifecycleState.ACCEPTED, LifecycleState.REJECTED}),
    LifecycleState.ACCEPTED: frozenset(
        {LifecycleState.PLANNING, LifecycleState.FAILED, LifecycleState.CANCELLED, LifecycleState.QUARANTINED}
    ),
    LifecycleState.PLANNING: frozenset(
        {LifecycleState.BUILDING, LifecycleState.FAILED, LifecycleState.CANCELLED, LifecycleState.QUARANTINED}
    ),
    LifecycleState.BUILDING: frozenset(
        {LifecycleState.VALIDATING, LifecycleState.FAILED, LifecycleState.CANCELLED, LifecycleState.QUARANTINED}
    ),
    LifecycleState.VALIDATING: frozenset(
        {LifecycleState.REPORTED, LifecycleState.FAILED, LifecycleState.CANCELLED, LifecycleState.QUARANTINED}
    ),
    LifecycleState.REPORTED: frozenset(),
    LifecycleState.FAILED: frozenset(),
    LifecycleState.REJECTED: frozenset(),
    LifecycleState.CANCELLED: frozenset(),
    LifecycleState.QUARANTINED: frozenset(),
}


NON_TRANSITION_METHODS = frozenset({"register", "heartbeat"})


METHOD_TARGETS = {
    "accept": LifecycleState.ACCEPTED,
    "refuse": LifecycleState.REJECTED,
    "plan": LifecycleState.PLANNING,
    "build": LifecycleState.BUILDING,
    "validate": LifecycleState.VALIDATING,
    "report": LifecycleState.REPORTED,
    "cancel": LifecycleState.CANCELLED,
    "fail": LifecycleState.FAILED,
    "quarantine": LifecycleState.QUARANTINED,
}


ACCEPTANCE_REFUSAL_REASONS = frozenset(
    {
        "OUT_OF_SCOPE",
        "MISSING_ADAPTER",
        "BUDGET_TOO_SMALL",
        "NO_VERIFIER",
        "VERSION_UNSUPPORTED",
        "POLICY",
    }
)


S1_LIFECYCLE_LEDGER_KIND = "s1_lifecycle_event"
S1_LIFECYCLE_LEDGER_CODE_REF = "argus-core:s1.lifecycle-store"
S1_LIFECYCLE_LEDGER_ENVIRONMENT_DIGEST = "python:s1-lifecycle-store:v1"
S1_SANDBOX_ATTACHMENT_KIND = "s1_sandbox_attachment"
S1_SANDBOX_ATTACHMENT_CODE_REF = "argus-core:s1.sandbox-attachment"
S1_SANDBOX_ATTACHMENT_ENVIRONMENT_DIGEST = "python:s1-sandbox-attachment:v1"
S1_BUILD_REPAIR_ATTEMPT_KIND = "s1_build_repair_attempt"
S1_BUILD_REPAIR_CODE_REF = "argus-core:s1.build-auto-repair"
S1_BUILD_REPAIR_ENVIRONMENT_DIGEST = "python:s1-build-auto-repair:v1"
S1_BUILD_REPAIRABLE_ERROR_CATEGORIES = frozenset({"RETRYABLE", "PERMANENT", "VALIDATION"})
S1_FROZEN_PIPELINE_KIND = "frozen_pipeline"
S1_VALIDATION_REQUEST_KIND = "validation_request"
S1_VALIDATION_HANDOFF_CODE_REF = "argus-core:s1.validation-handoff"
S1_VALIDATION_HANDOFF_ENVIRONMENT_DIGEST = "python:s1-validation-handoff:v1"
S1_REFERENCE_CONFORMANCE_EVIDENCE_KIND = "s1_reference_conformance_evidence"
S1_REFERENCE_CONFORMANCE_CODE_REF = "argus-core:s1.reference-conformance"
S1_REFERENCE_CONFORMANCE_ENVIRONMENT_DIGEST = "python:s1-reference-conformance:v1"
S1_REFERENCE_CONFORMANCE_CREATED_AT = "1970-01-01T00:00:00Z"
S1_REFERENCE_CONFORMANCE_SUITE_VERSION = "s1-reference-conformance.v1"
S1_REFERENCE_CONFORMANCE_STANDARD_REF = "c4://standard/c1/1.0.0"
_S1_DESCRIPTOR_CONFORMANCE_FIELDS = frozenset(
    {
        "level",
        "suite_version",
        "standard_release_ref",
        "evidence_ref",
        "determinism_hash",
        "expires_at",
    }
)
S1_CONFORMANCE_LEVEL_ORDER = {"none": 0, "bronze": 1, "silver": 2, "gold": 3}
S1_CAPABILITY_DESCRIPTOR_DEFAULT_SCOPES = ("c1.accept", "c1.plan", "c1.build", "c1.validate", "c1.report")
S1_CONTENT_STORE_EGRESS_RULE = EgressRule("store.local", 443, "https")
S1_EGRESS_PROTOCOLS = frozenset({"https", "grpc", "tcp"})
S1_HEARTBEAT_COST_FIELDS = frozenset({"compute_units", "gpu_seconds", "model_tokens", "cost_usd"})
S1_CANCEL_DEFAULT_GRACE_SECONDS = 30.0


def derive_sandbox_egress_allowlist(
    allowed_adapters: tuple[str, ...],
    adapter_egress_allowlist: Mapping[str, Any] | None = None,
    *,
    store_egress_rule: EgressRule = S1_CONTENT_STORE_EGRESS_RULE,
) -> tuple[EgressRule, ...]:
    normalized_map = _normalize_adapter_egress_mapping(adapter_egress_allowlist or {})
    rules: list[EgressRule] = [store_egress_rule]
    _assert_egress_rule_valid(store_egress_rule, "content store")
    for adapter_ref in tuple(dict.fromkeys(allowed_adapters)):
        adapter_rules = normalized_map.get(adapter_ref)
        if adapter_rules is None:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_EGRESS_ENDPOINT_UNAVAILABLE",
                    message=f"no egress endpoint is registered for declared adapter {adapter_ref}",
                )
            )
        rules.extend(adapter_rules)
    return _dedupe_egress_rules(rules)


def _normalize_adapter_egress_mapping(adapter_egress_allowlist: Mapping[str, Any]) -> dict[str, tuple[EgressRule, ...]]:
    normalized: dict[str, tuple[EgressRule, ...]] = {}
    for adapter_ref, value in adapter_egress_allowlist.items():
        ref = str(adapter_ref)
        rules = _normalize_egress_rule_sequence(ref, value)
        if not rules:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_EGRESS_ENDPOINT_UNAVAILABLE",
                    message=f"no egress endpoint is registered for declared adapter {ref}",
                )
            )
        normalized[ref] = rules
    return normalized


def _normalize_egress_rule_sequence(adapter_ref: str, value: Any) -> tuple[EgressRule, ...]:
    if isinstance(value, EgressRule):
        candidates = (value,)
    elif isinstance(value, Mapping):
        candidates = (_egress_rule_from_mapping(adapter_ref, value),)
    else:
        try:
            candidates = tuple(value)
        except TypeError as exc:
            raise _invalid_egress_endpoint(adapter_ref, "endpoint must be an EgressRule or sequence") from exc
    rules: list[EgressRule] = []
    for candidate in candidates:
        if isinstance(candidate, Mapping):
            candidate = _egress_rule_from_mapping(adapter_ref, candidate)
        if not isinstance(candidate, EgressRule):
            raise _invalid_egress_endpoint(adapter_ref, "endpoint must be an EgressRule")
        _assert_egress_rule_valid(candidate, adapter_ref)
        rules.append(candidate)
    return _dedupe_egress_rules(rules)


def _egress_rule_from_mapping(adapter_ref: str, value: Mapping[str, Any]) -> EgressRule:
    try:
        return EgressRule(host=str(value["host"]), port=int(value["port"]), proto=str(value["proto"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise _invalid_egress_endpoint(adapter_ref, "endpoint mapping must contain host, port, and proto") from exc


def _assert_egress_rule_valid(rule: EgressRule, owner: str) -> None:
    if not rule.host:
        raise _invalid_egress_endpoint(owner, "endpoint host is required")
    if isinstance(rule.port, bool) or rule.port < 1 or rule.port > 65535:
        raise _invalid_egress_endpoint(owner, "endpoint port must be between 1 and 65535")
    if rule.proto not in S1_EGRESS_PROTOCOLS:
        raise _invalid_egress_endpoint(owner, f"endpoint proto must be one of {sorted(S1_EGRESS_PROTOCOLS)}")


def _dedupe_egress_rules(rules: list[EgressRule] | tuple[EgressRule, ...]) -> tuple[EgressRule, ...]:
    deduped: list[EgressRule] = []
    seen: set[EgressRule] = set()
    for rule in rules:
        if rule not in seen:
            deduped.append(rule)
            seen.add(rule)
    return tuple(deduped)


def _egress_rule_sort_key(rule: EgressRule) -> tuple[str, int, str]:
    return (rule.host, rule.port, rule.proto)


def _format_egress_rules(rules: tuple[EgressRule, ...]) -> str:
    return ", ".join(f"{rule.proto}://{rule.host}:{rule.port}" for rule in rules)


def _invalid_egress_endpoint(owner: str, message: str) -> LifecyclePolicyError:
    return LifecyclePolicyError(
        build_error_envelope(
            category="SANDBOX",
            code="S10_EGRESS_ENDPOINT_INVALID",
            message=f"invalid egress endpoint for {owner}: {message}",
        )
    )


class S1Error(Exception):
    """Base class for S1 runtime failures."""


@dataclass(frozen=True)
class ErrorEnvelope:
    code: str
    category: str
    message: str
    retryable: bool = False
    retry_after_seconds: int | None = None
    provenance_ref: str | None = None

    def __post_init__(self) -> None:
        if self.category not in ERROR_CATEGORIES:
            raise ValueError(f"unknown C1 error category: {self.category}")
        behavior = error_behavior(self.category)
        if self.retryable != behavior.retryable:
            raise ValueError(f"{self.category} retryable must be {behavior.retryable}")
        if self.retryable and self.retry_after_seconds is None:
            raise ValueError("RETRYABLE errors must carry retry_after_seconds")
        if not self.retryable and self.retry_after_seconds is not None:
            raise ValueError(f"{self.category} errors must not carry retry_after_seconds")
        if self.retry_after_seconds is not None and self.retry_after_seconds < 0:
            raise ValueError("retry_after_seconds cannot be negative")

    @property
    def behavior(self) -> ErrorBehavior:
        return error_behavior(self.category)

    def as_c1_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "category": self.category,
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
        }
        if self.retry_after_seconds is not None:
            payload["retry_after_seconds"] = self.retry_after_seconds
        if self.provenance_ref is not None:
            payload["provenance_ref"] = self.provenance_ref
        return payload


class LifecyclePolicyError(S1Error):
    """Raised when a lifecycle transition violates the C1 FSM."""

    def __init__(self, envelope: ErrorEnvelope) -> None:
        super().__init__(envelope.message)
        self.envelope = envelope


@dataclass(frozen=True)
class LifecycleEvent:
    job_id: str
    sequence: int
    from_state: LifecycleState
    to_state: LifecycleState
    method: str
    trigger: str
    payload_hash: str
    idempotency_key: str
    root_request_id: str
    trace_id: str
    event_id: str
    ledger_ref: str | None = None


@dataclass(frozen=True)
class JobCurrent:
    job_id: str
    state: LifecycleState
    last_sequence: int


@dataclass(frozen=True)
class HeartbeatStatus:
    job_id: str
    status: LifecycleState
    progress: float
    spend_so_far: dict[str, float]
    last_heartbeat_at: str

    def as_c1_payload(self) -> dict[str, object]:
        return {
            "job_id": self.job_id,
            "status": self.status.value,
            "progress": self.progress,
            "spend_so_far": dict(self.spend_so_far),
            "last_heartbeat_at": self.last_heartbeat_at,
        }


@dataclass(frozen=True)
class S1LifecycleBusEvent:
    subject: str
    event_id: str
    trace_id: str
    root_request_id: str
    payload: dict[str, Any]
    occurred_at: str


@dataclass(frozen=True)
class S1TelemetrySpan:
    trace_id: str
    span_id: str
    name: str
    subsystem: str
    attributes: dict[str, Any]


class InMemoryS1EventBus:
    """Deterministic NATS-style event bus for S1 local tests and mock consumers."""

    def __init__(self) -> None:
        self._events: list[S1LifecycleBusEvent] = []

    def publish(
        self,
        subject: str,
        payload: Mapping[str, Any],
        *,
        event_id: str | None = None,
        trace_id: str | None = None,
        root_request_id: str | None = None,
    ) -> S1LifecycleBusEvent:
        normalized_payload = dict(_json_compatible_payload(payload))
        resolved_trace_id = _event_trace_id(normalized_payload, trace_id)
        resolved_root_request_id = _event_root_request_id(normalized_payload, root_request_id)
        resolved_event_id = event_id or _derive_s1_bus_event_id(
            subject=subject,
            payload=normalized_payload,
            index=len(self._events) + 1,
        )
        event = S1LifecycleBusEvent(
            subject=subject,
            event_id=resolved_event_id,
            trace_id=resolved_trace_id,
            root_request_id=resolved_root_request_id,
            payload=normalized_payload,
            occurred_at=_utc_now_s1(),
        )
        self._events.append(event)
        return event

    def subscribe(self, subject: str) -> tuple[S1LifecycleBusEvent, ...]:
        return tuple(event for event in self._events if event.subject == subject)

    def events(self, subject: str | None = None) -> tuple[S1LifecycleBusEvent, ...]:
        if subject is None:
            return tuple(self._events)
        return self.subscribe(subject)


class InMemoryS1TelemetrySink:
    """S11-compatible in-memory span sink for S1 runtime and wire-method spans."""

    def __init__(self) -> None:
        self._spans: list[S1TelemetrySpan] = []

    def record_span(
        self,
        name: str,
        *,
        trace_id: str,
        attributes: Mapping[str, Any] | None = None,
        span_id: str | None = None,
    ) -> S1TelemetrySpan:
        normalized_attributes = dict(_json_compatible_payload(attributes or {}))
        resolved_span_id = span_id or _derive_s1_span_id(
            trace_id=trace_id,
            name=name,
            attributes=normalized_attributes,
            index=len(self._spans) + 1,
        )
        span = S1TelemetrySpan(
            trace_id=trace_id,
            span_id=resolved_span_id,
            name=name,
            subsystem="S1",
            attributes=normalized_attributes,
        )
        self._spans.append(span)
        return span

    def spans(self, trace_id: str | None = None) -> tuple[S1TelemetrySpan, ...]:
        if trace_id is None:
            return tuple(self._spans)
        return tuple(span for span in self._spans if span.trace_id == trace_id)


@dataclass(frozen=True)
class S10SandboxMarshaler:
    launcher: Any

    def submit_sandbox_job(self, *, job_id: str, spec: Mapping[str, Any]) -> Any:
        request = _launch_request_from_sandbox_spec(job_id, spec)
        try:
            if hasattr(self.launcher, "launch_and_wait"):
                return self.launcher.launch_and_wait(request)
            if hasattr(self.launcher, "launch"):
                return self.launcher.launch(request)
        except S10Error as exc:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_SANDBOX_LAUNCH_FAILED",
                    message=f"S10 sandbox launch failed: {exc}",
                )
            ) from exc
        raise LifecyclePolicyError(
            build_error_envelope(
                category="SANDBOX",
                code="S10_MARSHALER_INVALID",
                message="S10 sandbox marshaler must expose launch or launch_and_wait",
            )
        )

    def cancel_sandbox_job(
        self,
        *,
        job_id: str,
        sandbox_id: str,
        reason: str,
        grace_seconds: float,
    ) -> Any:
        try:
            for name in ("cancel_sandbox_job", "terminate_sandbox_job", "cancel"):
                hook = getattr(self.launcher, name, None)
                if callable(hook):
                    return hook(
                        job_id=job_id,
                        sandbox_id=sandbox_id,
                        reason=reason,
                        grace_seconds=grace_seconds,
                    )
        except S10Error as exc:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_SANDBOX_CANCEL_FAILED",
                    message=f"S10 sandbox cancel failed: {exc}",
                )
            ) from exc
        return {
            "job_id": job_id,
            "sandbox_id": sandbox_id,
            "state": "CANCEL_REQUESTED",
            "terminate_succeeded": False,
        }

    def get(self, sandbox_id: str) -> Any:
        hook = getattr(self.launcher, "get", None)
        if callable(hook):
            try:
                return hook(sandbox_id)
            except S10Error as exc:
                raise LifecyclePolicyError(
                    build_error_envelope(
                        category="SANDBOX",
                        code="S10_SANDBOX_REATTACH_FAILED",
                        message=f"S10 sandbox reattach failed: {exc}",
                    )
                ) from exc
        raise LifecyclePolicyError(
            build_error_envelope(
                category="SANDBOX",
                code="S10_SANDBOX_REATTACH_UNAVAILABLE",
                message="S10 sandbox marshaler cannot resolve durable sandbox handles",
            )
        )

    def quarantine_sandbox_job(
        self,
        *,
        job_id: str,
        sandbox_id: str,
        reason: str,
        grace_seconds: float,
        error: Mapping[str, Any] | None = None,
    ) -> Any:
        try:
            quarantine_hook = getattr(self.launcher, "quarantine_sandbox_job", None)
            if callable(quarantine_hook):
                return quarantine_hook(
                    job_id=job_id,
                    sandbox_id=sandbox_id,
                    reason=reason,
                    grace_seconds=grace_seconds,
                    error=error or {},
                )
            for name in ("cancel_sandbox_job", "terminate_sandbox_job", "cancel"):
                hook = getattr(self.launcher, name, None)
                if callable(hook):
                    return hook(
                        job_id=job_id,
                        sandbox_id=sandbox_id,
                        reason=reason,
                        grace_seconds=grace_seconds,
                    )
        except S10Error as exc:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_SANDBOX_QUARANTINE_FAILED",
                    message=f"S10 sandbox quarantine failed: {exc}",
                )
            ) from exc
        return {
            "job_id": job_id,
            "sandbox_id": sandbox_id,
            "state": "QUARANTINE_REQUESTED",
            "terminate_succeeded": False,
        }


EXEC_CONTEXT_CAPABILITIES = (
    "submit_sandbox_job",
    "emit_artifact",
    "call_adapter",
    "read_dataset",
    "log",
    "span",
)
_EXEC_CONTEXT_CAPABILITY_SET = frozenset(EXEC_CONTEXT_CAPABILITIES)
UNCERTAINTY_REPRESENTATIONS = frozenset(
    {"covariance", "interval", "samples", "conformal", "ensemble", "none"}
)
UNCERTAINTY_REQUIRED_CLAIM_TIERS = frozenset({"recapitulated-known", "novel-needs-human"})
BUILD_RESULT_FIELDS = frozenset(
    {
        "job_id",
        "artifact_refs",
        "training_log_ref",
        "diagnostics",
        "self_checks",
        "uncertainty_summary",
    }
)
BUILD_RESULT_TIER_SELF_PROMOTION_FIELDS = frozenset(
    {
        "claim_tier",
        "claimed_tier",
        "tier",
        "validation_report_payload",
        "validation_report_ref",
    }
)


def no_uncertainty_summary() -> dict[str, Any]:
    return {"representation": "none", "value": {}}


def tag_uncertainty(representation: str, value: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return _normalize_uncertainty_summary({"representation": representation, "value": dict(value or {})})


def uncertainty_tag_for_artifact(summary: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _normalize_uncertainty_summary(summary)
    representation = normalized["representation"]
    if representation == "none":
        _raise_uncertainty_policy(
            "S1_UNCERTAINTY_TAG_REQUIRED",
            "C4 uncertainty_tag cannot be built from a none uncertainty summary",
        )
    return {"kind": representation, **normalized["value"]}


def _normalize_uncertainty_summary(value: Mapping[str, Any] | Any) -> dict[str, Any]:
    if value is None:
        return no_uncertainty_summary()
    payload = _json_compatible_payload(value)
    if not isinstance(payload, Mapping):
        _raise_uncertainty_policy(
            "S1_UNCERTAINTY_SUMMARY_INVALID",
            "uncertainty_summary must be a mapping",
        )
    extra = set(payload) - {"representation", "value"}
    if extra:
        _raise_uncertainty_policy(
            "S1_UNCERTAINTY_SUMMARY_INVALID",
            "uncertainty_summary contains unsupported fields: " + ", ".join(sorted(str(key) for key in extra)),
        )
    representation = payload.get("representation", "none")
    if representation not in UNCERTAINTY_REPRESENTATIONS:
        _raise_uncertainty_policy(
            "S1_UNCERTAINTY_REPRESENTATION_INVALID",
            f"unsupported uncertainty representation: {representation}",
        )
    raw_value = payload.get("value", {})
    if not isinstance(raw_value, Mapping):
        _raise_uncertainty_policy(
            "S1_UNCERTAINTY_VALUE_INVALID",
            "uncertainty_summary.value must be a mapping",
        )
    normalized_value = dict(raw_value)
    if representation == "none" and normalized_value:
        _raise_uncertainty_policy(
            "S1_UNCERTAINTY_VALUE_INVALID",
            "uncertainty_summary.value must be empty when representation is none",
        )
    if representation != "none" and not normalized_value:
        _raise_uncertainty_policy(
            "S1_UNCERTAINTY_VALUE_REQUIRED",
            f"uncertainty representation {representation} requires a non-empty value",
        )
    return {"representation": str(representation), "value": normalized_value}


def _assert_uncertainty_for_claim_tier(summary: Mapping[str, Any], claim_tier: str) -> None:
    normalized = _normalize_uncertainty_summary(summary)
    if claim_tier in UNCERTAINTY_REQUIRED_CLAIM_TIERS and normalized["representation"] == "none":
        _raise_uncertainty_policy(
            "S1_UNCERTAINTY_REQUIRED_FOR_TIER",
            f"claim tier {claim_tier} requires explicit uncertainty_summary; bare point estimates are rejected at Silver",
        )


def _raise_uncertainty_policy(code: str, message: str) -> NoReturn:
    _raise_policy(code, message)


def _raise_policy(code: str, message: str) -> NoReturn:
    raise LifecyclePolicyError(
        build_error_envelope(
            category="POLICY",
            code=code,
            message=message,
        )
    )


@dataclass(frozen=True)
class AdapterBrokerHandle:
    handle_id: str
    scope_id: str
    expires_at: int


@dataclass(frozen=True)
class _S1AdapterBrokerCapability:
    scope_token: ScopeToken
    token_service: InMemoryTokenService
    adapter_broker: AdapterBroker
    audit_ledger: InMemoryAuditLedger


_S1_ADAPTER_BROKER_CAPABILITIES: dict[str, _S1AdapterBrokerCapability] = {}
_S1_ADAPTER_BROKER_ENDPOINT = None


class S1AdapterBrokerProxy:
    """Brokered C6 adapter evaluation path for S1 author contexts."""

    def __init__(
        self,
        *,
        token_service: InMemoryTokenService,
        adapter_broker: AdapterBroker,
        audit_ledger: InMemoryAuditLedger,
    ) -> None:
        self._token_service = token_service
        self._adapter_broker = adapter_broker
        self._audit_ledger = audit_ledger

    def client_for(self, scope_token: ScopeToken) -> "BrokeredAdapterClient":
        handle = AdapterBrokerHandle(
            handle_id=str(uuid4()),
            scope_id=scope_token.scope_id,
            expires_at=scope_token.expires_at,
        )
        _S1_ADAPTER_BROKER_CAPABILITIES[handle.handle_id] = _S1AdapterBrokerCapability(
            scope_token=scope_token,
            token_service=self._token_service,
            adapter_broker=self._adapter_broker,
            audit_ledger=self._audit_ledger,
        )
        return BrokeredAdapterClient(handle=handle, endpoint=_s1_adapter_broker_endpoint())


def _s1_adapter_broker_endpoint() -> "_S1AdapterBrokerEndpoint":
    global _S1_ADAPTER_BROKER_ENDPOINT
    if _S1_ADAPTER_BROKER_ENDPOINT is None:
        _S1_ADAPTER_BROKER_ENDPOINT = _S1AdapterBrokerEndpoint()
    return _S1_ADAPTER_BROKER_ENDPOINT


def _evaluate_s1_adapter_broker_capability(
    *,
    handle: AdapterBrokerHandle,
    request: EvalRequest,
) -> EvalResult:
    capability = _S1_ADAPTER_BROKER_CAPABILITIES.get(handle.handle_id)
    if capability is None or capability.scope_token.scope_id != handle.scope_id:
        raise ScopeDeniedError("invalid adapter broker handle")
    scope_token = capability.scope_token
    verification = capability.token_service.verify_scope(scope_token)
    if not verification.valid:
        capability.audit_ledger.append(
            "adapter.token_verify_fail",
            {"token": "scope", "reason": verification.reason, "audience": request.adapter_id},
        )
        raise TokenInvalidError(verification.reason or "invalid scope token")
    if request.adapter_id not in scope_token.scopes.allowed_adapters:
        _deny_s1_adapter_request(
            audit_ledger=capability.audit_ledger,
            scope_token=scope_token,
            adapter_id=request.adapter_id,
            reason="adapter_not_allowlisted",
            message=f"adapter is not allowlisted by scope token: {request.adapter_id}",
        )
    if request.adapter_id not in scope_token.scopes.broker_audiences:
        _deny_s1_adapter_request(
            audit_ledger=capability.audit_ledger,
            scope_token=scope_token,
            adapter_id=request.adapter_id,
            reason="broker_audience_missing",
            message=f"adapter broker audience is not granted: {request.adapter_id}",
        )
    try:
        result = capability.adapter_broker.evaluate(request)
    except KeyError:
        _deny_s1_adapter_request(
            audit_ledger=capability.audit_ledger,
            scope_token=scope_token,
            adapter_id=request.adapter_id,
            reason="adapter_not_registered",
            message=f"adapter is not registered with broker: {request.adapter_id}",
        )
    capability.audit_ledger.append(
        "adapter.evaluate",
        {
            "audience": request.adapter_id,
            "adapter_id": request.adapter_id,
            "scope_id": scope_token.scope_id,
            "job_id": scope_token.job_id,
            "provenance_ref": result.provenance_ref,
            "request_hash": hash_json(_eval_request_payload(request)),
        },
    )
    return result


def _deny_s1_adapter_request(
    *,
    audit_ledger: InMemoryAuditLedger,
    scope_token: ScopeToken,
    adapter_id: str,
    reason: str,
    message: str,
) -> NoReturn:
    audit_ledger.append(
        "adapter.denied",
        {
            "audience": adapter_id,
            "adapter_id": adapter_id,
            "reason": reason,
            "scope_id": scope_token.scope_id,
            "job_id": scope_token.job_id,
        },
    )
    raise ScopeDeniedError(message)


class _S1AdapterBrokerEndpoint:
    """In-process adapter broker endpoint; clients only hold opaque handles."""

    __slots__ = ()

    def evaluate(self, *, handle: AdapterBrokerHandle, request: EvalRequest) -> EvalResult:
        return _evaluate_s1_adapter_broker_capability(handle=handle, request=request)


class BrokeredAdapterClient:
    """Sandbox-facing adapter client exposing only C6 evaluate via an opaque handle."""

    __slots__ = ("_handle", "_endpoint")

    def __init__(self, *, handle: AdapterBrokerHandle, endpoint: _S1AdapterBrokerEndpoint) -> None:
        self._handle = handle
        self._endpoint = endpoint

    def evaluate(self, request: EvalRequest) -> EvalResult:
        return self._endpoint.evaluate(handle=self._handle, request=request)


@dataclass(frozen=True, init=False)
class ExecContext:
    job_id: str
    capabilities: tuple[str, ...]
    _allowed_adapters: tuple[str, ...] = field(repr=False, compare=False)
    _allowed_datasets: tuple[str, ...] = field(repr=False, compare=False)
    _adapter_egress_allowlist: Mapping[str, tuple[EgressRule, ...]] = field(repr=False, compare=False)
    _store_egress_rule: EgressRule = field(repr=False, compare=False)
    _artifact_store: InMemoryArtifactStore = field(init=False, repr=False, compare=False)
    _sandbox_marshaler: Any = field(init=False, repr=False, compare=False)
    _adapter_client: Any = field(init=False, repr=False, compare=False)
    _heartbeat_recorder: Any = field(init=False, repr=False, compare=False)
    _sandbox_result_recorder: Any = field(init=False, repr=False, compare=False)
    _cancel_checker: Any = field(init=False, repr=False, compare=False)
    _trace_id: str | None = field(init=False, repr=False, compare=False)
    _root_request_id: str | None = field(init=False, repr=False, compare=False)
    _telemetry_sink: InMemoryS1TelemetrySink | None = field(init=False, repr=False, compare=False)
    _event_bus: InMemoryS1EventBus | None = field(init=False, repr=False, compare=False)

    def __init__(
        self,
        *,
        job_id: str,
        capabilities: tuple[str, ...] = EXEC_CONTEXT_CAPABILITIES,
        allowed_adapters: tuple[str, ...] = (),
        allowed_datasets: tuple[str, ...] = (),
        adapter_egress_allowlist: Mapping[str, Any] | None = None,
        store_egress_rule: EgressRule = S1_CONTENT_STORE_EGRESS_RULE,
        artifact_store: InMemoryArtifactStore | None = None,
        sandbox_marshaler: Any | None = None,
        adapter_client: Any | None = None,
        heartbeat_recorder: Any | None = None,
        sandbox_result_recorder: Any | None = None,
        cancel_checker: Any | None = None,
        trace_id: str | None = None,
        root_request_id: str | None = None,
        telemetry_sink: InMemoryS1TelemetrySink | None = None,
        event_bus: InMemoryS1EventBus | None = None,
    ) -> None:
        capabilities = tuple(dict.fromkeys(capabilities))
        unknown = tuple(capability for capability in capabilities if capability not in _EXEC_CONTEXT_CAPABILITY_SET)
        if unknown:
            raise ValueError("unknown ExecContext capability: " + ", ".join(unknown))
        object.__setattr__(self, "job_id", job_id)
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "_allowed_adapters", tuple(allowed_adapters))
        object.__setattr__(self, "_allowed_datasets", tuple(allowed_datasets))
        object.__setattr__(
            self,
            "_adapter_egress_allowlist",
            _normalize_adapter_egress_mapping(adapter_egress_allowlist or {}),
        )
        _assert_egress_rule_valid(store_egress_rule, "content store")
        object.__setattr__(self, "_store_egress_rule", store_egress_rule)
        object.__setattr__(
            self,
            "_artifact_store",
            artifact_store if artifact_store is not None else InMemoryArtifactStore(),
        )
        object.__setattr__(self, "_sandbox_marshaler", sandbox_marshaler)
        object.__setattr__(self, "_adapter_client", adapter_client)
        object.__setattr__(self, "_heartbeat_recorder", heartbeat_recorder)
        object.__setattr__(self, "_sandbox_result_recorder", sandbox_result_recorder)
        object.__setattr__(self, "_cancel_checker", cancel_checker)
        object.__setattr__(self, "_trace_id", trace_id)
        object.__setattr__(self, "_root_request_id", root_request_id)
        object.__setattr__(self, "_telemetry_sink", telemetry_sink)
        object.__setattr__(self, "_event_bus", event_bus)

    def capability_methods(self) -> tuple[str, ...]:
        return self.capabilities

    def as_c1_payload(self) -> dict[str, object]:
        return {"job_id": self.job_id, "capabilities": list(self.capabilities)}

    def submit_sandbox_job(self, spec: dict[str, Any]) -> dict[str, Any]:
        self._require_capability("submit_sandbox_job")
        if self._sandbox_marshaler is None:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_MARSHALER_UNAVAILABLE",
                    message=(
                        "S10 sandbox marshaler is unavailable; "
                        "direct in-process execution is forbidden"
                    ),
                )
            )
        if not hasattr(self._sandbox_marshaler, "submit_sandbox_job"):
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_MARSHALER_INVALID",
                    message="S10 sandbox marshaler must expose submit_sandbox_job",
                )
            )
        request = _launch_request_from_sandbox_spec(self.job_id, spec)
        self._assert_sandbox_launch_scopes(request)
        result = self._sandbox_marshaler.submit_sandbox_job(job_id=self.job_id, spec=spec)
        payload = _normalize_sandbox_result(self.job_id, result)
        if self._sandbox_result_recorder is not None:
            self._sandbox_result_recorder(self.job_id, payload)
        return payload

    def record_heartbeat(self, *, progress: float, spend_so_far: Mapping[str, Any]) -> dict[str, object]:
        if self._heartbeat_recorder is None:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="POLICY",
                    code="S1_HEARTBEAT_RECORDER_UNAVAILABLE",
                    message="ExecContext cannot record heartbeat without a runtime heartbeat recorder",
                )
            )
        heartbeat = self._heartbeat_recorder(
            self.job_id,
            progress=progress,
            spend_so_far=spend_so_far,
        )
        return heartbeat.as_c1_payload()

    def cancel_requested(self) -> bool:
        if self._cancel_checker is None:
            return False
        return bool(self._cancel_checker(self.job_id))

    def emit_artifact(
        self,
        payload: Any,
        kind: str,
        lineage_inputs: tuple[str, ...] = (),
        *,
        lineage: Lineage | Mapping[str, Any] | None = None,
        claim_tier: str = "ran-toy",
        validation_report_ref: str | None = None,
    ) -> dict[str, Any]:
        self._require_capability("emit_artifact")
        if claim_tier != "ran-toy":
            _raise_policy(
                "S1_ARTIFACT_TIER_SELF_PROMOTION_FORBIDDEN",
                "ExecContext.emit_artifact cannot set claim_tier above ran-toy; promoted artifacts require framework-owned signed C3 validation",
            )
        if validation_report_ref is not None:
            _raise_policy(
                "S1_ARTIFACT_VALIDATION_REPORT_REF_FORBIDDEN",
                "ExecContext.emit_artifact cannot attach validation_report_ref; signed validation refs are framework-owned",
            )
        resolved_lineage = self._artifact_lineage(
            payload=payload,
            kind=kind,
            lineage_inputs=lineage_inputs,
            lineage=lineage,
            claim_tier=claim_tier,
            validation_report_ref=validation_report_ref,
        )
        producer = Producer(
            subsystem="s1",
            version="exec-context-v1",
            actor_id="subagent-runtime",
            job_id=self.job_id,
        )
        try:
            record = self._artifact_store.create_artifact(
                kind=kind,
                payload=payload,
                producer=producer,
                lineage=resolved_lineage,
                claim_tier=claim_tier,
                validation_report_ref=validation_report_ref,
            )
        except S8Error as exc:
            _raise_c4_write_error(exc)
        handle = {
            "capability": "emit_artifact",
            "job_id": self.job_id,
            "artifact_ref": record.artifact_ref,
            "kind": record.kind,
            "content_hash": record.content_hash,
            "claim_tier": record.claim_tier,
            "validation_report_ref": record.validation_report_ref,
        }
        if self._event_bus is not None:
            self._event_bus.publish(
                "s1.artifact.emitted",
                {
                    "job_id": self.job_id,
                    "artifact_ref": record.artifact_ref,
                    "kind": record.kind,
                    "content_hash": record.content_hash,
                    "claim_tier": record.claim_tier,
                    "validation_report_ref": record.validation_report_ref,
                    "root_request_id": self._root_request_id or self.job_id,
                    "trace_id": self._trace_id or f"trace:{self.job_id}",
                },
                trace_id=self._trace_id,
                root_request_id=self._root_request_id,
            )
        return handle

    def _artifact_lineage(
        self,
        *,
        payload: Any,
        kind: str,
        lineage_inputs: tuple[str, ...],
        lineage: Lineage | Mapping[str, Any] | None,
        claim_tier: str,
        validation_report_ref: str | None,
    ) -> Lineage:
        if lineage is not None and lineage_inputs:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="POLICY",
                    code="ARTIFACT_LINEAGE_CONFLICT",
                    message="emit_artifact received both lineage and lineage_inputs",
                )
            )
        if lineage is None:
            resolved = Lineage(
                input_refs=tuple(lineage_inputs),
                code_ref="argus-core:s1.exec_context.emit_artifact",
                environment_digest="python:s1-exec-context:v1",
                job_id=self.job_id,
            )
        elif isinstance(lineage, Lineage):
            resolved = lineage
        elif isinstance(lineage, Mapping):
            try:
                assert_lineage_complete(
                    lineage,
                    kind=kind,
                    payload=payload if isinstance(payload, Mapping) else None,
                    claim_tier=claim_tier,
                    validation_report_ref=validation_report_ref,
                )
            except S8Error as exc:
                _raise_c4_write_error(exc)
            resolved = _lineage_from_mapping(lineage)
        else:
            raise TypeError("lineage must be a Lineage or mapping")
        return replace(
            resolved,
            actor_id=resolved.actor_id or "subagent-runtime",
            job_id=self.job_id,
        )

    def call_adapter(self, adapter_ref: str, request: dict[str, Any]) -> dict[str, Any]:
        self._require_capability("call_adapter")
        if adapter_ref not in self._allowed_adapters:
            self._deny_capability("call_adapter", f"adapter is not allowlisted: {adapter_ref}")
        if self._adapter_client is None:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S1_ADAPTER_BROKER_UNAVAILABLE",
                    message="S1 brokered adapter proxy is unavailable; direct adapter calls are forbidden",
                )
            )
        if not hasattr(self._adapter_client, "evaluate"):
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S1_ADAPTER_BROKER_INVALID",
                    message="S1 brokered adapter proxy must expose evaluate",
                )
            )
        eval_request = _eval_request_from_call(adapter_ref, request)
        try:
            result = self._adapter_client.evaluate(eval_request)
        except TokenInvalidError as exc:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="POLICY",
                    code="S1_ADAPTER_SCOPE_TOKEN_INVALID",
                    message=f"S1 adapter scope token is invalid: {exc}",
                )
            ) from exc
        except ScopeDeniedError as exc:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="POLICY",
                    code="S1_ADAPTER_SCOPE_DENIED",
                    message=f"S1 adapter broker denied request: {exc}",
                )
            ) from exc
        except S7Error as exc:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="VALIDATION",
                    code=exc.category,
                    message=exc.message,
                )
            ) from exc
        return {
            "capability": "call_adapter",
            "job_id": self.job_id,
            "adapter_ref": adapter_ref,
            "request_hash": hash_json(_eval_request_payload(eval_request)),
            "provenance_ref": result.provenance_ref,
            "result": _eval_result_payload(result),
        }

    def read_dataset(self, dataset_ref: str) -> dict[str, str]:
        self._require_capability("read_dataset")
        if dataset_ref not in self._allowed_datasets:
            self._deny_capability("read_dataset", f"dataset is not allowlisted: {dataset_ref}")
        return {"capability": "read_dataset", "job_id": self.job_id, "dataset_ref": dataset_ref}

    def log(self, message: str, *, fields: Mapping[str, Any] | None = None) -> dict[str, Any]:
        self._require_capability("log")
        payload = {"message": message, "fields": dict(fields or {})}
        return {"capability": "log", "job_id": self.job_id, "message_hash": hash_json(payload)}

    def span(self, name: str, *, attributes: Mapping[str, Any] | None = None) -> dict[str, Any]:
        self._require_capability("span")
        normalized_attributes = dict(attributes or {})
        payload = {"name": name, "attributes": normalized_attributes}
        span_name = f"S1.exec.{name}"
        trace_id = self._trace_id or f"trace:{self.job_id}"
        handle: dict[str, Any] = {
            "capability": "span",
            "job_id": self.job_id,
            "span_hash": hash_json(payload),
            "span_name": span_name,
            "trace_id": trace_id,
        }
        if self._telemetry_sink is not None:
            recorded = self._telemetry_sink.record_span(
                span_name,
                trace_id=trace_id,
                attributes={
                    **normalized_attributes,
                    "author_span_name": name,
                    "job_id": self.job_id,
                    "root_request_id": self._root_request_id or self.job_id,
                },
            )
            handle["span_id"] = recorded.span_id
        return handle

    def tag_uncertainty(self, representation: str, value: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return tag_uncertainty(representation, value)

    def _require_capability(self, capability: str) -> None:
        if capability not in self.capabilities:
            self._deny_capability(capability, f"capability is not enabled: {capability}")

    def _deny_capability(self, capability: str, message: str) -> None:
        raise LifecyclePolicyError(
            ErrorEnvelope(
                code="EXEC_CONTEXT_CAPABILITY_DENIED",
                category="POLICY",
                message=f"ExecContext denied {capability}: {message}",
            )
        )

    def _assert_sandbox_launch_scopes(self, request: LaunchRequest) -> None:
        context_adapters = tuple(dict.fromkeys(self._allowed_adapters))
        scope_adapters = tuple(dict.fromkeys(request.scope_token.scopes.allowed_adapters))
        extra_adapters = tuple(sorted(set(scope_adapters) - set(context_adapters)))
        if extra_adapters:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_ADAPTER_SCOPE_WIDENED",
                    message="S10 scope token includes undeclared adapters: " + ", ".join(extra_adapters),
                )
            )
        missing_adapters = tuple(sorted(set(context_adapters) - set(scope_adapters)))
        if missing_adapters:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_ADAPTER_SCOPE_MISSING",
                    message="S10 scope token is missing declared adapters: " + ", ".join(missing_adapters),
                )
            )

        expected_egress = set(
            derive_sandbox_egress_allowlist(
                scope_adapters,
                self._adapter_egress_allowlist,
                store_egress_rule=self._store_egress_rule,
            )
        )
        requested_egress = set(request.scope_token.scopes.egress_allowlist)
        extra_egress = tuple(sorted(requested_egress - expected_egress, key=_egress_rule_sort_key))
        if extra_egress:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_EGRESS_SCOPE_WIDENED",
                    message="S10 scope token includes non-derived egress endpoints: "
                    + _format_egress_rules(extra_egress),
                )
            )
        missing_egress = tuple(sorted(expected_egress - requested_egress, key=_egress_rule_sort_key))
        if missing_egress:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_EGRESS_SCOPE_MISSING",
                    message="S10 scope token is missing derived egress endpoints: "
                    + _format_egress_rules(missing_egress),
                )
            )


def _lineage_from_mapping(lineage: Mapping[str, Any]) -> Lineage:
    values = dict(lineage)
    return Lineage(
        input_refs=tuple(str(ref) for ref in values.get("input_refs", ())),
        code_ref=str(values.get("code_ref") or ""),
        environment_digest=str(values.get("environment_digest") or ""),
        seeds=tuple(str(seed) for seed in values.get("seeds", ())),
        actor_id=_optional_str(values.get("actor_id")),
        job_id=_optional_str(values.get("job_id")),
        contamination_index_version=_optional_str(values.get("contamination_index_version")),
    )


def _optional_str(value: Any) -> str | None:
    return None if value is None else str(value)


def _raise_c4_write_error(exc: S8Error) -> None:
    code = str(getattr(exc, "category", exc.__class__.__name__))
    details = getattr(exc, "missing_fields", None)
    message = str(exc)
    if details:
        message = f"{message}; missing_fields={', '.join(str(field) for field in details)}"
    raise LifecyclePolicyError(
        build_error_envelope(
            category="POLICY",
            code=code,
            message=message,
        )
    ) from exc


def _eval_request_from_call(adapter_ref: str, request: Mapping[str, Any]) -> EvalRequest:
    if not isinstance(adapter_ref, str) or not adapter_ref:
        _raise_adapter_request_error("S1_ADAPTER_REQUEST_INVALID", "adapter_ref is required")
    if not isinstance(request, Mapping):
        _raise_adapter_request_error("S1_ADAPTER_REQUEST_INVALID", "adapter request must be a mapping")
    raw_request = request.get("eval_request")
    if raw_request is None:
        eval_request = _eval_request_from_mapping(request, default_adapter_ref=adapter_ref)
    elif isinstance(raw_request, EvalRequest):
        eval_request = raw_request
    elif isinstance(raw_request, Mapping):
        eval_request = _eval_request_from_mapping(raw_request, default_adapter_ref=adapter_ref)
    else:
        _raise_adapter_request_error("S1_ADAPTER_REQUEST_INVALID", "eval_request must be an EvalRequest or mapping")
    if eval_request.adapter_id != adapter_ref:
        raise LifecyclePolicyError(
            build_error_envelope(
                category="POLICY",
                code="S1_ADAPTER_REQUEST_MISMATCH",
                message=f"adapter_ref {adapter_ref} does not match EvalRequest adapter_id {eval_request.adapter_id}",
            )
        )
    return eval_request


def _eval_request_from_mapping(request: Mapping[str, Any], *, default_adapter_ref: str) -> EvalRequest:
    adapter_id = str(request.get("adapter_id") or default_adapter_ref)
    raw_inputs = request.get("inputs")
    if not isinstance(raw_inputs, Mapping):
        _raise_adapter_request_error("S1_ADAPTER_REQUEST_INVALID", "adapter request inputs must be a mapping")
    inputs = {str(field): _quantity_from_value(value) for field, value in raw_inputs.items()}
    seed_value = request.get("seed")
    if seed_value is None:
        seed = None
    elif isinstance(seed_value, bool):
        _raise_adapter_request_error("S1_ADAPTER_REQUEST_INVALID", "adapter request seed must be an integer")
    else:
        try:
            seed = int(seed_value)
        except (TypeError, ValueError) as exc:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="POLICY",
                    code="S1_ADAPTER_REQUEST_INVALID",
                    message="adapter request seed must be an integer",
                )
            ) from exc
    return EvalRequest(adapter_id=adapter_id, inputs=inputs, seed=seed)


def _quantity_from_value(value: Any) -> Quantity:
    if isinstance(value, Quantity):
        return value
    if not isinstance(value, Mapping):
        _raise_adapter_request_error("S1_ADAPTER_REQUEST_INVALID", "adapter input quantities must be mappings")
    if "value" not in value or "units" not in value:
        _raise_adapter_request_error("S1_ADAPTER_REQUEST_INVALID", "adapter input quantity requires value and units")
    try:
        quantity_value = float(value["value"])
    except (TypeError, ValueError) as exc:
        raise LifecyclePolicyError(
            build_error_envelope(
                category="POLICY",
                code="S1_ADAPTER_REQUEST_INVALID",
                message="adapter input quantity value must be numeric",
            )
        ) from exc
    return Quantity(
        value=quantity_value,
        units=str(value["units"]),
        uncertainty=value.get("uncertainty"),
    )


def _eval_request_payload(request: EvalRequest) -> dict[str, Any]:
    return {
        "adapter_id": request.adapter_id,
        "inputs": {field: asdict(quantity) for field, quantity in sorted(request.inputs.items())},
        "seed": request.seed,
    }


def _eval_result_payload(result: EvalResult) -> dict[str, Any]:
    return {
        "adapter_id": result.adapter_id,
        "outputs": {field: asdict(quantity) for field, quantity in sorted(result.outputs.items())},
        "in_validity_domain": result.in_validity_domain,
        "extrapolation_flag": result.extrapolation_flag,
        "provenance_ref": result.provenance_ref,
        "violated_fields": list(result.violated_fields),
        "cache_hit": result.cache_hit,
        "unit_registry_version": result.unit_registry_version,
        "unit_registry_hash": result.unit_registry_hash,
    }


def _raise_adapter_request_error(code: str, message: str) -> None:
    raise LifecyclePolicyError(
        build_error_envelope(
            category="POLICY",
            code=code,
            message=message,
        )
    )


def _launch_request_from_sandbox_spec(job_id: str, spec: Mapping[str, Any]) -> LaunchRequest:
    request = spec.get("launch_request")
    if not isinstance(request, LaunchRequest):
        raise LifecyclePolicyError(
            build_error_envelope(
                category="SANDBOX",
                code="S10_LAUNCH_REQUEST_REQUIRED",
                message="submit_sandbox_job requires a canonical S10 LaunchRequest",
            )
        )
    if request.job_id != job_id:
        raise LifecyclePolicyError(
            build_error_envelope(
                category="SANDBOX",
                code="S10_LAUNCH_REQUEST_JOB_MISMATCH",
                message=f"S10 LaunchRequest job_id {request.job_id} does not match ExecContext job_id {job_id}",
            )
        )
    return request


def _normalize_sandbox_result(job_id: str, result: Any) -> dict[str, Any]:
    if isinstance(result, SandboxExecutionResult):
        payload = _sandbox_handle_payload(job_id, result.handle)
        payload.update(
            {
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "timed_out": result.timed_out,
                "duration_s": result.duration_s,
                "budget_usage": _json_compatible_payload(result.budget_usage),
            }
        )
        if result.partial_result is not None:
            payload["partial_result"] = _json_compatible_payload(result.partial_result)
        return payload
    if isinstance(result, SandboxHandle):
        return _sandbox_handle_payload(job_id, result)
    if isinstance(result, Mapping):
        return _normalize_sandbox_mapping(job_id, result)
    raise LifecyclePolicyError(
        build_error_envelope(
            category="SANDBOX",
            code="S10_SANDBOX_RESULT_INVALID",
            message=f"S10 sandbox marshaler returned unsupported result type: {type(result).__name__}",
        )
    )


def _sandbox_handle_payload(job_id: str, handle: SandboxHandle) -> dict[str, Any]:
    if handle.job_id != job_id:
        raise LifecyclePolicyError(
            build_error_envelope(
                category="SANDBOX",
                code="S10_SANDBOX_RESULT_JOB_MISMATCH",
                message=f"S10 sandbox result job_id {handle.job_id} does not match ExecContext job_id {job_id}",
            )
        )
    return {
        "capability": "submit_sandbox_job",
        "job_id": job_id,
        "sandbox_id": handle.sandbox_id,
        "runtime_class": handle.runtime_class,
        "budget_epoch": handle.budget_epoch,
        "policy_bundle_version": handle.policy_bundle_version,
        "state": handle.state,
        "launch_provenance_ref": handle.launch_provenance_ref,
    }


def _normalize_sandbox_mapping(job_id: str, result: Mapping[str, Any]) -> dict[str, Any]:
    handle = result.get("handle")
    if isinstance(handle, SandboxHandle):
        payload = _sandbox_handle_payload(job_id, handle)
        for key in ("exit_code", "stdout", "stderr", "timed_out", "duration_s", "budget_usage", "partial_result"):
            if key in result:
                payload[key] = _json_compatible_payload(result[key])
        return payload
    payload = _json_compatible_payload(result)
    if not isinstance(payload, dict):
        raise LifecyclePolicyError(
            build_error_envelope(
                category="SANDBOX",
                code="S10_SANDBOX_RESULT_INVALID",
                message="S10 sandbox marshaler returned a non-object mapping payload",
            )
        )
    result_job_id = str(payload.get("job_id", job_id))
    if result_job_id != job_id:
        raise LifecyclePolicyError(
            build_error_envelope(
                category="SANDBOX",
                code="S10_SANDBOX_RESULT_JOB_MISMATCH",
                message=f"S10 sandbox result job_id {result_job_id} does not match ExecContext job_id {job_id}",
            )
        )
    payload.setdefault("capability", "submit_sandbox_job")
    payload["job_id"] = job_id
    return payload


def _utc_now_s1() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_heartbeat_progress(progress: Any) -> float:
    if isinstance(progress, bool):
        _raise_heartbeat_policy("S1_HEARTBEAT_PROGRESS_INVALID", "heartbeat progress must be a number in [0, 1]")
    try:
        value = float(progress)
    except (TypeError, ValueError) as exc:
        raise LifecyclePolicyError(
            build_error_envelope(
                category="POLICY",
                code="S1_HEARTBEAT_PROGRESS_INVALID",
                message="heartbeat progress must be a number in [0, 1]",
            )
        ) from exc
    if value < 0.0 or value > 1.0:
        _raise_heartbeat_policy("S1_HEARTBEAT_PROGRESS_INVALID", "heartbeat progress must be a number in [0, 1]")
    return value


def _normalize_heartbeat_spend(spend_so_far: Mapping[str, Any]) -> dict[str, float]:
    if not isinstance(spend_so_far, Mapping):
        _raise_heartbeat_policy("S1_HEARTBEAT_SPEND_INVALID", "heartbeat spend_so_far must be a CostEstimate object")
    fields = set(str(field) for field in spend_so_far)
    extra = fields - S1_HEARTBEAT_COST_FIELDS
    if extra:
        _raise_heartbeat_policy(
            "S1_HEARTBEAT_SPEND_INVALID",
            "heartbeat spend_so_far contains unsupported fields: " + ", ".join(sorted(extra)),
        )
    if "cost_usd" not in fields:
        _raise_heartbeat_policy("S1_HEARTBEAT_SPEND_INVALID", "heartbeat spend_so_far requires cost_usd")
    normalized: dict[str, float] = {}
    for field_name, raw_value in spend_so_far.items():
        if isinstance(raw_value, bool):
            _raise_heartbeat_policy("S1_HEARTBEAT_SPEND_INVALID", f"heartbeat spend {field_name} must be numeric")
        try:
            value = float(raw_value)
        except (TypeError, ValueError) as exc:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="POLICY",
                    code="S1_HEARTBEAT_SPEND_INVALID",
                    message=f"heartbeat spend {field_name} must be numeric",
                )
            ) from exc
        if value < 0.0:
            _raise_heartbeat_policy("S1_HEARTBEAT_SPEND_INVALID", f"heartbeat spend {field_name} cannot be negative")
        normalized[str(field_name)] = value
    return normalized


def _assert_heartbeat_spend_monotonic(previous: Mapping[str, float], current: Mapping[str, float]) -> None:
    missing_fields = tuple(sorted(set(previous) - set(current)))
    if missing_fields:
        _raise_heartbeat_policy(
            "S1_HEARTBEAT_SPEND_REGRESSION",
            "heartbeat spend_so_far cannot drop previously reported fields: " + ", ".join(missing_fields),
        )
    regressed = tuple(
        sorted(field for field, previous_value in previous.items() if current[field] < previous_value)
    )
    if regressed:
        _raise_heartbeat_policy(
            "S1_HEARTBEAT_SPEND_REGRESSION",
            "heartbeat spend_so_far must be monotonically non-decreasing: " + ", ".join(regressed),
        )


def _raise_heartbeat_policy(code: str, message: str) -> NoReturn:
    raise LifecyclePolicyError(build_error_envelope(category="POLICY", code=code, message=message))


def _normalize_cancel_grace_seconds(grace_seconds: Any) -> float:
    if isinstance(grace_seconds, bool):
        _raise_policy("S1_CANCEL_GRACE_INVALID", "cancel grace_seconds must be non-negative")
    try:
        value = float(grace_seconds)
    except (TypeError, ValueError) as exc:
        raise LifecyclePolicyError(
            build_error_envelope(
                category="POLICY",
                code="S1_CANCEL_GRACE_INVALID",
                message="cancel grace_seconds must be non-negative",
            )
        ) from exc
    if value < 0:
        _raise_policy("S1_CANCEL_GRACE_INVALID", "cancel grace_seconds must be non-negative")
    return value


def _normalize_sandbox_cancellation(
    *,
    job_id: str,
    active: Mapping[str, Any],
    result: Any,
) -> dict[str, Any]:
    sandbox_id = str(active["sandbox_id"])
    payload: dict[str, Any] = {
        "job_id": job_id,
        "sandbox_id": sandbox_id,
    }
    launch_provenance_ref = active.get("launch_provenance_ref")
    if isinstance(launch_provenance_ref, str) and launch_provenance_ref:
        payload["launch_provenance_ref"] = launch_provenance_ref
    result_payload = _json_compatible_payload(result)
    if isinstance(result_payload, Mapping):
        state = result_payload.get("state")
        if state is not None:
            payload["state"] = str(state)
        terminate_succeeded = result_payload.get("terminate_succeeded")
        if terminate_succeeded is not None:
            payload["terminate_succeeded"] = bool(terminate_succeeded)
        partial_result_ref = result_payload.get("partial_result_ref")
        if isinstance(partial_result_ref, str) and partial_result_ref:
            payload["partial_result_ref"] = partial_result_ref
        elif "partial_result" in result_payload:
            payload["partial_result"] = result_payload["partial_result"]
    else:
        payload["state"] = "CANCEL_REQUESTED"
        payload["terminate_succeeded"] = False
    payload.setdefault("state", "CANCEL_REQUESTED")
    payload.setdefault("terminate_succeeded", False)
    return payload


def _normalize_sandbox_quarantine(
    *,
    job_id: str,
    active: Mapping[str, Any],
    result: Any,
) -> dict[str, Any]:
    sandbox_id = str(active["sandbox_id"])
    payload: dict[str, Any] = {
        "job_id": job_id,
        "sandbox_id": sandbox_id,
    }
    launch_provenance_ref = active.get("launch_provenance_ref")
    if isinstance(launch_provenance_ref, str) and launch_provenance_ref:
        payload["launch_provenance_ref"] = launch_provenance_ref
    result_payload = _json_compatible_payload(result)
    if isinstance(result_payload, Mapping):
        state = result_payload.get("state")
        if state is not None:
            payload["state"] = str(state)
        terminate_succeeded = result_payload.get("terminate_succeeded")
        if terminate_succeeded is not None:
            payload["terminate_succeeded"] = bool(terminate_succeeded)
        partial_result_ref = result_payload.get("partial_result_ref")
        if isinstance(partial_result_ref, str) and partial_result_ref:
            payload["partial_result_ref"] = partial_result_ref
        elif "partial_result" in result_payload:
            payload["partial_result"] = result_payload["partial_result"]
    else:
        payload["state"] = "QUARANTINE_REQUESTED"
        payload["terminate_succeeded"] = False
    payload.setdefault("state", "QUARANTINE_REQUESTED")
    payload.setdefault("terminate_succeeded", False)
    return payload


@dataclass(frozen=True)
class SubagentReport:
    artifact_refs: tuple[str, ...]
    validation_report_ref: str | None
    claim_tier: str
    uncertainty_summary: dict[str, Any] = field(default_factory=no_uncertainty_summary)
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class SubagentDescriptor:
    subagent_id: str
    contract_version: str
    subtopics: tuple[str, ...]
    required_adapters: tuple[str, ...] = ()


@dataclass(frozen=True)
class JobEnvelope:
    job_id: str
    envelope_version: str
    subtopic: str
    required_adapters: tuple[str, ...] = ()
    allowed_adapters: tuple[str, ...] = ()
    verifier_profile_ref: str | None = None
    estimated_cost: float = 0.0
    budget_cost: float = 0.0


JOB_ENVELOPE_FIELDS = frozenset(JobEnvelope.__dataclass_fields__)


@dataclass(frozen=True)
class Acceptance:
    job_id: str
    accepted: bool
    reason: str | None
    state: LifecycleState
    idempotency_key: str
    estimated_cost: float = 0.0

    def __post_init__(self) -> None:
        if self.accepted:
            if self.reason is not None:
                raise ValueError("accepted Acceptance must not carry a refusal reason")
            if self.state != LifecycleState.ACCEPTED:
                raise ValueError("accepted Acceptance must have state ACCEPTED")
        else:
            if self.reason not in ACCEPTANCE_REFUSAL_REASONS:
                raise ValueError("refused Acceptance must carry a C1 refusal reason")
            if self.state != LifecycleState.REJECTED:
                raise ValueError("refused Acceptance must have state REJECTED")
        if self.estimated_cost < 0:
            raise ValueError("estimated_cost cannot be negative")

    def as_c1_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "job_id": self.job_id,
            "accepted": self.accepted,
            "reason": self.reason,
            "state": self.state.value,
            "idempotency_key": self.idempotency_key,
        }
        if self.estimated_cost:
            payload["estimated_cost"] = {"cost_usd": self.estimated_cost}
        return payload


SDK_FRAMEWORK_METHODS = frozenset({"register", "accept", "validate", "report", "cancel", "heartbeat"})
DIRECT_EXEC_FORBIDDEN_CALLS = frozenset(
    {
        "eval",
        "exec",
        "os.popen",
        "os.system",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "subprocess.Popen",
        "subprocess.run",
    }
)


def _sdk_framework_method_owner(cls: type[object], method: str) -> type[object] | None:
    for owner in cls.__mro__:
        if method in owner.__dict__:
            return owner
    return None


def lint_subagent_for_direct_exec(subagent: "Subagent") -> tuple[str, ...]:
    violations: list[str] = []
    for method in ("plan", "build"):
        violations.extend(_direct_exec_violations(method, getattr(subagent, method)))
    return tuple(dict.fromkeys(violations))


def _direct_exec_violations(method: str, hook: Any) -> tuple[str, ...]:
    violations: list[str] = []
    hook = inspect.unwrap(hook)
    function = getattr(hook, "__func__", hook)
    try:
        source = textwrap.dedent(inspect.getsource(hook))
    except (OSError, TypeError):
        source = ""
    if source:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            tree = None
        if tree is not None:
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    call_name = _ast_call_name(node.func)
                    if call_name in DIRECT_EXEC_FORBIDDEN_CALLS:
                        violations.append(f"{method}: {call_name}")
    code = getattr(function, "__code__", None)
    if code is not None:
        names = set(code.co_names)
        if "eval" in names:
            violations.append(f"{method}: eval")
        if "exec" in names:
            violations.append(f"{method}: exec")
        for module, function in (("os", "popen"), ("os", "system")):
            if module in names and function in names:
                violations.append(f"{method}: {module}.{function}")
        for function in (
            "call",
            "check_call",
            "check_output",
            "getoutput",
            "getstatusoutput",
            "Popen",
            "run",
        ):
            if "subprocess" in names and function in names:
                violations.append(f"{method}: subprocess.{function}")
    return tuple(dict.fromkeys(violations))


def _ast_call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _ast_call_name(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    return None


@dataclass(frozen=True)
class SDKInvocationResult:
    event: LifecycleEvent
    payload: dict[str, Any]


@dataclass(frozen=True)
class S1ConformanceCheck:
    check_id: str
    level: str
    status: str
    oracle_spec: str
    reason: str | None = None
    evidence_refs: tuple[str, ...] = ()

    def as_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "check_id": self.check_id,
            "level": self.level,
            "status": self.status,
            "oracle_spec": self.oracle_spec,
            "evidence_refs": list(self.evidence_refs),
        }
        if self.reason is not None:
            payload["reason"] = self.reason
        return payload


@dataclass(frozen=True)
class S1ConformanceResult:
    subagent_id: str
    level_requested: str
    level_awarded: str
    suite_version: str
    standard_release_ref: str
    checks: tuple[S1ConformanceCheck, ...]
    aggregate_passed: bool
    determinism_hash: str
    evidence_ref: str

    def descriptor_conformance_block(self, *, expires_at: str | None = None) -> dict[str, str]:
        block = {
            "level": self.level_awarded,
            "suite_version": self.suite_version,
            "standard_release_ref": self.standard_release_ref,
            "evidence_ref": self.evidence_ref,
            "determinism_hash": self.determinism_hash,
        }
        if expires_at is not None:
            block["expires_at"] = _non_empty_conformance_string(expires_at, "expires_at")
        return block

    def as_payload(self) -> dict[str, Any]:
        return {
            "schema": "argus.s1.reference_conformance_result.v1",
            "subagent_id": self.subagent_id,
            "level_requested": self.level_requested,
            "level_awarded": self.level_awarded,
            "suite_version": self.suite_version,
            "standard_release_ref": self.standard_release_ref,
            "aggregate_passed": self.aggregate_passed,
            "determinism_hash": self.determinism_hash,
            "evidence_ref": self.evidence_ref,
            "checks": [check.as_payload() for check in self.checks],
        }


def build_s1_capability_descriptor(
    descriptor: SubagentDescriptor,
    *,
    revision: int,
    capability_scopes: tuple[str, ...] | None = None,
    independence_tags: tuple[str, ...] = (),
    trust_class: str = "internal",
    provenance_ref: str = "c4://pending",
    conformance: Mapping[str, str] | None = None,
    conformance_result: S1ConformanceResult | None = None,
    conformance_expires_at: str | None = None,
) -> CapabilityDescriptor:
    """Build an S1-owned C5 descriptor from the C1 subagent descriptor."""

    if conformance is not None and conformance_result is not None:
        raise ValueError("provide either conformance or conformance_result, not both")
    conformance_block = (
        _s1_descriptor_conformance_from_result(
            descriptor,
            conformance_result,
            expires_at=conformance_expires_at,
        )
        if conformance_result is not None
        else _normalize_s1_descriptor_conformance(conformance)
    )
    scopes = _normalize_s1_descriptor_values(
        capability_scopes if capability_scopes is not None else S1_CAPABILITY_DESCRIPTOR_DEFAULT_SCOPES,
        "capability_scopes",
    )
    _assert_s1_descriptor_scopes(scopes)
    return CapabilityDescriptor(
        entity_id=_non_empty_conformance_string(descriptor.subagent_id, "subagent_id"),
        revision=revision,
        kind="subagent",
        owner_subsystem="S1",
        contract_versions={"C1": descriptor.contract_version, "C5": "1.0.0"},
        trust_class=trust_class,
        capability_scopes=scopes,
        provenance_ref=provenance_ref,
        subtopics=_normalize_s1_descriptor_values(descriptor.subtopics, "subtopics"),
        independence_tags=_normalize_s1_descriptor_values(independence_tags, "independence_tags"),
        conformance=conformance_block,
    )


def publish_s1_capability_descriptor(
    registry: InMemoryRegistry,
    descriptor: SubagentDescriptor,
    *,
    revision: int,
    capability_scopes: tuple[str, ...] | None = None,
    independence_tags: tuple[str, ...] = (),
    trust_class: str = "internal",
    conformance: Mapping[str, str] | None = None,
    conformance_result: S1ConformanceResult | None = None,
    conformance_expires_at: str | None = None,
) -> CapabilityDescriptor:
    """Publish an S1 C5 descriptor through the registry with C4 provenance."""

    return registry.publish(
        build_s1_capability_descriptor(
            descriptor,
            revision=revision,
            capability_scopes=capability_scopes,
            independence_tags=independence_tags,
            trust_class=trust_class,
            conformance=conformance,
            conformance_result=conformance_result,
            conformance_expires_at=conformance_expires_at,
        )
    )


def _normalize_s1_descriptor_values(values: tuple[str, ...], name: str) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        item = str(value).strip()
        if not item:
            raise ValueError(f"{name} entries must be non-empty")
        normalized.append(item)
    return tuple(dict.fromkeys(normalized))


def _assert_s1_descriptor_scopes(scopes: tuple[str, ...]) -> None:
    missing = [scope for scope in S1_CAPABILITY_DESCRIPTOR_DEFAULT_SCOPES if scope not in scopes]
    if missing:
        raise ValueError("S1 capability descriptor missing required scope(s): " + ", ".join(missing))


def _normalize_s1_descriptor_conformance(conformance: Mapping[str, str] | None) -> dict[str, str] | None:
    if conformance is None:
        return None
    if not isinstance(conformance, CollectionsMapping):
        raise ValueError("conformance must be a mapping")
    normalized: dict[str, str] = {}
    for key, value in conformance.items():
        normalized[_non_empty_conformance_string(key, "conformance key")] = _non_empty_conformance_string(
            value,
            f"conformance.{key}",
        )
    missing = sorted(_S1_DESCRIPTOR_CONFORMANCE_FIELDS - set(normalized))
    if missing:
        raise ValueError("conformance missing required field(s): " + ", ".join(missing))
    extra = sorted(set(normalized) - _S1_DESCRIPTOR_CONFORMANCE_FIELDS)
    if extra:
        raise ValueError("conformance has unrecognized field(s): " + ", ".join(extra))
    if normalized["level"] not in {"bronze", "silver", "gold"}:
        raise ValueError("conformance.level must be one of: bronze, silver, gold")
    _assert_s1_descriptor_artifact_ref(normalized["standard_release_ref"], "conformance.standard_release_ref")
    _assert_s1_descriptor_artifact_ref(normalized["evidence_ref"], "conformance.evidence_ref")
    _assert_s1_descriptor_determinism_hash(normalized["determinism_hash"])
    _assert_s1_descriptor_conformance_expiry_parseable(normalized["expires_at"])
    return normalized


def _assert_s1_descriptor_artifact_ref(value: str, name: str) -> None:
    if not value.startswith("c4://") or value == "c4://":
        raise ValueError(f"{name} must be a C4 artifact ref")


def _assert_s1_descriptor_determinism_hash(value: str) -> None:
    prefix = "blake3:"
    digest = value[len(prefix) :] if value.startswith(prefix) else ""
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError("conformance.determinism_hash must be a blake3 digest")


def _assert_s1_descriptor_conformance_expiry_parseable(value: str) -> None:
    normalized = value.replace("Z", "+00:00") if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("conformance.expires_at must be an RFC3339 date-time") from exc
    if parsed.tzinfo is None:
        raise ValueError("conformance.expires_at must include a timezone")


def _s1_descriptor_conformance_from_result(
    descriptor: SubagentDescriptor,
    result: S1ConformanceResult,
    *,
    expires_at: str | None,
) -> dict[str, str]:
    if result.subagent_id != descriptor.subagent_id:
        raise ValueError("S1 descriptor conformance result subagent_id mismatch")
    if not result.aggregate_passed or result.level_awarded != result.level_requested:
        raise ValueError("S1 descriptor requires a passing conformance result")
    if expires_at is None:
        raise ValueError("S1 descriptor conformance expires_at is required")
    return result.descriptor_conformance_block(expires_at=expires_at)


class S1ReferenceConformanceHarness:
    """Executable Bronze/Silver/Gold reference harness for real S1 SDK subjects."""

    def __init__(
        self,
        *,
        suite_version: str = S1_REFERENCE_CONFORMANCE_SUITE_VERSION,
        standard_release_ref: str = S1_REFERENCE_CONFORMANCE_STANDARD_REF,
        attestation_signer: S1ConformanceAttestationSigner | None = None,
    ) -> None:
        self.suite_version = _non_empty_conformance_string(suite_version, "suite_version")
        self.standard_release_ref = _non_empty_conformance_string(standard_release_ref, "standard_release_ref")
        self._attestation_signer = attestation_signer

    def run(
        self,
        subagent: "Subagent",
        *,
        envelope: JobEnvelope,
        level: str,
        artifact_store: InMemoryArtifactStore | None = None,
        capability_descriptor: CapabilityDescriptor | None = None,
    ) -> S1ConformanceResult:
        requested_level = _normalize_s1_conformance_level(level)
        store = artifact_store if artifact_store is not None else InMemoryArtifactStore()
        runtime = SubagentRuntime(descriptor=subagent.descriptor, artifact_store=store)
        runner = SubagentSDKRunner(subagent, runtime=runtime)
        execution = _run_s1_reference_conformance_subject(runner, envelope)
        checks = _s1_reference_conformance_checks(
            execution=execution,
            requested_level=requested_level,
            capability_descriptor=capability_descriptor,
        )
        level_awarded = _s1_conformance_level_awarded(checks, requested_level)
        aggregate_passed = level_awarded == requested_level
        evidence_payload = _s1_reference_conformance_evidence_payload(
            subagent_id=subagent.descriptor.subagent_id,
            level_requested=requested_level,
            level_awarded=level_awarded,
            suite_version=self.suite_version,
            standard_release_ref=self.standard_release_ref,
            aggregate_passed=aggregate_passed,
            checks=checks,
            capability_descriptor=capability_descriptor,
        )
        determinism_hash = hash_json(evidence_payload)
        evidence_payload["determinism_hash"] = determinism_hash
        if self._attestation_signer is not None:
            evidence_payload = self._attestation_signer.sign_evidence(evidence_payload)
        evidence_record = store.create_artifact(
            kind=S1_REFERENCE_CONFORMANCE_EVIDENCE_KIND,
            payload=evidence_payload,
            producer=Producer(
                subsystem="S1",
                version=self.suite_version,
                actor_id="s1.reference_conformance",
                job_id=envelope.job_id,
            ),
            lineage=Lineage(
                input_refs=_s1_conformance_evidence_inputs(execution, capability_descriptor),
                code_ref=S1_REFERENCE_CONFORMANCE_CODE_REF,
                environment_digest=S1_REFERENCE_CONFORMANCE_ENVIRONMENT_DIGEST,
                seeds=("s1-reference-conformance-seed-v1",),
                job_id=envelope.job_id,
            ),
            created_at=S1_REFERENCE_CONFORMANCE_CREATED_AT,
        )
        return S1ConformanceResult(
            subagent_id=subagent.descriptor.subagent_id,
            level_requested=requested_level,
            level_awarded=level_awarded,
            suite_version=self.suite_version,
            standard_release_ref=self.standard_release_ref,
            checks=checks,
            aggregate_passed=aggregate_passed,
            determinism_hash=determinism_hash,
            evidence_ref=evidence_record.artifact_ref,
        )


@dataclass(frozen=True)
class _S1ConformanceExecution:
    runner: SubagentSDKRunner
    envelope: JobEnvelope
    accepted: Acceptance | None
    plan_payload: dict[str, Any] | None
    build_payload: dict[str, Any] | None
    error: Exception | None


def _run_s1_reference_conformance_subject(
    runner: SubagentSDKRunner,
    envelope: JobEnvelope,
) -> _S1ConformanceExecution:
    accepted: Acceptance | None = None
    plan_payload: dict[str, Any] | None = None
    build_payload: dict[str, Any] | None = None
    error: Exception | None = None
    try:
        accepted = runner.accept(
            envelope,
            idempotency_key=f"s1-conformance:accept:{envelope.job_id}",
            root_request_id="s1-reference-conformance",
            trace_id=f"trace:s1-reference-conformance:{envelope.job_id}",
        )
        if accepted.accepted:
            planned = runner.plan(
                envelope,
                idempotency_key=f"s1-conformance:plan:{envelope.job_id}",
                root_request_id="s1-reference-conformance",
                trace_id=f"trace:s1-reference-conformance:{envelope.job_id}",
            )
            plan_payload = planned.payload
            built = runner.build(
                envelope.job_id,
                plan_payload,
                idempotency_key=f"s1-conformance:build:{envelope.job_id}",
                root_request_id="s1-reference-conformance",
                trace_id=f"trace:s1-reference-conformance:{envelope.job_id}",
            )
            build_payload = built.payload
    except Exception as exc:
        error = exc
    return _S1ConformanceExecution(
        runner=runner,
        envelope=envelope,
        accepted=accepted,
        plan_payload=plan_payload,
        build_payload=build_payload,
        error=error,
    )


def _s1_reference_conformance_checks(
    *,
    execution: _S1ConformanceExecution,
    requested_level: str,
    capability_descriptor: CapabilityDescriptor | None,
) -> tuple[S1ConformanceCheck, ...]:
    checks = [
        _s1_bronze_lifecycle_check(execution),
        _s1_bronze_provenance_check(execution),
        _s1_bronze_no_self_tier_check(execution),
        _s1_bronze_declared_scope_check(execution),
    ]
    if _s1_conformance_rank(requested_level) >= _s1_conformance_rank("silver"):
        checks.append(_s1_silver_uncertainty_check(execution))
    if _s1_conformance_rank(requested_level) >= _s1_conformance_rank("gold"):
        checks.append(_s1_gold_cross_code_check(execution, capability_descriptor))
    return tuple(checks)


def _s1_bronze_lifecycle_check(execution: _S1ConformanceExecution) -> S1ConformanceCheck:
    oracle = "accepted=true AND lifecycle_methods==['accept','plan','build'] AND final_state=='BUILDING'"
    if execution.error is not None:
        return _s1_check(
            "S1-TC-36:bronze_lifecycle_statemachine",
            "bronze",
            False,
            oracle,
            reason=_s1_exception_reason(execution.error),
        )
    if execution.accepted is None or not execution.accepted.accepted:
        reason = execution.accepted.reason if execution.accepted is not None else "accept_not_run"
        return _s1_check(
            "S1-TC-36:bronze_lifecycle_statemachine",
            "bronze",
            False,
            oracle,
            reason=f"acceptance_refused:{reason}",
        )
    methods = [event.method for event in execution.runner.runtime.store.events(execution.envelope.job_id)]
    current = execution.runner.runtime.store.current(execution.envelope.job_id)
    passed = methods == ["accept", "plan", "build"] and current.state == LifecycleState.BUILDING
    reason = None if passed else f"methods={methods};state={current.state.value}"
    return _s1_check("S1-TC-36:bronze_lifecycle_statemachine", "bronze", passed, oracle, reason=reason)


def _s1_bronze_provenance_check(execution: _S1ConformanceExecution) -> S1ConformanceCheck:
    oracle = "artifact_refs non-empty AND every referenced C4 record exists with complete lineage"
    artifact_refs = _s1_build_artifact_refs(execution.build_payload)
    if not artifact_refs:
        return _s1_check(
            "S1-TC-36:bronze_c4_provenance_complete",
            "bronze",
            False,
            oracle,
            reason="build payload emitted no artifact_refs",
        )
    for artifact_ref in artifact_refs:
        try:
            record = execution.runner.runtime.artifact_store.get_record(artifact_ref)
            assert_lineage_complete(record.lineage)
        except Exception as exc:
            return _s1_check(
                "S1-TC-36:bronze_c4_provenance_complete",
                "bronze",
                False,
                oracle,
                reason=f"{artifact_ref}:{_s1_exception_reason(exc)}",
                evidence_refs=artifact_refs,
            )
    return _s1_check(
        "S1-TC-36:bronze_c4_provenance_complete",
        "bronze",
        True,
        oracle,
        evidence_refs=artifact_refs,
    )


def _s1_bronze_no_self_tier_check(execution: _S1ConformanceExecution) -> S1ConformanceCheck:
    oracle = "build payload omits tier/validation self-promotion fields AND artifact claim_tier=='ran-toy'"
    if isinstance(execution.error, LifecyclePolicyError) and execution.error.envelope.code in {
        "S1_BUILD_TIER_SELF_PROMOTION_FORBIDDEN",
        "S1_ARTIFACT_TIER_SELF_PROMOTION_FORBIDDEN",
    }:
        return _s1_check(
            "S1-TC-36:bronze_no_self_tier_promotion",
            "bronze",
            False,
            oracle,
            reason=execution.error.envelope.code,
        )
    payload = execution.build_payload or {}
    forbidden = sorted(set(payload) & BUILD_RESULT_TIER_SELF_PROMOTION_FIELDS)
    artifact_refs = _s1_build_artifact_refs(execution.build_payload)
    promoted_refs: list[str] = []
    for artifact_ref in artifact_refs:
        try:
            record = execution.runner.runtime.artifact_store.get_record(artifact_ref)
        except Exception:
            continue
        if record.claim_tier != "ran-toy":
            promoted_refs.append(record.artifact_ref)
    passed = not forbidden and not promoted_refs and execution.build_payload is not None
    reason = None
    if forbidden:
        reason = "forbidden_fields:" + ",".join(forbidden)
    elif promoted_refs:
        reason = "promoted_artifacts:" + ",".join(promoted_refs)
    elif execution.build_payload is None:
        reason = "build_not_completed"
    return _s1_check(
        "S1-TC-36:bronze_no_self_tier_promotion",
        "bronze",
        passed,
        oracle,
        reason=reason,
        evidence_refs=artifact_refs,
    )


def _s1_bronze_declared_scope_check(execution: _S1ConformanceExecution) -> S1ConformanceCheck:
    oracle = (
        "plan.adapters_required subset envelope.allowed_adapters "
        "AND plan.adapters_required subset descriptor.required_adapters"
    )
    if execution.plan_payload is None:
        return _s1_check(
            "S1-TC-36:bronze_declared_scope",
            "bronze",
            False,
            oracle,
            reason="plan_not_completed",
        )
    try:
        plan_adapters = tuple(str(adapter) for adapter in execution.plan_payload.get("adapters_required", ()))
    except Exception as exc:
        return _s1_check(
            "S1-TC-36:bronze_declared_scope",
            "bronze",
            False,
            oracle,
            reason=_s1_exception_reason(exc),
        )
    allowed_adapters = set(execution.envelope.allowed_adapters)
    descriptor_adapters = set(execution.runner.descriptor.required_adapters)
    outside_envelope = sorted(adapter for adapter in plan_adapters if adapter not in allowed_adapters)
    outside_descriptor = sorted(adapter for adapter in plan_adapters if adapter not in descriptor_adapters)
    passed = not outside_envelope and not outside_descriptor
    reason = None
    if outside_envelope:
        reason = "outside_envelope_allowed_adapters:" + ",".join(outside_envelope)
    elif outside_descriptor:
        reason = "outside_descriptor_required_adapters:" + ",".join(outside_descriptor)
    return _s1_check(
        "S1-TC-36:bronze_declared_scope",
        "bronze",
        passed,
        oracle,
        reason=reason,
    )


def _s1_silver_uncertainty_check(execution: _S1ConformanceExecution) -> S1ConformanceCheck:
    oracle = "uncertainty_summary.representation != 'none' for predictive build outputs"
    try:
        summary = _normalize_uncertainty_summary(
            (execution.build_payload or {}).get("uncertainty_summary", no_uncertainty_summary())
        )
        passed = summary["representation"] != "none"
        reason = None if passed else "uncertainty_summary.representation is none"
    except Exception as exc:
        passed = False
        reason = _s1_exception_reason(exc)
    return _s1_check("S1-TC-12:uncertainty_present", "silver", passed, oracle, reason=reason)


def _s1_gold_cross_code_check(
    execution: _S1ConformanceExecution,
    capability_descriptor: CapabilityDescriptor | None,
) -> S1ConformanceCheck:
    oracle = (
        "C5 descriptor entity matches the S1 descriptor AND independence_tags non-empty "
        "AND the S1 descriptor declares at least one cross-code adapter"
    )
    descriptor = capability_descriptor
    missing: list[str] = []
    if descriptor is None:
        missing.append("capability_descriptor")
    else:
        if descriptor.entity_id != execution.runner.descriptor.subagent_id:
            missing.append("entity_id")
        if descriptor.kind != "subagent":
            missing.append("kind")
        if not descriptor.independence_tags:
            missing.append("independence_tags")
        if execution.envelope.subtopic not in descriptor.subtopics:
            missing.append("subtopics")
    if not execution.runner.descriptor.required_adapters:
        missing.append("required_adapters")
    passed = not missing
    return _s1_check(
        "S1-TC-37:cross_code_ready",
        "gold",
        passed,
        oracle,
        reason=None if passed else "missing_or_mismatched:" + ",".join(missing),
    )


def _s1_check(
    check_id: str,
    level: str,
    passed: bool,
    oracle_spec: str,
    *,
    reason: str | None = None,
    evidence_refs: tuple[str, ...] = (),
) -> S1ConformanceCheck:
    return S1ConformanceCheck(
        check_id=check_id,
        level=level,
        status="PASS" if passed else "FAIL",
        oracle_spec=oracle_spec,
        reason=None if passed else (reason or "predicate failed"),
        evidence_refs=tuple(sorted(dict.fromkeys(evidence_refs))),
    )


def _s1_reference_conformance_evidence_payload(
    *,
    subagent_id: str,
    level_requested: str,
    level_awarded: str,
    suite_version: str,
    standard_release_ref: str,
    aggregate_passed: bool,
    checks: tuple[S1ConformanceCheck, ...],
    capability_descriptor: CapabilityDescriptor | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": "argus.s1.reference_conformance_evidence.v1",
        "subagent_id": subagent_id,
        "level_requested": level_requested,
        "level_awarded": level_awarded,
        "suite_version": suite_version,
        "standard_release_ref": standard_release_ref,
        "aggregate_passed": aggregate_passed,
        "checks": [check.as_payload() for check in checks],
    }
    if capability_descriptor is not None:
        payload["capability_descriptor_hash"] = hash_json(asdict(capability_descriptor))
    return payload


def _s1_conformance_evidence_inputs(
    execution: _S1ConformanceExecution,
    capability_descriptor: CapabilityDescriptor | None,
) -> tuple[str, ...]:
    refs = list(_s1_build_artifact_refs(execution.build_payload))
    if capability_descriptor is not None and capability_descriptor.provenance_ref:
        refs.append(capability_descriptor.provenance_ref)
    return tuple(sorted(dict.fromkeys(refs)))


def _s1_build_artifact_refs(build_payload: Mapping[str, Any] | None) -> tuple[str, ...]:
    if build_payload is None:
        return ()
    raw_refs = build_payload.get("artifact_refs", ())
    try:
        return tuple(str(ref) for ref in raw_refs)
    except TypeError:
        return ()


def _s1_conformance_level_awarded(checks: tuple[S1ConformanceCheck, ...], requested_level: str) -> str:
    for candidate in ("gold", "silver", "bronze"):
        if _s1_conformance_rank(candidate) > _s1_conformance_rank(requested_level):
            continue
        if all(
            check.status == "PASS"
            for check in checks
            if _s1_conformance_rank(check.level) <= _s1_conformance_rank(candidate)
        ):
            return candidate
    return "none"


def _normalize_s1_conformance_level(level: str) -> str:
    normalized = str(level).strip().lower()
    if normalized not in {"bronze", "silver", "gold"}:
        raise ValueError("S1 conformance level must be one of: bronze, silver, gold")
    return normalized


def _s1_conformance_rank(level: str) -> int:
    try:
        return S1_CONFORMANCE_LEVEL_ORDER[level]
    except KeyError as exc:
        raise ValueError(f"unknown S1 conformance level: {level}") from exc


def _non_empty_conformance_string(value: str, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _s1_exception_reason(exc: Exception) -> str:
    if isinstance(exc, LifecyclePolicyError):
        return f"{exc.envelope.category}:{exc.envelope.code}:{exc.envelope.message}"
    return f"{type(exc).__name__}:{exc}"


class Subagent(ABC):
    """Author-facing SDK base class for C1 subagents."""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        overridden = sorted(
            method
            for method in SDK_FRAMEWORK_METHODS
            if (owner := _sdk_framework_method_owner(cls, method)) is not None and owner is not Subagent
        )
        if overridden:
            methods = ", ".join(overridden)
            raise TypeError(f"{cls.__name__} overrides framework-owned S1 SDK method(s): {methods}")

    def __init__(self, descriptor: SubagentDescriptor) -> None:
        self.descriptor = descriptor

    @abstractmethod
    def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> Mapping[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def build(self, ctx: ExecContext, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        raise NotImplementedError

    @final
    def validate(self, *_args: Any, **_kwargs: Any) -> Mapping[str, Any]:
        raise LifecyclePolicyError(
            ErrorEnvelope(
                code="SDK_VALIDATE_FRAMEWORK_OWNED",
                category="POLICY",
                message="validate is framework-owned and cannot be implemented by subagent authors",
            )
        )

    @final
    def report(self, *_args: Any, **_kwargs: Any) -> Mapping[str, Any]:
        raise LifecyclePolicyError(
            ErrorEnvelope(
                code="SDK_REPORT_FRAMEWORK_OWNED",
                category="POLICY",
                message="report is framework-owned and cannot be implemented by subagent authors",
            )
        )


@dataclass(frozen=True)
class IdempotencyRecord:
    job_id: str
    method: str
    idempotency_key: str
    request_hash: str
    response_hash: str
    response: Any


class InMemoryIdempotencyStore:
    """In-memory idempotency table for mutating S1 method calls."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str, str], IdempotencyRecord] = {}

    def resolve(
        self,
        *,
        job_id: str,
        method: str,
        idempotency_key: str,
        request_hash: str,
    ) -> IdempotencyRecord | None:
        record = self._records.get((job_id, method, idempotency_key))
        if record is None:
            return None
        if record.request_hash != request_hash:
            raise LifecyclePolicyError(
                ErrorEnvelope(
                    code="IDEMPOTENCY_CONFLICT",
                    category="POLICY",
                    message=f"{method} idempotency key reused with a different request",
                )
            )
        return record

    def record(
        self,
        *,
        job_id: str,
        method: str,
        idempotency_key: str,
        request_hash: str,
        response: Any,
    ) -> IdempotencyRecord:
        existing = self.resolve(
            job_id=job_id,
            method=method,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
        )
        if existing is not None:
            return existing
        record = IdempotencyRecord(
            job_id=job_id,
            method=method,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            response_hash=_idempotency_response_hash(response),
            response=response,
        )
        self._records[(job_id, method, idempotency_key)] = record
        return record

    def records(self, job_id: str | None = None) -> tuple[IdempotencyRecord, ...]:
        records = tuple(self._records.values())
        if job_id is not None:
            records = tuple(record for record in records if record.job_id == job_id)
        return tuple(sorted(records, key=lambda record: (record.job_id, record.method, record.idempotency_key)))


def parse_job_envelope(payload: Mapping[str, Any]) -> JobEnvelope:
    values = {name: payload[name] for name in JOB_ENVELOPE_FIELDS if name in payload}
    for tuple_field in ("required_adapters", "allowed_adapters"):
        if tuple_field in values:
            values[tuple_field] = tuple(values[tuple_field])
    try:
        return JobEnvelope(**values)
    except TypeError as exc:
        raise ValueError(f"invalid C1 JobEnvelope payload: {exc}") from exc


class LifecycleStore:
    """In-memory event-sourced lifecycle store with optional C4 mirroring."""

    def __init__(
        self,
        *,
        artifact_store: InMemoryArtifactStore | None = None,
        idempotency_store: InMemoryIdempotencyStore | None = None,
        event_bus: InMemoryS1EventBus | None = None,
        ledger_producer: Producer | None = None,
        ledger_code_ref: str = S1_LIFECYCLE_LEDGER_CODE_REF,
        ledger_environment_digest: str = S1_LIFECYCLE_LEDGER_ENVIRONMENT_DIGEST,
    ) -> None:
        self._events: dict[str, list[LifecycleEvent]] = {}
        self._current: dict[str, JobCurrent] = {}
        self._artifact_store = artifact_store
        self._idempotency_store = idempotency_store or InMemoryIdempotencyStore()
        self._event_bus = event_bus
        self._ledger_producer = ledger_producer or Producer(
            subsystem="S1",
            version="0.0.0",
            actor_id="s1.lifecycle-store",
        )
        self._ledger_code_ref = ledger_code_ref
        self._ledger_environment_digest = ledger_environment_digest

    @classmethod
    def from_event_log(
        cls,
        events_by_job: Mapping[str, tuple[LifecycleEvent, ...]],
        *,
        artifact_store: InMemoryArtifactStore | None = None,
        idempotency_store: InMemoryIdempotencyStore | None = None,
        event_bus: InMemoryS1EventBus | None = None,
        ledger_producer: Producer | None = None,
        ledger_code_ref: str = S1_LIFECYCLE_LEDGER_CODE_REF,
        ledger_environment_digest: str = S1_LIFECYCLE_LEDGER_ENVIRONMENT_DIGEST,
    ) -> "LifecycleStore":
        store = cls(
            artifact_store=artifact_store,
            idempotency_store=idempotency_store,
            event_bus=event_bus,
            ledger_producer=ledger_producer,
            ledger_code_ref=ledger_code_ref,
            ledger_environment_digest=ledger_environment_digest,
        )
        for job_id, events in events_by_job.items():
            store._events[job_id] = list(events)
            store._current[job_id] = reduce_lifecycle(tuple(events), job_id=job_id)
            for event in events:
                store._record_event_idempotency(event)
        return store

    def create_job(self, job_id: str) -> JobCurrent:
        if job_id in self._current:
            return self._current[job_id]
        if job_id in self._events:
            return self.rebuild_current(job_id)
        current = JobCurrent(job_id=job_id, state=LifecycleState.REGISTERED, last_sequence=0)
        self._events.setdefault(job_id, [])
        self._current[job_id] = current
        return current

    def apply_method(
        self,
        job_id: str,
        method: str,
        *,
        trigger: str = "",
        payload: Any | None = None,
        idempotency_key: str | None = None,
        root_request_id: str | None = None,
        trace_id: str | None = None,
    ) -> LifecycleEvent:
        if method not in METHOD_TARGETS:
            raise ValueError(f"unknown lifecycle method: {method}")
        return self.transition(
            job_id,
            METHOD_TARGETS[method],
            method=method,
            trigger=trigger,
            payload=payload,
            idempotency_key=idempotency_key,
            root_request_id=root_request_id,
            trace_id=trace_id,
        )

    def transition(
        self,
        job_id: str,
        to_state: LifecycleState,
        *,
        method: str,
        trigger: str = "",
        payload: Any | None = None,
        idempotency_key: str | None = None,
        root_request_id: str | None = None,
        trace_id: str | None = None,
    ) -> LifecycleEvent:
        current = self._current.get(job_id)
        if current is None:
            current = self.create_job(job_id)
        payload_hash = hash_json(payload or {})
        request_hash = _lifecycle_request_hash(
            job_id=job_id,
            method=method,
            to_state=to_state,
            trigger=trigger,
            payload_hash=payload_hash,
        )
        resolved_idempotency_key = idempotency_key or _derive_lifecycle_idempotency_key(
            job_id=job_id,
            method=method,
            request_hash=request_hash,
        )
        existing = self._idempotency_store.resolve(
            job_id=job_id,
            method=_lifecycle_idempotency_method(method),
            idempotency_key=resolved_idempotency_key,
            request_hash=request_hash,
        )
        if existing is not None:
            return existing.response

        self._assert_legal_transition(current.state, to_state, method)
        next_sequence = current.last_sequence + 1
        event = LifecycleEvent(
            job_id=job_id,
            sequence=next_sequence,
            from_state=current.state,
            to_state=to_state,
            method=method,
            trigger=trigger,
            payload_hash=payload_hash,
            idempotency_key=resolved_idempotency_key,
            root_request_id=root_request_id or job_id,
            trace_id=trace_id or f"trace:{job_id}",
            event_id=_derive_lifecycle_event_id(
                job_id=job_id,
                sequence=next_sequence,
                method=method,
                request_hash=request_hash,
            ),
        )
        event = self._mirror_event(event)
        self._events[job_id].append(event)
        self._current[job_id] = JobCurrent(job_id=job_id, state=to_state, last_sequence=event.sequence)
        self._record_event_idempotency(event)
        self._publish_transition_event(event)
        return event

    def current(self, job_id: str) -> JobCurrent:
        if job_id not in self._current and job_id in self._events:
            return self.rebuild_current(job_id)
        return self._current[job_id]

    def events(self, job_id: str) -> tuple[LifecycleEvent, ...]:
        return tuple(self._events.get(job_id, ()))

    def replay(self, job_id: str) -> JobCurrent:
        return reduce_lifecycle(self.events(job_id), job_id=job_id)

    def rebuild_current(self, job_id: str) -> JobCurrent:
        current = self.replay(job_id)
        self._current[job_id] = current
        return current

    def ledger_refs(self, job_id: str) -> tuple[str, ...]:
        return tuple(event.ledger_ref for event in self.events(job_id) if event.ledger_ref is not None)

    def ledger_records(self, job_id: str) -> tuple[ArtifactRecord, ...]:
        if self._artifact_store is None:
            return ()
        return tuple(self._artifact_store.get_record(ref) for ref in self.ledger_refs(job_id))

    @property
    def artifact_store(self) -> InMemoryArtifactStore | None:
        return self._artifact_store

    @property
    def event_bus(self) -> InMemoryS1EventBus | None:
        return self._event_bus

    def idempotency_records(self, job_id: str | None = None) -> tuple[IdempotencyRecord, ...]:
        return self._idempotency_store.records(job_id)

    def _mirror_event(self, event: LifecycleEvent) -> LifecycleEvent:
        if self._artifact_store is None:
            return event
        record = self._artifact_store.create_artifact(
            kind=S1_LIFECYCLE_LEDGER_KIND,
            payload=_lifecycle_event_ledger_payload(event),
            producer=self._producer_for_event(event),
            lineage=Lineage(
                input_refs=self.ledger_refs(event.job_id)[-1:],
                code_ref=self._ledger_code_ref,
                environment_digest=self._ledger_environment_digest,
                job_id=event.job_id,
            ),
        )
        return replace(event, ledger_ref=record.artifact_ref)

    def _producer_for_event(self, event: LifecycleEvent) -> Producer:
        if self._ledger_producer.job_id is not None:
            return self._ledger_producer
        return replace(self._ledger_producer, job_id=event.job_id)

    def _record_event_idempotency(self, event: LifecycleEvent) -> IdempotencyRecord:
        return self._idempotency_store.record(
            job_id=event.job_id,
            method=_lifecycle_idempotency_method(event.method),
            idempotency_key=event.idempotency_key,
            request_hash=_lifecycle_request_hash(
                job_id=event.job_id,
                method=event.method,
                to_state=event.to_state,
                trigger=event.trigger,
                payload_hash=event.payload_hash,
            ),
            response=event,
        )

    def _publish_transition_event(self, event: LifecycleEvent) -> None:
        if self._event_bus is None:
            return
        self._event_bus.publish(
            "s1.lifecycle.transition",
            _lifecycle_event_bus_payload(event),
            event_id=event.event_id,
            trace_id=event.trace_id,
            root_request_id=event.root_request_id,
        )

    @staticmethod
    def _assert_legal_transition(from_state: LifecycleState, to_state: LifecycleState, method: str) -> None:
        if to_state not in LEGAL_TRANSITIONS[from_state]:
            raise LifecyclePolicyError(
                ErrorEnvelope(
                    code="ILLEGAL_TRANSITION",
                    category="POLICY",
                    message=f"{method} cannot transition {from_state.value} to {to_state.value}",
                )
        )


class SubagentRuntime:
    """Small S1 runtime facade for default accept gate, idempotency, and C4 provenance."""

    def __init__(
        self,
        *,
        descriptor: SubagentDescriptor,
        store: LifecycleStore | None = None,
        idempotency_store: InMemoryIdempotencyStore | None = None,
        artifact_store: InMemoryArtifactStore | None = None,
        sandbox_marshaler: Any | None = None,
        adapter_client: Any | None = None,
        adapter_egress_allowlist: Mapping[str, Any] | None = None,
        store_egress_rule: EgressRule = S1_CONTENT_STORE_EGRESS_RULE,
        max_build_repair_attempts: int = 0,
        build_repair_hook: Any | None = None,
        event_bus: InMemoryS1EventBus | None = None,
        telemetry_sink: InMemoryS1TelemetrySink | None = None,
    ) -> None:
        if max_build_repair_attempts < 0:
            raise ValueError("max_build_repair_attempts cannot be negative")
        self.descriptor = descriptor
        self.idempotency_store = idempotency_store or InMemoryIdempotencyStore()
        self.event_bus = event_bus or (store.event_bus if store is not None else None)
        self.telemetry_sink = telemetry_sink
        self.sandbox_marshaler = sandbox_marshaler
        self.adapter_client = adapter_client
        self.adapter_egress_allowlist = _normalize_adapter_egress_mapping(adapter_egress_allowlist or {})
        _assert_egress_rule_valid(store_egress_rule, "content store")
        self.store_egress_rule = store_egress_rule
        self.max_build_repair_attempts = max_build_repair_attempts
        self.build_repair_hook = build_repair_hook
        if store is not None:
            if artifact_store is not None:
                raise ValueError("artifact_store cannot be provided with an explicit LifecycleStore")
            self.store = store
            if self.event_bus is not None and store.event_bus is None:
                store._event_bus = self.event_bus
            self.artifact_store = store.artifact_store
        else:
            self.artifact_store = artifact_store if artifact_store is not None else InMemoryArtifactStore()
            self.store = LifecycleStore(
                artifact_store=self.artifact_store,
                idempotency_store=self.idempotency_store,
                event_bus=self.event_bus,
            )
        self.gate_invocations = 0
        self._heartbeats: dict[str, HeartbeatStatus] = {}
        self._cancel_flags: set[str] = set()
        self._active_sandboxes: dict[str, dict[str, dict[str, Any]]] = {}
        self._sandbox_attachment_refs: dict[str, dict[str, str]] = {}
        self._cancel_events: dict[str, LifecycleEvent] = {}
        self._quarantine_events: dict[str, LifecycleEvent] = {}

    def register(
        self,
        *,
        subagent_id: str | None = None,
        root_request_id: str | None = None,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        if subagent_id is not None and subagent_id != self.descriptor.subagent_id:
            raise ValueError(f"subagent_id {subagent_id} does not match {self.descriptor.subagent_id}")
        payload: dict[str, Any] = {
            "subagent_id": self.descriptor.subagent_id,
            "contract_version": self.descriptor.contract_version,
            "subtopics": list(self.descriptor.subtopics),
            "required_adapters": list(self.descriptor.required_adapters),
        }
        self._record_method_span(
            "register",
            root_request_id=root_request_id or self.descriptor.subagent_id,
            trace_id=trace_id or f"trace:{self.descriptor.subagent_id}",
            attributes={"status": "ok"},
        )
        self._publish_domain_event(
            "s1.subagent.registered",
            {
                **payload,
                "root_request_id": root_request_id or self.descriptor.subagent_id,
                "trace_id": trace_id or f"trace:{self.descriptor.subagent_id}",
            },
            root_request_id=root_request_id or self.descriptor.subagent_id,
            trace_id=trace_id or f"trace:{self.descriptor.subagent_id}",
        )
        return payload

    def accept(
        self,
        envelope: JobEnvelope,
        *,
        idempotency_key: str | None = None,
        root_request_id: str | None = None,
        trace_id: str | None = None,
    ) -> Acceptance:
        resolved_idempotency_key = idempotency_key or _default_accept_idempotency_key(envelope.job_id)
        request_hash = hash_json(envelope.__dict__)
        existing = self.idempotency_store.resolve(
            job_id=envelope.job_id,
            method="accept",
            idempotency_key=resolved_idempotency_key,
            request_hash=request_hash,
        )
        if existing is not None:
            self._record_method_span(
                "accept",
                job_id=envelope.job_id,
                root_request_id=root_request_id or envelope.job_id,
                trace_id=trace_id or f"trace:{envelope.job_id}",
                attributes={
                    "accepted": existing.response.accepted,
                    "reason": existing.response.reason,
                    "state": existing.response.state.value,
                    "idempotent": True,
                },
            )
            return existing.response

        self.gate_invocations += 1
        self.store.create_job(envelope.job_id)
        acceptance = default_accept(self.descriptor, envelope, idempotency_key=resolved_idempotency_key)
        transition_payload = {
            "accepted": acceptance.accepted,
            "reason": acceptance.reason,
            "state": acceptance.state.value,
            "estimated_cost": acceptance.estimated_cost,
        }
        self.store.apply_method(
            envelope.job_id,
            "accept" if acceptance.accepted else "refuse",
            trigger="S5",
            payload=transition_payload,
            idempotency_key=resolved_idempotency_key,
            root_request_id=root_request_id,
            trace_id=trace_id,
        )
        self._record_method_span(
            "accept",
            job_id=envelope.job_id,
            root_request_id=root_request_id or envelope.job_id,
            trace_id=trace_id or f"trace:{envelope.job_id}",
            attributes={
                "accepted": acceptance.accepted,
                "reason": acceptance.reason,
                "state": acceptance.state.value,
                "idempotent": False,
            },
        )
        if not acceptance.accepted:
            self._publish_domain_event(
                "s1.job.refused",
                {
                    "job_id": envelope.job_id,
                    "reason": acceptance.reason,
                    "state": acceptance.state.value,
                    "idempotency_key": acceptance.idempotency_key,
                    "root_request_id": root_request_id or envelope.job_id,
                    "trace_id": trace_id or f"trace:{envelope.job_id}",
                },
                root_request_id=root_request_id or envelope.job_id,
                trace_id=trace_id or f"trace:{envelope.job_id}",
            )
        self.idempotency_store.record(
            job_id=envelope.job_id,
            method="accept",
            idempotency_key=resolved_idempotency_key,
            request_hash=request_hash,
            response=acceptance,
        )
        return acceptance

    def record_heartbeat(
        self,
        job_id: str,
        *,
        progress: float,
        spend_so_far: Mapping[str, Any],
    ) -> HeartbeatStatus:
        current = self.store.current(job_id)
        normalized_progress = _normalize_heartbeat_progress(progress)
        normalized_spend = _normalize_heartbeat_spend(spend_so_far)
        previous = self._heartbeats.get(job_id)
        if previous is not None:
            _assert_heartbeat_spend_monotonic(previous.spend_so_far, normalized_spend)
        heartbeat = HeartbeatStatus(
            job_id=job_id,
            status=current.state,
            progress=normalized_progress,
            spend_so_far=normalized_spend,
            last_heartbeat_at=_utc_now_s1(),
        )
        self._heartbeats[job_id] = heartbeat
        return heartbeat

    def heartbeat(
        self,
        job_id: str,
        *,
        root_request_id: str | None = None,
        trace_id: str | None = None,
    ) -> HeartbeatStatus:
        current = self.store.current(job_id)
        heartbeat = self._heartbeats.get(job_id)
        if heartbeat is None:
            heartbeat = HeartbeatStatus(
                job_id=job_id,
                status=current.state,
                progress=1.0 if current.state in TERMINAL_STATES else 0.0,
                spend_so_far={"cost_usd": 0.0},
                last_heartbeat_at=_utc_now_s1(),
            )
        heartbeat = replace(heartbeat, status=current.state)
        self._record_method_span(
            "heartbeat",
            job_id=job_id,
            root_request_id=root_request_id or job_id,
            trace_id=trace_id or f"trace:{job_id}",
            attributes={
                "state": heartbeat.status.value,
                "progress": heartbeat.progress,
            },
        )
        return heartbeat

    def register_sandbox_result(self, job_id: str, result: Mapping[str, Any]) -> None:
        sandbox_id = result.get("sandbox_id")
        if not isinstance(sandbox_id, str) or not sandbox_id:
            return
        payload = dict(_json_compatible_payload(result))
        attachment_ref = self._record_sandbox_attachment(job_id=job_id, sandbox_id=sandbox_id, payload=payload)
        if attachment_ref is not None:
            payload["attachment_ref"] = attachment_ref
            self._sandbox_attachment_refs.setdefault(job_id, {})[sandbox_id] = attachment_ref
        self._active_sandboxes.setdefault(job_id, {})[sandbox_id] = payload

    def active_sandboxes(self, job_id: str) -> tuple[dict[str, Any], ...]:
        return tuple(dict(payload) for _sandbox_id, payload in sorted(self._active_sandboxes.get(job_id, {}).items()))

    def sandbox_attachment_refs(self, job_id: str) -> tuple[str, ...]:
        refs = tuple(ref for _sandbox_id, ref in sorted(self._sandbox_attachment_refs.get(job_id, {}).items()))
        if refs:
            return refs
        return tuple(record.artifact_ref for record, _payload in self._sandbox_attachment_records(job_id))

    def recover_active_sandboxes(self, job_id: str) -> tuple[dict[str, Any], ...]:
        current = self.store.current(job_id)
        if current.state != LifecycleState.BUILDING:
            self._active_sandboxes.pop(job_id, None)
            return ()
        recovered: dict[str, dict[str, Any]] = {}
        attachment_refs: dict[str, str] = {}
        for record, payload in self._sandbox_attachment_records(job_id):
            sandbox_payload = payload.get("sandbox_result")
            if not isinstance(sandbox_payload, dict):
                raise LifecyclePolicyError(
                    build_error_envelope(
                        category="SANDBOX",
                        code="S10_SANDBOX_ATTACHMENT_INVALID",
                        message=f"sandbox attachment {record.artifact_ref} has no sandbox_result object",
                    )
                )
            sandbox_id = sandbox_payload.get("sandbox_id")
            if not isinstance(sandbox_id, str) or not sandbox_id:
                raise LifecyclePolicyError(
                    build_error_envelope(
                        category="SANDBOX",
                        code="S10_SANDBOX_ATTACHMENT_INVALID",
                        message=f"sandbox attachment {record.artifact_ref} has no sandbox_id",
                    )
                )
            restored = self._resolve_sandbox_attachment(job_id=job_id, active=sandbox_payload)
            restored["attachment_ref"] = record.artifact_ref
            recovered[sandbox_id] = restored
            attachment_refs[sandbox_id] = record.artifact_ref
        self._active_sandboxes[job_id] = recovered
        self._sandbox_attachment_refs[job_id] = attachment_refs
        return self.active_sandboxes(job_id)

    def _record_sandbox_attachment(self, *, job_id: str, sandbox_id: str, payload: dict[str, Any]) -> str | None:
        if self.artifact_store is None:
            return None
        attachment_payload = {
            "schema": "argus.s1.sandbox_attachment.v1",
            "job_id": job_id,
            "sandbox_id": sandbox_id,
            "sandbox_result": dict(payload),
        }
        input_refs = list(self.store.ledger_refs(job_id)[-1:])
        launch_provenance_ref = payload.get("launch_provenance_ref")
        if isinstance(launch_provenance_ref, str) and launch_provenance_ref and launch_provenance_ref not in input_refs:
            input_refs.append(launch_provenance_ref)
        record = self.artifact_store.create_artifact(
            kind=S1_SANDBOX_ATTACHMENT_KIND,
            payload=attachment_payload,
            producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.sandbox-attachment", job_id=job_id),
            lineage=Lineage(
                input_refs=tuple(input_refs),
                code_ref=S1_SANDBOX_ATTACHMENT_CODE_REF,
                environment_digest=S1_SANDBOX_ATTACHMENT_ENVIRONMENT_DIGEST,
                job_id=job_id,
            ),
        )
        return record.artifact_ref

    def _sandbox_attachment_records(self, job_id: str) -> tuple[tuple[ArtifactRecord, dict[str, Any]], ...]:
        if self.artifact_store is None:
            return ()
        records = sorted(
            self.artifact_store.query_artifacts({"kind": S1_SANDBOX_ATTACHMENT_KIND, "job_id": job_id}),
            key=lambda record: (record.created_at, record.artifact_ref),
        )
        parsed: list[tuple[ArtifactRecord, dict[str, Any]]] = []
        for record in records:
            payload = json.loads(self.artifact_store.get_artifact(record.artifact_ref).decode("utf-8"))
            if not isinstance(payload, dict):
                raise LifecyclePolicyError(
                    build_error_envelope(
                        category="SANDBOX",
                        code="S10_SANDBOX_ATTACHMENT_INVALID",
                        message=f"sandbox attachment {record.artifact_ref} payload is not an object",
                    )
                )
            if payload.get("job_id") != job_id:
                raise LifecyclePolicyError(
                    build_error_envelope(
                        category="SANDBOX",
                        code="S10_SANDBOX_ATTACHMENT_INVALID",
                        message=f"sandbox attachment {record.artifact_ref} job_id does not match {job_id}",
                    )
                )
            sandbox_payload = payload.get("sandbox_result")
            declared_sandbox_id = payload.get("sandbox_id")
            if isinstance(sandbox_payload, dict) and sandbox_payload.get("sandbox_id") != declared_sandbox_id:
                raise LifecyclePolicyError(
                    build_error_envelope(
                        category="SANDBOX",
                        code="S10_SANDBOX_ATTACHMENT_INVALID",
                        message=f"sandbox attachment {record.artifact_ref} sandbox_id does not match sandbox_result",
                    )
                )
            parsed.append((record, payload))
        return tuple(parsed)

    def _resolve_sandbox_attachment(self, *, job_id: str, active: Mapping[str, Any]) -> dict[str, Any]:
        sandbox_id = str(active["sandbox_id"])
        if self.sandbox_marshaler is None:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_SANDBOX_REATTACH_UNAVAILABLE",
                    message="cannot recover active sandbox without an S10 sandbox marshaler",
                )
            )
        result = self._call_sandbox_resolver(job_id=job_id, sandbox_id=sandbox_id, active=active)
        resolved = _normalize_sandbox_result(job_id, result)
        if resolved.get("sandbox_id") != sandbox_id:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_SANDBOX_REATTACH_MISMATCH",
                    message=f"resolved sandbox {resolved.get('sandbox_id')} does not match attachment {sandbox_id}",
                )
            )
        restored = dict(active)
        restored.update(resolved)
        restored["reattach_state"] = str(resolved.get("state", restored.get("state", "UNKNOWN")))
        return restored

    def _call_sandbox_resolver(self, *, job_id: str, sandbox_id: str, active: Mapping[str, Any]) -> Any:
        reattach = getattr(self.sandbox_marshaler, "reattach_sandbox_job", None)
        if callable(reattach):
            try:
                return reattach(job_id=job_id, sandbox_id=sandbox_id, attachment=dict(active))
            except KeyError as exc:
                raise self._sandbox_reattach_failed(sandbox_id, exc) from exc
        resolve = getattr(self.sandbox_marshaler, "resolve_sandbox_job", None)
        if callable(resolve):
            try:
                return resolve(job_id=job_id, sandbox_id=sandbox_id)
            except KeyError as exc:
                raise self._sandbox_reattach_failed(sandbox_id, exc) from exc
        get = getattr(self.sandbox_marshaler, "get", None)
        if callable(get):
            try:
                return get(sandbox_id)
            except KeyError as exc:
                raise self._sandbox_reattach_failed(sandbox_id, exc) from exc
        raise LifecyclePolicyError(
            build_error_envelope(
                category="SANDBOX",
                code="S10_SANDBOX_REATTACH_UNAVAILABLE",
                message="S10 sandbox marshaler cannot resolve durable sandbox handles",
            )
        )

    @staticmethod
    def _sandbox_reattach_failed(sandbox_id: str, exc: Exception) -> LifecyclePolicyError:
        return LifecyclePolicyError(
            build_error_envelope(
                category="SANDBOX",
                code="S10_SANDBOX_REATTACH_FAILED",
                message=f"S10 sandbox reattach failed for {sandbox_id}: {exc}",
            )
        )

    def cancel_requested(self, job_id: str) -> bool:
        return job_id in self._cancel_flags

    def cancel(
        self,
        job_id: str,
        *,
        reason: str = "operator",
        grace_seconds: float = S1_CANCEL_DEFAULT_GRACE_SECONDS,
        idempotency_key: str | None = None,
        root_request_id: str | None = None,
        trace_id: str | None = None,
    ) -> LifecycleEvent:
        if job_id in self._cancel_events and idempotency_key is None:
            self._record_method_span(
                "cancel",
                job_id=job_id,
                root_request_id=root_request_id or job_id,
                trace_id=trace_id or f"trace:{job_id}",
                attributes={"state": self._cancel_events[job_id].to_state.value, "idempotent": True},
            )
            return self._cancel_events[job_id]
        normalized_grace_seconds = _normalize_cancel_grace_seconds(grace_seconds)
        self._cancel_flags.add(job_id)
        sandbox_cancellations = [
            self._cancel_active_sandbox(
                job_id=job_id,
                active=active,
                reason=str(reason),
                grace_seconds=normalized_grace_seconds,
            )
            for _sandbox_id, active in sorted(self._active_sandboxes.get(job_id, {}).items())
        ]
        payload = {
            "category": "CANCELLED",
            "cooperative": True,
            "grace_seconds": normalized_grace_seconds,
            "reason": str(reason),
            "sandbox_cancellations": sandbox_cancellations,
        }
        event = self.store.apply_method(
            job_id,
            "cancel",
            trigger="cancel",
            payload=payload,
            idempotency_key=idempotency_key,
            root_request_id=root_request_id,
            trace_id=trace_id,
        )
        self._cancel_events[job_id] = event
        self._active_sandboxes.pop(job_id, None)
        self._record_method_span(
            "cancel",
            job_id=job_id,
            root_request_id=root_request_id or job_id,
            trace_id=trace_id or f"trace:{job_id}",
            attributes={"state": event.to_state.value, "idempotent": False},
        )
        return event

    def _cancel_active_sandbox(
        self,
        *,
        job_id: str,
        active: Mapping[str, Any],
        reason: str,
        grace_seconds: float,
    ) -> dict[str, Any]:
        sandbox_id = str(active["sandbox_id"])
        hook = None
        for name in ("cancel_sandbox_job", "terminate_sandbox_job", "cancel"):
            candidate = getattr(self.sandbox_marshaler, name, None)
            if callable(candidate):
                hook = candidate
                break
        if hook is None:
            return _normalize_sandbox_cancellation(
                job_id=job_id,
                active=active,
                result={"state": "CANCEL_REQUESTED", "terminate_succeeded": False},
            )
        result = hook(
            job_id=job_id,
            sandbox_id=sandbox_id,
            reason=reason,
            grace_seconds=grace_seconds,
        )
        return _normalize_sandbox_cancellation(job_id=job_id, active=active, result=result)

    def quarantine(
        self,
        job_id: str,
        *,
        error: ErrorEnvelope,
        reason: str | None = None,
        grace_seconds: float = S1_CANCEL_DEFAULT_GRACE_SECONDS,
        idempotency_key: str | None = None,
        root_request_id: str | None = None,
        trace_id: str | None = None,
    ) -> LifecycleEvent:
        if job_id in self._quarantine_events and idempotency_key is None:
            self._record_method_span(
                "quarantine",
                job_id=job_id,
                root_request_id=root_request_id or job_id,
                trace_id=trace_id or f"trace:{job_id}",
                attributes={"state": self._quarantine_events[job_id].to_state.value, "idempotent": True},
            )
            return self._quarantine_events[job_id]
        if not error.behavior.quarantine:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="POLICY",
                    code="S1_QUARANTINE_ERROR_CATEGORY_INVALID",
                    message=f"{error.category} errors do not use the S1 quarantine path",
                )
            )
        normalized_grace_seconds = _normalize_cancel_grace_seconds(grace_seconds)
        resolved_reason = reason or f"{error.category}:{error.code}"
        error_payload = error.as_c1_payload()
        sandbox_quarantines = [
            self._quarantine_active_sandbox(
                job_id=job_id,
                active=active,
                reason=resolved_reason,
                grace_seconds=normalized_grace_seconds,
                error_payload=error_payload,
            )
            for _sandbox_id, active in sorted(self._active_sandboxes.get(job_id, {}).items())
        ]
        payload = {
            "category": error.category,
            "code": error.code,
            "error": error_payload,
            "grace_seconds": normalized_grace_seconds,
            "reason": resolved_reason,
            "sandbox_quarantines": sandbox_quarantines,
        }
        event = self.store.apply_method(
            job_id,
            "quarantine",
            trigger="S1 quarantine",
            payload=payload,
            idempotency_key=idempotency_key,
            root_request_id=root_request_id,
            trace_id=trace_id,
        )
        self._quarantine_events[job_id] = event
        self._active_sandboxes.pop(job_id, None)
        self._record_method_span(
            "quarantine",
            job_id=job_id,
            root_request_id=root_request_id or job_id,
            trace_id=trace_id or f"trace:{job_id}",
            attributes={
                "state": event.to_state.value,
                "category": error.category,
                "code": error.code,
                "idempotent": False,
            },
        )
        self._publish_domain_event(
            "s1.job.quarantined",
            {
                "job_id": job_id,
                "reason": resolved_reason,
                "state": event.to_state.value,
                "error": error_payload,
                "root_request_id": root_request_id or job_id,
                "trace_id": trace_id or f"trace:{job_id}",
            },
            root_request_id=root_request_id or job_id,
            trace_id=trace_id or f"trace:{job_id}",
        )
        return event

    def _record_method_span(
        self,
        method: str,
        *,
        job_id: str | None = None,
        root_request_id: str | None = None,
        trace_id: str | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> S1TelemetrySpan | None:
        if self.telemetry_sink is None:
            return None
        resolved_trace_id = trace_id or (f"trace:{job_id}" if job_id is not None else f"trace:{self.descriptor.subagent_id}")
        resolved_root_request_id = root_request_id or job_id or self.descriptor.subagent_id
        span_attributes: dict[str, Any] = {
            "method": method,
            "root_request_id": resolved_root_request_id,
            "subagent_id": self.descriptor.subagent_id,
        }
        if job_id is not None:
            span_attributes["job_id"] = job_id
            try:
                span_attributes["state"] = self.store.current(job_id).state.value
            except KeyError:
                pass
        span_attributes.update(dict(attributes or {}))
        return self.telemetry_sink.record_span(
            f"S1.{method}",
            trace_id=resolved_trace_id,
            attributes=span_attributes,
        )

    def _publish_domain_event(
        self,
        subject: str,
        payload: Mapping[str, Any],
        *,
        root_request_id: str | None = None,
        trace_id: str | None = None,
    ) -> S1LifecycleBusEvent | None:
        if self.event_bus is None:
            return None
        return self.event_bus.publish(
            subject,
            payload,
            trace_id=trace_id,
            root_request_id=root_request_id,
        )

    def _quarantine_active_sandbox(
        self,
        *,
        job_id: str,
        active: Mapping[str, Any],
        reason: str,
        grace_seconds: float,
        error_payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        sandbox_id = str(active["sandbox_id"])
        quarantine_hook = getattr(self.sandbox_marshaler, "quarantine_sandbox_job", None)
        try:
            if callable(quarantine_hook):
                result = quarantine_hook(
                    job_id=job_id,
                    sandbox_id=sandbox_id,
                    reason=reason,
                    grace_seconds=grace_seconds,
                    error=dict(error_payload),
                )
                return _normalize_sandbox_quarantine(job_id=job_id, active=active, result=result)
            return self._cancel_active_sandbox(
                job_id=job_id,
                active=active,
                reason=reason,
                grace_seconds=grace_seconds,
            )
        except LifecyclePolicyError as exc:
            return _normalize_sandbox_quarantine(
                job_id=job_id,
                active=active,
                result={
                    "state": "QUARANTINE_FAILED",
                    "terminate_succeeded": False,
                    "error": exc.envelope.as_c1_payload(),
                },
            )


class SubagentSDKRunner:
    """IoC runner that binds an author Subagent to the real S1 runtime."""

    def __init__(self, subagent: Subagent, *, runtime: SubagentRuntime | None = None) -> None:
        self.subagent = subagent
        self.runtime = runtime or SubagentRuntime(descriptor=subagent.descriptor)
        if self.runtime.descriptor != subagent.descriptor:
            raise ValueError("SubagentSDKRunner runtime descriptor must match the subagent descriptor")

    @property
    def descriptor(self) -> SubagentDescriptor:
        return self.runtime.descriptor

    def accept(
        self,
        envelope: JobEnvelope,
        *,
        idempotency_key: str | None = None,
        root_request_id: str | None = None,
        trace_id: str | None = None,
    ) -> Acceptance:
        return self.runtime.accept(
            envelope,
            idempotency_key=idempotency_key,
            root_request_id=root_request_id,
            trace_id=trace_id,
        )

    def plan(
        self,
        envelope: JobEnvelope,
        *,
        idempotency_key: str | None = None,
        root_request_id: str | None = None,
        trace_id: str | None = None,
    ) -> SDKInvocationResult:
        self._assert_can_apply(envelope.job_id, "plan")
        self._assert_no_direct_exec(
            envelope.job_id,
            "plan",
            self.subagent.plan,
            root_request_id=root_request_id,
            trace_id=trace_id,
        )
        ctx = self._exec_context(
            envelope.job_id,
            allowed_adapters=envelope.allowed_adapters,
            root_request_id=root_request_id,
            trace_id=trace_id,
        )
        payload = _normalize_plan_payload(envelope, self.subagent.plan(ctx, envelope))
        event = self.runtime.store.apply_method(
            envelope.job_id,
            "plan",
            trigger="internal",
            payload={"plan_hash": payload["plan_hash"]},
            idempotency_key=idempotency_key,
            root_request_id=root_request_id,
            trace_id=trace_id,
        )
        self.runtime._record_method_span(
            "plan",
            job_id=envelope.job_id,
            root_request_id=root_request_id or envelope.job_id,
            trace_id=trace_id or f"trace:{envelope.job_id}",
            attributes={"state": event.to_state.value},
        )
        return SDKInvocationResult(event=event, payload=payload)

    def build(
        self,
        job_id: str,
        plan: Mapping[str, Any],
        *,
        idempotency_key: str | None = None,
        root_request_id: str | None = None,
        trace_id: str | None = None,
    ) -> SDKInvocationResult:
        self._assert_can_apply(job_id, "build")
        self._assert_no_direct_exec(
            job_id,
            "build",
            self.subagent.build,
            root_request_id=root_request_id,
            trace_id=trace_id,
        )
        plan_payload = _mapping_payload("plan", plan)
        repair_attempts: list[dict[str, Any]] = []
        current_plan = dict(plan_payload)
        while True:
            ctx = self._exec_context(
                job_id,
                allowed_adapters=tuple(str(adapter) for adapter in current_plan.get("adapters_required", ())),
                allowed_datasets=tuple(str(dataset) for dataset in current_plan.get("datasets_required", ())),
                root_request_id=root_request_id,
                trace_id=trace_id,
            )
            try:
                payload = _normalize_build_payload(job_id, self.subagent.build(ctx, current_plan))
                payload = _attach_build_repair_diagnostics(payload, repair_attempts)
                break
            except LifecyclePolicyError as exc:
                if not self._can_auto_repair_build(exc):
                    self._quarantine_build_error(
                        job_id=job_id,
                        error=exc,
                        idempotency_key=idempotency_key,
                        root_request_id=root_request_id,
                        trace_id=trace_id,
                    )
                    raise
                current_plan = self._repair_build_plan(
                    job_id=job_id,
                    plan_payload=current_plan,
                    error=exc,
                    repair_attempts=repair_attempts,
                    idempotency_key=idempotency_key,
                    root_request_id=root_request_id,
                    trace_id=trace_id,
                )
            except Exception as exc:
                error = LifecyclePolicyError(
                    build_error_envelope(
                        category="PERMANENT",
                        code="S1_BUILD_HOOK_FAILED",
                        message=f"build hook failed before returning a valid payload: {exc}",
                    )
                )
                if not self._can_auto_repair_build(error):
                    raise error from exc
                current_plan = self._repair_build_plan(
                    job_id=job_id,
                    plan_payload=current_plan,
                    error=error,
                    repair_attempts=repair_attempts,
                    idempotency_key=idempotency_key,
                    root_request_id=root_request_id,
                    trace_id=trace_id,
                )
        event = self.runtime.store.apply_method(
            job_id,
            "build",
            trigger="internal",
            payload={
                "plan_hash": plan_payload.get("plan_hash"),
                "build_result_hash": hash_json(payload),
            },
            idempotency_key=idempotency_key,
            root_request_id=root_request_id,
            trace_id=trace_id,
        )
        self.runtime._record_method_span(
            "build",
            job_id=job_id,
            root_request_id=root_request_id or job_id,
            trace_id=trace_id or f"trace:{job_id}",
            attributes={"state": event.to_state.value},
        )
        return SDKInvocationResult(event=event, payload=payload)

    def _can_auto_repair_build(self, error: LifecyclePolicyError) -> bool:
        if self.runtime.max_build_repair_attempts <= 0:
            return False
        if self.runtime.build_repair_hook is None:
            return False
        return error.envelope.category in S1_BUILD_REPAIRABLE_ERROR_CATEGORIES

    def _quarantine_build_error(
        self,
        *,
        job_id: str,
        error: LifecyclePolicyError,
        idempotency_key: str | None,
        root_request_id: str | None,
        trace_id: str | None,
    ) -> None:
        if not error.envelope.behavior.quarantine:
            return
        self.runtime.quarantine(
            job_id,
            error=error.envelope,
            idempotency_key=idempotency_key,
            root_request_id=root_request_id,
            trace_id=trace_id,
        )

    def _repair_build_plan(
        self,
        *,
        job_id: str,
        plan_payload: Mapping[str, Any],
        error: LifecyclePolicyError,
        repair_attempts: list[dict[str, Any]],
        idempotency_key: str | None,
        root_request_id: str | None,
        trace_id: str | None,
    ) -> dict[str, Any]:
        max_attempts = self.runtime.max_build_repair_attempts
        attempt_number = len(repair_attempts) + 1
        if attempt_number > max_attempts:
            exhausted = LifecyclePolicyError(
                build_error_envelope(
                    category="PERMANENT",
                    code="S1_BUILD_AUTO_REPAIR_EXHAUSTED",
                    message=(
                        f"build failed after {max_attempts} repair attempts; last error "
                        f"{error.envelope.category}:{error.envelope.code}: {error.envelope.message}"
                    ),
                )
            )
            self.runtime.store.apply_method(
                job_id,
                "fail",
                trigger="S1 auto-repair",
                payload={
                    "plan_hash": plan_payload.get("plan_hash"),
                    "error": exhausted.envelope.as_c1_payload(),
                    "last_error": error.envelope.as_c1_payload(),
                    "repair": _build_repair_summary(repair_attempts),
                },
                idempotency_key=idempotency_key,
                root_request_id=root_request_id,
                trace_id=trace_id,
            )
            raise exhausted from error

        repair_ctx = self._exec_context(
            job_id,
            allowed_adapters=tuple(str(adapter) for adapter in plan_payload.get("adapters_required", ())),
            allowed_datasets=tuple(str(dataset) for dataset in plan_payload.get("datasets_required", ())),
            root_request_id=root_request_id,
            trace_id=trace_id,
        )
        attempt_payload = _build_repair_attempt_payload(
            job_id=job_id,
            attempt=attempt_number,
            max_attempts=max_attempts,
            plan_payload=plan_payload,
            error=error,
        )
        decision = _call_build_repair_hook(self.runtime.build_repair_hook, repair_ctx, attempt_payload)
        next_plan = _apply_build_repair_decision(plan_payload, decision)
        recorded_attempt = _record_build_repair_attempt(
            artifact_store=self.runtime.artifact_store,
            job_id=job_id,
            attempt_payload=attempt_payload,
            decision=decision,
            next_plan_hash=str(next_plan["plan_hash"]),
            prior_attempt_refs=tuple(str(attempt["provenance_ref"]) for attempt in repair_attempts),
        )
        repair_attempts.append(recorded_attempt)
        return next_plan

    def validate(
        self,
        job_id: str,
        build_result: Mapping[str, Any],
        *,
        profile_ref: str,
        blind_dataset_handle: str,
        budget_token_ref: str,
        validation_client: Any | None = None,
        report_verifier: C3ReportVerifier | None = None,
        idempotency_key: str | None = None,
        root_request_id: str | None = None,
        trace_id: str | None = None,
    ) -> SDKInvocationResult:
        self._assert_can_apply(job_id, "validate")
        payload = _build_validation_handoff_payload(
            job_id=job_id,
            build_result=build_result,
            profile_ref=profile_ref,
            blind_dataset_handle=blind_dataset_handle,
            budget_token_ref=budget_token_ref,
            trace_id=trace_id or f"trace:{job_id}",
            subagent_id=self.descriptor.subagent_id,
            artifact_store=self.runtime.artifact_store,
            validation_client=validation_client,
            report_verifier=report_verifier,
        )
        event = self.runtime.store.apply_method(
            job_id,
            "validate",
            trigger="S3",
            payload={
                "frozen_pipeline_ref": payload["frozen_pipeline_ref"],
                "validation_request_ref": payload["validation_request_ref"],
                "validation_report_ref": payload["validation_report_ref"],
                "claim_tier": payload["subagent_report"]["claim_tier"],
            },
            idempotency_key=idempotency_key,
            root_request_id=root_request_id,
            trace_id=trace_id,
        )
        self.runtime._record_method_span(
            "validate",
            job_id=job_id,
            root_request_id=root_request_id or job_id,
            trace_id=trace_id or f"trace:{job_id}",
            attributes={"state": event.to_state.value},
        )
        return SDKInvocationResult(event=event, payload=payload)

    def report(
        self,
        job_id: str,
        subagent_report: Mapping[str, Any],
        *,
        idempotency_key: str | None = None,
        root_request_id: str | None = None,
        trace_id: str | None = None,
    ) -> SDKInvocationResult:
        self._assert_can_apply(job_id, "report")
        payload = _normalize_report_payload(job_id, subagent_report)
        event = self.runtime.store.apply_method(
            job_id,
            "report",
            trigger="S1",
            payload={
                "artifact_refs": payload["artifact_refs"],
                "validation_report_ref": payload.get("validation_report_ref"),
                "claim_tier": payload["claim_tier"],
                "reproducibility_manifest": payload["reproducibility_manifest"],
            },
            idempotency_key=idempotency_key,
            root_request_id=root_request_id,
            trace_id=trace_id,
        )
        self.runtime._record_method_span(
            "report",
            job_id=job_id,
            root_request_id=root_request_id or job_id,
            trace_id=trace_id or f"trace:{job_id}",
            attributes={"state": event.to_state.value},
        )
        return SDKInvocationResult(event=event, payload=payload)

    def _exec_context(
        self,
        job_id: str,
        *,
        allowed_adapters: tuple[str, ...] = (),
        allowed_datasets: tuple[str, ...] = (),
        root_request_id: str | None = None,
        trace_id: str | None = None,
    ) -> ExecContext:
        return ExecContext(
            job_id=job_id,
            allowed_adapters=allowed_adapters,
            allowed_datasets=allowed_datasets,
            adapter_egress_allowlist=self.runtime.adapter_egress_allowlist,
            store_egress_rule=self.runtime.store_egress_rule,
            artifact_store=self.runtime.artifact_store,
            sandbox_marshaler=self.runtime.sandbox_marshaler,
            adapter_client=self.runtime.adapter_client,
            heartbeat_recorder=self.runtime.record_heartbeat,
            sandbox_result_recorder=self.runtime.register_sandbox_result,
            cancel_checker=self.runtime.cancel_requested,
            trace_id=trace_id,
            root_request_id=root_request_id,
            telemetry_sink=self.runtime.telemetry_sink,
            event_bus=self.runtime.event_bus,
        )

    def _assert_no_direct_exec(
        self,
        job_id: str,
        method: str,
        hook: Any,
        *,
        root_request_id: str | None = None,
        trace_id: str | None = None,
    ) -> None:
        violations = _direct_exec_violations(method, hook)
        if not violations:
            return
        envelope = build_error_envelope(
            category="SANDBOX",
            code="DIRECT_IN_PROCESS_EXEC_FORBIDDEN",
            message=f"{method} hook contains forbidden direct in-process execution: {', '.join(violations)}",
        )
        self.runtime.quarantine(
            job_id,
            error=envelope,
            reason="S1 direct-exec guard",
            root_request_id=root_request_id,
            trace_id=trace_id,
        )
        raise LifecyclePolicyError(envelope)

    def _assert_can_apply(self, job_id: str, method: str) -> None:
        try:
            current = self.runtime.store.current(job_id)
        except KeyError as exc:
            raise LifecyclePolicyError(
                ErrorEnvelope(
                    code="JOB_NOT_FOUND",
                    category="NOT_FOUND",
                    message=f"{method} cannot run before job {job_id} exists",
                )
            ) from exc
        LifecycleStore._assert_legal_transition(current.state, METHOD_TARGETS[method], method)


def default_accept(
    descriptor: SubagentDescriptor,
    envelope: JobEnvelope,
    *,
    idempotency_key: str | None = None,
) -> Acceptance:
    resolved_idempotency_key = idempotency_key or _default_accept_idempotency_key(envelope.job_id)
    if _semver_major(descriptor.contract_version) != _semver_major(envelope.envelope_version):
        return Acceptance(envelope.job_id, False, "VERSION_UNSUPPORTED", LifecycleState.REJECTED, resolved_idempotency_key)
    if envelope.subtopic not in set(descriptor.subtopics):
        return Acceptance(envelope.job_id, False, "OUT_OF_SCOPE", LifecycleState.REJECTED, resolved_idempotency_key)
    descriptor_adapters = set(descriptor.required_adapters)
    allowed_adapters = set(envelope.allowed_adapters)
    for adapter_ref in envelope.required_adapters:
        if adapter_ref not in descriptor_adapters or adapter_ref not in allowed_adapters:
            return Acceptance(envelope.job_id, False, "MISSING_ADAPTER", LifecycleState.REJECTED, resolved_idempotency_key)
    if envelope.verifier_profile_ref is None:
        return Acceptance(envelope.job_id, False, "NO_VERIFIER", LifecycleState.REJECTED, resolved_idempotency_key)
    if envelope.budget_cost and envelope.estimated_cost > envelope.budget_cost:
        return Acceptance(
            envelope.job_id,
            False,
            "BUDGET_TOO_SMALL",
            LifecycleState.REJECTED,
            resolved_idempotency_key,
            estimated_cost=envelope.estimated_cost,
        )
    return Acceptance(
        envelope.job_id,
        True,
        None,
        LifecycleState.ACCEPTED,
        resolved_idempotency_key,
        estimated_cost=envelope.estimated_cost,
    )


def _semver_major(version: str) -> int:
    try:
        return int(version.split(".", 1)[0])
    except (ValueError, IndexError) as exc:
        raise ValueError(f"invalid semver: {version}") from exc


def reduce_lifecycle(events: tuple[LifecycleEvent, ...], *, job_id: str) -> JobCurrent:
    state = LifecycleState.REGISTERED
    sequence = 0
    for event in events:
        if event.job_id != job_id:
            raise LifecyclePolicyError(
                ErrorEnvelope(
                    code="LIFECYCLE_REPLAY_JOB_MISMATCH",
                    category="POLICY",
                    message=f"event for {event.job_id} cannot rebuild {job_id}",
                )
            )
        if event.sequence != sequence + 1:
            raise LifecyclePolicyError(
                ErrorEnvelope(
                    code="LIFECYCLE_REPLAY_SEQUENCE_GAP",
                    category="POLICY",
                    message=f"event sequence {event.sequence} does not follow {sequence}",
                )
            )
        if event.from_state != state:
            raise LifecyclePolicyError(
                ErrorEnvelope(
                    code="LIFECYCLE_REPLAY_STATE_DIVERGED",
                    category="POLICY",
                    message=f"event from_state {event.from_state.value} does not match replay state {state.value}",
                )
            )
        LifecycleStore._assert_legal_transition(state, event.to_state, event.method)
        state = event.to_state
        sequence = event.sequence
    return JobCurrent(job_id=job_id, state=state, last_sequence=sequence)


def _lifecycle_event_ledger_payload(event: LifecycleEvent) -> dict[str, object]:
    return {
        "schema": "argus.s1.lifecycle_event.v1",
        "event_id": event.event_id,
        "job_id": event.job_id,
        "root_request_id": event.root_request_id,
        "sequence": event.sequence,
        "seq": event.sequence,
        "from_state": event.from_state.value,
        "to_state": event.to_state.value,
        "method": event.method,
        "trigger": event.trigger,
        "payload_hash": event.payload_hash,
        "trace_id": event.trace_id,
        "idempotency_key": event.idempotency_key,
    }


def _lifecycle_event_bus_payload(event: LifecycleEvent) -> dict[str, object]:
    payload = _lifecycle_event_ledger_payload(event)
    payload["ledger_ref"] = event.ledger_ref
    return payload


def _event_trace_id(payload: Mapping[str, Any], trace_id: str | None) -> str:
    if trace_id:
        return trace_id
    payload_trace_id = payload.get("trace_id")
    if isinstance(payload_trace_id, str) and payload_trace_id:
        return payload_trace_id
    payload_job_id = payload.get("job_id")
    if isinstance(payload_job_id, str) and payload_job_id:
        return f"trace:{payload_job_id}"
    payload_subagent_id = payload.get("subagent_id")
    if isinstance(payload_subagent_id, str) and payload_subagent_id:
        return f"trace:{payload_subagent_id}"
    return "trace:s1"


def _event_root_request_id(payload: Mapping[str, Any], root_request_id: str | None) -> str:
    if root_request_id:
        return root_request_id
    payload_root_request_id = payload.get("root_request_id")
    if isinstance(payload_root_request_id, str) and payload_root_request_id:
        return payload_root_request_id
    payload_job_id = payload.get("job_id")
    if isinstance(payload_job_id, str) and payload_job_id:
        return payload_job_id
    payload_subagent_id = payload.get("subagent_id")
    if isinstance(payload_subagent_id, str) and payload_subagent_id:
        return payload_subagent_id
    return "s1"


def _derive_s1_bus_event_id(*, subject: str, payload: Mapping[str, Any], index: int) -> str:
    return str(uuid5(NAMESPACE_URL, f"argus:s1:event-bus:{subject}:{index}:{hash_json(payload)}"))


def _derive_s1_span_id(*, trace_id: str, name: str, attributes: Mapping[str, Any], index: int) -> str:
    return str(uuid5(NAMESPACE_URL, f"argus:s1:span:{trace_id}:{name}:{index}:{hash_json(attributes)}"))


def _default_accept_idempotency_key(job_id: str) -> str:
    return f"accept:{job_id}"


def _lifecycle_idempotency_method(method: str) -> str:
    return f"lifecycle.{method}"


def _lifecycle_request_hash(
    *,
    job_id: str,
    method: str,
    to_state: LifecycleState,
    trigger: str,
    payload_hash: str,
) -> str:
    return hash_json(
        {
            "job_id": job_id,
            "method": method,
            "to_state": to_state.value,
            "trigger": trigger,
            "payload_hash": payload_hash,
        }
    )


def _derive_lifecycle_idempotency_key(*, job_id: str, method: str, request_hash: str) -> str:
    return f"{method}:{job_id}:{request_hash}"


def _derive_lifecycle_event_id(*, job_id: str, sequence: int, method: str, request_hash: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"argus:s1:lifecycle:{job_id}:{sequence}:{method}:{request_hash}"))


def _idempotency_response_hash(response: Any) -> str:
    if isinstance(response, Acceptance):
        return hash_json(response.as_c1_payload())
    if isinstance(response, LifecycleEvent):
        payload = _lifecycle_event_ledger_payload(response)
        if response.ledger_ref is not None:
            payload["ledger_ref"] = response.ledger_ref
        return hash_json(payload)
    return hash_json(response)


def _mapping_payload(name: str, value: Mapping[str, Any] | Any) -> dict[str, Any]:
    payload = _json_compatible_payload(value)
    if not isinstance(payload, dict):
        raise TypeError(f"{name} hook must return a mapping payload")
    return payload


def _normalize_plan_payload(envelope: JobEnvelope, value: Mapping[str, Any] | Any) -> dict[str, Any]:
    payload = _mapping_payload("plan", value)
    payload.setdefault("job_id", envelope.job_id)
    if payload["job_id"] != envelope.job_id:
        raise ValueError("plan payload job_id must match the accepted envelope")
    payload.setdefault("adapters_required", list(envelope.required_adapters))
    payload.setdefault("datasets_required", [])
    if envelope.verifier_profile_ref is not None:
        payload.setdefault("verifier_profile_ref", envelope.verifier_profile_ref)
    payload.setdefault("budget_breakdown", {"total": {"cost_usd": envelope.estimated_cost}})
    payload.setdefault("risk_notes", [])
    if "plan_hash" not in payload:
        hash_payload = {key: item for key, item in payload.items() if key != "plan_hash"}
        payload["plan_hash"] = hash_json(hash_payload)
    return payload


def _normalize_build_payload(job_id: str, value: Mapping[str, Any] | Any) -> dict[str, Any]:
    payload = _mapping_payload("build", value)
    payload.setdefault("job_id", job_id)
    if payload["job_id"] != job_id:
        raise ValueError("build payload job_id must match the lifecycle job")
    payload.setdefault("diagnostics", {})
    payload.setdefault("self_checks", [])
    payload["uncertainty_summary"] = _normalize_uncertainty_summary(
        payload.get("uncertainty_summary", no_uncertainty_summary())
    )
    extra = set(payload) - BUILD_RESULT_FIELDS
    self_promotion_fields = extra & BUILD_RESULT_TIER_SELF_PROMOTION_FIELDS
    if self_promotion_fields:
        _raise_policy(
            "S1_BUILD_TIER_SELF_PROMOTION_FORBIDDEN",
            "build payload cannot set tier or validation fields: "
            + ", ".join(sorted(str(field) for field in self_promotion_fields))
            + "; claim_tier comes only from signed C3 reports",
        )
    if extra:
        _raise_policy(
            "S1_BUILD_RESULT_FIELD_UNSUPPORTED",
            "build payload contains unsupported top-level fields: "
            + ", ".join(sorted(str(field) for field in extra)),
        )
    return payload


def _attach_build_repair_diagnostics(
    payload: dict[str, Any],
    repair_attempts: list[dict[str, Any]],
) -> dict[str, Any]:
    if not repair_attempts:
        return payload
    diagnostics = payload.get("diagnostics")
    if isinstance(diagnostics, Mapping):
        normalized_diagnostics = dict(diagnostics)
    else:
        normalized_diagnostics = {"value": diagnostics}
    normalized_diagnostics["repair"] = _build_repair_summary(repair_attempts)
    payload["diagnostics"] = normalized_diagnostics
    return payload


def _build_repair_summary(repair_attempts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "repair_attempts": len(repair_attempts),
        "attempts": [dict(attempt) for attempt in repair_attempts],
        "provenance_refs": [str(attempt["provenance_ref"]) for attempt in repair_attempts],
    }


def _build_repair_attempt_payload(
    *,
    job_id: str,
    attempt: int,
    max_attempts: int,
    plan_payload: Mapping[str, Any],
    error: LifecyclePolicyError,
) -> dict[str, Any]:
    return {
        "schema": "argus.s1.build_repair_attempt.v1",
        "job_id": job_id,
        "attempt": attempt,
        "max_attempts": max_attempts,
        "plan_hash": str(plan_payload.get("plan_hash") or hash_json(plan_payload)),
        "error": error.envelope.as_c1_payload(),
    }


def _call_build_repair_hook(hook: Any, ctx: ExecContext, attempt_payload: Mapping[str, Any]) -> dict[str, Any]:
    try:
        if hasattr(hook, "repair_build"):
            decision = hook.repair_build(ctx, dict(attempt_payload))
        elif callable(hook):
            decision = hook(ctx, dict(attempt_payload))
        else:
            raise TypeError("build_repair_hook must be callable or expose repair_build")
    except LifecyclePolicyError:
        raise
    except Exception as exc:
        raise LifecyclePolicyError(
            build_error_envelope(
                category="PERMANENT",
                code="S1_BUILD_AUTO_REPAIR_HOOK_FAILED",
                message=f"build repair hook failed: {exc}",
            )
        ) from exc
    return _normalize_build_repair_decision(decision)


def _normalize_build_repair_decision(value: Mapping[str, Any] | Any) -> dict[str, Any]:
    payload = _mapping_payload("build repair", value)
    plan_patch_raw = payload.get("plan_patch", {})
    if plan_patch_raw is None:
        plan_patch: dict[str, Any] = {}
    elif isinstance(plan_patch_raw, Mapping):
        plan_patch = dict(plan_patch_raw)
    else:
        raise TypeError("build repair plan_patch must be a mapping")
    diagnostics_raw = payload.get("diagnostics", {})
    if diagnostics_raw is None:
        diagnostics: dict[str, Any] = {}
    elif isinstance(diagnostics_raw, Mapping):
        diagnostics = dict(diagnostics_raw)
    else:
        diagnostics = {"value": diagnostics_raw}
    return {
        "plan_patch": plan_patch,
        "diagnostics": diagnostics,
        "stop": bool(payload.get("stop", False)),
    }


def _apply_build_repair_decision(
    plan_payload: Mapping[str, Any],
    decision: Mapping[str, Any],
) -> dict[str, Any]:
    if decision.get("stop"):
        raise LifecyclePolicyError(
            build_error_envelope(
                category="PERMANENT",
                code="S1_BUILD_AUTO_REPAIR_STOPPED",
                message="build repair hook stopped the bounded repair loop",
            )
        )
    patched_plan = dict(plan_payload)
    patch = decision.get("plan_patch", {})
    if not isinstance(patch, Mapping):
        raise TypeError("normalized build repair plan_patch must be a mapping")
    patched_plan.update(dict(patch))
    patched_plan.pop("plan_hash", None)
    patched_plan["plan_hash"] = hash_json(patched_plan)
    return patched_plan


def _record_build_repair_attempt(
    *,
    artifact_store: InMemoryArtifactStore | None,
    job_id: str,
    attempt_payload: Mapping[str, Any],
    decision: Mapping[str, Any],
    next_plan_hash: str,
    prior_attempt_refs: tuple[str, ...],
) -> dict[str, Any]:
    if artifact_store is None:
        raise LifecyclePolicyError(
            build_error_envelope(
                category="POLICY",
                code="S1_BUILD_AUTO_REPAIR_PROVENANCE_REQUIRED",
                message="bounded build repair requires a C4 artifact store for per-attempt provenance",
            )
        )
    payload = {
        **dict(attempt_payload),
        "decision": {
            "plan_patch_hash": hash_json(decision.get("plan_patch", {})),
            "diagnostics": dict(decision.get("diagnostics", {})),
            "stop": bool(decision.get("stop", False)),
        },
        "next_plan_hash": next_plan_hash,
    }
    record = artifact_store.create_artifact(
        kind=S1_BUILD_REPAIR_ATTEMPT_KIND,
        payload=payload,
        producer=Producer(
            subsystem="S1",
            version="0.0.0",
            actor_id="s1.build-auto-repair",
            job_id=job_id,
        ),
        lineage=Lineage(
            input_refs=prior_attempt_refs[-1:],
            code_ref=S1_BUILD_REPAIR_CODE_REF,
            environment_digest=S1_BUILD_REPAIR_ENVIRONMENT_DIGEST,
            job_id=job_id,
        ),
    )
    return {**payload, "provenance_ref": record.artifact_ref}


def _normalize_report_payload(job_id: str, value: Mapping[str, Any] | Any) -> dict[str, Any]:
    payload = _mapping_payload("report", value)
    payload.setdefault("job_id", job_id)
    if payload["job_id"] != job_id:
        raise ValueError("report payload job_id must match the lifecycle job")
    payload.setdefault("status", LifecycleState.REPORTED.value)
    if payload["status"] != LifecycleState.REPORTED.value:
        _raise_policy("S1_REPORT_STATUS_INVALID", "report payload status must be REPORTED")
    artifact_refs = payload.get("artifact_refs")
    if not isinstance(artifact_refs, list) or not all(isinstance(ref, str) and ref for ref in artifact_refs):
        _raise_policy("S1_REPORT_ARTIFACT_REFS_REQUIRED", "report payload requires non-empty string artifact_refs")
    if not artifact_refs:
        _raise_policy("S1_REPORT_ARTIFACT_REFS_REQUIRED", "report payload requires at least one artifact_ref")
    claim_tier = payload.get("claim_tier")
    if not isinstance(claim_tier, str) or not claim_tier:
        _raise_policy("S1_REPORT_CLAIM_TIER_REQUIRED", "report payload requires claim_tier")
    reproducibility = payload.get("reproducibility_manifest")
    if not isinstance(reproducibility, Mapping):
        _raise_policy("S1_REPORT_REPRODUCIBILITY_REQUIRED", "report payload requires reproducibility_manifest")
    validation_ref = payload.get("validation_report_ref")
    if validation_ref is not None and (not isinstance(validation_ref, str) or not validation_ref):
        _raise_policy("S1_REPORT_VALIDATION_REF_INVALID", "validation_report_ref must be a non-empty string")
    return payload


def _build_validation_handoff_payload(
    *,
    job_id: str,
    build_result: Mapping[str, Any],
    profile_ref: str,
    blind_dataset_handle: str,
    budget_token_ref: str,
    trace_id: str,
    subagent_id: str,
    artifact_store: InMemoryArtifactStore | None,
    validation_client: Any | None,
    report_verifier: C3ReportVerifier | None,
) -> dict[str, Any]:
    if artifact_store is None:
        raise LifecyclePolicyError(
            build_error_envelope(
                category="POLICY",
                code="S1_VALIDATION_ARTIFACT_STORE_REQUIRED",
                message="validate requires a C4 artifact store for frozen-pipeline and S3 report provenance",
            )
        )
    if validation_client is None or not hasattr(validation_client, "validate"):
        raise LifecyclePolicyError(
            build_error_envelope(
                category="VERIFIER_UNAVAILABLE",
                code="S1_VALIDATION_CLIENT_REQUIRED",
                message="validate requires an S3 validation client",
            )
        )
    if report_verifier is None:
        raise LifecyclePolicyError(
            build_error_envelope(
                category="VERIFIER_UNAVAILABLE",
                code="S1_REPORT_VERIFIER_REQUIRED",
                message="validate requires a C3 report verifier for S3 tier relay",
            )
        )
    build_payload = _normalize_build_payload(job_id, build_result)
    artifact_refs = tuple(str(ref) for ref in build_payload.get("artifact_refs", ()))
    if not artifact_refs:
        _raise_policy("S1_VALIDATION_ARTIFACT_REFS_REQUIRED", "validate requires at least one build artifact_ref")
    profile_ref = _non_empty_string(profile_ref, "profile_ref")
    blind_dataset_handle = _non_empty_string(blind_dataset_handle, "blind_dataset_handle")
    budget_token_ref = _non_empty_string(budget_token_ref, "budget_token_ref")
    trace_id = _non_empty_string(trace_id, "trace_id")

    frozen_pipeline_record = artifact_store.create_artifact(
        kind=S1_FROZEN_PIPELINE_KIND,
        payload=_frozen_pipeline_payload(job_id=job_id, build_payload=build_payload, artifact_refs=artifact_refs),
        producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.validate", job_id=job_id),
        lineage=Lineage(
            input_refs=artifact_refs,
            code_ref=S1_VALIDATION_HANDOFF_CODE_REF,
            environment_digest=S1_VALIDATION_HANDOFF_ENVIRONMENT_DIGEST,
            job_id=job_id,
        ),
    )
    validation_request = {
        "job_id": job_id,
        "frozen_pipeline_ref": frozen_pipeline_record.artifact_ref,
        "artifact_refs": list(artifact_refs),
        "profile_ref": profile_ref,
        "blind_dataset_handle": blind_dataset_handle,
        "budget_token_ref": budget_token_ref,
        "trace_id": trace_id,
    }
    validation_request_record = artifact_store.create_artifact(
        kind=S1_VALIDATION_REQUEST_KIND,
        payload=validation_request,
        producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.validate", job_id=job_id),
        lineage=Lineage(
            input_refs=(frozen_pipeline_record.artifact_ref, profile_ref),
            code_ref=S1_VALIDATION_HANDOFF_CODE_REF,
            environment_digest=S1_VALIDATION_HANDOFF_ENVIRONMENT_DIGEST,
            job_id=job_id,
        ),
    )
    validation_report_payload = _call_s3_validation_client(validation_client, validation_request)
    verification = report_verifier.verify(validation_report_payload)
    if not verification.valid:
        raise LifecyclePolicyError(
            build_error_envelope(
                category="VALIDATION",
                code="S1_VALIDATION_REPORT_REJECTED",
                message=f"S3 validation report was rejected: {verification.reason or 'invalid'}",
            )
        )
    from .s3 import S3ReportBuilder

    committed_report = S3ReportBuilder(
        artifact_store=artifact_store,
        producer=Producer(subsystem="S3", version="0.0.0", actor_id="s3.validate"),
        code_ref="argus-core:s3.validate",
        environment_digest="python:s3-validate:v1",
    ).commit_signed_report(
        validation_report_payload,
        input_refs=(validation_request_record.artifact_ref, frozen_pipeline_record.artifact_ref, profile_ref, *artifact_refs),
        job_id=job_id,
    )
    validation_report_payload = committed_report.report
    report_record = committed_report.record
    report = build_subagent_report(
        artifact_refs=artifact_refs,
        validation_report_ref=report_record.artifact_ref,
        validation_report_payload=validation_report_payload,
        report_verifier=report_verifier,
        uncertainty_summary=build_payload["uncertainty_summary"],
    )
    return {
        "job_id": job_id,
        "frozen_pipeline_ref": frozen_pipeline_record.artifact_ref,
        "validation_request_ref": validation_request_record.artifact_ref,
        "validation_request": validation_request,
        "validation_report_ref": report_record.artifact_ref,
        "validation_report_payload": validation_report_payload,
        "subagent_report": _subagent_report_payload(job_id=job_id, subagent_id=subagent_id, report=report),
    }


def _frozen_pipeline_payload(
    *,
    job_id: str,
    build_payload: Mapping[str, Any],
    artifact_refs: tuple[str, ...],
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": "argus.s1.frozen_pipeline.v1",
        "entrypoint": "predict",
        "entrypoint_contract_version": "argus.s3.frozen_pipeline_entrypoint.v1",
        "job_id": job_id,
        "artifact_refs": list(artifact_refs),
        "build_result_hash": hash_json(build_payload),
        "diagnostics_hash": hash_json(build_payload.get("diagnostics", {})),
        "self_checks_hash": hash_json(build_payload.get("self_checks", ())),
        "uncertainty_summary": build_payload["uncertainty_summary"],
        "code_ref": S1_VALIDATION_HANDOFF_CODE_REF,
        "environment_digest": S1_VALIDATION_HANDOFF_ENVIRONMENT_DIGEST,
    }
    training_log_ref = build_payload.get("training_log_ref")
    if training_log_ref is not None:
        payload["training_log_ref"] = str(training_log_ref)
    return payload


def _call_s3_validation_client(validation_client: Any, validation_request: Mapping[str, Any]) -> dict[str, Any]:
    try:
        raw_report = validation_client.validate(dict(validation_request))
    except LifecyclePolicyError:
        raise
    except Exception as exc:
        raise LifecyclePolicyError(
            build_error_envelope(
                category="VALIDATION",
                code="S1_VALIDATION_HANDOFF_FAILED",
                message=f"S3 validation handoff failed: {exc}",
            )
        ) from exc
    report_payload = _json_compatible_payload(raw_report)
    if not isinstance(report_payload, dict):
        raise LifecyclePolicyError(
            build_error_envelope(
                category="VALIDATION",
                code="S1_VALIDATION_REPORT_INVALID",
                message="S3 validation client must return a C3 report mapping",
            )
        )
    return report_payload


def _subagent_report_payload(*, job_id: str, subagent_id: str, report: SubagentReport) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "job_id": job_id,
        "subagent_id": subagent_id,
        "status": LifecycleState.REPORTED.value,
        "claim_tier": report.claim_tier,
        "artifact_refs": list(report.artifact_refs),
        "uncertainty_summary": report.uncertainty_summary,
        "cost_actual": {"cost_usd": 0.0},
        "reproducibility_manifest": {
            "lineage_ref": report.artifact_refs[0],
            "environment_digest": S1_VALIDATION_HANDOFF_ENVIRONMENT_DIGEST,
            "code_ref": S1_VALIDATION_HANDOFF_CODE_REF,
            "seeds": [],
        },
    }
    if report.validation_report_ref is not None:
        payload["validation_report_ref"] = report.validation_report_ref
    return payload


def _non_empty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        _raise_policy("S1_VALIDATION_REQUEST_FIELD_REQUIRED", f"{name} must be a non-empty string")
    return value


def _json_compatible_payload(value: Any) -> Any:
    if is_dataclass(value):
        return _json_compatible_payload(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _json_compatible_payload(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_compatible_payload(item) for item in value]
    if isinstance(value, Enum):
        return value.value
    return value


def build_subagent_report(
    *,
    artifact_refs: tuple[str, ...],
    attempted_claim_tier: str | None = None,
    validation_report_ref: str | None = None,
    validation_report_payload: dict[str, Any] | None = None,
    report_verifier: C3ReportVerifier | None = None,
    uncertainty_summary: Mapping[str, Any] | None = None,
) -> SubagentReport:
    """Build a C1 report whose tier can only come from a signed C3 report."""
    warnings: list[str] = []
    normalized_uncertainty = _normalize_uncertainty_summary(uncertainty_summary or no_uncertainty_summary())
    if validation_report_payload is not None and report_verifier is not None:
        verification = report_verifier.verify(validation_report_payload)
        if verification.valid and verification.claim_tier:
            _assert_uncertainty_for_claim_tier(normalized_uncertainty, verification.claim_tier)
            if verification.claim_tier != "ran-toy" and not validation_report_ref:
                _raise_policy(
                    "S1_VALIDATION_REPORT_REF_REQUIRED",
                    f"claim tier {verification.claim_tier} requires validation_report_ref from the signed C3 report artifact",
                )
            return SubagentReport(
                artifact_refs=artifact_refs,
                validation_report_ref=validation_report_ref,
                claim_tier=verification.claim_tier,
                uncertainty_summary=normalized_uncertainty,
                warnings=(),
            )
        warnings.append("validation_report_rejected")
    if attempted_claim_tier and attempted_claim_tier != "ran-toy":
        warnings.append("self_tier_dropped")
    return SubagentReport(
        artifact_refs=artifact_refs,
        validation_report_ref=None,
        claim_tier="ran-toy",
        uncertainty_summary=normalized_uncertainty,
        warnings=tuple(warnings),
    )
