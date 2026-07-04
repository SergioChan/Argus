"""S1 lifecycle and tier-relay semantics for the subagent runtime."""

from __future__ import annotations

import ast
import inspect
import textwrap
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field, is_dataclass, replace
from enum import Enum
from typing import Any, Mapping, final
from uuid import NAMESPACE_URL, uuid5

from argusverify import C3ReportVerifier
from .hashing import hash_json
from .s10 import EgressRule, LaunchRequest, S10Error, SandboxExecutionResult, SandboxHandle
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
S1_CONTENT_STORE_EGRESS_RULE = EgressRule("store.local", 443, "https")
S1_EGRESS_PROTOCOLS = frozenset({"https", "grpc", "tcp"})


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


EXEC_CONTEXT_CAPABILITIES = (
    "submit_sandbox_job",
    "emit_artifact",
    "call_adapter",
    "read_dataset",
    "log",
    "span",
)
_EXEC_CONTEXT_CAPABILITY_SET = frozenset(EXEC_CONTEXT_CAPABILITIES)


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
        object.__setattr__(self, "_artifact_store", artifact_store or InMemoryArtifactStore())
        object.__setattr__(self, "_sandbox_marshaler", sandbox_marshaler)

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
        return _normalize_sandbox_result(self.job_id, result)

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
        return {
            "capability": "emit_artifact",
            "job_id": self.job_id,
            "artifact_ref": record.artifact_ref,
            "kind": record.kind,
            "content_hash": record.content_hash,
            "claim_tier": record.claim_tier,
            "validation_report_ref": record.validation_report_ref,
        }

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
        return {
            "capability": "call_adapter",
            "job_id": self.job_id,
            "adapter_ref": adapter_ref,
            "request_hash": hash_json(request),
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
        payload = {"name": name, "attributes": dict(attributes or {})}
        return {"capability": "span", "job_id": self.job_id, "span_hash": hash_json(payload)}

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


@dataclass(frozen=True)
class SubagentReport:
    artifact_refs: tuple[str, ...]
    validation_report_ref: str | None
    claim_tier: str
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
        ledger_producer: Producer | None = None,
        ledger_code_ref: str = S1_LIFECYCLE_LEDGER_CODE_REF,
        ledger_environment_digest: str = S1_LIFECYCLE_LEDGER_ENVIRONMENT_DIGEST,
    ) -> None:
        self._events: dict[str, list[LifecycleEvent]] = {}
        self._current: dict[str, JobCurrent] = {}
        self._artifact_store = artifact_store
        self._idempotency_store = idempotency_store or InMemoryIdempotencyStore()
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
        ledger_producer: Producer | None = None,
        ledger_code_ref: str = S1_LIFECYCLE_LEDGER_CODE_REF,
        ledger_environment_digest: str = S1_LIFECYCLE_LEDGER_ENVIRONMENT_DIGEST,
    ) -> "LifecycleStore":
        store = cls(
            artifact_store=artifact_store,
            idempotency_store=idempotency_store,
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
        adapter_egress_allowlist: Mapping[str, Any] | None = None,
        store_egress_rule: EgressRule = S1_CONTENT_STORE_EGRESS_RULE,
    ) -> None:
        self.descriptor = descriptor
        self.idempotency_store = idempotency_store or InMemoryIdempotencyStore()
        self.sandbox_marshaler = sandbox_marshaler
        self.adapter_egress_allowlist = _normalize_adapter_egress_mapping(adapter_egress_allowlist or {})
        _assert_egress_rule_valid(store_egress_rule, "content store")
        self.store_egress_rule = store_egress_rule
        if store is not None:
            if artifact_store is not None:
                raise ValueError("artifact_store cannot be provided with an explicit LifecycleStore")
            self.store = store
            self.artifact_store = store.artifact_store
        else:
            self.artifact_store = artifact_store or InMemoryArtifactStore()
            self.store = LifecycleStore(
                artifact_store=self.artifact_store,
                idempotency_store=self.idempotency_store,
            )
        self.gate_invocations = 0

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
            return existing.response

        self.gate_invocations += 1
        self.store.create_job(envelope.job_id)
        acceptance = default_accept(self.descriptor, envelope, idempotency_key=resolved_idempotency_key)
        self.store.apply_method(
            envelope.job_id,
            "accept" if acceptance.accepted else "refuse",
            trigger="S5",
            idempotency_key=resolved_idempotency_key,
            root_request_id=root_request_id,
            trace_id=trace_id,
        )
        self.idempotency_store.record(
            job_id=envelope.job_id,
            method="accept",
            idempotency_key=resolved_idempotency_key,
            request_hash=request_hash,
            response=acceptance,
        )
        return acceptance


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
        self._assert_no_direct_exec(envelope.job_id, "plan", self.subagent.plan)
        ctx = self._exec_context(envelope.job_id, allowed_adapters=envelope.allowed_adapters)
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
        self._assert_no_direct_exec(job_id, "build", self.subagent.build)
        plan_payload = _mapping_payload("plan", plan)
        ctx = self._exec_context(
            job_id,
            allowed_adapters=tuple(str(adapter) for adapter in plan_payload.get("adapters_required", ())),
            allowed_datasets=tuple(str(dataset) for dataset in plan_payload.get("datasets_required", ())),
        )
        payload = _normalize_build_payload(job_id, self.subagent.build(ctx, plan_payload))
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
        return SDKInvocationResult(event=event, payload=payload)

    def _exec_context(
        self,
        job_id: str,
        *,
        allowed_adapters: tuple[str, ...] = (),
        allowed_datasets: tuple[str, ...] = (),
    ) -> ExecContext:
        return ExecContext(
            job_id=job_id,
            allowed_adapters=allowed_adapters,
            allowed_datasets=allowed_datasets,
            adapter_egress_allowlist=self.runtime.adapter_egress_allowlist,
            store_egress_rule=self.runtime.store_egress_rule,
            artifact_store=self.runtime.artifact_store,
            sandbox_marshaler=self.runtime.sandbox_marshaler,
        )

    def _assert_no_direct_exec(self, job_id: str, method: str, hook: Any) -> None:
        violations = _direct_exec_violations(method, hook)
        if not violations:
            return
        envelope = build_error_envelope(
            category="SANDBOX",
            code="DIRECT_IN_PROCESS_EXEC_FORBIDDEN",
            message=f"{method} hook contains forbidden direct in-process execution: {', '.join(violations)}",
        )
        self.runtime.store.apply_method(
            job_id,
            "quarantine",
            trigger="S1 direct-exec guard",
            payload={"error": envelope.as_c1_payload(), "violations": list(violations)},
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
    payload.setdefault("uncertainty_summary", {"representation": "none", "value": {}})
    return payload


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
) -> SubagentReport:
    """Build a C1 report whose tier can only come from a signed C3 report."""
    warnings: list[str] = []
    if validation_report_payload is not None and report_verifier is not None:
        verification = report_verifier.verify(validation_report_payload)
        if verification.valid and verification.claim_tier:
            return SubagentReport(
                artifact_refs=artifact_refs,
                validation_report_ref=validation_report_ref,
                claim_tier=verification.claim_tier,
                warnings=(),
            )
        warnings.append("validation_report_rejected")
    if attempted_claim_tier and attempted_claim_tier != "ran-toy":
        warnings.append("self_tier_dropped")
    return SubagentReport(
        artifact_refs=artifact_refs,
        validation_report_ref=None,
        claim_tier="ran-toy",
        warnings=tuple(warnings),
    )
