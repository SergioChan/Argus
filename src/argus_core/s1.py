"""S1 lifecycle and tier-relay semantics for the subagent runtime."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from .c3 import C3ReportVerifier
from .hashing import hash_json


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
    QUARANTINED = "QUARANTINED"


TERMINAL_STATES = frozenset(
    {
        LifecycleState.REPORTED,
        LifecycleState.FAILED,
        LifecycleState.REJECTED,
        LifecycleState.QUARANTINED,
    }
)


LEGAL_TRANSITIONS: dict[LifecycleState, frozenset[LifecycleState]] = {
    LifecycleState.REGISTERED: frozenset({LifecycleState.ACCEPTED, LifecycleState.REJECTED}),
    LifecycleState.ACCEPTED: frozenset({LifecycleState.PLANNING, LifecycleState.FAILED, LifecycleState.QUARANTINED}),
    LifecycleState.PLANNING: frozenset({LifecycleState.BUILDING, LifecycleState.FAILED, LifecycleState.QUARANTINED}),
    LifecycleState.BUILDING: frozenset({LifecycleState.VALIDATING, LifecycleState.FAILED, LifecycleState.QUARANTINED}),
    LifecycleState.VALIDATING: frozenset({LifecycleState.REPORTED, LifecycleState.FAILED, LifecycleState.QUARANTINED}),
    LifecycleState.REPORTED: frozenset(),
    LifecycleState.FAILED: frozenset(),
    LifecycleState.REJECTED: frozenset(),
    LifecycleState.QUARANTINED: frozenset(),
}


METHOD_TARGETS = {
    "accept": LifecycleState.ACCEPTED,
    "refuse": LifecycleState.REJECTED,
    "plan": LifecycleState.PLANNING,
    "build": LifecycleState.BUILDING,
    "validate": LifecycleState.VALIDATING,
    "report": LifecycleState.REPORTED,
    "fail": LifecycleState.FAILED,
    "quarantine": LifecycleState.QUARANTINED,
}


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


@dataclass(frozen=True)
class JobCurrent:
    job_id: str
    state: LifecycleState
    last_sequence: int


@dataclass(frozen=True)
class ExecContext:
    job_id: str

    def submit_sandbox_job(self, spec: dict[str, Any]) -> dict[str, Any]:
        return {"submitted": True, "spec_hash": hash_json(spec)}

    def emit_artifact(self, payload: Any, kind: str, lineage_inputs: tuple[str, ...]) -> dict[str, Any]:
        return {"kind": kind, "payload_hash": hash_json(payload), "lineage_inputs": lineage_inputs}

    def call_adapter(self, adapter_ref: str, request: dict[str, Any]) -> dict[str, Any]:
        return {"adapter_ref": adapter_ref, "request_hash": hash_json(request)}

    def read_dataset(self, dataset_ref: str) -> dict[str, str]:
        return {"dataset_ref": dataset_ref}


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
    accepted: bool
    reason: str | None
    state: LifecycleState
    estimated_cost: float = 0.0


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
    """In-memory event-sourced lifecycle store."""

    def __init__(self) -> None:
        self._events: dict[str, list[LifecycleEvent]] = {}
        self._current: dict[str, JobCurrent] = {}

    def create_job(self, job_id: str) -> JobCurrent:
        current = JobCurrent(job_id=job_id, state=LifecycleState.REGISTERED, last_sequence=0)
        self._events.setdefault(job_id, [])
        self._current[job_id] = current
        return current

    def apply_method(self, job_id: str, method: str, *, trigger: str = "", payload: Any | None = None) -> LifecycleEvent:
        if method not in METHOD_TARGETS:
            raise ValueError(f"unknown lifecycle method: {method}")
        return self.transition(job_id, METHOD_TARGETS[method], method=method, trigger=trigger, payload=payload)

    def transition(
        self,
        job_id: str,
        to_state: LifecycleState,
        *,
        method: str,
        trigger: str = "",
        payload: Any | None = None,
    ) -> LifecycleEvent:
        current = self._current.get(job_id)
        if current is None:
            current = self.create_job(job_id)
        self._assert_legal_transition(current.state, to_state, method)
        event = LifecycleEvent(
            job_id=job_id,
            sequence=current.last_sequence + 1,
            from_state=current.state,
            to_state=to_state,
            method=method,
            trigger=trigger,
            payload_hash=hash_json(payload or {}),
        )
        self._events[job_id].append(event)
        self._current[job_id] = JobCurrent(job_id=job_id, state=to_state, last_sequence=event.sequence)
        return event

    def current(self, job_id: str) -> JobCurrent:
        return self._current[job_id]

    def events(self, job_id: str) -> tuple[LifecycleEvent, ...]:
        return tuple(self._events.get(job_id, ()))

    def replay(self, job_id: str) -> JobCurrent:
        return reduce_lifecycle(self.events(job_id), job_id=job_id)

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
    """Small S1 runtime facade for default accept gate and idempotency."""

    def __init__(
        self,
        *,
        descriptor: SubagentDescriptor,
        store: LifecycleStore | None = None,
    ) -> None:
        self.descriptor = descriptor
        self.store = store or LifecycleStore()
        self.gate_invocations = 0
        self._acceptance_cache: dict[str, tuple[str, Acceptance]] = {}

    def accept(self, envelope: JobEnvelope) -> Acceptance:
        request_hash = hash_json(envelope.__dict__)
        cached = self._acceptance_cache.get(envelope.job_id)
        if cached is not None:
            cached_hash, cached_acceptance = cached
            if cached_hash != request_hash:
                raise LifecyclePolicyError(
                    ErrorEnvelope(
                        code="IDEMPOTENCY_CONFLICT",
                        category="POLICY",
                        message="same job_id accepted with a different envelope",
                    )
                )
            return cached_acceptance

        self.gate_invocations += 1
        self.store.create_job(envelope.job_id)
        acceptance = default_accept(self.descriptor, envelope)
        self.store.apply_method(envelope.job_id, "accept" if acceptance.accepted else "refuse")
        self._acceptance_cache[envelope.job_id] = (request_hash, acceptance)
        return acceptance


def default_accept(descriptor: SubagentDescriptor, envelope: JobEnvelope) -> Acceptance:
    if _semver_major(descriptor.contract_version) != _semver_major(envelope.envelope_version):
        return Acceptance(False, "VERSION_UNSUPPORTED", LifecycleState.REJECTED)
    if envelope.subtopic not in set(descriptor.subtopics):
        return Acceptance(False, "OUT_OF_SCOPE", LifecycleState.REJECTED)
    descriptor_adapters = set(descriptor.required_adapters)
    allowed_adapters = set(envelope.allowed_adapters)
    for adapter_ref in envelope.required_adapters:
        if adapter_ref not in descriptor_adapters or adapter_ref not in allowed_adapters:
            return Acceptance(False, "MISSING_ADAPTER", LifecycleState.REJECTED)
    if envelope.verifier_profile_ref is None:
        return Acceptance(False, "NO_VERIFIER", LifecycleState.REJECTED)
    if envelope.budget_cost and envelope.estimated_cost > envelope.budget_cost:
        return Acceptance(False, "BUDGET_TOO_SMALL", LifecycleState.REJECTED, estimated_cost=envelope.estimated_cost)
    return Acceptance(True, None, LifecycleState.ACCEPTED, estimated_cost=envelope.estimated_cost)


def _semver_major(version: str) -> int:
    try:
        return int(version.split(".", 1)[0])
    except (ValueError, IndexError) as exc:
        raise ValueError(f"invalid semver: {version}") from exc


def reduce_lifecycle(events: tuple[LifecycleEvent, ...], *, job_id: str) -> JobCurrent:
    state = LifecycleState.REGISTERED
    sequence = 0
    for event in events:
        LifecycleStore._assert_legal_transition(state, event.to_state, event.method)
        state = event.to_state
        sequence = event.sequence
    return JobCurrent(job_id=job_id, state=state, last_sequence=sequence)


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
