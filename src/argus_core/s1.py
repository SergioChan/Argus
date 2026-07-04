"""S1 lifecycle and tier-relay semantics for the subagent runtime."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Mapping
from uuid import NAMESPACE_URL, uuid5

from argusverify import C3ReportVerifier
from .hashing import hash_json
from .s8 import ArtifactRecord, InMemoryArtifactStore, Lineage, Producer


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


S1_LIFECYCLE_LEDGER_KIND = "s1_lifecycle_event"
S1_LIFECYCLE_LEDGER_CODE_REF = "argus-core:s1.lifecycle-store"
S1_LIFECYCLE_LEDGER_ENVIRONMENT_DIGEST = "python:s1-lifecycle-store:v1"


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
    job_id: str
    accepted: bool
    reason: str | None
    state: LifecycleState
    idempotency_key: str
    estimated_cost: float = 0.0

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
    """Small S1 runtime facade for default accept gate and idempotency."""

    def __init__(
        self,
        *,
        descriptor: SubagentDescriptor,
        store: LifecycleStore | None = None,
        idempotency_store: InMemoryIdempotencyStore | None = None,
    ) -> None:
        self.descriptor = descriptor
        self.idempotency_store = idempotency_store or InMemoryIdempotencyStore()
        self.store = store or LifecycleStore(idempotency_store=self.idempotency_store)
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
