"""S9 human-governance review gate and emission-authorization core semantics."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, replace
from hashlib import sha256
from typing import Any
import hmac

from argusverify import C3ReportVerifier
from .canonical import canonical_json_bytes
from .hashing import hash_json
from .s8 import HashMismatchError, InMemoryArtifactStore


class S9Error(Exception):
    """Base class for S9 governance failures."""


class S9PolicyError(S9Error):
    """Raised when guardrail, novelty, or sign-off policy blocks an action."""


class S9SignatureError(S9Error):
    """Raised when an emission authorization signature is invalid."""


@dataclass(frozen=True)
class GuardrailResult:
    allowed: bool
    hard_block: bool = False
    rule_id: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class SignOff:
    principal_id: str
    role: str
    decision: str
    rationale: str
    step_up_auth: bool = False


@dataclass(frozen=True)
class ReviewTask:
    task_id: str
    state: str
    validation_report_ref: str
    artifact_refs: tuple[str, ...]
    artifact_content_hashes: tuple[str, ...]
    claim_tier: str
    emission_class: str
    idempotency_key: str
    quarantine_reason: str | None = None
    signoffs: tuple[SignOff, ...] = ()
    guardrail_result: GuardrailResult | None = None


@dataclass(frozen=True)
class GovernanceLedgerEntry:
    sequence: int
    event_type: str
    payload: dict[str, Any]
    previous_hash: str
    entry_hash: str


@dataclass(frozen=True)
class LedgerVerification:
    intact: bool
    break_sequence: int | None = None


@dataclass(frozen=True)
class EmissionAuthorization:
    token_id: str
    signer_key_id: str
    emission_class: str
    bound_artifact_content_hashes: tuple[str, ...]
    single_use: bool
    consumed: bool
    signature: str


class GovernanceLedger:
    """Append-only hash-chained S9 governance ledger."""

    def __init__(self) -> None:
        self._entries: list[GovernanceLedgerEntry] = []

    @property
    def entries(self) -> tuple[GovernanceLedgerEntry, ...]:
        return tuple(self._entries)

    def append(self, event_type: str, payload: dict[str, Any]) -> GovernanceLedgerEntry:
        previous_hash = self._entries[-1].entry_hash if self._entries else self._zero_hash()
        sequence = len(self._entries) + 1
        entry_hash = hash_json({"sequence": sequence, "event_type": event_type, "payload": payload, "previous_hash": previous_hash})
        entry = GovernanceLedgerEntry(
            sequence=sequence,
            event_type=event_type,
            payload=deepcopy(payload),
            previous_hash=previous_hash,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        return entry

    def verify(self) -> LedgerVerification:
        previous_hash = self._zero_hash()
        for entry in self._entries:
            expected = hash_json(
                {
                    "sequence": entry.sequence,
                    "event_type": entry.event_type,
                    "payload": entry.payload,
                    "previous_hash": previous_hash,
                }
            )
            if entry.previous_hash != previous_hash or entry.entry_hash != expected:
                return LedgerVerification(intact=False, break_sequence=entry.sequence)
            previous_hash = entry.entry_hash
        return LedgerVerification(intact=True)

    @staticmethod
    def _zero_hash() -> str:
        return "blake3:" + ("0" * 64)


class EmissionAuthorizationMinter:
    """HSM-like signer for single-use S9 emission authorizations."""

    def __init__(self, *, signer_key_id: str, secret: bytes) -> None:
        self._signer_key_id = signer_key_id
        self._secret = secret
        self._consumed: set[str] = set()

    def mint(self, *, task_id: str, emission_class: str, artifact_content_hashes: tuple[str, ...]) -> EmissionAuthorization:
        token_id = "s9-emission-" + hash_json(
            {
                "task_id": task_id,
                "emission_class": emission_class,
                "artifact_content_hashes": tuple(sorted(artifact_content_hashes)),
            }
        )[:16]
        unsigned = {
            "token_id": token_id,
            "signer_key_id": self._signer_key_id,
            "emission_class": emission_class,
            "bound_artifact_content_hashes": tuple(sorted(artifact_content_hashes)),
            "single_use": True,
            "consumed": False,
        }
        return EmissionAuthorization(signature=self._sign(unsigned), **unsigned)

    def verify(self, authorization: EmissionAuthorization) -> bool:
        unsigned = {
            "token_id": authorization.token_id,
            "signer_key_id": authorization.signer_key_id,
            "emission_class": authorization.emission_class,
            "bound_artifact_content_hashes": authorization.bound_artifact_content_hashes,
            "single_use": authorization.single_use,
            "consumed": False,
        }
        return (
            authorization.signer_key_id == self._signer_key_id
            and hmac.compare_digest(authorization.signature, self._sign(unsigned))
            and authorization.token_id not in self._consumed
        )

    def consume(self, authorization: EmissionAuthorization) -> EmissionAuthorization:
        if not self.verify(authorization):
            raise S9SignatureError("invalid or consumed emission authorization")
        self._consumed.add(authorization.token_id)
        return replace(authorization, consumed=True)

    def _sign(self, payload: dict[str, Any]) -> str:
        digest = hmac.new(self._secret, canonical_json_bytes(payload), sha256).hexdigest()
        return "s9-hmac-sha256:" + digest


class S9Governance:
    """In-memory S9 review gate with fail-closed intake and emission checks."""

    _REQUIRED_ROLES = ("domain", "ml", "governance")

    def __init__(
        self,
        *,
        report_verifier: C3ReportVerifier,
        artifact_store: InMemoryArtifactStore,
        emission_minter: EmissionAuthorizationMinter,
        ledger: GovernanceLedger | None = None,
    ) -> None:
        self._report_verifier = report_verifier
        self._artifact_store = artifact_store
        self._emission_minter = emission_minter
        self.ledger = ledger or GovernanceLedger()
        self._tasks_by_id: dict[str, ReviewTask] = {}
        self._tasks_by_idempotency: dict[str, str] = {}
        self._reports_by_task_id: dict[str, dict[str, Any]] = {}

    def create_review_task(
        self,
        *,
        report_payload: dict[str, Any],
        validation_report_ref: str,
        artifact_refs: tuple[str, ...],
        emission_class: str,
        idempotency_key: str,
    ) -> ReviewTask:
        if idempotency_key in self._tasks_by_idempotency:
            return self._tasks_by_id[self._tasks_by_idempotency[idempotency_key]]
        task_id = "s9-task-" + hash_json({"idempotency_key": idempotency_key})[:16]
        guardrail = self.evaluate_guardrail(emission_class=emission_class)
        verification = self._report_verifier.verify(report_payload)
        artifact_hashes: tuple[str, ...] = ()
        state = "QUEUED"
        quarantine_reason = None
        if not verification.valid:
            state = "QUARANTINED"
            quarantine_reason = "SIGNATURE_INVALID"
        elif guardrail.hard_block:
            state = "REFUSED"
            quarantine_reason = guardrail.rule_id
        else:
            try:
                artifact_hashes = tuple(self._artifact_store.get_record(ref).content_hash for ref in artifact_refs)
            except HashMismatchError:
                state = "QUARANTINED"
                quarantine_reason = "HASH_MISMATCH"
        task = ReviewTask(
            task_id=task_id,
            state=state,
            validation_report_ref=validation_report_ref,
            artifact_refs=artifact_refs,
            artifact_content_hashes=artifact_hashes,
            claim_tier=str(report_payload.get("claim_tier", "ran-toy")),
            emission_class=emission_class,
            idempotency_key=idempotency_key,
            quarantine_reason=quarantine_reason,
            guardrail_result=guardrail,
        )
        self._tasks_by_id[task_id] = task
        self._tasks_by_idempotency[idempotency_key] = task_id
        self._reports_by_task_id[task_id] = deepcopy(report_payload)
        self.ledger.append("s9.review.task_created", {"task_id": task_id, "state": state, "reason": quarantine_reason})
        return task

    @staticmethod
    def evaluate_guardrail(*, emission_class: str) -> GuardrailResult:
        if emission_class in {"autonomous-paper-submission", "empirical-validation-claim", "flagship-hpc"}:
            return GuardrailResult(
                allowed=False,
                hard_block=True,
                rule_id="NON_GOAL_EMISSION",
                reason=f"{emission_class} is hard-blocked",
            )
        return GuardrailResult(allowed=True)

    def record_signoff(
        self,
        task_id: str,
        *,
        principal_id: str,
        role: str,
        decision: str,
        rationale: str,
        step_up_auth: bool = False,
    ) -> ReviewTask:
        task = self._tasks_by_id[task_id]
        if task.state not in {"QUEUED", "IN_REVIEW", "APPROVED_FOR_EMISSION"}:
            raise S9PolicyError(f"task cannot be signed off in state {task.state}")
        if any(signoff.principal_id == principal_id for signoff in task.signoffs):
            raise S9PolicyError("distinct-principal sign-off required")
        if role == "governance" and not step_up_auth:
            raise S9PolicyError("governance sign-off requires step-up authentication")
        if decision == "APPROVE":
            self._assert_novelty_gate(task)
        signoff = SignOff(
            principal_id=principal_id,
            role=role,
            decision=decision,
            rationale=rationale,
            step_up_auth=step_up_auth,
        )
        updated = replace(task, state="IN_REVIEW", signoffs=task.signoffs + (signoff,))
        if self._required_roles_satisfied(updated):
            updated = replace(updated, state="APPROVED_FOR_EMISSION")
        self._tasks_by_id[task_id] = updated
        self.ledger.append(
            "s9.review.signoff_recorded",
            {"task_id": task_id, "principal_id": principal_id, "role": role, "decision": decision},
        )
        return updated

    def authorize_emission(self, task_id: str) -> EmissionAuthorization:
        task = self._tasks_by_id[task_id]
        if task.guardrail_result and task.guardrail_result.hard_block:
            raise S9PolicyError("GUARDRAIL_BLOCK")
        if task.state != "APPROVED_FOR_EMISSION":
            raise S9PolicyError(f"task is not approved for emission: {task.state}")
        self._assert_novelty_gate(task)
        authorization = self._emission_minter.mint(
            task_id=task.task_id,
            emission_class=task.emission_class,
            artifact_content_hashes=task.artifact_content_hashes,
        )
        self._tasks_by_id[task_id] = replace(task, state="EMISSION_AUTHORIZED")
        self.ledger.append(
            "s9.emission.authorized",
            {"task_id": task_id, "token_id": authorization.token_id, "emission_class": authorization.emission_class},
        )
        return authorization

    def _required_roles_satisfied(self, task: ReviewTask) -> bool:
        approved_roles = {signoff.role for signoff in task.signoffs if signoff.decision == "APPROVE"}
        return set(self._REQUIRED_ROLES).issubset(approved_roles)

    def _assert_novelty_gate(self, task: ReviewTask) -> None:
        if task.claim_tier != "novel-needs-human":
            return
        report = self._reports_by_task_id[task.task_id]
        statuses = {
            check.get("check"): check.get("status")
            for check in report.get("checks", [])
            if isinstance(check, dict)
        }
        if statuses.get("LEAKAGE") != "PASS":
            raise S9PolicyError("novelty gate requires LEAKAGE PASS")
        if statuses.get("CROSS_CODE") != "PASS":
            raise S9PolicyError("novelty gate requires CROSS_CODE PASS")
