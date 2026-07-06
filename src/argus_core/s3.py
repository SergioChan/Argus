"""S3 verifier, perturbation oracle, and signed report core semantics."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from functools import lru_cache
import json
import math
from pathlib import Path
from typing import Any, Mapping
from uuid import NAMESPACE_URL, uuid4, uuid5

from jsonschema import Draft202012Validator

from argusverify import C3ReportSigner, canonical_c3_json_bytes
from .canonical import canonical_json_bytes
from .hashing import hash_bytes, hash_json
from .s6 import (
    CapabilityDescriptor,
    ContaminationIndex,
    FrozenContaminationSnapshot,
    IndependenceAttestation,
)


class S3Error(Exception):
    """Base class for S3 verifier failures."""


class RefereePolicyError(S3Error):
    """Raised when the S3 referee is not distinct from the proponent."""


class SignerIdentityError(S3Error):
    """Raised when referee metadata does not match the real signer key."""


class ReportCanonicalizationError(S3Error):
    """Raised when a C3 report cannot be canonically serialized for hashing."""

    def __init__(self, *, code: str, message: str, digest: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.digest = digest


class FrozenPipelineEntrypointContractError(S3Error):
    """Raised when an S3 frozen-pipeline entrypoint request violates contract."""

    def __init__(self, *, code: str, message: str, category: str = "POLICY") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.category = category
        self.retryable = False

    def as_c1_payload(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
        }


S3_FROZEN_PIPELINE_ENTRYPOINT_REQUEST_SCHEMA = "argus.s3.frozen_pipeline_entrypoint_request.v1"
S3_REPORT_CANONICALIZATION_SPEC_VERSION = "argus.s3.validation_report.canonical.v1"
S3_REPORT_DIGEST_ALGORITHM = "BLAKE3"
S3_FROZEN_PIPELINE_ALLOWED_KINDS = frozenset({"frozen_pipeline", "container", "pipeline"})
S3_VERIFICATION_REQUEST_ALLOWED_FIELDS = frozenset(
    {
        "request_id",
        "job_id",
        "profile_ref",
        "frozen_pipeline_ref",
        "artifact_refs",
        "blind_dataset_handle",
        "blind_data_handle",
        "budget_token_ref",
        "scope_token_ref",
        "trace_id",
    }
)
S3_FORBIDDEN_LABEL_MATERIAL_FIELDS = frozenset(
    {
        "answers",
        "blind_answers",
        "blind_labels",
        "ground_truth",
        "labels",
        "targets",
        "truth",
    }
)
S3_VERIFIER_PROFILE_SPEC_VERSION = "argus.s3.verifier_profile.v1"
S3_VERIFIER_PROFILE_STATUSES = frozenset({"active", "deprecated", "revoked"})
S3_VERIFIER_PROFILE_CHECKS = frozenset(
    {
        "INJECTION",
        "NULL_CONTROL",
        "CROSS_CODE",
        "PHYSICAL_CONSISTENCY",
        "LEAKAGE",
        "CALIBRATION",
        "PERTURBATION_PAIR",
        "INSENSITIVITY",
    }
)
S3_PROFILE_REF_PREFIX = "c4://profile"
_S3_PROFILE_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


class VerifierProfileRegistryError(S3Error):
    """Raised when an S3 VerifierProfile registry operation fails closed."""

    def __init__(self, *, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class VerifierProfileStatusEvent:
    profile_id: str
    revision: int
    status: str
    reason: str
    actor: str = "s3-profile-registry"


@dataclass(frozen=True)
class VerifierProfileRevision:
    profile_id: str
    revision: int
    profile_ref: str
    subtopic: str
    checks: tuple[str, ...]
    cost_estimate: dict[str, Any]
    spec_json: dict[str, Any]
    spec_hash: str
    status: str = "active"

    @property
    def spec_json_bytes(self) -> bytes:
        return canonical_json_bytes(self.spec_json)

    def to_c3_profile(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "revision": self.revision,
            "subtopic": self.subtopic,
            "checks": list(self.checks),
            "cost_estimate": _profile_json_value(self.cost_estimate, path="cost_estimate"),
        }


class InMemoryVerifierProfileRegistry:
    """Append-only VerifierProfile registry used by S3-T07 tests and local flows."""

    def __init__(self) -> None:
        self._revisions: dict[tuple[str, int], VerifierProfileRevision] = {}
        self._status_events: list[VerifierProfileStatusEvent] = []

    def publish(self, spec: Mapping[str, Any]) -> VerifierProfileRevision:
        draft = _profile_mapping_payload(spec)
        profile_id = _profile_id(draft.get("profile_id"))
        revision = self._next_revision(profile_id)
        revision_payload = _build_verifier_profile_revision(draft, revision=revision, status="active")
        key = (revision_payload.profile_id, revision_payload.revision)
        self._revisions[key] = revision_payload
        self._status_events.append(
            VerifierProfileStatusEvent(
                profile_id=revision_payload.profile_id,
                revision=revision_payload.revision,
                status="active",
                reason="published",
            )
        )
        return revision_payload

    def get(self, *, profile_id: str, revision: int) -> VerifierProfileRevision:
        normalized_id = _profile_id(profile_id)
        if not isinstance(revision, int) or revision < 1:
            _profile_error(code="S3_PROFILE_REVISION_INVALID", message="profile revision must be a positive integer")
        try:
            profile = self._revisions[(normalized_id, revision)]
        except KeyError as exc:
            raise VerifierProfileRegistryError(
                code="S3_PROFILE_NOT_FOUND",
                message=f"VerifierProfile {normalized_id} revision {revision} was not found",
            ) from exc
        return replace(profile, status=self._latest_status(profile_id=normalized_id, revision=revision))

    def get_by_ref(self, profile_ref: str) -> VerifierProfileRevision:
        for profile in self._revisions.values():
            if profile.profile_ref == profile_ref:
                return self.get(profile_id=profile.profile_id, revision=profile.revision)
        raise VerifierProfileRegistryError(
            code="S3_PROFILE_NOT_FOUND",
            message=f"VerifierProfile ref {profile_ref} was not found",
        )

    def latest(self, profile_id: str) -> VerifierProfileRevision:
        normalized_id = _profile_id(profile_id)
        revisions = [revision for pid, revision in self._revisions if pid == normalized_id]
        if not revisions:
            raise VerifierProfileRegistryError(
                code="S3_PROFILE_NOT_FOUND",
                message=f"VerifierProfile {normalized_id} was not found",
            )
        return self.get(profile_id=normalized_id, revision=max(revisions))

    def list_profiles(self, *, subtopic: str | None = None, include_revoked: bool = False) -> tuple[VerifierProfileRevision, ...]:
        profiles = [self.get(profile_id=profile.profile_id, revision=profile.revision) for profile in self._revisions.values()]
        if subtopic is not None:
            profiles = [profile for profile in profiles if profile.subtopic == subtopic]
        if not include_revoked:
            profiles = [profile for profile in profiles if profile.status != "revoked"]
        return tuple(sorted(profiles, key=lambda item: (item.profile_id, item.revision)))

    def deprecate(self, *, profile_id: str, revision: int, reason: str, actor: str = "s3-profile-registry") -> VerifierProfileRevision:
        return self._append_status(profile_id=profile_id, revision=revision, status="deprecated", reason=reason, actor=actor)

    def revoke(self, *, profile_id: str, revision: int, reason: str, actor: str = "s3-profile-registry") -> VerifierProfileRevision:
        return self._append_status(profile_id=profile_id, revision=revision, status="revoked", reason=reason, actor=actor)

    def status_events(self, *, profile_id: str | None = None, revision: int | None = None) -> tuple[VerifierProfileStatusEvent, ...]:
        events = self._status_events
        if profile_id is not None:
            normalized_id = _profile_id(profile_id)
            events = [event for event in events if event.profile_id == normalized_id]
        if revision is not None:
            events = [event for event in events if event.revision == revision]
        return tuple(events)

    def _next_revision(self, profile_id: str) -> int:
        revisions = [revision for pid, revision in self._revisions if pid == profile_id]
        return max(revisions, default=0) + 1

    def _append_status(
        self,
        *,
        profile_id: str,
        revision: int,
        status: str,
        reason: str,
        actor: str,
    ) -> VerifierProfileRevision:
        profile = self.get(profile_id=profile_id, revision=revision)
        if status not in S3_VERIFIER_PROFILE_STATUSES:
            _profile_error(code="S3_PROFILE_STATUS_INVALID", message=f"unsupported profile status: {status}")
        if not isinstance(reason, str) or not reason:
            _profile_error(code="S3_PROFILE_STATUS_REASON_REQUIRED", message="profile status event requires a reason")
        if not isinstance(actor, str) or not actor:
            _profile_error(code="S3_PROFILE_STATUS_ACTOR_REQUIRED", message="profile status event requires an actor")
        self._status_events.append(
            VerifierProfileStatusEvent(
                profile_id=profile.profile_id,
                revision=profile.revision,
                status=status,
                reason=reason,
                actor=actor,
            )
        )
        return self.get(profile_id=profile.profile_id, revision=profile.revision)

    def _latest_status(self, *, profile_id: str, revision: int) -> str:
        for event in reversed(self._status_events):
            if event.profile_id == profile_id and event.revision == revision:
                return event.status
        return "active"


def build_verifier_profile_revision(
    spec: Mapping[str, Any],
    *,
    revision: int,
    status: str = "active",
) -> VerifierProfileRevision:
    """Build a normalized VerifierProfile revision after a registry assigns the revision."""
    return _build_verifier_profile_revision(spec, revision=revision, status=status)


@dataclass(frozen=True)
class CheckResult:
    check: str
    status: str
    metrics: dict[str, Any] | None = None


@dataclass(frozen=True)
class PerturbationResult:
    perturbation_id: str
    kind: str
    verdict: str
    amplitude_linearity: dict[str, float] | None = None
    observed_degradation: dict[str, float] | None = None


@dataclass(frozen=True)
class InsensitivityFlag:
    perturbation_id: str
    reason: str
    severity: str = "fail"


@dataclass(frozen=True)
class CanonicalValidationReport:
    spec_version: str
    hash_algorithm: str
    report: dict[str, Any]
    canonical_bytes: bytes
    digest: str
    signing_payload: dict[str, Any]
    signing_payload_bytes: bytes
    signing_payload_digest: str


@dataclass(frozen=True)
class PerturbationPairOutcome:
    perturbation_pairs: tuple[PerturbationResult, ...]
    insensitivity_flags: tuple[InsensitivityFlag, ...]


def canonicalize_validation_report(report: Mapping[str, Any]) -> CanonicalValidationReport:
    """Validate and canonicalize a C3 ValidationReport for stable BLAKE3 hashing."""
    payload = _validation_report_payload(report)
    _assert_c3_validation_report_schema(payload)
    canonical_bytes = canonical_c3_json_bytes(payload)
    signing_payload = validation_report_signing_payload(payload)
    signing_payload_bytes = canonical_c3_json_bytes(signing_payload)
    return CanonicalValidationReport(
        spec_version=S3_REPORT_CANONICALIZATION_SPEC_VERSION,
        hash_algorithm=S3_REPORT_DIGEST_ALGORITHM,
        report=payload,
        canonical_bytes=canonical_bytes,
        digest=hash_bytes(canonical_bytes),
        signing_payload=signing_payload,
        signing_payload_bytes=signing_payload_bytes,
        signing_payload_digest=hash_bytes(signing_payload_bytes),
    )


def canonical_validation_report_bytes(report: Mapping[str, Any]) -> bytes:
    return canonicalize_validation_report(report).canonical_bytes


def validation_report_digest(report: Mapping[str, Any]) -> str:
    return canonicalize_validation_report(report).digest


def validation_report_signing_payload(report: Mapping[str, Any]) -> dict[str, Any]:
    payload = _validation_report_payload(report)
    _assert_c3_validation_report_schema(payload)
    signature = payload.get("signature")
    if not isinstance(signature, Mapping):
        _report_error(
            code="S3_REPORT_SCHEMA_INVALID",
            message="ValidationReport signature must be an object",
        )
    signing_payload = _validation_report_payload(payload)
    signing_payload["signature"] = {
        "algorithm": signature.get("algorithm"),
        "key_id": signature.get("key_id"),
        "value": "",
    }
    return signing_payload


def build_frozen_pipeline_entrypoint_request(
    validation_request: Mapping[str, Any],
    *,
    artifact_store: Any,
) -> dict[str, Any]:
    """Build a deterministic S3 request for invoking a C4 frozen pipeline."""
    request_payload = _mapping_payload("validation_request", validation_request)
    _assert_no_label_material(request_payload, code="S3_VERIFICATION_REQUEST_LABEL_MATERIAL_FORBIDDEN")
    _assert_supported_request_fields(request_payload)

    frozen_pipeline_ref = _c4_ref(
        request_payload.get("frozen_pipeline_ref"),
        field_name="frozen_pipeline_ref",
        code="S3_FROZEN_PIPELINE_REF_INVALID",
    )
    profile_ref = _c4_ref(
        request_payload.get("profile_ref"),
        field_name="profile_ref",
        code="S3_VERIFIER_PROFILE_REF_INVALID",
    )
    job_id = _non_empty_string(request_payload.get("job_id"), "job_id", code="S3_VERIFICATION_REQUEST_FIELD_REQUIRED")
    blind_data_handle = _blind_data_handle(request_payload)
    budget_token_ref = _optional_non_empty_string(request_payload.get("budget_token_ref"), "budget_token_ref")
    scope_token_ref = _optional_non_empty_string(request_payload.get("scope_token_ref"), "scope_token_ref")
    trace_id = _optional_non_empty_string(request_payload.get("trace_id"), "trace_id")
    artifact_refs = _artifact_refs(request_payload.get("artifact_refs"))

    record = _frozen_pipeline_record(artifact_store, frozen_pipeline_ref)
    pipeline_payload = _frozen_pipeline_payload(artifact_store, frozen_pipeline_ref)
    _assert_no_label_material(pipeline_payload, code="S3_FROZEN_PIPELINE_LABEL_MATERIAL_FORBIDDEN")
    _assert_frozen_pipeline_record(record)
    entrypoint = _entrypoint_contract(record=record, payload=pipeline_payload)
    merged_artifact_refs = _merge_artifact_refs(artifact_refs, _artifact_refs(pipeline_payload.get("artifact_refs")))

    verification_request = {
        "request_id": _request_id(request_payload, job_id, profile_ref, frozen_pipeline_ref, blind_data_handle),
        "job_id": job_id,
        "profile_ref": profile_ref,
        "frozen_pipeline_ref": frozen_pipeline_ref,
        "blind_data_handle": blind_data_handle,
    }
    if budget_token_ref is not None:
        verification_request["budget_token_ref"] = budget_token_ref
    if scope_token_ref is not None:
        verification_request["scope_token_ref"] = scope_token_ref

    entrypoint_request = {
        "schema": S3_FROZEN_PIPELINE_ENTRYPOINT_REQUEST_SCHEMA,
        "verification_request": verification_request,
        "entrypoint": entrypoint,
        "artifact_refs": list(merged_artifact_refs),
    }
    if trace_id is not None:
        entrypoint_request["trace_id"] = trace_id
    return entrypoint_request


class S3Verifier:
    """Minimal non-gameable S3 referee that emits signed C3 reports."""

    def __init__(self, *, verifier_id: str, signer_key_id: str, signer: C3ReportSigner) -> None:
        if signer_key_id != signer.key_id:
            raise SignerIdentityError("referee signed_by must match the C3 signer key_id")
        self.verifier_id = verifier_id
        self.signer_key_id = signer.key_id
        self.signer = signer

    def build_report(
        self,
        *,
        profile_ref: str,
        frozen_pipeline_ref: str,
        checks: tuple[CheckResult, ...],
        proponent_id: str,
        perturbation_outcome: PerturbationPairOutcome | None = None,
        challenger_ids: tuple[str, ...] = (),
        independence_attestation: IndependenceAttestation | None = None,
        debate_ref: str = "c4://debate/not-run",
    ) -> dict[str, Any]:
        referee = build_referee_block(
            referee_id=self.verifier_id,
            signer_key_id=self.signer_key_id,
            proponent_id=proponent_id,
        )
        perturbation_outcome = perturbation_outcome or PerturbationPairOutcome((), ())
        independence_attestation = independence_attestation or _default_independence_attestation(challenger_ids)
        aggregate_passed = _aggregate_passed(checks, perturbation_outcome)
        base_claim_tier = tier_from_checks(checks) if aggregate_passed else "ran-toy"
        claim_tier = _tier_after_independence_gate(base_claim_tier, independence_attestation)
        report = {
            "report_id": str(uuid4()),
            "profile_ref": profile_ref,
            "frozen_pipeline_ref": frozen_pipeline_ref,
            "checks": [_check_to_contract(check) for check in checks],
            "aggregate": {
                "passed": aggregate_passed,
                "score": _aggregate_score(checks),
            },
            "claim_tier": claim_tier,
            "claim_tier_is_candidate": claim_tier == "novel-needs-human",
            "perturbation_pairs": [_dataclass_contract(pair) for pair in perturbation_outcome.perturbation_pairs],
            "insensitivity_flags": [_dataclass_contract(flag) for flag in perturbation_outcome.insensitivity_flags],
            "challenger_panel": {
                "challenger_ids": list(challenger_ids),
                "min_required": len(challenger_ids) if challenger_ids else 1,
            },
            "independence_attestation_debate": {
                "min_independent_challengers": independence_attestation.min_independent,
                "lineage_disjoint": independence_attestation.lineage_disjoint,
                "correlation_warning": independence_attestation.correlation_warning,
            },
            "referee": referee,
            "debate_ref": debate_ref,
        }
        return self.signer.sign(report)


def run_perturbation_pair(
    *,
    perturbation_id: str,
    must_react_expected: float,
    must_react_observed: float,
    must_not_react_observed: float,
    unperturbed_headline: float,
    perturbed_headline: float,
    relative_tolerance: float = 0.1,
    null_abs_tolerance: float = 0.05,
    sensitivity_floor: float = 0.05,
) -> PerturbationPairOutcome:
    must_react_error = abs(must_react_observed - must_react_expected)
    allowed_error = max(abs(must_react_expected) * relative_tolerance, sensitivity_floor)
    must_react_pass = must_react_error <= allowed_error
    must_not_react_pass = abs(must_not_react_observed) <= null_abs_tolerance

    flags: list[InsensitivityFlag] = []
    if abs(unperturbed_headline) > sensitivity_floor and abs(unperturbed_headline - perturbed_headline) <= sensitivity_floor:
        flags.append(
            InsensitivityFlag(
                perturbation_id=perturbation_id,
                reason="headline_result_invariant_under_should-react_perturbation",
            )
        )

    return PerturbationPairOutcome(
        perturbation_pairs=(
            PerturbationResult(
                perturbation_id=perturbation_id,
                kind="must_react",
                verdict="pass" if must_react_pass else "fail",
                amplitude_linearity={
                    "expected": must_react_expected,
                    "observed": must_react_observed,
                    "absolute_error": must_react_error,
                },
            ),
            PerturbationResult(
                perturbation_id=perturbation_id,
                kind="must_not_react",
                verdict="pass" if must_not_react_pass else "fail",
                observed_degradation={
                    "observed_signal": must_not_react_observed,
                    "absolute_tolerance": null_abs_tolerance,
                },
            ),
        ),
        insensitivity_flags=tuple(flags),
    )


def build_referee_block(*, referee_id: str, signer_key_id: str, proponent_id: str) -> dict[str, Any]:
    if referee_id == proponent_id:
        raise RefereePolicyError("referee must be distinct from proponent")
    return {
        "referee_id": referee_id,
        "non_gameable": True,
        "signed_by": signer_key_id,
        "distinct_from_proponent": True,
    }


def _build_verifier_profile_revision(
    spec: Mapping[str, Any],
    *,
    revision: int,
    status: str,
) -> VerifierProfileRevision:
    normalized = _normalized_verifier_profile_spec(spec, revision=revision)
    profile = VerifierProfileRevision(
        profile_id=str(normalized["profile_id"]),
        revision=int(normalized["revision"]),
        profile_ref=str(normalized["profile_ref"]),
        subtopic=str(normalized["subtopic"]),
        checks=tuple(str(check) for check in normalized["checks"]),
        cost_estimate=dict(normalized["cost_estimate"]),
        spec_json=normalized,
        spec_hash=hash_bytes(canonical_json_bytes(normalized)),
        status=status,
    )
    _assert_c3_verifier_profile_schema(profile.to_c3_profile())
    return profile


def _normalized_verifier_profile_spec(spec: Mapping[str, Any], *, revision: int) -> dict[str, Any]:
    if not isinstance(revision, int) or revision < 1:
        _profile_error(code="S3_PROFILE_REVISION_INVALID", message="profile revision must be a positive integer")
    payload = _profile_mapping_payload(spec)
    profile_id = _profile_id(payload.get("profile_id"))
    subtopic = _profile_non_empty_string(payload.get("subtopic"), field_name="subtopic")
    checks = _profile_checks(payload.get("checks"))
    cost_estimate = _profile_mapping_payload(payload.get("cost_estimate"), field_name="cost_estimate")
    review_signatures = _review_signatures(payload.get("review_signatures"))

    if "revision" in payload and payload["revision"] != revision:
        _profile_error(
            code="S3_PROFILE_REVISION_MISMATCH",
            message="profile revision is assigned by the append-only registry",
        )
    profile_ref = f"{S3_PROFILE_REF_PREFIX}/{profile_id}/r{revision}"
    if "profile_ref" in payload and payload["profile_ref"] != profile_ref:
        _profile_error(
            code="S3_PROFILE_REF_MISMATCH",
            message="profile_ref must match the registry-assigned revision",
        )
    if "status" in payload:
        _profile_error(
            code="S3_PROFILE_STATUS_FIELD_FORBIDDEN",
            message="profile status is append-only registry metadata, not mutable spec_json",
        )

    normalized = dict(payload)
    normalized["schema"] = str(normalized.get("schema") or S3_VERIFIER_PROFILE_SPEC_VERSION)
    normalized["profile_id"] = profile_id
    normalized["revision"] = revision
    normalized["profile_ref"] = profile_ref
    normalized["subtopic"] = subtopic
    normalized["checks"] = list(checks)
    normalized["cost_estimate"] = cost_estimate
    normalized["review_signatures"] = review_signatures
    canonical_json_bytes(normalized)
    return normalized


def _profile_mapping_payload(value: Mapping[str, Any] | Any, *, field_name: str = "VerifierProfile") -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _profile_error(code="S3_PROFILE_JSON_INVALID", message=f"{field_name} must be a JSON object")
    payload = _profile_json_value(value, path=field_name)
    if not isinstance(payload, dict):
        _profile_error(code="S3_PROFILE_JSON_INVALID", message=f"{field_name} must be a JSON object")
    return payload


def _profile_json_value(value: Any, *, path: str) -> Any:
    if isinstance(value, Mapping):
        payload: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                _profile_error(code="S3_PROFILE_JSON_INVALID", message=f"{path} contains a non-string key")
            payload[key] = _profile_json_value(item, path=f"{path}.{key}")
        return payload
    if isinstance(value, list):
        return [_profile_json_value(item, path=f"{path}[]") for item in value]
    if isinstance(value, tuple):
        _profile_error(code="S3_PROFILE_JSON_INVALID", message=f"{path} contains a tuple; use JSON arrays")
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            _profile_error(code="S3_PROFILE_JSON_INVALID", message=f"{path} contains a non-finite number")
        return value
    _profile_error(
        code="S3_PROFILE_JSON_INVALID",
        message=f"{path} contains non-JSON value of type {type(value).__name__}",
    )


def _profile_id(value: Any) -> str:
    profile_id = _profile_non_empty_string(value, field_name="profile_id")
    if any(char not in _S3_PROFILE_ID_CHARS for char in profile_id):
        _profile_error(
            code="S3_PROFILE_ID_INVALID",
            message="profile_id may contain only letters, digits, dot, underscore, and hyphen",
        )
    return profile_id


def _profile_non_empty_string(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        _profile_error(code="S3_PROFILE_FIELD_REQUIRED", message=f"{field_name} must be a non-empty string")
    return value


def _profile_checks(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        _profile_error(code="S3_PROFILE_CHECKS_INVALID", message="checks must be a non-empty JSON array")
    checks: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            _profile_error(code="S3_PROFILE_CHECKS_INVALID", message="checks must contain non-empty strings")
        if item not in S3_VERIFIER_PROFILE_CHECKS:
            _profile_error(code="S3_PROFILE_CHECK_UNSUPPORTED", message=f"unsupported S3 check: {item}")
        if item in checks:
            _profile_error(code="S3_PROFILE_CHECKS_INVALID", message=f"duplicate S3 check: {item}")
        checks.append(item)
    return tuple(checks)


def _review_signatures(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        _profile_error(
            code="S3_PROFILE_REVIEW_SIGNATURE_REQUIRED",
            message="profile publication requires at least one review signature envelope",
        )
    signatures: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        payload = _profile_mapping_payload(item, field_name=f"review_signatures[{index}]")
        _profile_non_empty_string(payload.get("reviewer_id"), field_name=f"review_signatures[{index}].reviewer_id")
        _profile_non_empty_string(payload.get("signature"), field_name=f"review_signatures[{index}].signature")
        signatures.append(payload)
    return signatures


def _assert_c3_verifier_profile_schema(profile: Mapping[str, Any]) -> None:
    errors = sorted(
        _c3_verifier_profile_validator().iter_errors(profile),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    if errors:
        first = errors[0]
        path = ".".join(str(part) for part in first.absolute_path) or "$"
        _profile_error(
            code="S3_PROFILE_SCHEMA_INVALID",
            message=f"VerifierProfile schema violation at {path}: {first.message}",
        )


@lru_cache(maxsize=1)
def _c3_verifier_profile_validator() -> Draft202012Validator:
    schema_path = Path(__file__).resolve().parents[2] / "schemas" / "contracts" / "c3.validation-report.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    verifier_profile = dict(schema["$defs"]["VerifierProfile"])
    verifier_profile["$schema"] = schema["$schema"]
    verifier_profile["$defs"] = schema["$defs"]
    Draft202012Validator.check_schema(verifier_profile)
    return Draft202012Validator(verifier_profile)


def _profile_error(*, code: str, message: str) -> None:
    raise VerifierProfileRegistryError(code=code, message=message)


def _validation_report_payload(value: Mapping[str, Any] | Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _report_error(
            code="S3_REPORT_JSON_INVALID",
            message="ValidationReport must be a JSON object",
        )
    payload = _strict_report_json_value(value, path="ValidationReport")
    if not isinstance(payload, dict):
        _report_error(
            code="S3_REPORT_JSON_INVALID",
            message="ValidationReport must be a JSON object",
        )
    return payload


def _strict_report_json_value(value: Any, *, path: str) -> Any:
    if isinstance(value, Mapping):
        payload: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                _report_error(
                    code="S3_REPORT_JSON_INVALID",
                    message=f"{path} contains a non-string key",
                )
            payload[key] = _strict_report_json_value(item, path=f"{path}.{key}")
        return payload
    if isinstance(value, list):
        return [_strict_report_json_value(item, path=f"{path}[]") for item in value]
    if isinstance(value, tuple):
        _report_error(
            code="S3_REPORT_JSON_INVALID",
            message=f"{path} contains a tuple; ValidationReport arrays must be JSON lists",
        )
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            _report_error(
                code="S3_REPORT_JSON_INVALID",
                message=f"{path} contains a non-finite number",
            )
        return value
    _report_error(
        code="S3_REPORT_JSON_INVALID",
        message=f"{path} contains non-JSON value of type {type(value).__name__}",
    )


def _assert_c3_validation_report_schema(report: Mapping[str, Any]) -> None:
    errors = sorted(
        _c3_validation_report_validator().iter_errors(report),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    if errors:
        first = errors[0]
        path = ".".join(str(part) for part in first.absolute_path) or "$"
        _report_error(
            code="S3_REPORT_SCHEMA_INVALID",
            message=f"ValidationReport schema violation at {path}: {first.message}",
        )


@lru_cache(maxsize=1)
def _c3_validation_report_validator() -> Draft202012Validator:
    schema_path = Path(__file__).resolve().parents[2] / "schemas" / "contracts" / "c3.validation-report.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validation_report = dict(schema["$defs"]["ValidationReport"])
    validation_report["$schema"] = schema["$schema"]
    validation_report["$defs"] = schema["$defs"]
    Draft202012Validator.check_schema(validation_report)
    return Draft202012Validator(validation_report)


def _report_error(*, code: str, message: str) -> None:
    raise ReportCanonicalizationError(code=code, message=message)


def _mapping_payload(name: str, value: Mapping[str, Any] | Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _contract_error(
            code="S3_VERIFICATION_REQUEST_INVALID",
            message=f"{name} must be a mapping",
        )
    return {str(key): _json_safe_value(item) for key, item in value.items()}


def _json_safe_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_safe_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_safe_value(item) for item in value]
    if isinstance(value, list):
        return [_json_safe_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    _contract_error(
        code="S3_VERIFICATION_REQUEST_JSON_INVALID",
        message=f"verification request contains non-JSON value of type {type(value).__name__}",
    )


def _assert_supported_request_fields(payload: Mapping[str, Any]) -> None:
    unknown = sorted(set(payload) - S3_VERIFICATION_REQUEST_ALLOWED_FIELDS)
    if unknown:
        _contract_error(
            code="S3_VERIFICATION_REQUEST_FIELD_UNSUPPORTED",
            message="verification request contains unsupported fields: " + ", ".join(unknown),
        )


def _assert_no_label_material(value: Any, *, code: str) -> None:
    def walk(item: Any) -> bool:
        if isinstance(item, Mapping):
            for key, child in item.items():
                if str(key) in S3_FORBIDDEN_LABEL_MATERIAL_FIELDS:
                    return True
                if walk(child):
                    return True
        elif isinstance(item, list):
            return any(walk(child) for child in item)
        return False

    if walk(value):
        _contract_error(
            code=code,
            message="verification request contains forbidden raw label or answer material",
        )


def _c4_ref(value: Any, *, field_name: str, code: str) -> str:
    text = _non_empty_string(value, field_name, code=code)
    if not text.startswith("c4://"):
        _contract_error(code=code, message=f"{field_name} must be a C4 artifact ref")
    return text


def _non_empty_string(value: Any, field_name: str, *, code: str) -> str:
    if not isinstance(value, str) or not value:
        _contract_error(code=code, message=f"{field_name} must be a non-empty string")
    return value


def _optional_non_empty_string(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    return _non_empty_string(value, field_name, code="S3_VERIFICATION_REQUEST_FIELD_REQUIRED")


def _blind_data_handle(payload: Mapping[str, Any]) -> str:
    c1_handle = payload.get("blind_dataset_handle")
    c3_handle = payload.get("blind_data_handle")
    if c1_handle is not None and c3_handle is not None and c1_handle != c3_handle:
        _contract_error(
            code="S3_BLIND_DATA_HANDLE_CONFLICT",
            message="blind_dataset_handle and blind_data_handle must match when both are provided",
        )
    value = c3_handle if c3_handle is not None else c1_handle
    return _non_empty_string(value, "blind_data_handle", code="S3_VERIFICATION_REQUEST_FIELD_REQUIRED")


def _artifact_refs(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list | tuple):
        _contract_error(
            code="S3_ARTIFACT_REFS_INVALID",
            message="artifact_refs must be a list of C4 artifact refs",
        )
    refs: list[str] = []
    for item in value:
        refs.append(_c4_ref(item, field_name="artifact_refs", code="S3_ARTIFACT_REFS_INVALID"))
    return tuple(dict.fromkeys(refs))


def _merge_artifact_refs(left: tuple[str, ...], right: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(left + right))


def _frozen_pipeline_record(artifact_store: Any, frozen_pipeline_ref: str) -> Any:
    if artifact_store is None or not hasattr(artifact_store, "get_artifact_record"):
        _contract_error(
            code="S3_ARTIFACT_STORE_REQUIRED",
            message="artifact_store with get_artifact_record is required",
        )
    try:
        return artifact_store.get_artifact_record(frozen_pipeline_ref)
    except KeyError as exc:
        raise FrozenPipelineEntrypointContractError(
            code="S3_FROZEN_PIPELINE_REF_NOT_FOUND",
            message="frozen_pipeline_ref is not present in the C4 artifact store",
        ) from exc


def _frozen_pipeline_payload(artifact_store: Any, frozen_pipeline_ref: str) -> dict[str, Any]:
    if artifact_store is None or not hasattr(artifact_store, "get_artifact"):
        _contract_error(
            code="S3_ARTIFACT_STORE_REQUIRED",
            message="artifact_store with get_artifact is required",
        )
    try:
        raw = artifact_store.get_artifact(frozen_pipeline_ref)
    except KeyError as exc:
        raise FrozenPipelineEntrypointContractError(
            code="S3_FROZEN_PIPELINE_REF_NOT_FOUND",
            message="frozen_pipeline_ref payload is not present in the C4 artifact store",
        ) from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FrozenPipelineEntrypointContractError(
            code="S3_FROZEN_PIPELINE_PAYLOAD_INVALID",
            message="frozen pipeline payload must be canonical JSON object bytes",
        ) from exc
    if not isinstance(payload, dict):
        _contract_error(
            code="S3_FROZEN_PIPELINE_PAYLOAD_INVALID",
            message="frozen pipeline payload must be a JSON object",
        )
    return payload


def _assert_frozen_pipeline_record(record: Any) -> None:
    kind = getattr(record, "kind", None)
    if kind not in S3_FROZEN_PIPELINE_ALLOWED_KINDS:
        _contract_error(
            code="S3_FROZEN_PIPELINE_RECORD_KIND_INVALID",
            message="frozen_pipeline_ref must point to a C4 frozen pipeline, container, or pipeline record",
        )


def _entrypoint_contract(*, record: Any, payload: Mapping[str, Any]) -> dict[str, Any]:
    raw_entrypoint = payload.get("entrypoint")
    method = _predict_method(raw_entrypoint)
    if payload.get("self_replay_passed") is False:
        _contract_error(
            code="S3_FROZEN_PIPELINE_SELF_REPLAY_FAILED",
            message="frozen pipeline self-replay must not be failed",
        )
    code_ref = _payload_or_lineage_field(payload, record, "code_ref")
    environment_digest = _payload_or_lineage_field(payload, record, "environment_digest")
    entrypoint = {
        "method": method,
        "entrypoint_ref": raw_entrypoint,
        "frozen_pipeline_ref": getattr(record, "artifact_ref"),
        "record_kind": getattr(record, "kind"),
        "content_hash": getattr(record, "content_hash"),
        "code_ref": code_ref,
        "environment_digest": environment_digest,
    }
    model_ref = payload.get("model_ref")
    if isinstance(model_ref, str) and model_ref:
        entrypoint["model_ref"] = model_ref
    io_signature = payload.get("io_signature")
    if isinstance(io_signature, Mapping):
        entrypoint["io_signature"] = _json_safe_value(io_signature)
    return entrypoint


def _predict_method(entrypoint: Any) -> str:
    if not isinstance(entrypoint, str) or not entrypoint:
        _contract_error(
            code="S3_FROZEN_PIPELINE_ENTRYPOINT_INVALID",
            message="frozen pipeline entrypoint must be a non-empty predict entrypoint",
        )
    if entrypoint == "predict" or entrypoint.endswith(".predict") or entrypoint.endswith(":predict"):
        return "predict"
    _contract_error(
        code="S3_FROZEN_PIPELINE_ENTRYPOINT_INVALID",
        message="frozen pipeline entrypoint must resolve to predict",
    )


def _payload_or_lineage_field(payload: Mapping[str, Any], record: Any, field_name: str) -> str:
    value = payload.get(field_name)
    if isinstance(value, str) and value:
        return value
    lineage = getattr(record, "lineage", None)
    lineage_value = getattr(lineage, field_name, None)
    if isinstance(lineage_value, str) and lineage_value:
        return lineage_value
    _contract_error(
        code="S3_FROZEN_PIPELINE_LINEAGE_FIELD_REQUIRED",
        message=f"frozen pipeline record requires lineage.{field_name}",
    )


def _request_id(
    payload: Mapping[str, Any],
    job_id: str,
    profile_ref: str,
    frozen_pipeline_ref: str,
    blind_data_handle: str,
) -> str:
    existing = payload.get("request_id")
    if existing is not None:
        return _non_empty_string(existing, "request_id", code="S3_VERIFICATION_REQUEST_FIELD_REQUIRED")
    request_hash = hash_json(
        {
            "job_id": job_id,
            "profile_ref": profile_ref,
            "frozen_pipeline_ref": frozen_pipeline_ref,
            "blind_data_handle": blind_data_handle,
        }
    )
    return str(uuid5(NAMESPACE_URL, f"argus:s3:frozen-pipeline-entrypoint:{request_hash}"))


def _contract_error(*, code: str, message: str, category: str = "POLICY") -> None:
    raise FrozenPipelineEntrypointContractError(code=code, message=message, category=category)


def run_leakage_check(
    *,
    contamination_index: ContaminationIndex,
    snapshot: FrozenContaminationSnapshot,
    candidate_text: str,
    threshold: float,
) -> CheckResult:
    result = contamination_index.query(snapshot=snapshot, text=candidate_text, threshold=threshold)
    return CheckResult(
        check="LEAKAGE",
        status="FAIL" if result.leakage else "PASS",
        metrics={
            "snapshot_ref": result.snapshot_ref,
            "max_overlap": result.max_overlap,
            "matched_doc_id": result.matched_doc_id,
            "threshold": threshold,
        },
    )


def run_calibration_check(*, nominal_coverage: float, empirical_coverage: float, tolerance: float) -> CheckResult:
    error = abs(empirical_coverage - nominal_coverage)
    return CheckResult(
        check="CALIBRATION",
        status="PASS" if error <= tolerance else "FAIL",
        metrics={
            "nominal_coverage": nominal_coverage,
            "empirical_coverage": empirical_coverage,
            "absolute_error": error,
            "tolerance": tolerance,
        },
    )


def run_cross_code_check(
    *,
    observed: tuple[float, ...],
    independent: tuple[float, ...],
    combined_uncertainty: tuple[float, ...],
    extrapolation_flags: tuple[bool, ...] = (),
    z_max: float = 3.0,
) -> CheckResult:
    if len(observed) != len(independent) or len(observed) != len(combined_uncertainty):
        raise ValueError("observed, independent, and combined_uncertainty lengths must match")
    if any(uncertainty <= 0 for uncertainty in combined_uncertainty):
        raise ValueError("combined_uncertainty values must be positive")
    flags = extrapolation_flags or tuple(False for _ in observed)
    if len(flags) != len(observed):
        raise ValueError("extrapolation_flags length must match observed")
    if any(flags):
        return CheckResult(
            check="CROSS_CODE",
            status="INCONCLUSIVE",
            metrics={"excluded_fraction": sum(1 for flag in flags if flag) / len(flags)},
        )
    z_scores = tuple(
        abs(left - right) / uncertainty
        for left, right, uncertainty in zip(observed, independent, combined_uncertainty)
    )
    max_z = max(z_scores) if z_scores else 0.0
    return CheckResult(
        check="CROSS_CODE",
        status="PASS" if max_z <= z_max else "FAIL",
        metrics={"max_z": max_z, "z_max": z_max},
    )


def attest_challenger_independence(
    *,
    challengers: tuple[CapabilityDescriptor, ...],
    min_independent: int,
    excluded_tags: tuple[str, ...] = (),
) -> IndependenceAttestation:
    excluded = set(excluded_tags)
    selected: list[CapabilityDescriptor] = []
    used_tags: set[str] = set()
    for challenger in sorted(challengers, key=lambda item: item.entity_id):
        tags = set(challenger.independence_tags)
        if tags & excluded:
            continue
        if tags and tags.isdisjoint(used_tags):
            selected.append(challenger)
            used_tags.update(tags)
    selected_ids = tuple(challenger.entity_id for challenger in selected)
    return IndependenceAttestation(
        candidate_ids=tuple(challenger.entity_id for challenger in challengers),
        selected_entity_ids=selected_ids,
        min_independent=min_independent,
        lineage_disjoint=len(selected_ids) >= min_independent,
        correlation_warning=len(selected_ids) < min_independent,
        excluded_tags=tuple(sorted(excluded_tags)),
    )


def tier_from_checks(checks: tuple[CheckResult, ...]) -> str:
    statuses = {check.check: check.status for check in checks}
    recap_required = ("INJECTION", "NULL_CONTROL", "PHYSICAL_CONSISTENCY", "CALIBRATION")
    if not all(statuses.get(check) == "PASS" for check in recap_required):
        return "ran-toy"
    if statuses.get("CROSS_CODE") == "PASS" and statuses.get("LEAKAGE") == "PASS":
        return "novel-needs-human"
    return "recapitulated-known"


def _tier_after_independence_gate(claim_tier: str, attestation: IndependenceAttestation) -> str:
    if claim_tier != "novel-needs-human":
        return claim_tier
    if _novel_independence_satisfied(attestation):
        return claim_tier
    return "recapitulated-known"


def _novel_independence_satisfied(attestation: IndependenceAttestation) -> bool:
    selected_ids = tuple(attestation.selected_entity_ids)
    selected = set(selected_ids)
    candidates = set(attestation.candidate_ids)
    return (
        attestation.min_independent >= 2
        and len(selected) >= attestation.min_independent
        and selected.issubset(candidates)
        and len(selected) == len(selected_ids)
        and attestation.lineage_disjoint
        and not attestation.correlation_warning
    )


def _aggregate_passed(checks: tuple[CheckResult, ...], perturbation_outcome: PerturbationPairOutcome) -> bool:
    return (
        all(check.status == "PASS" for check in checks)
        and all(pair.verdict == "pass" for pair in perturbation_outcome.perturbation_pairs)
        and len(perturbation_outcome.insensitivity_flags) == 0
    )


def _aggregate_score(checks: tuple[CheckResult, ...]) -> float:
    if not checks:
        return 0.0
    return sum(1.0 for check in checks if check.status == "PASS") / len(checks)


def _check_to_contract(check: CheckResult) -> dict[str, Any]:
    payload = {
        "check": check.check,
        "status": check.status,
    }
    if check.metrics is not None:
        payload["metrics"] = check.metrics
    return payload


def _dataclass_contract(value: Any) -> dict[str, Any]:
    return {key: item for key, item in asdict(value).items() if item is not None}


def _default_independence_attestation(challenger_ids: tuple[str, ...]) -> IndependenceAttestation:
    return IndependenceAttestation(
        candidate_ids=challenger_ids,
        selected_entity_ids=tuple(dict.fromkeys(challenger_ids)),
        min_independent=len(challenger_ids) if challenger_ids else 1,
        lineage_disjoint=len(set(challenger_ids)) == len(challenger_ids),
        correlation_warning=len(set(challenger_ids)) != len(challenger_ids),
        excluded_tags=(),
    )
