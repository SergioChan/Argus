"""S3 verifier, perturbation oracle, and signed report core semantics."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from dataclasses import asdict, dataclass, replace
from functools import lru_cache
from hashlib import sha256
import hmac
import json
import math
from pathlib import Path
import random
from typing import Any, Mapping, Protocol
from uuid import NAMESPACE_URL, uuid4, uuid5

from jsonschema import Draft202012Validator

from argusverify import (
    C3ReportSigner,
    C3ReportVerifier,
    C3SignatureVerification,
    C3_SIGNATURE_ALGORITHM,
    C3_SIGNATURE_PREFIX,
    SIGNATURE_VERIFICATION_ACCEPTED,
    VerifierKey,
    canonical_c3_json_bytes,
)
from .canonical import canonical_json_bytes
from .hashing import hash_bytes, hash_json
from .s2 import S2ContractModelError, UnitsAlgebra
from .s8 import InMemoryArtifactStore, Lineage, Producer
from .s10 import (
    BudgetToken,
    BudgetUsage,
    LaunchEnvelope,
    LaunchRequest,
    SandboxExecutionResult,
    ScopeToken,
)
from .s6 import (
    CapabilityDescriptor,
    ContaminationIndex,
    FrozenContaminationSnapshot,
    IndependenceAttestation,
)
from .s7 import AdapterDescriptor, AdapterVersionError, select_adapter_version


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
S3_CHECK_PLUGIN_HOST_VERSION = "argus.s3.check_plugin_host.v1"
S3_CHECK_RESULT_EVIDENCE_KIND = "s3_check_result"
S3_CHECK_RESULT_EVIDENCE_SCHEMA = "argus.s3.check_result_evidence.v1"
S3_FROZEN_PIPELINE_RUNNER_VERSION = "argus.s3.frozen_pipeline_runner.v1"
S3_FROZEN_PIPELINE_RUN_EVIDENCE_KIND = "s3_frozen_pipeline_run"
S3_FROZEN_PIPELINE_RUN_EVIDENCE_SCHEMA = "argus.s3.frozen_pipeline_run_evidence.v1"
S3_FROZEN_PIPELINE_RUNNER_ENTRYPOINT = ("python", "-m", "argus_runtime.s3_frozen_pipeline_entrypoint")
S3_BLIND_DATA_VAULT_VERSION = "argus.s3.blind_data_vault.v1"
S3_BLIND_DATA_METADATA_KIND = "s3_blind_dataset_metadata"
S3_BLIND_DATA_METADATA_SCHEMA = "argus.s3.blind_dataset_metadata.v1"
S3_BLIND_OPAQUE_INPUT_KIND = "s3_blind_opaque_input"
S3_BLIND_OPAQUE_INPUT_SCHEMA = "argus.s3.blind_opaque_input.v1"
S3_BLIND_DATA_STAGE_KIND = "s3_blind_data_stage"
S3_BLIND_DATA_STAGE_SCHEMA = "argus.s3.blind_data_stage.v1"
S3_BLIND_DATA_QUARANTINE_KIND = "s3_blind_data_quarantine"
S3_BLIND_DATA_QUARANTINE_SCHEMA = "argus.s3.blind_data_quarantine.v1"
_S3_PROFILE_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


class VerifierProfileRegistryError(S3Error):
    """Raised when an S3 VerifierProfile registry operation fails closed."""

    def __init__(self, *, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class S3ProfileCompilerError(S3Error):
    """Raised when S3 cannot resolve or compile a verifier profile safely."""

    def __init__(self, *, category: str, code: str, message: str) -> None:
        super().__init__(message)
        self.category = category
        self.code = code
        self.message = message
        self.before_execution = True
        self.retryable = False

    def as_c1_payload(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "code": self.code,
            "message": self.message,
            "before_execution": self.before_execution,
            "retryable": self.retryable,
        }


class CheckPluginHostError(S3Error):
    """Raised when the S3 check-plugin host fails closed."""

    def __init__(
        self,
        *,
        category: str,
        code: str,
        message: str,
        before_execution: bool,
        partial_results: tuple[CheckResult, ...] = (),
    ) -> None:
        super().__init__(message)
        self.category = category
        self.code = code
        self.message = message
        self.before_execution = before_execution
        self.retryable = False
        self.partial_results = partial_results

    def as_c1_payload(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "code": self.code,
            "message": self.message,
            "before_execution": self.before_execution,
            "retryable": self.retryable,
        }


class S3FrozenPipelineRunnerError(S3Error):
    """Raised when S3 cannot safely launch a frozen pipeline through S10."""

    def __init__(self, *, category: str, code: str, message: str, before_execution: bool = True) -> None:
        super().__init__(message)
        self.category = category
        self.code = code
        self.message = message
        self.before_execution = before_execution
        self.retryable = False

    def as_c1_payload(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "code": self.code,
            "message": self.message,
            "before_execution": self.before_execution,
            "retryable": self.retryable,
        }


class S3BlindDataVaultError(S3Error):
    """Raised when S3 blind-data staging fails closed."""

    def __init__(
        self,
        *,
        category: str,
        code: str,
        message: str,
        quarantine_ref: str | None = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.code = code
        self.message = message
        self.quarantine_ref = quarantine_ref or ""
        self.retryable = retryable

    def as_c1_payload(self) -> dict[str, Any]:
        payload = {
            "category": self.category,
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
        }
        if self.quarantine_ref:
            payload["quarantine_ref"] = self.quarantine_ref
        return payload


class S3StatisticsError(S3Error):
    """Raised when an S3 statistics helper receives invalid input."""

    def __init__(self, *, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class S3KeyManagementError(S3Error):
    """Raised when S3 signing/trust-store key management fails closed."""

    def __init__(self, *, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class S3ReportSignerProtocol(Protocol):
    @property
    def key_id(self) -> str:
        ...

    def sign(self, report: dict[str, Any]) -> dict[str, Any]:
        ...


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


@dataclass(frozen=True)
class BlindDatasetRecord:
    handle: str
    handle_hash: str
    dataset_id: str
    version: str
    split: str
    dataset_kind: str
    opaque_input_hash: str
    truth_hash: str
    expected_opaque_input_hash: str
    expected_truth_hash: str
    metadata_ref: str


@dataclass(frozen=True)
class BlindDataStage:
    blind_data_handle: str
    handle_hash: str
    opaque_input_ref: str
    opaque_input_hash: str
    truth_hash: str
    stage_evidence_ref: str
    truth_retained_server_side: bool = True
    truth_bytes_delivered_to_sandbox: bool = False
    truth_hash_delivered_to_sandbox: bool = False


@dataclass(frozen=True)
class _BlindDatasetEntry:
    record: BlindDatasetRecord
    opaque_input: Any
    truth: Any


@dataclass(frozen=True)
class S3ToleranceResult:
    observed: float
    expected: float
    error: float
    tolerance: float
    absolute_tolerance: float | None
    relative_tolerance: float | None
    passed: bool
    tolerance_policy: str = "max(abs, rel*scale)"

    def as_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class S3AgreementResult:
    chi_square: float
    dof: int
    reduced_chi_square: float
    z_scores: tuple[float, ...]
    max_observed_abs_z: float
    max_allowed_abs_z: float
    max_allowed_reduced_chi_square: float
    p_value: float
    alpha: float
    passed: bool
    method: str = "chi-square-z-agreement"

    def as_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class S3CoverageResult:
    empirical_coverage: float
    nominal_coverage: float
    tolerance: float
    covered_count: int
    total_count: int
    absolute_error: float
    passed: bool
    method: str = "empirical-interval-coverage"

    def as_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class S3PITUniformityResult:
    ks_statistic: float
    p_value: float
    alpha: float
    sample_count: int
    passed: bool
    method: str = "pit-ks-uniformity"

    def as_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class S3BinomialBoundResult:
    false_positives: int
    trials: int
    observed_rate: float
    upper_bound: float
    confidence_level: float
    max_rate: float | None
    passed: bool
    method: str = "exact-binomial-one-sided"

    def as_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class S3BootstrapCIResult:
    estimate: float
    lower: float
    upper: float
    confidence_level: float
    statistic: str
    seed: int
    resamples: int
    samples_digest: str
    method: str = "percentile-bootstrap"

    def as_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class S3MultipleComparisonResult:
    p_values: tuple[float, ...]
    adjusted_p_values: tuple[float, ...]
    thresholds: tuple[float, ...]
    rejected: tuple[bool, ...]
    naive_rejected: tuple[bool, ...]
    corrected_decision_differs_from_naive: bool
    alpha: float
    method: str
    test_case: str = "S3-TC45"

    def as_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class S3SigningKeyMetadata:
    key_id: str
    epoch: int
    status: str
    active: bool
    algorithm: str = C3_SIGNATURE_ALGORITHM
    provider: str = "s3-trust-store-key-manager"
    key_material_exposed: bool = False

    def as_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class S3KeyUseAuditEvent:
    sequence: int
    event_type: str
    key_id: str
    epoch: int
    actor_id: str
    outcome: str
    report_digest: str = ""
    reason: str = ""
    key_material_exposed: bool = False

    def as_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class _S3SigningKeyMaterial:
    key_id: str
    key_bytes: bytes
    epoch: int
    revoked: bool = False
    active: bool = False


class S3TrustStoreKeyManager:
    """S3-owned report signing key manager and secretless verifier trust store."""

    def __init__(self, *, actor_id: str = "s3-trust-store-key-manager") -> None:
        if not actor_id:
            raise ValueError("actor_id is required")
        self.actor_id = actor_id
        self._keys: dict[str, _S3SigningKeyMaterial] = {}
        self._active_key_id: str | None = None
        self._epoch = 0
        self._audit: list[S3KeyUseAuditEvent] = []

    @property
    def key_id(self) -> str:
        return self._active_key().key_id

    @property
    def epoch(self) -> int:
        return self._epoch

    def register_signing_key(self, key_id: str, key_material: bytes, *, make_active: bool = True) -> S3SigningKeyMetadata:
        normalized_key_id = _s3_key_id(key_id)
        self._ensure_unused_key_id(normalized_key_id)
        material = _s3_key_material(key_material)
        self._epoch += 1
        if make_active:
            self._retire_active_key()
        key = _S3SigningKeyMaterial(
            key_id=normalized_key_id,
            key_bytes=material,
            epoch=self._epoch,
            active=make_active,
        )
        self._keys[normalized_key_id] = key
        if make_active:
            self._active_key_id = normalized_key_id
        self._record_key_event(
            event_type="s3.key.register",
            key_id=normalized_key_id,
            epoch=key.epoch,
            outcome="accepted",
        )
        return self._metadata_for(key)

    def rotate_signing_key(self, key_id: str, key_material: bytes) -> S3SigningKeyMetadata:
        normalized_key_id = _s3_key_id(key_id)
        self._ensure_unused_key_id(normalized_key_id)
        material = _s3_key_material(key_material)
        self._epoch += 1
        self._retire_active_key()
        key = _S3SigningKeyMaterial(
            key_id=normalized_key_id,
            key_bytes=material,
            epoch=self._epoch,
            active=True,
        )
        self._keys[normalized_key_id] = key
        self._active_key_id = normalized_key_id
        self._record_key_event(
            event_type="s3.key.rotate",
            key_id=normalized_key_id,
            epoch=key.epoch,
            outcome="accepted",
        )
        return self._metadata_for(key)

    def revoke_signing_key(self, key_id: str, *, reason: str = "") -> S3SigningKeyMetadata:
        key = self._known_key(key_id)
        self._epoch += 1
        revoked = replace(key, revoked=True, active=False, epoch=self._epoch)
        self._keys[revoked.key_id] = revoked
        self._record_key_event(
            event_type="s3.key.revoke",
            key_id=revoked.key_id,
            epoch=revoked.epoch,
            outcome="accepted",
            reason=reason,
        )
        return self._metadata_for(revoked)

    def sign(self, report: dict[str, Any]) -> dict[str, Any]:
        key = self._active_key()
        unsigned = deepcopy(report)
        unsigned["signature"] = {
            "algorithm": C3_SIGNATURE_ALGORITHM,
            "key_id": key.key_id,
            "value": "",
        }
        signed = deepcopy(unsigned)
        signed["signature"]["value"] = _s3_c3_signature_value(unsigned, key.key_bytes)
        self._record_key_event(
            event_type="s3.key.sign",
            key_id=key.key_id,
            epoch=key.epoch,
            outcome="accepted",
            report_digest=_s3_report_payload_digest(unsigned),
        )
        return signed

    def verify_report(self, report: dict[str, Any]) -> C3SignatureVerification:
        audit_count = len(self._audit)
        verification = C3ReportVerifier(self).verify(report)
        if len(self._audit) == audit_count:
            key_id = _s3_report_key_id(report)
            key = self._keys.get(key_id)
            self._record_key_event(
                event_type="s3.key.verify",
                key_id=key_id or "<missing>",
                epoch=key.epoch if key is not None else self._epoch,
                outcome="accepted" if verification.valid else (verification.reason or "rejected"),
                report_digest=_s3_report_payload_digest(_s3_report_with_empty_signature(report)),
            )
        return verification

    def get_key(self, key_id: str) -> VerifierKey | None:
        key = self._keys.get(key_id)
        if key is None:
            return None
        return VerifierKey(key_id=key.key_id, secret=b"", revoked=key.revoked)

    def verify_signature_value(
        self,
        *,
        key_id: str,
        report_with_empty_signature: dict[str, Any],
        signature_value: str,
    ) -> str | None:
        key = self._keys.get(key_id)
        if key is None:
            outcome = "unknown_key"
            epoch = self._epoch
        elif key.revoked:
            outcome = "revoked_key"
            epoch = key.epoch
        else:
            expected = _s3_c3_signature_value(report_with_empty_signature, key.key_bytes)
            outcome = (
                SIGNATURE_VERIFICATION_ACCEPTED
                if hmac.compare_digest(signature_value, expected)
                else "signature_invalid"
            )
            epoch = key.epoch
        self._record_key_event(
            event_type="s3.key.verify",
            key_id=key_id,
            epoch=epoch,
            outcome="accepted" if outcome == SIGNATURE_VERIFICATION_ACCEPTED else outcome,
            report_digest=_s3_report_payload_digest(report_with_empty_signature),
        )
        return outcome

    def key_metadata(self) -> tuple[S3SigningKeyMetadata, ...]:
        return tuple(self._metadata_for(key) for key in sorted(self._keys.values(), key=lambda item: item.key_id))

    def audit_events(self) -> tuple[S3KeyUseAuditEvent, ...]:
        return tuple(self._audit)

    def _active_key(self) -> _S3SigningKeyMaterial:
        if self._active_key_id is None:
            raise S3KeyManagementError(
                code="S3_SIGNING_KEY_UNAVAILABLE",
                message="no active S3 signing key is available",
            )
        key = self._keys[self._active_key_id]
        if key.revoked:
            raise S3KeyManagementError(
                code="S3_SIGNING_KEY_REVOKED",
                message=f"active S3 signing key is revoked: {key.key_id}",
            )
        if not key.active:
            raise S3KeyManagementError(
                code="S3_SIGNING_KEY_INACTIVE",
                message=f"S3 signing key is not active: {key.key_id}",
            )
        return key

    def _known_key(self, key_id: str) -> _S3SigningKeyMaterial:
        normalized = _s3_key_id(key_id)
        key = self._keys.get(normalized)
        if key is None:
            raise S3KeyManagementError(code="S3_SIGNING_KEY_UNKNOWN", message=f"unknown S3 signing key: {normalized}")
        return key

    def _ensure_unused_key_id(self, key_id: str) -> None:
        if key_id in self._keys:
            raise S3KeyManagementError(
                code="S3_SIGNING_KEY_ALREADY_EXISTS",
                message=f"S3 signing key already exists: {key_id}",
            )

    def _retire_active_key(self) -> None:
        if self._active_key_id is None:
            return
        current = self._keys[self._active_key_id]
        self._keys[current.key_id] = replace(current, active=False)

    def _metadata_for(self, key: _S3SigningKeyMaterial) -> S3SigningKeyMetadata:
        status = "revoked" if key.revoked else ("active" if key.active else "retired")
        return S3SigningKeyMetadata(
            key_id=key.key_id,
            epoch=key.epoch,
            status=status,
            active=key.active,
        )

    def _record_key_event(
        self,
        *,
        event_type: str,
        key_id: str,
        epoch: int,
        outcome: str,
        report_digest: str = "",
        reason: str = "",
    ) -> None:
        self._audit.append(
            S3KeyUseAuditEvent(
                sequence=len(self._audit) + 1,
                event_type=event_type,
                key_id=key_id,
                epoch=epoch,
                actor_id=self.actor_id,
                outcome=outcome,
                report_digest=report_digest,
                reason=reason,
            )
        )


class S3StatisticsLibrary:
    """Seeded, pure statistics helpers shared by S3 check families."""

    @staticmethod
    def tolerance(
        *,
        observed: float,
        expected: float,
        absolute_tolerance: float | None = None,
        relative_tolerance: float | None = None,
    ) -> S3ToleranceResult:
        observed_value = _s3_stats_float(observed, field="observed")
        expected_value = _s3_stats_float(expected, field="expected")
        if absolute_tolerance is None and relative_tolerance is None:
            _s3_stats_error("STAT_TOLERANCE_REQUIRED", "absolute_tolerance or relative_tolerance is required")
        abs_tol = _s3_stats_optional_non_negative(absolute_tolerance, field="absolute_tolerance")
        rel_tol = _s3_stats_optional_non_negative(relative_tolerance, field="relative_tolerance")
        candidates: list[float] = []
        if abs_tol is not None:
            candidates.append(abs_tol)
        if rel_tol is not None:
            candidates.append(rel_tol * max(abs(expected_value), 1.0))
        tolerance = max(candidates)
        error = abs(observed_value - expected_value)
        return S3ToleranceResult(
            observed=observed_value,
            expected=expected_value,
            error=error,
            tolerance=tolerance,
            absolute_tolerance=abs_tol,
            relative_tolerance=rel_tol,
            passed=error <= tolerance,
        )

    @staticmethod
    def chi_square_z_agreement(
        *,
        observed: tuple[float, ...] | list[float],
        expected: tuple[float, ...] | list[float],
        observed_uncertainty: tuple[float, ...] | list[float],
        expected_uncertainty: tuple[float, ...] | list[float] | None = None,
        max_abs_z: float = 3.0,
        max_reduced_chi_square: float = 2.0,
        alpha: float = 0.05,
    ) -> S3AgreementResult:
        observed_values = _s3_stats_sequence(observed, field="observed")
        expected_values = _s3_stats_sequence(expected, field="expected")
        observed_sigma = _s3_stats_sequence(observed_uncertainty, field="observed_uncertainty")
        expected_sigma = (
            _s3_stats_sequence(expected_uncertainty, field="expected_uncertainty")
            if expected_uncertainty is not None
            else tuple(0.0 for _ in observed_values)
        )
        _s3_stats_same_length(
            observed=observed_values,
            expected=expected_values,
            observed_uncertainty=observed_sigma,
            expected_uncertainty=expected_sigma,
        )
        allowed_z = _s3_stats_positive(max_abs_z, field="max_abs_z")
        allowed_reduced = _s3_stats_positive(max_reduced_chi_square, field="max_reduced_chi_square")
        alpha_value = _s3_stats_probability(alpha, field="alpha", allow_zero=False, allow_one=False)
        z_scores: list[float] = []
        for index, (obs, exp, obs_sigma, exp_sigma) in enumerate(
            zip(observed_values, expected_values, observed_sigma, expected_sigma, strict=True)
        ):
            if obs_sigma < 0 or exp_sigma < 0:
                _s3_stats_error("STAT_NEGATIVE_UNCERTAINTY", f"uncertainty at index {index} must be non-negative")
            combined_sigma = math.sqrt(obs_sigma * obs_sigma + exp_sigma * exp_sigma)
            if combined_sigma <= 0:
                _s3_stats_error("STAT_ZERO_UNCERTAINTY", f"combined uncertainty at index {index} must be positive")
            z_scores.append((obs - exp) / combined_sigma)
        chi_square = sum(z * z for z in z_scores)
        dof = len(z_scores)
        reduced = chi_square / dof
        p_value = _s3_stats_chi_square_survival(chi_square, dof)
        max_observed_z = max(abs(z) for z in z_scores)
        passed = max_observed_z <= allowed_z and reduced <= allowed_reduced and p_value >= alpha_value
        return S3AgreementResult(
            chi_square=chi_square,
            dof=dof,
            reduced_chi_square=reduced,
            z_scores=tuple(z_scores),
            max_observed_abs_z=max_observed_z,
            max_allowed_abs_z=allowed_z,
            max_allowed_reduced_chi_square=allowed_reduced,
            p_value=p_value,
            alpha=alpha_value,
            passed=passed,
        )

    @staticmethod
    def coverage(
        *,
        truth: tuple[float, ...] | list[float],
        lower: tuple[float, ...] | list[float],
        upper: tuple[float, ...] | list[float],
        nominal_coverage: float,
        tolerance: float,
    ) -> S3CoverageResult:
        truth_values = _s3_stats_sequence(truth, field="truth")
        lower_values = _s3_stats_sequence(lower, field="lower")
        upper_values = _s3_stats_sequence(upper, field="upper")
        _s3_stats_same_length(truth=truth_values, lower=lower_values, upper=upper_values)
        nominal = _s3_stats_probability(nominal_coverage, field="nominal_coverage")
        tolerance_value = _s3_stats_non_negative(tolerance, field="tolerance")
        covered = 0
        for index, (truth_value, lower_value, upper_value) in enumerate(
            zip(truth_values, lower_values, upper_values, strict=True)
        ):
            if lower_value > upper_value:
                _s3_stats_error("STAT_INTERVAL_INVALID", f"lower bound exceeds upper bound at index {index}")
            if lower_value <= truth_value <= upper_value:
                covered += 1
        empirical = covered / len(truth_values)
        error = abs(empirical - nominal)
        return S3CoverageResult(
            empirical_coverage=empirical,
            nominal_coverage=nominal,
            tolerance=tolerance_value,
            covered_count=covered,
            total_count=len(truth_values),
            absolute_error=error,
            passed=error <= tolerance_value,
        )

    @staticmethod
    def pit_uniformity(pit_values: tuple[float, ...] | list[float], *, alpha: float = 0.05) -> S3PITUniformityResult:
        values = _s3_stats_sequence(pit_values, field="pit_values")
        for index, value in enumerate(values):
            if value < 0 or value > 1:
                _s3_stats_error("STAT_PIT_OUT_OF_RANGE", f"PIT value at index {index} must be in [0, 1]")
        alpha_value = _s3_stats_probability(alpha, field="alpha", allow_zero=False, allow_one=False)
        ordered = tuple(sorted(values))
        n = len(ordered)
        ks_statistic = 0.0
        for index, value in enumerate(ordered, start=1):
            ks_statistic = max(ks_statistic, index / n - value, value - (index - 1) / n)
        p_value = _s3_stats_ks_uniform_p_value(ks_statistic, n)
        return S3PITUniformityResult(
            ks_statistic=ks_statistic,
            p_value=p_value,
            alpha=alpha_value,
            sample_count=n,
            passed=p_value >= alpha_value,
        )

    @staticmethod
    def false_positive_rate_bound(
        *,
        false_positives: int,
        trials: int,
        confidence_level: float = 0.95,
        max_rate: float | None = None,
    ) -> S3BinomialBoundResult:
        if not isinstance(false_positives, int) or not isinstance(trials, int):
            _s3_stats_error("STAT_INVALID_COUNTS", "false_positives and trials must be integers")
        if trials <= 0 or false_positives < 0 or false_positives > trials:
            _s3_stats_error("STAT_INVALID_COUNTS", "false_positives must satisfy 0 <= k <= trials and trials > 0")
        confidence = _s3_stats_probability(
            confidence_level,
            field="confidence_level",
            allow_zero=False,
            allow_one=False,
        )
        max_rate_value = _s3_stats_probability(max_rate, field="max_rate") if max_rate is not None else None
        observed_rate = false_positives / trials
        upper = _s3_stats_binomial_upper_bound(false_positives, trials, confidence)
        return S3BinomialBoundResult(
            false_positives=false_positives,
            trials=trials,
            observed_rate=observed_rate,
            upper_bound=upper,
            confidence_level=confidence,
            max_rate=max_rate_value,
            passed=True if max_rate_value is None else upper <= max_rate_value,
        )

    @staticmethod
    def bootstrap_ci(
        values: tuple[float, ...] | list[float],
        *,
        seed: int,
        resamples: int = 1000,
        confidence_level: float = 0.95,
        statistic: str = "mean",
    ) -> S3BootstrapCIResult:
        values_tuple = _s3_stats_sequence(values, field="values")
        if not isinstance(seed, int):
            _s3_stats_error("STAT_SEED_INVALID", "seed must be an integer")
        if not isinstance(resamples, int) or resamples < 1:
            _s3_stats_error("STAT_RESAMPLES_INVALID", "resamples must be a positive integer")
        confidence = _s3_stats_probability(
            confidence_level,
            field="confidence_level",
            allow_zero=False,
            allow_one=False,
        )
        estimate = _s3_stats_statistic(values_tuple, statistic)
        rng = random.Random(seed)
        samples: list[float] = []
        n = len(values_tuple)
        for _ in range(resamples):
            sample = tuple(values_tuple[rng.randrange(n)] for _ in range(n))
            samples.append(_s3_stats_statistic(sample, statistic))
        samples.sort()
        tail = (1.0 - confidence) / 2.0
        lower = _s3_stats_percentile(samples, tail)
        upper = _s3_stats_percentile(samples, 1.0 - tail)
        return S3BootstrapCIResult(
            estimate=estimate,
            lower=lower,
            upper=upper,
            confidence_level=confidence,
            statistic=statistic,
            seed=seed,
            resamples=resamples,
            samples_digest=hash_json(samples),
        )

    @staticmethod
    def benjamini_hochberg(p_values: tuple[float, ...] | list[float], *, alpha: float = 0.05) -> S3MultipleComparisonResult:
        return _s3_stats_multiple_comparison(p_values, alpha=alpha, method="benjamini-hochberg")

    @staticmethod
    def bonferroni(p_values: tuple[float, ...] | list[float], *, alpha: float = 0.05) -> S3MultipleComparisonResult:
        return _s3_stats_multiple_comparison(p_values, alpha=alpha, method="bonferroni")


@dataclass(frozen=True)
class S3CostCeiling:
    max_profile_wallclock_s: float | None = None
    max_profile_cost_usd: float | None = None
    max_check_wallclock_s: float | None = None
    max_check_cost_usd: float | None = None
    allowed_adapter_cost_classes: tuple[str, ...] = ("standard", "low")


@dataclass(frozen=True)
class CompiledC6Adapter:
    adapter_id: str
    requested_major: int | None
    selected_adapter_id: str
    selected_version: str
    determinism: str
    cost_class: str
    provenance_ref: str
    c5_revision: int
    c5_provenance_ref: str


@dataclass(frozen=True)
class CompiledCheckSpec:
    check: str
    plugin_ref: str
    plugin_version: str
    mandatory: bool
    thresholds: dict[str, Any]
    determinism: str
    seed: int | None
    tolerance: dict[str, Any]
    requires_independence: bool
    budget: dict[str, Any]
    adapter: CompiledC6Adapter | None = None


@dataclass(frozen=True)
class CompiledProfile:
    profile_id: str
    revision: int
    profile_ref: str
    subtopic: str
    spec_hash: str
    public_profile: dict[str, Any]
    cost_estimate: dict[str, Any]
    checks: tuple[CompiledCheckSpec, ...]
    independence_policy: dict[str, Any]
    determinism_profile: dict[str, Any]


class S3IndependenceResolverError(S3Error):
    """Raised when S3 cannot query C5 for independence evidence."""

    def __init__(self, *, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class S3IndependenceResolution:
    test_case: str
    verdict: str
    candidate_ids: tuple[str, ...]
    cross_codes: tuple[str, ...]
    rejected_candidate_ids: tuple[str, ...]
    excluded_tags: tuple[str, ...]
    degradations: tuple[str, ...]
    min_independent: int
    refused: bool = False
    refusal_code: str | None = None
    downgraded_profile_ref: str | None = None
    max_claim_tier: str = "recapitulated-known"
    c5_pinned_revisions: dict[str, int] | None = None

    def to_independence_attestation(self) -> IndependenceAttestation:
        return IndependenceAttestation(
            candidate_ids=self.candidate_ids,
            selected_entity_ids=self.cross_codes,
            min_independent=self.min_independent,
            lineage_disjoint=self.verdict == "INDEPENDENT",
            correlation_warning=self.verdict != "INDEPENDENT",
            excluded_tags=self.excluded_tags,
        )

    def to_check_result(self) -> "CheckResult":
        metrics: dict[str, Any] = {
            "test_case": self.test_case,
            "verdict": self.verdict,
            "candidate_ids": list(self.candidate_ids),
            "cross_codes": list(self.cross_codes),
            "rejected_candidate_ids": list(self.rejected_candidate_ids),
            "excluded_tags": list(self.excluded_tags),
            "degradations": list(self.degradations),
            "min_independent": self.min_independent,
            "refused": self.refused,
            "refusal_code": self.refusal_code,
            "max_claim_tier": self.max_claim_tier,
            "c5_pinned_revisions": dict(self.c5_pinned_revisions or {}),
        }
        if self.downgraded_profile_ref is not None:
            metrics["downgraded_profile_ref"] = self.downgraded_profile_ref
        return CheckResult(
            "CROSS_CODE",
            "PASS" if self.verdict == "INDEPENDENT" else "INCONCLUSIVE",
            metrics=metrics,
        )

    def as_payload(self) -> dict[str, Any]:
        return {
            "test_case": self.test_case,
            "verdict": self.verdict,
            "candidate_ids": list(self.candidate_ids),
            "cross_codes": list(self.cross_codes),
            "rejected_candidate_ids": list(self.rejected_candidate_ids),
            "excluded_tags": list(self.excluded_tags),
            "degradations": list(self.degradations),
            "min_independent": self.min_independent,
            "refused": self.refused,
            "refusal_code": self.refusal_code,
            "downgraded_profile_ref": self.downgraded_profile_ref,
            "max_claim_tier": self.max_claim_tier,
            "c5_pinned_revisions": dict(self.c5_pinned_revisions or {}),
        }


class S3IndependenceResolver:
    """Resolve S3 cross-code independence through C5 without hiding rejected candidates."""

    def __init__(self, *, c5_registry: Any) -> None:
        if c5_registry is None or not hasattr(c5_registry, "resolve"):
            raise S3IndependenceResolverError(
                code="C5_REGISTRY_UNAVAILABLE",
                message="S3 Independence Resolver requires a C5 registry with resolve()",
            )
        self._c5_registry = c5_registry

    def resolve_cross_code(
        self,
        *,
        subtopic: str,
        code_under_test: CapabilityDescriptor,
        required_scope: str = "c6.evaluate",
        kind: str = "adapter",
        min_independent: int = 1,
        requested_tier: str | None = None,
        policy: Mapping[str, Any] | None = None,
    ) -> S3IndependenceResolution:
        if not isinstance(min_independent, int) or min_independent < 1:
            raise S3IndependenceResolverError(
                code="INDEPENDENCE_MIN_INVALID",
                message="min_independent must be a positive integer",
            )
        if not isinstance(code_under_test, CapabilityDescriptor):
            raise S3IndependenceResolverError(
                code="CODE_UNDER_TEST_INVALID",
                message="code_under_test must be a C5 CapabilityDescriptor",
            )
        c5_resolution = self._resolve_c5(kind=kind, subtopic=subtopic, required_scope=required_scope)
        excluded_tags = tuple(sorted(set(code_under_test.independence_tags)))
        candidate_descriptors = tuple(
            descriptor
            for descriptor in c5_resolution.descriptors
            if descriptor.entity_id != code_under_test.entity_id
        )
        selected: list[CapabilityDescriptor] = []
        rejected: list[CapabilityDescriptor] = []
        used_tags: set[str] = set()
        excluded = set(excluded_tags)
        for descriptor in candidate_descriptors:
            tags = set(descriptor.independence_tags)
            if not tags or tags & excluded or not tags.isdisjoint(used_tags):
                rejected.append(descriptor)
                continue
            selected.append(descriptor)
            used_tags.update(tags)

        cross_codes = tuple(descriptor.entity_id for descriptor in selected)
        independent = len(cross_codes) >= min_independent
        policy_payload = dict(policy or {})
        strict = bool(policy_payload.get("strict")) or str(policy_payload.get("mode", "")).lower() == "strict"
        requested_novel = requested_tier == "novel-needs-human"
        if independent:
            verdict = "INDEPENDENT"
            test_case = "S3-T14"
        elif strict and requested_novel:
            verdict = "REFUSED"
            test_case = "S3-TC50"
        elif requested_novel:
            verdict = "NOT_INDEPENDENT" if rejected else "INDEPENDENCE_UNAVAILABLE"
            test_case = "S3-TC23"
        else:
            verdict = "NOT_INDEPENDENT" if rejected else "INDEPENDENCE_UNAVAILABLE"
            test_case = "S3-TC24"

        degradation = () if independent else ("INDEPENDENCE_UNAVAILABLE",)
        downgraded_profile_ref = policy_payload.get("downgraded_profile_ref")
        if downgraded_profile_ref is not None and not isinstance(downgraded_profile_ref, str):
            raise S3IndependenceResolverError(
                code="DOWNGRADED_PROFILE_REF_INVALID",
                message="downgraded_profile_ref must be a string when provided",
            )
        return S3IndependenceResolution(
            test_case=test_case,
            verdict=verdict,
            candidate_ids=tuple(descriptor.entity_id for descriptor in candidate_descriptors),
            cross_codes=cross_codes,
            rejected_candidate_ids=tuple(descriptor.entity_id for descriptor in rejected),
            excluded_tags=excluded_tags,
            degradations=degradation,
            min_independent=min_independent,
            refused=verdict == "REFUSED",
            refusal_code="INDEPENDENCE_UNAVAILABLE" if verdict == "REFUSED" else None,
            downgraded_profile_ref=downgraded_profile_ref,
            max_claim_tier="novel-needs-human" if independent else "recapitulated-known",
            c5_pinned_revisions=dict(c5_resolution.pinned_revisions),
        )

    def _resolve_c5(self, *, kind: str, subtopic: str, required_scope: str):
        try:
            return self._c5_registry.resolve(kind=kind, subtopic=subtopic, required_scope=required_scope)
        except Exception as exc:  # pragma: no cover - defensive wrapper for external C5 clients.
            raise S3IndependenceResolverError(
                code="C5_RESOLVE_FAILED",
                message=f"C5 independence resolve failed: {exc}",
            ) from exc


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


class S3ProfileCompiler:
    """Resolve an immutable VerifierProfile revision and compile S3 preflight metadata."""

    def __init__(
        self,
        *,
        profile_registry: Any,
        adapter_descriptors: tuple[AdapterDescriptor, ...] = (),
        capability_registry: Any | None = None,
        cost_ceiling: S3CostCeiling | None = None,
    ) -> None:
        self._profile_registry = profile_registry
        self._adapter_descriptors = tuple(adapter_descriptors)
        self._capability_registry = capability_registry
        self._cost_ceiling = cost_ceiling or S3CostCeiling()

    def compile(self, *, profile_ref: str, subtopic: str | None = None) -> CompiledProfile:
        profile = self._resolve_profile(profile_ref)
        if subtopic is not None and profile.subtopic != subtopic:
            _compiler_error(
                category="VERIFIER_UNAVAILABLE",
                code="PROFILE_UNSUPPORTED",
                message=f"VerifierProfile {profile.profile_ref} does not support subtopic {subtopic}",
            )
        if profile.status != "active":
            _compiler_error(
                category="VERIFIER_UNAVAILABLE",
                code="PROFILE_UNSUPPORTED",
                message=f"VerifierProfile {profile.profile_ref} is not active",
            )
        self._assert_profile_cost_ceiling(profile.cost_estimate)
        check_specs = tuple(self._compile_check(profile, check) for check in profile.checks)
        return CompiledProfile(
            profile_id=profile.profile_id,
            revision=profile.revision,
            profile_ref=profile.profile_ref,
            subtopic=profile.subtopic,
            spec_hash=profile.spec_hash,
            public_profile=profile.to_c3_profile(),
            cost_estimate=dict(profile.cost_estimate),
            checks=check_specs,
            independence_policy=_compiler_mapping(profile.spec_json.get("independence_policy"), default={}),
            determinism_profile=_determinism_profile(check_specs),
        )

    def _resolve_profile(self, profile_ref: str) -> VerifierProfileRevision:
        if not isinstance(profile_ref, str) or not profile_ref:
            _compiler_error(
                category="VERIFIER_UNAVAILABLE",
                code="PROFILE_REF_REQUIRED",
                message="S3 Profile Compiler requires a non-empty profile_ref",
            )
        if self._profile_registry is None or not hasattr(self._profile_registry, "get_by_ref"):
            _compiler_error(
                category="VERIFIER_UNAVAILABLE",
                code="PROFILE_REGISTRY_UNAVAILABLE",
                message="S3 Profile Compiler requires a registry with get_by_ref",
            )
        try:
            profile = self._profile_registry.get_by_ref(profile_ref)
        except VerifierProfileRegistryError as exc:
            raise S3ProfileCompilerError(
                category="VERIFIER_UNAVAILABLE",
                code="PROFILE_UNSUPPORTED" if exc.code == "S3_PROFILE_NOT_FOUND" else exc.code,
                message=exc.message,
            ) from exc
        if not isinstance(profile, VerifierProfileRevision):
            _compiler_error(
                category="VERIFIER_UNAVAILABLE",
                code="PROFILE_INVALID",
                message="profile registry returned an invalid VerifierProfile revision",
            )
        return profile

    def _compile_check(self, profile: VerifierProfileRevision, check: str) -> CompiledCheckSpec:
        spec = _check_spec_for(profile, check)
        plugin_version = _semver_string(spec.get("plugin_version") or "1.0.0", field_name=f"{check}.plugin_version")
        thresholds = _compiler_mapping(spec.get("thresholds"), default=_thresholds_for(profile, check))
        budget = _compiler_mapping(spec.get("budget"), default={})
        self._assert_check_cost_ceiling(check=check, budget=budget)
        adapter = self._compile_adapter(profile=profile, check=check, spec=spec)
        determinism = _check_determinism(profile=profile, check=check, spec=spec, adapter=adapter)
        seed = _check_seed(profile=profile, spec=spec)
        if determinism == "seeded" and seed is None:
            _compiler_error(category="POLICY", code="PROFILE_UNSUPPORTED", message=f"{check} seeded determinism requires a seed")
        tolerance = _compiler_mapping(spec.get("tolerance"), default={})
        return CompiledCheckSpec(
            check=check,
            plugin_ref=_non_empty_plugin_ref(spec.get("plugin_ref") or f"argus.s3.checks.{check.lower()}"),
            plugin_version=plugin_version,
            mandatory=bool(spec.get("mandatory", True)),
            thresholds=thresholds,
            determinism=determinism,
            seed=seed,
            tolerance=tolerance,
            requires_independence=_requires_independence(profile=profile, check=check, spec=spec),
            budget=budget,
            adapter=adapter,
        )

    def _compile_adapter(
        self,
        *,
        profile: VerifierProfileRevision,
        check: str,
        spec: Mapping[str, Any],
    ) -> CompiledC6Adapter | None:
        adapter_id = spec.get("adapter_id") or spec.get("adapter_ref") or spec.get("c6_adapter_id")
        if adapter_id is None:
            return None
        if not isinstance(adapter_id, str) or not adapter_id:
            _compiler_error(category="POLICY", code="C6_ADAPTER_UNSUPPORTED", message=f"{check} adapter_id must be non-empty")
        requested_major = _optional_positive_int(spec.get("adapter_major"), field_name=f"{check}.adapter_major")
        selected = self._select_adapter_descriptor(adapter_id=adapter_id, requested_major=requested_major)
        c5_descriptor = self._resolve_c5_adapter_descriptor(adapter_id=adapter_id, subtopic=profile.subtopic)
        self._assert_adapter_cost_ceiling(adapter_id=adapter_id, cost_class=selected.cost_class)
        return CompiledC6Adapter(
            adapter_id=adapter_id,
            requested_major=requested_major,
            selected_adapter_id=selected.adapter_id,
            selected_version=selected.version,
            determinism=selected.determinism,
            cost_class=selected.cost_class,
            provenance_ref=selected.provenance_ref,
            c5_revision=c5_descriptor.revision,
            c5_provenance_ref=c5_descriptor.provenance_ref,
        )

    def _select_adapter_descriptor(self, *, adapter_id: str, requested_major: int | None) -> AdapterDescriptor:
        candidates = tuple(descriptor for descriptor in self._adapter_descriptors if descriptor.adapter_id == adapter_id)
        if not candidates:
            _compiler_error(
                category="POLICY",
                code="C6_ADAPTER_UNSUPPORTED",
                message=f"C6 adapter {adapter_id} is not in the S3 compiler descriptor catalog",
            )
        try:
            if requested_major is not None:
                selection = select_adapter_version(candidates, requested_major=requested_major)
                return next(
                    descriptor
                    for descriptor in candidates
                    if descriptor.adapter_id == selection.selected_adapter_id and descriptor.version == selection.selected_version
                )
            return max(candidates, key=lambda descriptor: _parse_semver_tuple(descriptor.version))
        except (AdapterVersionError, StopIteration) as exc:
            raise S3ProfileCompilerError(
                category="POLICY",
                code="C6_ADAPTER_UNSUPPORTED",
                message=str(exc),
            ) from exc

    def _resolve_c5_adapter_descriptor(self, *, adapter_id: str, subtopic: str) -> CapabilityDescriptor:
        if self._capability_registry is None or not hasattr(self._capability_registry, "get"):
            _compiler_error(
                category="POLICY",
                code="C6_ADAPTER_UNSUPPORTED",
                message="S3 Profile Compiler requires a C5 registry for C6 adapter resolution",
            )
        try:
            descriptor = self._capability_registry.get(adapter_id)
        except (KeyError, LookupError) as exc:
            raise S3ProfileCompilerError(
                category="POLICY",
                code="C6_ADAPTER_UNSUPPORTED",
                message=f"C6 adapter {adapter_id} was not resolvable through C5",
            ) from exc
        if not isinstance(descriptor, CapabilityDescriptor):
            _compiler_error(category="POLICY", code="C6_ADAPTER_UNSUPPORTED", message="C5 returned an invalid adapter descriptor")
        if descriptor.kind != "adapter" or descriptor.owner_subsystem != "S7":
            _compiler_error(category="POLICY", code="C6_ADAPTER_UNSUPPORTED", message=f"{adapter_id} is not an S7 adapter")
        if "C6" not in descriptor.contract_versions:
            _compiler_error(category="POLICY", code="C6_ADAPTER_UNSUPPORTED", message=f"{adapter_id} does not declare C6")
        if descriptor.subtopics and subtopic not in descriptor.subtopics:
            _compiler_error(
                category="POLICY",
                code="C6_ADAPTER_UNSUPPORTED",
                message=f"C6 adapter {adapter_id} does not support subtopic {subtopic}",
            )
        scopes = set(descriptor.capability_scopes)
        if "evaluate" not in scopes and "c6.evaluate" not in scopes:
            _compiler_error(
                category="POLICY",
                code="C6_ADAPTER_UNSUPPORTED",
                message=f"C6 adapter {adapter_id} does not expose evaluate",
            )
        if descriptor.status != "active":
            _compiler_error(category="POLICY", code="C6_ADAPTER_UNSUPPORTED", message=f"C6 adapter {adapter_id} is not active")
        return descriptor

    def _assert_profile_cost_ceiling(self, cost_estimate: Mapping[str, Any]) -> None:
        self._assert_numeric_ceiling(
            value=cost_estimate.get("max_wallclock_s"),
            ceiling=self._cost_ceiling.max_profile_wallclock_s,
            field_name="cost_estimate.max_wallclock_s",
        )
        self._assert_numeric_ceiling(
            value=cost_estimate.get("max_cost_usd"),
            ceiling=self._cost_ceiling.max_profile_cost_usd,
            field_name="cost_estimate.max_cost_usd",
        )

    def _assert_check_cost_ceiling(self, *, check: str, budget: Mapping[str, Any]) -> None:
        self._assert_numeric_ceiling(
            value=budget.get("max_wallclock_s"),
            ceiling=self._cost_ceiling.max_check_wallclock_s,
            field_name=f"{check}.budget.max_wallclock_s",
        )
        self._assert_numeric_ceiling(
            value=budget.get("max_cost_usd"),
            ceiling=self._cost_ceiling.max_check_cost_usd,
            field_name=f"{check}.budget.max_cost_usd",
        )

    def _assert_adapter_cost_ceiling(self, *, adapter_id: str, cost_class: str) -> None:
        if cost_class not in self._cost_ceiling.allowed_adapter_cost_classes:
            _compiler_error(
                category="POLICY",
                code="C6_COST_CEILING_EXCEEDED",
                message=f"C6 adapter {adapter_id} cost_class {cost_class} exceeds the S3 profile compiler ceiling",
            )

    @staticmethod
    def _assert_numeric_ceiling(*, value: Any, ceiling: float | None, field_name: str) -> None:
        if ceiling is None:
            return
        numeric = _optional_number(value, field_name=field_name)
        if numeric is None or numeric > ceiling:
            _compiler_error(
                category="POLICY",
                code="C6_COST_CEILING_EXCEEDED",
                message=f"{field_name} exceeds the S3 profile compiler ceiling",
            )


def compile_verifier_profile(
    *,
    profile_ref: str,
    profile_registry: Any,
    subtopic: str | None = None,
    adapter_descriptors: tuple[AdapterDescriptor, ...] = (),
    capability_registry: Any | None = None,
    cost_ceiling: S3CostCeiling | None = None,
) -> CompiledProfile:
    compiler = S3ProfileCompiler(
        profile_registry=profile_registry,
        adapter_descriptors=adapter_descriptors,
        capability_registry=capability_registry,
        cost_ceiling=cost_ceiling,
    )
    return compiler.compile(profile_ref=profile_ref, subtopic=subtopic)


@dataclass(frozen=True)
class CheckResult:
    check: str
    status: str
    metrics: dict[str, Any] | None = None
    evidence_ref: str | None = None
    plugin_ref: str | None = None
    plugin_version: str | None = None
    dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class CheckPluginDescriptor:
    check: str
    plugin_ref: str
    plugin_version: str
    dependencies: tuple[str, ...] = ()
    determinism: str = "deterministic"
    declared_inputs: tuple[str, ...] = ()


@dataclass(frozen=True)
class CheckPluginContext:
    compiled_profile: CompiledProfile
    check_spec: CompiledCheckSpec
    completed_results: Mapping[str, CheckResult]
    artifact_store: InMemoryArtifactStore | None = None
    actor_id: str = "s3-check-plugin-host"
    job_id: str | None = None
    trace_id: str | None = None


class CheckPlugin(Protocol):
    def describe(self) -> CheckPluginDescriptor:
        ...

    def run(self, ctx: CheckPluginContext) -> CheckResult:
        ...


class S3InjectionCheckError(S3Error):
    """Raised when the S3 INJECTION check cannot be evaluated safely."""

    def __init__(self, *, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class S3NullControlCheckError(S3Error):
    """Raised when the S3 NULL_CONTROL check cannot be evaluated safely."""

    def __init__(self, *, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class S3CrossCodeCheckError(S3Error):
    """Raised when the S3 CROSS_CODE check cannot be evaluated safely."""

    def __init__(self, *, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class S3PhysicalConsistencyCheckError(S3Error):
    """Raised when the S3 PHYSICAL_CONSISTENCY check cannot be evaluated safely."""

    def __init__(self, *, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class S3InjectionSample:
    sample_id: str
    injected_value: float
    recovered_value: float


@dataclass(frozen=True)
class S3NullControlSample:
    sample_id: str
    variant: str
    detected: bool


@dataclass(frozen=True)
class S3CrossCodeSample:
    sample_id: str
    pipeline_value: float
    reference_value: float
    pipeline_uncertainty: float
    reference_uncertainty: float
    pipeline_units: str
    reference_units: str
    extrapolation_flag: bool = False


@dataclass(frozen=True)
class S3PhysicalConsistencySample:
    sample_id: str
    observable: str
    value: float
    units: str
    expected_units: str
    non_negative: bool = False
    normalization_group: str | None = None
    symmetry_transform: str | None = None
    transformed_value: float | None = None
    asymptotic_expected: float | None = None


class S3InjectionCheckPlugin:
    """Concrete INJECTION check plugin for S3-TC04/05/05b."""

    def __init__(
        self,
        *,
        samples: tuple[S3InjectionSample, ...],
        plugin_version: str = "1.0.0",
    ) -> None:
        self._samples = tuple(samples)
        self._plugin_version = plugin_version

    def describe(self) -> CheckPluginDescriptor:
        return CheckPluginDescriptor(
            check="INJECTION",
            plugin_ref="argus.s3.plugins.injection",
            plugin_version=self._plugin_version,
            determinism="deterministic",
            declared_inputs=(
                "s3.blind_data_stage",
                "s3.frozen_pipeline_observations",
            ),
        )

    def run(self, ctx: CheckPluginContext) -> CheckResult:
        if ctx.check_spec.check != "INJECTION":
            _s3_injection_error(
                "S3_INJECTION_CHECK_SPEC_MISMATCH",
                f"injection plugin cannot run {ctx.check_spec.check}",
            )
        samples = _s3_injection_samples(self._samples)
        recovery_rate_min = _s3_injection_probability(
            ctx.check_spec.thresholds.get("recovery_rate_min"),
            field="recovery_rate_min",
            allow_zero=False,
        )
        relative_tolerance = _s3_injection_optional_non_negative(
            ctx.check_spec.tolerance.get("relative_tolerance"),
            field="relative_tolerance",
        )
        absolute_tolerance = _s3_injection_optional_non_negative(
            ctx.check_spec.tolerance.get("absolute_tolerance"),
            field="absolute_tolerance",
        )
        if relative_tolerance is None and absolute_tolerance is None:
            _s3_injection_error(
                "S3_INJECTION_TOLERANCE_REQUIRED",
                "INJECTION requires relative_tolerance or absolute_tolerance",
            )
        slope_tolerance = _s3_injection_positive(
            ctx.check_spec.tolerance.get("slope_tolerance"),
            field="slope_tolerance",
        )
        intercept_tolerance_abs = _s3_injection_non_negative(
            ctx.check_spec.tolerance.get("intercept_tolerance_abs"),
            field="intercept_tolerance_abs",
        )

        recovered_count = 0
        for _sample_id, injected, recovered in samples:
            tolerance_result = S3StatisticsLibrary.tolerance(
                observed=recovered,
                expected=injected,
                absolute_tolerance=absolute_tolerance,
                relative_tolerance=relative_tolerance,
            )
            if tolerance_result.passed:
                recovered_count += 1
        recovery_rate = recovered_count / len(samples)
        recovery_pass = recovery_rate >= recovery_rate_min

        slope, intercept = _s3_injection_linear_fit(samples)
        slope_result = S3StatisticsLibrary.tolerance(
            observed=slope,
            expected=1.0,
            absolute_tolerance=slope_tolerance,
        )
        intercept_result = S3StatisticsLibrary.tolerance(
            observed=intercept,
            expected=0.0,
            absolute_tolerance=intercept_tolerance_abs,
        )
        amplitude_linearity_pass = slope_result.passed and intercept_result.passed
        failure_reason = _s3_injection_linearity_failure_reason(
            slope_pass=slope_result.passed,
            intercept_pass=intercept_result.passed,
        )
        status = "PASS" if recovery_pass and amplitude_linearity_pass else "FAIL"
        test_cases = ["S3-TC04"]
        if not recovery_pass:
            test_cases.append("S3-TC05")
        test_cases.append("S3-TC05b")

        return CheckResult(
            check="INJECTION",
            status=status,
            metrics={
                "test_cases": test_cases,
                "sample_count": len(samples),
                "sample_digest": _s3_injection_samples_digest(samples),
                "recovered_count": recovered_count,
                "recovery_rate": recovery_rate,
                "recovery_rate_min": recovery_rate_min,
                "recovery_pass": recovery_pass,
                "relative_tolerance": relative_tolerance,
                "absolute_tolerance": absolute_tolerance,
                "tolerance_policy": "max(abs, rel*scale)",
                "linearity_slope": slope,
                "linearity_intercept": intercept,
                "slope_tolerance": slope_tolerance,
                "intercept_tolerance_abs": intercept_tolerance_abs,
                "amplitude_linearity_pass": amplitude_linearity_pass,
                "linearity_failure_reason": failure_reason,
            },
        )


class S3NullControlCheckPlugin:
    """Concrete NULL_CONTROL check plugin for S3-TC06/07/08."""

    def __init__(
        self,
        *,
        samples: tuple[S3NullControlSample, ...],
        plugin_version: str = "1.0.0",
    ) -> None:
        self._samples = tuple(samples)
        self._plugin_version = plugin_version

    def describe(self) -> CheckPluginDescriptor:
        return CheckPluginDescriptor(
            check="NULL_CONTROL",
            plugin_ref="argus.s3.plugins.null_control",
            plugin_version=self._plugin_version,
            determinism="deterministic",
            declared_inputs=(
                "s3.blind_data_stage",
                "s3.frozen_pipeline_observations",
            ),
        )

    def run(self, ctx: CheckPluginContext) -> CheckResult:
        if ctx.check_spec.check != "NULL_CONTROL":
            _s3_null_control_error(
                "S3_NULL_CONTROL_CHECK_SPEC_MISMATCH",
                f"null-control plugin cannot run {ctx.check_spec.check}",
            )
        samples = _s3_null_control_samples(self._samples)
        alpha = _s3_null_control_probability(
            ctx.check_spec.thresholds.get("alpha"),
            field="alpha",
        )
        confidence_level = _s3_null_control_probability(
            ctx.check_spec.thresholds.get("confidence_level", 0.95),
            field="confidence_level",
        )
        false_positives = sum(1 for _sample_id, _variant, detected in samples if detected)
        aggregate_bound = S3StatisticsLibrary.false_positive_rate_bound(
            false_positives=false_positives,
            trials=len(samples),
            confidence_level=confidence_level,
            max_rate=alpha,
        )
        variant_results = _s3_null_control_variant_results(
            samples=samples,
            alpha=alpha,
            confidence_level=confidence_level,
        )
        all_variants_pass = all(result["passed"] for result in variant_results)
        null_control_pass = aggregate_bound.passed and all_variants_pass
        status = "PASS" if null_control_pass else "FAIL"
        variants = tuple(dict.fromkeys(variant for _sample_id, variant, _detected in samples))
        test_cases = _s3_null_control_test_cases(status=status, variants=variants)
        failure_reason = _s3_null_control_failure_reason(
            aggregate_pass=aggregate_bound.passed,
            all_variants_pass=all_variants_pass,
        )

        return CheckResult(
            check="NULL_CONTROL",
            status=status,
            metrics={
                "test_cases": test_cases,
                "trial_count": len(samples),
                "sample_digest": _s3_null_control_samples_digest(samples),
                "false_positives": false_positives,
                "false_positive_rate": aggregate_bound.observed_rate,
                "false_positive_rate_upper": aggregate_bound.upper_bound,
                "alpha": alpha,
                "confidence_level": confidence_level,
                "binomial_method": aggregate_bound.method,
                "null_control_pass": null_control_pass,
                "variant_counts": _s3_null_control_variant_counts(samples),
                "variant_results": variant_results,
                "failure_reason": failure_reason,
            },
        )


class S3CrossCodeCheckPlugin:
    """Concrete CROSS_CODE check plugin for S3-TC09/10/11/47."""

    def __init__(
        self,
        *,
        samples: tuple[S3CrossCodeSample, ...],
        independence_resolution: S3IndependenceResolution | None,
        plugin_version: str = "1.0.0",
    ) -> None:
        self._samples = tuple(samples)
        self._independence_resolution = independence_resolution
        self._plugin_version = plugin_version

    def describe(self) -> CheckPluginDescriptor:
        return CheckPluginDescriptor(
            check="CROSS_CODE",
            plugin_ref="argus.s3.plugins.cross_code",
            plugin_version=self._plugin_version,
            determinism="deterministic",
            declared_inputs=(
                "s3.frozen_pipeline_observations",
                "c5.independence_resolution",
                "c6.independent_adapter_observations",
            ),
        )

    def run(self, ctx: CheckPluginContext) -> CheckResult:
        if ctx.check_spec.check != "CROSS_CODE":
            _s3_cross_code_error(
                "S3_CROSS_CODE_CHECK_SPEC_MISMATCH",
                f"cross-code plugin cannot run {ctx.check_spec.check}",
            )
        independence = _s3_cross_code_independence_resolution(self._independence_resolution)
        if independence.verdict != "INDEPENDENT":
            return CheckResult(
                check="CROSS_CODE",
                status="INCONCLUSIVE",
                metrics={
                    "test_cases": ["S3-TC11"],
                    "independence_verdict": independence.verdict,
                    "cross_codes": list(independence.cross_codes),
                    "degradations": list(independence.degradations or ("INDEPENDENCE_UNAVAILABLE",)),
                    "min_independent": independence.min_independent,
                    "failure_reason": "INDEPENDENCE_UNAVAILABLE",
                    "numeric_coercion_performed": False,
                },
            )

        samples = _s3_cross_code_samples(self._samples)
        reduced_min = _s3_cross_code_non_negative(
            ctx.check_spec.thresholds.get("reduced_chi_square_min"),
            field="reduced_chi_square_min",
        )
        reduced_max = _s3_cross_code_positive(
            ctx.check_spec.thresholds.get("reduced_chi_square_max"),
            field="reduced_chi_square_max",
        )
        if reduced_max < reduced_min:
            _s3_cross_code_error(
                "S3_CROSS_CODE_THRESHOLD_INVALID",
                "reduced_chi_square_max must be >= reduced_chi_square_min",
            )
        z_max = _s3_cross_code_positive(ctx.check_spec.thresholds.get("z_max"), field="z_max")
        max_excluded_fraction = _s3_cross_code_fraction(
            ctx.check_spec.thresholds.get("max_excluded_fraction", 0.0),
            field="max_excluded_fraction",
        )
        min_valid_points = _s3_cross_code_positive_int(
            ctx.check_spec.thresholds.get("min_valid_points", 2),
            field="min_valid_points",
        )
        alpha = _s3_cross_code_probability(
            ctx.check_spec.thresholds.get("alpha", 0.05),
            field="alpha",
        )

        units_mismatch_count = sum(
            1 for sample in samples if sample["pipeline_units"] != sample["reference_units"]
        )
        base_metrics = _s3_cross_code_base_metrics(
            samples=samples,
            independence=independence,
            reduced_min=reduced_min,
            reduced_max=reduced_max,
            z_max=z_max,
            max_excluded_fraction=max_excluded_fraction,
            min_valid_points=min_valid_points,
        )
        if units_mismatch_count:
            return CheckResult(
                check="CROSS_CODE",
                status="FAIL",
                metrics={
                    **base_metrics,
                    "test_cases": ["S3-TC47"],
                    "units_mismatch_count": units_mismatch_count,
                    "cross_code_pass": False,
                    "numeric_coercion_performed": False,
                    "failure_reason": "UNITS_MISMATCH",
                },
            )

        valid_samples = tuple(sample for sample in samples if not sample["extrapolation_flag"])
        points_excluded = len(samples) - len(valid_samples)
        excluded_fraction = points_excluded / len(samples)
        if excluded_fraction > max_excluded_fraction:
            return CheckResult(
                check="CROSS_CODE",
                status="INCONCLUSIVE",
                metrics={
                    **base_metrics,
                    "test_cases": ["S3-TC11"],
                    "valid_point_count": len(valid_samples),
                    "points_excluded": points_excluded,
                    "excluded_fraction": excluded_fraction,
                    "cross_code_pass": False,
                    "numeric_coercion_performed": False,
                    "failure_reason": "EXCLUDED_FRACTION_EXCEEDS_MAX",
                },
            )
        if len(valid_samples) < min_valid_points:
            return CheckResult(
                check="CROSS_CODE",
                status="INCONCLUSIVE",
                metrics={
                    **base_metrics,
                    "test_cases": ["S3-TC11"],
                    "valid_point_count": len(valid_samples),
                    "points_excluded": points_excluded,
                    "excluded_fraction": excluded_fraction,
                    "cross_code_pass": False,
                    "numeric_coercion_performed": False,
                    "failure_reason": "INSUFFICIENT_VALID_POINTS",
                },
            )

        agreement = S3StatisticsLibrary.chi_square_z_agreement(
            observed=tuple(sample["pipeline_value"] for sample in valid_samples),
            expected=tuple(sample["reference_value"] for sample in valid_samples),
            observed_uncertainty=tuple(sample["pipeline_uncertainty"] for sample in valid_samples),
            expected_uncertainty=tuple(sample["reference_uncertainty"] for sample in valid_samples),
            max_abs_z=z_max,
            max_reduced_chi_square=reduced_max,
            alpha=alpha,
        )
        cross_code_pass = (
            reduced_min <= agreement.reduced_chi_square <= reduced_max
            and agreement.max_observed_abs_z <= z_max
        )
        return CheckResult(
            check="CROSS_CODE",
            status="PASS" if cross_code_pass else "FAIL",
            metrics={
                **base_metrics,
                "test_cases": ["S3-TC09"] if cross_code_pass else ["S3-TC10"],
                "valid_point_count": len(valid_samples),
                "points_excluded": points_excluded,
                "excluded_fraction": excluded_fraction,
                "chi_square": agreement.chi_square,
                "dof": agreement.dof,
                "reduced_chi_square": agreement.reduced_chi_square,
                "max_abs_z": agreement.max_observed_abs_z,
                "p_value": agreement.p_value,
                "agreement_method": agreement.method,
                "cross_code_pass": cross_code_pass,
                "numeric_coercion_performed": False,
                "failure_reason": None if cross_code_pass else "AGREEMENT_OUT_OF_BOUNDS",
            },
        )


class S3PhysicalConsistencyCheckPlugin:
    """Concrete PHYSICAL_CONSISTENCY check plugin for S3-TC12/13/14/15/16."""

    def __init__(
        self,
        *,
        samples: tuple[S3PhysicalConsistencySample, ...],
        plugin_version: str = "1.0.0",
        units_algebra: UnitsAlgebra | None = None,
    ) -> None:
        self._samples = tuple(samples)
        self._plugin_version = plugin_version
        self._units_algebra = units_algebra or UnitsAlgebra()

    def describe(self) -> CheckPluginDescriptor:
        return CheckPluginDescriptor(
            check="PHYSICAL_CONSISTENCY",
            plugin_ref="argus.s3.plugins.physical_consistency",
            plugin_version=self._plugin_version,
            determinism="deterministic",
            declared_inputs=(
                "c2.units_contract",
                "s3.frozen_pipeline_observations",
                "s3.physical_consistency_profile",
            ),
        )

    def run(self, ctx: CheckPluginContext) -> CheckResult:
        if ctx.check_spec.check != "PHYSICAL_CONSISTENCY":
            _s3_physical_consistency_error(
                "S3_PHYSICAL_CONSISTENCY_CHECK_SPEC_MISMATCH",
                f"physical-consistency plugin cannot run {ctx.check_spec.check}",
            )
        samples = _s3_physical_consistency_samples(self._samples)
        mandatory_gates = _s3_physical_consistency_mandatory_gates(
            ctx.check_spec.thresholds.get("mandatory_gates"),
        )
        normalization_epsilon = _s3_physical_consistency_non_negative(
            ctx.check_spec.thresholds.get("normalization_epsilon", 0.0),
            field="normalization_epsilon",
        )
        absolute_tolerance = _s3_physical_consistency_optional_non_negative(
            ctx.check_spec.tolerance.get("absolute_tolerance"),
            field="absolute_tolerance",
        )
        relative_tolerance = _s3_physical_consistency_optional_non_negative(
            ctx.check_spec.tolerance.get("relative_tolerance"),
            field="relative_tolerance",
        )
        if ("symmetry" in mandatory_gates or "asymptotic" in mandatory_gates) and (
            absolute_tolerance is None and relative_tolerance is None
        ):
            _s3_physical_consistency_error(
                "S3_PHYSICAL_CONSISTENCY_TOLERANCE_REQUIRED",
                "PHYSICAL_CONSISTENCY symmetry/asymptotic gates require absolute_tolerance or relative_tolerance",
            )

        sub_gates = {
            "dimensional": _s3_physical_consistency_dimensional_gate(
                samples=samples,
                units_algebra=self._units_algebra,
            ),
            "positivity": _s3_physical_consistency_positivity_gate(samples),
            "normalization": _s3_physical_consistency_normalization_gate(
                samples=samples,
                epsilon=normalization_epsilon,
            ),
            "symmetry": _s3_physical_consistency_symmetry_gate(
                samples=samples,
                absolute_tolerance=absolute_tolerance,
                relative_tolerance=relative_tolerance,
            ),
            "asymptotic": _s3_physical_consistency_asymptotic_gate(
                samples=samples,
                absolute_tolerance=absolute_tolerance,
                relative_tolerance=relative_tolerance,
            ),
        }
        _s3_physical_consistency_assert_mandatory_gates(mandatory_gates, sub_gates)
        failed_mandatory = tuple(gate for gate in mandatory_gates if sub_gates[gate]["status"] != "PASS")
        physical_consistency_pass = not failed_mandatory
        failure_reasons = [
            _S3_PHYSICAL_CONSISTENCY_FAILURE_REASONS[gate]
            for gate in failed_mandatory
        ]
        test_cases = _s3_physical_consistency_test_cases(
            mandatory_gates=mandatory_gates,
            failed_gates=failed_mandatory,
        )

        return CheckResult(
            check="PHYSICAL_CONSISTENCY",
            status="PASS" if physical_consistency_pass else "FAIL",
            metrics={
                "test_cases": test_cases,
                "sample_count": len(samples),
                "sample_digest": _s3_physical_consistency_samples_digest(samples),
                "mandatory_gates": list(mandatory_gates),
                "physical_consistency_pass": physical_consistency_pass,
                "failure_reasons": failure_reasons,
                "sub_gates": sub_gates,
                "normalization_epsilon": normalization_epsilon,
                "absolute_tolerance": absolute_tolerance,
                "relative_tolerance": relative_tolerance,
                "units_algebra": "argus.s3.units_algebra.v1",
            },
        )


class CheckPluginHost:
    """Runs compiled S3 check plugins with dependency-aware concurrency and C4 evidence."""

    def __init__(
        self,
        *,
        plugins: tuple[CheckPlugin, ...],
        artifact_store: InMemoryArtifactStore | None = None,
        max_workers: int | None = None,
        actor_id: str = "s3-check-plugin-host",
        job_id: str | None = None,
        trace_id: str | None = None,
    ) -> None:
        if max_workers is not None and max_workers < 1:
            _check_host_error(
                category="POLICY",
                code="CHECK_PLUGIN_MAX_WORKERS_INVALID",
                message="max_workers must be positive",
                before_execution=True,
            )
        self._plugins = tuple(plugins)
        self._artifact_store = artifact_store
        self._max_workers = max_workers
        self._actor_id = actor_id
        self._job_id = job_id
        self._trace_id = trace_id

    def run(self, compiled_profile: CompiledProfile) -> tuple[CheckResult, ...]:
        specs_by_check = _check_host_profile_specs(compiled_profile)
        plugin_entries = _check_host_plugin_entries(self._plugins)
        dependencies_by_check = _check_host_dependencies(
            compiled_profile=compiled_profile,
            specs_by_check=specs_by_check,
            plugin_entries=plugin_entries,
        )
        _check_host_assert_acyclic(dependencies_by_check)

        pending = set(specs_by_check)
        completed: dict[str, CheckResult] = {}
        while pending:
            for check in tuple(pending):
                failed_dependencies = tuple(
                    dependency
                    for dependency in dependencies_by_check[check]
                    if dependency in completed and completed[dependency].status != "PASS"
                )
                if failed_dependencies:
                    _check_host_error(
                        category="CHECK_FAILED",
                        code="CHECK_PLUGIN_DEPENDENCY_FAILED",
                        message=(
                            f"{check} blocked by failed dependency checks: "
                            + ", ".join(sorted(failed_dependencies))
                        ),
                        before_execution=False,
                        partial_results=_check_host_ordered_results(compiled_profile, completed),
                    )

            ready = tuple(
                spec.check
                for spec in compiled_profile.checks
                if spec.check in pending and set(dependencies_by_check[spec.check]).issubset(completed)
            )
            if not ready:
                _check_host_error(
                    category="POLICY",
                    code="CHECK_PLUGIN_DEPENDENCY_CYCLE",
                    message="check plugin dependency graph has no runnable node",
                    before_execution=True,
                )

            max_workers = min(len(ready), self._max_workers or len(ready))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(
                        self._run_one,
                        compiled_profile,
                        specs_by_check[check],
                        plugin_entries[check][0],
                        plugin_entries[check][1],
                        {dependency: completed[dependency] for dependency in dependencies_by_check[check]},
                    ): check
                    for check in ready
                }
                layer_results: dict[str, CheckResult] = {}
                for future in as_completed(futures):
                    check = futures[future]
                    try:
                        layer_results[check] = future.result()
                    except CheckPluginHostError as exc:
                        if exc.partial_results:
                            raise
                        _check_host_error(
                            category=exc.category,
                            code=exc.code,
                            message=exc.message,
                            before_execution=exc.before_execution,
                            partial_results=_check_host_ordered_results(compiled_profile, completed),
                        )
                    except Exception as exc:
                        _check_host_error(
                            category="CHECK_FAILED",
                            code="CHECK_PLUGIN_FAILED",
                            message=f"{check} plugin failed: {exc}",
                            before_execution=False,
                            partial_results=_check_host_ordered_results(compiled_profile, completed),
                        )

            for check in ready:
                completed[check] = layer_results[check]
                pending.remove(check)

        return _check_host_ordered_results(compiled_profile, completed)

    def _run_one(
        self,
        compiled_profile: CompiledProfile,
        check_spec: CompiledCheckSpec,
        plugin: CheckPlugin,
        descriptor: CheckPluginDescriptor,
        completed_results: dict[str, CheckResult],
    ) -> CheckResult:
        ctx = CheckPluginContext(
            compiled_profile=compiled_profile,
            check_spec=check_spec,
            completed_results=dict(completed_results),
            artifact_store=self._artifact_store,
            actor_id=self._actor_id,
            job_id=self._job_id,
            trace_id=self._trace_id,
        )
        result = plugin.run(ctx)
        if not isinstance(result, CheckResult):
            _check_host_error(
                category="CHECK_FAILED",
                code="CHECK_PLUGIN_INVALID_RESULT",
                message=f"{check_spec.check} plugin did not return CheckResult",
                before_execution=False,
                partial_results=tuple(completed_results.values()),
            )
        if result.check != check_spec.check:
            _check_host_error(
                category="CHECK_FAILED",
                code="CHECK_PLUGIN_RESULT_CHECK_MISMATCH",
                message=f"{check_spec.check} plugin returned result for {result.check}",
                before_execution=False,
                partial_results=tuple(completed_results.values()),
            )
        if result.status not in {"PASS", "FAIL", "INCONCLUSIVE"}:
            _check_host_error(
                category="CHECK_FAILED",
                code="CHECK_PLUGIN_RESULT_STATUS_INVALID",
                message=f"{check_spec.check} plugin returned unsupported status {result.status}",
                before_execution=False,
                partial_results=tuple(completed_results.values()),
            )
        enriched = replace(
            result,
            plugin_ref=descriptor.plugin_ref,
            plugin_version=descriptor.plugin_version,
            dependencies=descriptor.dependencies,
        )
        return self._write_evidence(compiled_profile, check_spec, descriptor, enriched, completed_results)

    def _write_evidence(
        self,
        compiled_profile: CompiledProfile,
        check_spec: CompiledCheckSpec,
        descriptor: CheckPluginDescriptor,
        result: CheckResult,
        completed_results: dict[str, CheckResult],
    ) -> CheckResult:
        if self._artifact_store is None:
            return result
        dependency_refs = {
            check: dependency_result.evidence_ref
            for check, dependency_result in completed_results.items()
            if dependency_result.evidence_ref is not None
        }
        payload = {
            "schema": S3_CHECK_RESULT_EVIDENCE_SCHEMA,
            "profile_id": compiled_profile.profile_id,
            "profile_revision": compiled_profile.revision,
            "profile_ref": compiled_profile.profile_ref,
            "profile_spec_hash": compiled_profile.spec_hash,
            "subtopic": compiled_profile.subtopic,
            "check": result.check,
            "status": result.status,
            "metrics": _check_host_json_value(result.metrics or {}, path="metrics"),
            "plugin_ref": descriptor.plugin_ref,
            "plugin_version": descriptor.plugin_version,
            "determinism": descriptor.determinism,
            "declared_inputs": list(descriptor.declared_inputs),
            "dependencies": list(descriptor.dependencies),
            "dependency_evidence_refs": dependency_refs,
            "thresholds": _check_host_json_value(check_spec.thresholds, path="thresholds"),
            "budget": _check_host_json_value(check_spec.budget, path="budget"),
            "seed": check_spec.seed,
            "tolerance": _check_host_json_value(check_spec.tolerance, path="tolerance"),
            "requires_independence": check_spec.requires_independence,
            "trace_id": self._trace_id,
        }
        input_refs = [compiled_profile.profile_ref]
        if check_spec.adapter is not None:
            input_refs.append(check_spec.adapter.provenance_ref)
            input_refs.append(check_spec.adapter.c5_provenance_ref)
        input_refs.extend(ref for ref in dependency_refs.values() if ref is not None)
        lineage = Lineage(
            input_refs=tuple(dict.fromkeys(input_refs)),
            code_ref=f"{descriptor.plugin_ref}@{descriptor.plugin_version}",
            environment_digest=hash_json(
                {
                    "host": S3_CHECK_PLUGIN_HOST_VERSION,
                    "plugin_ref": descriptor.plugin_ref,
                    "plugin_version": descriptor.plugin_version,
                    "determinism": descriptor.determinism,
                }
            ),
            seeds=(str(check_spec.seed),) if check_spec.seed is not None else (),
            actor_id=self._actor_id,
            job_id=self._job_id,
        )
        record = self._artifact_store.create_artifact(
            kind=S3_CHECK_RESULT_EVIDENCE_KIND,
            payload=payload,
            producer=Producer(
                subsystem="S3",
                version=S3_CHECK_PLUGIN_HOST_VERSION,
                actor_id=self._actor_id,
                job_id=self._job_id,
            ),
            lineage=lineage,
        )
        return replace(result, evidence_ref=record.artifact_ref)


class InMemoryBlindDataVault:
    """Verifier-zone-only blind-data vault used by S3-T12 local flows."""

    def __init__(
        self,
        *,
        artifact_store: InMemoryArtifactStore,
        audit_ledger: Any | None = None,
        actor_id: str = "s3-blind-data-vault",
    ) -> None:
        if artifact_store is None:
            _blind_error(code="S3_ARTIFACT_STORE_REQUIRED", message="Blind-data vault requires artifact_store")
        self._artifact_store = artifact_store
        self._audit_ledger = audit_ledger
        self._actor_id = actor_id
        self._entries: dict[str, _BlindDatasetEntry] = {}

    def register_dataset(
        self,
        *,
        dataset_id: str,
        version: str,
        split: str,
        dataset_kind: str,
        opaque_input: Any,
        truth: Any,
        expected_opaque_input_hash: str | None = None,
        expected_truth_hash: str | None = None,
    ) -> BlindDatasetRecord:
        dataset_id = _blind_non_empty(dataset_id, "dataset_id")
        version = _blind_non_empty(version, "version")
        split = _blind_non_empty(split, "split")
        dataset_kind = _blind_non_empty(dataset_kind, "dataset_kind")
        handle = f"blind://vault/{dataset_id}/{version}/{split}"
        if handle in self._entries:
            _blind_error(
                code="S3_BLIND_DATA_HANDLE_EXISTS",
                message=f"blind dataset already exists for handle {handle}",
            )
        _blind_assert_no_label_material(
            opaque_input,
            code="S3_BLIND_OPAQUE_INPUT_LABEL_MATERIAL_FORBIDDEN",
            path="opaque_input",
        )
        opaque_payload = _blind_json_value(opaque_input, path="opaque_input")
        truth_payload = _blind_json_value(truth, path="truth")
        opaque_input_hash = hash_json(opaque_payload)
        truth_hash = hash_json(truth_payload)
        expected_opaque_input_hash = _blind_hash_or_default(
            expected_opaque_input_hash,
            opaque_input_hash,
            "expected_opaque_input_hash",
        )
        expected_truth_hash = _blind_hash_or_default(expected_truth_hash, truth_hash, "expected_truth_hash")
        handle_hash = hash_json({"blind_data_handle": handle})
        metadata_payload = {
            "schema": S3_BLIND_DATA_METADATA_SCHEMA,
            "vault_version": S3_BLIND_DATA_VAULT_VERSION,
            "dataset_id": dataset_id,
            "version": version,
            "split": split,
            "dataset_kind": dataset_kind,
            "handle_hash": handle_hash,
            "opaque_input_hash": opaque_input_hash,
            "truth_hash": truth_hash,
            "expected_opaque_input_hash": expected_opaque_input_hash,
            "expected_truth_hash": expected_truth_hash,
            "truth_material_stored_server_side": True,
            "raw_truth_in_c4": False,
        }
        metadata_record = self._artifact_store.create_artifact(
            kind=S3_BLIND_DATA_METADATA_KIND,
            payload=metadata_payload,
            producer=Producer(
                subsystem="S3",
                version=S3_BLIND_DATA_VAULT_VERSION,
                actor_id=self._actor_id,
            ),
            lineage=Lineage(
                input_refs=(),
                code_ref=S3_BLIND_DATA_VAULT_VERSION,
                environment_digest=hash_json(
                    {
                        "vault": S3_BLIND_DATA_VAULT_VERSION,
                        "kind": S3_BLIND_DATA_METADATA_KIND,
                    }
                ),
                actor_id=self._actor_id,
            ),
        )
        record = BlindDatasetRecord(
            handle=handle,
            handle_hash=handle_hash,
            dataset_id=dataset_id,
            version=version,
            split=split,
            dataset_kind=dataset_kind,
            opaque_input_hash=opaque_input_hash,
            truth_hash=truth_hash,
            expected_opaque_input_hash=expected_opaque_input_hash,
            expected_truth_hash=expected_truth_hash,
            metadata_ref=metadata_record.artifact_ref,
        )
        self._entries[handle] = _BlindDatasetEntry(record=record, opaque_input=opaque_payload, truth=truth_payload)
        return record

    def resolve(self, handle: str) -> BlindDatasetRecord:
        entry = self._entry(handle)
        return entry.record

    def truth_for_scoring(self, handle: str) -> Any:
        entry = self._entry(handle)
        return json.loads(canonical_json_bytes(entry.truth).decode("utf-8"))

    def _entry(self, handle: str) -> _BlindDatasetEntry:
        handle = _blind_non_empty(handle, "blind_data_handle")
        try:
            return self._entries[handle]
        except KeyError:
            _blind_error(
                code="S3_BLIND_DATA_HANDLE_NOT_FOUND",
                message=f"blind dataset handle was not found: {handle}",
            )


class S3BlindDataManager:
    """Stages verifier-zone blind data as sandbox-visible opaque input artifacts."""

    def __init__(
        self,
        *,
        artifact_store: InMemoryArtifactStore,
        vault: InMemoryBlindDataVault,
        audit_ledger: Any | None = None,
        actor_id: str = "s3-blind-data-manager",
    ) -> None:
        if artifact_store is None:
            _blind_error(code="S3_ARTIFACT_STORE_REQUIRED", message="Blind-data manager requires artifact_store")
        if not isinstance(vault, InMemoryBlindDataVault):
            _blind_error(code="S3_BLIND_DATA_VAULT_REQUIRED", message="Blind-data manager requires a vault")
        self._artifact_store = artifact_store
        self._vault = vault
        self._audit_ledger = audit_ledger
        self._actor_id = actor_id

    def stage_for_pipeline(self, *, blind_data_handle: str, job_id: str, trace_id: str | None = None) -> BlindDataStage:
        job_id = _blind_non_empty(job_id, "job_id")
        entry = self._vault._entry(blind_data_handle)
        record = entry.record
        mismatch = _blind_integrity_mismatch(record)
        if mismatch is not None:
            quarantine_ref = self._write_quarantine(record=record, mismatch=mismatch, job_id=job_id, trace_id=trace_id)
            raise S3BlindDataVaultError(
                category="QUARANTINE",
                code="S3_BLIND_DATA_HASH_MISMATCH",
                message=f"blind dataset integrity mismatch for {mismatch['field']}",
                quarantine_ref=quarantine_ref,
                retryable=False,
            )

        opaque_payload = {
            "schema": S3_BLIND_OPAQUE_INPUT_SCHEMA,
            "vault_version": S3_BLIND_DATA_VAULT_VERSION,
            "handle_hash": record.handle_hash,
            "dataset_id": record.dataset_id,
            "version": record.version,
            "split": record.split,
            "dataset_kind": record.dataset_kind,
            "opaque_input": _blind_json_value(entry.opaque_input, path="opaque_input"),
            "opaque_input_hash": record.opaque_input_hash,
            "truth_bytes_present": False,
            "truth_hash_present": False,
        }
        opaque_record = self._artifact_store.create_artifact(
            kind=S3_BLIND_OPAQUE_INPUT_KIND,
            payload=opaque_payload,
            producer=Producer(
                subsystem="S3",
                version=S3_BLIND_DATA_VAULT_VERSION,
                actor_id=self._actor_id,
                job_id=job_id,
            ),
            lineage=Lineage(
                input_refs=(record.metadata_ref,),
                code_ref=S3_BLIND_DATA_VAULT_VERSION,
                environment_digest=hash_json(
                    {
                        "vault": S3_BLIND_DATA_VAULT_VERSION,
                        "kind": S3_BLIND_OPAQUE_INPUT_KIND,
                    }
                ),
                actor_id=self._actor_id,
                job_id=job_id,
            ),
        )
        stage_payload = {
            "schema": S3_BLIND_DATA_STAGE_SCHEMA,
            "vault_version": S3_BLIND_DATA_VAULT_VERSION,
            "status": "STAGED",
            "handle_hash": record.handle_hash,
            "dataset_id": record.dataset_id,
            "version": record.version,
            "split": record.split,
            "dataset_kind": record.dataset_kind,
            "metadata_ref": record.metadata_ref,
            "opaque_input_ref": opaque_record.artifact_ref,
            "opaque_input_hash": record.opaque_input_hash,
            "truth_hash": record.truth_hash,
            "truth_retained_server_side": True,
            "truth_bytes_delivered_to_sandbox": False,
            "truth_hash_delivered_to_sandbox": False,
            "job_id": job_id,
            "trace_id": trace_id,
        }
        stage_record = self._artifact_store.create_artifact(
            kind=S3_BLIND_DATA_STAGE_KIND,
            payload=stage_payload,
            producer=Producer(
                subsystem="S3",
                version=S3_BLIND_DATA_VAULT_VERSION,
                actor_id=self._actor_id,
                job_id=job_id,
            ),
            lineage=Lineage(
                input_refs=(record.metadata_ref, opaque_record.artifact_ref),
                code_ref=S3_BLIND_DATA_VAULT_VERSION,
                environment_digest=hash_json(
                    {
                        "vault": S3_BLIND_DATA_VAULT_VERSION,
                        "kind": S3_BLIND_DATA_STAGE_KIND,
                    }
                ),
                actor_id=self._actor_id,
                job_id=job_id,
            ),
        )
        return BlindDataStage(
            blind_data_handle=record.handle,
            handle_hash=record.handle_hash,
            opaque_input_ref=opaque_record.artifact_ref,
            opaque_input_hash=record.opaque_input_hash,
            truth_hash=record.truth_hash,
            stage_evidence_ref=stage_record.artifact_ref,
        )

    def _write_quarantine(
        self,
        *,
        record: BlindDatasetRecord,
        mismatch: Mapping[str, Any],
        job_id: str,
        trace_id: str | None,
    ) -> str:
        payload = {
            "schema": S3_BLIND_DATA_QUARANTINE_SCHEMA,
            "vault_version": S3_BLIND_DATA_VAULT_VERSION,
            "status": "QUARANTINED",
            "handle_hash": record.handle_hash,
            "metadata_ref": record.metadata_ref,
            "mismatch": _blind_json_value(dict(mismatch), path="mismatch"),
            "quarantine": {
                "severity": "Sev-1",
                "reason": "S3:BLIND_HASH_MISMATCH",
            },
            "truth_bytes_delivered_to_sandbox": False,
            "truth_hash_delivered_to_sandbox": False,
            "job_id": job_id,
            "trace_id": trace_id,
        }
        quarantine_record = self._artifact_store.create_artifact(
            kind=S3_BLIND_DATA_QUARANTINE_KIND,
            payload=payload,
            producer=Producer(
                subsystem="S3",
                version=S3_BLIND_DATA_VAULT_VERSION,
                actor_id=self._actor_id,
                job_id=job_id,
            ),
            lineage=Lineage(
                input_refs=(record.metadata_ref,),
                code_ref=S3_BLIND_DATA_VAULT_VERSION,
                environment_digest=hash_json(
                    {
                        "vault": S3_BLIND_DATA_VAULT_VERSION,
                        "kind": S3_BLIND_DATA_QUARANTINE_KIND,
                    }
                ),
                actor_id=self._actor_id,
                job_id=job_id,
            ),
        )
        _blind_audit(
            self._audit_ledger,
            "s3.quarantine",
            {
                "severity": "Sev-1",
                "reason": "S3:BLIND_HASH_MISMATCH",
                "quarantine_ref": quarantine_record.artifact_ref,
                "handle_hash": record.handle_hash,
                "mismatch_field": mismatch.get("field"),
                "job_id": job_id,
            },
        )
        return quarantine_record.artifact_ref


@dataclass(frozen=True)
class S3FrozenPipelineRunResult:
    status: str
    evidence_ref: str
    sandbox_id: str
    sandbox_state: str
    launch_request: LaunchRequest


class S3FrozenPipelineRunner:
    """Launches frozen pipeline predict entrypoints only through a nested S10 sandbox."""

    def __init__(
        self,
        *,
        artifact_store: InMemoryArtifactStore,
        sandbox_orchestrator: Any,
        budget_token: BudgetToken,
        scope_token: ScopeToken,
        audit_ledger: Any | None = None,
        launch_envelope: LaunchEnvelope | None = None,
        blind_data_manager: S3BlindDataManager | None = None,
        actor_id: str = "s3-frozen-pipeline-runner",
    ) -> None:
        if artifact_store is None:
            _runner_error(code="S3_ARTIFACT_STORE_REQUIRED", message="S3 frozen-pipeline runner requires artifact_store")
        if sandbox_orchestrator is None:
            _runner_error(code="S10_SANDBOX_ORCHESTRATOR_REQUIRED", message="S3 frozen-pipeline runner requires S10")
        self._artifact_store = artifact_store
        self._sandbox_orchestrator = sandbox_orchestrator
        self._audit_ledger = audit_ledger
        self._budget_token = budget_token
        self._scope_token = scope_token
        self._launch_envelope = launch_envelope or LaunchEnvelope(
            cpu_m=1_000,
            mem_bytes=512_000_000,
            gpu_count=0,
            wallclock_s=30,
            scratch_bytes=1_000_000,
            pids=32,
            estimated_cost_usd=0.01,
        )
        self._blind_data_manager = blind_data_manager
        self._actor_id = actor_id

    def run(self, validation_request: Mapping[str, Any]) -> S3FrozenPipelineRunResult:
        blind_data_stage = self._stage_blind_data(validation_request)
        if blind_data_stage is not None:
            validation_request = _runner_request_with_blind_stage(validation_request, blind_data_stage)
        entrypoint_request = build_frozen_pipeline_entrypoint_request(
            validation_request,
            artifact_store=self._artifact_store,
        )
        verification_request = _runner_mapping(entrypoint_request.get("verification_request"), "verification_request")
        frozen_pipeline_ref = _non_empty_string(
            verification_request.get("frozen_pipeline_ref"),
            "frozen_pipeline_ref",
            code="S3_FROZEN_PIPELINE_REF_INVALID",
        )
        pipeline_payload = _frozen_pipeline_payload(self._artifact_store, frozen_pipeline_ref)
        security_probe = _runner_security_probe(pipeline_payload)
        launch_request = self._launch_request(
            entrypoint_request=entrypoint_request,
            pipeline_payload=pipeline_payload,
            security_probe=security_probe,
        )
        event_start = _runner_audit_len(self._audit_ledger)
        execution = self._launch_nested_s10(launch_request)
        audit_events = _runner_audit_events_since(self._audit_ledger, event_start)
        evidence_ref = self._write_evidence(
            entrypoint_request=entrypoint_request,
            pipeline_payload=pipeline_payload,
            security_probe=security_probe,
            launch_request=launch_request,
            execution=execution,
            audit_events=audit_events,
            blind_data_stage=blind_data_stage,
        )
        return S3FrozenPipelineRunResult(
            status=_runner_status(execution),
            evidence_ref=evidence_ref,
            sandbox_id=execution.handle.sandbox_id,
            sandbox_state=execution.handle.state,
            launch_request=launch_request,
        )

    def _stage_blind_data(self, validation_request: Mapping[str, Any]) -> BlindDataStage | None:
        if self._blind_data_manager is None:
            return None
        request_payload = _runner_mapping(validation_request, "validation_request")
        blind_data_handle = _blind_data_handle(request_payload)
        job_id = _non_empty_string(
            request_payload.get("job_id"),
            "job_id",
            code="S3_VERIFICATION_REQUEST_FIELD_REQUIRED",
        )
        trace_id = _optional_non_empty_string(request_payload.get("trace_id"), "trace_id")
        return self._blind_data_manager.stage_for_pipeline(
            blind_data_handle=blind_data_handle,
            job_id=job_id,
            trace_id=trace_id,
        )

    def _launch_request(
        self,
        *,
        entrypoint_request: Mapping[str, Any],
        pipeline_payload: Mapping[str, Any],
        security_probe: Mapping[str, Any],
    ) -> LaunchRequest:
        verification_request = _runner_mapping(entrypoint_request.get("verification_request"), "verification_request")
        job_id = _non_empty_string(
            verification_request.get("job_id"),
            "job_id",
            code="S3_VERIFICATION_REQUEST_FIELD_REQUIRED",
        )
        trace_id = str(entrypoint_request.get("trace_id") or verification_request.get("request_id") or job_id)
        args = (
            "--entrypoint-request-json",
            canonical_json_bytes(entrypoint_request).decode("utf-8"),
        )
        if security_probe:
            args = args + ("--security-probe-json", canonical_json_bytes(security_probe).decode("utf-8"))
        return LaunchRequest(
            job_id=job_id,
            subagent_id=self._actor_id,
            trace_id=trace_id,
            budget_token=self._budget_token,
            scope_token=self._scope_token,
            image=_runner_image(pipeline_payload),
            entrypoint=S3_FROZEN_PIPELINE_RUNNER_ENTRYPOINT,
            args=args,
            env={},
            env_allowlist=(),
            requested_envelope=self._launch_envelope,
            runtime_class_hint="auto",
        )

    def _launch_nested_s10(self, launch_request: LaunchRequest) -> SandboxExecutionResult:
        launch_and_wait = getattr(self._sandbox_orchestrator, "launch_and_wait", None)
        if callable(launch_and_wait):
            try:
                execution = launch_and_wait(launch_request)
            except Exception as exc:
                raise S3FrozenPipelineRunnerError(
                    category="SANDBOX",
                    code="S10_SANDBOX_LAUNCH_FAILED",
                    message=f"S10 sandbox launch failed: {exc}",
                    before_execution=False,
                ) from exc
            if not isinstance(execution, SandboxExecutionResult):
                raise S3FrozenPipelineRunnerError(
                    category="SANDBOX",
                    code="S10_SANDBOX_RESULT_INVALID",
                    message="S10 launch_and_wait returned an invalid result",
                    before_execution=False,
                )
            return execution

        launch = getattr(self._sandbox_orchestrator, "launch", None)
        if not callable(launch):
            _runner_error(
                category="SANDBOX",
                code="S10_SANDBOX_ORCHESTRATOR_INVALID",
                message="S10 sandbox orchestrator must expose launch_and_wait or launch",
            )
        try:
            handle = launch(launch_request)
        except Exception as exc:
            raise S3FrozenPipelineRunnerError(
                category="SANDBOX",
                code="S10_SANDBOX_LAUNCH_FAILED",
                message=f"S10 sandbox launch failed: {exc}",
                before_execution=False,
            ) from exc
        return SandboxExecutionResult(
            handle=handle,
            exit_code=None,
            stdout="",
            stderr="",
            timed_out=False,
            duration_s=0.0,
            budget_usage=BudgetUsage(),
            partial_result=None,
        )

    def _write_evidence(
        self,
        *,
        entrypoint_request: Mapping[str, Any],
        pipeline_payload: Mapping[str, Any],
        security_probe: Mapping[str, Any],
        launch_request: LaunchRequest,
        execution: SandboxExecutionResult,
        audit_events: tuple[Any, ...],
        blind_data_stage: BlindDataStage | None,
    ) -> str:
        status = _runner_status(execution)
        partial = execution.partial_result
        audit_event_types = tuple(str(getattr(event, "event_type", "")) for event in audit_events)
        quarantine = _runner_quarantine_payload(execution, audit_events)
        egress = _runner_egress_payload(execution, audit_events, security_probe)
        payload = {
            "schema": S3_FROZEN_PIPELINE_RUN_EVIDENCE_SCHEMA,
            "runner_version": S3_FROZEN_PIPELINE_RUNNER_VERSION,
            "status": status,
            "execution_boundary": "nested_s10_sandbox",
            "verifier_imported_pipeline_code": False,
            "entrypoint_request": _runner_json_value(entrypoint_request, path="entrypoint_request"),
            "launch_request": _runner_launch_payload(launch_request),
            "sandbox": {
                "sandbox_id": execution.handle.sandbox_id,
                "state": execution.handle.state,
                "runtime_class": execution.handle.runtime_class,
                "policy_bundle_version": execution.handle.policy_bundle_version,
                "launch_provenance_ref": execution.handle.launch_provenance_ref,
                "exit_code": execution.exit_code,
                "timed_out": execution.timed_out,
                "duration_s": execution.duration_s,
            },
            "quarantine": quarantine,
            "egress": egress,
            "blind_data_stage": _runner_blind_data_stage_payload(blind_data_stage),
            "partial_result": _runner_partial_payload(partial),
            "audit_event_types": list(audit_event_types),
            "s3_test_cases": {
                "S3-TC25": {
                    "status": "PASS",
                    "assertion": "frozen pipeline launched through nested S10 sandbox; verifier imported no pipeline code",
                },
                "S3-TC26": _runner_tc26_status(blind_data_stage),
                "S3-TC27": _runner_tc27_status(quarantine),
                "S3-TC44": _runner_tc44_status(egress),
            },
        }
        input_refs = [str(entrypoint_request["verification_request"]["frozen_pipeline_ref"])]
        input_refs.extend(str(ref) for ref in entrypoint_request.get("artifact_refs", ()) if isinstance(ref, str))
        if blind_data_stage is not None:
            input_refs.append(blind_data_stage.stage_evidence_ref)
            input_refs.append(blind_data_stage.opaque_input_ref)
        if execution.handle.launch_provenance_ref:
            input_refs.append(execution.handle.launch_provenance_ref)
        record = self._artifact_store.create_artifact(
            kind=S3_FROZEN_PIPELINE_RUN_EVIDENCE_KIND,
            payload=payload,
            producer=Producer(
                subsystem="S3",
                version=S3_FROZEN_PIPELINE_RUNNER_VERSION,
                actor_id=self._actor_id,
                job_id=launch_request.job_id,
            ),
            lineage=Lineage(
                input_refs=tuple(dict.fromkeys(input_refs)),
                code_ref=str(pipeline_payload.get("code_ref") or entrypoint_request["entrypoint"].get("code_ref")),
                environment_digest=hash_json(
                    {
                        "runner": S3_FROZEN_PIPELINE_RUNNER_VERSION,
                        "image": launch_request.image,
                        "entrypoint": list(launch_request.entrypoint),
                        "args_hash": hash_bytes(canonical_json_bytes(list(launch_request.args))),
                    }
                ),
                seeds=(launch_request.trace_id,),
                actor_id=self._actor_id,
                job_id=launch_request.job_id,
            ),
        )
        return record.artifact_ref


def _blind_error(
    *,
    code: str,
    message: str,
    category: str = "POLICY",
    quarantine_ref: str | None = None,
) -> None:
    raise S3BlindDataVaultError(
        category=category,
        code=code,
        message=message,
        quarantine_ref=quarantine_ref,
    )


def _blind_non_empty(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        _blind_error(code="S3_BLIND_DATA_FIELD_REQUIRED", message=f"{field_name} must be a non-empty string")
    return value


def _blind_hash_or_default(value: Any, default: str, field_name: str) -> str:
    if value is None:
        return default
    if not isinstance(value, str) or not value.startswith("blake3:"):
        _blind_error(code="S3_BLIND_DATA_HASH_INVALID", message=f"{field_name} must be a BLAKE3 hash")
    return value


def _blind_assert_no_label_material(value: Any, *, code: str, path: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key).lower()
            if key_text in S3_FORBIDDEN_LABEL_MATERIAL_FIELDS:
                _blind_error(code=code, message=f"{path}.{key} contains forbidden label or truth material")
            _blind_assert_no_label_material(item, code=code, path=f"{path}.{key}")
    elif isinstance(value, list | tuple):
        for index, item in enumerate(value):
            _blind_assert_no_label_material(item, code=code, path=f"{path}[{index}]")


def _blind_json_value(value: Any, *, path: str) -> Any:
    if isinstance(value, Mapping):
        payload: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                _blind_error(code="S3_BLIND_DATA_JSON_INVALID", message=f"{path} contains a non-string key")
            payload[key] = _blind_json_value(item, path=f"{path}.{key}")
        return payload
    if isinstance(value, tuple):
        return [_blind_json_value(item, path=f"{path}[]") for item in value]
    if isinstance(value, list):
        return [_blind_json_value(item, path=f"{path}[]") for item in value]
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            _blind_error(code="S3_BLIND_DATA_JSON_INVALID", message=f"{path} contains a non-finite number")
        return value
    _blind_error(
        code="S3_BLIND_DATA_JSON_INVALID",
        message=f"{path} contains non-JSON value of type {type(value).__name__}",
    )


def _blind_integrity_mismatch(record: BlindDatasetRecord) -> dict[str, str] | None:
    if record.expected_opaque_input_hash != record.opaque_input_hash:
        return {
            "field": "opaque_input_hash",
            "expected_hash": record.expected_opaque_input_hash,
            "actual_hash": record.opaque_input_hash,
        }
    if record.expected_truth_hash != record.truth_hash:
        return {
            "field": "truth_hash",
            "expected_hash": record.expected_truth_hash,
            "actual_hash": record.truth_hash,
        }
    return None


def _blind_audit(audit_ledger: Any | None, event_type: str, payload: Mapping[str, Any]) -> None:
    if audit_ledger is None:
        return
    append = getattr(audit_ledger, "append", None)
    if not callable(append):
        return
    try:
        append(event_type, dict(payload))
    except Exception:
        return


def _runner_request_with_blind_stage(
    validation_request: Mapping[str, Any],
    blind_data_stage: BlindDataStage,
) -> dict[str, Any]:
    request = _runner_mapping(validation_request, "validation_request")
    request["blind_data_handle"] = blind_data_stage.opaque_input_ref
    if "blind_dataset_handle" in request:
        request["blind_dataset_handle"] = blind_data_stage.opaque_input_ref
    artifact_refs = list(request.get("artifact_refs") or [])
    artifact_refs.append(blind_data_stage.opaque_input_ref)
    request["artifact_refs"] = list(dict.fromkeys(str(ref) for ref in artifact_refs))
    return request


def _runner_blind_data_stage_payload(stage: BlindDataStage | None) -> dict[str, Any] | None:
    if stage is None:
        return None
    return {
        "stage_evidence_ref": stage.stage_evidence_ref,
        "handle_hash": stage.handle_hash,
        "vault_handle_hash": stage.handle_hash,
        "opaque_input_ref": stage.opaque_input_ref,
        "opaque_input_hash": stage.opaque_input_hash,
        "truth_hash": stage.truth_hash,
        "truth_retained_server_side": stage.truth_retained_server_side,
        "truth_bytes_delivered_to_sandbox": stage.truth_bytes_delivered_to_sandbox,
        "truth_hash_delivered_to_sandbox": stage.truth_hash_delivered_to_sandbox,
    }


def _runner_tc26_status(stage: BlindDataStage | None) -> dict[str, str]:
    if (
        stage is not None
        and stage.truth_retained_server_side
        and not stage.truth_bytes_delivered_to_sandbox
        and not stage.truth_hash_delivered_to_sandbox
    ):
        return {"status": "PASS", "assertion": "only opaque blind input was staged into the nested sandbox"}
    return {"status": "NOT_EVALUATED", "assertion": "no blind-data manager was configured for this run"}


def _runner_error(
    *,
    code: str,
    message: str,
    category: str = "POLICY",
    before_execution: bool = True,
) -> None:
    raise S3FrozenPipelineRunnerError(
        category=category,
        code=code,
        message=message,
        before_execution=before_execution,
    )


def _runner_mapping(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _runner_error(code="S3_FROZEN_PIPELINE_RUNNER_PAYLOAD_INVALID", message=f"{field_name} must be a mapping")
    return dict(value)


def _runner_security_probe(pipeline_payload: Mapping[str, Any]) -> dict[str, Any]:
    config = pipeline_payload.get("config")
    if not isinstance(config, Mapping):
        return {}
    probe = config.get("s3_t10_probe")
    if probe is None:
        return {}
    if not isinstance(probe, Mapping):
        _runner_error(
            code="S3_FROZEN_PIPELINE_SECURITY_PROBE_INVALID",
            message="s3_t10_probe must be a JSON object when present",
        )
    return _runner_json_value(probe, path="s3_t10_probe")


def _runner_image(pipeline_payload: Mapping[str, Any]) -> str:
    raw = pipeline_payload.get("container_digest") or pipeline_payload.get("image")
    if not isinstance(raw, str) or not raw:
        _runner_error(
            code="S3_FROZEN_PIPELINE_IMAGE_REQUIRED",
            message="frozen pipeline payload requires a digest-pinned container_digest or image",
        )
    digest_source = raw.strip()
    if "@sha256:" in digest_source:
        digest = digest_source.rsplit("@sha256:", 1)[1]
    elif "sha256:" in digest_source:
        digest = digest_source.rsplit("sha256:", 1)[1]
    else:
        digest = digest_source
    digest = digest.strip()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        _runner_error(
            code="S3_FROZEN_PIPELINE_IMAGE_UNPINNED",
            message="frozen pipeline image must be pinned to a sha256 digest",
        )
    return f"argus-s3-frozen-pipeline@sha256:{digest}"


def _runner_audit_len(audit_ledger: Any | None) -> int:
    if audit_ledger is None or not hasattr(audit_ledger, "events"):
        return 0
    try:
        return len(audit_ledger.events())
    except Exception:
        return 0


def _runner_audit_events_since(audit_ledger: Any | None, start: int) -> tuple[Any, ...]:
    if audit_ledger is None or not hasattr(audit_ledger, "events"):
        return ()
    try:
        return tuple(audit_ledger.events()[start:])
    except Exception:
        return ()


def _runner_status(execution: SandboxExecutionResult) -> str:
    partial_reason = execution.partial_result.reason if execution.partial_result is not None else ""
    if execution.handle.state == "QUARANTINED" or partial_reason.startswith("SANDBOX:"):
        return "QUARANTINED"
    if execution.handle.state == "SUCCEEDED" and execution.exit_code in (0, None):
        return "SUCCEEDED"
    if execution.handle.state in {"ADMITTED", "RUNNING"} and execution.exit_code is None:
        return execution.handle.state
    if execution.timed_out:
        return "TIMED_OUT"
    return "FAILED"


def _runner_launch_payload(request: LaunchRequest) -> dict[str, Any]:
    return {
        "job_id": request.job_id,
        "subagent_id": request.subagent_id,
        "trace_id": request.trace_id,
        "image": request.image,
        "entrypoint": list(request.entrypoint),
        "args": list(request.args),
        "env_keys": sorted(request.env),
        "env_allowlist": list(request.env_allowlist),
        "runtime_class_hint": request.runtime_class_hint,
        "budget_id": request.budget_token.budget_id,
        "scope_id": request.scope_token.scope_id,
        "requested_envelope": asdict(request.requested_envelope),
    }


def _runner_partial_payload(partial: Any | None) -> dict[str, Any] | None:
    if partial is None:
        return None
    return {
        "reason": partial.reason,
        "stdout": partial.stdout,
        "stderr": partial.stderr,
        "captured_after_freeze": partial.captured_after_freeze,
        "freeze_succeeded": partial.freeze_succeeded,
        "terminate_succeeded": partial.terminate_succeeded,
        "stdout_bytes": partial.stdout_bytes,
        "stderr_bytes": partial.stderr_bytes,
        "logs_truncated": partial.logs_truncated,
        "frozen_state": partial.frozen_state,
        "terminated_state": partial.terminated_state,
    }


def _runner_quarantine_payload(execution: SandboxExecutionResult, audit_events: tuple[Any, ...]) -> dict[str, Any] | None:
    partial = execution.partial_result
    if execution.handle.state != "QUARANTINED" and partial is None:
        return None
    severity = "Sev-1" if partial is not None and partial.reason in {"SANDBOX:TRUST_PATH_WRITE", "SANDBOX:EGRESS_DENIED"} else "Sev-2"
    for event in audit_events:
        if getattr(event, "event_type", "") == "s3.quarantine":
            payload = getattr(event, "payload", {})
            if isinstance(payload, Mapping) and isinstance(payload.get("severity"), str):
                severity = str(payload["severity"])
    return {
        "severity": severity,
        "reason": partial.reason if partial is not None else "SANDBOX:QUARANTINED",
        "stdout": partial.stdout if partial is not None else "",
        "stderr": partial.stderr if partial is not None else "",
    }


def _runner_egress_payload(
    execution: SandboxExecutionResult,
    audit_events: tuple[Any, ...],
    security_probe: Mapping[str, Any],
) -> dict[str, Any] | None:
    denied_dest = None
    allowed_bytes = None
    for event in audit_events:
        if getattr(event, "event_type", "") == "egress.denied":
            payload = getattr(event, "payload", {})
            if isinstance(payload, Mapping):
                if isinstance(payload.get("dest"), Mapping):
                    denied_dest = _runner_json_value(payload["dest"], path="egress.dest")
                allowed = payload.get("allowed_bytes")
                if isinstance(allowed, int):
                    allowed_bytes = allowed
    partial = execution.partial_result
    if denied_dest is None and isinstance(security_probe.get("egress"), Mapping):
        denied_dest = _runner_json_value(security_probe["egress"], path="s3_t10_probe.egress")
    if allowed_bytes is None and partial is not None and partial.reason == "SANDBOX:EGRESS_DENIED":
        allowed_bytes = 0
    if denied_dest is None and allowed_bytes is None:
        return None
    return {
        "denied_dest": denied_dest,
        "allowed_bytes": allowed_bytes if allowed_bytes is not None else 0,
    }


def _runner_tc27_status(quarantine: Mapping[str, Any] | None) -> dict[str, str]:
    if quarantine is not None and quarantine.get("reason") == "SANDBOX:TRUST_PATH_WRITE":
        return {"status": "PASS", "assertion": "verifier/trust mount write was denied and quarantined as Sev-1"}
    return {"status": "NOT_EVALUATED", "assertion": "no verifier/trust mount write probe was requested"}


def _runner_tc44_status(egress: Mapping[str, Any] | None) -> dict[str, str]:
    if egress is not None and egress.get("allowed_bytes") == 0:
        return {"status": "PASS", "assertion": "non-allowlisted egress was denied with zero allowed bytes"}
    return {"status": "NOT_EVALUATED", "assertion": "no non-allowlisted egress probe was requested"}


def _runner_json_value(value: Any, *, path: str) -> Any:
    if isinstance(value, Mapping):
        payload: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                _runner_error(
                    code="S3_FROZEN_PIPELINE_EVIDENCE_JSON_INVALID",
                    message=f"{path} contains a non-string key",
                )
            payload[key] = _runner_json_value(item, path=f"{path}.{key}")
        return payload
    if isinstance(value, tuple):
        return [_runner_json_value(item, path=f"{path}[]") for item in value]
    if isinstance(value, list):
        return [_runner_json_value(item, path=f"{path}[]") for item in value]
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            _runner_error(
                code="S3_FROZEN_PIPELINE_EVIDENCE_JSON_INVALID",
                message=f"{path} contains a non-finite number",
            )
        return value
    _runner_error(
        code="S3_FROZEN_PIPELINE_EVIDENCE_JSON_INVALID",
        message=f"{path} contains non-JSON value of type {type(value).__name__}",
    )


def _check_host_profile_specs(compiled_profile: CompiledProfile) -> dict[str, CompiledCheckSpec]:
    specs_by_check: dict[str, CompiledCheckSpec] = {}
    duplicates: list[str] = []
    for spec in compiled_profile.checks:
        _check_host_non_empty_string(spec.check, "check")
        if spec.check in specs_by_check:
            duplicates.append(spec.check)
            continue
        specs_by_check[spec.check] = spec
    if duplicates:
        _check_host_error(
            category="POLICY",
            code="CHECK_PLUGIN_DUPLICATE_CHECK",
            message="compiled profile contains duplicate checks: " + ", ".join(sorted(set(duplicates))),
            before_execution=True,
        )
    return specs_by_check


def _check_host_plugin_entries(
    plugins: tuple[CheckPlugin, ...],
) -> dict[str, tuple[CheckPlugin, CheckPluginDescriptor]]:
    entries: dict[str, tuple[CheckPlugin, CheckPluginDescriptor]] = {}
    duplicates: list[str] = []
    for plugin in plugins:
        try:
            descriptor = plugin.describe()
        except Exception as exc:
            _check_host_error(
                category="VERIFIER_UNAVAILABLE",
                code="CHECK_PLUGIN_DESCRIPTOR_FAILED",
                message=f"check plugin descriptor failed: {exc}",
                before_execution=True,
            )
        if not isinstance(descriptor, CheckPluginDescriptor):
            _check_host_error(
                category="VERIFIER_UNAVAILABLE",
                code="CHECK_PLUGIN_DESCRIPTOR_INVALID",
                message="check plugin describe() must return CheckPluginDescriptor",
                before_execution=True,
            )
        _check_host_descriptor_valid(descriptor)
        if descriptor.check in entries:
            duplicates.append(descriptor.check)
            continue
        entries[descriptor.check] = (plugin, descriptor)
    if duplicates:
        _check_host_error(
            category="POLICY",
            code="CHECK_PLUGIN_DUPLICATE_PLUGIN",
            message="multiple plugins registered for checks: " + ", ".join(sorted(set(duplicates))),
            before_execution=True,
        )
    return entries


def _check_host_dependencies(
    *,
    compiled_profile: CompiledProfile,
    specs_by_check: Mapping[str, CompiledCheckSpec],
    plugin_entries: Mapping[str, tuple[CheckPlugin, CheckPluginDescriptor]],
) -> dict[str, tuple[str, ...]]:
    dependencies_by_check: dict[str, tuple[str, ...]] = {}
    for spec in compiled_profile.checks:
        entry = plugin_entries.get(spec.check)
        if entry is None:
            _check_host_error(
                category="VERIFIER_UNAVAILABLE",
                code="CHECK_PLUGIN_UNAVAILABLE",
                message=f"compiled profile requires unavailable check plugin: {spec.check}",
                before_execution=True,
            )
        _plugin, descriptor = entry
        if descriptor.plugin_ref != spec.plugin_ref or descriptor.plugin_version != spec.plugin_version:
            _check_host_error(
                category="VERIFIER_UNAVAILABLE",
                code="CHECK_PLUGIN_DESCRIPTOR_MISMATCH",
                message=(
                    f"{spec.check} plugin descriptor does not match compiled spec "
                    f"{spec.plugin_ref}@{spec.plugin_version}"
                ),
                before_execution=True,
            )
        if descriptor.determinism != spec.determinism:
            _check_host_error(
                category="VERIFIER_UNAVAILABLE",
                code="CHECK_PLUGIN_DETERMINISM_MISMATCH",
                message=f"{spec.check} plugin determinism does not match compiled spec",
                before_execution=True,
            )
        seen_dependencies: list[str] = []
        for dependency in descriptor.dependencies:
            _check_host_non_empty_string(dependency, "dependency")
            if dependency == spec.check:
                _check_host_error(
                    category="POLICY",
                    code="CHECK_PLUGIN_DEPENDENCY_CYCLE",
                    message=f"{spec.check} depends on itself",
                    before_execution=True,
                )
            if dependency not in specs_by_check:
                _check_host_error(
                    category="POLICY",
                    code="CHECK_PLUGIN_DEPENDENCY_UNDECLARED",
                    message=f"{spec.check} depends on undeclared check {dependency}",
                    before_execution=True,
                )
            if dependency not in seen_dependencies:
                seen_dependencies.append(dependency)
        dependencies_by_check[spec.check] = tuple(seen_dependencies)
    return dependencies_by_check


def _check_host_assert_acyclic(dependencies_by_check: Mapping[str, tuple[str, ...]]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(check: str, path: tuple[str, ...]) -> None:
        if check in visiting:
            cycle = " -> ".join(path + (check,))
            _check_host_error(
                category="POLICY",
                code="CHECK_PLUGIN_DEPENDENCY_CYCLE",
                message=f"check plugin dependency cycle detected: {cycle}",
                before_execution=True,
            )
        if check in visited:
            return
        visiting.add(check)
        for dependency in dependencies_by_check.get(check, ()):
            visit(dependency, path + (check,))
        visiting.remove(check)
        visited.add(check)

    for check in sorted(dependencies_by_check):
        visit(check, ())


def _check_host_descriptor_valid(descriptor: CheckPluginDescriptor) -> None:
    _check_host_non_empty_string(descriptor.check, "check")
    _check_host_non_empty_string(descriptor.plugin_ref, "plugin_ref")
    _check_host_non_empty_string(descriptor.plugin_version, "plugin_version")
    _check_host_non_empty_string(descriptor.determinism, "determinism")
    if not isinstance(descriptor.dependencies, tuple) or not all(
        isinstance(dependency, str) and dependency for dependency in descriptor.dependencies
    ):
        _check_host_error(
            category="VERIFIER_UNAVAILABLE",
            code="CHECK_PLUGIN_DESCRIPTOR_INVALID",
            message=f"{descriptor.check} descriptor dependencies must be a tuple of non-empty strings",
            before_execution=True,
        )
    if not isinstance(descriptor.declared_inputs, tuple) or not all(
        isinstance(input_name, str) and input_name for input_name in descriptor.declared_inputs
    ):
        _check_host_error(
            category="VERIFIER_UNAVAILABLE",
            code="CHECK_PLUGIN_DESCRIPTOR_INVALID",
            message=f"{descriptor.check} descriptor declared_inputs must be a tuple of non-empty strings",
            before_execution=True,
        )


def _check_host_non_empty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        _check_host_error(
            category="VERIFIER_UNAVAILABLE",
            code="CHECK_PLUGIN_DESCRIPTOR_INVALID",
            message=f"check plugin {field_name} must be a non-empty string",
            before_execution=True,
        )
    return value


def _check_host_json_value(value: Any, *, path: str) -> Any:
    if isinstance(value, Mapping):
        payload: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                _check_host_error(
                    category="CHECK_FAILED",
                    code="CHECK_PLUGIN_EVIDENCE_JSON_INVALID",
                    message=f"{path} contains a non-string key",
                    before_execution=False,
                )
            payload[key] = _check_host_json_value(item, path=f"{path}.{key}")
        return payload
    if isinstance(value, tuple):
        return [_check_host_json_value(item, path=f"{path}[]") for item in value]
    if isinstance(value, list):
        return [_check_host_json_value(item, path=f"{path}[]") for item in value]
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            _check_host_error(
                category="CHECK_FAILED",
                code="CHECK_PLUGIN_EVIDENCE_JSON_INVALID",
                message=f"{path} contains a non-finite number",
                before_execution=False,
            )
        return value
    _check_host_error(
        category="CHECK_FAILED",
        code="CHECK_PLUGIN_EVIDENCE_JSON_INVALID",
        message=f"{path} contains non-JSON value of type {type(value).__name__}",
        before_execution=False,
    )


def _check_host_ordered_results(
    compiled_profile: CompiledProfile,
    completed: Mapping[str, CheckResult],
) -> tuple[CheckResult, ...]:
    return tuple(completed[spec.check] for spec in compiled_profile.checks if spec.check in completed)


def _check_host_error(
    *,
    category: str,
    code: str,
    message: str,
    before_execution: bool,
    partial_results: tuple[CheckResult, ...] = (),
) -> None:
    raise CheckPluginHostError(
        category=category,
        code=code,
        message=message,
        before_execution=before_execution,
        partial_results=partial_results,
    )


def _s3_injection_samples(samples: tuple[S3InjectionSample, ...]) -> tuple[tuple[str, float, float], ...]:
    if not samples:
        _s3_injection_error("S3_INJECTION_SAMPLES_REQUIRED", "INJECTION requires at least two planted samples")
    normalized: list[tuple[str, float, float]] = []
    seen: set[str] = set()
    for index, sample in enumerate(samples):
        if not isinstance(sample, S3InjectionSample):
            _s3_injection_error(
                "S3_INJECTION_SAMPLE_INVALID",
                f"sample at index {index} must be S3InjectionSample",
            )
        sample_id = sample.sample_id
        if not isinstance(sample_id, str) or not sample_id:
            _s3_injection_error("S3_INJECTION_SAMPLE_ID_INVALID", "sample_id must be a non-empty string")
        if sample_id in seen:
            _s3_injection_error("S3_INJECTION_SAMPLE_DUPLICATE", f"duplicate sample_id {sample_id}")
        seen.add(sample_id)
        injected = _s3_injection_float(sample.injected_value, field=f"{sample_id}.injected_value")
        recovered = _s3_injection_float(sample.recovered_value, field=f"{sample_id}.recovered_value")
        normalized.append((sample_id, injected, recovered))
    if len(normalized) < 2:
        _s3_injection_error("S3_INJECTION_SAMPLES_REQUIRED", "INJECTION requires at least two planted samples")
    return tuple(normalized)


def _s3_injection_samples_digest(samples: tuple[tuple[str, float, float], ...]) -> str:
    return hash_json(
        [
            {
                "sample_id": sample_id,
                "injected_value": injected,
                "recovered_value": recovered,
            }
            for sample_id, injected, recovered in samples
        ]
    )


def _s3_injection_linear_fit(samples: tuple[tuple[str, float, float], ...]) -> tuple[float, float]:
    injected_values = tuple(injected for _sample_id, injected, _recovered in samples)
    recovered_values = tuple(recovered for _sample_id, _injected, recovered in samples)
    x_mean = sum(injected_values) / len(injected_values)
    y_mean = sum(recovered_values) / len(recovered_values)
    centered_x = tuple(value - x_mean for value in injected_values)
    ss_xx = sum(value * value for value in centered_x)
    if ss_xx <= 0:
        _s3_injection_error(
            "S3_INJECTION_AMPLITUDE_GRID_DEGENERATE",
            "INJECTION amplitude grid must contain at least two distinct amplitudes",
        )
    ss_xy = sum((x - x_mean) * (y - y_mean) for x, y in zip(injected_values, recovered_values, strict=True))
    slope = ss_xy / ss_xx
    intercept = y_mean - slope * x_mean
    if not math.isfinite(slope) or not math.isfinite(intercept):
        _s3_injection_error("S3_INJECTION_LINEARITY_NONFINITE", "INJECTION linear fit produced non-finite values")
    return slope, intercept


def _s3_injection_linearity_failure_reason(*, slope_pass: bool, intercept_pass: bool) -> str | None:
    if slope_pass and intercept_pass:
        return None
    if not slope_pass and not intercept_pass:
        return "SLOPE_AND_INTERCEPT_OUT_OF_TOLERANCE"
    if not slope_pass:
        return "SLOPE_OUT_OF_TOLERANCE"
    return "INTERCEPT_OUT_OF_TOLERANCE"


def _s3_injection_float(value: Any, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _s3_injection_error("S3_INJECTION_VALUE_INVALID", f"{field} must be numeric")
    numeric = float(value)
    if not math.isfinite(numeric):
        _s3_injection_error("S3_INJECTION_VALUE_NONFINITE", f"{field} must be finite")
    return numeric


def _s3_injection_probability(value: Any, *, field: str, allow_zero: bool = True) -> float:
    numeric = _s3_injection_float(value, field=field)
    lower_ok = numeric >= 0 if allow_zero else numeric > 0
    if not lower_ok or numeric > 1:
        _s3_injection_error("S3_INJECTION_PROBABILITY_INVALID", f"{field} must be in (0, 1]")
    return numeric


def _s3_injection_positive(value: Any, *, field: str) -> float:
    numeric = _s3_injection_float(value, field=field)
    if numeric <= 0:
        _s3_injection_error("S3_INJECTION_VALUE_INVALID", f"{field} must be positive")
    return numeric


def _s3_injection_non_negative(value: Any, *, field: str) -> float:
    numeric = _s3_injection_float(value, field=field)
    if numeric < 0:
        _s3_injection_error("S3_INJECTION_VALUE_INVALID", f"{field} must be non-negative")
    return numeric


def _s3_injection_optional_non_negative(value: Any, *, field: str) -> float | None:
    if value is None:
        return None
    return _s3_injection_non_negative(value, field=field)


def _s3_injection_error(code: str, message: str) -> None:
    raise S3InjectionCheckError(code=code, message=message)


def _s3_null_control_samples(samples: tuple[S3NullControlSample, ...]) -> tuple[tuple[str, str, bool], ...]:
    if not samples:
        _s3_null_control_error("S3_NULL_CONTROL_SAMPLES_REQUIRED", "NULL_CONTROL requires at least one null sample")
    normalized: list[tuple[str, str, bool]] = []
    seen: set[str] = set()
    for index, sample in enumerate(samples):
        if not isinstance(sample, S3NullControlSample):
            _s3_null_control_error(
                "S3_NULL_CONTROL_SAMPLE_INVALID",
                f"sample at index {index} must be S3NullControlSample",
            )
        sample_id = sample.sample_id
        if not isinstance(sample_id, str) or not sample_id:
            _s3_null_control_error("S3_NULL_CONTROL_SAMPLE_ID_INVALID", "sample_id must be a non-empty string")
        if sample_id in seen:
            _s3_null_control_error("S3_NULL_CONTROL_SAMPLE_DUPLICATE", f"duplicate sample_id {sample_id}")
        seen.add(sample_id)
        variant = _s3_null_control_variant(sample.variant, field=f"{sample_id}.variant")
        detected = _s3_null_control_bool(sample.detected, field=f"{sample_id}.detected")
        normalized.append((sample_id, variant, detected))
    return tuple(normalized)


def _s3_null_control_samples_digest(samples: tuple[tuple[str, str, bool], ...]) -> str:
    return hash_json(
        [
            {
                "sample_id": sample_id,
                "variant": variant,
                "detected": detected,
            }
            for sample_id, variant, detected in samples
        ]
    )


def _s3_null_control_variant_counts(samples: tuple[tuple[str, str, bool], ...]) -> list[dict[str, Any]]:
    counts: dict[str, dict[str, Any]] = {}
    for _sample_id, variant, detected in samples:
        entry = counts.setdefault(variant, {"variant": variant, "false_positives": 0, "trials": 0})
        entry["trials"] += 1
        if detected:
            entry["false_positives"] += 1
    return list(counts.values())


def _s3_null_control_variant_results(
    *,
    samples: tuple[tuple[str, str, bool], ...],
    alpha: float,
    confidence_level: float,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for count in _s3_null_control_variant_counts(samples):
        bound = S3StatisticsLibrary.false_positive_rate_bound(
            false_positives=count["false_positives"],
            trials=count["trials"],
            confidence_level=confidence_level,
            max_rate=alpha,
        )
        results.append(
            {
                "variant": count["variant"],
                "false_positives": count["false_positives"],
                "trials": count["trials"],
                "false_positive_rate": bound.observed_rate,
                "false_positive_rate_upper": bound.upper_bound,
                "passed": bound.passed,
            }
        )
    return results


def _s3_null_control_test_cases(*, status: str, variants: tuple[str, ...]) -> list[str]:
    test_cases: list[str] = []
    signal_free_variants = {"signal_free", "pure_noise", "fake_contamination", "data_contamination"}
    if status == "FAIL" and any(variant in signal_free_variants for variant in variants):
        test_cases.append("S3-TC06")
    elif status == "PASS" and any(variant in signal_free_variants for variant in variants):
        test_cases.append("S3-TC07")
    if "label_shuffle" in variants:
        test_cases.append("S3-TC08")
    if not test_cases:
        test_cases.append("S3-TC06" if status == "FAIL" else "S3-TC07")
    return test_cases


def _s3_null_control_failure_reason(*, aggregate_pass: bool, all_variants_pass: bool) -> str | None:
    if aggregate_pass and all_variants_pass:
        return None
    if not aggregate_pass:
        return "FPR_UPPER_EXCEEDS_ALPHA"
    return "VARIANT_FPR_UPPER_EXCEEDS_ALPHA"


def _s3_null_control_variant(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _s3_null_control_error("S3_NULL_CONTROL_VARIANT_INVALID", f"{field} must be a non-empty string")
    normalized = value.strip().lower().replace("-", "_")
    allowed = {"signal_free", "pure_noise", "label_shuffle", "fake_contamination", "data_contamination"}
    if normalized not in allowed:
        _s3_null_control_error(
            "S3_NULL_CONTROL_VARIANT_INVALID",
            f"{field} must be one of {', '.join(sorted(allowed))}",
        )
    return normalized


def _s3_null_control_bool(value: Any, *, field: str) -> bool:
    if not isinstance(value, bool):
        _s3_null_control_error("S3_NULL_CONTROL_DETECTION_INVALID", f"{field} must be boolean")
    return value


def _s3_null_control_float(value: Any, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _s3_null_control_error("S3_NULL_CONTROL_VALUE_INVALID", f"{field} must be numeric")
    numeric = float(value)
    if not math.isfinite(numeric):
        _s3_null_control_error("S3_NULL_CONTROL_VALUE_NONFINITE", f"{field} must be finite")
    return numeric


def _s3_null_control_probability(value: Any, *, field: str) -> float:
    numeric = _s3_null_control_float(value, field=field)
    if numeric <= 0 or numeric >= 1:
        _s3_null_control_error("S3_NULL_CONTROL_PROBABILITY_INVALID", f"{field} must be in (0, 1)")
    return numeric


def _s3_null_control_error(code: str, message: str) -> None:
    raise S3NullControlCheckError(code=code, message=message)


def _s3_cross_code_independence_resolution(
    value: S3IndependenceResolution | None,
) -> S3IndependenceResolution:
    if not isinstance(value, S3IndependenceResolution):
        _s3_cross_code_error(
            "S3_CROSS_CODE_INDEPENDENCE_REQUIRED",
            "CROSS_CODE requires an S3IndependenceResolution from S3-T14",
        )
    if value.verdict == "INDEPENDENT" and not value.cross_codes:
        _s3_cross_code_error(
            "S3_CROSS_CODE_INDEPENDENCE_INVALID",
            "independent CROSS_CODE resolution must include at least one cross-code id",
        )
    return value


def _s3_cross_code_samples(samples: tuple[S3CrossCodeSample, ...]) -> tuple[dict[str, Any], ...]:
    if not samples:
        _s3_cross_code_error("S3_CROSS_CODE_SAMPLES_REQUIRED", "CROSS_CODE requires comparison samples")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, sample in enumerate(samples):
        if not isinstance(sample, S3CrossCodeSample):
            _s3_cross_code_error(
                "S3_CROSS_CODE_SAMPLE_INVALID",
                f"sample at index {index} must be S3CrossCodeSample",
            )
        sample_id = sample.sample_id
        if not isinstance(sample_id, str) or not sample_id:
            _s3_cross_code_error("S3_CROSS_CODE_SAMPLE_ID_INVALID", "sample_id must be a non-empty string")
        if sample_id in seen:
            _s3_cross_code_error("S3_CROSS_CODE_SAMPLE_DUPLICATE", f"duplicate sample_id {sample_id}")
        seen.add(sample_id)
        pipeline_uncertainty = _s3_cross_code_non_negative(
            sample.pipeline_uncertainty,
            field=f"{sample_id}.pipeline_uncertainty",
        )
        reference_uncertainty = _s3_cross_code_non_negative(
            sample.reference_uncertainty,
            field=f"{sample_id}.reference_uncertainty",
        )
        pipeline_units = _s3_cross_code_units(sample.pipeline_units, field=f"{sample_id}.pipeline_units")
        reference_units = _s3_cross_code_units(sample.reference_units, field=f"{sample_id}.reference_units")
        extrapolation_flag = _s3_cross_code_bool(
            sample.extrapolation_flag,
            field=f"{sample_id}.extrapolation_flag",
        )
        if pipeline_units == reference_units and not extrapolation_flag:
            _s3_cross_code_combined_uncertainty(
                pipeline_uncertainty=pipeline_uncertainty,
                reference_uncertainty=reference_uncertainty,
                field=sample_id,
            )
        normalized.append(
            {
                "sample_id": sample_id,
                "pipeline_value": _s3_cross_code_float(sample.pipeline_value, field=f"{sample_id}.pipeline_value"),
                "reference_value": _s3_cross_code_float(sample.reference_value, field=f"{sample_id}.reference_value"),
                "pipeline_uncertainty": pipeline_uncertainty,
                "reference_uncertainty": reference_uncertainty,
                "pipeline_units": pipeline_units,
                "reference_units": reference_units,
                "extrapolation_flag": extrapolation_flag,
            }
        )
    return tuple(normalized)


def _s3_cross_code_base_metrics(
    *,
    samples: tuple[dict[str, Any], ...],
    independence: S3IndependenceResolution,
    reduced_min: float,
    reduced_max: float,
    z_max: float,
    max_excluded_fraction: float,
    min_valid_points: int,
) -> dict[str, Any]:
    return {
        "sample_count": len(samples),
        "sample_digest": _s3_cross_code_samples_digest(samples),
        "independence_verdict": independence.verdict,
        "cross_codes": list(independence.cross_codes),
        "rejected_candidate_ids": list(independence.rejected_candidate_ids),
        "degradations": list(independence.degradations),
        "min_independent": independence.min_independent,
        "c5_pinned_revisions": dict(independence.c5_pinned_revisions or {}),
        "reduced_chi_square_min": reduced_min,
        "reduced_chi_square_max": reduced_max,
        "z_max": z_max,
        "max_excluded_fraction": max_excluded_fraction,
        "min_valid_points": min_valid_points,
        "units": sorted({sample["pipeline_units"] for sample in samples} | {sample["reference_units"] for sample in samples}),
    }


def _s3_cross_code_samples_digest(samples: tuple[dict[str, Any], ...]) -> str:
    return hash_json(
        [
            {
                "sample_id": sample["sample_id"],
                "pipeline_value": sample["pipeline_value"],
                "reference_value": sample["reference_value"],
                "pipeline_uncertainty": sample["pipeline_uncertainty"],
                "reference_uncertainty": sample["reference_uncertainty"],
                "pipeline_units": sample["pipeline_units"],
                "reference_units": sample["reference_units"],
                "extrapolation_flag": sample["extrapolation_flag"],
            }
            for sample in samples
        ]
    )


def _s3_cross_code_units(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _s3_cross_code_error("S3_CROSS_CODE_UNITS_INVALID", f"{field} must be a non-empty string")
    return value.strip()


def _s3_cross_code_bool(value: Any, *, field: str) -> bool:
    if not isinstance(value, bool):
        _s3_cross_code_error("S3_CROSS_CODE_FLAG_INVALID", f"{field} must be boolean")
    return value


def _s3_cross_code_float(value: Any, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _s3_cross_code_error("S3_CROSS_CODE_VALUE_INVALID", f"{field} must be numeric")
    numeric = float(value)
    if not math.isfinite(numeric):
        _s3_cross_code_error("S3_CROSS_CODE_VALUE_NONFINITE", f"{field} must be finite")
    return numeric


def _s3_cross_code_positive(value: Any, *, field: str) -> float:
    numeric = _s3_cross_code_float(value, field=field)
    if numeric <= 0:
        _s3_cross_code_error("S3_CROSS_CODE_VALUE_INVALID", f"{field} must be positive")
    return numeric


def _s3_cross_code_non_negative(value: Any, *, field: str) -> float:
    numeric = _s3_cross_code_float(value, field=field)
    if numeric < 0:
        _s3_cross_code_error("S3_CROSS_CODE_VALUE_INVALID", f"{field} must be non-negative")
    return numeric


def _s3_cross_code_fraction(value: Any, *, field: str) -> float:
    numeric = _s3_cross_code_float(value, field=field)
    if numeric < 0 or numeric > 1:
        _s3_cross_code_error("S3_CROSS_CODE_FRACTION_INVALID", f"{field} must be in [0, 1]")
    return numeric


def _s3_cross_code_probability(value: Any, *, field: str) -> float:
    numeric = _s3_cross_code_float(value, field=field)
    if numeric <= 0 or numeric >= 1:
        _s3_cross_code_error("S3_CROSS_CODE_PROBABILITY_INVALID", f"{field} must be in (0, 1)")
    return numeric


def _s3_cross_code_combined_uncertainty(
    *,
    pipeline_uncertainty: float,
    reference_uncertainty: float,
    field: str,
) -> float:
    combined = math.sqrt(
        pipeline_uncertainty * pipeline_uncertainty
        + reference_uncertainty * reference_uncertainty
    )
    if combined <= 0:
        _s3_cross_code_error(
            "S3_CROSS_CODE_ZERO_UNCERTAINTY",
            f"{field} combined uncertainty must be positive",
        )
    return combined


def _s3_cross_code_positive_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        _s3_cross_code_error("S3_CROSS_CODE_INTEGER_INVALID", f"{field} must be a positive integer")
    return value


def _s3_cross_code_error(code: str, message: str) -> None:
    raise S3CrossCodeCheckError(code=code, message=message)


_S3_PHYSICAL_CONSISTENCY_ALLOWED_GATES = frozenset(
    {"dimensional", "positivity", "normalization", "symmetry", "asymptotic"}
)
_S3_PHYSICAL_CONSISTENCY_TEST_CASES = {
    "dimensional": "S3-TC12",
    "positivity": "S3-TC13",
    "normalization": "S3-TC14",
    "symmetry": "S3-TC15",
    "asymptotic": "S3-TC16",
}
_S3_PHYSICAL_CONSISTENCY_FAILURE_REASONS = {
    "dimensional": "DIMENSION_MISMATCH",
    "positivity": "NEGATIVE_NON_NEGATIVE_OBSERVABLE",
    "normalization": "NORMALIZATION_BOUND_EXCEEDED",
    "symmetry": "SYMMETRY_INVARIANCE_VIOLATION",
    "asymptotic": "ASYMPTOTIC_LIMIT_VIOLATION",
}


def _s3_physical_consistency_samples(
    samples: tuple[S3PhysicalConsistencySample, ...],
) -> tuple[dict[str, Any], ...]:
    if not samples:
        _s3_physical_consistency_error(
            "S3_PHYSICAL_CONSISTENCY_SAMPLES_REQUIRED",
            "PHYSICAL_CONSISTENCY requires at least one sample",
        )
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, sample in enumerate(samples):
        if not isinstance(sample, S3PhysicalConsistencySample):
            _s3_physical_consistency_error(
                "S3_PHYSICAL_CONSISTENCY_SAMPLE_INVALID",
                f"sample at index {index} must be S3PhysicalConsistencySample",
            )
        sample_id = _s3_physical_consistency_text(sample.sample_id, field="sample_id")
        if sample_id in seen:
            _s3_physical_consistency_error(
                "S3_PHYSICAL_CONSISTENCY_SAMPLE_DUPLICATE",
                f"duplicate sample_id {sample_id}",
            )
        seen.add(sample_id)
        symmetry_transform = _s3_physical_consistency_optional_text(
            sample.symmetry_transform,
            field=f"{sample_id}.symmetry_transform",
        )
        transformed_value = _s3_physical_consistency_optional_float(
            sample.transformed_value,
            field=f"{sample_id}.transformed_value",
        )
        if (symmetry_transform is None) != (transformed_value is None):
            _s3_physical_consistency_error(
                "S3_PHYSICAL_CONSISTENCY_SYMMETRY_PAIR_INVALID",
                f"{sample_id} must provide both symmetry_transform and transformed_value",
            )
        normalized.append(
            {
                "sample_id": sample_id,
                "observable": _s3_physical_consistency_text(sample.observable, field=f"{sample_id}.observable"),
                "value": _s3_physical_consistency_float(sample.value, field=f"{sample_id}.value"),
                "units": _s3_physical_consistency_text(sample.units, field=f"{sample_id}.units"),
                "expected_units": _s3_physical_consistency_text(
                    sample.expected_units,
                    field=f"{sample_id}.expected_units",
                ),
                "non_negative": _s3_physical_consistency_bool(
                    sample.non_negative,
                    field=f"{sample_id}.non_negative",
                ),
                "normalization_group": _s3_physical_consistency_optional_text(
                    sample.normalization_group,
                    field=f"{sample_id}.normalization_group",
                ),
                "symmetry_transform": symmetry_transform,
                "transformed_value": transformed_value,
                "asymptotic_expected": _s3_physical_consistency_optional_float(
                    sample.asymptotic_expected,
                    field=f"{sample_id}.asymptotic_expected",
                ),
            }
        )
    return tuple(normalized)


def _s3_physical_consistency_mandatory_gates(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list | tuple) or not value:
        _s3_physical_consistency_error(
            "S3_PHYSICAL_CONSISTENCY_MANDATORY_GATES_REQUIRED",
            "PHYSICAL_CONSISTENCY requires a non-empty mandatory_gates list",
        )
    gates: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item.strip():
            _s3_physical_consistency_error(
                "S3_PHYSICAL_CONSISTENCY_MANDATORY_GATE_INVALID",
                "mandatory_gates entries must be non-empty strings",
            )
        gate = item.strip().lower().replace("-", "_")
        if gate not in _S3_PHYSICAL_CONSISTENCY_ALLOWED_GATES:
            _s3_physical_consistency_error(
                "S3_PHYSICAL_CONSISTENCY_MANDATORY_GATE_INVALID",
                f"unsupported PHYSICAL_CONSISTENCY gate: {gate}",
            )
        if gate not in seen:
            seen.add(gate)
            gates.append(gate)
    return tuple(gates)


def _s3_physical_consistency_assert_mandatory_gates(
    mandatory_gates: tuple[str, ...],
    sub_gates: Mapping[str, Mapping[str, Any]],
) -> None:
    for gate in mandatory_gates:
        result = sub_gates[gate]
        if result["evaluated_count"] <= 0:
            _s3_physical_consistency_error(
                "S3_PHYSICAL_CONSISTENCY_MANDATORY_GATE_MISSING",
                f"mandatory PHYSICAL_CONSISTENCY gate {gate} has no evaluable samples",
            )


def _s3_physical_consistency_dimensional_gate(
    *,
    samples: tuple[dict[str, Any], ...],
    units_algebra: UnitsAlgebra,
) -> dict[str, Any]:
    mismatches: list[dict[str, Any]] = []
    dimensions_seen: list[str] = []
    for sample in samples:
        try:
            actual = units_algebra.dimension(sample["units"])
            expected = units_algebra.dimension(sample["expected_units"])
        except S2ContractModelError as exc:
            _s3_physical_consistency_error(
                "S3_PHYSICAL_CONSISTENCY_UNITS_INVALID",
                f"invalid units for {sample['observable']}: {exc}",
            )
        actual_text = str(actual)
        expected_text = str(expected)
        dimensions_seen.append(actual_text)
        dimensions_seen.append(expected_text)
        if actual != expected:
            mismatches.append(
                {
                    "observable": sample["observable"],
                    "sample_digest": _s3_physical_consistency_sample_digest(sample),
                    "units": sample["units"],
                    "expected_units": sample["expected_units"],
                    "actual_dimension": actual_text,
                    "expected_dimension": expected_text,
                }
            )
    return {
        "status": "FAIL" if mismatches else "PASS",
        "evaluated_count": len(samples),
        "dimension_mismatch_count": len(mismatches),
        "mismatches": mismatches,
        "dimensions_seen": sorted(set(dimensions_seen)),
    }


def _s3_physical_consistency_positivity_gate(samples: tuple[dict[str, Any], ...]) -> dict[str, Any]:
    checked = tuple(sample for sample in samples if sample["non_negative"])
    offending = [
        {
            "observable": sample["observable"],
            "sample_digest": _s3_physical_consistency_sample_digest(sample),
            "value": sample["value"],
        }
        for sample in checked
        if sample["value"] < 0
    ]
    values = tuple(sample["value"] for sample in checked)
    return {
        "status": "NOT_EVALUATED" if not checked else ("FAIL" if offending else "PASS"),
        "evaluated_count": len(checked),
        "negative_count": len(offending),
        "min_output": min(values) if values else None,
        "offending_points": offending,
    }


def _s3_physical_consistency_normalization_gate(
    *,
    samples: tuple[dict[str, Any], ...],
    epsilon: float,
) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for sample in samples:
        group = sample["normalization_group"]
        if group is not None:
            groups.setdefault(group, []).append(sample)
    group_results: list[dict[str, Any]] = []
    for group, group_samples in sorted(groups.items()):
        total = sum(sample["value"] for sample in group_samples)
        passed = total <= 1.0 + epsilon
        group_results.append(
            {
                "group": group,
                "sample_count": len(group_samples),
                "sum": total,
                "epsilon": epsilon,
                "limit": 1.0 + epsilon,
                "passed": passed,
            }
        )
    failed = [result for result in group_results if not result["passed"]]
    return {
        "status": "NOT_EVALUATED" if not group_results else ("FAIL" if failed else "PASS"),
        "evaluated_count": len(group_results),
        "failed_group_count": len(failed),
        "group_results": group_results,
        "epsilon": epsilon,
    }


def _s3_physical_consistency_symmetry_gate(
    *,
    samples: tuple[dict[str, Any], ...],
    absolute_tolerance: float | None,
    relative_tolerance: float | None,
) -> dict[str, Any]:
    comparisons = tuple(sample for sample in samples if sample["transformed_value"] is not None)
    results: list[dict[str, Any]] = []
    for sample in comparisons:
        tolerance = S3StatisticsLibrary.tolerance(
            observed=sample["transformed_value"],
            expected=sample["value"],
            absolute_tolerance=absolute_tolerance,
            relative_tolerance=relative_tolerance,
        )
        results.append(
            {
                "observable": sample["observable"],
                "sample_digest": _s3_physical_consistency_sample_digest(sample),
                "symmetry_transform": sample["symmetry_transform"],
                "error": tolerance.error,
                "tolerance": tolerance.tolerance,
                "passed": tolerance.passed,
            }
        )
    failed = [result for result in results if not result["passed"]]
    max_error = max((result["error"] for result in results), default=0.0)
    return {
        "status": "NOT_EVALUATED" if not results else ("FAIL" if failed else "PASS"),
        "evaluated_count": len(results),
        "symmetry_pass": bool(results) and not failed,
        "failed_count": len(failed),
        "max_error": max_error,
        "comparisons": results,
    }


def _s3_physical_consistency_asymptotic_gate(
    *,
    samples: tuple[dict[str, Any], ...],
    absolute_tolerance: float | None,
    relative_tolerance: float | None,
) -> dict[str, Any]:
    comparisons = tuple(sample for sample in samples if sample["asymptotic_expected"] is not None)
    results: list[dict[str, Any]] = []
    for sample in comparisons:
        tolerance = S3StatisticsLibrary.tolerance(
            observed=sample["value"],
            expected=sample["asymptotic_expected"],
            absolute_tolerance=absolute_tolerance,
            relative_tolerance=relative_tolerance,
        )
        results.append(
            {
                "observable": sample["observable"],
                "sample_digest": _s3_physical_consistency_sample_digest(sample),
                "error": tolerance.error,
                "tolerance": tolerance.tolerance,
                "expected": sample["asymptotic_expected"],
                "passed": tolerance.passed,
            }
        )
    failed = [result for result in results if not result["passed"]]
    max_error = max((result["error"] for result in results), default=0.0)
    return {
        "status": "NOT_EVALUATED" if not results else ("FAIL" if failed else "PASS"),
        "evaluated_count": len(results),
        "asymptotic_pass": bool(results) and not failed,
        "failed_count": len(failed),
        "max_error": max_error,
        "comparisons": results,
    }


def _s3_physical_consistency_test_cases(
    *,
    mandatory_gates: tuple[str, ...],
    failed_gates: tuple[str, ...],
) -> list[str]:
    gates = failed_gates if failed_gates else mandatory_gates
    return [
        _S3_PHYSICAL_CONSISTENCY_TEST_CASES[gate]
        for gate in gates
    ]


def _s3_physical_consistency_samples_digest(samples: tuple[dict[str, Any], ...]) -> str:
    return hash_json(
        [
            {
                "sample_id": sample["sample_id"],
                "observable": sample["observable"],
                "value": sample["value"],
                "units": sample["units"],
                "expected_units": sample["expected_units"],
                "non_negative": sample["non_negative"],
                "normalization_group": sample["normalization_group"],
                "symmetry_transform": sample["symmetry_transform"],
                "transformed_value": sample["transformed_value"],
                "asymptotic_expected": sample["asymptotic_expected"],
            }
            for sample in samples
        ]
    )


def _s3_physical_consistency_sample_digest(sample: Mapping[str, Any]) -> str:
    return hash_json(
        {
            "sample_id": sample["sample_id"],
            "observable": sample["observable"],
            "value": sample["value"],
            "units": sample["units"],
            "expected_units": sample["expected_units"],
        }
    )


def _s3_physical_consistency_text(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _s3_physical_consistency_error(
            "S3_PHYSICAL_CONSISTENCY_TEXT_INVALID",
            f"{field} must be a non-empty string",
        )
    return value.strip()


def _s3_physical_consistency_optional_text(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    return _s3_physical_consistency_text(value, field=field)


def _s3_physical_consistency_bool(value: Any, *, field: str) -> bool:
    if not isinstance(value, bool):
        _s3_physical_consistency_error(
            "S3_PHYSICAL_CONSISTENCY_BOOL_INVALID",
            f"{field} must be boolean",
        )
    return value


def _s3_physical_consistency_float(value: Any, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _s3_physical_consistency_error(
            "S3_PHYSICAL_CONSISTENCY_VALUE_INVALID",
            f"{field} must be numeric",
        )
    numeric = float(value)
    if not math.isfinite(numeric):
        _s3_physical_consistency_error(
            "S3_PHYSICAL_CONSISTENCY_VALUE_NONFINITE",
            f"{field} must be finite",
        )
    return numeric


def _s3_physical_consistency_optional_float(value: Any, *, field: str) -> float | None:
    if value is None:
        return None
    return _s3_physical_consistency_float(value, field=field)


def _s3_physical_consistency_non_negative(value: Any, *, field: str) -> float:
    numeric = _s3_physical_consistency_float(value, field=field)
    if numeric < 0:
        _s3_physical_consistency_error(
            "S3_PHYSICAL_CONSISTENCY_VALUE_INVALID",
            f"{field} must be non-negative",
        )
    return numeric


def _s3_physical_consistency_optional_non_negative(value: Any, *, field: str) -> float | None:
    if value is None:
        return None
    return _s3_physical_consistency_non_negative(value, field=field)


def _s3_physical_consistency_error(code: str, message: str) -> None:
    raise S3PhysicalConsistencyCheckError(code=code, message=message)


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

    def __init__(self, *, verifier_id: str, signer_key_id: str, signer: S3ReportSignerProtocol) -> None:
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


def _compiler_error(*, category: str, code: str, message: str) -> None:
    raise S3ProfileCompilerError(category=category, code=code, message=message)


def _compiler_mapping(value: Any, *, default: Mapping[str, Any]) -> dict[str, Any]:
    if value is None:
        return dict(default)
    if not isinstance(value, Mapping):
        _compiler_error(category="POLICY", code="PROFILE_UNSUPPORTED", message="profile compiler expected a JSON object")
    payload = _profile_json_value(value, path="CompiledProfile")
    if not isinstance(payload, dict):
        _compiler_error(category="POLICY", code="PROFILE_UNSUPPORTED", message="profile compiler expected a JSON object")
    return payload


def _check_spec_for(profile: VerifierProfileRevision, check: str) -> dict[str, Any]:
    specs = _check_specs_by_check(profile)
    return dict(specs.get(check, {"check": check}))


def _check_specs_by_check(profile: VerifierProfileRevision) -> dict[str, dict[str, Any]]:
    raw_specs = profile.spec_json.get("check_specs")
    if raw_specs is None:
        return {}
    if isinstance(raw_specs, Mapping):
        values = []
        for check, value in raw_specs.items():
            payload = _compiler_mapping(value, default={})
            payload.setdefault("check", check)
            values.append(payload)
    elif isinstance(raw_specs, list):
        values = [_compiler_mapping(value, default={}) for value in raw_specs]
    else:
        _compiler_error(category="POLICY", code="PROFILE_UNSUPPORTED", message="check_specs must be a JSON object or array")

    known_checks = set(profile.checks)
    compiled: dict[str, dict[str, Any]] = {}
    for spec in values:
        check = spec.get("check") or spec.get("check_id") or spec.get("type")
        if not isinstance(check, str) or not check:
            _compiler_error(category="POLICY", code="PROFILE_UNSUPPORTED", message="check_specs entries require check")
        if check not in S3_VERIFIER_PROFILE_CHECKS or check not in known_checks:
            _compiler_error(category="POLICY", code="PROFILE_UNSUPPORTED", message=f"unsupported profile check spec: {check}")
        if check in compiled:
            _compiler_error(category="POLICY", code="PROFILE_UNSUPPORTED", message=f"duplicate profile check spec: {check}")
        compiled[check] = dict(spec)
    return compiled


def _thresholds_for(profile: VerifierProfileRevision, check: str) -> dict[str, Any]:
    thresholds = profile.spec_json.get("thresholds")
    if not isinstance(thresholds, Mapping):
        return {}
    value = thresholds.get(check)
    if value is None:
        return {}
    return _compiler_mapping(value, default={})


def _non_empty_plugin_ref(value: Any) -> str:
    if not isinstance(value, str) or not value:
        _compiler_error(category="POLICY", code="PROFILE_UNSUPPORTED", message="check plugin_ref must be a non-empty string")
    return value


def _semver_string(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        _compiler_error(category="POLICY", code="PROFILE_UNSUPPORTED", message=f"{field_name} must be a non-empty semver string")
    _parse_semver_tuple(value)
    return value


def _parse_semver_tuple(value: str) -> tuple[int, int, int]:
    parts = value.split(".")
    if len(parts) != 3:
        _compiler_error(category="POLICY", code="PROFILE_UNSUPPORTED", message=f"invalid semver: {value}")
    try:
        parsed = tuple(int(part) for part in parts)
    except ValueError as exc:
        raise S3ProfileCompilerError(
            category="POLICY",
            code="PROFILE_UNSUPPORTED",
            message=f"invalid semver: {value}",
        ) from exc
    if any(part < 0 for part in parsed):
        _compiler_error(category="POLICY", code="PROFILE_UNSUPPORTED", message=f"invalid semver: {value}")
    return parsed  # type: ignore[return-value]


def _optional_positive_int(value: Any, *, field_name: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or value < 1:
        _compiler_error(category="POLICY", code="PROFILE_UNSUPPORTED", message=f"{field_name} must be a positive integer")
    return value


def _optional_number(value: Any, *, field_name: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        _compiler_error(category="POLICY", code="PROFILE_UNSUPPORTED", message=f"{field_name} must be a finite number")
    if float(value) < 0:
        _compiler_error(category="POLICY", code="PROFILE_UNSUPPORTED", message=f"{field_name} must be non-negative")
    return float(value)


def _check_determinism(
    *,
    profile: VerifierProfileRevision,
    check: str,
    spec: Mapping[str, Any],
    adapter: CompiledC6Adapter | None,
) -> str:
    value = spec.get("determinism")
    if value is None and adapter is not None:
        value = adapter.determinism
    if value is None:
        determinism_policy = profile.spec_json.get("determinism_policy")
        if isinstance(determinism_policy, Mapping):
            value = determinism_policy.get("class")
    if value is None:
        value = "deterministic"
    if value not in {"deterministic", "seeded", "stochastic"}:
        _compiler_error(category="POLICY", code="PROFILE_UNSUPPORTED", message=f"{check} determinism is unsupported")
    return str(value)


def _check_seed(*, profile: VerifierProfileRevision, spec: Mapping[str, Any]) -> int | None:
    seed = spec.get("seed")
    if seed is None:
        determinism_policy = profile.spec_json.get("determinism_policy")
        if isinstance(determinism_policy, Mapping):
            seed = determinism_policy.get("seed")
    if seed is None:
        return None
    if not isinstance(seed, int):
        _compiler_error(category="POLICY", code="PROFILE_UNSUPPORTED", message="seeded profile checks require an integer seed")
    return seed


def _requires_independence(*, profile: VerifierProfileRevision, check: str, spec: Mapping[str, Any]) -> bool:
    value = spec.get("requires_independence")
    if isinstance(value, bool):
        return value
    independence_policy = profile.spec_json.get("independence_policy")
    if isinstance(independence_policy, Mapping):
        if check == "CROSS_CODE" and bool(independence_policy.get("requires_cross_code")):
            return True
        required_checks = independence_policy.get("requires_checks")
        if isinstance(required_checks, list) and check in required_checks:
            return True
    return check == "CROSS_CODE"


def _determinism_profile(checks: tuple[CompiledCheckSpec, ...]) -> dict[str, Any]:
    deterministic: list[str] = []
    seeded: list[dict[str, Any]] = []
    stochastic: list[dict[str, Any]] = []
    adapter_determinism: list[dict[str, Any]] = []
    for check in checks:
        if check.determinism == "deterministic":
            deterministic.append(check.check)
        elif check.determinism == "seeded":
            seeded.append({"check": check.check, "seed": check.seed})
        elif check.determinism == "stochastic":
            stochastic.append({"check": check.check, "tolerance": dict(check.tolerance)})
        if check.adapter is not None:
            adapter_determinism.append(
                {
                    "check": check.check,
                    "adapter_id": check.adapter.adapter_id,
                    "adapter_version": check.adapter.selected_version,
                    "determinism": check.adapter.determinism,
                }
            )
    return {
        "deterministic_checks": deterministic,
        "seeded_checks": seeded,
        "stochastic_checks": stochastic,
        "adapter_determinism": adapter_determinism,
    }


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


def _s3_key_id(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise S3KeyManagementError(code="S3_SIGNING_KEY_ID_INVALID", message="S3 signing key_id is required")
    return value.strip()


def _s3_key_material(value: Any) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or not bytes(value):
        raise S3KeyManagementError(
            code="S3_SIGNING_KEY_MATERIAL_UNAVAILABLE",
            message="S3 signing key material is unavailable",
        )
    return bytes(value)


def _s3_c3_signature_value(report_with_empty_signature: dict[str, Any], key_material: bytes) -> str:
    digest = hmac.new(key_material, canonical_c3_json_bytes(report_with_empty_signature), sha256).hexdigest()
    return f"{C3_SIGNATURE_PREFIX}{digest}"


def _s3_report_key_id(report: Mapping[str, Any]) -> str:
    signature = report.get("signature")
    if isinstance(signature, Mapping) and isinstance(signature.get("key_id"), str):
        return str(signature["key_id"])
    return ""


def _s3_report_with_empty_signature(report: Mapping[str, Any]) -> dict[str, Any]:
    payload = deepcopy(dict(report))
    signature = payload.get("signature")
    algorithm = C3_SIGNATURE_ALGORITHM
    key_id = ""
    if isinstance(signature, Mapping):
        algorithm = str(signature.get("algorithm") or C3_SIGNATURE_ALGORITHM)
        key_id = str(signature.get("key_id") or "")
    payload["signature"] = {
        "algorithm": algorithm,
        "key_id": key_id,
        "value": "",
    }
    return payload


def _s3_report_payload_digest(report_payload: Mapping[str, Any]) -> str:
    try:
        return hash_bytes(canonical_c3_json_bytes(report_payload))
    except (TypeError, ValueError):
        return ""


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


def _s3_stats_error(code: str, message: str) -> None:
    raise S3StatisticsError(code=code, message=message)


def _s3_stats_float(value: float, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _s3_stats_error("STAT_VALUE_INVALID", f"{field} must be a finite number")
    float_value = float(value)
    if not math.isfinite(float_value):
        _s3_stats_error("STAT_VALUE_INVALID", f"{field} must be a finite number")
    return float_value


def _s3_stats_sequence(values: tuple[float, ...] | list[float], *, field: str) -> tuple[float, ...]:
    if not isinstance(values, (tuple, list)):
        _s3_stats_error("STAT_SEQUENCE_INVALID", f"{field} must be a list or tuple")
    if len(values) == 0:
        _s3_stats_error("STAT_SEQUENCE_EMPTY", f"{field} must be non-empty")
    return tuple(_s3_stats_float(value, field=f"{field}[{index}]") for index, value in enumerate(values))


def _s3_stats_same_length(**series: tuple[float, ...]) -> None:
    lengths = {name: len(values) for name, values in series.items()}
    if len(set(lengths.values())) != 1:
        _s3_stats_error("STAT_LENGTH_MISMATCH", "statistical input series must have equal lengths")


def _s3_stats_optional_non_negative(value: float | None, *, field: str) -> float | None:
    if value is None:
        return None
    return _s3_stats_non_negative(value, field=field)


def _s3_stats_non_negative(value: float, *, field: str) -> float:
    float_value = _s3_stats_float(value, field=field)
    if float_value < 0:
        _s3_stats_error("STAT_NEGATIVE_VALUE", f"{field} must be non-negative")
    return float_value


def _s3_stats_positive(value: float, *, field: str) -> float:
    float_value = _s3_stats_float(value, field=field)
    if float_value <= 0:
        _s3_stats_error("STAT_NON_POSITIVE_VALUE", f"{field} must be positive")
    return float_value


def _s3_stats_probability(
    value: float | None,
    *,
    field: str,
    allow_zero: bool = True,
    allow_one: bool = True,
) -> float:
    if value is None:
        _s3_stats_error("STAT_PROBABILITY_REQUIRED", f"{field} is required")
    float_value = _s3_stats_float(value, field=field)
    lower_ok = float_value >= 0 if allow_zero else float_value > 0
    upper_ok = float_value <= 1 if allow_one else float_value < 1
    if not (lower_ok and upper_ok):
        interval = "[0, 1]" if allow_zero and allow_one else "(0, 1)"
        _s3_stats_error("STAT_PROBABILITY_INVALID", f"{field} must be in {interval}")
    return float_value


def _s3_stats_chi_square_survival(chi_square: float, dof: int) -> float:
    if chi_square < 0 or dof <= 0:
        _s3_stats_error("STAT_CHI_SQUARE_INVALID", "chi_square must be non-negative and dof must be positive")
    if chi_square == 0:
        return 1.0
    z = ((chi_square / dof) ** (1.0 / 3.0) - (1.0 - 2.0 / (9.0 * dof))) / math.sqrt(2.0 / (9.0 * dof))
    return max(0.0, min(1.0, 0.5 * math.erfc(z / math.sqrt(2.0))))


def _s3_stats_ks_uniform_p_value(ks_statistic: float, sample_count: int) -> float:
    if sample_count <= 0:
        _s3_stats_error("STAT_KS_INVALID", "sample_count must be positive")
    if ks_statistic <= 0:
        return 1.0
    root_n = math.sqrt(sample_count)
    lam = (root_n + 0.12 + 0.11 / root_n) * ks_statistic
    total = 0.0
    for index in range(1, 101):
        term = 2.0 * ((-1.0) ** (index - 1)) * math.exp(-2.0 * index * index * lam * lam)
        total += term
        if abs(term) < 1e-12:
            break
    return max(0.0, min(1.0, total))


def _s3_stats_binomial_cdf(successes: int, trials: int, probability: float) -> float:
    if probability <= 0:
        return 1.0
    if probability >= 1:
        return 1.0 if successes >= trials else 0.0
    term = (1.0 - probability) ** trials
    total = term
    for count in range(0, successes):
        term *= (trials - count) / (count + 1) * probability / (1.0 - probability)
        total += term
    return max(0.0, min(1.0, total))


def _s3_stats_binomial_upper_bound(false_positives: int, trials: int, confidence_level: float) -> float:
    if false_positives >= trials:
        return 1.0
    tail_probability = 1.0 - confidence_level
    low = 0.0
    high = 1.0
    for _ in range(80):
        mid = (low + high) / 2.0
        cdf = _s3_stats_binomial_cdf(false_positives, trials, mid)
        if cdf > tail_probability:
            low = mid
        else:
            high = mid
    return high


def _s3_stats_statistic(values: tuple[float, ...], statistic: str) -> float:
    if statistic == "mean":
        return sum(values) / len(values)
    if statistic == "median":
        ordered = tuple(sorted(values))
        midpoint = len(ordered) // 2
        if len(ordered) % 2 == 1:
            return ordered[midpoint]
        return (ordered[midpoint - 1] + ordered[midpoint]) / 2.0
    _s3_stats_error("STATISTIC_UNSUPPORTED", f"unsupported bootstrap statistic: {statistic}")


def _s3_stats_percentile(sorted_values: list[float], probability: float) -> float:
    if not sorted_values:
        _s3_stats_error("STAT_SEQUENCE_EMPTY", "sorted_values must be non-empty")
    probability = _s3_stats_probability(probability, field="probability")
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = probability * (len(sorted_values) - 1)
    lower_index = math.floor(position)
    upper_index = math.ceil(position)
    if lower_index == upper_index:
        return sorted_values[lower_index]
    fraction = position - lower_index
    return sorted_values[lower_index] * (1.0 - fraction) + sorted_values[upper_index] * fraction


def _s3_stats_multiple_comparison(
    p_values: tuple[float, ...] | list[float],
    *,
    alpha: float,
    method: str,
) -> S3MultipleComparisonResult:
    values = _s3_stats_sequence(p_values, field="p_values")
    for index, value in enumerate(values):
        _s3_stats_probability(value, field=f"p_values[{index}]")
    alpha_value = _s3_stats_probability(alpha, field="alpha", allow_zero=False, allow_one=False)
    if method == "benjamini-hochberg":
        adjusted, thresholds, rejected = _s3_stats_bh(values, alpha_value)
    elif method == "bonferroni":
        adjusted, thresholds, rejected = _s3_stats_bonferroni(values, alpha_value)
    else:
        _s3_stats_error("STAT_CORRECTION_UNSUPPORTED", f"unsupported multiple-comparison method: {method}")
    naive = tuple(value <= alpha_value for value in values)
    return S3MultipleComparisonResult(
        p_values=values,
        adjusted_p_values=adjusted,
        thresholds=thresholds,
        rejected=rejected,
        naive_rejected=naive,
        corrected_decision_differs_from_naive=rejected != naive,
        alpha=alpha_value,
        method=method,
    )


def _s3_stats_bh(values: tuple[float, ...], alpha: float) -> tuple[tuple[float, ...], tuple[float, ...], tuple[bool, ...]]:
    total = len(values)
    ordered = sorted(enumerate(values), key=lambda item: (item[1], item[0]))
    thresholds_by_index = [0.0] * total
    rejected_by_index = [False] * total
    adjusted_by_sorted = [0.0] * total
    max_rejected_rank = 0
    for rank, (original_index, p_value) in enumerate(ordered, start=1):
        threshold = alpha * rank / total
        thresholds_by_index[original_index] = threshold
        if p_value <= threshold:
            max_rejected_rank = rank
    running = 1.0
    for rank in range(total, 0, -1):
        original_index, p_value = ordered[rank - 1]
        running = min(running, p_value * total / rank)
        adjusted_by_sorted[rank - 1] = min(1.0, running)
        if rank <= max_rejected_rank:
            rejected_by_index[original_index] = True
    adjusted_by_index = [0.0] * total
    for rank, (original_index, _) in enumerate(ordered):
        adjusted_by_index[original_index] = adjusted_by_sorted[rank]
    return tuple(adjusted_by_index), tuple(thresholds_by_index), tuple(rejected_by_index)


def _s3_stats_bonferroni(
    values: tuple[float, ...],
    alpha: float,
) -> tuple[tuple[float, ...], tuple[float, ...], tuple[bool, ...]]:
    total = len(values)
    threshold = alpha / total
    adjusted = tuple(min(1.0, value * total) for value in values)
    thresholds = tuple(threshold for _ in values)
    rejected = tuple(value <= threshold for value in values)
    return adjusted, thresholds, rejected


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
