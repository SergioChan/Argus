"""S3 verifier, perturbation oracle, and signed report core semantics."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, replace
from functools import lru_cache
import json
import math
from pathlib import Path
from typing import Any, Mapping, Protocol
from uuid import NAMESPACE_URL, uuid4, uuid5

from jsonschema import Draft202012Validator

from argusverify import C3ReportSigner, canonical_c3_json_bytes
from .canonical import canonical_json_bytes
from .hashing import hash_bytes, hash_json
from .s8 import InMemoryArtifactStore, Lineage, Producer
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
