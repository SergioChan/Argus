"""S2 baseline builder semantics for the first oracle-gated vertical slice."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
import hashlib
from itertools import product
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any, Callable, Mapping

from .s5 import C2VersionPolicy, parse_c2_job_envelope
from .s6 import CapabilityDescriptor, RegistryError
from .s7 import AdapterBroker, EvalRequest, EvalResult
from .s8 import ArtifactRecord, IllegalTierError, InMemoryArtifactStore, Lineage, Producer, assert_lineage_complete


class S2Error(Exception):
    """Base class for S2 builder failures."""


class SelfGradeError(S2Error):
    """Raised when S2 tries to assign a tier above ran-toy."""


class RewardSourceError(S2Error):
    """Raised when S2 is asked to accept a non-C3 score or reward."""


class S2ContractModelError(S2Error):
    """Raised when S2's contract-bound model surface is missing or drifting."""


class S2SpecCompilerError(S2Error):
    """Raised when S2 refuses a build before any training execution starts."""

    def __init__(self, *, category: str, code: str, message: str, before_execution: bool = True) -> None:
        super().__init__(message)
        self.category = category
        self.code = code
        self.message = message
        self.retryable = False
        self.before_execution = before_execution

    def as_c1_payload(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "before_execution": self.before_execution,
        }


S2_REQUIRED_CONTRACT_IDS = ("C1", "C2", "C4", "C6")


@dataclass(frozen=True)
class S2ContractBinding:
    contract_id: str
    version: str
    schema: str
    schema_sha256: str


@dataclass(frozen=True)
class S2ContractModelSet:
    bindings: tuple[S2ContractBinding, ...]

    def by_id(self, contract_id: str) -> S2ContractBinding:
        for binding in self.bindings:
            if binding.contract_id == contract_id:
                return binding
        raise S2ContractModelError(f"S2 contract binding missing: {contract_id}")


@dataclass(frozen=True)
class FieldSpec:
    name: str
    units: str
    role: str = "feature"

    def __post_init__(self) -> None:
        if not self.name:
            raise S2ContractModelError("S2 field specs require a name")
        if not self.units:
            raise S2ContractModelError(f"S2 field {self.name!r} requires units")


S2_DIMENSION_BASES = ("energy", "length", "time", "mass", "temperature", "charge")
S2_UNIT_REGISTRY_VERSION = "argus-s2-units@1"
S2_MODEL_REGISTRY_VERSION = "argus-s2-model-family-registry@1"


class DimensionalError(S2Error):
    """Raised when a derived S2 feature has the wrong physical dimension."""

    def __init__(
        self,
        *,
        node_id: str,
        expected: "DimensionVector",
        actual: "DimensionVector",
        valid_nodes: tuple["FeatureNode", ...] = (),
    ) -> None:
        super().__init__(f"feature {node_id!r} has dimension {actual}, expected {expected}")
        self.category = "POLICY"
        self.code = "DIMENSIONAL_INCONSISTENCY"
        self.node_id = node_id
        self.expected = expected
        self.actual = actual
        self.valid_nodes = valid_nodes
        self.valid_node_count = len(valid_nodes)
        self.retryable = False


@dataclass(frozen=True)
class DimensionVector:
    exponents: tuple[int, ...]

    def __post_init__(self) -> None:
        normalized = tuple(int(value) for value in self.exponents)
        if len(normalized) != len(S2_DIMENSION_BASES):
            raise S2ContractModelError(
                f"dimension vector must have {len(S2_DIMENSION_BASES)} exponents, got {len(normalized)}"
            )
        object.__setattr__(self, "exponents", normalized)

    @classmethod
    def dimensionless(cls) -> "DimensionVector":
        return cls((0,) * len(S2_DIMENSION_BASES))

    @property
    def is_dimensionless(self) -> bool:
        return all(value == 0 for value in self.exponents)

    def __mul__(self, other: "DimensionVector") -> "DimensionVector":
        return DimensionVector(tuple(left + right for left, right in zip(self.exponents, other.exponents)))

    def __truediv__(self, other: "DimensionVector") -> "DimensionVector":
        return DimensionVector(tuple(left - right for left, right in zip(self.exponents, other.exponents)))

    def __pow__(self, exponent: int) -> "DimensionVector":
        return DimensionVector(tuple(value * int(exponent) for value in self.exponents))

    def __str__(self) -> str:
        if self.is_dimensionless:
            return "dimensionless"
        parts = []
        for name, exponent in zip(S2_DIMENSION_BASES, self.exponents):
            if exponent == 0:
                continue
            parts.append(name if exponent == 1 else f"{name}^{exponent}")
        return "*".join(parts)


@dataclass(frozen=True)
class UnitDefinition:
    symbol: str
    dimension: DimensionVector


@dataclass(frozen=True)
class UnitRegistry:
    version: str
    units: dict[str, UnitDefinition]

    @classmethod
    def default(cls) -> "UnitRegistry":
        dimensionless = DimensionVector.dimensionless()
        energy = _base_dimension("energy")
        length = _base_dimension("length")
        time = _base_dimension("time")
        mass = _base_dimension("mass")
        temperature = _base_dimension("temperature")
        charge = _base_dimension("charge")
        definitions = {
            "1": UnitDefinition("1", dimensionless),
            "dimensionless": UnitDefinition("dimensionless", dimensionless),
            "GeV": UnitDefinition("GeV", energy),
            "TeV": UnitDefinition("TeV", energy),
            "MeV": UnitDefinition("MeV", energy),
            "eV": UnitDefinition("eV", energy),
            "Hz": UnitDefinition("Hz", time ** -1),
            "mHz": UnitDefinition("mHz", time ** -1),
            "m": UnitDefinition("m", length),
            "cm": UnitDefinition("cm", length),
            "mm": UnitDefinition("mm", length),
            "s": UnitDefinition("s", time),
            "kg": UnitDefinition("kg", mass),
            "K": UnitDefinition("K", temperature),
            "C": UnitDefinition("C", charge),
            "pb": UnitDefinition("pb", length ** 2),
            "fb": UnitDefinition("fb", length ** 2),
            "barn": UnitDefinition("barn", length ** 2),
        }
        return cls(version=S2_UNIT_REGISTRY_VERSION, units=definitions)

    def dimension(self, symbol: str) -> DimensionVector:
        try:
            return self.units[symbol].dimension
        except KeyError as exc:
            raise S2ContractModelError(f"unknown S2 unit: {symbol}") from exc


class UnitsAlgebra:
    """Deterministic dimension arithmetic over the frozen S2 unit registry."""

    def __init__(self, registry: UnitRegistry | None = None) -> None:
        self.registry = registry or UnitRegistry.default()

    def dimension(self, unit_expression: str) -> DimensionVector:
        expression = unit_expression.replace(" ", "")
        if expression in {"", "1", "dimensionless"}:
            return DimensionVector.dimensionless()
        result = DimensionVector.dimensionless()
        operator = 1
        for raw_token in _unit_expression_tokens(expression):
            if raw_token == "*":
                operator = 1
                continue
            if raw_token == "/":
                operator = -1
                continue
            symbol, exponent = _unit_token_power(raw_token)
            result = result * (self.registry.dimension(symbol) ** (operator * exponent))
            operator = 1
        return result

    def multiply(self, left: str | DimensionVector, right: str | DimensionVector) -> DimensionVector:
        return self._dimension_value(left) * self._dimension_value(right)

    def divide(self, left: str | DimensionVector, right: str | DimensionVector) -> DimensionVector:
        return self._dimension_value(left) / self._dimension_value(right)

    def power(self, value: str | DimensionVector, exponent: int) -> DimensionVector:
        return self._dimension_value(value) ** exponent

    def feature_dimension(self, node: "FeatureNode") -> DimensionVector:
        result = DimensionVector.dimensionless()
        for term in node.terms:
            result = result * (self.dimension(term.units) ** term.exponent)
        return result

    def _dimension_value(self, value: str | DimensionVector) -> DimensionVector:
        return value if isinstance(value, DimensionVector) else self.dimension(value)


@dataclass(frozen=True)
class FeatureTerm:
    field_name: str
    units: str
    exponent: int = 1

    def __post_init__(self) -> None:
        if not self.field_name:
            raise S2ContractModelError("feature terms require field_name")
        if not self.units:
            raise S2ContractModelError(f"feature term {self.field_name!r} requires units")
        object.__setattr__(self, "exponent", int(self.exponent))


@dataclass(frozen=True)
class FeatureNode:
    node_id: str
    terms: tuple[FeatureTerm, ...]
    declared_units: str

    def __post_init__(self) -> None:
        if not self.node_id:
            raise S2ContractModelError("feature nodes require node_id")
        if not self.terms:
            raise S2ContractModelError(f"feature node {self.node_id!r} requires at least one term")
        if not self.declared_units:
            raise S2ContractModelError(f"feature node {self.node_id!r} requires declared_units")
        object.__setattr__(self, "terms", tuple(self.terms))


@dataclass(frozen=True)
class FeatureDimensionValidation:
    valid_nodes: tuple[FeatureNode, ...]
    rejected_nodes: tuple[FeatureNode, ...]
    errors: tuple[DimensionalError, ...]


def validate_feature_graph_dimensions(
    nodes: tuple[FeatureNode, ...],
    *,
    algebra: UnitsAlgebra | None = None,
    raise_on_error: bool = True,
) -> FeatureDimensionValidation:
    units = algebra or UnitsAlgebra()
    valid_nodes: list[FeatureNode] = []
    rejected_nodes: list[FeatureNode] = []
    errors: list[DimensionalError] = []
    for node in nodes:
        actual = units.feature_dimension(node)
        expected = units.dimension(node.declared_units)
        if actual != expected:
            rejected_nodes.append(node)
            errors.append(
                DimensionalError(
                    node_id=node.node_id,
                    expected=expected,
                    actual=actual,
                    valid_nodes=tuple(valid_nodes),
                )
            )
            continue
        valid_nodes.append(node)
    validation = FeatureDimensionValidation(
        valid_nodes=tuple(valid_nodes),
        rejected_nodes=tuple(rejected_nodes),
        errors=tuple(errors),
    )
    if raise_on_error and validation.errors:
        raise validation.errors[0]
    return validation


def _base_dimension(name: str) -> DimensionVector:
    values = [0] * len(S2_DIMENSION_BASES)
    values[S2_DIMENSION_BASES.index(name)] = 1
    return DimensionVector(tuple(values))


def _unit_expression_tokens(expression: str) -> tuple[str, ...]:
    tokens: list[str] = []
    current: list[str] = []
    expect_operand = True
    for char in expression:
        if char in "*/":
            if not current:
                if expect_operand:
                    raise S2ContractModelError(f"invalid unit expression: {expression}")
            else:
                tokens.append("".join(current))
                current = []
            tokens.append(char)
            expect_operand = True
        else:
            current.append(char)
            expect_operand = False
    if current:
        tokens.append("".join(current))
    elif tokens and tokens[-1] in {"*", "/"}:
        raise S2ContractModelError(f"invalid unit expression: {expression}")
    if not tokens:
        raise S2ContractModelError("unit expression is empty")
    return tuple(tokens)


def _unit_token_power(token: str) -> tuple[str, int]:
    if token == "1":
        return "1", 1
    if "^" not in token:
        return token, 1
    symbol, exponent = token.split("^", 1)
    if not symbol or not exponent:
        raise S2ContractModelError(f"invalid unit power expression: {token}")
    try:
        return symbol, int(exponent)
    except ValueError as exc:
        raise S2ContractModelError(f"unit exponents must be integers: {token}") from exc


@dataclass(frozen=True)
class C3VerifierProfile:
    profile_ref: str
    profile_id: str
    version: str
    checks: tuple[str, ...]
    provenance_ref: str

    def __post_init__(self) -> None:
        if not self.profile_ref:
            raise S2ContractModelError("C3 verifier profile requires profile_ref")
        if not self.profile_id:
            raise S2ContractModelError("C3 verifier profile requires profile_id")
        if not self.version:
            raise S2ContractModelError("C3 verifier profile requires version")
        object.__setattr__(self, "checks", tuple(self.checks))


class C3VerifierProfileCatalog:
    """Presence-only C3 verifier profile catalog used by S2 preflight."""

    def __init__(self, profiles: tuple[C3VerifierProfile, ...] = ()) -> None:
        self._profiles: dict[str, C3VerifierProfile] = {}
        for profile in profiles:
            self.register(profile)

    def register(self, profile: C3VerifierProfile) -> C3VerifierProfile:
        self._profiles[profile.profile_ref] = profile
        return profile

    def resolve(self, profile_ref: str) -> C3VerifierProfile:
        try:
            return self._profiles[profile_ref]
        except KeyError as exc:
            raise KeyError(profile_ref) from exc


@dataclass(frozen=True)
class ResolvedC5Descriptor:
    entity_id: str
    revision: int
    kind: str
    owner_subsystem: str
    provenance_ref: str
    capability_scopes: tuple[str, ...]
    contract_versions: tuple[tuple[str, str], ...]

    @classmethod
    def from_descriptor(cls, descriptor: CapabilityDescriptor) -> "ResolvedC5Descriptor":
        return cls(
            entity_id=descriptor.entity_id,
            revision=descriptor.revision,
            kind=descriptor.kind,
            owner_subsystem=descriptor.owner_subsystem,
            provenance_ref=descriptor.provenance_ref,
            capability_scopes=tuple(descriptor.capability_scopes),
            contract_versions=tuple(sorted((str(k), str(v)) for k, v in descriptor.contract_versions.items())),
        )


@dataclass(frozen=True)
class ResolvedC4Artifact:
    artifact_ref: str
    kind: str
    content_hash: str
    producer_subsystem: str

    @classmethod
    def from_record(cls, record: ArtifactRecord) -> "ResolvedC4Artifact":
        return cls(
            artifact_ref=record.artifact_ref,
            kind=record.kind,
            content_hash=record.content_hash,
            producer_subsystem=record.producer.subsystem,
        )


@dataclass(frozen=True)
class BuildBudget:
    max_usd: float
    max_wallclock_seconds: int
    max_gpu_seconds: float | None = None
    max_model_tokens: int | None = None

    def __post_init__(self) -> None:
        if self.max_usd < 0:
            raise S2ContractModelError("S2 build budget max_usd must be non-negative")
        if self.max_wallclock_seconds < 0:
            raise S2ContractModelError("S2 build budget max_wallclock_seconds must be non-negative")
        if self.max_gpu_seconds is not None and self.max_gpu_seconds < 0:
            raise S2ContractModelError("S2 build budget max_gpu_seconds must be non-negative")
        if self.max_model_tokens is not None and self.max_model_tokens < 0:
            raise S2ContractModelError("S2 build budget max_model_tokens must be non-negative")


@dataclass(frozen=True)
class PartialModelCheckpoint:
    artifact_ref: str
    reason: str
    metrics: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.artifact_ref:
            raise S2ContractModelError("S2 partial checkpoints require artifact_ref")
        if not self.reason:
            raise S2ContractModelError("S2 partial checkpoints require reason")


@dataclass(frozen=True)
class SpendSnapshot:
    job_id: str
    wallclock_seconds: float
    gpu_seconds: float
    model_tokens: int
    cost_usd: float
    halted_reason: str | None = None
    partial_checkpoint: PartialModelCheckpoint | None = None

    def as_cost_actual(self) -> dict[str, float | int]:
        return {
            "wallclock_seconds": self.wallclock_seconds,
            "gpu_seconds": self.gpu_seconds,
            "model_tokens": self.model_tokens,
            "cost_usd": self.cost_usd,
        }


class S2BudgetExceededError(S2Error):
    """Raised when S2 metered spend exceeds a hard C2-derived budget cap."""

    def __init__(
        self,
        *,
        code: str,
        message: str,
        snapshot: SpendSnapshot,
        limit: float | int,
        observed: float | int,
        grace_limit: float | int,
        partial_checkpoint: PartialModelCheckpoint | None = None,
    ) -> None:
        super().__init__(message)
        self.category = "BUDGET"
        self.code = code
        self.message = message
        self.retryable = False
        self.snapshot = snapshot
        self.limit = limit
        self.observed = observed
        self.grace_limit = grace_limit
        self.partial_checkpoint = partial_checkpoint

    def as_c1_payload(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "cost_actual": self.snapshot.as_cost_actual(),
            "partial_checkpoint_ref": self.partial_checkpoint.artifact_ref if self.partial_checkpoint else None,
        }


class BudgetMeter:
    """S2 spend meter that fails closed on hard budget breaches."""

    def __init__(
        self,
        *,
        job_id: str,
        budget: BuildBudget,
        grace_fraction: float = 0.0,
    ) -> None:
        if not job_id:
            raise S2ContractModelError("S2 BudgetMeter requires job_id")
        if grace_fraction < 0:
            raise S2ContractModelError("S2 BudgetMeter grace_fraction must be non-negative")
        self._job_id = job_id
        self._budget = budget
        self._grace_fraction = float(grace_fraction)
        self._snapshot = SpendSnapshot(
            job_id=job_id,
            wallclock_seconds=0.0,
            gpu_seconds=0.0,
            model_tokens=0,
            cost_usd=0.0,
        )
        self._halt_error: S2BudgetExceededError | None = None

    @classmethod
    def from_budget(
        cls,
        *,
        job_id: str,
        budget: BuildBudget,
        grace_fraction: float = 0.0,
    ) -> "BudgetMeter":
        return cls(job_id=job_id, budget=budget, grace_fraction=grace_fraction)

    @property
    def job_id(self) -> str:
        return self._job_id

    @property
    def budget(self) -> BuildBudget:
        return self._budget

    def record(
        self,
        *,
        wallclock_seconds: float = 0.0,
        gpu_seconds: float = 0.0,
        model_tokens: int = 0,
        cost_usd: float = 0.0,
        partial_checkpoint: PartialModelCheckpoint | None = None,
    ) -> SpendSnapshot:
        if self._halt_error is not None:
            raise self._halt_error
        self._assert_non_negative(
            wallclock_seconds=wallclock_seconds,
            gpu_seconds=gpu_seconds,
            model_tokens=model_tokens,
            cost_usd=cost_usd,
        )
        next_snapshot = SpendSnapshot(
            job_id=self._job_id,
            wallclock_seconds=self._snapshot.wallclock_seconds + float(wallclock_seconds),
            gpu_seconds=self._snapshot.gpu_seconds + float(gpu_seconds),
            model_tokens=self._snapshot.model_tokens + int(model_tokens),
            cost_usd=self._snapshot.cost_usd + float(cost_usd),
        )
        breach = self._breach(next_snapshot)
        if breach is not None:
            code, limit, observed = breach
            halted = SpendSnapshot(
                job_id=next_snapshot.job_id,
                wallclock_seconds=next_snapshot.wallclock_seconds,
                gpu_seconds=next_snapshot.gpu_seconds,
                model_tokens=next_snapshot.model_tokens,
                cost_usd=next_snapshot.cost_usd,
                halted_reason=code,
                partial_checkpoint=partial_checkpoint,
            )
            self._snapshot = halted
            self._halt_error = S2BudgetExceededError(
                code=code,
                message=f"S2 budget exceeded: {code}",
                snapshot=halted,
                limit=limit,
                observed=observed,
                grace_limit=self._grace_limit(limit),
                partial_checkpoint=partial_checkpoint,
            )
            raise self._halt_error
        self._snapshot = next_snapshot
        return self._snapshot

    def snapshot(self) -> SpendSnapshot:
        return self._snapshot

    def assert_open(self) -> None:
        if self._halt_error is not None:
            raise self._halt_error

    def _breach(self, snapshot: SpendSnapshot) -> tuple[str, float | int, float | int] | None:
        if snapshot.wallclock_seconds > self._budget.max_wallclock_seconds:
            return ("WALLCLOCK_SECONDS_EXCEEDED", self._budget.max_wallclock_seconds, snapshot.wallclock_seconds)
        if self._budget.max_gpu_seconds is not None and snapshot.gpu_seconds > self._budget.max_gpu_seconds:
            return ("GPU_SECONDS_EXCEEDED", self._budget.max_gpu_seconds, snapshot.gpu_seconds)
        if self._budget.max_model_tokens is not None and snapshot.model_tokens > self._budget.max_model_tokens:
            return ("MODEL_TOKENS_EXCEEDED", self._budget.max_model_tokens, snapshot.model_tokens)
        if snapshot.cost_usd > self._budget.max_usd:
            return ("COST_USD_EXCEEDED", self._budget.max_usd, snapshot.cost_usd)
        return None

    def _grace_limit(self, limit: float | int) -> float:
        return float(limit) * (1.0 + self._grace_fraction)

    @staticmethod
    def _assert_non_negative(
        *,
        wallclock_seconds: float,
        gpu_seconds: float,
        model_tokens: int,
        cost_usd: float,
    ) -> None:
        if wallclock_seconds < 0:
            raise S2ContractModelError("S2 BudgetMeter wallclock_seconds increments must be non-negative")
        if gpu_seconds < 0:
            raise S2ContractModelError("S2 BudgetMeter gpu_seconds increments must be non-negative")
        if model_tokens < 0:
            raise S2ContractModelError("S2 BudgetMeter model_tokens increments must be non-negative")
        if cost_usd < 0:
            raise S2ContractModelError("S2 BudgetMeter cost_usd increments must be non-negative")


@dataclass(frozen=True)
class BuildSpec:
    job_id: str
    trace_id: str
    subtopic: str
    task_type: str
    target_observable: str
    required_claim_tier_max: str
    verifier_profile_ref: str
    budget: BuildBudget
    input_artifact_refs: tuple[str, ...]
    allowed_adapters: tuple[str, ...]
    allowed_datasets: tuple[str, ...]
    fields: tuple[FieldSpec, ...] = ()
    constraints: dict[str, Any] = field(default_factory=dict)
    verifier_profile: C3VerifierProfile | None = None
    resolved_adapters: tuple[ResolvedC5Descriptor, ...] = ()
    resolved_datasets: tuple[ResolvedC5Descriptor, ...] = ()
    resolved_input_artifacts: tuple[ResolvedC4Artifact, ...] = ()


@dataclass(frozen=True)
class ModelFamilyDescriptor:
    family_id: str
    family_kind: str
    differentiable: bool
    physics_informed: bool
    native_uq: str
    name: str = ""
    task_types: tuple[str, ...] = ("regression",)
    cost_class: str = "standard"
    deterministic_training: bool = True
    supported_constraints: tuple[str, ...] = ()
    training_entrypoint: str = ""
    prediction_entrypoint: str = ""
    provenance_ref: str = ""

    def __post_init__(self) -> None:
        family_id = self.family_id.strip()
        if not family_id:
            raise S2ContractModelError("model family descriptors require family_id")
        family_kind = self.family_kind.strip()
        if not family_kind:
            raise S2ContractModelError(f"model family {family_id!r} requires family_kind")
        native_uq = self.native_uq.strip()
        if not native_uq:
            raise S2ContractModelError(f"model family {family_id!r} requires native_uq")
        cost_class = self.cost_class.strip()
        if not cost_class:
            raise S2ContractModelError(f"model family {family_id!r} requires cost_class")
        task_types = tuple(str(task_type).strip() for task_type in self.task_types)
        if not task_types or any(not task_type for task_type in task_types):
            raise S2ContractModelError(f"model family {family_id!r} requires task_types")
        supported_constraints = tuple(str(constraint).strip() for constraint in self.supported_constraints)
        if any(not constraint for constraint in supported_constraints):
            raise S2ContractModelError(f"model family {family_id!r} has an empty supported constraint")
        safe_entrypoint_id = family_id.replace("-", "_")
        training_entrypoint = self.training_entrypoint or f"argus_core.s2.model_families.{safe_entrypoint_id}.train"
        prediction_entrypoint = self.prediction_entrypoint or f"argus_core.s2.model_families.{safe_entrypoint_id}.predict"
        provenance_ref = self.provenance_ref or f"c4://model-family/{family_id}/{S2_MODEL_REGISTRY_VERSION}"
        if not provenance_ref.startswith("c4://"):
            raise S2ContractModelError(f"model family {family_id!r} requires a C4 provenance_ref")
        object.__setattr__(self, "family_id", family_id)
        object.__setattr__(self, "family_kind", family_kind)
        object.__setattr__(self, "native_uq", native_uq)
        object.__setattr__(self, "name", self.name.strip() or family_id.replace("-", " ").title())
        object.__setattr__(self, "task_types", task_types)
        object.__setattr__(self, "cost_class", cost_class)
        object.__setattr__(self, "supported_constraints", supported_constraints)
        object.__setattr__(self, "training_entrypoint", training_entrypoint)
        object.__setattr__(self, "prediction_entrypoint", prediction_entrypoint)
        object.__setattr__(self, "provenance_ref", provenance_ref)

    def as_c4_payload(self) -> dict[str, Any]:
        return {
            "family_id": self.family_id,
            "name": self.name,
            "family_kind": self.family_kind,
            "task_types": list(self.task_types),
            "cost_class": self.cost_class,
            "differentiable": self.differentiable,
            "physics_informed": self.physics_informed,
            "native_uq": self.native_uq,
            "deterministic_training": self.deterministic_training,
            "supported_constraints": list(self.supported_constraints),
            "training_entrypoint": self.training_entrypoint,
            "prediction_entrypoint": self.prediction_entrypoint,
            "provenance_ref": self.provenance_ref,
            "registry_version": S2_MODEL_REGISTRY_VERSION,
        }


class ModelFamilyRegistry:
    """Descriptor registry for S2 model-family metadata, not a training runtime."""

    def __init__(self, descriptors: tuple[ModelFamilyDescriptor, ...] = ()) -> None:
        self._descriptors: dict[str, ModelFamilyDescriptor] = {}
        for descriptor in descriptors:
            self.register(descriptor)

    @classmethod
    def default(cls) -> "ModelFamilyRegistry":
        return cls(_default_model_family_descriptors())

    def register(self, descriptor: ModelFamilyDescriptor) -> ModelFamilyDescriptor:
        if not isinstance(descriptor, ModelFamilyDescriptor):
            raise S2ContractModelError("model family registry accepts only ModelFamilyDescriptor values")
        if descriptor.family_id in self._descriptors:
            raise S2ContractModelError(f"duplicate S2 model family descriptor: {descriptor.family_id}")
        self._descriptors[descriptor.family_id] = descriptor
        return descriptor

    def get(self, family_id: str) -> ModelFamilyDescriptor:
        try:
            return self._descriptors[family_id]
        except KeyError as exc:
            raise S2ContractModelError(f"unknown S2 model family: {family_id}") from exc

    def list(self) -> tuple[ModelFamilyDescriptor, ...]:
        return tuple(self._descriptors.values())


@dataclass(frozen=True)
class HPOTrial:
    trial_id: str
    score: float
    calibration_error: float
    cost: float
    parameters: dict[str, Any]
    family_id: str = ""
    status: str = "SUCCEEDED"
    checkpoint_ref: str | None = None
    training_log_ref: str | None = None
    trial_artifact_ref: str | None = None
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        trial_id = self.trial_id.strip()
        family_id = self.family_id.strip()
        status = self.status.strip()
        if not trial_id:
            raise S2ContractModelError("S2 HPO trials require trial_id")
        if status not in {"SUCCEEDED", "WARM_STARTED", "BUDGET_HALTED", "CANCELLED", "INTERRUPTED", "FAILED"}:
            raise S2ContractModelError(f"unsupported S2 HPO trial status: {status}")
        if self.calibration_error < 0:
            raise S2ContractModelError("S2 HPO trial calibration_error must be non-negative")
        if self.cost < 0:
            raise S2ContractModelError("S2 HPO trial cost must be non-negative")
        object.__setattr__(self, "trial_id", trial_id)
        object.__setattr__(self, "family_id", family_id)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "parameters", dict(self.parameters))
        object.__setattr__(self, "diagnostics", dict(self.diagnostics))


@dataclass(frozen=True)
class HPOSelection:
    trial_id: str
    parameters: dict[str, Any]
    score: float
    calibration_error: float
    cost: float
    family_id: str = ""
    selection_artifact_ref: str | None = None
    trial_artifact_refs: tuple[str, ...] = ()
    pareto_front_trial_ids: tuple[str, ...] = ()
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.trial_id:
            raise S2ContractModelError("S2 HPO selection requires trial_id")
        if self.calibration_error < 0:
            raise S2ContractModelError("S2 HPO selection calibration_error must be non-negative")
        if self.cost < 0:
            raise S2ContractModelError("S2 HPO selection cost must be non-negative")
        object.__setattr__(self, "parameters", dict(self.parameters))
        object.__setattr__(self, "trial_artifact_refs", tuple(self.trial_artifact_refs))
        object.__setattr__(self, "pareto_front_trial_ids", tuple(self.pareto_front_trial_ids))
        object.__setattr__(self, "diagnostics", dict(self.diagnostics))


@dataclass(frozen=True)
class HPORequest:
    job_id: str
    family_ids: tuple[str, ...]
    parameter_grid: Mapping[str, tuple[Any, ...]]
    input_refs: tuple[str, ...]
    training_rows: tuple[Mapping[str, Any], ...]
    feature_names: tuple[str, ...]
    target_name: str
    max_epochs: int
    code_ref: str
    environment_digest: str
    seed: str
    objective_metric: str = "loss"
    objective: str = "minimize"
    learning_rate: float = 0.01
    wallclock_seconds_per_epoch: float = 0.0
    gpu_seconds_per_epoch: float = 0.0
    model_tokens_per_epoch: int = 0
    cost_usd_per_epoch: float = 0.0
    max_trials: int | None = None
    max_calibration_error: float | None = None
    trial_budget: BuildBudget | None = None
    warm_start_trials: tuple[HPOTrial, ...] = ()
    warm_start_ref: str | None = None

    def __post_init__(self) -> None:
        job_id = self.job_id.strip()
        family_ids = tuple(str(family_id).strip() for family_id in self.family_ids)
        input_refs = tuple(str(ref).strip() for ref in self.input_refs)
        feature_names = tuple(str(name).strip() for name in self.feature_names)
        target_name = self.target_name.strip()
        objective_metric = self.objective_metric.strip()
        code_ref = self.code_ref.strip()
        environment_digest = self.environment_digest.strip()
        seed = self.seed.strip()
        if not job_id:
            raise S2ContractModelError("S2 HPORequest requires job_id")
        if not family_ids or any(not family_id for family_id in family_ids):
            raise S2ContractModelError("S2 HPORequest requires family_ids")
        if len(set(family_ids)) != len(family_ids):
            raise S2ContractModelError("S2 HPORequest family_ids must be unique")
        if not input_refs or any(not ref for ref in input_refs):
            raise S2ContractModelError("S2 HPORequest requires input_refs")
        if not self.training_rows:
            raise S2ContractModelError("S2 HPORequest requires training_rows")
        if not feature_names or any(not name for name in feature_names):
            raise S2ContractModelError("S2 HPORequest requires feature_names")
        if not target_name:
            raise S2ContractModelError("S2 HPORequest requires target_name")
        if self.max_epochs <= 0:
            raise S2ContractModelError("S2 HPORequest max_epochs must be positive")
        if self.learning_rate <= 0:
            raise S2ContractModelError("S2 HPORequest learning_rate must be positive")
        if self.objective not in {"maximize", "minimize"}:
            raise S2ContractModelError(f"unsupported S2 HPO objective: {self.objective}")
        if not objective_metric:
            raise S2ContractModelError("S2 HPORequest requires objective_metric")
        if not code_ref:
            raise S2ContractModelError("S2 HPORequest requires code_ref")
        if not environment_digest:
            raise S2ContractModelError("S2 HPORequest requires environment_digest")
        if not seed:
            raise S2ContractModelError("S2 HPORequest requires seed")
        if self.wallclock_seconds_per_epoch < 0:
            raise S2ContractModelError("S2 HPORequest wallclock_seconds_per_epoch must be non-negative")
        if self.gpu_seconds_per_epoch < 0:
            raise S2ContractModelError("S2 HPORequest gpu_seconds_per_epoch must be non-negative")
        if self.model_tokens_per_epoch < 0:
            raise S2ContractModelError("S2 HPORequest model_tokens_per_epoch must be non-negative")
        if self.cost_usd_per_epoch < 0:
            raise S2ContractModelError("S2 HPORequest cost_usd_per_epoch must be non-negative")
        if self.max_trials is not None and self.max_trials < 0:
            raise S2ContractModelError("S2 HPORequest max_trials must be non-negative")
        if self.max_calibration_error is not None and self.max_calibration_error < 0:
            raise S2ContractModelError("S2 HPORequest max_calibration_error must be non-negative")
        normalized_rows: list[dict[str, Any]] = []
        for row in self.training_rows:
            normalized = dict(row)
            for name in feature_names + (target_name,):
                if name not in normalized:
                    raise S2ContractModelError(f"S2 HPORequest row missing field: {name}")
            normalized_rows.append(normalized)
        normalized_grid = _normalize_hpo_parameter_grid(self.parameter_grid)
        warm_start_ids: set[str] = set()
        for trial in self.warm_start_trials:
            if trial.status != "SUCCEEDED":
                raise S2ContractModelError("S2 HPO warm-start trials must be completed SUCCEEDED trials")
            if trial.trial_id in warm_start_ids:
                raise S2ContractModelError(f"duplicate S2 HPO warm-start trial: {trial.trial_id}")
            warm_start_ids.add(trial.trial_id)
        object.__setattr__(self, "job_id", job_id)
        object.__setattr__(self, "family_ids", family_ids)
        object.__setattr__(self, "parameter_grid", normalized_grid)
        object.__setattr__(self, "input_refs", input_refs)
        object.__setattr__(self, "training_rows", tuple(normalized_rows))
        object.__setattr__(self, "feature_names", feature_names)
        object.__setattr__(self, "target_name", target_name)
        object.__setattr__(self, "objective_metric", objective_metric)
        object.__setattr__(self, "code_ref", code_ref)
        object.__setattr__(self, "environment_digest", environment_digest)
        object.__setattr__(self, "seed", seed)
        object.__setattr__(self, "warm_start_trials", tuple(self.warm_start_trials))


@dataclass(frozen=True)
class HPORunResult:
    job_id: str
    status: str
    trials: tuple[HPOTrial, ...]
    selected: HPOSelection
    trial_artifact_refs: tuple[str, ...]
    selection_artifact_ref: str
    diagnostics: dict[str, Any]
    wallclock_seconds: float


class HPOEngine:
    """Executes S2 HPO trials through Optuna search, Ray Tune scheduling, and C4 provenance."""

    def __init__(
        self,
        *,
        artifact_store: InMemoryArtifactStore,
        provenance_emitter: ProvenanceEmitter | None = None,
        registry: ModelFamilyRegistry | None = None,
        backends: Mapping[str, DeterministicLinearTrainingBackend] | None = None,
        worker_count: int = 1,
        scheduler_backend: str = "optuna_ray",
        ray_storage_path: str | None = None,
    ) -> None:
        if worker_count <= 0:
            raise S2ContractModelError("S2 HPOEngine worker_count must be positive")
        if scheduler_backend not in {"optuna_ray", "threadpool"}:
            raise S2ContractModelError(f"unsupported S2 HPOEngine scheduler_backend: {scheduler_backend}")
        self._artifact_store = artifact_store
        self._provenance_emitter = provenance_emitter or ProvenanceEmitter(artifact_store=artifact_store)
        self._registry = registry or _default_model_family_registry()
        self._backends = dict(backends or {})
        self._worker_count = int(worker_count)
        self._scheduler_backend = scheduler_backend
        self._ray_storage_path = ray_storage_path

    def run(self, request: HPORequest) -> HPORunResult:
        started_at = time.perf_counter()
        trial_specs = self._trial_specs(request)
        warm_trials = tuple(self._emit_warm_started_trial(request, trial) for trial in request.warm_start_trials)
        new_trials = self._run_trial_specs(request, trial_specs)
        trials = warm_trials + new_trials
        eligible_trials = tuple(trial for trial in trials if trial.status in {"SUCCEEDED", "WARM_STARTED"})
        if not eligible_trials:
            raise S2Error("S2 HPOEngine produced no eligible trial")
        selected = self._select_with_optuna_study(request=request, eligible_trials=eligible_trials)
        selection_record = self._emit_selection(request=request, trials=trials, selected=selected)
        selected_with_ref = HPOSelection(
            trial_id=selected.trial_id,
            parameters=selected.parameters,
            score=selected.score,
            calibration_error=selected.calibration_error,
            cost=selected.cost,
            family_id=selected.family_id,
            selection_artifact_ref=selection_record.artifact_ref,
            trial_artifact_refs=tuple(trial.trial_artifact_ref for trial in trials if trial.trial_artifact_ref),
            pareto_front_trial_ids=selected.pareto_front_trial_ids,
            diagnostics=selected.diagnostics,
        )
        elapsed = time.perf_counter() - started_at
        return HPORunResult(
            job_id=request.job_id,
            status="SUCCEEDED",
            trials=trials,
            selected=selected_with_ref,
            trial_artifact_refs=tuple(trial.trial_artifact_ref for trial in trials if trial.trial_artifact_ref),
            selection_artifact_ref=selection_record.artifact_ref,
            diagnostics={
                "objective": request.objective,
                "objective_metric": request.objective_metric,
                "worker_count": self._worker_count,
                "eligible_trial_count": len(eligible_trials),
                "search_backend": "optuna",
                "scheduler_backend": "ray_tune" if self._scheduler_backend == "optuna_ray" else "threadpool",
                "ray_scheduler": "ASHAScheduler" if self._scheduler_backend == "optuna_ray" else None,
                "optuna_sampler": "NSGAIISampler",
            },
            wallclock_seconds=elapsed,
        )

    def _trial_specs(self, request: HPORequest) -> tuple[dict[str, Any], ...]:
        parameter_names = tuple(sorted(request.parameter_grid))
        parameter_value_sets = tuple(tuple(request.parameter_grid[name]) for name in parameter_names)
        specs: list[dict[str, Any]] = []
        seen_trial_ids: set[str] = set()
        for family_id in request.family_ids:
            self._registry.get(family_id)
            for values in product(*parameter_value_sets):
                parameters = dict(zip(parameter_names, values))
                index = len(specs) + 1
                trial_id = self._trial_id(request=request, family_id=family_id, parameters=parameters, index=index)
                if trial_id in seen_trial_ids:
                    raise S2ContractModelError(f"duplicate S2 HPO trial id: {trial_id}")
                seen_trial_ids.add(trial_id)
                specs.append(
                    {
                        "index": index,
                        "trial_id": trial_id,
                        "family_id": family_id,
                        "parameters": parameters,
                    }
                )
        if request.max_trials is not None:
            specs = specs[: request.max_trials]
        if not specs and not request.warm_start_trials:
            raise S2ContractModelError("S2 HPOEngine requires at least one scheduled or warm-start trial")
        return tuple(specs)

    def _run_trial_specs(self, request: HPORequest, specs: tuple[dict[str, Any], ...]) -> tuple[HPOTrial, ...]:
        if not specs:
            return ()
        if self._scheduler_backend == "optuna_ray":
            return self._run_trial_specs_with_ray_tune(request, specs)
        if self._worker_count == 1 or len(specs) == 1:
            return tuple(self._run_training_trial(request, spec) for spec in specs)
        results: dict[int, HPOTrial] = {}
        with ThreadPoolExecutor(max_workers=self._worker_count) as executor:
            futures = {executor.submit(self._run_training_trial, request, spec): int(spec["index"]) for spec in specs}
            for future in as_completed(futures):
                results[futures[future]] = future.result()
        return tuple(results[index] for index in sorted(results))

    def _run_trial_specs_with_ray_tune(
        self,
        request: HPORequest,
        specs: tuple[dict[str, Any], ...],
    ) -> tuple[HPOTrial, ...]:
        ray, tune, RunConfig, ASHAScheduler = _import_ray_tune()
        _ensure_ray_initialized(ray, worker_count=self._worker_count)
        os.environ.setdefault("RAY_AIR_NEW_OUTPUT", "0")
        tune_metric = "argus_objective"
        tune_mode = "max" if request.objective == "maximize" else "min"
        trainable = tune.with_parameters(
            _ray_tune_hpo_trainable,
            request=request,
            registry=self._registry,
            backends=self._backends,
        )
        scheduler = ASHAScheduler(
            metric=tune_metric,
            mode=tune_mode,
            max_t=max(1, request.max_epochs),
            grace_period=1,
            reduction_factor=2,
        )
        storage_context = tempfile.TemporaryDirectory(prefix="argus-hpo-ray-") if self._ray_storage_path is None else None
        storage_path = self._ray_storage_path or storage_context.name
        try:
            tuner = tune.Tuner(
                trainable,
                param_space={"spec": tune.grid_search([dict(spec) for spec in specs])},
                tune_config=tune.TuneConfig(
                    max_concurrent_trials=self._worker_count,
                    scheduler=scheduler,
                ),
                run_config=RunConfig(
                    name=f"{request.job_id}-ray-tune",
                    storage_path=storage_path,
                    verbose=0,
                ),
            )
            result_grid = tuner.fit()
            packets: dict[int, dict[str, Any]] = {}
            errors: list[str] = []
            for result in result_grid:
                if result.error is not None:
                    errors.append(str(result.error))
                    continue
                packet_path = result.metrics.get("argus_trial_packet_path")
                if not isinstance(packet_path, str) or not packet_path:
                    errors.append(f"Ray Tune result missing argus_trial_packet_path for config {result.config}")
                    continue
                try:
                    with open(packet_path, "r", encoding="utf-8") as packet_file:
                        packet = json.load(packet_file)
                except OSError as exc:
                    errors.append(f"Ray Tune packet read failed for config {result.config}: {exc}")
                    continue
                packet = dict(packet)
                diagnostics = dict(packet.get("diagnostics", {}))
                diagnostics.update(
                    {
                        "scheduler_backend": "ray_tune",
                        "ray_scheduler": "ASHAScheduler",
                        "ray_tune_trial_path": str(getattr(result, "path", "")),
                    }
                )
                packet["diagnostics"] = diagnostics
                packets[int(packet["index"])] = packet
            expected_indexes = {int(spec["index"]) for spec in specs}
            if errors:
                raise S2Error("S2 Ray Tune HPO trial execution failed: " + "; ".join(errors))
            if set(packets) != expected_indexes:
                raise S2Error("S2 Ray Tune HPO did not return every scheduled trial")
            return tuple(self._materialize_trial_packet(request, packets[index]) for index in sorted(packets))
        finally:
            if storage_context is not None:
                storage_context.cleanup()

    def _materialize_trial_packet(self, request: HPORequest, packet: Mapping[str, Any]) -> HPOTrial:
        for artifact_packet in packet.get("artifact_packets", ()):
            _import_hpo_artifact_packet(self._artifact_store, artifact_packet)
        status = str(packet["status"])
        if status in {"SUCCEEDED", "CANCELLED", "INTERRUPTED"}:
            return self._emit_completed_trial(
                request=request,
                trial_id=str(packet["trial_id"]),
                family_id=str(packet["family_id"]),
                parameters=dict(packet["parameters"]),
                status=status,
                score=float(packet["score"]),
                calibration_error=float(packet["calibration_error"]),
                cost=float(packet["cost"]),
                checkpoint_ref=packet.get("checkpoint_ref"),
                training_log_ref=packet.get("training_log_ref"),
                completed_epochs=int(packet.get("completed_epochs", 0)),
                diagnostics=dict(packet.get("diagnostics", {})),
            )
        partial_payload = packet.get("partial_checkpoint")
        partial_checkpoint = None
        if isinstance(partial_payload, Mapping):
            partial_checkpoint = PartialModelCheckpoint(
                artifact_ref=str(partial_payload["artifact_ref"]),
                reason=str(partial_payload.get("reason", status)),
                metrics=dict(partial_payload.get("metrics", {})),
            )
        return self._emit_failed_trial(
            request=request,
            trial_id=str(packet["trial_id"]),
            family_id=str(packet["family_id"]),
            parameters=dict(packet["parameters"]),
            status=status,
            error_code=str(packet["error_code"]),
            error_message=str(packet["error_message"]),
            cost_actual=dict(packet["cost_actual"]),
            partial_checkpoint=partial_checkpoint,
        )

    def _select_with_optuna_study(
        self,
        *,
        request: HPORequest,
        eligible_trials: tuple[HPOTrial, ...],
    ) -> HPOSelection:
        max_calibration_error = request.max_calibration_error if request.max_calibration_error is not None else float("inf")
        eligible = tuple(trial for trial in eligible_trials if trial.calibration_error <= max_calibration_error)
        if not eligible:
            raise S2Error("no HPO trial satisfies calibration constraint")
        study = _build_optuna_hpo_study(request=request, trials=eligible)
        pareto_trial_ids = tuple(sorted(str(trial.user_attrs["argus_trial_id"]) for trial in study.best_trials))
        pareto_trials = tuple(trial for trial in eligible if trial.trial_id in set(pareto_trial_ids))
        if not pareto_trials:
            raise S2Error("Optuna HPO study produced an empty Pareto front")
        selected = sorted(pareto_trials, key=lambda trial: _hpo_selection_key(trial, objective=request.objective))[0]
        return HPOSelection(
            trial_id=selected.trial_id,
            parameters=selected.parameters,
            score=selected.score,
            calibration_error=selected.calibration_error,
            cost=selected.cost,
            family_id=selected.family_id,
            trial_artifact_refs=tuple(trial.trial_artifact_ref for trial in eligible if trial.trial_artifact_ref),
            pareto_front_trial_ids=pareto_trial_ids,
            diagnostics={
                "policy": "pareto_lexicographic",
                "objective": request.objective,
                "search_backend": "optuna",
                "optuna_study_name": study.study_name,
                "optuna_sampler": "NSGAIISampler",
                "optuna_directions": tuple(direction.name for direction in study.directions),
                "optuna_trial_count": len(study.trials),
            },
        )

    def _run_training_trial(self, request: HPORequest, spec: Mapping[str, Any]) -> HPOTrial:
        trial_id = str(spec["trial_id"])
        family_id = str(spec["family_id"])
        parameters = dict(spec["parameters"])
        trial_job_id = f"{request.job_id}:{trial_id}"
        meter = BudgetMeter.from_budget(job_id=trial_job_id, budget=request.trial_budget) if request.trial_budget else None
        runtime = TrainingRuntime(
            artifact_store=self._artifact_store,
            provenance_emitter=self._provenance_emitter,
            registry=self._registry,
            budget_meter=meter,
            backends=self._backends,
        )
        try:
            result = runtime.train(
                TrainingRequest(
                    job_id=trial_job_id,
                    family_id=family_id,
                    input_refs=request.input_refs,
                    training_rows=request.training_rows,
                    feature_names=request.feature_names,
                    target_name=request.target_name,
                    max_epochs=int(parameters.get("max_epochs", request.max_epochs)),
                    learning_rate=float(parameters.get("learning_rate", request.learning_rate)),
                    code_ref=request.code_ref,
                    environment_digest=request.environment_digest,
                    seed=f"{request.seed}:{trial_id}",
                    parameters=parameters,
                    wallclock_seconds_per_epoch=float(
                        parameters.get("wallclock_seconds_per_epoch", request.wallclock_seconds_per_epoch)
                    ),
                    gpu_seconds_per_epoch=float(parameters.get("gpu_seconds_per_epoch", request.gpu_seconds_per_epoch)),
                    model_tokens_per_epoch=int(parameters.get("model_tokens_per_epoch", request.model_tokens_per_epoch)),
                    cost_usd_per_epoch=float(parameters.get("cost_usd_per_epoch", request.cost_usd_per_epoch)),
                )
            )
        except S2BudgetExceededError as exc:
            return self._emit_failed_trial(
                request=request,
                trial_id=trial_id,
                family_id=family_id,
                parameters=parameters,
                status="BUDGET_HALTED",
                error_code=exc.code,
                error_message=exc.message,
                cost_actual=exc.snapshot.as_cost_actual(),
                partial_checkpoint=exc.partial_checkpoint,
            )
        except S2Error as exc:
            return self._emit_failed_trial(
                request=request,
                trial_id=trial_id,
                family_id=family_id,
                parameters=parameters,
                status="FAILED",
                error_code=exc.__class__.__name__,
                error_message=str(exc),
                cost_actual=meter.snapshot().as_cost_actual() if meter else SpendSnapshot(
                    job_id=trial_job_id,
                    wallclock_seconds=0.0,
                    gpu_seconds=0.0,
                    model_tokens=0,
                    cost_usd=0.0,
                ).as_cost_actual(),
                partial_checkpoint=None,
            )
        final_metrics = dict(result.diagnostics.get("final_metrics", {}))
        if request.objective_metric not in final_metrics:
            return self._emit_failed_trial(
                request=request,
                trial_id=trial_id,
                family_id=family_id,
                parameters=parameters,
                status="FAILED",
                error_code="OBJECTIVE_METRIC_MISSING",
                error_message=f"S2 HPO trial missing objective metric: {request.objective_metric}",
                cost_actual=result.cost_actual,
                partial_checkpoint=result.partial_checkpoint,
            )
        score = float(final_metrics[request.objective_metric])
        calibration_error = float(final_metrics.get("calibration_error", 0.0))
        return self._emit_completed_trial(
            request=request,
            trial_id=trial_id,
            family_id=family_id,
            parameters=parameters,
            status=result.status,
            score=score,
            calibration_error=calibration_error,
            cost=float(result.cost_actual.get("cost_usd", 0.0)),
            checkpoint_ref=result.final_checkpoint_ref,
            training_log_ref=result.training_log_ref,
            completed_epochs=result.completed_epochs,
            diagnostics={"final_metrics": final_metrics, "cost_actual": result.cost_actual},
        )

    def _emit_warm_started_trial(self, request: HPORequest, trial: HPOTrial) -> HPOTrial:
        lineage_inputs = (request.warm_start_ref,) if request.warm_start_ref else request.input_refs
        record = self._provenance_emitter.emit_artifact(
            kind="hpo_trial",
            payload={
                "job_id": request.job_id,
                "trial_id": trial.trial_id,
                "family_id": trial.family_id,
                "status": "WARM_STARTED",
                "parameters": dict(trial.parameters),
                "objective": request.objective,
                "objective_metric": request.objective_metric,
                "score": trial.score,
                "calibration_error": trial.calibration_error,
                "cost": trial.cost,
                "final_checkpoint_ref": trial.checkpoint_ref,
                "training_log_ref": trial.training_log_ref,
                "partial_checkpoint_ref": None,
                "diagnostics": {"warm_start_ref": request.warm_start_ref, **trial.diagnostics},
            },
            producer=Producer(subsystem="S2", version="0.0.0", job_id=request.job_id),
            lineage=Lineage(
                input_refs=lineage_inputs,
                code_ref=request.code_ref,
                environment_digest=request.environment_digest,
                seeds=(request.seed, f"warm-start:{trial.trial_id}"),
                job_id=request.job_id,
            ),
            claim_tier="ran-toy",
        )
        return HPOTrial(
            trial_id=trial.trial_id,
            score=trial.score,
            calibration_error=trial.calibration_error,
            cost=trial.cost,
            parameters=trial.parameters,
            family_id=trial.family_id,
            status="WARM_STARTED",
            checkpoint_ref=trial.checkpoint_ref,
            training_log_ref=trial.training_log_ref,
            trial_artifact_ref=record.artifact_ref,
            diagnostics={"warm_start_ref": request.warm_start_ref, **trial.diagnostics},
        )

    def _emit_completed_trial(
        self,
        *,
        request: HPORequest,
        trial_id: str,
        family_id: str,
        parameters: Mapping[str, Any],
        status: str,
        score: float,
        calibration_error: float,
        cost: float,
        checkpoint_ref: str | None,
        training_log_ref: str | None,
        completed_epochs: int,
        diagnostics: Mapping[str, Any],
    ) -> HPOTrial:
        input_refs = tuple(ref for ref in request.input_refs + (checkpoint_ref, training_log_ref) if ref)
        record = self._provenance_emitter.emit_artifact(
            kind="hpo_trial",
            payload={
                "job_id": request.job_id,
                "trial_id": trial_id,
                "family_id": family_id,
                "status": status,
                "parameters": dict(parameters),
                "objective": request.objective,
                "objective_metric": request.objective_metric,
                "score": score,
                "calibration_error": calibration_error,
                "cost": cost,
                "final_checkpoint_ref": checkpoint_ref,
                "training_log_ref": training_log_ref,
                "completed_epochs": completed_epochs,
                "partial_checkpoint_ref": None,
                "diagnostics": dict(diagnostics),
            },
            producer=Producer(subsystem="S2", version="0.0.0", job_id=request.job_id),
            lineage=Lineage(
                input_refs=input_refs,
                code_ref=request.code_ref,
                environment_digest=request.environment_digest,
                seeds=(request.seed, f"trial:{trial_id}"),
                job_id=request.job_id,
            ),
            claim_tier="ran-toy",
        )
        return HPOTrial(
            trial_id=trial_id,
            score=score,
            calibration_error=calibration_error,
            cost=cost,
            parameters=dict(parameters),
            family_id=family_id,
            status=status,
            checkpoint_ref=checkpoint_ref,
            training_log_ref=training_log_ref,
            trial_artifact_ref=record.artifact_ref,
            diagnostics=dict(diagnostics),
        )

    def _emit_failed_trial(
        self,
        *,
        request: HPORequest,
        trial_id: str,
        family_id: str,
        parameters: Mapping[str, Any],
        status: str,
        error_code: str,
        error_message: str,
        cost_actual: Mapping[str, float | int],
        partial_checkpoint: PartialModelCheckpoint | None,
    ) -> HPOTrial:
        checkpoint_ref = partial_checkpoint.artifact_ref if partial_checkpoint else None
        input_refs = tuple(ref for ref in request.input_refs + (checkpoint_ref,) if ref)
        cost = float(cost_actual.get("cost_usd", 0.0))
        diagnostics = {
            "error_code": error_code,
            "error_message": error_message,
            "cost_actual": dict(cost_actual),
        }
        record = self._provenance_emitter.emit_artifact(
            kind="hpo_trial",
            payload={
                "job_id": request.job_id,
                "trial_id": trial_id,
                "family_id": family_id,
                "status": status,
                "parameters": dict(parameters),
                "objective": request.objective,
                "objective_metric": request.objective_metric,
                "score": None,
                "calibration_error": None,
                "cost": cost,
                "final_checkpoint_ref": None,
                "training_log_ref": None,
                "partial_checkpoint_ref": checkpoint_ref,
                "diagnostics": diagnostics,
            },
            producer=Producer(subsystem="S2", version="0.0.0", job_id=request.job_id),
            lineage=Lineage(
                input_refs=input_refs,
                code_ref=request.code_ref,
                environment_digest=request.environment_digest,
                seeds=(request.seed, f"trial:{trial_id}"),
                job_id=request.job_id,
            ),
            claim_tier="ran-toy",
        )
        return HPOTrial(
            trial_id=trial_id,
            score=0.0,
            calibration_error=request.max_calibration_error + 1.0 if request.max_calibration_error is not None else 1.0,
            cost=cost,
            parameters=dict(parameters),
            family_id=family_id,
            status=status,
            checkpoint_ref=checkpoint_ref,
            training_log_ref=None,
            trial_artifact_ref=record.artifact_ref,
            diagnostics=diagnostics,
        )

    def _emit_selection(self, *, request: HPORequest, trials: tuple[HPOTrial, ...], selected: HPOSelection) -> ArtifactRecord:
        trial_refs = tuple(trial.trial_artifact_ref for trial in trials if trial.trial_artifact_ref)
        return self._provenance_emitter.emit_artifact(
            kind="hpo_selection",
            payload={
                "job_id": request.job_id,
                "selected_trial_id": selected.trial_id,
                "selected_family_id": selected.family_id,
                "selected_parameters": dict(selected.parameters),
                "score": selected.score,
                "calibration_error": selected.calibration_error,
                "cost": selected.cost,
                "objective": request.objective,
                "objective_metric": request.objective_metric,
                "policy": "pareto_lexicographic",
                "diagnostics": dict(selected.diagnostics),
                "pareto_front_trial_ids": list(selected.pareto_front_trial_ids),
                "trial_artifact_refs": list(trial_refs),
            },
            producer=Producer(subsystem="S2", version="0.0.0", job_id=request.job_id),
            lineage=Lineage(
                input_refs=trial_refs,
                code_ref=request.code_ref,
                environment_digest=request.environment_digest,
                seeds=(request.seed, "hpo-selection"),
                job_id=request.job_id,
            ),
            claim_tier="ran-toy",
        )

    @staticmethod
    def _trial_id(*, request: HPORequest, family_id: str, parameters: Mapping[str, Any], index: int) -> str:
        digest = hashlib.sha256(
            _stable_hpo_json({"family_id": family_id, "parameters": dict(parameters), "seed": request.seed}).encode("utf-8")
        ).hexdigest()[:12]
        return f"{request.job_id}-trial-{index:04d}-{digest}"


def _ray_tune_hpo_trainable(
    config: Mapping[str, Any],
    *,
    request: HPORequest,
    registry: ModelFamilyRegistry,
    backends: Mapping[str, DeterministicLinearTrainingBackend],
) -> None:
    from ray import tune as ray_tune

    packet = _execute_hpo_training_trial_packet(
        request=request,
        spec=dict(config["spec"]),
        registry=registry,
        backends=backends,
    )
    if packet["status"] in {"SUCCEEDED", "WARM_STARTED"}:
        tune_objective = float(packet["score"])
    else:
        tune_objective = float("-inf") if request.objective == "maximize" else float("inf")
    trial_dir = ray_tune.get_context().get_trial_dir()
    packet_path = os.path.join(trial_dir, "argus_trial_packet.json")
    with open(packet_path, "w", encoding="utf-8") as packet_file:
        json.dump(packet, packet_file, sort_keys=True, separators=(",", ":"))
    ray_tune.report(
        {
            "argus_objective": tune_objective,
            "argus_trial_index": int(packet["index"]),
            "argus_trial_status": str(packet["status"]),
            "argus_trial_packet_path": packet_path,
        }
    )


def _execute_hpo_training_trial_packet(
    *,
    request: HPORequest,
    spec: Mapping[str, Any],
    registry: ModelFamilyRegistry,
    backends: Mapping[str, DeterministicLinearTrainingBackend],
) -> dict[str, Any]:
    trial_id = str(spec["trial_id"])
    family_id = str(spec["family_id"])
    parameters = dict(spec["parameters"])
    trial_job_id = f"{request.job_id}:{trial_id}"
    artifact_store = InMemoryArtifactStore()
    provenance_emitter = ProvenanceEmitter(artifact_store=artifact_store)
    meter = BudgetMeter.from_budget(job_id=trial_job_id, budget=request.trial_budget) if request.trial_budget else None
    runtime = TrainingRuntime(
        artifact_store=artifact_store,
        provenance_emitter=provenance_emitter,
        registry=registry,
        budget_meter=meter,
        backends=backends,
    )
    try:
        result = runtime.train(
            TrainingRequest(
                job_id=trial_job_id,
                family_id=family_id,
                input_refs=request.input_refs,
                training_rows=request.training_rows,
                feature_names=request.feature_names,
                target_name=request.target_name,
                max_epochs=int(parameters.get("max_epochs", request.max_epochs)),
                learning_rate=float(parameters.get("learning_rate", request.learning_rate)),
                code_ref=request.code_ref,
                environment_digest=request.environment_digest,
                seed=f"{request.seed}:{trial_id}",
                parameters=parameters,
                wallclock_seconds_per_epoch=float(
                    parameters.get("wallclock_seconds_per_epoch", request.wallclock_seconds_per_epoch)
                ),
                gpu_seconds_per_epoch=float(parameters.get("gpu_seconds_per_epoch", request.gpu_seconds_per_epoch)),
                model_tokens_per_epoch=int(parameters.get("model_tokens_per_epoch", request.model_tokens_per_epoch)),
                cost_usd_per_epoch=float(parameters.get("cost_usd_per_epoch", request.cost_usd_per_epoch)),
            )
        )
    except S2BudgetExceededError as exc:
        artifact_refs = (exc.partial_checkpoint.artifact_ref,) if exc.partial_checkpoint else ()
        partial_payload = None
        if exc.partial_checkpoint:
            partial_payload = {
                "artifact_ref": exc.partial_checkpoint.artifact_ref,
                "reason": exc.partial_checkpoint.reason,
                "metrics": dict(exc.partial_checkpoint.metrics),
            }
        return _hpo_jsonable(
            {
                "index": int(spec["index"]),
                "trial_id": trial_id,
                "family_id": family_id,
                "parameters": parameters,
                "status": "BUDGET_HALTED",
                "score": None,
                "calibration_error": None,
                "cost": float(exc.snapshot.cost_usd),
                "checkpoint_ref": exc.partial_checkpoint.artifact_ref if exc.partial_checkpoint else None,
                "training_log_ref": None,
                "completed_epochs": 0,
                "error_code": exc.code,
                "error_message": exc.message,
                "cost_actual": exc.snapshot.as_cost_actual(),
                "partial_checkpoint": partial_payload,
                "artifact_packets": [_export_hpo_artifact_packet(artifact_store, ref) for ref in artifact_refs],
                "diagnostics": {
                    "error_code": exc.code,
                    "cost_actual": exc.snapshot.as_cost_actual(),
                    "scheduler_backend": "ray_tune",
                },
            }
        )
    except S2Error as exc:
        cost_actual = (
            meter.snapshot().as_cost_actual()
            if meter
            else SpendSnapshot(
                job_id=trial_job_id,
                wallclock_seconds=0.0,
                gpu_seconds=0.0,
                model_tokens=0,
                cost_usd=0.0,
            ).as_cost_actual()
        )
        return _hpo_jsonable(
            {
                "index": int(spec["index"]),
                "trial_id": trial_id,
                "family_id": family_id,
                "parameters": parameters,
                "status": "FAILED",
                "score": None,
                "calibration_error": None,
                "cost": float(cost_actual.get("cost_usd", 0.0)),
                "checkpoint_ref": None,
                "training_log_ref": None,
                "completed_epochs": 0,
                "error_code": exc.__class__.__name__,
                "error_message": str(exc),
                "cost_actual": cost_actual,
                "partial_checkpoint": None,
                "artifact_packets": [],
                "diagnostics": {
                    "error_code": exc.__class__.__name__,
                    "cost_actual": cost_actual,
                    "scheduler_backend": "ray_tune",
                },
            }
        )
    final_metrics = dict(result.diagnostics.get("final_metrics", {}))
    if request.objective_metric not in final_metrics:
        return _hpo_jsonable(
            {
                "index": int(spec["index"]),
                "trial_id": trial_id,
                "family_id": family_id,
                "parameters": parameters,
                "status": "FAILED",
                "score": None,
                "calibration_error": None,
                "cost": float(result.cost_actual.get("cost_usd", 0.0)),
                "checkpoint_ref": result.partial_checkpoint.artifact_ref if result.partial_checkpoint else None,
                "training_log_ref": result.training_log_ref,
                "completed_epochs": result.completed_epochs,
                "error_code": "OBJECTIVE_METRIC_MISSING",
                "error_message": f"S2 HPO trial missing objective metric: {request.objective_metric}",
                "cost_actual": result.cost_actual,
                "partial_checkpoint": None,
                "artifact_packets": [
                    _export_hpo_artifact_packet(artifact_store, ref)
                    for ref in tuple(result.checkpoint_refs) + ((result.training_log_ref,) if result.training_log_ref else ())
                ],
                "diagnostics": {
                    "final_metrics": final_metrics,
                    "cost_actual": result.cost_actual,
                    "scheduler_backend": "ray_tune",
                },
            }
        )
    artifact_refs = tuple(result.checkpoint_refs) + ((result.training_log_ref,) if result.training_log_ref else ())
    return _hpo_jsonable(
        {
            "index": int(spec["index"]),
            "trial_id": trial_id,
            "family_id": family_id,
            "parameters": parameters,
            "status": result.status,
            "score": float(final_metrics[request.objective_metric]),
            "calibration_error": float(final_metrics.get("calibration_error", 0.0)),
            "cost": float(result.cost_actual.get("cost_usd", 0.0)),
            "checkpoint_ref": result.final_checkpoint_ref,
            "training_log_ref": result.training_log_ref,
            "completed_epochs": result.completed_epochs,
            "error_code": None,
            "error_message": None,
            "cost_actual": result.cost_actual,
            "partial_checkpoint": None,
            "artifact_packets": [_export_hpo_artifact_packet(artifact_store, ref) for ref in artifact_refs],
            "diagnostics": {
                "final_metrics": final_metrics,
                "cost_actual": result.cost_actual,
                "scheduler_backend": "ray_tune",
            },
        }
    )


def _export_hpo_artifact_packet(artifact_store: InMemoryArtifactStore, artifact_ref: str) -> dict[str, Any]:
    record = artifact_store.get_record(artifact_ref)
    payload = json.loads(artifact_store.get_artifact(artifact_ref).decode("utf-8"))
    return _hpo_jsonable(
        {
            "artifact_ref": record.artifact_ref,
            "kind": record.kind,
            "payload": payload,
            "producer": asdict(record.producer),
            "lineage": asdict(record.lineage),
            "claim_tier": record.claim_tier,
            "validation_report_ref": record.validation_report_ref,
            "created_at": record.created_at,
        }
    )


def _import_hpo_artifact_packet(artifact_store: InMemoryArtifactStore, packet: Mapping[str, Any]) -> ArtifactRecord:
    producer_payload = dict(packet["producer"])
    lineage_payload = dict(packet["lineage"])
    producer = Producer(
        subsystem=str(producer_payload["subsystem"]),
        version=str(producer_payload["version"]),
        actor_id=producer_payload.get("actor_id"),
        job_id=producer_payload.get("job_id"),
    )
    lineage = Lineage(
        input_refs=tuple(lineage_payload.get("input_refs", ())),
        code_ref=str(lineage_payload["code_ref"]),
        environment_digest=str(lineage_payload["environment_digest"]),
        seeds=tuple(lineage_payload.get("seeds", ())),
        actor_id=lineage_payload.get("actor_id"),
        job_id=lineage_payload.get("job_id"),
        contamination_index_version=lineage_payload.get("contamination_index_version"),
    )
    return artifact_store.create_artifact(
        kind=str(packet["kind"]),
        payload=packet["payload"],
        producer=producer,
        lineage=lineage,
        artifact_ref=str(packet["artifact_ref"]),
        claim_tier=str(packet.get("claim_tier") or "ran-toy"),
        validation_report_ref=packet.get("validation_report_ref"),
        created_at=packet.get("created_at"),
    )


def _hpo_jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False))


def _import_ray_tune() -> tuple[Any, Any, Any, Any]:
    try:
        import ray
        from ray import tune
        try:
            from ray.tune import RunConfig
        except ImportError:
            from ray.air import RunConfig
        from ray.tune.schedulers import ASHAScheduler
    except ImportError as exc:
        raise S2ContractModelError("S2-T14 requires installed ray[tune] for HPOEngine") from exc
    return ray, tune, RunConfig, ASHAScheduler


def _ensure_ray_initialized(ray: Any, *, worker_count: int) -> None:
    requested_cpus = max(worker_count, int(os.environ.get("ARGUS_HPO_RAY_MIN_CPUS", "4")))
    if ray.is_initialized():
        available_cpus = float(ray.cluster_resources().get("CPU", 0.0))
        if available_cpus >= worker_count:
            return
        ray.shutdown()
    ray.init(num_cpus=requested_cpus, include_dashboard=False, ignore_reinit_error=True, log_to_driver=False)


@dataclass(frozen=True)
class ComplexityEscalationPolicy:
    min_absolute_gain: float = 0.0
    min_relative_gain: float = 0.0
    standard_error_margin: float = 0.0
    max_cost: float | None = None
    objective: str = "maximize"

    def __post_init__(self) -> None:
        if self.objective not in {"maximize", "minimize"}:
            raise S2ContractModelError(f"unsupported S2 escalation objective: {self.objective}")
        if self.min_absolute_gain < 0:
            raise S2ContractModelError("S2 escalation min_absolute_gain must be non-negative")
        if self.min_relative_gain < 0:
            raise S2ContractModelError("S2 escalation min_relative_gain must be non-negative")
        if self.standard_error_margin < 0:
            raise S2ContractModelError("S2 escalation standard_error_margin must be non-negative")
        if self.max_cost is not None and self.max_cost < 0:
            raise S2ContractModelError("S2 escalation max_cost must be non-negative")

    def gain(self, *, incumbent_score: float, candidate_score: float) -> float:
        if self.objective == "maximize":
            return candidate_score - incumbent_score
        return incumbent_score - candidate_score

    def significant(
        self,
        *,
        incumbent_score: float,
        candidate_score: float,
        incumbent_standard_error: float = 0.0,
    ) -> bool:
        gain = self.gain(incumbent_score=incumbent_score, candidate_score=candidate_score)
        required_gain = max(self.min_absolute_gain, self.standard_error_margin * incumbent_standard_error)
        if gain <= required_gain:
            return False
        if self.min_relative_gain == 0:
            return True
        denominator = abs(incumbent_score)
        if denominator == 0:
            return False
        return gain / denominator > self.min_relative_gain


@dataclass(frozen=True)
class ModelCandidateResult:
    family_id: str
    heldout_score: float | None
    cost: float
    heldout_standard_error: float = 0.0
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        family_id = self.family_id.strip()
        if not family_id:
            raise S2ContractModelError("S2 model candidate requires family_id")
        if self.cost < 0:
            raise S2ContractModelError(f"S2 model candidate {family_id!r} has negative cost")
        if self.heldout_standard_error < 0:
            raise S2ContractModelError(f"S2 model candidate {family_id!r} has negative held-out standard error")
        object.__setattr__(self, "family_id", family_id)
        object.__setattr__(self, "diagnostics", dict(self.diagnostics))


@dataclass(frozen=True)
class CandidateRejection:
    family_id: str
    code: str
    message: str
    heldout_gain: float | None = None
    cost: float | None = None


@dataclass(frozen=True)
class ModelSynthesisDecision:
    incumbent_family_id: str
    selected_family_id: str
    escalated: bool
    reason: str
    heldout_gain: float
    rejected_candidates: tuple[CandidateRejection, ...] = ()


class ModelSynthesizer:
    """Deterministic S2 family selector; it does not train or run HPO."""

    _COST_CLASS_RANK = {
        "low": 0,
        "standard": 1,
        "medium": 2,
        "high": 3,
    }

    def __init__(
        self,
        *,
        registry: ModelFamilyRegistry | None = None,
        policy: ComplexityEscalationPolicy | None = None,
    ) -> None:
        self._registry = registry or _default_model_family_registry()
        self._policy = policy or ComplexityEscalationPolicy()

    def select_family(
        self,
        *,
        incumbent_family_id: str,
        candidates: tuple[ModelCandidateResult, ...],
    ) -> ModelSynthesisDecision:
        incumbent = self._registry.get(incumbent_family_id)
        candidate_by_family = self._validated_candidates(candidates)
        incumbent_candidate = candidate_by_family.get(incumbent.family_id)
        if incumbent_candidate is None or incumbent_candidate.heldout_score is None:
            raise S2ContractModelError("S2 ModelSynthesizer requires incumbent held-out evidence")

        incumbent_rank = self._complexity_rank(incumbent)
        eligible: list[tuple[float, ModelCandidateResult]] = []
        rejected: list[CandidateRejection] = []
        for candidate in candidates:
            if candidate.family_id == incumbent.family_id:
                continue
            descriptor = self._registry.get(candidate.family_id)
            if self._complexity_rank(descriptor) <= incumbent_rank:
                rejected.append(
                    CandidateRejection(
                        family_id=candidate.family_id,
                        code="NOT_HIGHER_COMPLEXITY",
                        message="candidate is not a higher-complexity family than the incumbent",
                        cost=candidate.cost,
                    )
                )
                continue
            if self._policy.max_cost is not None and candidate.cost > self._policy.max_cost:
                rejected.append(
                    CandidateRejection(
                        family_id=candidate.family_id,
                        code="COST_OVER_BUDGET",
                        message="candidate cost exceeds the S2 complexity-escalation budget",
                        cost=candidate.cost,
                    )
                )
                continue
            if candidate.heldout_score is None:
                rejected.append(
                    CandidateRejection(
                        family_id=candidate.family_id,
                        code="HELD_OUT_EVIDENCE_REQUIRED",
                        message="candidate is missing held-out metric evidence",
                        cost=candidate.cost,
                    )
                )
                continue
            gain = self._policy.gain(
                incumbent_score=incumbent_candidate.heldout_score,
                candidate_score=candidate.heldout_score,
            )
            if not self._policy.significant(
                incumbent_score=incumbent_candidate.heldout_score,
                candidate_score=candidate.heldout_score,
                incumbent_standard_error=incumbent_candidate.heldout_standard_error,
            ):
                rejected.append(
                    CandidateRejection(
                        family_id=candidate.family_id,
                        code="INSUFFICIENT_HELD_OUT_GAIN",
                        message="candidate held-out gain is below the escalation threshold",
                        heldout_gain=gain,
                        cost=candidate.cost,
                    )
                )
                continue
            eligible.append((gain, candidate))

        if eligible:
            gain, selected = sorted(eligible, key=lambda item: (-item[0], item[1].cost, item[1].family_id))[0]
            return ModelSynthesisDecision(
                incumbent_family_id=incumbent.family_id,
                selected_family_id=selected.family_id,
                escalated=True,
                reason="significant_held_out_gain",
                heldout_gain=gain,
                rejected_candidates=tuple(rejected),
            )

        reason = "insufficient_held_out_gain"
        if any(rejection.code != "INSUFFICIENT_HELD_OUT_GAIN" for rejection in rejected):
            reason = "no_eligible_escalation"
        best_rejected_gain = max(
            (rejection.heldout_gain for rejection in rejected if rejection.heldout_gain is not None),
            default=0.0,
        )
        return ModelSynthesisDecision(
            incumbent_family_id=incumbent.family_id,
            selected_family_id=incumbent.family_id,
            escalated=False,
            reason=reason,
            heldout_gain=best_rejected_gain,
            rejected_candidates=tuple(rejected),
        )

    def _validated_candidates(self, candidates: tuple[ModelCandidateResult, ...]) -> dict[str, ModelCandidateResult]:
        if not candidates:
            raise S2ContractModelError("S2 ModelSynthesizer requires candidate metrics")
        candidate_by_family: dict[str, ModelCandidateResult] = {}
        for candidate in candidates:
            self._registry.get(candidate.family_id)
            if candidate.family_id in candidate_by_family:
                raise S2ContractModelError(f"duplicate S2 model candidate: {candidate.family_id}")
            candidate_by_family[candidate.family_id] = candidate
        return candidate_by_family

    def _complexity_rank(self, descriptor: ModelFamilyDescriptor) -> int:
        return self._COST_CLASS_RANK.get(descriptor.cost_class, self._COST_CLASS_RANK["standard"])


@dataclass(frozen=True)
class DataSplitRequest:
    job_id: str
    dataset_ref: str
    split_seed: str
    code_ref: str
    environment_digest: str
    train_ratio: float = 0.7
    validation_ratio: float = 0.15
    test_ratio: float = 0.15
    row_id_key: str = "row_id"
    label_key: str | None = None
    group_key: str | None = None
    blind_role_key: str | None = None
    blind_roles: tuple[str, ...] = ("blind",)
    fold_count: int = 0

    def __post_init__(self) -> None:
        job_id = self.job_id.strip()
        dataset_ref = self.dataset_ref.strip()
        split_seed = self.split_seed.strip()
        code_ref = self.code_ref.strip()
        environment_digest = self.environment_digest.strip()
        row_id_key = self.row_id_key.strip()
        label_key = self.label_key.strip() if self.label_key is not None else None
        group_key = self.group_key.strip() if self.group_key is not None else None
        blind_role_key = self.blind_role_key.strip() if self.blind_role_key is not None else None
        blind_roles = tuple(str(role).strip() for role in self.blind_roles if str(role).strip())
        if not job_id:
            raise S2ContractModelError("S2 DataSplitRequest requires job_id")
        if not dataset_ref:
            raise S2ContractModelError("S2 DataSplitRequest requires dataset_ref")
        if not split_seed:
            raise S2ContractModelError("S2 DataSplitRequest requires split_seed")
        if not code_ref:
            raise S2ContractModelError("S2 DataSplitRequest requires code_ref")
        if not environment_digest:
            raise S2ContractModelError("S2 DataSplitRequest requires environment_digest")
        if not row_id_key:
            raise S2ContractModelError("S2 DataSplitRequest requires row_id_key")
        if blind_role_key is not None and not blind_roles:
            raise S2ContractModelError("S2 blind_role_key requires at least one blind role")
        ratios = (float(self.train_ratio), float(self.validation_ratio), float(self.test_ratio))
        if any(ratio <= 0 for ratio in ratios):
            raise S2ContractModelError("S2 split ratios must be positive")
        if abs(sum(ratios) - 1.0) > 1e-9:
            raise S2ContractModelError("S2 split ratios must sum to 1.0")
        if self.fold_count < 0 or self.fold_count == 1:
            raise S2ContractModelError("S2 fold_count must be 0 or at least 2")
        object.__setattr__(self, "job_id", job_id)
        object.__setattr__(self, "dataset_ref", dataset_ref)
        object.__setattr__(self, "split_seed", split_seed)
        object.__setattr__(self, "code_ref", code_ref)
        object.__setattr__(self, "environment_digest", environment_digest)
        object.__setattr__(self, "train_ratio", ratios[0])
        object.__setattr__(self, "validation_ratio", ratios[1])
        object.__setattr__(self, "test_ratio", ratios[2])
        object.__setattr__(self, "row_id_key", row_id_key)
        object.__setattr__(self, "label_key", label_key)
        object.__setattr__(self, "group_key", group_key)
        object.__setattr__(self, "blind_role_key", blind_role_key)
        object.__setattr__(self, "blind_roles", blind_roles)


@dataclass(frozen=True)
class FoldAssignment:
    fold_id: str
    train_indices: tuple[int, ...]
    validation_indices: tuple[int, ...]


@dataclass(frozen=True)
class DataSplitResult:
    job_id: str
    dataset_ref: str
    split_manifest_ref: str
    split_indices: dict[str, tuple[int, ...]]
    split_group_ids: dict[str, tuple[str, ...]]
    folds: tuple[FoldAssignment, ...]
    blind_input_indices: tuple[int, ...]
    diagnostics: dict[str, Any]


class DataManager:
    """S2 deterministic split/fold manager that never materializes blind labels."""

    def __init__(
        self,
        *,
        artifact_store: InMemoryArtifactStore,
        provenance_emitter: "ProvenanceEmitter" | None = None,
    ) -> None:
        self._artifact_store = artifact_store
        self._provenance_emitter = provenance_emitter or ProvenanceEmitter(artifact_store=artifact_store)

    def create_splits(self, request: DataSplitRequest) -> DataSplitResult:
        dataset_record = self._artifact_store.get_record(request.dataset_ref)
        if dataset_record.kind != "dataset":
            raise S2ContractModelError(f"S2 DataManager requires a dataset artifact, got {dataset_record.kind!r}")
        dataset_payload = json.loads(self._artifact_store.get_artifact(request.dataset_ref).decode("utf-8"))
        rows = self._dataset_rows(dataset_payload)
        row_ids = self._row_ids(rows, request.row_id_key)
        units = self._split_units(rows, row_ids, request)
        split_units = self._partition_units(units, request)
        split_indices = {
            role: tuple(sorted(index for _, indices in selected for index in indices))
            for role, selected in split_units.items()
        }
        split_group_ids = self._split_group_ids(split_units, request)
        folds = self._folds(units, request)
        blind_input_indices = self._blind_input_indices(rows, request)
        payload = self._manifest_payload(
            request=request,
            row_ids=row_ids,
            split_indices=split_indices,
            split_group_ids=split_group_ids,
            folds=folds,
            blind_input_indices=blind_input_indices,
        )
        record = self._provenance_emitter.emit_artifact(
            kind="dataset_split",
            payload=payload,
            producer=Producer(subsystem="S2", version="0.0.0", job_id=request.job_id),
            lineage=Lineage(
                input_refs=(request.dataset_ref,),
                code_ref=request.code_ref,
                environment_digest=request.environment_digest,
                seeds=(request.split_seed,),
                job_id=request.job_id,
            ),
            claim_tier="ran-toy",
        )
        return DataSplitResult(
            job_id=request.job_id,
            dataset_ref=request.dataset_ref,
            split_manifest_ref=record.artifact_ref,
            split_indices=split_indices,
            split_group_ids=split_group_ids,
            folds=folds,
            blind_input_indices=blind_input_indices,
            diagnostics={
                "row_count": len(rows),
                "group_aware": request.group_key is not None,
                "fold_count": request.fold_count,
                "label_materialized": False,
            },
        )

    @staticmethod
    def _dataset_rows(payload: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
        if not isinstance(payload, Mapping):
            raise S2ContractModelError("S2 DataManager dataset payload must be an object")
        rows = payload.get("rows")
        if not isinstance(rows, list) or not rows:
            raise S2ContractModelError("S2 DataManager dataset payload requires non-empty rows")
        normalized: list[Mapping[str, Any]] = []
        for row in rows:
            if not isinstance(row, Mapping):
                raise S2ContractModelError("S2 DataManager dataset rows must be objects")
            normalized.append(dict(row))
        return tuple(normalized)

    @staticmethod
    def _row_ids(rows: tuple[Mapping[str, Any], ...], row_id_key: str) -> tuple[str, ...]:
        row_ids: list[str] = []
        seen: set[str] = set()
        for index, row in enumerate(rows):
            if row_id_key not in row:
                raise S2ContractModelError(f"S2 DataManager row {index} missing row_id_key {row_id_key!r}")
            row_id = str(row[row_id_key]).strip()
            if not row_id:
                raise S2ContractModelError(f"S2 DataManager row {index} has an empty row id")
            if row_id in seen:
                raise S2ContractModelError(f"S2 DataManager duplicate row id: {row_id}")
            row_ids.append(row_id)
            seen.add(row_id)
        return tuple(row_ids)

    def _split_units(
        self,
        rows: tuple[Mapping[str, Any], ...],
        row_ids: tuple[str, ...],
        request: DataSplitRequest,
    ) -> tuple[tuple[str, tuple[int, ...]], ...]:
        if request.group_key is None:
            return tuple((row_id, (index,)) for index, row_id in enumerate(row_ids))
        groups: dict[str, list[int]] = {}
        for index, row in enumerate(rows):
            if request.group_key not in row:
                raise S2ContractModelError(f"S2 DataManager row {index} missing group_key {request.group_key!r}")
            group_id = str(row[request.group_key]).strip()
            if not group_id:
                raise S2ContractModelError(f"S2 DataManager row {index} has an empty group id")
            groups.setdefault(group_id, []).append(index)
        return tuple((group_id, tuple(indices)) for group_id, indices in groups.items())

    def _partition_units(
        self,
        units: tuple[tuple[str, tuple[int, ...]], ...],
        request: DataSplitRequest,
    ) -> dict[str, tuple[tuple[str, tuple[int, ...]], ...]]:
        if not units:
            raise S2ContractModelError("S2 DataManager requires at least one split unit")
        ordered = tuple(sorted(units, key=lambda unit: self._stable_key(request.split_seed, unit[0])))
        train_count, validation_count, test_count = self._allocation_counts(
            len(ordered),
            (request.train_ratio, request.validation_ratio, request.test_ratio),
        )
        if min(train_count, validation_count, test_count) == 0:
            raise S2ContractModelError("S2 DataManager requires non-empty train, validation, and test splits")
        train_end = train_count
        validation_end = train_end + validation_count
        return {
            "train": ordered[:train_end],
            "validation": ordered[train_end:validation_end],
            "test": ordered[validation_end : validation_end + test_count],
        }

    @staticmethod
    def _allocation_counts(total: int, ratios: tuple[float, float, float]) -> tuple[int, int, int]:
        raw = [ratio * total for ratio in ratios]
        counts = [int(value) for value in raw]
        remaining = total - sum(counts)
        remainders = sorted(
            ((raw[index] - counts[index], index) for index in range(len(raw))),
            key=lambda item: (-item[0], item[1]),
        )
        for _, index in remainders[:remaining]:
            counts[index] += 1
        return counts[0], counts[1], counts[2]

    def _folds(
        self,
        units: tuple[tuple[str, tuple[int, ...]], ...],
        request: DataSplitRequest,
    ) -> tuple[FoldAssignment, ...]:
        if request.fold_count == 0:
            return ()
        if request.fold_count > len(units):
            raise S2ContractModelError("S2 fold_count cannot exceed split unit count")
        ordered = tuple(sorted(units, key=lambda unit: self._stable_key(f"{request.split_seed}:fold", unit[0])))
        folds: list[FoldAssignment] = []
        for fold_index in range(request.fold_count):
            validation_indices = sorted(
                index
                for position, (_, indices) in enumerate(ordered)
                if position % request.fold_count == fold_index
                for index in indices
            )
            train_indices = sorted(
                index
                for position, (_, indices) in enumerate(ordered)
                if position % request.fold_count != fold_index
                for index in indices
            )
            folds.append(
                FoldAssignment(
                    fold_id=f"fold-{fold_index + 1}",
                    train_indices=tuple(train_indices),
                    validation_indices=tuple(validation_indices),
                )
            )
        return tuple(folds)

    @staticmethod
    def _split_group_ids(
        split_units: Mapping[str, tuple[tuple[str, tuple[int, ...]], ...]],
        request: DataSplitRequest,
    ) -> dict[str, tuple[str, ...]]:
        if request.group_key is None:
            return {role: () for role in split_units}
        return {role: tuple(sorted(unit_id for unit_id, _ in units)) for role, units in split_units.items()}

    @staticmethod
    def _blind_input_indices(rows: tuple[Mapping[str, Any], ...], request: DataSplitRequest) -> tuple[int, ...]:
        if request.blind_role_key is None:
            return ()
        blind_roles = set(request.blind_roles)
        return tuple(
            index
            for index, row in enumerate(rows)
            if str(row.get(request.blind_role_key, "")).strip() in blind_roles
        )

    @staticmethod
    def _manifest_payload(
        *,
        request: DataSplitRequest,
        row_ids: tuple[str, ...],
        split_indices: Mapping[str, tuple[int, ...]],
        split_group_ids: Mapping[str, tuple[str, ...]],
        folds: tuple[FoldAssignment, ...],
        blind_input_indices: tuple[int, ...],
    ) -> dict[str, Any]:
        return {
            "job_id": request.job_id,
            "dataset_ref": request.dataset_ref,
            "split_seed": request.split_seed,
            "row_count": len(row_ids),
            "split_ratios": {
                "train": request.train_ratio,
                "validation": request.validation_ratio,
                "test": request.test_ratio,
            },
            "row_id_key": request.row_id_key,
            "group_key": request.group_key,
            "splits": {
                role: {
                    "indices": list(indices),
                    "row_ids": [row_ids[index] for index in indices],
                    "group_ids": list(split_group_ids.get(role, ())),
                }
                for role, indices in split_indices.items()
            },
            "folds": [
                {
                    "fold_id": fold.fold_id,
                    "train_indices": list(fold.train_indices),
                    "validation_indices": list(fold.validation_indices),
                }
                for fold in folds
            ],
            "blind_inputs": {
                "indices": list(blind_input_indices),
                "row_ids": [row_ids[index] for index in blind_input_indices],
                "role_key": request.blind_role_key,
                "roles": list(request.blind_roles),
                "label_materialized": False,
            },
            "label_policy": {
                "label_key": request.label_key,
                "materialized": False,
            },
        }

    @staticmethod
    def _stable_key(seed: str, unit_id: str) -> str:
        return hashlib.sha256(f"{seed}\0{unit_id}".encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TrainingRequest:
    job_id: str
    family_id: str
    input_refs: tuple[str, ...]
    training_rows: tuple[Mapping[str, Any], ...]
    feature_names: tuple[str, ...]
    target_name: str
    max_epochs: int
    code_ref: str
    environment_digest: str
    seed: str
    learning_rate: float = 0.01
    parameters: dict[str, Any] = field(default_factory=dict)
    resume_from_checkpoint_ref: str | None = None
    wallclock_seconds_per_epoch: float = 0.0
    gpu_seconds_per_epoch: float = 0.0
    model_tokens_per_epoch: int = 0
    cost_usd_per_epoch: float = 0.0
    on_epoch_complete: Callable[["TrainingProgress"], None] | None = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        job_id = self.job_id.strip()
        family_id = self.family_id.strip()
        target_name = self.target_name.strip()
        feature_names = tuple(str(name).strip() for name in self.feature_names)
        if not job_id:
            raise S2ContractModelError("S2 TrainingRequest requires job_id")
        if not family_id:
            raise S2ContractModelError("S2 TrainingRequest requires family_id")
        if not self.input_refs:
            raise S2ContractModelError("S2 TrainingRequest requires at least one input_ref")
        if not self.training_rows:
            raise S2ContractModelError("S2 TrainingRequest requires training_rows")
        if not feature_names or any(not name for name in feature_names):
            raise S2ContractModelError("S2 TrainingRequest requires feature_names")
        if not target_name:
            raise S2ContractModelError("S2 TrainingRequest requires target_name")
        if self.max_epochs <= 0:
            raise S2ContractModelError("S2 TrainingRequest max_epochs must be positive")
        if self.learning_rate <= 0:
            raise S2ContractModelError("S2 TrainingRequest learning_rate must be positive")
        if not self.code_ref:
            raise S2ContractModelError("S2 TrainingRequest requires code_ref")
        if not self.environment_digest:
            raise S2ContractModelError("S2 TrainingRequest requires environment_digest")
        if not self.seed:
            raise S2ContractModelError("S2 TrainingRequest requires seed")
        if self.wallclock_seconds_per_epoch < 0:
            raise S2ContractModelError("S2 TrainingRequest wallclock_seconds_per_epoch must be non-negative")
        if self.gpu_seconds_per_epoch < 0:
            raise S2ContractModelError("S2 TrainingRequest gpu_seconds_per_epoch must be non-negative")
        if self.model_tokens_per_epoch < 0:
            raise S2ContractModelError("S2 TrainingRequest model_tokens_per_epoch must be non-negative")
        if self.cost_usd_per_epoch < 0:
            raise S2ContractModelError("S2 TrainingRequest cost_usd_per_epoch must be non-negative")
        normalized_rows: list[dict[str, Any]] = []
        for row in self.training_rows:
            normalized = dict(row)
            for name in feature_names + (target_name,):
                if name not in normalized:
                    raise S2ContractModelError(f"S2 TrainingRequest row missing field: {name}")
            normalized_rows.append(normalized)
        object.__setattr__(self, "job_id", job_id)
        object.__setattr__(self, "family_id", family_id)
        object.__setattr__(self, "target_name", target_name)
        object.__setattr__(self, "feature_names", feature_names)
        object.__setattr__(self, "input_refs", tuple(str(ref) for ref in self.input_refs))
        object.__setattr__(self, "training_rows", tuple(normalized_rows))
        object.__setattr__(self, "parameters", dict(self.parameters))


@dataclass(frozen=True)
class TrainingProgress:
    job_id: str
    epoch: int
    checkpoint_ref: str
    metrics: dict[str, Any]
    cost_actual: dict[str, float | int]


@dataclass(frozen=True)
class TrainingEpochResult:
    epoch: int
    model_state: dict[str, Any]
    metrics: dict[str, Any]


@dataclass(frozen=True)
class TrainingRunResult:
    job_id: str
    family_id: str
    status: str
    start_epoch: int
    completed_epochs: int
    checkpoint_refs: tuple[str, ...]
    final_checkpoint_ref: str | None
    training_log_ref: str | None
    partial_checkpoint: PartialModelCheckpoint | None
    diagnostics: dict[str, Any]
    cost_actual: dict[str, float | int]


class DeterministicLinearTrainingBackend:
    """Small deterministic regression backend used by S2's runtime boundary."""

    backend_id = "deterministic-linear"

    def __init__(self, *, learning_rate: float | None = None, delay_seconds: float = 0.0) -> None:
        if learning_rate is not None and learning_rate <= 0:
            raise S2ContractModelError("S2 deterministic linear backend learning_rate must be positive")
        if delay_seconds < 0:
            raise S2ContractModelError("S2 deterministic linear backend delay_seconds must be non-negative")
        self._learning_rate = learning_rate
        self._delay_seconds = float(delay_seconds)

    def initial_state(self, request: TrainingRequest) -> dict[str, Any]:
        return {
            "feature_names": list(request.feature_names),
            "target_name": request.target_name,
            "weights": {name: 0.0 for name in request.feature_names},
            "bias": 0.0,
        }

    def train_epoch(self, request: TrainingRequest, state: Mapping[str, Any], *, epoch: int) -> TrainingEpochResult:
        if self._delay_seconds:
            time.sleep(self._delay_seconds)
        feature_names = tuple(state.get("feature_names", request.feature_names))
        weights = {name: float(dict(state.get("weights", {})).get(name, 0.0)) for name in feature_names}
        bias = float(state.get("bias", 0.0))
        count = float(len(request.training_rows))
        errors: list[float] = []
        for row in request.training_rows:
            prediction = bias + sum(weights[name] * float(row[name]) for name in feature_names)
            error = prediction - float(row[request.target_name])
            errors.append(error)
        grad_bias = 2.0 * sum(errors) / count
        grad_weights = {
            name: 2.0 * sum(error * float(row[name]) for error, row in zip(errors, request.training_rows)) / count
            for name in feature_names
        }
        learning_rate = float(self._learning_rate if self._learning_rate is not None else request.learning_rate)
        next_weights = {name: weights[name] - learning_rate * grad_weights[name] for name in feature_names}
        next_bias = bias - learning_rate * grad_bias
        loss = self._loss(request, feature_names=feature_names, weights=next_weights, bias=next_bias)
        next_state = {
            "feature_names": list(feature_names),
            "target_name": request.target_name,
            "weights": next_weights,
            "bias": next_bias,
        }
        return TrainingEpochResult(
            epoch=epoch,
            model_state=next_state,
            metrics={"loss": loss, "learning_rate": learning_rate},
        )

    @staticmethod
    def _loss(
        request: TrainingRequest,
        *,
        feature_names: tuple[str, ...],
        weights: Mapping[str, float],
        bias: float,
    ) -> float:
        total = 0.0
        for row in request.training_rows:
            prediction = bias + sum(float(weights[name]) * float(row[name]) for name in feature_names)
            error = prediction - float(row[request.target_name])
            total += error * error
        return total / float(len(request.training_rows))


class TrainingRuntime:
    """S2 training runtime with checkpoint/restart, budget, and cancel semantics."""

    def __init__(
        self,
        *,
        artifact_store: InMemoryArtifactStore,
        provenance_emitter: ProvenanceEmitter | None = None,
        registry: ModelFamilyRegistry | None = None,
        budget_meter: BudgetMeter | None = None,
        backends: Mapping[str, DeterministicLinearTrainingBackend] | None = None,
    ) -> None:
        self._artifact_store = artifact_store
        self._provenance_emitter = provenance_emitter or ProvenanceEmitter(artifact_store=artifact_store)
        self._registry = registry or _default_model_family_registry()
        self._budget_meter = budget_meter
        self._backends: dict[str, DeterministicLinearTrainingBackend] = {
            "tabular-baseline": DeterministicLinearTrainingBackend(),
        }
        if backends:
            for family_id, backend in backends.items():
                self.register_backend(family_id, backend)
        self._cancel_reasons: dict[str, str] = {}
        self._interrupt_reasons: dict[str, str] = {}

    def register_backend(self, family_id: str, backend: DeterministicLinearTrainingBackend) -> None:
        family_id = family_id.strip()
        if not family_id:
            raise S2ContractModelError("S2 TrainingRuntime backend registration requires family_id")
        if not hasattr(backend, "train_epoch") or not hasattr(backend, "initial_state"):
            raise S2ContractModelError("S2 TrainingRuntime backend must implement initial_state and train_epoch")
        self._backends[family_id] = backend

    def cancel(self, job_id: str, *, reason: str = "operator") -> dict[str, str]:
        if not job_id:
            raise S2ContractModelError("S2 TrainingRuntime cancel requires job_id")
        if not reason:
            raise S2ContractModelError("S2 TrainingRuntime cancel requires reason")
        self._cancel_reasons[job_id] = reason
        return {"job_id": job_id, "status": "CANCEL_REQUESTED", "reason": reason}

    def interrupt(self, job_id: str, *, reason: str = "runtime-restart") -> dict[str, str]:
        if not job_id:
            raise S2ContractModelError("S2 TrainingRuntime interrupt requires job_id")
        if not reason:
            raise S2ContractModelError("S2 TrainingRuntime interrupt requires reason")
        self._interrupt_reasons[job_id] = reason
        return {"job_id": job_id, "status": "INTERRUPT_REQUESTED", "reason": reason}

    def train(self, request: TrainingRequest) -> TrainingRunResult:
        descriptor = self._registry.get(request.family_id)
        backend = self._backend_for(descriptor.family_id)
        self._assert_budget_job(request)
        start_epoch, state = self._initial_training_state(request, backend)
        completed_epoch = start_epoch
        checkpoint_refs: list[str] = []
        final_metrics: dict[str, Any] = {}
        previous_checkpoint_ref = request.resume_from_checkpoint_ref

        for epoch in range(start_epoch + 1, request.max_epochs + 1):
            epoch_result = backend.train_epoch(request, state, epoch=epoch)
            state = epoch_result.model_state
            final_metrics = dict(epoch_result.metrics)
            completed_epoch = epoch
            checkpoint_status = "SUCCEEDED" if epoch == request.max_epochs else "RUNNING"
            if self._would_budget_breach(request):
                checkpoint_status = "BUDGET_HALTED"
            checkpoint_ref = self._emit_checkpoint(
                request=request,
                descriptor=descriptor,
                backend=backend,
                epoch=epoch,
                model_state=state,
                metrics=final_metrics,
                status=checkpoint_status,
                previous_checkpoint_ref=previous_checkpoint_ref,
            )
            previous_checkpoint_ref = checkpoint_ref
            checkpoint_refs.append(checkpoint_ref)
            partial_checkpoint = PartialModelCheckpoint(
                artifact_ref=checkpoint_ref,
                reason="best-so-far",
                metrics=final_metrics,
            )
            self._record_epoch_spend(request, partial_checkpoint=partial_checkpoint)

            progress = TrainingProgress(
                job_id=request.job_id,
                epoch=epoch,
                checkpoint_ref=checkpoint_ref,
                metrics=final_metrics,
                cost_actual=self._budget_snapshot(request).as_cost_actual(),
            )
            if request.on_epoch_complete is not None:
                request.on_epoch_complete(progress)
            if request.job_id in self._cancel_reasons:
                reason = self._cancel_reasons.pop(request.job_id)
                cancel_ref = self._emit_checkpoint(
                    request=request,
                    descriptor=descriptor,
                    backend=backend,
                    epoch=epoch,
                    model_state=state,
                    metrics=final_metrics,
                    status="CANCELLED",
                    previous_checkpoint_ref=checkpoint_ref,
                    reason=reason,
                )
                checkpoint_refs.append(cancel_ref)
                partial = PartialModelCheckpoint(artifact_ref=cancel_ref, reason=reason, metrics=final_metrics)
                log_ref = self._emit_training_log(
                    request=request,
                    status="CANCELLED",
                    start_epoch=start_epoch,
                    completed_epochs=completed_epoch,
                    checkpoint_refs=tuple(checkpoint_refs),
                    final_checkpoint_ref=cancel_ref,
                    diagnostics={"cancel_reason": reason, "final_metrics": final_metrics},
                )
                return TrainingRunResult(
                    job_id=request.job_id,
                    family_id=request.family_id,
                    status="CANCELLED",
                    start_epoch=start_epoch,
                    completed_epochs=completed_epoch,
                    checkpoint_refs=tuple(checkpoint_refs),
                    final_checkpoint_ref=cancel_ref,
                    training_log_ref=log_ref,
                    partial_checkpoint=partial,
                    diagnostics={"cancel_reason": reason, "final_metrics": final_metrics},
                    cost_actual=self._budget_snapshot(request).as_cost_actual(),
                )
            if request.job_id in self._interrupt_reasons:
                reason = self._interrupt_reasons.pop(request.job_id)
                interrupt_ref = self._emit_checkpoint(
                    request=request,
                    descriptor=descriptor,
                    backend=backend,
                    epoch=epoch,
                    model_state=state,
                    metrics=final_metrics,
                    status="INTERRUPTED",
                    previous_checkpoint_ref=checkpoint_ref,
                    reason=reason,
                )
                checkpoint_refs.append(interrupt_ref)
                log_ref = self._emit_training_log(
                    request=request,
                    status="INTERRUPTED",
                    start_epoch=start_epoch,
                    completed_epochs=completed_epoch,
                    checkpoint_refs=tuple(checkpoint_refs),
                    final_checkpoint_ref=interrupt_ref,
                    diagnostics={"interrupt_reason": reason, "final_metrics": final_metrics},
                )
                return TrainingRunResult(
                    job_id=request.job_id,
                    family_id=request.family_id,
                    status="INTERRUPTED",
                    start_epoch=start_epoch,
                    completed_epochs=completed_epoch,
                    checkpoint_refs=tuple(checkpoint_refs),
                    final_checkpoint_ref=interrupt_ref,
                    training_log_ref=log_ref,
                    partial_checkpoint=PartialModelCheckpoint(
                        artifact_ref=interrupt_ref,
                        reason=reason,
                        metrics=final_metrics,
                    ),
                    diagnostics={"interrupt_reason": reason, "final_metrics": final_metrics},
                    cost_actual=self._budget_snapshot(request).as_cost_actual(),
                )

        final_checkpoint_ref = checkpoint_refs[-1] if checkpoint_refs else None
        diagnostics = {
            "final_metrics": final_metrics,
            "backend": backend.backend_id,
            "model_family": descriptor.family_id,
        }
        log_ref = self._emit_training_log(
            request=request,
            status="SUCCEEDED",
            start_epoch=start_epoch,
            completed_epochs=completed_epoch,
            checkpoint_refs=tuple(checkpoint_refs),
            final_checkpoint_ref=final_checkpoint_ref,
            diagnostics=diagnostics,
        )
        return TrainingRunResult(
            job_id=request.job_id,
            family_id=request.family_id,
            status="SUCCEEDED",
            start_epoch=start_epoch,
            completed_epochs=completed_epoch,
            checkpoint_refs=tuple(checkpoint_refs),
            final_checkpoint_ref=final_checkpoint_ref,
            training_log_ref=log_ref,
            partial_checkpoint=None,
            diagnostics=diagnostics,
            cost_actual=self._budget_snapshot(request).as_cost_actual(),
        )

    def _backend_for(self, family_id: str) -> DeterministicLinearTrainingBackend:
        try:
            return self._backends[family_id]
        except KeyError as exc:
            raise S2ContractModelError(f"S2 TrainingRuntime has no backend for model family: {family_id}") from exc

    def _initial_training_state(
        self,
        request: TrainingRequest,
        backend: DeterministicLinearTrainingBackend,
    ) -> tuple[int, dict[str, Any]]:
        if request.resume_from_checkpoint_ref is None:
            return 0, backend.initial_state(request)
        payload = self._artifact_payload(request.resume_from_checkpoint_ref)
        if payload.get("job_id") != request.job_id:
            raise S2ContractModelError("S2 TrainingRuntime checkpoint job_id does not match request")
        if payload.get("family_id") != request.family_id:
            raise S2ContractModelError("S2 TrainingRuntime checkpoint family_id does not match request")
        epoch = int(payload.get("epoch", 0))
        if epoch < 0 or epoch >= request.max_epochs:
            raise S2ContractModelError("S2 TrainingRuntime checkpoint epoch is outside the requested run")
        model_state = payload.get("model_state")
        if not isinstance(model_state, Mapping):
            raise S2ContractModelError("S2 TrainingRuntime checkpoint is missing model_state")
        return epoch, dict(model_state)

    def _artifact_payload(self, artifact_ref: str) -> dict[str, Any]:
        try:
            return json.loads(self._artifact_store.get_artifact(artifact_ref).decode("utf-8"))
        except KeyError as exc:
            raise S2ContractModelError(f"S2 TrainingRuntime checkpoint not found: {artifact_ref}") from exc

    def _emit_checkpoint(
        self,
        *,
        request: TrainingRequest,
        descriptor: ModelFamilyDescriptor,
        backend: DeterministicLinearTrainingBackend,
        epoch: int,
        model_state: Mapping[str, Any],
        metrics: Mapping[str, Any],
        status: str,
        previous_checkpoint_ref: str | None,
        reason: str | None = None,
    ) -> str:
        lineage_input_refs = tuple(request.input_refs)
        if previous_checkpoint_ref:
            lineage_input_refs = lineage_input_refs + (previous_checkpoint_ref,)
        payload = {
            "job_id": request.job_id,
            "family_id": descriptor.family_id,
            "backend": backend.backend_id,
            "epoch": epoch,
            "status": status,
            "reason": reason,
            "metrics": dict(metrics),
            "model_state": dict(model_state),
            "parameters": dict(request.parameters),
            "training_entrypoint": descriptor.training_entrypoint,
            "prediction_entrypoint": descriptor.prediction_entrypoint,
        }
        record = self._provenance_emitter.emit_artifact(
            kind="model_checkpoint",
            payload=payload,
            producer=Producer(subsystem="S2", version="0.0.0", job_id=request.job_id),
            lineage=Lineage(
                input_refs=lineage_input_refs,
                code_ref=request.code_ref,
                environment_digest=request.environment_digest,
                seeds=(request.seed, f"epoch:{epoch}"),
                job_id=request.job_id,
            ),
            claim_tier="ran-toy",
        )
        return record.artifact_ref

    def _emit_training_log(
        self,
        *,
        request: TrainingRequest,
        status: str,
        start_epoch: int,
        completed_epochs: int,
        checkpoint_refs: tuple[str, ...],
        final_checkpoint_ref: str | None,
        diagnostics: Mapping[str, Any],
    ) -> str:
        payload = {
            "job_id": request.job_id,
            "family_id": request.family_id,
            "status": status,
            "start_epoch": start_epoch,
            "completed_epochs": completed_epochs,
            "checkpoint_refs": list(checkpoint_refs),
            "final_checkpoint_ref": final_checkpoint_ref,
            "diagnostics": dict(diagnostics),
            "cost_actual": self._budget_snapshot(request).as_cost_actual(),
        }
        record = self._provenance_emitter.emit_artifact(
            kind="training_log",
            payload=payload,
            producer=Producer(subsystem="S2", version="0.0.0", job_id=request.job_id),
            lineage=Lineage(
                input_refs=tuple(request.input_refs) + tuple(checkpoint_refs),
                code_ref=request.code_ref,
                environment_digest=request.environment_digest,
                seeds=(request.seed,),
                job_id=request.job_id,
            ),
            claim_tier="ran-toy",
        )
        return record.artifact_ref

    def _assert_budget_job(self, request: TrainingRequest) -> None:
        if self._budget_meter is not None and self._budget_meter.job_id != request.job_id:
            raise S2ContractModelError("S2 BudgetMeter job_id must match TrainingRequest job_id")

    def _would_budget_breach(self, request: TrainingRequest) -> bool:
        if self._budget_meter is None:
            return False
        snapshot = self._budget_meter.snapshot()
        budget = self._budget_meter.budget
        if snapshot.wallclock_seconds + request.wallclock_seconds_per_epoch > budget.max_wallclock_seconds:
            return True
        if budget.max_gpu_seconds is not None and snapshot.gpu_seconds + request.gpu_seconds_per_epoch > budget.max_gpu_seconds:
            return True
        if budget.max_model_tokens is not None and snapshot.model_tokens + request.model_tokens_per_epoch > budget.max_model_tokens:
            return True
        return snapshot.cost_usd + request.cost_usd_per_epoch > budget.max_usd

    def _record_epoch_spend(
        self,
        request: TrainingRequest,
        *,
        partial_checkpoint: PartialModelCheckpoint,
    ) -> None:
        if self._budget_meter is None:
            return
        self._budget_meter.record(
            wallclock_seconds=request.wallclock_seconds_per_epoch,
            gpu_seconds=request.gpu_seconds_per_epoch,
            model_tokens=request.model_tokens_per_epoch,
            cost_usd=request.cost_usd_per_epoch,
            partial_checkpoint=partial_checkpoint,
        )

    def _budget_snapshot(self, request: TrainingRequest) -> SpendSnapshot:
        if self._budget_meter is None:
            return SpendSnapshot(
                job_id=request.job_id,
                wallclock_seconds=0.0,
                gpu_seconds=0.0,
                model_tokens=0,
                cost_usd=0.0,
            )
        return self._budget_meter.snapshot()


@dataclass(frozen=True)
class MutationSpec:
    variant_id: str
    model_family: str
    parameters: dict[str, Any]


@dataclass(frozen=True)
class BuildPlan:
    job_id: str
    input_refs: tuple[str, ...]
    adapter_request: EvalRequest
    model_family: str = "tabular-baseline"
    code_ref: str = "git:s2-baseline"
    environment_digest: str = "oci:s2-baseline"
    seed: str = "seed-0"


@dataclass(frozen=True)
class BuildResult:
    job_id: str
    model_ref: str
    frozen_pipeline_ref: str
    artifact_refs: tuple[str, ...]
    adapter_provenance_refs: tuple[str, ...]
    claim_tier: str
    diagnostics: dict[str, Any]
    cost_actual: dict[str, float | int] = field(default_factory=dict)


@dataclass(frozen=True)
class VariantBuildResult:
    variant_id: str
    model_ref: str
    frozen_pipeline_ref: str
    artifact_refs: tuple[str, ...]
    base_pipeline_ref: str
    diagnostics: dict[str, Any]


class ProvenanceEmitter:
    """S2 C4 writer client with fail-closed lineage and tier coupling checks."""

    def __init__(
        self,
        *,
        artifact_store: InMemoryArtifactStore,
        producer: Producer | None = None,
    ) -> None:
        self._artifact_store = artifact_store
        self._producer = producer or Producer(subsystem="S2", version="0.0.0")
        self._assert_valid_producer(self._producer)

    @property
    def producer(self) -> Producer:
        return self._producer

    def emit_artifact(
        self,
        *,
        kind: str,
        payload: Any,
        lineage: Lineage,
        claim_tier: str = "ran-toy",
        validation_report_ref: str | None = None,
        artifact_ref: str | None = None,
        producer: Producer | None = None,
    ) -> ArtifactRecord:
        if claim_tier != "ran-toy" and not validation_report_ref:
            raise IllegalTierError("tier above ran-toy requires validation_report_ref")
        artifact_producer = producer or self._producer
        self._assert_valid_producer(artifact_producer)
        assert_lineage_complete(
            lineage,
            kind=kind,
            payload=payload if isinstance(payload, Mapping) else None,
            claim_tier=claim_tier,
            validation_report_ref=validation_report_ref,
        )
        return self._artifact_store.create_artifact(
            kind=kind,
            payload=payload,
            producer=artifact_producer,
            lineage=lineage,
            artifact_ref=artifact_ref,
            claim_tier=claim_tier,
            validation_report_ref=validation_report_ref,
        )

    @staticmethod
    def _assert_valid_producer(producer: Producer) -> None:
        if not producer.subsystem:
            raise S2ContractModelError("S2 ProvenanceEmitter requires producer.subsystem")
        if not producer.version:
            raise S2ContractModelError("S2 ProvenanceEmitter requires producer.version")


def validate_s2_contract_model_set(
    contract_by_id: Mapping[str, Any],
    *,
    schema_root: str | Path,
) -> S2ContractModelSet:
    root = Path(schema_root)
    bindings: list[S2ContractBinding] = []
    for contract_id in S2_REQUIRED_CONTRACT_IDS:
        contract = contract_by_id.get(contract_id)
        if contract is None:
            raise S2ContractModelError(f"S2 generated bindings missing {contract_id}")
        consumers = tuple(_contract_value(contract, "consumers"))
        if "S2" not in consumers:
            raise S2ContractModelError(f"{contract_id} generated binding does not list S2 as a consumer")
        schema_name = str(_contract_value(contract, "schema"))
        schema_path = root / schema_name
        if not schema_path.is_file():
            raise S2ContractModelError(f"{contract_id} canonical schema file is missing: {schema_name}")
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        metadata = schema.get("x-argus-contract", {})
        if metadata.get("id") != contract_id:
            raise S2ContractModelError(f"{schema_name} declares {metadata.get('id')!r}, expected {contract_id}")
        if metadata.get("version") != _contract_value(contract, "version"):
            raise S2ContractModelError(f"{contract_id} generated binding version is stale")
        digest = _schema_sha256(schema)
        if digest != _contract_value(contract, "schema_sha256"):
            raise S2ContractModelError(f"{contract_id} generated binding digest is stale")
        bindings.append(
            S2ContractBinding(
                contract_id=contract_id,
                version=str(_contract_value(contract, "version")),
                schema=schema_name,
                schema_sha256=digest,
            )
        )
    return S2ContractModelSet(bindings=tuple(bindings))


def compile_build_spec_from_c2_envelope(
    payload: Mapping[str, Any],
    *,
    runtime_version: str = "1.0.0",
    version_policy: C2VersionPolicy | None = None,
    now: int = 0,
) -> BuildSpec:
    envelope = parse_c2_job_envelope(
        payload,
        runtime_version=runtime_version,
        version_policy=version_policy,
        now=now,
    )
    problem_spec = dict(envelope.problem_spec or {})
    constraints = payload.get("constraints", problem_spec.get("constraints", {}))
    if constraints is None:
        constraints = {}
    if not isinstance(constraints, Mapping):
        raise S2ContractModelError("C2 constraints must be an object when provided")
    target_observable = str(problem_spec.get("target_observable") or problem_spec.get("observable") or "")
    if not target_observable:
        raise S2ContractModelError("C2 problem_spec must declare observable or target_observable for S2")

    return BuildSpec(
        job_id=envelope.job_id,
        trace_id=envelope.trace_id,
        subtopic=envelope.subtopic,
        task_type=str(problem_spec.get("task_type", "regression")),
        target_observable=target_observable,
        required_claim_tier_max=envelope.required_claim_tier_max,
        verifier_profile_ref=envelope.verifier_profile_ref,
        budget=_build_budget(envelope.budget),
        input_artifact_refs=tuple(envelope.input_artifact_refs),
        allowed_adapters=tuple(envelope.capability_scopes.get("allowed_adapters", ())),
        allowed_datasets=tuple(envelope.capability_scopes.get("allowed_datasets", ())),
        fields=_field_specs(problem_spec),
        constraints=dict(constraints),
    )


class SpecCompiler:
    """C2 to S2 BuildSpec compiler with C3/C5 fail-closed preflight."""

    def __init__(
        self,
        *,
        verifier_profiles: C3VerifierProfileCatalog | Mapping[str, C3VerifierProfile],
        capability_registry: Any,
        artifact_store: InMemoryArtifactStore | None = None,
        runtime_version: str = "1.0.0",
        version_policy: C2VersionPolicy | None = None,
        now: int = 0,
    ) -> None:
        self._verifier_profiles = verifier_profiles
        self._capability_registry = capability_registry
        self._artifact_store = artifact_store
        self._runtime_version = runtime_version
        self._version_policy = version_policy
        self._now = now

    def compile(self, payload: Mapping[str, Any]) -> BuildSpec:
        spec = compile_build_spec_from_c2_envelope(
            payload,
            runtime_version=self._runtime_version,
            version_policy=self._version_policy,
            now=self._now,
        )
        self._require_target_units(spec)
        verifier_profile = self._resolve_verifier_profile(spec.verifier_profile_ref)
        resolved_adapters = tuple(
            self._resolve_descriptor(ref, kind="adapter", required_scope="c6.evaluate", code="ADAPTER_UNAVAILABLE")
            for ref in spec.allowed_adapters
        )
        resolved_datasets = tuple(
            self._resolve_descriptor(ref, kind="dataset", required_scope="c4.read", code="DATASET_UNAVAILABLE")
            for ref in spec.allowed_datasets
        )
        resolved_input_artifacts = tuple(self._resolve_input_artifact(ref) for ref in spec.input_artifact_refs)
        return BuildSpec(
            job_id=spec.job_id,
            trace_id=spec.trace_id,
            subtopic=spec.subtopic,
            task_type=spec.task_type,
            target_observable=spec.target_observable,
            required_claim_tier_max=spec.required_claim_tier_max,
            verifier_profile_ref=spec.verifier_profile_ref,
            budget=spec.budget,
            input_artifact_refs=spec.input_artifact_refs,
            allowed_adapters=spec.allowed_adapters,
            allowed_datasets=spec.allowed_datasets,
            fields=spec.fields,
            constraints=dict(spec.constraints),
            verifier_profile=verifier_profile,
            resolved_adapters=resolved_adapters,
            resolved_datasets=resolved_datasets,
            resolved_input_artifacts=resolved_input_artifacts,
        )

    def compile_then_execute(self, payload: Mapping[str, Any], executor: Callable[[BuildSpec], Any]) -> Any:
        spec = self.compile(payload)
        return executor(spec)

    @staticmethod
    def _require_target_units(spec: BuildSpec) -> None:
        if not any(field.role == "target" and field.units for field in spec.fields):
            raise S2SpecCompilerError(
                category="POLICY",
                code="UNITS_CONTRACT_INCOMPLETE",
                message="S2 SpecCompiler requires target units before execution",
            )

    def _resolve_verifier_profile(self, profile_ref: str) -> C3VerifierProfile:
        if not profile_ref:
            raise S2SpecCompilerError(
                category="VERIFIER_UNAVAILABLE",
                code="VERIFIER_PROFILE_REQUIRED",
                message="S2 SpecCompiler requires a verifier_profile_ref",
            )
        try:
            if hasattr(self._verifier_profiles, "resolve"):
                profile = self._verifier_profiles.resolve(profile_ref)
            else:
                profile = self._verifier_profiles[profile_ref]  # type: ignore[index]
        except (KeyError, LookupError) as exc:
            raise S2SpecCompilerError(
                category="VERIFIER_UNAVAILABLE",
                code="VERIFIER_PROFILE_UNAVAILABLE",
                message=f"S2 SpecCompiler could not resolve verifier profile: {profile_ref}",
            ) from exc
        if not isinstance(profile, C3VerifierProfile):
            raise S2SpecCompilerError(
                category="VERIFIER_UNAVAILABLE",
                code="VERIFIER_PROFILE_INVALID",
                message=f"S2 SpecCompiler resolver returned an invalid verifier profile: {profile_ref}",
            )
        return profile

    def _resolve_descriptor(
        self,
        ref: str,
        *,
        kind: str,
        required_scope: str,
        code: str,
    ) -> ResolvedC5Descriptor:
        if self._capability_registry is None or not hasattr(self._capability_registry, "get"):
            raise S2SpecCompilerError(
                category="POLICY",
                code=code,
                message=f"S2 SpecCompiler requires a C5 registry to resolve {kind}: {ref}",
            )
        try:
            descriptor = self._capability_registry.get(ref)
        except (KeyError, RegistryError) as exc:
            raise S2SpecCompilerError(
                category="POLICY",
                code=code,
                message=f"S2 SpecCompiler could not resolve {kind}: {ref}",
            ) from exc
        if descriptor.status != "active" or descriptor.kind != kind or required_scope not in descriptor.capability_scopes:
            raise S2SpecCompilerError(
                category="POLICY",
                code=code,
                message=f"S2 SpecCompiler rejected {kind} descriptor: {ref}",
            )
        return ResolvedC5Descriptor.from_descriptor(descriptor)

    def _resolve_input_artifact(self, ref: str) -> ResolvedC4Artifact:
        if self._artifact_store is None:
            raise S2SpecCompilerError(
                category="POLICY",
                code="INPUT_ARTIFACT_UNAVAILABLE",
                message=f"S2 SpecCompiler requires a C4 artifact store to resolve input: {ref}",
            )
        try:
            record = self._artifact_store.get_record(ref)
        except KeyError as exc:
            raise S2SpecCompilerError(
                category="POLICY",
                code="INPUT_ARTIFACT_UNAVAILABLE",
                message=f"S2 SpecCompiler could not resolve input artifact: {ref}",
            ) from exc
        return ResolvedC4Artifact.from_record(record)


class BaselineBuilder:
    """Small deterministic S2 builder that emits C4 provenance and never self-grades."""

    def __init__(
        self,
        *,
        artifact_store: InMemoryArtifactStore,
        adapter_broker: AdapterBroker,
        provenance_emitter: ProvenanceEmitter | None = None,
        budget_meter: BudgetMeter | None = None,
    ) -> None:
        self._artifact_store = artifact_store
        self._adapter_broker = adapter_broker
        self._provenance_emitter = provenance_emitter or ProvenanceEmitter(artifact_store=artifact_store)
        self._budget_meter = budget_meter

    def build(self, plan: BuildPlan, *, attempted_claim_tier: str | None = None) -> BuildResult:
        if attempted_claim_tier and attempted_claim_tier != "ran-toy":
            raise SelfGradeError("S2 cannot assign claim_tier above ran-toy")
        self._assert_budget_open(plan)

        adapter_result = self._adapter_broker.evaluate(plan.adapter_request)
        model_record = self._write_model(plan, adapter_result)
        pipeline_record = self._write_frozen_pipeline(plan, model_record, adapter_result)
        budget_snapshot = self._budget_snapshot(plan)
        return BuildResult(
            job_id=plan.job_id,
            model_ref=model_record.artifact_ref,
            frozen_pipeline_ref=pipeline_record.artifact_ref,
            artifact_refs=(model_record.artifact_ref, pipeline_record.artifact_ref),
            adapter_provenance_refs=(adapter_result.provenance_ref,),
            claim_tier="ran-toy",
            diagnostics={
                "model_family": plan.model_family,
                "adapter_id": adapter_result.adapter_id,
                "extrapolation_flag": adapter_result.extrapolation_flag,
                "budget_halted": budget_snapshot.halted_reason is not None,
                "budget_halted_reason": budget_snapshot.halted_reason,
            },
            cost_actual=budget_snapshot.as_cost_actual(),
        )

    def build_variant(
        self,
        *,
        base_pipeline_ref: str,
        plan: BuildPlan,
        mutation: MutationSpec,
        fabricated_score: float | None = None,
    ) -> VariantBuildResult:
        if fabricated_score is not None:
            raise RewardSourceError("S2 build_variant cannot accept non-C3 scores")
        variant_plan = BuildPlan(
            job_id=plan.job_id,
            input_refs=plan.input_refs + (base_pipeline_ref,),
            adapter_request=plan.adapter_request,
            model_family=mutation.model_family,
            code_ref=plan.code_ref,
            environment_digest=plan.environment_digest,
            seed=plan.seed,
        )
        build_result = self.build(variant_plan)
        return VariantBuildResult(
            variant_id=mutation.variant_id,
            model_ref=build_result.model_ref,
            frozen_pipeline_ref=build_result.frozen_pipeline_ref,
            artifact_refs=build_result.artifact_refs,
            base_pipeline_ref=base_pipeline_ref,
            diagnostics={
                **build_result.diagnostics,
                "mutation_parameters": mutation.parameters,
                "reward_source": "c3-only",
            },
        )

    def _write_model(self, plan: BuildPlan, adapter_result: EvalResult) -> ArtifactRecord:
        payload = {
            "model_family": plan.model_family,
            "adapter_outputs": {field: asdict(quantity) for field, quantity in adapter_result.outputs.items()},
            "diagnostics": {
                "in_validity_domain": adapter_result.in_validity_domain,
                "extrapolation_flag": adapter_result.extrapolation_flag,
            },
        }
        return self._provenance_emitter.emit_artifact(
            kind="model",
            payload=payload,
            producer=Producer(subsystem="S2", version="0.0.0", job_id=plan.job_id),
            lineage=Lineage(
                input_refs=plan.input_refs + (adapter_result.provenance_ref,),
                code_ref=plan.code_ref,
                environment_digest=plan.environment_digest,
                seeds=(plan.seed,),
                job_id=plan.job_id,
            ),
            claim_tier="ran-toy",
        )

    def _write_frozen_pipeline(
        self,
        plan: BuildPlan,
        model_record: ArtifactRecord,
        adapter_result: EvalResult,
    ) -> ArtifactRecord:
        payload = {
            "entrypoint": "argus_core.s2.baseline.predict",
            "model_ref": model_record.artifact_ref,
            "adapter_provenance_ref": adapter_result.provenance_ref,
            "code_ref": plan.code_ref,
            "environment_digest": plan.environment_digest,
        }
        return self._provenance_emitter.emit_artifact(
            kind="container",
            payload=payload,
            producer=Producer(subsystem="S2", version="0.0.0", job_id=plan.job_id),
            lineage=Lineage(
                input_refs=(model_record.artifact_ref, adapter_result.provenance_ref),
                code_ref=plan.code_ref,
                environment_digest=plan.environment_digest,
                seeds=(plan.seed,),
                job_id=plan.job_id,
            ),
            claim_tier="ran-toy",
        )

    def _assert_budget_open(self, plan: BuildPlan) -> None:
        if self._budget_meter is None:
            return
        if self._budget_meter.job_id != plan.job_id:
            raise S2ContractModelError("S2 BudgetMeter job_id must match BuildPlan job_id")
        self._budget_meter.assert_open()

    def _budget_snapshot(self, plan: BuildPlan) -> SpendSnapshot:
        if self._budget_meter is None:
            return SpendSnapshot(
                job_id=plan.job_id,
                wallclock_seconds=0.0,
                gpu_seconds=0.0,
                model_tokens=0,
                cost_usd=0.0,
            )
        return self._budget_meter.snapshot()


_MODEL_FAMILY_REGISTRY: ModelFamilyRegistry | None = None


def _default_model_family_registry() -> ModelFamilyRegistry:
    global _MODEL_FAMILY_REGISTRY
    if _MODEL_FAMILY_REGISTRY is None:
        _MODEL_FAMILY_REGISTRY = ModelFamilyRegistry.default()
    return _MODEL_FAMILY_REGISTRY


def list_model_families(*, registry: ModelFamilyRegistry | None = None) -> tuple[ModelFamilyDescriptor, ...]:
    return (registry or _default_model_family_registry()).list()


def register_model_family(
    descriptor: ModelFamilyDescriptor,
    *,
    registry: ModelFamilyRegistry | None = None,
) -> ModelFamilyDescriptor:
    return (registry or _default_model_family_registry()).register(descriptor)


def _default_model_family_descriptors() -> tuple[ModelFamilyDescriptor, ...]:
    return (
        ModelFamilyDescriptor(
            family_id="tabular-baseline",
            name="Tabular Baseline",
            family_kind="classical",
            task_types=("regression", "surrogate_emulation"),
            cost_class="low",
            differentiable=False,
            physics_informed=False,
            native_uq="conformal",
            deterministic_training=True,
            supported_constraints=("standardization", "conformal_uq"),
            training_entrypoint="argus_core.s2.model_families.tabular_baseline.train",
            prediction_entrypoint="argus_core.s2.model_families.tabular_baseline.predict",
            provenance_ref="c4://model-family/tabular-baseline/v1",
        ),
        ModelFamilyDescriptor(
            family_id="physics-informed-mlp",
            name="Physics-Informed MLP",
            family_kind="deep",
            task_types=("regression", "surrogate_emulation"),
            cost_class="high",
            differentiable=True,
            physics_informed=True,
            native_uq="ensemble",
            deterministic_training=True,
            supported_constraints=("positivity", "asymptotic_limit", "symmetry"),
            training_entrypoint="argus_core.s2.model_families.physics_informed_mlp.train",
            prediction_entrypoint="argus_core.s2.model_families.physics_informed_mlp.predict",
            provenance_ref="c4://model-family/physics-informed-mlp/v1",
        ),
        ModelFamilyDescriptor(
            family_id="differentiable-surrogate",
            name="Differentiable Surrogate",
            family_kind="deep",
            task_types=("surrogate_emulation",),
            cost_class="medium",
            differentiable=True,
            physics_informed=True,
            native_uq="interval",
            deterministic_training=True,
            supported_constraints=("forward_model_loss", "gradient_based"),
            training_entrypoint="argus_core.s2.model_families.differentiable_surrogate.train",
            prediction_entrypoint="argus_core.s2.model_families.differentiable_surrogate.predict",
            provenance_ref="c4://model-family/differentiable-surrogate/v1",
        ),
    )


def _build_optuna_hpo_study(*, request: HPORequest, trials: tuple[HPOTrial, ...]) -> Any:
    optuna = _import_optuna()
    directions = ("maximize" if request.objective == "maximize" else "minimize", "minimize", "minimize")
    sampler = optuna.samplers.NSGAIISampler(seed=_stable_hpo_seed_int(request.seed))
    study = optuna.create_study(
        study_name=f"{request.job_id}-optuna-study",
        directions=directions,
        sampler=sampler,
    )
    distributions = _optuna_categorical_distributions(request=request, trials=trials, optuna=optuna)
    for trial in trials:
        params = {name: _stable_hpo_json(value) for name, value in sorted(trial.parameters.items())}
        trial_distributions = {name: distributions[name] for name in params}
        study.add_trial(
            optuna.trial.create_trial(
                params=params,
                distributions=trial_distributions,
                values=(trial.score, trial.calibration_error, trial.cost),
                state=optuna.trial.TrialState.COMPLETE,
                user_attrs={
                    "argus_trial_id": trial.trial_id,
                    "argus_family_id": trial.family_id,
                    "argus_parameters": dict(trial.parameters),
                },
            )
        )
    return study


def _optuna_categorical_distributions(*, request: HPORequest, trials: tuple[HPOTrial, ...], optuna: Any) -> dict[str, Any]:
    choices_by_name: dict[str, set[str]] = {}
    for name, values in request.parameter_grid.items():
        choices_by_name.setdefault(name, set()).update(_stable_hpo_json(value) for value in values)
    for trial in trials:
        for name, value in trial.parameters.items():
            choices_by_name.setdefault(str(name), set()).add(_stable_hpo_json(value))
    return {
        name: optuna.distributions.CategoricalDistribution(tuple(sorted(choices)))
        for name, choices in choices_by_name.items()
    }


def _import_optuna() -> Any:
    try:
        import optuna
    except ImportError as exc:
        raise S2ContractModelError("S2-T14 requires installed optuna for HPOEngine") from exc
    return optuna


def _stable_hpo_seed_int(seed: str) -> int:
    return int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8], 16)


def select_hpo_winner(
    trials: tuple[HPOTrial, ...],
    *,
    max_calibration_error: float,
    objective: str = "maximize",
) -> HPOSelection:
    if objective not in {"maximize", "minimize"}:
        raise S2ContractModelError(f"unsupported S2 HPO objective: {objective}")
    eligible = tuple(
        trial
        for trial in trials
        if trial.status in {"SUCCEEDED", "WARM_STARTED"} and trial.calibration_error <= max_calibration_error
    )
    if not eligible:
        raise S2Error("no HPO trial satisfies calibration constraint")
    pareto_front = _hpo_pareto_front(eligible, objective=objective)
    selected = sorted(pareto_front, key=lambda trial: _hpo_selection_key(trial, objective=objective))[0]
    return HPOSelection(
        trial_id=selected.trial_id,
        parameters=selected.parameters,
        score=selected.score,
        calibration_error=selected.calibration_error,
        cost=selected.cost,
        family_id=selected.family_id,
        trial_artifact_refs=tuple(trial.trial_artifact_ref for trial in eligible if trial.trial_artifact_ref),
        pareto_front_trial_ids=tuple(sorted(trial.trial_id for trial in pareto_front)),
        diagnostics={"policy": "pareto_lexicographic", "objective": objective},
    )


def _normalize_hpo_parameter_grid(parameter_grid: Mapping[str, tuple[Any, ...]]) -> dict[str, tuple[Any, ...]]:
    if not parameter_grid:
        raise S2ContractModelError("S2 HPO parameter_grid must be non-empty")
    normalized: dict[str, tuple[Any, ...]] = {}
    for raw_name, raw_values in parameter_grid.items():
        name = str(raw_name).strip()
        if not name:
            raise S2ContractModelError("S2 HPO parameter names must be non-empty")
        values = tuple(raw_values)
        if not values:
            raise S2ContractModelError(f"S2 HPO parameter {name!r} requires at least one value")
        seen_value_keys: set[str] = set()
        for value in values:
            value_key = _stable_hpo_json(value)
            if value_key in seen_value_keys:
                raise S2ContractModelError(f"duplicate S2 HPO value for parameter {name!r}")
            seen_value_keys.add(value_key)
            if name == "learning_rate" and float(value) <= 0:
                raise S2ContractModelError("S2 HPO learning_rate values must be positive")
            if name == "max_epochs" and int(value) <= 0:
                raise S2ContractModelError("S2 HPO max_epochs values must be positive")
            if name in {
                "wallclock_seconds_per_epoch",
                "gpu_seconds_per_epoch",
                "cost_usd_per_epoch",
            } and float(value) < 0:
                raise S2ContractModelError(f"S2 HPO {name} values must be non-negative")
            if name == "model_tokens_per_epoch" and int(value) < 0:
                raise S2ContractModelError("S2 HPO model_tokens_per_epoch values must be non-negative")
        normalized[name] = values
    return normalized


def _stable_hpo_json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise S2ContractModelError("S2 HPO parameter values must be canonical JSON serializable") from exc


def _hpo_pareto_front(trials: tuple[HPOTrial, ...], *, objective: str) -> tuple[HPOTrial, ...]:
    front = []
    for trial in trials:
        if any(_hpo_dominates(other, trial, objective=objective) for other in trials if other.trial_id != trial.trial_id):
            continue
        front.append(trial)
    return tuple(front)


def _hpo_dominates(left: HPOTrial, right: HPOTrial, *, objective: str) -> bool:
    if objective == "maximize":
        score_no_worse = left.score >= right.score
        score_better = left.score > right.score
    else:
        score_no_worse = left.score <= right.score
        score_better = left.score < right.score
    calibration_no_worse = left.calibration_error <= right.calibration_error
    cost_no_worse = left.cost <= right.cost
    return (
        score_no_worse
        and calibration_no_worse
        and cost_no_worse
        and (score_better or left.calibration_error < right.calibration_error or left.cost < right.cost)
    )


def _hpo_selection_key(trial: HPOTrial, *, objective: str) -> tuple[float, float, float, str]:
    score_key = -trial.score if objective == "maximize" else trial.score
    return (score_key, trial.calibration_error, trial.cost, trial.trial_id)


def _build_budget(value: Mapping[str, Any]) -> BuildBudget:
    return BuildBudget(
        max_usd=float(value["max_usd"]),
        max_wallclock_seconds=int(value["max_wallclock_seconds"]),
        max_gpu_seconds=float(value["max_gpu_seconds"]) if "max_gpu_seconds" in value else None,
        max_model_tokens=int(value["max_model_tokens"]) if "max_model_tokens" in value else None,
    )


def _field_specs(problem_spec: Mapping[str, Any]) -> tuple[FieldSpec, ...]:
    fields = problem_spec.get("inputs_schema", ())
    parsed = []
    for field in fields:
        if not isinstance(field, Mapping):
            raise S2ContractModelError("S2 input field specs must be objects")
        if "name" not in field or "units" not in field:
            raise S2ContractModelError("S2 input field specs require name and units")
        parsed.append(
            FieldSpec(
                name=str(field["name"]),
                units=str(field["units"]),
                role=str(field.get("role", "feature")),
            )
        )
    if "target_units" in problem_spec:
        parsed.append(
            FieldSpec(
                name=str(problem_spec.get("target_observable") or problem_spec.get("observable") or "target"),
                units=str(problem_spec["target_units"]),
                role="target",
            )
        )
    return tuple(parsed)


def _contract_value(contract: Any, name: str) -> Any:
    if isinstance(contract, Mapping):
        return contract[name]
    return getattr(contract, name)


def _schema_sha256(schema: Mapping[str, Any]) -> str:
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()
