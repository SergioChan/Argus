"""S2 baseline builder semantics for the first oracle-gated vertical slice."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping

from .s5 import C2VersionPolicy, parse_c2_job_envelope
from .s6 import CapabilityDescriptor, RegistryError
from .s7 import AdapterBroker, EvalRequest, EvalResult
from .s8 import ArtifactRecord, InMemoryArtifactStore, Lineage, Producer


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


@dataclass(frozen=True)
class HPOSelection:
    trial_id: str
    parameters: dict[str, Any]
    score: float
    calibration_error: float
    cost: float


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


@dataclass(frozen=True)
class VariantBuildResult:
    variant_id: str
    model_ref: str
    frozen_pipeline_ref: str
    artifact_refs: tuple[str, ...]
    base_pipeline_ref: str
    diagnostics: dict[str, Any]


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

    def __init__(self, *, artifact_store: InMemoryArtifactStore, adapter_broker: AdapterBroker) -> None:
        self._artifact_store = artifact_store
        self._adapter_broker = adapter_broker

    def build(self, plan: BuildPlan, *, attempted_claim_tier: str | None = None) -> BuildResult:
        if attempted_claim_tier and attempted_claim_tier != "ran-toy":
            raise SelfGradeError("S2 cannot assign claim_tier above ran-toy")

        adapter_result = self._adapter_broker.evaluate(plan.adapter_request)
        model_record = self._write_model(plan, adapter_result)
        pipeline_record = self._write_frozen_pipeline(plan, model_record, adapter_result)
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
            },
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
        return self._artifact_store.create_artifact(
            kind="model",
            payload=payload,
            producer=Producer(subsystem="S2", version="0.0.0"),
            lineage=Lineage(
                input_refs=plan.input_refs + (adapter_result.provenance_ref,),
                code_ref=plan.code_ref,
                environment_digest=plan.environment_digest,
                seeds=(plan.seed,),
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
        return self._artifact_store.create_artifact(
            kind="container",
            payload=payload,
            producer=Producer(subsystem="S2", version="0.0.0"),
            lineage=Lineage(
                input_refs=(model_record.artifact_ref, adapter_result.provenance_ref),
                code_ref=plan.code_ref,
                environment_digest=plan.environment_digest,
                seeds=(plan.seed,),
            ),
            claim_tier="ran-toy",
        )


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


def select_hpo_winner(trials: tuple[HPOTrial, ...], *, max_calibration_error: float) -> HPOSelection:
    eligible = tuple(trial for trial in trials if trial.calibration_error <= max_calibration_error)
    if not eligible:
        raise S2Error("no HPO trial satisfies calibration constraint")
    selected = max(eligible, key=lambda trial: (trial.score, -trial.cost, trial.trial_id))
    return HPOSelection(
        trial_id=selected.trial_id,
        parameters=selected.parameters,
        score=selected.score,
        calibration_error=selected.calibration_error,
        cost=selected.cost,
    )


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
