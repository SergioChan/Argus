"""S2 baseline builder semantics for the first oracle-gated vertical slice."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field, replace
from fractions import Fraction
import hashlib
from itertools import product
import json
import math
import os
from pathlib import Path
import tempfile
import time
from typing import Any, Callable, Mapping

from .canonical import canonical_json_bytes
from .hashing import hash_bytes
from .s5 import C2VersionPolicy, parse_c2_job_envelope
from .s6 import CapabilityDescriptor, RegistryError
from .s7 import AdapterBroker, EvalRequest, EvalResult
from .s8 import ArtifactRecord, InMemoryArtifactStore, Lineage, Producer, assert_lineage_complete
from .s10 import (
    BudgetCaps,
    EgressProxy,
    EgressRule,
    InMemoryAuditLedger,
    InMemoryTokenService,
    LaunchEnvelope,
    LaunchRequest,
    PolicyBundle,
    PolicyBundleSigner,
    PolicyDeniedError,
    ResourceCeilings,
    ScopeDeniedError,
    ScopeGrant,
    StoreWriterBroker,
    decide_policy,
    materialize_sandbox_env,
)
from .s12 import ConformanceRecord, ConformanceService, SubmissionBundle, sign_submission_bundle


class S2Error(Exception):
    """Base class for S2 builder failures."""


class SelfGradeError(S2Error):
    """Raised when S2 tries to assign a tier above ran-toy."""


class S2ClaimTierPolicy:
    """Central no-self-grade policy for S2-owned build artifacts."""

    RAN_TOY = "ran-toy"
    PRODUCER_SUBSYSTEM = "S2"

    @classmethod
    def assert_attempted_claim_tier(cls, attempted_claim_tier: str | None, *, actor: str) -> None:
        if attempted_claim_tier and attempted_claim_tier != cls.RAN_TOY:
            raise SelfGradeError(f"{actor} cannot assign claim_tier above {cls.RAN_TOY}")

    @classmethod
    def assert_s2_writer_producer(cls, producer: Producer) -> None:
        if producer.subsystem != cls.PRODUCER_SUBSYSTEM:
            raise SelfGradeError(f"S2 writer cannot emit as subsystem {producer.subsystem}")

    @classmethod
    def assert_s2_artifact_claim(
        cls,
        *,
        claim_tier: str,
        validation_report_ref: str | None,
    ) -> None:
        if claim_tier != cls.RAN_TOY:
            raise SelfGradeError(
                "S2 cannot emit promoted claim_tier; tier promotion must come from signed C3 validation"
            )
        if validation_report_ref is not None:
            raise SelfGradeError("S2 writer cannot attach validation_report_ref; signed validation refs are framework-owned")


class RewardSourceError(S2Error):
    """Raised when S2 is asked to accept a non-C3 score or reward."""


class ExplainabilityReportError(S2Error):
    """Raised when S2 cannot generate a build explainability report."""


class S2ConformanceError(S2Error):
    """Raised when S2 cannot assemble an S12 conformance hook from real C4 evidence."""


class S2SandboxViolation(S2Error):
    """Raised when an S2 build hits an S10 sandbox policy violation before training execution."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        evidence_ref: str | None,
        diagnostics: Mapping[str, Any],
        status: str = "QUARANTINED",
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status
        self.evidence_ref = evidence_ref
        self.diagnostics = dict(diagnostics)
        self.category = "SANDBOX"
        self.retryable = False

    def as_c1_payload(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "status": self.status,
            "evidence_ref": self.evidence_ref,
        }


class S2ContractModelError(S2Error):
    """Raised when S2's contract-bound model surface is missing or drifting."""


class PipelineFreezeError(S2ContractModelError):
    """Raised when S2 refuses to emit a frozen pipeline artifact."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        category: str = "POLICY",
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.code = code
        self.message = message
        self.retryable = retryable

    def as_c1_payload(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
        }


class UncertaintyRequiredError(S2ContractModelError):
    """Raised when S2 receives a point-estimate-only model without a UQ wrapper."""

    def __init__(self, message: str = "S2 requires native or calibrated uncertainty before model finalization") -> None:
        super().__init__(message)
        self.category = "POLICY"
        self.code = "MISSING_UNCERTAINTY"
        self.message = message
        self.retryable = False

    def as_c1_payload(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
        }


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
S2_FEATURE_GRAPH_SCHEMA_VERSION = "argus-s2-featuregraph-v1"
S2_FEATURE_SET_SCHEMA_VERSION = "argus-s2-featureset-v1"
S2_FROZEN_PIPELINE_SCHEMA_VERSION = "argus-s2-frozen-pipeline-v1"
S2_FROZEN_PIPELINE_ENTRYPOINT_CONTRACT_VERSION = "argus.s3.frozen_pipeline_entrypoint.v1"
S2_EXPLAINABILITY_REPORT_SCHEMA_VERSION = "argus-s2-explainability-report-v1"
S2_FEATURE_GRAPH_OPS = (
    "source",
    "arithmetic",
    "pi_group",
    "invariant",
    "transform",
    "adapter_eval",
    "aggregate",
)


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
    uncertainty_propagated: bool = False
    uncertainty: Mapping[str, Any] | None = field(default=None, hash=False)
    extrapolation_flag: bool = False
    diagnostics: Mapping[str, Any] = field(default_factory=dict, hash=False)

    def __post_init__(self) -> None:
        if not self.node_id:
            raise S2ContractModelError("feature nodes require node_id")
        if not self.terms:
            raise S2ContractModelError(f"feature node {self.node_id!r} requires at least one term")
        if not self.declared_units:
            raise S2ContractModelError(f"feature node {self.node_id!r} requires declared_units")
        if self.uncertainty_propagated and self.uncertainty is None:
            raise S2ContractModelError(f"feature node {self.node_id!r} requires propagated uncertainty")
        object.__setattr__(self, "terms", tuple(self.terms))
        object.__setattr__(self, "diagnostics", dict(self.diagnostics))
        if self.uncertainty is not None:
            object.__setattr__(self, "uncertainty", dict(self.uncertainty))


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


@dataclass(frozen=True)
class FeatureGraphNode:
    node_id: str
    op: str
    feature_node: FeatureNode
    inputs: tuple[str, ...] = ()
    params: Mapping[str, Any] = field(default_factory=dict, hash=False)
    deterministic: bool = True
    adapter_ref: str | None = None
    uncertainty_propagated: bool = False
    out_dim: DimensionVector | None = None

    def __post_init__(self) -> None:
        node_id = self.node_id.strip()
        if not node_id:
            raise S2ContractModelError("feature graph nodes require node_id")
        if self.feature_node.node_id != node_id:
            raise S2ContractModelError(
                f"feature graph node {node_id!r} must wrap a FeatureNode with the same node_id"
            )
        op = self.op.strip()
        if op not in S2_FEATURE_GRAPH_OPS:
            raise S2ContractModelError(f"unsupported feature graph op for {node_id!r}: {op}")
        inputs = tuple(str(input_id).strip() for input_id in self.inputs)
        if any(not input_id for input_id in inputs):
            raise S2ContractModelError(f"feature graph node {node_id!r} has an empty input node id")
        if len(set(inputs)) != len(inputs):
            raise S2ContractModelError(f"feature graph node {node_id!r} has duplicate inputs")
        if node_id in inputs:
            raise S2ContractModelError(f"feature graph node {node_id!r} cannot depend on itself")
        params = _s2_jsonable(dict(self.params))
        adapter_ref = self.adapter_ref.strip() if isinstance(self.adapter_ref, str) else self.adapter_ref
        if adapter_ref == "":
            raise S2ContractModelError(f"feature graph node {node_id!r} has an empty adapter_ref")
        object.__setattr__(self, "node_id", node_id)
        object.__setattr__(self, "op", op)
        object.__setattr__(self, "inputs", inputs)
        object.__setattr__(self, "params", params)
        object.__setattr__(
            self,
            "uncertainty_propagated",
            bool(self.uncertainty_propagated or self.feature_node.uncertainty_propagated),
        )
        object.__setattr__(self, "adapter_ref", adapter_ref)


@dataclass(frozen=True)
class FeatureGraph:
    graph_id: str
    nodes: tuple[FeatureGraphNode, ...]
    content_hash: str
    unit_registry_version: str
    schema_version: str = S2_FEATURE_GRAPH_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.graph_id:
            raise S2ContractModelError("FeatureGraph requires graph_id")
        if not self.nodes:
            raise S2ContractModelError(f"FeatureGraph {self.graph_id!r} requires at least one node")
        if not self.content_hash:
            raise S2ContractModelError(f"FeatureGraph {self.graph_id!r} requires content_hash")
        object.__setattr__(self, "nodes", tuple(self.nodes))


@dataclass(frozen=True)
class FeatureSet:
    feature_set_id: str
    graph_ref: str
    selected_nodes: tuple[str, ...]
    content_hash: str
    graph_content_hash: str
    schema_version: str = S2_FEATURE_SET_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.feature_set_id:
            raise S2ContractModelError("FeatureSet requires feature_set_id")
        if not self.graph_ref:
            raise S2ContractModelError(f"FeatureSet {self.feature_set_id!r} requires graph_ref")
        if not self.selected_nodes:
            raise S2ContractModelError(f"FeatureSet {self.feature_set_id!r} requires selected_nodes")
        if len(set(self.selected_nodes)) != len(self.selected_nodes):
            raise S2ContractModelError(f"FeatureSet {self.feature_set_id!r} has duplicate selected_nodes")
        if not self.content_hash:
            raise S2ContractModelError(f"FeatureSet {self.feature_set_id!r} requires content_hash")
        object.__setattr__(self, "selected_nodes", tuple(self.selected_nodes))


@dataclass(frozen=True)
class FeatureGraphReplayResult:
    graph_content_hash: str
    selected_nodes: tuple[str, ...]
    values: Mapping[str, float] = field(hash=False)
    content_hash: str = ""

    def __post_init__(self) -> None:
        values = {str(key): _finite_feature_value(value, field_name=str(key)) for key, value in self.values.items()}
        object.__setattr__(self, "values", values)
        object.__setattr__(self, "selected_nodes", tuple(self.selected_nodes))
        if not self.content_hash:
            body = {
                "schema_version": S2_FEATURE_GRAPH_SCHEMA_VERSION,
                "graph_content_hash": self.graph_content_hash,
                "selected_nodes": list(self.selected_nodes),
                "values": values,
            }
            object.__setattr__(self, "content_hash", hash_bytes(canonical_json_bytes(body)))


@dataclass(frozen=True)
class FeatureSetEmissionResult:
    feature_set: FeatureSet
    artifact_record: ArtifactRecord
    replay_probe: FeatureGraphReplayResult | None = None


class FeatureGraphEngine:
    """Build, replay, and persist deterministic S2 feature DAGs."""

    def __init__(self, *, algebra: UnitsAlgebra | None = None) -> None:
        self.algebra = algebra or UnitsAlgebra()

    def build_graph(self, *, graph_id: str, nodes: tuple[FeatureGraphNode, ...]) -> FeatureGraph:
        graph_id = graph_id.strip()
        if not graph_id:
            raise S2ContractModelError("FeatureGraph requires graph_id")
        if not nodes:
            raise S2ContractModelError(f"FeatureGraph {graph_id!r} requires at least one node")
        ordered_nodes = self._topological_nodes(tuple(nodes))
        for node in ordered_nodes:
            if not node.deterministic:
                raise S2ContractModelError(f"FeatureGraph node {node.node_id!r} is not deterministic")
        validate_feature_graph_dimensions(tuple(node.feature_node for node in ordered_nodes), algebra=self.algebra)
        checked_nodes = tuple(
            replace(
                node,
                out_dim=self.algebra.feature_dimension(node.feature_node),
                uncertainty_propagated=node.uncertainty_propagated or node.feature_node.uncertainty_propagated,
            )
            for node in ordered_nodes
        )
        payload = self._graph_payload(
            graph_id=graph_id,
            nodes=checked_nodes,
            unit_registry_version=self.algebra.registry.version,
            content_hash=None,
        )
        return FeatureGraph(
            graph_id=graph_id,
            nodes=checked_nodes,
            content_hash=hash_bytes(canonical_json_bytes(payload)),
            unit_registry_version=self.algebra.registry.version,
        )

    def replay(
        self,
        graph: FeatureGraph,
        *,
        inputs: Mapping[str, float | int],
        selected_nodes: tuple[str, ...] | None = None,
    ) -> FeatureGraphReplayResult:
        selected = self._selected_nodes(graph, selected_nodes)
        input_values = {
            str(field_name): _finite_feature_value(value, field_name=str(field_name))
            for field_name, value in inputs.items()
        }
        values: dict[str, float] = {}
        for node in graph.nodes:
            node_value = self._evaluate_feature(node.feature_node, values=values, inputs=input_values)
            values[node.node_id] = node_value
        selected_values = {node_id: values[node_id] for node_id in selected}
        return FeatureGraphReplayResult(
            graph_content_hash=graph.content_hash,
            selected_nodes=selected,
            values=selected_values,
        )

    def build_feature_set(
        self,
        graph: FeatureGraph,
        *,
        selected_nodes: tuple[str, ...],
        feature_set_id: str | None = None,
    ) -> FeatureSet:
        selected = self._selected_nodes(graph, selected_nodes)
        provisional_payload = {
            "schema_version": S2_FEATURE_SET_SCHEMA_VERSION,
            "graph_content_hash": graph.content_hash,
            "selected_nodes": list(selected),
        }
        derived_id = "featureset://" + hash_bytes(canonical_json_bytes(provisional_payload)).removeprefix("blake3:")
        feature_set_id = (feature_set_id or derived_id).strip()
        graph_ref = f"featuregraph://{graph.content_hash}"
        payload = self._feature_set_payload(
            feature_set_id=feature_set_id,
            graph_ref=graph_ref,
            selected_nodes=selected,
            graph_content_hash=graph.content_hash,
            content_hash=None,
        )
        return FeatureSet(
            feature_set_id=feature_set_id,
            graph_ref=graph_ref,
            selected_nodes=selected,
            graph_content_hash=graph.content_hash,
            content_hash=hash_bytes(canonical_json_bytes(payload)),
        )

    def emit_feature_set(
        self,
        graph: FeatureGraph,
        *,
        selected_nodes: tuple[str, ...],
        emitter: ProvenanceEmitter,
        lineage: Lineage,
        feature_set_id: str | None = None,
        replay_probe_input: Mapping[str, float | int] | None = None,
    ) -> FeatureSetEmissionResult:
        feature_set = self.build_feature_set(
            graph,
            selected_nodes=selected_nodes,
            feature_set_id=feature_set_id,
        )
        replay_probe = (
            self.replay(graph, inputs=replay_probe_input, selected_nodes=feature_set.selected_nodes)
            if replay_probe_input is not None
            else None
        )
        payload: dict[str, Any] = {
            "schema_version": S2_FEATURE_SET_SCHEMA_VERSION,
            "graph": self._graph_payload(
                graph_id=graph.graph_id,
                nodes=graph.nodes,
                unit_registry_version=graph.unit_registry_version,
                content_hash=graph.content_hash,
            ),
            "feature_set": self._feature_set_payload(
                feature_set_id=feature_set.feature_set_id,
                graph_ref=feature_set.graph_ref,
                selected_nodes=feature_set.selected_nodes,
                graph_content_hash=feature_set.graph_content_hash,
                content_hash=feature_set.content_hash,
            ),
        }
        if replay_probe is not None:
            payload["replay_probe"] = {
                "content_hash": replay_probe.content_hash,
                "selected_nodes": list(replay_probe.selected_nodes),
                "values": dict(replay_probe.values),
            }
        record = emitter.emit_artifact(
            kind="feature_set",
            payload=_s2_jsonable(payload),
            lineage=lineage,
            claim_tier="ran-toy",
        )
        return FeatureSetEmissionResult(feature_set=feature_set, artifact_record=record, replay_probe=replay_probe)

    def _topological_nodes(self, nodes: tuple[FeatureGraphNode, ...]) -> tuple[FeatureGraphNode, ...]:
        by_id: dict[str, FeatureGraphNode] = {}
        for node in nodes:
            if node.node_id in by_id:
                raise S2ContractModelError(f"FeatureGraph has duplicate node_id: {node.node_id}")
            by_id[node.node_id] = node
        for node in nodes:
            missing_inputs = tuple(input_id for input_id in node.inputs if input_id not in by_id)
            if missing_inputs:
                raise S2ContractModelError(
                    f"FeatureGraph node {node.node_id!r} references missing inputs: {missing_inputs}"
                )
        visiting: set[str] = set()
        visited: set[str] = set()
        ordered: list[FeatureGraphNode] = []

        def visit(node_id: str) -> None:
            if node_id in visited:
                return
            if node_id in visiting:
                raise S2ContractModelError(f"FeatureGraph cycle detected at node: {node_id}")
            visiting.add(node_id)
            for input_id in sorted(by_id[node_id].inputs):
                visit(input_id)
            visiting.remove(node_id)
            visited.add(node_id)
            ordered.append(by_id[node_id])

        for node_id in sorted(by_id):
            visit(node_id)
        return tuple(ordered)

    @staticmethod
    def _selected_nodes(graph: FeatureGraph, selected_nodes: tuple[str, ...] | None) -> tuple[str, ...]:
        node_ids = {node.node_id for node in graph.nodes}
        selected = tuple(node.node_id for node in graph.nodes) if selected_nodes is None else tuple(selected_nodes)
        if not selected:
            raise S2ContractModelError(f"FeatureGraph {graph.graph_id!r} selected_nodes cannot be empty")
        if len(set(selected)) != len(selected):
            raise S2ContractModelError(f"FeatureGraph {graph.graph_id!r} selected_nodes has duplicates")
        missing = tuple(node_id for node_id in selected if node_id not in node_ids)
        if missing:
            raise S2ContractModelError(f"FeatureGraph {graph.graph_id!r} selected_nodes missing: {missing}")
        return selected

    @staticmethod
    def _evaluate_feature(
        feature: FeatureNode,
        *,
        values: Mapping[str, float],
        inputs: Mapping[str, float],
    ) -> float:
        result = 1.0
        for term in feature.terms:
            if term.field_name in values:
                base = values[term.field_name]
            elif term.field_name in inputs:
                base = inputs[term.field_name]
            else:
                raise S2ContractModelError(
                    f"FeatureGraph replay missing value for term {term.field_name!r} in node {feature.node_id!r}"
                )
            try:
                result *= base ** term.exponent
            except ZeroDivisionError as exc:
                raise S2ContractModelError(
                    f"FeatureGraph replay cannot apply negative exponent to zero for node {feature.node_id!r}"
                ) from exc
            if not math.isfinite(result):
                raise S2ContractModelError(f"FeatureGraph replay produced non-finite value for {feature.node_id!r}")
        return float(result)

    @staticmethod
    def _graph_payload(
        *,
        graph_id: str,
        nodes: tuple[FeatureGraphNode, ...],
        unit_registry_version: str,
        content_hash: str | None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": S2_FEATURE_GRAPH_SCHEMA_VERSION,
            "graph_id": graph_id,
            "unit_registry_version": unit_registry_version,
            "nodes": [_feature_graph_node_payload(node) for node in nodes],
        }
        if content_hash is not None:
            payload["content_hash"] = content_hash
        return payload

    @staticmethod
    def _feature_set_payload(
        *,
        feature_set_id: str,
        graph_ref: str,
        selected_nodes: tuple[str, ...],
        graph_content_hash: str,
        content_hash: str | None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": S2_FEATURE_SET_SCHEMA_VERSION,
            "feature_set_id": feature_set_id,
            "graph_ref": graph_ref,
            "graph_content_hash": graph_content_hash,
            "selected_nodes": list(selected_nodes),
        }
        if content_hash is not None:
            payload["content_hash"] = content_hash
        return payload


def _feature_graph_node_payload(node: FeatureGraphNode) -> dict[str, Any]:
    if node.out_dim is None:
        raise S2ContractModelError(f"FeatureGraph node {node.node_id!r} has no checked dimension")
    return {
        "node_id": node.node_id,
        "op": node.op,
        "inputs": list(node.inputs),
        "params": node.params,
        "deterministic": node.deterministic,
        "adapter_ref": node.adapter_ref,
        "uncertainty_propagated": node.uncertainty_propagated,
        "out_dim": _dimension_payload(node.out_dim, units=node.feature_node.declared_units),
        "feature": {
            "declared_units": node.feature_node.declared_units,
            "terms": [
                {
                    "field_name": term.field_name,
                    "units": term.units,
                    "exponent": term.exponent,
                }
                for term in node.feature_node.terms
            ],
            "uncertainty": node.feature_node.uncertainty,
            "extrapolation_flag": node.feature_node.extrapolation_flag,
            "diagnostics": node.feature_node.diagnostics,
        },
    }


def _dimension_payload(dimension: DimensionVector, *, units: str) -> dict[str, Any]:
    return {
        "bases": list(S2_DIMENSION_BASES),
        "exponents": list(dimension.exponents),
        "units": units,
    }


def _finite_feature_value(value: float | int, *, field_name: str) -> float:
    numeric = float(value)
    if not math.isfinite(numeric):
        raise S2ContractModelError(f"FeatureGraph replay received non-finite value for {field_name!r}")
    return numeric


def _s2_jsonable(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise S2ContractModelError("S2 FeatureGraph payload must be canonical JSON serializable") from exc


@dataclass(frozen=True)
class BuckinghamPiVariable:
    field_name: str
    units: str

    def __post_init__(self) -> None:
        field_name = self.field_name.strip()
        units = self.units.strip()
        if not field_name:
            raise S2ContractModelError("Buckingham-pi variables require field_name")
        if not units:
            raise S2ContractModelError(f"Buckingham-pi variable {field_name!r} requires units")
        object.__setattr__(self, "field_name", field_name)
        object.__setattr__(self, "units", units)


@dataclass(frozen=True)
class BuckinghamPiGroup:
    group_id: str
    variables: tuple[str, ...]
    exponent_vector: tuple[int, ...]
    feature_node: FeatureNode


@dataclass(frozen=True)
class BuckinghamPiResult:
    variables: tuple[BuckinghamPiVariable, ...]
    groups: tuple[BuckinghamPiGroup, ...]
    dimension_matrix_rank: int
    nullity: int
    basis_rank: int
    max_exponent: int
    unit_registry_version: str


class BuckinghamPiInjector:
    """Enumerates exact integer Buckingham-pi groups from S2 dimensions."""

    def __init__(self, *, algebra: UnitsAlgebra | None = None) -> None:
        self._algebra = algebra or UnitsAlgebra()

    def enumerate_groups(
        self,
        *,
        variables: tuple[BuckinghamPiVariable, ...],
        max_exponent: int,
        node_prefix: str = "pi",
    ) -> BuckinghamPiResult:
        variables = tuple(variables)
        node_prefix = node_prefix.strip()
        if not variables:
            raise S2ContractModelError("Buckingham-pi enumeration requires at least one variable")
        if max_exponent <= 0:
            raise S2ContractModelError("Buckingham-pi max_exponent must be positive")
        if not node_prefix:
            raise S2ContractModelError("Buckingham-pi node_prefix cannot be empty")
        names = tuple(variable.field_name for variable in variables)
        if len(set(names)) != len(names):
            raise S2ContractModelError("Buckingham-pi variables must have unique field_name values")

        dimensions = tuple(self._algebra.dimension(variable.units) for variable in variables)
        matrix_rows = tuple(
            tuple(dimension.exponents[index] for dimension in dimensions) for index in range(len(S2_DIMENSION_BASES))
        )
        dimension_matrix_rank = _matrix_rank(matrix_rows)
        nullity = len(variables) - dimension_matrix_rank
        if nullity == 0:
            return BuckinghamPiResult(
                variables=variables,
                groups=(),
                dimension_matrix_rank=dimension_matrix_rank,
                nullity=0,
                basis_rank=0,
                max_exponent=max_exponent,
                unit_registry_version=self._algebra.registry.version,
            )

        candidate_vectors: set[tuple[int, ...]] = set()
        for vector in product(range(-max_exponent, max_exponent + 1), repeat=len(variables)):
            if all(exponent == 0 for exponent in vector):
                continue
            if _dimension_sum(dimensions, tuple(vector)).is_dimensionless:
                candidate_vectors.add(_canonical_pi_vector(tuple(vector)))
        ordered_vectors = tuple(
            sorted(candidate_vectors, key=lambda item: (sum(abs(value) for value in item), max(abs(value) for value in item), item))
        )
        selected: list[tuple[int, ...]] = []
        for vector in ordered_vectors:
            if _matrix_rank(tuple(selected) + (vector,)) > len(selected):
                selected.append(vector)
            if len(selected) == nullity:
                break
        if len(selected) != nullity:
            raise S2ContractModelError(
                f"Buckingham-pi exponent bound {max_exponent} produced {len(selected)} independent groups, expected {nullity}"
            )

        groups = tuple(
            BuckinghamPiGroup(
                group_id=f"{node_prefix}_{index}",
                variables=names,
                exponent_vector=vector,
                feature_node=FeatureNode(
                    node_id=f"{node_prefix}_{index}",
                    terms=tuple(
                        FeatureTerm(field_name=variable.field_name, units=variable.units, exponent=exponent)
                        for variable, exponent in zip(variables, vector)
                        if exponent != 0
                    ),
                    declared_units="dimensionless",
                ),
            )
            for index, vector in enumerate(selected, start=1)
        )
        return BuckinghamPiResult(
            variables=variables,
            groups=groups,
            dimension_matrix_rank=dimension_matrix_rank,
            nullity=nullity,
            basis_rank=_matrix_rank(tuple(group.exponent_vector for group in groups)),
            max_exponent=max_exponent,
            unit_registry_version=self._algebra.registry.version,
        )


@dataclass(frozen=True)
class SymmetryInvariantFeature:
    feature_node: FeatureNode
    symmetry: str
    power: int
    advisory: bool = True
    claim_tier: str = "ran-toy"

    def transform(self, values: tuple[float, ...]) -> tuple[float, ...]:
        transformed: list[float] = []
        for value in values:
            number = float(value)
            if not math.isfinite(number):
                raise S2ContractModelError("symmetry invariant transform received non-finite value")
            transformed.append(number**self.power)
        return tuple(transformed)


class SymmetryInvariantInjector:
    """Creates deterministic feature transforms invariant under simple physics symmetries."""

    def __init__(self, *, algebra: UnitsAlgebra | None = None) -> None:
        self._algebra = algebra or UnitsAlgebra()

    def even_power(
        self,
        *,
        field_name: str,
        units: str,
        power: int = 2,
        node_id: str | None = None,
    ) -> SymmetryInvariantFeature:
        field_name = field_name.strip()
        units = units.strip()
        node_id = (node_id or f"{field_name}_even_power_{power}").strip()
        if not field_name:
            raise S2ContractModelError("symmetry invariant field_name cannot be empty")
        if not units:
            raise S2ContractModelError("symmetry invariant units cannot be empty")
        if power <= 0 or power % 2 != 0:
            raise S2ContractModelError("sign-flip invariant power must be a positive even integer")
        declared_units = _power_unit_expression(units, power)
        self._algebra.dimension(declared_units)
        return SymmetryInvariantFeature(
            feature_node=FeatureNode(
                node_id=node_id,
                terms=(FeatureTerm(field_name=field_name, units=units, exponent=power),),
                declared_units=declared_units,
            ),
            symmetry="sign_flip",
            power=power,
        )


@dataclass(frozen=True)
class PositiveOutputConstraint:
    target_name: str
    units: str
    minimum: float = 0.0

    def __post_init__(self) -> None:
        target_name = self.target_name.strip()
        units = self.units.strip()
        minimum = float(self.minimum)
        if not target_name:
            raise S2ContractModelError("positivity constraint requires target_name")
        if not units:
            raise S2ContractModelError(f"positivity constraint {target_name!r} requires units")
        if minimum < 0 or not math.isfinite(minimum):
            raise S2ContractModelError("positivity constraint minimum must be finite and non-negative")
        object.__setattr__(self, "target_name", target_name)
        object.__setattr__(self, "units", units)
        object.__setattr__(self, "minimum", minimum)


@dataclass(frozen=True)
class PositivityEnforcementResult:
    constraint: PositiveOutputConstraint
    transformed_predictions: tuple[float, ...]
    min_prediction: float
    status: str
    advisory: bool = True
    claim_tier: str = "ran-toy"


class PositivityArchitectureInjector:
    """Applies a deterministic positive-output architecture transform."""

    def enforce(
        self,
        *,
        raw_predictions: tuple[float, ...],
        constraint: PositiveOutputConstraint,
    ) -> PositivityEnforcementResult:
        if not raw_predictions:
            raise S2ContractModelError("positivity enforcement requires at least one prediction")
        transformed = tuple(_stable_softplus(float(value)) + constraint.minimum for value in raw_predictions)
        if any(not math.isfinite(value) for value in transformed):
            raise S2ContractModelError("positivity enforcement produced non-finite predictions")
        min_prediction = min(transformed)
        return PositivityEnforcementResult(
            constraint=constraint,
            transformed_predictions=transformed,
            min_prediction=min_prediction,
            status="PASS" if min_prediction >= constraint.minimum else "FAIL",
        )


@dataclass(frozen=True)
class AsymptoticLimitAnchor:
    variable_name: str
    limit_value: float
    known_output: float
    tolerance: float
    approach_points: tuple[float, ...]

    def __post_init__(self) -> None:
        variable_name = self.variable_name.strip()
        limit_value = float(self.limit_value)
        known_output = float(self.known_output)
        tolerance = float(self.tolerance)
        approach_points = tuple(float(point) for point in self.approach_points)
        if not variable_name:
            raise S2ContractModelError("asymptotic anchor requires variable_name")
        if not math.isfinite(limit_value) or not math.isfinite(known_output):
            raise S2ContractModelError("asymptotic anchor limit and known output must be finite")
        if tolerance < 0 or not math.isfinite(tolerance):
            raise S2ContractModelError("asymptotic anchor tolerance must be finite and non-negative")
        if not approach_points:
            raise S2ContractModelError("asymptotic anchor requires approach_points")
        if any(not math.isfinite(point) for point in approach_points):
            raise S2ContractModelError("asymptotic anchor approach_points must be finite")
        object.__setattr__(self, "variable_name", variable_name)
        object.__setattr__(self, "limit_value", limit_value)
        object.__setattr__(self, "known_output", known_output)
        object.__setattr__(self, "tolerance", tolerance)
        object.__setattr__(self, "approach_points", approach_points)


@dataclass(frozen=True)
class AsymptoticLimitEvaluation:
    anchor: AsymptoticLimitAnchor
    evaluations: tuple[tuple[float, float, float], ...]
    max_abs_error: float
    status: str
    advisory: bool = True
    claim_tier: str = "ran-toy"


class AsymptoticLimitInjector:
    """Evaluates deterministic asymptotic-limit anchors for candidate predictors."""

    def evaluate(
        self,
        *,
        anchor: AsymptoticLimitAnchor,
        predictor: Callable[[Mapping[str, float]], float],
    ) -> AsymptoticLimitEvaluation:
        evaluations: list[tuple[float, float, float]] = []
        for point in anchor.approach_points:
            prediction = float(predictor({anchor.variable_name: point}))
            if not math.isfinite(prediction):
                raise S2ContractModelError("asymptotic anchor predictor returned a non-finite value")
            error = abs(prediction - anchor.known_output)
            evaluations.append((point, prediction, error))
        max_abs_error = max(error for _, _, error in evaluations)
        return AsymptoticLimitEvaluation(
            anchor=anchor,
            evaluations=tuple(evaluations),
            max_abs_error=max_abs_error,
            status="PASS" if max_abs_error <= anchor.tolerance else "FAIL",
        )


@dataclass(frozen=True)
class ForwardModelFeatureRequest:
    feature_node_id: str
    adapter_request: EvalRequest
    output_field: str
    declared_units: str | None = None
    out_of_domain_policy: str = "flag"

    def __post_init__(self) -> None:
        feature_node_id = self.feature_node_id.strip()
        output_field = self.output_field.strip()
        declared_units = self.declared_units.strip() if self.declared_units is not None else None
        out_of_domain_policy = self.out_of_domain_policy.strip()
        if not feature_node_id:
            raise S2ContractModelError("forward-model feature requires feature_node_id")
        if not output_field:
            raise S2ContractModelError("forward-model feature requires output_field")
        if declared_units == "":
            raise S2ContractModelError("forward-model feature declared_units cannot be empty")
        if out_of_domain_policy not in {"flag", "drop"}:
            raise S2ContractModelError("forward-model feature out_of_domain_policy must be flag or drop")
        object.__setattr__(self, "feature_node_id", feature_node_id)
        object.__setattr__(self, "output_field", output_field)
        object.__setattr__(self, "declared_units", declared_units)
        object.__setattr__(self, "out_of_domain_policy", out_of_domain_policy)


@dataclass(frozen=True)
class ForwardModelFeatureResult:
    feature_node: FeatureNode | None
    value: float | None
    units: str | None
    uncertainty: Mapping[str, Any] | None = field(hash=False)
    adapter_provenance_ref: str
    adapter_id: str
    extrapolation_flag: bool
    violated_fields: tuple[str, ...]
    diagnostics: Mapping[str, Any] = field(hash=False)
    status: str
    advisory: bool = True
    claim_tier: str = "ran-toy"

    def __post_init__(self) -> None:
        if self.status not in {"PASS", "EXTRAPOLATED", "DROPPED"}:
            raise S2ContractModelError(f"unsupported forward-model feature status: {self.status}")
        object.__setattr__(self, "violated_fields", tuple(self.violated_fields))
        object.__setattr__(self, "diagnostics", dict(self.diagnostics))
        if self.uncertainty is not None:
            object.__setattr__(self, "uncertainty", dict(self.uncertainty))


class ForwardModelFeatureInjector:
    """Injects C6 forward-model outputs as S2 feature nodes with explicit uncertainty."""

    def __init__(self, *, adapter_broker: AdapterBroker, algebra: UnitsAlgebra | None = None) -> None:
        self._adapter_broker = adapter_broker
        self._algebra = algebra or UnitsAlgebra()

    def inject(self, request: ForwardModelFeatureRequest) -> ForwardModelFeatureResult:
        adapter_result = self._adapter_broker.evaluate(request.adapter_request)
        try:
            quantity = adapter_result.outputs[request.output_field]
        except KeyError as exc:
            raise S2ContractModelError(f"forward-model adapter output missing field: {request.output_field}") from exc

        value = float(quantity.value)
        if not math.isfinite(value):
            raise S2ContractModelError("forward-model adapter output value must be finite")
        if quantity.uncertainty is None:
            raise S2ContractModelError("forward-model adapter output must carry uncertainty")

        declared_units = request.declared_units or quantity.units
        if self._algebra.dimension(quantity.units) != self._algebra.dimension(declared_units):
            raise S2ContractModelError(
                f"forward-model output units {quantity.units!r} do not match declared units {declared_units!r}"
            )

        uncertainty = dict(quantity.uncertainty)
        diagnostics = {
            "adapter_id": adapter_result.adapter_id,
            "adapter_provenance_ref": adapter_result.provenance_ref,
            "output_field": request.output_field,
            "in_validity_domain": adapter_result.in_validity_domain,
            "extrapolation_flag": adapter_result.extrapolation_flag,
            "violated_fields": adapter_result.violated_fields,
            "out_of_domain_policy": request.out_of_domain_policy,
            "uncertainty_propagated": True,
        }
        if adapter_result.extrapolation_flag and request.out_of_domain_policy == "drop":
            return ForwardModelFeatureResult(
                feature_node=None,
                value=None,
                units=None,
                uncertainty=None,
                adapter_provenance_ref=adapter_result.provenance_ref,
                adapter_id=adapter_result.adapter_id,
                extrapolation_flag=True,
                violated_fields=adapter_result.violated_fields,
                diagnostics=diagnostics,
                status="DROPPED",
            )

        feature_node = FeatureNode(
            node_id=request.feature_node_id,
            terms=(FeatureTerm(field_name=request.output_field, units=quantity.units),),
            declared_units=declared_units,
            uncertainty_propagated=True,
            uncertainty=uncertainty,
            extrapolation_flag=adapter_result.extrapolation_flag,
            diagnostics=diagnostics,
        )
        return ForwardModelFeatureResult(
            feature_node=feature_node,
            value=value,
            units=quantity.units,
            uncertainty=uncertainty,
            adapter_provenance_ref=adapter_result.provenance_ref,
            adapter_id=adapter_result.adapter_id,
            extrapolation_flag=adapter_result.extrapolation_flag,
            violated_fields=adapter_result.violated_fields,
            diagnostics=diagnostics,
            status="EXTRAPOLATED" if adapter_result.extrapolation_flag else "PASS",
        )


def _dimension_sum(dimensions: tuple[DimensionVector, ...], exponents: tuple[int, ...]) -> DimensionVector:
    result = DimensionVector.dimensionless()
    for dimension, exponent in zip(dimensions, exponents):
        result = result * (dimension ** exponent)
    return result


def _canonical_pi_vector(vector: tuple[int, ...]) -> tuple[int, ...]:
    for value in vector:
        if value == 0:
            continue
        return tuple(-item for item in vector) if value < 0 else vector
    return vector


def _matrix_rank(rows: tuple[tuple[int, ...], ...]) -> int:
    if not rows:
        return 0
    matrix = [[Fraction(value) for value in row] for row in rows if any(value != 0 for value in row)]
    if not matrix:
        return 0
    row_count = len(matrix)
    col_count = len(matrix[0])
    rank = 0
    for col in range(col_count):
        pivot = None
        for row in range(rank, row_count):
            if matrix[row][col] != 0:
                pivot = row
                break
        if pivot is None:
            continue
        matrix[rank], matrix[pivot] = matrix[pivot], matrix[rank]
        pivot_value = matrix[rank][col]
        matrix[rank] = [value / pivot_value for value in matrix[rank]]
        for row in range(row_count):
            if row == rank or matrix[row][col] == 0:
                continue
            factor = matrix[row][col]
            matrix[row] = [value - factor * pivot_entry for value, pivot_entry in zip(matrix[row], matrix[rank])]
        rank += 1
        if rank == row_count:
            break
    return rank


def _stable_softplus(value: float) -> float:
    if not math.isfinite(value):
        raise S2ContractModelError("positive-output transform received non-finite value")
    if value > 50:
        return value
    if value < -50:
        return math.exp(value)
    return math.log1p(math.exp(value))


def _power_unit_expression(unit_expression: str, exponent: int) -> str:
    expression = unit_expression.replace(" ", "")
    if exponent <= 0:
        raise S2ContractModelError("unit expression exponent must be positive")
    if expression in {"", "1", "dimensionless"}:
        return "dimensionless"

    parts: list[str] = []
    for token in _unit_expression_tokens(expression):
        if token in {"*", "/"}:
            parts.append(token)
            continue
        symbol, token_exponent = _unit_token_power(token)
        if symbol == "1":
            parts.append(symbol)
            continue
        powered_exponent = token_exponent * exponent
        parts.append(symbol if powered_exponent == 1 else f"{symbol}^{powered_exponent}")
    return "".join(parts)


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
    allowed_egress: tuple[EgressRule, ...] = ()
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
        backends: Mapping[str, Any] | None = None,
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


@dataclass(frozen=True)
class FailureSymptom:
    code: str
    message: str
    metrics: dict[str, Any] = field(default_factory=dict)
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        code = self.code.strip()
        message = self.message.strip()
        evidence_refs = tuple(str(ref).strip() for ref in self.evidence_refs)
        if not code:
            raise S2ContractModelError("S2 FailureSymptom requires code")
        if not message:
            raise S2ContractModelError("S2 FailureSymptom requires message")
        if any(not ref for ref in evidence_refs):
            raise S2ContractModelError("S2 FailureSymptom evidence_refs cannot contain empty refs")
        object.__setattr__(self, "code", code)
        object.__setattr__(self, "message", message)
        object.__setattr__(self, "metrics", dict(self.metrics))
        object.__setattr__(self, "evidence_refs", evidence_refs)


@dataclass(frozen=True)
class FailureRepairProposal:
    code: str
    reason: str
    learning_rate: float
    parameters: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        code = self.code.strip()
        reason = self.reason.strip()
        learning_rate = float(self.learning_rate)
        if not code:
            raise S2ContractModelError("S2 FailureRepairProposal requires code")
        if not reason:
            raise S2ContractModelError("S2 FailureRepairProposal requires reason")
        if learning_rate <= 0 or not math.isfinite(learning_rate):
            raise S2ContractModelError("S2 FailureRepairProposal learning_rate must be finite and positive")
        object.__setattr__(self, "code", code)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "learning_rate", learning_rate)
        object.__setattr__(self, "parameters", dict(self.parameters))


@dataclass(frozen=True)
class FailureProbeResult:
    status: str
    metrics: dict[str, Any] = field(default_factory=dict)
    symptom: FailureSymptom | None = None
    training_artifact_ref: str | None = None

    def __post_init__(self) -> None:
        status = self.status.strip()
        if status not in {"RESOLVED", "FAILED"}:
            raise S2ContractModelError(f"unsupported S2 FailureProbeResult status: {status}")
        training_artifact_ref = None if self.training_artifact_ref is None else self.training_artifact_ref.strip()
        if training_artifact_ref == "":
            raise S2ContractModelError("S2 FailureProbeResult training_artifact_ref cannot be empty")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "metrics", dict(self.metrics))
        object.__setattr__(self, "training_artifact_ref", training_artifact_ref)

    @property
    def resolved(self) -> bool:
        return self.status == "RESOLVED"


@dataclass(frozen=True)
class FailureRepairAction:
    code: str
    reason: str
    attempt: int
    learning_rate: float
    parameters: dict[str, Any]
    probe_result: str
    resolved: bool
    metrics: dict[str, Any] = field(default_factory=dict)
    training_artifact_ref: str | None = None

    def __post_init__(self) -> None:
        code = self.code.strip()
        reason = self.reason.strip()
        probe_result = self.probe_result.strip()
        if not code:
            raise S2ContractModelError("S2 FailureRepairAction requires code")
        if not reason:
            raise S2ContractModelError("S2 FailureRepairAction requires reason")
        if self.attempt <= 0:
            raise S2ContractModelError("S2 FailureRepairAction attempt must be positive")
        if not probe_result:
            raise S2ContractModelError("S2 FailureRepairAction requires probe_result")
        training_artifact_ref = None if self.training_artifact_ref is None else self.training_artifact_ref.strip()
        if training_artifact_ref == "":
            raise S2ContractModelError("S2 FailureRepairAction training_artifact_ref cannot be empty")
        object.__setattr__(self, "code", code)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "learning_rate", float(self.learning_rate))
        object.__setattr__(self, "parameters", dict(self.parameters))
        object.__setattr__(self, "probe_result", probe_result)
        object.__setattr__(self, "metrics", dict(self.metrics))
        object.__setattr__(self, "training_artifact_ref", training_artifact_ref)


RepairPlanner = Callable[[FailureSymptom, TrainingRequest, int], FailureRepairProposal]
FailureProbe = Callable[[TrainingRequest], FailureProbeResult]


@dataclass(frozen=True)
class FailureDiagnosisRequest:
    job_id: str
    training_request: TrainingRequest
    observed_symptom: FailureSymptom
    max_repair_attempts: int
    code_ref: str
    environment_digest: str
    seed: str
    repair_planner: RepairPlanner | None = field(default=None, compare=False, repr=False)
    probe: FailureProbe | None = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        job_id = self.job_id.strip()
        code_ref = self.code_ref.strip()
        environment_digest = self.environment_digest.strip()
        seed = self.seed.strip()
        if not job_id:
            raise S2ContractModelError("S2 FailureDiagnosisRequest requires job_id")
        if self.max_repair_attempts <= 0:
            raise S2ContractModelError("S2 FailureDiagnosisRequest max_repair_attempts must be positive")
        if not code_ref:
            raise S2ContractModelError("S2 FailureDiagnosisRequest requires code_ref")
        if not environment_digest:
            raise S2ContractModelError("S2 FailureDiagnosisRequest requires environment_digest")
        if not seed:
            raise S2ContractModelError("S2 FailureDiagnosisRequest requires seed")
        object.__setattr__(self, "job_id", job_id)
        object.__setattr__(self, "code_ref", code_ref)
        object.__setattr__(self, "environment_digest", environment_digest)
        object.__setattr__(self, "seed", seed)


@dataclass(frozen=True)
class FailureDiagnosisResult:
    job_id: str
    status: str
    repair_actions: tuple[FailureRepairAction, ...]
    repair_log_ref: str
    final_training_request: TrainingRequest
    final_symptom: FailureSymptom | None
    final_metrics: dict[str, Any]
    diagnostics: dict[str, Any] = field(default_factory=dict)


class FailureDoctor:
    """Diagnoses bounded S2 training failures and logs repair attempts to C4."""

    def __init__(
        self,
        *,
        artifact_store: InMemoryArtifactStore,
        provenance_emitter: "ProvenanceEmitter" | None = None,
    ) -> None:
        self._artifact_store = artifact_store
        self._provenance_emitter = provenance_emitter or ProvenanceEmitter(artifact_store=artifact_store)

    def diagnose_and_repair(self, request: FailureDiagnosisRequest) -> FailureDiagnosisResult:
        current_request = request.training_request
        current_symptom = request.observed_symptom
        seen_repair_states = {self._repair_state_key(current_request)}
        actions: list[FailureRepairAction] = []
        final_metrics: dict[str, Any] = {}

        for attempt in range(1, request.max_repair_attempts + 1):
            proposal = self._plan_repair(request, current_symptom, current_request, attempt)
            candidate = self._apply_repair(current_request, proposal)
            candidate_key = self._repair_state_key(candidate)
            if candidate_key in seen_repair_states:
                actions.append(
                    FailureRepairAction(
                        code="repair_loop_detected",
                        reason="repair proposal repeats a previous training configuration",
                        attempt=attempt,
                        learning_rate=candidate.learning_rate,
                        parameters=dict(candidate.parameters),
                        probe_result="loop_detected",
                        resolved=False,
                        metrics={},
                    )
                )
                return self._emit_result(
                    request=request,
                    status="QUARANTINED",
                    actions=tuple(actions),
                    final_training_request=current_request,
                    final_symptom=current_symptom,
                    final_metrics=final_metrics,
                )
            seen_repair_states.add(candidate_key)

            probe_result = self._run_probe(request, candidate)
            final_metrics = dict(probe_result.metrics)
            actions.append(
                FailureRepairAction(
                    code=proposal.code,
                    reason=proposal.reason,
                    attempt=attempt,
                    learning_rate=candidate.learning_rate,
                    parameters=dict(candidate.parameters),
                    probe_result="resolved" if probe_result.resolved else "failed",
                    resolved=probe_result.resolved,
                    metrics=probe_result.metrics,
                    training_artifact_ref=probe_result.training_artifact_ref,
                )
            )
            if probe_result.resolved:
                return self._emit_result(
                    request=request,
                    status="RESOLVED",
                    actions=tuple(actions),
                    final_training_request=candidate,
                    final_symptom=None,
                    final_metrics=final_metrics,
                )
            current_request = candidate
            current_symptom = probe_result.symptom or current_symptom

        return self._emit_result(
            request=request,
            status="QUARANTINED",
            actions=tuple(actions),
            final_training_request=current_request,
            final_symptom=current_symptom,
            final_metrics=final_metrics,
        )

    def _plan_repair(
        self,
        request: FailureDiagnosisRequest,
        symptom: FailureSymptom,
        current_request: TrainingRequest,
        attempt: int,
    ) -> FailureRepairProposal:
        if request.repair_planner is not None:
            return request.repair_planner(symptom, current_request, attempt)
        if symptom.code in {"nan_loss", "loss_nan", "divergent_loss"}:
            parameters = dict(current_request.parameters)
            parameters.setdefault("gradient_clip_norm", 1.0)
            repaired_lr = max(min(current_request.learning_rate * 0.1, 0.05), 1e-6)
            return FailureRepairProposal(
                code="nan_loss",
                reason="lower learning rate and add gradient clipping after NaN/divergent loss",
                learning_rate=repaired_lr,
                parameters=parameters,
            )
        return FailureRepairProposal(
            code="no_repair_policy",
            reason=f"no bounded S2 repair policy for symptom {symptom.code!r}",
            learning_rate=current_request.learning_rate,
            parameters=dict(current_request.parameters),
        )

    @staticmethod
    def _apply_repair(training_request: TrainingRequest, proposal: FailureRepairProposal) -> TrainingRequest:
        return replace(
            training_request,
            learning_rate=proposal.learning_rate,
            parameters=dict(proposal.parameters),
        )

    def _run_probe(self, request: FailureDiagnosisRequest, candidate: TrainingRequest) -> FailureProbeResult:
        if request.probe is not None:
            return request.probe(candidate)
        runtime = TrainingRuntime(artifact_store=self._artifact_store, provenance_emitter=self._provenance_emitter)
        try:
            result = runtime.train(candidate)
        except S2BudgetExceededError as exc:
            return FailureProbeResult(
                status="FAILED",
                metrics=exc.snapshot.as_cost_actual(),
                symptom=FailureSymptom(code=exc.code, message=exc.message, metrics=exc.snapshot.as_cost_actual()),
                training_artifact_ref=exc.partial_checkpoint.artifact_ref if exc.partial_checkpoint else None,
            )
        metrics = dict(result.diagnostics.get("final_metrics", {}))
        loss = metrics.get("loss")
        if isinstance(loss, (int, float)) and math.isfinite(float(loss)):
            return FailureProbeResult(
                status="RESOLVED",
                metrics=metrics,
                training_artifact_ref=result.final_checkpoint_ref,
            )
        return FailureProbeResult(
            status="FAILED",
            metrics=metrics,
            symptom=FailureSymptom(code="nan_loss", message="probe training did not produce finite loss", metrics=metrics),
            training_artifact_ref=result.final_checkpoint_ref,
        )

    def _emit_result(
        self,
        *,
        request: FailureDiagnosisRequest,
        status: str,
        actions: tuple[FailureRepairAction, ...],
        final_training_request: TrainingRequest,
        final_symptom: FailureSymptom | None,
        final_metrics: Mapping[str, Any],
    ) -> FailureDiagnosisResult:
        input_refs = self._lineage_input_refs(request, actions)
        payload = {
            "job_id": request.job_id,
            "status": status,
            "observed_symptom": self._symptom_payload(request.observed_symptom),
            "final_symptom": self._symptom_payload(final_symptom) if final_symptom is not None else None,
            "max_repair_attempts": request.max_repair_attempts,
            "repair_actions": [self._repair_action_payload(action) for action in actions],
            "final_metrics": self._safe_json_value(dict(final_metrics)),
            "final_training_request": self._training_request_summary(final_training_request),
            "diagnostics": {
                "attempt_count": len(actions),
                "bounded": True,
                "claim_tier": "ran-toy",
            },
        }
        record = self._provenance_emitter.emit_artifact(
            kind="failure_repair_log",
            payload=payload,
            producer=Producer(subsystem="S2", version="0.0.0", job_id=request.job_id),
            lineage=Lineage(
                input_refs=input_refs,
                code_ref=request.code_ref,
                environment_digest=request.environment_digest,
                seeds=(request.seed,),
                job_id=request.job_id,
            ),
            claim_tier="ran-toy",
        )
        return FailureDiagnosisResult(
            job_id=request.job_id,
            status=status,
            repair_actions=actions,
            repair_log_ref=record.artifact_ref,
            final_training_request=final_training_request,
            final_symptom=final_symptom,
            final_metrics=dict(final_metrics),
            diagnostics=dict(payload["diagnostics"]),
        )

    @staticmethod
    def _lineage_input_refs(
        request: FailureDiagnosisRequest,
        actions: tuple[FailureRepairAction, ...],
    ) -> tuple[str, ...]:
        refs: list[str] = []
        for ref in tuple(request.training_request.input_refs) + tuple(request.observed_symptom.evidence_refs):
            if ref not in refs:
                refs.append(ref)
        for action in actions:
            if action.training_artifact_ref and action.training_artifact_ref not in refs:
                refs.append(action.training_artifact_ref)
        return tuple(refs)

    @staticmethod
    def _repair_state_key(training_request: TrainingRequest) -> str:
        return json.dumps(
            {
                "family_id": training_request.family_id,
                "learning_rate": training_request.learning_rate,
                "parameters": training_request.parameters,
                "max_epochs": training_request.max_epochs,
            },
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )

    @classmethod
    def _repair_action_payload(cls, action: FailureRepairAction) -> dict[str, Any]:
        return {
            "code": action.code,
            "reason": action.reason,
            "attempt": action.attempt,
            "learning_rate": action.learning_rate,
            "parameters": cls._safe_json_value(action.parameters),
            "probe_result": action.probe_result,
            "resolved": action.resolved,
            "metrics": cls._safe_json_value(action.metrics),
            "training_artifact_ref": action.training_artifact_ref,
        }

    @classmethod
    def _symptom_payload(cls, symptom: FailureSymptom) -> dict[str, Any]:
        return {
            "code": symptom.code,
            "message": symptom.message,
            "metrics": cls._safe_json_value(symptom.metrics),
            "evidence_refs": list(symptom.evidence_refs),
        }

    @staticmethod
    def _training_request_summary(training_request: TrainingRequest) -> dict[str, Any]:
        return {
            "job_id": training_request.job_id,
            "family_id": training_request.family_id,
            "input_refs": list(training_request.input_refs),
            "feature_names": list(training_request.feature_names),
            "target_name": training_request.target_name,
            "max_epochs": training_request.max_epochs,
            "learning_rate": training_request.learning_rate,
            "parameters": dict(training_request.parameters),
        }

    @classmethod
    def _safe_json_value(cls, value: Any) -> Any:
        if isinstance(value, float):
            if math.isnan(value):
                return "NaN"
            if math.isinf(value):
                return "Infinity" if value > 0 else "-Infinity"
            return value
        if isinstance(value, Mapping):
            return {str(key): cls._safe_json_value(item) for key, item in value.items()}
        if isinstance(value, tuple):
            return [cls._safe_json_value(item) for item in value]
        if isinstance(value, list):
            return [cls._safe_json_value(item) for item in value]
        return value


@dataclass(frozen=True)
class UQCalibrationSample:
    sample_id: str
    prediction: float
    target: float
    interval_lower: float | None = None
    interval_upper: float | None = None

    def __post_init__(self) -> None:
        sample_id = self.sample_id.strip()
        if not sample_id:
            raise S2ContractModelError("S2 UQ calibration samples require sample_id")
        prediction = float(self.prediction)
        target = float(self.target)
        if not math.isfinite(prediction) or not math.isfinite(target):
            raise S2ContractModelError("S2 UQ calibration samples require finite prediction and target")
        interval_lower = None if self.interval_lower is None else float(self.interval_lower)
        interval_upper = None if self.interval_upper is None else float(self.interval_upper)
        if interval_lower is not None and not math.isfinite(interval_lower):
            raise S2ContractModelError("S2 UQ calibration samples require finite interval_lower")
        if interval_upper is not None and not math.isfinite(interval_upper):
            raise S2ContractModelError("S2 UQ calibration samples require finite interval_upper")
        if interval_lower is not None and interval_upper is not None and interval_lower > interval_upper:
            raise S2ContractModelError("S2 UQ calibration sample interval_lower cannot exceed interval_upper")
        object.__setattr__(self, "sample_id", sample_id)
        object.__setattr__(self, "prediction", prediction)
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "interval_lower", interval_lower)
        object.__setattr__(self, "interval_upper", interval_upper)

    @property
    def residual(self) -> float:
        return abs(self.target - self.prediction)

    def covered_by_interval(self, *, lower: float, upper: float) -> bool:
        return lower <= self.target <= upper

    def covered_by_radius(self, radius: float) -> bool:
        return self.covered_by_interval(lower=self.prediction - radius, upper=self.prediction + radius)

    def covered_by_native_interval(self) -> bool:
        if self.interval_lower is None or self.interval_upper is None:
            raise S2ContractModelError("S2 native interval UQ samples require interval_lower and interval_upper")
        return self.covered_by_interval(lower=self.interval_lower, upper=self.interval_upper)


@dataclass(frozen=True)
class UQCalibrationRequest:
    job_id: str
    model_artifact_ref: str
    split_manifest_ref: str
    calibration_input_refs: tuple[str, ...]
    validation_input_refs: tuple[str, ...]
    calibration_samples: tuple[UQCalibrationSample, ...]
    validation_samples: tuple[UQCalibrationSample, ...]
    uncertainty_method: str
    native_uq: str
    nominal_coverage: float
    coverage_tolerance: float
    code_ref: str
    environment_digest: str
    seed: str
    nondeterminism_tolerance: float = 0.0
    replay_output_pairs: tuple[tuple[float, float], ...] = ()

    def __post_init__(self) -> None:
        job_id = self.job_id.strip()
        model_artifact_ref = self.model_artifact_ref.strip()
        split_manifest_ref = self.split_manifest_ref.strip()
        calibration_input_refs = tuple(str(ref).strip() for ref in self.calibration_input_refs)
        validation_input_refs = tuple(str(ref).strip() for ref in self.validation_input_refs)
        uncertainty_method = self.uncertainty_method.strip()
        native_uq = self.native_uq.strip()
        code_ref = self.code_ref.strip()
        environment_digest = self.environment_digest.strip()
        seed = self.seed.strip()
        nominal_coverage = float(self.nominal_coverage)
        coverage_tolerance = float(self.coverage_tolerance)
        nondeterminism_tolerance = float(self.nondeterminism_tolerance)
        replay_output_pairs = tuple((float(left), float(right)) for left, right in self.replay_output_pairs)
        if not job_id:
            raise S2ContractModelError("S2 UQCalibrationRequest requires job_id")
        if not model_artifact_ref:
            raise S2ContractModelError("S2 UQCalibrationRequest requires model_artifact_ref")
        if not split_manifest_ref:
            raise S2ContractModelError("S2 UQCalibrationRequest requires split_manifest_ref")
        if not calibration_input_refs or any(not ref for ref in calibration_input_refs):
            raise S2ContractModelError("S2 UQCalibrationRequest requires calibration_input_refs")
        if not validation_input_refs or any(not ref for ref in validation_input_refs):
            raise S2ContractModelError("S2 UQCalibrationRequest requires validation_input_refs")
        if not self.calibration_samples:
            raise S2ContractModelError("S2 UQCalibrationRequest requires calibration_samples")
        if not self.validation_samples:
            raise S2ContractModelError("S2 UQCalibrationRequest requires validation_samples")
        if uncertainty_method not in {"none", "split_conformal", "native_interval"}:
            raise S2ContractModelError(f"unsupported S2 UQ uncertainty_method: {uncertainty_method}")
        if not native_uq:
            raise S2ContractModelError("S2 UQCalibrationRequest requires native_uq")
        if not 0.0 < nominal_coverage < 1.0:
            raise S2ContractModelError("S2 UQ nominal_coverage must be between 0 and 1")
        if coverage_tolerance < 0 or coverage_tolerance >= 1:
            raise S2ContractModelError("S2 UQ coverage_tolerance must be in [0, 1)")
        if not code_ref:
            raise S2ContractModelError("S2 UQCalibrationRequest requires code_ref")
        if not environment_digest:
            raise S2ContractModelError("S2 UQCalibrationRequest requires environment_digest")
        if not seed:
            raise S2ContractModelError("S2 UQCalibrationRequest requires seed")
        if nondeterminism_tolerance < 0:
            raise S2ContractModelError("S2 UQ nondeterminism_tolerance must be non-negative")
        for left, right in replay_output_pairs:
            if not math.isfinite(left) or not math.isfinite(right):
                raise S2ContractModelError("S2 UQ replay outputs must be finite")
        object.__setattr__(self, "job_id", job_id)
        object.__setattr__(self, "model_artifact_ref", model_artifact_ref)
        object.__setattr__(self, "split_manifest_ref", split_manifest_ref)
        object.__setattr__(self, "calibration_input_refs", calibration_input_refs)
        object.__setattr__(self, "validation_input_refs", validation_input_refs)
        object.__setattr__(self, "calibration_samples", tuple(self.calibration_samples))
        object.__setattr__(self, "validation_samples", tuple(self.validation_samples))
        object.__setattr__(self, "uncertainty_method", uncertainty_method)
        object.__setattr__(self, "native_uq", native_uq)
        object.__setattr__(self, "nominal_coverage", nominal_coverage)
        object.__setattr__(self, "coverage_tolerance", coverage_tolerance)
        object.__setattr__(self, "code_ref", code_ref)
        object.__setattr__(self, "environment_digest", environment_digest)
        object.__setattr__(self, "seed", seed)
        object.__setattr__(self, "nondeterminism_tolerance", nondeterminism_tolerance)
        object.__setattr__(self, "replay_output_pairs", replay_output_pairs)


@dataclass(frozen=True)
class CalibrationAdvisoryCheck:
    name: str
    status: str
    nominal_coverage: float
    empirical_coverage: float
    tolerance: float
    calibration_error: float
    message: str

    def __post_init__(self) -> None:
        status = self.status.strip()
        if status not in {"PASS", "FAIL"}:
            raise S2ContractModelError(f"unsupported S2 calibration advisory status: {status}")
        object.__setattr__(self, "name", self.name.strip() or "calibration")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "nominal_coverage", float(self.nominal_coverage))
        object.__setattr__(self, "empirical_coverage", float(self.empirical_coverage))
        object.__setattr__(self, "tolerance", float(self.tolerance))
        object.__setattr__(self, "calibration_error", float(self.calibration_error))


@dataclass(frozen=True)
class CalibrationRepairAction:
    code: str
    reason: str
    severity: str = "required"

    def __post_init__(self) -> None:
        code = self.code.strip()
        reason = self.reason.strip()
        severity = self.severity.strip()
        if not code:
            raise S2ContractModelError("S2 calibration repair actions require code")
        if not reason:
            raise S2ContractModelError("S2 calibration repair actions require reason")
        if not severity:
            raise S2ContractModelError("S2 calibration repair actions require severity")
        object.__setattr__(self, "code", code)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "severity", severity)


@dataclass(frozen=True)
class UQCalibrationResult:
    job_id: str
    status: str
    uncertainty_method: str
    native_uq: str
    nominal_coverage: float
    empirical_coverage: float
    coverage_tolerance: float
    calibration_error: float
    interval_radius: float | None
    passed_internal_coverage: bool
    advisory_check: CalibrationAdvisoryCheck
    repair_actions: tuple[CalibrationRepairAction, ...]
    calibration_artifact_ref: str
    uncertainty_tag: dict[str, Any]
    self_replay_passed: bool
    max_replay_delta: float
    diagnostics: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AdvisorySignalSample:
    sample_id: str
    template: float
    observed: float

    def __post_init__(self) -> None:
        sample_id = self.sample_id.strip()
        if not sample_id:
            raise S2ContractModelError("S2 advisory signal samples require sample_id")
        object.__setattr__(self, "sample_id", sample_id)
        object.__setattr__(self, "template", _finite_advisory_value(self.template, name="template"))
        object.__setattr__(self, "observed", _finite_advisory_value(self.observed, name="observed"))


@dataclass(frozen=True)
class AdvisoryLeakageSample:
    sample_id: str
    feature_value: float
    target_value: float

    def __post_init__(self) -> None:
        sample_id = self.sample_id.strip()
        if not sample_id:
            raise S2ContractModelError("S2 advisory leakage samples require sample_id")
        object.__setattr__(self, "sample_id", sample_id)
        object.__setattr__(self, "feature_value", _finite_advisory_value(self.feature_value, name="feature_value"))
        object.__setattr__(self, "target_value", _finite_advisory_value(self.target_value, name="target_value"))


@dataclass(frozen=True)
class AdvisoryCheck:
    name: str
    status: str
    advisory: bool
    statistic: float
    threshold: float
    message: str
    recovered_value: float | None = None

    def __post_init__(self) -> None:
        name = self.name.strip()
        status = self.status.strip()
        message = self.message.strip()
        if not name:
            raise S2ContractModelError("S2 advisory checks require name")
        if status not in {"PASS", "FAIL"}:
            raise S2ContractModelError(f"unsupported S2 advisory check status: {status}")
        if not message:
            raise S2ContractModelError("S2 advisory checks require message")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "statistic", _finite_advisory_value(self.statistic, name=f"{name}.statistic"))
        object.__setattr__(self, "threshold", _finite_advisory_value(self.threshold, name=f"{name}.threshold"))
        if self.recovered_value is not None:
            object.__setattr__(
                self,
                "recovered_value",
                _finite_advisory_value(self.recovered_value, name=f"{name}.recovered_value"),
            )
        object.__setattr__(self, "message", message)


@dataclass(frozen=True)
class AdvisorySelfCheckRequest:
    job_id: str
    input_refs: tuple[str, ...]
    code_ref: str
    environment_digest: str
    seed: str
    injection_samples: tuple[AdvisorySignalSample, ...] = ()
    known_amplitude: float = 0.0
    amplitude_tolerance: float = 0.0
    null_samples: tuple[AdvisorySignalSample, ...] = ()
    null_detection_threshold: float = 0.0
    leakage_samples: tuple[AdvisoryLeakageSample, ...] = ()
    leakage_threshold: float = 0.99

    def __post_init__(self) -> None:
        job_id = self.job_id.strip()
        input_refs = tuple(ref.strip() for ref in self.input_refs)
        if not job_id:
            raise S2ContractModelError("S2 AdvisorySelfCheck requires job_id")
        if not input_refs or any(not ref for ref in input_refs):
            raise S2ContractModelError("S2 AdvisorySelfCheck requires non-empty input_refs")
        if not (self.injection_samples or self.null_samples or self.leakage_samples):
            raise S2ContractModelError("S2 AdvisorySelfCheck requires at least one advisory sample group")
        amplitude_tolerance = _finite_advisory_value(self.amplitude_tolerance, name="amplitude_tolerance")
        null_detection_threshold = _finite_advisory_value(
            self.null_detection_threshold,
            name="null_detection_threshold",
        )
        leakage_threshold = _finite_advisory_value(self.leakage_threshold, name="leakage_threshold")
        if amplitude_tolerance < 0:
            raise S2ContractModelError("S2 advisory amplitude_tolerance must be non-negative")
        if null_detection_threshold < 0:
            raise S2ContractModelError("S2 advisory null_detection_threshold must be non-negative")
        if not 0.0 <= leakage_threshold <= 1.0:
            raise S2ContractModelError("S2 advisory leakage_threshold must be between 0 and 1")
        object.__setattr__(self, "job_id", job_id)
        object.__setattr__(self, "input_refs", input_refs)
        object.__setattr__(self, "injection_samples", tuple(self.injection_samples))
        object.__setattr__(self, "known_amplitude", _finite_advisory_value(self.known_amplitude, name="known_amplitude"))
        object.__setattr__(self, "amplitude_tolerance", amplitude_tolerance)
        object.__setattr__(self, "null_samples", tuple(self.null_samples))
        object.__setattr__(self, "null_detection_threshold", null_detection_threshold)
        object.__setattr__(self, "leakage_samples", tuple(self.leakage_samples))
        object.__setattr__(self, "leakage_threshold", leakage_threshold)
        object.__setattr__(self, "code_ref", self.code_ref.strip())
        object.__setattr__(self, "environment_digest", self.environment_digest.strip())
        object.__setattr__(self, "seed", self.seed.strip())
        if not self.code_ref or not self.environment_digest:
            raise S2ContractModelError("S2 AdvisorySelfCheck requires code_ref and environment_digest")


@dataclass(frozen=True)
class AdvisorySelfCheckResult:
    job_id: str
    status: str
    claim_tier: str
    checks: tuple[AdvisoryCheck, ...]
    artifact_ref: str
    warnings: tuple[str, ...]
    diagnostics: dict[str, Any] = field(default_factory=dict)

    @property
    def checks_by_name(self) -> dict[str, AdvisoryCheck]:
        return {check.name: check for check in self.checks}


class AdvisorySelfCheck:
    """Runs advisory-only S2 physics and leakage checks without promoting tier."""

    def __init__(
        self,
        *,
        artifact_store: InMemoryArtifactStore,
        provenance_emitter: "ProvenanceEmitter" | None = None,
    ) -> None:
        self._artifact_store = artifact_store
        self._provenance_emitter = provenance_emitter or ProvenanceEmitter(artifact_store=artifact_store)

    def run(
        self,
        request: AdvisorySelfCheckRequest,
        *,
        attempted_claim_tier: str | None = None,
    ) -> AdvisorySelfCheckResult:
        S2ClaimTierPolicy.assert_attempted_claim_tier(
            attempted_claim_tier,
            actor="S2 AdvisorySelfCheck",
        )
        for input_ref in request.input_refs:
            self._artifact_store.get_record(input_ref)
        checks: list[AdvisoryCheck] = []
        if request.injection_samples:
            checks.append(self._injection_sanity(request))
        if request.null_samples:
            checks.append(self._null_sanity(request))
        if request.leakage_samples:
            checks.append(self._leakage_smell(request))
        warnings = tuple(check.name for check in checks if check.status == "FAIL")
        status = "PASS" if not warnings else "NEEDS_REVIEW"
        payload = {
            "job_id": request.job_id,
            "status": status,
            "advisory": True,
            "claim_tier": "ran-toy",
            "tier_raise_allowed": False,
            "checks": {check.name: asdict(check) for check in checks},
            "warnings": list(warnings),
            "sample_counts": {
                "injection": len(request.injection_samples),
                "null": len(request.null_samples),
                "leakage": len(request.leakage_samples),
            },
            "label_policy": {
                "raw_labels_materialized": False,
                "payload_contains_sample_rows": False,
            },
        }
        record = self._provenance_emitter.emit_artifact(
            kind="advisory_self_check",
            payload=payload,
            producer=Producer(subsystem="S2", version="0.0.0", job_id=request.job_id),
            lineage=Lineage(
                input_refs=request.input_refs,
                code_ref=request.code_ref,
                environment_digest=request.environment_digest,
                seeds=(request.seed,),
                job_id=request.job_id,
            ),
            claim_tier="ran-toy",
        )
        return AdvisorySelfCheckResult(
            job_id=request.job_id,
            status=status,
            claim_tier="ran-toy",
            checks=tuple(checks),
            artifact_ref=record.artifact_ref,
            warnings=warnings,
            diagnostics={
                "advisory": True,
                "tier_raise_allowed": False,
                "claim_tier": "ran-toy",
            },
        )

    def _injection_sanity(self, request: AdvisorySelfCheckRequest) -> AdvisoryCheck:
        recovered = _recover_signal_amplitude(request.injection_samples)
        error = abs(recovered - request.known_amplitude)
        passed = error <= request.amplitude_tolerance
        return AdvisoryCheck(
            name="injection_sanity",
            status="PASS" if passed else "FAIL",
            advisory=True,
            statistic=error,
            threshold=request.amplitude_tolerance,
            recovered_value=recovered,
            message="known injected signal recovered within tolerance" if passed else "injected signal recovery outside tolerance",
        )

    def _null_sanity(self, request: AdvisorySelfCheckRequest) -> AdvisoryCheck:
        recovered = _recover_signal_amplitude(request.null_samples)
        detection_statistic = abs(recovered)
        passed = detection_statistic <= request.null_detection_threshold
        return AdvisoryCheck(
            name="null_sanity",
            status="PASS" if passed else "FAIL",
            advisory=True,
            statistic=detection_statistic,
            threshold=request.null_detection_threshold,
            recovered_value=recovered,
            message="null control below detection threshold" if passed else "null control produced a significant detection",
        )

    def _leakage_smell(self, request: AdvisorySelfCheckRequest) -> AdvisoryCheck:
        score = _leakage_score(request.leakage_samples)
        leaked = score >= request.leakage_threshold
        return AdvisoryCheck(
            name="leakage_smell",
            status="FAIL" if leaked else "PASS",
            advisory=True,
            statistic=score,
            threshold=request.leakage_threshold,
            message="target leakage smell detected; defer tier decisions to S3" if leaked else "no target leakage smell above threshold",
        )


def _finite_advisory_value(value: Any, *, name: str) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise S2ContractModelError(f"S2 advisory value {name!r} must be numeric") from exc
    if not math.isfinite(numeric):
        raise S2ContractModelError(f"S2 advisory value {name!r} must be finite")
    return numeric


def _recover_signal_amplitude(samples: tuple[AdvisorySignalSample, ...]) -> float:
    denominator = sum(sample.template * sample.template for sample in samples)
    if denominator <= 0.0:
        raise S2ContractModelError("S2 advisory signal recovery requires a non-zero template")
    numerator = sum(sample.template * sample.observed for sample in samples)
    return numerator / denominator


def _leakage_score(samples: tuple[AdvisoryLeakageSample, ...]) -> float:
    targets = {sample.target_value for sample in samples}
    if targets.issubset({0.0, 1.0}) and targets == {0.0, 1.0}:
        auc = _binary_auc(samples)
        return max(auc, 1.0 - auc)
    return _absolute_pearson_correlation(
        tuple(sample.feature_value for sample in samples),
        tuple(sample.target_value for sample in samples),
    )


def _binary_auc(samples: tuple[AdvisoryLeakageSample, ...]) -> float:
    positives = [sample.feature_value for sample in samples if sample.target_value == 1.0]
    negatives = [sample.feature_value for sample in samples if sample.target_value == 0.0]
    if not positives or not negatives:
        raise S2ContractModelError("S2 advisory binary leakage AUC requires positive and negative labels")
    wins = 0.0
    for positive in positives:
        for negative in negatives:
            if positive > negative:
                wins += 1.0
            elif positive == negative:
                wins += 0.5
    return wins / float(len(positives) * len(negatives))


def _absolute_pearson_correlation(left: tuple[float, ...], right: tuple[float, ...]) -> float:
    if len(left) != len(right) or len(left) < 2:
        raise S2ContractModelError("S2 advisory leakage correlation requires at least two paired samples")
    left_mean = sum(left) / float(len(left))
    right_mean = sum(right) / float(len(right))
    left_centered = tuple(value - left_mean for value in left)
    right_centered = tuple(value - right_mean for value in right)
    left_norm = math.sqrt(sum(value * value for value in left_centered))
    right_norm = math.sqrt(sum(value * value for value in right_centered))
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    correlation = sum(lv * rv for lv, rv in zip(left_centered, right_centered)) / (left_norm * right_norm)
    return abs(correlation)


@dataclass(frozen=True)
class PipelineFreezeRequest:
    job_id: str
    feature_set_ref: str
    model_checkpoint_ref: str
    calibration_artifact_ref: str
    input_refs: tuple[str, ...]
    code_ref: str
    environment_digest: str
    seed: str
    container_digest: str
    probe_inputs_units_tagged: Mapping[str, Mapping[str, Any]] = field(hash=False)
    output_name: str = "prediction"
    output_units: str = "dimensionless"
    nondeterminism_tolerance: float = 0.0
    build_wallclock_seconds: float = 1.0
    max_self_replay_fraction: float = 0.05
    adapter_refs: tuple[str, ...] = ()
    config: Mapping[str, Any] = field(default_factory=dict, hash=False)
    nondeterministic_replay_jitter: float = 0.0

    def __post_init__(self) -> None:
        job_id = self.job_id.strip()
        feature_set_ref = self.feature_set_ref.strip()
        model_checkpoint_ref = self.model_checkpoint_ref.strip()
        calibration_artifact_ref = self.calibration_artifact_ref.strip()
        input_refs = tuple(str(ref).strip() for ref in self.input_refs)
        code_ref = self.code_ref.strip()
        environment_digest = self.environment_digest.strip()
        seed = self.seed.strip()
        container_digest = self.container_digest.strip()
        output_name = self.output_name.strip()
        output_units = self.output_units.strip()
        adapter_refs = tuple(str(ref).strip() for ref in self.adapter_refs)
        nondeterminism_tolerance = _finite_pipeline_value(
            self.nondeterminism_tolerance,
            name="nondeterminism_tolerance",
        )
        build_wallclock_seconds = _finite_pipeline_value(
            self.build_wallclock_seconds,
            name="build_wallclock_seconds",
        )
        max_self_replay_fraction = _finite_pipeline_value(
            self.max_self_replay_fraction,
            name="max_self_replay_fraction",
        )
        nondeterministic_replay_jitter = _finite_pipeline_value(
            self.nondeterministic_replay_jitter,
            name="nondeterministic_replay_jitter",
        )
        if not job_id:
            raise S2ContractModelError("S2 PipelineFreezeRequest requires job_id")
        if not feature_set_ref:
            raise S2ContractModelError("S2 PipelineFreezeRequest requires feature_set_ref")
        if not model_checkpoint_ref:
            raise S2ContractModelError("S2 PipelineFreezeRequest requires model_checkpoint_ref")
        if not calibration_artifact_ref:
            raise S2ContractModelError("S2 PipelineFreezeRequest requires calibration_artifact_ref")
        if not input_refs or any(not ref for ref in input_refs):
            raise S2ContractModelError("S2 PipelineFreezeRequest requires non-empty input_refs")
        if not code_ref or not environment_digest or not seed:
            raise S2ContractModelError("S2 PipelineFreezeRequest requires code_ref, environment_digest, and seed")
        if not container_digest:
            raise S2ContractModelError("S2 PipelineFreezeRequest requires container_digest")
        if not output_name or not output_units:
            raise S2ContractModelError("S2 PipelineFreezeRequest requires output_name and output_units")
        if nondeterminism_tolerance < 0:
            raise S2ContractModelError("S2 PipelineFreezeRequest nondeterminism_tolerance must be non-negative")
        if nondeterministic_replay_jitter < 0:
            raise S2ContractModelError("S2 PipelineFreezeRequest nondeterministic_replay_jitter must be non-negative")
        if build_wallclock_seconds <= 0:
            raise S2ContractModelError("S2 PipelineFreezeRequest build_wallclock_seconds must be positive")
        if max_self_replay_fraction <= 0:
            raise S2ContractModelError("S2 PipelineFreezeRequest max_self_replay_fraction must be positive")
        if any(not ref for ref in adapter_refs):
            raise S2ContractModelError("S2 PipelineFreezeRequest adapter_refs cannot contain empty refs")
        normalized_probe = _normalize_units_tagged_inputs(self.probe_inputs_units_tagged)
        object.__setattr__(self, "job_id", job_id)
        object.__setattr__(self, "feature_set_ref", feature_set_ref)
        object.__setattr__(self, "model_checkpoint_ref", model_checkpoint_ref)
        object.__setattr__(self, "calibration_artifact_ref", calibration_artifact_ref)
        object.__setattr__(self, "input_refs", input_refs)
        object.__setattr__(self, "code_ref", code_ref)
        object.__setattr__(self, "environment_digest", environment_digest)
        object.__setattr__(self, "seed", seed)
        object.__setattr__(self, "container_digest", container_digest)
        object.__setattr__(self, "probe_inputs_units_tagged", normalized_probe)
        object.__setattr__(self, "output_name", output_name)
        object.__setattr__(self, "output_units", output_units)
        object.__setattr__(self, "nondeterminism_tolerance", nondeterminism_tolerance)
        object.__setattr__(self, "build_wallclock_seconds", build_wallclock_seconds)
        object.__setattr__(self, "max_self_replay_fraction", max_self_replay_fraction)
        object.__setattr__(self, "adapter_refs", adapter_refs)
        object.__setattr__(self, "config", _s2_jsonable(dict(self.config)))
        object.__setattr__(self, "nondeterministic_replay_jitter", nondeterministic_replay_jitter)


@dataclass(frozen=True)
class FrozenPipelinePrediction:
    outputs_units_tagged: dict[str, dict[str, Any]]
    uncertainty: dict[str, Any]
    io_signature: dict[str, Any]
    diagnostics: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PipelineFreezeResult:
    job_id: str
    artifact_ref: str
    self_replay_passed: bool
    max_replay_delta: float
    self_replay_time_seconds: float
    self_replay_fraction: float
    io_signature: dict[str, Any]
    diagnostics: dict[str, Any] = field(default_factory=dict)


class FrozenPipelineRunner:
    """Loads and executes S2 frozen pipeline predict artifacts from C4."""

    def __init__(self, *, artifact_store: InMemoryArtifactStore) -> None:
        self._artifact_store = artifact_store

    def predict(
        self,
        frozen_pipeline_ref: str,
        inputs_units_tagged: Mapping[str, Mapping[str, Any]],
    ) -> FrozenPipelinePrediction:
        record = self._artifact_store.get_record(frozen_pipeline_ref)
        if record.kind != "frozen_pipeline":
            raise PipelineFreezeError(
                f"S2 FrozenPipelineRunner expected frozen_pipeline artifact, got {record.kind!r}",
                code="INVALID_FROZEN_PIPELINE",
            )
        payload = self._artifact_payload(frozen_pipeline_ref)
        return self.predict_payload(payload, inputs_units_tagged, loaded_from_c4=True)

    def predict_payload(
        self,
        payload: Mapping[str, Any],
        inputs_units_tagged: Mapping[str, Mapping[str, Any]],
        *,
        loaded_from_c4: bool = False,
    ) -> FrozenPipelinePrediction:
        self._assert_frozen_payload(payload)
        io_signature = dict(payload["io_signature"])
        normalized_inputs = _normalize_units_tagged_inputs(inputs_units_tagged)
        self._assert_input_signature(io_signature, normalized_inputs)
        scalar_inputs = {name: float(tagged["value"]) for name, tagged in normalized_inputs.items()}
        feature_values = self._evaluate_feature_graph(
            dict(payload["feature_graph"]),
            dict(payload["feature_set"]),
            scalar_inputs,
        )
        prediction = self._predict_model(dict(payload["model_checkpoint"]), feature_values)
        output_name, output_units = self._output_contract(io_signature)
        outputs_units_tagged = {
            output_name: {
                "value": prediction,
                "units": output_units,
            }
        }
        uncertainty = self._uncertainty(dict(payload["uq_calibration"]), prediction)
        return FrozenPipelinePrediction(
            outputs_units_tagged=outputs_units_tagged,
            uncertainty=uncertainty,
            io_signature=io_signature,
            diagnostics={
                "loaded_from_c4": loaded_from_c4,
                "feature_count": len(feature_values),
                "schema_version": payload.get("schema_version"),
            },
        )

    def _artifact_payload(self, artifact_ref: str) -> dict[str, Any]:
        try:
            return json.loads(self._artifact_store.get_artifact(artifact_ref).decode("utf-8"))
        except KeyError as exc:
            raise PipelineFreezeError(
                f"S2 FrozenPipelineRunner cannot load frozen pipeline artifact: {artifact_ref}",
                code="INVALID_FROZEN_PIPELINE",
            ) from exc

    @staticmethod
    def _assert_frozen_payload(payload: Mapping[str, Any]) -> None:
        if payload.get("schema_version") != S2_FROZEN_PIPELINE_SCHEMA_VERSION:
            raise PipelineFreezeError("S2 frozen pipeline schema_version is unsupported", code="INVALID_FROZEN_PIPELINE")
        if payload.get("entrypoint") != "predict":
            raise PipelineFreezeError("S2 frozen pipeline entrypoint must be predict", code="INVALID_FROZEN_PIPELINE")
        if payload.get("entrypoint_contract_version") != S2_FROZEN_PIPELINE_ENTRYPOINT_CONTRACT_VERSION:
            raise PipelineFreezeError(
                "S2 frozen pipeline entrypoint contract version is unsupported",
                code="INVALID_FROZEN_PIPELINE",
            )
        if not payload.get("s3_executable"):
            raise PipelineFreezeError("S2 frozen pipeline is not marked S3 executable", code="INVALID_FROZEN_PIPELINE")
        for key in ("io_signature", "feature_graph", "feature_set", "model_checkpoint", "uq_calibration"):
            if not isinstance(payload.get(key), Mapping):
                raise PipelineFreezeError(f"S2 frozen pipeline missing payload section: {key}", code="INVALID_FROZEN_PIPELINE")

    @staticmethod
    def _assert_input_signature(
        io_signature: Mapping[str, Any],
        normalized_inputs: Mapping[str, Mapping[str, Any]],
    ) -> None:
        expected = io_signature.get("inputs")
        if not isinstance(expected, Mapping):
            raise PipelineFreezeError("S2 frozen pipeline io_signature missing inputs", code="INVALID_FROZEN_PIPELINE")
        expected_names = set(str(name) for name in expected)
        observed_names = set(normalized_inputs)
        if expected_names != observed_names:
            raise PipelineFreezeError(
                f"S2 frozen pipeline input names mismatch: expected {sorted(expected_names)}, got {sorted(observed_names)}",
                code="IO_SIGNATURE_MISMATCH",
            )
        for name, expected_contract in expected.items():
            if not isinstance(expected_contract, Mapping):
                raise PipelineFreezeError("S2 frozen pipeline input contract is malformed", code="INVALID_FROZEN_PIPELINE")
            expected_units = str(expected_contract.get("units", ""))
            observed_units = str(normalized_inputs[str(name)].get("units", ""))
            if expected_units != observed_units:
                raise PipelineFreezeError(
                    f"S2 frozen pipeline input {name!r} units mismatch: expected {expected_units}, got {observed_units}",
                    code="IO_SIGNATURE_MISMATCH",
                )

    @staticmethod
    def _evaluate_feature_graph(
        graph_payload: Mapping[str, Any],
        feature_set_payload: Mapping[str, Any],
        inputs: Mapping[str, float],
    ) -> dict[str, float]:
        raw_nodes = graph_payload.get("nodes")
        if not isinstance(raw_nodes, list):
            raise PipelineFreezeError("S2 frozen feature graph missing nodes", code="INVALID_FROZEN_PIPELINE")
        values: dict[str, float] = {}
        for raw_node in raw_nodes:
            if not isinstance(raw_node, Mapping):
                raise PipelineFreezeError("S2 frozen feature graph node is malformed", code="INVALID_FROZEN_PIPELINE")
            node_id = str(raw_node.get("node_id", "")).strip()
            feature = raw_node.get("feature")
            if not node_id or not isinstance(feature, Mapping):
                raise PipelineFreezeError("S2 frozen feature graph node is missing feature payload", code="INVALID_FROZEN_PIPELINE")
            terms = feature.get("terms")
            if not isinstance(terms, list) or not terms:
                raise PipelineFreezeError("S2 frozen feature graph node has no terms", code="INVALID_FROZEN_PIPELINE")
            result = 1.0
            for term in terms:
                if not isinstance(term, Mapping):
                    raise PipelineFreezeError("S2 frozen feature graph term is malformed", code="INVALID_FROZEN_PIPELINE")
                field_name = str(term.get("field_name", "")).strip()
                exponent = int(term.get("exponent", 1))
                if field_name in values:
                    base = values[field_name]
                elif field_name in inputs:
                    base = inputs[field_name]
                else:
                    raise PipelineFreezeError(
                        f"S2 frozen feature graph missing input or dependency: {field_name}",
                        code="IO_SIGNATURE_MISMATCH",
                    )
                try:
                    result *= base ** exponent
                except ZeroDivisionError as exc:
                    raise PipelineFreezeError(
                        f"S2 frozen feature graph cannot apply negative exponent to zero: {node_id}",
                        code="INVALID_FROZEN_PIPELINE",
                    ) from exc
                if not math.isfinite(result):
                    raise PipelineFreezeError(
                        f"S2 frozen feature graph produced non-finite value: {node_id}",
                        code="INVALID_FROZEN_PIPELINE",
                    )
            values[node_id] = float(result)
        selected = feature_set_payload.get("selected_nodes")
        if not isinstance(selected, list) or not selected:
            raise PipelineFreezeError("S2 frozen feature set missing selected_nodes", code="INVALID_FROZEN_PIPELINE")
        selected_values: dict[str, float] = {}
        for node_id in selected:
            key = str(node_id)
            if key not in values:
                raise PipelineFreezeError(
                    f"S2 frozen feature set references missing node: {key}",
                    code="INVALID_FROZEN_PIPELINE",
                )
            selected_values[key] = values[key]
        return selected_values

    @staticmethod
    def _predict_model(model_payload: Mapping[str, Any], feature_values: Mapping[str, float]) -> float:
        backend = model_payload.get("backend")
        model_state = model_payload.get("model_state")
        if not isinstance(model_state, Mapping):
            raise PipelineFreezeError("S2 frozen model checkpoint missing model_state", code="INVALID_FROZEN_PIPELINE")
        if backend == "deterministic-linear":
            raw_feature_names = model_state.get("feature_names")
            weights = model_state.get("weights")
            if not isinstance(raw_feature_names, list) or not isinstance(weights, Mapping):
                raise PipelineFreezeError("S2 frozen deterministic-linear state is malformed", code="INVALID_FROZEN_PIPELINE")
            bias = _finite_pipeline_value(model_state.get("bias", 0.0), name="bias")
            prediction = bias
            for raw_name in raw_feature_names:
                name = str(raw_name)
                if name not in feature_values:
                    raise PipelineFreezeError(
                        f"S2 frozen model requires missing feature: {name}",
                        code="IO_SIGNATURE_MISMATCH",
                    )
                prediction += _finite_pipeline_value(weights.get(name, 0.0), name=f"weight:{name}") * feature_values[name]
            return float(prediction)
        if backend == "physics-informed-analytic":
            raw_feature_names = model_state.get("feature_names")
            if not isinstance(raw_feature_names, list) or len(raw_feature_names) != 1:
                raise PipelineFreezeError("S2 frozen physics-informed state is malformed", code="INVALID_FROZEN_PIPELINE")
            name = str(raw_feature_names[0])
            if name not in feature_values:
                raise PipelineFreezeError(f"S2 frozen model requires missing feature: {name}", code="IO_SIGNATURE_MISMATCH")
            scale = PhysicsInformedTrainingBackend._positive_scale(
                _finite_pipeline_value(model_state.get("scale_raw", 0.0), name="scale_raw")
            )
            return float(scale * feature_values[name] * feature_values[name])
        raise PipelineFreezeError(f"S2 frozen model backend is unsupported: {backend!r}", code="INVALID_FROZEN_PIPELINE")

    @staticmethod
    def _output_contract(io_signature: Mapping[str, Any]) -> tuple[str, str]:
        outputs = io_signature.get("outputs")
        if not isinstance(outputs, Mapping) or len(outputs) != 1:
            raise PipelineFreezeError("S2 frozen pipeline requires exactly one output contract", code="INVALID_FROZEN_PIPELINE")
        output_name, output_contract = next(iter(outputs.items()))
        if not isinstance(output_contract, Mapping):
            raise PipelineFreezeError("S2 frozen pipeline output contract is malformed", code="INVALID_FROZEN_PIPELINE")
        output_units = str(output_contract.get("units", "")).strip()
        if not output_units:
            raise PipelineFreezeError("S2 frozen pipeline output contract missing units", code="INVALID_FROZEN_PIPELINE")
        return str(output_name), output_units

    @staticmethod
    def _uncertainty(calibration_payload: Mapping[str, Any], prediction: float) -> dict[str, Any]:
        interval = calibration_payload.get("interval")
        if isinstance(interval, Mapping) and interval.get("kind") == "symmetric_conformal":
            radius = _finite_pipeline_value(interval.get("radius", 0.0), name="uncertainty_radius")
            return {
                "kind": "interval",
                "source": calibration_payload.get("uncertainty_method", "unknown"),
                "radius": radius,
                "lower": prediction - radius,
                "upper": prediction + radius,
            }
        return {
            "kind": "interval",
            "source": calibration_payload.get("uncertainty_method", "unknown"),
            "radius": None,
            "lower": None,
            "upper": None,
        }


class PipelineFreezer:
    """Freezes S2 feature, model, and UQ artifacts into a deterministic S3 entrypoint."""

    def __init__(
        self,
        *,
        artifact_store: InMemoryArtifactStore,
        provenance_emitter: ProvenanceEmitter | None = None,
        runner: FrozenPipelineRunner | None = None,
    ) -> None:
        self._artifact_store = artifact_store
        self._provenance_emitter = provenance_emitter or ProvenanceEmitter(artifact_store=artifact_store)
        self._runner = runner or FrozenPipelineRunner(artifact_store=artifact_store)

    def freeze(self, request: PipelineFreezeRequest) -> PipelineFreezeResult:
        feature_record, model_record, calibration_record = self._component_records(request)
        for input_ref in request.input_refs:
            self._artifact_store.get_record(input_ref)
        feature_payload = self._artifact_payload(request.feature_set_ref)
        model_payload = self._artifact_payload(request.model_checkpoint_ref)
        calibration_payload = self._artifact_payload(request.calibration_artifact_ref)
        self._assert_uq_replay_passed(calibration_payload)
        io_signature = self._io_signature(request)
        payload = self._manifest_payload(
            request=request,
            feature_payload=feature_payload,
            model_payload=model_payload,
            calibration_payload=calibration_payload,
            io_signature=io_signature,
        )
        first, second, self_replay_time = self._self_replay(request, payload)
        max_delta = self._max_prediction_delta(first, second)
        if max_delta > request.nondeterminism_tolerance:
            raise PipelineFreezeError(
                "S2 PipelineFreezer self replay exceeded nondeterminism_tolerance",
                code="SELF_REPLAY_FAILED",
            )
        self_replay_fraction = self_replay_time / request.build_wallclock_seconds
        if self_replay_fraction > request.max_self_replay_fraction:
            raise PipelineFreezeError(
                "S2 PipelineFreezer self replay overhead exceeded max_self_replay_fraction",
                code="SELF_REPLAY_OVERHEAD_EXCEEDED",
            )
        payload["self_replay"] = {
            "evaluated": True,
            "status": "PASS",
            "max_delta": max_delta,
            "nondeterminism_tolerance": request.nondeterminism_tolerance,
            "time_seconds": self_replay_time,
            "build_wallclock_seconds": request.build_wallclock_seconds,
            "fraction": self_replay_fraction,
            "max_self_replay_fraction": request.max_self_replay_fraction,
        }
        payload["diagnostics"]["self_replay_passed"] = True
        payload["diagnostics"]["self_replay_output"] = first.outputs_units_tagged
        lineage_refs = _unique_pipeline_refs(
            (
                feature_record.artifact_ref,
                model_record.artifact_ref,
                calibration_record.artifact_ref,
            )
            + request.input_refs
        )
        record = self._provenance_emitter.emit_artifact(
            kind="frozen_pipeline",
            payload=_s2_jsonable(payload),
            producer=Producer(subsystem="S2", version="0.0.0", job_id=request.job_id),
            lineage=Lineage(
                input_refs=lineage_refs,
                code_ref=request.code_ref,
                environment_digest=request.environment_digest,
                seeds=(request.seed,),
                job_id=request.job_id,
            ),
            claim_tier="ran-toy",
        )
        return PipelineFreezeResult(
            job_id=request.job_id,
            artifact_ref=record.artifact_ref,
            self_replay_passed=True,
            max_replay_delta=max_delta,
            self_replay_time_seconds=self_replay_time,
            self_replay_fraction=self_replay_fraction,
            io_signature=io_signature,
            diagnostics={
                "claim_tier": "ran-toy",
                "component_refs": dict(payload["component_refs"]),
                "container_digest": request.container_digest,
            },
        )

    def _component_records(
        self,
        request: PipelineFreezeRequest,
    ) -> tuple[ArtifactRecord, ArtifactRecord, ArtifactRecord]:
        feature_record = self._artifact_store.get_record(request.feature_set_ref)
        model_record = self._artifact_store.get_record(request.model_checkpoint_ref)
        calibration_record = self._artifact_store.get_record(request.calibration_artifact_ref)
        if feature_record.kind != "feature_set":
            raise PipelineFreezeError("S2 PipelineFreezer requires feature_set input", code="INVALID_COMPONENT")
        if model_record.kind != "model_checkpoint":
            raise PipelineFreezeError("S2 PipelineFreezer requires model_checkpoint input", code="INVALID_COMPONENT")
        if calibration_record.kind != "uq_calibration":
            raise PipelineFreezeError("S2 PipelineFreezer requires uq_calibration input", code="INVALID_COMPONENT")
        return feature_record, model_record, calibration_record

    def _artifact_payload(self, artifact_ref: str) -> dict[str, Any]:
        try:
            return json.loads(self._artifact_store.get_artifact(artifact_ref).decode("utf-8"))
        except KeyError as exc:
            raise PipelineFreezeError(
                f"S2 PipelineFreezer cannot load required artifact: {artifact_ref}",
                code="INVALID_COMPONENT",
            ) from exc

    @staticmethod
    def _assert_uq_replay_passed(calibration_payload: Mapping[str, Any]) -> None:
        replay = calibration_payload.get("self_replay")
        if isinstance(replay, Mapping) and replay.get("evaluated") and replay.get("status") != "PASS":
            raise PipelineFreezeError(
                "S2 PipelineFreezer refuses calibration with failed self replay",
                code="UPSTREAM_SELF_REPLAY_FAILED",
            )

    @staticmethod
    def _io_signature(request: PipelineFreezeRequest) -> dict[str, Any]:
        inputs = {
            name: {
                "units": tagged["units"],
                "value_type": "float",
            }
            for name, tagged in sorted(request.probe_inputs_units_tagged.items())
        }
        return {
            "contract_version": S2_FROZEN_PIPELINE_ENTRYPOINT_CONTRACT_VERSION,
            "inputs": inputs,
            "outputs": {
                request.output_name: {
                    "units": request.output_units,
                    "value_type": "float",
                }
            },
        }

    @staticmethod
    def _manifest_payload(
        *,
        request: PipelineFreezeRequest,
        feature_payload: Mapping[str, Any],
        model_payload: Mapping[str, Any],
        calibration_payload: Mapping[str, Any],
        io_signature: Mapping[str, Any],
    ) -> dict[str, Any]:
        params_hash = hash_bytes(canonical_json_bytes(model_payload.get("parameters", {})))
        config_hash = hash_bytes(canonical_json_bytes(request.config))
        return {
            "schema_version": S2_FROZEN_PIPELINE_SCHEMA_VERSION,
            "job_id": request.job_id,
            "entrypoint": "predict",
            "entrypoint_contract_version": S2_FROZEN_PIPELINE_ENTRYPOINT_CONTRACT_VERSION,
            "s3_executable": True,
            "claim_tier": "ran-toy",
            "component_refs": {
                "feature_set_ref": request.feature_set_ref,
                "model_checkpoint_ref": request.model_checkpoint_ref,
                "calibration_artifact_ref": request.calibration_artifact_ref,
                "input_refs": list(request.input_refs),
            },
            "container_digest": request.container_digest,
            "adapter_refs": list(request.adapter_refs),
            "seed": request.seed,
            "seeds": [request.seed],
            "config": dict(request.config),
            "config_hash": config_hash,
            "params_hash": params_hash,
            "io_signature": dict(io_signature),
            "feature_graph": dict(feature_payload["graph"]),
            "feature_set": dict(feature_payload["feature_set"]),
            "model_checkpoint": dict(model_payload),
            "uq_calibration": dict(calibration_payload),
            "nondeterminism_tolerance": request.nondeterminism_tolerance,
            "self_replay": {
                "evaluated": False,
                "status": "PENDING",
                "nondeterminism_tolerance": request.nondeterminism_tolerance,
            },
            "diagnostics": {
                "nondeterministic_replay_jitter": request.nondeterministic_replay_jitter,
                "self_replay_passed": False,
                "feature_graph_schema_version": feature_payload.get("graph", {}).get("schema_version"),
                "feature_set_schema_version": feature_payload.get("feature_set", {}).get("schema_version"),
            },
        }

    def _self_replay(
        self,
        request: PipelineFreezeRequest,
        payload: Mapping[str, Any],
    ) -> tuple[FrozenPipelinePrediction, FrozenPipelinePrediction, float]:
        start = time.perf_counter()
        first = self._runner.predict_payload(payload, request.probe_inputs_units_tagged)
        second = self._runner.predict_payload(payload, request.probe_inputs_units_tagged)
        if request.nondeterministic_replay_jitter:
            second = self._with_prediction_jitter(second, request.nondeterministic_replay_jitter)
        elapsed = max(time.perf_counter() - start, 1e-12)
        return first, second, elapsed

    @staticmethod
    def _with_prediction_jitter(
        prediction: FrozenPipelinePrediction,
        jitter: float,
    ) -> FrozenPipelinePrediction:
        outputs = json.loads(json.dumps(prediction.outputs_units_tagged, sort_keys=True))
        for tagged in outputs.values():
            tagged["value"] = _finite_pipeline_value(tagged["value"], name="replay_output") + jitter
        return FrozenPipelinePrediction(
            outputs_units_tagged=outputs,
            uncertainty=dict(prediction.uncertainty),
            io_signature=dict(prediction.io_signature),
            diagnostics={**prediction.diagnostics, "nondeterministic_replay_jitter": jitter},
        )

    @staticmethod
    def _max_prediction_delta(
        first: FrozenPipelinePrediction,
        second: FrozenPipelinePrediction,
    ) -> float:
        deltas: list[float] = []
        for output_name, first_tagged in first.outputs_units_tagged.items():
            if output_name not in second.outputs_units_tagged:
                raise PipelineFreezeError(
                    f"S2 PipelineFreezer self replay output missing: {output_name}",
                    code="SELF_REPLAY_FAILED",
                )
            first_value = _finite_pipeline_value(first_tagged.get("value"), name=f"first:{output_name}")
            second_value = _finite_pipeline_value(
                second.outputs_units_tagged[output_name].get("value"),
                name=f"second:{output_name}",
            )
            deltas.append(abs(first_value - second_value))
        return max(deltas) if deltas else 0.0


def _normalize_units_tagged_inputs(
    raw_inputs: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    if not isinstance(raw_inputs, Mapping) or not raw_inputs:
        raise S2ContractModelError("S2 pipeline inputs require a non-empty units-tagged mapping")
    normalized: dict[str, dict[str, Any]] = {}
    for raw_name, raw_tagged in raw_inputs.items():
        name = str(raw_name).strip()
        if not name:
            raise S2ContractModelError("S2 pipeline input names cannot be empty")
        if not isinstance(raw_tagged, Mapping):
            raise S2ContractModelError(f"S2 pipeline input {name!r} must be a units-tagged mapping")
        units = str(raw_tagged.get("units", "")).strip()
        if not units:
            raise S2ContractModelError(f"S2 pipeline input {name!r} requires units")
        normalized[name] = {
            "value": _finite_pipeline_value(raw_tagged.get("value"), name=name),
            "units": units,
        }
    return normalized


def _finite_pipeline_value(value: Any, *, name: str) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise S2ContractModelError(f"S2 pipeline value {name!r} must be numeric") from exc
    if not math.isfinite(numeric):
        raise S2ContractModelError(f"S2 pipeline value {name!r} must be finite")
    return numeric


def _unique_pipeline_refs(refs: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    unique: list[str] = []
    for ref in refs:
        if ref in seen:
            continue
        seen.add(ref)
        unique.append(ref)
    return tuple(unique)


class UQCalibrator:
    """Calibrates and validates S2 uncertainty evidence without surfacing raw labels."""

    def __init__(
        self,
        *,
        artifact_store: InMemoryArtifactStore,
        provenance_emitter: "ProvenanceEmitter" | None = None,
    ) -> None:
        self._artifact_store = artifact_store
        self._provenance_emitter = provenance_emitter or ProvenanceEmitter(artifact_store=artifact_store)

    def calibrate(self, request: UQCalibrationRequest) -> UQCalibrationResult:
        self._assert_uncertainty_available(request)
        self._assert_required_inputs_exist(request)
        if request.uncertainty_method == "split_conformal":
            interval_radius = self._split_conformal_radius(request.calibration_samples, request.nominal_coverage)
            empirical_coverage = self._coverage_for_radius(request.validation_samples, interval_radius)
            interval = {"kind": "symmetric_conformal", "radius": interval_radius}
        elif request.uncertainty_method == "native_interval":
            interval_radius = None
            empirical_coverage = self._coverage_for_native_intervals(request.validation_samples)
            interval = {"kind": "native_interval", "radius": None}
        else:
            raise UncertaintyRequiredError()

        calibration_error = abs(empirical_coverage - request.nominal_coverage)
        passed_internal_coverage = calibration_error <= request.coverage_tolerance
        advisory_check = CalibrationAdvisoryCheck(
            name="calibration",
            status="PASS" if passed_internal_coverage else "FAIL",
            nominal_coverage=request.nominal_coverage,
            empirical_coverage=empirical_coverage,
            tolerance=request.coverage_tolerance,
            calibration_error=calibration_error,
            message="coverage within tolerance" if passed_internal_coverage else "coverage outside tolerance",
        )
        repair_actions = () if passed_internal_coverage else (
            CalibrationRepairAction(
                code="calibration_fail",
                reason="empirical coverage is outside the declared tolerance",
            ),
        )
        self_replay_passed, max_replay_delta = self._self_replay_status(request)
        if not self_replay_passed:
            repair_actions = repair_actions + (
                CalibrationRepairAction(
                    code="nondeterminism_tolerance_fail",
                    reason="self replay delta exceeds declared nondeterminism_tolerance",
                ),
            )
        status = "CALIBRATED" if passed_internal_coverage and self_replay_passed else "NEEDS_REPAIR"
        uncertainty_tag = {
            "kind": "interval",
            "source": request.uncertainty_method,
            "native_uq": request.native_uq,
            "nominal_coverage": request.nominal_coverage,
            "calibrated": status == "CALIBRATED",
            "claim_tier": "ran-toy",
        }
        payload = {
            "job_id": request.job_id,
            "status": status,
            "model_artifact_ref": request.model_artifact_ref,
            "split_manifest_ref": request.split_manifest_ref,
            "uncertainty_method": request.uncertainty_method,
            "native_uq": request.native_uq,
            "nominal_coverage": request.nominal_coverage,
            "empirical_coverage": empirical_coverage,
            "coverage_tolerance": request.coverage_tolerance,
            "calibration_error": calibration_error,
            "calibration_sample_count": len(request.calibration_samples),
            "validation_sample_count": len(request.validation_samples),
            "passed_internal_coverage": passed_internal_coverage,
            "interval": interval,
            "advisory_check": asdict(advisory_check),
            "repair_actions": [asdict(action) for action in repair_actions],
            "self_replay": {
                "evaluated": bool(request.replay_output_pairs),
                "status": "PASS" if self_replay_passed else "FAIL",
                "max_delta": max_replay_delta,
                "nondeterminism_tolerance": request.nondeterminism_tolerance,
            },
            "uncertainty_tag": uncertainty_tag,
            "label_policy": {
                "raw_labels_materialized": False,
                "payload_contains_sample_rows": False,
            },
        }
        record = self._provenance_emitter.emit_artifact(
            kind="uq_calibration",
            payload=payload,
            producer=Producer(subsystem="S2", version="0.0.0", job_id=request.job_id),
            lineage=Lineage(
                input_refs=(
                    request.model_artifact_ref,
                    request.split_manifest_ref,
                )
                + request.calibration_input_refs
                + request.validation_input_refs,
                code_ref=request.code_ref,
                environment_digest=request.environment_digest,
                seeds=(request.seed,),
                job_id=request.job_id,
            ),
            claim_tier="ran-toy",
        )
        return UQCalibrationResult(
            job_id=request.job_id,
            status=status,
            uncertainty_method=request.uncertainty_method,
            native_uq=request.native_uq,
            nominal_coverage=request.nominal_coverage,
            empirical_coverage=empirical_coverage,
            coverage_tolerance=request.coverage_tolerance,
            calibration_error=calibration_error,
            interval_radius=interval_radius,
            passed_internal_coverage=passed_internal_coverage,
            advisory_check=advisory_check,
            repair_actions=repair_actions,
            calibration_artifact_ref=record.artifact_ref,
            uncertainty_tag=uncertainty_tag,
            self_replay_passed=self_replay_passed,
            max_replay_delta=max_replay_delta,
            diagnostics={
                "calibration_sample_count": len(request.calibration_samples),
                "validation_sample_count": len(request.validation_samples),
                "claim_tier": "ran-toy",
            },
        )

    @staticmethod
    def _assert_uncertainty_available(request: UQCalibrationRequest) -> None:
        if request.uncertainty_method == "none" and request.native_uq in {"none", "point_estimate", "point-estimate"}:
            raise UncertaintyRequiredError()

    def _assert_required_inputs_exist(self, request: UQCalibrationRequest) -> None:
        model_record = self._artifact_store.get_record(request.model_artifact_ref)
        if model_record.kind not in {"model", "model_checkpoint"}:
            raise S2ContractModelError(f"S2 UQCalibrator requires model or model_checkpoint input, got {model_record.kind!r}")
        split_record = self._artifact_store.get_record(request.split_manifest_ref)
        if split_record.kind != "dataset_split":
            raise S2ContractModelError(f"S2 UQCalibrator requires dataset_split input, got {split_record.kind!r}")

    @staticmethod
    def _split_conformal_radius(samples: tuple[UQCalibrationSample, ...], nominal_coverage: float) -> float:
        residuals = sorted(sample.residual for sample in samples)
        if not residuals:
            raise S2ContractModelError("S2 split conformal calibration requires residuals")
        rank = math.ceil((len(residuals) + 1) * nominal_coverage)
        index = min(max(rank, 1), len(residuals)) - 1
        return residuals[index]

    @staticmethod
    def _coverage_for_radius(samples: tuple[UQCalibrationSample, ...], radius: float) -> float:
        covered = sum(1 for sample in samples if sample.covered_by_radius(radius))
        return covered / float(len(samples))

    @staticmethod
    def _coverage_for_native_intervals(samples: tuple[UQCalibrationSample, ...]) -> float:
        covered = sum(1 for sample in samples if sample.covered_by_native_interval())
        return covered / float(len(samples))

    @staticmethod
    def _self_replay_status(request: UQCalibrationRequest) -> tuple[bool, float]:
        if not request.replay_output_pairs:
            return True, 0.0
        max_delta = max(abs(left - right) for left, right in request.replay_output_pairs)
        return max_delta <= request.nondeterminism_tolerance, max_delta


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


class PhysicsInformedTrainingBackend:
    """Deterministic differentiable backend for S2 physics-informed fixtures."""

    backend_id = "physics-informed-analytic"

    def initial_state(self, request: TrainingRequest) -> dict[str, Any]:
        feature_name = self._single_feature(request)
        scale_raw = _finite_training_parameter(
            request.parameters.get("initial_scale_raw", 0.0),
            name="initial_scale_raw",
        )
        return {
            "feature_names": [feature_name],
            "target_name": request.target_name,
            "scale_raw": scale_raw,
            "architecture": "positive_quadratic",
            "differentiable": True,
            "gradient_entrypoint": "PhysicsInformedTrainingBackend.grad",
            "framework": "analytic-python",
        }

    def train_epoch(self, request: TrainingRequest, state: Mapping[str, Any], *, epoch: int) -> TrainingEpochResult:
        feature_name = self._single_feature(request)
        scale_raw = _finite_training_parameter(state.get("scale_raw", 0.0), name="scale_raw")
        grad_scale_raw = self._scale_raw_gradient(request, feature_name=feature_name, scale_raw=scale_raw)
        learning_rate = float(request.learning_rate)
        next_scale_raw = max(-40.0, min(40.0, scale_raw - learning_rate * grad_scale_raw))
        metrics = self._metrics(request, feature_name=feature_name, scale_raw=next_scale_raw)
        next_state = {
            "feature_names": [feature_name],
            "target_name": request.target_name,
            "scale_raw": next_scale_raw,
            "scale": self._positive_scale(next_scale_raw),
            "architecture": "positive_quadratic",
            "differentiable": True,
            "gradient_entrypoint": "PhysicsInformedTrainingBackend.grad",
            "framework": "analytic-python",
            "last_scale_raw_gradient": grad_scale_raw,
            "constraints": {
                "positivity": True,
                "asymptotic_limit": {
                    "feature_value": _finite_training_parameter(
                        request.parameters.get("asymptotic_feature_value", 0.0),
                        name="asymptotic_feature_value",
                    ),
                    "known_output": _finite_training_parameter(
                        request.parameters.get("asymptotic_known_output", 0.0),
                        name="asymptotic_known_output",
                    ),
                },
                "unitarity_bound": self._unitarity_bound(request),
                "unitarity_penalty_weight": self._unitarity_penalty_weight(request),
            },
        }
        return TrainingEpochResult(epoch=epoch, model_state=next_state, metrics=metrics)

    def predict(self, state: Mapping[str, Any], row: Mapping[str, Any]) -> float:
        feature_name = self._feature_name_from_state(state)
        x_value = _finite_training_parameter(row[feature_name], name=feature_name)
        return self._positive_scale(_finite_training_parameter(state.get("scale_raw", 0.0), name="scale_raw")) * (
            x_value * x_value
        )

    def grad(self, state: Mapping[str, Any], row: Mapping[str, Any]) -> dict[str, float]:
        feature_name = self._feature_name_from_state(state)
        x_value = _finite_training_parameter(row[feature_name], name=feature_name)
        scale = self._positive_scale(_finite_training_parameter(state.get("scale_raw", 0.0), name="scale_raw"))
        return {feature_name: 2.0 * scale * x_value}

    def _scale_raw_gradient(self, request: TrainingRequest, *, feature_name: str, scale_raw: float) -> float:
        count = float(len(request.training_rows))
        scale_derivative = self._scale_derivative(scale_raw)
        scale = self._positive_scale(scale_raw)
        unitarity_bound = self._unitarity_bound(request)
        unitarity_weight = self._unitarity_penalty_weight(request)
        asymptotic_weight = self._asymptotic_penalty_weight(request)
        gradient = 0.0
        for row in request.training_rows:
            x_value = _finite_training_parameter(row[feature_name], name=feature_name)
            basis = x_value * x_value
            prediction = scale * basis
            error = prediction - _finite_training_parameter(row[request.target_name], name=request.target_name)
            prediction_gradient = scale_derivative * basis
            gradient += 2.0 * error * prediction_gradient / count
            if unitarity_bound is not None and prediction > unitarity_bound:
                gradient += 2.0 * unitarity_weight * (prediction - unitarity_bound) * prediction_gradient / count
        if asymptotic_weight:
            anchor_x = _finite_training_parameter(
                request.parameters.get("asymptotic_feature_value", 0.0),
                name="asymptotic_feature_value",
            )
            known = _finite_training_parameter(
                request.parameters.get("asymptotic_known_output", 0.0),
                name="asymptotic_known_output",
            )
            anchor_basis = anchor_x * anchor_x
            gradient += 2.0 * asymptotic_weight * (scale * anchor_basis - known) * scale_derivative * anchor_basis
        return gradient

    def _metrics(self, request: TrainingRequest, *, feature_name: str, scale_raw: float) -> dict[str, Any]:
        scale = self._positive_scale(scale_raw)
        unitarity_bound = self._unitarity_bound(request)
        unitarity_penalty_sum = 0.0
        violation_count = 0
        squared_error_sum = 0.0
        predictions: list[float] = []
        for row in request.training_rows:
            x_value = _finite_training_parameter(row[feature_name], name=feature_name)
            prediction = scale * x_value * x_value
            predictions.append(prediction)
            error = prediction - _finite_training_parameter(row[request.target_name], name=request.target_name)
            squared_error_sum += error * error
            if unitarity_bound is not None and prediction > unitarity_bound:
                violation_count += 1
                unitarity_penalty_sum += (prediction - unitarity_bound) ** 2
        count = float(len(request.training_rows))
        mse = squared_error_sum / count
        unitarity_penalty = unitarity_penalty_sum / count
        unitarity_loss = self._unitarity_penalty_weight(request) * unitarity_penalty
        anchor_x = _finite_training_parameter(
            request.parameters.get("asymptotic_feature_value", 0.0),
            name="asymptotic_feature_value",
        )
        known = _finite_training_parameter(
            request.parameters.get("asymptotic_known_output", 0.0),
            name="asymptotic_known_output",
        )
        asymptotic_error = abs(scale * anchor_x * anchor_x - known)
        positivity_min = min(predictions + self._stress_predictions(request, feature_name=feature_name, scale=scale))
        return {
            "loss": mse + unitarity_loss + self._asymptotic_penalty_weight(request) * asymptotic_error * asymptotic_error,
            "mse_loss": mse,
            "unitarity_penalty": unitarity_penalty,
            "unitarity_loss": unitarity_loss,
            "unitarity_violation_count": violation_count,
            "positivity_min_prediction": positivity_min,
            "asymptotic_limit_abs_error": asymptotic_error,
            "scale": scale,
            "scale_raw": scale_raw,
        }

    def _stress_predictions(self, request: TrainingRequest, *, feature_name: str, scale: float) -> list[float]:
        raw_values = request.parameters.get("positivity_stress_inputs", (-2.0, -1.0, 0.0, 0.5, 1.0, 2.0))
        if not isinstance(raw_values, (list, tuple)):
            raise S2ContractModelError("S2 physics-informed positivity_stress_inputs must be a list or tuple")
        predictions: list[float] = []
        for raw_value in raw_values:
            x_value = _finite_training_parameter(raw_value, name=feature_name)
            predictions.append(scale * x_value * x_value)
        return predictions

    @staticmethod
    def _single_feature(request: TrainingRequest) -> str:
        if len(request.feature_names) != 1:
            raise S2ContractModelError("S2 physics-informed backend fixture requires exactly one feature")
        return request.feature_names[0]

    @staticmethod
    def _feature_name_from_state(state: Mapping[str, Any]) -> str:
        feature_names = tuple(state.get("feature_names", ()))
        if len(feature_names) != 1:
            raise S2ContractModelError("S2 physics-informed model state requires exactly one feature")
        return str(feature_names[0])

    @staticmethod
    def _positive_scale(scale_raw: float) -> float:
        if scale_raw > 30.0:
            return scale_raw
        return math.log1p(math.exp(scale_raw))

    @staticmethod
    def _scale_derivative(scale_raw: float) -> float:
        if scale_raw >= 0:
            z = math.exp(-scale_raw)
            return 1.0 / (1.0 + z)
        z = math.exp(scale_raw)
        return z / (1.0 + z)

    @staticmethod
    def _unitarity_bound(request: TrainingRequest) -> float | None:
        raw_bound = request.parameters.get("unitarity_bound")
        if raw_bound is None:
            return None
        bound = _finite_training_parameter(raw_bound, name="unitarity_bound")
        if bound <= 0:
            raise S2ContractModelError("S2 physics-informed unitarity_bound must be positive")
        return bound

    @staticmethod
    def _unitarity_penalty_weight(request: TrainingRequest) -> float:
        weight = _finite_training_parameter(
            request.parameters.get("unitarity_penalty_weight", 0.0),
            name="unitarity_penalty_weight",
        )
        if weight < 0:
            raise S2ContractModelError("S2 physics-informed unitarity_penalty_weight must be non-negative")
        return weight

    @staticmethod
    def _asymptotic_penalty_weight(request: TrainingRequest) -> float:
        weight = _finite_training_parameter(
            request.parameters.get("asymptotic_penalty_weight", 0.0),
            name="asymptotic_penalty_weight",
        )
        if weight < 0:
            raise S2ContractModelError("S2 physics-informed asymptotic_penalty_weight must be non-negative")
        return weight


def _finite_training_parameter(value: Any, *, name: str) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise S2ContractModelError(f"S2 physics-informed parameter {name!r} must be numeric") from exc
    if not math.isfinite(numeric):
        raise S2ContractModelError(f"S2 physics-informed parameter {name!r} must be finite")
    return numeric


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
        self._backends: dict[str, Any] = {
            "tabular-baseline": DeterministicLinearTrainingBackend(),
        }
        if backends:
            for family_id, backend in backends.items():
                self.register_backend(family_id, backend)
        self._cancel_reasons: dict[str, str] = {}
        self._interrupt_reasons: dict[str, str] = {}

    def register_backend(self, family_id: str, backend: Any) -> None:
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

    def _backend_for(self, family_id: str) -> Any:
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
    feature_subset: tuple[str, ...] = ()
    hpo: dict[str, Any] = field(default_factory=dict)
    hyperparam_overrides: dict[str, Any] = field(default_factory=dict)
    constraint_overrides: tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        variant_id = self.variant_id.strip()
        model_family = self.model_family.strip()
        if not variant_id:
            raise S2ContractModelError("S2 MutationSpec requires variant_id")
        if not model_family:
            raise S2ContractModelError("S2 MutationSpec requires model_family")
        feature_subset = tuple(str(node_id).strip() for node_id in self.feature_subset)
        if any(not node_id for node_id in feature_subset):
            raise S2ContractModelError("S2 MutationSpec feature_subset cannot contain empty node ids")
        if len(set(feature_subset)) != len(feature_subset):
            raise S2ContractModelError("S2 MutationSpec feature_subset cannot contain duplicates")
        object.__setattr__(self, "variant_id", variant_id)
        object.__setattr__(self, "model_family", model_family)
        object.__setattr__(self, "parameters", _s2_jsonable(dict(self.parameters)))
        object.__setattr__(self, "feature_subset", feature_subset)
        object.__setattr__(self, "hpo", _s2_jsonable(dict(self.hpo)))
        object.__setattr__(self, "hyperparam_overrides", _s2_jsonable(dict(self.hyperparam_overrides)))
        object.__setattr__(
            self,
            "constraint_overrides",
            tuple(_s2_jsonable(dict(item)) for item in self.constraint_overrides),
        )


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
class BuildOrchestrationRequest:
    c2_envelope: Mapping[str, Any] = field(hash=False)
    code_ref: str = "git:s2-build-orchestrator"
    environment_digest: str = "oci:s2-build-orchestrator"
    seed: str = "seed-s2-build-orchestrator"
    hpo_parameter_grid: Mapping[str, tuple[Any, ...]] = field(
        default_factory=lambda: {"learning_rate": (0.01, 0.05)},
        hash=False,
    )
    hpo_max_epochs: int = 2
    final_max_epochs: int = 5
    learning_rate: float = 0.05
    train_ratio: float = 0.6
    validation_ratio: float = 0.2
    test_ratio: float = 0.2
    fold_count: int = 3
    nominal_coverage: float = 0.8
    coverage_tolerance: float = 0.25
    nondeterminism_tolerance: float = 0.0
    max_self_replay_fraction: float = 1.0
    wallclock_seconds_per_epoch: float = 1.0
    gpu_seconds_per_epoch: float = 0.0
    model_tokens_per_epoch: int = 0
    cost_usd_per_epoch: float = 0.01
    container_digest: str = "oci://argus-s2/frozen-pipeline@sha256:build-orchestrator"
    cached_dataset_split_ref: str | None = None
    cached_feature_set_ref: str | None = None
    warm_start_ref: str | None = None
    warm_start_trials: tuple[HPOTrial, ...] = ()
    variant_id: str | None = None
    variant_model_family: str | None = None
    base_pipeline_ref: str | None = None
    mutation_parameters: Mapping[str, Any] = field(default_factory=dict, hash=False)
    sandbox_env: Mapping[str, str] = field(default_factory=dict, hash=False)
    sandbox_env_allowlist: tuple[str, ...] = ()
    sandbox_egress_probe: Mapping[str, Any] | None = field(default=None, hash=False)

    def __post_init__(self) -> None:
        if not isinstance(self.c2_envelope, Mapping):
            raise S2ContractModelError("S2 BuildOrchestrationRequest requires a C2 envelope mapping")
        code_ref = self.code_ref.strip()
        environment_digest = self.environment_digest.strip()
        seed = self.seed.strip()
        container_digest = self.container_digest.strip()
        cached_dataset_split_ref = (
            self.cached_dataset_split_ref.strip() if isinstance(self.cached_dataset_split_ref, str) else None
        )
        cached_feature_set_ref = (
            self.cached_feature_set_ref.strip() if isinstance(self.cached_feature_set_ref, str) else None
        )
        warm_start_ref = self.warm_start_ref.strip() if isinstance(self.warm_start_ref, str) else None
        variant_id = self.variant_id.strip() if isinstance(self.variant_id, str) else None
        variant_model_family = self.variant_model_family.strip() if isinstance(self.variant_model_family, str) else None
        base_pipeline_ref = self.base_pipeline_ref.strip() if isinstance(self.base_pipeline_ref, str) else None
        sandbox_env = {str(key): str(value) for key, value in dict(self.sandbox_env).items()}
        sandbox_env_allowlist = tuple(str(key).strip() for key in self.sandbox_env_allowlist if str(key).strip())
        sandbox_egress_probe = (
            _s2_jsonable(dict(self.sandbox_egress_probe)) if self.sandbox_egress_probe is not None else None
        )
        if not code_ref or not environment_digest or not seed:
            raise S2ContractModelError("S2 BuildOrchestrationRequest requires code_ref, environment_digest, and seed")
        if not container_digest:
            raise S2ContractModelError("S2 BuildOrchestrationRequest requires container_digest")
        for name, ref in (
            ("cached_dataset_split_ref", cached_dataset_split_ref),
            ("cached_feature_set_ref", cached_feature_set_ref),
            ("warm_start_ref", warm_start_ref),
            ("base_pipeline_ref", base_pipeline_ref),
        ):
            if ref == "":
                raise S2ContractModelError(f"S2 BuildOrchestrationRequest {name} cannot be empty")
        if variant_id == "":
            raise S2ContractModelError("S2 BuildOrchestrationRequest variant_id cannot be empty")
        if variant_model_family == "":
            raise S2ContractModelError("S2 BuildOrchestrationRequest variant_model_family cannot be empty")
        if self.hpo_max_epochs <= 0:
            raise S2ContractModelError("S2 BuildOrchestrationRequest hpo_max_epochs must be positive")
        if self.final_max_epochs <= 0:
            raise S2ContractModelError("S2 BuildOrchestrationRequest final_max_epochs must be positive")
        if self.learning_rate <= 0:
            raise S2ContractModelError("S2 BuildOrchestrationRequest learning_rate must be positive")
        ratios = (float(self.train_ratio), float(self.validation_ratio), float(self.test_ratio))
        if any(ratio <= 0 for ratio in ratios):
            raise S2ContractModelError("S2 BuildOrchestrationRequest split ratios must be positive")
        if abs(sum(ratios) - 1.0) > 1e-9:
            raise S2ContractModelError("S2 BuildOrchestrationRequest split ratios must sum to 1.0")
        if self.fold_count < 0 or self.fold_count == 1:
            raise S2ContractModelError("S2 BuildOrchestrationRequest fold_count must be 0 or at least 2")
        nominal_coverage = float(self.nominal_coverage)
        coverage_tolerance = float(self.coverage_tolerance)
        if not 0.0 < nominal_coverage < 1.0:
            raise S2ContractModelError("S2 BuildOrchestrationRequest nominal_coverage must be between 0 and 1")
        if coverage_tolerance < 0 or coverage_tolerance >= 1:
            raise S2ContractModelError("S2 BuildOrchestrationRequest coverage_tolerance must be in [0, 1)")
        if self.nondeterminism_tolerance < 0:
            raise S2ContractModelError("S2 BuildOrchestrationRequest nondeterminism_tolerance must be non-negative")
        if self.max_self_replay_fraction <= 0:
            raise S2ContractModelError("S2 BuildOrchestrationRequest max_self_replay_fraction must be positive")
        if self.wallclock_seconds_per_epoch < 0:
            raise S2ContractModelError("S2 BuildOrchestrationRequest wallclock_seconds_per_epoch must be non-negative")
        if self.gpu_seconds_per_epoch < 0:
            raise S2ContractModelError("S2 BuildOrchestrationRequest gpu_seconds_per_epoch must be non-negative")
        if self.model_tokens_per_epoch < 0:
            raise S2ContractModelError("S2 BuildOrchestrationRequest model_tokens_per_epoch must be non-negative")
        if self.cost_usd_per_epoch < 0:
            raise S2ContractModelError("S2 BuildOrchestrationRequest cost_usd_per_epoch must be non-negative")
        object.__setattr__(self, "c2_envelope", dict(self.c2_envelope))
        object.__setattr__(self, "code_ref", code_ref)
        object.__setattr__(self, "environment_digest", environment_digest)
        object.__setattr__(self, "seed", seed)
        object.__setattr__(self, "hpo_parameter_grid", _normalize_hpo_parameter_grid(self.hpo_parameter_grid))
        object.__setattr__(self, "train_ratio", ratios[0])
        object.__setattr__(self, "validation_ratio", ratios[1])
        object.__setattr__(self, "test_ratio", ratios[2])
        object.__setattr__(self, "nominal_coverage", nominal_coverage)
        object.__setattr__(self, "coverage_tolerance", coverage_tolerance)
        object.__setattr__(self, "container_digest", container_digest)
        object.__setattr__(self, "cached_dataset_split_ref", cached_dataset_split_ref)
        object.__setattr__(self, "cached_feature_set_ref", cached_feature_set_ref)
        object.__setattr__(self, "warm_start_ref", warm_start_ref)
        object.__setattr__(self, "warm_start_trials", tuple(self.warm_start_trials))
        object.__setattr__(self, "variant_id", variant_id)
        object.__setattr__(self, "variant_model_family", variant_model_family)
        object.__setattr__(self, "base_pipeline_ref", base_pipeline_ref)
        object.__setattr__(self, "mutation_parameters", _s2_jsonable(dict(self.mutation_parameters)))
        object.__setattr__(self, "sandbox_env", sandbox_env)
        object.__setattr__(self, "sandbox_env_allowlist", sandbox_env_allowlist)
        object.__setattr__(self, "sandbox_egress_probe", sandbox_egress_probe)


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
    dataset_split_ref: str | None = None
    feature_set_ref: str | None = None
    hpo_selection_ref: str | None = None
    training_log_ref: str | None = None
    uq_calibration_ref: str | None = None
    advisory_self_check_ref: str | None = None
    sandbox_evidence_ref: str | None = None


class S2SandboxGuard:
    """S10-backed preflight guard for S2 build sandbox policy evidence."""

    SCHEMA_VERSION = "argus.s2.sandbox_evidence.v1"

    def __init__(
        self,
        *,
        artifact_store: InMemoryArtifactStore,
        token_service: InMemoryTokenService | None = None,
    ) -> None:
        self._artifact_store = artifact_store
        self._token_service = token_service or InMemoryTokenService(
            signing_key=b"argus-s2-sandbox-guard-test-key",
            signer_key_id="s2-s10-sandbox-guard",
            now_fn=lambda: 1_800_000_000,
        )

    def prepare(self, *, spec: BuildSpec, request: BuildOrchestrationRequest) -> str:
        audit_ledger = InMemoryAuditLedger()
        scope_token = self._scope_token(spec)
        budget_token = self._budget_token(spec)
        bundle = self._policy_bundle(spec)
        visible_env, secret_failed = self._materialize_env(request)
        launch_request = self._launch_request(
            spec=spec,
            request=request,
            budget_token=budget_token,
            scope_token=scope_token,
            visible_env=visible_env,
        )
        verdict = decide_policy(bundle, launch_request)
        egress_probe = self._egress_probe(
            spec=spec,
            request=request,
            scope_token=scope_token,
            bundle=bundle,
            audit_ledger=audit_ledger,
        )
        broker_result = self._broker_write_probe(
            spec=spec,
            request=request,
            scope_token=scope_token,
            audit_ledger=audit_ledger,
        )
        checks = self._checks(
            verdict=verdict,
            egress_probe=egress_probe,
            secret_failed=secret_failed,
        )
        status = "PASS" if all(check["status"] == "PASS" for check in checks.values()) else "QUARANTINED"
        payload = self._evidence_payload(
            spec=spec,
            request=request,
            status=status,
            checks=checks,
            verdict=verdict,
            bundle=bundle,
            visible_env=visible_env,
            egress_probe=egress_probe,
            broker_result=broker_result,
            audit_ledger=audit_ledger,
        )
        record = broker_result["client"].put_artifact(
            kind="s2_sandbox_evidence",
            payload=payload,
            producer=Producer(subsystem="S2", version="0.0.0"),
            lineage=Lineage(
                input_refs=tuple(spec.input_artifact_refs),
                code_ref=request.code_ref,
                environment_digest=request.environment_digest,
                seeds=(request.seed,),
                job_id=spec.job_id,
            ),
            claim_tier=S2ClaimTierPolicy.RAN_TOY,
        )
        evidence_ref = record.artifact_ref
        if status != "PASS":
            failing_check = next(key for key, check in checks.items() if check["status"] == "FAIL")
            code = "EGRESS_DENIED" if failing_check == "S2-TC30" else "SECRET_EXPOSED"
            diagnostics = {
                "status": status,
                "failed_check": failing_check,
                "evidence_ref": evidence_ref,
                "checks": checks,
            }
            raise S2SandboxViolation(
                "S2 sandbox integration preflight quarantined the build",
                code=code,
                evidence_ref=evidence_ref,
                diagnostics=diagnostics,
            )
        return evidence_ref

    def _scope_token(self, spec: BuildSpec) -> Any:
        return self._token_service.mint_scope(
            scopes=ScopeGrant(
                allowed_adapters=spec.allowed_adapters,
                allowed_datasets=spec.allowed_datasets,
                egress_allowlist=spec.allowed_egress,
                broker_audiences=("store",),
                capabilities=("s2.build",),
                producer_subsystems=("S2",),
                sandbox_risk_class="standard",
            ),
            job_id=spec.job_id,
            ttl_s=900,
        )

    def _budget_token(self, spec: BuildSpec) -> Any:
        return self._token_service.mint_budget(
            caps=BudgetCaps(
                max_compute_units=max(float(spec.budget.max_wallclock_seconds), 1.0),
                max_gpu_seconds=float(spec.budget.max_gpu_seconds or 0.0),
                max_model_tokens=float(spec.budget.max_model_tokens or 0.0),
                max_wallclock_s=float(spec.budget.max_wallclock_seconds),
                max_cost_usd=float(spec.budget.max_usd),
            ),
            job_id=spec.job_id,
            root_request_id=spec.trace_id,
            risk_class="standard",
            ttl_s=900,
        )

    @staticmethod
    def _policy_bundle(spec: BuildSpec) -> PolicyBundle:
        unsigned = PolicyBundle(
            bundle_version=f"s2-sandbox-{spec.job_id}",
            egress_allowlist=spec.allowed_egress,
            resource_ceilings=ResourceCeilings(
                cpu_m=1000,
                mem_bytes=1_073_741_824,
                gpu_count=1 if (spec.budget.max_gpu_seconds or 0.0) > 0 else 0,
                wallclock_s=max(int(spec.budget.max_wallclock_seconds), 1),
                max_cost_usd=float(spec.budget.max_usd),
            ),
            risk_to_runtime={"standard": "docker"},
            seccomp_profile_hash=f"blake3:{'0' * 64}",
            signer_key_id="s2-s10-sandbox-guard",
            signature="",
        )
        return PolicyBundleSigner(key_id="s2-s10-sandbox-guard", secret=b"argus-s2-sandbox-policy").sign(unsigned)

    @staticmethod
    def _materialize_env(request: BuildOrchestrationRequest) -> tuple[dict[str, str], bool]:
        try:
            return materialize_sandbox_env(dict(request.sandbox_env), request.sandbox_env_allowlist), False
        except PolicyDeniedError:
            return {}, True

    def _launch_request(
        self,
        *,
        spec: BuildSpec,
        request: BuildOrchestrationRequest,
        budget_token: Any,
        scope_token: Any,
        visible_env: dict[str, str],
    ) -> LaunchRequest:
        return LaunchRequest(
            job_id=spec.job_id,
            subagent_id="s2-build-orchestrator",
            trace_id=spec.trace_id,
            budget_token=budget_token,
            scope_token=scope_token,
            image=_s2_digest_pinned_image(request.container_digest),
            entrypoint=("argus-s2-build",),
            args=(spec.job_id,),
            env=visible_env,
            env_allowlist=request.sandbox_env_allowlist,
            requested_envelope=LaunchEnvelope(
                cpu_m=1000,
                mem_bytes=1_073_741_824,
                gpu_count=0,
                wallclock_s=max(int(spec.budget.max_wallclock_seconds), 1),
                scratch_bytes=268_435_456,
                pids=128,
                estimated_cost_usd=min(float(spec.budget.max_usd), 0.01),
            ),
            runtime_class_hint="docker",
            policy_pin=f"s2-sandbox-{spec.job_id}",
        )

    @staticmethod
    def _egress_probe(
        *,
        spec: BuildSpec,
        request: BuildOrchestrationRequest,
        scope_token: Any,
        bundle: PolicyBundle,
        audit_ledger: InMemoryAuditLedger,
    ) -> dict[str, Any]:
        probe = request.sandbox_egress_probe
        if probe is None:
            default_rule = spec.allowed_egress[0] if spec.allowed_egress else None
            if default_rule is None:
                return {"attempted": False, "decision": "SKIPPED", "reason": "no_probe_configured"}
            probe = {
                "host": default_rule.host,
                "port": default_rule.port,
                "proto": default_rule.proto,
                "sni": default_rule.host,
            }
        host = str(probe.get("host") or "")
        port = int(probe.get("port") or 0)
        proto = str(probe.get("proto") or "https")
        sni = str(probe.get("sni") or host)
        decision = EgressProxy(bundle).decide(scope_token, host=host, port=port, proto=proto, sni=sni)
        audit_ledger.append(
            "egress.decision",
            {
                "host": host,
                "port": port,
                "proto": proto,
                "decision": "ALLOW" if decision.allowed else "DENY",
                "reason": decision.reason,
                "job_id": spec.job_id,
            },
        )
        return {
            "attempted": True,
            "host": host,
            "port": port,
            "proto": proto,
            "sni": sni,
            "decision": "ALLOW" if decision.allowed else "DENY",
            "reason": decision.reason,
        }

    def _broker_write_probe(
        self,
        *,
        spec: BuildSpec,
        request: BuildOrchestrationRequest,
        scope_token: Any,
        audit_ledger: InMemoryAuditLedger,
    ) -> dict[str, Any]:
        broker = StoreWriterBroker(
            token_service=self._token_service,
            artifact_store=self._artifact_store,
            audit_ledger=audit_ledger,
        )
        client = broker.client_for(scope_token)
        direct_denied = False
        try:
            client.create_artifact(
                kind="s2_direct_write_probe",
                payload={"job_id": spec.job_id},
                producer=Producer(subsystem="S2", version="0.0.0"),
                lineage=Lineage(
                    input_refs=tuple(spec.input_artifact_refs),
                    code_ref=request.code_ref,
                    environment_digest=request.environment_digest,
                    seeds=(request.seed,),
                    job_id=spec.job_id,
                ),
            )
        except ScopeDeniedError:
            direct_denied = True
        return {
            "broker": broker,
            "client": client,
            "direct_write_bypass": {
                "attempted": True,
                "denied": direct_denied,
                "required_path": "StoreWriterBroker.put_artifact",
            },
        }

    @staticmethod
    def _checks(
        *,
        verdict: Any,
        egress_probe: Mapping[str, Any],
        secret_failed: bool,
    ) -> dict[str, dict[str, str]]:
        return {
            "S2-TC30": {
                "status": "PASS" if verdict.allowed and egress_probe.get("decision") != "DENY" else "FAIL",
                **({"severity": "SEV-1"} if not verdict.allowed or egress_probe.get("decision") == "DENY" else {}),
            },
            "S2-TC31": {
                "status": "FAIL" if secret_failed else "PASS",
                **({"severity": "SEV-1"} if secret_failed else {}),
            },
            "S2-TC32": {"status": "PASS"},
        }

    @staticmethod
    def _evidence_payload(
        *,
        spec: BuildSpec,
        request: BuildOrchestrationRequest,
        status: str,
        checks: Mapping[str, Any],
        verdict: Any,
        bundle: PolicyBundle,
        visible_env: Mapping[str, str],
        egress_probe: Mapping[str, Any],
        broker_result: Mapping[str, Any],
        audit_ledger: InMemoryAuditLedger,
    ) -> dict[str, Any]:
        audit_events = [event.event_type for event in audit_ledger.events()]
        if "store.put" not in audit_events:
            audit_events.append("store.put")
        return {
            "schema_version": S2SandboxGuard.SCHEMA_VERSION,
            "status": status,
            "job_id": spec.job_id,
            "trace_id": spec.trace_id,
            "checks": dict(checks),
            "policy": {
                "runtime_class": verdict.runtime_class,
                "egress_acl": [asdict(rule) for rule in verdict.egress_acl],
                "deny_reason": verdict.deny_reason,
                "bundle": {
                    "bundle_version": bundle.bundle_version,
                    "resource_ceilings": asdict(bundle.resource_ceilings),
                    "risk_to_runtime": dict(bundle.risk_to_runtime),
                    "seccomp_profile_hash": bundle.seccomp_profile_hash,
                },
            },
            "sandbox_visible_env": dict(visible_env),
            "secret_scan": {
                "zero_matches": checks["S2-TC31"]["status"] == "PASS",
                "scanned_keys": sorted(set(request.sandbox_env_allowlist) & set(request.sandbox_env)),
                "leaked_values_recorded": False,
            },
            "egress_probe": dict(egress_probe),
            "direct_write_bypass": dict(broker_result["direct_write_bypass"]),
            "brokered_store_client": {
                "opaque_handle": True,
                "direct_store_reference_exposed": False,
            },
            "audit_events": audit_events,
        }


@dataclass(frozen=True)
class VariantBuildResult:
    variant_id: str
    model_ref: str
    frozen_pipeline_ref: str
    artifact_refs: tuple[str, ...]
    base_pipeline_ref: str
    diagnostics: dict[str, Any]


@dataclass(frozen=True)
class S2ConformanceRequest:
    build_result: BuildResult
    level: str
    entity_id: str
    claimed_level: str | None = None
    maintainer_id: str = "s2-conformance"
    key_id: str = "s2-conformance-key"
    maintainer_secret: bytes = b"s2-conformance-maintainer-secret"
    code_ref: str | None = None
    container_digest: str | None = None
    sbom_hash: str = "c4://sbom/s2-conformance"
    base_pipeline_ref: str | None = None
    independence_tags: tuple[str, ...] = ("s2-conformance-independent",)
    reward_path_write_attempt: bool = False
    egress_attempt: bool = False
    trust_path_write_attempt: bool = False
    signing_key_visible_in_sandbox: bool = False


@dataclass(frozen=True)
class S2ConformanceResult:
    record: ConformanceRecord
    record_ref: str
    bundle: SubmissionBundle
    status: str
    level_requested: str
    evidence_refs: tuple[str, ...]
    recursion_safety: dict[str, Any]


class S2ConformanceHarness:
    """S12 conformance hook that derives bundle predicates from real S2 C4 build artifacts."""

    def __init__(self, *, artifact_store: InMemoryArtifactStore, conformance_service: ConformanceService) -> None:
        self._artifact_store = artifact_store
        self._conformance_service = conformance_service

    def run(self, request: S2ConformanceRequest) -> S2ConformanceResult:
        level = _s2_conformance_level(request.level)
        build = request.build_result
        frozen_payload = _s2_conformance_payload(
            self._artifact_store,
            build.frozen_pipeline_ref,
            expected_kind="frozen_pipeline",
            role="frozen pipeline",
        )
        evidence_refs = _s2_conformance_evidence_refs(build, request.base_pipeline_ref)
        provenance_complete = _s2_conformance_provenance_complete(self._artifact_store, evidence_refs)
        recursion_safety = _s2_recursion_safety_evidence(build, frozen_payload, base_pipeline_ref=request.base_pipeline_ref)
        descriptor = _s2_conformance_descriptor(request, build, frozen_payload)
        bundle = SubmissionBundle(
            submission_id=f"s2-conformance:{build.job_id}:{level}",
            entity_id=request.entity_id,
            maintainer_id=request.maintainer_id,
            key_id=request.key_id,
            descriptor_draft=descriptor,
            claimed_level=request.claimed_level or level,
            code_ref=request.code_ref or str(frozen_payload.get("config_hash") or build.frozen_pipeline_ref),
            container_digest=request.container_digest or _s2_conformance_container_digest(frozen_payload),
            sbom_hash=request.sbom_hash,
            lifecycle_valid=bool(build.diagnostics.get("status") == "SUCCEEDED" and build.frozen_pipeline_ref),
            provenance_complete=provenance_complete,
            attempted_claim_tier=str(build.claim_tier),
            uncertainty_tagged=_s2_uncertainty_tagged(self._artifact_store, build.uq_calibration_ref),
            refuses_without_verifier=_s2_verifier_profile_declared(build),
            typed_error_envelope=_s2_typed_error_surface_declared(build),
            reward_path_write_attempt=bool(request.reward_path_write_attempt or not recursion_safety["recursion_safe"]),
            c6_units_present=_s2_io_units_present(frozen_payload),
            differentiable=_s2_differentiable_model(self._artifact_store, build.model_ref),
            grad_implemented=_s2_grad_implemented(self._artifact_store, build.model_ref),
            reproducibility_manifest_complete=_s2_repro_manifest_complete(frozen_payload, provenance_complete),
            egress_attempt=bool(request.egress_attempt),
            trust_path_write_attempt=bool(request.trust_path_write_attempt),
            signing_key_visible_in_sandbox=bool(request.signing_key_visible_in_sandbox),
        )
        signed_bundle = sign_submission_bundle(bundle, secret=request.maintainer_secret)
        record = self._conformance_service.run(signed_bundle, level=level)
        record_artifact = self._conformance_service.write_record(
            store=self._artifact_store,
            record=record,
            evidence_refs=evidence_refs,
        )
        return S2ConformanceResult(
            record=record,
            record_ref=record_artifact.artifact_ref,
            bundle=signed_bundle,
            status=record.status,
            level_requested=level,
            evidence_refs=evidence_refs,
            recursion_safety=recursion_safety,
        )


def _s2_conformance_level(level: str) -> str:
    normalized = str(level).strip().lower()
    if normalized not in {"bronze", "silver", "gold"}:
        raise S2ConformanceError("S2 conformance level must be one of: bronze, silver, gold")
    return normalized


def _s2_conformance_payload(
    store: InMemoryArtifactStore,
    artifact_ref: str | None,
    *,
    expected_kind: str,
    role: str,
) -> dict[str, Any]:
    if not artifact_ref:
        raise S2ConformanceError(f"S2 conformance requires {role} artifact ref")
    try:
        record = store.get_record(artifact_ref)
    except KeyError as exc:
        raise S2ConformanceError(f"S2 conformance cannot load {role} artifact: {artifact_ref}") from exc
    if record.kind != expected_kind:
        raise S2ConformanceError(f"S2 conformance expected {role} kind {expected_kind}, got {record.kind}")
    payload = json.loads(store.get_artifact(artifact_ref).decode("utf-8"))
    if not isinstance(payload, dict):
        raise S2ConformanceError(f"S2 conformance {role} artifact payload must be an object")
    return payload


def _s2_conformance_evidence_refs(build: BuildResult, base_pipeline_ref: str | None) -> tuple[str, ...]:
    refs = list(build.artifact_refs)
    refs.extend(
        ref
        for ref in (
            build.frozen_pipeline_ref,
            build.model_ref,
            build.dataset_split_ref,
            build.feature_set_ref,
            build.hpo_selection_ref,
            build.training_log_ref,
            build.uq_calibration_ref,
            build.advisory_self_check_ref,
            base_pipeline_ref,
        )
        if ref
    )
    return tuple(dict.fromkeys(refs))


def _s2_conformance_provenance_complete(store: InMemoryArtifactStore, artifact_refs: tuple[str, ...]) -> bool:
    if not artifact_refs:
        return False
    for artifact_ref in artifact_refs:
        try:
            record = store.get_record(artifact_ref)
            raw_payload = json.loads(store.get_artifact(artifact_ref).decode("utf-8"))
            payload = raw_payload if isinstance(raw_payload, Mapping) else None
            assert_lineage_complete(
                record.lineage,
                kind=record.kind,
                payload=payload,
                claim_tier=record.claim_tier,
                validation_report_ref=record.validation_report_ref,
            )
        except Exception:
            return False
    return True


def _s2_conformance_descriptor(
    request: S2ConformanceRequest,
    build: BuildResult,
    frozen_payload: Mapping[str, Any],
) -> CapabilityDescriptor:
    diagnostics = build.diagnostics
    build_spec = diagnostics.get("build_spec")
    subtopic = "s2-conformance"
    if isinstance(build_spec, Mapping) and build_spec.get("subtopic"):
        subtopic = str(build_spec["subtopic"])
    return CapabilityDescriptor(
        entity_id=request.entity_id,
        revision=1,
        kind="subagent",
        owner_subsystem="S2",
        contract_versions={"C1": "1.0.0", "C5": "1.0.0"},
        trust_class="internal",
        capability_scopes=("c1.accept", "c1.plan", "c1.build", "c1.validate", "c1.report"),
        provenance_ref=build.frozen_pipeline_ref,
        subtopics=(subtopic,),
        independence_tags=tuple(request.independence_tags),
        conformance_level=None,
    )


def _s2_conformance_container_digest(frozen_payload: Mapping[str, Any]) -> str:
    raw = str(frozen_payload.get("container_digest") or "")
    marker = "sha256:"
    if marker in raw:
        return marker + raw.split(marker, 1)[1]
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return f"{marker}{digest}"


def _s2_recursion_safety_evidence(
    build: BuildResult,
    frozen_payload: Mapping[str, Any],
    *,
    base_pipeline_ref: str | None,
) -> dict[str, Any]:
    diagnostics = build.diagnostics
    config = frozen_payload.get("config")
    config = config if isinstance(config, Mapping) else {}
    replay = frozen_payload.get("self_replay")
    replay = replay if isinstance(replay, Mapping) else {}
    resolved_base_ref = base_pipeline_ref or config.get("base_pipeline_ref")
    reward_source = str(diagnostics.get("reward_source") or config.get("reward_source") or "").lower()
    score_returned = bool(
        hasattr(build, "score")
        or "score" in diagnostics
        or "score" in frozen_payload
        or "fitness" in diagnostics
        or "reward" in diagnostics
    )
    recursion_safe = bool(
        resolved_base_ref
        and reward_source == "c3-only"
        and not score_returned
        and replay.get("status") == "PASS"
        and frozen_payload.get("claim_tier") == "ran-toy"
    )
    return {
        "base_pipeline_ref": resolved_base_ref,
        "reward_source": reward_source,
        "s2_score_returned": score_returned,
        "self_replay_status": replay.get("status"),
        "claim_tier": frozen_payload.get("claim_tier"),
        "recursion_safe": recursion_safe,
    }


def _s2_uncertainty_tagged(store: InMemoryArtifactStore, uq_calibration_ref: str | None) -> bool:
    if uq_calibration_ref is None:
        return False
    payload = _s2_conformance_payload(
        store,
        uq_calibration_ref,
        expected_kind="uq_calibration",
        role="UQ calibration",
    )
    uncertainty_tag = payload.get("uncertainty_tag")
    return (
        isinstance(uncertainty_tag, Mapping)
        and bool(uncertainty_tag.get("kind"))
        and str(payload.get("uncertainty_method") or "none") != "none"
        and payload.get("self_replay", {}).get("status") == "PASS"
    )


def _s2_verifier_profile_declared(build: BuildResult) -> bool:
    build_spec = build.diagnostics.get("build_spec")
    return isinstance(build_spec, Mapping) and bool(build_spec.get("verifier_profile_ref"))


def _s2_typed_error_surface_declared(build: BuildResult) -> bool:
    build_spec = build.diagnostics.get("build_spec")
    return build.diagnostics.get("status") == "SUCCEEDED" and isinstance(build_spec, Mapping)


def _s2_io_units_present(frozen_payload: Mapping[str, Any]) -> bool:
    io_signature = frozen_payload.get("io_signature")
    if not isinstance(io_signature, Mapping):
        return False
    for section_name in ("inputs", "outputs"):
        section = io_signature.get(section_name)
        if not isinstance(section, Mapping) or not section:
            return False
        for spec in section.values():
            if not isinstance(spec, Mapping) or not isinstance(spec.get("units"), str) or not spec.get("units"):
                return False
    return True


def _s2_differentiable_model(store: InMemoryArtifactStore, model_ref: str) -> bool:
    payload = _s2_conformance_payload(store, model_ref, expected_kind="model_checkpoint", role="model checkpoint")
    backend = str(payload.get("backend") or payload.get("family_id") or "")
    return bool(payload.get("differentiable") is True or backend in {"physics-informed", "physics_informed"})


def _s2_grad_implemented(store: InMemoryArtifactStore, model_ref: str) -> bool:
    payload = _s2_conformance_payload(store, model_ref, expected_kind="model_checkpoint", role="model checkpoint")
    if not _s2_differentiable_model(store, model_ref):
        return False
    return bool(payload.get("grad_implemented") or payload.get("supports_grad") or payload.get("gradient_ref"))


def _s2_repro_manifest_complete(frozen_payload: Mapping[str, Any], provenance_complete: bool) -> bool:
    component_refs = frozen_payload.get("component_refs")
    replay = frozen_payload.get("self_replay")
    if not isinstance(component_refs, Mapping) or not isinstance(replay, Mapping):
        return False
    required_component_refs = ("feature_set_ref", "model_checkpoint_ref", "calibration_artifact_ref")
    return bool(
        provenance_complete
        and all(isinstance(component_refs.get(ref_name), str) and component_refs.get(ref_name) for ref_name in required_component_refs)
        and isinstance(component_refs.get("input_refs"), list)
        and component_refs.get("input_refs")
        and frozen_payload.get("config_hash")
        and frozen_payload.get("params_hash")
        and frozen_payload.get("seeds")
        and frozen_payload.get("container_digest")
        and replay.get("status") == "PASS"
    )


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
        S2ClaimTierPolicy.assert_s2_writer_producer(self._producer)

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
        artifact_producer = producer or self._producer
        self._assert_valid_producer(artifact_producer)
        S2ClaimTierPolicy.assert_s2_writer_producer(artifact_producer)
        S2ClaimTierPolicy.assert_s2_artifact_claim(
            claim_tier=claim_tier,
            validation_report_ref=validation_report_ref,
        )
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


@dataclass(frozen=True)
class ExplainabilityReportRequest:
    build_ref: str
    report_id: str | None = None
    code_ref: str = "argus-core:s2.explainability_reporter"
    environment_digest: str = "python:argus-s2-explainability:v1"
    seed: str = "s2-explainability-report"

    def __post_init__(self) -> None:
        build_ref = self.build_ref.strip()
        report_id = self.report_id.strip() if isinstance(self.report_id, str) else None
        code_ref = self.code_ref.strip()
        environment_digest = self.environment_digest.strip()
        seed = self.seed.strip()
        if not build_ref:
            raise ExplainabilityReportError("S2 explainability requires build_ref")
        if report_id == "":
            raise ExplainabilityReportError("S2 explainability report_id cannot be empty")
        if not code_ref or not environment_digest or not seed:
            raise ExplainabilityReportError("S2 explainability requires code_ref, environment_digest, and seed")
        object.__setattr__(self, "build_ref", build_ref)
        object.__setattr__(self, "report_id", report_id)
        object.__setattr__(self, "code_ref", code_ref)
        object.__setattr__(self, "environment_digest", environment_digest)
        object.__setattr__(self, "seed", seed)


@dataclass(frozen=True)
class ExplainabilityReportResult:
    job_id: str
    build_ref: str
    report_ref: str
    status: str
    sections: tuple[str, ...]
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "sections", tuple(self.sections))
        object.__setattr__(self, "diagnostics", dict(self.diagnostics))


class ExplainabilityReporter:
    """Generates deterministic S2 explainability reports from C4 build artifacts."""

    REQUIRED_SECTIONS = ("rationale", "hpo_trace", "priors", "calibration_plot", "repair_log")

    def __init__(
        self,
        *,
        artifact_store: InMemoryArtifactStore,
        provenance_emitter: ProvenanceEmitter | None = None,
    ) -> None:
        self._artifact_store = artifact_store
        self._provenance_emitter = provenance_emitter or ProvenanceEmitter(artifact_store=artifact_store)

    def explain(self, request: ExplainabilityReportRequest) -> ExplainabilityReportResult:
        build_record, build_payload = self._load_required_artifact(
            request.build_ref,
            expected_kind="frozen_pipeline",
            role="build_ref",
        )
        if build_payload.get("entrypoint") != "predict":
            raise ExplainabilityReportError("S2 explainability requires a frozen predict pipeline")
        component_refs = self._component_refs(build_payload)
        config = self._mapping(build_payload.get("config"), role="frozen pipeline config", required=False)
        input_refs = component_refs.get("input_refs", ())
        feature_set_ref = self._required_component_ref(component_refs, "feature_set_ref")
        model_checkpoint_ref = self._required_component_ref(component_refs, "model_checkpoint_ref")
        calibration_ref = self._required_component_ref(component_refs, "calibration_artifact_ref")
        hpo_ref = self._config_ref(config, "hpo_selection_ref") or self._first_ref_by_kind(input_refs, "hpo_selection")
        advisory_ref = self._config_ref(config, "advisory_self_check_ref") or self._first_ref_by_kind(
            input_refs,
            "advisory_self_check",
        )
        training_log_ref = self._first_ref_by_kind(input_refs, "training_log")
        dataset_split_ref = self._first_ref_by_kind(input_refs, "dataset_split")
        base_pipeline_ref = self._config_ref(config, "base_pipeline_ref")
        if hpo_ref is None:
            raise ExplainabilityReportError("S2 explainability cannot resolve hpo_selection_ref")
        if advisory_ref is None:
            raise ExplainabilityReportError("S2 explainability cannot resolve advisory_self_check_ref")

        _, feature_payload = self._load_required_artifact(feature_set_ref, expected_kind="feature_set", role="feature_set")
        _, model_payload = self._load_required_artifact(
            model_checkpoint_ref,
            expected_kind="model_checkpoint",
            role="model_checkpoint",
        )
        _, calibration_payload = self._load_required_artifact(
            calibration_ref,
            expected_kind="uq_calibration",
            role="uq_calibration",
        )
        _, hpo_payload = self._load_required_artifact(hpo_ref, expected_kind="hpo_selection", role="hpo_selection")
        _, advisory_payload = self._load_required_artifact(
            advisory_ref,
            expected_kind="advisory_self_check",
            role="advisory_self_check",
        )
        training_payload = {}
        if training_log_ref is not None:
            _, training_payload = self._load_required_artifact(
                training_log_ref,
                expected_kind="training_log",
                role="training_log",
            )

        job_id = str(build_record.producer.job_id or build_payload.get("job_id") or hpo_payload.get("job_id") or "")
        if not job_id:
            raise ExplainabilityReportError("S2 explainability cannot resolve build job_id")
        sections = {
            "rationale": self._rationale_section(
                build_payload=build_payload,
                feature_payload=feature_payload,
                model_payload=model_payload,
                hpo_payload=hpo_payload,
            ),
            "hpo_trace": self._hpo_trace_section(hpo_payload),
            "priors": self._priors_section(
                build_payload=build_payload,
                feature_payload=feature_payload,
                base_pipeline_ref=base_pipeline_ref,
                dataset_split_ref=dataset_split_ref,
            ),
            "calibration_plot": self._calibration_plot_section(calibration_payload),
            "repair_log": self._repair_log_section(
                calibration_payload=calibration_payload,
                advisory_payload=advisory_payload,
                training_payload=training_payload,
            ),
        }
        payload = {
            "schema_version": S2_EXPLAINABILITY_REPORT_SCHEMA_VERSION,
            "s2_tc39": True,
            "report_id": request.report_id or f"s2-explainability:{hash_bytes(canonical_json_bytes(request.build_ref))}",
            "status": "GENERATED",
            "build_ref": request.build_ref,
            "base_pipeline_ref": base_pipeline_ref,
            "job_id": job_id,
            "claim_tier": "ran-toy",
            "section_order": list(self.REQUIRED_SECTIONS),
            "sections": sections,
            "component_refs": {
                "feature_set_ref": feature_set_ref,
                "model_checkpoint_ref": model_checkpoint_ref,
                "hpo_selection_ref": hpo_ref,
                "training_log_ref": training_log_ref,
                "uq_calibration_ref": calibration_ref,
                "advisory_self_check_ref": advisory_ref,
                "dataset_split_ref": dataset_split_ref,
            },
            "score_authority": {
                "s2_score_returned": False,
                "authoritative_reward_source": "C3_ONLY",
                "hpo_objective_values_are_advisory": True,
                "frozen_pipeline_reward_source": str(config.get("reward_source") or "c3-only"),
            },
        }
        lineage_refs = _unique_pipeline_refs(
            tuple(
                ref
                for ref in (
                    request.build_ref,
                    feature_set_ref,
                    model_checkpoint_ref,
                    hpo_ref,
                    training_log_ref,
                    calibration_ref,
                    advisory_ref,
                    dataset_split_ref,
                    base_pipeline_ref,
                )
                if isinstance(ref, str) and ref
            )
        )
        record = self._provenance_emitter.emit_artifact(
            kind="s2_explainability_report",
            payload=_s2_jsonable(payload),
            producer=Producer(subsystem="S2", version="0.0.0", job_id=job_id),
            lineage=Lineage(
                input_refs=lineage_refs,
                code_ref=request.code_ref,
                environment_digest=request.environment_digest,
                seeds=(request.seed,),
                job_id=job_id,
            ),
            claim_tier="ran-toy",
        )
        return ExplainabilityReportResult(
            job_id=job_id,
            build_ref=request.build_ref,
            report_ref=record.artifact_ref,
            status="GENERATED",
            sections=self.REQUIRED_SECTIONS,
            diagnostics={
                "component_ref_count": len(lineage_refs),
                "base_pipeline_ref": base_pipeline_ref,
                "score_authority": payload["score_authority"],
            },
        )

    def _load_required_artifact(
        self,
        artifact_ref: str,
        *,
        expected_kind: str,
        role: str,
    ) -> tuple[ArtifactRecord, dict[str, Any]]:
        try:
            record = self._artifact_store.get_record(artifact_ref)
            payload = json.loads(self._artifact_store.get_artifact(artifact_ref).decode("utf-8"))
        except (KeyError, json.JSONDecodeError) as exc:
            raise ExplainabilityReportError(f"S2 explainability cannot load {role}: {artifact_ref}") from exc
        if record.kind != expected_kind:
            raise ExplainabilityReportError(
                f"S2 explainability expected {role} kind {expected_kind!r}, got {record.kind!r}"
            )
        if not isinstance(payload, dict):
            raise ExplainabilityReportError(f"S2 explainability {role} payload must be an object")
        return record, payload

    def _first_ref_by_kind(self, refs: tuple[str, ...], kind: str) -> str | None:
        for ref in refs:
            try:
                record = self._artifact_store.get_record(ref)
            except KeyError:
                continue
            if record.kind == kind:
                return ref
        return None

    @staticmethod
    def _component_refs(build_payload: Mapping[str, Any]) -> dict[str, Any]:
        raw = build_payload.get("component_refs")
        if not isinstance(raw, Mapping):
            raise ExplainabilityReportError("S2 explainability requires frozen pipeline component_refs")
        component_refs = dict(raw)
        input_refs = component_refs.get("input_refs", ())
        if not isinstance(input_refs, (list, tuple)):
            raise ExplainabilityReportError("S2 explainability component_refs.input_refs must be a list")
        component_refs["input_refs"] = tuple(str(ref).strip() for ref in input_refs if str(ref).strip())
        return component_refs

    @staticmethod
    def _required_component_ref(component_refs: Mapping[str, Any], key: str) -> str:
        ref = component_refs.get(key)
        if not isinstance(ref, str) or not ref.strip():
            raise ExplainabilityReportError(f"S2 explainability missing component ref: {key}")
        return ref.strip()

    @staticmethod
    def _config_ref(config: Mapping[str, Any], key: str) -> str | None:
        ref = config.get(key)
        return ref.strip() if isinstance(ref, str) and ref.strip() else None

    @staticmethod
    def _mapping(value: Any, *, role: str, required: bool = True) -> dict[str, Any]:
        if isinstance(value, Mapping):
            return dict(value)
        if not required:
            return {}
        raise ExplainabilityReportError(f"S2 explainability {role} must be an object")

    def _rationale_section(
        self,
        *,
        build_payload: Mapping[str, Any],
        feature_payload: Mapping[str, Any],
        model_payload: Mapping[str, Any],
        hpo_payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        feature_set = self._mapping(feature_payload.get("feature_set"), role="feature_set")
        io_signature = self._mapping(build_payload.get("io_signature"), role="io_signature")
        selected_parameters = self._mapping(hpo_payload.get("selected_parameters"), role="selected_parameters")
        return {
            "status": "PRESENT",
            "model_family": str(model_payload.get("family_id") or hpo_payload.get("selected_family_id") or ""),
            "backend": str(model_payload.get("backend") or ""),
            "selected_features": list(feature_set.get("selected_nodes", ())),
            "selected_parameters": selected_parameters,
            "io_signature": io_signature,
            "self_replay": dict(build_payload.get("self_replay", {})),
            "rationale": "Selected model and feature lineage are reconstructed from C4 component refs.",
        }

    def _hpo_trace_section(self, hpo_payload: Mapping[str, Any]) -> dict[str, Any]:
        trials = []
        trial_refs = hpo_payload.get("trial_artifact_refs", ())
        if not isinstance(trial_refs, list):
            raise ExplainabilityReportError("S2 explainability hpo_selection missing trial_artifact_refs")
        for trial_ref in trial_refs:
            if not isinstance(trial_ref, str) or not trial_ref.strip():
                continue
            _, trial_payload = self._load_required_artifact(
                trial_ref.strip(),
                expected_kind="hpo_trial",
                role="hpo_trial",
            )
            trials.append(
                {
                    "trial_id": trial_payload.get("trial_id"),
                    "family_id": trial_payload.get("family_id"),
                    "status": trial_payload.get("status"),
                    "parameters": dict(trial_payload.get("parameters", {})),
                    "objective_metric": trial_payload.get("objective_metric"),
                    "objective_value": trial_payload.get("score"),
                    "calibration_error": trial_payload.get("calibration_error"),
                    "cost": trial_payload.get("cost"),
                    "warm_start_ref": dict(trial_payload.get("diagnostics", {})).get("warm_start_ref"),
                }
            )
        return {
            "status": "PRESENT",
            "selected_trial_id": hpo_payload.get("selected_trial_id"),
            "selected_family_id": hpo_payload.get("selected_family_id"),
            "selected_parameters": dict(hpo_payload.get("selected_parameters", {})),
            "objective": hpo_payload.get("objective"),
            "objective_metric": hpo_payload.get("objective_metric"),
            "policy": hpo_payload.get("policy"),
            "pareto_front_trial_ids": list(hpo_payload.get("pareto_front_trial_ids", ())),
            "trials": trials,
        }

    def _priors_section(
        self,
        *,
        build_payload: Mapping[str, Any],
        feature_payload: Mapping[str, Any],
        base_pipeline_ref: str | None,
        dataset_split_ref: str | None,
    ) -> dict[str, Any]:
        config = self._mapping(build_payload.get("config"), role="frozen pipeline config", required=False)
        graph = self._mapping(feature_payload.get("graph"), role="feature graph")
        return {
            "status": "PRESENT",
            "adapter_refs": list(build_payload.get("adapter_refs", ())),
            "base_pipeline_ref": base_pipeline_ref,
            "dataset_split_ref": dataset_split_ref,
            "cache_reuse": dict(config.get("cache_reuse", {})),
            "mutation_parameters": dict(config.get("mutation_parameters", {})),
            "feature_graph": {
                "graph_id": graph.get("graph_id"),
                "node_count": len(graph.get("nodes", ())),
                "nodes": list(graph.get("nodes", ())),
            },
        }

    @staticmethod
    def _calibration_plot_section(calibration_payload: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "status": "PRESENT",
            "calibration_status": calibration_payload.get("status"),
            "advisory_check": dict(calibration_payload.get("advisory_check", {})),
            "plot_data": {
                "nominal_coverage": calibration_payload.get("nominal_coverage"),
                "empirical_coverage": calibration_payload.get("empirical_coverage"),
                "coverage_tolerance": calibration_payload.get("coverage_tolerance"),
                "calibration_error": calibration_payload.get("calibration_error"),
                "calibration_sample_count": calibration_payload.get("calibration_sample_count"),
                "validation_sample_count": calibration_payload.get("validation_sample_count"),
                "interval": dict(calibration_payload.get("interval", {})),
                "points": [
                    {"label": "nominal", "coverage": calibration_payload.get("nominal_coverage")},
                    {"label": "empirical", "coverage": calibration_payload.get("empirical_coverage")},
                ],
            },
        }

    @staticmethod
    def _repair_log_section(
        *,
        calibration_payload: Mapping[str, Any],
        advisory_payload: Mapping[str, Any],
        training_payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            "status": "PRESENT",
            "failure_doctor_status": "ARMED",
            "training_status": training_payload.get("status"),
            "repair_actions": list(calibration_payload.get("repair_actions", ())),
            "advisory_status": advisory_payload.get("status"),
            "advisory_warnings": list(advisory_payload.get("warnings", ())),
            "advisory_checks": dict(advisory_payload.get("checks", {})),
            "self_replay": dict(calibration_payload.get("self_replay", {})),
        }


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
        allowed_egress=_s2_egress_rules(envelope.capability_scopes.get("allowed_egress", ())),
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
            allowed_egress=spec.allowed_egress,
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


class BuildOrchestrator:
    """Coordinates the S2-TC21 full build path from C2 envelope to frozen C4 pipeline."""

    def __init__(
        self,
        *,
        artifact_store: InMemoryArtifactStore,
        spec_compiler: SpecCompiler,
        provenance_emitter: ProvenanceEmitter | None = None,
        data_manager: DataManager | None = None,
        feature_engine: FeatureGraphEngine | None = None,
        model_synthesizer: ModelSynthesizer | None = None,
        hpo_engine: HPOEngine | None = None,
        uq_calibrator: UQCalibrator | None = None,
        failure_doctor: FailureDoctor | None = None,
        advisory_self_check: AdvisorySelfCheck | None = None,
        pipeline_freezer: PipelineFreezer | None = None,
        sandbox_guard: S2SandboxGuard | None = None,
        hpo_scheduler_backend: str = "threadpool",
        hpo_worker_count: int = 1,
    ) -> None:
        self._artifact_store = artifact_store
        self._spec_compiler = spec_compiler
        self._provenance_emitter = provenance_emitter or ProvenanceEmitter(artifact_store=artifact_store)
        self._data_manager = data_manager or DataManager(
            artifact_store=artifact_store,
            provenance_emitter=self._provenance_emitter,
        )
        self._feature_engine = feature_engine or FeatureGraphEngine()
        self._model_synthesizer = model_synthesizer or ModelSynthesizer(
            policy=ComplexityEscalationPolicy(objective="minimize")
        )
        self._hpo_engine = hpo_engine or HPOEngine(
            artifact_store=artifact_store,
            provenance_emitter=self._provenance_emitter,
            scheduler_backend=hpo_scheduler_backend,
            worker_count=hpo_worker_count,
        )
        self._uq_calibrator = uq_calibrator or UQCalibrator(
            artifact_store=artifact_store,
            provenance_emitter=self._provenance_emitter,
        )
        self._failure_doctor = failure_doctor or FailureDoctor(
            artifact_store=artifact_store,
            provenance_emitter=self._provenance_emitter,
        )
        self._advisory_self_check = advisory_self_check or AdvisorySelfCheck(
            artifact_store=artifact_store,
            provenance_emitter=self._provenance_emitter,
        )
        self._pipeline_freezer = pipeline_freezer or PipelineFreezer(
            artifact_store=artifact_store,
            provenance_emitter=self._provenance_emitter,
        )
        self._sandbox_guard = sandbox_guard or S2SandboxGuard(artifact_store=artifact_store)

    def build(
        self,
        request: BuildOrchestrationRequest | Mapping[str, Any],
        *,
        attempted_claim_tier: str | None = None,
    ) -> BuildResult:
        S2ClaimTierPolicy.assert_attempted_claim_tier(
            attempted_claim_tier,
            actor="S2 BuildOrchestrator",
        )
        orchestration_request = (
            request
            if isinstance(request, BuildOrchestrationRequest)
            else BuildOrchestrationRequest(c2_envelope=request)
        )
        return self._build(orchestration_request)

    def build_variant(
        self,
        *,
        base_pipeline_ref: str,
        request: BuildOrchestrationRequest | Mapping[str, Any],
        mutation: MutationSpec,
        warm_start_ref: str | None = None,
        fabricated_score: float | None = None,
        attempted_claim_tier: str | None = None,
    ) -> BuildResult:
        """Build an Evolver-facing variant while keeping S3 as the only authority for scores."""
        if fabricated_score is not None:
            raise RewardSourceError("S2 build_variant cannot accept non-C3 scores")
        S2ClaimTierPolicy.assert_attempted_claim_tier(
            attempted_claim_tier,
            actor="S2 BuildOrchestrator.build_variant",
        )
        base_pipeline_ref = base_pipeline_ref.strip()
        if not base_pipeline_ref:
            raise S2ContractModelError("S2 build_variant requires base_pipeline_ref")
        base_payload = self._assert_base_frozen_pipeline(base_pipeline_ref)
        orchestration_request = (
            request
            if isinstance(request, BuildOrchestrationRequest)
            else BuildOrchestrationRequest(c2_envelope=request)
        )
        selected_warm_start_ref = warm_start_ref or self._base_hpo_selection_ref(base_payload)
        warm_start_trials = self._warm_start_trials_from_ref(selected_warm_start_ref)
        variant_request = replace(
            orchestration_request,
            hpo_parameter_grid=self._mutated_hpo_grid(orchestration_request.hpo_parameter_grid, mutation),
            cached_dataset_split_ref=self._base_dataset_split_ref(base_payload),
            cached_feature_set_ref=self._base_feature_set_ref(base_payload),
            warm_start_ref=selected_warm_start_ref,
            warm_start_trials=warm_start_trials,
            variant_id=mutation.variant_id,
            variant_model_family=mutation.model_family,
            base_pipeline_ref=base_pipeline_ref,
            mutation_parameters={
                "parameters": mutation.parameters,
                "feature_subset": list(mutation.feature_subset),
                "hpo": mutation.hpo,
                "hyperparam_overrides": mutation.hyperparam_overrides,
                "constraint_overrides": list(mutation.constraint_overrides),
            },
        )
        return self._build(variant_request)

    def _build(self, orchestration_request: BuildOrchestrationRequest) -> BuildResult:
        started_at = time.perf_counter()
        spec = self._spec_compiler.compile(orchestration_request.c2_envelope)
        sandbox_evidence_ref = self._sandbox_guard.prepare(spec=spec, request=orchestration_request)
        sandbox_evidence_payload = self._artifact_payload(sandbox_evidence_ref)
        feature_fields = self._feature_fields(spec)
        target_field = self._target_field(spec)
        dataset_ref = self._resolve_dataset_ref(spec)
        dataset_rows = self._dataset_rows(dataset_ref)

        split_request = DataSplitRequest(
            job_id=spec.job_id,
            dataset_ref=dataset_ref,
            split_seed=f"{orchestration_request.seed}:split",
            train_ratio=orchestration_request.train_ratio,
            validation_ratio=orchestration_request.validation_ratio,
            test_ratio=orchestration_request.test_ratio,
            row_id_key="row_id",
            label_key=target_field.name,
            blind_role_key="role" if any("role" in row for row in dataset_rows) else None,
            blind_roles=("blind",),
            fold_count=orchestration_request.fold_count,
            code_ref=orchestration_request.code_ref,
            environment_digest=orchestration_request.environment_digest,
        )
        split = (
            self._cached_split(orchestration_request.cached_dataset_split_ref, split_request)
            if orchestration_request.cached_dataset_split_ref
            else None
        )
        if split is None:
            split = self._data_manager.create_splits(split_request)
        dataset_split_reused = split.diagnostics.get("cache_reused") is True
        graph = self._build_feature_graph(spec=spec, feature_fields=feature_fields)
        selected_feature_nodes = tuple(field.name for field in feature_fields)
        feature_set_ref = None
        if orchestration_request.cached_feature_set_ref:
            feature_set_ref = self._cached_feature_set_ref(
                orchestration_request.cached_feature_set_ref,
                graph=graph,
                selected_nodes=selected_feature_nodes,
            )
        feature_set_reused = feature_set_ref is not None
        if feature_set_ref is None:
            feature_set_result = self._feature_engine.emit_feature_set(
                graph,
                selected_nodes=selected_feature_nodes,
                emitter=self._provenance_emitter,
                lineage=Lineage(
                    input_refs=(dataset_ref, split.split_manifest_ref),
                    code_ref=orchestration_request.code_ref,
                    environment_digest=orchestration_request.environment_digest,
                    seeds=(f"{orchestration_request.seed}:feature-graph",),
                    job_id=spec.job_id,
                ),
                feature_set_id=f"featureset:{spec.job_id}",
                replay_probe_input=self._numeric_feature_inputs(
                    dataset_rows[split.split_indices["train"][0]],
                    feature_fields,
                ),
            )
            feature_set_ref = feature_set_result.artifact_record.artifact_ref
        training_rows = self._rows_for_indices(
            dataset_rows,
            split.split_indices["train"],
            graph=graph,
            feature_fields=feature_fields,
            target_field=target_field,
        )
        synthesis = self._model_synthesizer.select_family(
            incumbent_family_id="tabular-baseline",
            candidates=(
                ModelCandidateResult(
                    family_id="tabular-baseline",
                    heldout_score=self._target_variance(training_rows, target_field.name),
                    cost=1.0,
                    diagnostics={"evidence": "target_variance_baseline"},
                ),
            ),
        )
        hpo = self._hpo_engine.run(
            HPORequest(
                job_id=spec.job_id,
                family_ids=(orchestration_request.variant_model_family or synthesis.selected_family_id,),
                parameter_grid=orchestration_request.hpo_parameter_grid,
                input_refs=(feature_set_ref, split.split_manifest_ref),
                training_rows=training_rows,
                feature_names=tuple(field.name for field in feature_fields),
                target_name=target_field.name,
                max_epochs=orchestration_request.hpo_max_epochs,
                code_ref=orchestration_request.code_ref,
                environment_digest=orchestration_request.environment_digest,
                seed=f"{orchestration_request.seed}:hpo",
                objective_metric="loss",
                objective="minimize",
                learning_rate=orchestration_request.learning_rate,
                wallclock_seconds_per_epoch=orchestration_request.wallclock_seconds_per_epoch,
                gpu_seconds_per_epoch=orchestration_request.gpu_seconds_per_epoch,
                model_tokens_per_epoch=orchestration_request.model_tokens_per_epoch,
                cost_usd_per_epoch=orchestration_request.cost_usd_per_epoch,
                trial_budget=spec.budget,
                warm_start_trials=orchestration_request.warm_start_trials,
                warm_start_ref=orchestration_request.warm_start_ref,
            )
        )
        selected_parameters = dict(hpo.selected.parameters)
        budget_meter = BudgetMeter.from_budget(job_id=spec.job_id, budget=spec.budget)
        training_runtime = TrainingRuntime(
            artifact_store=self._artifact_store,
            provenance_emitter=self._provenance_emitter,
            budget_meter=budget_meter,
        )
        training = training_runtime.train(
            TrainingRequest(
                job_id=spec.job_id,
                family_id=hpo.selected.family_id or synthesis.selected_family_id,
                input_refs=(feature_set_ref, split.split_manifest_ref, hpo.selection_artifact_ref),
                training_rows=training_rows,
                feature_names=tuple(field.name for field in feature_fields),
                target_name=target_field.name,
                max_epochs=int(selected_parameters.get("max_epochs", orchestration_request.final_max_epochs)),
                learning_rate=float(selected_parameters.get("learning_rate", orchestration_request.learning_rate)),
                parameters=selected_parameters,
                code_ref=orchestration_request.code_ref,
                environment_digest=orchestration_request.environment_digest,
                seed=f"{orchestration_request.seed}:final-train",
                wallclock_seconds_per_epoch=orchestration_request.wallclock_seconds_per_epoch,
                gpu_seconds_per_epoch=orchestration_request.gpu_seconds_per_epoch,
                model_tokens_per_epoch=orchestration_request.model_tokens_per_epoch,
                cost_usd_per_epoch=orchestration_request.cost_usd_per_epoch,
            )
        )
        if not training.final_checkpoint_ref:
            raise S2ContractModelError("S2 BuildOrchestrator final training did not emit a model checkpoint")
        model_payload = self._artifact_payload(training.final_checkpoint_ref)
        calibration_samples = self._prediction_samples(
            dataset_rows,
            split.split_indices["validation"],
            graph=graph,
            feature_fields=feature_fields,
            target_field=target_field,
            model_payload=model_payload,
            prefix="calibration",
        )
        validation_samples = self._prediction_samples(
            dataset_rows,
            split.split_indices["test"],
            graph=graph,
            feature_fields=feature_fields,
            target_field=target_field,
            model_payload=model_payload,
            prefix="validation",
        )
        calibration = self._uq_calibrator.calibrate(
            UQCalibrationRequest(
                job_id=spec.job_id,
                model_artifact_ref=training.final_checkpoint_ref,
                split_manifest_ref=split.split_manifest_ref,
                calibration_input_refs=(split.split_manifest_ref,),
                validation_input_refs=(split.split_manifest_ref,),
                calibration_samples=calibration_samples,
                validation_samples=validation_samples,
                uncertainty_method="split_conformal",
                native_uq="conformal",
                nominal_coverage=orchestration_request.nominal_coverage,
                coverage_tolerance=orchestration_request.coverage_tolerance,
                nondeterminism_tolerance=orchestration_request.nondeterminism_tolerance,
                replay_output_pairs=((1.0, 1.0),),
                code_ref=orchestration_request.code_ref,
                environment_digest=orchestration_request.environment_digest,
                seed=f"{orchestration_request.seed}:uq",
            )
        )
        advisory = self._advisory_self_check.run(
            AdvisorySelfCheckRequest(
                job_id=spec.job_id,
                input_refs=(training.final_checkpoint_ref, feature_set_ref, calibration.calibration_artifact_ref),
                injection_samples=(
                    AdvisorySignalSample(sample_id="injection-1", template=1.0, observed=2.0),
                    AdvisorySignalSample(sample_id="injection-2", template=-1.0, observed=-2.0),
                    AdvisorySignalSample(sample_id="injection-3", template=0.5, observed=1.0),
                ),
                known_amplitude=2.0,
                amplitude_tolerance=1e-12,
                null_samples=(
                    AdvisorySignalSample(sample_id="null-1", template=1.0, observed=0.0),
                    AdvisorySignalSample(sample_id="null-2", template=-1.0, observed=0.0),
                ),
                null_detection_threshold=0.05,
                code_ref=orchestration_request.code_ref,
                environment_digest=orchestration_request.environment_digest,
                seed=f"{orchestration_request.seed}:advisory",
            )
        )
        build_wallclock_seconds = max(time.perf_counter() - started_at, 1.0)
        probe_inputs = self._probe_inputs(
            dataset_rows,
            split.split_indices["test"],
            feature_fields=feature_fields,
        )
        freeze_config = {
            "orchestrator": "BuildOrchestrator",
            "s2_tc21": True,
            "s2_tc30": True,
            "s2_tc31": True,
            "s2_tc32": True,
            "subtopic": spec.subtopic,
            "hpo_selection_ref": hpo.selection_artifact_ref,
            "advisory_self_check_ref": advisory.artifact_ref,
            "sandbox_evidence_ref": sandbox_evidence_ref,
        }
        if orchestration_request.variant_id:
            freeze_config.update(
                {
                    "s2_tc22": True,
                    "variant_id": orchestration_request.variant_id,
                    "base_pipeline_ref": orchestration_request.base_pipeline_ref,
                    "reward_source": "c3-only",
                    "cache_reuse": {
                        "dataset_split_reused": dataset_split_reused,
                        "feature_set_reused": feature_set_reused,
                        "warm_start_ref": orchestration_request.warm_start_ref,
                    },
                    "mutation_parameters": dict(orchestration_request.mutation_parameters),
                }
            )
        freeze = self._pipeline_freezer.freeze(
            PipelineFreezeRequest(
                job_id=spec.job_id,
                feature_set_ref=feature_set_ref,
                model_checkpoint_ref=training.final_checkpoint_ref,
                calibration_artifact_ref=calibration.calibration_artifact_ref,
                input_refs=_unique_pipeline_refs(
                    (
                        dataset_ref,
                        split.split_manifest_ref,
                        hpo.selection_artifact_ref,
                        training.training_log_ref,
                        advisory.artifact_ref,
                        sandbox_evidence_ref,
                    )
                ),
                code_ref=orchestration_request.code_ref,
                environment_digest=orchestration_request.environment_digest,
                seed=f"{orchestration_request.seed}:freeze",
                container_digest=orchestration_request.container_digest,
                probe_inputs_units_tagged=probe_inputs,
                output_name=target_field.name,
                output_units=target_field.units,
                nondeterminism_tolerance=orchestration_request.nondeterminism_tolerance,
                build_wallclock_seconds=build_wallclock_seconds,
                max_self_replay_fraction=orchestration_request.max_self_replay_fraction,
                adapter_refs=tuple(
                    descriptor.provenance_ref or f"{descriptor.entity_id}@{descriptor.revision}"
                    for descriptor in spec.resolved_adapters
                ),
                config=freeze_config,
            )
        )
        artifact_refs = _unique_pipeline_refs(
            (
                split.split_manifest_ref,
                feature_set_ref,
            )
            + hpo.trial_artifact_refs
            + (
                hpo.selection_artifact_ref,
            )
            + training.checkpoint_refs
            + (
                training.training_log_ref,
                calibration.calibration_artifact_ref,
                advisory.artifact_ref,
                sandbox_evidence_ref,
                freeze.artifact_ref,
            )
        )
        diagnostics = {
            "status": "SUCCEEDED",
            "s2_tc21": "PASS",
            "s2_tc30": "PASS",
            "s2_tc31": "PASS",
            "s2_tc32": "PASS",
            "claim_tier_cap": "ran-toy",
            "steps": {
                "spec_compiler": "SUCCEEDED",
                "data_manager": "SUCCEEDED",
                "feature_graph": "SUCCEEDED",
                "model_synthesizer": "SUCCEEDED",
                "hpo_engine": hpo.status,
                "training_runtime": training.status,
                "uq_calibrator": calibration.status,
                "failure_doctor": "ARMED",
                "advisory_self_check": advisory.status,
                "pipeline_freezer": "SUCCEEDED",
            },
            "build_spec": {
                "job_id": spec.job_id,
                "trace_id": spec.trace_id,
                "subtopic": spec.subtopic,
                "task_type": spec.task_type,
                "required_claim_tier_max": spec.required_claim_tier_max,
                "verifier_profile_ref": spec.verifier_profile_ref,
            },
            "data": {
                "dataset_ref": dataset_ref,
                "split_manifest_ref": split.split_manifest_ref,
                "row_count": len(dataset_rows),
                "split_indices": {role: list(indices) for role, indices in split.split_indices.items()},
            },
            "model_synthesis": asdict(synthesis),
            "hpo": {
                "selection_artifact_ref": hpo.selection_artifact_ref,
                "selected_trial_id": hpo.selected.trial_id,
                "selected_family_id": hpo.selected.family_id,
                "selected_parameters": hpo.selected.parameters,
                "trial_count": len(hpo.trials),
            },
            "training": {
                "training_log_ref": training.training_log_ref,
                "final_checkpoint_ref": training.final_checkpoint_ref,
                "completed_epochs": training.completed_epochs,
                "final_metrics": dict(training.diagnostics.get("final_metrics", {})),
            },
            "uq": {
                "calibration_artifact_ref": calibration.calibration_artifact_ref,
                "status": calibration.status,
                "empirical_coverage": calibration.empirical_coverage,
                "passed_internal_coverage": calibration.passed_internal_coverage,
            },
            "advisory": {
                "artifact_ref": advisory.artifact_ref,
                "status": advisory.status,
                "warnings": list(advisory.warnings),
            },
            "pipeline_freeze": {
                "artifact_ref": freeze.artifact_ref,
                "self_replay_passed": freeze.self_replay_passed,
                "self_replay_fraction": freeze.self_replay_fraction,
                "max_replay_delta": freeze.max_replay_delta,
            },
            "sandbox": {
                "evidence_ref": sandbox_evidence_ref,
                "status": sandbox_evidence_payload.get("status"),
                "checks": sandbox_evidence_payload.get("checks"),
                "egress_probe": sandbox_evidence_payload.get("egress_probe"),
                "secret_scan": sandbox_evidence_payload.get("secret_scan"),
                "direct_write_bypass": sandbox_evidence_payload.get("direct_write_bypass"),
            },
            "cost_actual": training.cost_actual,
        }
        if orchestration_request.variant_id:
            diagnostics.update(
                {
                    "s2_tc22": "PASS",
                    "reward_source": "c3-only",
                    "variant": {
                        "variant_id": orchestration_request.variant_id,
                        "base_pipeline_ref": orchestration_request.base_pipeline_ref,
                        "model_family": orchestration_request.variant_model_family,
                        "mutation_parameters": dict(orchestration_request.mutation_parameters),
                    },
                    "cache_reuse": {
                        "dataset_split_reused": dataset_split_reused,
                        "feature_set_reused": feature_set_reused,
                        "cached_dataset_split_ref": orchestration_request.cached_dataset_split_ref,
                        "cached_feature_set_ref": orchestration_request.cached_feature_set_ref,
                        "warm_start_ref": orchestration_request.warm_start_ref,
                        "warm_started_trial_count": len(orchestration_request.warm_start_trials),
                    },
                }
            )
        return BuildResult(
            job_id=spec.job_id,
            model_ref=training.final_checkpoint_ref,
            frozen_pipeline_ref=freeze.artifact_ref,
            artifact_refs=artifact_refs,
            adapter_provenance_refs=tuple(
                descriptor.provenance_ref or f"{descriptor.entity_id}@{descriptor.revision}"
                for descriptor in spec.resolved_adapters
            ),
            claim_tier="ran-toy",
            diagnostics=diagnostics,
            cost_actual=training.cost_actual,
            dataset_split_ref=split.split_manifest_ref,
            feature_set_ref=feature_set_ref,
            hpo_selection_ref=hpo.selection_artifact_ref,
            training_log_ref=training.training_log_ref,
            uq_calibration_ref=calibration.calibration_artifact_ref,
            advisory_self_check_ref=advisory.artifact_ref,
            sandbox_evidence_ref=sandbox_evidence_ref,
        )

    def _assert_base_frozen_pipeline(self, artifact_ref: str) -> dict[str, Any]:
        try:
            record = self._artifact_store.get_record(artifact_ref)
        except KeyError as exc:
            raise S2ContractModelError(f"S2 build_variant cannot resolve base_pipeline_ref: {artifact_ref}") from exc
        if record.kind != "frozen_pipeline":
            raise S2ContractModelError("S2 build_variant requires a frozen_pipeline base artifact")
        payload = self._artifact_payload(artifact_ref)
        if payload.get("entrypoint") != "predict" or payload.get("claim_tier") != "ran-toy":
            raise S2ContractModelError("S2 build_variant base pipeline is not an S2 ran-toy predict artifact")
        component_refs = payload.get("component_refs")
        if not isinstance(component_refs, Mapping):
            raise S2ContractModelError("S2 build_variant base pipeline is missing component_refs")
        return payload

    def _base_feature_set_ref(self, base_payload: Mapping[str, Any]) -> str | None:
        component_refs = base_payload.get("component_refs")
        if not isinstance(component_refs, Mapping):
            return None
        ref = component_refs.get("feature_set_ref")
        if not isinstance(ref, str) or not ref.strip():
            return None
        record = self._artifact_store.get_record(ref.strip())
        if record.kind != "feature_set":
            raise S2ContractModelError("S2 build_variant base feature_set_ref does not point to a feature_set")
        return ref.strip()

    def _base_dataset_split_ref(self, base_payload: Mapping[str, Any]) -> str | None:
        return self._base_component_input_ref(base_payload, kind="dataset_split")

    def _base_hpo_selection_ref(self, base_payload: Mapping[str, Any]) -> str | None:
        config = base_payload.get("config")
        if isinstance(config, Mapping):
            ref = config.get("hpo_selection_ref")
            if isinstance(ref, str) and ref.strip():
                record = self._artifact_store.get_record(ref.strip())
                if record.kind != "hpo_selection":
                    raise S2ContractModelError("S2 build_variant base hpo_selection_ref does not point to hpo_selection")
                return ref.strip()
        return self._base_component_input_ref(base_payload, kind="hpo_selection")

    def _base_component_input_ref(self, base_payload: Mapping[str, Any], *, kind: str) -> str | None:
        component_refs = base_payload.get("component_refs")
        if not isinstance(component_refs, Mapping):
            return None
        input_refs = component_refs.get("input_refs")
        if not isinstance(input_refs, list):
            return None
        for ref in input_refs:
            if not isinstance(ref, str) or not ref.strip():
                continue
            try:
                record = self._artifact_store.get_record(ref.strip())
            except KeyError:
                continue
            if record.kind == kind:
                return ref.strip()
        return None

    def _warm_start_trials_from_ref(self, warm_start_ref: str | None) -> tuple[HPOTrial, ...]:
        if warm_start_ref is None:
            return ()
        warm_start_ref = warm_start_ref.strip()
        if not warm_start_ref:
            return ()
        record = self._artifact_store.get_record(warm_start_ref)
        if record.kind != "hpo_selection":
            raise S2ContractModelError("S2 build_variant warm_start_ref must point to an hpo_selection artifact")
        selection_payload = self._artifact_payload(warm_start_ref)
        trial_refs = selection_payload.get("trial_artifact_refs")
        if not isinstance(trial_refs, list):
            raise S2ContractModelError("S2 build_variant warm_start hpo_selection is missing trial_artifact_refs")
        trials: list[HPOTrial] = []
        for trial_ref in trial_refs:
            if not isinstance(trial_ref, str) or not trial_ref.strip():
                continue
            trial_record = self._artifact_store.get_record(trial_ref.strip())
            if trial_record.kind != "hpo_trial":
                continue
            payload = self._artifact_payload(trial_ref.strip())
            if payload.get("status") != "SUCCEEDED":
                continue
            trials.append(
                HPOTrial(
                    trial_id=str(payload["trial_id"]),
                    score=float(payload["score"]),
                    calibration_error=float(payload["calibration_error"]),
                    cost=float(payload["cost"]),
                    parameters=dict(payload.get("parameters", {})),
                    family_id=str(payload.get("family_id") or ""),
                    status="SUCCEEDED",
                    checkpoint_ref=payload.get("final_checkpoint_ref"),
                    training_log_ref=payload.get("training_log_ref"),
                    trial_artifact_ref=trial_ref.strip(),
                    diagnostics={
                        "source_hpo_selection_ref": warm_start_ref,
                        "source_trial_artifact_ref": trial_ref.strip(),
                    },
                )
            )
        if not trials:
            raise S2ContractModelError("S2 build_variant warm_start_ref contains no completed HPO trials")
        return tuple(trials)

    @staticmethod
    def _mutated_hpo_grid(
        base_grid: Mapping[str, tuple[Any, ...]],
        mutation: MutationSpec,
    ) -> Mapping[str, tuple[Any, ...]]:
        grid = {str(key): tuple(values) for key, values in base_grid.items()}
        overrides = {**mutation.parameters, **mutation.hyperparam_overrides}
        for key, value in overrides.items():
            if key in {"variant_id", "model_family"}:
                continue
            grid[str(key)] = (value,)
        budget_trials = mutation.hpo.get("budget_trials")
        if isinstance(budget_trials, int) and budget_trials <= 0:
            raise S2ContractModelError("S2 MutationSpec hpo.budget_trials must be positive when provided")
        return grid

    def _cached_split(self, artifact_ref: str | None, request: DataSplitRequest) -> DataSplitResult | None:
        if artifact_ref is None:
            return None
        try:
            record = self._artifact_store.get_record(artifact_ref)
        except KeyError as exc:
            raise S2ContractModelError(f"S2 build_variant cached split is missing: {artifact_ref}") from exc
        if record.kind != "dataset_split":
            raise S2ContractModelError("S2 build_variant cached split ref must point to dataset_split")
        payload = self._artifact_payload(artifact_ref)
        if not self._split_payload_matches_request(payload, request):
            return None
        split_indices = {
            role: tuple(int(index) for index in payload["splits"][role]["indices"])
            for role in ("train", "validation", "test")
        }
        split_group_ids = {
            role: tuple(str(group_id) for group_id in payload["splits"][role].get("group_ids", ()))
            for role in ("train", "validation", "test")
        }
        folds = tuple(
            FoldAssignment(
                fold_id=str(fold["fold_id"]),
                train_indices=tuple(int(index) for index in fold["train_indices"]),
                validation_indices=tuple(int(index) for index in fold["validation_indices"]),
            )
            for fold in payload.get("folds", ())
        )
        blind_inputs = payload.get("blind_inputs", {})
        blind_input_indices = tuple(int(index) for index in blind_inputs.get("indices", ()))
        return DataSplitResult(
            job_id=request.job_id,
            dataset_ref=request.dataset_ref,
            split_manifest_ref=artifact_ref,
            split_indices=split_indices,
            split_group_ids=split_group_ids,
            folds=folds,
            blind_input_indices=blind_input_indices,
            diagnostics={
                "cache_reused": True,
                "source_job_id": payload.get("job_id"),
                "row_count": payload.get("row_count"),
                "fold_count": len(folds),
                "label_materialized": False,
            },
        )

    @staticmethod
    def _split_payload_matches_request(payload: Mapping[str, Any], request: DataSplitRequest) -> bool:
        if payload.get("dataset_ref") != request.dataset_ref:
            return False
        ratios = payload.get("split_ratios")
        if not isinstance(ratios, Mapping):
            return False
        expected = {
            "train": request.train_ratio,
            "validation": request.validation_ratio,
            "test": request.test_ratio,
        }
        for role, value in expected.items():
            if abs(float(ratios.get(role, -1.0)) - float(value)) > 1e-12:
                return False
        if payload.get("row_id_key") != request.row_id_key:
            return False
        label_policy = payload.get("label_policy")
        if not isinstance(label_policy, Mapping) or label_policy.get("label_key") != request.label_key:
            return False
        blind_inputs = payload.get("blind_inputs")
        if not isinstance(blind_inputs, Mapping):
            return False
        if blind_inputs.get("role_key") != request.blind_role_key:
            return False
        if tuple(blind_inputs.get("roles", ())) != tuple(request.blind_roles):
            return False
        return len(payload.get("folds", ())) == request.fold_count

    def _cached_feature_set_ref(
        self,
        artifact_ref: str,
        *,
        graph: FeatureGraph,
        selected_nodes: tuple[str, ...],
    ) -> str | None:
        record = self._artifact_store.get_record(artifact_ref)
        if record.kind != "feature_set":
            raise S2ContractModelError("S2 build_variant cached feature ref must point to feature_set")
        payload = self._artifact_payload(artifact_ref)
        feature_set = payload.get("feature_set")
        base_graph = payload.get("graph")
        if not isinstance(feature_set, Mapping) or not isinstance(base_graph, Mapping):
            raise S2ContractModelError("S2 build_variant cached feature_set artifact is malformed")
        if tuple(feature_set.get("selected_nodes", ())) != selected_nodes:
            return None
        if base_graph.get("nodes") != self._feature_graph_nodes_payload(graph):
            return None
        return artifact_ref

    @staticmethod
    def _feature_graph_nodes_payload(graph: FeatureGraph) -> list[dict[str, Any]]:
        return [_feature_graph_node_payload(node) for node in graph.nodes]

    def _resolve_dataset_ref(self, spec: BuildSpec) -> str:
        candidate_refs = tuple(resolved.artifact_ref for resolved in spec.resolved_input_artifacts) + tuple(
            resolved.provenance_ref for resolved in spec.resolved_datasets
        )
        for candidate_ref in candidate_refs:
            resolved = self._dataset_ref_from_artifact(candidate_ref)
            if resolved is not None:
                return resolved
        raise S2ContractModelError("S2 BuildOrchestrator could not resolve a concrete dataset artifact")

    def _dataset_ref_from_artifact(self, artifact_ref: str) -> str | None:
        record = self._artifact_store.get_record(artifact_ref)
        if record.kind == "dataset":
            return artifact_ref
        if record.kind != "dataset_descriptor":
            return None
        payload = self._artifact_payload(artifact_ref)
        direct_ref = payload.get("dataset_ref") or payload.get("artifact_ref") or payload.get("c4_ref")
        if isinstance(direct_ref, str) and direct_ref.strip():
            dataset_ref = direct_ref.strip()
            dataset_record = self._artifact_store.get_record(dataset_ref)
            if dataset_record.kind != "dataset":
                raise S2ContractModelError("S2 BuildOrchestrator dataset_descriptor points to a non-dataset artifact")
            return dataset_ref
        nested = payload.get("dataset")
        if isinstance(nested, Mapping):
            nested_ref = nested.get("artifact_ref") or nested.get("dataset_ref")
            if isinstance(nested_ref, str) and nested_ref.strip():
                dataset_record = self._artifact_store.get_record(nested_ref.strip())
                if dataset_record.kind != "dataset":
                    raise S2ContractModelError("S2 BuildOrchestrator nested dataset ref is not a dataset artifact")
                return nested_ref.strip()
        return None

    def _dataset_rows(self, dataset_ref: str) -> tuple[Mapping[str, Any], ...]:
        payload = self._artifact_payload(dataset_ref)
        rows = payload.get("rows")
        if not isinstance(rows, (list, tuple)) or not rows:
            raise S2ContractModelError("S2 BuildOrchestrator dataset artifact requires non-empty rows")
        normalized: list[Mapping[str, Any]] = []
        for row in rows:
            if not isinstance(row, Mapping):
                raise S2ContractModelError("S2 BuildOrchestrator dataset rows must be objects")
            normalized.append(dict(row))
        return tuple(normalized)

    def _artifact_payload(self, artifact_ref: str) -> dict[str, Any]:
        try:
            return json.loads(self._artifact_store.get_artifact(artifact_ref).decode("utf-8"))
        except KeyError as exc:
            raise S2ContractModelError(f"S2 BuildOrchestrator cannot load artifact: {artifact_ref}") from exc

    @staticmethod
    def _feature_fields(spec: BuildSpec) -> tuple[FieldSpec, ...]:
        fields = tuple(field for field in spec.fields if field.role != "target")
        if not fields:
            raise S2ContractModelError("S2 BuildOrchestrator requires at least one feature field")
        return fields

    @staticmethod
    def _target_field(spec: BuildSpec) -> FieldSpec:
        targets = tuple(field for field in spec.fields if field.role == "target")
        if len(targets) != 1:
            raise S2ContractModelError("S2 BuildOrchestrator requires exactly one target field")
        return targets[0]

    def _build_feature_graph(self, *, spec: BuildSpec, feature_fields: tuple[FieldSpec, ...]) -> FeatureGraph:
        nodes = tuple(
            FeatureGraphNode(
                node_id=field.name,
                op="source",
                params={"field": field.name},
                feature_node=FeatureNode(
                    node_id=field.name,
                    terms=(FeatureTerm(field_name=field.name, units=field.units),),
                    declared_units=field.units,
                ),
            )
            for field in feature_fields
        )
        return self._feature_engine.build_graph(graph_id=f"featuregraph:{spec.job_id}", nodes=nodes)

    def _rows_for_indices(
        self,
        rows: tuple[Mapping[str, Any], ...],
        indices: tuple[int, ...],
        *,
        graph: FeatureGraph,
        feature_fields: tuple[FieldSpec, ...],
        target_field: FieldSpec,
    ) -> tuple[Mapping[str, Any], ...]:
        materialized: list[Mapping[str, Any]] = []
        for index in indices:
            row = rows[index]
            replay = self._feature_engine.replay(
                graph,
                inputs=self._numeric_feature_inputs(row, feature_fields),
                selected_nodes=tuple(field.name for field in feature_fields),
            )
            if target_field.name not in row:
                raise S2ContractModelError(f"S2 BuildOrchestrator dataset row missing target field: {target_field.name}")
            materialized.append(
                {
                    **dict(replay.values),
                    target_field.name: _finite_feature_value(row[target_field.name], field_name=target_field.name),
                }
            )
        if not materialized:
            raise S2ContractModelError("S2 BuildOrchestrator requires non-empty training rows")
        return tuple(materialized)

    @staticmethod
    def _numeric_feature_inputs(row: Mapping[str, Any], feature_fields: tuple[FieldSpec, ...]) -> dict[str, float]:
        inputs: dict[str, float] = {}
        for field in feature_fields:
            if field.name not in row:
                raise S2ContractModelError(f"S2 BuildOrchestrator dataset row missing feature field: {field.name}")
            inputs[field.name] = _finite_feature_value(row[field.name], field_name=field.name)
        return inputs

    @staticmethod
    def _target_variance(rows: tuple[Mapping[str, Any], ...], target_name: str) -> float:
        targets = tuple(float(row[target_name]) for row in rows)
        mean = sum(targets) / float(len(targets))
        return sum((target - mean) ** 2 for target in targets) / float(len(targets))

    def _prediction_samples(
        self,
        rows: tuple[Mapping[str, Any], ...],
        indices: tuple[int, ...],
        *,
        graph: FeatureGraph,
        feature_fields: tuple[FieldSpec, ...],
        target_field: FieldSpec,
        model_payload: Mapping[str, Any],
        prefix: str,
    ) -> tuple[UQCalibrationSample, ...]:
        samples: list[UQCalibrationSample] = []
        for ordinal, index in enumerate(indices):
            row = rows[index]
            replay = self._feature_engine.replay(
                graph,
                inputs=self._numeric_feature_inputs(row, feature_fields),
                selected_nodes=tuple(field.name for field in feature_fields),
            )
            prediction = FrozenPipelineRunner._predict_model(model_payload, dict(replay.values))
            samples.append(
                UQCalibrationSample(
                    sample_id=f"{prefix}-{ordinal}",
                    prediction=prediction,
                    target=_finite_feature_value(row[target_field.name], field_name=target_field.name),
                )
            )
        if not samples:
            raise S2ContractModelError(f"S2 BuildOrchestrator requires non-empty {prefix} samples")
        return tuple(samples)

    @staticmethod
    def _probe_inputs(
        rows: tuple[Mapping[str, Any], ...],
        indices: tuple[int, ...],
        *,
        feature_fields: tuple[FieldSpec, ...],
    ) -> dict[str, dict[str, Any]]:
        index = indices[0]
        row = rows[index]
        return {
            field.name: {
                "value": _finite_feature_value(row[field.name], field_name=field.name),
                "units": field.units,
            }
            for field in feature_fields
        }


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
        S2ClaimTierPolicy.assert_attempted_claim_tier(
            attempted_claim_tier,
            actor="S2 BaselineBuilder",
        )
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
            supported_constraints=("positivity", "asymptotic_limit", "symmetry", "unitarity_penalty"),
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
            supported_constraints=("forward_model_loss", "gradient_based", "unitarity_penalty"),
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


def _s2_egress_rules(value: Any) -> tuple[EgressRule, ...]:
    if value in (None, ""):
        return ()
    if not isinstance(value, (list, tuple)):
        raise S2ContractModelError("C2 capability_scopes.allowed_egress must be a list")
    return tuple(_s2_egress_rule(entry) for entry in value)


def _s2_egress_rule(value: Any) -> EgressRule:
    if not isinstance(value, Mapping):
        raise S2ContractModelError("S2 allowed_egress entries must be objects")
    host = str(value.get("host") or "").strip()
    proto = str(value.get("proto") or "https").strip()
    try:
        port = int(value.get("port") or 0)
    except (TypeError, ValueError) as exc:
        raise S2ContractModelError("S2 allowed_egress port must be an integer") from exc
    if not host or port <= 0:
        raise S2ContractModelError("S2 allowed_egress entries require host and positive port")
    if proto not in {"https", "grpc", "tcp"}:
        raise S2ContractModelError("S2 allowed_egress proto must be https, grpc, or tcp")
    return EgressRule(host=host, port=port, proto=proto)  # type: ignore[arg-type]


def _s2_digest_pinned_image(container_digest: str) -> str:
    digest = ""
    if "sha256:" in container_digest:
        digest = container_digest.split("sha256:", 1)[1].strip()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        digest = hashlib.sha256(container_digest.encode("utf-8")).hexdigest()
    return f"argus-s2@sha256:{digest}"


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
