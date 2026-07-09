"""S7 compute-adapter core semantics for C6 evaluation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from typing import Any, Callable, Mapping

from .hashing import hash_json
from .s6 import CapabilityDescriptor, InMemoryRegistry, IndependenceAttestation
from .s8 import InMemoryArtifactStore, Lineage, Producer


UNIT_REGISTRY_VERSION = "argus-units-1.0.0"
_UNIT_DIMENSION_KEYS = ("energy", "frequency", "time", "cross_section")
_UNIT_DEFINITION_SPECS = {
    "dimensionless": {"dimensions": {}, "scale_to_canonical": 1.0},
    "Omega_h2": {"dimensions": {}, "scale_to_canonical": 1.0},
    "GeV": {"dimensions": {"energy": 1}, "scale_to_canonical": 1.0},
    "MeV": {"dimensions": {"energy": 1}, "scale_to_canonical": 0.001},
    "TeV": {"dimensions": {"energy": 1}, "scale_to_canonical": 1000.0},
    "Hz": {"dimensions": {"frequency": 1}, "scale_to_canonical": 1.0},
    "mHz": {"dimensions": {"frequency": 1}, "scale_to_canonical": 0.001},
    "s": {"dimensions": {"time": 1}, "scale_to_canonical": 1.0},
    "pb": {"dimensions": {"cross_section": 1}, "scale_to_canonical": 1.0},
    "fb": {"dimensions": {"cross_section": 1}, "scale_to_canonical": 0.001},
}
UNIT_REGISTRY_HASH = hash_json({"version": UNIT_REGISTRY_VERSION, "definitions": _UNIT_DEFINITION_SPECS})
UNIT_DEFINITIONS = {
    symbol: (next(iter(spec["dimensions"]), "dimensionless"), spec["scale_to_canonical"])
    for symbol, spec in _UNIT_DEFINITION_SPECS.items()
}


class S7Error(Exception):
    """Base class for S7 adapter failures."""

    def __init__(self, category: str, message: str) -> None:
        super().__init__(message)
        self.category = category
        self.message = message


class UnitsMismatchError(S7Error):
    """Raised when an input or output unit has incompatible dimensions."""

    def __init__(self, message: str) -> None:
        super().__init__("UNITS_MISMATCH", message)


class OutOfDomainError(S7Error):
    """Raised when an adapter refuses out-of-domain input."""

    def __init__(self, message: str) -> None:
        super().__init__("OUT_OF_DOMAIN", message)


class ProvenanceUnavailableError(S7Error):
    """Raised when a successful adapter call cannot be provenanced."""

    def __init__(self, message: str) -> None:
        super().__init__("PROVENANCE_UNAVAILABLE", message)


class AdapterConformanceError(S7Error):
    """Raised when an adapter implementation violates C6 postconditions."""

    def __init__(self, message: str) -> None:
        super().__init__("ADAPTER_ERROR", message)


class AdapterVersionError(S7Error):
    """Raised when adapter version negotiation cannot find a compatible version."""

    def __init__(self, message: str) -> None:
        super().__init__("VERSION_UNSUPPORTED", message)


@dataclass(frozen=True)
class S7UnitDefinition:
    symbol: str
    dimensions: tuple[int, ...]
    scale_to_canonical: float


@dataclass(frozen=True)
class S7UnitFieldSpec:
    units: str
    log_space: str | None = None


@dataclass(frozen=True)
class S7ParsedUnitExpression:
    dimensions: tuple[int, ...]
    scale_to_canonical: float


class S7UnitRegistry:
    """Frozen S7 unit registry used to normalize C6 adapter quantities."""

    def __init__(
        self,
        *,
        version: str = UNIT_REGISTRY_VERSION,
        definitions: Mapping[str, S7UnitDefinition] | None = None,
        registry_hash: str = UNIT_REGISTRY_HASH,
    ) -> None:
        self.version = version
        self.registry_hash = registry_hash
        self._definitions = dict(definitions or _default_unit_definitions())

    @classmethod
    def default(cls) -> "S7UnitRegistry":
        return cls()

    def parse(self, unit_expression: str) -> S7ParsedUnitExpression:
        expression = _unit_expression(unit_expression)
        dimensions = [0 for _ in _UNIT_DIMENSION_KEYS]
        scale = 1.0
        for symbol, exponent in _unit_expression_tokens(expression):
            if symbol == "1":
                continue
            try:
                definition = self._definitions[symbol]
            except KeyError as exc:
                raise UnitsMismatchError(f"unsupported unit: {symbol}") from exc
            for index, power in enumerate(definition.dimensions):
                dimensions[index] += power * exponent
            scale *= definition.scale_to_canonical**exponent
        return S7ParsedUnitExpression(tuple(dimensions), scale)

    def conversion_factor(self, input_units: str, expected_units: str) -> float:
        input_unit = self.parse(input_units)
        expected_unit = self.parse(expected_units)
        if input_unit.dimensions != expected_unit.dimensions:
            raise UnitsMismatchError(f"{input_units} is not compatible with {expected_units}")
        return input_unit.scale_to_canonical / expected_unit.scale_to_canonical

    def dimension_payload(self, unit_expression: str) -> dict[str, int]:
        parsed = self.parse(unit_expression)
        return {
            dimension: power
            for dimension, power in zip(_UNIT_DIMENSION_KEYS, parsed.dimensions, strict=True)
            if power
        }


@dataclass(frozen=True)
class Quantity:
    value: float
    units: str
    uncertainty: dict[str, Any] | None = None


@dataclass(frozen=True)
class NormalizedQuantity:
    value: float
    units: str
    original_units: str
    unit_registry_version: str = UNIT_REGISTRY_VERSION
    original_value: float | None = None
    unit_registry_hash: str = UNIT_REGISTRY_HASH
    dimensions: dict[str, int] | None = None
    log_space: str | None = None
    domain_value: float | None = None


@dataclass(frozen=True)
class AdapterDescriptor:
    adapter_id: str
    version: str
    input_units: dict[str, Any]
    output_units: dict[str, Any]
    validity_domain: dict[str, tuple[float, float]]
    determinism: str
    provenance_ref: str
    domain_policy: str = "flag"
    differentiable: bool = False
    cost_class: str = "standard"
    independence_tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvalRequest:
    adapter_id: str
    inputs: dict[str, Quantity]
    seed: int | None = None


@dataclass(frozen=True)
class EvalResult:
    adapter_id: str
    outputs: dict[str, Quantity]
    in_validity_domain: bool
    extrapolation_flag: bool
    provenance_ref: str
    violated_fields: tuple[str, ...] = ()
    cache_hit: bool = False
    unit_registry_version: str = UNIT_REGISTRY_VERSION
    unit_registry_hash: str = UNIT_REGISTRY_HASH


@dataclass(frozen=True)
class AdapterVersionSelection:
    requested_major: int
    selected_adapter_id: str
    selected_version: str


class SimpleAdapter:
    """Adapter wrapper around a pure normalized-input evaluation function."""

    def __init__(
        self,
        descriptor: AdapterDescriptor,
        evaluate_fn: Callable[[dict[str, NormalizedQuantity], int | None], dict[str, Quantity]],
    ) -> None:
        self.descriptor = descriptor
        self._evaluate_fn = evaluate_fn

    def evaluate(self, normalized_inputs: dict[str, NormalizedQuantity], seed: int | None = None) -> dict[str, Quantity]:
        return self._evaluate_fn(normalized_inputs, seed)


class AdapterBroker:
    """C6 broker that enforces units, domain flags, uncertainty, and provenance."""

    def __init__(self, *, artifact_store: InMemoryArtifactStore | None, unit_registry: S7UnitRegistry | None = None) -> None:
        self._artifact_store = artifact_store
        self._unit_registry = unit_registry or S7UnitRegistry.default()
        self._adapters: dict[str, SimpleAdapter] = {}

    def register(self, adapter: SimpleAdapter) -> None:
        self._adapters[adapter.descriptor.adapter_id] = adapter

    def evaluate(self, request: EvalRequest) -> EvalResult:
        adapter = self._adapters[request.adapter_id]
        descriptor = adapter.descriptor
        normalized_inputs = normalize_inputs(request.inputs, descriptor.input_units, registry=self._unit_registry)
        violated_fields = classify_validity(normalized_inputs, descriptor.validity_domain)
        if violated_fields and descriptor.domain_policy == "refuse":
            raise OutOfDomainError(f"out-of-domain fields: {', '.join(violated_fields)}")

        raw_outputs = adapter.evaluate(normalized_inputs, request.seed)
        outputs = self._normalize_outputs_conform(raw_outputs, descriptor.output_units)
        provenance_ref = self._write_provenance(descriptor, request, normalized_inputs, outputs)
        return EvalResult(
            adapter_id=descriptor.adapter_id,
            outputs=outputs,
            in_validity_domain=not violated_fields,
            extrapolation_flag=bool(violated_fields),
            provenance_ref=provenance_ref,
            violated_fields=violated_fields,
            unit_registry_version=self._unit_registry.version,
            unit_registry_hash=self._unit_registry.registry_hash,
        )

    def _write_provenance(
        self,
        descriptor: AdapterDescriptor,
        request: EvalRequest,
        normalized_inputs: dict[str, NormalizedQuantity],
        outputs: dict[str, Quantity],
    ) -> str:
        if self._artifact_store is None:
            raise ProvenanceUnavailableError("S8 artifact store unavailable")
        payload = {
            "adapter_id": descriptor.adapter_id,
            "adapter_version": descriptor.version,
            "input_hash": hash_json({key: asdict(value) for key, value in normalized_inputs.items()}),
            "output_hash": hash_json({key: asdict(value) for key, value in outputs.items()}),
            "seed": request.seed,
            "unit_registry_version": self._unit_registry.version,
            "unit_registry_hash": self._unit_registry.registry_hash,
        }
        record = self._artifact_store.create_artifact(
            kind="log",
            payload=payload,
            producer=Producer(subsystem="S7", version=descriptor.version),
            lineage=Lineage(
                input_refs=(descriptor.provenance_ref,),
                code_ref=f"adapter:{descriptor.adapter_id}@{descriptor.version}",
                environment_digest=hash_json({"adapter": descriptor.adapter_id, "version": descriptor.version}),
                seeds=(str(request.seed),) if request.seed is not None else (),
            ),
        )
        return record.artifact_ref

    def _normalize_outputs_conform(self, outputs: dict[str, Quantity], expected_units: dict[str, Any]) -> dict[str, Quantity]:
        extra_fields = set(outputs) - set(expected_units)
        if extra_fields:
            raise AdapterConformanceError(f"unexpected output fields: {', '.join(sorted(extra_fields))}")
        normalized_outputs = {}
        for field, expected_unit in expected_units.items():
            if field not in outputs:
                raise AdapterConformanceError(f"missing output field: {field}")
            quantity = outputs[field]
            if quantity.uncertainty is None:
                raise AdapterConformanceError(f"missing uncertainty for output field: {field}")
            spec = _unit_field_spec(expected_unit)
            if spec.log_space is not None:
                raise AdapterConformanceError(f"output field {field} cannot declare log-space units")
            scale = self._unit_registry.conversion_factor(quantity.units, spec.units)
            normalized = normalize_quantity(quantity, expected_unit, registry=self._unit_registry)
            normalized_outputs[field] = Quantity(
                value=normalized.value,
                units=normalized.units,
                uncertainty=_scale_uncertainty(quantity.uncertainty, scale),
            )
        return normalized_outputs


def normalize_inputs(
    inputs: dict[str, Quantity],
    expected_units: dict[str, Any],
    *,
    registry: S7UnitRegistry | None = None,
) -> dict[str, NormalizedQuantity]:
    normalized = {}
    for field, expected_unit in expected_units.items():
        if field not in inputs:
            raise UnitsMismatchError(f"missing input field: {field}")
        normalized[field] = normalize_quantity(inputs[field], expected_unit, registry=registry)
    return normalized


def normalize_quantity(
    quantity: Quantity,
    expected_unit: Any,
    *,
    registry: S7UnitRegistry | None = None,
) -> NormalizedQuantity:
    registry = registry or S7UnitRegistry.default()
    spec = _unit_field_spec(expected_unit)
    value = _finite_quantity_value(quantity.value, "quantity.value")
    if spec.log_space is not None:
        input_dimension = registry.parse(quantity.units).dimensions
        dimensionless = registry.parse("dimensionless").dimensions
        if input_dimension != dimensionless:
            raise UnitsMismatchError(f"log-space input {quantity.units} must be dimensionless")
        canonical_value = _delinearize_log_space(value, spec.log_space)
    else:
        canonical_value = value * registry.conversion_factor(quantity.units, spec.units)
    return NormalizedQuantity(
        value=canonical_value,
        units=spec.units,
        original_units=quantity.units,
        unit_registry_version=registry.version,
        original_value=value,
        unit_registry_hash=registry.registry_hash,
        dimensions=registry.dimension_payload(spec.units),
        log_space=spec.log_space,
        domain_value=value if spec.log_space is not None else canonical_value,
    )


def classify_validity(
    normalized_inputs: dict[str, NormalizedQuantity],
    validity_domain: dict[str, tuple[float, float]],
) -> tuple[str, ...]:
    violated = []
    for field, (lower, upper) in validity_domain.items():
        value = normalized_inputs[field].domain_value
        if value is None:
            value = normalized_inputs[field].value
        if value < lower or value > upper:
            violated.append(field)
    return tuple(violated)


def _default_unit_definitions() -> dict[str, S7UnitDefinition]:
    definitions = {}
    for symbol, spec in _UNIT_DEFINITION_SPECS.items():
        raw_dimensions = spec["dimensions"]
        definitions[symbol] = S7UnitDefinition(
            symbol=symbol,
            dimensions=tuple(int(raw_dimensions.get(key, 0)) for key in _UNIT_DIMENSION_KEYS),
            scale_to_canonical=float(spec["scale_to_canonical"]),
        )
    return definitions


def _unit_expression(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise UnitsMismatchError("unit expression must be a non-empty string")
    return value.replace(" ", "")


def _unit_expression_tokens(expression: str) -> tuple[tuple[str, int], ...]:
    tokens: list[tuple[str, int]] = []
    current = []
    operator = 1
    for character in expression:
        if character in "*/":
            _append_unit_token(tokens, "".join(current), operator)
            current = []
            operator = 1 if character == "*" else -1
        else:
            current.append(character)
    _append_unit_token(tokens, "".join(current), operator)
    return tuple(tokens)


def _append_unit_token(tokens: list[tuple[str, int]], raw_token: str, operator: int) -> None:
    token = raw_token.strip()
    if not token:
        raise UnitsMismatchError("invalid unit expression")
    if token == "1":
        tokens.append((token, 0))
        return
    if "^" in token:
        symbol, exponent_text = token.split("^", 1)
        try:
            exponent = int(exponent_text)
        except ValueError as exc:
            raise UnitsMismatchError(f"invalid unit exponent: {token}") from exc
    else:
        symbol = token
        exponent = 1
    if not symbol:
        raise UnitsMismatchError(f"invalid unit token: {token}")
    tokens.append((symbol, operator * exponent))


def _unit_field_spec(value: Any) -> S7UnitFieldSpec:
    if isinstance(value, S7UnitFieldSpec):
        return value
    if isinstance(value, str):
        return S7UnitFieldSpec(units=_unit_expression(value))
    if isinstance(value, Mapping):
        raw_units = value.get("units") or value.get("canonical_units")
        units = _unit_expression(raw_units)
        raw_log_space = value.get("log_space")
        log_space = None
        if raw_log_space is True:
            log_space = "log10"
        elif isinstance(raw_log_space, str) and raw_log_space:
            log_space = raw_log_space
        elif raw_log_space not in (None, False):
            raise UnitsMismatchError("log_space must be true, false, or a string")
        if log_space not in (None, "log10", "ln"):
            raise UnitsMismatchError(f"unsupported log_space: {log_space}")
        return S7UnitFieldSpec(units=units, log_space=log_space)
    raise UnitsMismatchError("unit field spec must be a string or mapping")


def _finite_quantity_value(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise UnitsMismatchError(f"{field_name} must be a finite number")
    numeric = float(value)
    if not math.isfinite(numeric):
        raise UnitsMismatchError(f"{field_name} must be finite")
    return numeric


def _delinearize_log_space(value: float, log_space: str) -> float:
    if log_space == "log10":
        return 10.0**value
    if log_space == "ln":
        return math.exp(value)
    raise UnitsMismatchError(f"unsupported log_space: {log_space}")


def _scale_uncertainty(uncertainty: dict[str, Any], scale: float) -> dict[str, Any]:
    scaled = dict(uncertainty)
    radius = scaled.get("radius")
    if isinstance(radius, (int, float)) and not isinstance(radius, bool) and math.isfinite(float(radius)):
        scaled["radius"] = float(radius) * abs(scale)
    return scaled


def derive_seed(*, job_seed: int, dag_node_id: str, call_index: int, adapter_id: str) -> int:
    digest = hash_json(
        {
            "job_seed": job_seed,
            "dag_node_id": dag_node_id,
            "call_index": call_index,
            "adapter_id": adapter_id,
        }
    ).removeprefix("blake3:")
    return int(digest[:16], 16)


def adapter_capability_descriptor(
    descriptor: AdapterDescriptor,
    *,
    subtopics: tuple[str, ...],
    revision: int = 1,
    trust_class: str = "internal",
    status: str = "active",
) -> CapabilityDescriptor:
    scopes = ["describe", "evaluate", "batch_evaluate"]
    if descriptor.differentiable:
        scopes.append("grad")
    return CapabilityDescriptor(
        entity_id=descriptor.adapter_id,
        revision=revision,
        kind="adapter",
        owner_subsystem="S7",
        contract_versions={"C5": "1.0.0", "C6": "1.1.0"},
        trust_class=trust_class,
        capability_scopes=tuple(scopes),
        provenance_ref=descriptor.provenance_ref,
        subtopics=subtopics,
        independence_tags=descriptor.independence_tags,
        conformance_level="gold",
        status=status,
    )


def publish_adapter_capability(
    registry: InMemoryRegistry,
    descriptor: AdapterDescriptor,
    *,
    subtopics: tuple[str, ...],
    revision: int = 1,
) -> CapabilityDescriptor:
    return registry.publish(
        adapter_capability_descriptor(
            descriptor,
            subtopics=subtopics,
            revision=revision,
        )
    )


def resolve_independent_adapter_capabilities(
    registry: InMemoryRegistry,
    *,
    subtopic: str,
    excluded_independence_tags: tuple[str, ...],
    min_independent: int,
) -> IndependenceAttestation:
    return registry.attest_independence(
        kind="adapter",
        subtopic=subtopic,
        excluded_independence_tags=excluded_independence_tags,
        min_independent=min_independent,
    )


def select_adapter_version(
    descriptors: tuple[AdapterDescriptor, ...],
    *,
    requested_major: int,
) -> AdapterVersionSelection:
    compatible = tuple(
        descriptor
        for descriptor in descriptors
        if _parse_semver(descriptor.version)[0] == requested_major
    )
    if not compatible:
        raise AdapterVersionError(f"no adapter version compatible with major {requested_major}")
    selected = max(compatible, key=lambda descriptor: _parse_semver(descriptor.version))
    return AdapterVersionSelection(
        requested_major=requested_major,
        selected_adapter_id=selected.adapter_id,
        selected_version=selected.version,
    )


def _parse_semver(version: str) -> tuple[int, int, int]:
    parts = version.split(".")
    if len(parts) != 3:
        raise AdapterVersionError(f"invalid adapter semver: {version}")
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError as exc:
        raise AdapterVersionError(f"invalid adapter semver: {version}") from exc
