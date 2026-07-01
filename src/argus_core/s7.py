"""S7 compute-adapter core semantics for C6 evaluation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Callable

from .hashing import hash_json
from .s8 import InMemoryArtifactStore, Lineage, Producer


UNIT_REGISTRY_VERSION = "argus-units-1.0.0"
UNIT_DEFINITIONS = {
    "dimensionless": ("dimensionless", 1.0),
    "GeV": ("energy", 1.0),
    "TeV": ("energy", 1000.0),
    "Hz": ("frequency", 1.0),
    "mHz": ("frequency", 0.001),
    "s": ("time", 1.0),
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


@dataclass(frozen=True)
class AdapterDescriptor:
    adapter_id: str
    version: str
    input_units: dict[str, str]
    output_units: dict[str, str]
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

    def __init__(self, *, artifact_store: InMemoryArtifactStore | None) -> None:
        self._artifact_store = artifact_store
        self._adapters: dict[str, SimpleAdapter] = {}

    def register(self, adapter: SimpleAdapter) -> None:
        self._adapters[adapter.descriptor.adapter_id] = adapter

    def evaluate(self, request: EvalRequest) -> EvalResult:
        adapter = self._adapters[request.adapter_id]
        descriptor = adapter.descriptor
        normalized_inputs = normalize_inputs(request.inputs, descriptor.input_units)
        violated_fields = classify_validity(normalized_inputs, descriptor.validity_domain)
        if violated_fields and descriptor.domain_policy == "refuse":
            raise OutOfDomainError(f"out-of-domain fields: {', '.join(violated_fields)}")

        outputs = adapter.evaluate(normalized_inputs, request.seed)
        self._assert_outputs_conform(outputs, descriptor.output_units)
        provenance_ref = self._write_provenance(descriptor, request, normalized_inputs, outputs)
        return EvalResult(
            adapter_id=descriptor.adapter_id,
            outputs=outputs,
            in_validity_domain=not violated_fields,
            extrapolation_flag=bool(violated_fields),
            provenance_ref=provenance_ref,
            violated_fields=violated_fields,
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
            "unit_registry_version": UNIT_REGISTRY_VERSION,
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

    @staticmethod
    def _assert_outputs_conform(outputs: dict[str, Quantity], expected_units: dict[str, str]) -> None:
        for field, expected_unit in expected_units.items():
            if field not in outputs:
                raise AdapterConformanceError(f"missing output field: {field}")
            quantity = outputs[field]
            if quantity.uncertainty is None:
                raise AdapterConformanceError(f"missing uncertainty for output field: {field}")
            normalize_quantity(quantity, expected_unit)


def normalize_inputs(inputs: dict[str, Quantity], expected_units: dict[str, str]) -> dict[str, NormalizedQuantity]:
    return {field: normalize_quantity(inputs[field], expected_unit) for field, expected_unit in expected_units.items()}


def normalize_quantity(quantity: Quantity, expected_unit: str) -> NormalizedQuantity:
    if quantity.units not in UNIT_DEFINITIONS:
        raise UnitsMismatchError(f"unsupported unit: {quantity.units}")
    if expected_unit not in UNIT_DEFINITIONS:
        raise UnitsMismatchError(f"unsupported expected unit: {expected_unit}")
    input_dimension, input_scale = UNIT_DEFINITIONS[quantity.units]
    expected_dimension, expected_scale = UNIT_DEFINITIONS[expected_unit]
    if input_dimension != expected_dimension:
        raise UnitsMismatchError(f"{quantity.units} is not compatible with {expected_unit}")
    canonical_value = quantity.value * input_scale / expected_scale
    return NormalizedQuantity(value=canonical_value, units=expected_unit, original_units=quantity.units)


def classify_validity(
    normalized_inputs: dict[str, NormalizedQuantity],
    validity_domain: dict[str, tuple[float, float]],
) -> tuple[str, ...]:
    violated = []
    for field, (lower, upper) in validity_domain.items():
        value = normalized_inputs[field].value
        if value < lower or value > upper:
            violated.append(field)
    return tuple(violated)


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
