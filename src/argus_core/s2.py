"""S2 baseline builder semantics for the first oracle-gated vertical slice."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .s5 import C2VersionPolicy, parse_c2_job_envelope
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


@dataclass(frozen=True)
class ModelFamilyDescriptor:
    family_id: str
    family_kind: str
    differentiable: bool
    physics_informed: bool
    native_uq: str


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
    )


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


def list_model_families() -> tuple[ModelFamilyDescriptor, ...]:
    return (
        ModelFamilyDescriptor(
            family_id="tabular-baseline",
            family_kind="classical",
            differentiable=False,
            physics_informed=False,
            native_uq="conformal",
        ),
        ModelFamilyDescriptor(
            family_id="physics-informed-mlp",
            family_kind="deep",
            differentiable=True,
            physics_informed=True,
            native_uq="ensemble",
        ),
        ModelFamilyDescriptor(
            family_id="differentiable-surrogate",
            family_kind="deep",
            differentiable=True,
            physics_informed=True,
            native_uq="interval",
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
    return tuple(parsed)


def _contract_value(contract: Any, name: str) -> Any:
    if isinstance(contract, Mapping):
        return contract[name]
    return getattr(contract, name)


def _schema_sha256(schema: Mapping[str, Any]) -> str:
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()
