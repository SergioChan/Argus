"""S2 baseline builder semantics for the first oracle-gated vertical slice."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .s7 import AdapterBroker, EvalRequest, EvalResult
from .s8 import ArtifactRecord, InMemoryArtifactStore, Lineage, Producer


class S2Error(Exception):
    """Base class for S2 builder failures."""


class SelfGradeError(S2Error):
    """Raised when S2 tries to assign a tier above ran-toy."""


class RewardSourceError(S2Error):
    """Raised when S2 is asked to accept a non-C3 score or reward."""


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
