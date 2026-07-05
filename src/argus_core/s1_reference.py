"""Reference S1 physics subagent integration harness for the M1 vertical slice."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping

from .c3 import C3ReportSigner, C3ReportVerifier, InMemoryVerifierTrustStore
from .s1 import (
    Acceptance,
    ExecContext,
    JobEnvelope,
    LifecyclePolicyError,
    LifecycleState,
    S1AdapterBrokerProxy,
    Subagent,
    SubagentDescriptor,
    SubagentRuntime,
    SubagentSDKRunner,
)
from .s3 import (
    CheckResult,
    PerturbationPairOutcome,
    S3Verifier,
    attest_challenger_independence,
    run_calibration_check,
    run_cross_code_check,
    run_leakage_check,
    run_perturbation_pair,
)
from .s6 import CapabilityDescriptor, ContaminationIndex, FrozenContaminationSnapshot, SourceDocument
from .s7 import AdapterBroker, AdapterDescriptor, NormalizedQuantity, Quantity, SimpleAdapter
from .s8 import ArtifactRecord, InMemoryArtifactStore, Lineage, Producer
from .s10 import InMemoryAuditLedger, InMemoryTokenService, ScopeGrant
from .s11 import ObservatoryLineageBundle, ObservatoryRenderResult, render_observatory_v0_html


S1_REFERENCE_PHYSICS_ADAPTER_ID = "gw_spectrum_surrogate"
S1_REFERENCE_PHYSICS_SUBTOPIC = "ewpt"
S1_REFERENCE_PHYSICS_PROFILE_REF = "c4://profile/ewpt-reference/v1"
S1_REFERENCE_PHYSICS_DATASET_REF = "c4://dataset/ewpt-reference/v1"
S1_REFERENCE_PHYSICS_PROPONENT_ID = "s1-reference-physics"
S1_REFERENCE_S3_VERIFIER_ID = "s3-reference-verifier"
S1_REFERENCE_S3_REFEREE_KEY_ID = "s3-reference-referee-key"
S1_REFERENCE_S3_REFEREE_SECRET = b"s3-reference-referee-secret"
S1_REFERENCE_SHOULD_REACT_ALPHA_SCALE = 0.2
S1_REFERENCE_MUST_NOT_REACT_VW_DELTA = 0.02


@dataclass(frozen=True)
class S1ReferencePhysicsRunResult:
    job_id: str
    acceptance: Acceptance
    final_state: LifecycleState
    lifecycle_methods: tuple[str, ...]
    plan_payload: dict[str, Any]
    build_payload: dict[str, Any]
    artifact_refs: tuple[str, ...]
    validation_report_ref: str
    validation_report_payload: dict[str, Any]
    subagent_report: dict[str, Any]
    promoted_artifact: ArtifactRecord
    observatory_render: ObservatoryRenderResult
    observatory_html_ref: str


@dataclass(frozen=True)
class S1ReferencePhysicsFailureResult:
    job_id: str
    final_state: LifecycleState
    error: dict[str, Any]
    build_diagnostics: dict[str, Any]
    lifecycle_methods: tuple[str, ...]


@dataclass(frozen=True)
class S1ReferencePhysicsRerouteResult:
    first_acceptance: Acceptance
    first_final_state: LifecycleState
    second: S1ReferencePhysicsRunResult


class S1ReferencePhysicsHarness:
    """Runs the reference EWPT physics subagent through real S1/C3/C4/C6 surfaces."""

    def __init__(self, *, artifact_store: InMemoryArtifactStore | None = None) -> None:
        self.trust_store = InMemoryVerifierTrustStore()
        self.trust_store.register_key(S1_REFERENCE_S3_REFEREE_KEY_ID, S1_REFERENCE_S3_REFEREE_SECRET)
        self.report_verifier = C3ReportVerifier(self.trust_store)
        self.signer = C3ReportSigner(key_id=S1_REFERENCE_S3_REFEREE_KEY_ID, secret=S1_REFERENCE_S3_REFEREE_SECRET)
        self.s3_verifier = S3Verifier(
            verifier_id=S1_REFERENCE_S3_VERIFIER_ID,
            signer_key_id=self.signer.key_id,
            signer=self.signer,
        )
        self.artifact_store = artifact_store or InMemoryArtifactStore(report_verifier=self.report_verifier)
        self.contamination_index = ContaminationIndex(artifact_store=self.artifact_store)
        self.contamination_snapshot = self._reference_contamination_snapshot()
        self.audit_ledger = InMemoryAuditLedger()
        self.token_service = InMemoryTokenService(signing_key=b"s1-reference-token-key", now_fn=lambda: 1_000)
        self.adapter_broker = AdapterBroker(artifact_store=self.artifact_store)
        self.adapter_broker.register(_reference_physics_adapter())
        self.adapter_proxy = S1AdapterBrokerProxy(
            token_service=self.token_service,
            adapter_broker=self.adapter_broker,
            audit_ledger=self.audit_ledger,
        )
        self._ensure_reference_records()

    def run_happy_path(self, *, job_id: str) -> S1ReferencePhysicsRunResult:
        return self._run(job_id=job_id, mode="happy")

    def run_refusal_reroute(self, *, job_id: str) -> S1ReferencePhysicsRerouteResult:
        refuser = S1ReferencePhysicsSubagent(
            descriptor=SubagentDescriptor(
                subagent_id="s1-reference-physics-refuser",
                contract_version="1.0.0",
                subtopics=("cosmology",),
                required_adapters=(S1_REFERENCE_PHYSICS_ADAPTER_ID,),
            ),
            dataset_ref=S1_REFERENCE_PHYSICS_DATASET_REF,
            adapter_inputs=_reference_adapter_inputs(),
        )
        runtime = SubagentRuntime(
            descriptor=refuser.descriptor,
            artifact_store=self.artifact_store,
            adapter_client=self._adapter_client_for(job_id),
        )
        runner = SubagentSDKRunner(refuser, runtime=runtime)
        refused = runner.accept(_job_envelope(job_id=job_id))
        first_state = runtime.store.current(job_id).state
        second = self._run(job_id=f"{job_id}-accepted", mode="happy")
        return S1ReferencePhysicsRerouteResult(
            first_acceptance=refused,
            first_final_state=first_state,
            second=second,
        )

    def run_units_mismatch(self, *, job_id: str) -> S1ReferencePhysicsFailureResult:
        runner = self._runner(
            job_id=job_id,
            adapter_inputs={
                **_reference_adapter_inputs(),
                "T_n": {"value": 100.0, "units": "Hz", "uncertainty": {"kind": "interval", "radius": 1.0}},
            },
        )
        envelope = _job_envelope(job_id=job_id)
        runner.accept(envelope)
        plan = runner.plan(envelope)
        try:
            runner.build(job_id, plan.payload)
        except LifecyclePolicyError as exc:
            diagnostics = {"adapter_error": exc.envelope.as_c1_payload()}
            runner.runtime.store.apply_method(job_id, "fail", trigger="S1 reference harness", payload=diagnostics)
            return S1ReferencePhysicsFailureResult(
                job_id=job_id,
                final_state=runner.runtime.store.current(job_id).state,
                error=exc.envelope.as_c1_payload(),
                build_diagnostics=diagnostics,
                lifecycle_methods=_lifecycle_methods(runner, job_id),
            )
        raise AssertionError("units mismatch run unexpectedly succeeded")

    def run_extrapolated(self, *, job_id: str) -> S1ReferencePhysicsRunResult:
        return self._run(
            job_id=job_id,
            mode="extrapolated",
            adapter_inputs={
                **_reference_adapter_inputs(),
                "v_w": {"value": 1.2, "units": "dimensionless", "uncertainty": {"kind": "interval", "radius": 0.02}},
            },
        )

    def run_variant(self, *, job_id: str, base_artifact_ref: str) -> S1ReferencePhysicsRunResult:
        return self._run(
            job_id=job_id,
            mode="variant",
            variant_base_ref=base_artifact_ref,
            variant_parameters={"model_family": "tabular-baseline-mutated", "temperature_shift": 0.05},
        )

    def _run(
        self,
        *,
        job_id: str,
        mode: str,
        adapter_inputs: Mapping[str, Any] | None = None,
        variant_base_ref: str | None = None,
        variant_parameters: Mapping[str, Any] | None = None,
    ) -> S1ReferencePhysicsRunResult:
        runner = self._runner(
            job_id=job_id,
            adapter_inputs=adapter_inputs or _reference_adapter_inputs(),
            variant_base_ref=variant_base_ref,
            variant_parameters=variant_parameters,
        )
        envelope = _job_envelope(job_id=job_id)
        acceptance = runner.accept(envelope)
        plan = runner.plan(envelope)
        build = runner.build(job_id, plan.payload)
        validation = runner.validate(
            job_id,
            build.payload,
            profile_ref=S1_REFERENCE_PHYSICS_PROFILE_REF,
            blind_dataset_handle=f"blind://s1-reference/{job_id}",
            budget_token_ref=f"budget://s1-reference/{job_id}",
            validation_client=_ReferenceS3ValidationClient(
                artifact_store=self.artifact_store,
                verifier=self.s3_verifier,
                contamination_index=self.contamination_index,
                contamination_snapshot=self.contamination_snapshot,
                mode=mode,
            ),
            report_verifier=self.report_verifier,
            trace_id=f"trace:{job_id}",
        )
        promoted = self._promote_validated_subject(
            job_id=job_id,
            build_payload=build.payload,
            validation_payload=validation.payload,
            variant_base_ref=variant_base_ref,
            variant_parameters=variant_parameters,
        )
        subagent_report = dict(validation.payload["subagent_report"])
        subagent_report["artifact_refs"] = [promoted.artifact_ref]
        subagent_report["reproducibility_manifest"] = {
            **dict(subagent_report["reproducibility_manifest"]),
            "lineage_ref": promoted.artifact_ref,
        }
        report = runner.report(job_id, subagent_report)
        observatory = self._render_observatory(
            subject_ref=promoted.artifact_ref,
            report_ref=str(validation.payload["validation_report_ref"]),
            validation_report_payload=dict(validation.payload["validation_report_payload"]),
        )
        return S1ReferencePhysicsRunResult(
            job_id=job_id,
            acceptance=acceptance,
            final_state=runner.runtime.store.current(job_id).state,
            lifecycle_methods=_lifecycle_methods(runner, job_id),
            plan_payload=plan.payload,
            build_payload=build.payload,
            artifact_refs=tuple(str(ref) for ref in report.payload["artifact_refs"]),
            validation_report_ref=str(validation.payload["validation_report_ref"]),
            validation_report_payload=dict(validation.payload["validation_report_payload"]),
            subagent_report=report.payload,
            promoted_artifact=promoted,
            observatory_render=observatory[0],
            observatory_html_ref=observatory[1],
        )

    def _runner(
        self,
        *,
        job_id: str,
        adapter_inputs: Mapping[str, Any],
        variant_base_ref: str | None = None,
        variant_parameters: Mapping[str, Any] | None = None,
    ) -> SubagentSDKRunner:
        descriptor = SubagentDescriptor(
            subagent_id="s1-reference-physics",
            contract_version="1.0.0",
            subtopics=(S1_REFERENCE_PHYSICS_SUBTOPIC,),
            required_adapters=(S1_REFERENCE_PHYSICS_ADAPTER_ID,),
        )
        subagent = S1ReferencePhysicsSubagent(
            descriptor=descriptor,
            dataset_ref=S1_REFERENCE_PHYSICS_DATASET_REF,
            adapter_inputs=adapter_inputs,
            variant_base_ref=variant_base_ref,
            variant_parameters=variant_parameters,
        )
        runtime = SubagentRuntime(
            descriptor=descriptor,
            artifact_store=self.artifact_store,
            adapter_client=self._adapter_client_for(job_id),
        )
        return SubagentSDKRunner(subagent, runtime=runtime)

    def _adapter_client_for(self, job_id: str) -> object:
        scope = self.token_service.mint_scope(
            job_id=job_id,
            scopes=ScopeGrant(
                allowed_adapters=(S1_REFERENCE_PHYSICS_ADAPTER_ID,),
                broker_audiences=(S1_REFERENCE_PHYSICS_ADAPTER_ID,),
            ),
        )
        return self.adapter_proxy.client_for(scope)

    def _ensure_reference_records(self) -> None:
        self.artifact_store.create_artifact(
            kind="profile",
            artifact_ref=S1_REFERENCE_PHYSICS_PROFILE_REF,
            payload={"profile": "ewpt-reference", "checks": ["injection", "null", "physical-consistency"]},
            producer=Producer(subsystem="S3", version="0.0.0", actor_id="s3.reference-profile"),
            lineage=Lineage(input_refs=(), code_ref="git:s3-reference-profile", environment_digest="oci:s3-reference"),
        )
        self.artifact_store.create_artifact(
            kind="dataset",
            artifact_ref=S1_REFERENCE_PHYSICS_DATASET_REF,
            payload={"rows": [{"T_n": 100.0, "alpha": 0.2, "v_w": 0.7, "known_omega": 0.02}]},
            producer=Producer(subsystem="S6", version="0.0.0", actor_id="s6.reference-dataset"),
            lineage=Lineage(input_refs=(), code_ref="git:s6-reference-dataset", environment_digest="oci:s6-reference"),
        )

    def _reference_contamination_snapshot(self) -> FrozenContaminationSnapshot:
        return self.contamination_index.freeze(
            version="s1-reference-physics-v1",
            documents=(
                SourceDocument(
                    doc_id="control-calibration-note",
                    text="detector calibration control sample with no electroweak transition spectrum result",
                    source_ref="c4://source/reference-control-calibration-note",
                ),
                SourceDocument(
                    doc_id="background-method-note",
                    text="background estimation workflow for unrelated tabular benchmark diagnostics",
                    source_ref="c4://source/reference-background-method-note",
                ),
            ),
        )

    def _promote_validated_subject(
        self,
        *,
        job_id: str,
        build_payload: Mapping[str, Any],
        validation_payload: Mapping[str, Any],
        variant_base_ref: str | None,
        variant_parameters: Mapping[str, Any] | None,
    ) -> ArtifactRecord:
        report_payload = dict(validation_payload["validation_report_payload"])
        validation_report_ref = str(validation_payload["validation_report_ref"])
        artifact_refs = tuple(str(ref) for ref in build_payload["artifact_refs"])
        subject_payload: dict[str, Any] = {
            "schema": "argus.s1.reference_physics_subject.v1",
            "job_id": job_id,
            "artifact_refs": list(artifact_refs),
            "validation_report_ref": validation_report_ref,
            "uncertainty_tag": {"kind": "interval", "source": "s1-reference-physics"},
            "report_id": report_payload.get("report_id"),
        }
        lineage_inputs = artifact_refs
        if variant_base_ref is not None:
            subject_payload["variant"] = {
                "derived_from": variant_base_ref,
                "parameters": dict(variant_parameters or {}),
            }
            lineage_inputs = artifact_refs + (variant_base_ref,)
        promoted = self.artifact_store.create_artifact(
            kind="model",
            payload=subject_payload,
            producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.reference-physics", job_id=job_id),
            lineage=Lineage(
                input_refs=lineage_inputs,
                code_ref="argus-core:s1.reference-physics.promote",
                environment_digest="python:s1-reference-physics:v1",
                seeds=("s1-reference-seed",),
                job_id=job_id,
            ),
            claim_tier=str(report_payload["claim_tier"]),
            validation_report_ref=validation_report_ref,
        )
        if variant_base_ref is not None:
            self.artifact_store.insert_lineage_edge(variant_base_ref, promoted.artifact_ref, "derived_from")
        return promoted

    def _render_observatory(
        self,
        *,
        subject_ref: str,
        report_ref: str,
        validation_report_payload: dict[str, Any],
    ) -> tuple[ObservatoryRenderResult, str]:
        bundle = ObservatoryLineageBundle(
            subject_ref=subject_ref,
            report_ref=report_ref,
            graph=self.artifact_store.get_lineage(subject_ref, direction="ancestors"),
        )
        render = render_observatory_v0_html(
            report_payload=validation_report_payload,
            lineage=bundle,
            report_verifier=self.report_verifier,
        )
        html_record = self.artifact_store.create_artifact(
            kind="observatory_report",
            payload={"html": render.html, "trusted": render.verification.trusted, "subject_ref": subject_ref},
            producer=Producer(subsystem="S11", version="0.0.0", actor_id="s11.observatory-v0"),
            lineage=Lineage(
                input_refs=(subject_ref, report_ref),
                code_ref="argus-core:s11.render_observatory_v0_html",
                environment_digest="python:s11-observatory-v0:v1",
            ),
        )
        return render, html_record.artifact_ref


class S1ReferencePhysicsSubagent(Subagent):
    """Reference author subagent that calls a brokered C6 physics adapter."""

    def __init__(
        self,
        descriptor: SubagentDescriptor,
        *,
        dataset_ref: str,
        adapter_inputs: Mapping[str, Any],
        variant_base_ref: str | None = None,
        variant_parameters: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(descriptor)
        self.dataset_ref = dataset_ref
        self.adapter_inputs = dict(adapter_inputs)
        self.variant_base_ref = variant_base_ref
        self.variant_parameters = dict(variant_parameters or {})

    def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> Mapping[str, Any]:
        del ctx
        return {
            "job_id": envelope.job_id,
            "steps": [
                {
                    "step_id": "reference-physics-build",
                    "kind": "train",
                    "description": "Build the EWPT reference physics model with a brokered C6 adapter",
                    "est_cost": {"cost_usd": envelope.estimated_cost},
                }
            ],
            "adapters_required": [S1_REFERENCE_PHYSICS_ADAPTER_ID],
            "datasets_required": [self.dataset_ref],
            "verifier_profile_ref": envelope.verifier_profile_ref,
            "budget_breakdown": {"total": {"cost_usd": envelope.estimated_cost}},
            "risk_notes": [],
        }

    def build(self, ctx: ExecContext, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        dataset = ctx.read_dataset(self.dataset_ref)
        adapter_call = ctx.call_adapter(
            S1_REFERENCE_PHYSICS_ADAPTER_ID,
            {"inputs": self.adapter_inputs, "seed": 7},
        )
        result = dict(adapter_call["result"])
        perturbation_observations = _reference_adapter_perturbation_observations(
            ctx=ctx,
            adapter_inputs=self.adapter_inputs,
        )
        diagnostics = {
            "dataset_ref": dataset["dataset_ref"],
            "adapter_id": result["adapter_id"],
            "adapter_provenance_ref": adapter_call["provenance_ref"],
            "perturbation_provenance_refs": [
                perturbation_observations["must_react"]["provenance_ref"],
                perturbation_observations["must_not_react"]["provenance_ref"],
            ],
            "in_validity_domain": result["in_validity_domain"],
            "extrapolation_flag": result["extrapolation_flag"],
            "risk_notes": [],
        }
        if result["extrapolation_flag"]:
            diagnostics["risk_notes"].append(
                {
                    "kind": "adapter_extrapolation",
                    "extrapolation_flag": True,
                    "violated_fields": result["violated_fields"],
                }
            )
        model_payload: dict[str, Any] = {
            "schema": "argus.s1.reference_physics_model.v1",
            "model_family": "ewpt-tabular-reference",
            "dataset_ref": self.dataset_ref,
            "adapter_outputs": result["outputs"],
            "perturbation_observations": perturbation_observations,
            "diagnostics": diagnostics,
            "uncertainty_tag": {"kind": "interval", "source": "gw_spectrum_surrogate"},
        }
        lineage_inputs = (
            self.dataset_ref,
            str(adapter_call["provenance_ref"]),
            str(perturbation_observations["must_react"]["provenance_ref"]),
            str(perturbation_observations["must_not_react"]["provenance_ref"]),
        )
        if self.variant_base_ref is not None:
            model_payload["variant"] = {
                "derived_from": self.variant_base_ref,
                "parameters": self.variant_parameters,
            }
            lineage_inputs = lineage_inputs + (self.variant_base_ref,)
        model = ctx.emit_artifact(
            model_payload,
            kind="model",
            lineage=Lineage(
                input_refs=lineage_inputs,
                code_ref="argus-core:s1.reference-physics.build",
                environment_digest="python:s1-reference-physics:v1",
                seeds=("7",),
            ),
        )
        pipeline = ctx.emit_artifact(
            {
                "schema": "argus.s1.reference_physics_pipeline.v1",
                "entrypoint": "predict",
                "model_ref": model["artifact_ref"],
                "adapter_provenance_ref": adapter_call["provenance_ref"],
                "uncertainty_tag": {"kind": "interval", "source": "gw_spectrum_surrogate"},
            },
            kind="container",
            lineage=Lineage(
                input_refs=(str(model["artifact_ref"]), str(adapter_call["provenance_ref"])),
                code_ref="argus-core:s1.reference-physics.freeze",
                environment_digest="python:s1-reference-physics:v1",
                seeds=("7",),
            ),
        )
        return {
            "job_id": plan["job_id"],
            "artifact_refs": [str(model["artifact_ref"]), str(pipeline["artifact_ref"])],
            "training_log_ref": str(adapter_call["provenance_ref"]),
            "diagnostics": diagnostics,
            "self_checks": [
                {
                    "type": "PHYSICAL_CONSISTENCY",
                    "status": "PASS" if result["in_validity_domain"] else "INCONCLUSIVE",
                    "advisory": True,
                }
            ],
            "uncertainty_summary": ctx.tag_uncertainty(
                "interval",
                {"radius": 0.01, "source": "gw_spectrum_surrogate"},
            ),
        }


class _ReferenceS3ValidationClient:
    def __init__(
        self,
        *,
        artifact_store: InMemoryArtifactStore,
        verifier: S3Verifier,
        contamination_index: ContaminationIndex,
        contamination_snapshot: FrozenContaminationSnapshot,
        mode: str,
    ) -> None:
        self.artifact_store = artifact_store
        self.verifier = verifier
        self.contamination_index = contamination_index
        self.contamination_snapshot = contamination_snapshot
        self.mode = mode

    def validate(self, request: dict[str, object]) -> dict[str, Any]:
        frozen_payload = _artifact_payload(self.artifact_store, str(request["frozen_pipeline_ref"]))
        model_payload = _reference_model_payload(self.artifact_store, frozen_payload)
        dataset_payload = _artifact_payload(self.artifact_store, str(model_payload["dataset_ref"]))
        extrapolated = self._request_has_extrapolated_artifact(request)
        checks = _reference_checks(
            model_payload=model_payload,
            dataset_payload=dataset_payload,
            contamination_index=self.contamination_index,
            contamination_snapshot=self.contamination_snapshot,
            extrapolated=extrapolated or self.mode == "extrapolated",
        )
        outcome = _reference_perturbation_outcome(
            model_payload=model_payload,
            dataset_payload=dataset_payload,
            perturbation_id=f"pair-{request['job_id']}",
        )
        challengers = _reference_challengers()
        independence = attest_challenger_independence(challengers=challengers, min_independent=2)
        return self.verifier.build_report(
            profile_ref=str(request["profile_ref"]),
            frozen_pipeline_ref=str(request["frozen_pipeline_ref"]),
            checks=checks,
            proponent_id=S1_REFERENCE_PHYSICS_PROPONENT_ID,
            perturbation_outcome=outcome,
            challenger_ids=tuple(challenger.entity_id for challenger in challengers),
            independence_attestation=independence,
            debate_ref=f"c4://debate/s1-reference/{request['job_id']}",
        )

    def _request_has_extrapolated_artifact(self, request: Mapping[str, object]) -> bool:
        frozen_payload = _artifact_payload(self.artifact_store, str(request["frozen_pipeline_ref"]))
        refs = frozen_payload.get("artifact_refs", [])
        if not isinstance(refs, list):
            return False
        for artifact_ref in refs:
            if not isinstance(artifact_ref, str):
                continue
            payload = _artifact_payload(self.artifact_store, artifact_ref)
            diagnostics = payload.get("diagnostics")
            if isinstance(diagnostics, Mapping) and diagnostics.get("extrapolation_flag") is True:
                return True
        return False


def _job_envelope(*, job_id: str) -> JobEnvelope:
    return JobEnvelope(
        job_id=job_id,
        envelope_version="1.0.0",
        subtopic=S1_REFERENCE_PHYSICS_SUBTOPIC,
        required_adapters=(S1_REFERENCE_PHYSICS_ADAPTER_ID,),
        allowed_adapters=(S1_REFERENCE_PHYSICS_ADAPTER_ID,),
        verifier_profile_ref=S1_REFERENCE_PHYSICS_PROFILE_REF,
        estimated_cost=1.0,
        budget_cost=2.0,
    )


def _reference_adapter_inputs() -> dict[str, dict[str, object]]:
    return {
        "T_n": {"value": 100.0, "units": "GeV", "uncertainty": {"kind": "interval", "radius": 1.0}},
        "alpha": {"value": 0.2, "units": "dimensionless", "uncertainty": {"kind": "interval", "radius": 0.01}},
        "v_w": {"value": 0.7, "units": "dimensionless", "uncertainty": {"kind": "interval", "radius": 0.02}},
    }


def _reference_adapter_perturbation_observations(
    *,
    ctx: ExecContext,
    adapter_inputs: Mapping[str, Any],
) -> dict[str, Any]:
    should_react_inputs = _reference_inputs_with_value(
        adapter_inputs,
        field="alpha",
        value=_reference_input_value(adapter_inputs, "alpha") * S1_REFERENCE_SHOULD_REACT_ALPHA_SCALE,
    )
    must_react_call = ctx.call_adapter(
        S1_REFERENCE_PHYSICS_ADAPTER_ID,
        {"inputs": should_react_inputs, "seed": 8},
    )
    must_react_result = dict(must_react_call["result"])

    must_not_react_inputs = _reference_inputs_with_value(
        adapter_inputs,
        field="v_w",
        value=_reference_null_vw_value(_reference_input_value(adapter_inputs, "v_w")),
    )
    must_not_react_call = ctx.call_adapter(
        S1_REFERENCE_PHYSICS_ADAPTER_ID,
        {"inputs": must_not_react_inputs, "seed": 9},
    )
    must_not_react_result = dict(must_not_react_call["result"])

    return {
        "schema": "argus.s1.reference_physics_perturbation_observations.v1",
        "must_react": {
            "perturbation": {
                "field": "alpha",
                "scale": S1_REFERENCE_SHOULD_REACT_ALPHA_SCALE,
            },
            "omega": dict(must_react_result["outputs"]["omega"]),
            "provenance_ref": str(must_react_call["provenance_ref"]),
            "in_validity_domain": bool(must_react_result["in_validity_domain"]),
        },
        "must_not_react": {
            "perturbation": {
                "field": "v_w",
                "delta": S1_REFERENCE_MUST_NOT_REACT_VW_DELTA,
            },
            "omega": dict(must_not_react_result["outputs"]["omega"]),
            "provenance_ref": str(must_not_react_call["provenance_ref"]),
            "in_validity_domain": bool(must_not_react_result["in_validity_domain"]),
        },
    }


def _reference_inputs_with_value(
    adapter_inputs: Mapping[str, Any],
    *,
    field: str,
    value: float,
) -> dict[str, Any]:
    updated = {key: dict(quantity) for key, quantity in adapter_inputs.items()}
    updated[field] = {**updated[field], "value": value}
    return updated


def _reference_input_value(adapter_inputs: Mapping[str, Any], field: str) -> float:
    quantity = adapter_inputs[field]
    if not isinstance(quantity, Mapping):
        raise ValueError(f"reference adapter input {field} must be a mapping")
    return float(quantity["value"])


def _reference_null_vw_value(value: float) -> float:
    candidate = value + S1_REFERENCE_MUST_NOT_REACT_VW_DELTA
    if candidate <= 0.95:
        return candidate
    return value - S1_REFERENCE_MUST_NOT_REACT_VW_DELTA


def _reference_physics_adapter() -> SimpleAdapter:
    return SimpleAdapter(
        AdapterDescriptor(
            adapter_id=S1_REFERENCE_PHYSICS_ADAPTER_ID,
            version="1.0.0",
            input_units={"T_n": "GeV", "alpha": "dimensionless", "v_w": "dimensionless"},
            output_units={"omega": "dimensionless"},
            validity_domain={"v_w": (0.4, 0.95)},
            determinism="deterministic",
            provenance_ref="c4://adapter/gw_spectrum_surrogate/v1",
            differentiable=True,
            independence_tags=("reference-physics",),
        ),
        _evaluate_reference_physics,
    )


def _evaluate_reference_physics(inputs: dict[str, NormalizedQuantity], _seed: int | None) -> dict[str, Quantity]:
    omega = inputs["alpha"].value * inputs["T_n"].value / 1000.0
    return {
        "omega": Quantity(
            value=omega,
            units="dimensionless",
            uncertainty={"kind": "interval", "radius": 0.01},
        )
    }


def _reference_checks(
    *,
    model_payload: Mapping[str, Any],
    dataset_payload: Mapping[str, Any],
    contamination_index: ContaminationIndex,
    contamination_snapshot: FrozenContaminationSnapshot,
    extrapolated: bool,
) -> tuple[CheckResult, ...]:
    row = _reference_dataset_row(dataset_payload)
    observed_omega = _reference_observed_omega(model_payload)
    expected_omega = float(row["known_omega"])
    omega_tolerance = _reference_omega_tolerance(model_payload)
    injection_error = abs(observed_omega - expected_omega)
    injection = CheckResult(
        "INJECTION",
        "PASS" if injection_error <= omega_tolerance else "FAIL",
        {
            "observed_omega": observed_omega,
            "expected_omega": expected_omega,
            "absolute_error": injection_error,
            "tolerance": omega_tolerance,
            "recovery_rate": observed_omega / expected_omega if expected_omega else 0.0,
        },
    )
    null_alpha = 0.0
    null_omega = _reference_predict_omega(model_payload, t_n=float(row["T_n"]), alpha=null_alpha)
    null_tolerance = 0.001
    null_control = CheckResult(
        "NULL_CONTROL",
        "PASS" if abs(null_omega) <= null_tolerance else "FAIL",
        {"null_alpha": null_alpha, "null_omega": null_omega, "absolute_tolerance": null_tolerance},
    )
    cross_code = run_cross_code_check(
        observed=(observed_omega,),
        independent=(expected_omega + 0.0005,),
        combined_uncertainty=(omega_tolerance,),
        extrapolation_flags=(extrapolated,),
    )
    expected_from_equation = _reference_predict_omega(model_payload, t_n=float(row["T_n"]), alpha=float(row["alpha"]))
    physical_error = abs(observed_omega - expected_from_equation)
    physical_consistency = CheckResult(
        "PHYSICAL_CONSISTENCY",
        "PASS" if physical_error <= omega_tolerance else "FAIL",
        {
            "model_family": str(model_payload.get("model_family", "")),
            "observed_omega": observed_omega,
            "expected_from_reference_equation": expected_from_equation,
            "absolute_error": physical_error,
            "units": _reference_omega_units(model_payload),
        },
    )
    leakage = run_leakage_check(
        contamination_index=contamination_index,
        snapshot=contamination_snapshot,
        candidate_text=_reference_candidate_text(model_payload=model_payload, observed_omega=observed_omega),
        threshold=0.8,
    )
    calibration = run_calibration_check(
        nominal_coverage=1.0,
        empirical_coverage=1.0 if injection_error <= omega_tolerance else 0.0,
        tolerance=0.0,
    )
    return (
        injection,
        null_control,
        cross_code,
        physical_consistency,
        leakage,
        calibration,
    )


def _reference_perturbation_outcome(
    *,
    model_payload: Mapping[str, Any],
    dataset_payload: Mapping[str, Any],
    perturbation_id: str,
) -> PerturbationPairOutcome:
    row = _reference_dataset_row(dataset_payload)
    t_n = float(row["T_n"])
    alpha = float(row["alpha"])
    expected_omega = float(row["known_omega"])
    observed_omega = _reference_observed_omega(model_payload)
    perturbed_alpha = alpha * S1_REFERENCE_SHOULD_REACT_ALPHA_SCALE
    expected_perturbed_omega = _reference_predict_omega(model_payload, t_n=t_n, alpha=perturbed_alpha)
    expected_delta = expected_omega - expected_perturbed_omega

    observed_perturbed_omega = _reference_observed_perturbation_omega(model_payload, "must_react")
    if observed_perturbed_omega is None:
        observed_perturbed_omega = expected_perturbed_omega * _reference_ratio(observed_omega, expected_omega)
    observed_null_omega = _reference_observed_perturbation_omega(model_payload, "must_not_react")
    if observed_null_omega is None:
        observed_null_omega = observed_omega

    return run_perturbation_pair(
        perturbation_id=perturbation_id,
        must_react_expected=_reference_ratio(expected_delta, expected_delta),
        must_react_observed=_reference_ratio(observed_omega - observed_perturbed_omega, expected_delta),
        must_not_react_observed=_reference_ratio(observed_null_omega - observed_omega, expected_delta),
        unperturbed_headline=_reference_ratio(observed_omega, expected_omega),
        perturbed_headline=_reference_ratio(observed_perturbed_omega, expected_omega),
    )


def _reference_observed_perturbation_omega(model_payload: Mapping[str, Any], kind: str) -> float | None:
    observations = model_payload.get("perturbation_observations")
    if not isinstance(observations, Mapping):
        return None
    observation = observations.get(kind)
    if not isinstance(observation, Mapping):
        return None
    omega = observation.get("omega")
    if not isinstance(omega, Mapping):
        outputs = observation.get("outputs")
        if isinstance(outputs, Mapping):
            omega = outputs.get("omega")
    if not isinstance(omega, Mapping):
        return None
    return float(omega["value"])


def _reference_ratio(numerator: float, denominator: float) -> float:
    if denominator == 0.0:
        return 0.0
    return numerator / denominator


def _reference_model_payload(store: InMemoryArtifactStore, frozen_payload: Mapping[str, Any]) -> dict[str, Any]:
    if frozen_payload.get("schema") == "argus.s1.reference_physics_model.v1":
        return dict(frozen_payload)
    artifact_refs = frozen_payload.get("artifact_refs", ())
    if not isinstance(artifact_refs, list | tuple):
        raise ValueError("reference frozen pipeline payload has no artifact_refs")
    for artifact_ref in artifact_refs:
        if not isinstance(artifact_ref, str):
            continue
        payload = _artifact_payload(store, artifact_ref)
        if payload.get("schema") == "argus.s1.reference_physics_model.v1":
            return payload
        model_ref = payload.get("model_ref")
        if isinstance(model_ref, str):
            model_payload = _artifact_payload(store, model_ref)
            if model_payload.get("schema") == "argus.s1.reference_physics_model.v1":
                return model_payload
    raise ValueError("reference frozen pipeline does not point at a physics model artifact")


def _reference_dataset_row(dataset_payload: Mapping[str, Any]) -> Mapping[str, Any]:
    rows = dataset_payload.get("rows")
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], Mapping):
        raise ValueError("reference dataset payload must contain at least one row")
    return rows[0]


def _reference_observed_omega(model_payload: Mapping[str, Any]) -> float:
    omega = _reference_omega_payload(model_payload)
    return float(omega["value"])


def _reference_omega_tolerance(model_payload: Mapping[str, Any]) -> float:
    omega = _reference_omega_payload(model_payload)
    uncertainty = omega.get("uncertainty")
    if isinstance(uncertainty, Mapping) and uncertainty.get("kind") == "interval":
        return float(uncertainty["radius"])
    return 0.0


def _reference_omega_units(model_payload: Mapping[str, Any]) -> str:
    return str(_reference_omega_payload(model_payload).get("units", ""))


def _reference_omega_payload(model_payload: Mapping[str, Any]) -> Mapping[str, Any]:
    outputs = model_payload.get("adapter_outputs")
    if not isinstance(outputs, Mapping):
        raise ValueError("reference model payload must contain adapter_outputs")
    omega = outputs.get("omega")
    if not isinstance(omega, Mapping):
        raise ValueError("reference model payload must contain adapter_outputs.omega")
    return omega


def _reference_predict_omega(model_payload: Mapping[str, Any], *, t_n: float, alpha: float) -> float:
    if model_payload.get("model_family") != "ewpt-tabular-reference":
        raise ValueError("reference S3 verifier only supports ewpt-tabular-reference models")
    return alpha * t_n / 1000.0


def _reference_candidate_text(*, model_payload: Mapping[str, Any], observed_omega: float) -> str:
    return (
        f"{model_payload.get('model_family', 'unknown-model')} produced omega {observed_omega} "
        f"from dataset {model_payload.get('dataset_ref', 'unknown-dataset')}"
    )


def _reference_challengers() -> tuple[CapabilityDescriptor, ...]:
    return (
        _reference_challenger("challenger-a", tags=("independent-code-a",)),
        _reference_challenger("challenger-b", tags=("independent-code-b",)),
    )


def _reference_challenger(entity_id: str, *, tags: tuple[str, ...]) -> CapabilityDescriptor:
    return CapabilityDescriptor(
        entity_id=entity_id,
        revision=1,
        kind="subagent",
        owner_subsystem="S1",
        contract_versions={"C1": "1.0.0", "C5": "1.0.0"},
        trust_class="internal",
        capability_scopes=("challenge",),
        provenance_ref=f"c4://descriptor/{entity_id}",
        subtopics=(S1_REFERENCE_PHYSICS_SUBTOPIC,),
        independence_tags=tags,
        conformance_level="gold",
    )


def _artifact_payload(store: InMemoryArtifactStore, artifact_ref: str) -> dict[str, Any]:
    payload = json.loads(store.get_artifact(artifact_ref).decode("utf-8"))
    if not isinstance(payload, dict):
        return {}
    return payload


def _lifecycle_methods(runner: SubagentSDKRunner, job_id: str) -> tuple[str, ...]:
    return tuple(event.method for event in runner.runtime.store.events(job_id))
