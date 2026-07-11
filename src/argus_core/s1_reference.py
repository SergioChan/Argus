"""Reference S1 physics subagent integration harness for the M1 vertical slice."""

from __future__ import annotations

from dataclasses import dataclass
import json
from math import isfinite
import secrets
from typing import Any, Callable, Mapping

from .c3 import C3ReportVerifier
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
    build_error_envelope,
)
from .s3 import (
    BlindDataStage,
    CheckResult,
    CheckPluginHost,
    CompiledCheckSpec,
    CompiledProfile,
    InMemoryBlindDataVault,
    PerturbationPairOutcome,
    S3BlindDataManager,
    S3CalibrationCheckPlugin,
    S3CalibrationSample,
    S3CrossCodeCheckPlugin,
    S3CrossCodeSample,
    S3InjectionCheckPlugin,
    S3InjectionSample,
    S3IndependenceResolution,
    S3LeakageCheckPlugin,
    S3NullControlCheckPlugin,
    S3NullControlSample,
    S3PhysicalConsistencyCheckPlugin,
    S3PhysicalConsistencySample,
    S3RecapBenchmarkCheckPlugin,
    S3RecapBenchmarkPrediction,
    S3ReportSignerProtocol,
    S3TrustStoreKeyManager,
    S3Verifier,
    attest_challenger_independence,
    run_perturbation_pair,
)
from .s6 import CapabilityDescriptor, ContaminationIndex, FrozenContaminationSnapshot, SourceDocument
from .gw_spectrum import GW_SPECTRUM_ADAPTER_ID, GWSpectrumAdapter, evaluate_sound_wave_spectrum
from .s7 import AdapterBroker, Quantity, SimpleAdapter
from .s8 import ArtifactRecord, InMemoryArtifactStore, Lineage, Producer
from .s2 import FrozenPipelineRunner
from .s10 import InMemoryAuditLedger, InMemoryTokenService, ScopeGrant
from .s11 import ObservatoryLineageBundle, ObservatoryRenderResult, render_observatory_v0_html


S1_REFERENCE_PHYSICS_ADAPTER_ID = GW_SPECTRUM_ADAPTER_ID
S1_REFERENCE_PHYSICS_SUBTOPIC = "ewpt"
S1_REFERENCE_PHYSICS_PROFILE_REF = "c4://profile/ewpt-reference/v1"
S1_REFERENCE_PHYSICS_DATASET_REF = "c4://dataset/ewpt-reference/v1"
S1_REFERENCE_PHYSICS_PROPONENT_ID = "s1-reference-physics"
S1_REFERENCE_S3_VERIFIER_ID = "s3-reference-verifier"
S1_REFERENCE_S3_REFEREE_KEY_ID = "s3-reference-referee-key"
S1_REFERENCE_SHOULD_REACT_ALPHA_SCALE = 0.2
S1_REFERENCE_MUST_NOT_REACT_VW_UNCERTAINTY_SCALE = 2.0

S3ReferenceSignerFactory = Callable[[str, bytes], S3ReportSignerProtocol]
ReferenceSandboxSpecFactory = Callable[[str, Mapping[str, Any]], Mapping[str, Any]]
ReferenceBuildDelegate = Callable[
    [ExecContext, Mapping[str, Any], Mapping[str, Any]],
    Mapping[str, Any],
]


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


class _ReferenceS3KeyManagerSigner:
    def __init__(self, key_manager: S3TrustStoreKeyManager) -> None:
        self._key_manager = key_manager

    @property
    def key_id(self) -> str:
        return self._key_manager.key_id

    def sign(self, report: dict[str, Any]) -> dict[str, Any]:
        return self._key_manager.sign(report)


class S1ReferencePhysicsHarness:
    """Runs the reference EWPT physics subagent through real S1/C3/C4/C6 surfaces."""

    def __init__(
        self,
        *,
        artifact_store: InMemoryArtifactStore | None = None,
        s3_signer_factory: S3ReferenceSignerFactory | None = None,
        sandbox_marshaler: Any | None = None,
        sandbox_spec_factory: ReferenceSandboxSpecFactory | None = None,
        adapter_egress_allowlist: Mapping[str, Any] | None = None,
    ) -> None:
        self.s3_key_manager = S3TrustStoreKeyManager(actor_id="s1-reference-s3-key-manager")
        s3_referee_key_material = secrets.token_urlsafe(32).encode("utf-8")
        self.s3_key_manager.register_signing_key(
            S1_REFERENCE_S3_REFEREE_KEY_ID,
            s3_referee_key_material,
        )
        self.trust_store = self.s3_key_manager
        self.report_verifier = C3ReportVerifier(self.trust_store)
        self.signer = (
            s3_signer_factory(S1_REFERENCE_S3_REFEREE_KEY_ID, s3_referee_key_material)
            if s3_signer_factory is not None
            else _ReferenceS3KeyManagerSigner(self.s3_key_manager)
        )
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
        self.sandbox_marshaler = sandbox_marshaler
        self.sandbox_spec_factory = sandbox_spec_factory
        self.adapter_egress_allowlist = dict(adapter_egress_allowlist or {})
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
            sandbox_spec_factory=self.sandbox_spec_factory,
        )
        runtime = SubagentRuntime(
            descriptor=descriptor,
            artifact_store=self.artifact_store,
            sandbox_marshaler=self.sandbox_marshaler,
            adapter_client=self._adapter_client_for(job_id),
            adapter_egress_allowlist=self.adapter_egress_allowlist,
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
        adapter_inputs = _reference_adapter_inputs()
        known_omega = _reference_predict_omega(
            {"model_family": "ewpt-tabular-reference"},
            t_n=_reference_input_value(adapter_inputs, "T_n"),
            alpha=_reference_input_value(adapter_inputs, "alpha"),
            beta_over_h=_reference_input_value(adapter_inputs, "beta_over_H"),
            wall_velocity=_reference_input_value(adapter_inputs, "v_w"),
            frequency_hz=_reference_input_value(adapter_inputs, "frequency"),
        )
        self.artifact_store.create_artifact(
            kind="dataset",
            artifact_ref=S1_REFERENCE_PHYSICS_DATASET_REF,
            payload={
                "rows": [
                    {
                        "T_n": _reference_input_value(adapter_inputs, "T_n"),
                        "alpha": _reference_input_value(adapter_inputs, "alpha"),
                        "beta_over_H": _reference_input_value(adapter_inputs, "beta_over_H"),
                        "v_w": _reference_input_value(adapter_inputs, "v_w"),
                        "frequency": _reference_input_value(adapter_inputs, "frequency"),
                        "known_omega": known_omega,
                    }
                ]
            },
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
        sandbox_spec_factory: ReferenceSandboxSpecFactory | None = None,
        build_delegate: ReferenceBuildDelegate | None = None,
    ) -> None:
        super().__init__(descriptor)
        self.dataset_ref = dataset_ref
        self.adapter_inputs = dict(adapter_inputs)
        self.variant_base_ref = variant_base_ref
        self.variant_parameters = dict(variant_parameters or {})
        self.sandbox_spec_factory = sandbox_spec_factory
        self.build_delegate = build_delegate

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
        output_payloads = result.get("outputs")
        if not isinstance(output_payloads, Mapping):
            raise ValueError("C6 result outputs must be an object")
        omega_payload = output_payloads.get("omega")
        if not isinstance(omega_payload, Mapping):
            raise ValueError("C6 result outputs.omega must be an object")
        omega_uncertainty = omega_payload.get("uncertainty")
        if not isinstance(omega_uncertainty, Mapping) or omega_uncertainty.get("kind") != "interval":
            raise ValueError("C6 result outputs.omega must carry interval uncertainty")
        omega_radius = float(omega_uncertainty["radius"])
        omega_source = str(omega_uncertainty.get("source") or S1_REFERENCE_PHYSICS_ADAPTER_ID)
        perturbation_observations = _reference_adapter_perturbation_observations(
            ctx=ctx,
            adapter_inputs=self.adapter_inputs,
        )
        sandbox_diagnostics = self._run_sandbox_compute(
            ctx=ctx,
            adapter_outputs=output_payloads,
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
        if sandbox_diagnostics is not None:
            diagnostics["sandbox"] = sandbox_diagnostics
        if result["extrapolation_flag"]:
            domain_diagnostics = result.get("domain_diagnostics")
            if not isinstance(domain_diagnostics, Mapping):
                raise ValueError("C6 result domain_diagnostics must be an object")
            violated_fields = domain_diagnostics.get("violated_fields")
            if not isinstance(violated_fields, list) or not all(isinstance(field, str) for field in violated_fields):
                raise ValueError("C6 result domain_diagnostics.violated_fields must be a string array")
            diagnostics["risk_notes"].append(
                {
                    "kind": "adapter_extrapolation",
                    "extrapolation_flag": True,
                    "violated_fields": violated_fields,
                }
            )
        if self.build_delegate is not None:
            return self.build_delegate(
                ctx,
                plan,
                {
                    "dataset": dict(dataset),
                    "adapter_call": dict(adapter_call),
                    "adapter_outputs": dict(output_payloads),
                    "omega_radius": omega_radius,
                    "omega_source": omega_source,
                    "perturbation_observations": dict(perturbation_observations),
                    "sandbox_diagnostics": dict(sandbox_diagnostics) if sandbox_diagnostics is not None else None,
                    "diagnostics": diagnostics,
                },
            )
        model_payload: dict[str, Any] = {
            "schema": "argus.s1.reference_physics_model.v1",
            "model_family": "ewpt-tabular-reference",
            "dataset_ref": self.dataset_ref,
            "adapter_outputs": result["outputs"],
            "perturbation_observations": perturbation_observations,
            "diagnostics": diagnostics,
            "uncertainty_tag": {"kind": "interval", "source": omega_source},
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
                "uncertainty_tag": {"kind": "interval", "source": omega_source},
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
                {"radius": omega_radius, "source": omega_source},
            ),
        }

    def _run_sandbox_compute(
        self,
        *,
        ctx: ExecContext,
        adapter_outputs: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        if self.sandbox_spec_factory is None:
            return None
        spec = self.sandbox_spec_factory(ctx.job_id, self.adapter_inputs)
        if not isinstance(spec, Mapping):
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_REFERENCE_SANDBOX_SPEC_INVALID",
                    message="reference sandbox spec factory must return an object",
                )
            )
        execution = ctx.submit_sandbox_job(dict(spec))
        if execution.get("timed_out") is True or execution.get("exit_code") != 0:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_REFERENCE_SANDBOX_FAILED",
                    message="reference S10 sandbox did not complete successfully",
                    provenance_ref=_optional_reference_sandbox_ref(execution),
                )
            )
        if execution.get("state") != "SUCCEEDED":
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_REFERENCE_SANDBOX_STATE_INVALID",
                    message="reference S10 sandbox returned a non-success state",
                    provenance_ref=_optional_reference_sandbox_ref(execution),
                )
            )
        stdout = execution.get("stdout")
        if not isinstance(stdout, str) or not stdout.strip():
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_REFERENCE_SANDBOX_OUTPUT_MISSING",
                    message="reference S10 sandbox did not return a JSON computation result",
                    provenance_ref=_optional_reference_sandbox_ref(execution),
                )
            )
        try:
            output = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_REFERENCE_SANDBOX_OUTPUT_INVALID",
                    message="reference S10 sandbox returned invalid JSON",
                    provenance_ref=_optional_reference_sandbox_ref(execution),
                )
            ) from exc
        if not isinstance(output, Mapping):
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_REFERENCE_SANDBOX_OUTPUT_INVALID",
                    message="reference S10 sandbox output must be an object",
                    provenance_ref=_optional_reference_sandbox_ref(execution),
                )
            )
        normalized_output = _reference_sandbox_output(output, adapter_outputs=adapter_outputs)
        return {
            "sandbox_id": execution.get("sandbox_id"),
            "state": execution.get("state"),
            "launch_provenance_ref": _optional_reference_sandbox_ref(execution),
            "duration_s": execution.get("duration_s"),
            "output": normalized_output,
        }


def _optional_reference_sandbox_ref(execution: Mapping[str, Any]) -> str | None:
    reference = execution.get("launch_provenance_ref")
    return reference if isinstance(reference, str) and reference else None


def _reference_sandbox_output(
    output: Mapping[str, Any],
    *,
    adapter_outputs: Mapping[str, Any],
) -> dict[str, float]:
    normalized: dict[str, float] = {}
    for field in ("omega", "peak_omega", "peak_frequency"):
        expected_payload = adapter_outputs.get(field)
        if not isinstance(expected_payload, Mapping):
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_REFERENCE_SANDBOX_ADAPTER_OUTPUT_INVALID",
                    message=f"reference adapter output {field} is unavailable for sandbox verification",
                )
            )
        try:
            expected = float(expected_payload["value"])
            actual = float(output[field])
        except (KeyError, TypeError, ValueError) as exc:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_REFERENCE_SANDBOX_OUTPUT_INVALID",
                    message=f"reference S10 sandbox output requires numeric {field}",
                )
            ) from exc
        if not isfinite(actual):
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_REFERENCE_SANDBOX_OUTPUT_INVALID",
                    message=f"reference S10 sandbox output {field} must be finite",
                )
            )
        tolerance = max(abs(expected) * 1e-12, 1e-30)
        if abs(actual - expected) > tolerance:
            raise LifecyclePolicyError(
                build_error_envelope(
                    category="SANDBOX",
                    code="S10_REFERENCE_SANDBOX_OUTPUT_MISMATCH",
                    message=f"reference S10 sandbox output {field} does not match the brokered S7 result",
                )
            )
        normalized[field] = actual
    return normalized


class ReferenceS3ValidationEngine:
    """Reference EWPT validation logic reusable by an isolated S3 referee service."""

    def __init__(
        self,
        *,
        artifact_store: Any,
        verifier: S3Verifier,
        contamination_index: ContaminationIndex | None,
        contamination_snapshot: FrozenContaminationSnapshot | None,
        mode: str,
    ) -> None:
        self.artifact_store = artifact_store
        self.verifier = verifier
        self.contamination_index = contamination_index
        self.contamination_snapshot = contamination_snapshot
        self.mode = mode

    def validate(
        self,
        request: dict[str, object],
        *,
        frozen_pipeline_execution: Mapping[str, Any] | None = None,
        recap_blind_data_vault: InMemoryBlindDataVault | None = None,
        recap_blind_data_stage: BlindDataStage | None = None,
    ) -> dict[str, Any]:
        frozen_pipeline_ref = str(request["frozen_pipeline_ref"])
        frozen_payload = _artifact_payload(self.artifact_store, frozen_pipeline_ref)
        model_payload = _reference_model_payload(
            self.artifact_store,
            frozen_pipeline_ref=frozen_pipeline_ref,
            frozen_payload=frozen_payload,
            frozen_pipeline_execution=frozen_pipeline_execution,
        )
        dataset_payload = _artifact_payload(self.artifact_store, str(model_payload["dataset_ref"]))
        extrapolated = self._request_has_extrapolated_artifact(request)
        job_id = str(request["job_id"])
        trace_id = str(request["trace_id"]) if request.get("trace_id") is not None else None
        checks = _reference_plugin_checks(
            artifact_store=self.artifact_store,
            model_payload=model_payload,
            dataset_payload=dataset_payload,
            contamination_index=self.contamination_index,
            contamination_snapshot=self.contamination_snapshot,
            extrapolated=extrapolated or self.mode == "extrapolated",
            include_m3_checks=self.mode == "extrapolated",
            profile_ref=str(request["profile_ref"]),
            job_id=job_id,
            trace_id=trace_id,
            recap_blind_data_vault=recap_blind_data_vault,
            recap_blind_data_stage=recap_blind_data_stage,
        )
        outcome = _reference_perturbation_outcome(
            model_payload=model_payload,
            dataset_payload=dataset_payload,
            perturbation_id=f"pair-{job_id}",
        )
        challengers = _reference_challengers() if self.mode == "extrapolated" else ()
        independence = (
            attest_challenger_independence(challengers=challengers, min_independent=2)
            if challengers
            else None
        )
        return self.verifier.build_report(
            profile_ref=str(request["profile_ref"]),
            frozen_pipeline_ref=str(request["frozen_pipeline_ref"]),
            checks=checks,
            proponent_id=S1_REFERENCE_PHYSICS_PROPONENT_ID,
            perturbation_outcome=outcome,
            challenger_ids=tuple(challenger.entity_id for challenger in challengers),
            independence_attestation=independence,
            debate_ref=f"c4://debate/s1-reference/{job_id}",
            requested_tier="novel-needs-human" if challengers else "recapitulated-known",
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


class _ReferenceS3ValidationClient(ReferenceS3ValidationEngine):
    """Compatibility wrapper for the legacy in-process reference harness."""

    pass


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
        "beta_over_H": {"value": 100.0, "units": "dimensionless", "uncertainty": {"kind": "interval", "radius": 5.0}},
        "v_w": {"value": 0.7, "units": "dimensionless", "uncertainty": {"kind": "interval", "radius": 0.02}},
        "frequency": {"value": 0.003, "units": "Hz", "uncertainty": {"kind": "interval", "radius": 0.0001}},
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

    must_not_react_inputs = _reference_inputs_with_uncertainty_scale(
        adapter_inputs,
        field="v_w",
        scale=S1_REFERENCE_MUST_NOT_REACT_VW_UNCERTAINTY_SCALE,
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
                "field": "v_w.uncertainty.radius",
                "scale": S1_REFERENCE_MUST_NOT_REACT_VW_UNCERTAINTY_SCALE,
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


def _reference_inputs_with_uncertainty_scale(
    adapter_inputs: Mapping[str, Any],
    *,
    field: str,
    scale: float,
) -> dict[str, Any]:
    updated = {key: dict(quantity) for key, quantity in adapter_inputs.items()}
    uncertainty = updated[field].get("uncertainty")
    if not isinstance(uncertainty, Mapping) or "radius" not in uncertainty:
        raise ValueError(f"reference adapter input {field} must carry interval uncertainty")
    updated[field]["uncertainty"] = {**uncertainty, "radius": float(uncertainty["radius"]) * scale}
    return updated


def _reference_physics_adapter() -> SimpleAdapter:
    return GWSpectrumAdapter().as_simple_adapter()


def _reference_plugin_checks(
    *,
    artifact_store: Any,
    model_payload: Mapping[str, Any],
    dataset_payload: Mapping[str, Any],
    contamination_index: ContaminationIndex | None,
    contamination_snapshot: FrozenContaminationSnapshot | None,
    extrapolated: bool,
    include_m3_checks: bool,
    profile_ref: str,
    job_id: str,
    trace_id: str | None,
    recap_blind_data_vault: InMemoryBlindDataVault | None = None,
    recap_blind_data_stage: BlindDataStage | None = None,
) -> tuple[CheckResult, ...]:
    profile = _reference_compiled_profile(profile_ref=profile_ref, include_m3_checks=include_m3_checks)
    plugins = _reference_check_plugins(
        artifact_store=artifact_store,
        model_payload=model_payload,
        dataset_payload=dataset_payload,
        contamination_index=contamination_index,
        contamination_snapshot=contamination_snapshot,
        extrapolated=extrapolated,
        include_m3_checks=include_m3_checks,
        job_id=job_id,
        trace_id=trace_id,
        recap_blind_data_vault=recap_blind_data_vault,
        recap_blind_data_stage=recap_blind_data_stage,
    )
    return CheckPluginHost(
        plugins=plugins,
        artifact_store=artifact_store,
        actor_id=S1_REFERENCE_S3_VERIFIER_ID,
        job_id=job_id,
        trace_id=trace_id,
    ).run(profile)


def _reference_check_plugins(
    *,
    artifact_store: InMemoryArtifactStore,
    model_payload: Mapping[str, Any],
    dataset_payload: Mapping[str, Any],
    contamination_index: ContaminationIndex,
    contamination_snapshot: FrozenContaminationSnapshot,
    extrapolated: bool,
    include_m3_checks: bool,
    job_id: str,
    trace_id: str | None,
    recap_blind_data_vault: InMemoryBlindDataVault | None = None,
    recap_blind_data_stage: BlindDataStage | None = None,
) -> tuple[Any, ...]:
    row = _reference_dataset_row(dataset_payload)
    observed_omega = _reference_observed_omega(model_payload)
    expected_omega = float(row["known_omega"])
    omega_tolerance = max(_reference_omega_tolerance(model_payload), abs(observed_omega) * 0.01, 1e-30)
    expected_from_equation = _reference_predict_omega(
        model_payload,
        t_n=float(row["T_n"]),
        alpha=float(row["alpha"]),
        beta_over_h=float(row.get("beta_over_H", 100.0)),
        wall_velocity=float(row.get("v_w", 0.7)),
        frequency_hz=float(row.get("frequency", 0.003)),
    )
    if (recap_blind_data_vault is None) != (recap_blind_data_stage is None):
        raise ValueError("reference recap vault and stage must be supplied together")
    if recap_blind_data_vault is None:
        recap_vault, recap_stage = _reference_recap_stage(
            artifact_store=artifact_store,
            row=row,
            expected_omega=expected_omega,
            job_id=job_id,
            trace_id=trace_id,
        )
    else:
        recap_vault = recap_blind_data_vault
        recap_stage = recap_blind_data_stage
    plugins: list[Any] = [
        S3InjectionCheckPlugin(
            samples=_reference_injection_samples(expected_omega=expected_omega, observed_omega=observed_omega),
        ),
        S3NullControlCheckPlugin(samples=_reference_null_control_samples()),
        S3PhysicalConsistencyCheckPlugin(
            samples=(
                S3PhysicalConsistencySample(
                    sample_id="ewpt-reference-omega",
                    observable="omega",
                    value=observed_omega,
                    units=_reference_omega_units(model_payload),
                    expected_units="dimensionless",
                    non_negative=True,
                    asymptotic_expected=expected_from_equation,
                ),
            ),
        ),
        S3CalibrationCheckPlugin(
            samples=_reference_calibration_samples(
                prediction=observed_omega,
                truth=expected_omega,
                tolerance=omega_tolerance,
            ),
        ),
        S3RecapBenchmarkCheckPlugin(
            blind_data_vault=recap_vault,
            blind_data_stage=recap_stage,
            predictions=(
                S3RecapBenchmarkPrediction(
                    sample_id="ewpt-reference-omega",
                    prediction=observed_omega,
                ),
            ),
        ),
    ]
    if include_m3_checks:
        if contamination_index is None or contamination_snapshot is None:
            raise ValueError("reference M3 checks require a frozen contamination snapshot")
        plugins.insert(
            2,
            S3CrossCodeCheckPlugin(
                samples=(
                    S3CrossCodeSample(
                        sample_id="ewpt-reference-omega",
                        pipeline_value=observed_omega,
                        reference_value=expected_omega,
                        pipeline_uncertainty=omega_tolerance,
                        reference_uncertainty=omega_tolerance,
                        pipeline_units=_reference_omega_units(model_payload),
                        reference_units="dimensionless",
                        extrapolation_flag=extrapolated,
                    ),
                ),
                independence_resolution=_reference_independence_resolution(),
            ),
        )
        plugins.insert(
            4,
            S3LeakageCheckPlugin(
                candidate_text=_reference_candidate_text(
                    model_payload=model_payload,
                    observed_omega=observed_omega,
                ),
                contamination_index=contamination_index,
                contamination_snapshot=contamination_snapshot,
            ),
        )
    return tuple(plugins)


def _reference_compiled_profile(*, profile_ref: str, include_m3_checks: bool) -> CompiledProfile:
    checks: list[CompiledCheckSpec] = [
        _reference_compiled_check(
            "INJECTION",
            thresholds={"recovery_rate_min": 1.0},
            tolerance={
                "relative_tolerance": 0.35,
                "absolute_tolerance": 0.01,
                "slope_tolerance": 0.3,
                "intercept_tolerance_abs": 0.01,
            },
            seed=17,
        ),
        _reference_compiled_check(
            "NULL_CONTROL",
            thresholds={"alpha": 0.5, "confidence_level": 0.95},
            seed=18,
        ),
        _reference_compiled_check(
            "PHYSICAL_CONSISTENCY",
            thresholds={
                "mandatory_gates": ["dimensional", "positivity", "asymptotic"],
                "normalization_epsilon": 0.01,
            },
            tolerance={"absolute_tolerance": 0.01},
            seed=20,
        ),
        _reference_compiled_check(
            "CALIBRATION",
            thresholds={"nominal_coverage": 0.68, "alpha": 0.05, "min_samples": 10},
            tolerance={"coverage_abs": 0.5},
            seed=22,
        ),
        _reference_compiled_check(
            "RECAP_BENCHMARK",
            thresholds={"absolute_tolerance": 0.01, "relative_tolerance": 0.0, "min_recovered_fraction": 1.0},
            seed=23,
        ),
    ]
    if include_m3_checks:
        checks.insert(
            2,
            _reference_compiled_check(
                "CROSS_CODE",
                thresholds={
                    "reduced_chi_square_min": 0.0,
                    "reduced_chi_square_max": 1.5,
                    "z_max": 3.0,
                    "max_excluded_fraction": 0.0,
                    "min_valid_points": 1,
                },
                requires_independence=True,
                seed=19,
            ),
        )
        checks.insert(
            4,
            _reference_compiled_check(
                "LEAKAGE",
                thresholds={
                    "mandatory_gates": ["frozen_index_overlap"],
                    "overlap_threshold": 0.8,
                    "frozen_index_threshold": 0.8,
                    "target_leakage_purity_threshold": 0.95,
                    "target_leakage_min_support": 2,
                    "shingle_size": 5,
                    "min_reward_score_delta": 0.0,
                },
                seed=21,
            ),
        )
    return CompiledProfile(
        profile_id="s1-reference-ewpt",
        revision=1,
        profile_ref=profile_ref,
        subtopic=S1_REFERENCE_PHYSICS_SUBTOPIC,
        spec_hash="hash-s1-reference-ewpt",
        public_profile={
            "profile_id": "s1-reference-ewpt",
            "revision": 1,
            "checks": [check.check for check in checks],
        },
        cost_estimate={"max_wallclock_s": 3.0},
        checks=tuple(checks),
        independence_policy={"requires_cross_code": include_m3_checks, "min_independent": 2 if include_m3_checks else 0},
        determinism_profile={
            "seeded_checks": [{"check": check.check, "seed": check.seed} for check in checks],
        },
    )


def _reference_compiled_check(
    check: str,
    *,
    thresholds: dict[str, Any],
    tolerance: dict[str, Any] | None = None,
    requires_independence: bool = False,
    seed: int,
) -> CompiledCheckSpec:
    return CompiledCheckSpec(
        check=check,
        plugin_ref=f"argus.s3.plugins.{check.lower()}",
        plugin_version="1.0.0",
        mandatory=True,
        thresholds=thresholds,
        determinism="deterministic",
        seed=seed,
        tolerance=tolerance or {},
        requires_independence=requires_independence,
        budget={"max_wallclock_s": 3.0},
        adapter=None,
    )


def _reference_injection_samples(*, expected_omega: float, observed_omega: float) -> tuple[S3InjectionSample, ...]:
    return tuple(
        S3InjectionSample(
            sample_id=f"ewpt-injection-{index}",
            injected_value=expected_omega * scale,
            recovered_value=observed_omega * scale,
        )
        for index, scale in enumerate((0.5, 1.0, 1.5), start=1)
    )


def _reference_null_control_samples() -> tuple[S3NullControlSample, ...]:
    return tuple(
        S3NullControlSample(
            sample_id=f"ewpt-null-alpha-{index}",
            variant="label_shuffle",
            detected=False,
        )
        for index in range(1, 11)
    )


def _reference_calibration_samples(
    *,
    prediction: float,
    truth: float,
    tolerance: float,
) -> tuple[S3CalibrationSample, ...]:
    pit_values = (0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95)
    return tuple(
        S3CalibrationSample(
            sample_id=f"ewpt-calibration-{index}",
            prediction=prediction,
            interval_lower=prediction - tolerance,
            interval_upper=prediction + tolerance,
            truth=truth,
            pit_value=pit,
        )
        for index, pit in enumerate(pit_values, start=1)
    )


def _reference_independence_resolution() -> S3IndependenceResolution:
    challengers = _reference_challengers()
    return S3IndependenceResolution(
        test_case="S3-TC09",
        verdict="INDEPENDENT",
        candidate_ids=tuple(challenger.entity_id for challenger in challengers),
        cross_codes=tuple(challenger.entity_id for challenger in challengers),
        rejected_candidate_ids=(),
        excluded_tags=("reference-physics",),
        degradations=(),
        min_independent=2,
        max_claim_tier="novel-needs-human",
        c5_pinned_revisions={challenger.entity_id: challenger.revision for challenger in challengers},
    )


def _reference_recap_stage(
    *,
    artifact_store: InMemoryArtifactStore,
    row: Mapping[str, Any],
    expected_omega: float,
    job_id: str,
    trace_id: str | None,
):
    vault = InMemoryBlindDataVault(artifact_store=artifact_store, actor_id=S1_REFERENCE_S3_VERIFIER_ID)
    record = vault.register_dataset(
        dataset_id=f"s1-reference-recap-{job_id}",
        version="1.0.0",
        split="recap",
        dataset_kind="recap_benchmark",
        opaque_input={
            "schema": "argus.s3.reference_recap_opaque_input.v1",
            "samples": [
                {
                    "sample_id": "ewpt-reference-omega",
                    "T_n": float(row["T_n"]),
                    "alpha": float(row["alpha"]),
                    "v_w": float(row["v_w"]),
                }
            ],
        },
        truth={
            "samples": [
                {
                    "sample_id": "ewpt-reference-omega",
                    "expected": expected_omega,
                }
            ],
        },
    )
    stage = S3BlindDataManager(
        artifact_store=artifact_store,
        vault=vault,
        actor_id=S1_REFERENCE_S3_VERIFIER_ID,
    ).stage_for_pipeline(
        blind_data_handle=record.handle,
        job_id=job_id,
        trace_id=trace_id,
    )
    return vault, stage


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
    expected_perturbed_omega = _reference_predict_omega(
        model_payload,
        t_n=t_n,
        alpha=perturbed_alpha,
        beta_over_h=float(row.get("beta_over_H", 100.0)),
        wall_velocity=float(row.get("v_w", 0.7)),
        frequency_hz=float(row.get("frequency", 0.003)),
    )
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


def _reference_model_payload(
    store: InMemoryArtifactStore,
    *,
    frozen_pipeline_ref: str,
    frozen_payload: Mapping[str, Any],
    frozen_pipeline_execution: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if frozen_payload.get("schema") == "argus.s1.reference_physics_model.v1":
        return dict(frozen_payload)
    if frozen_payload.get("s3_executable") is True and isinstance(frozen_payload.get("component_refs"), Mapping):
        return _reference_s2_model_payload(
            store,
            frozen_pipeline_ref=frozen_pipeline_ref,
            frozen_payload=frozen_payload,
            frozen_pipeline_execution=frozen_pipeline_execution,
        )
    model_ref = frozen_payload.get("model_ref")
    if isinstance(model_ref, str):
        model_payload = _artifact_payload(store, model_ref)
        if model_payload.get("schema") == "argus.s1.reference_physics_model.v1":
            return model_payload
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


def _reference_s2_model_payload(
    store: InMemoryArtifactStore,
    *,
    frozen_pipeline_ref: str,
    frozen_payload: Mapping[str, Any],
    frozen_pipeline_execution: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    component_refs = frozen_payload.get("component_refs")
    if not isinstance(component_refs, Mapping):
        raise ValueError("S2 reference frozen pipeline requires component_refs")
    input_refs = component_refs.get("input_refs")
    if not isinstance(input_refs, list):
        raise ValueError("S2 reference frozen pipeline requires input_refs")
    dataset_ref = _reference_s2_dataset_ref(store, input_refs)
    dataset_payload = _artifact_payload(store, dataset_ref)
    row = _reference_dataset_row(dataset_payload)
    target_scale = _reference_positive_scale(dataset_payload.get("target_scale"), "S2 reference target_scale")
    if frozen_pipeline_execution is None:
        prediction = FrozenPipelineRunner(artifact_store=store).predict(
            frozen_pipeline_ref,
            {
                "adapter_omega_scaled": {
                    "value": _reference_scaled_row_value(row, "adapter_omega_scaled"),
                    "units": "dimensionless",
                }
            },
        )
        outputs_units_tagged = prediction.outputs_units_tagged
        uncertainty = prediction.uncertainty
    else:
        outputs_units_tagged, uncertainty = _reference_sandbox_pipeline_output(
            store,
            frozen_pipeline_ref=frozen_pipeline_ref,
            execution=frozen_pipeline_execution,
        )
    scaled_output = outputs_units_tagged.get("omega_scaled")
    if not isinstance(scaled_output, Mapping):
        raise ValueError("S2 reference frozen pipeline did not return omega_scaled")
    scaled_value = _reference_positive_scale(scaled_output.get("value"), "S2 reference prediction")
    if not isinstance(uncertainty, Mapping) or uncertainty.get("kind") != "interval":
        raise ValueError("S2 reference frozen pipeline requires interval uncertainty")
    scaled_radius = _reference_non_negative_finite(uncertainty.get("radius"), "S2 reference uncertainty radius")
    reference_context = dataset_payload.get("reference_context")
    perturbation_observations = (
        dict(reference_context.get("perturbation_observations"))
        if isinstance(reference_context, Mapping) and isinstance(reference_context.get("perturbation_observations"), Mapping)
        else {}
    )
    return {
        "schema": "argus.s3.s2_reference_model_view.v1",
        "model_family": "s2-ewpt-tabular-reference",
        "dataset_ref": dataset_ref,
        "s2_frozen_pipeline_ref": frozen_pipeline_ref,
        "adapter_outputs": {
            "omega": {
                "value": scaled_value * target_scale,
                "units": "dimensionless",
                "uncertainty": {
                    "kind": "interval",
                    "radius": scaled_radius * target_scale,
                    "source": uncertainty.get("source", "s2-uq"),
                },
            }
        },
        "perturbation_observations": perturbation_observations,
    }


def _reference_sandbox_pipeline_output(
    store: InMemoryArtifactStore,
    *,
    frozen_pipeline_ref: str,
    execution: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(execution, Mapping):
        raise ValueError("S2 reference sandbox execution must be a mapping")
    if execution.get("schema") != "argus.s3.frozen_pipeline_execution_output.v1":
        raise ValueError("S2 reference sandbox execution schema is unsupported")
    if execution.get("entrypoint") != "predict":
        raise ValueError("S2 reference sandbox execution entrypoint is invalid")
    if execution.get("frozen_pipeline_ref") != frozen_pipeline_ref:
        raise ValueError("S2 reference sandbox execution frozen pipeline does not match the validation request")
    record = store.get_record(frozen_pipeline_ref)
    if execution.get("frozen_pipeline_content_hash") != record.content_hash:
        raise ValueError("S2 reference sandbox execution content hash does not match C4")
    outputs = execution.get("outputs_units_tagged")
    uncertainty = execution.get("uncertainty")
    if not isinstance(outputs, Mapping):
        raise ValueError("S2 reference sandbox execution outputs are missing")
    if not isinstance(uncertainty, Mapping):
        raise ValueError("S2 reference sandbox execution uncertainty is missing")
    return dict(outputs), dict(uncertainty)


def _reference_s2_dataset_ref(store: InMemoryArtifactStore, input_refs: list[Any]) -> str:
    dataset_refs: list[str] = []
    for artifact_ref in input_refs:
        if not isinstance(artifact_ref, str) or not artifact_ref:
            continue
        try:
            record = store.get_record(artifact_ref)
        except KeyError:
            continue
        if record.kind == "dataset":
            dataset_refs.append(artifact_ref)
    if len(dataset_refs) != 1:
        raise ValueError("S2 reference frozen pipeline must resolve exactly one dataset input")
    return dataset_refs[0]


def _reference_scaled_row_value(row: Mapping[str, Any], field: str) -> float:
    return _reference_positive_scale(row.get(field), f"reference dataset {field}")


def _reference_positive_scale(value: Any, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{context} must be a positive finite number")
    normalized = float(value)
    if not isfinite(normalized) or normalized <= 0.0:
        raise ValueError(f"{context} must be a positive finite number")
    return normalized


def _reference_non_negative_finite(value: Any, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{context} must be a finite number")
    normalized = float(value)
    if not isfinite(normalized) or normalized < 0.0:
        raise ValueError(f"{context} must be a finite number")
    return normalized


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


def _reference_predict_omega(
    model_payload: Mapping[str, Any],
    *,
    t_n: float,
    alpha: float,
    beta_over_h: float,
    wall_velocity: float,
    frequency_hz: float,
) -> float:
    if model_payload.get("model_family") not in {"ewpt-tabular-reference", "s2-ewpt-tabular-reference"}:
        raise ValueError("reference S3 verifier only supports ewpt-tabular-reference models")
    return evaluate_sound_wave_spectrum(
        temperature_gev=t_n,
        alpha=alpha,
        beta_over_h=beta_over_h,
        wall_velocity=wall_velocity,
        frequency_hz=frequency_hz,
    ).omega


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
