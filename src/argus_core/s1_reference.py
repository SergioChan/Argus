"""Reference S1 physics subagent integration harness for the M1 vertical slice."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Any, Mapping
from uuid import NAMESPACE_URL, uuid5

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
from .s3 import CheckResult, run_cross_code_check, run_perturbation_pair
from .s7 import AdapterBroker, AdapterDescriptor, NormalizedQuantity, Quantity, SimpleAdapter
from .s8 import ArtifactRecord, InMemoryArtifactStore, Lineage, Producer
from .s10 import InMemoryAuditLedger, InMemoryTokenService, ScopeGrant
from .s11 import ObservatoryLineageBundle, ObservatoryRenderResult, render_observatory_v0_html


S1_REFERENCE_PHYSICS_ADAPTER_ID = "gw_spectrum_surrogate"
S1_REFERENCE_PHYSICS_SUBTOPIC = "ewpt"
S1_REFERENCE_PHYSICS_PROFILE_REF = "c4://profile/ewpt-reference/v1"
S1_REFERENCE_PHYSICS_DATASET_REF = "c4://dataset/ewpt-reference/v1"


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
        self.trust_store.register_key("s3-reference-key", b"s3-reference-secret")
        self.report_verifier = C3ReportVerifier(self.trust_store)
        self.signer = C3ReportSigner(key_id="s3-reference-key", secret=b"s3-reference-secret")
        self.artifact_store = artifact_store or InMemoryArtifactStore(report_verifier=self.report_verifier)
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
                signer=self.signer,
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
        diagnostics = {
            "dataset_ref": dataset["dataset_ref"],
            "adapter_id": result["adapter_id"],
            "adapter_provenance_ref": adapter_call["provenance_ref"],
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
            "diagnostics": diagnostics,
            "uncertainty_tag": {"kind": "interval", "source": "gw_spectrum_surrogate"},
        }
        lineage_inputs = (self.dataset_ref, str(adapter_call["provenance_ref"]))
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
    def __init__(self, *, artifact_store: InMemoryArtifactStore, signer: C3ReportSigner, mode: str) -> None:
        self.artifact_store = artifact_store
        self.signer = signer
        self.mode = mode

    def validate(self, request: dict[str, object]) -> dict[str, Any]:
        extrapolated = self._request_has_extrapolated_artifact(request)
        checks = _reference_checks(extrapolated=extrapolated or self.mode == "extrapolated")
        aggregate_passed = all(check.status == "PASS" for check in checks)
        claim_tier = "recapitulated-known" if aggregate_passed else "ran-toy"
        outcome = run_perturbation_pair(
            perturbation_id=f"pair-{request['job_id']}",
            must_react_expected=1.0,
            must_react_observed=1.0,
            must_not_react_observed=0.0,
            unperturbed_headline=1.0,
            perturbed_headline=0.2,
        )
        report = {
            "report_id": str(uuid5(NAMESPACE_URL, f"argus:s1-reference-physics:{request['job_id']}:{self.mode}")),
            "profile_ref": str(request["profile_ref"]),
            "frozen_pipeline_ref": str(request["frozen_pipeline_ref"]),
            "checks": [_check_payload(check) for check in checks],
            "aggregate": {
                "passed": aggregate_passed,
                "score": sum(1.0 for check in checks if check.status == "PASS") / len(checks),
            },
            "claim_tier": claim_tier,
            "claim_tier_is_candidate": False,
            "perturbation_pairs": [_drop_none(asdict(pair)) for pair in outcome.perturbation_pairs],
            "insensitivity_flags": [_drop_none(asdict(flag)) for flag in outcome.insensitivity_flags],
            "challenger_panel": {
                "challenger_ids": ["challenger-a", "challenger-b"],
                "min_required": 2,
                "attack_types": ["signal_injection", "null_noise"],
            },
            "independence_attestation_debate": {
                "min_independent_challengers": 2,
                "lineage_disjoint": True,
                "correlation_warning": False,
            },
            "referee": {
                "referee_id": "s3-reference-referee",
                "non_gameable": True,
                "signed_by": self.signer.key_id,
                "distinct_from_proponent": True,
            },
            "debate_ref": f"c4://debate/s1-reference/{request['job_id']}",
        }
        return self.signer.sign(report)

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


def _reference_checks(*, extrapolated: bool) -> tuple[CheckResult, ...]:
    cross_code = run_cross_code_check(
        observed=(0.02,),
        independent=(0.0205,),
        combined_uncertainty=(0.01,),
        extrapolation_flags=(extrapolated,),
    )
    return (
        CheckResult("INJECTION", "PASS", {"recovery_rate": 0.98}),
        CheckResult("NULL_CONTROL", "PASS", {"false_positive_rate": 0.0}),
        cross_code,
        CheckResult("PHYSICAL_CONSISTENCY", "PASS", {"unit_balance": "ok"}),
        CheckResult("LEAKAGE", "PASS", {"blind_label_access": 0}),
        CheckResult("CALIBRATION", "PASS", {"ece": 0.01}),
    )


def _check_payload(check: CheckResult) -> dict[str, Any]:
    payload = {"check": check.check, "status": check.status}
    if check.metrics is not None:
        payload["metrics"] = check.metrics
    return payload


def _drop_none(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if value is not None}


def _artifact_payload(store: InMemoryArtifactStore, artifact_ref: str) -> dict[str, Any]:
    payload = json.loads(store.get_artifact(artifact_ref).decode("utf-8"))
    if not isinstance(payload, dict):
        return {}
    return payload


def _lifecycle_methods(runner: SubagentSDKRunner, job_id: str) -> tuple[str, ...]:
    return tuple(event.method for event in runner.runtime.store.events(job_id))
