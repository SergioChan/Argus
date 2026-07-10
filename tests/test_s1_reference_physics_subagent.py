from __future__ import annotations

import json
import unittest

from argus_core import (
    BudgetCaps,
    CheckResult,
    EgressRule,
    GW_SPECTRUM_ADAPTER_ID,
    InMemoryTokenService,
    Lineage,
    LaunchEnvelope,
    LaunchRequest,
    LifecycleState,
    LifecyclePolicyError,
    Producer,
    ScopeGrant,
    S1_REFERENCE_PHYSICS_PROFILE_REF,
    S1ReferencePhysicsHarness,
    evaluate_sound_wave_spectrum,
    tier_from_checks,
)
import argus_core.s1_reference as s1_reference_module
from argus_core.s1_reference import _ReferenceS3ValidationClient, _reference_sandbox_output


class S1ReferencePhysicsSubagentTests(unittest.TestCase):
    def test_reference_sandbox_output_mismatch_is_fail_closed(self) -> None:
        adapter_outputs = {
            "omega": {"value": 2.1267660025483526e-11},
            "peak_omega": {"value": 2.1561841843479577e-11},
            "peak_frequency": {"value": 0.0027439964271339418},
        }

        with self.assertRaises(LifecyclePolicyError) as raised:
            _reference_sandbox_output(
                {
                    "omega": 1.0,
                    "peak_omega": 2.1561841843479577e-11,
                    "peak_frequency": 0.0027439964271339418,
                },
                adapter_outputs=adapter_outputs,
            )
        self.assertEqual(raised.exception.envelope.code, "S10_REFERENCE_SANDBOX_OUTPUT_MISMATCH")

    def test_reference_build_executes_an_injected_s10_sandbox_and_records_its_output(self) -> None:
        tokens = InMemoryTokenService(signing_key=b"reference-sandbox-test", now_fn=lambda: 1_000)
        calls: list[dict[str, object]] = []

        class SandboxMarshaler:
            def submit_sandbox_job(self, *, job_id: str, spec: dict[str, object]) -> dict[str, object]:
                calls.append({"job_id": job_id, "spec": spec})
                return {
                    "job_id": job_id,
                    "sandbox_id": "s1-reference-sandbox",
                    "state": "SUCCEEDED",
                    "exit_code": 0,
                    "timed_out": False,
                    "duration_s": 0.05,
                    "stdout": json.dumps(
                        {
                            "omega": 2.1267660025483526e-11,
                            "peak_omega": 2.1561841843479577e-11,
                            "peak_frequency": 0.0027439964271339418,
                        }
                    ),
                    "stderr": "",
                    "launch_provenance_ref": "c4://container/s1-reference-sandbox",
                    "budget_usage": {"wallclock_s": 0.05},
                }

        def sandbox_spec_factory(job_id: str, adapter_inputs: dict[str, object]) -> dict[str, object]:
            self.assertEqual(job_id, "job-s1-reference-sandbox")
            self.assertIn("alpha", adapter_inputs)
            return {
                "launch_request": LaunchRequest(
                    job_id=job_id,
                    subagent_id="s1-reference-physics",
                    trace_id=f"trace:{job_id}",
                    budget_token=tokens.mint_budget(
                        caps=BudgetCaps(max_compute_units=10, max_wallclock_s=10, max_cost_usd=1),
                        job_id=job_id,
                        root_request_id=f"root:{job_id}",
                    ),
                    scope_token=tokens.mint_scope(
                        job_id=job_id,
                        scopes=ScopeGrant(
                            allowed_adapters=(GW_SPECTRUM_ADAPTER_ID,),
                            egress_allowlist=(
                                EgressRule("store.local", 443, "https"),
                                EgressRule("adapter.local", 443, "https"),
                            ),
                            sandbox_risk_class="standard",
                        ),
                    ),
                    image="busybox@sha256:" + "b" * 64,
                    entrypoint=("awk",),
                    args=("BEGIN { print \\\"{}\\\" }",),
                    env={},
                    env_allowlist=(),
                    requested_envelope=LaunchEnvelope(
                        cpu_m=250,
                        mem_bytes=64 * 1024 * 1024,
                        gpu_count=0,
                        wallclock_s=10,
                        scratch_bytes=1024 * 1024,
                        pids=8,
                        estimated_cost_usd=0.01,
                    ),
                )
            }

        harness = S1ReferencePhysicsHarness(
            sandbox_marshaler=SandboxMarshaler(),
            sandbox_spec_factory=sandbox_spec_factory,
            adapter_egress_allowlist={
                GW_SPECTRUM_ADAPTER_ID: (EgressRule("adapter.local", 443, "https"),),
            },
        )

        result = harness.run_happy_path(job_id="job-s1-reference-sandbox")

        self.assertEqual(len(calls), 1)
        self.assertEqual(result.final_state, LifecycleState.REPORTED)
        sandbox = result.build_payload["diagnostics"]["sandbox"]
        self.assertEqual(sandbox["sandbox_id"], "s1-reference-sandbox")
        self.assertEqual(sandbox["launch_provenance_ref"], "c4://container/s1-reference-sandbox")
        self.assertEqual(sandbox["output"]["omega"], 2.1267660025483526e-11)

    def test_full_reference_physics_lifecycle_reaches_reported_and_observatory_verified(self) -> None:
        harness = S1ReferencePhysicsHarness()

        result = harness.run_happy_path(job_id="job-s1-t28-happy")

        self.assertTrue(result.acceptance.accepted)
        self.assertEqual(result.final_state, LifecycleState.REPORTED)
        self.assertEqual(result.lifecycle_methods, ("accept", "plan", "build", "validate", "report"))
        self.assertGreaterEqual(len(result.artifact_refs), 1)
        self.assertTrue(result.validation_report_ref.startswith("c4://"))
        self.assertEqual(result.validation_report_payload["claim_tier"], "recapitulated-known")
        self.assertFalse(result.validation_report_payload["claim_tier_is_candidate"])
        self.assertEqual(
            result.validation_report_payload["claim_tier_justification"]["requested_tier"],
            "recapitulated-known",
        )
        self.assertEqual(result.subagent_report["validation_report_ref"], result.validation_report_ref)
        self.assertEqual(result.subagent_report["claim_tier"], "recapitulated-known")
        self.assertIn("reproducibility_manifest", result.subagent_report)
        self.assertEqual(result.promoted_artifact.validation_report_ref, result.validation_report_ref)
        self.assertEqual(result.promoted_artifact.claim_tier, "recapitulated-known")
        self.assertTrue(result.observatory_render.verification.trusted)
        self.assertIn('data-verdict="VERIFIED"', result.observatory_render.html)
        self.assertTrue(result.observatory_html_ref.startswith("c4://"))

    def test_reference_physics_report_uses_s3_verifier_tier_and_distinct_referee_key(self) -> None:
        harness = S1ReferencePhysicsHarness()

        result = harness.run_happy_path(job_id="job-s1-t28-s3-verifier")
        report = result.validation_report_payload
        checks = tuple(
            CheckResult(str(check["check"]), str(check["status"]), dict(check.get("metrics", {})))
            for check in report["checks"]
        )

        self.assertEqual(report["claim_tier"], tier_from_checks(checks))
        self.assertEqual(report["signature"]["key_id"], "s3-reference-referee-key")
        self.assertEqual(report["referee"]["signed_by"], "s3-reference-referee-key")
        self.assertEqual(report["referee"]["referee_id"], "s3-reference-verifier")
        self.assertNotEqual(report["referee"]["referee_id"], "s1-reference-physics")

    def test_reference_physics_demo_uses_plugin_host_evidence_for_validation_checks(self) -> None:
        harness = S1ReferencePhysicsHarness()

        result = harness.run_happy_path(job_id="job-r48-m1-plugin-host")
        checks = {check["check"]: check for check in result.validation_report_payload["checks"]}
        expected_plugin_refs = {
            "INJECTION": "argus.s3.plugins.injection",
            "NULL_CONTROL": "argus.s3.plugins.null_control",
            "PHYSICAL_CONSISTENCY": "argus.s3.plugins.physical_consistency",
            "CALIBRATION": "argus.s3.plugins.calibration",
            "RECAP_BENCHMARK": "argus.s3.plugins.recap_benchmark",
        }

        self.assertEqual(set(checks), set(expected_plugin_refs))
        for check_name, plugin_ref in expected_plugin_refs.items():
            evidence_refs = checks[check_name].get("evidence_refs")
            self.assertIsInstance(evidence_refs, list)
            self.assertEqual(len(evidence_refs), 1)
            evidence_payload = json.loads(harness.artifact_store.get_artifact(evidence_refs[0]).decode("utf-8"))
            self.assertEqual(evidence_payload["schema"], "argus.s3.check_result_evidence.v1")
            self.assertEqual(evidence_payload["check"], check_name)
            self.assertEqual(evidence_payload["plugin_ref"], plugin_ref)
            self.assertEqual(evidence_payload["plugin_version"], "1.0.0")

    def test_reference_physics_demo_signer_uses_secretless_trust_store_boundary(self) -> None:
        self.assertFalse(hasattr(s1_reference_module, "S1_REFERENCE_S3_REFEREE_SECRET"))
        harness = S1ReferencePhysicsHarness()

        result = harness.run_happy_path(job_id="job-r48-m2-secretless-signer")

        verification = harness.report_verifier.verify(result.validation_report_payload)
        self.assertTrue(verification.valid)
        verifier_key = harness.s3_key_manager.get_key("s3-reference-referee-key")
        self.assertIsNotNone(verifier_key)
        assert verifier_key is not None
        self.assertEqual(verifier_key.secret, b"")

    def test_reference_physics_checks_are_computed_from_c4_handoff_artifacts(self) -> None:
        harness = S1ReferencePhysicsHarness()

        result = harness.run_happy_path(job_id="job-s1-t28-check-metrics")
        checks = {check["check"]: check for check in result.validation_report_payload["checks"]}

        self.assertEqual(
            set(checks),
            {
                "INJECTION",
                "NULL_CONTROL",
                "PHYSICAL_CONSISTENCY",
                "CALIBRATION",
                "RECAP_BENCHMARK",
            },
        )
        self.assertEqual(checks["INJECTION"]["metrics"]["recovery_rate"], 1.0)
        self.assertEqual(checks["INJECTION"]["metrics"]["linearity_slope"], 1.0)
        self.assertEqual(checks["NULL_CONTROL"]["metrics"]["false_positives"], 0)
        self.assertTrue(checks["PHYSICAL_CONSISTENCY"]["metrics"]["physical_consistency_pass"])
        expected_omega = evaluate_sound_wave_spectrum(
            temperature_gev=100.0,
            alpha=0.2,
            beta_over_h=100.0,
            wall_velocity=0.7,
            frequency_hz=0.003,
        ).omega
        self.assertAlmostEqual(
            checks["PHYSICAL_CONSISTENCY"]["metrics"]["sub_gates"]["asymptotic"]["comparisons"][0]["expected"],
            expected_omega,
        )
        self.assertEqual(result.build_payload["diagnostics"]["adapter_id"], GW_SPECTRUM_ADAPTER_ID)
        self.assertEqual(checks["CALIBRATION"]["metrics"]["nominal_coverage"], 0.68)
        recap_metrics = checks["RECAP_BENCHMARK"]["metrics"]
        self.assertTrue(recap_metrics["recap_benchmark_pass"])
        self.assertTrue(recap_metrics["truth_retained_server_side"])
        self.assertFalse(recap_metrics["truth_bytes_delivered_to_sandbox"])
        self.assertFalse(recap_metrics["truth_hash_delivered_to_sandbox"])
        self.assertFalse(recap_metrics["raw_truth_exposed"])

    def test_reference_perturbation_uses_c4_model_response_not_canned_literals(self) -> None:
        harness = S1ReferencePhysicsHarness()
        dataset_ref = "c4://dataset/ewpt-reference/r44-m2-underresponsive"
        must_react_ref = "c4://log/ewpt-reference/r44-m2-underresponsive-alpha"
        must_not_react_ref = "c4://log/ewpt-reference/r44-m2-underresponsive-vw"
        model_ref = "c4://model/ewpt-reference/r44-m2-underresponsive"
        pipeline_ref = "c4://pipeline/ewpt-reference/r44-m2-underresponsive"
        reference = evaluate_sound_wave_spectrum(
            temperature_gev=100.0,
            alpha=0.2,
            beta_over_h=100.0,
            wall_velocity=0.7,
            frequency_hz=0.003,
        )
        perturbed = evaluate_sound_wave_spectrum(
            temperature_gev=100.0,
            alpha=0.2 * 0.2,
            beta_over_h=100.0,
            wall_velocity=0.7,
            frequency_hz=0.003,
        )
        expected_omega = reference.omega
        observed_omega = expected_omega
        must_react_omega = observed_omega - 0.75 * (expected_omega - perturbed.omega)
        uncertainty_radius = 0.35 * expected_omega
        harness.artifact_store.create_artifact(
            kind="dataset",
            artifact_ref=dataset_ref,
            payload={
                "rows": [
                    {
                        "T_n": 100.0,
                        "alpha": 0.2,
                        "beta_over_H": 100.0,
                        "v_w": 0.7,
                        "frequency": 0.003,
                        "known_omega": expected_omega,
                    }
                ]
            },
            producer=Producer(subsystem="S6", version="0.0.0", actor_id="s6.reference-dataset"),
            lineage=Lineage(input_refs=(), code_ref="git:s6-r44-m2-dataset", environment_digest="oci:s6-reference"),
        )
        harness.artifact_store.create_artifact(
            kind="log",
            artifact_ref=must_react_ref,
            payload={
                "adapter_id": GW_SPECTRUM_ADAPTER_ID,
                "perturbation": {"field": "alpha", "scale": 0.2},
                "omega": {"value": must_react_omega, "units": "dimensionless"},
            },
            producer=Producer(subsystem="S7", version="1.0.0", actor_id="s7.adapter-broker"),
            lineage=Lineage(
                input_refs=(dataset_ref,),
                code_ref="adapter:gw_spectrum@1.0.0",
                environment_digest="oci:s7-reference",
            ),
        )
        harness.artifact_store.create_artifact(
            kind="log",
            artifact_ref=must_not_react_ref,
            payload={
                "adapter_id": GW_SPECTRUM_ADAPTER_ID,
                "perturbation": {"field": "v_w.uncertainty.radius", "scale": 2.0},
                "omega": {"value": observed_omega, "units": "dimensionless"},
            },
            producer=Producer(subsystem="S7", version="1.0.0", actor_id="s7.adapter-broker"),
            lineage=Lineage(
                input_refs=(dataset_ref,),
                code_ref="adapter:gw_spectrum@1.0.0",
                environment_digest="oci:s7-reference",
            ),
        )
        harness.artifact_store.create_artifact(
            kind="model",
            artifact_ref=model_ref,
            payload={
                "schema": "argus.s1.reference_physics_model.v1",
                "model_family": "ewpt-tabular-reference",
                "dataset_ref": dataset_ref,
                "adapter_outputs": {
                    "omega": {
                        "value": observed_omega,
                        "units": "dimensionless",
                        "uncertainty": {"kind": "interval", "radius": uncertainty_radius},
                    }
                },
                "perturbation_observations": {
                    "schema": "argus.s1.reference_physics_perturbation_observations.v1",
                    "must_react": {
                        "perturbation": {"field": "alpha", "scale": 0.2},
                        "omega": {
                            "value": must_react_omega,
                            "units": "dimensionless",
                            "uncertainty": {"kind": "interval", "radius": uncertainty_radius},
                        },
                        "provenance_ref": must_react_ref,
                    },
                    "must_not_react": {
                        "perturbation": {"field": "v_w.uncertainty.radius", "scale": 2.0},
                        "omega": {
                            "value": observed_omega,
                            "units": "dimensionless",
                            "uncertainty": {"kind": "interval", "radius": uncertainty_radius},
                        },
                        "provenance_ref": must_not_react_ref,
                    },
                },
                "diagnostics": {"dataset_ref": dataset_ref, "adapter_id": GW_SPECTRUM_ADAPTER_ID},
                "uncertainty_tag": {"kind": "interval", "source": GW_SPECTRUM_ADAPTER_ID},
            },
            producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.reference-physics"),
            lineage=Lineage(
                input_refs=(dataset_ref, must_react_ref, must_not_react_ref),
                code_ref="argus-core:s1.reference-physics.r44-m2",
                environment_digest="python:s1-reference-physics:v1",
                seeds=("7",),
            ),
        )
        harness.artifact_store.create_artifact(
            kind="container",
            artifact_ref=pipeline_ref,
            payload={
                "schema": "argus.s1.reference_physics_pipeline.v1",
                "entrypoint": "predict",
                "model_ref": model_ref,
                "artifact_refs": [model_ref],
                "uncertainty_tag": {"kind": "interval", "source": GW_SPECTRUM_ADAPTER_ID},
            },
            producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.reference-physics"),
            lineage=Lineage(
                input_refs=(model_ref,),
                code_ref="argus-core:s1.reference-physics.freeze",
                environment_digest="python:s1-reference-physics:v1",
                seeds=("7",),
            ),
        )
        validation_client = _ReferenceS3ValidationClient(
            artifact_store=harness.artifact_store,
            verifier=harness.s3_verifier,
            contamination_index=harness.contamination_index,
            contamination_snapshot=harness.contamination_snapshot,
            mode="happy",
        )

        report = validation_client.validate(
            {
                "job_id": "job-r44-m2-underresponsive",
                "profile_ref": S1_REFERENCE_PHYSICS_PROFILE_REF,
                "frozen_pipeline_ref": pipeline_ref,
            }
        )
        checks = {check["check"]: check for check in report["checks"]}
        must_react = next(pair for pair in report["perturbation_pairs"] if pair["kind"] == "must_react")
        must_not_react = next(pair for pair in report["perturbation_pairs"] if pair["kind"] == "must_not_react")

        self.assertTrue(
            all(check["status"] == "PASS" for check in checks.values()),
            {name: check["status"] for name, check in checks.items()},
        )
        self.assertEqual(must_react["verdict"], "fail")
        self.assertAlmostEqual(must_react["amplitude_linearity"]["observed"], 0.75)
        self.assertNotEqual(must_react["amplitude_linearity"]["observed"], 1.0)
        self.assertEqual(must_not_react["verdict"], "pass")
        self.assertAlmostEqual(must_not_react["observed_degradation"]["observed_signal"], 0.0)
        self.assertFalse(report["aggregate"]["passed"])
        self.assertEqual(report["claim_tier"], "ran-toy")

    def test_refusal_reroute_records_first_refused_and_second_reported(self) -> None:
        harness = S1ReferencePhysicsHarness()

        reroute = harness.run_refusal_reroute(job_id="job-s1-t28-reroute")

        self.assertFalse(reroute.first_acceptance.accepted)
        self.assertEqual(reroute.first_acceptance.reason, "OUT_OF_SCOPE")
        self.assertEqual(reroute.first_final_state, LifecycleState.REJECTED)
        self.assertTrue(reroute.second.acceptance.accepted)
        self.assertEqual(reroute.second.final_state, LifecycleState.REPORTED)
        self.assertEqual(reroute.second.lifecycle_methods, ("accept", "plan", "build", "validate", "report"))

    def test_units_mismatch_is_recorded_as_diagnostic_without_numeric_result(self) -> None:
        harness = S1ReferencePhysicsHarness()

        failure = harness.run_units_mismatch(job_id="job-s1-t28-units")

        self.assertEqual(failure.final_state, LifecycleState.FAILED)
        self.assertEqual(failure.error["category"], "VALIDATION")
        self.assertEqual(failure.error["code"], "UNITS_MISMATCH")
        self.assertEqual(failure.build_diagnostics["adapter_error"]["code"], "UNITS_MISMATCH")
        self.assertNotIn("outputs", json.dumps(failure.build_diagnostics, sort_keys=True))

    def test_extrapolated_adapter_output_is_risk_noted_and_s3_inconclusive(self) -> None:
        harness = S1ReferencePhysicsHarness()

        result = harness.run_extrapolated(job_id="job-s1-t28-extrapolated")

        self.assertEqual(result.final_state, LifecycleState.REPORTED)
        self.assertTrue(result.build_payload["diagnostics"]["risk_notes"][0]["extrapolation_flag"])
        statuses = {check["check"]: check["status"] for check in result.validation_report_payload["checks"]}
        self.assertEqual(statuses["CROSS_CODE"], "INCONCLUSIVE")
        self.assertFalse(result.validation_report_payload["aggregate"]["passed"])
        self.assertEqual(result.subagent_report["claim_tier"], "ran-toy")

    def test_evolver_variant_build_has_derived_from_edge_and_distinct_content_hash(self) -> None:
        harness = S1ReferencePhysicsHarness()
        base = harness.run_happy_path(job_id="job-s1-t28-base")

        variant = harness.run_variant(job_id="job-s1-t28-variant", base_artifact_ref=base.promoted_artifact.artifact_ref)

        self.assertEqual(variant.final_state, LifecycleState.REPORTED)
        self.assertNotEqual(variant.promoted_artifact.content_hash, base.promoted_artifact.content_hash)
        lineage = harness.artifact_store.get_lineage(variant.promoted_artifact.artifact_ref, direction="ancestors")
        derived_edges = {
            (edge.source_ref, edge.target_ref, edge.edge_type)
            for edge in lineage.edges
            if edge.edge_type == "derived_from"
        }
        self.assertIn(
            (base.promoted_artifact.artifact_ref, variant.promoted_artifact.artifact_ref, "derived_from"),
            derived_edges,
        )


if __name__ == "__main__":
    unittest.main()
