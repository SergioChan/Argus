from __future__ import annotations

import json
import unittest

from argus_core import (
    CheckResult,
    Lineage,
    LifecycleState,
    Producer,
    S1_REFERENCE_PHYSICS_PROFILE_REF,
    S1ReferencePhysicsHarness,
    tier_from_checks,
)
from argus_core.s1_reference import _ReferenceS3ValidationClient


class S1ReferencePhysicsSubagentTests(unittest.TestCase):
    def test_full_reference_physics_lifecycle_reaches_reported_and_observatory_verified(self) -> None:
        harness = S1ReferencePhysicsHarness()

        result = harness.run_happy_path(job_id="job-s1-t28-happy")

        self.assertTrue(result.acceptance.accepted)
        self.assertEqual(result.final_state, LifecycleState.REPORTED)
        self.assertEqual(result.lifecycle_methods, ("accept", "plan", "build", "validate", "report"))
        self.assertGreaterEqual(len(result.artifact_refs), 1)
        self.assertTrue(result.validation_report_ref.startswith("c4://"))
        self.assertEqual(result.validation_report_payload["claim_tier"], "novel-needs-human")
        self.assertTrue(result.validation_report_payload["claim_tier_is_candidate"])
        self.assertEqual(result.subagent_report["validation_report_ref"], result.validation_report_ref)
        self.assertEqual(result.subagent_report["claim_tier"], "novel-needs-human")
        self.assertIn("reproducibility_manifest", result.subagent_report)
        self.assertEqual(result.promoted_artifact.validation_report_ref, result.validation_report_ref)
        self.assertEqual(result.promoted_artifact.claim_tier, "novel-needs-human")
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

    def test_reference_physics_checks_are_computed_from_c4_handoff_artifacts(self) -> None:
        harness = S1ReferencePhysicsHarness()

        result = harness.run_happy_path(job_id="job-s1-t28-check-metrics")
        checks = {check["check"]: check for check in result.validation_report_payload["checks"]}

        self.assertEqual(
            set(checks),
            {
                "INJECTION",
                "NULL_CONTROL",
                "CROSS_CODE",
                "PHYSICAL_CONSISTENCY",
                "LEAKAGE",
                "CALIBRATION",
                "RECAP_BENCHMARK",
            },
        )
        self.assertEqual(checks["INJECTION"]["metrics"]["observed_omega"], 0.02)
        self.assertEqual(checks["INJECTION"]["metrics"]["expected_omega"], 0.02)
        self.assertEqual(checks["NULL_CONTROL"]["metrics"]["null_alpha"], 0.0)
        self.assertEqual(checks["PHYSICAL_CONSISTENCY"]["metrics"]["model_family"], "ewpt-tabular-reference")
        self.assertTrue(checks["LEAKAGE"]["metrics"]["snapshot_ref"].startswith("c4://"))
        self.assertEqual(checks["CALIBRATION"]["metrics"]["nominal_coverage"], 1.0)
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
        harness.artifact_store.create_artifact(
            kind="dataset",
            artifact_ref=dataset_ref,
            payload={"rows": [{"T_n": 100.0, "alpha": 0.2, "v_w": 0.7, "known_omega": 0.02}]},
            producer=Producer(subsystem="S6", version="0.0.0", actor_id="s6.reference-dataset"),
            lineage=Lineage(input_refs=(), code_ref="git:s6-r44-m2-dataset", environment_digest="oci:s6-reference"),
        )
        harness.artifact_store.create_artifact(
            kind="log",
            artifact_ref=must_react_ref,
            payload={
                "adapter_id": "gw_spectrum_surrogate",
                "perturbation": {"field": "alpha", "scale": 0.2},
                "omega": {"value": 0.003, "units": "dimensionless"},
            },
            producer=Producer(subsystem="S7", version="1.0.0", actor_id="s7.adapter-broker"),
            lineage=Lineage(
                input_refs=(dataset_ref,),
                code_ref="adapter:gw_spectrum_surrogate@1.0.0",
                environment_digest="oci:s7-reference",
            ),
        )
        harness.artifact_store.create_artifact(
            kind="log",
            artifact_ref=must_not_react_ref,
            payload={
                "adapter_id": "gw_spectrum_surrogate",
                "perturbation": {"field": "v_w", "delta": 0.02},
                "omega": {"value": 0.015, "units": "dimensionless"},
            },
            producer=Producer(subsystem="S7", version="1.0.0", actor_id="s7.adapter-broker"),
            lineage=Lineage(
                input_refs=(dataset_ref,),
                code_ref="adapter:gw_spectrum_surrogate@1.0.0",
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
                        "value": 0.015,
                        "units": "dimensionless",
                        "uncertainty": {"kind": "interval", "radius": 0.01},
                    }
                },
                "perturbation_observations": {
                    "schema": "argus.s1.reference_physics_perturbation_observations.v1",
                    "must_react": {
                        "perturbation": {"field": "alpha", "scale": 0.2},
                        "omega": {
                            "value": 0.003,
                            "units": "dimensionless",
                            "uncertainty": {"kind": "interval", "radius": 0.01},
                        },
                        "provenance_ref": must_react_ref,
                    },
                    "must_not_react": {
                        "perturbation": {"field": "v_w", "delta": 0.02},
                        "omega": {
                            "value": 0.015,
                            "units": "dimensionless",
                            "uncertainty": {"kind": "interval", "radius": 0.01},
                        },
                        "provenance_ref": must_not_react_ref,
                    },
                },
                "diagnostics": {"dataset_ref": dataset_ref, "adapter_id": "gw_spectrum_surrogate"},
                "uncertainty_tag": {"kind": "interval", "source": "gw_spectrum_surrogate"},
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
                "uncertainty_tag": {"kind": "interval", "source": "gw_spectrum_surrogate"},
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

        self.assertTrue(all(check["status"] == "PASS" for check in checks.values()))
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
