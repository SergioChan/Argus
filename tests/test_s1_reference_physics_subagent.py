from __future__ import annotations

import json
import unittest

from argus_core import (
    CheckResult,
    LifecycleState,
    S1ReferencePhysicsHarness,
    tier_from_checks,
)


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

    def test_reference_physics_six_checks_are_computed_from_c4_handoff_artifacts(self) -> None:
        harness = S1ReferencePhysicsHarness()

        result = harness.run_happy_path(job_id="job-s1-t28-check-metrics")
        checks = {check["check"]: check for check in result.validation_report_payload["checks"]}

        self.assertEqual(checks["INJECTION"]["metrics"]["observed_omega"], 0.02)
        self.assertEqual(checks["INJECTION"]["metrics"]["expected_omega"], 0.02)
        self.assertEqual(checks["NULL_CONTROL"]["metrics"]["null_alpha"], 0.0)
        self.assertEqual(checks["PHYSICAL_CONSISTENCY"]["metrics"]["model_family"], "ewpt-tabular-reference")
        self.assertTrue(checks["LEAKAGE"]["metrics"]["snapshot_ref"].startswith("c4://"))
        self.assertEqual(checks["CALIBRATION"]["metrics"]["nominal_coverage"], 1.0)

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
