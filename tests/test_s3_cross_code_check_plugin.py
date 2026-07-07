from __future__ import annotations

import json
import unittest

from argus_core import (
    CheckPluginHost,
    CheckPluginHostError,
    CompiledCheckSpec,
    CompiledProfile,
    InMemoryArtifactStore,
    S3CrossCodeCheckPlugin,
    S3CrossCodeSample,
    S3IndependenceResolution,
)


class S3CrossCodeCheckPluginTests(unittest.TestCase):
    def test_tc09_cross_code_agreement_passes_with_redacted_c4_evidence(self) -> None:
        store = InMemoryArtifactStore()
        plugin = S3CrossCodeCheckPlugin(
            samples=(
                S3CrossCodeSample(
                    sample_id="pt-1",
                    pipeline_value=10.00,
                    reference_value=10.24,
                    pipeline_uncertainty=0.20,
                    reference_uncertainty=0.20,
                    pipeline_units="pb",
                    reference_units="pb",
                ),
                S3CrossCodeSample(
                    sample_id="pt-2",
                    pipeline_value=12.00,
                    reference_value=11.75,
                    pipeline_uncertainty=0.25,
                    reference_uncertainty=0.25,
                    pipeline_units="pb",
                    reference_units="pb",
                ),
                S3CrossCodeSample(
                    sample_id="pt-3",
                    pipeline_value=8.00,
                    reference_value=8.28,
                    pipeline_uncertainty=0.20,
                    reference_uncertainty=0.20,
                    pipeline_units="pb",
                    reference_units="pb",
                ),
            ),
            independence_resolution=_independent_resolution(),
        )
        host = CheckPluginHost(
            plugins=(plugin,),
            artifact_store=store,
            actor_id="s3-cross-code-test",
            job_id="job-s3-t18-pass",
        )

        (result,) = host.run(_compiled_profile())

        self.assertEqual(result.check, "CROSS_CODE")
        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.plugin_ref, "argus.s3.plugins.cross_code")
        self.assertEqual(result.plugin_version, "1.0.0")
        self.assertEqual(result.metrics["test_cases"], ["S3-TC09"])
        self.assertTrue(result.metrics["cross_code_pass"])
        self.assertGreaterEqual(result.metrics["reduced_chi_square"], result.metrics["reduced_chi_square_min"])
        self.assertLessEqual(result.metrics["reduced_chi_square"], result.metrics["reduced_chi_square_max"])
        self.assertLessEqual(result.metrics["max_abs_z"], result.metrics["z_max"])
        self.assertEqual(result.metrics["valid_point_count"], 3)
        self.assertEqual(result.metrics["points_excluded"], 0)
        self.assertEqual(result.metrics["independence_verdict"], "INDEPENDENT")
        self.assertEqual(result.metrics["cross_codes"], ["s7-independent-twin"])
        self.assertNotIn("pipeline_values", result.metrics)
        self.assertNotIn("reference_values", result.metrics)
        self.assertNotIn("sample_ids", result.metrics)

        self.assertIsNotNone(result.evidence_ref)
        evidence_payload = json.loads(store.get_artifact(result.evidence_ref).decode("utf-8"))
        self.assertEqual(evidence_payload["check"], "CROSS_CODE")
        self.assertEqual(evidence_payload["status"], "PASS")
        self.assertNotIn("pipeline_values", evidence_payload["metrics"])
        self.assertNotIn("reference_values", evidence_payload["metrics"])
        self.assertNotIn("sample_ids", evidence_payload["metrics"])
        self.assertEqual(store.get_record(result.evidence_ref).kind, "s3_check_result")

    def test_tc10_cross_code_detects_single_implementation_bias(self) -> None:
        plugin = S3CrossCodeCheckPlugin(
            samples=(
                S3CrossCodeSample(
                    sample_id="bias-1",
                    pipeline_value=10.0,
                    reference_value=12.0,
                    pipeline_uncertainty=0.20,
                    reference_uncertainty=0.20,
                    pipeline_units="pb",
                    reference_units="pb",
                ),
                S3CrossCodeSample(
                    sample_id="bias-2",
                    pipeline_value=11.0,
                    reference_value=13.0,
                    pipeline_uncertainty=0.20,
                    reference_uncertainty=0.20,
                    pipeline_units="pb",
                    reference_units="pb",
                ),
                S3CrossCodeSample(
                    sample_id="bias-3",
                    pipeline_value=12.0,
                    reference_value=14.0,
                    pipeline_uncertainty=0.20,
                    reference_uncertainty=0.20,
                    pipeline_units="pb",
                    reference_units="pb",
                ),
            ),
            independence_resolution=_independent_resolution(),
        )

        (result,) = CheckPluginHost(plugins=(plugin,)).run(_compiled_profile())

        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.metrics["test_cases"], ["S3-TC10"])
        self.assertGreater(result.metrics["reduced_chi_square"], result.metrics["reduced_chi_square_max"])
        self.assertGreater(result.metrics["max_abs_z"], result.metrics["z_max"])
        self.assertEqual(result.metrics["failure_reason"], "AGREEMENT_OUT_OF_BOUNDS")

    def test_tc11_out_of_validity_points_are_excluded_and_can_make_check_inconclusive(self) -> None:
        plugin = S3CrossCodeCheckPlugin(
            samples=(
                S3CrossCodeSample(
                    sample_id="valid-1",
                    pipeline_value=4.0,
                    reference_value=4.02,
                    pipeline_uncertainty=0.10,
                    reference_uncertainty=0.10,
                    pipeline_units="pb",
                    reference_units="pb",
                ),
                S3CrossCodeSample(
                    sample_id="extrapolated-1",
                    pipeline_value=5.0,
                    reference_value=5.0,
                    pipeline_uncertainty=0.10,
                    reference_uncertainty=0.10,
                    pipeline_units="pb",
                    reference_units="pb",
                    extrapolation_flag=True,
                ),
                S3CrossCodeSample(
                    sample_id="extrapolated-2",
                    pipeline_value=6.0,
                    reference_value=6.0,
                    pipeline_uncertainty=0.10,
                    reference_uncertainty=0.10,
                    pipeline_units="pb",
                    reference_units="pb",
                    extrapolation_flag=True,
                ),
            ),
            independence_resolution=_independent_resolution(),
        )

        (result,) = CheckPluginHost(plugins=(plugin,)).run(_compiled_profile(thresholds={"max_excluded_fraction": 0.5}))

        self.assertEqual(result.status, "INCONCLUSIVE")
        self.assertEqual(result.metrics["test_cases"], ["S3-TC11"])
        self.assertEqual(result.metrics["points_excluded"], 2)
        self.assertEqual(result.metrics["valid_point_count"], 1)
        self.assertGreater(result.metrics["excluded_fraction"], result.metrics["max_excluded_fraction"])
        self.assertEqual(result.metrics["failure_reason"], "EXCLUDED_FRACTION_EXCEEDS_MAX")

    def test_tc47_units_mismatch_fails_without_numeric_coercion(self) -> None:
        plugin = S3CrossCodeCheckPlugin(
            samples=(
                S3CrossCodeSample(
                    sample_id="units-1",
                    pipeline_value=1.0,
                    reference_value=1000.0,
                    pipeline_uncertainty=0.10,
                    reference_uncertainty=100.0,
                    pipeline_units="pb",
                    reference_units="fb",
                ),
            ),
            independence_resolution=_independent_resolution(),
        )

        (result,) = CheckPluginHost(plugins=(plugin,)).run(_compiled_profile())

        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.metrics["test_cases"], ["S3-TC47"])
        self.assertEqual(result.metrics["failure_reason"], "UNITS_MISMATCH")
        self.assertEqual(result.metrics["units_mismatch_count"], 1)
        self.assertFalse(result.metrics["numeric_coercion_performed"])
        self.assertNotIn("coerced_values", result.metrics)

    def test_missing_independence_or_invalid_samples_fail_closed_before_c4_evidence(self) -> None:
        no_independence_store = InMemoryArtifactStore()
        no_independence_plugin = S3CrossCodeCheckPlugin(
            samples=(
                S3CrossCodeSample(
                    sample_id="pt-1",
                    pipeline_value=1.0,
                    reference_value=1.0,
                    pipeline_uncertainty=0.1,
                    reference_uncertainty=0.1,
                    pipeline_units="pb",
                    reference_units="pb",
                ),
            ),
            independence_resolution=None,
        )
        with self.assertRaises(CheckPluginHostError) as no_independence:
            CheckPluginHost(
                plugins=(no_independence_plugin,),
                artifact_store=no_independence_store,
            ).run(_compiled_profile())

        self.assertEqual(no_independence.exception.category, "CHECK_FAILED")
        self.assertEqual(no_independence.exception.code, "CHECK_PLUGIN_FAILED")
        self.assertEqual(no_independence_store.record_count, 0)

        invalid_store = InMemoryArtifactStore()
        invalid_plugin = S3CrossCodeCheckPlugin(
            samples=(
                S3CrossCodeSample(
                    sample_id="pt-1",
                    pipeline_value=1.0,
                    reference_value=1.0,
                    pipeline_uncertainty=0.0,
                    reference_uncertainty=0.0,
                    pipeline_units="pb",
                    reference_units="pb",
                ),
            ),
            independence_resolution=_independent_resolution(),
        )
        with self.assertRaises(CheckPluginHostError) as invalid:
            CheckPluginHost(plugins=(invalid_plugin,), artifact_store=invalid_store).run(_compiled_profile())

        self.assertEqual(invalid.exception.category, "CHECK_FAILED")
        self.assertEqual(invalid.exception.code, "CHECK_PLUGIN_FAILED")
        self.assertEqual(invalid_store.record_count, 0)


def _independent_resolution() -> S3IndependenceResolution:
    return S3IndependenceResolution(
        test_case="S3-T14",
        verdict="INDEPENDENT",
        candidate_ids=("s7-independent-twin",),
        cross_codes=("s7-independent-twin",),
        rejected_candidate_ids=(),
        excluded_tags=("pipeline-under-test",),
        degradations=(),
        min_independent=1,
        max_claim_tier="novel-needs-human",
        c5_pinned_revisions={"s7-independent-twin": 3},
    )


def _compiled_profile(*, thresholds: dict[str, float] | None = None) -> CompiledProfile:
    merged_thresholds = {
        "reduced_chi_square_min": 0.5,
        "reduced_chi_square_max": 1.5,
        "z_max": 3.0,
        "max_excluded_fraction": 0.25,
        "min_valid_points": 2,
    }
    if thresholds is not None:
        merged_thresholds.update(thresholds)
    return CompiledProfile(
        profile_id="s3-t18-test",
        revision=1,
        profile_ref="c4://profile/s3-t18-test/rev/1",
        subtopic="electroweak.phase_transition",
        spec_hash="hash-s3-t18",
        public_profile={"profile_id": "s3-t18-test", "revision": 1, "checks": ["CROSS_CODE"]},
        cost_estimate={"max_wallclock_s": 3.0},
        checks=(
            CompiledCheckSpec(
                check="CROSS_CODE",
                plugin_ref="argus.s3.plugins.cross_code",
                plugin_version="1.0.0",
                mandatory=True,
                thresholds=merged_thresholds,
                determinism="deterministic",
                seed=18,
                tolerance={},
                requires_independence=True,
                budget={"max_wallclock_s": 3.0},
                adapter=None,
            ),
        ),
        independence_policy={"requires_cross_code": True, "min_independent": 1},
        determinism_profile={"seeded_checks": [{"check": "CROSS_CODE", "seed": 18}]},
    )


if __name__ == "__main__":
    unittest.main()
