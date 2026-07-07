from __future__ import annotations

import json
import unittest

from argus_core import (
    CheckPluginHost,
    CheckPluginHostError,
    CompiledCheckSpec,
    CompiledProfile,
    InMemoryArtifactStore,
    S3PhysicalConsistencyCheckPlugin,
    S3PhysicalConsistencySample,
)


class S3PhysicalConsistencyCheckPluginTests(unittest.TestCase):
    def test_tc12_dimensional_gate_catches_unit_error_with_c4_evidence(self) -> None:
        store = InMemoryArtifactStore()
        plugin = S3PhysicalConsistencyCheckPlugin(
            samples=(
                S3PhysicalConsistencySample(
                    sample_id="unit-error",
                    observable="cross_section",
                    value=1.0,
                    units="GeV^2",
                    expected_units="GeV",
                ),
            )
        )

        (result,) = CheckPluginHost(
            plugins=(plugin,),
            artifact_store=store,
            actor_id="s3-physical-consistency-test",
            job_id="job-s3-t19-dimensional",
        ).run(_compiled_profile(mandatory_gates=("dimensional",)))

        self.assertEqual(result.check, "PHYSICAL_CONSISTENCY")
        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.plugin_ref, "argus.s3.plugins.physical_consistency")
        self.assertEqual(result.plugin_version, "1.0.0")
        self.assertEqual(result.metrics["test_cases"], ["S3-TC12"])
        self.assertFalse(result.metrics["physical_consistency_pass"])
        self.assertEqual(result.metrics["sub_gates"]["dimensional"]["status"], "FAIL")
        self.assertEqual(result.metrics["sub_gates"]["dimensional"]["dimension_mismatch_count"], 1)
        self.assertEqual(result.metrics["failure_reasons"], ["DIMENSION_MISMATCH"])
        self.assertNotIn("sample_ids", result.metrics)

        self.assertIsNotNone(result.evidence_ref)
        evidence_payload = json.loads(store.get_artifact(result.evidence_ref).decode("utf-8"))
        self.assertEqual(evidence_payload["check"], "PHYSICAL_CONSISTENCY")
        self.assertEqual(evidence_payload["status"], "FAIL")
        self.assertEqual(store.get_record(result.evidence_ref).kind, "s3_check_result")
        self.assertNotIn("sample_ids", evidence_payload["metrics"])

    def test_tc13_positivity_gate_reports_offending_point(self) -> None:
        plugin = S3PhysicalConsistencyCheckPlugin(
            samples=(
                S3PhysicalConsistencySample(
                    sample_id="negative-xs",
                    observable="cross_section",
                    value=-0.03,
                    units="pb",
                    expected_units="pb",
                    non_negative=True,
                ),
            )
        )

        (result,) = CheckPluginHost(plugins=(plugin,)).run(_compiled_profile(mandatory_gates=("positivity",)))

        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.metrics["test_cases"], ["S3-TC13"])
        positivity = result.metrics["sub_gates"]["positivity"]
        self.assertEqual(positivity["status"], "FAIL")
        self.assertEqual(positivity["negative_count"], 1)
        self.assertLess(positivity["min_output"], 0.0)
        self.assertEqual(positivity["offending_points"][0]["observable"], "cross_section")
        self.assertLess(positivity["offending_points"][0]["value"], 0.0)
        self.assertNotIn("sample_id", positivity["offending_points"][0])

    def test_tc14_unitarity_normalization_bound_fails_above_epsilon(self) -> None:
        plugin = S3PhysicalConsistencyCheckPlugin(
            samples=(
                S3PhysicalConsistencySample(
                    sample_id="p1",
                    observable="p_higgs",
                    value=0.6,
                    units="dimensionless",
                    expected_units="dimensionless",
                    normalization_group="branching_probabilities",
                ),
                S3PhysicalConsistencySample(
                    sample_id="p2",
                    observable="p_top",
                    value=0.5,
                    units="dimensionless",
                    expected_units="dimensionless",
                    normalization_group="branching_probabilities",
                ),
                S3PhysicalConsistencySample(
                    sample_id="p3",
                    observable="p_other",
                    value=0.2,
                    units="dimensionless",
                    expected_units="dimensionless",
                    normalization_group="branching_probabilities",
                ),
            )
        )

        (result,) = CheckPluginHost(plugins=(plugin,)).run(
            _compiled_profile(
                mandatory_gates=("normalization",),
                thresholds={"normalization_epsilon": 0.01},
            )
        )

        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.metrics["test_cases"], ["S3-TC14"])
        normalization = result.metrics["sub_gates"]["normalization"]
        self.assertEqual(normalization["status"], "FAIL")
        self.assertGreater(normalization["group_results"][0]["sum"], 1.0 + normalization["epsilon"])
        self.assertEqual(result.metrics["failure_reasons"], ["NORMALIZATION_BOUND_EXCEEDED"])

    def test_tc15_symmetry_invariance_passes_and_breaking_fixture_fails(self) -> None:
        passing = S3PhysicalConsistencyCheckPlugin(
            samples=(
                S3PhysicalConsistencySample(
                    sample_id="sym-pass",
                    observable="spectrum",
                    value=2.0,
                    units="GeV",
                    expected_units="GeV",
                    symmetry_transform="parity",
                    transformed_value=2.01,
                ),
            )
        )
        failing = S3PhysicalConsistencyCheckPlugin(
            samples=(
                S3PhysicalConsistencySample(
                    sample_id="sym-fail",
                    observable="spectrum",
                    value=2.0,
                    units="GeV",
                    expected_units="GeV",
                    symmetry_transform="parity",
                    transformed_value=2.2,
                ),
            )
        )

        (pass_result,) = CheckPluginHost(plugins=(passing,)).run(_compiled_profile(mandatory_gates=("symmetry",)))
        (fail_result,) = CheckPluginHost(plugins=(failing,)).run(_compiled_profile(mandatory_gates=("symmetry",)))

        self.assertEqual(pass_result.status, "PASS")
        self.assertEqual(pass_result.metrics["test_cases"], ["S3-TC15"])
        self.assertTrue(pass_result.metrics["sub_gates"]["symmetry"]["symmetry_pass"])
        self.assertEqual(fail_result.status, "FAIL")
        self.assertEqual(fail_result.metrics["test_cases"], ["S3-TC15"])
        self.assertFalse(fail_result.metrics["sub_gates"]["symmetry"]["symmetry_pass"])
        self.assertGreater(fail_result.metrics["sub_gates"]["symmetry"]["max_error"], 0.05)

    def test_tc16_asymptotic_limit_passes_and_deterministic_violation_fails(self) -> None:
        passing = S3PhysicalConsistencyCheckPlugin(
            samples=(
                S3PhysicalConsistencySample(
                    sample_id="limit-pass",
                    observable="theta_to_zero",
                    value=0.995,
                    units="dimensionless",
                    expected_units="dimensionless",
                    asymptotic_expected=1.0,
                ),
            )
        )
        failing = S3PhysicalConsistencyCheckPlugin(
            samples=(
                S3PhysicalConsistencySample(
                    sample_id="limit-fail",
                    observable="theta_to_zero",
                    value=0.75,
                    units="dimensionless",
                    expected_units="dimensionless",
                    asymptotic_expected=1.0,
                ),
            )
        )

        (pass_result,) = CheckPluginHost(plugins=(passing,)).run(_compiled_profile(mandatory_gates=("asymptotic",)))
        (fail_result,) = CheckPluginHost(plugins=(failing,)).run(_compiled_profile(mandatory_gates=("asymptotic",)))

        self.assertEqual(pass_result.status, "PASS")
        self.assertEqual(pass_result.metrics["test_cases"], ["S3-TC16"])
        self.assertTrue(pass_result.metrics["sub_gates"]["asymptotic"]["asymptotic_pass"])
        self.assertEqual(fail_result.status, "FAIL")
        self.assertEqual(fail_result.metrics["test_cases"], ["S3-TC16"])
        self.assertFalse(fail_result.metrics["sub_gates"]["asymptotic"]["asymptotic_pass"])
        self.assertGreater(fail_result.metrics["sub_gates"]["asymptotic"]["max_error"], 0.05)

    def test_missing_mandatory_gates_or_malformed_units_fail_closed_before_c4_evidence(self) -> None:
        missing_store = InMemoryArtifactStore()
        plugin = S3PhysicalConsistencyCheckPlugin(
            samples=(
                S3PhysicalConsistencySample(
                    sample_id="valid",
                    observable="probability",
                    value=0.4,
                    units="dimensionless",
                    expected_units="dimensionless",
                ),
            )
        )
        with self.assertRaises(CheckPluginHostError) as missing:
            CheckPluginHost(plugins=(plugin,), artifact_store=missing_store).run(
                _compiled_profile(mandatory_gates=None)
            )

        self.assertEqual(missing.exception.category, "CHECK_FAILED")
        self.assertEqual(missing.exception.code, "CHECK_PLUGIN_FAILED")
        self.assertEqual(missing_store.record_count, 0)

        malformed_store = InMemoryArtifactStore()
        malformed = S3PhysicalConsistencyCheckPlugin(
            samples=(
                S3PhysicalConsistencySample(
                    sample_id="bad-units",
                    observable="energy",
                    value=1.0,
                    units="mystery",
                    expected_units="GeV",
                ),
            )
        )
        with self.assertRaises(CheckPluginHostError) as invalid:
            CheckPluginHost(plugins=(malformed,), artifact_store=malformed_store).run(
                _compiled_profile(mandatory_gates=("dimensional",))
            )

        self.assertEqual(invalid.exception.category, "CHECK_FAILED")
        self.assertEqual(invalid.exception.code, "CHECK_PLUGIN_FAILED")
        self.assertEqual(malformed_store.record_count, 0)


def _compiled_profile(
    *,
    mandatory_gates: tuple[str, ...] | None,
    thresholds: dict[str, object] | None = None,
    tolerance: dict[str, float] | None = None,
) -> CompiledProfile:
    merged_thresholds: dict[str, object] = {
        "normalization_epsilon": 0.01,
    }
    if mandatory_gates is not None:
        merged_thresholds["mandatory_gates"] = list(mandatory_gates)
    if thresholds is not None:
        merged_thresholds.update(thresholds)
    merged_tolerance = {
        "absolute_tolerance": 0.05,
    }
    if tolerance is not None:
        merged_tolerance.update(tolerance)
    return CompiledProfile(
        profile_id="s3-t19-test",
        revision=1,
        profile_ref="c4://profile/s3-t19-test/rev/1",
        subtopic="electroweak.phase_transition",
        spec_hash="hash-s3-t19",
        public_profile={"profile_id": "s3-t19-test", "revision": 1, "checks": ["PHYSICAL_CONSISTENCY"]},
        cost_estimate={"max_wallclock_s": 3.0},
        checks=(
            CompiledCheckSpec(
                check="PHYSICAL_CONSISTENCY",
                plugin_ref="argus.s3.plugins.physical_consistency",
                plugin_version="1.0.0",
                mandatory=True,
                thresholds=merged_thresholds,
                determinism="deterministic",
                seed=19,
                tolerance=merged_tolerance,
                requires_independence=False,
                budget={"max_wallclock_s": 3.0},
                adapter=None,
            ),
        ),
        independence_policy={"requires_cross_code": False},
        determinism_profile={"deterministic_checks": ["PHYSICAL_CONSISTENCY"]},
    )


if __name__ == "__main__":
    unittest.main()
