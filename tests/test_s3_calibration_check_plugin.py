from __future__ import annotations

import json
import math
import unittest

from argus_core import (
    CheckPluginHost,
    CheckPluginHostError,
    CompiledCheckSpec,
    CompiledProfile,
    InMemoryArtifactStore,
    S3CalibrationCheckPlugin,
    S3CalibrationSample,
)


class S3CalibrationCheckPluginTests(unittest.TestCase):
    def test_tc19_overconfident_intervals_fail_with_c4_evidence(self) -> None:
        store = InMemoryArtifactStore()
        plugin = S3CalibrationCheckPlugin(
            samples=tuple(
                S3CalibrationSample(
                    sample_id=f"overconfident-{index}",
                    prediction=0.0,
                    interval_lower=-0.1,
                    interval_upper=0.1,
                    truth=0.0 if index < 3 else 1.0,
                    pit_value=0.99,
                )
                for index in range(10)
            )
        )

        (result,) = CheckPluginHost(
            plugins=(plugin,),
            artifact_store=store,
            actor_id="s3-calibration-test",
            job_id="job-s3-t21-overconfident",
        ).run(_compiled_profile())

        self.assertEqual(result.check, "CALIBRATION")
        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.plugin_ref, "argus.s3.plugins.calibration")
        self.assertEqual(result.plugin_version, "1.0.0")
        self.assertEqual(result.metrics["test_cases"], ["S3-TC19"])
        self.assertFalse(result.metrics["calibration_pass"])
        self.assertFalse(result.metrics["coverage_pass"])
        self.assertFalse(result.metrics["pit_pass"])
        self.assertEqual(result.metrics["covered_count"], 3)
        self.assertAlmostEqual(result.metrics["empirical_coverage"], 0.3)
        self.assertLess(result.metrics["pit_p_value"], result.metrics["alpha"])
        self.assertEqual(result.metrics["failure_reasons"], ["COVERAGE_OUT_OF_TOLERANCE", "PIT_KS_REJECTED"])
        self.assertNotIn("sample_id", json.dumps(result.metrics))
        self.assertNotIn("overconfident-", json.dumps(result.metrics))
        self.assertNotIn("truth", json.dumps(result.metrics).lower())
        self.assertNotIn("prediction", json.dumps(result.metrics).lower())

        self.assertIsNotNone(result.evidence_ref)
        evidence_payload = json.loads(store.get_artifact(result.evidence_ref).decode("utf-8"))
        self.assertEqual(evidence_payload["check"], "CALIBRATION")
        self.assertEqual(evidence_payload["status"], "FAIL")
        self.assertEqual(store.get_record(result.evidence_ref).kind, "s3_check_result")
        self.assertNotIn("overconfident-", json.dumps(evidence_payload))

    def test_tc20_well_calibrated_intervals_pass(self) -> None:
        samples = []
        for index in range(100):
            covered = index < 68
            samples.append(
                S3CalibrationSample(
                    sample_id=f"well-calibrated-{index}",
                    prediction=0.0,
                    interval_lower=-1.0,
                    interval_upper=1.0,
                    truth=0.0 if covered else 2.0,
                    pit_value=(index + 0.5) / 100.0,
                )
            )
        plugin = S3CalibrationCheckPlugin(samples=tuple(samples))

        (result,) = CheckPluginHost(plugins=(plugin,)).run(_compiled_profile(min_samples=50))

        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.metrics["test_cases"], ["S3-TC20"])
        self.assertTrue(result.metrics["calibration_pass"])
        self.assertTrue(result.metrics["coverage_pass"])
        self.assertTrue(result.metrics["pit_pass"])
        self.assertEqual(result.metrics["covered_count"], 68)
        self.assertEqual(result.metrics["sample_count"], 100)
        self.assertAlmostEqual(result.metrics["empirical_coverage"], 0.68)
        self.assertGreaterEqual(result.metrics["pit_p_value"], result.metrics["alpha"])
        self.assertNotIn("well-calibrated-", json.dumps(result.metrics))

    def test_missing_thresholds_duplicate_ids_invalid_intervals_and_pit_fail_closed(self) -> None:
        missing_store = InMemoryArtifactStore()
        with self.assertRaises(CheckPluginHostError) as missing:
            CheckPluginHost(
                plugins=(
                    S3CalibrationCheckPlugin(
                        samples=(
                            S3CalibrationSample(
                                sample_id="valid-1",
                                prediction=0.0,
                                interval_lower=-1.0,
                                interval_upper=1.0,
                                truth=0.0,
                                pit_value=0.5,
                            ),
                        )
                    ),
                ),
                artifact_store=missing_store,
            ).run(_compiled_profile(thresholds={"alpha": 0.05}, tolerance={}))

        self.assertEqual(missing.exception.category, "CHECK_FAILED")
        self.assertEqual(missing.exception.code, "CHECK_PLUGIN_FAILED")
        self.assertEqual(missing_store.record_count, 0)

        duplicate_store = InMemoryArtifactStore()
        with self.assertRaises(CheckPluginHostError):
            CheckPluginHost(
                plugins=(
                    S3CalibrationCheckPlugin(
                        samples=(
                            S3CalibrationSample("dup", 0.0, -1.0, 1.0, 0.0, 0.5),
                            S3CalibrationSample("dup", 0.0, -1.0, 1.0, 0.0, 0.5),
                        )
                    ),
                ),
                artifact_store=duplicate_store,
            ).run(_compiled_profile(min_samples=2))
        self.assertEqual(duplicate_store.record_count, 0)

        invalid_interval_store = InMemoryArtifactStore()
        with self.assertRaises(CheckPluginHostError):
            CheckPluginHost(
                plugins=(
                    S3CalibrationCheckPlugin(
                        samples=(
                            S3CalibrationSample("bad-interval", 0.0, 1.0, -1.0, 0.0, 0.5),
                            S3CalibrationSample("valid-2", 0.0, -1.0, 1.0, 0.0, 0.5),
                        )
                    ),
                ),
                artifact_store=invalid_interval_store,
            ).run(_compiled_profile(min_samples=2))
        self.assertEqual(invalid_interval_store.record_count, 0)

        invalid_pit_store = InMemoryArtifactStore()
        with self.assertRaises(CheckPluginHostError):
            CheckPluginHost(
                plugins=(
                    S3CalibrationCheckPlugin(
                        samples=(
                            S3CalibrationSample("bad-pit", 0.0, -1.0, 1.0, 0.0, math.nan),
                            S3CalibrationSample("valid-3", 0.0, -1.0, 1.0, 0.0, 0.5),
                        )
                    ),
                ),
                artifact_store=invalid_pit_store,
            ).run(_compiled_profile(min_samples=2))
        self.assertEqual(invalid_pit_store.record_count, 0)

        underpowered_store = InMemoryArtifactStore()
        with self.assertRaises(CheckPluginHostError):
            CheckPluginHost(
                plugins=(
                    S3CalibrationCheckPlugin(
                        samples=(
                            S3CalibrationSample("s1", 0.0, -1.0, 1.0, 0.0, 0.5),
                            S3CalibrationSample("s2", 0.0, -1.0, 1.0, 0.0, 0.5),
                        )
                    ),
                ),
                artifact_store=underpowered_store,
            ).run(_compiled_profile(min_samples=3))
        self.assertEqual(underpowered_store.record_count, 0)


def _compiled_profile(
    *,
    thresholds: dict[str, object] | None = None,
    tolerance: dict[str, object] | None = None,
    min_samples: int = 10,
) -> CompiledProfile:
    merged_thresholds: dict[str, object] = {
        "nominal_coverage": 0.68,
        "alpha": 0.05,
        "min_samples": min_samples,
    }
    if thresholds is not None:
        merged_thresholds.update(thresholds)
    return CompiledProfile(
        profile_id="s3-t21-test",
        revision=1,
        profile_ref="c4://profile/s3-t21-test/rev/1",
        subtopic="electroweak.phase_transition",
        spec_hash="hash-s3-t21",
        public_profile={"profile_id": "s3-t21-test", "revision": 1, "checks": ["CALIBRATION"]},
        cost_estimate={"max_wallclock_s": 3.0},
        checks=(
            CompiledCheckSpec(
                check="CALIBRATION",
                plugin_ref="argus.s3.plugins.calibration",
                plugin_version="1.0.0",
                mandatory=True,
                thresholds=merged_thresholds,
                determinism="deterministic",
                seed=21,
                tolerance={"coverage_abs": 0.08} if tolerance is None else tolerance,
                requires_independence=False,
                budget={"max_wallclock_s": 3.0},
                adapter=None,
            ),
        ),
        independence_policy={"requires_cross_code": False},
        determinism_profile={"deterministic_checks": ["CALIBRATION"]},
    )


if __name__ == "__main__":
    unittest.main()
