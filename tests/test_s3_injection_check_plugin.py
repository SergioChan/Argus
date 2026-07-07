from __future__ import annotations

import json
import unittest

from argus_core import (
    CheckPluginHost,
    CheckPluginHostError,
    CompiledCheckSpec,
    CompiledProfile,
    InMemoryArtifactStore,
    S3InjectionCheckPlugin,
    S3InjectionSample,
)


class S3InjectionCheckPluginTests(unittest.TestCase):
    def test_tc04_faithful_injection_recovery_passes_and_writes_redacted_c4_evidence(self) -> None:
        store = InMemoryArtifactStore()
        plugin = S3InjectionCheckPlugin(
            samples=(
                S3InjectionSample(sample_id="amp-1", injected_value=1.0, recovered_value=1.02),
                S3InjectionSample(sample_id="amp-2", injected_value=2.0, recovered_value=1.98),
                S3InjectionSample(sample_id="amp-4", injected_value=4.0, recovered_value=4.03),
                S3InjectionSample(sample_id="amp-8", injected_value=8.0, recovered_value=7.95),
            )
        )
        host = CheckPluginHost(
            plugins=(plugin,),
            artifact_store=store,
            actor_id="s3-injection-test",
            job_id="job-s3-t16-pass",
        )

        (result,) = host.run(_compiled_profile())

        self.assertEqual(result.check, "INJECTION")
        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.plugin_ref, "argus.s3.plugins.injection")
        self.assertEqual(result.plugin_version, "1.0.0")
        self.assertEqual(result.metrics["test_cases"], ["S3-TC04", "S3-TC05b"])
        self.assertGreaterEqual(result.metrics["recovery_rate"], 0.9)
        self.assertTrue(result.metrics["recovery_pass"])
        self.assertTrue(result.metrics["amplitude_linearity_pass"])
        self.assertEqual(result.metrics["sample_count"], 4)
        self.assertNotIn("injected_values", result.metrics)
        self.assertNotIn("recovered_values", result.metrics)

        self.assertIsNotNone(result.evidence_ref)
        evidence_payload = json.loads(store.get_artifact(result.evidence_ref).decode("utf-8"))
        self.assertEqual(evidence_payload["check"], "INJECTION")
        self.assertEqual(evidence_payload["status"], "PASS")
        self.assertNotIn("injected_values", evidence_payload["metrics"])
        self.assertNotIn("recovered_values", evidence_payload["metrics"])
        self.assertEqual(store.get_record(result.evidence_ref).kind, "s3_check_result")

    def test_tc05_inert_model_fails_recovery_and_linearity(self) -> None:
        plugin = S3InjectionCheckPlugin(
            samples=(
                S3InjectionSample(sample_id="amp-1", injected_value=1.0, recovered_value=0.0),
                S3InjectionSample(sample_id="amp-2", injected_value=2.0, recovered_value=0.0),
                S3InjectionSample(sample_id="amp-4", injected_value=4.0, recovered_value=0.0),
                S3InjectionSample(sample_id="amp-8", injected_value=8.0, recovered_value=0.0),
            )
        )

        (result,) = CheckPluginHost(plugins=(plugin,)).run(_compiled_profile())

        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.metrics["test_cases"], ["S3-TC04", "S3-TC05", "S3-TC05b"])
        self.assertLess(result.metrics["recovery_rate"], result.metrics["recovery_rate_min"])
        self.assertFalse(result.metrics["recovery_pass"])
        self.assertFalse(result.metrics["amplitude_linearity_pass"])

    def test_tc05b_amplitude_linearity_can_fail_even_when_point_recovery_passes(self) -> None:
        plugin = S3InjectionCheckPlugin(
            samples=(
                S3InjectionSample(sample_id="amp-1", injected_value=1.0, recovered_value=0.85),
                S3InjectionSample(sample_id="amp-2", injected_value=2.0, recovered_value=1.70),
                S3InjectionSample(sample_id="amp-4", injected_value=4.0, recovered_value=3.40),
                S3InjectionSample(sample_id="amp-8", injected_value=8.0, recovered_value=6.80),
            )
        )
        profile = _compiled_profile(
            tolerance={
                "relative_tolerance": 0.20,
                "absolute_tolerance": 0.05,
                "slope_tolerance": 0.05,
                "intercept_tolerance_abs": 0.05,
            }
        )

        (result,) = CheckPluginHost(plugins=(plugin,)).run(profile)

        self.assertEqual(result.status, "FAIL")
        self.assertTrue(result.metrics["recovery_pass"])
        self.assertAlmostEqual(result.metrics["linearity_slope"], 0.85, places=12)
        self.assertFalse(result.metrics["amplitude_linearity_pass"])
        self.assertEqual(result.metrics["linearity_failure_reason"], "SLOPE_OUT_OF_TOLERANCE")

    def test_missing_or_nonfinite_samples_fail_closed_before_c4_evidence(self) -> None:
        store = InMemoryArtifactStore()
        plugin = S3InjectionCheckPlugin(
            samples=(
                S3InjectionSample(sample_id="amp-1", injected_value=1.0, recovered_value=float("nan")),
            )
        )
        host = CheckPluginHost(plugins=(plugin,), artifact_store=store)

        with self.assertRaises(CheckPluginHostError) as raised:
            host.run(_compiled_profile())

        self.assertEqual(raised.exception.category, "CHECK_FAILED")
        self.assertEqual(raised.exception.code, "CHECK_PLUGIN_FAILED")
        self.assertEqual(store.record_count, 0)


def _compiled_profile(
    *,
    thresholds: dict[str, float] | None = None,
    tolerance: dict[str, float] | None = None,
) -> CompiledProfile:
    return CompiledProfile(
        profile_id="s3-t16-test",
        revision=1,
        profile_ref="c4://profile/s3-t16-test/rev/1",
        subtopic="electroweak.phase_transition",
        spec_hash="hash-s3-t16",
        public_profile={"profile_id": "s3-t16-test", "revision": 1, "checks": ["INJECTION"]},
        cost_estimate={"max_wallclock_s": 3.0},
        checks=(
            CompiledCheckSpec(
                check="INJECTION",
                plugin_ref="argus.s3.plugins.injection",
                plugin_version="1.0.0",
                mandatory=True,
                thresholds=thresholds or {"recovery_rate_min": 0.9},
                determinism="deterministic",
                seed=17,
                tolerance=tolerance
                or {
                    "relative_tolerance": 0.1,
                    "absolute_tolerance": 0.05,
                    "slope_tolerance": 0.1,
                    "intercept_tolerance_abs": 0.1,
                },
                requires_independence=False,
                budget={"max_wallclock_s": 3.0},
                adapter=None,
            ),
        ),
        independence_policy={},
        determinism_profile={"seeded_checks": [{"check": "INJECTION", "seed": 17}]},
    )


if __name__ == "__main__":
    unittest.main()
