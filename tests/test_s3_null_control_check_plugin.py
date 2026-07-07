from __future__ import annotations

import json
import unittest

from argus_core import (
    CheckPluginHost,
    CheckPluginHostError,
    CompiledCheckSpec,
    CompiledProfile,
    InMemoryArtifactStore,
    S3NullControlCheckPlugin,
    S3NullControlSample,
)


class S3NullControlCheckPluginTests(unittest.TestCase):
    def test_tc06_pure_noise_hallucinated_signal_fails_and_writes_redacted_c4_evidence(self) -> None:
        store = InMemoryArtifactStore()
        plugin = S3NullControlCheckPlugin(
            samples=_null_samples(trials=100, false_positives=10, variant="pure_noise")
        )
        host = CheckPluginHost(
            plugins=(plugin,),
            artifact_store=store,
            actor_id="s3-null-control-test",
            job_id="job-s3-t17-fail",
        )

        (result,) = host.run(_compiled_profile())

        self.assertEqual(result.check, "NULL_CONTROL")
        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.plugin_ref, "argus.s3.plugins.null_control")
        self.assertEqual(result.plugin_version, "1.0.0")
        self.assertEqual(result.metrics["test_cases"], ["S3-TC06"])
        self.assertEqual(result.metrics["false_positives"], 10)
        self.assertEqual(result.metrics["trial_count"], 100)
        self.assertGreater(result.metrics["false_positive_rate_upper"], result.metrics["alpha"])
        self.assertFalse(result.metrics["null_control_pass"])
        self.assertEqual(result.metrics["failure_reason"], "FPR_UPPER_EXCEEDS_ALPHA")
        self.assertIn({"variant": "pure_noise", "false_positives": 10, "trials": 100}, result.metrics["variant_counts"])
        self.assertNotIn("detections", result.metrics)
        self.assertNotIn("labels", result.metrics)
        self.assertNotIn("sample_ids", result.metrics)

        self.assertIsNotNone(result.evidence_ref)
        evidence_payload = json.loads(store.get_artifact(result.evidence_ref).decode("utf-8"))
        self.assertEqual(evidence_payload["check"], "NULL_CONTROL")
        self.assertEqual(evidence_payload["status"], "FAIL")
        self.assertNotIn("detections", evidence_payload["metrics"])
        self.assertNotIn("labels", evidence_payload["metrics"])
        self.assertNotIn("sample_ids", evidence_payload["metrics"])
        self.assertEqual(store.get_record(result.evidence_ref).kind, "s3_check_result")

    def test_tc07_signal_free_well_behaved_model_passes_with_binomial_upper_bound_under_alpha(self) -> None:
        plugin = S3NullControlCheckPlugin(
            samples=_null_samples(trials=1000, false_positives=0, variant="signal_free")
        )

        (result,) = CheckPluginHost(plugins=(plugin,)).run(_compiled_profile())

        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.metrics["test_cases"], ["S3-TC07"])
        self.assertEqual(result.metrics["false_positives"], 0)
        self.assertLessEqual(result.metrics["false_positive_rate_upper"], result.metrics["alpha"])
        self.assertTrue(result.metrics["null_control_pass"])

    def test_tc08_label_shuffle_null_collapses_to_chance_and_passes(self) -> None:
        plugin = S3NullControlCheckPlugin(
            samples=_null_samples(trials=1000, false_positives=0, variant="label_shuffle")
        )

        (result,) = CheckPluginHost(plugins=(plugin,)).run(_compiled_profile())

        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.metrics["test_cases"], ["S3-TC08"])
        self.assertEqual(result.metrics["variant_results"][0]["variant"], "label_shuffle")
        self.assertLessEqual(
            result.metrics["variant_results"][0]["false_positive_rate_upper"],
            result.metrics["alpha"],
        )
        self.assertTrue(result.metrics["variant_results"][0]["passed"])

    def test_missing_threshold_or_invalid_outcomes_fail_closed_before_c4_evidence(self) -> None:
        missing_threshold_store = InMemoryArtifactStore()
        missing_threshold_plugin = S3NullControlCheckPlugin(
            samples=_null_samples(trials=10, false_positives=0, variant="signal_free")
        )

        with self.assertRaises(CheckPluginHostError) as missing_threshold:
            CheckPluginHost(
                plugins=(missing_threshold_plugin,),
                artifact_store=missing_threshold_store,
            ).run(_compiled_profile(thresholds={}))

        self.assertEqual(missing_threshold.exception.category, "CHECK_FAILED")
        self.assertEqual(missing_threshold.exception.code, "CHECK_PLUGIN_FAILED")
        self.assertEqual(missing_threshold_store.record_count, 0)

        invalid_outcome_store = InMemoryArtifactStore()
        invalid_outcome_plugin = S3NullControlCheckPlugin(
            samples=(
                S3NullControlSample(sample_id="null-1", variant="signal_free", detected=1),  # type: ignore[arg-type]
            )
        )

        with self.assertRaises(CheckPluginHostError) as invalid_outcome:
            CheckPluginHost(
                plugins=(invalid_outcome_plugin,),
                artifact_store=invalid_outcome_store,
            ).run(_compiled_profile())

        self.assertEqual(invalid_outcome.exception.category, "CHECK_FAILED")
        self.assertEqual(invalid_outcome.exception.code, "CHECK_PLUGIN_FAILED")
        self.assertEqual(invalid_outcome_store.record_count, 0)


def _null_samples(*, trials: int, false_positives: int, variant: str) -> tuple[S3NullControlSample, ...]:
    return tuple(
        S3NullControlSample(
            sample_id=f"{variant}-{index}",
            variant=variant,
            detected=index < false_positives,
        )
        for index in range(trials)
    )


def _compiled_profile(*, thresholds: dict[str, float] | None = None) -> CompiledProfile:
    return CompiledProfile(
        profile_id="s3-t17-test",
        revision=1,
        profile_ref="c4://profile/s3-t17-test/rev/1",
        subtopic="electroweak.phase_transition",
        spec_hash="hash-s3-t17",
        public_profile={"profile_id": "s3-t17-test", "revision": 1, "checks": ["NULL_CONTROL"]},
        cost_estimate={"max_wallclock_s": 3.0},
        checks=(
            CompiledCheckSpec(
                check="NULL_CONTROL",
                plugin_ref="argus.s3.plugins.null_control",
                plugin_version="1.0.0",
                mandatory=True,
                thresholds=thresholds if thresholds is not None else {"alpha": 0.01, "confidence_level": 0.95},
                determinism="deterministic",
                seed=17,
                tolerance={},
                requires_independence=False,
                budget={"max_wallclock_s": 3.0},
                adapter=None,
            ),
        ),
        independence_policy={},
        determinism_profile={"seeded_checks": [{"check": "NULL_CONTROL", "seed": 17}]},
    )


if __name__ == "__main__":
    unittest.main()
