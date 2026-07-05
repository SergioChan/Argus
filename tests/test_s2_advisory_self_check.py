from __future__ import annotations

import json
import unittest

from argus_core import (
    AdvisoryLeakageSample,
    AdvisorySelfCheck,
    AdvisorySelfCheckRequest,
    AdvisorySignalSample,
    InMemoryArtifactStore,
    Lineage,
    Producer,
    ProvenanceEmitter,
    SelfGradeError,
)


class S2AdvisorySelfCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.emitter = ProvenanceEmitter(artifact_store=self.store)
        self.model_ref = self.store.create_artifact(
            kind="model_checkpoint",
            payload={"model_state": {"scale": 2.0}, "metrics": {"loss": 0.01}},
            producer=Producer(subsystem="S2", version="0.0.0", job_id="self-check-model"),
            lineage=Lineage(
                input_refs=(),
                code_ref="git:self-check-model",
                environment_digest="oci:self-check-model",
                job_id="self-check-model",
            ),
        ).artifact_ref
        self.feature_set_ref = self.store.create_artifact(
            kind="feature_set",
            payload={"feature_set_id": "self-check-features", "features": ["x"]},
            producer=Producer(subsystem="S2", version="0.0.0", job_id="self-check-features"),
            lineage=Lineage(
                input_refs=(self.model_ref,),
                code_ref="git:self-check-features",
                environment_digest="oci:self-check-features",
                job_id="self-check-features",
            ),
        ).artifact_ref

    def test_injection_and_null_sanity_emit_advisory_c4_without_tier_raise(self) -> None:
        result = AdvisorySelfCheck(artifact_store=self.store, provenance_emitter=self.emitter).run(
            self._request(
                injection_samples=(
                    AdvisorySignalSample(sample_id="i1", template=1.0, observed=2.0),
                    AdvisorySignalSample(sample_id="i2", template=2.0, observed=4.0),
                    AdvisorySignalSample(sample_id="i3", template=-1.0, observed=-2.0),
                ),
                known_amplitude=2.0,
                amplitude_tolerance=1e-12,
                null_samples=(
                    AdvisorySignalSample(sample_id="n1", template=1.0, observed=0.01),
                    AdvisorySignalSample(sample_id="n2", template=-1.0, observed=-0.01),
                    AdvisorySignalSample(sample_id="n3", template=2.0, observed=0.02),
                ),
                null_detection_threshold=0.05,
            )
        )

        payload = self._payload(result.artifact_ref)
        record = self.store.get_record(result.artifact_ref)

        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.claim_tier, "ran-toy")
        self.assertEqual(record.kind, "advisory_self_check")
        self.assertEqual(record.claim_tier, "ran-toy")
        self.assertEqual(record.lineage.input_refs, (self.model_ref, self.feature_set_ref))
        self.assertEqual(result.checks_by_name["injection_sanity"].status, "PASS")
        self.assertEqual(result.checks_by_name["null_sanity"].status, "PASS")
        self.assertAlmostEqual(result.checks_by_name["injection_sanity"].recovered_value, 2.0, places=12)
        self.assertTrue(payload["advisory"])
        self.assertEqual(payload["claim_tier"], "ran-toy")
        self.assertFalse(payload["tier_raise_allowed"])

    def test_leakage_smell_flags_perfect_target_encoding_and_stays_ran_toy(self) -> None:
        result = AdvisorySelfCheck(artifact_store=self.store, provenance_emitter=self.emitter).run(
            self._request(
                leakage_samples=(
                    AdvisoryLeakageSample(sample_id="l1", feature_value=0.0, target_value=0.0),
                    AdvisoryLeakageSample(sample_id="l2", feature_value=1.0, target_value=1.0),
                    AdvisoryLeakageSample(sample_id="l3", feature_value=0.0, target_value=0.0),
                    AdvisoryLeakageSample(sample_id="l4", feature_value=1.0, target_value=1.0),
                ),
                leakage_threshold=0.99,
            )
        )

        payload = self._payload(result.artifact_ref)

        self.assertEqual(result.status, "NEEDS_REVIEW")
        self.assertEqual(result.claim_tier, "ran-toy")
        self.assertEqual(result.checks_by_name["leakage_smell"].status, "FAIL")
        self.assertGreaterEqual(result.checks_by_name["leakage_smell"].statistic, 1.0)
        self.assertIn("target leakage", result.checks_by_name["leakage_smell"].message)
        self.assertIn("leakage_smell", payload["warnings"])
        self.assertEqual(payload["checks"]["leakage_smell"]["status"], "FAIL")
        self.assertEqual(payload["claim_tier"], "ran-toy")

    def test_self_check_refuses_attempted_claim_tier_raise_before_c4_write(self) -> None:
        before = self.store.record_count

        with self.assertRaises(SelfGradeError):
            AdvisorySelfCheck(artifact_store=self.store, provenance_emitter=self.emitter).run(
                self._request(
                    injection_samples=(AdvisorySignalSample(sample_id="i1", template=1.0, observed=1.0),),
                    known_amplitude=1.0,
                ),
                attempted_claim_tier="recapitulated-known",
            )

        self.assertEqual(self.store.record_count, before)

    def _request(
        self,
        *,
        injection_samples: tuple[AdvisorySignalSample, ...] = (),
        known_amplitude: float = 1.0,
        amplitude_tolerance: float = 0.1,
        null_samples: tuple[AdvisorySignalSample, ...] = (),
        null_detection_threshold: float = 0.1,
        leakage_samples: tuple[AdvisoryLeakageSample, ...] = (),
        leakage_threshold: float = 0.99,
    ) -> AdvisorySelfCheckRequest:
        return AdvisorySelfCheckRequest(
            job_id="self-check",
            input_refs=(self.model_ref, self.feature_set_ref),
            injection_samples=injection_samples,
            known_amplitude=known_amplitude,
            amplitude_tolerance=amplitude_tolerance,
            null_samples=null_samples,
            null_detection_threshold=null_detection_threshold,
            leakage_samples=leakage_samples,
            leakage_threshold=leakage_threshold,
            code_ref="git:s2-advisory-self-check",
            environment_digest="oci:s2-advisory-self-check",
            seed="self-check-seed",
        )

    def _payload(self, artifact_ref: str) -> dict:
        return json.loads(self.store.get_artifact(artifact_ref).decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
