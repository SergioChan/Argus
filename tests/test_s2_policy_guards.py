from __future__ import annotations

import unittest

from argus_core import (
    C3ReportSigner,
    C3ReportVerifier,
    InMemoryArtifactStore,
    InMemoryVerifierTrustStore,
    Lineage,
    Producer,
    ProvenanceEmitter,
    SelfGradeError,
)


class S2PolicyGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trust_store = InMemoryVerifierTrustStore()
        self.trust_store.register_key("s3-key", b"s3-secret")
        self.store = InMemoryArtifactStore(report_verifier=C3ReportVerifier(self.trust_store))
        self.emitter = ProvenanceEmitter(artifact_store=self.store)
        self.report_ref = self._signed_report_ref(claim_tier="recapitulated-known")

    def test_s2_writer_rejects_promoted_tier_even_with_valid_external_c3_report(self) -> None:
        before = self.store.record_count

        with self.assertRaises(SelfGradeError) as raised:
            self.emitter.emit_artifact(
                kind="model",
                payload={"weights": [1.0], "uncertainty_tag": {"kind": "interval", "radius": 0.1}},
                lineage=self._lineage(),
                claim_tier="recapitulated-known",
                validation_report_ref=self.report_ref,
            )

        self.assertIn("S2 cannot emit promoted claim_tier", str(raised.exception))
        self.assertEqual(self.store.record_count, before)

    def test_s2_writer_rejects_producer_impersonation_before_c4_write(self) -> None:
        before = self.store.record_count

        with self.assertRaises(SelfGradeError) as raised:
            self.emitter.emit_artifact(
                kind="model",
                payload={"weights": [1.0]},
                lineage=self._lineage(),
                producer=Producer(subsystem="S3", version="0.0.0", actor_id="spoofed-referee"),
            )

        self.assertIn("S2 writer cannot emit as subsystem S3", str(raised.exception))
        self.assertEqual(self.store.record_count, before)

    def test_s2_writer_rejects_validation_report_attachment_even_for_ran_toy(self) -> None:
        before = self.store.record_count

        with self.assertRaises(SelfGradeError) as raised:
            self.emitter.emit_artifact(
                kind="model",
                payload={"weights": [1.0]},
                lineage=self._lineage(),
                validation_report_ref=self.report_ref,
            )

        self.assertIn("S2 writer cannot attach validation_report_ref", str(raised.exception))
        self.assertEqual(self.store.record_count, before)

    def _signed_report_ref(self, *, claim_tier: str) -> str:
        signer = C3ReportSigner(key_id="s3-key", secret=b"s3-secret")
        report = self.store.create_artifact(
            kind="report",
            payload=signer.sign(self._report(claim_tier=claim_tier)),
            producer=Producer(subsystem="S3", version="0.0.0", actor_id="s3-referee"),
            lineage=Lineage(input_refs=(), code_ref="git:s3-report", environment_digest="oci:s3-report"),
        )
        return report.artifact_ref

    @staticmethod
    def _lineage() -> Lineage:
        return Lineage(
            input_refs=(),
            code_ref="git:s2-policy-guard",
            environment_digest="oci:s2-policy-guard",
            job_id="s2-policy-guard",
        )

    @staticmethod
    def _report(*, claim_tier: str) -> dict[str, object]:
        return {
            "report_id": "33333333-3333-4333-8333-333333333333",
            "profile_ref": "c4://profile/s2-policy/v1",
            "frozen_pipeline_ref": "c4://pipeline/s2-policy",
            "verifier": {"id": "s3-referee", "version": "0.0.0"},
            "referee": {
                "referee_id": "s3-referee",
                "signed_by": "s3-key",
                "proponent_id": "s2-builder",
                "distinct_from_proponent": True,
            },
            "checks": [
                {"check": "INJECTION", "status": "PASS"},
                {"check": "NULL_CONTROL", "status": "PASS"},
                {"check": "PHYSICAL_CONSISTENCY", "status": "PASS"},
                {"check": "CALIBRATION", "status": "PASS"},
            ],
            "aggregate": {"passed": True},
            "claim_tier": claim_tier,
            "claim_tier_is_candidate": False,
        }


if __name__ == "__main__":
    unittest.main()
