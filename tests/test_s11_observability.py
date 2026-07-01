from __future__ import annotations

from decimal import Decimal
import unittest

from argus_core import (
    C3ReportSigner,
    C3ReportVerifier,
    CanaryResult,
    InMemoryArtifactStore,
    InMemoryVerifierTrustStore,
    KPIProcessor,
    Lineage,
    PlatformEvent,
    Producer,
    ReRunCanary,
    TelemetryScrubber,
    TelemetrySpan,
    TraceAssembler,
    TransparencyDetector,
    detect_reward_hacking,
)
from argus_core.s8 import ArtifactRecord


class S11TelemetryAndKpiTests(unittest.TestCase):
    def test_scrubber_redacts_sensitive_and_unknown_fields(self) -> None:
        span = TelemetrySpan(
            trace_id="trace-1",
            span_id="span-1",
            name="S5.dispatch",
            subsystem="S5",
            attributes={"job_id": "job-1", "budget_token": "secret-token", "mystery": "raw"},
        )

        scrubbed = TelemetryScrubber(allowed_attribute_fields=("job_id",)).scrub(span)

        self.assertEqual(scrubbed.span.attributes["job_id"], "job-1")
        self.assertEqual(scrubbed.span.attributes["budget_token"], "REDACTED")
        self.assertEqual(scrubbed.span.attributes["mystery"], "REDACTED")
        self.assertEqual(scrubbed.redacted_fields, ("budget_token", "mystery"))
        self.assertEqual(scrubbed.scrub_uncertain_fields, ("mystery",))

    def test_trace_completeness_and_late_amendment(self) -> None:
        assembler = TraceAssembler(required_spans=("S5.dispatch", "S1.build", "S3.verify"))
        spans = (
            TelemetrySpan("trace-1", "span-1", "S5.dispatch", "S5", {}),
            TelemetrySpan("trace-1", "span-2", "S1.build", "S1", {}),
        )

        partial = assembler.assemble(trace_id="trace-1", spans=spans)
        amended = assembler.amend(
            partial,
            spans=spans + (TelemetrySpan("trace-1", "span-3", "S3.verify", "S3", {}),),
        )

        self.assertEqual(partial.status, "partial")
        self.assertAlmostEqual(partial.completeness, 2 / 3)
        self.assertEqual(partial.findings[0].kind, "broken_trace")
        self.assertEqual(amended.status, "complete")
        self.assertEqual(amended.revision, 2)

    def test_validation_pass_rate_is_deterministic_and_deduped(self) -> None:
        events = (
            PlatformEvent("e3", "validation.report_issued", {"report_id": "r2", "passed": False}),
            PlatformEvent("e1", "validation.report_issued", {"report_id": "r1", "passed": True}),
            PlatformEvent("e2", "validation.report_issued", {"report_id": "r1", "passed": True}),
        )
        processor = KPIProcessor()

        first = processor.validation_pass_rate(events)
        second = processor.validation_pass_rate(tuple(reversed(events)))

        self.assertEqual(first, second)
        self.assertEqual(first.numerator, Decimal("1"))
        self.assertEqual(first.denominator, Decimal("2"))
        self.assertEqual(first.value, Decimal("0.5"))

    def test_cost_per_verified_artifact_formula(self) -> None:
        sample = KPIProcessor().cost_per_verified_artifact(spend_usd="100", verified_artifact_count=4)

        self.assertEqual(sample.value, Decimal("25"))


class S11CanaryAndDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trust_store = InMemoryVerifierTrustStore()
        self.trust_store.register_key("s3-key", b"s3-secret")
        self.signer = C3ReportSigner(key_id="s3-key", secret=b"s3-secret")
        self.report_verifier = C3ReportVerifier(self.trust_store)

    def test_canary_hash_and_tolerance_comparators(self) -> None:
        canary = ReRunCanary()

        hash_result = canary.compare_hash(
            artifact_ref="c4://artifact/model",
            expected_hash="c4:abc",
            rederived_hash="c4:abc",
        )
        tolerance_result = canary.compare_tolerance(
            artifact_ref="c4://artifact/model",
            expected_value="1.000",
            rederived_value="1.005",
            tolerance="0.001",
        )

        self.assertEqual(hash_result.verdict, "reproducible")
        self.assertEqual(hash_result.comparator, "hash_equal")
        self.assertEqual(tolerance_result.verdict, "non_reproducible")
        self.assertEqual(tolerance_result.divergence, Decimal("0.005"))

    def test_canary_result_is_written_as_own_s8_artifact(self) -> None:
        store = InMemoryArtifactStore()
        model = store.create_artifact(
            kind="model",
            payload={"weights": [1]},
            producer=Producer(subsystem="S2", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:model", environment_digest="oci:model"),
        )
        canary = ReRunCanary()
        result = canary.compare_hash(
            artifact_ref=model.artifact_ref,
            expected_hash=model.content_hash,
            rederived_hash=model.content_hash,
        )

        record = canary.write_result(store=store, result=result)

        self.assertEqual(record.kind, "canary_result")
        self.assertEqual(record.producer.subsystem, "S11")
        self.assertEqual(record.lineage.input_refs, (model.artifact_ref,))
        self.assertEqual(store.get_record(record.artifact_ref), record)

    def test_transparency_detector_flags_tier_mismatch(self) -> None:
        report = self._signed_report(claim_tier="recapitulated-known", passed=True)
        record = self._record(
            artifact_ref="c4://artifact/promoted",
            claim_tier="novel-needs-human",
            validation_report_ref="c4://report/recap",
        )

        finding = TransparencyDetector(report_verifier=self.report_verifier).detect(
            record=record,
            report_payload=report,
        )

        self.assertIsNotNone(finding)
        self.assertEqual(finding.kind, "transparency_failure")
        self.assertEqual(finding.severity, "S1")

    def test_transparency_detector_flags_tampered_report_signature(self) -> None:
        report = self._signed_report(claim_tier="recapitulated-known", passed=True)
        report["aggregate"]["score"] = 0.1
        record = self._record(
            artifact_ref="c4://artifact/promoted",
            claim_tier="recapitulated-known",
            validation_report_ref="c4://report/recap",
        )

        finding = TransparencyDetector(report_verifier=self.report_verifier).detect(
            record=record,
            report_payload=report,
        )

        self.assertIsNotNone(finding)
        self.assertIn("invalid validation report signature", finding.reason)

    def test_reward_hacking_requires_signature_valid_report(self) -> None:
        finding = detect_reward_hacking(score_ref="score://candidate/1", report_ref=None, signature_valid=False)
        clean = detect_reward_hacking(
            score_ref="score://candidate/2",
            report_ref="c4://report/valid",
            signature_valid=True,
        )

        self.assertEqual(finding.kind, "reward_hacking")
        self.assertIsNone(clean)

    def _signed_report(self, *, claim_tier: str, passed: bool) -> dict:
        return self.signer.sign(
            {
                "report_id": "report-1",
                "profile_ref": "c4://profile/1",
                "frozen_pipeline_ref": "c4://pipeline/1",
                "claim_tier": claim_tier,
                "checks": [],
                "aggregate": {"passed": passed, "score": 1.0},
            }
        )

    @staticmethod
    def _record(*, artifact_ref: str, claim_tier: str, validation_report_ref: str) -> ArtifactRecord:
        return ArtifactRecord(
            artifact_ref=artifact_ref,
            kind="model",
            content_hash="c4://hash/example",
            size_bytes=1,
            producer=Producer(subsystem="S2", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:model", environment_digest="oci:model"),
            claim_tier=claim_tier,
            validation_report_ref=validation_report_ref,
        )


if __name__ == "__main__":
    unittest.main()
