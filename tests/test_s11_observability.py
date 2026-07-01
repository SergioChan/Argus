from __future__ import annotations

from decimal import Decimal
import json
import unittest

from argus_core import (
    CanaryResult,
    C3ReportSigner,
    C3ReportVerifier,
    EvalHarness,
    EvalTask,
    EvalVault,
    InMemoryArtifactStore,
    InMemoryVerifierTrustStore,
    KPIProcessor,
    Lineage,
    PlatformEvent,
    PlantedExploitRecord,
    Producer,
    ReRunCanary,
    SpuriousModelProbe,
    TelemetryScrubber,
    TelemetrySpan,
    TraceAssembler,
    TransparencyDetector,
    assemble_trust_digest,
    detect_cost_anomaly,
    detect_reward_hacking,
    planted_exploit_catch_rate,
    recommend_pause,
    run_planted_spurious_model_harness,
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


class S11EvalHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.task_input = self.store.create_artifact(
            kind="dataset",
            payload={"features": [1, 2, 3]},
            producer=Producer(subsystem="S6", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:eval-fixture", environment_digest="oci:eval-fixture"),
        )
        self.physics_input = self.store.create_artifact(
            kind="dataset",
            payload={"subtopic": "ewpt", "blind": True},
            producer=Producer(subsystem="S6", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:physics-fixture", environment_digest="oci:physics-fixture"),
        )
        self.vault = EvalVault(
            (
                EvalTask(
                    task_id="mle-1",
                    harness="mle_bench",
                    input_ref=self.task_input.artifact_ref,
                    expected_value=Decimal("0.80"),
                    tolerance=Decimal("0.10"),
                ),
                EvalTask(
                    task_id="physics-1",
                    harness="physics_recap",
                    input_ref=self.physics_input.artifact_ref,
                    expected_value=Decimal("1.50"),
                    tolerance=Decimal("0.05"),
                    expected_tier="recapitulated-known",
                ),
            )
        )
        self.harness = EvalHarness(vault=self.vault)

    def test_eval_vault_blind_payload_excludes_labels_and_denies_sandbox_read(self) -> None:
        payload = self.vault.blind_payload("physics-1")
        finding = self.vault.sandbox_label_read(task_id="physics-1", sandbox_identity="sandbox:s2")

        self.assertEqual(payload.input_ref, self.physics_input.artifact_ref)
        self.assertFalse(hasattr(payload, "expected_value"))
        self.assertEqual(finding.kind, "eval_vault_access_denied")
        self.assertEqual(finding.severity, "S1")

    def test_mle_bench_scorecard_is_reproducible_and_written_to_c4(self) -> None:
        previous = self.harness.run_scorecard(
            harness="mle_bench",
            suite_version="2026.07",
            platform_build="git:prev",
            run_id="run-prev",
            outputs={"mle-1": Decimal("0.80")},
        )

        first = self.harness.run_scorecard(
            harness="mle_bench",
            suite_version="2026.07",
            platform_build="git:new",
            run_id="run-new",
            outputs={"mle-1": Decimal("0.75")},
            previous=previous,
        )
        second = self.harness.run_scorecard(
            harness="mle_bench",
            suite_version="2026.07",
            platform_build="git:new",
            run_id="run-new",
            outputs={"mle-1": Decimal("0.75")},
            previous=previous,
        )
        record = self.harness.write_scorecard(store=self.store, scorecard=first)
        payload = json.loads(self.store.get_artifact(record.artifact_ref).decode("utf-8"))

        self.assertEqual(first.scorecard_id, second.scorecard_id)
        self.assertEqual(record.kind, "eval_scorecard")
        self.assertEqual(record.lineage.input_refs, (self.task_input.artifact_ref,))
        self.assertLess(first.regression_vs_prev, 0)
        self.assertEqual(payload["scorecard_id"], first.scorecard_id)

    def test_physics_recap_checks_tier_consistency_and_false_novel(self) -> None:
        recovered = self.harness.run_scorecard(
            harness="physics_recap",
            suite_version="2026.07",
            platform_build="git:recap",
            run_id="run-recap",
            outputs={"physics-1": Decimal("1.52")},
            observed_tiers={"physics-1": "recapitulated-known"},
        )
        false_novel = self.harness.run_scorecard(
            harness="physics_recap",
            suite_version="2026.07",
            platform_build="git:false-novel",
            run_id="run-false-novel",
            outputs={"physics-1": Decimal("1.52")},
            observed_tiers={"physics-1": "novel-needs-human"},
        )

        self.assertTrue(recovered.task_results[0].recovered)
        self.assertTrue(recovered.task_results[0].passed)
        self.assertFalse(false_novel.task_results[0].passed)
        self.assertEqual(false_novel.task_results[0].finding.kind, "transparency_failure")

    def test_planted_exploit_rate_excludes_planted_events_from_real_kpis(self) -> None:
        records = (
            PlantedExploitRecord("leaked-label", "leaked_label", caught=True),
            PlantedExploitRecord("replay", "replayable_report", caught=True),
            PlantedExploitRecord("collapsed-cross-code", "independence_collapse", caught=True),
        )
        rate = planted_exploit_catch_rate(records)
        pass_rate = KPIProcessor().validation_pass_rate(
            (
                PlatformEvent("e1", "validation.report_issued", {"report_id": "real", "passed": True}),
                PlatformEvent("e2", "validation.report_issued", {"report_id": "planted", "passed": False, "planted": True}),
            )
        )

        self.assertEqual(rate.value, Decimal("1"))
        self.assertEqual(pass_rate.denominator, Decimal("1"))
        self.assertEqual(pass_rate.value, Decimal("1"))

    def test_planted_spurious_model_harness_requires_insensitivity_catch(self) -> None:
        results, kpi = run_planted_spurious_model_harness(
            (
                SpuriousModelProbe(
                    scenario_id="constant-headline",
                    candidate_ref="c4://candidate/spurious",
                    insensitivity_detected=True,
                    survived_pre_human_gate=False,
                ),
            )
        )

        self.assertTrue(results[0].caught)
        self.assertIsNone(results[0].finding)
        self.assertEqual(kpi.name, "insensitivity_catch_rate")
        self.assertEqual(kpi.value, Decimal("1"))

    def test_cost_anomaly_is_advisory_only_and_digest_summarizes(self) -> None:
        finding = detect_cost_anomaly(
            subject_ref="s4-job-1",
            cost_usd="50.00",
            score_delta="0.001",
            min_cost_usd="10.00",
            max_score_delta="0.01",
        )
        recommendation = recommend_pause(finding)
        canary = CanaryResult(
            artifact_ref="c4://artifact/model",
            verdict="non_reproducible",
            comparator="hash_equal",
            expected_hash="c4:a",
            rederived_hash="c4:b",
        )
        scorecard = self.harness.run_scorecard(
            harness="mle_bench",
            suite_version="2026.07",
            platform_build="git:digest",
            run_id="run-digest",
            outputs={"mle-1": Decimal("0.70")},
            previous=self.harness.run_scorecard(
                harness="mle_bench",
                suite_version="2026.07",
                platform_build="git:prev",
                run_id="run-prev",
                outputs={"mle-1": Decimal("0.80")},
            ),
        )
        digest = assemble_trust_digest(
            digest_date="2026-07-01",
            kpis=(KPIProcessor().cost_per_verified_artifact(spend_usd="100", verified_artifact_count=4),),
            findings=(finding,),
            canaries=(canary,),
            scorecards=(scorecard,),
            quarantined_jobs=("job-b", "job-a"),
        )

        self.assertEqual(finding.kind, "cost_anomaly")
        self.assertTrue(recommendation.recommended)
        self.assertEqual(recommendation.authority, "advisory_only")
        self.assertEqual(digest.findings_by_severity, {"S2": 1})
        self.assertEqual(digest.canary_summary, {"non_reproducible": 1})
        self.assertEqual(digest.eval_regressions, (scorecard.scorecard_id,))
        self.assertEqual(digest.quarantined_jobs, ("job-a", "job-b"))


if __name__ == "__main__":
    unittest.main()
