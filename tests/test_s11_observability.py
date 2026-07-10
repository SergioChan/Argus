from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, replace
from decimal import Decimal
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Callable
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
    LineageGraph,
    ObservatoryLineageBundle,
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
    render_observatory_v0_html,
    planted_exploit_catch_rate,
    recommend_pause,
    run_planted_spurious_model_harness,
)
from argus_core import s11 as s11_module
from argus_core.s8 import ArtifactRecord


ROOT = Path(__file__).resolve().parents[1]


class S11ObservatoryV0Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = _observatory_fixture()

    def test_static_report_renders_signed_c3_and_c4_lineage(self) -> None:
        result = render_observatory_v0_html(
            report_payload=self.fixture["report"],
            lineage=self.fixture["lineage"],
            report_verifier=self.fixture["verifier"],
        )

        self.assertTrue(result.verification.trusted)
        html = result.html
        self.assertIn('data-verdict="VERIFIED"', html)
        for check_name in (
            "INJECTION",
            "NULL_CONTROL",
            "CROSS_CODE",
            "PHYSICAL_CONSISTENCY",
            "LEAKAGE",
            "CALIBRATION",
            "RECAP_BENCHMARK",
        ):
            self.assertIn(check_name, html)
        self.assertIn("must-react-1", html)
        self.assertIn("must-not-react-1", html)
        self.assertIn("No insensitivity flags recorded.", html)
        self.assertIn("recapitulated-known", html)
        self.assertIn("s3-referee", html)
        self.assertIn("c4://profile/ewpt-toy/v1", html)
        self.assertIn("c4://pipeline/ewpt-toy/baseline", html)
        self.assertIn("validation_report", html)
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html)
        self.assertNotIn("<script", html.lower())

    def test_tampered_report_renders_fail_banner(self) -> None:
        tampered = deepcopy(self.fixture["report"])
        tampered["checks"][0]["metrics"]["recovery_rate"] = 0.11

        result = render_observatory_v0_html(
            report_payload=tampered,
            lineage=self.fixture["lineage"],
            report_verifier=self.fixture["verifier"],
        )

        self.assertFalse(result.verification.trusted)
        self.assertIn("signature verification failed: signature_invalid", result.html)
        self.assertIn("validation report content hash mismatch", result.html)
        self.assertIn('data-verdict="FAIL"', result.html)

    def test_tampered_lineage_renders_fail_banner(self) -> None:
        lineage = self.fixture["lineage"]
        nodes = tuple(
            replace(record, validation_report_ref="c4://report/other")
            if record.artifact_ref == lineage.subject_ref
            else record
            for record in lineage.graph.nodes
        )
        tampered_lineage = ObservatoryLineageBundle(
            subject_ref=lineage.subject_ref,
            report_ref=lineage.report_ref,
            graph=LineageGraph(nodes=nodes, edges=lineage.graph.edges),
        )

        result = render_observatory_v0_html(
            report_payload=self.fixture["report"],
            lineage=tampered_lineage,
            report_verifier=self.fixture["verifier"],
        )

        self.assertFalse(result.verification.trusted)
        self.assertIn("subject validation_report_ref mismatch", result.html)
        self.assertIn('data-verdict="FAIL"', result.html)

    def test_referee_must_be_present_and_distinct_for_verified_banner(self) -> None:
        missing = _observatory_fixture(report_mutator=lambda report: report.pop("referee"))
        non_distinct = _observatory_fixture(
            report_mutator=lambda report: report["referee"].update({"distinct_from_proponent": False})
        )

        missing_result = render_observatory_v0_html(
            report_payload=missing["report"],
            lineage=missing["lineage"],
            report_verifier=missing["verifier"],
        )
        non_distinct_result = render_observatory_v0_html(
            report_payload=non_distinct["report"],
            lineage=non_distinct["lineage"],
            report_verifier=non_distinct["verifier"],
        )

        self.assertFalse(missing_result.verification.trusted)
        self.assertIn(
            "validation report schema violation at $: 'referee' is a required property",
            missing_result.verification.failures,
        )
        self.assertIn("validation report referee block is missing", missing_result.verification.failures)
        self.assertIn('data-verdict="FAIL"', missing_result.html)
        self.assertFalse(non_distinct_result.verification.trusted)
        self.assertIn(
            "validation report schema violation at $.referee.distinct_from_proponent: True was expected",
            non_distinct_result.verification.failures,
        )
        self.assertIn(
            "validation report referee.distinct_from_proponent is not true",
            non_distinct_result.verification.failures,
        )
        self.assertIn('data-verdict="FAIL"', non_distinct_result.html)

    def test_every_displayed_check_must_pass_for_verified_banner(self) -> None:
        fixture = _observatory_fixture(report_mutator=lambda report: report["checks"][0].update({"status": "FAIL"}))

        result = render_observatory_v0_html(
            report_payload=fixture["report"],
            lineage=fixture["lineage"],
            report_verifier=fixture["verifier"],
        )

        self.assertFalse(result.verification.trusted)
        self.assertIn("required check verdict is not PASS: INJECTION=FAIL", result.html)
        self.assertIn('data-verdict="FAIL"', result.html)

    def test_recap_report_is_verified_without_m3_cross_code_or_leakage(self) -> None:
        fixture = _observatory_fixture(
            report_mutator=lambda report: report.update(
                {
                    "checks": [
                        check
                        for check in report["checks"]
                        if check["check"] not in {"CROSS_CODE", "LEAKAGE"}
                    ]
                }
            )
        )

        result = render_observatory_v0_html(
            report_payload=fixture["report"],
            lineage=fixture["lineage"],
            report_verifier=fixture["verifier"],
        )

        self.assertTrue(result.verification.trusted)
        self.assertIn('data-verdict="VERIFIED"', result.html)
        self.assertNotIn("CROSS_CODE</td>", result.html)
        self.assertNotIn("LEAKAGE</td>", result.html)

    def test_perturbation_pairs_must_be_present_bidirectional_and_pass(self) -> None:
        missing = _observatory_fixture(report_mutator=lambda report: report.pop("perturbation_pairs"))
        failing = _observatory_fixture(
            report_mutator=lambda report: report["perturbation_pairs"][1].update({"verdict": "fail"})
        )
        one_sided = _observatory_fixture(
            report_mutator=lambda report: report.update({"perturbation_pairs": report["perturbation_pairs"][:1]})
        )

        missing_result = render_observatory_v0_html(
            report_payload=missing["report"],
            lineage=missing["lineage"],
            report_verifier=missing["verifier"],
        )
        failing_result = render_observatory_v0_html(
            report_payload=failing["report"],
            lineage=failing["lineage"],
            report_verifier=failing["verifier"],
        )
        one_sided_result = render_observatory_v0_html(
            report_payload=one_sided["report"],
            lineage=one_sided["lineage"],
            report_verifier=one_sided["verifier"],
        )

        self.assertFalse(missing_result.verification.trusted)
        self.assertIn(
            "validation report schema violation at $: 'perturbation_pairs' is a required property",
            missing_result.verification.failures,
        )
        self.assertIn(
            "validation report perturbation_pairs is empty or missing",
            missing_result.verification.failures,
        )
        self.assertFalse(failing_result.verification.trusted)
        self.assertIn(
            "perturbation pair verdict is not pass: must-not-react-1=fail",
            failing_result.verification.failures,
        )
        self.assertFalse(one_sided_result.verification.trusted)
        self.assertIn("missing perturbation kind: must_not_react", one_sided_result.verification.failures)

    def test_insensitivity_flags_block_verified_banner(self) -> None:
        fixture = _observatory_fixture(
            report_mutator=lambda report: report["insensitivity_flags"].append(
                {"perturbation_id": "must-react-1", "reason": "invariant under planted signal", "severity": "fail"}
            )
        )

        result = render_observatory_v0_html(
            report_payload=fixture["report"],
            lineage=fixture["lineage"],
            report_verifier=fixture["verifier"],
        )

        self.assertFalse(result.verification.trusted)
        self.assertIn("validation report has insensitivity flags", result.html)
        self.assertIn('data-verdict="FAIL"', result.html)

    def test_cli_writes_html_and_returns_nonzero_for_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            report_path = tmp_path / "report.json"
            tampered_path = tmp_path / "tampered-report.json"
            lineage_path = tmp_path / "lineage.json"
            trust_path = tmp_path / "trust.json"
            out_path = tmp_path / "observatory.html"
            fail_out_path = tmp_path / "observatory-fail.html"
            report_path.write_text(json.dumps(self.fixture["report"]), encoding="utf-8")
            lineage_path.write_text(json.dumps(_lineage_bundle_payload(self.fixture["lineage"])), encoding="utf-8")
            trust_path.write_text(json.dumps({"keys": [{"key_id": "s3-key", "secret": "s3-secret"}]}), encoding="utf-8")
            tampered = deepcopy(self.fixture["report"])
            tampered["aggregate"]["score"] = 0.01
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")

            ok = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "render_observatory_v0.py"),
                    "--report",
                    str(report_path),
                    "--lineage",
                    str(lineage_path),
                    "--trust-store",
                    str(trust_path),
                    "--out",
                    str(out_path),
                ],
                check=False,
                text=True,
                capture_output=True,
            )
            fail = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "render_observatory_v0.py"),
                    "--report",
                    str(tampered_path),
                    "--lineage",
                    str(lineage_path),
                    "--trust-store",
                    str(trust_path),
                    "--out",
                    str(fail_out_path),
                ],
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertIn('data-verdict="VERIFIED"', out_path.read_text(encoding="utf-8"))
            self.assertNotEqual(fail.returncode, 0)
            self.assertIn("FAIL", fail.stderr)
            self.assertIn('data-verdict="FAIL"', fail_out_path.read_text(encoding="utf-8"))

    def test_cli_returns_nonzero_for_signed_semantic_failures(self) -> None:
        fixture = _observatory_fixture(
            report_mutator=lambda report: report["referee"].update({"distinct_from_proponent": False})
        )
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            report_path = tmp_path / "report.json"
            lineage_path = tmp_path / "lineage.json"
            trust_path = tmp_path / "trust.json"
            out_path = tmp_path / "observatory.html"
            report_path.write_text(json.dumps(fixture["report"]), encoding="utf-8")
            lineage_path.write_text(json.dumps(_lineage_bundle_payload(fixture["lineage"])), encoding="utf-8")
            trust_path.write_text(json.dumps({"keys": [{"key_id": "s3-key", "secret": "s3-secret"}]}), encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "render_observatory_v0.py"),
                    "--report",
                    str(report_path),
                    "--lineage",
                    str(lineage_path),
                    "--trust-store",
                    str(trust_path),
                    "--out",
                    str(out_path),
                ],
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("FAIL", result.stderr)
            self.assertIn("referee.distinct_from_proponent", out_path.read_text(encoding="utf-8"))
            self.assertIn('data-verdict="FAIL"', out_path.read_text(encoding="utf-8"))

    def test_schema_validator_can_use_runtime_schema_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            schema_root = Path(tmp)
            contracts = schema_root / "contracts"
            contracts.mkdir()
            (contracts / "c3.validation-report.schema.json").write_text(
                json.dumps(
                    {
                        "$schema": "https://json-schema.org/draft/2020-12/schema",
                        "$id": "https://example.invalid/env-c3",
                        "$defs": {"ValidationReport": {"type": "object"}},
                    },
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            old_root = os.environ.get("ARGUS_SCHEMA_ROOT")
            os.environ["ARGUS_SCHEMA_ROOT"] = str(schema_root)
            s11_module._c3_validation_report_validator.cache_clear()
            try:
                validator = s11_module._c3_validation_report_validator()
                self.assertEqual(
                    validator.schema["$id"],
                    "https://example.invalid/env-c3#/$defs/ValidationReport",
                )
            finally:
                if old_root is None:
                    os.environ.pop("ARGUS_SCHEMA_ROOT", None)
                else:
                    os.environ["ARGUS_SCHEMA_ROOT"] = old_root
                s11_module._c3_validation_report_validator.cache_clear()


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


def _observatory_fixture(*, report_mutator: Callable[[dict[str, object]], None] | None = None) -> dict[str, object]:
    trust_store = InMemoryVerifierTrustStore()
    trust_store.register_key("s3-key", b"s3-secret")
    verifier = C3ReportVerifier(trust_store)
    signer = C3ReportSigner(key_id="s3-key", secret=b"s3-secret")
    store = InMemoryArtifactStore(report_verifier=verifier)
    profile = store.create_artifact(
        kind="verifier_profile",
        payload={"profile": "ewpt-toy", "checks": ["six-check"]},
        artifact_ref="c4://profile/ewpt-toy/v1",
        producer=Producer(subsystem="S3", version="0.0.0"),
        lineage=Lineage(input_refs=(), code_ref="git:s3-profile", environment_digest="oci:s3-profile"),
    )
    pipeline = store.create_artifact(
        kind="pipeline",
        payload={"pipeline": "ewpt-toy", "uncertainty_tag": "toy-recap"},
        artifact_ref="c4://pipeline/ewpt-toy/baseline",
        producer=Producer(subsystem="S2", version="0.0.0"),
        lineage=Lineage(input_refs=(), code_ref="git:s2-pipeline", environment_digest="oci:s2-pipeline"),
    )
    report_payload = _observatory_report(profile_ref=profile.artifact_ref, pipeline_ref=pipeline.artifact_ref)
    if report_mutator is not None:
        report_mutator(report_payload)
    report = signer.sign(report_payload)
    report_record = store.create_artifact(
        kind="report",
        payload=report,
        artifact_ref="c4://report/ewpt-toy/verified-run",
        producer=Producer(subsystem="S3", version="0.0.0"),
        lineage=Lineage(
            input_refs=(profile.artifact_ref, pipeline.artifact_ref),
            code_ref="git:s3-verifier",
            environment_digest="oci:s3-verifier",
        ),
    )
    subject = store.create_artifact(
        kind="model",
        payload={"weights": [1, 2, 3], "uncertainty_tag": "toy-recap"},
        artifact_ref="c4://artifact/ewpt-toy/model",
        producer=Producer(subsystem="S2", version="0.0.0"),
        lineage=Lineage(
            input_refs=(pipeline.artifact_ref,),
            code_ref="git:s2-builder",
            environment_digest="oci:s2-builder",
        ),
        claim_tier="recapitulated-known",
        validation_report_ref=report_record.artifact_ref,
    )
    return {
        "store": store,
        "report": report,
        "verifier": verifier,
        "lineage": ObservatoryLineageBundle(
            subject_ref=subject.artifact_ref,
            report_ref=report_record.artifact_ref,
            graph=store.get_lineage(subject.artifact_ref, direction="ancestors"),
        ),
    }


def _observatory_report(*, profile_ref: str, pipeline_ref: str) -> dict[str, object]:
    return {
        "report_id": "33333333-3333-4333-8333-333333333333",
        "profile_ref": profile_ref,
        "frozen_pipeline_ref": pipeline_ref,
        "checks": [
            {
                "check": "INJECTION",
                "status": "PASS",
                "metrics": {"recovery_rate": 0.98},
                "evidence_refs": ["c4://evidence/injection/example"],
            },
            {
                "check": "NULL_CONTROL",
                "status": "PASS",
                "metrics": {"false_positive_rate": 0.0},
                "evidence_refs": ["c4://evidence/null/example"],
            },
            {
                "check": "CROSS_CODE",
                "status": "PASS",
                "metrics": {"independent_reimplementation_delta": 0.002},
                "evidence_refs": ["c4://evidence/cross-code/example"],
            },
            {
                "check": "PHYSICAL_CONSISTENCY",
                "status": "PASS",
                "metrics": {"unit_balance": "ok"},
                "evidence_refs": ["c4://evidence/physics/example"],
            },
            {
                "check": "LEAKAGE",
                "status": "PASS",
                "metrics": {"blind_label_access": 0},
                "evidence_refs": ["c4://evidence/leakage/example"],
            },
            {
                "check": "CALIBRATION",
                "status": "PASS",
                "metrics": {"ece": 0.01},
                "evidence_refs": ["c4://evidence/calibration/example"],
            },
            {
                "check": "RECAP_BENCHMARK",
                "status": "PASS",
                "metrics": {"recovered_fraction": 1.0},
                "evidence_refs": ["c4://evidence/recap/example"],
            },
        ],
        "aggregate": {"passed": True, "score": 0.98},
        "claim_tier": "recapitulated-known",
        "claim_tier_is_candidate": False,
        "perturbation_pairs": [
            {
                "perturbation_id": "must-react-1",
                "kind": "must_react",
                "verdict": "pass",
                "amplitude_linearity": {"slope": 1.0, "intercept": 0.0},
            },
            {
                "perturbation_id": "must-not-react-1",
                "kind": "must_not_react",
                "verdict": "pass",
                "observed_degradation": {"signal": 0.0},
            },
        ],
        "insensitivity_flags": [],
        "challenger_panel": {
            "challenger_ids": ["challenger-a", "challenger-b"],
            "min_required": 2,
            "attack_types": ["signal_injection", "null_noise"],
        },
        "independence_attestation_debate": {
            "min_independent_challengers": 2,
            "lineage_disjoint": True,
            "correlation_warning": False,
            "evidence_refs": ["c4://evidence/independence/example"],
        },
        "referee": {
            "referee_id": "s3-referee",
            "non_gameable": True,
            "signed_by": "s3-key",
            "distinct_from_proponent": True,
        },
        "debate_ref": "c4://debate/ewpt-toy/example",
    }


def _lineage_bundle_payload(bundle: ObservatoryLineageBundle) -> dict[str, object]:
    return {
        "subject_ref": bundle.subject_ref,
        "report_ref": bundle.report_ref,
        "nodes": [asdict(record) for record in bundle.graph.nodes],
        "edges": [asdict(edge) for edge in bundle.graph.edges],
    }


if __name__ == "__main__":
    unittest.main()
