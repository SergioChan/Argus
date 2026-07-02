from __future__ import annotations

import unittest

from argus_core import (
    C3_SIGNATURE_ALGORITHM,
    C3ReportSigner,
    C3ReportVerifier,
    CapabilityDescriptor,
    CheckResult,
    ContaminationIndex,
    InMemoryArtifactStore,
    InMemoryVerifierTrustStore,
    RefereePolicyError,
    S3Verifier,
    SignerIdentityError,
    SourceDocument,
    attest_challenger_independence,
    build_referee_block,
    run_calibration_check,
    run_cross_code_check,
    run_leakage_check,
    run_perturbation_pair,
    tier_from_checks,
)


class S3PerturbationOracleTests(unittest.TestCase):
    def test_bidirectional_pair_passes_when_signal_recovers_and_null_degrades(self) -> None:
        outcome = run_perturbation_pair(
            perturbation_id="pair-1",
            must_react_expected=1.0,
            must_react_observed=0.97,
            must_not_react_observed=0.01,
            unperturbed_headline=1.0,
            perturbed_headline=0.2,
        )

        self.assertEqual([pair.verdict for pair in outcome.perturbation_pairs], ["pass", "pass"])
        self.assertEqual(outcome.insensitivity_flags, ())

    def test_must_react_fails_for_inert_model(self) -> None:
        outcome = run_perturbation_pair(
            perturbation_id="pair-1",
            must_react_expected=1.0,
            must_react_observed=0.0,
            must_not_react_observed=0.0,
            unperturbed_headline=0.0,
            perturbed_headline=0.0,
        )

        self.assertEqual(outcome.perturbation_pairs[0].kind, "must_react")
        self.assertEqual(outcome.perturbation_pairs[0].verdict, "fail")

    def test_insensitivity_flags_invariant_headline(self) -> None:
        outcome = run_perturbation_pair(
            perturbation_id="pair-1",
            must_react_expected=1.0,
            must_react_observed=1.0,
            must_not_react_observed=0.0,
            unperturbed_headline=0.9,
            perturbed_headline=0.89,
        )

        self.assertEqual(len(outcome.insensitivity_flags), 1)
        self.assertEqual(outcome.insensitivity_flags[0].severity, "fail")


class S3VerifierReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trust_store = InMemoryVerifierTrustStore()
        self.trust_store.register_key("s3-key", b"s3-secret")
        self.signer = C3ReportSigner(key_id="s3-key", secret=b"s3-secret")
        self.verifier = S3Verifier(verifier_id="s3-referee", signer_key_id="s3-key", signer=self.signer)

    def test_tier_rule_assigns_recap_and_novel_candidate(self) -> None:
        recap_checks = (
            CheckResult("INJECTION", "PASS"),
            CheckResult("NULL_CONTROL", "PASS"),
            CheckResult("PHYSICAL_CONSISTENCY", "PASS"),
            CheckResult("CALIBRATION", "PASS"),
        )
        novel_checks = recap_checks + (
            CheckResult("CROSS_CODE", "PASS"),
            CheckResult("LEAKAGE", "PASS"),
        )

        self.assertEqual(tier_from_checks(recap_checks), "recapitulated-known")
        self.assertEqual(tier_from_checks(novel_checks), "novel-needs-human")

    def test_referee_must_be_distinct_from_proponent(self) -> None:
        with self.assertRaises(RefereePolicyError):
            build_referee_block(referee_id="builder", signer_key_id="s3-key", proponent_id="builder")

    def test_referee_signed_by_must_match_real_signer_key(self) -> None:
        with self.assertRaises(SignerIdentityError):
            S3Verifier(verifier_id="s3-referee", signer_key_id="spoofed-key", signer=self.signer)

    def test_signed_report_verifies_with_c3_library(self) -> None:
        outcome = run_perturbation_pair(
            perturbation_id="pair-1",
            must_react_expected=1.0,
            must_react_observed=1.0,
            must_not_react_observed=0.0,
            unperturbed_headline=1.0,
            perturbed_headline=0.2,
        )
        report = self.verifier.build_report(
            profile_ref="c4://profile/ewpt/v1",
            frozen_pipeline_ref="c4://pipeline/ewpt/baseline",
            proponent_id="builder",
            checks=(
                CheckResult("INJECTION", "PASS"),
                CheckResult("NULL_CONTROL", "PASS"),
                CheckResult("PHYSICAL_CONSISTENCY", "PASS"),
                CheckResult("CALIBRATION", "PASS"),
            ),
            perturbation_outcome=outcome,
            challenger_ids=("challenger-a", "challenger-b"),
            debate_ref="c4://debate/example",
        )

        verification = C3ReportVerifier(self.trust_store).verify(report)

        self.assertTrue(verification.valid)
        self.assertEqual(verification.claim_tier, "recapitulated-known")
        self.assertTrue(verification.aggregate_passed)
        self.assertEqual(report["signature"]["algorithm"], C3_SIGNATURE_ALGORITHM)
        self.assertEqual(report["signature"]["key_id"], "s3-key")
        self.assertNotEqual(report["signature"]["value"], "placeholder")
        self.assertTrue(report["referee"]["distinct_from_proponent"])

    def test_insensitivity_forces_aggregate_fail_and_ran_toy(self) -> None:
        outcome = run_perturbation_pair(
            perturbation_id="pair-1",
            must_react_expected=1.0,
            must_react_observed=1.0,
            must_not_react_observed=0.0,
            unperturbed_headline=1.0,
            perturbed_headline=0.99,
        )

        report = self.verifier.build_report(
            profile_ref="c4://profile/ewpt/v1",
            frozen_pipeline_ref="c4://pipeline/ewpt/baseline",
            proponent_id="builder",
            checks=(CheckResult("INJECTION", "PASS"),),
            perturbation_outcome=outcome,
        )

        self.assertFalse(report["aggregate"]["passed"])
        self.assertEqual(report["claim_tier"], "ran-toy")
        self.assertEqual(len(report["insensitivity_flags"]), 1)

    def test_m3_leakage_check_consumes_frozen_contamination_snapshot(self) -> None:
        store = InMemoryArtifactStore()
        index = ContaminationIndex(artifact_store=store)
        snapshot = index.freeze(
            version="2026-07-01",
            documents=(
                SourceDocument(
                    doc_id="paper-1",
                    text="electroweak phase transition gravitational wave spectrum",
                    source_ref="c4://source/paper-1",
                ),
            ),
        )

        check = run_leakage_check(
            contamination_index=index,
            snapshot=snapshot,
            candidate_text="electroweak phase transition gravitational wave spectrum",
            threshold=0.8,
        )

        self.assertEqual(check.check, "LEAKAGE")
        self.assertEqual(check.status, "FAIL")
        self.assertEqual(check.metrics["matched_doc_id"], "paper-1")

    def test_m3_calibration_and_cross_code_checks(self) -> None:
        calibration = run_calibration_check(nominal_coverage=0.9, empirical_coverage=0.88, tolerance=0.03)
        cross_code = run_cross_code_check(
            observed=(1.0, 2.0),
            independent=(1.1, 2.1),
            combined_uncertainty=(0.2, 0.2),
            z_max=1.0,
        )
        extrapolated = run_cross_code_check(
            observed=(1.0,),
            independent=(1.0,),
            combined_uncertainty=(0.1,),
            extrapolation_flags=(True,),
        )

        self.assertEqual(calibration.status, "PASS")
        self.assertEqual(cross_code.status, "PASS")
        self.assertEqual(extrapolated.status, "INCONCLUSIVE")

    def test_challenger_independence_attestation_populates_signed_report(self) -> None:
        challengers = (
            self._challenger("challenger-a", tags=("impl-a",)),
            self._challenger("challenger-b", tags=("impl-b",)),
            self._challenger("challenger-c", tags=("impl-b",)),
        )
        attestation = attest_challenger_independence(challengers=challengers, min_independent=2)

        report = self.verifier.build_report(
            profile_ref="c4://profile/ewpt/v1",
            frozen_pipeline_ref="c4://pipeline/ewpt/baseline",
            proponent_id="builder",
            checks=(
                CheckResult("INJECTION", "PASS"),
                CheckResult("NULL_CONTROL", "PASS"),
                CheckResult("PHYSICAL_CONSISTENCY", "PASS"),
                CheckResult("CALIBRATION", "PASS"),
                CheckResult("CROSS_CODE", "PASS"),
                CheckResult("LEAKAGE", "PASS"),
            ),
            challenger_ids=tuple(challenger.entity_id for challenger in challengers),
            independence_attestation=attestation,
        )

        self.assertTrue(attestation.lineage_disjoint)
        self.assertEqual(attestation.selected_entity_ids, ("challenger-a", "challenger-b"))
        self.assertTrue(C3ReportVerifier(self.trust_store).verify(report).valid)
        self.assertEqual(report["claim_tier"], "novel-needs-human")
        self.assertEqual(report["independence_attestation_debate"]["min_independent_challengers"], 2)
        self.assertFalse(report["independence_attestation_debate"]["correlation_warning"])

    @staticmethod
    def _challenger(entity_id: str, *, tags: tuple[str, ...]) -> CapabilityDescriptor:
        return CapabilityDescriptor(
            entity_id=entity_id,
            revision=1,
            kind="subagent",
            owner_subsystem="S1",
            contract_versions={"C1": "1.0.0", "C5": "1.0.0"},
            trust_class="internal",
            capability_scopes=("challenge",),
            provenance_ref=f"c4://descriptor/{entity_id}",
            subtopics=("ewpt",),
            independence_tags=tags,
            conformance_level="gold",
        )


if __name__ == "__main__":
    unittest.main()
