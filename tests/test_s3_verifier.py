from __future__ import annotations

import unittest

from argus_core import (
    C3ReportSigner,
    C3ReportVerifier,
    CheckResult,
    InMemoryVerifierTrustStore,
    RefereePolicyError,
    S3Verifier,
    build_referee_block,
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


if __name__ == "__main__":
    unittest.main()
