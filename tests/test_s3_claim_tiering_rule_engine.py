from __future__ import annotations

import unittest

from argus_core import (
    C3ReportSigner,
    C3ReportVerifier,
    CheckResult,
    InMemoryVerifierTrustStore,
    IndependenceAttestation,
    S3ClaimTieringError,
    S3ClaimTieringRuleEngine,
    S3Verifier,
)


class S3ClaimTieringRuleEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = S3ClaimTieringRuleEngine()
        self.trust_store = InMemoryVerifierTrustStore()
        self.trust_store.register_key("s3-tier-key", b"s3-tier-secret")
        self.verifier = S3Verifier(
            verifier_id="s3-reference-referee",
            signer_key_id="s3-tier-key",
            signer=C3ReportSigner(key_id="s3-tier-key", secret=b"s3-tier-secret"),
        )

    def test_tc21_leakage_fail_caps_novel_and_records_monotonic_rule(self) -> None:
        decision = self.engine.evaluate(
            checks=self._recap_checks()
            + (
                CheckResult("CROSS_CODE", "PASS"),
                CheckResult("LEAKAGE", "FAIL", metrics={"max_claim_tier": "recapitulated-known"}),
            ),
            independence_attestation=self._trusted_independence(),
            requested_tier="novel-needs-human",
        )

        self.assertEqual(decision.claim_tier, "recapitulated-known")
        self.assertFalse(decision.claim_tier_is_candidate)
        self.assertFalse(decision.aggregate_passed)
        self.assertEqual(decision.reward_effect, "non-improvement")
        self.assertIn("S3-TC21", decision.test_cases)
        self.assertIn("tier.leakage_fail_caps_novel", decision.rule_ids)
        self.assertNotEqual(decision.claim_tier, "novel-needs-human")

    def test_tc22_all_pass_independent_is_candidate_novel_with_event_intent(self) -> None:
        decision = self.engine.evaluate(
            checks=self._novel_checks(),
            independence_attestation=self._trusted_independence(),
            requested_tier="novel-needs-human",
        )

        self.assertEqual(decision.claim_tier, "novel-needs-human")
        self.assertTrue(decision.claim_tier_is_candidate)
        self.assertTrue(decision.aggregate_passed)
        self.assertEqual(decision.reward_effect, "eligible")
        self.assertIn("S3-TC22", decision.test_cases)
        self.assertIn("s3.report.candidate_novel", decision.event_intents)
        self.assertIn("tier.novel_candidate_only", decision.rule_ids)

        report = self.verifier.build_report(
            profile_ref="c4://profile/ewpt/novel",
            frozen_pipeline_ref="c4://pipeline/ewpt/candidate",
            proponent_id="builder",
            checks=self._novel_checks(),
            challenger_ids=("challenger-a", "challenger-b"),
            independence_attestation=self._trusted_independence(),
        )

        verification = C3ReportVerifier(self.trust_store).verify(report)
        self.assertTrue(verification.valid)
        self.assertEqual(report["claim_tier"], "novel-needs-human")
        self.assertTrue(report["claim_tier_is_candidate"])
        self.assertIn("s3.report.candidate_novel", report["event_intents"])

    def test_tc23_independence_unavailable_caps_tier_and_keeps_signed_report(self) -> None:
        degraded = IndependenceAttestation(
            candidate_ids=("shared-lineage-adapter",),
            selected_entity_ids=(),
            min_independent=2,
            lineage_disjoint=False,
            correlation_warning=True,
            excluded_tags=("impl-a",),
        )
        decision = self.engine.evaluate(
            checks=self._recap_checks()
            + (
                CheckResult(
                    "CROSS_CODE",
                    "INCONCLUSIVE",
                    metrics={"degradations": ["INDEPENDENCE_UNAVAILABLE"], "max_claim_tier": "recapitulated-known"},
                ),
                CheckResult("LEAKAGE", "PASS"),
            ),
            independence_attestation=degraded,
            requested_tier="novel-needs-human",
        )

        self.assertEqual(decision.claim_tier, "recapitulated-known")
        self.assertFalse(decision.claim_tier_is_candidate)
        self.assertIn("INDEPENDENCE_UNAVAILABLE", decision.degradations)
        self.assertIn("S3-TC23", decision.test_cases)
        self.assertIn("tier.independence_unavailable_cap", decision.rule_ids)

        report = self.verifier.build_report(
            profile_ref="c4://profile/ewpt/degraded",
            frozen_pipeline_ref="c4://pipeline/ewpt/candidate",
            proponent_id="builder",
            checks=decision.checks,
            challenger_ids=degraded.candidate_ids,
            independence_attestation=degraded,
        )

        verification = C3ReportVerifier(self.trust_store).verify(report)
        self.assertTrue(verification.valid)
        self.assertEqual(report["claim_tier"], "recapitulated-known")
        self.assertIn("INDEPENDENCE_UNAVAILABLE", report["degradations"])

    def test_tc37_mandatory_inconclusive_is_reward_non_improvement(self) -> None:
        decision = self.engine.evaluate(
            checks=(
                CheckResult("INJECTION", "PASS"),
                CheckResult("NULL_CONTROL", "INCONCLUSIVE", metrics={"degradations": ["BUDGET"]}),
                CheckResult("PHYSICAL_CONSISTENCY", "PASS"),
                CheckResult("CALIBRATION", "PASS"),
                CheckResult("CROSS_CODE", "PASS"),
                CheckResult("LEAKAGE", "PASS"),
            ),
            independence_attestation=self._trusted_independence(),
            requested_tier="novel-needs-human",
        )

        self.assertEqual(decision.claim_tier, "ran-toy")
        self.assertFalse(decision.aggregate_passed)
        self.assertEqual(decision.reward_effect, "non-improvement")
        self.assertFalse(decision.reward_admissible)
        self.assertIn("S3-TC37", decision.test_cases)
        self.assertIn("tier.mandatory_inconclusive_non_improvement", decision.rule_ids)

    def test_invalid_duplicate_and_unknown_check_inputs_fail_closed(self) -> None:
        with self.assertRaises(S3ClaimTieringError):
            self.engine.evaluate(
                checks=(CheckResult("INJECTION", "PASS"), CheckResult("INJECTION", "PASS")),
                independence_attestation=self._trusted_independence(),
            )
        with self.assertRaises(S3ClaimTieringError):
            self.engine.evaluate(
                checks=self._recap_checks() + (CheckResult("LEAKAGE", "BOGUS"),),
                independence_attestation=self._trusted_independence(),
            )
        with self.assertRaises(S3ClaimTieringError):
            self.engine.evaluate(
                checks=self._recap_checks(),
                independence_attestation=self._trusted_independence(),
                requested_tier="silver",
            )

    @staticmethod
    def _recap_checks() -> tuple[CheckResult, ...]:
        return (
            CheckResult("INJECTION", "PASS"),
            CheckResult("NULL_CONTROL", "PASS"),
            CheckResult("PHYSICAL_CONSISTENCY", "PASS"),
            CheckResult("CALIBRATION", "PASS"),
        )

    def _novel_checks(self) -> tuple[CheckResult, ...]:
        return self._recap_checks() + (
            CheckResult("CROSS_CODE", "PASS"),
            CheckResult("LEAKAGE", "PASS"),
        )

    @staticmethod
    def _trusted_independence() -> IndependenceAttestation:
        return IndependenceAttestation(
            candidate_ids=("challenger-a", "challenger-b"),
            selected_entity_ids=("challenger-a", "challenger-b"),
            min_independent=2,
            lineage_disjoint=True,
            correlation_warning=False,
            excluded_tags=(),
        )


if __name__ == "__main__":
    unittest.main()
