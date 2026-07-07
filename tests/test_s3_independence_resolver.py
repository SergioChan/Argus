from __future__ import annotations

import unittest

from argus_core import (
    C3ReportSigner,
    C3ReportVerifier,
    CapabilityDescriptor,
    CheckResult,
    InMemoryRegistry,
    InMemoryVerifierTrustStore,
    S3IndependenceResolver,
    S3Verifier,
)


class S3IndependenceResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.c5 = InMemoryRegistry()
        self.resolver = S3IndependenceResolver(c5_registry=self.c5)
        self.trust_store = InMemoryVerifierTrustStore()
        self.trust_store.register_key("s3-independence-key", b"s3-independence-secret")
        self.verifier = S3Verifier(
            verifier_id="s3-reference-referee",
            signer_key_id="s3-independence-key",
            signer=C3ReportSigner(key_id="s3-independence-key", secret=b"s3-independence-secret"),
        )

    def test_tc24_rejects_non_independent_c5_code(self) -> None:
        self.c5.publish(self._adapter("candidate-under-test", tags=("impl-a",)))
        self.c5.publish(self._adapter("shared-lineage-adapter", tags=("impl-a",)))

        result = self.resolver.resolve_cross_code(
            subtopic="electroweak.phase_transition",
            code_under_test=self._adapter("candidate-under-test", tags=("impl-a",)),
            required_scope="c6.evaluate",
            min_independent=1,
        )

        self.assertEqual(result.test_case, "S3-TC24")
        self.assertEqual(result.verdict, "NOT_INDEPENDENT")
        self.assertEqual(result.cross_codes, ())
        self.assertEqual(result.candidate_ids, ("shared-lineage-adapter",))
        self.assertEqual(result.rejected_candidate_ids, ("shared-lineage-adapter",))
        self.assertIn("INDEPENDENCE_UNAVAILABLE", result.degradations)
        self.assertEqual(result.to_check_result().status, "INCONCLUSIVE")
        self.assertEqual(result.to_check_result().metrics["verdict"], "NOT_INDEPENDENT")

    def test_tc23_unavailable_independence_caps_novel_but_keeps_signed_report(self) -> None:
        self.c5.publish(self._adapter("shared-lineage-adapter", tags=("impl-a",)))

        result = self.resolver.resolve_cross_code(
            subtopic="electroweak.phase_transition",
            code_under_test=self._adapter("candidate-under-test", tags=("impl-a",)),
            required_scope="c6.evaluate",
            min_independent=1,
            requested_tier="novel-needs-human",
        )
        cross_code = result.to_check_result()
        report = self.verifier.build_report(
            profile_ref="c4://profile/strict-independence/v1",
            frozen_pipeline_ref="c4://pipeline/ewpt/baseline",
            proponent_id="builder",
            checks=self._recap_checks() + (cross_code, CheckResult("LEAKAGE", "PASS")),
            challenger_ids=result.candidate_ids,
            independence_attestation=result.to_independence_attestation(),
        )

        verification = C3ReportVerifier(self.trust_store).verify(report)

        self.assertEqual(result.test_case, "S3-TC23")
        self.assertEqual(cross_code.check, "CROSS_CODE")
        self.assertEqual(cross_code.status, "INCONCLUSIVE")
        self.assertIn("INDEPENDENCE_UNAVAILABLE", cross_code.metrics["degradations"])
        self.assertIn(report["claim_tier"], {"ran-toy", "recapitulated-known"})
        self.assertNotEqual(report["claim_tier"], "novel-needs-human")
        self.assertTrue(verification.valid)

    def test_tc50_strict_policy_refuses_novel_with_downgraded_profile_suggestion(self) -> None:
        result = self.resolver.resolve_cross_code(
            subtopic="electroweak.phase_transition",
            code_under_test=self._adapter("candidate-under-test", tags=("impl-a",)),
            required_scope="c6.evaluate",
            min_independent=1,
            requested_tier="novel-needs-human",
            policy={"mode": "strict", "downgraded_profile_ref": "c4://profile/ewpt/recap-only"},
        )

        self.assertEqual(result.test_case, "S3-TC50")
        self.assertEqual(result.verdict, "REFUSED")
        self.assertTrue(result.refused)
        self.assertEqual(result.refusal_code, "INDEPENDENCE_UNAVAILABLE")
        self.assertEqual(result.downgraded_profile_ref, "c4://profile/ewpt/recap-only")
        self.assertEqual(result.max_claim_tier, "recapitulated-known")
        self.assertEqual(result.cross_codes, ())
        self.assertEqual(result.to_check_result().status, "INCONCLUSIVE")

    @staticmethod
    def _recap_checks() -> tuple[CheckResult, ...]:
        return (
            CheckResult("INJECTION", "PASS"),
            CheckResult("NULL_CONTROL", "PASS"),
            CheckResult("PHYSICAL_CONSISTENCY", "PASS"),
            CheckResult("CALIBRATION", "PASS"),
            CheckResult("RECAP_BENCHMARK", "PASS", metrics={"test_cases": ["S3-T24", "S3-TC32"]}),
        )

    @staticmethod
    def _adapter(entity_id: str, *, tags: tuple[str, ...]) -> CapabilityDescriptor:
        return CapabilityDescriptor(
            entity_id=entity_id,
            revision=1,
            kind="adapter",
            owner_subsystem="S7",
            contract_versions={"C5": "1.0.0", "C6": "1.0.0"},
            trust_class="internal",
            capability_scopes=("c6.evaluate",),
            provenance_ref=f"c4://descriptor/{entity_id}",
            subtopics=("electroweak.phase_transition",),
            independence_tags=tags,
            conformance_level="gold",
        )


if __name__ == "__main__":
    unittest.main()
