from __future__ import annotations

import unittest

from argus_core import (
    C3ReportSigner,
    C3ReportVerifier,
    EmissionAuthorizationMinter,
    GovernanceLedger,
    InMemoryArtifactStore,
    InMemoryObjectStore,
    InMemoryVerifierTrustStore,
    Lineage,
    Producer,
    S9Governance,
    S9PolicyError,
    S9SignatureError,
)


class S9GovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trust_store = InMemoryVerifierTrustStore()
        self.trust_store.register_key("s3-key", b"s3-secret")
        self.signer = C3ReportSigner(key_id="s3-key", secret=b"s3-secret")
        self.object_store = InMemoryObjectStore()
        self.store = InMemoryArtifactStore(object_store=self.object_store)
        self.minter = EmissionAuthorizationMinter(signer_key_id="s9-hsm", secret=b"s9-secret")
        self.s9 = S9Governance(
            report_verifier=C3ReportVerifier(self.trust_store),
            artifact_store=self.store,
            emission_minter=self.minter,
        )

    def test_intake_rejects_invalid_report_signature(self) -> None:
        report = self._signed_report(claim_tier="recapitulated-known")
        report["aggregate"]["score"] = 0.0

        task = self.s9.create_review_task(
            report_payload=report,
            validation_report_ref="c4://report/tampered",
            artifact_refs=(),
            emission_class="internal-review",
            idempotency_key="task-1",
        )

        self.assertEqual(task.state, "QUARANTINED")
        self.assertEqual(task.quarantine_reason, "SIGNATURE_INVALID")
        self.assertIn("SIGNATURE_INVALID", self.s9.ledger.entries[-1].payload["reason"])

    def test_intake_rejects_placeholder_report_signature_before_emission(self) -> None:
        task = self.s9.create_review_task(
            report_payload=self._placeholder_report(claim_tier="novel-needs-human"),
            validation_report_ref="c4://report/placeholder",
            artifact_refs=(),
            emission_class="claim-external",
            idempotency_key="task-placeholder",
        )

        self.assertEqual(task.state, "QUARANTINED")
        self.assertEqual(task.quarantine_reason, "SIGNATURE_INVALID")
        with self.assertRaises(S9PolicyError):
            self.s9.authorize_emission(task.task_id)

    def test_intake_rejects_unsigned_report_before_emission(self) -> None:
        task = self.s9.create_review_task(
            report_payload=self._report_body(claim_tier="novel-needs-human"),
            validation_report_ref="c4://report/unsigned",
            artifact_refs=(),
            emission_class="claim-external",
            idempotency_key="task-unsigned",
        )

        self.assertEqual(task.state, "QUARANTINED")
        self.assertEqual(task.quarantine_reason, "SIGNATURE_INVALID")
        with self.assertRaises(S9PolicyError):
            self.s9.authorize_emission(task.task_id)

    def test_intake_rejects_content_hash_mismatch(self) -> None:
        artifact = self._artifact()
        self.object_store._objects[artifact.content_hash] = b'{"tampered":true}'

        task = self.s9.create_review_task(
            report_payload=self._signed_report(claim_tier="recapitulated-known"),
            validation_report_ref="c4://report/valid",
            artifact_refs=(artifact.artifact_ref,),
            emission_class="internal-review",
            idempotency_key="task-1",
        )

        self.assertEqual(task.state, "QUARANTINED")
        self.assertEqual(task.quarantine_reason, "HASH_MISMATCH")

    def test_guardrail_hard_blocks_non_goal_emission(self) -> None:
        task = self.s9.create_review_task(
            report_payload=self._signed_report(claim_tier="recapitulated-known"),
            validation_report_ref="c4://report/valid",
            artifact_refs=(),
            emission_class="autonomous-paper-submission",
            idempotency_key="task-1",
        )

        self.assertEqual(task.state, "REFUSED")
        self.assertTrue(task.guardrail_result.hard_block)
        with self.assertRaises(S9PolicyError):
            self.s9.authorize_emission(task.task_id)

    def test_duplicate_create_review_task_is_idempotent(self) -> None:
        report = self._signed_report(claim_tier="recapitulated-known")

        first = self.s9.create_review_task(
            report_payload=report,
            validation_report_ref="c4://report/valid",
            artifact_refs=(),
            emission_class="internal-review",
            idempotency_key="same",
        )
        second = self.s9.create_review_task(
            report_payload=report,
            validation_report_ref="c4://report/valid",
            artifact_refs=(),
            emission_class="internal-review",
            idempotency_key="same",
        )

        self.assertEqual(first.task_id, second.task_id)

    def test_distinct_principal_and_novelty_gate_are_enforced(self) -> None:
        task = self.s9.create_review_task(
            report_payload=self._signed_report(claim_tier="novel-needs-human", leakage_status="FAIL"),
            validation_report_ref="c4://report/novel",
            artifact_refs=(),
            emission_class="claim-external",
            idempotency_key="task-1",
        )

        with self.assertRaises(S9PolicyError):
            self.s9.record_signoff(
                task.task_id,
                principal_id="reviewer-1",
                role="domain",
                decision="APPROVE",
                rationale="looks good",
            )

    def test_novel_approval_mints_single_use_emission_authorization(self) -> None:
        artifact = self._artifact()
        task = self.s9.create_review_task(
            report_payload=self._signed_report(claim_tier="novel-needs-human"),
            validation_report_ref="c4://report/novel",
            artifact_refs=(artifact.artifact_ref,),
            emission_class="claim-external",
            idempotency_key="task-1",
        )

        self.s9.record_signoff(
            task.task_id,
            principal_id="domain-reviewer",
            role="domain",
            decision="APPROVE",
            rationale="domain evidence reviewed",
        )
        self.s9.record_signoff(
            task.task_id,
            principal_id="ml-reviewer",
            role="ml",
            decision="APPROVE",
            rationale="ml evidence reviewed",
        )
        approved = self.s9.record_signoff(
            task.task_id,
            principal_id="governance-reviewer",
            role="governance",
            decision="APPROVE",
            rationale="governance approved",
            step_up_auth=True,
        )

        authorization = self.s9.authorize_emission(approved.task_id)

        self.assertEqual(approved.state, "APPROVED_FOR_EMISSION")
        self.assertTrue(self.minter.verify(authorization))
        consumed = self.minter.consume(authorization)
        self.assertTrue(consumed.consumed)
        self.assertEqual(authorization.bound_artifact_content_hashes, (artifact.content_hash,))
        with self.assertRaises(S9SignatureError):
            self.minter.consume(authorization)

    def test_ledger_verifies_and_detects_tamper(self) -> None:
        ledger = GovernanceLedger()
        ledger.append("one", {"value": 1})
        ledger.append("two", {"value": 2})

        self.assertTrue(ledger.verify().intact)
        ledger.entries[0].payload["value"] = 99
        self.assertFalse(ledger.verify().intact)
        self.assertEqual(ledger.verify().break_sequence, 1)

    def _artifact(self):
        return self.store.create_artifact(
            kind="model",
            payload={"weights": [1]},
            producer=Producer(subsystem="S2", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:model", environment_digest="oci:model"),
        )

    def _placeholder_report(self, *, claim_tier: str) -> dict:
        report = self._report_body(claim_tier=claim_tier)
        report["signature"] = {"algorithm": "placeholder", "key_id": "placeholder", "value": "placeholder"}
        return report

    def _signed_report(
        self,
        *,
        claim_tier: str,
        leakage_status: str = "PASS",
        cross_code_status: str = "PASS",
    ) -> dict:
        return self.signer.sign(
            self._report_body(
                claim_tier=claim_tier,
                leakage_status=leakage_status,
                cross_code_status=cross_code_status,
            )
        )

    @staticmethod
    def _report_body(
        *,
        claim_tier: str,
        leakage_status: str = "PASS",
        cross_code_status: str = "PASS",
    ) -> dict:
        return {
            "report_id": "report-1",
            "profile_ref": "c4://profile/1",
            "frozen_pipeline_ref": "c4://pipeline/1",
            "claim_tier": claim_tier,
            "checks": [
                {"check": "INJECTION", "status": "PASS"},
                {"check": "NULL_CONTROL", "status": "PASS"},
                {"check": "PHYSICAL_CONSISTENCY", "status": "PASS"},
                {"check": "CALIBRATION", "status": "PASS"},
                {"check": "CROSS_CODE", "status": cross_code_status},
                {"check": "LEAKAGE", "status": leakage_status},
            ],
            "aggregate": {"passed": True, "score": 1.0},
        }


if __name__ == "__main__":
    unittest.main()
