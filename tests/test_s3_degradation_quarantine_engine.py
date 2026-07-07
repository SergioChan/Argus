from __future__ import annotations

from copy import deepcopy
import json
import unittest

from argus_core import (
    C3ReportSigner,
    C3ReportVerifier,
    CheckResult,
    InMemoryArtifactStore,
    InMemoryAuditLedger,
    InMemoryBlindDataVault,
    InMemoryVerifierTrustStore,
    Lineage,
    Producer,
    S3BlindDataManager,
    S3BlindDataVaultError,
    S3DegradationQuarantineEngine,
    S3KeyManagementError,
    S3ReportBuilder,
    S3Verifier,
    run_perturbation_pair,
)


class S3DegradationQuarantineEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trust_store = InMemoryVerifierTrustStore()
        self.trust_store.register_key("s3-degrade-key", b"s3-degrade-secret")
        self.report_verifier = C3ReportVerifier(self.trust_store)
        self.store = InMemoryArtifactStore(report_verifier=self.report_verifier)
        self.audit = InMemoryAuditLedger()
        self.refs = self._seed_c4_inputs()
        self.verifier = S3Verifier(
            verifier_id="s3-degrade-referee",
            signer_key_id="s3-degrade-key",
            signer=C3ReportSigner(key_id="s3-degrade-key", secret=b"s3-degrade-secret"),
        )
        self.builder = S3ReportBuilder(
            verifier=self.verifier,
            artifact_store=self.store,
            producer=Producer(subsystem="S3", version="0.0.0", actor_id="s3.report-builder"),
        )
        self.engine = S3DegradationQuarantineEngine(
            artifact_store=self.store,
            audit_ledger=self.audit,
            report_verifier=self.report_verifier,
        )

    def test_tc16_physical_asymptotic_degradation_records_explicit_tier_effect(self) -> None:
        failed_physics = CheckResult(
            "PHYSICAL_CONSISTENCY",
            "FAIL",
            metrics={
                "test_cases": ["S3-TC16"],
                "sub_gates": {
                    "asymptotic": {
                        "status": "FAIL",
                        "asymptotic_pass": False,
                        "max_error": 0.25,
                    },
                },
            },
        )

        result = self.engine.apply_degradation_policy(
            checks=(failed_physics,),
            job_id="job-s3-t26-physical",
        )

        self.assertEqual(result.status, "DEGRADED")
        self.assertEqual(result.category, "DEGRADATION")
        self.assertEqual(result.degradations[0].code, "PHYSICAL_ASYMPTOTIC_LIMIT_FAIL")
        self.assertEqual(result.degradations[0].tier_effect, "blocks_recap_and_novel")
        self.assertEqual(result.checks[0].metrics["degradations"], ["PHYSICAL_ASYMPTOTIC_LIMIT_FAIL"])
        self.assertEqual(
            result.checks[0].metrics["degradation_details"][0],
            {
                "code": "PHYSICAL_ASYMPTOTIC_LIMIT_FAIL",
                "detail": "PHYSICAL_CONSISTENCY asymptotic-limit gate failed",
                "tier_effect": "blocks_recap_and_novel",
                "category": "DEGRADATION",
                "severity": "degraded",
                "check": "PHYSICAL_CONSISTENCY",
                "test_cases": ["S3-TC16"],
                "retryable": False,
            },
        )
        self.assertEqual(self.store.get_record(result.evidence_ref).kind, "s3_degradation_decision")

    def test_tc40_budget_breach_commits_partial_signed_report_with_unrun_inconclusive(self) -> None:
        result = self.engine.build_budget_breach_partial_report(
            report_builder=self.builder,
            profile_ref=self.refs["profile"],
            frozen_pipeline_ref=self.refs["frozen_pipeline"],
            completed_checks=(
                CheckResult("INJECTION", "PASS"),
                CheckResult("NULL_CONTROL", "PASS"),
            ),
            scheduled_checks=(
                "INJECTION",
                "NULL_CONTROL",
                "PHYSICAL_CONSISTENCY",
                "CALIBRATION",
                "RECAP_BENCHMARK",
                "CROSS_CODE",
                "LEAKAGE",
            ),
            proponent_id="s1-reference-physics",
            budget_actual_usd=1.25,
            budget_cap_usd=1.0,
            input_refs=(self.refs["validation_request"], self.refs["frozen_pipeline"], self.refs["profile"]),
            job_id="job-s3-t26-budget",
        )

        self.assertEqual(result.status, "PARTIAL_REPORT_EMITTED")
        self.assertEqual(result.category, "BUDGET")
        self.assertEqual(result.code, "S3_BUDGET_BREACH")
        self.assertFalse(result.retryable)
        self.assertTrue(result.report_ref.startswith("c4://artifact/"))
        report = json.loads(self.store.get_artifact(result.report_ref).decode("utf-8"))
        self.assertTrue(self.report_verifier.verify(report).valid)
        self.assertFalse(report["aggregate"]["passed"])
        self.assertEqual(report["claim_tier"], "ran-toy")
        self.assertIn("BUDGET", report["degradations"])
        self.assertIn("S3-TC40", report["claim_tier_justification"]["test_cases"])
        by_name = {check["check"]: check for check in report["checks"]}
        for check_name in ("PHYSICAL_CONSISTENCY", "CALIBRATION", "RECAP_BENCHMARK", "CROSS_CODE", "LEAKAGE"):
            self.assertEqual(by_name[check_name]["status"], "INCONCLUSIVE")
            self.assertEqual(by_name[check_name]["metrics"]["category"], "BUDGET")
            self.assertEqual(by_name[check_name]["metrics"]["degradations"], ["BUDGET"])
            self.assertEqual(
                by_name[check_name]["metrics"]["degradation_details"][0]["tier_effect"],
                "partial_report_unrun_check",
            )

    def test_signing_unavailable_is_retryable_and_does_not_write_unsigned_report(self) -> None:
        failing_builder = S3ReportBuilder(
            verifier=S3Verifier(
                verifier_id="s3-degrade-referee",
                signer_key_id="missing-key",
                signer=_UnavailableSigner(),
            ),
            artifact_store=self.store,
        )

        result = self.engine.build_signed_report_or_fail_closed(
            report_builder=failing_builder,
            profile_ref=self.refs["profile"],
            frozen_pipeline_ref=self.refs["frozen_pipeline"],
            checks=self._recap_checks(),
            proponent_id="s1-reference-physics",
            input_refs=(self.refs["validation_request"], self.refs["frozen_pipeline"], self.refs["profile"]),
            job_id="job-s3-t26-signing",
        )

        self.assertEqual(result.status, "RETRYABLE")
        self.assertEqual(result.category, "SIGNING_UNAVAILABLE")
        self.assertEqual(result.code, "S3_SIGNING_UNAVAILABLE")
        self.assertTrue(result.retryable)
        self.assertIsNone(result.report_ref)
        self.assertEqual(self.store.query_artifacts({"kind": "report"}), ())
        self.assertEqual(self.store.get_record(result.evidence_ref).kind, "s3_fail_closed")
        self.assertIn("s3.signing.unavailable", [event.event_type for event in self.audit.events()])

    def test_blind_hash_mismatch_is_reported_as_quarantine_without_truth_exposure(self) -> None:
        vault = InMemoryBlindDataVault(artifact_store=self.store, audit_ledger=self.audit)
        dataset = vault.register_dataset(
            dataset_id="s3-t26-blind-mismatch",
            version="1.0.0",
            split="blind",
            dataset_kind="held_out",
            opaque_input={"samples": [{"x": 2.0}]},
            truth={"target": "server-side-secret"},
            expected_truth_hash="blake3:" + "0" * 64,
        )
        manager = S3BlindDataManager(artifact_store=self.store, vault=vault, audit_ledger=self.audit)

        with self.assertRaises(S3BlindDataVaultError) as raised:
            manager.stage_for_pipeline(blind_data_handle=dataset.handle, job_id="job-s3-t26-blind")

        result = self.engine.result_from_blind_data_error(raised.exception, job_id="job-s3-t26-blind")

        self.assertEqual(result.status, "QUARANTINED")
        self.assertEqual(result.category, "QUARANTINE")
        self.assertEqual(result.code, "S3_BLIND_DATA_HASH_MISMATCH")
        self.assertEqual(result.quarantine_ref, raised.exception.quarantine_ref)
        quarantine = json.loads(self.store.get_artifact(result.quarantine_ref).decode("utf-8"))
        self.assertEqual(quarantine["quarantine"]["reason"], "S3:BLIND_HASH_MISMATCH")
        self.assertNotIn("server-side-secret", json.dumps(quarantine, sort_keys=True))

    def test_unsigned_or_tampered_consumed_report_is_quarantined(self) -> None:
        committed = self.builder.build_and_commit_report(
            profile_ref=self.refs["profile"],
            frozen_pipeline_ref=self.refs["frozen_pipeline"],
            checks=self._recap_checks(),
            proponent_id="s1-reference-physics",
            perturbation_outcome=run_perturbation_pair(
                perturbation_id="pair-s3-t26",
                must_react_expected=1.0,
                must_react_observed=1.0,
                must_not_react_observed=0.0,
                unperturbed_headline=1.0,
                perturbed_headline=0.2,
            ),
            input_refs=(self.refs["validation_request"], self.refs["frozen_pipeline"], self.refs["profile"]),
            job_id="job-s3-t26-consumer",
        )
        tampered = deepcopy(committed.report)
        tampered["checks"][0]["metrics"] = {"mutated": True}

        result = self.engine.quarantine_invalid_consumed_report(
            report=tampered,
            report_ref=committed.validation_report_ref,
            job_id="job-s3-t26-consumer",
            trace_id="trace-s3-t26-consumer",
        )

        self.assertEqual(result.status, "QUARANTINED")
        self.assertEqual(result.category, "QUARANTINE")
        self.assertEqual(result.code, "S3_REPORT_SIGNATURE_INVALID")
        self.assertTrue(result.quarantine_ref.startswith("c4://artifact/"))
        quarantine = json.loads(self.store.get_artifact(result.quarantine_ref).decode("utf-8"))
        self.assertEqual(quarantine["quarantine"]["reason"], "S3:REPORT_SIGNATURE_INVALID")
        self.assertEqual(quarantine["report_ref"], committed.validation_report_ref)
        self.assertIn("s3.quarantine", [event.event_type for event in self.audit.events()])

    @staticmethod
    def _recap_checks() -> tuple[CheckResult, ...]:
        return (
            CheckResult("INJECTION", "PASS"),
            CheckResult("NULL_CONTROL", "PASS"),
            CheckResult("PHYSICAL_CONSISTENCY", "PASS"),
            CheckResult("CALIBRATION", "PASS"),
            CheckResult("RECAP_BENCHMARK", "PASS", metrics={"test_cases": ["S3-T24", "S3-TC32"]}),
        )

    def _seed_c4_inputs(self) -> dict[str, str]:
        profile = self.store.create_artifact(
            kind="profile",
            artifact_ref="c4://profile/s3-t26/ewpt-r1",
            payload={
                "schema": "argus.s3.profile.v1",
                "checks": ["INJECTION", "NULL_CONTROL", "PHYSICAL_CONSISTENCY", "CALIBRATION", "RECAP_BENCHMARK"],
            },
            producer=Producer(subsystem="S3", version="0.0.0", actor_id="s3.profile-registry"),
            lineage=Lineage(input_refs=(), code_ref="git:s3-profile", environment_digest="oci:s3-profile"),
        )
        frozen = self.store.create_artifact(
            kind="frozen_pipeline",
            artifact_ref="c4://pipeline/s3-t26/frozen",
            payload={
                "schema": "argus.s3.frozen_pipeline_entrypoint.v1",
                "entrypoint": "predict",
                "artifact_refs": [],
                "code_ref": "git:s1-frozen",
                "environment_digest": "oci:s1-frozen",
                "seeds": ["seed-s3-t26"],
                "self_replay_passed": True,
            },
            producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.validate"),
            lineage=Lineage(input_refs=(), code_ref="git:s1-frozen", environment_digest="oci:s1-frozen"),
        )
        request = self.store.create_artifact(
            kind="validation_request",
            payload={
                "schema": "argus.s3.validation_request.v1",
                "job_id": "job-s3-t26",
                "profile_ref": profile.artifact_ref,
                "frozen_pipeline_ref": frozen.artifact_ref,
                "blind_dataset_handle": "blind://s3-t26/features",
            },
            producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.validate"),
            lineage=Lineage(
                input_refs=(profile.artifact_ref, frozen.artifact_ref),
                code_ref="git:s1-validation-request",
                environment_digest="oci:s1-validation-request",
            ),
        )
        return {
            "profile": profile.artifact_ref,
            "frozen_pipeline": frozen.artifact_ref,
            "validation_request": request.artifact_ref,
        }


class _UnavailableSigner:
    @property
    def key_id(self) -> str:
        return "missing-key"

    def sign(self, report: dict) -> dict:
        raise S3KeyManagementError(
            code="S3_SIGNING_KEY_UNAVAILABLE",
            message="signing key is unavailable",
        )


if __name__ == "__main__":
    unittest.main()
