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
    InMemoryVerifierTrustStore,
    Lineage,
    Producer,
    S3ChallengeError,
    S3ChallengeReauditEngine,
    S3ReportBuilder,
    S3Verifier,
    validation_report_digest,
)


class S3ChallengeReauditEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trust_store = InMemoryVerifierTrustStore()
        self.trust_store.register_key("s3-key", b"s3-secret")
        self.signer = C3ReportSigner(key_id="s3-key", secret=b"s3-secret")
        self.report_verifier = C3ReportVerifier(self.trust_store)
        self.verifier = S3Verifier(verifier_id="s3-referee", signer_key_id="s3-key", signer=self.signer)
        self.store = InMemoryArtifactStore(report_verifier=self.report_verifier)
        self.audit = InMemoryAuditLedger()
        self.refs = self._seed_c4_inputs()
        self.builder = S3ReportBuilder(
            verifier=self.verifier,
            artifact_store=self.store,
            producer=Producer(subsystem="S3", version="0.0.0", actor_id="s3.report-builder"),
            code_ref="argus-core:s3.report-builder",
            environment_digest="python:s3-report-builder:v1",
        )
        self.engine = S3ChallengeReauditEngine(
            artifact_store=self.store,
            report_verifier=self.report_verifier,
            audit_ledger=self.audit,
            producer=Producer(subsystem="S3", version="0.0.0", actor_id="s3.challenge"),
            code_ref="argus-core:s3.challenge-reaudit",
            environment_digest="python:s3-challenge:v1",
        )

    def test_tc34_deterministic_challenge_reproduces_prior_report_exactly(self) -> None:
        committed = self._commit_report()

        result = self.engine.challenge(
            report_ref=committed.validation_report_ref,
            rerun_checks=self._base_checks(),
            job_id="job-s3-t25-exact",
            trace_id="trace-s3-t25-exact",
        )

        self.assertEqual(result.match, "EXACT")
        self.assertFalse(result.alarm_raised)
        self.assertIsNone(result.suspect_ref)
        self.assertEqual(result.canonical_hash_original, committed.canonical.digest)
        self.assertEqual(result.canonical_hash_rerun, committed.canonical.digest)
        self.assertEqual(result.signing_payload_hash_original, committed.canonical.signing_payload_digest)
        self.assertEqual(result.signing_payload_hash_rerun, committed.canonical.signing_payload_digest)
        self.assertTrue(all(delta.delta == 0 for delta in result.check_deltas))
        self.assertEqual(result.event_intents, ())
        self.assertIn("S3-TC34", result.test_cases)
        self.assertIn("S3-TC46", result.test_cases)

        payload = self._artifact_payload(result.challenge_ref)
        self.assertEqual(payload["match"], "EXACT")
        self.assertEqual(payload["report_ref"], committed.validation_report_ref)
        self.assertEqual(payload["canonical_hash_rerun"], validation_report_digest(committed.report))
        self.assertEqual(self.store.get_record(result.challenge_ref).lineage.input_refs, (committed.validation_report_ref,))

    def test_tc35_stochastic_declared_tolerance_returns_within_tolerance_without_alarm(self) -> None:
        committed = self._commit_report(
            checks=(
                CheckResult(
                    "INJECTION",
                    "PASS",
                    metrics={
                        "determinism": "stochastic",
                        "observed": 0.95,
                        "nondeterminism_tolerance": {"metric": "observed", "absolute": 0.02},
                    },
                ),
                *self._base_checks()[1:],
            )
        )
        rerun = (
            CheckResult(
                "INJECTION",
                "PASS",
                metrics={
                    "determinism": "stochastic",
                    "observed": 0.961,
                    "nondeterminism_tolerance": {"metric": "observed", "absolute": 0.02},
                },
            ),
            *self._base_checks()[1:],
        )

        result = self.engine.challenge(
            report_ref=committed.validation_report_ref,
            rerun_checks=rerun,
            job_id="job-s3-t25-tolerance",
            trace_id="trace-s3-t25-tolerance",
        )

        self.assertEqual(result.match, "WITHIN_TOLERANCE")
        self.assertFalse(result.alarm_raised)
        self.assertEqual(result.event_intents, ())
        self.assertIn("S3-TC35", result.test_cases)
        injection_delta = next(delta for delta in result.check_deltas if delta.check == "INJECTION")
        self.assertAlmostEqual(injection_delta.delta, 0.011)
        self.assertEqual(injection_delta.tolerance, 0.02)
        self.assertEqual(injection_delta.policy, "stochastic:absolute_tolerance")

        payload = self._artifact_payload(result.challenge_ref)
        self.assertEqual(payload["check_deltas"][0]["match"], "WITHIN_TOLERANCE")

    def test_tc36_mismatch_raises_canary_alarm_and_marks_original_report_suspect(self) -> None:
        committed = self._commit_report()
        rerun = (
            CheckResult("INJECTION", "PASS", metrics={"determinism": "deterministic", "observed": 0.5}),
            *self._base_checks()[1:],
        )

        result = self.engine.challenge(
            report_ref=committed.validation_report_ref,
            rerun_checks=rerun,
            job_id="job-s3-t25-mismatch",
            trace_id="trace-s3-t25-mismatch",
        )

        self.assertEqual(result.match, "MISMATCH")
        self.assertTrue(result.alarm_raised)
        self.assertIn("s3.canary.alarm", result.event_intents)
        self.assertIn("S3-TC36", result.test_cases)
        self.assertTrue(result.suspect_ref and result.suspect_ref.startswith("c4://artifact/"))
        self.assertNotEqual(result.canonical_hash_rerun, committed.canonical.digest)
        self.assertNotEqual(result.signing_payload_hash_rerun, committed.canonical.signing_payload_digest)

        suspect_payload = self._artifact_payload(result.suspect_ref or "")
        self.assertEqual(suspect_payload["status"], "SUSPECT")
        self.assertEqual(suspect_payload["report_ref"], committed.validation_report_ref)
        self.assertEqual(suspect_payload["reason"], "S3_CHALLENGE_MISMATCH")
        self.assertEqual(suspect_payload["challenge_ref"], result.challenge_ref)
        self.assertEqual(self.store.get_artifact(committed.validation_report_ref), json.dumps(committed.report, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        self.assertIn("s3.canary.alarm", [event.event_type for event in self.audit.events()])

    def test_tc46_seeded_check_is_exact_not_tolerance_based(self) -> None:
        committed = self._commit_report(
            checks=(
                CheckResult(
                    "INJECTION",
                    "PASS",
                    metrics={
                        "determinism": "seeded",
                        "seed": 17,
                        "observed": 0.95,
                        "nondeterminism_tolerance": {"metric": "observed", "absolute": 1.0},
                    },
                ),
                *self._base_checks()[1:],
            )
        )
        rerun = (
            CheckResult(
                "INJECTION",
                "PASS",
                metrics={
                    "determinism": "seeded",
                    "seed": 17,
                    "observed": 0.951,
                    "nondeterminism_tolerance": {"metric": "observed", "absolute": 1.0},
                },
            ),
            *self._base_checks()[1:],
        )

        result = self.engine.challenge(
            report_ref=committed.validation_report_ref,
            rerun_checks=rerun,
            job_id="job-s3-t25-seeded",
            trace_id="trace-s3-t25-seeded",
        )

        self.assertEqual(result.match, "MISMATCH")
        self.assertTrue(result.alarm_raised)
        seeded_delta = next(delta for delta in result.check_deltas if delta.check == "INJECTION")
        self.assertEqual(seeded_delta.policy, "seeded:exact")
        self.assertEqual(seeded_delta.tolerance, 0.0)

    def test_stochastic_beyond_tolerance_raises_canary_alarm(self) -> None:
        committed = self._commit_report(
            checks=(
                CheckResult(
                    "INJECTION",
                    "PASS",
                    metrics={
                        "determinism": "stochastic",
                        "observed": 0.95,
                        "nondeterminism_tolerance": {"metric": "observed", "absolute": 0.02},
                    },
                ),
                *self._base_checks()[1:],
            )
        )
        rerun = (
            CheckResult(
                "INJECTION",
                "PASS",
                metrics={
                    "determinism": "stochastic",
                    "observed": 0.99,
                    "nondeterminism_tolerance": {"metric": "observed", "absolute": 0.02},
                },
            ),
            *self._base_checks()[1:],
        )

        result = self.engine.challenge(
            report_ref=committed.validation_report_ref,
            rerun_checks=rerun,
            job_id="job-s3-t25-stochastic-mismatch",
            trace_id="trace-s3-t25-stochastic-mismatch",
        )

        self.assertEqual(result.match, "MISMATCH")
        self.assertTrue(result.alarm_raised)
        self.assertIn("S3-TC36", result.test_cases)
        injection_delta = next(delta for delta in result.check_deltas if delta.check == "INJECTION")
        self.assertEqual(injection_delta.policy, "stochastic:absolute_tolerance")
        self.assertAlmostEqual(injection_delta.delta, 0.04)
        self.assertEqual(injection_delta.tolerance, 0.02)
        self.assertEqual(injection_delta.reason, "outside_declared_tolerance")

    def test_tampered_prior_report_signature_is_rejected_before_challenge_artifact_write(self) -> None:
        committed = self._commit_report()
        tampered = deepcopy(committed.report)
        tampered["checks"][0]["metrics"]["observed"] = 0.5
        tampered_record = self.store.create_artifact(
            kind="tampered_report_fixture",
            payload=tampered,
            producer=Producer(subsystem="S3", version="0.0.0", actor_id="s3.test"),
            lineage=Lineage(
                input_refs=(committed.validation_report_ref,),
                code_ref="tests:s3.challenge",
                environment_digest="python:tests",
            ),
        )

        with self.assertRaises(S3ChallengeError) as raised:
            self.engine.challenge(
                report_ref=tampered_record.artifact_ref,
                rerun_checks=self._base_checks(),
                job_id="job-s3-t25-tampered",
            )

        self.assertEqual(raised.exception.code, "S3_CHALLENGE_REPORT_SIGNATURE_INVALID")
        self.assertNotIn("s3_challenge_result", [record.kind for record in self.store.query_artifacts()])

    def _commit_report(self, *, checks: tuple[CheckResult, ...] | None = None):
        return self.builder.build_and_commit_report(
            profile_ref=self.refs["profile"],
            frozen_pipeline_ref=self.refs["frozen_pipeline"],
            checks=checks or self._base_checks(),
            proponent_id="s1-reference-physics",
            challenger_ids=("challenger-a", "challenger-b"),
            debate_ref="c4://debate/s3-t25",
            input_refs=(
                self.refs["validation_request"],
                self.refs["frozen_pipeline"],
                self.refs["profile"],
                self.refs["model"],
            ),
            job_id="job-s3-t25-report",
        )

    def _base_checks(self) -> tuple[CheckResult, ...]:
        return (
            CheckResult("INJECTION", "PASS", metrics={"determinism": "deterministic", "observed": 0.95}),
            CheckResult("NULL_CONTROL", "PASS", metrics={"determinism": "deterministic", "observed": 0.0}),
            CheckResult("PHYSICAL_CONSISTENCY", "PASS", metrics={"determinism": "deterministic", "observed": 1.0}),
            CheckResult("CALIBRATION", "PASS", metrics={"determinism": "deterministic", "observed": 0.7}),
            CheckResult(
                "RECAP_BENCHMARK",
                "PASS",
                metrics={"determinism": "deterministic", "observed": 0.99, "test_cases": ["S3-T24", "S3-TC32"]},
            ),
        )

    def _seed_c4_inputs(self) -> dict[str, str]:
        profile = self.store.create_artifact(
            kind="profile",
            artifact_ref="c4://profile/s3-t25/ewpt-r1",
            payload={
                "schema": "argus.s3.profile.v1",
                "checks": ["INJECTION", "NULL_CONTROL", "PHYSICAL_CONSISTENCY", "CALIBRATION", "RECAP_BENCHMARK"],
            },
            producer=Producer(subsystem="S3", version="0.0.0", actor_id="s3.profile-registry"),
            lineage=Lineage(input_refs=(), code_ref="git:s3-profile", environment_digest="oci:s3-profile"),
        )
        model = self.store.create_artifact(
            kind="model",
            payload={"schema": "argus.s2.model.v1", "weights": [1.0], "uncertainty_tag": {"kind": "interval", "radius": 0.01}},
            producer=Producer(subsystem="S2", version="0.0.0", actor_id="s2.builder"),
            lineage=Lineage(
                input_refs=(),
                code_ref="git:s2-builder",
                environment_digest="oci:s2-builder",
                seeds=("seed-s3-t25-model",),
            ),
        )
        frozen = self.store.create_artifact(
            kind="frozen_pipeline",
            payload={
                "schema": "argus.s3.frozen_pipeline_entrypoint.v1",
                "entrypoint": "predict",
                "artifact_refs": [model.artifact_ref],
                "model_ref": model.artifact_ref,
                "code_ref": "git:s1-frozen",
                "environment_digest": "oci:s1-frozen",
                "seeds": ["seed-s3-t25-frozen"],
                "self_replay_passed": True,
            },
            producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.validate"),
            lineage=Lineage(
                input_refs=(model.artifact_ref,),
                code_ref="git:s1-frozen",
                environment_digest="oci:s1-frozen",
                seeds=("seed-s3-t25-frozen",),
            ),
        )
        request_payload = {
            "schema": "argus.s3.validation_request.v1",
            "job_id": "job-s3-t25",
            "profile_ref": profile.artifact_ref,
            "frozen_pipeline_ref": frozen.artifact_ref,
            "artifact_refs": [model.artifact_ref],
            "blind_dataset_handle": "blind://s3-t25/features",
        }
        validation_request = self.store.create_artifact(
            kind="validation_request",
            payload=deepcopy(request_payload),
            producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.validate"),
            lineage=Lineage(
                input_refs=(profile.artifact_ref, frozen.artifact_ref),
                code_ref="git:s1-validation-request",
                environment_digest="oci:s1-validation-request",
            ),
        )
        return {
            "profile": profile.artifact_ref,
            "model": model.artifact_ref,
            "frozen_pipeline": frozen.artifact_ref,
            "validation_request": validation_request.artifact_ref,
        }

    def _artifact_payload(self, artifact_ref: str) -> dict:
        return json.loads(self.store.get_artifact(artifact_ref).decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
