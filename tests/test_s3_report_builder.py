from __future__ import annotations

from copy import deepcopy
import json
import unittest

from argus_core import (
    C3ReportSigner,
    C3ReportVerifier,
    CheckResult,
    IllegalTierError,
    InMemoryArtifactStore,
    InMemoryVerifierTrustStore,
    Lineage,
    Producer,
    S3ReportBuilder,
    S3Verifier,
    WRITE_ONCE_BUCKET,
    WriteOnceViolationError,
    hash_bytes,
    run_perturbation_pair,
    validation_report_digest,
)


class S3ReportBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trust_store = InMemoryVerifierTrustStore()
        self.trust_store.register_key("s3-key", b"s3-secret")
        self.signer = C3ReportSigner(key_id="s3-key", secret=b"s3-secret")
        self.report_verifier = C3ReportVerifier(self.trust_store)
        self.verifier = S3Verifier(verifier_id="s3-referee", signer_key_id="s3-key", signer=self.signer)
        self.store = InMemoryArtifactStore(report_verifier=self.report_verifier)
        self.refs = self._seed_c4_inputs()
        self.builder = S3ReportBuilder(
            verifier=self.verifier,
            artifact_store=self.store,
            producer=Producer(subsystem="S3", version="0.0.0", actor_id="s3.report-builder"),
            code_ref="argus-core:s3.report-builder",
            environment_digest="python:s3-report-builder:v1",
        )

    def test_signed_report_is_committed_to_write_once_before_return(self) -> None:
        committed = self._commit_recap_report()

        stored_bytes = self.store.get_artifact(committed.validation_report_ref)
        stored_report = json.loads(stored_bytes.decode("utf-8"))
        verification = self.report_verifier.verify(stored_report)

        self.assertEqual(committed.report, stored_report)
        self.assertEqual(committed.record.artifact_ref, committed.validation_report_ref)
        self.assertEqual(committed.record.content_hash, hash_bytes(stored_bytes))
        self.assertEqual(self.store.bucket_class_for_artifact(committed.validation_report_ref), WRITE_ONCE_BUCKET)
        self.assertTrue(verification.valid)
        self.assertEqual(verification.claim_tier, "recapitulated-known")
        self.assertEqual(committed.canonical.digest, validation_report_digest(stored_report))

    def test_write_once_report_overwrite_and_delete_are_denied(self) -> None:
        committed = self._commit_recap_report(artifact_ref="c4://report/s3-t23/write-once")
        original_bytes = self.store.get_artifact(committed.validation_report_ref)
        original_hash = committed.record.content_hash

        with self.assertRaises(WriteOnceViolationError):
            self._commit_recap_report(artifact_ref=committed.validation_report_ref)

        with self.assertRaises(WriteOnceViolationError):
            self.store.delete_artifact(committed.validation_report_ref)

        self.assertEqual(self.store.get_artifact(committed.validation_report_ref), original_bytes)
        self.assertEqual(self.store.get_record(committed.validation_report_ref).content_hash, original_hash)

    def test_committed_report_couples_promoted_tier_and_lineage(self) -> None:
        committed = self._commit_recap_report()
        promoted = self.store.create_artifact(
            kind="model",
            payload={
                "schema": "argus.s3_t23.promoted_model.v1",
                "source_model_ref": self.refs["model"],
                "validation_report_ref": committed.validation_report_ref,
                "uncertainty_tag": {"kind": "interval", "radius": 0.01},
            },
            producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.promoter"),
            lineage=Lineage(
                input_refs=(self.refs["model"], committed.validation_report_ref),
                code_ref="argus-core:s1.promote",
                environment_digest="python:s1-promote:v1",
                seeds=("seed-s3-t23-promote",),
                job_id="job-s3-t23",
            ),
            claim_tier="recapitulated-known",
            validation_report_ref=committed.validation_report_ref,
        )

        with self.assertRaises(IllegalTierError):
            self.store.create_artifact(
                kind="model",
                payload={
                    "schema": "argus.s3_t23.promoted_model.v1",
                    "source_model_ref": self.refs["model"],
                    "validation_report_ref": committed.validation_report_ref,
                    "uncertainty_tag": {"kind": "interval", "radius": 0.01},
                },
                producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.promoter"),
                lineage=Lineage(
                    input_refs=(self.refs["model"], committed.validation_report_ref),
                    code_ref="argus-core:s1.promote",
                    environment_digest="python:s1-promote:v1",
                    seeds=("seed-s3-t23-promote",),
                    job_id="job-s3-t23",
                ),
                claim_tier="novel-needs-human",
                validation_report_ref=committed.validation_report_ref,
            )

        lineage = self.store.get_lineage(promoted.artifact_ref, direction="ancestors")
        lineage_refs = {node.artifact_ref for node in lineage.nodes}
        self.assertIn(committed.validation_report_ref, lineage_refs)
        self.assertIn(self.refs["validation_request"], lineage_refs)
        self.assertIn(self.refs["frozen_pipeline"], lineage_refs)
        self.assertIn(self.refs["profile"], lineage_refs)
        self.assertEqual(self.store.query_artifacts({"validation_report_ref": committed.validation_report_ref}), (promoted,))

    def _commit_recap_report(self, *, artifact_ref: str | None = None):
        outcome = run_perturbation_pair(
            perturbation_id="pair-s3-t23",
            must_react_expected=1.0,
            must_react_observed=1.0,
            must_not_react_observed=0.0,
            unperturbed_headline=1.0,
            perturbed_headline=0.2,
        )
        return self.builder.build_and_commit_report(
            profile_ref=self.refs["profile"],
            frozen_pipeline_ref=self.refs["frozen_pipeline"],
            checks=(
                CheckResult("INJECTION", "PASS"),
                CheckResult("NULL_CONTROL", "PASS"),
                CheckResult("PHYSICAL_CONSISTENCY", "PASS"),
                CheckResult("CALIBRATION", "PASS"),
                CheckResult("RECAP_BENCHMARK", "PASS", metrics={"test_cases": ["S3-T24", "S3-TC32"]}),
            ),
            proponent_id="s1-reference-physics",
            perturbation_outcome=outcome,
            challenger_ids=("challenger-a", "challenger-b"),
            debate_ref="c4://debate/s3-t23",
            input_refs=(
                self.refs["validation_request"],
                self.refs["frozen_pipeline"],
                self.refs["profile"],
                self.refs["model"],
            ),
            job_id="job-s3-t23",
            artifact_ref=artifact_ref,
        )

    def _seed_c4_inputs(self) -> dict[str, str]:
        profile = self.store.create_artifact(
            kind="profile",
            artifact_ref="c4://profile/s3-t23/ewpt-r1",
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
                seeds=("seed-s3-t23-model",),
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
                "seeds": ["seed-s3-t23-frozen"],
                "self_replay_passed": True,
            },
            producer=Producer(subsystem="S1", version="0.0.0", actor_id="s1.validate"),
            lineage=Lineage(
                input_refs=(model.artifact_ref,),
                code_ref="git:s1-frozen",
                environment_digest="oci:s1-frozen",
                seeds=("seed-s3-t23-frozen",),
            ),
        )
        request_payload = {
            "schema": "argus.s3.validation_request.v1",
            "job_id": "job-s3-t23",
            "profile_ref": profile.artifact_ref,
            "frozen_pipeline_ref": frozen.artifact_ref,
            "artifact_refs": [model.artifact_ref],
            "blind_dataset_handle": "blind://s3-t23/features",
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


if __name__ == "__main__":
    unittest.main()
