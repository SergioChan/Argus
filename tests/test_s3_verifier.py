from __future__ import annotations

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from argus_core import (
    C3_SIGNATURE_ALGORITHM,
    C3ReportSigner,
    C3ReportVerifier,
    CapabilityDescriptor,
    CheckResult,
    ContaminationIndex,
    FrozenPipelineEntrypointContractError,
    InMemoryArtifactStore,
    InMemoryVerifierTrustStore,
    IndependenceAttestation,
    Lineage,
    Producer,
    RefereePolicyError,
    S3Verifier,
    SignerIdentityError,
    SourceDocument,
    attest_challenger_independence,
    build_frozen_pipeline_entrypoint_request,
    build_referee_block,
    canonical_json_bytes,
    run_calibration_check,
    run_cross_code_check,
    run_leakage_check,
    run_perturbation_pair,
    tier_from_checks,
)


ROOT = Path(__file__).resolve().parents[1]
C3_SCHEMA_PATH = ROOT / "schemas" / "contracts" / "c3.validation-report.schema.json"


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


class S3FrozenPipelineEntrypointContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.c3_schema = json.loads(C3_SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(cls.c3_schema)
        cls.c3_validator = Draft202012Validator(cls.c3_schema)

    def test_contract_normalizes_c1_handoff_to_c3_verification_request(self) -> None:
        store = InMemoryArtifactStore()
        frozen_record = self._frozen_pipeline_record(store)
        c1_request = self._c1_validation_request(frozen_record.artifact_ref)

        request = build_frozen_pipeline_entrypoint_request(c1_request, artifact_store=store)
        repeated = build_frozen_pipeline_entrypoint_request(dict(reversed(c1_request.items())), artifact_store=store)
        verification_request = request["verification_request"]

        self._assert_c3_valid(verification_request)
        self.assertEqual(request, repeated)
        self.assertEqual(canonical_json_bytes(request), canonical_json_bytes(repeated))
        self.assertEqual(verification_request["blind_data_handle"], "blind://vault/job-1/features")
        self.assertNotIn("blind_dataset_handle", verification_request)
        self.assertEqual(verification_request["frozen_pipeline_ref"], frozen_record.artifact_ref)
        self.assertEqual(verification_request["budget_token_ref"], "budget://token/job-1")
        self.assertEqual(request["entrypoint"]["method"], "predict")
        self.assertEqual(request["entrypoint"]["entrypoint_ref"], "argus_core.s2.baseline.predict")
        self.assertEqual(request["entrypoint"]["content_hash"], frozen_record.content_hash)
        self.assertEqual(request["artifact_refs"], ["c4://artifact/model"])
        self.assertNotIn("secret-label", json.dumps(request, sort_keys=True))

    def test_contract_rejects_non_c4_frozen_pipeline_ref_with_typed_error(self) -> None:
        store = InMemoryArtifactStore()
        c1_request = self._c1_validation_request("file:///tmp/pipeline")

        with self.assertRaises(FrozenPipelineEntrypointContractError) as raised:
            build_frozen_pipeline_entrypoint_request(c1_request, artifact_store=store)

        error = raised.exception.as_c1_payload()
        self.assertEqual(error["category"], "POLICY")
        self.assertEqual(error["code"], "S3_FROZEN_PIPELINE_REF_INVALID")
        self.assertFalse(error["retryable"])

    def test_contract_rejects_pipeline_without_predict_entrypoint(self) -> None:
        store = InMemoryArtifactStore()
        frozen_record = self._frozen_pipeline_record(store, entrypoint="train")

        with self.assertRaises(FrozenPipelineEntrypointContractError) as raised:
            build_frozen_pipeline_entrypoint_request(
                self._c1_validation_request(frozen_record.artifact_ref),
                artifact_store=store,
            )

        self.assertEqual(raised.exception.as_c1_payload()["code"], "S3_FROZEN_PIPELINE_ENTRYPOINT_INVALID")

    def test_contract_rejects_raw_blind_label_material_without_echoing_secret(self) -> None:
        store = InMemoryArtifactStore()
        frozen_record = self._frozen_pipeline_record(store)
        c1_request = {
            **self._c1_validation_request(frozen_record.artifact_ref),
            "blind_labels": ["secret-label-must-not-leak"],
        }

        with self.assertRaises(FrozenPipelineEntrypointContractError) as raised:
            build_frozen_pipeline_entrypoint_request(c1_request, artifact_store=store)

        payload = raised.exception.as_c1_payload()
        self.assertEqual(payload["code"], "S3_VERIFICATION_REQUEST_LABEL_MATERIAL_FORBIDDEN")
        self.assertNotIn("secret-label-must-not-leak", str(raised.exception))
        self.assertNotIn("secret-label-must-not-leak", json.dumps(payload, sort_keys=True))

    def _assert_c3_valid(self, payload: dict[str, object]) -> None:
        errors = sorted(self.c3_validator.iter_errors(payload), key=lambda error: list(error.path))
        self.assertEqual(errors, [], msg=[error.message for error in errors])

    def _frozen_pipeline_record(
        self,
        store: InMemoryArtifactStore,
        *,
        entrypoint: str = "argus_core.s2.baseline.predict",
    ):
        return store.create_artifact(
            kind="frozen_pipeline",
            payload={
                "schema": "argus.s3.frozen_pipeline_entrypoint.v1",
                "entrypoint": entrypoint,
                "artifact_refs": ["c4://artifact/model"],
                "model_ref": "c4://artifact/model",
                "io_signature": {
                    "inputs": [{"name": "x", "dtype": "float64"}],
                    "outputs": [{"name": "prediction", "dtype": "float64"}],
                    "uncertainty": {"representation": "interval"},
                },
                "code_ref": "git:project-argus@s3-t11",
                "environment_digest": "oci:s3-frozen-pipeline@sha256-s3-t11",
                "seeds": ["seed-s3-t11"],
                "self_replay_passed": True,
            },
            producer=Producer(subsystem="S3", version="0.0.0", actor_id="s3-t11"),
            lineage=Lineage(
                input_refs=("c4://artifact/model",),
                code_ref="git:project-argus@s3-t11",
                environment_digest="oci:s3-frozen-pipeline@sha256-s3-t11",
                seeds=("seed-s3-t11",),
            ),
        )

    @staticmethod
    def _c1_validation_request(frozen_pipeline_ref: str) -> dict[str, object]:
        return {
            "job_id": "11111111-1111-4111-8111-000000000111",
            "frozen_pipeline_ref": frozen_pipeline_ref,
            "artifact_refs": ["c4://artifact/model"],
            "profile_ref": "c4://profile/ewpt/v1",
            "blind_dataset_handle": "blind://vault/job-1/features",
            "budget_token_ref": "budget://token/job-1",
            "trace_id": "trace-s3-t11",
        }


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
        self.assertNotIn("observed_degradation", report["perturbation_pairs"][0])
        self.assertNotIn("amplitude_linearity", report["perturbation_pairs"][1])

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

    def test_challenger_independence_gate_downgrades_untrusted_novel_candidates(self) -> None:
        cases = (
            (
                "lineage_not_disjoint",
                IndependenceAttestation(
                    candidate_ids=("challenger-a", "challenger-b"),
                    selected_entity_ids=("challenger-a", "challenger-b"),
                    min_independent=2,
                    lineage_disjoint=False,
                    correlation_warning=False,
                    excluded_tags=(),
                ),
            ),
            (
                "correlation_warning",
                IndependenceAttestation(
                    candidate_ids=("challenger-a", "challenger-b"),
                    selected_entity_ids=("challenger-a", "challenger-b"),
                    min_independent=2,
                    lineage_disjoint=True,
                    correlation_warning=True,
                    excluded_tags=(),
                ),
            ),
            (
                "selected_below_minimum",
                IndependenceAttestation(
                    candidate_ids=("challenger-a",),
                    selected_entity_ids=("challenger-a",),
                    min_independent=2,
                    lineage_disjoint=True,
                    correlation_warning=False,
                    excluded_tags=(),
                ),
            ),
            (
                "below_novel_independence_floor",
                IndependenceAttestation(
                    candidate_ids=("challenger-a",),
                    selected_entity_ids=("challenger-a",),
                    min_independent=1,
                    lineage_disjoint=True,
                    correlation_warning=False,
                    excluded_tags=(),
                ),
            ),
            (
                "selected_not_candidate",
                IndependenceAttestation(
                    candidate_ids=("challenger-a", "challenger-b"),
                    selected_entity_ids=("challenger-a", "challenger-c"),
                    min_independent=2,
                    lineage_disjoint=True,
                    correlation_warning=False,
                    excluded_tags=(),
                ),
            ),
        )

        for name, attestation in cases:
            with self.subTest(name=name):
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
                    challenger_ids=attestation.candidate_ids,
                    independence_attestation=attestation,
                )

                self.assertTrue(report["aggregate"]["passed"])
                self.assertEqual(report["claim_tier"], "recapitulated-known")
                self.assertFalse(report["claim_tier_is_candidate"])
                self.assertTrue(C3ReportVerifier(self.trust_store).verify(report).valid)

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
