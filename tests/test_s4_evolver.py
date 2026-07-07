from __future__ import annotations

from copy import deepcopy
import json
import unittest

from argus_core import (
    C3ReportSigner,
    C3ReportVerifier,
    CapabilityDescriptor,
    ChallengerPanel,
    ChallengerPanelError,
    CheckResult,
    DiversityPolicy,
    EvolutionResult,
    EvolverBounds,
    InMemoryArtifactStore,
    InMemoryVerifierTrustStore,
    IndependenceAttestation,
    Lineage,
    PerturbationPairOutcome,
    Producer,
    RefereeRoundEvidence,
    S3Verifier,
    admit_signed_reward,
    challenge_verdict_from_report,
    evolve_under_debate,
    precondition_gate,
    run_debate_round,
    run_perturbation_pair,
    select_challenger_panel,
    write_debate_ledger,
)


class S4EvolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trust_store = InMemoryVerifierTrustStore()
        self.trust_store.register_key("s3-key", b"s3-secret")
        self.signer = C3ReportSigner(key_id="s3-key", secret=b"s3-secret")
        self.report_verifier = C3ReportVerifier(self.trust_store)
        self.referee = S3Verifier(verifier_id="s3-referee", signer_key_id="s3-key", signer=self.signer)
        self.store = InMemoryArtifactStore(report_verifier=self.report_verifier)
        self.candidate = self.store.create_artifact(
            kind="container",
            payload={"entrypoint": "candidate.predict"},
            producer=Producer(subsystem="S2", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:candidate", environment_digest="oci:candidate"),
        )

    def test_precondition_refuses_without_verifier_and_commits_no_budget(self) -> None:
        preflight = precondition_gate(
            verifier_available=False,
            oracle_available=True,
            signer_trusted=True,
            estimated_cost_usd="0.25",
            single_call_budget_usd="1.00",
            independence_attestation=self._good_attestation(),
            require_independence=True,
        )

        self.assertEqual(preflight.status, "REFUSED")
        self.assertEqual(preflight.reason, "VERIFIER_UNAVAILABLE")
        self.assertFalse(preflight.budget_committed)

    def test_precondition_caps_tier_when_independence_is_missing(self) -> None:
        preflight = precondition_gate(
            verifier_available=True,
            oracle_available=True,
            signer_trusted=True,
            estimated_cost_usd="0.25",
            single_call_budget_usd="1.00",
            independence_attestation=IndependenceAttestation(
                candidate_ids=("challenger-a", "challenger-b"),
                selected_entity_ids=("challenger-a",),
                min_independent=2,
                lineage_disjoint=False,
                correlation_warning=True,
                excluded_tags=(),
            ),
        )

        self.assertEqual(preflight.status, "ACCEPTED")
        self.assertFalse(preflight.independence_available)
        self.assertEqual(preflight.max_achievable_tier, "recapitulated-known")

    def test_reward_admission_rejects_tampered_report_signature(self) -> None:
        report = self._signed_report(candidate_ref=self.candidate.artifact_ref, outcome=self._passing_outcome())
        tampered = deepcopy(report)
        tampered["aggregate"]["score"] = 0.99
        verification = self.report_verifier.verify(tampered)

        admission = admit_signed_reward(
            candidate_ref=self.candidate.artifact_ref,
            report=tampered,
            verification=verification,
            validation_report_ref="c4://report/tampered",
            expected_pipeline_ref=self.candidate.artifact_ref,
        )

        self.assertFalse(admission.admitted)
        self.assertEqual(admission.reason, "SIGNATURE")
        self.assertTrue(admission.quarantine_required)

    def test_reward_admission_uses_signed_score_and_routes_novel_to_human(self) -> None:
        report = self._signed_report(
            candidate_ref=self.candidate.artifact_ref,
            outcome=self._passing_outcome(),
            checks=self._novel_checks(),
            score=0.4,
        )
        report_ref = self._store_report(report, self.candidate.artifact_ref)
        verification = self.report_verifier.verify(report)

        admission = admit_signed_reward(
            candidate_ref=self.candidate.artifact_ref,
            report=report,
            verification=verification,
            validation_report_ref=report_ref,
            expected_pipeline_ref=self.candidate.artifact_ref,
            candidate_self_score=0.99,
        )

        self.assertTrue(admission.admitted)
        self.assertEqual(admission.score, 0.4)
        self.assertEqual(admission.claim_tier, "novel-needs-human")
        self.assertTrue(admission.human_review_required)

    def test_reward_admission_treats_inconclusive_as_non_improvement(self) -> None:
        report = self._signed_report(
            candidate_ref=self.candidate.artifact_ref,
            outcome=PerturbationPairOutcome((), ()),
            checks=(CheckResult("INJECTION", "INCONCLUSIVE"),),
        )
        verification = self.report_verifier.verify(report)

        admission = admit_signed_reward(
            candidate_ref=self.candidate.artifact_ref,
            report=report,
            verification=verification,
            validation_report_ref="c4://report/inconclusive",
        )

        self.assertFalse(admission.admitted)
        self.assertEqual(admission.reason, "INCONCLUSIVE")

    def test_debate_verdict_requires_bidirectional_pass_and_no_insensitivity(self) -> None:
        passing = self._signed_report(candidate_ref=self.candidate.artifact_ref, outcome=self._passing_outcome())
        insensitive = self._signed_report(
            candidate_ref=self.candidate.artifact_ref,
            outcome=run_perturbation_pair(
                perturbation_id="pair-1",
                must_react_expected=1.0,
                must_react_observed=1.0,
                must_not_react_observed=0.0,
                unperturbed_headline=1.0,
                perturbed_headline=0.99,
            ),
        )

        pass_verdict = challenge_verdict_from_report(
            report=passing,
            verification=self.report_verifier.verify(passing),
            proponent_id="builder",
        )
        fail_verdict = challenge_verdict_from_report(
            report=insensitive,
            verification=self.report_verifier.verify(insensitive),
            proponent_id="builder",
        )

        self.assertEqual(pass_verdict.overall, "PASS")
        self.assertEqual(fail_verdict.overall, "FAIL")
        self.assertTrue(fail_verdict.insensitivity_detected)
        self.assertEqual(fail_verdict.reason, "INSENSITIVITY")

    def test_select_challenger_panel_requires_independence_and_diversity(self) -> None:
        panel = select_challenger_panel(
            challengers=(
                self._challenger("challenger-a", tags=("impl-a",), attacks=("signal_injection",)),
                self._challenger("challenger-b", tags=("impl-b",), attacks=("null_noise",)),
                self._challenger("challenger-c", tags=("impl-c",), attacks=("label_shuffle",)),
            ),
            subtopic="ewpt",
            k=2,
            diversity_policy=DiversityPolicy(min_attack_types=2, min_code_lineages=2),
        )

        self.assertGreaterEqual(len(panel.challenger_ids), 2)
        self.assertGreaterEqual(len(panel.attack_types), 2)
        self.assertGreaterEqual(len(panel.code_lineages), 2)
        self.assertTrue(panel.attestation.lineage_disjoint)
        self.assertFalse(panel.attestation.correlation_warning)

    def test_select_challenger_panel_rejects_correlated_lineages(self) -> None:
        with self.assertRaises(ChallengerPanelError):
            select_challenger_panel(
                challengers=(
                    self._challenger("challenger-a", tags=("impl-shared",), attacks=("signal_injection",)),
                    self._challenger("challenger-b", tags=("impl-shared",), attacks=("null_noise",)),
                ),
                subtopic="ewpt",
                k=2,
                diversity_policy=DiversityPolicy(min_attack_types=2, min_code_lineages=2),
            )

    def test_collusion_screen_forces_debate_round_fail(self) -> None:
        bad_panel = ChallengerPanel(
            challenger_ids=("challenger-a", "challenger-b"),
            descriptors=(
                self._challenger("challenger-a", tags=("impl-shared",), attacks=("signal_injection",)),
                self._challenger("challenger-b", tags=("impl-shared",), attacks=("null_noise",)),
            ),
            attack_types=("null_noise", "signal_injection"),
            code_lineages=("impl-shared",),
            attestation=IndependenceAttestation(
                candidate_ids=("challenger-a", "challenger-b"),
                selected_entity_ids=("challenger-a",),
                min_independent=2,
                lineage_disjoint=False,
                correlation_warning=True,
                excluded_tags=(),
            ),
        )
        report = self._signed_report(candidate_ref=self.candidate.artifact_ref, outcome=self._passing_outcome())
        report_ref = self._store_report(report, self.candidate.artifact_ref)

        round_result = run_debate_round(
            round_id="round-1",
            candidate_ref=self.candidate.artifact_ref,
            proponent_id="builder",
            challenger_panel=bad_panel,
            referee_report=report,
            report_verification=self.report_verifier.verify(report),
            report_ref=report_ref,
        )

        self.assertFalse(round_result.survived)
        self.assertEqual(round_result.verdict.reason, "CHALLENGER_COLLUSION")
        self.assertEqual(round_result.reward_hack_events[0].kind, "challenger_collusion")

    def test_evolve_refuses_without_oracle_and_runs_no_rounds(self) -> None:
        preflight = precondition_gate(
            verifier_available=True,
            oracle_available=False,
            signer_trusted=True,
            estimated_cost_usd="0.25",
            single_call_budget_usd="1.00",
            independence_attestation=self._good_attestation(),
            require_independence=True,
        )
        result = evolve_under_debate(
            seed_candidate_ref=self.candidate.artifact_ref,
            proponent_id="builder",
            bounds=EvolverBounds(max_generations=2, max_debate_rounds=2, max_spend_usd="2"),
            preflight=preflight,
            challenger_panel=self._panel(),
            round_evidence=(),
        )

        self.assertEqual(result.status, "REFUSED")
        self.assertEqual(result.reason, "ORACLE_UNAVAILABLE")
        self.assertEqual(result.rounds_run, 0)
        self.assertEqual(result.cost_actual_usd, 0)

    def test_evolve_loops_on_fail_then_admits_passing_revision(self) -> None:
        first_report = self._signed_report(
            candidate_ref=self.candidate.artifact_ref,
            outcome=run_perturbation_pair(
                perturbation_id="pair-1",
                must_react_expected=1.0,
                must_react_observed=0.0,
                must_not_react_observed=0.0,
                unperturbed_headline=0.0,
                perturbed_headline=0.0,
            ),
        )
        revised_candidate_ref = f"{self.candidate.artifact_ref}:revision-1"
        second_report = self._signed_report(candidate_ref=revised_candidate_ref, outcome=self._passing_outcome())
        first_ref = self._store_report(first_report, self.candidate.artifact_ref)
        second_ref = self._store_report(second_report, revised_candidate_ref)

        result = evolve_under_debate(
            seed_candidate_ref=self.candidate.artifact_ref,
            proponent_id="builder",
            bounds=EvolverBounds(max_generations=3, max_debate_rounds=3, max_spend_usd="3", per_round_cost_usd="0.50"),
            preflight=self._accepted_preflight(),
            challenger_panel=self._panel(),
            round_evidence=(
                RefereeRoundEvidence(report_ref=first_ref, report=first_report, verification=self.report_verifier.verify(first_report)),
                RefereeRoundEvidence(
                    report_ref=second_ref,
                    report=second_report,
                    verification=self.report_verifier.verify(second_report),
                    candidate_ref=revised_candidate_ref,
                ),
            ),
            artifact_store=self.store,
        )

        self.assertEqual(result.status, "COMPLETED")
        self.assertEqual(result.rounds_run, 2)
        self.assertFalse(result.challenge_rounds[0].survived)
        self.assertTrue(result.challenge_rounds[0].feedback)
        self.assertEqual(result.best_candidate_ref, revised_candidate_ref)
        self.assertEqual(result.best_validation_report_ref, second_ref)
        self.assertIsNotNone(result.debate_ref)

    def test_debate_ledger_records_every_round_in_c4(self) -> None:
        report = self._signed_report(candidate_ref=self.candidate.artifact_ref, outcome=self._passing_outcome())
        report_ref = self._store_report(report, self.candidate.artifact_ref)
        round_result = run_debate_round(
            round_id="round-1",
            candidate_ref=self.candidate.artifact_ref,
            proponent_id="builder",
            challenger_panel=self._panel(),
            referee_report=report,
            report_verification=self.report_verifier.verify(report),
            report_ref=report_ref,
        )

        ledger = write_debate_ledger(
            artifact_store=self.store,
            subject_artifact_ref=self.candidate.artifact_ref,
            rounds=(round_result,),
        )
        payload = json.loads(self.store.get_artifact(ledger.artifact_ref).decode("utf-8"))
        lineage = self.store.get_lineage(ledger.artifact_ref, direction="ancestors")

        self.assertEqual(ledger.round_ids, ("round-1",))
        self.assertEqual(payload["rounds"][0]["round_id"], "round-1")
        self.assertIn(report_ref, {node.artifact_ref for node in lineage.nodes})

    def test_fixed_panel_overfit_quarantines_on_reused_failing_panel(self) -> None:
        evidences = []
        for index in range(2):
            report = self._signed_report(
                candidate_ref=f"{self.candidate.artifact_ref}:candidate-{index}",
                outcome=run_perturbation_pair(
                    perturbation_id=f"pair-{index}",
                    must_react_expected=1.0,
                    must_react_observed=0.0,
                    must_not_react_observed=0.0,
                    unperturbed_headline=0.0,
                    perturbed_headline=0.0,
                ),
            )
            report_ref = self._store_report(report, f"{self.candidate.artifact_ref}:candidate-{index}")
            evidences.append(
                RefereeRoundEvidence(
                    report_ref=report_ref,
                    report=report,
                    verification=self.report_verifier.verify(report),
                    candidate_ref=f"{self.candidate.artifact_ref}:candidate-{index}",
                )
            )

        result = evolve_under_debate(
            seed_candidate_ref=self.candidate.artifact_ref,
            proponent_id="builder",
            bounds=EvolverBounds(
                max_generations=3,
                max_debate_rounds=3,
                max_spend_usd="3",
                max_consecutive_panel_reuse=1,
            ),
            preflight=self._accepted_preflight(),
            challenger_panel=self._panel(),
            round_evidence=tuple(evidences),
        )

        self.assertIsInstance(result, EvolutionResult)
        self.assertEqual(result.status, "QUARANTINED")
        self.assertEqual(result.reason, "CHALLENGER_OVERFIT")
        self.assertEqual(result.reward_hack_events[0].kind, "challenger_overfit")

    def _accepted_preflight(self):
        return precondition_gate(
            verifier_available=True,
            oracle_available=True,
            signer_trusted=True,
            estimated_cost_usd="0.25",
            single_call_budget_usd="1.00",
            independence_attestation=self._good_attestation(),
            require_independence=True,
        )

    def _panel(self):
        return select_challenger_panel(
            challengers=(
                self._challenger("challenger-a", tags=("impl-a",), attacks=("signal_injection",)),
                self._challenger("challenger-b", tags=("impl-b",), attacks=("null_noise",)),
            ),
            subtopic="ewpt",
            k=2,
            diversity_policy=DiversityPolicy(min_attack_types=2, min_code_lineages=2),
        )

    def _good_attestation(self) -> IndependenceAttestation:
        return IndependenceAttestation(
            candidate_ids=("challenger-a", "challenger-b"),
            selected_entity_ids=("challenger-a", "challenger-b"),
            min_independent=2,
            lineage_disjoint=True,
            correlation_warning=False,
            excluded_tags=(),
        )

    def _signed_report(
        self,
        *,
        candidate_ref: str,
        outcome: PerturbationPairOutcome,
        checks: tuple[CheckResult, ...] | None = None,
        score: float | None = None,
    ) -> dict:
        report = self.referee.build_report(
            profile_ref="c4://profile/ewpt/v1",
            frozen_pipeline_ref=candidate_ref,
            proponent_id="builder",
            checks=checks or self._recap_checks(),
            perturbation_outcome=outcome,
            challenger_ids=("challenger-a", "challenger-b"),
            independence_attestation=self._good_attestation(),
        )
        if score is not None:
            report["aggregate"]["score"] = score
            report = self.signer.sign(report)
        return report

    def _store_report(self, report: dict, candidate_ref: str) -> str:
        record = self.store.create_artifact(
            kind="report",
            payload=report,
            producer=Producer(subsystem="S3", version="0.0.0"),
            lineage=Lineage(input_refs=(candidate_ref,), code_ref="git:s3-referee", environment_digest="oci:s3-referee"),
        )
        return record.artifact_ref

    @staticmethod
    def _passing_outcome() -> PerturbationPairOutcome:
        return run_perturbation_pair(
            perturbation_id="pair-1",
            must_react_expected=1.0,
            must_react_observed=1.0,
            must_not_react_observed=0.0,
            unperturbed_headline=1.0,
            perturbed_headline=0.2,
        )

    @staticmethod
    def _recap_checks() -> tuple[CheckResult, ...]:
        return (
            CheckResult("INJECTION", "PASS"),
            CheckResult("NULL_CONTROL", "PASS"),
            CheckResult("PHYSICAL_CONSISTENCY", "PASS"),
            CheckResult("CALIBRATION", "PASS"),
            CheckResult("RECAP_BENCHMARK", "PASS", metrics={"test_cases": ["S3-T24", "S3-TC32"]}),
        )

    def _novel_checks(self) -> tuple[CheckResult, ...]:
        return self._recap_checks() + (
            CheckResult("CROSS_CODE", "PASS"),
            CheckResult("LEAKAGE", "PASS"),
        )

    @staticmethod
    def _challenger(entity_id: str, *, tags: tuple[str, ...], attacks: tuple[str, ...]) -> CapabilityDescriptor:
        return CapabilityDescriptor(
            entity_id=entity_id,
            revision=1,
            kind="subagent",
            owner_subsystem="S1",
            contract_versions={"C1": "1.0.0", "C5": "1.0.0"},
            trust_class="internal",
            capability_scopes=("challenge",) + tuple(f"attack:{attack}" for attack in attacks),
            provenance_ref=f"c4://descriptor/{entity_id}",
            subtopics=("ewpt",),
            independence_tags=tags,
            conformance_level="gold",
        )


if __name__ == "__main__":
    unittest.main()
