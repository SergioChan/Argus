from __future__ import annotations

import unittest

from argus_core import (
    ComplexityEscalationPolicy,
    ModelCandidateResult,
    ModelFamilyRegistry,
    ModelSynthesizer,
    S2ContractModelError,
)


class S2ModelSynthesizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = ModelFamilyRegistry.default()

    def test_significant_held_out_gain_escalates_to_higher_complexity_family(self) -> None:
        synthesizer = ModelSynthesizer(
            registry=self.registry,
            policy=ComplexityEscalationPolicy(min_absolute_gain=0.03, max_cost=5.0),
        )

        decision = synthesizer.select_family(
            incumbent_family_id="tabular-baseline",
            candidates=(
                ModelCandidateResult("tabular-baseline", heldout_score=0.80, cost=1.0),
                ModelCandidateResult("physics-informed-mlp", heldout_score=0.85, cost=4.0),
            ),
        )

        self.assertTrue(decision.escalated)
        self.assertEqual(decision.selected_family_id, "physics-informed-mlp")
        self.assertEqual(decision.reason, "significant_held_out_gain")
        self.assertAlmostEqual(decision.heldout_gain, 0.05)

    def test_insufficient_gain_keeps_lower_complexity_family_with_reason(self) -> None:
        synthesizer = ModelSynthesizer(
            registry=self.registry,
            policy=ComplexityEscalationPolicy(min_absolute_gain=0.05, max_cost=5.0),
        )

        decision = synthesizer.select_family(
            incumbent_family_id="tabular-baseline",
            candidates=(
                ModelCandidateResult("tabular-baseline", heldout_score=0.80, cost=1.0),
                ModelCandidateResult("physics-informed-mlp", heldout_score=0.83, cost=4.0),
            ),
        )

        self.assertFalse(decision.escalated)
        self.assertEqual(decision.selected_family_id, "tabular-baseline")
        self.assertEqual(decision.reason, "insufficient_held_out_gain")
        self.assertEqual(decision.rejected_candidates[0].code, "INSUFFICIENT_HELD_OUT_GAIN")

    def test_significance_margin_uses_incumbent_standard_error(self) -> None:
        synthesizer = ModelSynthesizer(
            registry=self.registry,
            policy=ComplexityEscalationPolicy(standard_error_margin=2.0, max_cost=5.0),
        )

        decision = synthesizer.select_family(
            incumbent_family_id="tabular-baseline",
            candidates=(
                ModelCandidateResult(
                    "tabular-baseline",
                    heldout_score=0.80,
                    cost=1.0,
                    heldout_standard_error=0.03,
                ),
                ModelCandidateResult("physics-informed-mlp", heldout_score=0.85, cost=4.0),
            ),
        )

        self.assertFalse(decision.escalated)
        self.assertEqual(decision.selected_family_id, "tabular-baseline")
        self.assertEqual(decision.rejected_candidates[0].code, "INSUFFICIENT_HELD_OUT_GAIN")

    def test_budget_or_missing_held_out_evidence_blocks_escalation(self) -> None:
        synthesizer = ModelSynthesizer(
            registry=self.registry,
            policy=ComplexityEscalationPolicy(min_absolute_gain=0.01, max_cost=2.0),
        )

        decision = synthesizer.select_family(
            incumbent_family_id="tabular-baseline",
            candidates=(
                ModelCandidateResult("tabular-baseline", heldout_score=0.80, cost=1.0),
                ModelCandidateResult("differentiable-surrogate", heldout_score=None, cost=1.5),
                ModelCandidateResult("physics-informed-mlp", heldout_score=0.90, cost=4.0),
            ),
        )

        self.assertFalse(decision.escalated)
        self.assertEqual(decision.selected_family_id, "tabular-baseline")
        self.assertEqual(decision.reason, "no_eligible_escalation")
        rejection_by_family = {rejection.family_id: rejection.code for rejection in decision.rejected_candidates}
        self.assertEqual(rejection_by_family["differentiable-surrogate"], "HELD_OUT_EVIDENCE_REQUIRED")
        self.assertEqual(rejection_by_family["physics-informed-mlp"], "COST_OVER_BUDGET")

    def test_unknown_or_missing_incumbent_fails_closed(self) -> None:
        synthesizer = ModelSynthesizer(registry=self.registry)

        with self.assertRaises(S2ContractModelError):
            synthesizer.select_family(
                incumbent_family_id="unknown-family",
                candidates=(ModelCandidateResult("tabular-baseline", heldout_score=0.80, cost=1.0),),
            )

        with self.assertRaises(S2ContractModelError):
            synthesizer.select_family(
                incumbent_family_id="tabular-baseline",
                candidates=(ModelCandidateResult("unknown-family", heldout_score=0.90, cost=1.0),),
            )

    def test_deterministic_choice_prefers_gain_then_cost_then_family_id(self) -> None:
        synthesizer = ModelSynthesizer(
            registry=self.registry,
            policy=ComplexityEscalationPolicy(min_absolute_gain=0.01, max_cost=5.0),
        )

        decision = synthesizer.select_family(
            incumbent_family_id="tabular-baseline",
            candidates=(
                ModelCandidateResult("tabular-baseline", heldout_score=0.80, cost=1.0),
                ModelCandidateResult("physics-informed-mlp", heldout_score=0.85, cost=4.0),
                ModelCandidateResult("differentiable-surrogate", heldout_score=0.85, cost=2.0),
            ),
        )

        self.assertTrue(decision.escalated)
        self.assertEqual(decision.selected_family_id, "differentiable-surrogate")

    def test_minimize_objective_and_duplicate_candidates_fail_closed(self) -> None:
        synthesizer = ModelSynthesizer(
            registry=self.registry,
            policy=ComplexityEscalationPolicy(min_absolute_gain=0.02, max_cost=5.0, objective="minimize"),
        )

        decision = synthesizer.select_family(
            incumbent_family_id="tabular-baseline",
            candidates=(
                ModelCandidateResult("tabular-baseline", heldout_score=0.30, cost=1.0),
                ModelCandidateResult("physics-informed-mlp", heldout_score=0.25, cost=4.0),
            ),
        )
        self.assertTrue(decision.escalated)
        self.assertAlmostEqual(decision.heldout_gain, 0.05)

        with self.assertRaises(S2ContractModelError):
            synthesizer.select_family(
                incumbent_family_id="tabular-baseline",
                candidates=(
                    ModelCandidateResult("tabular-baseline", heldout_score=0.30, cost=1.0),
                    ModelCandidateResult("tabular-baseline", heldout_score=0.31, cost=1.1),
                ),
            )


if __name__ == "__main__":
    unittest.main()
