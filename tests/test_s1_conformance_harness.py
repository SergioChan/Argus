from __future__ import annotations

import json
import unittest

from argus_core import (
    CapabilityDescriptor,
    ExecContext,
    InMemoryArtifactStore,
    JobEnvelope,
    Lineage,
    Producer,
    S1ReferenceConformanceHarness,
    Subagent,
    SubagentDescriptor,
    tag_uncertainty,
)


class ReferenceConformanceSubagent(Subagent):
    def __init__(
        self,
        descriptor: SubagentDescriptor,
        *,
        uncertainty: dict[str, object] | None = None,
    ) -> None:
        super().__init__(descriptor)
        self._uncertainty = uncertainty

    def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
        return {
            "steps": [{"step_id": "fit", "kind": "train", "description": "Fit reference model"}],
            "adapters_required": list(envelope.required_adapters),
            "datasets_required": [],
            "risk_notes": [],
        }

    def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
        artifact = ctx.emit_artifact(
            {"weights": [1.0], "plan_hash": plan["plan_hash"]},
            kind="model",
            lineage=Lineage(
                input_refs=(),
                code_ref="git:project-argus@s1-reference-conformance",
                environment_digest="oci:s1-reference-conformance@sha256-reference",
                seeds=("s1-conformance-seed",),
            ),
        )
        payload: dict[str, object] = {
            "artifact_refs": [str(artifact["artifact_ref"])],
            "diagnostics": {"model_ref": str(artifact["artifact_ref"])},
            "self_checks": [{"type": "smoke", "status": "PASS", "advisory": True}],
        }
        if self._uncertainty is not None:
            payload["uncertainty_summary"] = self._uncertainty
        return payload


class S1ReferenceConformanceHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.descriptor = SubagentDescriptor(
            subagent_id="reference-subagent",
            contract_version="1.0.0",
            subtopics=("ewpt",),
            required_adapters=("adapter:bounce",),
        )
        self.envelope = JobEnvelope(
            job_id="88888888-8888-4888-8888-888888888888",
            envelope_version="1.0.0",
            subtopic="ewpt",
            required_adapters=("adapter:bounce",),
            allowed_adapters=("adapter:bounce",),
            verifier_profile_ref="c4://profile/ewpt/reference",
            estimated_cost=0.25,
            budget_cost=1.0,
        )
        self.harness = S1ReferenceConformanceHarness(
            suite_version="s1-reference-conformance.v1",
            standard_release_ref="c4://standard/c1/1.0.0",
        )

    def test_bronze_reference_subagent_writes_deterministic_evidence_and_descriptor_block(self) -> None:
        store = InMemoryArtifactStore()

        result = self.harness.run(
            ReferenceConformanceSubagent(self.descriptor),
            envelope=self.envelope,
            level="bronze",
            artifact_store=store,
        )

        self.assertTrue(result.aggregate_passed)
        self.assertEqual(result.level_awarded, "bronze")
        self.assertTrue(str(result.evidence_ref).startswith("c4://artifact/"))
        self.assertTrue(str(result.determinism_hash).startswith("blake3:"))
        self.assertEqual({check.status for check in result.checks}, {"PASS"})
        self.assertTrue(all(check.oracle_spec for check in result.checks))
        self.assertIn("S1-TC-36:bronze_lifecycle_statemachine", [check.check_id for check in result.checks])
        self.assertIn("S1-TC-36:bronze_c4_provenance_complete", [check.check_id for check in result.checks])
        self.assertIn("S1-TC-36:bronze_no_self_tier_promotion", [check.check_id for check in result.checks])

        evidence = json.loads(store.get_artifact(result.evidence_ref).decode("utf-8"))
        self.assertEqual(evidence["schema"], "argus.s1.reference_conformance_evidence.v1")
        self.assertEqual(evidence["suite_version"], "s1-reference-conformance.v1")
        self.assertEqual(evidence["level_requested"], "bronze")
        self.assertEqual(evidence["determinism_hash"], result.determinism_hash)
        self.assertEqual(
            result.descriptor_conformance_block(),
            {
                "level": "bronze",
                "suite_version": "s1-reference-conformance.v1",
                "standard_release_ref": "c4://standard/c1/1.0.0",
                "evidence_ref": result.evidence_ref,
                "determinism_hash": result.determinism_hash,
            },
        )

    def test_silver_fails_uncertainty_present_for_bare_point_estimate_without_losing_bronze(self) -> None:
        result = self.harness.run(
            ReferenceConformanceSubagent(self.descriptor),
            envelope=self.envelope,
            level="silver",
            artifact_store=InMemoryArtifactStore(),
        )
        by_id = {check.check_id: check for check in result.checks}

        self.assertFalse(result.aggregate_passed)
        self.assertEqual(result.level_awarded, "bronze")
        self.assertEqual(by_id["S1-TC-12:uncertainty_present"].status, "FAIL")
        self.assertEqual(by_id["S1-TC-36:bronze_lifecycle_statemachine"].status, "PASS")
        self.assertEqual(by_id["S1-TC-36:bronze_c4_provenance_complete"].status, "PASS")
        self.assertIn("uncertainty_summary.representation != 'none'", by_id["S1-TC-12:uncertainty_present"].oracle_spec)

    def test_gold_without_c5_independence_tags_fails_cross_code_but_bronze_and_silver_pass(self) -> None:
        result = self.harness.run(
            ReferenceConformanceSubagent(
                self.descriptor,
                uncertainty=tag_uncertainty("interval", {"radius": 0.01, "source": "reference"}),
            ),
            envelope=self.envelope,
            level="gold",
            artifact_store=InMemoryArtifactStore(),
            capability_descriptor=self._c5_descriptor(independence_tags=()),
        )
        by_id = {check.check_id: check for check in result.checks}

        self.assertFalse(result.aggregate_passed)
        self.assertEqual(result.level_awarded, "silver")
        self.assertEqual(by_id["S1-TC-12:uncertainty_present"].status, "PASS")
        self.assertEqual(by_id["S1-TC-37:cross_code_ready"].status, "FAIL")
        self.assertIn("independence_tags", by_id["S1-TC-37:cross_code_ready"].reason or "")

    def test_identical_runs_have_the_same_deterministic_evidence_payload(self) -> None:
        first_store = InMemoryArtifactStore()
        second_store = InMemoryArtifactStore()
        subagent = ReferenceConformanceSubagent(
            self.descriptor,
            uncertainty=tag_uncertainty("interval", {"radius": 0.01, "source": "reference"}),
        )

        first = self.harness.run(
            subagent,
            envelope=self.envelope,
            level="gold",
            artifact_store=first_store,
            capability_descriptor=self._c5_descriptor(independence_tags=("independent-bounce",)),
        )
        second = self.harness.run(
            ReferenceConformanceSubagent(
                self.descriptor,
                uncertainty=tag_uncertainty("interval", {"radius": 0.01, "source": "reference"}),
            ),
            envelope=self.envelope,
            level="gold",
            artifact_store=second_store,
            capability_descriptor=self._c5_descriptor(independence_tags=("independent-bounce",)),
        )

        self.assertTrue(first.aggregate_passed)
        self.assertEqual(first.level_awarded, "gold")
        self.assertEqual(first.determinism_hash, second.determinism_hash)
        self.assertEqual(
            first_store.get_artifact(first.evidence_ref),
            second_store.get_artifact(second.evidence_ref),
        )

    def _c5_descriptor(self, *, independence_tags: tuple[str, ...]) -> CapabilityDescriptor:
        return CapabilityDescriptor(
            entity_id=self.descriptor.subagent_id,
            revision=1,
            kind="subagent",
            owner_subsystem="S1",
            contract_versions={"C1": "1.0.0", "C5": "1.0.0"},
            trust_class="internal",
            capability_scopes=("c1.accept", "c1.plan", "c1.build"),
            provenance_ref="c4://descriptor/reference-subagent",
            subtopics=self.descriptor.subtopics,
            independence_tags=independence_tags,
        )


if __name__ == "__main__":
    unittest.main()
