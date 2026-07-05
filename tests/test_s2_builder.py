from __future__ import annotations

import unittest

from argus_core import (
    AdapterBroker,
    AdapterDescriptor,
    BaselineBuilder,
    BuildPlan,
    EvalRequest,
    HPOTrial,
    InMemoryArtifactStore,
    IncompleteLineageError,
    Lineage,
    MutationSpec,
    NormalizedQuantity,
    Producer,
    ProvenanceEmitter,
    Quantity,
    RewardSourceError,
    SelfGradeError,
    SimpleAdapter,
    list_model_families,
    select_hpo_winner,
)


class S2BaselineBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.broker = AdapterBroker(artifact_store=self.store)
        self.broker.register(self._adapter())
        self.builder = BaselineBuilder(artifact_store=self.store, adapter_broker=self.broker)

    def test_build_emits_model_and_frozen_pipeline_with_lineage(self) -> None:
        dataset = self.store.create_artifact(
            kind="dataset",
            payload={"rows": [1, 2, 3]},
            producer=self._producer("S6"),
            lineage=self._lineage(),
        )

        result = self.builder.build(
            BuildPlan(
                job_id="job-1",
                input_refs=(dataset.artifact_ref,),
                adapter_request=EvalRequest(
                    adapter_id="gw_spectrum_surrogate",
                    inputs={
                        "T_n": Quantity(value=100, units="GeV"),
                        "alpha": Quantity(value=0.2, units="dimensionless"),
                        "v_w": Quantity(value=0.7, units="dimensionless"),
                    },
                    seed=7,
                ),
            )
        )

        model = self.store.get_record(result.model_ref)
        pipeline = self.store.get_record(result.frozen_pipeline_ref)
        model_lineage = self.store.get_lineage(model.artifact_ref, direction="ancestors")
        pipeline_lineage = self.store.get_lineage(pipeline.artifact_ref, direction="ancestors")

        self.assertEqual(result.claim_tier, "ran-toy")
        self.assertEqual(model.kind, "model")
        self.assertEqual(pipeline.kind, "container")
        self.assertIn(dataset.artifact_ref, {node.artifact_ref for node in model_lineage.nodes})
        self.assertIn(model.artifact_ref, {node.artifact_ref for node in pipeline_lineage.nodes})
        self.assertEqual(len(result.adapter_provenance_refs), 1)

    def test_provenance_emitter_rejects_incomplete_lineage_without_record(self) -> None:
        emitter = ProvenanceEmitter(artifact_store=self.store)

        with self.assertRaises(IncompleteLineageError) as raised:
            emitter.emit_artifact(
                kind="model",
                payload={"weights": [1]},
                lineage=Lineage(input_refs=(), code_ref="git:model", environment_digest=""),
            )

        self.assertEqual(raised.exception.category, "INCOMPLETE_LINEAGE")
        self.assertEqual(raised.exception.missing_fields, ("lineage.environment_digest",))
        self.assertEqual(len(self.store), 0)

    def test_provenance_emitter_rejects_promoted_tier_from_s2_writer_without_record(self) -> None:
        emitter = ProvenanceEmitter(artifact_store=self.store)

        with self.assertRaises(SelfGradeError) as raised:
            emitter.emit_artifact(
                kind="model",
                payload={"weights": [1], "uncertainty_tag": {"kind": "interval", "radius": 0.1}},
                lineage=Lineage(input_refs=(), code_ref="git:model", environment_digest="oci:model"),
                claim_tier="recapitulated-known",
            )

        self.assertIn("S2 cannot emit promoted claim_tier", str(raised.exception))
        self.assertEqual(len(self.store), 0)

    def test_builder_writes_model_and_pipeline_through_provenance_emitter(self) -> None:
        emitter = RecordingProvenanceEmitter(artifact_store=self.store)
        builder = BaselineBuilder(
            artifact_store=self.store,
            adapter_broker=self.broker,
            provenance_emitter=emitter,
        )

        result = builder.build(self._plan(job_id="job-through-emitter"))

        self.assertEqual(result.artifact_refs, tuple(call["record"].artifact_ref for call in emitter.calls))
        self.assertEqual([call["kind"] for call in emitter.calls], ["model", "container"])
        self.assertTrue(all(call["claim_tier"] == "ran-toy" for call in emitter.calls))
        self.assertTrue(all(call["producer"].subsystem == "S2" for call in emitter.calls))
        self.assertTrue(all(call["producer"].job_id == "job-through-emitter" for call in emitter.calls))
        self.assertTrue(all(call["record"].lineage.code_ref for call in emitter.calls))
        self.assertTrue(all(call["record"].lineage.environment_digest for call in emitter.calls))

    def test_self_grade_above_ran_toy_is_rejected(self) -> None:
        with self.assertRaises(SelfGradeError):
            self.builder.build(
                BuildPlan(
                    job_id="job-1",
                    input_refs=(),
                    adapter_request=EvalRequest(
                        adapter_id="gw_spectrum_surrogate",
                        inputs={
                            "T_n": Quantity(value=100, units="GeV"),
                            "alpha": Quantity(value=0.2, units="dimensionless"),
                            "v_w": Quantity(value=0.7, units="dimensionless"),
                        },
                    ),
                ),
                attempted_claim_tier="recapitulated-known",
            )

    def test_model_family_registry_includes_deep_physics_informed_family(self) -> None:
        families = {family.family_id: family for family in list_model_families()}

        self.assertTrue(families["physics-informed-mlp"].differentiable)
        self.assertTrue(families["physics-informed-mlp"].physics_informed)
        self.assertEqual(families["tabular-baseline"].family_kind, "classical")

    def test_hpo_selection_respects_calibration_and_cost_tiebreak(self) -> None:
        selected = select_hpo_winner(
            (
                HPOTrial("overfit", score=0.99, calibration_error=0.3, cost=1.0, parameters={"lr": 1.0}),
                HPOTrial("expensive", score=0.9, calibration_error=0.01, cost=10.0, parameters={"lr": 0.1}),
                HPOTrial("cheap", score=0.9, calibration_error=0.01, cost=2.0, parameters={"lr": 0.05}),
            ),
            max_calibration_error=0.05,
        )

        self.assertEqual(selected.trial_id, "cheap")
        self.assertEqual(selected.parameters, {"lr": 0.05})

    def test_build_variant_links_base_pipeline_and_exposes_no_score(self) -> None:
        base = self.builder.build(self._plan(job_id="base"))

        variant = self.builder.build_variant(
            base_pipeline_ref=base.frozen_pipeline_ref,
            plan=self._plan(job_id="variant"),
            mutation=MutationSpec(
                variant_id="variant-1",
                model_family="physics-informed-mlp",
                parameters={"layers": 3},
            ),
        )
        model_lineage = self.store.get_lineage(variant.model_ref, direction="ancestors")

        self.assertEqual(variant.base_pipeline_ref, base.frozen_pipeline_ref)
        self.assertEqual(variant.diagnostics["reward_source"], "c3-only")
        self.assertFalse(hasattr(variant, "score"))
        self.assertIn(base.frozen_pipeline_ref, {node.artifact_ref for node in model_lineage.nodes})

    def test_build_variant_rejects_fabricated_score(self) -> None:
        base = self.builder.build(self._plan(job_id="base"))

        with self.assertRaises(RewardSourceError):
            self.builder.build_variant(
                base_pipeline_ref=base.frozen_pipeline_ref,
                plan=self._plan(job_id="variant"),
                mutation=MutationSpec(variant_id="variant-1", model_family="physics-informed-mlp", parameters={}),
                fabricated_score=1.0,
            )

    @staticmethod
    def _adapter() -> SimpleAdapter:
        descriptor = AdapterDescriptor(
            adapter_id="gw_spectrum_surrogate",
            version="1.0.0",
            input_units={"T_n": "GeV", "alpha": "dimensionless", "v_w": "dimensionless"},
            output_units={"omega": "dimensionless"},
            validity_domain={"v_w": (0.4, 0.95)},
            determinism="deterministic",
            provenance_ref="c4://adapter/gw_spectrum_surrogate/v1",
            differentiable=True,
        )
        return SimpleAdapter(descriptor, S2BaselineBuilderTests._evaluate)

    @staticmethod
    def _plan(job_id: str) -> BuildPlan:
        return BuildPlan(
            job_id=job_id,
            input_refs=(),
            adapter_request=EvalRequest(
                adapter_id="gw_spectrum_surrogate",
                inputs={
                    "T_n": Quantity(value=100, units="GeV"),
                    "alpha": Quantity(value=0.2, units="dimensionless"),
                    "v_w": Quantity(value=0.7, units="dimensionless"),
                },
                seed=7,
            ),
        )

    @staticmethod
    def _evaluate(inputs: dict[str, NormalizedQuantity], _seed: int | None) -> dict[str, Quantity]:
        omega = inputs["alpha"].value * inputs["T_n"].value / 1000.0
        return {
            "omega": Quantity(
                value=omega,
                units="dimensionless",
                uncertainty={"kind": "interval", "radius": 0.01},
            )
        }

    @staticmethod
    def _producer(subsystem: str):
        from argus_core import Producer

        return Producer(subsystem=subsystem, version="0.0.0")

    @staticmethod
    def _lineage():
        return Lineage(input_refs=(), code_ref="git:test", environment_digest="oci:test")


class RecordingProvenanceEmitter(ProvenanceEmitter):
    def __init__(self, *, artifact_store: InMemoryArtifactStore) -> None:
        super().__init__(artifact_store=artifact_store)
        self.calls: list[dict[str, object]] = []

    def emit_artifact(
        self,
        *,
        kind: str,
        payload: object,
        lineage: Lineage,
        claim_tier: str = "ran-toy",
        validation_report_ref: str | None = None,
        artifact_ref: str | None = None,
        producer: Producer | None = None,
    ):
        record = super().emit_artifact(
            kind=kind,
            payload=payload,
            lineage=lineage,
            claim_tier=claim_tier,
            validation_report_ref=validation_report_ref,
            artifact_ref=artifact_ref,
            producer=producer,
        )
        self.calls.append(
            {
                "kind": kind,
                "claim_tier": claim_tier,
                "producer": producer or self.producer,
                "record": record,
            }
        )
        return record


if __name__ == "__main__":
    unittest.main()
