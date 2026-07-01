from __future__ import annotations

import unittest

from argus_core import (
    AdapterBroker,
    AdapterDescriptor,
    BaselineBuilder,
    BuildPlan,
    EvalRequest,
    InMemoryArtifactStore,
    NormalizedQuantity,
    Quantity,
    SelfGradeError,
    SimpleAdapter,
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
        from argus_core import Lineage

        return Lineage(input_refs=(), code_ref="git:test", environment_digest="oci:test")


if __name__ == "__main__":
    unittest.main()
