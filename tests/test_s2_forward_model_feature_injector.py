from __future__ import annotations

import unittest

from argus_core import (
    AdapterBroker,
    AdapterDescriptor,
    EvalRequest,
    FeatureNode,
    FeatureTerm,
    ForwardModelFeatureInjector,
    ForwardModelFeatureRequest,
    InMemoryArtifactStore,
    NormalizedQuantity,
    Quantity,
    SimpleAdapter,
    UNCERTAINTY_ENGINE_HASH,
    UNCERTAINTY_ENGINE_VERSION,
    UNIT_REGISTRY_HASH,
    UNIT_REGISTRY_VERSION,
)


class S2ForwardModelFeatureInjectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.broker = AdapterBroker(artifact_store=self.store)
        self.broker.register(self._adapter())

    def test_forward_model_feature_propagates_c6_uncertainty_and_provenance(self) -> None:
        result = ForwardModelFeatureInjector(adapter_broker=self.broker).inject(
            ForwardModelFeatureRequest(
                feature_node_id="omega_forward",
                adapter_request=EvalRequest(
                    adapter_id="gw_spectrum_surrogate",
                    inputs={
                        "T_n": Quantity(value=100.0, units="GeV"),
                        "alpha": Quantity(value=0.2, units="dimensionless"),
                        "v_w": Quantity(value=0.7, units="dimensionless"),
                    },
                    seed=13,
                ),
                output_field="omega",
                declared_units="dimensionless",
            )
        )

        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.value, 0.02)
        self.assertEqual(result.uncertainty["kind"], "interval")
        self.assertEqual(result.uncertainty["source"], "adapter:omega")
        self.assertAlmostEqual(result.uncertainty["radius"], 0.01)
        self.assertEqual(result.uncertainty["uncertainty_engine_version"], UNCERTAINTY_ENGINE_VERSION)
        self.assertEqual(result.uncertainty["uncertainty_engine_hash"], UNCERTAINTY_ENGINE_HASH)
        self.assertEqual(result.feature_node.node_id, "omega_forward")
        self.assertTrue(result.feature_node.uncertainty_propagated)
        self.assertEqual(result.feature_node.uncertainty["kind"], "interval")
        self.assertAlmostEqual(result.feature_node.uncertainty["radius"], 0.01)
        self.assertFalse(result.feature_node.extrapolation_flag)
        self.assertFalse(result.diagnostics["extrapolation_flag"])
        self.assertEqual(result.diagnostics["adapter_id"], "gw_spectrum_surrogate")
        self.assertEqual(result.diagnostics["adapter_provenance_ref"], result.adapter_provenance_ref)
        self.assertEqual(result.diagnostics["unit_registry_version"], UNIT_REGISTRY_VERSION)
        self.assertEqual(result.diagnostics["unit_registry_hash"], UNIT_REGISTRY_HASH)
        self.assertEqual(result.diagnostics["uncertainty_engine_version"], UNCERTAINTY_ENGINE_VERSION)
        self.assertEqual(result.diagnostics["uncertainty_engine_hash"], UNCERTAINTY_ENGINE_HASH)
        self.assertEqual(self.store.get_record(result.adapter_provenance_ref).kind, "log")

    def test_out_of_domain_adapter_result_is_flagged_not_silent(self) -> None:
        result = ForwardModelFeatureInjector(adapter_broker=self.broker).inject(
            ForwardModelFeatureRequest(
                feature_node_id="omega_forward",
                adapter_request=EvalRequest(
                    adapter_id="gw_spectrum_surrogate",
                    inputs={
                        "T_n": Quantity(value=100.0, units="GeV"),
                        "alpha": Quantity(value=0.2, units="dimensionless"),
                        "v_w": Quantity(value=1.2, units="dimensionless"),
                    },
                    seed=13,
                ),
                output_field="omega",
                declared_units="dimensionless",
            )
        )

        self.assertEqual(result.status, "EXTRAPOLATED")
        self.assertTrue(result.extrapolation_flag)
        self.assertTrue(result.feature_node.extrapolation_flag)
        self.assertEqual(result.violated_fields, ("v_w",))
        self.assertEqual(result.diagnostics["violated_fields"], ("v_w",))
        self.assertEqual(result.diagnostics["out_of_domain_policy"], "flag")
        self.assertTrue(result.feature_node.diagnostics["extrapolation_flag"])

    def test_out_of_domain_adapter_result_can_be_dropped_with_diagnostics(self) -> None:
        result = ForwardModelFeatureInjector(adapter_broker=self.broker).inject(
            ForwardModelFeatureRequest(
                feature_node_id="omega_forward",
                adapter_request=EvalRequest(
                    adapter_id="gw_spectrum_surrogate",
                    inputs={
                        "T_n": Quantity(value=100.0, units="GeV"),
                        "alpha": Quantity(value=0.2, units="dimensionless"),
                        "v_w": Quantity(value=1.2, units="dimensionless"),
                    },
                    seed=13,
                ),
                output_field="omega",
                declared_units="dimensionless",
                out_of_domain_policy="drop",
            )
        )

        self.assertEqual(result.status, "DROPPED")
        self.assertIsNone(result.feature_node)
        self.assertIsNone(result.value)
        self.assertIsNone(result.uncertainty)
        self.assertTrue(result.extrapolation_flag)
        self.assertEqual(result.violated_fields, ("v_w",))
        self.assertTrue(result.diagnostics["extrapolation_flag"])
        self.assertEqual(result.diagnostics["out_of_domain_policy"], "drop")

    def test_feature_node_remains_hashable_with_default_metadata(self) -> None:
        node = FeatureNode(
            node_id="velocity",
            terms=(FeatureTerm(field_name="v_w", units="dimensionless"),),
            declared_units="dimensionless",
        )

        self.assertIsInstance(hash(node), int)

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
        )
        return SimpleAdapter(descriptor, S2ForwardModelFeatureInjectorTests._evaluate)

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


if __name__ == "__main__":
    unittest.main()
