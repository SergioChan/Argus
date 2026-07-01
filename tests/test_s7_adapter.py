from __future__ import annotations

import unittest

from argus_core import (
    AdapterBroker,
    AdapterConformanceError,
    AdapterDescriptor,
    EvalRequest,
    InMemoryArtifactStore,
    NormalizedQuantity,
    OutOfDomainError,
    ProvenanceUnavailableError,
    Quantity,
    SimpleAdapter,
    UNIT_REGISTRY_VERSION,
    UnitsMismatchError,
    derive_seed,
    normalize_quantity,
)


class S7UnitsAndAdapterTests(unittest.TestCase):
    def test_units_normalized_not_silently_coerced(self) -> None:
        normalized = normalize_quantity(Quantity(value=0.1, units="TeV"), "GeV")

        self.assertEqual(normalized.units, "GeV")
        self.assertEqual(normalized.original_units, "TeV")
        self.assertAlmostEqual(normalized.value, 100.0)
        self.assertEqual(normalized.unit_registry_version, UNIT_REGISTRY_VERSION)

    def test_units_mismatch_is_hard_error(self) -> None:
        with self.assertRaises(UnitsMismatchError) as raised:
            normalize_quantity(Quantity(value=1.0, units="s"), "GeV")

        self.assertEqual(raised.exception.category, "UNITS_MISMATCH")

    def test_evaluate_writes_provenance_and_flags_extrapolation(self) -> None:
        store = InMemoryArtifactStore()
        broker = AdapterBroker(artifact_store=store)
        broker.register(self._adapter(domain_policy="flag"))

        result = broker.evaluate(
            EvalRequest(
                adapter_id="gw_spectrum_surrogate",
                inputs={
                    "T_n": Quantity(value=0.1, units="TeV"),
                    "alpha": Quantity(value=0.2, units="dimensionless"),
                    "v_w": Quantity(value=1.2, units="dimensionless"),
                },
                seed=123,
            )
        )

        self.assertFalse(result.in_validity_domain)
        self.assertTrue(result.extrapolation_flag)
        self.assertEqual(result.violated_fields, ("v_w",))
        self.assertEqual(result.outputs["omega"].uncertainty, {"kind": "interval", "radius": 0.01})
        self.assertEqual(store.get_record(result.provenance_ref).kind, "log")

    def test_refuse_policy_rejects_out_of_domain(self) -> None:
        broker = AdapterBroker(artifact_store=InMemoryArtifactStore())
        broker.register(self._adapter(domain_policy="refuse"))

        with self.assertRaises(OutOfDomainError) as raised:
            broker.evaluate(
                EvalRequest(
                    adapter_id="gw_spectrum_surrogate",
                    inputs={
                        "T_n": Quantity(value=100, units="GeV"),
                        "alpha": Quantity(value=0.2, units="dimensionless"),
                        "v_w": Quantity(value=1.2, units="dimensionless"),
                    },
                )
            )

        self.assertEqual(raised.exception.category, "OUT_OF_DOMAIN")

    def test_missing_uncertainty_is_conformance_error(self) -> None:
        descriptor = self._descriptor(domain_policy="flag")
        broker = AdapterBroker(artifact_store=InMemoryArtifactStore())
        broker.register(
            SimpleAdapter(
                descriptor,
                lambda _inputs, _seed: {"omega": Quantity(value=1.0, units="dimensionless")},
            )
        )

        with self.assertRaises(AdapterConformanceError) as raised:
            broker.evaluate(
                EvalRequest(
                    adapter_id="gw_spectrum_surrogate",
                    inputs={
                        "T_n": Quantity(value=100, units="GeV"),
                        "alpha": Quantity(value=0.2, units="dimensionless"),
                        "v_w": Quantity(value=0.7, units="dimensionless"),
                    },
                )
            )

        self.assertEqual(raised.exception.category, "ADAPTER_ERROR")

    def test_provenance_unavailable_fails_closed(self) -> None:
        broker = AdapterBroker(artifact_store=None)
        broker.register(self._adapter(domain_policy="flag"))

        with self.assertRaises(ProvenanceUnavailableError) as raised:
            broker.evaluate(
                EvalRequest(
                    adapter_id="gw_spectrum_surrogate",
                    inputs={
                        "T_n": Quantity(value=100, units="GeV"),
                        "alpha": Quantity(value=0.2, units="dimensionless"),
                        "v_w": Quantity(value=0.7, units="dimensionless"),
                    },
                )
            )

        self.assertEqual(raised.exception.category, "PROVENANCE_UNAVAILABLE")

    def test_seed_derivation_is_deterministic(self) -> None:
        first = derive_seed(job_seed=7, dag_node_id="node-a", call_index=1, adapter_id="adapter")
        second = derive_seed(job_seed=7, dag_node_id="node-a", call_index=1, adapter_id="adapter")
        other = derive_seed(job_seed=7, dag_node_id="node-a", call_index=2, adapter_id="adapter")

        self.assertEqual(first, second)
        self.assertNotEqual(first, other)

    def _adapter(self, *, domain_policy: str) -> SimpleAdapter:
        return SimpleAdapter(self._descriptor(domain_policy=domain_policy), self._evaluate)

    @staticmethod
    def _descriptor(*, domain_policy: str) -> AdapterDescriptor:
        return AdapterDescriptor(
            adapter_id="gw_spectrum_surrogate",
            version="1.0.0",
            input_units={"T_n": "GeV", "alpha": "dimensionless", "v_w": "dimensionless"},
            output_units={"omega": "dimensionless"},
            validity_domain={"v_w": (0.4, 0.95)},
            determinism="deterministic",
            provenance_ref="c4://adapter/gw_spectrum_surrogate/v1",
            domain_policy=domain_policy,
            differentiable=True,
            independence_tags=("gw-surrogate-a",),
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


if __name__ == "__main__":
    unittest.main()
