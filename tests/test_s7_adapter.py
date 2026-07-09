from __future__ import annotations

import unittest

from argus_core import (
    AdapterBroker,
    AdapterConformanceError,
    AdapterDescriptor,
    AdapterVersionError,
    EvalRequest,
    InMemoryArtifactStore,
    InMemoryRegistry,
    NormalizedQuantity,
    OutOfDomainError,
    ProvenanceUnavailableError,
    Quantity,
    S7UnitRegistry,
    SimpleAdapter,
    UNIT_REGISTRY_HASH,
    UNIT_REGISTRY_VERSION,
    UnitsMismatchError,
    publish_adapter_capability,
    derive_seed,
    normalize_quantity,
    resolve_independent_adapter_capabilities,
    select_adapter_version,
)


class S7UnitsAndAdapterTests(unittest.TestCase):
    def test_frozen_unit_registry_digest_is_pinned_into_normalized_quantities_and_results(self) -> None:
        registry = S7UnitRegistry.default()

        normalized = normalize_quantity(Quantity(value=0.1, units="TeV"), "GeV", registry=registry)
        result = self._evaluate_with_broker(
            self._adapter(domain_policy="flag"),
            {
                "T_n": Quantity(value=0.1, units="TeV"),
                "alpha": Quantity(value=0.2, units="dimensionless"),
                "v_w": Quantity(value=0.7, units="dimensionless"),
            },
        )

        self.assertEqual(registry.version, UNIT_REGISTRY_VERSION)
        self.assertEqual(registry.registry_hash, UNIT_REGISTRY_HASH)
        self.assertEqual(normalized.unit_registry_version, UNIT_REGISTRY_VERSION)
        self.assertEqual(normalized.unit_registry_hash, UNIT_REGISTRY_HASH)
        self.assertEqual(result.unit_registry_version, UNIT_REGISTRY_VERSION)
        self.assertEqual(result.unit_registry_hash, UNIT_REGISTRY_HASH)

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

    def test_compound_units_normalize_and_reject_dimension_mismatch(self) -> None:
        normalized = normalize_quantity(Quantity(value=2.0, units="TeV/Hz"), "GeV/Hz")

        self.assertEqual(normalized.units, "GeV/Hz")
        self.assertEqual(normalized.original_units, "TeV/Hz")
        self.assertAlmostEqual(normalized.value, 2000.0)
        with self.assertRaises(UnitsMismatchError):
            normalize_quantity(Quantity(value=1.0, units="GeV/Hz"), "GeV")

    def test_log_space_inputs_are_delinearized_before_backend(self) -> None:
        captured: dict[str, float] = {}
        descriptor = AdapterDescriptor(
            adapter_id="log_adapter",
            version="1.0.0",
            input_units={
                "log10_beta_over_H": {"units": "dimensionless", "log_space": "log10"},
            },
            output_units={"omega": "dimensionless"},
            validity_domain={"log10_beta_over_H": (1.0, 3.0)},
            determinism="deterministic",
            provenance_ref="c4://adapter/log_adapter/v1",
        )

        def evaluate(inputs: dict[str, NormalizedQuantity], _seed: int | None) -> dict[str, Quantity]:
            captured["beta_over_H"] = inputs["log10_beta_over_H"].value
            return {
                "omega": Quantity(
                    value=inputs["log10_beta_over_H"].value,
                    units="dimensionless",
                    uncertainty={"kind": "interval", "radius": 0.01},
                )
            }

        result = self._evaluate_with_broker(
            SimpleAdapter(descriptor, evaluate),
            {"log10_beta_over_H": Quantity(value=2.0, units="dimensionless")},
        )

        self.assertAlmostEqual(captured["beta_over_H"], 100.0)
        self.assertEqual(result.outputs["omega"].value, 100.0)
        self.assertEqual(result.unit_registry_version, UNIT_REGISTRY_VERSION)

    def test_outputs_are_normalized_to_declared_units(self) -> None:
        descriptor = AdapterDescriptor(
            adapter_id="frequency_adapter",
            version="1.0.0",
            input_units={"alpha": "dimensionless"},
            output_units={"peak_frequency": "Hz"},
            validity_domain={},
            determinism="deterministic",
            provenance_ref="c4://adapter/frequency_adapter/v1",
        )
        result = self._evaluate_with_broker(
            SimpleAdapter(
                descriptor,
                lambda _inputs, _seed: {
                    "peak_frequency": Quantity(
                        value=2.0,
                        units="mHz",
                        uncertainty={"kind": "interval", "radius": 0.5},
                    )
                },
            ),
            {"alpha": Quantity(value=0.2, units="dimensionless")},
        )

        self.assertEqual(result.outputs["peak_frequency"].units, "Hz")
        self.assertAlmostEqual(result.outputs["peak_frequency"].value, 0.002)
        self.assertEqual(result.outputs["peak_frequency"].uncertainty, {"kind": "interval", "radius": 0.0005})

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

    def test_adapter_capability_publishes_to_c5_registry(self) -> None:
        registry = InMemoryRegistry()

        published = publish_adapter_capability(registry, self._descriptor(domain_policy="flag"), subtopics=("ewpt",))
        resolution = registry.resolve(kind="adapter", subtopic="ewpt", required_scope="grad")

        self.assertEqual(published.kind, "adapter")
        self.assertEqual(published.owner_subsystem, "S7")
        self.assertIn("gw-surrogate-a", published.independence_tags)
        self.assertEqual([descriptor.entity_id for descriptor in resolution.descriptors], ["gw_spectrum_surrogate"])

    def test_independent_adapter_resolution_excludes_revoked_and_same_lineage(self) -> None:
        registry = InMemoryRegistry()
        first = self._descriptor(domain_policy="flag", adapter_id="gw_a", tags=("impl-a",))
        second = self._descriptor(domain_policy="flag", adapter_id="gw_b", tags=("impl-b",))
        revoked = self._descriptor(domain_policy="flag", adapter_id="gw_c", tags=("impl-c",))
        publish_adapter_capability(registry, first, subtopics=("ewpt",))
        publish_adapter_capability(registry, second, subtopics=("ewpt",))
        publish_adapter_capability(registry, revoked, subtopics=("ewpt",))
        registry.revoke("gw_c")

        attestation = resolve_independent_adapter_capabilities(
            registry,
            subtopic="ewpt",
            excluded_independence_tags=("impl-a",),
            min_independent=1,
        )

        self.assertTrue(attestation.lineage_disjoint)
        self.assertEqual(attestation.selected_entity_ids, ("gw_b",))
        self.assertNotIn("gw_c", attestation.candidate_ids)

    def test_select_adapter_version_uses_highest_compatible_major(self) -> None:
        descriptors = (
            self._descriptor(domain_policy="flag", adapter_id="gw", version="1.0.0"),
            self._descriptor(domain_policy="flag", adapter_id="gw", version="1.2.0"),
            self._descriptor(domain_policy="flag", adapter_id="gw", version="2.0.0"),
        )

        selected = select_adapter_version(descriptors, requested_major=1)

        self.assertEqual(selected.selected_version, "1.2.0")
        with self.assertRaises(AdapterVersionError):
            select_adapter_version(descriptors, requested_major=3)

    def _adapter(self, *, domain_policy: str) -> SimpleAdapter:
        return SimpleAdapter(self._descriptor(domain_policy=domain_policy), self._evaluate)

    @staticmethod
    def _descriptor(
        *,
        domain_policy: str,
        adapter_id: str = "gw_spectrum_surrogate",
        version: str = "1.0.0",
        tags: tuple[str, ...] = ("gw-surrogate-a",),
    ) -> AdapterDescriptor:
        return AdapterDescriptor(
            adapter_id=adapter_id,
            version=version,
            input_units={"T_n": "GeV", "alpha": "dimensionless", "v_w": "dimensionless"},
            output_units={"omega": "dimensionless"},
            validity_domain={"v_w": (0.4, 0.95)},
            determinism="deterministic",
            provenance_ref=f"c4://adapter/{adapter_id}/v{version}",
            domain_policy=domain_policy,
            differentiable=True,
            independence_tags=tags,
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
    def _evaluate_with_broker(adapter: SimpleAdapter, inputs: dict[str, Quantity]):
        broker = AdapterBroker(artifact_store=InMemoryArtifactStore())
        broker.register(adapter)
        return broker.evaluate(EvalRequest(adapter_id=adapter.descriptor.adapter_id, inputs=inputs, seed=123))


if __name__ == "__main__":
    unittest.main()
