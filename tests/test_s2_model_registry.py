from __future__ import annotations

import unittest

from argus_core import (
    ModelFamilyDescriptor,
    ModelFamilyRegistry,
    S2ContractModelError,
    list_model_families,
    register_model_family,
)


class S2ModelFamilyRegistryTests(unittest.TestCase):
    def test_default_model_families_are_descriptor_backed_and_c4_ready(self) -> None:
        families = {family.family_id: family for family in list_model_families()}

        baseline = families["tabular-baseline"]
        self.assertEqual(baseline.family_kind, "classical")
        self.assertEqual(baseline.name, "Tabular Baseline")
        self.assertIn("regression", baseline.task_types)
        self.assertEqual(baseline.cost_class, "low")
        self.assertTrue(baseline.deterministic_training)
        self.assertTrue(baseline.training_entrypoint)
        self.assertTrue(baseline.prediction_entrypoint)
        self.assertTrue(baseline.provenance_ref.startswith("c4://"))

        payload = baseline.as_c4_payload()
        self.assertEqual(payload["family_id"], "tabular-baseline")
        self.assertEqual(payload["task_types"], ["regression", "surrogate_emulation"])
        self.assertEqual(payload["provenance_ref"], baseline.provenance_ref)

    def test_new_family_registers_without_core_list_change(self) -> None:
        registry = ModelFamilyRegistry.default()
        descriptor = ModelFamilyDescriptor(
            family_id="symbolic-regressor",
            name="Symbolic Regressor",
            family_kind="classical",
            task_types=("regression",),
            cost_class="medium",
            differentiable=False,
            physics_informed=False,
            native_uq="conformal",
            deterministic_training=True,
            supported_constraints=("monotonicity",),
            training_entrypoint="plugins.symbolic.train",
            prediction_entrypoint="plugins.symbolic.predict",
            provenance_ref="c4://model-family/symbolic-regressor/v1",
        )

        registered = register_model_family(descriptor, registry=registry)

        self.assertIs(registered, descriptor)
        self.assertIs(registry.get("symbolic-regressor"), descriptor)
        self.assertIn("symbolic-regressor", {family.family_id for family in list_model_families(registry=registry)})

    def test_duplicate_or_invalid_family_descriptors_fail_closed(self) -> None:
        registry = ModelFamilyRegistry.default()
        duplicate = registry.get("tabular-baseline")

        with self.assertRaises(S2ContractModelError):
            registry.register(duplicate)

        with self.assertRaises(S2ContractModelError):
            ModelFamilyDescriptor(
                family_id="",
                name="Missing ID",
                family_kind="classical",
                task_types=("regression",),
                cost_class="low",
                differentiable=False,
                physics_informed=False,
                native_uq="conformal",
                deterministic_training=True,
                training_entrypoint="plugins.bad.train",
                prediction_entrypoint="plugins.bad.predict",
                provenance_ref="c4://model-family/bad/v1",
            )

        with self.assertRaises(S2ContractModelError):
            ModelFamilyDescriptor(
                family_id="bad-provenance",
                name="Bad Provenance",
                family_kind="classical",
                task_types=("regression",),
                cost_class="low",
                differentiable=False,
                physics_informed=False,
                native_uq="conformal",
                deterministic_training=True,
                training_entrypoint="plugins.bad.train",
                prediction_entrypoint="plugins.bad.predict",
                provenance_ref="local-file",
            )


if __name__ == "__main__":
    unittest.main()
