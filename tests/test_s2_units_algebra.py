from __future__ import annotations

import unittest

from argus_core import (
    AsymptoticLimitAnchor,
    AsymptoticLimitInjector,
    BuckinghamPiInjector,
    BuckinghamPiVariable,
    DimensionalError,
    FeatureNode,
    FeatureTerm,
    PositiveOutputConstraint,
    PositivityArchitectureInjector,
    S2ContractModelError,
    SymmetryInvariantInjector,
    UnitRegistry,
    UnitsAlgebra,
    validate_feature_graph_dimensions,
)


class S2UnitsAlgebraTests(unittest.TestCase):
    def setUp(self) -> None:
        self.algebra = UnitsAlgebra(UnitRegistry.default())

    def test_dimension_arithmetic_is_deterministic_for_registry_units(self) -> None:
        energy = self.algebra.dimension("GeV")
        length = self.algebra.dimension("m")
        dimensionless = self.algebra.dimension("dimensionless")

        self.assertEqual(self.algebra.dimension("TeV"), energy)
        self.assertEqual(self.algebra.dimension("MeV"), energy)
        self.assertEqual(self.algebra.dimension("1"), dimensionless)
        self.assertTrue(dimensionless.is_dimensionless)
        self.assertEqual(self.algebra.multiply("GeV", "GeV^-1"), dimensionless)
        self.assertEqual(self.algebra.divide("GeV^2", "GeV"), energy)
        self.assertEqual(self.algebra.power("GeV", 2), energy ** 2)
        self.assertEqual(self.algebra.multiply("m", "m"), length ** 2)
        self.assertNotEqual(energy * length, dimensionless)

    def test_compound_unit_parser_handles_products_quotients_and_negative_powers(self) -> None:
        energy = self.algebra.dimension("GeV")
        length = self.algebra.dimension("m")
        time = self.algebra.dimension("s")

        self.assertEqual(self.algebra.dimension("GeV/m"), energy / length)
        self.assertEqual(self.algebra.dimension("m/s"), length / time)
        self.assertEqual(self.algebra.dimension("GeV^2*m^-1"), (energy ** 2) / length)
        self.assertEqual(self.algebra.dimension("1/GeV"), energy ** -1)
        self.assertEqual(self.algebra.dimension("m/GeV/s"), length / energy / time)
        self.assertEqual(self.algebra.dimension("pb"), length ** 2)

    def test_compound_unit_parser_rejects_malformed_expressions(self) -> None:
        for expression in ("GeV*", "m//s", "GeV^1.5", "unknown"):
            with self.subTest(expression=expression):
                with self.assertRaises(S2ContractModelError):
                    self.algebra.dimension(expression)

    def test_dimensional_guard_rejects_inconsistent_feature_and_excludes_node(self) -> None:
        valid = FeatureNode(
            node_id="temperature_ratio",
            terms=(
                FeatureTerm(field_name="temperature", units="GeV"),
                FeatureTerm(field_name="inverse_temperature", units="GeV", exponent=-1),
            ),
            declared_units="dimensionless",
        )
        invalid = FeatureNode(
            node_id="bad_energy_length",
            terms=(
                FeatureTerm(field_name="temperature", units="GeV"),
                FeatureTerm(field_name="baseline", units="m"),
            ),
            declared_units="dimensionless",
        )

        result = validate_feature_graph_dimensions((valid, invalid), algebra=self.algebra, raise_on_error=False)
        self.assertEqual(tuple(node.node_id for node in result.valid_nodes), ("temperature_ratio",))
        self.assertEqual(tuple(node.node_id for node in result.rejected_nodes), ("bad_energy_length",))

        with self.assertRaises(DimensionalError) as raised:
            validate_feature_graph_dimensions((valid, invalid), algebra=self.algebra)

        self.assertEqual(raised.exception.node_id, "bad_energy_length")
        self.assertEqual(raised.exception.expected, self.algebra.dimension("dimensionless"))
        self.assertEqual(raised.exception.actual, self.algebra.dimension("GeV*m"))
        self.assertEqual(raised.exception.valid_node_count, 1)
        self.assertEqual(tuple(node.node_id for node in raised.exception.valid_nodes), ("temperature_ratio",))

    def test_buckingham_pi_enumerates_exact_independent_dimensionless_basis(self) -> None:
        result = BuckinghamPiInjector(algebra=self.algebra).enumerate_groups(
            variables=(
                BuckinghamPiVariable("length", "m"),
                BuckinghamPiVariable("time", "s"),
                BuckinghamPiVariable("velocity", "m/s"),
                BuckinghamPiVariable("temperature", "GeV"),
                BuckinghamPiVariable("mass_scale", "GeV"),
            ),
            max_exponent=2,
            node_prefix="pi",
        )

        self.assertEqual(result.dimension_matrix_rank, 3)
        self.assertEqual(result.nullity, 2)
        self.assertEqual(result.unit_registry_version, UnitRegistry.default().version)
        self.assertEqual(len(result.groups), 2)
        self.assertEqual(result.basis_rank, 2)

        group_vectors = {group.exponent_vector for group in result.groups}
        self.assertEqual(group_vectors, {(1, -1, -1, 0, 0), (0, 0, 0, 1, -1)})
        for group in result.groups:
            self.assertEqual(self.algebra.feature_dimension(group.feature_node), self.algebra.dimension("dimensionless"))
            self.assertTrue(group.feature_node.node_id.startswith("pi_"))

    def test_buckingham_pi_rejects_invalid_variables_and_bounds(self) -> None:
        injector = BuckinghamPiInjector(algebra=self.algebra)

        with self.assertRaises(S2ContractModelError):
            injector.enumerate_groups(
                variables=(BuckinghamPiVariable("temperature", "GeV"), BuckinghamPiVariable("temperature", "GeV")),
                max_exponent=2,
            )
        with self.assertRaises(S2ContractModelError):
            injector.enumerate_groups(variables=(BuckinghamPiVariable("temperature", "GeV"),), max_exponent=0)

    def test_symmetry_even_power_invariant_is_dimensionally_valid_and_deterministic(self) -> None:
        invariant = SymmetryInvariantInjector(algebra=self.algebra).even_power(
            field_name="signed_mass",
            units="GeV",
            power=2,
            node_id="signed_mass_squared",
        )

        self.assertEqual(invariant.symmetry, "sign_flip")
        self.assertEqual(invariant.feature_node.declared_units, "GeV^2")
        self.assertEqual(invariant.transform((-3.0, 2.0, 0.5)), (9.0, 4.0, 0.25))
        validation = validate_feature_graph_dimensions((invariant.feature_node,), algebra=self.algebra)
        self.assertEqual(tuple(node.node_id for node in validation.valid_nodes), ("signed_mass_squared",))

    def test_symmetry_even_power_expands_compound_units(self) -> None:
        invariant = SymmetryInvariantInjector(algebra=self.algebra).even_power(
            field_name="velocity",
            units="m/s",
            power=2,
            node_id="speed_squared",
        )

        self.assertEqual(invariant.feature_node.declared_units, "m^2/s^2")
        self.assertEqual(self.algebra.feature_dimension(invariant.feature_node), self.algebra.dimension("m^2/s^2"))
        validation = validate_feature_graph_dimensions((invariant.feature_node,), algebra=self.algebra)
        self.assertEqual(tuple(node.node_id for node in validation.valid_nodes), ("speed_squared",))

    def test_positivity_architecture_enforces_non_negative_predictions(self) -> None:
        result = PositivityArchitectureInjector().enforce(
            raw_predictions=(-20.0, -1.0, 0.0, 3.0),
            constraint=PositiveOutputConstraint(target_name="cross_section", units="pb", minimum=0.0),
        )

        self.assertEqual(result.status, "PASS")
        self.assertGreaterEqual(result.min_prediction, 0.0)
        self.assertEqual(len(result.transformed_predictions), 4)
        self.assertLess(result.transformed_predictions[0], result.transformed_predictions[-1])

    def test_asymptotic_anchor_evaluates_near_limit_without_tier_claim(self) -> None:
        anchor = AsymptoticLimitAnchor(
            variable_name="temperature_ratio",
            limit_value=0.0,
            known_output=1.0,
            tolerance=0.02,
            approach_points=(0.1, 0.03, 0.01),
        )

        result = AsymptoticLimitInjector().evaluate(
            anchor=anchor,
            predictor=lambda inputs: 1.0 + float(inputs["temperature_ratio"]) ** 2,
        )

        self.assertEqual(result.status, "PASS")
        self.assertLessEqual(result.max_abs_error, 0.02)
        self.assertTrue(result.advisory)
        self.assertEqual(result.claim_tier, "ran-toy")


if __name__ == "__main__":
    unittest.main()
