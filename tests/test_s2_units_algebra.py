from __future__ import annotations

import unittest

from argus_core import (
    DimensionalError,
    FeatureNode,
    FeatureTerm,
    S2ContractModelError,
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


if __name__ == "__main__":
    unittest.main()
