from __future__ import annotations

import json
from pathlib import Path
import unittest

from argus_core import ADDITIVE_MINOR, BREAKING_MAJOR, assert_schema_version_declares_change, classify_json_schema_change


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "schemas" / "contracts"
C3_V11_FIELDS = {
    "perturbation_pairs",
    "insensitivity_flags",
    "challenger_panel",
    "independence_attestation_debate",
    "referee",
    "debate_ref",
}
C3_V2_REQUIRED_FIELDS = {
    "perturbation_pairs",
    "insensitivity_flags",
    "referee",
}


class C3TPR1CompatibilityTests(unittest.TestCase):
    def test_c3_v1_1_debate_fields_are_additive_from_v1_0(self) -> None:
        old_schema = self._load(CONTRACTS / "compatibility" / "c3.validation-report.v1.0.0.schema.json")
        new_schema = self._load(CONTRACTS / "compatibility" / "c3.validation-report.v1.1.0.schema.json")
        old_report = old_schema["$defs"]["ValidationReport"]
        new_report = new_schema["$defs"]["ValidationReport"]

        self.assertFalse(C3_V11_FIELDS & set(old_report["properties"]))
        self.assertTrue(C3_V11_FIELDS <= set(new_report["properties"]))
        self.assertFalse(C3_V11_FIELDS & set(new_report["required"]))
        for field in C3_V11_FIELDS:
            self.assertIn("default", new_report["properties"][field])

        result = classify_json_schema_change(old_schema, new_schema)

        self.assertEqual(result.classification, ADDITIVE_MINOR)
        self.assertFalse(result.breaking_changes)
        assert_schema_version_declares_change(
            old_version="1.0.0",
            new_version="1.1.0",
            classification=result.classification,
        )

    def test_c3_v2_requires_observatory_gate_semantics_from_v1_1(self) -> None:
        old_schema = self._load(CONTRACTS / "compatibility" / "c3.validation-report.v1.1.0.schema.json")
        new_schema = self._load(CONTRACTS / "c3.validation-report.schema.json")
        new_report = new_schema["$defs"]["ValidationReport"]

        self.assertEqual(new_schema["x-argus-contract"]["version"], "2.0.0")
        self.assertTrue(C3_V2_REQUIRED_FIELDS <= set(new_report["required"]))
        self.assertEqual(new_report["properties"]["perturbation_pairs"]["minItems"], 2)

        result = classify_json_schema_change(old_schema, new_schema)

        self.assertEqual(result.classification, BREAKING_MAJOR)
        self.assertTrue(result.breaking_changes)
        assert_schema_version_declares_change(
            old_version="1.1.0",
            new_version="2.0.0",
            classification=result.classification,
        )

    @staticmethod
    def _load(path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
