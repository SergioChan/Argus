from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
BINDINGS_PYTHON = ROOT / "bindings" / "python"
if str(BINDINGS_PYTHON) not in sys.path:
    sys.path.insert(0, str(BINDINGS_PYTHON))

from argus_contracts import CONTRACT_BY_ID  # noqa: E402


SCHEMA_PATH = ROOT / "schemas" / "contracts" / "c4.artifact-record.schema.json"
EXAMPLE_PATH = ROOT / "schemas" / "contracts" / "examples" / "c4.example.json"


class C4ContractSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        cls.example = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)

    def test_schema_is_canonical_c4_v1(self) -> None:
        definitions = self.schema["$defs"]

        self.assertEqual(self.schema["x-argus-contract"], {"id": "C4", "owner": "S8", "version": "1.0.0"})
        for name in ("ArtifactRecord", "ArtifactRef", "ClaimTier", "HashRef", "Lineage", "Producer", "RetentionPolicy"):
            self.assertIn(name, definitions)
        for name in ("ArtifactRecord", "Lineage", "Producer", "RetentionPolicy"):
            self.assertFalse(definitions[name]["additionalProperties"])

    def test_example_artifact_record_validates(self) -> None:
        self._assert_valid(self.example)

    def test_lineage_requires_environment_digest(self) -> None:
        payload = json.loads(json.dumps(self.example))
        payload["lineage"].pop("environment_digest")

        self._assert_invalid(payload)

    def test_promoted_tier_requires_validation_report_ref(self) -> None:
        payload = {
            **self.example,
            "claim_tier": "recapitulated-known",
        }
        valid = {
            **payload,
            "validation_report_ref": "c4://report/example",
        }

        self._assert_invalid(payload)
        self._assert_valid(valid)

    def test_nested_records_reject_unknown_fields(self) -> None:
        payload = json.loads(json.dumps(self.example))
        payload["producer"]["extra"] = "not allowed"

        self._assert_invalid(payload)

    def test_generated_python_binding_points_to_exact_c4_schema_digest(self) -> None:
        contract = CONTRACT_BY_ID["C4"]

        self.assertEqual(contract.version, "1.0.0")
        self.assertEqual(contract.schema, "c4.artifact-record.schema.json")
        self.assertEqual(contract.schema_sha256, self._schema_sha256(self.schema))

    def _assert_valid(self, payload: dict) -> None:
        errors = sorted(self.validator.iter_errors(payload), key=lambda error: list(error.path))
        self.assertEqual(errors, [], msg=[error.message for error in errors])

    def _assert_invalid(self, payload: dict) -> None:
        errors = sorted(self.validator.iter_errors(payload), key=lambda error: list(error.path))
        self.assertTrue(errors, msg=f"payload unexpectedly validated: {payload}")

    @staticmethod
    def _schema_sha256(schema: dict) -> str:
        canonical = json.dumps(schema, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()


if __name__ == "__main__":
    unittest.main()
