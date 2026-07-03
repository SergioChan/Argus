from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator

from argus_core import canonical_json_bytes


ROOT = Path(__file__).resolve().parents[1]
BINDINGS_PYTHON = ROOT / "bindings" / "python"
if str(BINDINGS_PYTHON) not in sys.path:
    sys.path.insert(0, str(BINDINGS_PYTHON))

from argus_contracts import CONTRACT_BY_ID  # noqa: E402


SCHEMA_PATH = ROOT / "schemas" / "contracts" / "c3.validation-report.schema.json"
EXAMPLE_PATH = ROOT / "schemas" / "contracts" / "examples" / "c3.example.json"
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


class C3ContractSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        cls.example = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)

    def test_schema_is_canonical_c3_v2(self) -> None:
        metadata = self.schema["x-argus-contract"]
        report = self.schema["$defs"]["ValidationReport"]

        self.assertEqual(metadata, {"id": "C3", "owner": "S3", "version": "2.0.0"})
        self.assertTrue(C3_V11_FIELDS <= set(report["properties"]))
        self.assertTrue(C3_V2_REQUIRED_FIELDS <= set(report["required"]))
        self.assertEqual(report["properties"]["perturbation_pairs"]["minItems"], 2)
        for field in C3_V11_FIELDS:
            self.assertIn("default", report["properties"][field])

    def test_example_validation_report_validates(self) -> None:
        self._assert_valid(self.example)

    def test_v1_0_shape_report_is_rejected_by_v2_schema(self) -> None:
        payload = dict(self.example)
        for field in C3_V11_FIELDS:
            payload.pop(field)

        errors = sorted(self.validator.iter_errors(payload), key=lambda error: list(error.path))
        messages = [message for error in errors for message in self._error_messages(error)]

        self.assertIn("'perturbation_pairs' is a required property", messages)
        self.assertIn("'insensitivity_flags' is a required property", messages)
        self.assertIn("'referee' is a required property", messages)

    def test_generated_python_binding_points_to_exact_c3_schema_digest(self) -> None:
        contract = CONTRACT_BY_ID["C3"]

        self.assertEqual(contract.version, "2.0.0")
        self.assertEqual(contract.schema, "c3.validation-report.schema.json")
        self.assertEqual(contract.schema_sha256, self._schema_sha256(self.schema))

    def test_generated_binding_metadata_round_trips_c3_example(self) -> None:
        contract = CONTRACT_BY_ID["C3"]
        schema_path = ROOT / "schemas" / "contracts" / contract.schema
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)

        encoded = canonical_json_bytes(self.example)
        round_tripped = json.loads(encoded.decode("utf-8"))
        errors = sorted(validator.iter_errors(round_tripped), key=lambda error: list(error.path))

        self.assertEqual(errors, [], msg=[error.message for error in errors])
        self.assertEqual(canonical_json_bytes(round_tripped), encoded)

    def _assert_valid(self, payload: dict) -> None:
        errors = sorted(self.validator.iter_errors(payload), key=lambda error: list(error.path))
        self.assertEqual(errors, [], msg=[error.message for error in errors])

    @staticmethod
    def _error_messages(error: object) -> list[str]:
        messages = [error.message]
        for child in getattr(error, "context", ()):
            messages.extend(C3ContractSchemaTests._error_messages(child))
        return messages

    @staticmethod
    def _schema_sha256(schema: dict) -> str:
        canonical = json.dumps(schema, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()


if __name__ == "__main__":
    unittest.main()
