from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator

from argus_core import (
    BREAKING_MAJOR,
    C2ContractError,
    classify_json_schema_change,
    parse_c2_job_envelope,
    schema_version_declares_change,
)


ROOT = Path(__file__).resolve().parents[1]
BINDINGS_PYTHON = ROOT / "bindings" / "python"
if str(BINDINGS_PYTHON) not in sys.path:
    sys.path.insert(0, str(BINDINGS_PYTHON))

from argus_contracts import CONTRACT_BY_ID  # noqa: E402


SCHEMA_PATH = ROOT / "schemas" / "contracts" / "c2.job-envelope.schema.json"
EXAMPLE_PATH = ROOT / "schemas" / "contracts" / "examples" / "c2.example.json"


class C2ContractSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        cls.example = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)

    def test_schema_is_canonical_c2_v1(self) -> None:
        self.assertEqual(self.schema["x-argus-contract"], {"id": "C2", "owner": "S5", "version": "1.0.0"})
        self.assertIn("JobEnvelope", self.schema["$defs"])
        self.assertIn("JobResult", self.schema["$defs"])

    def test_example_job_envelope_validates(self) -> None:
        self._assert_valid(self.example)

    def test_generated_python_binding_points_to_exact_c2_schema_digest(self) -> None:
        contract = CONTRACT_BY_ID["C2"]

        self.assertEqual(contract.version, "1.0.0")
        self.assertEqual(contract.schema, "c2.job-envelope.schema.json")
        self.assertEqual(contract.schema_sha256, self._schema_sha256(self.schema))

    def test_minor_forward_compatible_parse_ignores_unknown_additive_field(self) -> None:
        payload = {
            **self.example,
            "contract_version": "1.3.0",
            "future_scheduler_hint": {"ignored": True},
        }

        envelope = parse_c2_job_envelope(payload, runtime_version="1.0.0")

        self.assertEqual(envelope.contract_version, "1.3.0")
        self.assertEqual(envelope.job_id, self.example["job_id"])
        self.assertFalse(hasattr(envelope, "future_scheduler_hint"))

    def test_major_version_mismatch_is_typed_permanent_error(self) -> None:
        payload = {**self.example, "contract_version": "2.0.0"}

        with self.assertRaises(C2ContractError) as raised:
            parse_c2_job_envelope(payload, runtime_version="1.0.0")

        self.assertEqual(raised.exception.error.category, "PERMANENT")
        self.assertEqual(raised.exception.error.code, "VERSION_UNSUPPORTED")

    def test_breaking_schema_change_requires_major_bump(self) -> None:
        old_schema = self.schema["$defs"]["JobEnvelope"]
        new_schema = json.loads(json.dumps(old_schema))
        new_schema["properties"].pop("job_id")
        new_schema["required"] = [field for field in new_schema["required"] if field != "job_id"]

        result = classify_json_schema_change(old_schema, new_schema)

        self.assertEqual(result.classification, BREAKING_MAJOR)
        self.assertFalse(
            schema_version_declares_change(
                old_version="1.0.0",
                new_version="1.1.0",
                classification=result.classification,
            )
        )

    def _assert_valid(self, payload: dict) -> None:
        errors = sorted(self.validator.iter_errors(payload), key=lambda error: list(error.path))
        self.assertEqual(errors, [], msg=[error.message for error in errors])

    @staticmethod
    def _schema_sha256(schema: dict) -> str:
        canonical = json.dumps(schema, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()


if __name__ == "__main__":
    unittest.main()
