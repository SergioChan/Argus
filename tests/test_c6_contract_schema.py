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


SCHEMA_PATH = ROOT / "schemas" / "contracts" / "c6.compute-adapter.schema.json"
EXAMPLE_PATH = ROOT / "schemas" / "contracts" / "examples" / "c6.example.json"


class C6ContractSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        cls.example = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)

    def test_schema_is_canonical_c6_v1_3(self) -> None:
        definitions = self.schema["$defs"]

        self.assertEqual(self.schema["x-argus-contract"], {"id": "C6", "owner": "S7", "version": "1.3.0"})
        for name in ("AdapterDescriptor", "EvalRequest", "EvalResult", "Quantity", "OutputQuantity"):
            self.assertIn(name, definitions)
        self.assertIn("uncertainty", definitions["OutputQuantity"]["required"])
        self.assertIn("unit_registry_version", definitions["EvalResult"]["required"])
        self.assertIn("unit_registry_hash", definitions["EvalResult"]["required"])
        self.assertIn("uncertainty_engine_version", definitions["EvalResult"]["required"])
        self.assertIn("uncertainty_engine_hash", definitions["EvalResult"]["required"])
        self.assertIn("validity_domain_guard_version", definitions["EvalResult"]["required"])
        self.assertIn("validity_domain_guard_hash", definitions["EvalResult"]["required"])
        self.assertIn("domain_diagnostics", definitions["EvalResult"]["required"])
        self.assertEqual(
            definitions["EvalResult"]["properties"]["outputs"]["additionalProperties"]["$ref"],
            "#/$defs/OutputQuantity",
        )

    def test_example_eval_result_validates(self) -> None:
        self._assert_valid(self.example)

    def test_eval_result_output_without_uncertainty_is_invalid(self) -> None:
        payload = json.loads(json.dumps(self.example))
        payload["outputs"]["action"].pop("uncertainty")

        self._assert_invalid(payload)

    def test_adapter_descriptor_and_eval_request_validate(self) -> None:
        descriptor = {
            "adapter_id": "adapter:toy-bounce",
            "version": "1.0.0",
            "methods": ["describe", "evaluate", "batch_evaluate"],
            "units_schema": {"T_n": "GeV", "alpha": "dimensionless"},
            "validity_domain": {"alpha": [0.0, 1.0]},
            "determinism": "deterministic",
            "differentiable": False,
            "cost_class": "toy",
            "independence_tags": ["toy-bounce-python"],
            "provenance_ref": "c4://adapter/toy-bounce/v1",
        }
        request = {
            "adapter_id": "adapter:toy-bounce",
            "inputs": {
                "T_n": {"value": 100.0, "units": "GeV"},
                "alpha": {"value": 0.1, "units": "dimensionless"},
            },
            "seed": 7,
        }

        self._assert_valid(descriptor)
        self._assert_valid(request)

    def test_generated_python_binding_points_to_exact_c6_schema_digest(self) -> None:
        contract = CONTRACT_BY_ID["C6"]

        self.assertEqual(contract.version, "1.3.0")
        self.assertEqual(contract.schema, "c6.compute-adapter.schema.json")
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
