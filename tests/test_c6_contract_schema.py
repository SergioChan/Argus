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

    def test_schema_is_canonical_c6_v2_3(self) -> None:
        definitions = self.schema["$defs"]

        self.assertEqual(self.schema["x-argus-contract"], {"id": "C6", "owner": "S7", "version": "2.3.0"})
        for name in (
            "AdapterDescriptor",
            "AdapterError",
            "BatchItemResult",
            "BatchRequest",
            "BatchResult",
            "BudgetToken",
            "EvalRequest",
            "EvalResult",
            "GradRequest",
            "GradResult",
            "JacobianEntry",
            "Quantity",
            "OutputQuantity",
        ):
            self.assertIn(name, definitions)
        self.assertIn("uncertainty", definitions["OutputQuantity"]["required"])
        self.assertIn("job_seed", definitions["EvalRequest"]["properties"])
        self.assertIn("dag_node_id", definitions["EvalRequest"]["properties"])
        self.assertIn("call_index", definitions["EvalRequest"]["properties"])
        self.assertIn("c6_version", definitions["EvalRequest"]["properties"])
        self.assertIn("caller_scopes", definitions["EvalRequest"]["properties"])
        self.assertIn("budget_token_ref", definitions["EvalRequest"]["properties"])
        self.assertIn("c6_version", definitions["GradRequest"]["properties"])
        self.assertIn("caller_scopes", definitions["GradRequest"]["properties"])
        self.assertIn("budget_token_ref", definitions["GradRequest"]["properties"])
        self.assertEqual(definitions["BatchRequest"]["properties"]["method"]["const"], "batch_evaluate")
        self.assertEqual(definitions["BatchResult"]["properties"]["method"]["const"], "batch_evaluate")
        self.assertEqual(
            definitions["BatchRequest"]["properties"]["items"]["items"]["$ref"],
            "#/$defs/EvalRequest",
        )
        self.assertEqual(
            definitions["BatchResult"]["properties"]["items"]["items"]["$ref"],
            "#/$defs/BatchItemResult",
        )
        self.assertEqual(
            definitions["BatchItemResult"]["properties"]["error"]["$ref"],
            "#/$defs/AdapterError",
        )
        self.assertIn("seed_used", definitions["EvalResult"]["required"])
        self.assertIn("seed_source", definitions["EvalResult"]["required"])
        self.assertIn("seed_derivation", definitions["EvalResult"]["required"])
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
        self.assertEqual(
            definitions["GradResult"]["properties"]["jacobian"]["additionalProperties"]["additionalProperties"]["$ref"],
            "#/$defs/JacobianEntry",
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
            "c6_version": "2.3.0",
            "caller_scopes": ["adapter-invoke", "c6.read"],
            "inputs": {
                "T_n": {"value": 100.0, "units": "GeV"},
                "alpha": {"value": 0.1, "units": "dimensionless"},
            },
            "seed": 7,
            "job_seed": 3,
            "dag_node_id": "node-a",
            "call_index": 0,
        }

        self._assert_valid(descriptor)
        self._assert_valid(request)

    def test_batch_request_and_partial_budget_result_validate(self) -> None:
        request = {
            "method": "batch_evaluate",
            "items": [
                {
                    "adapter_id": "adapter:toy-bounce",
                    "c6_version": "2.3.0",
                    "caller_scopes": ["adapter-invoke"],
                    "inputs": {"alpha": {"value": 0.1, "units": "dimensionless"}},
                    "job_seed": 7,
                    "dag_node_id": "batch-node",
                    "call_index": 0,
                    "budget_token_ref": "budget://s7/batch-token",
                },
                {
                    "adapter_id": "adapter:toy-bounce",
                    "c6_version": "2.3.0",
                    "caller_scopes": ["adapter-invoke"],
                    "inputs": {"alpha": {"value": 0.2, "units": "dimensionless"}},
                    "job_seed": 7,
                    "dag_node_id": "batch-node",
                    "call_index": 1,
                    "budget_token_ref": "budget://s7/batch-token",
                },
            ],
            "budget_token": {
                "token_ref": "budget://s7/batch-token",
                "remaining_units": 1.0,
                "unit_cost": 1.0,
            },
        }
        completed_eval = json.loads(json.dumps(self.example))
        completed_eval["adapter_id"] = "adapter:toy-bounce"
        result = {
            "method": "batch_evaluate",
            "items": [
                {"index": 0, "result": completed_eval},
                {
                    "index": 1,
                    "error": {
                        "category": "BUDGET",
                        "message": "budget exhausted before batch item 1",
                    },
                },
            ],
            "n_ok": 1,
            "halted": True,
            "halted_index": 1,
            "budget": {
                "token_ref": "budget://s7/batch-token",
                "limit_units": 1.0,
                "unit_cost": 1.0,
                "spent_units": 1.0,
                "remaining_units": 0.0,
                "halted_reason": "BUDGET",
            },
            "partial_provenance_ref": "c4://adapter-call/batch/partial",
        }

        self._assert_valid(request)
        self._assert_valid(result)

    def test_grad_request_and_result_validate(self) -> None:
        request = {
            "method": "grad",
            "adapter_id": "adapter:jax-gw",
            "c6_version": "2.3.0",
            "caller_scopes": ["adapter-invoke"],
            "inputs": {
                "T_n": {"value": 100.0, "units": "GeV"},
                "alpha": {"value": 0.2, "units": "dimensionless"},
            },
            "seed": 11,
        }
        result = {
            "adapter_id": "adapter:jax-gw",
            "jacobian": {
                "omega": {
                    "T_n": {
                        "value": 0.0002,
                        "units": "1/GeV",
                        "output_units": "Omega_h2",
                        "input_units": "GeV",
                    }
                }
            },
            "in_validity_domain": True,
            "extrapolation_flag": False,
            "seed_used": 11,
            "seed_source": "explicit",
            "seed_derivation": {
                "algorithm": "explicit",
                "seed_manager_version": "argus-seed-1.0.0",
                "seed_manager_hash": "blake3:139c32ecf38beef7cca4a9d72338af65843428033330bd6d4516e58e9dc90267",
                "adapter_id": "adapter:jax-gw",
                "seed_used": 11,
                "seed_source": "explicit",
            },
            "domain_diagnostics": {
                "kind": "box",
                "policy": "flag",
                "violated_fields": [],
                "clamped_fields": [],
                "distance": 0.0,
                "fields": {},
                "validity_domain_guard_version": "argus-domain-1.0.0",
                "validity_domain_guard_hash": "blake3:353cb32c3b4d50a2f1a3626946cd23b7407b6a64240e405c32398e936f387bc5",
            },
            "backend_name": "jax",
            "backend_version": "argus-backend-jax-1.0.0",
            "backend_hash": "blake3:1111111111111111111111111111111111111111111111111111111111111111",
            "underlying_code_version": "jax-test@1",
            "provenance_ref": "c4://adapter-call/jax-gw/grad-example",
            "unit_registry_version": "argus-units-1.0.0",
            "unit_registry_hash": "blake3:d051549f426fb54fa67a0ef96611db2aebd0158c6b541e964c380d6cc58e06e5",
            "validity_domain_guard_version": "argus-domain-1.0.0",
            "validity_domain_guard_hash": "blake3:353cb32c3b4d50a2f1a3626946cd23b7407b6a64240e405c32398e936f387bc5",
            "seed_manager_version": "argus-seed-1.0.0",
            "seed_manager_hash": "blake3:139c32ecf38beef7cca4a9d72338af65843428033330bd6d4516e58e9dc90267",
        }

        self._assert_valid(request)
        self._assert_valid(result)

    def test_generated_python_binding_points_to_exact_c6_schema_digest(self) -> None:
        contract = CONTRACT_BY_ID["C6"]

        self.assertEqual(contract.version, "2.3.0")
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
