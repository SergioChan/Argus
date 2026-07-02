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


SCHEMA_PATH = ROOT / "schemas" / "contracts" / "c10.s10-runtime.schema.json"
EXAMPLES = ROOT / "schemas" / "contracts" / "examples"


class C10ContractSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)

    def test_schema_is_canonical_c10_v4(self) -> None:
        definitions = self.schema["$defs"]

        self.assertEqual(self.schema["x-argus-contract"], {"id": "C10", "owner": "S10", "version": "4.0.0"})
        for name in (
            "BudgetToken",
            "ScopeToken",
            "PolicyBundle",
            "LaunchRequest",
            "PolicyVerdict",
            "SandboxHandle",
            "SandboxExecutionResult",
            "QuotaState",
            "AuditEvent",
            "S8CheckpointSignature",
        ):
            self.assertIn(name, definitions)

    def test_all_c10_golden_samples_validate(self) -> None:
        golden_paths = [EXAMPLES / "c10.example.json", *sorted(EXAMPLES.glob("c10.*.example.json"))]

        for path in golden_paths:
            with self.subTest(path=path.name):
                self._assert_valid(json.loads(path.read_text(encoding="utf-8")))

    def test_launch_request_requires_digest_pinned_image(self) -> None:
        payload = json.loads((EXAMPLES / "c10.example.json").read_text(encoding="utf-8"))
        payload["image"] = "busybox:latest"

        self._assert_invalid(payload)

    def test_scope_grant_rejects_duplicate_broker_audiences(self) -> None:
        payload = json.loads((EXAMPLES / "c10.scope-token.example.json").read_text(encoding="utf-8"))
        payload["scopes"]["broker_audiences"] = ["store", "store"]

        self._assert_invalid(payload)

    def test_scope_grant_rejects_duplicate_capabilities(self) -> None:
        payload = json.loads((EXAMPLES / "c10.scope-token.example.json").read_text(encoding="utf-8"))
        payload["scopes"]["capabilities"] = ["s8.read", "s8.read"]

        self._assert_invalid(payload)

    def test_token_signature_accepts_ed25519_without_relaxing_policy_signatures(self) -> None:
        budget = json.loads((EXAMPLES / "c10.budget-token.example.json").read_text(encoding="utf-8"))
        budget["signature"] = "ed25519:" + "a" * 128
        self._assert_valid(budget)

        policy = json.loads((EXAMPLES / "c10.policy-bundle.example.json").read_text(encoding="utf-8"))
        policy["signature"] = "ed25519:" + "a" * 128
        self._assert_invalid(policy)

    def test_generated_python_binding_points_to_exact_c10_schema_digest(self) -> None:
        contract = CONTRACT_BY_ID["C10"]

        self.assertEqual(contract.version, "4.0.0")
        self.assertEqual(contract.schema, "c10.s10-runtime.schema.json")
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
