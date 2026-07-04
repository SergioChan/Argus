from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

from pydantic import ValidationError


ROOT = Path(__file__).resolve().parents[1]
BINDINGS_PYTHON = ROOT / "bindings" / "python"
if str(BINDINGS_PYTHON) not in sys.path:
    sys.path.insert(0, str(BINDINGS_PYTHON))

from argus_contracts import (  # noqa: E402
    Acceptance,
    C1_SCHEMA_SHA256,
    CONTRACT_BY_ID,
    SubagentEnvelope,
    validate_acceptance,
    validate_subagent_envelope,
)


C1_EXAMPLE = ROOT / "schemas" / "contracts" / "examples" / "c1.example.json"


class C1GeneratedBindingsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.envelope = json.loads(C1_EXAMPLE.read_text(encoding="utf-8"))

    def test_c1_python_binding_validates_schema_example_and_acceptance(self) -> None:
        envelope = validate_subagent_envelope(self.envelope)
        acceptance = validate_acceptance(
            {
                "job_id": self.envelope["job_id"],
                "accepted": True,
                "reason": None,
                "state": "ACCEPTED",
                "estimated_cost": {"cost_usd": 0.01},
                "idempotency_key": self.envelope["idempotency_key"],
            }
        )

        self.assertIsInstance(envelope, SubagentEnvelope)
        self.assertIsInstance(acceptance, Acceptance)
        self.assertEqual(envelope.method, "accept")
        self.assertEqual(acceptance.job_id, self.envelope["job_id"])
        self.assertEqual(C1_SCHEMA_SHA256, CONTRACT_BY_ID["C1"].schema_sha256)

    def test_c1_python_binding_rejects_schema_violations(self) -> None:
        missing_idempotency = copy.deepcopy(self.envelope)
        missing_idempotency.pop("idempotency_key")
        wrong_major = {**copy.deepcopy(self.envelope), "contract_version": "2.0.0"}
        inconsistent_refusal = {
            "job_id": self.envelope["job_id"],
            "accepted": False,
            "state": "ACCEPTED",
            "idempotency_key": "accept-11111111",
        }

        with self.assertRaises(ValidationError):
            validate_subagent_envelope(missing_idempotency)
        with self.assertRaises(ValidationError):
            validate_subagent_envelope(wrong_major)
        with self.assertRaises(ValidationError):
            validate_acceptance(inconsistent_refusal)

    def test_c1_registry_entry_is_present_in_typescript_and_rust_bindings(self) -> None:
        c1 = CONTRACT_BY_ID["C1"]
        typescript_contracts = (ROOT / "bindings" / "typescript" / "src" / "contracts.ts").read_text(
            encoding="utf-8"
        )
        typescript_c1 = (ROOT / "bindings" / "typescript" / "src" / "c1.ts").read_text(encoding="utf-8")
        rust_lib = (ROOT / "bindings" / "rust" / "src" / "lib.rs").read_text(encoding="utf-8")
        rust_c1 = (ROOT / "bindings" / "rust" / "src" / "c1.rs").read_text(encoding="utf-8")

        self.assertIn('"id": "C1"', typescript_contracts)
        self.assertIn(f'"schema_sha256": "{c1.schema_sha256}"', typescript_contracts)
        self.assertIn(f'export const C1_SCHEMA_SHA256 = "{c1.schema_sha256}"', typescript_c1)
        self.assertIn("pub mod c1;", rust_lib)
        self.assertIn(f'pub const C1_SCHEMA_SHA256: &str = "{c1.schema_sha256}"', rust_c1)

    def test_c1_binding_generator_is_byte_stable_and_drift_checked(self) -> None:
        result = subprocess.run(
            ["python3", "scripts/generate_bindings.py", "--check"],
            cwd=ROOT,
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        spec = importlib.util.spec_from_file_location("generate_bindings", ROOT / "scripts" / "generate_bindings.py")
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        rendered = module.generated_files()
        c1_files = {
            ROOT / "bindings" / "python" / "argus_contracts" / "c1.py",
            ROOT / "bindings" / "typescript" / "src" / "c1.ts",
            ROOT / "bindings" / "rust" / "src" / "c1.rs",
        }

        self.assertTrue(c1_files.issubset(rendered))

        drifted = dict(rendered)
        c1_python = ROOT / "bindings" / "python" / "argus_contracts" / "c1.py"
        drifted[c1_python] = drifted[c1_python] + "\n# synthetic drift\n"
        self.assertEqual(module.check_files(drifted), 1)


if __name__ == "__main__":
    unittest.main()
