from __future__ import annotations

import copy
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
    C10_SCHEMA_SHA256,
    CONTRACT_BY_ID,
    validate_launch_request,
    validate_policy_bundle,
)


C10_EXAMPLE = ROOT / "schemas" / "contracts" / "examples" / "c10.example.json"
C10_POLICY_EXAMPLE = ROOT / "schemas" / "contracts" / "examples" / "c10.policy-bundle.example.json"


class S10GeneratedBindingsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.launch_request = json.loads(C10_EXAMPLE.read_text(encoding="utf-8"))
        self.policy_bundle = json.loads(C10_POLICY_EXAMPLE.read_text(encoding="utf-8"))

    def test_c10_python_binding_validates_launch_request_and_policy_samples(self) -> None:
        launch_request = validate_launch_request(self.launch_request)
        policy_bundle = validate_policy_bundle(self.policy_bundle)

        self.assertEqual(launch_request.image, self.launch_request["image"])
        self.assertEqual(launch_request.budget_token.job_id, "job-s10-golden")
        self.assertEqual(policy_bundle.risk_to_runtime["standard"], "gvisor")
        self.assertEqual(C10_SCHEMA_SHA256, CONTRACT_BY_ID["C10"].schema_sha256)

    def test_c10_python_binding_rejects_schema_violations(self) -> None:
        tag_only_image = {**copy.deepcopy(self.launch_request), "image": "busybox:latest"}
        duplicate_allowlist = copy.deepcopy(self.launch_request)
        duplicate_allowlist["env_allowlist"] = ["ARGUS_MODE", "ARGUS_MODE"]
        bad_policy_signature = {**copy.deepcopy(self.policy_bundle), "signature": "hmac-sha256:bad"}

        with self.assertRaises(ValidationError):
            validate_launch_request(tag_only_image)
        with self.assertRaises(ValidationError):
            validate_launch_request(duplicate_allowlist)
        with self.assertRaises(ValidationError):
            validate_policy_bundle(bad_policy_signature)

    def test_c10_registry_entry_is_present_in_typescript_and_rust_bindings(self) -> None:
        c10 = CONTRACT_BY_ID["C10"]
        typescript_contracts = (ROOT / "bindings" / "typescript" / "src" / "contracts.ts").read_text(
            encoding="utf-8"
        )
        typescript_s10 = (ROOT / "bindings" / "typescript" / "src" / "s10.ts").read_text(encoding="utf-8")
        rust_lib = (ROOT / "bindings" / "rust" / "src" / "lib.rs").read_text(encoding="utf-8")
        rust_s10 = (ROOT / "bindings" / "rust" / "src" / "s10.rs").read_text(encoding="utf-8")

        self.assertIn('"id": "C10"', typescript_contracts)
        self.assertIn(f'"schema_sha256": "{c10.schema_sha256}"', typescript_contracts)
        self.assertIn(f'export const C10_SCHEMA_SHA256 = "{c10.schema_sha256}"', typescript_s10)
        self.assertIn('id: "C10"', rust_lib)
        self.assertIn(f'pub const C10_SCHEMA_SHA256: &str = "{c10.schema_sha256}"', rust_s10)

    def test_binding_generator_is_byte_stable_after_c10_generation(self) -> None:
        result = subprocess.run(
            ["python3", "scripts/generate_bindings.py", "--check"],
            cwd=ROOT,
            check=False,
            text=True,
            capture_output=True,
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)


if __name__ == "__main__":
    unittest.main()
