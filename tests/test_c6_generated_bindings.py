from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BINDINGS_PYTHON = ROOT / "bindings" / "python"
if str(BINDINGS_PYTHON) not in sys.path:
    sys.path.insert(0, str(BINDINGS_PYTHON))

from argus_contracts import CONTRACT_BY_ID  # noqa: E402


class C6GeneratedBindingsTests(unittest.TestCase):
    def test_c6_schema_digest_is_present_in_python_typescript_and_rust_bindings(self) -> None:
        c6 = CONTRACT_BY_ID["C6"]
        typescript = (ROOT / "bindings" / "typescript" / "src" / "contracts.ts").read_text(encoding="utf-8")
        rust = (ROOT / "bindings" / "rust" / "src" / "lib.rs").read_text(encoding="utf-8")

        self.assertEqual(c6.schema, "c6.compute-adapter.schema.json")
        self.assertTrue(c6.schema_sha256.startswith("sha256:"))
        self.assertIn('"id": "C6"', typescript)
        self.assertIn(f'"schema_sha256": "{c6.schema_sha256}"', typescript)
        self.assertIn('id: "C6"', rust)
        self.assertIn(f'schema_sha256: "{c6.schema_sha256}"', rust)

    def test_c6_binding_digest_matches_manifest_generated_payload(self) -> None:
        manifest = json.loads((ROOT / "schemas" / "contracts" / "manifest.json").read_text(encoding="utf-8"))
        manifest_c6 = next(contract for contract in manifest["contracts"] if contract["id"] == "C6")
        binding_c6 = CONTRACT_BY_ID["C6"]

        self.assertEqual(binding_c6.version, manifest_c6["version"])
        self.assertEqual(binding_c6.schema, manifest_c6["schema"])


if __name__ == "__main__":
    unittest.main()
