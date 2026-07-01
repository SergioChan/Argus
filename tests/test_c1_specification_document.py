from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "contracts" / "c1.subagent.schema.json"
SPEC_PATH = ROOT / "docs" / "contracts" / "C1_SPECIFICATION.md"


class C1SpecificationDocumentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        cls.spec = SPEC_PATH.read_text(encoding="utf-8")
        cls.definitions = cls.schema["$defs"]

    def test_spec_metadata_matches_canonical_schema(self) -> None:
        metadata = self.schema["x-argus-contract"]

        self.assertIn(f"| Contract id | `{metadata['id']}` |", self.spec)
        self.assertIn(f"| Owner | `{metadata['owner']}` |", self.spec)
        self.assertIn(f"| Version | `{metadata['version']}` |", self.spec)
        self.assertIn("schemas/contracts/c1.subagent.schema.json", self.spec)

    def test_spec_lists_every_public_definition_from_schema(self) -> None:
        for definition_name in sorted(self.definitions):
            self.assertIn(f"`{definition_name}`", self.spec)

    def test_spec_lists_lifecycle_states_methods_errors_and_refusal_reasons(self) -> None:
        for state in self.definitions["LifecycleState"]["enum"]:
            self.assertIn(f"`{state}`", self.spec)
        for method in self.definitions["LifecycleMethod"]["enum"]:
            self.assertIn(f"`{method}`", self.spec)
        for category in self.definitions["TypedError"]["properties"]["category"]["enum"]:
            self.assertIn(f"`{category}`", self.spec)
        for reason in self.definitions["Acceptance"]["properties"]["reason"]["enum"]:
            if reason is None:
                self.assertIn("`null`", self.spec)
            else:
                self.assertIn(f"`{reason}`", self.spec)

    def test_spec_documents_c1_migration_policy_and_cross_owner_review(self) -> None:
        required_fragments = (
            "Patch changes",
            "Minor changes may add optional fields",
            "Breaking wire changes require a major version bump",
            "dual-served only inside an explicit migration window",
            "`VERSION_UNSUPPORTED`",
            "scripts/schema_compatibility.py",
            "S1-TC-09",
            "S1-TC-10",
            "S1-TC-11",
            "`S5`",
            "`S3`",
            "`S12`",
        )

        for fragment in required_fragments:
            self.assertIn(fragment, self.spec)


if __name__ == "__main__":
    unittest.main()
