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

from argus_contracts import C4_SCHEMA_SHA256, CONTRACT_BY_ID, validate_artifact_record  # noqa: E402
from argus_core.hashing import hash_bytes  # noqa: E402


C4_EXAMPLE = ROOT / "schemas" / "contracts" / "examples" / "c4.example.json"
S8_BINDING_VECTOR = b"argus-s8-binding-vector"
S8_BINDING_VECTOR_HASH = "blake3:7e2fc64a9cc052211dfe7f54f2432c35588950f43d92bb08c87bbd182823d8d1"


class S8GeneratedBindingsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.example = json.loads(C4_EXAMPLE.read_text(encoding="utf-8"))

    def test_c4_python_binding_validates_schema_example(self) -> None:
        record = validate_artifact_record(self.example)

        self.assertEqual(record.artifact_ref, self.example["artifact_ref"])
        self.assertEqual(record.hash_algorithm, "BLAKE3")
        self.assertEqual(C4_SCHEMA_SHA256, CONTRACT_BY_ID["C4"].schema_sha256)

    def test_c4_python_binding_rejects_schema_violations(self) -> None:
        missing_environment = copy.deepcopy(self.example)
        missing_environment["lineage"].pop("environment_digest")
        duplicate_inputs = copy.deepcopy(self.example)
        duplicate_inputs["lineage"]["input_refs"] = ["c4://artifact/a", "c4://artifact/a"]
        promoted_without_report = {
            **copy.deepcopy(self.example),
            "claim_tier": "novel-needs-human",
        }

        with self.assertRaises(ValidationError):
            validate_artifact_record(missing_environment)
        with self.assertRaises(ValidationError):
            validate_artifact_record(duplicate_inputs)
        with self.assertRaises(ValidationError):
            validate_artifact_record(promoted_without_report)

    def test_binding_generator_is_byte_stable(self) -> None:
        result = subprocess.run(
            ["python3", "scripts/generate_bindings.py", "--check"],
            cwd=ROOT,
            check=False,
            text=True,
            capture_output=True,
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_binding_generator_renders_same_bytes_across_repeated_runs(self) -> None:
        spec = importlib.util.spec_from_file_location("generate_bindings", ROOT / "scripts" / "generate_bindings.py")
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        first = module.generated_files()
        second = module.generated_files()

        self.assertEqual(set(first), set(second))
        self.assertEqual(first, second)
        rendered = {path.relative_to(ROOT).as_posix(): content for path, content in first.items()}
        for required in (
            "bindings/python/argus_contracts/c4.py",
            "bindings/typescript/src/c4.ts",
            "bindings/rust/src/c4.rs",
        ):
            self.assertIn(required, rendered)
            self.assertIn(C4_SCHEMA_SHA256, rendered[required])

    def test_python_hash_vector_matches_s8_binding_vector(self) -> None:
        self.assertEqual(hash_bytes(b""), "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
        self.assertEqual(hash_bytes(S8_BINDING_VECTOR), S8_BINDING_VECTOR_HASH)


if __name__ == "__main__":
    unittest.main()
