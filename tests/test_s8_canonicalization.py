from __future__ import annotations

from pathlib import Path
import unittest

from argus_core import (
    CANONICALIZATION_SPEC,
    CANONICALIZATION_SPEC_VERSION,
    CANONICAL_RECORD_EXCLUDED_FIELDS,
    canonical_record_bytes,
    canonical_record_payload,
    hash_bytes,
)


ROOT = Path(__file__).resolve().parents[1]
SPEC_DOC = ROOT / "docs" / "contracts" / "S8_CANONICALIZATION.md"


class S8CanonicalizationSpecTests(unittest.TestCase):
    def test_spec_version_and_excluded_fields_are_frozen(self) -> None:
        self.assertEqual(CANONICALIZATION_SPEC_VERSION, "argus-jcs-v1")
        self.assertEqual(CANONICALIZATION_SPEC.version, "argus-jcs-v1")
        self.assertEqual(CANONICAL_RECORD_EXCLUDED_FIELDS, ("content_hash", "signature", "created_at"))
        self.assertEqual(CANONICALIZATION_SPEC.excluded_record_fields, CANONICAL_RECORD_EXCLUDED_FIELDS)

    def test_conformance_vector_ignores_order_whitespace_and_excluded_fields(self) -> None:
        left = {
            "artifact_ref": "c4://artifact/a",
            "kind": "model",
            "content_hash": "blake3:old",
            "created_at": "t1",
            "producer": {"subsystem": "S2", "version": "1.0.0"},
        }
        right = {
            "producer": {"version": "1.0.0", "subsystem": "S2"},
            "created_at": "t2",
            "content_hash": "blake3:new",
            "signature": "sig",
            "kind": "model",
            "artifact_ref": "c4://artifact/a",
        }

        self.assertEqual(canonical_record_payload(left), canonical_record_payload(right))
        self.assertEqual(canonical_record_bytes(left), canonical_record_bytes(right))
        self.assertEqual(hash_bytes(canonical_record_bytes(left)), hash_bytes(canonical_record_bytes(right)))

    def test_semantic_record_field_change_changes_canonical_bytes(self) -> None:
        base = {
            "artifact_ref": "c4://artifact/a",
            "kind": "model",
            "producer": {"subsystem": "S2", "version": "1.0.0"},
            "content_hash": "blake3:old",
        }
        changed = {**base, "kind": "dataset"}

        self.assertNotEqual(canonical_record_bytes(base), canonical_record_bytes(changed))
        self.assertNotEqual(hash_bytes(canonical_record_bytes(base)), hash_bytes(canonical_record_bytes(changed)))

    def test_spec_document_matches_code_constants(self) -> None:
        text = SPEC_DOC.read_text(encoding="utf-8")

        self.assertIn(f"`{CANONICALIZATION_SPEC_VERSION}`", text)
        for field in CANONICAL_RECORD_EXCLUDED_FIELDS:
            self.assertIn(f"`{field}`", text)
        self.assertIn("must produce identical canonical bytes", text)
        self.assertIn("must change the canonical bytes", text)


if __name__ == "__main__":
    unittest.main()
