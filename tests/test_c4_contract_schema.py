from __future__ import annotations

from copy import deepcopy
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
from argus_core import (  # noqa: E402
    InMemoryArtifactStore,
    InMemoryObjectStore,
    WRITE_ONCE_BUCKET,
    WriteOnceViolationError,
    publish_c4_schema,
)


SCHEMA_PATH = ROOT / "schemas" / "contracts" / "c4.artifact-record.schema.json"
BASELINE_PATH = ROOT / "schemas" / "contracts" / "compatibility" / "c4.artifact-record.v1.0.0.schema.json"
EXAMPLE_PATH = ROOT / "schemas" / "contracts" / "examples" / "c4.example.json"
MANIFEST_PATH = ROOT / "schemas" / "contracts" / "manifest.json"
COMPATIBILITY_PATH = ROOT / "schemas" / "contracts" / "compatibility.json"


class C4ContractSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        cls.baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        cls.example = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        cls.compatibility = json.loads(COMPATIBILITY_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)

    def test_schema_is_canonical_c4_v1(self) -> None:
        definitions = self.schema["$defs"]

        self.assertEqual(self.schema["x-argus-contract"], {"id": "C4", "owner": "S8", "version": "1.0.0"})
        for name in ("ArtifactRecord", "ArtifactRef", "ClaimTier", "HashRef", "Lineage", "Producer", "RetentionPolicy"):
            self.assertIn(name, definitions)
        for name in ("ArtifactRecord", "Lineage", "Producer", "RetentionPolicy"):
            self.assertFalse(definitions[name]["additionalProperties"])

    def test_example_artifact_record_validates(self) -> None:
        self._assert_valid(self.example)

    def test_c4_v1_schema_matches_frozen_compatibility_baseline(self) -> None:
        self.assertEqual(self.schema, self.baseline)

    def test_lineage_requires_environment_digest(self) -> None:
        payload = json.loads(json.dumps(self.example))
        payload["lineage"].pop("environment_digest")

        self._assert_invalid(payload)

    def test_promoted_tier_requires_validation_report_ref(self) -> None:
        payload = {
            **self.example,
            "claim_tier": "recapitulated-known",
        }
        valid = {
            **payload,
            "validation_report_ref": "c4://report/example",
        }

        self._assert_invalid(payload)
        self._assert_valid(valid)

    def test_nested_records_reject_unknown_fields(self) -> None:
        payload = json.loads(json.dumps(self.example))
        payload["producer"]["extra"] = "not allowed"

        self._assert_invalid(payload)

    def test_generated_python_binding_points_to_exact_c4_schema_digest(self) -> None:
        contract = CONTRACT_BY_ID["C4"]

        self.assertEqual(contract.version, "1.0.0")
        self.assertEqual(contract.schema, "c4.artifact-record.schema.json")
        self.assertEqual(contract.schema_sha256, self._schema_sha256(self.schema))

    def test_c4_schema_publication_writes_immutable_artifact(self) -> None:
        object_store = InMemoryObjectStore()
        store = InMemoryArtifactStore(object_store=object_store)

        publication = publish_c4_schema(
            store,
            schema=self.schema,
            manifest=self.manifest,
            compatibility=self.compatibility,
            baseline_schema=self.baseline,
            created_at="2026-07-02T00:00:00Z",
        )
        republished = publish_c4_schema(
            store,
            schema=self.schema,
            manifest=self.manifest,
            compatibility=self.compatibility,
            baseline_schema=self.baseline,
            created_at="2026-07-02T00:00:01Z",
        )

        self.assertEqual(publication, republished)
        self.assertEqual(publication.artifact_ref, "c4://schema/C4/1.0.0")
        self.assertEqual(publication.schema_sha256, self._schema_sha256(self.schema))
        self.assertEqual(store.bucket_class_for_artifact(publication.artifact_ref), WRITE_ONCE_BUCKET)
        self.assertEqual(store.object_count, 1)
        record = store.get_artifact_record(publication.artifact_ref)
        self.assertEqual(record.kind, "schema")
        self.assertEqual(record.producer.subsystem, "S8")
        self.assertEqual(record.lineage.environment_digest, publication.schema_sha256)
        payload = json.loads(store.get_artifact(publication.artifact_ref).decode("utf-8"))
        self.assertEqual(payload["publication_type"], "contract_schema")
        self.assertEqual(payload["contract_id"], "C4")
        self.assertEqual(payload["schema"], self.schema)
        self.assertEqual(payload["schema_sha256"], publication.schema_sha256)
        self.assertEqual(payload["baseline_schema_sha256"], publication.baseline_schema_sha256)

    def test_c4_schema_publication_rejects_source_drift_from_frozen_baseline(self) -> None:
        changed_schema = deepcopy(self.schema)
        changed_schema["title"] = "Changed C4 schema"

        with self.assertRaisesRegex(ValueError, "frozen v1 compatibility baseline"):
            publish_c4_schema(
                InMemoryArtifactStore(),
                schema=changed_schema,
                manifest=self.manifest,
                compatibility=self.compatibility,
                baseline_schema=self.baseline,
            )

    def test_c4_schema_publication_rejects_second_payload_for_same_version(self) -> None:
        store = InMemoryArtifactStore()
        publish_c4_schema(
            store,
            schema=self.schema,
            manifest=self.manifest,
            compatibility=self.compatibility,
            baseline_schema=self.baseline,
        )
        changed_schema = deepcopy(self.schema)
        changed_schema["title"] = "Changed C4 schema"

        with self.assertRaises(WriteOnceViolationError) as raised:
            publish_c4_schema(
                store,
                schema=changed_schema,
                manifest=self.manifest,
                compatibility=self.compatibility,
                baseline_schema=changed_schema,
            )

        self.assertEqual(raised.exception.category, "IMMUTABLE_VIOLATION")

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
