from __future__ import annotations

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from argus_core import (
    InMemoryArtifactStore,
    InMemoryRegistry,
    SubagentDescriptor,
    build_s1_capability_descriptor,
    publish_s1_capability_descriptor,
)


ROOT = Path(__file__).resolve().parents[1]
C5_SCHEMA_PATH = ROOT / "schemas" / "contracts" / "c5.capability-descriptor.schema.json"


class S1CapabilityDescriptorRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(C5_SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)

    def setUp(self) -> None:
        self.subagent_descriptor = SubagentDescriptor(
            subagent_id="s1-ewpt-reference",
            contract_version="1.0.0",
            subtopics=("ewpt", "gw-spectrum"),
            required_adapters=("adapter:bounce", "adapter:gw"),
        )

    def test_builder_emits_schema_valid_c5_descriptor_for_s1_subagent(self) -> None:
        descriptor = build_s1_capability_descriptor(
            self.subagent_descriptor,
            revision=1,
            independence_tags=("impl-reference",),
        )

        payload = descriptor.as_c5_payload()
        self._assert_valid(payload)
        self.assertEqual(payload["entity_id"], "s1-ewpt-reference")
        self.assertEqual(payload["kind"], "subagent")
        self.assertEqual(payload["owner_subsystem"], "S1")
        self.assertEqual(payload["contract_versions"], {"C1": "1.0.0", "C5": "1.0.0"})
        self.assertEqual(payload["subtopics"], ["ewpt", "gw-spectrum"])
        self.assertEqual(payload["capability_scopes"], ["c1.accept", "c1.plan", "c1.build", "c1.validate", "c1.report"])
        self.assertEqual(payload["independence_tags"], ["impl-reference"])
        self.assertNotIn("conformance_level", payload)

    def test_publish_writes_schema_valid_descriptor_artifact_and_registry_resolution(self) -> None:
        store = InMemoryArtifactStore()
        registry = InMemoryRegistry(artifact_store=store)

        published = publish_s1_capability_descriptor(
            registry,
            self.subagent_descriptor,
            revision=1,
            independence_tags=("impl-reference",),
        )

        self.assertNotEqual(published.provenance_ref, "c4://pending")
        self.assertEqual(published.conformance_level, None)
        record = store.get_record(published.provenance_ref)
        payload = json.loads(store.get_artifact(published.provenance_ref).decode("utf-8"))

        self.assertEqual(record.kind, "capability_descriptor")
        self._assert_valid(payload)
        self.assertEqual(payload["entity_id"], self.subagent_descriptor.subagent_id)
        self.assertEqual(registry.get(self.subagent_descriptor.subagent_id), published)
        resolution = registry.resolve(kind="subagent", subtopic="ewpt", required_scope="c1.build")
        self.assertEqual(resolution.descriptors, (published,))
        self.assertEqual(registry.events[-1].event_type, "s6.registry.published")

    def test_publish_rejects_descriptor_that_cannot_satisfy_s1_accept_scope(self) -> None:
        store = InMemoryArtifactStore()
        registry = InMemoryRegistry(artifact_store=store)

        with self.assertRaisesRegex(ValueError, "c1.accept"):
            publish_s1_capability_descriptor(
                registry,
                self.subagent_descriptor,
                revision=1,
                capability_scopes=("c1.plan", "c1.build"),
                independence_tags=("impl-reference",),
            )

        self.assertEqual(registry.events, ())
        self.assertEqual(store.record_count, 0)

    def _assert_valid(self, payload: dict[str, object]) -> None:
        errors = sorted(self.validator.iter_errors(payload), key=lambda error: list(error.path))
        self.assertEqual(errors, [], msg=[error.message for error in errors])


if __name__ == "__main__":
    unittest.main()
