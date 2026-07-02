from __future__ import annotations

import unittest

from argus_core import (
    ExternalSourceRef,
    ExternalSourceRegistry,
    InMemoryArtifactStore,
    WriteOnceViolationError,
)


class S8ExternalSourceRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.registry = ExternalSourceRegistry(artifact_store=self.store)
        self.source = ExternalSourceRef(
            source="arxiv",
            external_id="2401.00001",
            url="https://arxiv.org/abs/2401.00001",
            snapshot_hash="blake3:" + "a" * 64,
            ingested_at="2026-07-01T00:00:00Z",
            license="arXiv",
        )

    def test_register_and_get_external_source_ref(self) -> None:
        record = self.registry.register(self.source)

        self.assertEqual(record.kind, "external_source")
        self.assertEqual(record.artifact_ref, "c4://external_source/arxiv:2401.00001")
        self.assertEqual(self.registry.get(self.source.source_id), self.source)

    def test_register_same_external_source_is_idempotent(self) -> None:
        first = self.registry.register(self.source)
        second = self.registry.register(self.source)

        self.assertEqual(first, second)
        self.assertEqual(self.store.object_count, 1)
        self.assertEqual(self.store.record_count, 1)

    def test_reregister_different_snapshot_is_immutable_violation(self) -> None:
        original = self.registry.register(self.source)
        changed = ExternalSourceRef(
            source=self.source.source,
            external_id=self.source.external_id,
            url=self.source.url,
            snapshot_hash="blake3:" + "b" * 64,
            ingested_at=self.source.ingested_at,
            license=self.source.license,
        )

        with self.assertRaises(WriteOnceViolationError) as raised:
            self.registry.register(changed)

        self.assertEqual(raised.exception.category, "IMMUTABLE_VIOLATION")
        self.assertEqual(self.registry.get(self.source.source_id), self.source)
        self.assertEqual(self.store.get_record(original.artifact_ref), original)


if __name__ == "__main__":
    unittest.main()
