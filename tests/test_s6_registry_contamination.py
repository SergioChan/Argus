from __future__ import annotations

import unittest

from argus_core import (
    CapabilityDescriptor,
    ContaminationIndex,
    DescriptorRevokedError,
    HashMismatchError,
    InMemoryArtifactStore,
    InMemoryRegistry,
    RegistryError,
    SourceDocument,
)


class S6RegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.registry = InMemoryRegistry(artifact_store=self.store)

    def test_publish_writes_descriptor_artifact_and_gets_latest_revision(self) -> None:
        descriptor = self._descriptor("adapter-a", revision=1, tags=("impl-a",), provenance_ref="c4://pending")

        published = self.registry.publish(descriptor)
        fetched = self.registry.get("adapter-a")

        self.assertEqual(fetched, published)
        self.assertNotEqual(published.provenance_ref, "c4://pending")
        self.assertEqual(self.store.get_record(published.provenance_ref).kind, "capability_descriptor")
        self.assertEqual(self.registry.events[-1].event_type, "s6.registry.published")

    def test_descriptor_revision_is_immutable(self) -> None:
        descriptor = self._descriptor("adapter-a", revision=1, tags=("impl-a",))
        self.registry.publish(descriptor)

        with self.assertRaises(RegistryError):
            self.registry.publish(self._descriptor("adapter-a", revision=1, tags=("impl-b",)))

    def test_resolve_filters_active_subtopic_scope_and_excluded_lineage(self) -> None:
        self.registry.publish(self._descriptor("adapter-a", revision=1, tags=("impl-a",), scopes=("evaluate",)))
        self.registry.publish(self._descriptor("adapter-b", revision=1, tags=("impl-b",), scopes=("evaluate",)))
        self.registry.publish(
            self._descriptor("adapter-c", revision=1, tags=("impl-c",), scopes=("describe",), status="deprecated")
        )

        resolution = self.registry.resolve(
            kind="adapter",
            subtopic="ewpt",
            required_scope="evaluate",
            excluded_independence_tags=("impl-a",),
        )

        self.assertEqual([descriptor.entity_id for descriptor in resolution.descriptors], ["adapter-b"])
        self.assertEqual(resolution.pinned_revisions, {"adapter-b": 1})

    def test_revoke_hides_descriptor_and_blocks_republish(self) -> None:
        self.registry.publish(self._descriptor("adapter-a", revision=1, tags=("impl-a",)))

        revoked = self.registry.revoke("adapter-a")
        resolution = self.registry.resolve(kind="adapter", subtopic="ewpt")

        self.assertEqual(revoked.status, "revoked")
        self.assertEqual(resolution.descriptors, ())
        self.assertEqual(self.registry.events[-1].event_type, "s6.registry.revoked")
        with self.assertRaises(DescriptorRevokedError):
            self.registry.publish(self._descriptor("adapter-a", revision=3, tags=("impl-a",)))

    def test_independence_attestation_requires_disjoint_minimum(self) -> None:
        self.registry.publish(self._descriptor("adapter-a", revision=1, tags=("impl-a",)))
        self.registry.publish(self._descriptor("adapter-b", revision=1, tags=("impl-b",)))
        self.registry.publish(self._descriptor("adapter-c", revision=1, tags=("impl-b",)))

        passing = self.registry.attest_independence(
            kind="adapter",
            subtopic="ewpt",
            excluded_independence_tags=("builder-impl",),
            min_independent=2,
        )
        failing = self.registry.attest_independence(
            kind="adapter",
            subtopic="ewpt",
            excluded_independence_tags=("builder-impl", "impl-a"),
            min_independent=2,
        )

        self.assertTrue(passing.lineage_disjoint)
        self.assertFalse(passing.correlation_warning)
        self.assertEqual(passing.selected_entity_ids, ("adapter-a", "adapter-b"))
        self.assertFalse(failing.lineage_disjoint)
        self.assertTrue(failing.correlation_warning)

    @staticmethod
    def _descriptor(
        entity_id: str,
        *,
        revision: int,
        tags: tuple[str, ...],
        scopes: tuple[str, ...] = ("evaluate",),
        provenance_ref: str = "c4://descriptor/example",
        status: str = "active",
    ) -> CapabilityDescriptor:
        return CapabilityDescriptor(
            entity_id=entity_id,
            revision=revision,
            kind="adapter",
            owner_subsystem="S7",
            contract_versions={"C5": "1.0.0", "C6": "1.0.0"},
            trust_class="internal",
            capability_scopes=scopes,
            provenance_ref=provenance_ref,
            subtopics=("ewpt",),
            independence_tags=tags,
            conformance_level="gold",
            status=status,
        )


class S6ContaminationIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.index = ContaminationIndex(artifact_store=self.store)

    def test_freeze_writes_snapshot_and_query_flags_overlap(self) -> None:
        snapshot = self.index.freeze(
            version="2026-07-01",
            documents=(
                SourceDocument(
                    doc_id="paper-1",
                    text="electroweak phase transition gravitational wave spectrum benchmark",
                    source_ref="c4://source/paper-1",
                ),
                SourceDocument(
                    doc_id="paper-2",
                    text="higgs observable collider fast simulation",
                    source_ref="c4://source/paper-2",
                ),
            ),
        )

        result = self.index.query(
            snapshot=snapshot,
            text="electroweak phase transition gravitational wave spectrum",
            threshold=0.5,
        )

        self.assertTrue(self.index.verify_snapshot(snapshot))
        self.assertTrue(result.leakage)
        self.assertEqual(result.matched_doc_id, "paper-1")
        self.assertEqual(self.store.get_record(snapshot.snapshot_ref).kind, "contamination_index")

    def test_snapshot_integrity_fails_closed_on_tamper(self) -> None:
        snapshot = self.index.freeze(
            version="2026-07-01",
            documents=(SourceDocument(doc_id="paper-1", text="known result", source_ref="c4://source/paper-1"),),
        )
        record = self.store.get_record(snapshot.snapshot_ref)
        self.store._objects[record.content_hash] = b'{"tampered":true}'

        with self.assertRaises(HashMismatchError):
            self.index.verify_snapshot(snapshot)


if __name__ == "__main__":
    unittest.main()
