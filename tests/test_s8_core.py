from __future__ import annotations

from dataclasses import replace
import unittest

from argus_core import (
    BLAKE3_PREFIX,
    CycleDetectedError,
    HashMismatchError,
    IllegalTierError,
    InMemoryArtifactStore,
    IncompleteLineageError,
    Lineage,
    Producer,
    WriteOnceViolationError,
    canonical_json_bytes,
    hash_bytes,
    hash_json,
)


class CanonicalJsonTests(unittest.TestCase):
    def test_canonical_json_is_key_order_stable(self) -> None:
        left = canonical_json_bytes({"b": 2, "a": {"d": 4, "c": 3}})
        right = canonical_json_bytes({"a": {"c": 3, "d": 4}, "b": 2})

        self.assertEqual(left, right)
        self.assertEqual(left, b'{"a":{"c":3,"d":4},"b":2}')


class Blake3HashTests(unittest.TestCase):
    def test_hash_bytes_uses_c4_prefix_and_known_blake3_vector(self) -> None:
        self.assertEqual(
            hash_bytes(b""),
            f"{BLAKE3_PREFIX}af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        )

    def test_hash_json_is_key_order_stable(self) -> None:
        left = hash_json({"b": 2, "a": 1})
        right = hash_json({"a": 1, "b": 2})

        self.assertEqual(left, right)
        self.assertTrue(left.startswith(BLAKE3_PREFIX))


class InMemoryArtifactStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.producer = Producer(subsystem="S2", version="0.0.0")
        self.lineage = Lineage(
            input_refs=("c4://dataset/example",),
            code_ref="git:example",
            environment_digest="oci:sha256-example",
            seeds=("seed-1",),
        )

    def test_create_artifact_commits_complete_lineage(self) -> None:
        record = self.store.create_artifact(
            kind="model",
            payload={"weights": [1, 2, 3]},
            producer=self.producer,
            lineage=self.lineage,
        )

        self.assertEqual(record.claim_tier, "ran-toy")
        self.assertEqual(len(self.store), 1)
        self.assertEqual(self.store.object_count, 1)
        self.assertEqual(self.store.record_count, 1)
        self.assertEqual(self.store.get_record(record.artifact_ref), record)

    def test_identical_record_commit_is_idempotent(self) -> None:
        first = self.store.create_artifact(
            kind="model",
            payload={"weights": [1, 2, 3]},
            producer=self.producer,
            lineage=self.lineage,
        )
        second = self.store.create_artifact(
            kind="model",
            payload={"weights": [1, 2, 3]},
            producer=self.producer,
            lineage=self.lineage,
        )

        self.assertEqual(first, second)
        self.assertEqual(self.store.object_count, 1)
        self.assertEqual(self.store.record_count, 1)
        self.assertTrue(self.store.verify_audit_chain().valid)

    def test_content_addressed_dedup_allows_distinct_records(self) -> None:
        dataset = self.store.create_artifact(
            kind="dataset",
            payload={"same": True},
            producer=self.producer,
            lineage=Lineage(input_refs=(), code_ref="git:data", environment_digest="oci:data"),
        )
        model = self.store.create_artifact(
            kind="model",
            payload={"same": True},
            producer=self.producer,
            lineage=Lineage(
                input_refs=(dataset.artifact_ref,),
                code_ref="git:model",
                environment_digest="oci:model",
            ),
        )

        self.assertNotEqual(dataset.artifact_ref, model.artifact_ref)
        self.assertEqual(dataset.content_hash, model.content_hash)
        self.assertEqual(self.store.object_count, 1)
        self.assertEqual(self.store.record_count, 2)

    def test_explicit_ref_is_write_once(self) -> None:
        artifact_ref = "c4://artifact/fixed-ref"
        self.store.create_artifact(
            artifact_ref=artifact_ref,
            kind="model",
            payload={"weights": [1]},
            producer=self.producer,
            lineage=self.lineage,
        )

        with self.assertRaises(WriteOnceViolationError):
            self.store.create_artifact(
                artifact_ref=artifact_ref,
                kind="model",
                payload={"weights": [2]},
                producer=self.producer,
                lineage=self.lineage,
            )

    def test_incomplete_lineage_fails_closed(self) -> None:
        with self.assertRaises(IncompleteLineageError):
            self.store.create_artifact(
                kind="model",
                payload={"weights": [1]},
                producer=self.producer,
                lineage=Lineage(input_refs=(), code_ref="", environment_digest="oci:sha256-example"),
            )

        self.assertEqual(len(self.store), 0)

    def test_promoted_tier_requires_validation_report(self) -> None:
        with self.assertRaises(IllegalTierError):
            self.store.create_artifact(
                kind="model",
                payload={"weights": [1]},
                producer=self.producer,
                lineage=self.lineage,
                claim_tier="recapitulated-known",
            )

    def test_verify_on_read_detects_tampering(self) -> None:
        record = self.store.create_artifact(
            kind="model",
            payload={"weights": [1]},
            producer=self.producer,
            lineage=self.lineage,
        )
        self.store._objects[record.content_hash] = b'{"weights":[2]}'

        with self.assertRaises(HashMismatchError):
            self.store.get_artifact(record.artifact_ref)

    def test_self_cycle_is_rejected(self) -> None:
        artifact_ref = "c4://artifact/self-cycle"

        with self.assertRaises(CycleDetectedError):
            self.store.create_artifact(
                artifact_ref=artifact_ref,
                kind="model",
                payload={"weights": [1]},
                producer=self.producer,
                lineage=Lineage(
                    input_refs=(artifact_ref,),
                    code_ref="git:cycle",
                    environment_digest="oci:cycle",
                ),
            )

    def test_lineage_query_and_impact_set_follow_transitive_edges(self) -> None:
        source = self.store.create_artifact(
            kind="external_source",
            payload={"source": "paper"},
            producer=Producer(subsystem="S6", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:ingest", environment_digest="oci:ingest"),
        )
        dataset = self.store.create_artifact(
            kind="dataset",
            payload={"rows": [1]},
            producer=Producer(subsystem="S6", version="0.0.0"),
            lineage=Lineage(
                input_refs=(source.artifact_ref,),
                code_ref="git:normalize",
                environment_digest="oci:normalize",
            ),
        )
        model = self.store.create_artifact(
            kind="model",
            payload={"weights": [1]},
            producer=self.producer,
            lineage=Lineage(
                input_refs=(dataset.artifact_ref,),
                code_ref="git:train",
                environment_digest="oci:train",
            ),
        )

        lineage_graph = self.store.get_lineage(model.artifact_ref, direction="ancestors")
        lineage_refs = {node.artifact_ref for node in lineage_graph.nodes}
        impact_refs = {record.artifact_ref for record in self.store.query_impact_set((source.artifact_ref,))}

        self.assertEqual(lineage_refs, {source.artifact_ref, dataset.artifact_ref, model.artifact_ref})
        self.assertEqual(impact_refs, {dataset.artifact_ref, model.artifact_ref})
        self.assertEqual(len(lineage_graph.edges), 2)

    def test_audit_slice_and_chain_detect_record_tampering(self) -> None:
        source = self.store.create_artifact(
            kind="external_source",
            payload={"source": "paper"},
            producer=Producer(subsystem="S6", version="0.0.0"),
            lineage=Lineage(input_refs=(), code_ref="git:ingest", environment_digest="oci:ingest"),
        )
        dataset = self.store.create_artifact(
            kind="dataset",
            payload={"rows": [1]},
            producer=Producer(subsystem="S6", version="0.0.0"),
            lineage=Lineage(
                input_refs=(source.artifact_ref,),
                code_ref="git:normalize",
                environment_digest="oci:normalize",
            ),
        )

        audit_slice = self.store.export_audit_slice((dataset.artifact_ref,))

        self.assertTrue(self.store.verify_audit_slice(audit_slice).valid)
        self.assertTrue(self.store.verify_audit_chain().valid)

        self.store._records[dataset.artifact_ref] = replace(dataset, kind="tampered")

        slice_verification = self.store.verify_audit_slice(audit_slice)
        chain_verification = self.store.verify_audit_chain()
        self.assertFalse(slice_verification.valid)
        self.assertFalse(chain_verification.valid)
        self.assertEqual(chain_verification.break_sequence, 2)


if __name__ == "__main__":
    unittest.main()
