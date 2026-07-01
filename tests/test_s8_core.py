from __future__ import annotations

import unittest

from argus_core import (
    BLAKE3_PREFIX,
    HashMismatchError,
    IllegalTierError,
    InMemoryArtifactStore,
    IncompleteLineageError,
    Lineage,
    Producer,
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
        self.assertEqual(self.store.get_record(record.artifact_ref), record)

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
        self.store._objects[record.artifact_ref] = b'{"weights":[2]}'

        with self.assertRaises(HashMismatchError):
            self.store.get_artifact(record.artifact_ref)


if __name__ == "__main__":
    unittest.main()
