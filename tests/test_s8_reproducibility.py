from __future__ import annotations

import unittest

from argus_core import InMemoryArtifactStore, Lineage, Producer, hash_bytes, canonical_json_bytes


class S8ReproducibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.producer = Producer(subsystem="S2", version="0.0.0")
        self.lineage = Lineage(
            input_refs=("c4://artifact/input",),
            code_ref="git:model",
            environment_digest="oci:model",
            seeds=("seed-1",),
        )

    def test_manifest_contains_rederivation_inputs(self) -> None:
        record = self.store.create_artifact(
            kind="model",
            payload=self._payload(metric=1.0),
            producer=self.producer,
            lineage=self.lineage,
        )

        manifest = self.store.get_reproducibility_manifest(record.artifact_ref)

        self.assertEqual(manifest.artifact_ref, record.artifact_ref)
        self.assertEqual(manifest.content_hash, record.content_hash)
        self.assertEqual(manifest.lineage.environment_digest, "oci:model")
        self.assertEqual(manifest.lineage.seeds, ("seed-1",))
        self.assertEqual(
            manifest.nondeterminism_tolerance,
            {
                "comparator_id": "numeric_abs_tolerance",
                "params": {"field": "metric", "abs_tolerance": 0.1},
            },
        )

    def test_rederivation_within_tolerance_records_pass_without_mutating_original(self) -> None:
        record = self.store.create_artifact(
            kind="model",
            payload=self._payload(metric=1.0),
            producer=self.producer,
            lineage=self.lineage,
        )
        original_record = self.store.get_record(record.artifact_ref)
        original_bytes = self.store.get_artifact(record.artifact_ref)
        original_count = len(self.store)

        check = self.store.record_reproducibility_check(
            record.artifact_ref,
            rerun_payload=self._payload(metric=1.05),
            tolerance_id="model-metric-abs-0.1",
        )

        self.assertEqual(check.verdict, "PASS")
        self.assertEqual(check.comparator_id, "numeric_abs_tolerance")
        self.assertAlmostEqual(check.divergence or 0.0, 0.05)
        self.assertNotEqual(check.rerun_content_hash, record.content_hash)
        self.assertEqual(self.store.get_record(record.artifact_ref), original_record)
        self.assertEqual(self.store.get_artifact(record.artifact_ref), original_bytes)
        self.assertEqual(len(self.store), original_count)
        self.assertFalse(self.store.is_non_reproducible(record.artifact_ref))

    def test_rederivation_outside_tolerance_records_fail_and_flags_artifact(self) -> None:
        record = self.store.create_artifact(
            kind="model",
            payload=self._payload(metric=1.0),
            producer=self.producer,
            lineage=self.lineage,
        )

        check = self.store.record_reproducibility_check(
            record.artifact_ref,
            rerun_payload=self._payload(metric=1.25),
            tolerance_id="model-metric-abs-0.1",
        )

        self.assertEqual(check.verdict, "FAIL")
        self.assertAlmostEqual(check.divergence or 0.0, 0.25)
        self.assertTrue(self.store.is_non_reproducible(record.artifact_ref))
        self.assertEqual(len(self.store.reproducibility_checks(record.artifact_ref)), 1)

    def test_hash_equal_default_and_pluggable_comparator(self) -> None:
        deterministic = self.store.create_artifact(
            kind="dataset",
            payload={"value": 1},
            producer=self.producer,
            lineage=Lineage(input_refs=(), code_ref="git:data", environment_digest="oci:data"),
        )
        same_hash = hash_bytes(canonical_json_bytes({"value": 1}))
        different_hash = hash_bytes(canonical_json_bytes({"value": 2}))

        exact = self.store.record_reproducibility_check(
            deterministic.artifact_ref,
            rerun_content_hash=same_hash,
        )
        mismatch = self.store.record_reproducibility_check(
            deterministic.artifact_ref,
            rerun_content_hash=different_hash,
        )

        self.store.register_reproducibility_comparator(
            "accept_declared_external",
            lambda **kwargs: (True, None, None),
        )
        external = self.store.record_reproducibility_check(
            deterministic.artifact_ref,
            rerun_content_hash=different_hash,
            comparator_id="accept_declared_external",
            tolerance_id="external-comparator-v1",
        )

        self.assertEqual(exact.verdict, "PASS")
        self.assertEqual(mismatch.verdict, "FAIL")
        self.assertEqual(external.verdict, "PASS")
        self.assertEqual(external.comparator_id, "accept_declared_external")

    @staticmethod
    def _payload(*, metric: float) -> dict[str, object]:
        return {
            "metric": metric,
            "nondeterminism_tolerance": {
                "comparator_id": "numeric_abs_tolerance",
                "params": {
                    "field": "metric",
                    "abs_tolerance": 0.1,
                },
            },
        }


if __name__ == "__main__":
    unittest.main()
