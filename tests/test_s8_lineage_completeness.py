from __future__ import annotations

import unittest

from argus_core import (
    InMemoryArtifactStore,
    IncompleteLineageError,
    Lineage,
    Producer,
    assert_lineage_complete,
)


class S8LineageCompletenessGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.producer = Producer(subsystem="S2", version="1.0.0")

    def test_assert_lineage_complete_returns_structured_success(self) -> None:
        result = assert_lineage_complete(
            Lineage(input_refs=(), code_ref="git:abc", environment_digest="oci:abc", seeds=())
        )

        self.assertTrue(result.complete)
        self.assertEqual(result.missing_fields, ())
        self.assertFalse(result.non_promotable)
        self.assertIsNone(result.category)

    def test_missing_lineage_fields_are_reported_together(self) -> None:
        with self.assertRaises(IncompleteLineageError) as raised:
            assert_lineage_complete({"input_refs": ()})

        self.assertEqual(raised.exception.category, "INCOMPLETE_LINEAGE")
        self.assertEqual(
            raised.exception.missing_fields,
            ("lineage.code_ref", "lineage.environment_digest", "lineage.seeds"),
        )
        self.assertTrue(raised.exception.non_promotable)

    def test_create_artifact_rejects_incomplete_lineage_without_record(self) -> None:
        with self.assertRaises(IncompleteLineageError) as raised:
            self.store.create_artifact(
                kind="model",
                payload={"weights": [1]},
                producer=self.producer,
                lineage=Lineage(input_refs=(), code_ref="git:abc", environment_digest=""),
            )

        self.assertEqual(raised.exception.missing_fields, ("lineage.environment_digest",))
        self.assertEqual(len(self.store), 0)

    def test_promoted_predictive_artifact_without_uncertainty_tag_is_non_promotable(self) -> None:
        with self.assertRaises(IncompleteLineageError) as raised:
            self.store.create_artifact(
                kind="model",
                payload={"weights": [1]},
                producer=self.producer,
                lineage=Lineage(input_refs=(), code_ref="git:abc", environment_digest="oci:abc"),
                claim_tier="recapitulated-known",
                validation_report_ref="c4://artifact/report",
            )

        self.assertEqual(raised.exception.missing_fields, ("payload.uncertainty_tag",))
        self.assertTrue(raised.exception.non_promotable)
        self.assertEqual(len(self.store), 0)


if __name__ == "__main__":
    unittest.main()
