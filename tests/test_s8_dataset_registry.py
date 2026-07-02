from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from argus_core import (
    DatasetRegistry,
    DatasetRegistryError,
    DatasetSplit,
    FileSystemArtifactStore,
    InMemoryArtifactStore,
    InMemoryTokenService,
    Lineage,
    Producer,
    S8ScopeDeniedError,
    ScopeGrant,
    WriteOnceViolationError,
)


class DatasetRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.registry = DatasetRegistry(artifact_store=self.store)
        self.tokens = InMemoryTokenService(signing_key=b"test-key", now_fn=lambda: 1_000)

    def test_register_dataset_versions_with_typed_splits(self) -> None:
        v1 = self.registry.register(
            dataset_id="ewpt-corpus",
            version="1.0.0",
            splits=(
                self._split("blind", "blind", access_scope="verifier-only", label_seal_ref="c4://labels/blind"),
                self._split("train", "train"),
            ),
            contamination_index_version="contam-2026-07-01",
        )
        v2 = self.registry.register(
            dataset_id="ewpt-corpus",
            version="1.1.0",
            splits=(self._split("train", "train", row_count=12),),
            contamination_index_version="contam-2026-07-02",
        )

        self.assertEqual(self.registry.list_versions("ewpt-corpus"), ("1.0.0", "1.1.0"))
        self.assertEqual(
            self.registry.get("ewpt-corpus", "1.0.0", include_verifier_only_seals=True),
            v1,
        )
        self.assertEqual(self.registry.get("ewpt-corpus"), v2)
        self.assertEqual(v1.provenance_ref.artifact_ref, "c4://dataset/ewpt-corpus/1.0.0")
        self.assertEqual(self.store.get_record(v1.provenance_ref.artifact_ref).kind, "dataset")
        self.assertEqual({split.role for split in v1.splits}, {"blind", "train"})
        self.assertEqual(v1.splits[0].split_id, "blind")

    def test_get_masks_verifier_only_split_refs_by_default(self) -> None:
        self.registry.register(
            dataset_id="ewpt-corpus",
            version="1.0.0",
            splits=(
                self._split("blind", "blind", access_scope="verifier-only", label_seal_ref="c4://labels/blind"),
                self._split("train", "train"),
            ),
            contamination_index_version="contam-2026-07-01",
        )

        visible = self.registry.get("ewpt-corpus", "1.0.0")
        internal = self.registry.get("ewpt-corpus", "1.0.0", include_verifier_only_seals=True)
        visible_by_id = {split.split_id: split for split in visible.splits}
        internal_by_id = {split.split_id: split for split in internal.splits}

        self.assertIsNone(visible_by_id["blind"].content_hash)
        self.assertIsNone(visible_by_id["blind"].label_seal_ref)
        self.assertEqual(visible_by_id["train"].content_hash, "blake3:train")
        self.assertEqual(internal_by_id["blind"].content_hash, "blake3:blind")
        self.assertEqual(internal_by_id["blind"].label_seal_ref, "c4://labels/blind")

    def test_register_is_idempotent_but_conflicting_version_is_rejected(self) -> None:
        first = self.registry.register(
            dataset_id="ewpt-corpus",
            version="1.0.0",
            splits=(self._split("train", "train"),),
            contamination_index_version="contam-2026-07-01",
        )
        second = self.registry.register(
            dataset_id="ewpt-corpus",
            version="1.0.0",
            splits=(self._split("train", "train"),),
            contamination_index_version="contam-2026-07-01",
        )

        with self.assertRaises(WriteOnceViolationError):
            self.registry.register(
                dataset_id="ewpt-corpus",
                version="1.0.0",
                splits=(self._split("train", "train", row_count=99),),
                contamination_index_version="contam-2026-07-01",
            )

        self.assertEqual(first, second)
        self.assertEqual(self.store.record_count, 1)

    def test_invalid_split_roles_and_blind_scope_fail_closed(self) -> None:
        with self.assertRaises(DatasetRegistryError) as role_error:
            self.registry.register(
                dataset_id="ewpt-corpus",
                version="1.0.0",
                splits=(self._split("bad", "shadow"),),
                contamination_index_version="contam-2026-07-01",
            )

        with self.assertRaises(DatasetRegistryError) as scope_error:
            self.registry.register(
                dataset_id="ewpt-corpus",
                version="1.0.0",
                splits=(self._split("blind", "blind", access_scope="agent-readable"),),
                contamination_index_version="contam-2026-07-01",
            )

        self.assertEqual(role_error.exception.category, "DATASET_REGISTRY_INVALID")
        self.assertIn("unsupported split role", role_error.exception.reason)
        self.assertIn("verifier-only", scope_error.exception.reason)
        self.assertEqual(self.store.record_count, 0)

    def test_verifier_only_split_requires_label_seal_ref(self) -> None:
        with self.assertRaises(DatasetRegistryError) as seal_error:
            self.registry.register(
                dataset_id="ewpt-corpus",
                version="1.0.0",
                splits=(self._split("blind", "blind", access_scope="verifier-only"),),
                contamination_index_version="contam-2026-07-01",
            )

        self.assertIn("requires label_seal_ref", seal_error.exception.reason)
        self.assertEqual(self.store.record_count, 0)

    def test_resolve_split_denies_blind_labels_to_non_verifier_scope(self) -> None:
        self.registry.register(
            dataset_id="ewpt-corpus",
            version="1.0.0",
            splits=(
                self._split("blind", "blind", access_scope="verifier-only", label_seal_ref="c4://labels/blind"),
                self._split("train", "train"),
            ),
            contamination_index_version="contam-2026-07-01",
        )
        agent_scope = self._scope(audiences=("store",), datasets=("ewpt-corpus",))

        train = self.registry.resolve_split(
            dataset_id="ewpt-corpus",
            version="1.0.0",
            split_id="train",
            scope_token=agent_scope,
        )
        with self.assertRaises(S8ScopeDeniedError) as denied:
            self.registry.resolve_split(
                dataset_id="ewpt-corpus",
                version="1.0.0",
                split_id="blind",
                scope_token=agent_scope,
            )

        self.assertEqual(train.feature_blob_ref, "blake3:train")
        self.assertIsNone(train.label_blob_ref)
        self.assertEqual(denied.exception.category, "SCOPE_DENIED")
        self.assertNotIn("c4://labels/blind", str(denied.exception))
        self.assertEqual(self.registry.resolve_events[-1].verdict, "DENIED")
        self.assertIsNone(self.registry.resolve_events[-1].label_seal_ref)

    def test_verifier_scope_resolves_blind_label_seal_and_audits(self) -> None:
        self.registry.register(
            dataset_id="ewpt-corpus",
            version="1.0.0",
            splits=(self._split("blind", "blind", access_scope="verifier-only", label_seal_ref="c4://labels/blind"),),
            contamination_index_version="contam-2026-07-01",
        )
        verifier_scope = self._scope(audiences=("verifier",), datasets=("ewpt-corpus@1.0.0",))

        resolved = self.registry.resolve_split(
            dataset_id="ewpt-corpus",
            version=None,
            split_id="blind",
            scope_token=verifier_scope,
        )

        self.assertEqual(resolved.feature_blob_ref, "blake3:blind")
        self.assertEqual(resolved.label_blob_ref, "c4://labels/blind")
        self.assertEqual(resolved.audit_event.event_type, "dataset.split_resolved")
        self.assertEqual(resolved.audit_event.verdict, "ALLOWED")
        self.assertEqual(resolved.audit_event.label_seal_ref, "c4://labels/blind")
        self.assertEqual(resolved.audit_event.requester_audiences, ("verifier",))

    def test_filesystem_store_rebuilds_dataset_index_on_reopen(self) -> None:
        with TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            store = FileSystemArtifactStore(root)
            registry = DatasetRegistry(artifact_store=store)
            registered = registry.register(
                dataset_id="ewpt-corpus",
                version="2.0.0",
                splits=(self._split("train", "train"),),
                contamination_index_version="contam-2026-07-03",
                producer=Producer(subsystem="S6", version="0.0.0"),
                lineage=Lineage(input_refs=(), code_ref="git:dataset", environment_digest="oci:dataset"),
            )

            reopened = DatasetRegistry(artifact_store=FileSystemArtifactStore(root))

            self.assertEqual(reopened.list_versions("ewpt-corpus"), ("2.0.0",))
            self.assertEqual(reopened.get("ewpt-corpus"), registered)

    @staticmethod
    def _split(
        split_id: str,
        role: str,
        *,
        row_count: int = 10,
        access_scope: str = "agent-readable",
        label_seal_ref: str | None = None,
    ) -> DatasetSplit:
        return DatasetSplit(
            split_id=split_id,
            role=role,
            content_hash=f"blake3:{split_id}",
            row_count=row_count,
            schema_ref="c4://schema/ewpt/v1",
            access_scope=access_scope,
            label_seal_ref=label_seal_ref,
        )

    def _scope(self, *, audiences: tuple[str, ...], datasets: tuple[str, ...] = ()) -> object:
        return self.tokens.mint_scope(
            job_id="job-1",
            scopes=ScopeGrant(
                allowed_datasets=datasets,
                broker_audiences=audiences,
            ),
        )


if __name__ == "__main__":
    unittest.main()
