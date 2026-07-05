from __future__ import annotations

import json
import unittest

from argus_core import (
    DataManager,
    DataSplitRequest,
    InMemoryArtifactStore,
    Lineage,
    Producer,
    ProvenanceEmitter,
    S2ContractModelError,
)


class S2DataManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.emitter = ProvenanceEmitter(artifact_store=self.store)

    def test_deterministic_split_reproducibility_emits_c4_manifest(self) -> None:
        dataset = self._dataset(rows=self._rows(10))
        manager = DataManager(artifact_store=self.store, provenance_emitter=self.emitter)
        request = self._request(dataset_ref=dataset.artifact_ref, seed="split-seed-42")

        first = manager.create_splits(request)
        second = manager.create_splits(request)

        self.assertEqual(first.split_indices, second.split_indices)
        self.assertEqual(first.split_manifest_ref, second.split_manifest_ref)
        self.assertEqual(first.split_indices["train"], (0, 2, 4, 5, 7, 9))
        self.assertEqual(first.split_indices["validation"], (1, 3))
        self.assertEqual(first.split_indices["test"], (6, 8))
        record = self.store.get_record(first.split_manifest_ref)
        payload = self._payload(first.split_manifest_ref)
        self.assertEqual(record.kind, "dataset_split")
        self.assertEqual(record.lineage.input_refs, (dataset.artifact_ref,))
        self.assertEqual(payload["split_seed"], "split-seed-42")
        self.assertFalse(payload["label_policy"]["materialized"])
        self.assertNotIn(b"secret-label-", self.store.get_artifact(first.split_manifest_ref))

    def test_group_aware_split_prevents_train_test_group_overlap(self) -> None:
        dataset = self._dataset(
            rows=(
                self._row("r0", group="g-a"),
                self._row("r1", group="g-a"),
                self._row("r2", group="g-b"),
                self._row("r3", group="g-b"),
                self._row("r4", group="g-c"),
                self._row("r5", group="g-c"),
                self._row("r6", group="g-d"),
                self._row("r7", group="g-d"),
            )
        )
        manager = DataManager(artifact_store=self.store, provenance_emitter=self.emitter)

        result = manager.create_splits(
            self._request(
                dataset_ref=dataset.artifact_ref,
                seed="group-seed",
                group_key="group",
                train_ratio=0.5,
                validation_ratio=0.25,
                test_ratio=0.25,
            )
        )

        train_groups = set(result.split_group_ids["train"])
        test_groups = set(result.split_group_ids["test"])
        self.assertTrue(train_groups)
        self.assertTrue(test_groups)
        self.assertEqual(train_groups & test_groups, set())

    def test_kfold_assignments_are_deterministic_disjoint_and_complete(self) -> None:
        dataset = self._dataset(rows=self._rows(12))
        manager = DataManager(artifact_store=self.store, provenance_emitter=self.emitter)
        request = self._request(dataset_ref=dataset.artifact_ref, seed="fold-seed", fold_count=4)

        first = manager.create_splits(request)
        second = manager.create_splits(request)

        self.assertEqual(first.folds, second.folds)
        all_indices = set(range(12))
        validation_counts = {index: 0 for index in all_indices}
        for fold in first.folds:
            train_indices = set(fold.train_indices)
            validation_indices = set(fold.validation_indices)
            self.assertTrue(validation_indices)
            self.assertEqual(train_indices & validation_indices, set())
            self.assertEqual(train_indices | validation_indices, all_indices)
            for index in validation_indices:
                validation_counts[index] += 1
        self.assertEqual(set(validation_counts.values()), {1})
        payload = self._payload(first.split_manifest_ref)
        self.assertEqual(len(payload["folds"]), 4)
        self.assertNotIn(b"secret-label-", self.store.get_artifact(first.split_manifest_ref))

    def test_blind_inputs_never_surface_label_values(self) -> None:
        rows = (
            self._row("r0", label="train-label-0"),
            self._row("r1", label="train-label-1"),
            self._row("r2", role="blind", label="do-not-surface-2"),
            self._row("r3", role="blind", label="do-not-surface-3"),
            self._row("r4", label="train-label-4"),
        )
        dataset = self._dataset(rows=rows)
        manager = DataManager(artifact_store=self.store, provenance_emitter=self.emitter)

        result = manager.create_splits(
            self._request(
                dataset_ref=dataset.artifact_ref,
                seed="blind-seed",
                blind_role_key="role",
                blind_roles=("blind",),
            )
        )

        payload = self._payload(result.split_manifest_ref)
        manifest_bytes = self.store.get_artifact(result.split_manifest_ref)
        self.assertEqual(result.blind_input_indices, (2, 3))
        self.assertEqual(payload["blind_inputs"]["indices"], [2, 3])
        self.assertFalse(payload["blind_inputs"]["label_materialized"])
        self.assertNotIn(b"do-not-surface", manifest_bytes)
        self.assertNotIn("label_values", payload["blind_inputs"])

    def test_invalid_split_configuration_fails_closed_before_c4_write(self) -> None:
        dataset = self._dataset(rows=self._rows(3))
        manager = DataManager(artifact_store=self.store, provenance_emitter=self.emitter)

        with self.assertRaises(S2ContractModelError):
            manager.create_splits(
                self._request(
                    dataset_ref=dataset.artifact_ref,
                    seed="bad-ratio",
                    train_ratio=0.9,
                    validation_ratio=0.2,
                    test_ratio=0.2,
                )
            )

        self.assertEqual(
            [record.kind for record in self.store.query_artifacts({"producer_subsystem": "S2"})],
            [],
        )

    def test_blind_role_key_without_roles_fails_closed_before_c4_write(self) -> None:
        dataset = self._dataset(rows=self._rows(5))
        manager = DataManager(artifact_store=self.store, provenance_emitter=self.emitter)

        with self.assertRaises(S2ContractModelError):
            manager.create_splits(
                self._request(
                    dataset_ref=dataset.artifact_ref,
                    seed="missing-blind-roles",
                    blind_role_key="role",
                    blind_roles=(),
                )
            )

        self.assertEqual(
            [record.kind for record in self.store.query_artifacts({"producer_subsystem": "S2"})],
            [],
        )

    def test_tiny_dataset_fails_closed_before_empty_test_split_write(self) -> None:
        dataset = self._dataset(rows=self._rows(2))
        manager = DataManager(artifact_store=self.store, provenance_emitter=self.emitter)

        with self.assertRaises(S2ContractModelError):
            manager.create_splits(self._request(dataset_ref=dataset.artifact_ref, seed="too-small", fold_count=0))

        self.assertEqual(
            [record.kind for record in self.store.query_artifacts({"producer_subsystem": "S2"})],
            [],
        )

    def _dataset(self, *, rows: tuple[dict, ...]):
        return self.store.create_artifact(
            kind="dataset",
            payload={
                "schema": {"features": ["x"], "label": "label"},
                "rows": rows,
            },
            producer=Producer(subsystem="S8", version="0.0.0", job_id="dataset-ingest"),
            lineage=Lineage(
                input_refs=(),
                code_ref="git:s2-data-manager-fixture",
                environment_digest="oci:s2-data-manager-fixture",
            ),
        )

    def _request(
        self,
        *,
        dataset_ref: str,
        seed: str,
        train_ratio: float = 0.6,
        validation_ratio: float = 0.2,
        test_ratio: float = 0.2,
        group_key: str | None = None,
        blind_role_key: str | None = None,
        blind_roles: tuple[str, ...] = (),
        fold_count: int = 3,
    ) -> DataSplitRequest:
        return DataSplitRequest(
            job_id="split-job",
            dataset_ref=dataset_ref,
            split_seed=seed,
            train_ratio=train_ratio,
            validation_ratio=validation_ratio,
            test_ratio=test_ratio,
            row_id_key="row_id",
            label_key="label",
            group_key=group_key,
            blind_role_key=blind_role_key,
            blind_roles=blind_roles,
            fold_count=fold_count,
            code_ref="git:s2-data-manager",
            environment_digest="oci:s2-data-manager",
        )

    @staticmethod
    def _rows(count: int) -> tuple[dict, ...]:
        return tuple(S2DataManagerTests._row(f"r{index}", label=f"secret-label-{index}") for index in range(count))

    @staticmethod
    def _row(row_id: str, *, group: str | None = None, role: str = "train", label: str | None = None) -> dict:
        row = {
            "row_id": row_id,
            "x": float(row_id.removeprefix("r")),
            "label": label if label is not None else f"secret-label-{row_id}",
            "role": role,
        }
        if group is not None:
            row["group"] = group
        return row

    def _payload(self, artifact_ref: str) -> dict:
        return json.loads(self.store.get_artifact(artifact_ref).decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
