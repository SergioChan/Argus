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
    TrainingRequest,
    TrainingRuntime,
    UQCalibrationRequest,
    UQCalibrationSample,
    UQCalibrator,
    UncertaintyRequiredError,
)


class S2UQCalibratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.emitter = ProvenanceEmitter(artifact_store=self.store)

    def test_point_estimate_only_model_is_rejected_before_c4_write(self) -> None:
        request = UQCalibrationRequest(
            job_id="uq-missing",
            model_artifact_ref="c4://model-checkpoint/point-estimate-only",
            split_manifest_ref="c4://dataset-split/train-validation-test",
            calibration_input_refs=("c4://dataset-split/calibration-fold",),
            validation_input_refs=("c4://dataset-split/validation-fold",),
            calibration_samples=self._conformal_samples(20, covered_error=0.05),
            validation_samples=self._conformal_samples(20, covered_error=0.05),
            uncertainty_method="none",
            native_uq="none",
            nominal_coverage=0.9,
            coverage_tolerance=0.03,
            code_ref="git:s2-uq-calibrator",
            environment_digest="oci:s2-uq-calibrator",
            seed="uq-seed",
        )

        with self.assertRaises(UncertaintyRequiredError) as raised:
            UQCalibrator(artifact_store=self.store, provenance_emitter=self.emitter).calibrate(request)

        self.assertEqual(raised.exception.code, "MISSING_UNCERTAINTY")
        self.assertEqual(self.store.record_count, 0)

    def test_split_conformal_interval_hits_nominal_coverage_and_emits_c4_lineage(self) -> None:
        refs = self._training_checkpoint_and_split_refs()
        request = self._request(
            model_artifact_ref=refs["model"],
            split_manifest_ref=refs["split"],
            calibration_samples=self._conformal_samples(40, covered_error=0.10),
            validation_samples=self._mixed_coverage_samples(covered=90, uncovered=10, covered_error=0.05, uncovered_error=0.25),
        )

        result = UQCalibrator(artifact_store=self.store, provenance_emitter=self.emitter).calibrate(request)
        payload = self._payload(result.calibration_artifact_ref)
        record = self.store.get_record(result.calibration_artifact_ref)

        self.assertEqual(result.status, "CALIBRATED")
        self.assertTrue(result.passed_internal_coverage)
        self.assertAlmostEqual(result.empirical_coverage, 0.9, places=12)
        self.assertLessEqual(abs(result.empirical_coverage - 0.9), request.coverage_tolerance)
        self.assertEqual(record.kind, "uq_calibration")
        self.assertEqual(
            record.lineage.input_refs,
            (
                refs["model"],
                refs["split"],
                "c4://dataset-split/calibration-fold",
                "c4://dataset-split/validation-fold",
            ),
        )
        self.assertEqual(payload["uncertainty_tag"]["source"], "split_conformal")
        self.assertEqual(payload["interval"]["radius"], result.interval_radius)
        self.assertFalse(payload["label_policy"]["raw_labels_materialized"])
        self.assertNotIn("calibration_samples", payload)
        self.assertNotIn("validation_samples", payload)
        self.assertNotIn("secret-label-", self.store.get_artifact(result.calibration_artifact_ref).decode("utf-8"))

    def test_miscalibrated_native_uq_records_fail_advisory_and_repair_action(self) -> None:
        refs = self._training_checkpoint_and_split_refs()
        request = self._request(
            model_artifact_ref=refs["model"],
            split_manifest_ref=refs["split"],
            calibration_samples=self._native_interval_samples(40, covered=True),
            validation_samples=self._native_mixed_coverage_samples(covered=70, uncovered=30),
            uncertainty_method="native_interval",
            native_uq="interval",
        )

        result = UQCalibrator(artifact_store=self.store, provenance_emitter=self.emitter).calibrate(request)
        payload = self._payload(result.calibration_artifact_ref)

        self.assertEqual(result.status, "NEEDS_REPAIR")
        self.assertFalse(result.passed_internal_coverage)
        self.assertAlmostEqual(result.empirical_coverage, 0.7, places=12)
        self.assertEqual(result.advisory_check.status, "FAIL")
        self.assertEqual([action.code for action in result.repair_actions], ["calibration_fail"])
        self.assertEqual(payload["advisory_check"]["status"], "FAIL")
        self.assertEqual(payload["repair_actions"][0]["code"], "calibration_fail")
        self.assertFalse(payload["passed_internal_coverage"])

    def test_nondeterministic_kernel_tolerance_is_honored_in_self_replay(self) -> None:
        refs = self._training_checkpoint_and_split_refs()
        request = self._request(
            model_artifact_ref=refs["model"],
            split_manifest_ref=refs["split"],
            calibration_samples=self._conformal_samples(30, covered_error=0.08),
            validation_samples=self._mixed_coverage_samples(covered=90, uncovered=10, covered_error=0.04, uncovered_error=0.20),
            nondeterminism_tolerance=0.001,
            replay_output_pairs=((1.0, 1.0004), (2.0, 1.9996), (-3.0, -3.0002)),
        )

        result = UQCalibrator(artifact_store=self.store, provenance_emitter=self.emitter).calibrate(request)
        payload = self._payload(result.calibration_artifact_ref)

        self.assertTrue(result.self_replay_passed)
        self.assertLessEqual(result.max_replay_delta, request.nondeterminism_tolerance)
        self.assertEqual(payload["self_replay"]["status"], "PASS")
        self.assertLessEqual(payload["self_replay"]["max_delta"], 0.001)

    def _request(
        self,
        *,
        model_artifact_ref: str,
        split_manifest_ref: str,
        calibration_samples: tuple[UQCalibrationSample, ...],
        validation_samples: tuple[UQCalibrationSample, ...],
        uncertainty_method: str = "split_conformal",
        native_uq: str = "conformal",
        nondeterminism_tolerance: float = 0.0,
        replay_output_pairs: tuple[tuple[float, float], ...] = (),
    ) -> UQCalibrationRequest:
        return UQCalibrationRequest(
            job_id="uq-calibration",
            model_artifact_ref=model_artifact_ref,
            split_manifest_ref=split_manifest_ref,
            calibration_input_refs=("c4://dataset-split/calibration-fold",),
            validation_input_refs=("c4://dataset-split/validation-fold",),
            calibration_samples=calibration_samples,
            validation_samples=validation_samples,
            uncertainty_method=uncertainty_method,
            native_uq=native_uq,
            nominal_coverage=0.9,
            coverage_tolerance=0.03,
            nondeterminism_tolerance=nondeterminism_tolerance,
            replay_output_pairs=replay_output_pairs,
            code_ref="git:s2-uq-calibrator",
            environment_digest="oci:s2-uq-calibrator",
            seed="uq-seed",
        )

    def _training_checkpoint_and_split_refs(self) -> dict[str, str]:
        dataset = self.store.create_artifact(
            kind="dataset",
            payload={
                "schema": {"features": ["x"], "label": "label"},
                "rows": tuple(self._dataset_row(index) for index in range(12)),
            },
            producer=Producer(subsystem="S8", version="0.0.0", job_id="dataset-ingest"),
            lineage=Lineage(
                input_refs=(),
                code_ref="git:s2-uq-dataset-fixture",
                environment_digest="oci:s2-uq-dataset-fixture",
            ),
        )
        split = DataManager(artifact_store=self.store, provenance_emitter=self.emitter).create_splits(
            DataSplitRequest(
                job_id="uq-split",
                dataset_ref=dataset.artifact_ref,
                split_seed="uq-split-seed",
                train_ratio=0.5,
                validation_ratio=0.25,
                test_ratio=0.25,
                row_id_key="row_id",
                label_key="label",
                blind_role_key="role",
                blind_roles=("blind",),
                fold_count=3,
                code_ref="git:s2-uq-data-manager",
                environment_digest="oci:s2-uq-data-manager",
            )
        )
        training = TrainingRuntime(artifact_store=self.store, provenance_emitter=self.emitter).train(
            TrainingRequest(
                job_id="uq-train",
                family_id="tabular-baseline",
                input_refs=(split.split_manifest_ref,),
                training_rows=(
                    {"x": 0.0, "y": 1.0},
                    {"x": 1.0, "y": 3.0},
                    {"x": 2.0, "y": 5.0},
                    {"x": 3.0, "y": 7.0},
                ),
                feature_names=("x",),
                target_name="y",
                max_epochs=3,
                learning_rate=0.05,
                code_ref="git:s2-uq-training",
                environment_digest="oci:s2-uq-training",
                seed="uq-training-seed",
            )
        )
        self.assertIsNotNone(training.final_checkpoint_ref)
        return {"model": training.final_checkpoint_ref or "", "split": split.split_manifest_ref}

    @staticmethod
    def _dataset_row(index: int) -> dict:
        role = "blind" if index in {10, 11} else "train"
        return {
            "row_id": f"r{index}",
            "x": float(index),
            "label": f"secret-label-{index}",
            "role": role,
        }

    @staticmethod
    def _conformal_samples(count: int, *, covered_error: float) -> tuple[UQCalibrationSample, ...]:
        return tuple(
            UQCalibrationSample(sample_id=f"c{index}", prediction=float(index), target=float(index) + covered_error)
            for index in range(count)
        )

    @staticmethod
    def _mixed_coverage_samples(
        *,
        covered: int,
        uncovered: int,
        covered_error: float,
        uncovered_error: float,
    ) -> tuple[UQCalibrationSample, ...]:
        samples = [
            UQCalibrationSample(sample_id=f"v-covered-{index}", prediction=float(index), target=float(index) + covered_error)
            for index in range(covered)
        ]
        samples.extend(
            UQCalibrationSample(
                sample_id=f"v-uncovered-{index}",
                prediction=float(covered + index),
                target=float(covered + index) + uncovered_error,
            )
            for index in range(uncovered)
        )
        return tuple(samples)

    @staticmethod
    def _native_interval_samples(count: int, *, covered: bool) -> tuple[UQCalibrationSample, ...]:
        samples = []
        for index in range(count):
            prediction = float(index)
            target = prediction + (0.05 if covered else 0.25)
            samples.append(
                UQCalibrationSample(
                    sample_id=f"native-{index}",
                    prediction=prediction,
                    target=target,
                    interval_lower=prediction - 0.1,
                    interval_upper=prediction + 0.1,
                )
            )
        return tuple(samples)

    @classmethod
    def _native_mixed_coverage_samples(cls, *, covered: int, uncovered: int) -> tuple[UQCalibrationSample, ...]:
        return cls._native_interval_samples(covered, covered=True) + tuple(
            UQCalibrationSample(
                sample_id=f"native-uncovered-{index}",
                prediction=float(covered + index),
                target=float(covered + index) + 0.25,
                interval_lower=float(covered + index) - 0.1,
                interval_upper=float(covered + index) + 0.1,
            )
            for index in range(uncovered)
        )

    def _payload(self, artifact_ref: str) -> dict:
        return json.loads(self.store.get_artifact(artifact_ref).decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
