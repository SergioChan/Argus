from __future__ import annotations

import json
import unittest

from argus_core import (
    FeatureGraphEngine,
    FeatureGraphNode,
    FeatureNode,
    FeatureTerm,
    FrozenPipelineRunner,
    InMemoryArtifactStore,
    Lineage,
    PipelineFreezeError,
    PipelineFreezeRequest,
    PipelineFreezer,
    Producer,
    ProvenanceEmitter,
    TrainingRequest,
    TrainingRuntime,
    UQCalibrationRequest,
    UQCalibrationSample,
    UQCalibrator,
)


class S2PipelineFreezerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.emitter = ProvenanceEmitter(artifact_store=self.store)
        refs = self._upstream_c4_refs()
        self.feature_set_ref = refs["feature_set"]
        self.model_checkpoint_ref = refs["model_checkpoint"]
        self.calibration_artifact_ref = refs["calibration"]
        self.dataset_ref = refs["dataset"]
        self.split_ref = refs["split"]

    def test_freeze_emits_self_contained_predict_artifact_and_independent_runner_predicts_units_and_uncertainty(self) -> None:
        result = PipelineFreezer(artifact_store=self.store, provenance_emitter=self.emitter).freeze(
            self._request(build_wallclock_seconds=100.0)
        )
        record = self.store.get_record(result.artifact_ref)
        payload = self._payload(result.artifact_ref)

        self.assertEqual(record.kind, "frozen_pipeline")
        self.assertEqual(record.claim_tier, "ran-toy")
        self.assertTrue(result.self_replay_passed)
        self.assertLessEqual(result.self_replay_fraction, 0.05)
        self.assertEqual(payload["entrypoint"], "predict")
        self.assertTrue(payload["s3_executable"])
        self.assertEqual(payload["component_refs"]["feature_set_ref"], self.feature_set_ref)
        self.assertEqual(payload["component_refs"]["model_checkpoint_ref"], self.model_checkpoint_ref)
        self.assertEqual(payload["component_refs"]["calibration_artifact_ref"], self.calibration_artifact_ref)
        self.assertEqual(payload["io_signature"]["inputs"]["x"]["units"], "GeV")
        self.assertEqual(payload["io_signature"]["outputs"]["y"]["units"], "GeV")
        self.assertEqual(payload["self_replay"]["status"], "PASS")
        self.assertEqual(
            record.lineage.input_refs,
            (
                self.feature_set_ref,
                self.model_checkpoint_ref,
                self.calibration_artifact_ref,
                self.dataset_ref,
                self.split_ref,
            ),
        )

        prediction = FrozenPipelineRunner(artifact_store=self.store).predict(
            result.artifact_ref,
            {"x": {"value": 1.5, "units": "GeV"}},
        )

        self.assertEqual(prediction.outputs_units_tagged["y"]["units"], "GeV")
        self.assertIsInstance(prediction.outputs_units_tagged["y"]["value"], float)
        self.assertEqual(prediction.uncertainty["kind"], "interval")
        self.assertGreaterEqual(prediction.uncertainty["upper"], prediction.outputs_units_tagged["y"]["value"])
        self.assertLessEqual(prediction.uncertainty["lower"], prediction.outputs_units_tagged["y"]["value"])
        self.assertEqual(prediction.io_signature, payload["io_signature"])
        self.assertTrue(prediction.diagnostics["loaded_from_c4"])

    def test_nondeterministic_kernel_tolerance_is_honored_and_failures_do_not_emit(self) -> None:
        passing = PipelineFreezer(artifact_store=self.store, provenance_emitter=self.emitter).freeze(
            self._request(nondeterminism_tolerance=0.001, nondeterministic_replay_jitter=0.0005)
        )
        passing_payload = self._payload(passing.artifact_ref)

        self.assertTrue(passing.self_replay_passed)
        self.assertLessEqual(passing.max_replay_delta, 0.001)
        self.assertEqual(passing_payload["self_replay"]["status"], "PASS")
        self.assertEqual(passing_payload["nondeterminism_tolerance"], 0.001)

        before_count = self.store.record_count
        with self.assertRaises(PipelineFreezeError) as raised:
            PipelineFreezer(artifact_store=self.store, provenance_emitter=self.emitter).freeze(
                self._request(nondeterminism_tolerance=0.001, nondeterministic_replay_jitter=0.01)
            )

        self.assertEqual(raised.exception.code, "SELF_REPLAY_FAILED")
        self.assertEqual(self.store.record_count, before_count)

    def test_self_replay_overhead_is_bounded_before_c4_emit(self) -> None:
        before_count = self.store.record_count

        with self.assertRaises(PipelineFreezeError) as raised:
            PipelineFreezer(artifact_store=self.store, provenance_emitter=self.emitter).freeze(
                self._request(build_wallclock_seconds=0.000001, max_self_replay_fraction=0.000001)
            )

        self.assertEqual(raised.exception.code, "SELF_REPLAY_OVERHEAD_EXCEEDED")
        self.assertEqual(self.store.record_count, before_count)

    def test_runner_rejects_probe_unit_drift(self) -> None:
        result = PipelineFreezer(artifact_store=self.store, provenance_emitter=self.emitter).freeze(self._request())

        with self.assertRaises(PipelineFreezeError) as raised:
            FrozenPipelineRunner(artifact_store=self.store).predict(
                result.artifact_ref,
                {"x": {"value": 1.5, "units": "MeV"}},
            )

        self.assertEqual(raised.exception.code, "IO_SIGNATURE_MISMATCH")

    def _upstream_c4_refs(self) -> dict[str, str]:
        dataset = self.store.create_artifact(
            kind="dataset",
            payload={"rows": [{"x": 0.0}, {"x": 1.0}, {"x": 2.0}]},
            producer=Producer(subsystem="S8", version="0.0.0", job_id="freeze-dataset"),
            lineage=Lineage(
                input_refs=(),
                code_ref="git:s2-freeze-dataset",
                environment_digest="oci:s2-freeze-dataset",
                job_id="freeze-dataset",
            ),
        )
        split = self.emitter.emit_artifact(
            kind="dataset_split",
            payload={
                "job_id": "freeze-split",
                "dataset_ref": dataset.artifact_ref,
                "roles": {"train": ["r0", "r1"], "validation": ["r2"]},
            },
            lineage=Lineage(
                input_refs=(dataset.artifact_ref,),
                code_ref="git:s2-freeze-split",
                environment_digest="oci:s2-freeze-split",
                seeds=("split-seed",),
                job_id="freeze-split",
            ),
        )
        graph = FeatureGraphEngine().build_graph(
            graph_id="featuregraph:pipeline-freeze",
            nodes=(
                FeatureGraphNode(
                    node_id="x",
                    op="source",
                    params={"field": "x"},
                    feature_node=FeatureNode(
                        node_id="x",
                        terms=(FeatureTerm(field_name="x", units="GeV"),),
                        declared_units="GeV",
                    ),
                ),
            ),
        )
        feature_set = FeatureGraphEngine().emit_feature_set(
            graph,
            selected_nodes=("x",),
            emitter=self.emitter,
            lineage=Lineage(
                input_refs=(dataset.artifact_ref,),
                code_ref="git:s2-freeze-featuregraph",
                environment_digest="oci:s2-freeze-featuregraph",
                seeds=("feature-seed",),
                job_id="freeze-featuregraph",
            ),
            feature_set_id="featureset:pipeline-freeze",
            replay_probe_input={"x": 1.25},
        )
        training = TrainingRuntime(artifact_store=self.store, provenance_emitter=self.emitter).train(
            TrainingRequest(
                job_id="freeze-train",
                family_id="tabular-baseline",
                input_refs=(feature_set.artifact_record.artifact_ref,),
                training_rows=(
                    {"x": 0.0, "y": 1.0},
                    {"x": 1.0, "y": 3.0},
                    {"x": 2.0, "y": 5.0},
                    {"x": 3.0, "y": 7.0},
                ),
                feature_names=("x",),
                target_name="y",
                max_epochs=4,
                learning_rate=0.05,
                code_ref="git:s2-freeze-training",
                environment_digest="oci:s2-freeze-training",
                seed="training-seed",
            )
        )
        self.assertIsNotNone(training.final_checkpoint_ref)
        calibration = UQCalibrator(artifact_store=self.store, provenance_emitter=self.emitter).calibrate(
            UQCalibrationRequest(
                job_id="freeze-uq",
                model_artifact_ref=training.final_checkpoint_ref or "",
                split_manifest_ref=split.artifact_ref,
                calibration_input_refs=(split.artifact_ref,),
                validation_input_refs=(split.artifact_ref,),
                calibration_samples=self._conformal_samples(40, covered_error=0.08),
                validation_samples=self._mixed_coverage_samples(
                    covered=90,
                    uncovered=10,
                    covered_error=0.04,
                    uncovered_error=0.18,
                ),
                uncertainty_method="split_conformal",
                native_uq="conformal",
                nominal_coverage=0.9,
                coverage_tolerance=0.03,
                nondeterminism_tolerance=0.0,
                replay_output_pairs=((1.0, 1.0),),
                code_ref="git:s2-freeze-uq",
                environment_digest="oci:s2-freeze-uq",
                seed="uq-seed",
            )
        )
        self.assertTrue(calibration.self_replay_passed)
        return {
            "dataset": dataset.artifact_ref,
            "split": split.artifact_ref,
            "feature_set": feature_set.artifact_record.artifact_ref,
            "model_checkpoint": training.final_checkpoint_ref or "",
            "calibration": calibration.calibration_artifact_ref,
        }

    def _request(
        self,
        *,
        build_wallclock_seconds: float = 100.0,
        max_self_replay_fraction: float = 0.05,
        nondeterminism_tolerance: float = 0.0,
        nondeterministic_replay_jitter: float = 0.0,
    ) -> PipelineFreezeRequest:
        return PipelineFreezeRequest(
            job_id="freeze-pipeline",
            feature_set_ref=self.feature_set_ref,
            model_checkpoint_ref=self.model_checkpoint_ref,
            calibration_artifact_ref=self.calibration_artifact_ref,
            input_refs=(self.dataset_ref, self.split_ref),
            code_ref="git:s2-pipeline-freezer",
            environment_digest="oci:s2-pipeline-freezer@sha256:fixture",
            seed="freeze-seed",
            container_digest="oci://argus-s2/frozen-pipeline@sha256:fixture",
            probe_inputs_units_tagged={"x": {"value": 1.5, "units": "GeV"}},
            output_name="y",
            output_units="GeV",
            nondeterminism_tolerance=nondeterminism_tolerance,
            nondeterministic_replay_jitter=nondeterministic_replay_jitter,
            build_wallclock_seconds=build_wallclock_seconds,
            max_self_replay_fraction=max_self_replay_fraction,
            adapter_refs=("adapter://argus.s2.featuregraph/local",),
            config={"runtime": "python-independent-runner", "deterministic": True},
        )

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

    def _payload(self, artifact_ref: str) -> dict:
        return json.loads(self.store.get_artifact(artifact_ref).decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
