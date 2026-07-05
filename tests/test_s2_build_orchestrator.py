from __future__ import annotations

import json
import math
import unittest

from argus_core import (
    BuildOrchestrationRequest,
    BuildOrchestrator,
    C3VerifierProfile,
    C3VerifierProfileCatalog,
    CapabilityDescriptor,
    FrozenPipelineRunner,
    InMemoryArtifactStore,
    InMemoryRegistry,
    Lineage,
    Producer,
    ProvenanceEmitter,
    S2SpecCompilerError,
    SelfGradeError,
    SpecCompiler,
)


class S2BuildOrchestratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.emitter = ProvenanceEmitter(artifact_store=self.store)
        self.registry = InMemoryRegistry(artifact_store=self.store)
        self.profile_catalog = C3VerifierProfileCatalog(
            (
                C3VerifierProfile(
                    profile_ref="c4://profile/s2-tc21-linear/v1",
                    profile_id="s2-tc21-linear",
                    version="1.0.0",
                    checks=("six-check", "calibration", "freeze-replay"),
                    provenance_ref="c4://profile/s2-tc21-linear/v1",
                ),
            )
        )
        self.dataset_ref = self._dataset()
        self.dataset_descriptor_ref = self._dataset_descriptor(self.dataset_ref)
        self._publish_registry_descriptors()

    def test_build_runs_s2_tc21_end_to_end_and_freezes_predictable_c4_pipeline(self) -> None:
        result = self._orchestrator().build(self._request())

        self.assertEqual(result.claim_tier, "ran-toy")
        self.assertEqual(result.diagnostics["s2_tc21"], "PASS")
        self.assertEqual(result.diagnostics["status"], "SUCCEEDED")
        self.assertEqual(result.diagnostics["claim_tier_cap"], "ran-toy")
        self.assertTrue(result.diagnostics["pipeline_freeze"]["self_replay_passed"])
        self.assertGreater(result.cost_actual["cost_usd"], 0.0)
        self.assertIsNotNone(result.dataset_split_ref)
        self.assertIsNotNone(result.feature_set_ref)
        self.assertIsNotNone(result.hpo_selection_ref)
        self.assertIsNotNone(result.training_log_ref)
        self.assertIsNotNone(result.uq_calibration_ref)
        self.assertIsNotNone(result.advisory_self_check_ref)
        self.assertTrue(result.frozen_pipeline_ref)

        artifact_kinds = {self.store.get_record(ref).kind for ref in result.artifact_refs}
        self.assertIn("dataset_split", artifact_kinds)
        self.assertIn("feature_set", artifact_kinds)
        self.assertIn("hpo_selection", artifact_kinds)
        self.assertIn("training_log", artifact_kinds)
        self.assertIn("model_checkpoint", artifact_kinds)
        self.assertIn("uq_calibration", artifact_kinds)
        self.assertIn("advisory_self_check", artifact_kinds)
        self.assertIn("frozen_pipeline", artifact_kinds)

        for ref in result.artifact_refs:
            record = self.store.get_record(ref)
            if record.producer.subsystem == "S2":
                self.assertEqual(record.claim_tier, "ran-toy", ref)

        frozen_record = self.store.get_record(result.frozen_pipeline_ref)
        frozen_payload = self._payload(result.frozen_pipeline_ref)
        self.assertEqual(frozen_record.kind, "frozen_pipeline")
        self.assertEqual(frozen_record.claim_tier, "ran-toy")
        self.assertEqual(frozen_payload["self_replay"]["status"], "PASS")
        self.assertEqual(frozen_payload["claim_tier"], "ran-toy")
        self.assertEqual(frozen_payload["io_signature"]["inputs"]["x"]["units"], "GeV")
        self.assertEqual(frozen_payload["io_signature"]["outputs"]["y"]["units"], "GeV")
        self.assertIn(result.feature_set_ref, frozen_record.lineage.input_refs)
        self.assertIn(result.model_ref, frozen_record.lineage.input_refs)
        self.assertIn(result.uq_calibration_ref, frozen_record.lineage.input_refs)

        prediction = FrozenPipelineRunner(artifact_store=self.store).predict(
            result.frozen_pipeline_ref,
            {"x": {"value": 1.25, "units": "GeV"}},
        )

        predicted = prediction.outputs_units_tagged["y"]["value"]
        self.assertTrue(math.isfinite(predicted))
        self.assertEqual(prediction.outputs_units_tagged["y"]["units"], "GeV")
        self.assertEqual(prediction.uncertainty["kind"], "interval")
        self.assertLessEqual(prediction.uncertainty["lower"], predicted)
        self.assertGreaterEqual(prediction.uncertainty["upper"], predicted)

    def test_attempted_self_grade_raise_fails_before_orchestration_artifacts(self) -> None:
        before_count = self.store.record_count

        with self.assertRaises(SelfGradeError):
            self._orchestrator().build(self._request(), attempted_claim_tier="novel-needs-human")

        self.assertEqual(self.store.record_count, before_count)

    def test_missing_verifier_profile_fails_closed_before_training_or_freezing(self) -> None:
        payload = self._c2_payload()
        payload["verifier_profile_ref"] = "c4://profile/missing/v1"
        before_count = self.store.record_count

        with self.assertRaises(S2SpecCompilerError) as raised:
            self._orchestrator().build(BuildOrchestrationRequest(c2_envelope=payload))

        self.assertEqual(raised.exception.category, "VERIFIER_UNAVAILABLE")
        self.assertEqual(raised.exception.code, "VERIFIER_PROFILE_UNAVAILABLE")
        self.assertEqual(self.store.record_count, before_count)

    def _orchestrator(self) -> BuildOrchestrator:
        compiler = SpecCompiler(
            verifier_profiles=self.profile_catalog,
            capability_registry=self.registry,
            artifact_store=self.store,
        )
        return BuildOrchestrator(
            artifact_store=self.store,
            spec_compiler=compiler,
            provenance_emitter=self.emitter,
            hpo_scheduler_backend="threadpool",
        )

    def _request(self) -> BuildOrchestrationRequest:
        return BuildOrchestrationRequest(
            c2_envelope=self._c2_payload(),
            code_ref="git:s2-build-orchestrator-test",
            environment_digest="oci:s2-build-orchestrator-test@sha256:fixture",
            seed="s2-tc21-seed",
            hpo_parameter_grid={"learning_rate": (0.02, 0.05)},
            hpo_max_epochs=2,
            final_max_epochs=5,
            train_ratio=0.6,
            validation_ratio=0.2,
            test_ratio=0.2,
            nominal_coverage=0.8,
            coverage_tolerance=0.25,
            max_self_replay_fraction=1.0,
            cost_usd_per_epoch=0.01,
        )

    def _c2_payload(self) -> dict[str, object]:
        return {
            "contract_version": "1.0.0",
            "job_id": "33333333-3333-4333-8333-333333333333",
            "root_request_id": "33333333-3333-4333-8333-333333333334",
            "trace_id": "trace-s2-tc21",
            "subtopic": "s2-tc21-classical-baseline",
            "problem_spec": {
                "task_type": "regression",
                "observable": "y",
                "target_units": "GeV",
                "inputs_schema": [
                    {"name": "x", "units": "GeV"},
                ],
            },
            "required_claim_tier_max": "recapitulated-known",
            "verifier_profile_ref": "c4://profile/s2-tc21-linear/v1",
            "contamination_index_version": "contam-2026-07-01",
            "budget": {
                "max_usd": 10.0,
                "max_wallclock_seconds": 600,
                "max_gpu_seconds": 10.0,
                "max_model_tokens": 1000,
            },
            "constraints": {"max_features": 4},
            "capability_scopes": {
                "allowed_adapters": ["adapter:s2-local-featuregraph"],
                "allowed_datasets": ["dataset:s2-tc21-linear"],
                "allowed_egress": [],
            },
            "input_artifact_refs": [self.dataset_descriptor_ref],
        }

    def _dataset(self) -> str:
        rows = []
        for index in range(60):
            x_value = (index - 30) / 10.0
            rows.append(
                {
                    "row_id": f"r{index:03d}",
                    "x": x_value,
                    "y": 1.0 + 2.0 * x_value,
                    "role": "train",
                }
            )
        return self.store.create_artifact(
            kind="dataset",
            payload={
                "schema": {"features": ["x"], "target": "y"},
                "rows": rows,
            },
            producer=Producer(subsystem="S8", version="0.0.0", job_id="s2-tc21-dataset"),
            lineage=Lineage(
                input_refs=(),
                code_ref="git:s2-tc21-dataset",
                environment_digest="oci:s2-tc21-dataset",
                job_id="s2-tc21-dataset",
            ),
        ).artifact_ref

    def _dataset_descriptor(self, dataset_ref: str) -> str:
        return self.store.create_artifact(
            kind="dataset_descriptor",
            payload={
                "dataset_id": "dataset:s2-tc21-linear",
                "dataset_ref": dataset_ref,
                "rows": 60,
                "schema": {"features": ["x"], "target": "y"},
            },
            producer=Producer(subsystem="S8", version="0.0.0", job_id="s2-tc21-descriptor"),
            lineage=Lineage(
                input_refs=(dataset_ref,),
                code_ref="git:s2-tc21-descriptor",
                environment_digest="oci:s2-tc21-descriptor",
                job_id="s2-tc21-descriptor",
            ),
        ).artifact_ref

    def _publish_registry_descriptors(self) -> None:
        self.registry.publish(
            CapabilityDescriptor(
                entity_id="adapter:s2-local-featuregraph",
                revision=1,
                kind="adapter",
                owner_subsystem="S7",
                contract_versions={"C5": "1.0.0", "C6": "1.0.0"},
                trust_class="local",
                capability_scopes=("c6.evaluate",),
                provenance_ref="c4://descriptor/adapter-s2-local-featuregraph/v1",
                subtopics=("s2-tc21-classical-baseline",),
            )
        )
        self.registry.publish(
            CapabilityDescriptor(
                entity_id="dataset:s2-tc21-linear",
                revision=1,
                kind="dataset",
                owner_subsystem="S8",
                contract_versions={"C5": "1.0.0", "C4": "1.0.0"},
                trust_class="local",
                capability_scopes=("c4.read",),
                provenance_ref=self.dataset_descriptor_ref,
                subtopics=("s2-tc21-classical-baseline",),
            )
        )

    def _payload(self, artifact_ref: str) -> dict:
        return json.loads(self.store.get_artifact(artifact_ref).decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
