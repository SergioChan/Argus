from __future__ import annotations

import json
import math
import unittest

from argus_core import (
    FailureDiagnosisRequest,
    FailureDoctor,
    FailureProbeResult,
    FailureRepairProposal,
    FailureSymptom,
    InMemoryArtifactStore,
    ProvenanceEmitter,
    TrainingRequest,
)


class S2FailureDoctorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.emitter = ProvenanceEmitter(artifact_store=self.store)

    def test_nan_loss_repair_resolves_with_finite_probe_and_c4_log(self) -> None:
        request = FailureDiagnosisRequest(
            job_id="failure-nan",
            training_request=self._training_request(learning_rate=10.0),
            observed_symptom=FailureSymptom(
                code="nan_loss",
                message="loss became NaN at epoch 1",
                metrics={"loss": math.nan},
                evidence_refs=("c4://training-log/nan-loss",),
            ),
            max_repair_attempts=3,
            code_ref="git:s2-failure-doctor",
            environment_digest="oci:s2-failure-doctor",
            seed="failure-seed",
        )

        result = FailureDoctor(artifact_store=self.store, provenance_emitter=self.emitter).diagnose_and_repair(request)
        payload = self._payload(result.repair_log_ref)
        record = self.store.get_record(result.repair_log_ref)

        self.assertEqual(result.status, "RESOLVED")
        self.assertEqual(len(result.repair_actions), 1)
        action = result.repair_actions[0]
        self.assertEqual(action.code, "nan_loss")
        self.assertEqual(action.probe_result, "resolved")
        self.assertLess(action.learning_rate, request.training_request.learning_rate)
        self.assertLessEqual(action.learning_rate, 0.05)
        self.assertEqual(action.parameters["gradient_clip_norm"], 1.0)
        self.assertTrue(math.isfinite(result.final_metrics["loss"]))
        self.assertEqual(record.kind, "failure_repair_log")
        self.assertEqual(record.lineage.input_refs[0], "c4://dataset/failure-doctor")
        self.assertIn("c4://training-log/nan-loss", record.lineage.input_refs)
        self.assertIn(action.training_artifact_ref, record.lineage.input_refs)
        self.assertEqual(payload["status"], "RESOLVED")
        self.assertEqual(payload["repair_actions"][0]["probe_result"], "resolved")
        self.assertNotIn("training_rows", payload)

    def test_repair_loop_detection_quarantines_within_bound(self) -> None:
        def toggle_planner(symptom: FailureSymptom, current: TrainingRequest, attempt: int) -> FailureRepairProposal:
            mode = str(current.parameters.get("repair_mode", "a"))
            next_mode = "b" if mode == "a" else "a"
            return FailureRepairProposal(
                code="toggle_repair",
                reason=f"attempted toggle from {mode}",
                learning_rate=current.learning_rate,
                parameters={**current.parameters, "repair_mode": next_mode},
            )

        def always_fails(candidate: TrainingRequest) -> FailureProbeResult:
            return FailureProbeResult(
                status="FAILED",
                metrics={"loss": math.nan},
                symptom=FailureSymptom(code="oscillating_loss", message="repair toggled back", metrics={"loss": math.nan}),
            )

        request = FailureDiagnosisRequest(
            job_id="failure-loop",
            training_request=self._training_request(learning_rate=0.05, parameters={"repair_mode": "a"}),
            observed_symptom=FailureSymptom(code="oscillating_loss", message="repair alternates", metrics={}),
            max_repair_attempts=5,
            repair_planner=toggle_planner,
            probe=always_fails,
            code_ref="git:s2-failure-doctor",
            environment_digest="oci:s2-failure-doctor",
            seed="failure-seed",
        )

        result = FailureDoctor(artifact_store=self.store, provenance_emitter=self.emitter).diagnose_and_repair(request)
        payload = self._payload(result.repair_log_ref)

        self.assertEqual(result.status, "QUARANTINED")
        self.assertLessEqual(len(result.repair_actions), request.max_repair_attempts)
        self.assertEqual(result.repair_actions[-1].code, "repair_loop_detected")
        self.assertEqual(result.repair_actions[-1].probe_result, "loop_detected")
        self.assertEqual(payload["status"], "QUARANTINED")
        self.assertEqual(payload["repair_actions"][-1]["code"], "repair_loop_detected")
        self.assertEqual(payload["final_symptom"]["code"], "oscillating_loss")

    @staticmethod
    def _training_request(*, learning_rate: float, parameters: dict | None = None) -> TrainingRequest:
        return TrainingRequest(
            job_id="failure-train",
            family_id="tabular-baseline",
            input_refs=("c4://dataset/failure-doctor",),
            training_rows=(
                {"x": 0.0, "y": 1.0},
                {"x": 1.0, "y": 3.0},
                {"x": 2.0, "y": 5.0},
                {"x": 3.0, "y": 7.0},
            ),
            feature_names=("x",),
            target_name="y",
            max_epochs=4,
            learning_rate=learning_rate,
            parameters=parameters or {},
            code_ref="git:s2-failure-training",
            environment_digest="oci:s2-failure-training",
            seed="failure-training-seed",
        )

    def _payload(self, artifact_ref: str) -> dict:
        return json.loads(self.store.get_artifact(artifact_ref).decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
