from __future__ import annotations

import dataclasses
import json
import unittest

from argus_core import (
    BudgetMeter,
    BuildBudget,
    DeterministicLinearTrainingBackend,
    InMemoryArtifactStore,
    ModelFamilyDescriptor,
    ModelFamilyRegistry,
    ProvenanceEmitter,
    S2BudgetExceededError,
    TrainingRequest,
    TrainingRuntime,
)


class S2TrainingRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.emitter = ProvenanceEmitter(artifact_store=self.store)

    def test_checkpoint_restart_resumes_and_matches_uninterrupted_run(self) -> None:
        runtime = TrainingRuntime(artifact_store=self.store, provenance_emitter=self.emitter)

        def interrupt_after_second_epoch(progress) -> None:
            if progress.epoch == 2:
                runtime.interrupt(progress.job_id, reason="simulated-runtime-restart")

        interrupted = runtime.train(dataclasses.replace(self._request(), on_epoch_complete=interrupt_after_second_epoch))

        self.assertEqual(interrupted.status, "INTERRUPTED")
        self.assertEqual(interrupted.completed_epochs, 2)
        self.assertIsNotNone(interrupted.final_checkpoint_ref)
        interrupted_checkpoint = self._payload(interrupted.final_checkpoint_ref)
        self.assertEqual(interrupted_checkpoint["epoch"], 2)
        self.assertEqual(interrupted_checkpoint["status"], "INTERRUPTED")

        resumed = runtime.train(
            dataclasses.replace(
                self._request(),
                resume_from_checkpoint_ref=interrupted.final_checkpoint_ref,
            )
        )
        uninterrupted = TrainingRuntime(artifact_store=InMemoryArtifactStore()).train(self._request())

        self.assertEqual(resumed.status, "SUCCEEDED")
        self.assertEqual(resumed.start_epoch, 2)
        self.assertEqual(resumed.completed_epochs, self._request().max_epochs)
        self.assertAlmostEqual(
            resumed.diagnostics["final_metrics"]["loss"],
            uninterrupted.diagnostics["final_metrics"]["loss"],
            places=12,
        )
        self.assertGreaterEqual(len(resumed.checkpoint_refs), 3)
        self.assertEqual(self.store.get_record(resumed.training_log_ref).kind, "training_log")
        self.assertEqual(self.store.get_record(resumed.final_checkpoint_ref).kind, "model_checkpoint")

    def test_registered_training_backend_runs_without_core_selector_changes(self) -> None:
        registry = ModelFamilyRegistry(
            (
                ModelFamilyDescriptor(
                    family_id="ridge-linear",
                    name="Ridge Linear",
                    family_kind="classical",
                    task_types=("regression",),
                    cost_class="low",
                    differentiable=False,
                    physics_informed=False,
                    native_uq="conformal",
                    deterministic_training=True,
                    training_entrypoint="tests.ridge_linear.train",
                    prediction_entrypoint="tests.ridge_linear.predict",
                    provenance_ref="c4://model-family/ridge-linear/v1",
                ),
            )
        )
        runtime = TrainingRuntime(
            artifact_store=self.store,
            provenance_emitter=self.emitter,
            registry=registry,
            backends={"ridge-linear": DeterministicLinearTrainingBackend(learning_rate=0.02)},
        )

        result = runtime.train(dataclasses.replace(self._request(), family_id="ridge-linear"))
        checkpoint = self._payload(result.final_checkpoint_ref)

        self.assertEqual(result.status, "SUCCEEDED")
        self.assertEqual(checkpoint["family_id"], "ridge-linear")
        self.assertEqual(checkpoint["backend"], "deterministic-linear")
        self.assertEqual(checkpoint["model_state"]["feature_names"], ["x"])

    def test_budget_halt_preserves_best_so_far_checkpoint(self) -> None:
        meter = BudgetMeter.from_budget(
            job_id="train-budget",
            budget=BuildBudget(max_usd=0.05, max_wallclock_seconds=30, max_gpu_seconds=10.0),
        )
        runtime = TrainingRuntime(
            artifact_store=self.store,
            provenance_emitter=self.emitter,
            budget_meter=meter,
        )

        with self.assertRaises(S2BudgetExceededError) as raised:
            runtime.train(dataclasses.replace(self._request(job_id="train-budget"), cost_usd_per_epoch=0.03))

        error = raised.exception
        self.assertEqual(error.category, "BUDGET")
        self.assertEqual(error.code, "COST_USD_EXCEEDED")
        self.assertIsNotNone(error.partial_checkpoint)
        checkpoint = self._payload(error.partial_checkpoint.artifact_ref)
        self.assertEqual(checkpoint["status"], "BUDGET_HALTED")
        self.assertEqual(checkpoint["epoch"], 2)
        self.assertEqual(self.store.get_record(error.partial_checkpoint.artifact_ref).kind, "model_checkpoint")
        self.assertEqual(meter.snapshot().partial_checkpoint, error.partial_checkpoint)

    def test_cooperative_cancel_captures_partial_checkpoint_and_diagnostics(self) -> None:
        runtime = TrainingRuntime(artifact_store=self.store, provenance_emitter=self.emitter)

        def cancel_after_second_epoch(progress) -> None:
            if progress.epoch == 2:
                ack = runtime.cancel(progress.job_id, reason="operator-request")
                self.assertEqual(ack["status"], "CANCEL_REQUESTED")

        result = runtime.train(dataclasses.replace(self._request(), job_id="train-cancel", on_epoch_complete=cancel_after_second_epoch))

        self.assertEqual(result.status, "CANCELLED")
        self.assertEqual(result.completed_epochs, 2)
        self.assertIsNotNone(result.partial_checkpoint)
        self.assertEqual(result.partial_checkpoint.reason, "operator-request")
        self.assertEqual(result.diagnostics["cancel_reason"], "operator-request")
        checkpoint = self._payload(result.partial_checkpoint.artifact_ref)
        self.assertEqual(checkpoint["status"], "CANCELLED")
        self.assertEqual(checkpoint["epoch"], 2)
        self.assertEqual(self.store.get_record(result.partial_checkpoint.artifact_ref).kind, "model_checkpoint")

    @staticmethod
    def _request(job_id: str = "train-resume") -> TrainingRequest:
        return TrainingRequest(
            job_id=job_id,
            family_id="tabular-baseline",
            input_refs=("c4://dataset/synthetic-linear/v1",),
            training_rows=(
                {"x": 0.0, "y": 1.0},
                {"x": 1.0, "y": 3.0},
                {"x": 2.0, "y": 5.0},
                {"x": 3.0, "y": 7.0},
            ),
            feature_names=("x",),
            target_name="y",
            max_epochs=5,
            learning_rate=0.05,
            code_ref="git:s2-training-runtime",
            environment_digest="oci:s2-training-runtime",
            seed="seed-training-runtime",
            wallclock_seconds_per_epoch=1.0,
            gpu_seconds_per_epoch=0.0,
            model_tokens_per_epoch=0,
            cost_usd_per_epoch=0.01,
        )

    def _payload(self, artifact_ref: str | None) -> dict:
        self.assertIsNotNone(artifact_ref)
        return json.loads(self.store.get_artifact(artifact_ref).decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
