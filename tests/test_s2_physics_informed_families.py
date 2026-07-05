from __future__ import annotations

import json
import math
import unittest

from argus_core import (
    InMemoryArtifactStore,
    ModelFamilyRegistry,
    PhysicsInformedTrainingBackend,
    ProvenanceEmitter,
    TrainingRequest,
    TrainingRuntime,
    list_model_families,
)


class S2PhysicsInformedFamilyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.emitter = ProvenanceEmitter(artifact_store=self.store)

    def test_default_physics_informed_families_expose_gradient_capabilities(self) -> None:
        families = {family.family_id: family for family in list_model_families()}

        physics_mlp = families["physics-informed-mlp"]
        diff_surrogate = families["differentiable-surrogate"]

        self.assertTrue(physics_mlp.differentiable)
        self.assertTrue(physics_mlp.physics_informed)
        self.assertIn("unitarity_penalty", physics_mlp.supported_constraints)
        self.assertIn("gradient_based", diff_surrogate.supported_constraints)

    def test_physics_informed_backend_enforces_positive_asymptotic_predictions_and_grad(self) -> None:
        backend = PhysicsInformedTrainingBackend()
        runtime = TrainingRuntime(
            artifact_store=self.store,
            provenance_emitter=self.emitter,
            registry=ModelFamilyRegistry.default(),
            backends={"physics-informed-mlp": backend},
        )

        result = runtime.train(self._request(job_id="physics-positive", parameters={"unitarity_bound": 4.0}))
        checkpoint = self._payload(result.final_checkpoint_ref)
        model_state = checkpoint["model_state"]
        metrics = checkpoint["metrics"]

        self.assertEqual(result.status, "SUCCEEDED")
        self.assertEqual(checkpoint["backend"], "physics-informed-analytic")
        self.assertGreaterEqual(metrics["positivity_min_prediction"], 0.0)
        self.assertLessEqual(metrics["asymptotic_limit_abs_error"], 1e-12)
        gradient = backend.grad(model_state, {"x": 0.5})
        self.assertIn("x", gradient)
        self.assertTrue(math.isfinite(gradient["x"]))
        self.assertGreater(gradient["x"], 0.0)

    def test_unitarity_penalty_reduces_violations_against_unpenalized_training(self) -> None:
        unpenalized = self._train_with_penalty("physics-unpenalized", penalty_weight=0.0)
        penalized = self._train_with_penalty("physics-penalized", penalty_weight=25.0)

        unpenalized_metrics = self._payload(unpenalized.final_checkpoint_ref)["metrics"]
        penalized_metrics = self._payload(penalized.final_checkpoint_ref)["metrics"]

        self.assertGreater(unpenalized_metrics["unitarity_violation_count"], 0)
        self.assertLess(
            penalized_metrics["unitarity_violation_count"],
            unpenalized_metrics["unitarity_violation_count"],
        )
        self.assertLess(
            penalized_metrics["unitarity_penalty"],
            unpenalized_metrics["unitarity_penalty"],
        )

    def _train_with_penalty(self, job_id: str, *, penalty_weight: float):
        backend = PhysicsInformedTrainingBackend()
        runtime = TrainingRuntime(
            artifact_store=self.store,
            provenance_emitter=self.emitter,
            registry=ModelFamilyRegistry.default(),
            backends={"physics-informed-mlp": backend},
        )
        return runtime.train(
            self._request(
                job_id=job_id,
                parameters={
                    "unitarity_bound": 1.0,
                    "unitarity_penalty_weight": penalty_weight,
                    "initial_scale_raw": 0.0,
                },
                max_epochs=80,
                learning_rate=0.08,
            )
        )

    @staticmethod
    def _request(
        *,
        job_id: str,
        parameters: dict[str, float] | None = None,
        max_epochs: int = 40,
        learning_rate: float = 0.08,
    ) -> TrainingRequest:
        return TrainingRequest(
            job_id=job_id,
            family_id="physics-informed-mlp",
            input_refs=("c4://dataset/physics-informed-fixture/v1",),
            training_rows=(
                {"x": 0.0, "y": 0.0},
                {"x": 0.25, "y": 0.1875},
                {"x": 0.5, "y": 0.75},
                {"x": 0.75, "y": 1.6875},
                {"x": 1.0, "y": 3.0},
                {"x": 1.2, "y": 4.32},
            ),
            feature_names=("x",),
            target_name="y",
            max_epochs=max_epochs,
            learning_rate=learning_rate,
            parameters=parameters or {},
            code_ref="git:s2-physics-informed",
            environment_digest="oci:s2-physics-informed",
            seed="seed-physics-informed",
            wallclock_seconds_per_epoch=0.25,
            gpu_seconds_per_epoch=0.0,
            model_tokens_per_epoch=0,
            cost_usd_per_epoch=0.001,
        )

    def _payload(self, artifact_ref: str | None) -> dict:
        self.assertIsNotNone(artifact_ref)
        return json.loads(self.store.get_artifact(artifact_ref).decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
