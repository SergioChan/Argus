from __future__ import annotations

import json
import time
import unittest

from argus_core import (
    BuildBudget,
    DeterministicLinearTrainingBackend,
    HPOEngine,
    HPORequest,
    HPOTrial,
    InMemoryArtifactStore,
    ProvenanceEmitter,
    S2ContractModelError,
    select_hpo_winner,
)


class S2HPOEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()
        self.emitter = ProvenanceEmitter(artifact_store=self.store)

    def test_hpo_engine_runs_training_trials_and_emits_c4_selection(self) -> None:
        first = HPOEngine(artifact_store=self.store, provenance_emitter=self.emitter).run(self._request())
        second_store = InMemoryArtifactStore()
        second = HPOEngine(
            artifact_store=second_store,
            provenance_emitter=ProvenanceEmitter(artifact_store=second_store),
        ).run(self._request())

        self.assertEqual(first.status, "SUCCEEDED")
        self.assertEqual(first.selected.parameters, second.selected.parameters)
        self.assertEqual([trial.trial_id for trial in first.trials], [trial.trial_id for trial in second.trials])
        self.assertEqual({trial.status for trial in first.trials}, {"SUCCEEDED"})
        self.assertEqual(len(first.trials), 2)
        self.assertIsNotNone(first.selection_artifact_ref)

        selection_record = self.store.get_record(first.selection_artifact_ref)
        selection_payload = self._payload(first.selection_artifact_ref)
        trial_refs = tuple(trial.trial_artifact_ref for trial in first.trials)

        self.assertEqual(selection_record.kind, "hpo_selection")
        self.assertEqual(selection_payload["selected_trial_id"], first.selected.trial_id)
        self.assertEqual(selection_payload["objective"], "minimize")
        self.assertEqual(selection_payload["policy"], "pareto_lexicographic")
        self.assertEqual(selection_record.lineage.input_refs, trial_refs)
        for trial in first.trials:
            self.assertEqual(self.store.get_record(trial.trial_artifact_ref).kind, "hpo_trial")
            trial_payload = self._payload(trial.trial_artifact_ref)
            self.assertEqual(trial_payload["status"], "SUCCEEDED")
            self.assertEqual(self.store.get_record(trial_payload["final_checkpoint_ref"]).kind, "model_checkpoint")
            self.assertEqual(self.store.get_record(trial_payload["training_log_ref"]).kind, "training_log")

    def test_warm_start_completed_trial_can_win_without_consuming_new_trial_budget(self) -> None:
        cold = HPOEngine(artifact_store=InMemoryArtifactStore()).run(self._request(max_trials=1))
        warm_store = InMemoryArtifactStore()
        warm = HPOEngine(artifact_store=warm_store).run(
            self._request(
                max_trials=1,
                warm_start_trials=(
                    HPOTrial(
                        "prior-good",
                        score=0.001,
                        calibration_error=0.0,
                        cost=0.02,
                        parameters={"learning_rate": 0.2},
                        family_id="tabular-baseline",
                        status="SUCCEEDED",
                    ),
                ),
                warm_start_ref="c4://hpo-study/prior-good",
            )
        )

        self.assertLessEqual(warm.selected.score, cold.selected.score)
        self.assertEqual(warm.selected.trial_id, "prior-good")
        self.assertEqual(warm.trials[0].status, "WARM_STARTED")
        self.assertEqual(warm_store.get_record(warm.trials[0].trial_artifact_ref).lineage.input_refs, ("c4://hpo-study/prior-good",))

    def test_multi_objective_pareto_selection_is_deterministic(self) -> None:
        selected = select_hpo_winner(
            (
                HPOTrial("dominated", score=0.80, calibration_error=0.20, cost=5.0, parameters={"lr": 0.03}),
                HPOTrial("balanced", score=0.90, calibration_error=0.10, cost=5.0, parameters={"lr": 0.05}),
                HPOTrial("cheap", score=0.90, calibration_error=0.10, cost=2.0, parameters={"lr": 0.04}),
                HPOTrial("calibrated", score=0.88, calibration_error=0.01, cost=1.0, parameters={"lr": 0.02}),
            ),
            max_calibration_error=0.25,
            objective="maximize",
        )

        self.assertEqual(selected.trial_id, "cheap")
        self.assertEqual(selected.pareto_front_trial_ids, ("calibrated", "cheap"))
        self.assertNotIn("dominated", selected.pareto_front_trial_ids)

    def test_budget_halted_trial_records_partial_evidence_and_is_not_selected(self) -> None:
        result = HPOEngine(artifact_store=self.store, provenance_emitter=self.emitter).run(
            self._request(
                parameter_grid={
                    "learning_rate": (0.05,),
                    "cost_usd_per_epoch": (0.01, 0.03),
                },
                max_epochs=2,
                trial_budget=BuildBudget(max_usd=0.05, max_wallclock_seconds=20),
            )
        )

        by_status = {trial.status: trial for trial in result.trials}
        self.assertEqual(result.status, "SUCCEEDED")
        self.assertEqual(by_status["BUDGET_HALTED"].diagnostics["error_code"], "COST_USD_EXCEEDED")
        self.assertIsNotNone(by_status["BUDGET_HALTED"].checkpoint_ref)
        self.assertNotEqual(result.selected.trial_id, by_status["BUDGET_HALTED"].trial_id)
        halted_payload = self._payload(by_status["BUDGET_HALTED"].trial_artifact_ref)
        self.assertEqual(halted_payload["status"], "BUDGET_HALTED")
        self.assertEqual(halted_payload["partial_checkpoint_ref"], by_status["BUDGET_HALTED"].checkpoint_ref)

    def test_invalid_search_space_fails_before_c4_write(self) -> None:
        with self.assertRaises(S2ContractModelError):
            HPOEngine(artifact_store=self.store, provenance_emitter=self.emitter).run(
                self._request(parameter_grid={"learning_rate": (0.05, 0.05)})
            )

        self.assertEqual(self.store.record_count, 0)

    def test_worker_count_reduces_wallclock_for_parallel_trials(self) -> None:
        parameter_grid = {"learning_rate": (0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08)}
        slow_backend = {"tabular-baseline": SlowLinearBackend(delay_seconds=0.06)}

        single_start = time.perf_counter()
        HPOEngine(artifact_store=InMemoryArtifactStore(), backends=slow_backend, worker_count=1).run(
            self._request(parameter_grid=parameter_grid, max_epochs=1)
        )
        single_elapsed = time.perf_counter() - single_start

        parallel_start = time.perf_counter()
        HPOEngine(artifact_store=InMemoryArtifactStore(), backends=slow_backend, worker_count=4).run(
            self._request(parameter_grid=parameter_grid, max_epochs=1)
        )
        parallel_elapsed = time.perf_counter() - parallel_start

        self.assertLessEqual(parallel_elapsed, single_elapsed / (0.7 * 4))

    def _request(
        self,
        *,
        parameter_grid: dict[str, tuple[float, ...]] | None = None,
        max_trials: int | None = None,
        max_epochs: int = 4,
        trial_budget: BuildBudget | None = None,
        warm_start_trials: tuple[HPOTrial, ...] = (),
        warm_start_ref: str | None = None,
    ) -> HPORequest:
        return HPORequest(
            job_id="hpo-job",
            family_ids=("tabular-baseline",),
            parameter_grid=parameter_grid or {"learning_rate": (0.01, 0.05)},
            input_refs=("c4://dataset/hpo-synthetic/v1",),
            training_rows=(
                {"x": 0.0, "y": 1.0},
                {"x": 1.0, "y": 3.0},
                {"x": 2.0, "y": 5.0},
                {"x": 3.0, "y": 7.0},
            ),
            feature_names=("x",),
            target_name="y",
            max_epochs=max_epochs,
            code_ref="git:s2-hpo-engine",
            environment_digest="oci:s2-hpo-engine",
            seed="seed-hpo",
            objective_metric="loss",
            objective="minimize",
            max_trials=max_trials,
            trial_budget=trial_budget,
            warm_start_trials=warm_start_trials,
            warm_start_ref=warm_start_ref,
        )

    def _payload(self, artifact_ref: str | None) -> dict:
        self.assertIsNotNone(artifact_ref)
        return json.loads(self.store.get_artifact(artifact_ref).decode("utf-8"))


class SlowLinearBackend(DeterministicLinearTrainingBackend):
    def __init__(self, *, delay_seconds: float) -> None:
        super().__init__()
        self._delay_seconds = delay_seconds

    def train_epoch(self, request, state, *, epoch: int):
        time.sleep(self._delay_seconds)
        return super().train_epoch(request, state, epoch=epoch)


if __name__ == "__main__":
    unittest.main()
