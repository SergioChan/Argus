from __future__ import annotations

import unittest

from argus_core import (
    AdapterBroker,
    AdapterDescriptor,
    BaselineBuilder,
    BudgetMeter,
    BuildBudget,
    BuildPlan,
    EvalRequest,
    InMemoryArtifactStore,
    NormalizedQuantity,
    PartialModelCheckpoint,
    Quantity,
    S2BudgetExceededError,
    SimpleAdapter,
)


class S2BudgetMeterTests(unittest.TestCase):
    def test_budget_meter_halts_on_gpu_seconds_breach_with_partial_checkpoint(self) -> None:
        meter = BudgetMeter.from_budget(
            job_id="job-budget",
            budget=BuildBudget(max_usd=10.0, max_wallclock_seconds=60, max_gpu_seconds=1.0),
            grace_fraction=0.1,
        )
        checkpoint = PartialModelCheckpoint(
            artifact_ref="c4://checkpoint/job-budget/best",
            reason="best-so-far",
            metrics={"loss": 0.12},
        )

        with self.assertRaises(S2BudgetExceededError) as raised:
            meter.record(
                wallclock_seconds=2.0,
                gpu_seconds=1.05,
                model_tokens=0,
                cost_usd=0.42,
                partial_checkpoint=checkpoint,
            )

        error = raised.exception
        self.assertEqual(error.category, "BUDGET")
        self.assertEqual(error.code, "GPU_SECONDS_EXCEEDED")
        self.assertFalse(error.retryable)
        self.assertEqual(error.partial_checkpoint, checkpoint)
        self.assertLessEqual(error.snapshot.gpu_seconds, 1.1)
        self.assertEqual(meter.snapshot().halted_reason, "GPU_SECONDS_EXCEEDED")

    def test_budget_meter_halts_on_cost_breach_without_overwriting_first_halt_reason(self) -> None:
        meter = BudgetMeter.from_budget(
            job_id="job-cost",
            budget=BuildBudget(max_usd=1.0, max_wallclock_seconds=60, max_model_tokens=100),
            grace_fraction=0.05,
        )

        with self.assertRaises(S2BudgetExceededError) as raised:
            meter.record(wallclock_seconds=1.0, gpu_seconds=0.0, model_tokens=40, cost_usd=1.01)

        self.assertEqual(raised.exception.code, "COST_USD_EXCEEDED")
        self.assertEqual(meter.snapshot().halted_reason, "COST_USD_EXCEEDED")

        with self.assertRaises(S2BudgetExceededError) as raised_again:
            meter.record(wallclock_seconds=1.0, gpu_seconds=0.0, model_tokens=101, cost_usd=0.0)

        self.assertEqual(raised_again.exception.code, "COST_USD_EXCEEDED")
        self.assertEqual(raised_again.exception.snapshot.model_tokens, 40)

    def test_builder_reports_cost_actual_from_budget_meter_totals(self) -> None:
        store = InMemoryArtifactStore()
        broker = AdapterBroker(artifact_store=store)
        broker.register(self._adapter())
        meter = BudgetMeter.from_budget(
            job_id="job-build-cost",
            budget=BuildBudget(max_usd=5.0, max_wallclock_seconds=60, max_gpu_seconds=10.0, max_model_tokens=500),
        )
        meter.record(wallclock_seconds=0.25, gpu_seconds=0.5, model_tokens=11, cost_usd=0.075)
        builder = BaselineBuilder(artifact_store=store, adapter_broker=broker, budget_meter=meter)

        result = builder.build(
            BuildPlan(
                job_id="job-build-cost",
                input_refs=(),
                adapter_request=EvalRequest(
                    adapter_id="gw_spectrum_surrogate",
                    inputs={
                        "T_n": Quantity(value=100, units="GeV"),
                        "alpha": Quantity(value=0.2, units="dimensionless"),
                        "v_w": Quantity(value=0.7, units="dimensionless"),
                    },
                    seed=7,
                ),
            )
        )

        self.assertEqual(
            result.cost_actual,
            {
                "wallclock_seconds": 0.25,
                "gpu_seconds": 0.5,
                "model_tokens": 11,
                "cost_usd": 0.075,
            },
        )
        self.assertEqual(result.diagnostics["budget_halted"], False)

    @staticmethod
    def _adapter() -> SimpleAdapter:
        descriptor = AdapterDescriptor(
            adapter_id="gw_spectrum_surrogate",
            version="1.0.0",
            input_units={"T_n": "GeV", "alpha": "dimensionless", "v_w": "dimensionless"},
            output_units={"omega": "dimensionless"},
            validity_domain={"v_w": (0.4, 0.95)},
            determinism="deterministic",
            provenance_ref="c4://adapter/gw_spectrum_surrogate/v1",
            differentiable=True,
        )
        return SimpleAdapter(descriptor, S2BudgetMeterTests._evaluate)

    @staticmethod
    def _evaluate(inputs: dict[str, NormalizedQuantity], _seed: int | None) -> dict[str, Quantity]:
        omega = inputs["alpha"].value * inputs["T_n"].value / 1000.0
        return {"omega": Quantity(value=omega, units="dimensionless", uncertainty={"kind": "interval", "radius": 0.01})}


if __name__ == "__main__":
    unittest.main()
