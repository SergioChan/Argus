from __future__ import annotations

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from argus_core import (
    ExecContext,
    JobEnvelope,
    LifecyclePolicyError,
    LifecycleState,
    Subagent,
    SubagentDescriptor,
    SubagentSDKRunner,
)


class ExampleSubagent(Subagent):
    def __init__(self, descriptor: SubagentDescriptor) -> None:
        super().__init__(descriptor)
        self.plan_ctx_job_id: str | None = None
        self.build_ctx_job_id: str | None = None
        self.seen_plan_hash: str | None = None

    def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
        self.plan_ctx_job_id = ctx.job_id
        return {
            "steps": [
                {
                    "step_id": "inspect",
                    "kind": "feature",
                    "description": "Inspect the toy spectrum",
                    "est_cost": {"cost_usd": 0.25},
                }
            ],
            "datasets_required": ["c4://dataset/ewpt-toy"],
            "risk_notes": ["toy baseline only"],
        }

    def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
        self.build_ctx_job_id = ctx.job_id
        self.seen_plan_hash = str(plan["plan_hash"])
        return {
            "artifact_refs": ["c4://artifact/ewpt-toy/model"],
            "diagnostics": {"plan_hash": self.seen_plan_hash},
            "self_checks": [{"type": "smoke", "status": "PASS", "advisory": True}],
        }


class S1SDKBaseClassTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / "contracts" / "c1.subagent.schema.json"
        cls.c1_validator = Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8")))

    def setUp(self) -> None:
        self.descriptor = SubagentDescriptor(
            subagent_id="sdk-subagent",
            contract_version="1.0.0",
            subtopics=("ewpt",),
            required_adapters=("adapter:bounce",),
        )
        self.envelope = JobEnvelope(
            job_id="55555555-5555-4555-8555-555555555555",
            envelope_version="1.0.0",
            subtopic="ewpt",
            required_adapters=("adapter:bounce",),
            allowed_adapters=("adapter:bounce",),
            verifier_profile_ref="c4://profile/ewpt/v1",
            estimated_cost=0.5,
            budget_cost=1.0,
        )

    def test_runner_wraps_author_plan_build_in_real_lifecycle(self) -> None:
        subagent = ExampleSubagent(self.descriptor)
        runner = SubagentSDKRunner(subagent)

        acceptance = runner.accept(self.envelope)
        planned = runner.plan(self.envelope)
        built = runner.build(self.envelope.job_id, planned.payload)

        self.assertTrue(acceptance.accepted)
        self.assertEqual(subagent.plan_ctx_job_id, self.envelope.job_id)
        self.assertEqual(subagent.build_ctx_job_id, self.envelope.job_id)
        self.assertEqual(subagent.seen_plan_hash, planned.payload["plan_hash"])
        self.assertEqual(runner.runtime.store.current(self.envelope.job_id).state, LifecycleState.BUILDING)
        self.assertEqual([event.method for event in runner.runtime.store.events(self.envelope.job_id)], ["accept", "plan", "build"])
        self.assertEqual(planned.event.to_state, LifecycleState.PLANNING)
        self.assertEqual(planned.event.trigger, "internal")
        self.assertEqual(built.event.to_state, LifecycleState.BUILDING)
        self.assertEqual(built.event.trigger, "internal")
        self.assertEqual(planned.payload["job_id"], self.envelope.job_id)
        self.assertEqual(planned.payload["adapters_required"], ["adapter:bounce"])
        self.assertEqual(planned.payload["verifier_profile_ref"], "c4://profile/ewpt/v1")
        self.assertTrue(str(planned.payload["plan_hash"]).startswith("blake3:"))
        self.assertEqual(built.payload["job_id"], self.envelope.job_id)
        self.assertEqual(built.payload["uncertainty_summary"], {"representation": "none", "value": {}})
        self._assert_c1_valid(planned.payload)
        self._assert_c1_valid(built.payload)

    def test_framework_owned_methods_cannot_be_overridden_by_authors(self) -> None:
        with self.assertRaisesRegex(TypeError, "validate"):

            class BadValidateSubagent(Subagent):
                def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
                    return {}

                def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                    return {}

                def validate(self) -> dict[str, object]:
                    return {}

        with self.assertRaisesRegex(TypeError, "accept"):

            class BadAcceptSubagent(Subagent):
                def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
                    return {}

                def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                    return {}

                def accept(self) -> bool:
                    return True

    def test_framework_owned_methods_cannot_be_inherited_from_mixins(self) -> None:
        def plan(self: Subagent, ctx: ExecContext, envelope: JobEnvelope) -> dict[str, object]:
            return {}

        def build(self: Subagent, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
            return {}

        for method in ("register", "accept", "validate", "report", "cancel", "heartbeat"):
            with self.subTest(method=method):
                mixin_method = lambda self, *args, **kwargs: {"bypassed": method}
                mixin = type(f"{method.title()}Mixin", (), {method: mixin_method})
                attrs = {"plan": plan, "build": build}

                with self.assertRaisesRegex(TypeError, method):
                    type(f"Sneaky{method.title()}Subagent", (mixin, Subagent), attrs)

    def test_base_validate_is_framework_owned_policy_error(self) -> None:
        subagent = ExampleSubagent(self.descriptor)

        with self.assertRaises(LifecyclePolicyError) as raised:
            subagent.validate()

        self.assertEqual(raised.exception.envelope.code, "SDK_VALIDATE_FRAMEWORK_OWNED")
        self.assertEqual(raised.exception.envelope.category, "POLICY")

    def test_invalid_author_plan_payload_does_not_advance_lifecycle(self) -> None:
        class BadPlanSubagent(Subagent):
            def plan(self, ctx: ExecContext, envelope: JobEnvelope) -> list[str]:
                return ["not", "a", "mapping"]

            def build(self, ctx: ExecContext, plan: dict[str, object]) -> dict[str, object]:
                return {}

        runner = SubagentSDKRunner(BadPlanSubagent(self.descriptor))
        runner.accept(self.envelope)

        with self.assertRaises(TypeError):
            runner.plan(self.envelope)

        self.assertEqual(runner.runtime.store.current(self.envelope.job_id).state, LifecycleState.ACCEPTED)
        self.assertEqual([event.method for event in runner.runtime.store.events(self.envelope.job_id)], ["accept"])

    def _assert_c1_valid(self, payload: dict[str, object]) -> None:
        errors = sorted(self.c1_validator.iter_errors(payload), key=lambda error: list(error.path))
        self.assertEqual(errors, [], msg=[error.message for error in errors])


if __name__ == "__main__":
    unittest.main()
